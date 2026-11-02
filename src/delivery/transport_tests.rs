use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn owned_loopback_tcp_fixture_is_reachable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
    let connected = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(address),
    )
    .await;
    assert!(connected.is_ok(), "owned loopback TCP connect timed out");
    assert!(
        connected.unwrap().is_ok(),
        "owned loopback TCP connect failed"
    );
    accept.await.unwrap();
}

// Public, non-production certificate and key generated solely for these tests.
// No configured runtime CA/key material is read. Valid through 2100, SAN is one
// owned .test hostname; the signing CA private key is never retained.
const CA_DER: &str = "MIIBkzCCATmgAwIBAgIUOtkNFQl+7SdnXIkt73QzANpIiX0wCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwaUGhhc2UyMCBkaXNwb3NhYmxlIHRlc3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMCUxIzAhBgNVBAMMGlBoYXNlMjAgZGlzcG9zYWJsZSB0ZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjzfklvSXDjeJxzk/Y7dPewhx0tUPbhZbcBAg2KHqJMmFllUe9ikdyjC0V4AFTyAxrI2UU90m4bWHXJizqRm4JKNFMEMwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFARRhufxECHBzmvQzYSjIGBFZGgOMAoGCCqGSM49BAMCA0gAMEUCIQCkraC+pV1ZSkzP3wGlsa/l5IStwZEmGuBfC30L/r3lTAIgEoLzU9bTVQeZqtkWkSoW7VCnFBmWHTqfqOpr9Ev+hQE=";
const CERT_DER: &str = "MIIBxTCCAWugAwIBAgIUZCbD1MM3ng4uoRtgS3J52ImN4ZEwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwaUGhhc2UyMCBkaXNwb3NhYmxlIHRlc3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMCIxIDAeBgNVBAMMF2NvbGxlY3Rvci5kZWxpdmVyeS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyfn8e3TgSNgSPZ4DM9BYAy5e/2OQ1r8gDuHOkY1Q9chW1zlqpcw6Cqalf18meppZmyQ7XgCMeYNlmf7poEy+IKN6MHgwDAYDVR0TAQH/BAIwADAiBgNVHREEGzAZghdjb2xsZWN0b3IuZGVsaXZlcnkudGVzdDATBgNVHSUEDDAKBggrBgEFBQcDATAfBgNVHSMEGDAWgBQEUYbn8RAhwc5r0M2EoyBgRWRoDjAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIgJBxHcGFpxTsWdVKysa6LUQDk43JceYiZeNUunBuqhvsCIQDplYL7yp9RtGfP5BuXw+8REqwK6VL7/1LWdwCFgfVu8A==";
const KEY_DER: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6Na3TGVM5VxE4n/7KXrya6dkBX46dbte77ob2mZ8m7ChRANCAATJ+fx7dOBI2BI9ngMz0FgDLl7/Y5DWvyAO4c6RjVD1yFbXOWqlzDoKpqV/XyZ6mlmbJDteAIx5g2WZ/umgTL4g";

fn settings(origin: Option<&str>) -> Settings {
    let mut env = HashMap::from([("AUTH_DELIVERY_WORKER_ENABLED".into(), "true".into())]);
    if let Some(origin) = origin {
        env.insert("AUTH_DELIVERY_TEST_ORIGINS".into(), origin.into());
    }
    let mut value = Settings::load(&env, "test").unwrap();
    value
        .certificates
        .push(reqwest::Certificate::from_der(&STANDARD.decode(CA_DER).unwrap()).unwrap());
    value
}
fn target(raw: &str, ips: &[&str]) -> Target {
    Target {
        url: raw.into(),
        allowed_ips: ips.iter().map(|ip| (*ip).into()).collect(),
    }
}
fn ip(raw: &str) -> IpAddr {
    raw.parse().unwrap()
}

struct Answers {
    calls: AtomicUsize,
    first: Vec<IpAddr>,
    later: Vec<IpAddr>,
}
impl Answers {
    fn fixed(ips: &[&str]) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            first: ips.iter().map(|raw| ip(raw)).collect(),
            later: vec![ip("169.254.169.254")],
        }
    }
}
impl Resolver for Answers {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolveFuture<'a> {
        Box::pin(async move {
            Ok(if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first.clone()
            } else {
                self.later.clone()
            })
        })
    }
}
struct PendingDns;
impl Resolver for PendingDns {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolveFuture<'a> {
        Box::pin(async { std::future::pending().await })
    }
}

#[derive(Default)]
struct Seen {
    original_host: bool,
    original_sni: bool,
    proof_received: bool,
    body_received: bool,
    connections: usize,
}
enum Reply {
    Normal(u16, usize),
    Redirect,
    Chunked(usize),
    Hang,
    Disconnect,
}
struct Collector {
    port: u16,
    stage: Arc<AtomicUsize>,
    task: Option<tokio::task::JoinHandle<Seen>>,
}
impl Drop for Collector {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Collector {
    async fn start(reply: Reply) -> Self {
        let cert = rustls::pki_types::CertificateDer::from(STANDARD.decode(CERT_DER).unwrap());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(STANDARD.decode(KEY_DER).unwrap()),
        );
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stage = Arc::new(AtomicUsize::new(0));
        let stage_in_task = stage.clone();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            stage_in_task.store(1, Ordering::SeqCst);
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return Seen::default();
            };
            stage_in_task.store(2, Ordering::SeqCst);
            let original_sni = tls.get_ref().1.server_name() == Some("collector.delivery.test");
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let (header_end, content_length) = loop {
                let count = tls.read(&mut buffer).await.unwrap();
                assert!(count > 0 && request.len() + count <= MAX_BYTES + 8192);
                request.extend_from_slice(&buffer[..count]);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&request[..end]);
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while request.len() < header_end + content_length {
                let count = tls.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
            }
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let mut seen = Seen {
                original_sni,
                original_host: headers
                    .contains(&format!("host: collector.delivery.test:{port}\r\n")),
                proof_received: headers.contains("x-identity-delivery-proof: owned-test-proof\r\n"),
                body_received: &request[header_end..] == b"owned-test-body",
                connections: 1,
            };
            stage_in_task.store(3, Ordering::SeqCst);
            match reply {
                Reply::Normal(status, length) => {
                    let header = format!("HTTP/1.1 {status} Owned fixture\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n");
                    let _ = tls.write_all(header.as_bytes()).await;
                    let _ = tls.write_all(&vec![b'x'; length]).await;
                }
                Reply::Redirect => {
                    let _ = tls.write_all(b"HTTP/1.1 302 Owned fixture\r\nLocation: http://169.254.169.254/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                }
                Reply::Chunked(length) => {
                    let _ = tls.write_all(b"HTTP/1.1 200 Owned fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await;
                    for chunk in vec![b'x'; length].chunks(4096) {
                        let _ = tls
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .await;
                        let _ = tls.write_all(chunk).await;
                        let _ = tls.write_all(b"\r\n").await;
                    }
                    let _ = tls.write_all(b"0\r\n\r\n").await;
                }
                Reply::Hang => {
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 Owned fixture\r\nContent-Length: 1\r\n\r\n")
                        .await;
                    std::future::pending::<()>().await;
                }
                Reply::Disconnect => {}
            }
            let _ = tls.shutdown().await;
            drop(tls);
            if let Ok(Ok((_connection, _))) =
                tokio::time::timeout(Duration::from_millis(150), listener.accept()).await
            {
                seen.connections += 1;
            }
            seen
        });
        Self {
            port,
            stage,
            task: Some(task),
        }
    }
    fn origin(&self) -> String {
        format!("https://collector.delivery.test:{}", self.port)
    }
    fn target(&self) -> Target {
        target(&format!("{}/receive", self.origin()), &["127.0.0.1"])
    }
    async fn finish(mut self) -> Seen {
        let mut task = self.task.take().unwrap();
        match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
            Ok(result) => result.unwrap(),
            Err(_) => {
                task.abort();
                panic!("owned collector completion deadline");
            }
        }
    }
}

#[test]
fn production_forbids_the_presence_of_test_origins() {
    for origin in ["", "https://collector.delivery.test"] {
        assert!(Settings::load(
            &HashMap::from([("AUTH_DELIVERY_TEST_ORIGINS".into(), origin.into())]),
            "production"
        )
        .is_err());
    }
}

#[test]
fn settings_are_explicit_and_test_exceptions_cannot_expand_scope() {
    assert!(
        !Settings::load(&HashMap::new(), "production")
            .unwrap()
            .worker_enabled
    );
    for value in ["TRUE", "1", "", " false"] {
        assert!(Settings::load(
            &HashMap::from([("AUTH_DELIVERY_WORKER_ENABLED".into(), value.into())]),
            "test"
        )
        .is_err());
    }
    for origin in [
        "http://collector.delivery.test",
        "https://localhost",
        "https://127.0.0.1",
        "https://collector.delivery.test/",
        "https://collector.delivery.test/path",
        "https://collector.delivery.test:0",
        "https://user@collector.delivery.test",
        "https://collector.delivery.test?x=1",
        "https://collector.delivery.test#fragment",
        "https://collector.delivery.test,https://collector.delivery.test",
    ] {
        assert!(Settings::load(
            &HashMap::from([("AUTH_DELIVERY_TEST_ORIGINS".into(), origin.into())]),
            "test"
        )
        .is_err());
    }
    assert!(Settings::load(
        &HashMap::from([("AUTH_DELIVERY_CA_FILE".into(), "relative.pem".into())]),
        "test"
    )
    .is_err());
}

#[test]
fn absolute_ca_files_are_bounded_validated_and_closed() {
    struct OwnedCa(std::path::PathBuf);
    impl Drop for OwnedCa {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let file = OwnedCa(std::env::temp_dir().join(format!(
        "phase20-transport-test-ca-{}.pem",
        crate::util::uuid7::new_uuid()
    )));
    let env = HashMap::from([(
        "AUTH_DELIVERY_CA_FILE".into(),
        file.0.to_str().unwrap().to_owned(),
    )]);
    std::fs::write(
        &file.0,
        format!("-----BEGIN CERTIFICATE-----\n{CA_DER}\n-----END CERTIFICATE-----\n"),
    )
    .unwrap();
    assert_eq!(Settings::load(&env, "test").unwrap().certificates.len(), 1);
    for invalid in [
        Vec::new(),
        b"not a certificate".to_vec(),
        vec![b'x'; 1_048_577],
    ] {
        std::fs::write(&file.0, invalid).unwrap();
        assert!(Settings::load(&env, "test").is_err());
    }
    drop(file);
}

#[test]
fn production_ip_policy_rejects_metadata_private_and_reserved_ipv4_and_ipv6() {
    for raw in [
        "0.0.0.0",
        "0.8.8.8",
        "10.1.2.3",
        "100.64.0.1",
        "100.100.100.200",
        "100.127.255.254",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "192.0.0.9",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.19.1.1",
        "198.51.100.2",
        "203.0.113.2",
        "224.0.0.1",
        "239.255.255.255",
        "240.1.2.3",
        "255.255.255.255",
        "168.63.129.16",
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "::ffff:127.0.0.1",
        "fc00::1",
        "fd00:ec2::254",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "64:ff9b::a00:1",
        "2001::1",
        "2001:2::1",
        "2001:20::1",
        "2001:db8::1",
        "2002:0808:0808::1",
        "3ffe::1",
        "3fff::1",
        "3fff:ffff::1",
        "5f00::1",
    ] {
        assert!(
            !publicly_routable(ip(raw)),
            "special-use fixture was accepted"
        );
    }
    for raw in [
        "1.1.1.1",
        "8.8.8.8",
        "172.15.255.254",
        "172.32.0.1",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ] {
        assert!(publicly_routable(ip(raw)));
    }
}

#[test]
fn urls_owner_ips_and_every_dns_answer_are_checked_before_connecting() {
    let settings = settings(None);
    for raw in [
        "http://delivery.example/receive",
        "https://user:secret@delivery.example/receive",
        "https://@delivery.example/receive",
        "https://delivery.example/receive?token=value",
        "https://delivery.example/receive#token",
        "https://delivery.example",
        "https://DELIVERY.example/receive",
        "https://delivery.example:443/receive",
        "https://delivery.example:0/receive",
        "https://delivery.example\\@127.0.0.1/receive",
    ] {
        assert!(check_target(&settings, &target(raw, &["8.8.8.8"])).is_err());
    }
    for ips in [
        vec![],
        vec!["8.8.8.8", "127.0.0.1"],
        vec!["8.8.8.8", "8.8.8.8"],
        vec!["8.8.8.0/24"],
        vec!["not-an-address"],
    ] {
        assert!(
            check_target(&settings, &target("https://delivery.example/receive", &ips)).is_err()
        );
    }
    let checked = check_target(
        &settings,
        &target(
            "https://delivery.example/receive",
            &["8.8.8.8", "2001:4860:4860::8888"],
        ),
    )
    .unwrap();
    for answers in [
        vec![],
        vec![ip("8.8.8.8"), ip("127.0.0.1")],
        vec![ip("8.8.8.8"), ip("1.1.1.1")],
        vec![ip("8.8.8.8"); 33],
    ] {
        assert!(checked_addresses(&checked, answers).is_err());
    }
    assert_eq!(
        checked_addresses(&checked, vec![ip("8.8.8.8"), ip("2001:4860:4860::8888")])
            .unwrap()
            .len(),
        2
    );
    let test = settings_for_origin_scope();
    assert!(check_target(
        &test,
        &target(
            "https://collector.delivery.test:4431/receive",
            &["127.0.0.1"]
        )
    )
    .is_ok());
    assert!(check_target(
        &test,
        &target(
            "https://collector.delivery.test:4432/receive",
            &["127.0.0.1"]
        )
    )
    .is_err());
    assert!(check_target(
        &test,
        &target(
            "https://collector.delivery.test:4431/receive",
            &["10.0.0.1"]
        )
    )
    .is_err());
}
fn settings_for_origin_scope() -> Settings {
    settings(Some("https://collector.delivery.test:4431"))
}

#[tokio::test]
async fn dns_timeout_and_request_rejection_are_bounded_and_redacted() {
    let settings = settings(None);
    let target = target("https://delivery.example/receive", &["8.8.8.8"]);
    let resolver = Answers::fixed(&["8.8.8.8"]);
    let disabled = Settings::load(&HashMap::new(), "production").unwrap();
    assert_eq!(
        send_with_resolver(
            &disabled,
            &target,
            b"owned-test-body",
            "application/json",
            None,
            &resolver
        )
        .await
        .unwrap_err(),
        denied("DELIVERY_WORKER_DISABLED")
    );
    assert_eq!(
        send_with_resolver(
            &settings,
            &target,
            &vec![b'x'; MAX_BYTES + 1],
            "application/json",
            None,
            &resolver
        )
        .await
        .unwrap_err(),
        denied("DELIVERY_REQUEST_INVALID")
    );
    for (body, content_type, proof) in [
        (b"".as_slice(), "application/json", None),
        (b"owned-test-body".as_slice(), "text/plain", None),
        (
            b"owned-test-body".as_slice(),
            "application/json",
            Some("private\r\nInjected: bad"),
        ),
    ] {
        assert!(
            !send_with_resolver(&settings, &target, body, content_type, proof, &resolver)
                .await
                .unwrap_err()
                .retryable
        );
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    let failure = send_with_resolver(
        &settings,
        &target,
        b"owned-test-body",
        "application/json",
        None,
        &PendingDns,
    )
    .await
    .unwrap_err();
    assert_eq!(failure, unavailable("DELIVERY_DNS_TIMEOUT"));
    assert!(!format!("{failure:?}").contains("delivery.example"));
}

async fn positive_collector() {
    let collector = Collector::start(Reply::Normal(202, 0)).await;
    let settings = settings(Some(&collector.origin()));
    let target = collector.target();
    let resolver = Answers::fixed(&["127.0.0.1"]);
    let response = send_with_resolver(
        &settings,
        &target,
        b"owned-test-body",
        "application/json",
        Some("owned-test-proof"),
        &resolver,
    )
    .await;
    assert!(
        response.is_ok(),
        "fixed-code transport result {response:?}; collector phase {}",
        collector.stage.load(Ordering::SeqCst)
    );
    assert_eq!(response.unwrap(), 202);
    let seen = collector.finish().await;
    assert!(seen.original_host && seen.original_sni && seen.proof_received && seen.body_received);
    assert_eq!(seen.connections, 1);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_tls_pins_one_dns_snapshot_and_preserves_original_host_and_proof() {
    positive_collector().await;
}

#[tokio::test]
async fn certificate_chain_and_original_hostname_are_never_bypassed() {
    for wrong_name in [false, true] {
        let collector = Collector::start(Reply::Normal(200, 0)).await;
        let origin = if wrong_name {
            format!("https://other.delivery.test:{}", collector.port)
        } else {
            collector.origin()
        };
        let mut settings = settings(Some(&origin));
        if !wrong_name {
            settings.certificates.clear();
        }
        let target = target(&format!("{origin}/receive"), &["127.0.0.1"]);
        assert!(send_with_resolver(
            &settings,
            &target,
            b"owned-test-body",
            "application/json",
            None,
            &Answers::fixed(&["127.0.0.1"])
        )
        .await
        .is_err());
        drop(collector);
    }
}

#[tokio::test]
async fn redirects_are_not_followed_and_network_requests_are_not_retried() {
    for (reply, expected) in [
        (Reply::Redirect, "DELIVERY_REDIRECT_DENIED"),
        (Reply::Disconnect, "DELIVERY_NETWORK_FAILED"),
    ] {
        let collector = Collector::start(reply).await;
        let settings = settings(Some(&collector.origin()));
        let resolver = Answers::fixed(&["127.0.0.1"]);
        let failure = send_with_resolver(
            &settings,
            &collector.target(),
            b"owned-test-body",
            "application/x-www-form-urlencoded",
            None,
            &resolver,
        )
        .await
        .unwrap_err();
        assert_eq!(failure.code, expected);
        if expected == "DELIVERY_REDIRECT_DENIED" {
            assert!(!failure.retryable);
        }
        assert_eq!(collector.finish().await.connections, 1);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn declared_streamed_and_exact_response_bounds_are_enforced() {
    for reply in [
        Reply::Normal(200, MAX_BYTES + 1),
        Reply::Chunked(MAX_BYTES + 1),
    ] {
        let collector = Collector::start(reply).await;
        let settings = settings(Some(&collector.origin()));
        assert_eq!(
            send_with_resolver(
                &settings,
                &collector.target(),
                b"owned-test-body",
                "application/json",
                None,
                &Answers::fixed(&["127.0.0.1"])
            )
            .await
            .unwrap_err(),
            denied("DELIVERY_RESPONSE_TOO_LARGE")
        );
        drop(collector);
    }
    let collector = Collector::start(Reply::Normal(200, MAX_BYTES)).await;
    let settings = settings(Some(&collector.origin()));
    assert_eq!(
        send_with_resolver(
            &settings,
            &collector.target(),
            b"owned-test-body",
            "application/json",
            None,
            &Answers::fixed(&["127.0.0.1"])
        )
        .await
        .unwrap(),
        200
    );
    collector.finish().await;
}

#[tokio::test]
async fn slow_response_cannot_extend_the_total_three_second_deadline() {
    let collector = Collector::start(Reply::Hang).await;
    let settings = settings(Some(&collector.origin()));
    let started = std::time::Instant::now();
    let failure = send_with_resolver(
        &settings,
        &collector.target(),
        b"owned-test-body",
        "application/json",
        None,
        &Answers::fixed(&["127.0.0.1"]),
    )
    .await
    .unwrap_err();
    assert!(
        failure.retryable
            && matches!(
                failure.code,
                "DELIVERY_TOTAL_TIMEOUT" | "DELIVERY_RESPONSE_INTERRUPTED"
            )
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(collector);
}

#[test]
fn environment_proxies_are_ignored_in_an_isolated_process() {
    const CHILD: &str = "IDENTITY_PHASE20_TRANSPORT_PROXY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(positive_collector());
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "delivery::transport::tests::environment_proxies_are_ignored_in_an_isolated_process",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("http_proxy", "http://127.0.0.1:1")
        .env("https_proxy", "http://127.0.0.1:1")
        .env("all_proxy", "http://127.0.0.1:1")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "isolated proxy transport check failed"
    );
}
