//! Bounded, pinned HTTPS transport. Worker ownership/policy checks precede this
//! boundary; it independently rejects unsafe network destinations.
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    time::Duration,
};

const MAX_BYTES: usize = 65_536;
const MAX_ADDRESSES: usize = 32;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) worker_enabled: bool,
    test_origins: HashSet<String>,
    certificates: Vec<reqwest::Certificate>,
}
pub(crate) struct Target {
    pub(crate) url: String,
    pub(crate) allowed_ips: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) code: &'static str,
    pub(crate) retryable: bool,
}
impl Settings {
    pub(crate) fn load(env: &HashMap<String, String>, app_env: &str) -> anyhow::Result<Self> {
        let worker_enabled = match env.get("AUTH_DELIVERY_WORKER_ENABLED").map(String::as_str) {
            None | Some("false") => false,
            Some("true") => true,
            _ => anyhow::bail!("AUTH_DELIVERY_WORKER_ENABLED_INVALID"),
        };
        let mut test_origins = HashSet::new();
        if let Some(raw) = env.get("AUTH_DELIVERY_TEST_ORIGINS") {
            anyhow::ensure!(app_env == "test", "AUTH_DELIVERY_TEST_ORIGINS_FORBIDDEN");
            anyhow::ensure!(
                !raw.is_empty() && raw.len() <= 8192,
                "AUTH_DELIVERY_TEST_ORIGINS_INVALID"
            );
            for origin in raw.split(',') {
                let url = reqwest::Url::parse(origin)
                    .map_err(|_| anyhow::anyhow!("AUTH_DELIVERY_TEST_ORIGINS_INVALID"))?;
                anyhow::ensure!(
                    url.scheme() == "https"
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.query().is_none()
                        && url.fragment().is_none()
                        && url.path() == "/"
                        && url.port_or_known_default().is_some_and(|port| port != 0)
                        && url.origin().ascii_serialization() == origin
                        && url
                            .host_str()
                            .is_some_and(|host| host.ends_with(".test") && host.len() > 5)
                        && test_origins.insert(origin.to_owned()),
                    "AUTH_DELIVERY_TEST_ORIGINS_INVALID"
                );
            }
            anyhow::ensure!(
                test_origins.len() <= MAX_ADDRESSES,
                "AUTH_DELIVERY_TEST_ORIGINS_INVALID"
            );
        }
        let certificates = if let Some(path) = env.get("AUTH_DELIVERY_CA_FILE") {
            anyhow::ensure!(
                Path::new(path).is_absolute(),
                "AUTH_DELIVERY_CA_FILE_MUST_BE_ABSOLUTE"
            );
            let file = std::fs::File::open(path)
                .map_err(|_| anyhow::anyhow!("AUTH_DELIVERY_CA_FILE_UNREADABLE"))?;
            let metadata = file
                .metadata()
                .map_err(|_| anyhow::anyhow!("AUTH_DELIVERY_CA_FILE_UNREADABLE"))?;
            anyhow::ensure!(
                metadata.is_file() && metadata.len() <= 1_048_576,
                "AUTH_DELIVERY_CA_FILE_INVALID"
            );
            let mut bytes = Vec::new();
            file.take(1_048_577)
                .read_to_end(&mut bytes)
                .map_err(|_| anyhow::anyhow!("AUTH_DELIVERY_CA_FILE_UNREADABLE"))?;
            anyhow::ensure!(
                !bytes.is_empty() && bytes.len() <= 1_048_576,
                "AUTH_DELIVERY_CA_FILE_INVALID"
            );
            let certificates = reqwest::Certificate::from_pem_bundle(&bytes)
                .map_err(|_| anyhow::anyhow!("AUTH_DELIVERY_CA_FILE_INVALID"))?;
            anyhow::ensure!(
                !certificates.is_empty() && certificates.len() <= 16,
                "AUTH_DELIVERY_CA_FILE_INVALID"
            );
            certificates
        } else {
            Vec::new()
        };
        Ok(Self {
            worker_enabled,
            test_origins,
            certificates,
        })
    }
}

fn denied(code: &'static str) -> Failure {
    Failure {
        code,
        retryable: false,
    }
}
fn unavailable(code: &'static str) -> Failure {
    Failure {
        code,
        retryable: true,
    }
}

/// Conservatively accepts global unicast, excluding special-use networks even
/// where a prefix contains an isolated globally routable anycast exception.
fn publicly_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255) || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254) || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || (b == 0 && matches!(c, 0 | 2)) || (b == 88 && c == 99)))
                || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113)
                // Azure platform/metadata destination in ordinary public space.
                || [a,b,c,d] == [168,63,129,16])
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && (segments[1] < 0x0200 || segments[1] == 0x0db8))
                && !matches!(segments[0], 0x2002 | 0x3ffe | 0x3fff)
        }
    }
}
struct CheckedTarget {
    url: reqwest::Url,
    host: String,
    port: u16,
    allowed: HashSet<IpAddr>,
    test_loopback: bool,
}
fn check_target(settings: &Settings, target: &Target) -> Result<CheckedTarget, Failure> {
    if target.url.len() > 4096
        || target
            .url
            .bytes()
            .any(|b| b <= 32 || b == 127 || b == b'\\')
    {
        return Err(denied("DELIVERY_URL_INVALID"));
    }
    let url = reqwest::Url::parse(&target.url).map_err(|_| denied("DELIVERY_URL_INVALID"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != target.url
    {
        return Err(denied("DELIVERY_URL_INVALID"));
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| denied("DELIVERY_URL_INVALID"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url
        .port_or_known_default()
        .filter(|port| *port != 0)
        .ok_or_else(|| denied("DELIVERY_URL_INVALID"))?;
    let test_loopback = settings
        .test_origins
        .contains(&url.origin().ascii_serialization());
    if target.allowed_ips.is_empty() || target.allowed_ips.len() > MAX_ADDRESSES {
        return Err(denied("DELIVERY_OWNER_IPS_INVALID"));
    }
    let mut allowed = HashSet::new();
    for raw in &target.allowed_ips {
        let ip = raw
            .parse::<IpAddr>()
            .map_err(|_| denied("DELIVERY_OWNER_IPS_INVALID"))?;
        if !(publicly_routable(ip) || (test_loopback && ip.is_loopback())) || !allowed.insert(ip) {
            return Err(denied("DELIVERY_OWNER_IPS_UNSAFE"));
        }
    }
    Ok(CheckedTarget {
        url,
        host,
        port,
        allowed,
        test_loopback,
    })
}
fn checked_addresses(
    target: &CheckedTarget,
    resolved: Vec<IpAddr>,
) -> Result<Vec<SocketAddr>, Failure> {
    if resolved.is_empty() || resolved.len() > MAX_ADDRESSES {
        return Err(denied("DELIVERY_DNS_EMPTY_OR_OVERSIZED"));
    }
    let mut unique = HashSet::new();
    let mut addresses = Vec::new();
    for ip in resolved {
        if !target.allowed.contains(&ip)
            || !(publicly_routable(ip) || (target.test_loopback && ip.is_loopback()))
        {
            return Err(denied("DELIVERY_DNS_UNVERIFIED_OR_UNSAFE"));
        }
        if unique.insert(ip) {
            addresses.push(SocketAddr::new(ip, target.port));
        }
    }
    Ok(addresses)
}
type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, Failure>> + Send + 'a>>;
trait Resolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}
struct SystemResolver;
impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(vec![ip]);
            }
            let records = tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| unavailable("DELIVERY_DNS_UNAVAILABLE"))?;
            Ok(records
                .take(MAX_ADDRESSES + 1)
                .map(|address| address.ip())
                .collect())
        })
    }
}
pub(crate) async fn send(
    settings: &Settings,
    target: &Target,
    body: &[u8],
    content_type: &str,
    proof: Option<&str>,
) -> Result<u16, Failure> {
    send_with_resolver(settings, target, body, content_type, proof, &SystemResolver).await
}
async fn send_with_resolver<R: Resolver>(
    settings: &Settings,
    target: &Target,
    body: &[u8],
    content_type: &str,
    proof: Option<&str>,
    resolver: &R,
) -> Result<u16, Failure> {
    if !settings.worker_enabled {
        return Err(denied("DELIVERY_WORKER_DISABLED"));
    }
    if body.is_empty()
        || body.len() > MAX_BYTES
        || !matches!(
            content_type,
            "application/json" | "application/x-www-form-urlencoded"
        )
    {
        return Err(denied("DELIVERY_REQUEST_INVALID"));
    }
    let proof = proof
        .map(|value| {
            if value.is_empty()
                || value.len() > 2048
                || !value.bytes().all(|byte| (33..=126).contains(&byte))
            {
                return Err(denied("DELIVERY_PROOF_INVALID"));
            }
            let mut header = reqwest::header::HeaderValue::from_str(value)
                .map_err(|_| denied("DELIVERY_PROOF_INVALID"))?;
            header.set_sensitive(true);
            Ok(header)
        })
        .transpose()?;
    tokio::time::timeout(TOTAL_TIMEOUT, async {
        let checked = check_target(settings, target)?;
        let resolved = tokio::time::timeout(
            Duration::from_secs(1),
            resolver.resolve(&checked.host, checked.port),
        )
        .await
        .map_err(|_| unavailable("DELIVERY_DNS_TIMEOUT"))??;
        let addresses = checked_addresses(&checked, resolved)?;
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(1))
            .timeout(TOTAL_TIMEOUT)
            .resolve_to_addrs(&checked.host, &addresses);
        for certificate in &settings.certificates {
            builder = builder.add_root_certificate(certificate.clone());
        }
        let client = builder
            .build()
            .map_err(|_| denied("DELIVERY_CLIENT_CONFIGURATION_FAILED"))?;
        let mut request = client
            .post(checked.url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body.to_vec());
        if let Some(proof) = proof {
            request = request.header("X-Identity-Delivery-Proof", proof);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| unavailable("DELIVERY_NETWORK_FAILED"))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(denied("DELIVERY_REDIRECT_DENIED"));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BYTES as u64)
        {
            return Err(denied("DELIVERY_RESPONSE_TOO_LARGE"));
        }
        let mut received = 0usize;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| unavailable("DELIVERY_RESPONSE_INTERRUPTED"))?
        {
            received = received
                .checked_add(chunk.len())
                .filter(|size| *size <= MAX_BYTES)
                .ok_or_else(|| denied("DELIVERY_RESPONSE_TOO_LARGE"))?;
        }
        Ok(status.as_u16())
    })
    .await
    .map_err(|_| unavailable("DELIVERY_TOTAL_TIMEOUT"))?
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
