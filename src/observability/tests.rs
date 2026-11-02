use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    middleware,
    routing::post,
    Router,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

const CREDENTIAL: &str = "owned-metrics-credential-8ca9d3b057e2";

pub(super) fn fixture_state(pool: PgPool, enabled: bool) -> crate::state::AppState {
    let mut values = HashMap::from([
        ("APP_ENV".into(), "test".into()),
        (
            "DATABASE_URL".into(),
            "postgres://metrics_fixture@127.0.0.1:1/metrics_fixture".into(),
        ),
    ]);
    if enabled {
        values.insert("IDENTITY_METRICS_TOKEN".into(), CREDENTIAL.into());
    }
    let config = crate::config::Config::from_values(&values).unwrap();
    crate::state::AppState::new(pool, Arc::new(config))
}

fn lazy_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://metrics_fixture@127.0.0.1:1/metrics_fixture")
        .unwrap()
}

pub(super) async fn scrape(state: &crate::state::AppState) -> (StatusCode, String) {
    let response = routes()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/internal/identity/metrics")
                .header(header::AUTHORIZATION, format!("Bearer {CREDENTIAL}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = String::from_utf8(
        to_bytes(response.into_body(), 4_194_304)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, body)
}

#[test]
fn metrics_settings_require_independent_bounded_operational_credentials() {
    let empty = Settings::load(&HashMap::new(), "production").unwrap();
    assert!(!empty.enabled() && !empty.accepts(CREDENTIAL));
    for value in [
        "short".to_owned(),
        " ".repeat(32),
        "a".repeat(257),
        "valid-length-but-has-newline\n".into(),
    ] {
        let values = HashMap::from([("IDENTITY_METRICS_TOKEN".into(), value)]);
        assert!(Settings::load(&values, "test").is_err());
    }
    for value in [
        "a".repeat(64),
        "replace-this-production-credential-0123456789".into(),
        "change-me-this-is-a-production-placeholder-012345".into(),
        "short-but-valid-test-token".into(),
    ] {
        assert!(Settings::load(
            &HashMap::from([("IDENTITY_METRICS_TOKEN".into(), value)]),
            "production"
        )
        .is_err());
    }
    let token = "c7ea1590b283d46f580a9ec1376df824a61bc507ed094f32a8d176e40cb935fa2";
    let mut values = HashMap::from([("IDENTITY_METRICS_TOKEN".into(), token.into())]);
    let enabled = Settings::load(&values, "production").unwrap();
    assert!(enabled.enabled() && enabled.accepts(token) && !enabled.accepts(CREDENTIAL));
    for key in [
        "CONTEXT_PLATFORM_SERVICE_SECRET",
        "SSO_TOTP_ENCRYPTION_KEY",
        "METRICS_TOKEN",
    ] {
        values.insert(key.into(), token.into());
        assert!(Settings::load(&values, "production").is_err());
        values.remove(key);
    }
}

#[test]
fn known_route_labels_match_current_router_parameter_names() {
    let source = concat!(
        include_str!("../lib.rs"),
        include_str!("../sso/routes.rs"),
        include_str!("../oidc/protocol.rs"),
        include_str!("../auth_invitations.rs"),
        include_str!("../auth_invitations/activation.rs"),
        include_str!("../internal.rs")
    );
    for template in registry::ROUTES.iter().skip(1) {
        assert!(
            source.contains(&format!("\"{template}\"")),
            "metric template has no current router definition: {template}"
        );
        assert_ne!(registry::route(Some(template)), 0);
    }
    assert_ne!(
        registry::route(Some("/api/sso/consents/{consent}/revoke")),
        0
    );
    assert_ne!(
        registry::route(Some("/oauth/logout/operations/{operation}")),
        0
    );
}

#[test]
fn request_cardinality_and_histograms_have_no_request_derived_labels() {
    let mut metrics = registry::Registry::default();
    for number in 0..10_000 {
        let raw = format!("/unregistered/private-canary-{number}?token=never-label-this");
        metrics.request(
            registry::route(Some(&raw)),
            registry::method("X-PRIVATE-CANARY"),
            Some(418),
            0.25,
        );
    }
    metrics.request(
        registry::route(Some("/oauth/token")),
        registry::method("POST"),
        Some(503),
        0.5,
    );
    metrics.request(
        registry::route(Some("/oauth/token")),
        registry::method("POST"),
        None,
        0.1,
    );
    metrics.request(
        registry::route(Some("/oauth/token")),
        registry::method("POST"),
        Some(777),
        0.1,
    );
    let output = metrics.render();
    let series = output
        .lines()
        .filter(|line| line.starts_with("identity_http_requests_total{"))
        .count();
    assert_eq!(series, 4);
    assert!(series <= registry::REQUEST_SERIES_LIMIT);
    assert!(output.contains("status=\"4xx\",outcome=\"denied\"} 10000"));
    assert!(output.contains("status=\"503\",outcome=\"failed\""));
    assert!(output.contains("status=\"other\",outcome=\"failed\""));
    assert!(output.contains("status=\"cancelled\",outcome=\"cancelled\""));
    assert!(output.contains("le=\"0.25\"} 10000") && output.contains("le=\"+Inf\"} 10000"));
    for forbidden in ["private-canary", "never-label-this", "X-PRIVATE", "?token"] {
        assert!(!output.contains(forbidden));
    }
}

#[tokio::test]
async fn metrics_authentication_rejects_before_observing_database_and_does_not_set_cookies() {
    let pool = lazy_pool();
    let enabled = fixture_state(pool.clone(), true);
    for (authorized, cookie, query, expected) in [
        (false, false, false, StatusCode::UNAUTHORIZED),
        (true, true, false, StatusCode::BAD_REQUEST),
        (true, false, true, StatusCode::BAD_REQUEST),
    ] {
        let mut request = Request::builder().uri(if query {
            "/internal/identity/metrics?credential=PRIVATE_QUERY_CANARY"
        } else {
            "/internal/identity/metrics"
        });
        if authorized {
            request = request.header(header::AUTHORIZATION, format!("Bearer {CREDENTIAL}"));
        }
        if cookie {
            request = request.header(header::COOKIE, "PRIVATE_COOKIE_CANARY");
        }
        let response = routes()
            .with_state(enabled.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let body = String::from_utf8(to_bytes(response.into_body(), 8192).await.unwrap().to_vec())
            .unwrap();
        assert!(!body.contains("PRIVATE_") && !body.contains(CREDENTIAL));
    }
    let response = routes()
        .with_state(enabled)
        .oneshot(
            Request::builder()
                .uri("/internal/identity/metrics")
                .header(header::AUTHORIZATION, format!("Bearer {CREDENTIAL}"))
                .header(header::AUTHORIZATION, format!("Bearer {CREDENTIAL}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let (status, _) = scrape(&fixture_state(pool.clone(), false)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        pool.size(),
        0,
        "rejected scrape acquired a database connection"
    );
    pool.close().await;
}

#[tokio::test]
async fn database_failure_does_not_report_a_healthy_empty_delivery_queue() {
    let pool = lazy_pool();
    pool.close().await;
    let (status, output) = scrape(&fixture_state(pool, true)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        output.contains("identity_database_up 0")
            && output.contains("identity_delivery_observation_up 0")
    );
    assert!(!output.contains("identity_delivery_jobs{"));
    assert!(!output.contains("identity_delivery_source_events{"));
    assert!(!output.contains(CREDENTIAL) && !output.contains("postgres://"));
}

#[tokio::test]
async fn cancelled_http_work_is_observed_without_a_successful_response() {
    fn count() -> u64 {
        registry::render().lines().find_map(|line| line.strip_prefix(
            "identity_http_requests_total{route=\"/oauth/token\",method=\"POST\",status=\"cancelled\",outcome=\"cancelled\"} ")
            .and_then(|value| value.parse().ok())).unwrap_or(0)
    }
    let before = count();
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = entered.clone();
    let pool = lazy_pool();
    let state = fixture_state(pool.clone(), true);
    let app = Router::new()
        .route(
            "/oauth/token",
            post(move || {
                let signal = signal.clone();
                async move {
                    signal.notify_one();
                    std::future::pending::<StatusCode>().await
                }
            }),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            observe_request,
        ))
        .with_state(state);
    let work = tokio::spawn(async move {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .body(Body::from("PRIVATE_CANCELLED_BODY_CANARY"))
                .unwrap(),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    work.abort();
    assert!(work.await.unwrap_err().is_cancelled());
    assert!(count() > before);
    assert!(!registry::render().contains("PRIVATE_CANCELLED"));
    pool.close().await;
}

#[derive(Clone)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn request_bodies_headers_and_queries_never_enter_metrics_or_password_logs() {
    let pool = lazy_pool();
    let state = fixture_state(pool.clone(), true);
    let app = Router::new()
        .route(
            "/api/sso/invitations/{id}/accept",
            post(|| async { StatusCode::FORBIDDEN }),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            observe_request,
        ))
        .with_state(state);
    for number in 0..40 {
        let response = app.clone().oneshot(Request::builder().method("POST")
            .uri(format!("/api/sso/invitations/PRIVATE_PATH_CANARY_{number}/accept?token=PRIVATE_QUERY_CANARY"))
            .header(header::AUTHORIZATION, "Bearer PRIVATE_HEADER_CANARY")
            .header(header::COOKIE, "PRIVATE_COOKIE_CANARY")
            .body(Body::from("PRIVATE_BODY_PASSWORD_TOKEN_PHC_CANARY")).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || LogCapture(writer.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        timer(Stage::PasswordQueue).finish(Outcome::Timeout);
        timer(Stage::PasswordExecution).finish(Outcome::Denied);
        audit_failure();
    });
    let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    let output = registry::render();
    assert!(logs.contains("identity_password_stage") && logs.contains("outcome=\"timeout\""));
    assert!(output.contains("route=\"/api/sso/invitations/{id}/accept\""));
    assert!(output.contains("identity_audit_write_failures_total"));
    assert!(
        !output.contains("PRIVATE_") && !logs.contains("PRIVATE_") && !output.contains(CREDENTIAL)
    );
    pool.close().await;
}
