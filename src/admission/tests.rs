use super::*;
use axum::{body::to_bytes, http::Request as HttpRequest, routing::post, Router};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tower::ServiceExt;

fn state(extra: &[(&str, &str)]) -> AppState {
    let mut env = HashMap::from([
        (
            "DATABASE_URL".into(),
            "postgres://owned@127.0.0.1:9/owned_phase22".into(),
        ),
        ("APP_ENV".into(), "test".into()),
    ]);
    for (k, v) in extra {
        env.insert((*k).into(), (*v).into());
    }
    let config = Arc::new(crate::config::Config::from_values(&env).unwrap());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy(&config.database_url)
        .unwrap();
    AppState::new(pool, config)
}
fn app(state: AppState, hits: Arc<AtomicUsize>) -> Router {
    Router::new()
        .route(
            "/oauth/probe",
            post(move |headers: axum::http::HeaderMap| {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    headers
                        .get("x-real-ip")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("missing")
                        .to_owned()
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(state.clone(), bounded))
        .layer(axum::middleware::from_fn_with_state(state, source))
}
fn request(peer: &str, claimed: &str) -> HttpRequest<Body> {
    let mut request = HttpRequest::post("/oauth/probe")
        .header("x-real-ip", claimed)
        .header("forwarded", "for=canary-secret")
        .header("x-forwarded-for", "another-canary-secret")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(Peer(peer.parse::<SocketAddr>().unwrap())));
    request
}
#[tokio::test]
async fn untrusted_forwarding_cannot_change_the_real_peer_budget() {
    let state = state(&[("AUTH_SOURCE_REQUESTS", "1")]);
    let hits = Arc::new(AtomicUsize::new(0));
    let app = app(state, hits.clone());
    let first = app
        .clone()
        .oneshot(request("127.0.0.8:30000", "198.51.100.1"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(to_bytes(first.into_body(), 100).await.unwrap(), "127.0.0.8");
    let second = app
        .oneshot(request("127.0.0.8:30001", "198.51.100.2"))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn only_the_configured_exact_peer_may_forward_one_canonical_source() {
    let state = state(&[
        ("AUTH_SOURCE_REQUESTS", "1"),
        ("TRUSTED_PROXY_IPS", "127.0.0.1"),
    ]);
    let app = app(state, Arc::new(AtomicUsize::new(0)));
    for ip in ["198.51.100.1", "198.51.100.2"] {
        let response = app
            .clone()
            .oneshot(request("127.0.0.1:30000", ip))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(to_bytes(response.into_body(), 100).await.unwrap(), ip);
    }
    assert_eq!(
        app.clone()
            .oneshot(request("127.0.0.2:30000", "198.51.100.3"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request("127.0.0.2:30001", "198.51.100.4"))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let mut duplicate = request("127.0.0.1:30000", "198.51.100.5");
    duplicate
        .headers_mut()
        .append("x-real-ip", "198.51.100.6".parse().unwrap());
    let response = app.oneshot(duplicate).await.unwrap();
    assert_eq!(
        to_bytes(response.into_body(), 100).await.unwrap(),
        "127.0.0.1"
    );
}
#[tokio::test]
async fn full_request_budget_and_oversized_body_do_not_reach_authority() {
    let state = state(&[("AUTH_REQUEST_CONCURRENCY", "1")]);
    let hits = Arc::new(AtomicUsize::new(0));
    let app = app(state.clone(), hits.clone());
    let held = state.auth_slots.clone().acquire_owned().await.unwrap();
    let response = app
        .clone()
        .oneshot(request("127.0.0.8:1", "untrusted"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    drop(held);
    let mut large = request("127.0.0.8:1", "untrusted");
    *large.body_mut() = Body::from(vec![b'x'; 32769]);
    let response = app.clone().oneshot(large).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        app.oneshot(request("127.0.0.8:1", "untrusted"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
#[tokio::test]
async fn closed_database_preserves_process_liveness_and_fails_readiness() {
    let state = state(&[]);
    state.pool.close().await;
    let app = crate::router(state);
    for path in ["/healthz", "/livez"] {
        assert_eq!(
            app.clone()
                .oneshot(HttpRequest::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        app.oneshot(HttpRequest::get("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn client_budget_is_independent_per_state_and_never_a_shared_authority_lock() {
    let first = state(&[("AUTH_CLIENT_REQUESTS", "1")]);
    let second = AppState::new(first.pool.clone(), first.config.clone());
    assert!(!Arc::ptr_eq(&first.auth_limits, &second.auth_limits));
    assert!(first.admit_protocol_client("one-client").is_ok());
    assert!(matches!(
        first.admit_protocol_client("one-client"),
        Err(crate::error::AppError::RateLimited(_))
    ));
    assert!(second.admit_protocol_client("one-client").is_ok());
    assert!(first.admit_protocol_client("other-client").is_ok());
}
