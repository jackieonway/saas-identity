use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use sqlx::postgres::PgPoolOptions;
use std::{collections::HashMap, sync::Arc};
use tower::ServiceExt;

fn page_state(enabled: bool) -> AppState {
    let mut config = crate::config::Config::from_values(&HashMap::from([
        ("APP_ENV".into(), "test".into()),
        (
            "DATABASE_URL".into(),
            "postgres://page_fixture@page-fixture.invalid/page_fixture".into(),
        ),
    ]))
    .unwrap();
    config.sso_enabled = enabled;
    config.sso_origin = Some("https://auth.saas.test".into());
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://page_fixture@page-fixture.invalid/page_fixture")
        .unwrap();
    AppState::new(pool, Arc::new(config))
}

#[tokio::test]
async fn public_invitation_page_is_a_safe_shell_without_database_or_session_authority() {
    let state = page_state(true);
    let app = crate::internal::routes()
        .layer(middleware::from_fn_with_state(
            state.clone(),
            internal::guard,
        ))
        .with_state(state);
    let id = Uuid::now_v7();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/sso/invitations/{id}"))
                .header(header::COOKIE, "untrusted-cookie=value")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    for (name, value) in [
        ("content-type", "text/html; charset=utf-8"),
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
    ] {
        assert_eq!(response.headers().get(name).unwrap(), value);
    }
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let policy = response.headers().get("content-security-policy").unwrap();
    assert!(policy.to_str().unwrap().contains("script-src 'self'"));
    assert!(policy.to_str().unwrap().contains("frame-ancestors 'none'"));
    let body = String::from_utf8(
        to_bytes(response.into_body(), 32768)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("/sso/assets/invitation.js"));
    assert!(body.contains("id=\"invitation-token\""));
    assert!(body.contains("id=\"verification-ref\""));
    assert!(!body.contains(&id.to_string()));
    assert!(!body.contains("recipientRef"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/sso/assets/invitation.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/javascript; charset=utf-8"
    );
}

#[tokio::test]
async fn public_invitation_page_rejects_noncanonical_ids_queries_and_disabled_sso() {
    let id = Uuid::parse_str("019a1234-abcd-7890-8123-123456789abc").unwrap();
    for (enabled, path, status) in [
        (
            true,
            "/sso/invitations/not-an-id".into(),
            StatusCode::BAD_REQUEST,
        ),
        (
            true,
            format!("/sso/invitations/{}", id.to_string().to_uppercase()),
            StatusCode::BAD_REQUEST,
        ),
        (
            true,
            format!("/sso/invitations/{id}?token=unused"),
            StatusCode::BAD_REQUEST,
        ),
        (
            false,
            format!("/sso/invitations/{id}"),
            StatusCode::NOT_FOUND,
        ),
        (
            false,
            "/sso/assets/invitation.js".into(),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let response = routes()
            .with_state(page_state(enabled))
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
}
