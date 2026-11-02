//! HTTP protocol boundaries. OAuth back-channel endpoints do not accept Cookies as authentication.

use super::{invalid, keys, Result};
use crate::{error::AppError, state::AppState};
use axum::{
    extract::{RawForm, RawQuery, Request, State},
    http::{header, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/oauth/login", get(login_page))
        .route("/oauth/authorize", get(super::oauth::authorize))
        .route(
            "/oauth/interaction/{id}",
            get(super::oauth::get_interaction).post(super::oauth::submit_interaction),
        )
        .route("/oauth/token", post(super::oauth::token))
        .route("/oauth/logout", post(super::oauth::logout::command))
        .route(
            "/oauth/logout/operations/{operation}",
            post(super::oauth::logout::operation),
        )
        .route(
            "/internal/identity/auth/context-interactions",
            post(super::oauth::unified_context::create),
        )
        .route(
            "/internal/identity/auth/context-selection/source",
            post(super::oauth::unified_context::source),
        )
        .route(
            "/oauth/userinfo",
            get(super::oauth::userinfo_get).post(super::oauth::userinfo_post),
        )
        .route("/oauth/introspect", post(super::oauth::introspect))
        .route("/oauth/revoke", post(super::oauth::revoke))
        .route("/oauth/jwks", get(keys::jwks))
        .route("/internal/identity/auth/keys/publish", post(keys::publish))
        .route(
            "/internal/identity/auth/keys/activate",
            post(keys::activate),
        )
        .route(
            "/internal/identity/auth/keys/{kid}",
            axum::routing::delete(keys::retire),
        )
        .route(
            "/internal/identity/auth/keys/{kid}/revoke",
            post(keys::revoke),
        )
        .route("/sso/login", get(login_page))
        .route("/sso/applications", get(applications_page))
        .route("/sso/security", get(security_page))
        .route("/sso/assets/applications.js", get(applications_js))
        .route("/sso/assets/security.js", get(security_js))
        .route("/sso/assets/applications.css", get(applications_css))
        .route("/sso/assets/identity.css", get(identity_css))
        .route("/sso/assets/identity.js", get(identity_js))
        .route_layer(middleware::from_fn(protected_headers))
}

async fn protected_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name,value) in [
        ("cache-control","no-store"),("pragma","no-cache"),("referrer-policy","no-referrer"),
        ("x-content-type-options","nosniff"),("x-frame-options","DENY"),
        ("content-security-policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    ] {response.headers_mut().insert(name,HeaderValue::from_static(value));}
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin, Cookie"));
    response
}

async fn login_page(State(state): State<AppState>) -> std::result::Result<Response, AppError> {
    super::enabled(&state)?;
    Ok((
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../static/identity/login.html"),
    )
        .into_response())
}
async fn identity_css(State(state): State<AppState>) -> std::result::Result<Response, AppError> {
    super::enabled(&state)?;
    Ok((
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../static/identity/identity.css"),
    )
        .into_response())
}
async fn applications_page(
    State(state): State<AppState>,
) -> std::result::Result<Response, AppError> {
    super::enabled(&state)?;
    Ok((
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../static/identity/applications.html"),
    )
        .into_response())
}
async fn security_page(State(state): State<AppState>) -> std::result::Result<Response, AppError> {
    super::enabled(&state)?;
    Ok((
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../static/identity/security.html"),
    )
        .into_response())
}
async fn applications_js(State(state): State<AppState>) -> std::result::Result<Response, AppError> {
    super::enabled(&state)?;
    Ok((
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../static/identity/applications.js"),
    )
        .into_response())
}
async fn security_js(State(state): State<AppState>) -> std::result::Result<Response, AppError> {
    super::enabled(&state)?;
    Ok((
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../static/identity/security.js"),
    )
        .into_response())
}
async fn applications_css(
    State(state): State<AppState>,
) -> std::result::Result<Response, AppError> {
    super::enabled(&state)?;
    Ok((
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../static/identity/applications.css"),
    )
        .into_response())
}
async fn identity_js(State(state): State<AppState>) -> std::result::Result<Response, AppError> {
    super::enabled(&state)?;
    Ok((
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../static/identity/identity.js"),
    )
        .into_response())
}

async fn discovery(State(state): State<AppState>) -> Result<Json<Value>> {
    let issuer = super::authority(&state).await?;
    Ok(Json(
        json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/oauth/authorize"),
        "token_endpoint":format!("{issuer}/oauth/token"),"userinfo_endpoint":format!("{issuer}/oauth/userinfo"),
        "jwks_uri":format!("{issuer}/oauth/jwks"),
        "response_types_supported":["code"],"response_modes_supported":["query"],
        "grant_types_supported":["authorization_code","refresh_token","client_credentials"],"subject_types_supported":["pairwise"],
        "introspection_endpoint":format!("{issuer}/oauth/introspect"),
        "introspection_endpoint_auth_methods_supported":["client_secret_basic"],
        "revocation_endpoint":format!("{issuer}/oauth/revoke"),
        "revocation_endpoint_auth_methods_supported":["client_secret_basic"],
        "rp_logout_command_endpoint":format!("{issuer}/oauth/logout"),
        "backchannel_logout_supported":state.config.delivery.worker_enabled,
        "backchannel_logout_session_supported":true,
        "id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["client_secret_basic","none"],
        "scopes_supported":["openid","profile","offline_access"],"code_challenge_methods_supported":["S256"],
        "claims_supported":["iss","sub","sid","aud","exp","iat","auth_time","nonce","name","picture"],
        "authorization_response_iss_parameter_supported":true,"request_parameter_supported":false,"request_uri_parameter_supported":false}),
    ))
}

pub(super) fn decode_component(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(invalid());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let value = percent_encoding::percent_decode_str(&raw.replace('+', " "))
        .decode_utf8()
        .map_err(|_| invalid())?
        .into_owned();
    if value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn parameters(raw: &str) -> Result<BTreeMap<String, String>> {
    if raw.len() > 16384 {
        return Err(invalid());
    }
    let mut result = BTreeMap::new();
    for part in raw.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let key = decode_component(key)?;
        let value = decode_component(value)?;
        if key.is_empty()
            || key.len() > 80
            || value.len() > 4096
            || result.len() >= 40
            || result.insert(key, value).is_some()
        {
            return Err(invalid());
        }
    }
    Ok(result)
}

pub(super) fn form(raw: RawForm, query: RawQuery) -> Result<BTreeMap<String, String>> {
    if query.0.is_some_and(|query| !query.is_empty()) {
        return Err(invalid());
    }
    parameters(std::str::from_utf8(&raw.0).map_err(|_| invalid())?)
}

pub(super) fn required<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    values
        .get(name)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(invalid)
}

pub(super) fn callback(
    redirect: &str,
    state: &str,
    issuer: &str,
    value: (&str, &str),
) -> Result<String> {
    let mut target = reqwest::Url::parse(redirect).map_err(|_| invalid())?;
    target
        .query_pairs_mut()
        .append_pair(value.0, value.1)
        .append_pair("state", state)
        .append_pair("iss", issuer);
    Ok(target.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn retired_protocol_and_registry_routes_are_absent() {
        use axum::{
            body::Body,
            http::{Method, Request, StatusCode},
        };
        use std::{collections::HashMap, sync::Arc};
        use tower::ServiceExt;

        // A lazy pool proves these route decisions cannot fall through to any
        // old issuer or database-backed compatibility adapter.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        let config = crate::config::Config::from_values(&HashMap::from([
            ("APP_ENV".to_owned(), "test".to_owned()),
            (
                "DATABASE_URL".to_owned(),
                "postgres://unused:unused@127.0.0.1:1/unused".to_owned(),
            ),
        ]))
        .unwrap();
        let state = AppState::new(pool, Arc::new(config));
        let app = routes()
            .merge(crate::internal::routes())
            .merge(crate::sso::routes())
            .with_state(state);
        for (method, path) in [
            (Method::GET, "/oidc/authorize"),
            (Method::POST, "/oidc/authorize"),
            (
                Method::GET,
                "/oidc/interaction/018f0aa3-635c-7a12-98de-56789abcdef0",
            ),
            (Method::POST, "/oidc/token"),
            (Method::POST, "/oidc/context-interactions"),
            (Method::GET, "/oidc/userinfo"),
            (Method::GET, "/oidc/jwks"),
            (Method::POST, "/oidc/introspect"),
            (Method::POST, "/oidc/revoke"),
            (Method::POST, "/oidc/account/logout"),
            (Method::POST, "/internal/identity/context-selection/source"),
            (Method::GET, "/internal/identity/oidc/clients"),
            (Method::POST, "/internal/identity/oidc/clients"),
            (Method::POST, "/internal/identity/oidc/keys/publish"),
            (
                Method::GET,
                "/internal/identity/oidc/operations/018f0aa3-635c-7a12-98de-56789abcdef0",
            ),
            (Method::GET, "/api/sso/applications"),
            (
                Method::POST,
                "/api/sso/applications/018f0aa3-635c-7a12-98de-56789abcdef0/revoke",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "retired route {path} was still registered"
            );
        }
        // Wrong methods distinguish current endpoints from an absent router.
        for (method, path) in [
            (Method::GET, "/oauth/token"),
            (Method::GET, "/internal/identity/auth/keys/publish"),
            (
                Method::POST,
                "/internal/identity/auth/key-operations/018f0aa3-635c-7a12-98de-56789abcdef0",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "canonical route {path} was absent"
            );
        }
    }

    #[test]
    fn duplicate_encoded_names_and_controls_are_rejected() {
        assert!(parameters("state=a&st%61te=b").is_err());
        assert!(parameters("state=%0A").is_err());
        assert!(parameters("state=%zz").is_err());
        assert!(parameters("state=one").is_ok());
    }
    #[test]
    fn callbacks_keep_exact_registered_url_and_bind_issuer() {
        let target = callback(
            "https://customer.saas.test/auth/callback",
            "a&b",
            "https://auth.saas.test",
            ("code", "opaque"),
        )
        .unwrap_or_else(|_| panic!("static callback parameters rejected"));
        let url = reqwest::Url::parse(&target).unwrap();
        let pairs = url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(pairs.get("state").unwrap(), "a&b");
        assert_eq!(pairs.get("iss").unwrap(), "https://auth.saas.test");
    }
}
