//! HTTP protocol boundaries. OAuth back-channel endpoints do not accept Cookies as authentication.

use super::{account_logout, clients, interaction, invalid, keys, tokens, Result};
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
        .route(
            "/oidc/authorize",
            get(interaction::authorize_get).post(interaction::authorize_post),
        )
        .route(
            "/oidc/interaction/{id}",
            get(interaction::get).post(interaction::submit),
        )
        .route("/oidc/token", post(tokens::token))
        .route(
            "/oidc/userinfo",
            get(tokens::userinfo).post(tokens::userinfo),
        )
        .route("/oidc/jwks", get(keys::jwks))
        .route("/oidc/introspect", post(tokens::introspect))
        .route("/oidc/revoke", post(tokens::revoke))
        .route("/oidc/account/logout", post(account_logout::logout))
        .route(
            "/internal/identity/oidc/clients",
            get(clients::list).post(clients::create),
        )
        .route(
            "/internal/identity/oidc/clients/{id}",
            axum::routing::patch(clients::update),
        )
        .route("/internal/identity/oidc/keys/publish", post(keys::publish))
        .route(
            "/internal/identity/oidc/keys/activate",
            post(keys::activate),
        )
        .route(
            "/internal/identity/oidc/keys/{kid}",
            axum::routing::delete(keys::retire),
        )
        .route(
            "/internal/identity/oidc/keys/{kid}/revoke",
            post(keys::revoke),
        )
        .route("/sso/login", get(login_page))
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
        json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/oidc/authorize"),
        "token_endpoint":format!("{issuer}/oidc/token"),"userinfo_endpoint":format!("{issuer}/oidc/userinfo"),
        "jwks_uri":format!("{issuer}/oidc/jwks"),"revocation_endpoint":format!("{issuer}/oidc/revoke"),
        "introspection_endpoint":format!("{issuer}/oidc/introspect"),
        "response_types_supported":["code"],"response_modes_supported":["query"],
        "grant_types_supported":["authorization_code","refresh_token"],"subject_types_supported":["public"],
        "id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["client_secret_basic"],
        "revocation_endpoint_auth_methods_supported":["client_secret_basic"],"introspection_endpoint_auth_methods_supported":["client_secret_basic"],
        "scopes_supported":["openid","profile","offline_access"],"code_challenge_methods_supported":["S256"],
        "claims_supported":["iss","sub","aud","exp","iat","auth_time","nonce","sid","name","preferred_username","picture"],
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
