//! Consumer-defined private ports; service credentials never become human proof.

use crate::{error::AppError, extractors::ApiJson, state::AppState};
use axum::{
    extract::{FromRequestParts, RawQuery, Request, State},
    http::{header, request::Parts, HeaderMap, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

/// Incoming machine credential, deliberately without Debug or serialization.
pub(crate) struct ServicePrincipal {
    pub(crate) id: Uuid,
    purpose: String,
    secret: String,
}
impl ServicePrincipal {
    pub(crate) fn require(&self, purpose: &str) -> Result<(), AppError> {
        if self.purpose == purpose {
            Ok(())
        } else {
            Err(AppError::forbidden("服务用途不匹配"))
        }
    }
    pub(crate) fn secret(&self) -> &str {
        &self.secret
    }
}

fn basic(headers: &HeaderMap) -> Result<(Uuid, String), AppError> {
    let invalid = || AppError::forbidden("内部服务认证失败");
    if headers.contains_key(header::COOKIE) {
        return Err(invalid());
    }
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let raw = values
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or_else(invalid)?;
    if values.next().is_some() {
        return Err(invalid());
    }
    let encoded = raw
        .strip_prefix("Basic ")
        .filter(|v| v.len() <= 2048)
        .ok_or_else(invalid)?;
    let bytes = STANDARD.decode(encoded).map_err(|_| invalid())?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(invalid());
    }
    let plain = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    let (id, secret) = plain.split_once(':').ok_or_else(invalid)?;
    let parsed = Uuid::parse_str(id).map_err(|_| invalid())?;
    if !crate::util::uuid7::is_uuid_v7(parsed)
        || parsed.to_string() != id
        || !canonical_secret(secret)
    {
        return Err(invalid());
    }
    Ok((parsed, secret.to_owned()))
}
fn canonical_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn equal(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0, |diff, (x, y)| diff | (x ^ y))
            == 0
}

pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    purpose: &str,
) -> Result<ServicePrincipal, AppError> {
    let (id, secret) = basic(headers)?;
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT secret_hash,purpose,status FROM identity_service_clients WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| AppError::Unavailable)?;
    let (hash, registered, status) = row.ok_or_else(|| AppError::forbidden("内部服务认证失败"))?;
    if status != "ENABLED"
        || registered != purpose
        || !equal(&hash, &crate::util::hash::sha256_hex(&secret))
    {
        return Err(AppError::forbidden("内部服务认证失败"));
    }
    let reused: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oidc_clients WHERE secret_hash=$1)")
            .bind(&hash)
            .fetch_one(&state.pool)
            .await
            .map_err(|_| AppError::Unavailable)?;
    if reused {
        return Err(AppError::forbidden("内部服务认证失败"));
    }
    Ok(ServicePrincipal {
        id,
        purpose: registered,
        secret,
    })
}
impl FromRequestParts<AppState> for ServicePrincipal {
    type Rejection = AppError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        authenticate(state, &parts.headers, "OIDC_ADMIN").await
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/internal/identity/customer-access-proof",
            post(customer_access_proof),
        )
        .merge(crate::accounts::routes())
        .merge(crate::admin_operations::routes())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CustomerProofRequest {
    contract_version: String,
    oidc_access_token: String,
    expected_client_id: String,
}
async fn customer_access_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<CustomerProofRequest>,
) -> Result<Json<Value>, AppError> {
    authenticate(&state, &headers, "CUSTOMER_ACCESS_PROOF").await?;
    if query.is_some() || body.contract_version != "customer-access-proof-request/1" {
        return Err(AppError::bad_request("客户证明请求无效"));
    }
    let id = Uuid::parse_str(&body.expected_client_id)
        .map_err(|_| AppError::bad_request("客户证明请求无效"))?;
    if !crate::util::uuid7::is_uuid_v7(id) || id.to_string() != body.expected_client_id {
        return Err(AppError::bad_request("客户证明请求无效"));
    }
    Ok(Json(
        crate::oidc::customer_access_proof(&state, &body.oidc_access_token, id).await?,
    ))
}

/// One bounded deadline includes service authentication, database waits and all
/// response body work. No dependency failure falls back to cached authorization.
pub(crate) async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !request.uri().path().starts_with("/internal/") {
        return next.run(request).await;
    }
    let mut response = if request.headers().contains_key(header::COOKIE)
        || (request.uri().query().is_some()
            && !request
                .uri()
                .path()
                .starts_with("/internal/identity/accounts/operations/"))
    {
        AppError::bad_request("内部端口不接受Cookie或查询参数").into_response()
    } else {
        match state.internal_slots.clone().try_acquire_owned() {
            Ok(_permit) => {
                match tokio::time::timeout(std::time::Duration::from_secs(3), next.run(request))
                    .await
                {
                    Ok(response) => response,
                    Err(_) => AppError::Unavailable.into_response(),
                }
            }
            Err(_) => AppError::Unavailable.into_response(),
        }
    };
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_basic_is_canonical_and_separate_from_browser_auth() {
        let id = Uuid::now_v7();
        let secret = "a".repeat(64);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")))
                .parse()
                .unwrap(),
        );
        assert_eq!(basic(&headers).unwrap().0, id);
        headers.append(header::AUTHORIZATION, "Bearer anything".parse().unwrap());
        assert!(basic(&headers).is_err());
        headers.remove(header::AUTHORIZATION);
        headers.insert(header::AUTHORIZATION, "Bearer anything".parse().unwrap());
        assert!(basic(&headers).is_err());
    }
}
