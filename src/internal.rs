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
    let reused: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_client_credentials WHERE secret_digest=$1)",
    )
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
        authenticate(state, &parts.headers, "KEY_ADMIN").await
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/internal/identity/customer-access-proof",
            post(customer_access_proof),
        )
        .route(
            "/internal/identity/auth/account-proof",
            post(platform_account_proof),
        )
        .route(
            "/internal/identity/auth/customer-account-proof",
            post(customer_account_proof),
        )
        .route(
            "/internal/identity/auth/resource-access-proof",
            post(resource_access_proof),
        )
        .merge(crate::accounts::routes())
        .merge(crate::admin_operations::routes())
        .merge(crate::auth_admin::routes())
        .merge(crate::auth_invitations::routes())
        .merge(crate::auth_projection::routes())
        .merge(crate::auth_review::routes())
        .merge(crate::sso::mfa_recovery::routes())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CustomerProofRequest {
    contract_version: String,
    oidc_access_token: String,
    expected_client_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceProofRequest {
    contract_version: String,
    token: String,
    resource: String,
    scope: String,
    audience: String,
}

async fn resource_service_allowed(
    state: &AppState,
    service: &ServicePrincipal,
    body: &ResourceProofRequest,
) -> Result<(), AppError> {
    let allowed: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.identity_service_clients service JOIN public.auth_resources resource ON resource.id=ANY(service.allowed_auth_resources) JOIN public.auth_scopes scope ON scope.resource_id=resource.id WHERE service.id=$1 AND service.purpose='RESOURCE_ACCESS_PROOF' AND service.status='ENABLED' AND service.secret_hash=$2 AND resource.status='ACTIVE' AND resource.resource_key=$3 AND resource.audience=$4 AND scope.status='ACTIVE' AND scope.scope_name=$5)")
        .bind(service.id).bind(crate::util::hash::sha256_hex(service.secret())).bind(&body.resource).bind(&body.audience).bind(&body.scope).fetch_one(&state.pool).await?;
    if !allowed {
        return Err(AppError::forbidden(
            "资源证明服务未获准此资源、受众或 scope",
        ));
    }
    Ok(())
}

async fn resource_access_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<ResourceProofRequest>,
) -> Result<Json<Value>, AppError> {
    let service = authenticate(&state, &headers, "RESOURCE_ACCESS_PROOF").await?;
    let identifier = |value: &str, max: usize, colon: bool| {
        value.len() <= max
            && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && value.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'_' | b'-')
                    || (colon && b == b':')
            })
    };
    if query.is_some()
        || body.contract_version != "resource-access-proof-request/1"
        || !canonical_secret(&body.token)
        || !identifier(&body.resource, 64, false)
        || !identifier(&body.scope, 128, true)
        || body.audience.is_empty()
        || body.audience.len() > 500
        || body.audience.trim() != body.audience
        || body.audience.chars().any(char::is_control)
    {
        return Err(AppError::bad_request("资源访问证明请求无效"));
    }
    resource_service_allowed(&state, &service, &body).await?;
    let proof = crate::oidc::resource_access_proof(
        &state,
        &body.token,
        &body.resource,
        &body.audience,
        &body.scope,
    )
    .await?;
    resource_service_allowed(&state, &service, &body).await?;
    Ok(Json(proof))
}
async fn customer_access_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<CustomerProofRequest>,
) -> Result<Json<Value>, AppError> {
    let service = authenticate(&state, &headers, "CUSTOMER_ACCESS_PROOF").await?;
    if query.is_some()
        || body.contract_version != "customer-access-proof-request/1"
        || !canonical_secret(&body.oidc_access_token)
    {
        return Err(AppError::bad_request("客户证明请求无效"));
    }
    let id = Uuid::parse_str(&body.expected_client_id)
        .map_err(|_| AppError::bad_request("客户证明请求无效"))?;
    if !crate::util::uuid7::is_uuid_v7(id) || id.to_string() != body.expected_client_id {
        return Err(AppError::bad_request("客户证明请求无效"));
    }
    customer_client_allowed(&state, service.id, id, "CUSTOMER_ACCESS_PROOF").await?;
    Ok(Json(
        crate::oidc::customer_access_proof(&state, &body.oidc_access_token, id).await?,
    ))
}

async fn customer_client_allowed(
    state: &AppState,
    service: Uuid,
    client: Uuid,
    purpose: &str,
) -> Result<(), AppError> {
    let allowed: bool = sqlx::query_scalar("SELECT $2=ANY(allowed_auth_clients) FROM identity_service_clients WHERE id=$1 AND status='ENABLED' AND purpose=$3")
        .bind(service).bind(client).bind(purpose).fetch_optional(&state.pool).await?.unwrap_or(false);
    if !allowed {
        return Err(AppError::forbidden("服务未登记此客户认证客户端"));
    }
    Ok(())
}

async fn customer_account_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<CustomerProofRequest>,
) -> Result<Json<Value>, AppError> {
    let service = authenticate(&state, &headers, "CONTEXT_SELECTION_SOURCE").await?;
    if query.is_some()
        || body.contract_version != "customer-account-proof-request/1"
        || !canonical_secret(&body.oidc_access_token)
    {
        return Err(AppError::bad_request("客户账号证明请求无效"));
    }
    let client = Uuid::parse_str(&body.expected_client_id)
        .map_err(|_| AppError::bad_request("客户账号证明请求无效"))?;
    if !crate::util::uuid7::is_uuid_v7(client) || client.to_string() != body.expected_client_id {
        return Err(AppError::bad_request("客户账号证明请求无效"));
    }
    customer_client_allowed(&state, service.id, client, "CONTEXT_SELECTION_SOURCE").await?;
    Ok(Json(
        crate::oidc::customer_account_proof(&state, &body.oidc_access_token, client).await?,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlatformAccountProofRequest {
    contract_version: String,
    oidc_access_token: String,
    expected_client_id: String,
}

async fn platform_account_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<PlatformAccountProofRequest>,
) -> Result<Json<Value>, AppError> {
    let service = authenticate(&state, &headers, "CONTEXT_SELECTION_SOURCE").await?;
    if query.is_some()
        || body.contract_version != "platform-account-proof-request/1"
        || !canonical_secret(&body.oidc_access_token)
    {
        return Err(AppError::bad_request("平台账号证明请求无效"));
    }
    let client = Uuid::parse_str(&body.expected_client_id)
        .map_err(|_| AppError::bad_request("平台账号证明请求无效"))?;
    if !crate::util::uuid7::is_uuid_v7(client) || client.to_string() != body.expected_client_id {
        return Err(AppError::bad_request("平台账号证明请求无效"));
    }
    let allowed: bool = sqlx::query_scalar(
        "SELECT $2=ANY(allowed_auth_clients) FROM identity_service_clients \
         WHERE id=$1 AND status='ENABLED' AND purpose='CONTEXT_SELECTION_SOURCE'",
    )
    .bind(service.id)
    .bind(client)
    .fetch_optional(&state.pool)
    .await?
    .unwrap_or(false);
    if !allowed {
        return Err(AppError::forbidden("服务未登记此认证客户端"));
    }
    Ok(Json(
        crate::oidc::platform_account_proof(&state, &body.oidc_access_token, client).await?,
    ))
}

/// One bounded deadline includes service authentication, database waits and all
/// response body work. No dependency failure falls back to cached authorization.
pub(crate) async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !request.uri().path().starts_with("/internal/") {
        return next.run(request).await;
    }
    let client_list_query = request.method() == axum::http::Method::GET
        && request.uri().path() == "/internal/identity/auth/clients";
    let mut response = if request.headers().contains_key(header::COOKIE)
        || (request.uri().query().is_some()
            && !client_list_query
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
