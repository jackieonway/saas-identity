//! Durable authority administration results. Mutation callers retain this transaction
//! for provider writes and audit, so an unknown response is safely recoverable.

use axum::{
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{error::AppError, internal::ServicePrincipal, state::AppState};

const OPERATION_HEADER: &str = "x-identity-operation";
const DIGEST_HEADER: &str = "x-identity-operation-digest";
const KEY_PREFIX: &str = "/internal/identity/auth/keys/";
const AUTH_PREFIX: &str = "/internal/identity/auth/";
const AUTH_CLIENTS_PREFIX: &str = "/internal/identity/auth/clients";
const AUTH_INVITATIONS_PREFIX: &str = "/internal/identity/auth/invitations";
const AUTH_REVIEW_PREFIX: &str = "/internal/identity/auth/review/applications/";

/// Contains a service credential and deliberately implements neither Debug nor
/// serialization. Only `tx` and the operation's public identity reach callers.
pub(crate) struct AdminTransaction {
    pub(crate) tx: Transaction<'static, Postgres>,
    pub(crate) operation_id: Uuid,
    service_id: Uuid,
    request_digest: String,
    service_secret_hash: String,
    method: String,
    path: String,
    service_secret: String,
    existing: Option<StoredReceipt>,
}

#[derive(sqlx::FromRow)]
struct StoredReceipt {
    operation_id: Uuid,
    service_id: Uuid,
    request_digest: String,
    service_secret_hash: String,
    method: String,
    path: String,
    result_json: Value,
    returns_secret: bool,
}

/// Authenticate before calling. The service purpose is checked again here, and
/// the raw body is digested before any handler normalization or policy mutation.
pub(crate) async fn begin(
    state: &AppState,
    user: &ServicePrincipal,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &Value,
) -> Result<AdminTransaction, AppError> {
    user.require(service_purpose(path).ok_or_else(|| AppError::bad_request("内部操作路径无效"))?)?;
    validate_route(method, path, body)?;
    let operation_id = canonical_id(single_header(headers, OPERATION_HEADER)?)?;
    let supplied_digest = digest_header(headers)?;
    let request_digest = request_digest(method, path, body)?;
    if !equal(&request_digest, supplied_digest) {
        return Err(AppError::conflict("认证操作摘要不匹配"));
    }
    let mut tx = state.pool.begin().await?;
    let existing = locked_load(&mut tx, operation_id).await?;
    let operation = AdminTransaction {
        tx,
        operation_id,
        service_id: user.id,
        request_digest,
        service_secret_hash: crate::util::hash::sha256_hex(user.secret()),
        method: method.into(),
        path: path.into(),
        service_secret: user.secret().into(),
        existing,
    };
    // A completed operation is independent of its old accepted-intent deadline.
    // Check service identity/key and digest before returning any result content.
    if operation.replay()?.is_some() {
        return Ok(operation);
    }
    let mut operation = operation;
    operation.require_intent().await?;
    Ok(operation)
}

impl AdminTransaction {
    async fn require_intent(&mut self) -> Result<(), AppError> {
        let accepted: bool =
            sqlx::query_scalar("SELECT public.identity_auth_command_intent_active($1,$2,$3,$4,$5)")
                .bind(self.operation_id)
                .bind(self.service_id)
                .bind(&self.request_digest)
                .bind(&self.method)
                .bind(&self.path)
                .fetch_one(&mut *self.tx)
                .await?;
        if accepted {
            Ok(())
        } else {
            Err(AppError::conflict("认证操作未获接受或已失效"))
        }
    }

    pub(crate) fn replay(&self) -> Result<Option<Value>, AppError> {
        let Some(stored) = &self.existing else {
            return Ok(None);
        };
        if stored.method != self.method || stored.path != self.path {
            return Err(AppError::conflict("认证操作内容冲突"));
        }
        reconstruct(
            stored,
            self.service_id,
            &self.service_secret,
            &self.request_digest,
        )
        .map(Some)
    }

    pub(crate) fn auth_client_secret(&self) -> String {
        auth_client_secret(
            &self.service_secret,
            self.operation_id,
            &self.request_digest,
        )
    }

    pub(crate) async fn commit(mut self, result: Value) -> Result<Value, AppError> {
        if let Some(original) = self.replay()? {
            // A caller that missed replay must not commit a second mutation.
            self.tx.rollback().await?;
            return Ok(original);
        }
        let expected_secret = receipt_secret(
            &self.service_secret,
            self.operation_id,
            &self.request_digest,
            &self.method,
            &self.path,
        );
        let (safe, returns_secret) = safe_result(
            result,
            &self.method,
            &self.path,
            self.operation_id,
            &expected_secret,
        )?;
        self.require_intent().await?;
        let written = sqlx::query(
            "INSERT INTO public.identity_auth_command_receipts \
             (operation_id,service_id,request_digest,service_secret_hash,method,path,result_json,returns_secret,created_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp())",
        )
        .bind(self.operation_id)
        .bind(self.service_id)
        .bind(&self.request_digest)
        .bind(&self.service_secret_hash)
        .bind(&self.method)
        .bind(&self.path)
        .bind(&safe)
        .bind(returns_secret)
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if written != 1 {
            return Err(AppError::Unavailable);
        }
        // Provider mutations, audits and receipt insertion may wait. The
        // durable acceptance deadline is re-proved after all of those waits.
        self.require_intent().await?;
        self.tx.commit().await?;
        let mut result = safe;
        if returns_secret {
            result["clientSecret"] = json!(expected_secret);
        }
        Ok(result)
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/internal/identity/auth/key-operations/{id}",
            get(operation),
        )
        .route(
            "/internal/identity/auth/operations/{id}",
            get(projection_operation),
        )
        .route(
            "/internal/identity/auth/client-operations/{id}",
            get(auth_client_operation),
        )
        .route(
            "/internal/identity/auth/invitation-operations/{id}",
            get(invitation_operation),
        )
        .route(
            "/internal/identity/auth/review-operations/{id}",
            get(review_operation),
        )
}

async fn operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, AppError> {
    operation_for(state, headers, raw, query, "KEY_ADMIN").await
}

async fn projection_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, AppError> {
    operation_for(state, headers, raw, query, "APPLICATION_PROJECTION").await
}

async fn auth_client_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, AppError> {
    operation_for(state, headers, raw, query, "AUTH_ADMIN").await
}

async fn invitation_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, AppError> {
    operation_for(state, headers, raw, query, "AUTH_INVITATION").await
}

async fn review_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, AppError> {
    operation_for(state, headers, raw, query, "AUTH_REVIEW").await
}

async fn operation_for(
    state: AppState,
    headers: HeaderMap,
    raw: String,
    query: Option<String>,
    purpose: &'static str,
) -> Result<Json<Value>, AppError> {
    let user = crate::internal::authenticate(&state, &headers, purpose).await?;
    if query.is_some() {
        return Err(AppError::bad_request("认证操作查询不接受查询参数"));
    }
    let id = canonical_id(&raw)?;
    let digest = digest_header(&headers)?;
    if headers.contains_key(OPERATION_HEADER)
        && canonical_id(single_header(&headers, OPERATION_HEADER)?)? != id
    {
        return Err(AppError::conflict("认证操作编号冲突"));
    }
    let mut tx = state.pool.begin().await?;
    let stored = locked_load(&mut tx, id)
        .await?
        .ok_or_else(|| AppError::not_found("认证操作结果尚未确认"))?;
    let result = reconstruct(&stored, user.id, user.secret(), digest)?;
    tx.commit().await?;
    Ok(Json(result))
}

async fn locked_load(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
) -> Result<Option<StoredReceipt>, AppError> {
    // Both mutation and lookup take the same transaction-scoped operation lock.
    // A missing result is conclusive only after an earlier in-flight mutation
    // has committed or rolled back. The platform also checks the accepted
    // intent's database deadline before calling that outcome NOT_APPLIED.
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))")
        .bind(operation_id.to_string())
        .execute(&mut **tx)
        .await?;
    sqlx::query_as(
        "SELECT operation_id,service_id,request_digest,service_secret_hash,method,path,result_json,returns_secret \
         FROM public.identity_auth_command_receipts WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

fn reconstruct(
    stored: &StoredReceipt,
    service: Uuid,
    secret: &str,
    digest: &str,
) -> Result<Value, AppError> {
    if stored.service_id != service || !equal(&stored.request_digest, digest) {
        return Err(AppError::conflict("认证操作归属或摘要冲突"));
    }
    if !equal(
        &stored.service_secret_hash,
        &crate::util::hash::sha256_hex(secret),
    ) {
        return Err(AppError::conflict(
            "服务密钥已轮换，无法恢复原客户端密钥，请重新配置客户端",
        ));
    }
    let body_kind = if stored.method == "DELETE"
        || (stored.path.starts_with(KEY_PREFIX) && stored.path.ends_with("/revoke"))
    {
        Value::Null
    } else {
        json!({})
    };
    validate_route(&stored.method, &stored.path, &body_kind).map_err(|_| AppError::Unavailable)?;
    if stored.returns_secret != returns_secret(&stored.method, &stored.path)
        || !safe_object(&stored.result_json)
    {
        return Err(AppError::Unavailable);
    }
    let mut result = stored.result_json.clone();
    if stored.returns_secret {
        ensure_secret_identity(&result, stored.operation_id, &stored.method, &stored.path)?;
        result["clientSecret"] = json!(receipt_secret(
            secret,
            stored.operation_id,
            digest,
            &stored.method,
            &stored.path,
        ));
    }
    Ok(result)
}

fn safe_result(
    mut result: Value,
    method: &str,
    path: &str,
    operation: Uuid,
    expected_secret: &str,
) -> Result<(Value, bool), AppError> {
    let object = result.as_object_mut().ok_or(AppError::Unavailable)?;
    let secret = object.remove("clientSecret");
    let returns_secret = returns_secret(method, path);
    if let Some(application) = path
        .strip_prefix(AUTH_PREFIX)
        .and_then(|suffix| suffix.strip_prefix("applications/"))
    {
        let projection_id = canonical_id(application).map_err(|_| AppError::Unavailable)?;
        if secret.is_some()
            || returns_secret
            || !exact(&result, &["applicationId", "projectionVersion", "status"])
            || result["applicationId"].as_str() != Some(projection_id.to_string().as_str())
            || !result["projectionVersion"].as_i64().is_some_and(|v| v >= 1)
            || !result["status"].as_str().is_some_and(|status| {
                matches!(
                    status,
                    "DRAFT" | "PENDING_REVIEW" | "APPROVED" | "SUSPENDED" | "RETIRED"
                )
            })
        {
            return Err(AppError::Unavailable);
        }
        return Ok((result, false));
    }
    if returns_secret {
        let supplied = secret
            .and_then(|secret| secret.as_str().map(str::to_owned))
            .ok_or(AppError::Unavailable)?;
        if !equal(&supplied, expected_secret) {
            return Err(AppError::Unavailable);
        }
        ensure_secret_identity(&result, operation, method, path)?;
    } else if secret.is_some() {
        return Err(AppError::Unavailable);
    }
    if !safe_object(&result) {
        return Err(AppError::Unavailable);
    }
    Ok((result, returns_secret))
}

fn ensure_secret_identity(
    result: &Value,
    operation: Uuid,
    method: &str,
    path: &str,
) -> Result<(), AppError> {
    let Some(client_id) = path
        .strip_prefix(AUTH_CLIENTS_PREFIX)
        .and_then(|suffix| suffix.strip_suffix("/credentials"))
        .and_then(|suffix| suffix.strip_prefix('/'))
    else {
        return Err(AppError::Unavailable);
    };
    if !is_auth_credential_creation(method, path)
        || result.get("credentialId").and_then(Value::as_str)
            != Some(operation.to_string().as_str())
        || result.get("clientId").and_then(Value::as_str) != Some(client_id)
    {
        return Err(AppError::Unavailable);
    }
    Ok(())
}

fn safe_object(result: &Value) -> bool {
    fn no_secrets(value: &Value) -> bool {
        match value {
            Value::Object(object) => object.iter().all(|(key, value)| {
                !matches!(
                    key.to_ascii_lowercase().as_str(),
                    "clientsecret"
                        | "secret"
                        | "secrethash"
                        | "secret_hash"
                        | "password"
                        | "passwordhash"
                        | "password_hash"
                        | "privatekey"
                        | "private_key"
                        | "privatepem"
                        | "private_pem"
                ) && no_secrets(value)
            }),
            Value::Array(values) => values.iter().all(no_secrets),
            _ => true,
        }
    }
    result.is_object() && no_secrets(result)
}

fn auth_client_secret(secret: &str, operation: Uuid, digest: &str) -> String {
    let input = format!("saas-identity/auth-client-secret/1\n{operation}\n{digest}");
    hex::encode(crate::accounts::hmac_sha256(
        secret.as_bytes(),
        input.as_bytes(),
    ))
}

fn receipt_secret(
    secret: &str,
    operation: Uuid,
    digest: &str,
    _method: &str,
    _path: &str,
) -> String {
    auth_client_secret(secret, operation, digest)
}

fn request_digest(method: &str, path: &str, body: &Value) -> Result<String, AppError> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let ordered = object
                    .iter()
                    .map(|(key, value)| (key.clone(), sorted(value)))
                    .collect::<std::collections::BTreeMap<_, _>>();
                Value::Object(ordered.into_iter().collect())
            }
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            value => value.clone(),
        }
    }
    let canonical = serde_json::to_vec(&sorted(&json!({"method":method,"path":path,"body":body})))
        .map_err(|_| AppError::bad_request("认证操作内容无效"))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, AppError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::bad_request("缺少规范认证操作元数据"))?;
    if values.next().is_some() {
        return Err(AppError::bad_request("认证操作元数据重复"));
    }
    Ok(value)
}

fn digest_header(headers: &HeaderMap) -> Result<&str, AppError> {
    let digest = single_header(headers, DIGEST_HEADER)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::bad_request("认证操作摘要无效"));
    }
    Ok(digest)
}

fn canonical_id(raw: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(raw).map_err(|_| AppError::bad_request("认证操作编号无效"))?;
    if !crate::util::uuid7::is_uuid_v7(id) || id.to_string() != raw {
        return Err(AppError::bad_request("认证操作编号必须为规范UUIDv7"));
    }
    Ok(id)
}

fn is_auth_credential_creation(method: &str, path: &str) -> bool {
    method == "POST"
        && path.starts_with(AUTH_CLIENTS_PREFIX)
        && path.ends_with("/credentials")
        && path
            .strip_prefix(AUTH_CLIENTS_PREFIX)
            .and_then(|suffix| suffix.strip_suffix("/credentials"))
            .and_then(|suffix| suffix.strip_prefix('/'))
            .is_some_and(|raw| canonical_id(raw).is_ok())
}

fn returns_secret(method: &str, path: &str) -> bool {
    is_auth_credential_creation(method, path)
}

fn exact(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn service_purpose(path: &str) -> Option<&'static str> {
    if path.starts_with(KEY_PREFIX) {
        Some("KEY_ADMIN")
    } else if path.starts_with(AUTH_REVIEW_PREFIX) {
        Some("AUTH_REVIEW")
    } else if path == AUTH_INVITATIONS_PREFIX
        || path.starts_with(&format!("{AUTH_INVITATIONS_PREFIX}/"))
    {
        Some("AUTH_INVITATION")
    } else if path.starts_with(AUTH_CLIENTS_PREFIX) {
        Some("AUTH_ADMIN")
    } else if path.starts_with(AUTH_PREFIX) {
        let projection = path
            .strip_prefix(AUTH_PREFIX)
            .and_then(|suffix| suffix.strip_prefix("applications/"))
            .is_some_and(|suffix| canonical_id(suffix).is_ok());
        Some(if projection {
            "APPLICATION_PROJECTION"
        } else {
            "AUTH_ADMIN"
        })
    } else {
        None
    }
}

fn validate_route(method: &str, path: &str, body: &Value) -> Result<(), AppError> {
    if let Some(suffix) = path.strip_prefix(KEY_PREFIX) {
        let valid_kid = |kid: &str| {
            !kid.is_empty()
                && kid.len() <= 80
                && kid
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        };
        let valid = match (method, suffix) {
            ("POST", "publish" | "activate") => body.is_object(),
            ("DELETE", kid) => valid_kid(kid) && body.is_null(),
            ("POST", value) if value.ends_with("/revoke") => {
                value.strip_suffix("/revoke").is_some_and(valid_kid) && body.is_null()
            }
            _ => false,
        };
        return if valid {
            Ok(())
        } else {
            Err(AppError::bad_request("签名密钥管理操作无效"))
        };
    }
    if let Some(suffix) = path.strip_prefix(AUTH_PREFIX) {
        let valid = if let Some(review_path) = suffix.strip_prefix("review/applications/") {
            review_path
                .split_once('/')
                .is_some_and(|(application, environment)| {
                    canonical_id(application).is_ok()
                        && matches!(environment, "test" | "production")
                        && method == "PUT"
                        && body.is_object()
                })
        } else if method == "PUT"
            && suffix.starts_with("applications/")
            && canonical_id(&suffix[13..]).is_ok()
        {
            body.is_object()
        } else if matches!(suffix, "clients" | "consent-groups" | "invitations") {
            method == "POST" && body.is_object()
        } else if let Some(invitation_path) = suffix.strip_prefix("invitations/") {
            invitation_path
                .split_once('/')
                .is_some_and(|(raw_id, action)| {
                    canonical_id(raw_id).is_ok()
                        && action == "revoke"
                        && method == "POST"
                        && body.is_object()
                })
        } else if let Some(group_path) = suffix.strip_prefix("consent-groups/") {
            let (raw_id, action) = group_path
                .split_once('/')
                .map_or((group_path, ""), |(id, action)| (id, action));
            canonical_id(raw_id).is_ok()
                && body.is_object()
                && matches!((method, action), ("POST", "clients"))
        } else if let Some(client_path) = suffix.strip_prefix("clients/") {
            let (raw_id, action) = client_path
                .split_once('/')
                .map_or((client_path, ""), |(id, action)| (id, action));
            canonical_id(raw_id).is_ok()
                && body.is_object()
                && matches!(
                    (method, action),
                    ("PATCH", "") | ("POST", "credentials") | ("POST", "credentials/revoke")
                )
        } else {
            false
        };
        return if valid {
            Ok(())
        } else {
            Err(AppError::bad_request("统一认证管理操作无效"))
        };
    }
    Err(AppError::bad_request("统一认证管理操作路径无效"))
}

fn equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = AUTH_PREFIX;

    fn stored(secret: &str) -> StoredReceipt {
        let id = Uuid::parse_str("018f0aa3-635c-7a12-98de-56789abcdef0").unwrap();
        StoredReceipt {
            operation_id: id,
            service_id: Uuid::now_v7(),
            request_digest: "a".repeat(64),
            service_secret_hash: crate::util::hash::sha256_hex(secret),
            method: "POST".into(),
            path: format!("{PREFIX}clients/{id}/credentials"),
            result_json: json!({"credentialId":id,"clientId":id,"status":"ENABLED"}),
            returns_secret: true,
        }
    }

    #[test]
    fn mutation_headers_are_single_canonical_and_complete() {
        let mut headers = HeaderMap::new();
        assert!(digest_header(&headers).is_err());
        headers.insert(DIGEST_HEADER, "a".repeat(64).parse().unwrap());
        assert!(digest_header(&headers).is_ok());
        headers.append(DIGEST_HEADER, "a".repeat(64).parse().unwrap());
        assert!(digest_header(&headers).is_err());
        headers.remove(DIGEST_HEADER);
        headers.insert(DIGEST_HEADER, "A".repeat(64).parse().unwrap());
        assert!(digest_header(&headers).is_err());
        for raw in [
            "00000000-0000-0000-0000-000000000000",
            "018F0AA3-635C-7A12-98DE-56789ABCDEF0",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        ] {
            assert!(canonical_id(raw).is_err());
        }
    }

    #[test]
    fn digest_binds_full_method_path_body_and_keeps_array_order() {
        let path = format!("{PREFIX}clients");
        let left = json!({"z":{"b":2,"a":1},"a":["EMPLOYEE","CUSTOMER"]});
        let right: Value =
            serde_json::from_str(r#"{"a":["EMPLOYEE","CUSTOMER"],"z":{"a":1,"b":2}}"#).unwrap();
        let digest = request_digest("POST", &path, &left).unwrap();
        assert_eq!(digest, request_digest("POST", &path, &right).unwrap());
        assert_ne!(digest, request_digest("PATCH", &path, &left).unwrap());
        assert_ne!(
            digest,
            request_digest("POST", &format!("{PREFIX}keys/publish"), &left).unwrap()
        );
        assert_ne!(
            digest,
            request_digest(
                "POST",
                &path,
                &json!({"z":{"b":2,"a":1},"a":["CUSTOMER","EMPLOYEE"]})
            )
            .unwrap()
        );
        assert_ne!(
            request_digest("DELETE", &format!("{PREFIX}keys/a"), &Value::Null).unwrap(),
            request_digest("DELETE", &format!("{PREFIX}keys/a"), &json!({})).unwrap()
        );
    }

    #[test]
    fn routes_are_fixed_and_forbid_query_encoding_or_unrelated_commands() {
        assert!(validate_route("POST", &format!("{PREFIX}clients"), &json!({})).is_ok());
        assert!(validate_route("DELETE", &format!("{PREFIX}keys/key-1"), &Value::Null).is_ok());
        assert!(
            validate_route("POST", &format!("{PREFIX}keys/key-1/revoke"), &Value::Null).is_ok()
        );
        for (method, path, body) in [
            ("post", format!("{PREFIX}clients"), json!({})),
            ("POST", "/internal/identity/oidc/clients".into(), json!({})),
            (
                "POST",
                "/internal/identity/oidc/keys/publish".into(),
                json!({"kid":"key"}),
            ),
            ("POST", format!("{PREFIX}clients?x=1"), json!({})),
            ("DELETE", format!("{PREFIX}keys/a%2Fb"), Value::Null),
            ("DELETE", format!("{PREFIX}keys/a"), json!({})),
            (
                "POST",
                "/internal/identity/accounts/commands".into(),
                json!({}),
            ),
            ("POST", format!("{PREFIX}keys/revoke"), Value::Null),
            ("POST", format!("{PREFIX}keys//revoke"), Value::Null),
        ] {
            assert!(validate_route(method, &path, &body).is_err());
        }
    }

    #[test]
    fn derived_creation_secret_is_stable_and_bound_to_service_operation_digest() {
        let row = stored("service-key-one");
        let original = auth_client_secret("service-key-one", row.operation_id, &row.request_digest);
        assert_eq!(original.len(), 64);
        assert_eq!(
            original,
            auth_client_secret("service-key-one", row.operation_id, &row.request_digest)
        );
        assert_ne!(
            original,
            auth_client_secret("service-key-two", row.operation_id, &row.request_digest)
        );
        assert_ne!(
            original,
            auth_client_secret("service-key-one", Uuid::now_v7(), &row.request_digest)
        );
        assert_ne!(
            original,
            auth_client_secret("service-key-one", row.operation_id, &"b".repeat(64))
        );
    }

    #[test]
    fn safe_receipt_strips_only_derived_creation_secret_and_never_persists_credentials() {
        let row = stored("service-key-one");
        let derived = auth_client_secret("service-key-one", row.operation_id, &row.request_digest);
        let mut result = row.result_json.clone();
        result["clientSecret"] = json!(derived);
        let (safe, returns) =
            safe_result(result, &row.method, &row.path, row.operation_id, &derived).unwrap();
        assert!(returns);
        assert!(safe.get("clientSecret").is_none());
        assert_eq!(safe, row.result_json);
        let mut wrong = row.result_json.clone();
        wrong["clientSecret"] = json!("unrelated-secret");
        assert!(safe_result(wrong, &row.method, &row.path, row.operation_id, &derived).is_err());
        assert!(!safe_object(&json!({"safe":{"secret_hash":"never-store"}})));
        assert!(!safe_object(&json!({"clientSecret":"never-store"})));
        assert!(safe_result(
            json!({"kid":"key","status":"ACTIVE"}),
            "POST",
            &format!("{PREFIX}keys/activate"),
            row.operation_id,
            &derived
        )
        .is_ok());
    }

    #[test]
    fn replay_requires_same_service_digest_and_unrotated_service_secret() {
        let row = stored("service-key-one");
        let replay =
            reconstruct(&row, row.service_id, "service-key-one", &row.request_digest).unwrap();
        assert_eq!(
            replay["clientSecret"],
            auth_client_secret("service-key-one", row.operation_id, &row.request_digest)
        );
        assert!(matches!(
            reconstruct(&row, Uuid::now_v7(), "service-key-one", &row.request_digest),
            Err(AppError::Conflict(_))
        ));
        assert!(matches!(
            reconstruct(&row, row.service_id, "service-key-one", &"b".repeat(64)),
            Err(AppError::Conflict(_))
        ));
        assert!(matches!(
            reconstruct(&row, row.service_id, "service-key-two", &row.request_digest),
            Err(AppError::Conflict(_))
        ));
    }
}
