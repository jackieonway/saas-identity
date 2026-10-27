//! Account-only interaction authority for centralized member selection.
//! No platform membership, application, tenant or organization tables are read.

use super::{clients, invalid, store, tokens, OidcError, Result};
use crate::{error::AppError, extractors::ApiJson, state::AppState};
use axum::{
    extract::{RawQuery, State},
    http::{header, HeaderMap},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

const VERSION: &str = "context-selection/1";

pub(crate) mod bridge;
pub(crate) mod crypto;
mod selection;
pub(super) use selection::{
    attach_grant, choices, code_extension, prepare, restart, selection_deadline,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum Intent {
    Login {},
    Switch {
        #[serde(rename = "sessionId", deserialize_with = "canonical_id")]
        session_id: Uuid,
        #[serde(rename = "expectedVersion")]
        expected_version: String,
    },
}

impl Intent {
    fn valid(&self) -> bool {
        match self {
            Self::Login {} => true,
            Self::Switch {
                expected_version, ..
            } => expected_version
                .parse::<i64>()
                .is_ok_and(|v| v >= 1 && v.to_string() == *expected_version),
        }
    }
}

fn canonical_id<'de, D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Uuid, D::Error> {
    let raw = String::deserialize(de)?;
    clients::canonical_id(&raw).map_err(|_| serde::de::Error::custom("canonical UUIDv7 required"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Create {
    contract_version: String,
    #[serde(deserialize_with = "canonical_id")]
    transaction_id: Uuid,
    intent: Intent,
    redirect_uri: String,
    state_hash: String,
    nonce_hash: String,
    code_challenge: String,
}

impl Create {
    fn valid(&self, client: &clients::Client) -> bool {
        self.contract_version == VERSION
            && self.intent.valid()
            && client.redirect_uris.contains(&self.redirect_uri)
            && super::canonical_secret(&self.state_hash)
            && super::canonical_secret(&self.nonce_hash)
            && URL_SAFE_NO_PAD
                .decode(&self.code_challenge)
                .is_ok_and(|v| v.len() == 32 && URL_SAFE_NO_PAD.encode(v) == self.code_challenge)
    }
}

pub(super) async fn required<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    client: Uuid,
) -> std::result::Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oidc_context_clients WHERE client_id=$1 AND enabled)",
    )
    .bind(client)
    .fetch_one(executor)
    .await
    .map_err(|_| AppError::Unavailable)
}

pub(super) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<Create>,
) -> Result<Json<Value>> {
    super::authority(&state).await?;
    tokens::admission(&state, &headers)?;
    if query.is_some() || headers.contains_key(header::COOKIE) {
        return Err(invalid());
    }
    let initial = clients::authenticate(&state, &headers, &Default::default()).await?;
    if !body.valid(&initial) {
        return Err(invalid());
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let client = clients::load(&mut *tx, initial.id, true)
        .await?
        .ok_or_else(invalid)?;
    if client.status != "ENABLED"
        || client.access_policy_version != initial.access_policy_version
        || !matches!(
            client.purpose.as_str(),
            "PLATFORM_CONSOLE" | "CUSTOMER_PORTAL"
        )
        || !required(&mut *tx, client.id).await?
    {
        return Err(invalid());
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('oidc-context-capacity-v1',0))")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM oidc_context_interactions WHERE transaction_id IN (SELECT transaction_id FROM oidc_context_interactions WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 256)").execute(&mut *tx).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_context_interactions")
        .fetch_one(&mut *tx)
        .await?;
    if count >= state.config.login_max_entries as i64 {
        return Err(AppError::RateLimited(1).into());
    }
    let handle = super::secret()?;
    let intent = serde_json::to_string(&body.intent).map_err(|_| AppError::Unavailable)?;
    let expires:DateTime<Utc>=sqlx::query_scalar("INSERT INTO oidc_context_interactions(transaction_id,request_hash,client_id,client_policy_version,redirect_uri,state_hash,nonce_hash,code_challenge,intent,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,clock_timestamp(),clock_timestamp()+$10*interval '1 second') RETURNING expires_at")
        .bind(body.transaction_id).bind(super::digest(&handle)).bind(client.id).bind(client.access_policy_version)
        .bind(&body.redirect_uri).bind(&body.state_hash).bind(&body.nonce_hash).bind(&body.code_challenge).bind(intent)
        .bind(state.config.oidc_interaction_ttl_seconds as f64).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"contractVersion":VERSION,"contextRequest":handle,"expiresAt":expires}),
    ))
}

/// Called after the authorization flow insert and before any code is issued.
pub(super) async fn bind(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    flow: &store::Flow,
    handle: Option<&str>,
) -> Result<bool> {
    let needed = required(&mut **tx, flow.client_id).await?;
    if !needed {
        if handle.is_some() {
            return Err(invalid());
        }
        return Ok(false);
    }
    let handle = handle
        .filter(|v| super::canonical_secret(v))
        .ok_or_else(invalid)?;
    let count=sqlx::query("UPDATE oidc_context_interactions SET flow_id=$2,expires_at=LEAST(expires_at,$9) WHERE request_hash=$1 AND flow_id IS NULL AND client_id=$3 AND client_policy_version=$4 AND redirect_uri=$5 AND state_hash=$6 AND nonce_hash=$7 AND code_challenge=$8 AND expires_at>clock_timestamp()")
        .bind(super::digest(handle)).bind(flow.id).bind(flow.client_id).bind(flow.client_policy_version)
        .bind(&flow.redirect_uri).bind(super::digest(&flow.state)).bind(super::digest(&flow.nonce)).bind(&flow.code_challenge)
        .bind(flow.expires_at).execute(&mut **tx).await?.rows_affected();
    if count != 1 {
        return Err(invalid());
    }
    Ok(true)
}

fn source_handle(browser: &str, flow: Uuid) -> String {
    super::digest(&format!("context-selection-source-v1:{browser}:{flow}"))
}

/// Activate only after the caller has verified browser/CSRF and exact SSO source.
/// The returned handle is for a backend call; it must never reach browser JSON.
pub(super) async fn activate(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    flow: &store::Flow,
    browser: &str,
) -> std::result::Result<Option<String>, AppError> {
    if !required(&mut **tx, flow.client_id).await? {
        return Ok(None);
    }
    if flow.session_id.is_none() || flow.user_id.is_none() || flow.account_version.is_none() {
        return Err(AppError::unauthorized("选择交互尚未认证"));
    }
    let handle = source_handle(browser, flow.id);
    let count=sqlx::query("UPDATE oidc_context_interactions SET source_hash=COALESCE(source_hash,$2) WHERE flow_id=$1 AND (source_hash IS NULL OR source_hash=$2) AND expires_at>clock_timestamp()")
        .bind(flow.id).bind(super::digest(&handle)).execute(&mut **tx).await?.rows_affected();
    if count != 1 {
        return Err(AppError::conflict("选择交互不存在或已失效"));
    }
    Ok(Some(handle))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SourceRequest {
    contract_version: String,
    #[serde(default)]
    source_proof: Option<String>,
    #[serde(default)]
    transaction_id: Option<String>,
    #[serde(deserialize_with = "canonical_id")]
    expected_client_id: Uuid,
    #[serde(default)]
    oidc_access_token: Option<String>,
}

#[derive(sqlx::FromRow)]
struct Context {
    transaction_id: Uuid,
    client_id: Uuid,
    client_policy_version: i64,
    redirect_uri: String,
    intent: String,
    flow_id: Uuid,
    grant_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
}

fn source_error(error: OidcError) -> AppError {
    match error {
        OidcError::App(error) => error,
        _ => AppError::unauthorized("选择交互账号来源已失效"),
    }
}

pub(super) async fn source(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<SourceRequest>,
) -> std::result::Result<Json<Value>, AppError> {
    let issuer = super::authority(&state).await?;
    let principal =
        crate::internal::authenticate(&state, &headers, "CONTEXT_SELECTION_SOURCE").await?;
    let transaction = body
        .transaction_id
        .as_deref()
        .map(clients::canonical_id)
        .transpose()
        .map_err(|_| AppError::bad_request("选择事务标识无效"))?;
    let valid_mode = match (&body.source_proof, transaction, &body.oidc_access_token) {
        (Some(proof), None, None) => super::canonical_secret(proof),
        (None, Some(_), Some(access)) => super::canonical_secret(access),
        _ => false,
    };
    if query.is_some() || body.contract_version != VERSION || !valid_mode {
        return Err(AppError::bad_request("选择来源请求无效"));
    }
    let allowed:bool=sqlx::query_scalar("SELECT $2=ANY(allowed_oidc_clients) FROM identity_service_clients WHERE id=$1 AND status='ENABLED' AND purpose='CONTEXT_SELECTION_SOURCE'")
        .bind(principal.id).bind(body.expected_client_id).fetch_optional(&state.pool).await.map_err(|_|AppError::Unavailable)?.unwrap_or(false);
    if !allowed {
        return Err(AppError::forbidden("未登记此 RP 的来源核验用途"));
    }
    let context:Context=sqlx::query_as("SELECT transaction_id,client_id,client_policy_version,redirect_uri,intent::text,flow_id,grant_id,expires_at FROM oidc_context_interactions WHERE (source_hash=$1 OR transaction_id=$3) AND client_id=$2 AND source_hash IS NOT NULL AND expires_at>clock_timestamp()")
        .bind(body.source_proof.as_deref().map(super::digest)).bind(body.expected_client_id).bind(transaction).fetch_optional(&state.pool).await.map_err(|_|AppError::Unavailable)?
        .ok_or_else(||AppError::unauthorized("选择来源不存在或已失效"))?;
    let initial = store::flow(&state.pool, context.flow_id, false)
        .await?
        .ok_or_else(|| AppError::unauthorized("选择交互不存在"))?;
    let user = initial
        .user_id
        .ok_or_else(|| AppError::unauthorized("选择交互未认证"))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    // Read-only authority checks must not acquire the account write lock: the
    // platform caller can already hold it while committing its own context.
    let client = clients::load(&mut *tx, context.client_id, true)
        .await?
        .ok_or_else(|| AppError::unauthorized("RP 已失效"))?;
    let flow = store::flow(&mut *tx, context.flow_id, true)
        .await?
        .ok_or_else(|| AppError::unauthorized("选择交互已失效"))?;
    if client.status != "ENABLED"
        || client.access_policy_version != context.client_policy_version
        || flow.client_id != client.id
        || flow.client_policy_version != client.access_policy_version
        || flow.redirect_uri != context.redirect_uri
        || !required(&mut *tx, client.id).await?
    {
        return Err(AppError::unauthorized("选择交互 RP 策略已变化"));
    }
    let proof = store::session(
        &mut *tx,
        flow.session_id
            .ok_or_else(|| AppError::unauthorized("选择交互未认证"))?,
        user,
        flow.account_version
            .ok_or_else(|| AppError::unauthorized("选择交互未认证"))?,
    )
    .await
    .map_err(source_error)?;
    let eligible:bool=sqlx::query_scalar("SELECT (NOT $1 OR $2::timestamptz >= $3::timestamptz) AND ($4::bigint IS NULL OR $4=0 OR $2::timestamptz >= clock_timestamp()-$4*interval '1 second')")
        .bind(flow.force_login).bind(proof.authenticated_at).bind(flow.created_at).bind(flow.max_age)
        .fetch_one(&mut *tx).await.map_err(|_|AppError::Unavailable)?;
    if !eligible {
        return Err(AppError::unauthorized("选择交互要求重新认证"));
    }
    let source_expiry = if let Some(access) = &body.oidc_access_token {
        if !super::canonical_secret(access) {
            return Err(AppError::unauthorized("选择消费来源无效"));
        }
        let live = tokens::live(&mut *tx, &super::digest(access), false)
            .await
            .map_err(source_error)?
            .ok_or_else(|| AppError::unauthorized("选择消费来源失效"))?;
        if context.grant_id != Some(live.grant_id)
            || flow.consumed_at.is_none()
            || live.client_id != client.id
            || live.user_id != user
            || live.session_id != proof.id
            || live.account_version != proof.account_version
            || live.client_policy_version != client.access_policy_version
        {
            return Err(AppError::unauthorized("消费凭据不属于原选择交互"));
        }
        live.expires_at
    } else {
        if flow.consumed_at.is_some() {
            return Err(AppError::unauthorized("已结束交互必须证明原始 grant"));
        }
        proof.expires_at
    };
    let source_expiry = match flow.max_age {
        Some(age) if age > 0 => {
            source_expiry.min(proof.authenticated_at + chrono::Duration::seconds(age))
        }
        _ => source_expiry,
    };
    let expiry = source_expiry.min(context.expires_at).min(flow.expires_at);
    super::deadline(&mut tx, expiry)
        .await
        .map_err(source_error)?;
    let intent: Intent =
        serde_json::from_str(&context.intent).map_err(|_| AppError::Unavailable)?;
    let value = json!({"contractVersion":VERSION,"transactionId":context.transaction_id,"intent":intent,
        "source":{"issuer":issuer,"userId":user,"accountVersion":proof.account_version.to_string(),"globalSessionId":proof.id,"interactionId":flow.id,"authTime":proof.authenticated_at},
        "client":{"id":client.id,"policyVersion":client.access_policy_version.to_string(),"purpose":client.purpose,"allowedMemberTypes":client.allowed_member_types,"redirectUri":flow.redirect_uri},
        "sourceExpiresAt":source_expiry,"interactionExpiresAt":context.expires_at.min(flow.expires_at)});
    tx.commit().await.map_err(|_| AppError::Unavailable)?;
    Ok(Json(value))
}

#[cfg(test)]
mod consent_tests;
#[cfg(test)]
mod selection_tests;
#[cfg(test)]
mod tests;
