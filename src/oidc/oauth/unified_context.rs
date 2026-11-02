//! PLATFORM_CONTEXT transactions for the canonical auth_* authorization flow.
//! It binds the current canonical client, account source and one-time selection.

use super::{Client, Flow};
use crate::{
    auth_consent::{self, ConsentState},
    error::AppError,
    extractors::ApiJson,
    oidc::context::bridge,
    sso::{self, AccountSessionProof},
    state::AppState,
};
use axum::{
    extract::{RawQuery, State},
    http::{header, HeaderMap},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Executor, Postgres, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

const VERSION: &str = "context-selection/1";

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(
    tag = "kind",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Intent {
    Login {},
    Switch {
        #[serde(deserialize_with = "canonical_id")]
        session_id: Uuid,
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
                .is_ok_and(|version| version >= 1 && version.to_string() == *expected_version),
        }
    }
}

fn canonical_id<'de, D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Uuid, D::Error> {
    let raw = String::deserialize(de)?;
    let id = Uuid::parse_str(&raw).map_err(|_| serde::de::Error::custom("UUIDv7 required"))?;
    if crate::util::uuid7::is_uuid_v7(id) && id.to_string() == raw {
        Ok(id)
    } else {
        Err(serde::de::Error::custom("canonical UUIDv7 required"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Create {
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
    fn valid(&self, client: &Client) -> bool {
        self.contract_version == VERSION
            && self.intent.valid()
            && client
                .redirect_uris
                .iter()
                .any(|uri| uri == &self.redirect_uri)
            && crate::oidc::canonical_secret(&self.state_hash)
            && crate::oidc::canonical_secret(&self.nonce_hash)
            && URL_SAFE_NO_PAD
                .decode(&self.code_challenge)
                .is_ok_and(|decoded| {
                    decoded.len() == 32 && URL_SAFE_NO_PAD.encode(decoded) == self.code_challenge
                })
    }
}

#[derive(sqlx::FromRow)]
struct ContextRow {
    transaction_id: Uuid,
    client_id: Uuid,
    client_policy_version: i64,
    application_id: Uuid,
    application_projection_version: i64,
    redirect_uri: String,
    state_digest: String,
    nonce_digest: String,
    code_challenge: String,
    intent: String,
    authorization_request_id: Option<Uuid>,
    source_digest: Option<String>,
    selected_membership_id: Option<Uuid>,
    credential_ciphertext: Option<String>,
    selection_expires_at: Option<DateTime<Utc>>,
    grant_id: Option<Uuid>,
    delivered_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
}

async fn context_row<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    flow_id: Uuid,
    lock: bool,
) -> Result<ContextRow, AppError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    sqlx::query_as(&format!(
        "SELECT transaction_id,client_id,client_policy_version,application_id, \
         application_projection_version,redirect_uri,state_digest,nonce_digest,code_challenge, \
         intent::text,authorization_request_id,source_digest,selected_membership_id, \
         credential_ciphertext,selection_expires_at,grant_id,delivered_at,expires_at \
         FROM public.auth_context_interactions WHERE authorization_request_id=$1{suffix}"
    ))
    .bind(flow_id)
    .fetch_optional(executor)
    .await
    .map_err(|_| AppError::Unavailable)?
    .ok_or_else(|| AppError::conflict("此授权请求缺少已登记的业务上下文事务"))
}

async fn transaction_row<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    transaction_id: Uuid,
    lock: bool,
) -> Result<ContextRow, AppError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    sqlx::query_as(&format!(
        "SELECT transaction_id,client_id,client_policy_version,application_id, \
         application_projection_version,redirect_uri,state_digest,nonce_digest,code_challenge, \
         intent::text,authorization_request_id,source_digest,selected_membership_id, \
         credential_ciphertext,selection_expires_at,grant_id,delivered_at,expires_at \
         FROM public.auth_context_interactions WHERE transaction_id=$1{suffix}"
    ))
    .bind(transaction_id)
    .fetch_optional(executor)
    .await
    .map_err(|_| AppError::Unavailable)?
    .ok_or_else(|| AppError::conflict("业务上下文事务不存在"))
}

pub(super) async fn required<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    client_id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.auth_clients \
         WHERE id=$1 AND subject_mode='USER' AND context_mode='PLATFORM_CONTEXT')",
    )
    .bind(client_id)
    .fetch_one(executor)
    .await
    .map_err(|_| AppError::Unavailable)
}

fn source_handle(browser: &str, flow_id: Uuid) -> String {
    crate::oidc::digest(&format!(
        "auth-context-selection-source-v1:{browser}:{flow_id}"
    ))
}

pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<Create>,
) -> crate::oidc::Result<Json<Value>> {
    crate::oidc::authority(&state).await?;
    if query.is_some() || headers.contains_key(header::COOKIE) {
        return Err(crate::oidc::invalid());
    }
    let client = super::confidential_client(&state, &headers, &BTreeMap::new()).await?;
    if client.subject_mode != "USER"
        || client.context_mode.as_deref() != Some("PLATFORM_CONTEXT")
        || client.runtime_kind != "WEB_BFF"
        || !client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
        || client.allowed_member_types.len() != 1
        || !body.valid(&client)
    {
        return Err(AppError::forbidden("此客户端未登记平台业务上下文用途").into());
    }
    let _permit = state
        .context_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Unavailable)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    current_client(&mut tx, &client).await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('auth-context-selection-capacity-v1',0))",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM public.auth_context_interactions WHERE transaction_id IN ( \
         SELECT interaction.transaction_id FROM public.auth_context_interactions interaction \
         WHERE interaction.expires_at<=clock_timestamp() AND interaction.grant_id IS NULL \
         ORDER BY interaction.expires_at LIMIT 256)",
    )
    .execute(&mut *tx)
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.auth_context_interactions WHERE \
         expires_at>clock_timestamp() OR grant_id IS NOT NULL",
    )
    .fetch_one(&mut *tx)
    .await?;
    if count >= state.config.login_max_entries as i64 {
        return Err(AppError::RateLimited(1).into());
    }
    let request = sso::opaque_secret()?;
    let intent = serde_json::to_value(&body.intent).map_err(|_| AppError::Unavailable)?;
    let expires: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO public.auth_context_interactions( \
           transaction_id,request_hash,client_id,client_policy_version,application_id, \
           application_projection_version,redirect_uri,state_digest,nonce_digest,code_challenge, \
           intent,created_at,expires_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp(), \
           clock_timestamp()+LEAST($12,300)*interval '1 second') RETURNING expires_at",
    )
    .bind(body.transaction_id)
    .bind(crate::oidc::digest(&request))
    .bind(client.id)
    .bind(client.policy_version)
    .bind(client.application_id)
    .bind(client.application_projection_version)
    .bind(&body.redirect_uri)
    .bind(&body.state_hash)
    .bind(&body.nonce_hash)
    .bind(&body.code_challenge)
    .bind(intent)
    .bind(state.config.oidc_interaction_ttl_seconds)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"contractVersion":VERSION,"contextRequest":request,"expiresAt":expires}),
    ))
}

#[derive(sqlx::FromRow)]
struct CurrentClient {
    status: String,
    policy_version: i64,
    subject_mode: String,
    context_mode: Option<String>,
    application_status: String,
    projection_version: i64,
    allowed_member_types: Vec<String>,
}

async fn current_client(
    tx: &mut Transaction<'_, Postgres>,
    client: &Client,
) -> Result<(), AppError> {
    let current: Option<CurrentClient> =
        sqlx::query_as(
            "SELECT registration.status,registration.policy_version,registration.subject_mode, \
             registration.context_mode,application.status AS application_status,application.projection_version, \
             registration.allowed_member_types \
             FROM public.auth_clients registration \
             JOIN public.auth_applications application ON application.application_id=registration.application_id \
             WHERE registration.id=$1 AND registration.application_id=$2 FOR SHARE OF registration,application",
        )
        .bind(client.id)
        .bind(client.application_id)
        .fetch_optional(&mut **tx)
        .await?;
    if !current.is_some_and(|current| {
        current.status == "ENABLED"
            && current.policy_version == client.policy_version
            && current.subject_mode == "USER"
            && current.context_mode.as_deref() == Some("PLATFORM_CONTEXT")
            && current.application_status == "APPROVED"
            && current.projection_version == client.application_projection_version
            && current.allowed_member_types == client.allowed_member_types
    }) {
        return Err(AppError::conflict("客户端或应用策略已变化"));
    }
    Ok(())
}

// Each field is an independent protocol fence; keep the complete binding
// explicit at the single authorization-request boundary.
#[allow(clippy::too_many_arguments)]
pub(super) async fn bind(
    tx: &mut Transaction<'_, Postgres>,
    client: &Client,
    flow_id: Uuid,
    flow_expires_at: DateTime<Utc>,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    challenge: &str,
    handle: Option<&str>,
) -> crate::oidc::Result<()> {
    let context_required = required(&mut **tx, client.id).await?;
    if !context_required {
        if handle.is_some() {
            return Err(crate::oidc::invalid());
        }
        return Ok(());
    }
    let handle = handle
        .filter(|value| crate::oidc::canonical_secret(value))
        .ok_or_else(crate::oidc::invalid)?;
    let changed = sqlx::query(
        "UPDATE public.auth_context_interactions SET authorization_request_id=$2, \
         expires_at=LEAST(expires_at,$3) \
         WHERE request_hash=$1 AND authorization_request_id IS NULL AND source_digest IS NULL \
           AND client_id=$4 AND client_policy_version=$5 AND application_id=$6 \
           AND application_projection_version=$7 AND redirect_uri=$8 AND state_digest=$9 \
           AND nonce_digest=$10 AND code_challenge=$11 AND expires_at>clock_timestamp()",
    )
    .bind(crate::oidc::digest(handle))
    .bind(flow_id)
    .bind(flow_expires_at)
    .bind(client.id)
    .bind(client.policy_version)
    .bind(client.application_id)
    .bind(client.application_projection_version)
    .bind(redirect_uri)
    .bind(crate::oidc::digest(state))
    .bind(crate::oidc::digest(nonce))
    .bind(challenge)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(crate::oidc::invalid());
    }
    Ok(())
}

pub(super) async fn activate(
    tx: &mut Transaction<'_, Postgres>,
    flow: &Flow,
    browser: &str,
) -> Result<Option<String>, AppError> {
    if !required(&mut **tx, flow.client_id).await? {
        return Ok(None);
    }
    if flow.source_session_id.is_none()
        || flow.user_id.is_none()
        || flow.account_version.is_none()
        || flow.auth_time.is_none()
    {
        return Err(AppError::unauthorized("业务上下文选择必须绑定已认证账号"));
    }
    let handle = source_handle(browser, flow.id);
    let changed = sqlx::query(
        "UPDATE public.auth_context_interactions SET source_digest=COALESCE(source_digest,$2) \
         WHERE authorization_request_id=$1 AND (source_digest IS NULL OR source_digest=$2) \
           AND expires_at>clock_timestamp() AND selected_membership_id IS NULL",
    )
    .bind(flow.id)
    .bind(crate::oidc::digest(&handle))
    .execute(&mut **tx)
    .await
    .map_err(|_| AppError::Unavailable)?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::conflict("业务上下文交互已失效"));
    }
    Ok(Some(handle))
}

fn same_flow_snapshot(original: &Flow, current: &Flow) -> bool {
    original.id == current.id
        && original.client_id == current.client_id
        && original.user_id == current.user_id
        && original.source_session_id == current.source_session_id
        && original.account_version == current.account_version
        && original.auth_time == current.auth_time
        && original.client_policy_version == current.client_policy_version
        && original.application_projection_version == current.application_projection_version
        && original.redirect_uri == current.redirect_uri
        && original.state_digest == current.state_digest
        && original.state_value == current.state_value
        && original.nonce_digest == current.nonce_digest
        && original.nonce_value == current.nonce_value
        && original.code_challenge == current.code_challenge
        && original.scope_ids == current.scope_ids
        && original.browser_digest == current.browser_digest
        && original.csrf_digest == current.csrf_digest
        && original.force_login == current.force_login
        && original.force_consent == current.force_consent
        && original.max_age_seconds == current.max_age_seconds
        && original.prior_session_id == current.prior_session_id
        && original.created_at == current.created_at
        && original.expires_at == current.expires_at
}

fn same_flow(original: &Flow, current: &Flow) -> bool {
    same_flow_snapshot(original, current)
        && current.status == "PENDING"
        && current.consumed_at.is_none()
}

async fn live_proof(
    tx: &mut Transaction<'_, Postgres>,
    flow: &Flow,
) -> Result<AccountSessionProof, AppError> {
    let user_id = flow
        .user_id
        .ok_or_else(|| AppError::unauthorized("原账号来源已失效"))?;
    let source_session_id = flow
        .source_session_id
        .ok_or_else(|| AppError::unauthorized("原账号来源已失效"))?;
    let account_version = flow
        .account_version
        .ok_or_else(|| AppError::unauthorized("原账号来源已失效"))?;
    let account: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.users WHERE id=$1 AND status='ENABLED' \
         AND session_version=$2 FOR SHARE",
    )
    .bind(user_id)
    .bind(account_version)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| AppError::Unavailable)?;
    let session: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.sso_sessions WHERE id=$1 AND user_id=$2 \
         AND account_version=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE",
    )
    .bind(source_session_id)
    .bind(user_id)
    .bind(account_version)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| AppError::Unavailable)?;
    if account != Some(user_id) || session != Some(source_session_id) {
        return Err(AppError::unauthorized("原账号来源已失效"));
    }
    let proof = crate::oidc::store::session(&mut **tx, source_session_id, user_id, account_version)
        .await
        .map_err(|_| AppError::unauthorized("原账号来源已失效"))?;
    if Some(proof.authenticated_at) != flow.auth_time
        || !super::flow_proof_acceptable(flow, &proof)
        || proof.expires_at <= Utc::now()
    {
        return Err(AppError::unauthorized("原账号认证或业务上下文来源已失效"));
    }
    Ok(proof)
}

pub(super) async fn choices(
    state: &AppState,
    flow: &Flow,
    browser: &str,
) -> Result<Option<bridge::Choices>, AppError> {
    if !required(&state.pool, flow.client_id).await? {
        return Ok(None);
    }
    let _permit = state
        .context_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Unavailable)?;
    super::check_browser(flow, browser).map_err(|_| AppError::forbidden("浏览器交互无效"))?;
    let current = super::get_flow(state, flow.id)
        .await
        .map_err(source_error)?;
    if !same_flow(flow, &current) {
        return Err(AppError::conflict("原始授权交互已变化"));
    }
    let client = super::client_by_internal_id(state, flow.client_id)
        .await
        .map_err(source_error)?;
    if client.status != "ENABLED"
        || client.application_status != "APPROVED"
        || client.policy_version != flow.client_policy_version
        || client.application_projection_version != flow.application_projection_version
        || client.subject_mode != "USER"
        || client.context_mode.as_deref() != Some("PLATFORM_CONTEXT")
        || client.allowed_member_types.len() != 1
    {
        return Err(AppError::conflict("客户端业务上下文策略已变化"));
    }
    let context = context_row(&state.pool, flow.id, false).await?;
    let proof = crate::oidc::store::session(
        &state.pool,
        flow.source_session_id.ok_or(AppError::Unavailable)?,
        flow.user_id.ok_or(AppError::Unavailable)?,
        flow.account_version.ok_or(AppError::Unavailable)?,
    )
    .await
    .map_err(|_| AppError::unauthorized("原账号来源已失效"))?;
    if Some(proof.authenticated_at) != flow.auth_time || !super::flow_proof_acceptable(flow, &proof)
    {
        return Err(AppError::unauthorized("原账号认证已变化"));
    }
    let intent: Value = serde_json::from_str(&context.intent).map_err(|_| AppError::Unavailable)?;
    let result = state
        .context_platform
        .choices(&source_handle(browser, flow.id), flow.client_id)
        .await?;
    result.validate(
        flow.user_id.ok_or(AppError::Unavailable)?,
        &client.allowed_member_types[0],
    )?;
    if context.transaction_id != result.transaction_id || result.intent != intent {
        return Err(AppError::Unavailable);
    }
    let fresh = super::get_flow(state, flow.id)
        .await
        .map_err(source_error)?;
    if !same_flow(flow, &fresh) {
        return Err(AppError::conflict("平台查询期间原授权来源已变化"));
    }
    Ok(Some(result))
}

pub(super) async fn prepare(
    state: &AppState,
    flow: &Flow,
    browser: &str,
    proof: &AccountSessionProof,
    member: Uuid,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    if !required(&state.pool, flow.client_id).await? {
        return Err(AppError::bad_request("纯账号客户端不接受成员选择"));
    }
    if flow.source_session_id != Some(proof.id)
        || flow.user_id != Some(proof.user_id)
        || flow.account_version != Some(proof.account_version)
        || flow.auth_time != Some(proof.authenticated_at)
    {
        return Err(AppError::unauthorized("原账号认证已变化"));
    }
    let _permit = state
        .context_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Unavailable)?;
    super::check_browser(flow, browser).map_err(|_| AppError::forbidden("浏览器交互无效"))?;
    let context = context_row(&state.pool, flow.id, false).await?;
    if context.source_digest.as_deref()
        != Some(&crate::oidc::digest(&source_handle(browser, flow.id)))
        || context.expires_at <= Utc::now()
    {
        return Err(AppError::unauthorized("上下文交互来源已失效"));
    }
    let client = super::client_by_internal_id(state, flow.client_id)
        .await
        .map_err(source_error)?;
    if client.allowed_member_types.len() != 1
        || client.subject_mode != "USER"
        || client.context_mode.as_deref() != Some("PLATFORM_CONTEXT")
        || client.status != "ENABLED"
        || client.application_status != "APPROVED"
        || client.policy_version != flow.client_policy_version
        || client.application_projection_version != flow.application_projection_version
    {
        return Err(AppError::conflict("RP 业务上下文策略已变化"));
    }
    let confirmed = state
        .context_platform
        .confirm(&source_handle(browser, flow.id), flow.client_id, member)
        .await?;
    if confirmed.contract_version != VERSION
        || confirmed.transaction_id != context.transaction_id
        || !crate::oidc::canonical_secret(&confirmed.credential)
        || confirmed.expires_at <= Utc::now()
        || confirmed.expires_at > context.expires_at
        || confirmed.expires_at > flow.expires_at
        || confirmed.expires_at > proof.expires_at
        || confirmed.expires_at > Utc::now() + Duration::seconds(120)
    {
        return Err(AppError::Unavailable);
    }
    if let Some(selected) = context.selected_membership_id {
        if selected != member
            || context.credential_ciphertext.is_none()
            || context.grant_id.is_some()
            || context.delivered_at.is_some()
            || context.selection_expires_at != Some(confirmed.expires_at)
        {
            return Err(AppError::conflict("已确认其他身份，请从应用重新发起登录"));
        }
    }
    let issuer = crate::oidc::enabled(state)?;
    let encrypted = state
        .config
        .context_cipher
        .as_ref()
        .ok_or(AppError::Unavailable)?
        .seal(
            context.transaction_id,
            flow.id,
            flow.client_id,
            issuer,
            &confirmed.credential,
        )?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let current_proof = live_proof(&mut tx, flow).await?;
    current_client(&mut tx, &client).await?;
    if current_proof.id != proof.id
        || current_proof.user_id != proof.user_id
        || current_proof.account_version != proof.account_version
        || current_proof.authenticated_at != proof.authenticated_at
    {
        return Err(AppError::conflict("确认期间原授权来源或客户端策略已变化"));
    }
    let current_flow = flow_for(&mut *tx, flow.id, true).await?;
    if !same_flow(flow, &current_flow) {
        return Err(AppError::conflict("确认期间原授权交互已变化"));
    }
    let locked_context = context_row(&mut *tx, flow.id, true).await?;
    if locked_context.transaction_id != context.transaction_id
        || locked_context.client_id != flow.client_id
        || locked_context.client_policy_version != flow.client_policy_version
        || locked_context.application_projection_version != flow.application_projection_version
        || locked_context.source_digest.as_deref()
            != Some(&crate::oidc::digest(&source_handle(browser, flow.id)))
        || locked_context.expires_at <= Utc::now()
        || locked_context.grant_id.is_some()
        || locked_context.delivered_at.is_some()
    {
        return Err(AppError::conflict("确认期间原业务上下文已变化"));
    }
    if let Some(selected) = locked_context.selected_membership_id {
        if selected != member
            || locked_context.credential_ciphertext.is_none()
            || locked_context.selection_expires_at != Some(confirmed.expires_at)
        {
            return Err(AppError::conflict("已确认其他身份，请从应用重新发起登录"));
        }
        let issuer = crate::oidc::enabled(state)?;
        let existing_credential = state
            .config
            .context_cipher
            .as_ref()
            .ok_or(AppError::Unavailable)?
            .open(
                locked_context.transaction_id,
                flow.id,
                flow.client_id,
                issuer,
                locked_context
                    .credential_ciphertext
                    .as_deref()
                    .ok_or(AppError::Unavailable)?,
            )?;
        if !crate::oidc::equal(&existing_credential, &confirmed.credential) {
            return Err(AppError::conflict("原身份选择结果已变化"));
        }
        tx.commit().await.map_err(|_| AppError::Unavailable)?;
        return Ok(());
    }
    let changed = sqlx::query(
        "UPDATE public.auth_context_interactions \
         SET selected_membership_id=$2,credential_ciphertext=$3,selection_expires_at=$4, \
             expires_at=LEAST(expires_at,$4) \
         WHERE transaction_id=$1 AND authorization_request_id=$5 AND source_digest=$6 \
           AND selected_membership_id IS NULL AND grant_id IS NULL AND delivered_at IS NULL \
           AND expires_at>clock_timestamp() AND $4::timestamptz>clock_timestamp()",
    )
    .bind(context.transaction_id)
    .bind(member)
    .bind(encrypted)
    .bind(confirmed.expires_at)
    .bind(flow.id)
    .bind(crate::oidc::digest(&source_handle(browser, flow.id)))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::conflict("其他请求已完成身份选择"));
    }
    super::audit_authorize(
        &mut tx,
        &current_proof,
        headers,
        flow.client_id,
        "AUTH_CONTEXT_SELECTION",
    )
    .await
    .map_err(source_error)?;
    tx.commit().await.map_err(|_| AppError::Unavailable)?;
    Ok(())
}

async fn flow_for<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    id: Uuid,
    lock: bool,
) -> Result<Flow, AppError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    sqlx::query_as(&format!(
        "SELECT id,client_id,user_id,source_session_id,account_version,auth_time, \
         client_policy_version,application_projection_version,redirect_uri,state_digest,state_value, \
         nonce_digest,nonce_value,code_challenge,scope_ids,browser_digest,csrf_digest,force_login, \
         force_consent,max_age_seconds,prior_session_id,status,created_at,expires_at,consumed_at \
         FROM public.auth_authorization_requests WHERE id=$1{suffix}"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await
    .map_err(|_| AppError::Unavailable)?
    .ok_or_else(|| AppError::unauthorized("原授权交互不存在"))
}

pub(super) async fn selection_deadline(
    tx: &mut Transaction<'_, Postgres>,
    flow: &Flow,
) -> crate::oidc::Result<Option<DateTime<Utc>>> {
    if !required(&mut **tx, flow.client_id).await? {
        return Ok(None);
    }
    let context = context_row(&mut **tx, flow.id, true).await?;
    let expires = context
        .selection_expires_at
        .ok_or_else(|| AppError::conflict("请先完成成员身份选择"))?;
    if context.selected_membership_id.is_none()
        || context.credential_ciphertext.is_none()
        || context.grant_id.is_some()
        || context.delivered_at.is_some()
        || expires <= Utc::now()
        || state_deadline(&context, flow) <= Utc::now()
    {
        return Err(AppError::conflict("身份选择尚未完成或已失效").into());
    }
    crate::oidc::deadline(tx, expires.min(context.expires_at).min(flow.expires_at)).await?;
    Ok(Some(expires))
}

fn state_deadline(context: &ContextRow, flow: &Flow) -> DateTime<Utc> {
    context.expires_at.min(flow.expires_at)
}

pub(super) async fn context_ref(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    client: &Client,
) -> crate::oidc::Result<Option<Uuid>> {
    if client.context_mode.as_deref() != Some("PLATFORM_CONTEXT") {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM public.auth_context_interactions \
             WHERE authorization_request_id=$1)",
        )
        .bind(request_id)
        .fetch_one(&mut **tx)
        .await?;
        if exists {
            return Err(crate::oidc::invalid_grant());
        }
        return Ok(None);
    }
    let context = context_row(&mut **tx, request_id, true).await?;
    if context.client_id != client.id
        || context.client_policy_version != client.policy_version
        || context.application_id != client.application_id
        || context.application_projection_version != client.application_projection_version
        || context.selected_membership_id.is_none()
        || context.credential_ciphertext.is_none()
        || context.grant_id.is_some()
        || context.delivered_at.is_some()
        || context
            .selection_expires_at
            .is_none_or(|expires| expires <= Utc::now())
    {
        return Err(crate::oidc::invalid_grant());
    }
    Ok(Some(context.transaction_id))
}

// The source snapshot is checked field by field against the persisted grant.
#[allow(clippy::too_many_arguments)]
pub(super) async fn validate_grant_binding(
    tx: &mut Transaction<'_, Postgres>,
    transaction_id: Uuid,
    grant_id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    source_session_id: Uuid,
    account_version: i64,
    client_policy_version: i64,
    application_projection_version: i64,
) -> crate::oidc::Result<()> {
    let request_id: Uuid = sqlx::query_scalar(
        "SELECT authorization_request_id FROM public.auth_context_interactions \
         WHERE transaction_id=$1",
    )
    .bind(transaction_id)
    .fetch_optional(&mut **tx)
    .await?
    .flatten()
    .ok_or_else(crate::oidc::invalid_grant)?;
    let flow = flow_for(&mut **tx, request_id, true).await?;
    let context = transaction_row(&mut **tx, transaction_id, true).await?;
    if context.authorization_request_id != Some(request_id)
        || context.grant_id != Some(grant_id)
        || context.client_id != client_id
        || context.client_policy_version != client_policy_version
        || context.application_projection_version != application_projection_version
        || context.selected_membership_id.is_none()
        || context.delivered_at.is_none()
        || context.credential_ciphertext.is_some()
        || flow.status != "CONSUMED"
        || flow.user_id != Some(user_id)
        || flow.source_session_id != Some(source_session_id)
        || flow.account_version != Some(account_version)
        || flow.client_policy_version != client_policy_version
        || flow.application_projection_version != application_projection_version
    {
        return Err(crate::oidc::invalid_grant());
    }
    Ok(())
}

pub(super) async fn deliver_code_extension(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    exchange: &super::CodeExchange,
    grant_id: Uuid,
    context_ref: Option<Uuid>,
) -> crate::oidc::Result<Option<Value>> {
    let Some(transaction_id) = context_ref else {
        return Ok(None);
    };
    let context = context_row(&mut **tx, exchange.request_id, true).await?;
    if context.transaction_id != transaction_id
        || context.client_id != exchange.client_id
        || context.client_policy_version != exchange.client_policy_version
        || context.application_projection_version != exchange.application_projection_version
        || context.authorization_request_id != Some(exchange.request_id)
        || context.selected_membership_id.is_none()
        || context.grant_id.is_some()
        || context.delivered_at.is_some()
        || context.credential_ciphertext.is_none()
        || context
            .selection_expires_at
            .is_none_or(|expires| expires <= Utc::now())
    {
        return Err(crate::oidc::invalid_grant());
    }
    let issuer = crate::oidc::enabled(state)?;
    let credential = state
        .config
        .context_cipher
        .as_ref()
        .ok_or(AppError::Unavailable)?
        .open(
            context.transaction_id,
            exchange.request_id,
            exchange.client_id,
            issuer,
            context
                .credential_ciphertext
                .as_deref()
                .ok_or(AppError::Unavailable)?,
        )?;
    let changed = sqlx::query(
        "UPDATE public.auth_context_interactions SET grant_id=$2,delivered_at=clock_timestamp(), \
         credential_ciphertext=NULL WHERE transaction_id=$1 AND authorization_request_id=$3 \
           AND grant_id IS NULL AND delivered_at IS NULL AND selection_expires_at>clock_timestamp()",
    )
    .bind(transaction_id)
    .bind(grant_id)
    .bind(exchange.request_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(crate::oidc::invalid_grant());
    }
    Ok(Some(
        json!({"contractVersion":VERSION,"transactionId":transaction_id,"credential":credential}),
    ))
}

pub(super) async fn restart(
    tx: &mut Transaction<'_, Postgres>,
    old_flow: Uuid,
    new_flow: Uuid,
) -> Result<(), AppError> {
    let context = sqlx::query_as::<_, (Uuid, Option<Uuid>, Option<Uuid>, Option<String>)>(
        "SELECT transaction_id,selected_membership_id,grant_id,source_digest \
         FROM public.auth_context_interactions WHERE authorization_request_id=$1 FOR UPDATE",
    )
    .bind(old_flow)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((transaction, selected, grant, source)) = context else {
        return Ok(());
    };
    if selected.is_some() || grant.is_some() {
        return Err(AppError::conflict("已确认业务身份不能转移到新授权交互"));
    }
    let changed = sqlx::query(
        "UPDATE public.auth_context_interactions SET authorization_request_id=$2,source_digest=NULL \
         WHERE transaction_id=$1 AND authorization_request_id=$3 AND selected_membership_id IS NULL \
           AND grant_id IS NULL AND expires_at>clock_timestamp()",
    )
    .bind(transaction)
    .bind(new_flow)
    .bind(old_flow)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if changed != 1 || source.is_none() {
        return Err(AppError::conflict("原业务上下文事务不能替换"));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SourceRequest {
    contract_version: String,
    #[serde(default)]
    source_proof: Option<String>,
    #[serde(default)]
    transaction_id: Option<String>,
    #[serde(deserialize_with = "canonical_id")]
    expected_client_id: Uuid,
    #[serde(default, alias = "accessToken")]
    oidc_access_token: Option<String>,
}

pub(crate) async fn source(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<SourceRequest>,
) -> std::result::Result<Json<Value>, AppError> {
    let issuer = crate::oidc::authority(&state).await?;
    let principal =
        crate::internal::authenticate(&state, &headers, "CONTEXT_SELECTION_SOURCE").await?;
    let transaction = body
        .transaction_id
        .as_deref()
        .map(canonical_uuid)
        .transpose()
        .map_err(|_| AppError::bad_request("业务上下文事务标识无效"))?;
    let valid_mode = match (&body.source_proof, transaction, &body.oidc_access_token) {
        (Some(proof), None, None) => crate::oidc::canonical_secret(proof),
        (None, Some(_), Some(access)) => crate::oidc::canonical_secret(access),
        _ => false,
    };
    if query.is_some() || body.contract_version != VERSION || !valid_mode {
        return Err(AppError::bad_request("业务上下文来源请求无效"));
    }
    let allowed: bool = sqlx::query_scalar(
        "SELECT $2=ANY(allowed_auth_clients) FROM public.identity_service_clients \
         WHERE id=$1 AND status='ENABLED' AND purpose='CONTEXT_SELECTION_SOURCE'",
    )
    .bind(principal.id)
    .bind(body.expected_client_id)
    .fetch_optional(&state.pool)
    .await?
    .unwrap_or(false);
    if !allowed {
        return Err(AppError::forbidden("未登记此 auth client 的来源核验用途"));
    }
    let context: ContextRow = sqlx::query_as(
        "SELECT transaction_id,client_id,client_policy_version,application_id, \
         application_projection_version,redirect_uri,state_digest,nonce_digest,code_challenge, \
         intent::text,authorization_request_id,source_digest,selected_membership_id, \
         credential_ciphertext,selection_expires_at,grant_id,delivered_at,expires_at \
         FROM public.auth_context_interactions \
         WHERE (source_digest=$1 OR transaction_id=$3) AND client_id=$2 \
           AND source_digest IS NOT NULL",
    )
    .bind(body.source_proof.as_deref().map(crate::oidc::digest))
    .bind(body.expected_client_id)
    .bind(transaction)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("业务上下文来源不存在"))?;
    let request_id = context
        .authorization_request_id
        .ok_or_else(|| AppError::unauthorized("授权交互尚未绑定"))?;
    let initial = super::get_flow(&state, request_id)
        .await
        .map_err(source_error)?;
    let client = super::client_by_internal_id(&state, context.client_id)
        .await
        .map_err(source_error)?;
    if client.subject_mode != "USER"
        || client.context_mode.as_deref() != Some("PLATFORM_CONTEXT")
        || client.status != "ENABLED"
        || client.application_status != "APPROVED"
        || client.policy_version != context.client_policy_version
        || client.application_projection_version != context.application_projection_version
        || client.application_id != context.application_id
        || client
            .redirect_uris
            .iter()
            .all(|uri| uri != &context.redirect_uri)
        || !same_flow_binding(&initial, &context)
    {
        return Err(AppError::unauthorized("auth client 或原始交互策略已变化"));
    }
    let grant = if let Some(access) = body.oidc_access_token.as_deref() {
        let verified = super::verified_user_access(&state, access)
            .await
            .map_err(source_error)?;
        if context.grant_id != Some(verified.live.grant_id)
            || verified.live.context_mode != "PLATFORM_CONTEXT"
            || verified.live.context_ref != Some(context.transaction_id)
            || verified.live.client_id != client.id
            || verified.live.user_id != initial.user_id.ok_or(AppError::Unavailable)?
            || verified.live.source_session_id
                != initial.source_session_id.ok_or(AppError::Unavailable)?
            || verified.live.account_version
                != initial.account_version.ok_or(AppError::Unavailable)?
            || verified.live.client_policy_version != client.policy_version
            || context.delivered_at.is_none()
            || context.selected_membership_id.is_none()
            || context
                .selection_expires_at
                .is_none_or(|expires| expires <= Utc::now())
        {
            return Err(AppError::unauthorized("访问令牌不属于原业务上下文授权"));
        }
        Some(verified)
    } else {
        None
    };
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let service: bool =
        sqlx::query_scalar("SELECT public.identity_context_source_service_active($1,$2,$3)")
            .bind(principal.id)
            .bind(crate::oidc::digest(principal.secret()))
            .bind(context.client_id)
            .fetch_one(&mut *tx)
            .await?;
    if !service {
        return Err(AppError::forbidden("来源核验服务登记已变化"));
    }
    let proof = live_proof(&mut tx, &initial).await?;
    let locked_client = super::client_by_internal_id(&state, context.client_id)
        .await
        .map_err(source_error)?;
    current_client(&mut tx, &locked_client).await?;
    if let Some(access) = &grant {
        let live = &access.live;
        let consent = auth_consent::sufficient(
            &mut tx,
            &proof,
            locked_client.id,
            &super::to_grants(&access.scopes),
        )
        .await?;
        let ConsentState::Sufficient {
            consent_id,
            generation,
            ..
        } = consent
        else {
            return Err(AppError::unauthorized("原授权同意已撤销或变化"));
        };
        let current_group_version = super::consent_group_version(&mut tx, consent_id)
            .await
            .map_err(source_error)?;
        if consent_id != live.consent_id
            || generation != live.consent_generation
            || current_group_version != live.consent_group_version
        {
            return Err(AppError::unauthorized("原授权同意版本已变化"));
        }
    }
    let flow = flow_for(&mut *tx, request_id, true).await?;
    let flow_state_valid = match grant.as_ref() {
        Some(_) => flow.status == "CONSUMED" && flow.consumed_at.is_some(),
        None => flow.status == "PENDING" && flow.consumed_at.is_none(),
    };
    if !same_flow_snapshot(&initial, &flow) || !flow_state_valid {
        return Err(AppError::unauthorized("原授权请求绑定已变化"));
    }
    let locked: ContextRow = context_row(&mut *tx, request_id, true).await?;
    if !same_flow_binding(&flow, &locked)
        || locked_client.policy_version != context.client_policy_version
        || locked_client.application_projection_version != context.application_projection_version
        || grant
            .as_ref()
            .is_some_and(|access| locked.grant_id != Some(access.live.grant_id))
    {
        return Err(AppError::unauthorized("原业务上下文来源已变化"));
    }
    if grant.is_none() && (locked.grant_id.is_some() || locked.delivered_at.is_some()) {
        return Err(AppError::unauthorized(
            "业务上下文结果已交付，需使用其授权令牌核验",
        ));
    }
    let max_age_deadline = flow
        .max_age_seconds
        .filter(|age| *age > 0)
        .map(|age| proof.authenticated_at + Duration::seconds(age))
        .unwrap_or(proof.expires_at);
    let mut source_expires_at = proof.expires_at.min(max_age_deadline);
    if let Some(access) = &grant {
        let live = &access.live;
        let token_still_live: Option<bool> = sqlx::query_scalar(
            "SELECT true FROM public.auth_access_tokens token \
             JOIN public.auth_grants grant_row ON grant_row.id=token.grant_id \
             WHERE token.id=$1 AND token.token_digest=$2 AND token.revoked_at IS NULL \
               AND token.expires_at>clock_timestamp() AND token.expires_at=$3 \
               AND token.created_at=$4 AND grant_row.id=$5 AND grant_row.revoked_at IS NULL \
               AND grant_row.expires_at>clock_timestamp() AND grant_row.client_id=$6 \
               AND grant_row.user_id=$7 AND grant_row.consent_id=$8 \
               AND grant_row.consent_generation=$9 AND grant_row.source_session_id=$10 \
               AND grant_row.account_version=$11 AND grant_row.auth_time=$12 \
               AND grant_row.client_policy_version=$13 \
               AND grant_row.application_projection_version=$14 \
               AND grant_row.consent_group_version=$15 AND grant_row.context_mode=$16 \
               AND grant_row.context_ref=$17 FOR SHARE OF token,grant_row",
        )
        .bind(live.token_id)
        .bind(crate::oidc::digest(
            body.oidc_access_token
                .as_deref()
                .ok_or(AppError::Unavailable)?,
        ))
        .bind(live.token_expires_at)
        .bind(live.token_created_at)
        .bind(live.grant_id)
        .bind(live.client_id)
        .bind(live.user_id)
        .bind(live.consent_id)
        .bind(live.consent_generation)
        .bind(live.source_session_id)
        .bind(live.account_version)
        .bind(live.auth_time)
        .bind(live.client_policy_version)
        .bind(live.application_projection_version)
        .bind(live.consent_group_version)
        .bind(&live.context_mode)
        .bind(live.context_ref)
        .fetch_optional(&mut *tx)
        .await?;
        if token_still_live != Some(true)
            || live.context_mode != "PLATFORM_CONTEXT"
            || live.context_ref != Some(locked.transaction_id)
            || live.client_id != locked_client.id
            || live.user_id != proof.user_id
            || live.source_session_id != proof.id
            || live.account_version != proof.account_version
            || live.auth_time != proof.authenticated_at
            || live.client_policy_version != locked_client.policy_version
            || live.application_projection_version != locked_client.application_projection_version
        {
            return Err(AppError::unauthorized("访问令牌来源已撤销或变化"));
        }
        validate_grant_binding(
            &mut tx,
            locked.transaction_id,
            live.grant_id,
            live.client_id,
            live.user_id,
            live.source_session_id,
            live.account_version,
            live.client_policy_version,
            live.application_projection_version,
        )
        .await
        .map_err(source_error)?;
        source_expires_at = source_expires_at.min(live.token_expires_at);
    }
    let interaction_expires_at = locked
        .selection_expires_at
        .unwrap_or(locked.expires_at)
        .min(locked.expires_at)
        .min(flow.expires_at);
    if source_expires_at <= Utc::now() || interaction_expires_at <= Utc::now() {
        return Err(AppError::unauthorized("业务上下文来源或选择期限已失效"));
    }
    let member_type = match locked_client.allowed_member_types.as_slice() {
        [member_type] if member_type == "EMPLOYEE" => "PLATFORM_CONSOLE",
        [member_type] if member_type == "CUSTOMER" => "CUSTOMER_PORTAL",
        _ => return Err(AppError::forbidden("auth client 未登记单一人员用途")),
    };
    let intent: Value = serde_json::from_str(&locked.intent).map_err(|_| AppError::Unavailable)?;
    let response = json!({
        "contractVersion":VERSION,
        "transactionId":locked.transaction_id,
        "intent":intent,
        "source":{"issuer":issuer,"userId":proof.user_id,"accountVersion":proof.account_version.to_string(),"globalSessionId":proof.id,"interactionId":flow.id,"authTime":proof.authenticated_at},
        "client":{"id":locked_client.id,"policyVersion":locked_client.policy_version.to_string(),"purpose":member_type,"allowedMemberTypes":locked_client.allowed_member_types,"redirectUri":flow.redirect_uri,"clientRegistry":"AUTH","subjectMode":"USER","contextMode":"PLATFORM_CONTEXT","applicationId":locked_client.application_id},
        "sourceExpiresAt":source_expires_at,
        "interactionExpiresAt":interaction_expires_at
    });
    crate::oidc::deadline(&mut tx, source_expires_at.min(interaction_expires_at))
        .await
        .map_err(source_error)?;
    tx.commit().await.map_err(|_| AppError::Unavailable)?;
    Ok(Json(response))
}

fn canonical_uuid(raw: &str) -> Result<Uuid, ()> {
    let id = Uuid::parse_str(raw).map_err(|_| ())?;
    if crate::util::uuid7::is_uuid_v7(id) && id.to_string() == raw {
        Ok(id)
    } else {
        Err(())
    }
}

fn same_flow_binding(flow: &Flow, context: &ContextRow) -> bool {
    flow.id == context.authorization_request_id.unwrap_or_default()
        && flow.client_id == context.client_id
        && flow.client_policy_version == context.client_policy_version
        && flow.application_projection_version == context.application_projection_version
        && flow.redirect_uri == context.redirect_uri
        && crate::oidc::equal(&flow.state_digest, &context.state_digest)
        && flow
            .nonce_digest
            .as_deref()
            .is_some_and(|digest| crate::oidc::equal(digest, &context.nonce_digest))
        && flow.code_challenge == context.code_challenge
}

fn source_error(error: crate::oidc::OidcError) -> AppError {
    match error {
        crate::oidc::OidcError::App(error) => error,
        _ => AppError::unauthorized("业务上下文授权来源已失效"),
    }
}
