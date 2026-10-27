//! Bridge calls run outside identity write transactions to avoid reentrant locks.
use super::{bridge, source_error, source_handle, VERSION};
use crate::oidc::{clients, store};
use crate::{error::AppError, sso::AccountSessionProof, state::AppState};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{Executor, Postgres, Transaction};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct Row {
    transaction_id: Uuid,
    intent: String,
    selected_membership_id: Option<Uuid>,
    credential_ciphertext: Option<String>,
    selection_expires_at: Option<DateTime<Utc>>,
    grant_id: Option<Uuid>,
    delivered_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
}

async fn row<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    flow: Uuid,
    lock: bool,
) -> Result<Row, AppError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    sqlx::query_as(&format!("SELECT transaction_id,intent::text,selected_membership_id,credential_ciphertext,selection_expires_at,grant_id,delivered_at,expires_at FROM oidc_context_interactions WHERE flow_id=$1{suffix}"))
        .bind(flow).fetch_optional(executor).await.map_err(|_|AppError::Unavailable)?.ok_or_else(||AppError::conflict("身份选择交互不存在"))
}

fn same_flow(original: &store::Flow, current: &store::Flow) -> bool {
    original.id == current.id
        && original.client_id == current.client_id
        && original.client_policy_version == current.client_policy_version
        && original.user_id == current.user_id
        && original.session_id == current.session_id
        && original.account_version == current.account_version
        && original.browser_hash == current.browser_hash
        && original.redirect_uri == current.redirect_uri
        && original.nonce == current.nonce
        && original.state == current.state
        && current.consumed_at.is_none()
}

async fn live<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    flow: &store::Flow,
) -> Result<AccountSessionProof, AppError> {
    store::session(
        executor,
        flow.session_id
            .ok_or_else(|| AppError::unauthorized("请先确认账号"))?,
        flow.user_id
            .ok_or_else(|| AppError::unauthorized("请先确认账号"))?,
        flow.account_version
            .ok_or_else(|| AppError::unauthorized("请先确认账号"))?,
    )
    .await
    .map_err(source_error)
}

async fn eligible(
    connection: &mut sqlx::PgConnection,
    flow: &store::Flow,
    proof: &AccountSessionProof,
) -> Result<(), AppError> {
    let valid:bool=sqlx::query_scalar("SELECT $1::timestamptz>clock_timestamp() AND (NOT $2 OR $3::timestamptz >= $4::timestamptz) AND ($5::bigint IS NULL OR $5=0 OR $3::timestamptz >= clock_timestamp()-$5*interval '1 second')")
        .bind(flow.expires_at).bind(flow.force_login).bind(proof.authenticated_at).bind(flow.created_at).bind(flow.max_age).fetch_one(connection).await.map_err(|_|AppError::Unavailable)?;
    if !valid {
        return Err(AppError::unauthorized("原账号认证或选择交互已失效"));
    }
    Ok(())
}

async fn assert_live(
    state: &AppState,
    flow: &store::Flow,
    browser: &str,
) -> Result<clients::Client, AppError> {
    if !crate::oidc::equal(&flow.browser_hash, &crate::oidc::digest(browser)) {
        return Err(AppError::forbidden("选择交互不属于当前浏览器"));
    }
    let current = store::flow(&state.pool, flow.id, false)
        .await?
        .ok_or_else(|| AppError::unauthorized("选择交互已失效"))?;
    if !same_flow(flow, &current) {
        return Err(AppError::conflict("选择交互来源已变化"));
    }
    let client = clients::load(&state.pool, flow.client_id, false)
        .await?
        .ok_or_else(|| AppError::unauthorized("RP 已失效"))?;
    if client.status != "ENABLED" || client.access_policy_version != flow.client_policy_version {
        return Err(AppError::unauthorized("RP 策略已变化"));
    }
    let proof = live(&state.pool, flow).await?;
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| AppError::Unavailable)?;
    eligible(&mut connection, flow, &proof).await?;
    Ok(client)
}

pub(crate) async fn choices(
    state: &AppState,
    flow: &store::Flow,
    browser: &str,
) -> Result<Option<bridge::Choices>, AppError> {
    if !super::required(&state.pool, flow.client_id).await? {
        return Ok(None);
    }
    let _permit = state
        .context_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Unavailable)?;
    let client = assert_live(state, flow, browser).await?;
    let context = row(&state.pool, flow.id, false).await?;
    let handle = source_handle(browser, flow.id);
    let result = state
        .context_platform
        .choices(&handle, flow.client_id)
        .await?;
    let member_type = match client.purpose.as_str() {
        "PLATFORM_CONSOLE" => "EMPLOYEE",
        "CUSTOMER_PORTAL" => "CUSTOMER",
        _ => return Err(AppError::Unavailable),
    };
    result.validate(flow.user_id.ok_or(AppError::Unavailable)?, member_type)?;
    let intent: Value = serde_json::from_str(&context.intent).map_err(|_| AppError::Unavailable)?;
    if result.transaction_id != context.transaction_id || result.intent != intent {
        return Err(AppError::Unavailable);
    }
    assert_live(state, flow, browser).await?;
    Ok(Some(result))
}

pub(crate) async fn prepare(
    state: &AppState,
    flow: &store::Flow,
    browser: &str,
    proof: &AccountSessionProof,
    member: Option<Uuid>,
    headers: &axum::http::HeaderMap,
) -> Result<(), AppError> {
    if !super::required(&state.pool, flow.client_id).await? {
        if member.is_some() {
            return Err(AppError::bad_request("此 RP 不接受成员选择"));
        }
        return Ok(());
    }
    let member = member.ok_or_else(|| AppError::bad_request("请选择成员身份"))?;
    if flow.session_id != Some(proof.id)
        || flow.user_id != Some(proof.user_id)
        || flow.account_version != Some(proof.account_version)
    {
        return Err(AppError::unauthorized("原账号认证已变化"));
    }
    let _permit = state
        .context_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Unavailable)?;
    assert_live(state, flow, browser).await?;
    let context = row(&state.pool, flow.id, false).await?;
    if let Some(selected) = context.selected_membership_id {
        if selected != member
            || context.credential_ciphertext.is_none()
            || context.grant_id.is_some()
            || !context.selection_expires_at.is_some_and(|v| v > Utc::now())
        {
            return Err(AppError::conflict("原身份选择已确认，请返回应用重新发起"));
        }
        return Ok(());
    }
    let handle = source_handle(browser, flow.id);
    let result = state
        .context_platform
        .confirm(&handle, flow.client_id, member)
        .await?;
    if result.contract_version != VERSION
        || result.transaction_id != context.transaction_id
        || !crate::oidc::canonical_secret(&result.credential)
        || result.expires_at <= Utc::now()
        || result.expires_at > context.expires_at
        || result.expires_at > Utc::now() + chrono::Duration::seconds(120)
    {
        return Err(AppError::Unavailable);
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
            &result.credential,
        )?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    store::lock_user(&mut tx, proof.user_id)
        .await
        .map_err(source_error)?;
    let client = clients::load(&mut *tx, flow.client_id, true)
        .await?
        .ok_or(AppError::Unavailable)?;
    let current = store::flow(&mut *tx, flow.id, true)
        .await?
        .ok_or(AppError::Unavailable)?;
    if !same_flow(flow, &current)
        || client.status != "ENABLED"
        || client.access_policy_version != flow.client_policy_version
    {
        return Err(AppError::conflict("选择交互来源已变化"));
    }
    let proof = live(&mut *tx, &current).await?;
    eligible(&mut tx, &current, &proof).await?;
    let changed=sqlx::query("UPDATE oidc_context_interactions SET selected_membership_id=$2,credential_ciphertext=$3,selection_expires_at=$4,expires_at=LEAST(expires_at,$4) WHERE flow_id=$1 AND selected_membership_id IS NULL AND grant_id IS NULL AND expires_at>clock_timestamp() AND $4::timestamptz>clock_timestamp()")
        .bind(flow.id).bind(member).bind(encrypted).bind(result.expires_at).execute(&mut *tx).await.map_err(|_|AppError::Unavailable)?.rows_affected();
    if changed != 1 {
        return Err(AppError::conflict("其他请求已完成身份选择"));
    }
    store::account_audit(
        &mut tx,
        &proof,
        headers,
        "OIDC_CONTEXT_SELECTION",
        client.id,
    )
    .await
    .map_err(source_error)?;
    tx.commit().await.map_err(|_| AppError::Unavailable)?;
    Ok(())
}

pub(crate) async fn selection_deadline(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    flow: &store::Flow,
) -> crate::oidc::Result<Option<DateTime<Utc>>> {
    if !super::required(&mut **tx, flow.client_id).await? {
        return Ok(None);
    }
    let context = row(&mut **tx, flow.id, true).await?;
    let expires = context
        .selection_expires_at
        .ok_or_else(|| AppError::conflict("请先完成成员身份选择"))?;
    if context.selected_membership_id.is_none()
        || context.credential_ciphertext.is_none()
        || context.grant_id.is_some()
        || state.config.context_cipher.is_none()
    {
        return Err(AppError::conflict("身份选择尚未完成或已使用").into());
    }
    crate::oidc::deadline(tx, expires.min(context.expires_at)).await?;
    Ok(Some(expires))
}

pub(crate) async fn attach_grant(
    tx: &mut Transaction<'_, Postgres>,
    flow: &store::Flow,
    grant: Uuid,
) -> crate::oidc::Result<()> {
    if !super::required(&mut **tx, flow.client_id).await? {
        return Ok(());
    }
    let changed=sqlx::query("UPDATE oidc_context_interactions SET grant_id=$2 WHERE flow_id=$1 AND grant_id IS NULL AND selected_membership_id IS NOT NULL AND selection_expires_at>clock_timestamp()")
        .bind(flow.id).bind(grant).execute(&mut **tx).await?.rows_affected();
    if changed != 1 {
        return Err(crate::oidc::invalid_grant());
    }
    Ok(())
}

pub(crate) async fn code_extension(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    grant: &store::Grant,
) -> crate::oidc::Result<Option<Value>> {
    if !super::required(&mut **tx, grant.client_id).await? {
        return Ok(None);
    }
    let flow_id: Uuid =
        sqlx::query_scalar("SELECT flow_id FROM oidc_context_interactions WHERE grant_id=$1")
            .bind(grant.id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(crate::oidc::invalid_grant)?;
    let context = row(&mut **tx, flow_id, true).await?;
    let expiry = context
        .selection_expires_at
        .ok_or_else(crate::oidc::invalid_grant)?;
    crate::oidc::deadline(tx, expiry.min(context.expires_at)).await?;
    if context.delivered_at.is_some() {
        return Err(crate::oidc::invalid_grant());
    }
    let flow = store::flow(&mut **tx, flow_id, false)
        .await?
        .ok_or_else(crate::oidc::invalid_grant)?;
    if flow.consumed_at.is_none()
        || flow.client_id != grant.client_id
        || flow.user_id != Some(grant.user_id)
        || flow.session_id != Some(grant.session_id)
        || flow.account_version != Some(grant.account_version)
        || flow.client_policy_version != grant.client_policy_version
    {
        return Err(crate::oidc::invalid_grant());
    }
    let credential = state
        .config
        .context_cipher
        .as_ref()
        .ok_or(AppError::Unavailable)?
        .open(
            context.transaction_id,
            flow_id,
            grant.client_id,
            crate::oidc::enabled(state)?,
            context
                .credential_ciphertext
                .as_deref()
                .ok_or(AppError::Unavailable)?,
        )?;
    let changed=sqlx::query("UPDATE oidc_context_interactions SET delivered_at=clock_timestamp(),credential_ciphertext=NULL WHERE flow_id=$1 AND delivered_at IS NULL AND selection_expires_at>clock_timestamp()")
        .bind(flow_id).execute(&mut **tx).await?.rows_affected();
    if changed != 1 {
        return Err(crate::oidc::invalid_grant());
    }
    Ok(Some(
        json!({"contractVersion":VERSION,"transactionId":context.transaction_id,"credential":credential}),
    ))
}

pub(crate) async fn restart(
    tx: &mut Transaction<'_, Postgres>,
    old: Uuid,
    next: Uuid,
) -> Result<(), AppError> {
    let context = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT selected_membership_id FROM oidc_context_interactions WHERE flow_id=$1 FOR UPDATE",
    )
    .bind(old)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| AppError::Unavailable)?;
    if let Some(member) = context {
        if member.is_some() {
            return Err(AppError::conflict("身份选择已确认，请取消并从应用重新发起"));
        }
        sqlx::query("UPDATE oidc_context_interactions SET flow_id=$2,source_hash=NULL WHERE flow_id=$1 AND grant_id IS NULL").bind(old).bind(next).execute(&mut **tx).await.map_err(|_|AppError::Unavailable)?;
    }
    Ok(())
}
