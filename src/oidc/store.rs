//! Fresh account/session authority and immutable protocol proofs.

use chrono::{DateTime, Utc};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

use super::{invalid_grant, Result};
use crate::{error::AppError, sso::AccountSessionProof};

#[derive(sqlx::FromRow, Clone)]
pub(super) struct Flow {
    pub id: Uuid,
    pub browser_hash: String,
    pub csrf_hash: String,
    pub client_id: Uuid,
    pub client_policy_version: i64,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub force_login: bool,
    pub max_age: Option<i64>,
    pub session_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub account_version: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow, Clone)]
pub(super) struct Grant {
    pub id: Uuid,
    pub client_id: Uuid,
    pub client_policy_version: i64,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub account_version: i64,
    pub scope: Vec<String>,
    pub nonce: String,
    pub auth_time: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub(super) async fn flow<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    id: Uuid,
    lock: bool,
) -> std::result::Result<Option<Flow>, AppError> {
    let sql = if lock {
        "SELECT * FROM oidc_authorization_requests WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM oidc_authorization_requests WHERE id=$1"
    };
    sqlx::query_as(sql)
        .bind(id)
        .fetch_optional(executor)
        .await
        .map_err(|_| AppError::Unavailable)
}

pub(super) async fn grant<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    id: Uuid,
    lock: bool,
) -> std::result::Result<Option<Grant>, AppError> {
    let sql = if lock {
        "SELECT * FROM oidc_grants WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM oidc_grants WHERE id=$1"
    };
    sqlx::query_as(sql)
        .bind(id)
        .fetch_optional(executor)
        .await
        .map_err(|_| AppError::Unavailable)
}

pub(super) async fn lock_user(connection: &mut sqlx::PgConnection, user: Uuid) -> Result<()> {
    let found: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_optional(connection)
        .await
        .map_err(|_| AppError::Unavailable)?;
    if found.is_none() {
        return Err(invalid_grant());
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    account_version: i64,
    authenticated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    username: String,
    real_name: String,
    avatar: String,
}

pub(super) async fn session<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    sid: Uuid,
    user: Uuid,
    version: i64,
) -> Result<AccountSessionProof> {
    let row:SessionRow=sqlx::query_as(
        "SELECT s.id,s.user_id,s.account_version,s.authenticated_at,s.expires_at,u.username,COALESCE(u.real_name,'') AS real_name,COALESCE(u.avatar,'') AS avatar \
         FROM sso_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2 AND s.account_version=$3 \
         AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.status='ENABLED' AND u.session_version=s.account_version")
        .bind(sid).bind(user).bind(version).fetch_optional(executor).await.map_err(|_|AppError::Unavailable)?.ok_or_else(invalid_grant)?;
    if !crate::util::uuid7::is_uuid_v7(row.user_id) || !crate::util::uuid7::is_uuid_v7(row.id) {
        return Err(invalid_grant());
    }
    Ok(AccountSessionProof {
        id: row.id,
        user_id: row.user_id,
        account_version: row.account_version,
        authenticated_at: row.authenticated_at,
        expires_at: row.expires_at,
        username: row.username,
        real_name: row.real_name,
        avatar: row.avatar,
    })
}

pub(super) fn valid_grant(grant: &Grant, client: &super::clients::Client) -> Result<()> {
    if grant.client_id != client.id
        || grant.client_policy_version != client.access_policy_version
        || grant.revoked_at.is_some()
        || client.status != "ENABLED"
    {
        return Err(invalid_grant());
    }
    Ok(())
}

pub(super) async fn revoke_grant(connection: &mut sqlx::PgConnection, id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE oidc_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1",
    )
    .bind(id)
    .execute(connection)
    .await?;
    Ok(())
}

pub(super) async fn code(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    state: &crate::state::AppState,
    flow: &Flow,
    session: &AccountSessionProof,
) -> Result<(String, DateTime<Utc>)> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| AppError::Unavailable)?;
    let grant_id = crate::util::uuid7::new_uuid();
    let token = super::secret()?;
    let grant_expiry = session
        .expires_at
        .min(now + chrono::Duration::seconds(state.config.oidc_refresh_ttl_seconds));
    let code_expiry =
        grant_expiry.min(now + chrono::Duration::seconds(state.config.oidc_code_ttl_seconds));
    super::deadline(tx, code_expiry).await?;
    sqlx::query("INSERT INTO oidc_grants(id,client_id,client_policy_version,session_id,user_id,account_version,scope,nonce,auth_time,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(grant_id).bind(flow.client_id).bind(flow.client_policy_version).bind(session.id).bind(session.user_id)
        .bind(session.account_version).bind(&flow.scope).bind(&flow.nonce).bind(session.authenticated_at).bind(now).bind(grant_expiry).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO oidc_authorization_codes(id,grant_id,token_hash,redirect_uri,code_challenge,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(crate::util::uuid7::new_uuid()).bind(grant_id).bind(super::digest(&token)).bind(&flow.redirect_uri)
        .bind(&flow.code_challenge).bind(now).bind(code_expiry).execute(&mut **tx).await?;
    Ok((token, code_expiry))
}

pub(super) async fn account_audit(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    headers: &axum::http::HeaderMap,
    action: &str,
    client: Uuid,
) -> Result<()> {
    crate::util::audit::write_in_tx(
        tx,
        crate::util::audit::AuditInfo {
            user_id: Some(proof.user_id),
            username: &proof.username,
            action,
            detail: &serde_json::json!({"clientId":client,"scope":"OIDC_ACCOUNT"}).to_string(),
            ip: &crate::util::audit::client_ip(headers),
            user_agent: &crate::util::audit::ua_of(headers),
        },
    )
    .await?;
    Ok(())
}
