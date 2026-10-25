//! PostgreSQL authority; callers hold the account lock before session mutation.

use chrono::{DateTime, Utc};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

#[derive(sqlx::FromRow)]
pub(super) struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub account_version: i64,
    pub authenticated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub csrf_hash: String,
    pub username: String,
    pub real_name: String,
    pub avatar: String,
}

pub(super) async fn session<'e, E>(executor: E, hash: &str) -> Result<Session, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as(
        "SELECT s.id,s.user_id,s.account_version,s.authenticated_at,s.expires_at,s.csrf_hash, \
         u.username,COALESCE(u.real_name,'') AS real_name,COALESCE(u.avatar,'') AS avatar \
         FROM sso_sessions s JOIN users u ON u.id=s.user_id \
         WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() \
         AND u.status='ENABLED' AND u.session_version=s.account_version",
    )
    .bind(hash)
    .fetch_optional(executor)
    .await
    .map_err(|_| AppError::Unavailable)?
    .ok_or_else(|| AppError::unauthorized("账号认证已失效，请重新登录"))
}

pub(super) async fn challenge(state: &AppState, token: &str, csrf: &str) -> Result<(), AppError> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    // Serialize capacity reservation across processes as well as HTTP tasks.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('sso-login-challenge-capacity-v1',0))",
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| AppError::Unavailable)?;
    sqlx::query(
        "DELETE FROM sso_login_challenges WHERE id IN \
         (SELECT id FROM sso_login_challenges WHERE expires_at<=clock_timestamp() \
          OR consumed_at IS NOT NULL ORDER BY expires_at LIMIT 1024)",
    )
    .execute(&mut *tx)
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sso_login_challenges \
         WHERE consumed_at IS NULL AND expires_at>clock_timestamp()",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| AppError::Unavailable)?;
    if count >= state.config.login_max_entries as i64 {
        return Err(AppError::RateLimited(1));
    }
    sqlx::query(
        "INSERT INTO sso_login_challenges(id,token_hash,csrf_hash,created_at,expires_at) \
         VALUES($1,$2,$3,clock_timestamp(),clock_timestamp()+$4*interval '1 second')",
    )
    .bind(crate::util::uuid7::new_uuid())
    .bind(super::digest(token))
    .bind(super::digest(csrf))
    .bind(state.config.sso_preauth_ttl_seconds as f64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn consume_challenge(
    state: &AppState,
    token: &str,
    csrf: &str,
) -> Result<(), AppError> {
    let consumed = sqlx::query(
        "UPDATE sso_login_challenges SET consumed_at=clock_timestamp() \
         WHERE token_hash=$1 AND csrf_hash=$2 AND consumed_at IS NULL \
         AND expires_at>clock_timestamp()",
    )
    .bind(super::digest(token))
    .bind(super::digest(csrf))
    .execute(&state.pool)
    .await
    .map_err(|_| AppError::Unavailable)?
    .rows_affected();
    if consumed != 1 {
        return Err(AppError::forbidden("登录 CSRF 证明已失效"));
    }
    Ok(())
}
