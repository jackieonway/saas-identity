//! Current SSO account proof for canonical context selection.
use chrono::{DateTime, Utc};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

use super::{invalid_grant, Result};
use crate::{error::AppError, sso::AccountSessionProof};

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    account_version: i64,
    authenticated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    username: String,
    real_name: String,
}

pub(super) async fn session<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    sid: Uuid,
    user: Uuid,
    version: i64,
) -> Result<AccountSessionProof> {
    let row:SessionRow=sqlx::query_as(
        "SELECT s.id,s.user_id,s.account_version,s.authenticated_at,s.expires_at,u.username,COALESCE(u.real_name,'') AS real_name \
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
    })
}
