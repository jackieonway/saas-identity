use crate::error::AppError;
use axum::http::HeaderMap;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(crate) fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .unwrap_or("unknown")
        .chars()
        .take(100)
        .collect()
}
pub(crate) fn ua_of(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(500)
        .collect()
}
pub(crate) struct AuditInfo<'a> {
    pub(crate) user_id: Option<Uuid>,
    pub(crate) username: &'a str,
    pub(crate) action: &'a str,
    pub(crate) detail: &'a str,
    pub(crate) ip: &'a str,
    pub(crate) user_agent: &'a str,
}
pub(crate) async fn write_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    info: AuditInfo<'_>,
) -> Result<(), AppError> {
    let written=sqlx::query("INSERT INTO identity_audit_logs(id,user_id,username,action,detail,ip,user_agent,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp())")
        .bind(super::uuid7::new_uuid()).bind(info.user_id).bind(info.username).bind(info.action).bind(info.detail).bind(info.ip).bind(info.user_agent)
        .execute(&mut **tx).await.map_err(|_|{crate::observability::audit_failure();AppError::Unavailable})?;
    if written.rows_affected() != 1 {
        crate::observability::audit_failure();
        return Err(AppError::Unavailable);
    }
    Ok(())
}
