//! Cookie-bound self-service application approvals. No RP credential is exposed.
use super::{proof, write_audit};
use crate::{error::AppError, state::AppState};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde_json::{json, Value};

fn client_id(raw: &str) -> Result<uuid::Uuid, AppError> {
    let client = uuid::Uuid::parse_str(raw).map_err(|_| AppError::bad_request("应用标识无效"))?;
    if !crate::util::uuid7::is_uuid_v7(client) || client.to_string() != raw {
        return Err(AppError::bad_request("应用标识无效"));
    }
    Ok(client)
}

pub(super) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let account = proof(&state, &headers, false).await?;
    let applications:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('clientId',c.id,'name',c.name,'purpose',c.purpose,'scopes',a.scopes,'approvedAt',a.approved_at,'revokedAt',a.revoked_at,'available',c.status='ENABLED') FROM oidc_consents a JOIN oidc_clients c ON c.id=a.client_id WHERE a.user_id=$1 ORDER BY a.revoked_at NULLS FIRST,a.approved_at DESC,c.id")
        .bind(account.session.user_id).fetch_all(&state.pool).await?;
    Ok(Json(json!({"applications":applications})))
}

pub(super) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Json<Value>, AppError> {
    let account = proof(&state, &headers, true).await?;
    let client = client_id(&raw)?;
    let mut tx = state.pool.begin().await?;
    // Serialize with authorization approval/code issuance, then recheck the
    // original cookie under that lock. Revocation cannot lose to a stale tab.
    let current = super::revalidate(&mut tx, &account).await?;
    let changed=sqlx::query("UPDATE oidc_consents SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE user_id=$1 AND client_id=$2")
        .bind(current.user_id).bind(client).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(AppError::not_found("未找到此账号的应用授权"));
    }
    sqlx::query("UPDATE oidc_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE user_id=$1 AND client_id=$2")
        .bind(current.user_id).bind(client).execute(&mut *tx).await?;
    sqlx::query("UPDATE oidc_authorization_requests SET consumed_at=COALESCE(consumed_at,clock_timestamp()) WHERE user_id=$1 AND client_id=$2")
        .bind(current.user_id).bind(client).execute(&mut *tx).await?;
    write_audit(
        &mut tx,
        &current,
        &headers,
        "OIDC_REVOKE_CONSENT",
        json!({"clientId":client}),
    )
    .await?;
    super::ensure_deadline(&mut tx, &current.expires_at).await?;
    tx.commit().await?;
    Ok(Json(json!({"revoked":true,"clientId":client})))
}

pub(super) async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Json<Value>, AppError> {
    let account = proof(&state, &headers, true).await?;
    let client = client_id(&raw)?;
    let mut tx = state.pool.begin().await?;
    let current = super::revalidate(&mut tx, &account).await?;
    let revoked: Option<bool> = sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM oidc_consents WHERE user_id=$1 AND client_id=$2 FOR UPDATE")
        .bind(current.user_id).bind(client).fetch_optional(&mut *tx).await?;
    match revoked {
        None => return Err(AppError::not_found("授权记录不存在")),
        Some(false) => return Err(AppError::conflict("请先撤销应用授权，再删除记录")),
        Some(true) => {}
    }
    let changed = sqlx::query(
        "DELETE FROM oidc_consents WHERE user_id=$1 AND client_id=$2 AND revoked_at IS NOT NULL",
    )
    .bind(current.user_id)
    .bind(client)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::conflict("授权状态已变化，请刷新列表"));
    }
    write_audit(
        &mut tx,
        &current,
        &headers,
        "OIDC_DELETE_REVOKED_CONSENT",
        json!({"clientId":client}),
    )
    .await?;
    super::ensure_deadline(&mut tx, &current.expires_at).await?;
    tx.commit().await?;
    Ok(Json(json!({"deleted":true,"clientId":client})))
}
