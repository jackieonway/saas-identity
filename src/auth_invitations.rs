//! Directed invitations create one new account through an owner-verified
//! channel. No invitation grants business membership or signs in an account.

mod activation;
mod delivery;
mod keys;
mod trust;
pub(crate) use delivery::{material_for_delivery, revalidate_delivery};
pub(crate) use keys::InvitationKeys;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppError,
    extractors::ApiJson,
    internal,
    state::AppState,
    util::{audit, hash::sha256_hex, uuid7},
};

const PATH: &str = "/internal/identity/auth/invitations";
const ADMIN: &str = "AUTH_INVITATION";
const SELECT: &str = "SELECT id,service_id,operation_id,request_digest,recipient_ref,purpose,actor_user_id,actor_session_id,key_version,token_digest,status,version,created_at,expires_at,revoked_at,consumed_at,expires_at<=clock_timestamp() AS expired FROM public.auth_invitations";

/// Only a worker with a current lease receives this in memory. Deliberately
/// has no Debug or Serialize; retry rows never contain the token.
pub(crate) struct InvitationDeliveryMaterial {
    pub(crate) invitation_id: Uuid,
    pub(crate) recipient_ref: String,
    pub(crate) purpose: String,
    pub(crate) token: String,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) verification_ref: Uuid,
    pub(crate) verification_version: i64,
    pub(crate) verified_channel_ref: Uuid,
    pub(crate) target_version: i64,
}

#[derive(sqlx::FromRow)]
struct Invitation {
    id: Uuid,
    service_id: Uuid,
    operation_id: Uuid,
    request_digest: String,
    recipient_ref: String,
    purpose: String,
    actor_user_id: Uuid,
    actor_session_id: Uuid,
    key_version: i64,
    token_digest: String,
    status: String,
    version: i64,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
    expired: bool,
}

impl Invitation {
    fn metadata(&self) -> Value {
        json!({
            "id":self.id,"recipientRef":self.recipient_ref,"purpose":self.purpose,
            "status":if self.status=="ACTIVE" && self.expired {"EXPIRED"} else {&self.status},
            "version":self.version,"createdAt":self.created_at,"expiresAt":self.expires_at,
            "revokedAt":self.revoked_at,"consumedAt":self.consumed_at,
        })
    }

    fn require_active(&self, expected: i64) -> Result<(), AppError> {
        if self.version != expected || self.status != "ACTIVE" || self.expired {
            return Err(AppError::conflict("邀请已过期、撤销、消费或版本已变化"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Issue {
    actor_user_id: String,
    actor_session_id: String,
    recipient_ref: String,
    purpose: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Revoke {
    actor_user_id: String,
    actor_session_id: String,
    expected_version: i64,
}

struct ManagementProof {
    operation: Uuid,
    service: Uuid,
    actor: Uuid,
    session: Uuid,
    digest: String,
    path: String,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(PATH, get(list).post(issue))
        .route("/internal/identity/auth/invitations/{id}", get(detail))
        .route(
            "/internal/identity/auth/invitations/{id}/revoke",
            post(revoke),
        )
        .merge(activation::routes())
}

fn canonical_id(raw: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(raw).map_err(|_| AppError::bad_request("邀请标识必须为规范UUIDv7"))?;
    if !uuid7::is_uuid_v7(id) || id.to_string() != raw {
        return Err(AppError::bad_request("邀请标识必须为规范UUIDv7"));
    }
    Ok(id)
}

fn binding(recipient: &str, purpose: &str) -> Result<(), AppError> {
    if recipient.is_empty()
        || recipient.len() > 256
        || recipient.trim() != recipient
        || recipient.chars().any(char::is_control)
        || purpose != "ACCOUNT_ONBOARDING"
    {
        return Err(AppError::bad_request("邀请接收人或用途无效"));
    }
    Ok(())
}

fn equal_digest(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0, |different, (a, b)| different | (a ^ b))
            == 0
}

async fn configured_keys(state: &AppState) -> Result<&InvitationKeys, AppError> {
    let keys = state
        .config
        .invitation_keys
        .as_deref()
        .ok_or(AppError::Unavailable)?;
    if state
        .config
        .sso_totp_encryption_key
        .as_ref()
        .is_some_and(|key| keys.uses_material(key))
    {
        return Err(AppError::Unavailable);
    }
    // A dedicated file name alone is insufficient when its bytes were reused
    // as a service/client secret. Check all registered credential digests.
    let reused: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.identity_service_clients WHERE secret_hash=ANY($1)) \
         OR EXISTS(SELECT 1 FROM public.auth_client_credentials WHERE secret_digest=ANY($1))",
    )
    .bind(keys.service_secret_digests())
    .fetch_one(&state.pool)
    .await?;
    if reused {
        return Err(AppError::Unavailable);
    }
    Ok(keys)
}

fn proof(
    headers: &HeaderMap,
    operation: Uuid,
    service: Uuid,
    actor: &str,
    session: &str,
    path: &str,
) -> Result<ManagementProof, AppError> {
    let digest = headers
        .get("x-identity-operation-digest")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::bad_request("邀请操作摘要无效"))?
        .to_owned();
    Ok(ManagementProof {
        operation,
        service,
        actor: canonical_id(actor)?,
        session: canonical_id(session)?,
        digest,
        path: path.to_owned(),
    })
}

async fn require_proof(
    tx: &mut Transaction<'_, Postgres>,
    proof: &ManagementProof,
) -> Result<(), AppError> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT public.identity_auth_invitation_intent_active($1,$2,$3,'POST',$4,$5,$6)",
    )
    .bind(proof.operation)
    .bind(proof.service)
    .bind(&proof.digest)
    .bind(&proof.path)
    .bind(proof.actor)
    .bind(proof.session)
    .fetch_one(&mut **tx)
    .await?;
    if !authorized {
        return Err(AppError::forbidden(
            "邀请操作缺少当前管理员会话授权或近期二次认证",
        ));
    }
    Ok(())
}

async fn load(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    lock: bool,
) -> Result<Invitation, AppError> {
    let sql = format!(
        "{SELECT} WHERE id=$1 {}",
        if lock { "FOR UPDATE" } else { "FOR SHARE" }
    );
    sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| AppError::not_found("邀请不存在"))
}

async fn record(
    tx: &mut Transaction<'_, Postgres>,
    invitation: &Invitation,
    action: &str,
    actor: Option<Uuid>,
) -> Result<(), AppError> {
    audit::write_in_tx(tx, audit::AuditInfo {
        user_id:actor, username:"INVITATION_AUTHORITY", action,
        detail:&json!({"invitationId":invitation.id,"recipientDigest":sha256_hex(&invitation.recipient_ref),"purpose":invitation.purpose,"version":invitation.version}).to_string(),
        ip:"trusted-private-service", user_agent:"invitation-contract/1",
    }).await
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, AppError> {
    internal::authenticate(&state, &headers, ADMIN).await?;
    let sql = format!("{SELECT} ORDER BY created_at DESC,id DESC LIMIT 50");
    let rows: Vec<Invitation> = sqlx::query_as(&sql).fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"records":rows.iter().map(Invitation::metadata).collect::<Vec<_>>(),"limit":50}),
    ))
}

async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Json<Value>, AppError> {
    internal::authenticate(&state, &headers, ADMIN).await?;
    let id = canonical_id(&raw)?;
    let mut tx = state.pool.begin().await?;
    let invitation = load(&mut tx, id, false).await?;
    tx.commit().await?;
    Ok(Json(invitation.metadata()))
}

async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(raw): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = internal::authenticate(&state, &headers, ADMIN).await?;
    // Complete credential-independence reads before reserving the command's
    // transaction connection; simultaneous requests must not need two slots.
    let keys = configured_keys(&state).await?;
    let mut operation =
        crate::admin_operations::begin(&state, &service, &headers, "POST", PATH, &raw).await?;
    if let Some(result) = operation.replay()? {
        return Ok(Json(result));
    }
    let input: Issue =
        serde_json::from_value(raw).map_err(|_| AppError::bad_request("邀请签发请求无效"))?;
    binding(&input.recipient_ref, &input.purpose)?;
    let proof = proof(
        &headers,
        operation.operation_id,
        service.id,
        &input.actor_user_id,
        &input.actor_session_id,
        PATH,
    )?;
    require_proof(&mut operation.tx, &proof).await?;
    let target = trust::target_for_issue(&mut operation.tx, &input.recipient_ref).await?;
    let created_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *operation.tx)
        .await?;
    let expires_at = created_at
        .checked_add_signed(Duration::hours(24))
        .ok_or(AppError::Unavailable)?;
    let mut invitation = Invitation {
        id: operation.operation_id,
        service_id: service.id,
        operation_id: operation.operation_id,
        request_digest: proof.digest.clone(),
        recipient_ref: input.recipient_ref,
        purpose: input.purpose,
        actor_user_id: proof.actor,
        actor_session_id: proof.session,
        key_version: keys.active_version,
        token_digest: String::new(),
        status: "ACTIVE".into(),
        version: 1,
        created_at,
        expires_at,
        revoked_at: None,
        consumed_at: None,
        expired: false,
    };
    invitation.token_digest = sha256_hex(&keys.derive(&invitation)?);
    let changed = sqlx::query("INSERT INTO public.auth_invitations(id,service_id,operation_id,request_digest,recipient_ref,purpose,actor_user_id,actor_session_id,key_version,token_digest,status,version,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'ACTIVE',1,$11,$12)")
        .bind(invitation.id).bind(invitation.service_id).bind(invitation.operation_id).bind(&invitation.request_digest)
        .bind(&invitation.recipient_ref).bind(&invitation.purpose).bind(invitation.actor_user_id).bind(invitation.actor_session_id)
        .bind(invitation.key_version).bind(&invitation.token_digest).bind(created_at).bind(expires_at)
        .execute(&mut *operation.tx).await?.rows_affected();
    if changed != 1 {
        return Err(AppError::Unavailable);
    }
    let event_key = sha256_hex(&format!("auth-invitation/1\n{}", invitation.id));
    let queued = sqlx::query("INSERT INTO public.auth_delivery_jobs(id,kind,event_key,target_id,target_version,invitation_id,state,available_at,created_at) VALUES($1,'INVITATION',$2,$3,$4,$5,'PENDING',clock_timestamp(),clock_timestamp())")
        .bind(uuid7::new_uuid()).bind(event_key).bind(target.id).bind(target.version).bind(invitation.id)
        .execute(&mut *operation.tx).await?.rows_affected();
    if queued != 1 {
        return Err(AppError::Unavailable);
    }
    record(
        &mut operation.tx,
        &invitation,
        "AUTH_INVITATION_ISSUED",
        Some(proof.actor),
    )
    .await?;
    trust::require_target(&mut operation.tx, &invitation, target.id, target.version).await?;
    require_proof(&mut operation.tx, &proof).await?;
    Ok(Json(operation.commit(invitation.metadata()).await?))
}

async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    ApiJson(raw): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = internal::authenticate(&state, &headers, ADMIN).await?;
    let id = canonical_id(&raw_id)?;
    let path = format!("{PATH}/{id}/revoke");
    let mut operation =
        crate::admin_operations::begin(&state, &service, &headers, "POST", &path, &raw).await?;
    if let Some(result) = operation.replay()? {
        return Ok(Json(result));
    }
    let input: Revoke =
        serde_json::from_value(raw).map_err(|_| AppError::bad_request("邀请撤销请求无效"))?;
    let proof = proof(
        &headers,
        operation.operation_id,
        service.id,
        &input.actor_user_id,
        &input.actor_session_id,
        &path,
    )?;
    require_proof(&mut operation.tx, &proof).await?;
    let invitation = load(&mut operation.tx, id, true).await?;
    invitation.require_active(input.expected_version)?;
    let changed = sqlx::query("UPDATE public.auth_invitations SET status='REVOKED',version=version+1,revoked_at=clock_timestamp() WHERE id=$1 AND version=$2 AND status='ACTIVE' AND expires_at>clock_timestamp() AND version<9223372036854775807")
        .bind(id).bind(input.expected_version).execute(&mut *operation.tx).await?.rows_affected();
    if changed != 1 {
        return Err(AppError::conflict("邀请状态已变化"));
    }
    let invitation = load(&mut operation.tx, id, true).await?;
    record(
        &mut operation.tx,
        &invitation,
        "AUTH_INVITATION_REVOKED",
        Some(proof.actor),
    )
    .await?;
    require_proof(&mut operation.tx, &proof).await?;
    Ok(Json(operation.commit(invitation.metadata()).await?))
}

#[cfg(test)]
mod tests;
