//! Cookie-authenticated management for canonical, group-scoped user consent.

use super::{proof, revalidate, write_audit};
use crate::{error::AppError, extractors::ApiJson, state::AppState, util::uuid7::new_uuid};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConsentCommand {
    operation_id: String,
    expected_version: i64,
}

fn parse_id(raw: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(raw).map_err(|_| AppError::bad_request("授权标识无效"))?;
    if !crate::util::uuid7::is_uuid_v7(id) || id.to_string() != raw {
        return Err(AppError::bad_request("授权标识无效"));
    }
    Ok(id)
}

fn command_digest(action: &str, consent: Uuid, expected_version: i64) -> String {
    crate::util::hash::sha256_hex(&format!(
        "identity-user-consent-command/1\n{action}\n{consent}\n{expected_version}"
    ))
}

pub(super) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let account = proof(&state, &headers, false).await?;
    let consents: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object( \
           'id',c.id,'version',c.version,'generation',c.generation,'displayName',g.display_name, \
           'applicationName',a.display_name,'purpose',g.purpose,'environment',g.environment, \
           'contextMode',g.context_mode,'authorizedAt',c.authorized_at,'revokedAt',c.revoked_at, \
           'requiresConfirmation',(c.group_version<>g.version), \
           'available',(g.status='ACTIVE' AND a.status='APPROVED' AND EXISTS( \
             SELECT 1 FROM public.auth_consent_group_clients m JOIN public.auth_clients x ON x.id=m.client_id \
             WHERE m.group_id=g.id AND x.status='ENABLED')), \
           'clients',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',x.id,'displayName',x.display_name) ORDER BY x.display_name,x.id) \
             FROM public.auth_consent_group_clients m JOIN public.auth_clients x ON x.id=m.client_id WHERE m.group_id=g.id),'[]'::jsonb), \
           'scopes',COALESCE((SELECT jsonb_agg(jsonb_build_object('resourceKey',r.resource_key,'audience',r.audience,'scope',s.scope_name) \
             ORDER BY r.resource_key,s.scope_name) FROM public.auth_consent_scopes x \
             JOIN public.auth_resources r ON r.id=x.resource_id JOIN public.auth_scopes s ON s.id=x.scope_id AND s.resource_id=x.resource_id \
             WHERE x.consent_id=c.id),'[]'::jsonb)) \
         FROM public.auth_consents c JOIN public.auth_consent_groups g ON g.id=c.group_id \
         JOIN public.auth_applications a ON a.application_id=g.application_id \
         WHERE c.user_id=$1 AND c.display_deleted_at IS NULL \
         ORDER BY c.revoked_at NULLS FIRST,c.authorized_at DESC,c.id",
    )
    .bind(account.session.user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({"consents":consents})))
}

pub(super) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    ApiJson(body): ApiJson<ConsentCommand>,
) -> Result<Json<Value>, AppError> {
    command(state, headers, raw, body, "REVOKE").await
}

pub(super) async fn delete_display(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    ApiJson(body): ApiJson<ConsentCommand>,
) -> Result<Json<Value>, AppError> {
    command(state, headers, raw, body, "DISPLAY_DELETE").await
}

async fn command(
    state: AppState,
    headers: HeaderMap,
    raw: String,
    body: ConsentCommand,
    action: &'static str,
) -> Result<Json<Value>, AppError> {
    let account = proof(&state, &headers, true).await?;
    let consent_id = parse_id(&raw)?;
    let operation_id = parse_id(&body.operation_id)?;
    if body.expected_version < 1 {
        return Err(AppError::bad_request("授权版本无效"));
    }
    let digest = command_digest(action, consent_id, body.expected_version);
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let current = revalidate(&mut tx, &account).await?;
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))")
        .bind(operation_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::Unavailable)?;
    if let Some((owner, stored_consent, stored_digest, stored_action, stored_version, result)) =
        sqlx::query_as::<_, (Uuid, Uuid, String, String, i64, Value)>(
            // The operation advisory lock serializes creation and replay. This
            // append-only receipt needs only SELECT; row locks require UPDATE.
            "SELECT user_id,consent_id,request_digest,action,expected_version,result_json \
             FROM public.identity_consent_command_receipts WHERE operation_id=$1",
        )
        .bind(operation_id)
        .fetch_optional(&mut *tx)
        .await?
    {
        if owner != current.user_id
            || stored_consent != consent_id
            || stored_digest != digest
            || stored_action != action
            || stored_version != body.expected_version
        {
            return Err(AppError::conflict("授权操作编号已用于其他请求"));
        }
        super::ensure_deadline(&mut tx, &current.expires_at).await?;
        tx.commit().await?;
        return Ok(Json(result));
    }

    let group_id: Option<Uuid> =
        sqlx::query_scalar("SELECT group_id FROM public.auth_consents WHERE id=$1 AND user_id=$2")
            .bind(consent_id)
            .bind(current.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let group_id = group_id.ok_or_else(|| AppError::not_found("账号授权记录不存在"))?;
    let application_id: Option<Uuid> =
        sqlx::query_scalar("SELECT application_id FROM public.auth_consent_groups WHERE id=$1")
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
    let application_id = application_id.ok_or_else(|| AppError::not_found("授权组不存在"))?;

    // Keep the contract lock order: account (revalidate), app, clients in UUID
    // order, group, consent, authorization records, grants and tokens.
    sqlx::query(
        "SELECT application_id FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(application_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::not_found("授权所属应用不存在"))?;
    let client_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT c.id FROM public.auth_consent_group_clients m \
         JOIN public.auth_clients c ON c.id=m.client_id WHERE m.group_id=$1 ORDER BY c.id FOR UPDATE OF c",
    )
    .bind(group_id)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("SELECT id FROM public.auth_consent_groups WHERE id=$1 FOR UPDATE")
        .bind(group_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::not_found("授权组不存在"))?;
    let consent: Option<(String, i64, i64, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT status,generation,version,display_deleted_at FROM public.auth_consents \
             WHERE id=$1 AND user_id=$2 AND group_id=$3 FOR UPDATE",
        )
        .bind(consent_id)
        .bind(current.user_id)
        .bind(group_id)
        .fetch_optional(&mut *tx)
        .await?;
    let (status, generation, version, display_deleted_at) =
        consent.ok_or_else(|| AppError::not_found("账号授权记录不存在"))?;
    if version != body.expected_version {
        return Err(AppError::conflict("账号授权版本已变化，请刷新列表"));
    }

    let result = match action {
        "REVOKE" => {
            if status != "ACTIVE" || display_deleted_at.is_some() {
                return Err(AppError::conflict("只有当前有效的授权可以撤销"));
            }
            let next_generation = generation.checked_add(1).ok_or(AppError::Unavailable)?;
            let next_version = version.checked_add(1).ok_or(AppError::Unavailable)?;
            let requests =
                lock_authorization_requests(&mut tx, current.user_id, &client_ids).await?;
            let codes = lock_authorization_codes(&mut tx, current.user_id, consent_id).await?;
            let grants = lock_grants(&mut tx, current.user_id, consent_id).await?;
            lock_refresh_families(&mut tx, current.user_id, consent_id).await?;
            lock_access_tokens(&mut tx, current.user_id, consent_id).await?;
            lock_refresh_tokens(&mut tx, current.user_id, consent_id).await?;

            let changed = sqlx::query(
                "UPDATE public.auth_consents SET status='REVOKED',generation=$2,version=$3,revoked_at=clock_timestamp() \
                 WHERE id=$1 AND status='ACTIVE' AND generation=$4 AND version=$5",
            )
            .bind(consent_id)
            .bind(next_generation)
            .bind(next_version)
            .bind(generation)
            .bind(version)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(AppError::conflict("账号授权版本已变化，请刷新列表"));
            }
            sqlx::query(
                "UPDATE public.auth_authorization_requests SET status='DENIED',version=version+1,consumed_at=COALESCE(consumed_at,clock_timestamp()) \
                 WHERE user_id=$1 AND client_id=ANY($2) AND status IN ('PENDING','AUTHORIZED')",
            )
            .bind(current.user_id)
            .bind(&client_ids)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE public.auth_authorization_codes SET consumed_at=COALESCE(consumed_at,clock_timestamp()) WHERE user_id=$1 AND consent_id=$2 AND consumed_at IS NULL")
                .bind(current.user_id).bind(consent_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE public.auth_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()),version=version+1 WHERE user_id=$1 AND consent_id=$2 AND revoked_at IS NULL")
                .bind(current.user_id).bind(consent_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE public.auth_refresh_families f SET revoked_at=COALESCE(f.revoked_at,clock_timestamp()),version=f.version+1 FROM public.auth_grants g WHERE f.grant_id=g.id AND g.user_id=$1 AND g.consent_id=$2 AND f.revoked_at IS NULL")
                .bind(current.user_id).bind(consent_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE public.auth_access_tokens t SET revoked_at=COALESCE(t.revoked_at,clock_timestamp()) FROM public.auth_grants g WHERE t.grant_id=g.id AND g.user_id=$1 AND g.consent_id=$2 AND t.revoked_at IS NULL")
                .bind(current.user_id).bind(consent_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE public.auth_refresh_tokens t SET revoked_at=COALESCE(t.revoked_at,clock_timestamp()) FROM public.auth_refresh_families f JOIN public.auth_grants g ON g.id=f.grant_id WHERE t.family_id=f.id AND g.user_id=$1 AND g.consent_id=$2 AND t.revoked_at IS NULL")
                .bind(current.user_id).bind(consent_id).execute(&mut *tx).await?;
            for client_id in &client_ids {
                sqlx::query(
                    "INSERT INTO public.auth_consent_revocation_outbox(id,consent_id,user_id,group_id,client_id,consent_generation,event_kind) \
                     VALUES($1,$2,$3,$4,$5,$6,'CONSENT_REVOKED') ON CONFLICT(consent_id,consent_generation,client_id,event_kind) DO NOTHING",
                )
                .bind(new_uuid())
                .bind(consent_id)
                .bind(current.user_id)
                .bind(group_id)
                .bind(client_id)
                .bind(next_generation)
                .execute(&mut *tx)
                .await?;
            }
            let pending_requests = requests.len();
            let pending_codes = codes.len();
            let affected_grants = grants.len();
            write_audit(
                &mut tx,
                &current,
                &headers,
                "AUTH_REVOKE_CONSENT_GROUP",
                json!({"operationId":operation_id,"consentId":consent_id,"groupId":group_id,"clientCount":client_ids.len(),"generation":next_generation,"pendingRequestCount":pending_requests,"codeCount":pending_codes,"grantCount":affected_grants}),
            )
            .await?;
            json!({"revoked":true,"consentId":consent_id,"generation":next_generation,"version":next_version,"affectedClients":client_ids.len()})
        }
        "DISPLAY_DELETE" => {
            if status != "REVOKED" || display_deleted_at.is_some() {
                return Err(AppError::conflict("只有未删除的已撤销授权可以删除"));
            }
            let next_version = version.checked_add(1).ok_or(AppError::Unavailable)?;
            let changed = sqlx::query(
                "UPDATE public.auth_consents SET display_deleted_at=clock_timestamp(),version=$2 \
                 WHERE id=$1 AND user_id=$3 AND status='REVOKED' AND generation=$4 AND version=$5 AND display_deleted_at IS NULL",
            )
            .bind(consent_id)
            .bind(next_version)
            .bind(current.user_id)
            .bind(generation)
            .bind(version)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(AppError::conflict("账号授权版本已变化，请刷新列表"));
            }
            sqlx::query("DELETE FROM public.auth_consent_scopes WHERE consent_id=$1")
                .bind(consent_id)
                .execute(&mut *tx)
                .await?;
            write_audit(
                &mut tx,
                &current,
                &headers,
                "AUTH_DELETE_REVOKED_CONSENT_DISPLAY",
                json!({"operationId":operation_id,"consentId":consent_id,"groupId":group_id,"generation":generation}),
            )
            .await?;
            json!({"deleted":true,"consentId":consent_id,"version":next_version})
        }
        _ => return Err(AppError::bad_request("账号授权操作无效")),
    };
    sqlx::query(
        "INSERT INTO public.identity_consent_command_receipts(operation_id,user_id,consent_id,request_digest,action,expected_version,result_json,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp())",
    )
    .bind(operation_id)
    .bind(current.user_id)
    .bind(consent_id)
    .bind(&digest)
    .bind(action)
    .bind(body.expected_version)
    .bind(&result)
    .execute(&mut *tx)
    .await?;
    super::ensure_deadline(&mut tx, &current.expires_at).await?;
    tx.commit().await?;
    Ok(Json(result))
}

async fn lock_authorization_requests(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    clients: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM public.auth_authorization_requests WHERE user_id=$1 AND client_id=ANY($2) \
         AND status IN ('PENDING','AUTHORIZED') ORDER BY id FOR UPDATE",
    )
    .bind(user)
    .bind(clients)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)
}

async fn lock_authorization_codes(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    consent: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM public.auth_authorization_codes WHERE user_id=$1 AND consent_id=$2 \
         AND consumed_at IS NULL ORDER BY id FOR UPDATE",
    )
    .bind(user)
    .bind(consent)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)
}

async fn lock_grants(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    consent: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM public.auth_grants WHERE user_id=$1 AND consent_id=$2 AND revoked_at IS NULL ORDER BY id FOR UPDATE",
    )
    .bind(user)
    .bind(consent)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)
}

async fn lock_refresh_families(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    consent: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT f.id FROM public.auth_refresh_families f JOIN public.auth_grants g ON g.id=f.grant_id \
         WHERE g.user_id=$1 AND g.consent_id=$2 AND f.revoked_at IS NULL ORDER BY f.id FOR UPDATE OF f",
    )
    .bind(user)
    .bind(consent)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)
}

async fn lock_access_tokens(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    consent: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT t.id FROM public.auth_access_tokens t JOIN public.auth_grants g ON g.id=t.grant_id \
         WHERE g.user_id=$1 AND g.consent_id=$2 AND t.revoked_at IS NULL ORDER BY t.id FOR UPDATE OF t",
    )
    .bind(user)
    .bind(consent)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)
}

async fn lock_refresh_tokens(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    consent: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT t.id FROM public.auth_refresh_tokens t JOIN public.auth_refresh_families f ON f.id=t.family_id \
         JOIN public.auth_grants g ON g.id=f.grant_id WHERE g.user_id=$1 AND g.consent_id=$2 \
         AND t.revoked_at IS NULL ORDER BY t.id FOR UPDATE OF t",
    )
    .bind(user)
    .bind(consent)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub(super) async fn operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Json<Value>, AppError> {
    let account = proof(&state, &headers, false).await?;
    let operation_id = parse_id(&raw)?;
    let result: Option<Value> = sqlx::query_scalar(
        "SELECT result_json FROM public.identity_consent_command_receipts WHERE operation_id=$1 AND user_id=$2",
    )
    .bind(operation_id)
    .bind(account.session.user_id)
    .fetch_optional(&state.pool)
    .await?;
    result
        .map(|result| Json(json!({"result":result})))
        .ok_or_else(|| AppError::not_found("授权操作结果尚未确认"))
}
