//! Two-person administrator MFA recovery. The platform remains the authority
//! for administrator roles and signs each approver's recent-auth statement.

use crate::{
    error::AppError,
    extractors::ApiJson,
    internal,
    state::AppState,
    util::{audit, hash::sha256_hex, uuid7},
};
use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

const AUTH_SECURITY: &str = "AUTH_SECURITY";

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Approval {
    user_id: String,
    approval_id: String,
    primary_authenticated_at: i64,
    mfa_verified_at: i64,
    signature: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Recovery {
    operation_id: String,
    target_user_id: String,
    reason: String,
    approvals: Vec<Approval>,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/internal/identity/security/mfa/recover", post(recover))
}

async fn recover(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ApiJson(body): ApiJson<Recovery>,
) -> Result<Json<Value>, AppError> {
    let service = internal::authenticate(&state, &headers, AUTH_SECURITY).await?;
    service.require(AUTH_SECURITY)?;
    if query.is_some() {
        return Err(AppError::bad_request("MFA 恢复请求不接受查询参数"));
    }
    let operation_id = canonical_uuid(&body.operation_id)?;
    let target_user_id = canonical_uuid(&body.target_user_id)?;
    if body.reason.trim().len() < 10
        || body.reason.len() > 1000
        || body.reason.chars().any(char::is_control)
        || body.approvals.len() != 2
    {
        return Err(AppError::bad_request("MFA 恢复请求无效"));
    }
    let canonical_body = serde_json::to_string(&body).map_err(|_| AppError::Unavailable)?;
    let request_digest = sha256_hex(&canonical_body);
    let reason_digest = sha256_hex(body.reason.trim());
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("identity-mfa-recovery-v1:{operation_id}"))
        .execute(&mut *tx)
        .await?;
    let existing: Option<(String, Value)> = sqlx::query_as(
        "SELECT request_digest,result_json FROM public.auth_mfa_recovery_receipts WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((stored_digest, result)) = existing {
        if stored_digest != request_digest {
            return Err(AppError::conflict("MFA 恢复操作编号已绑定到其他请求"));
        }
        tx.commit().await?;
        return Ok(Json(result));
    }

    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let mut approver_ids = Vec::with_capacity(2);
    let mut approval_ids = Vec::with_capacity(2);
    for approval in &body.approvals {
        let user_id = canonical_uuid(&approval.user_id)?;
        let approval_id = canonical_uuid(&approval.approval_id)?;
        if user_id == target_user_id
            || approver_ids.contains(&user_id)
            || approval_ids.contains(&approval_id)
            || approval.signature.len() != 64
            || !approval
                .signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AppError::forbidden("MFA 恢复需要两名不同的授权人员"));
        }
        let primary = DateTime::<Utc>::from_timestamp(approval.primary_authenticated_at, 0)
            .ok_or_else(|| AppError::bad_request("MFA 恢复时间证明无效"))?;
        let second_factor = DateTime::<Utc>::from_timestamp(approval.mfa_verified_at, 0)
            .ok_or_else(|| AppError::bad_request("MFA 恢复时间证明无效"))?;
        if !crate::sso::mfa::recent_enough(primary, now, 300)
            || !crate::sso::mfa::recent_enough(second_factor, now, 300)
            || second_factor < primary
        {
            return Err(AppError::forbidden(
                "MFA 恢复要求最近 5 分钟内的主认证与 TOTP",
            ));
        }
        let signed = approval_message(
            operation_id,
            target_user_id,
            user_id,
            approval_id,
            approval.primary_authenticated_at,
            approval.mfa_verified_at,
            &reason_digest,
        );
        let signature = hex::decode(&approval.signature)
            .map_err(|_| AppError::forbidden("MFA 恢复签名无效"))?;
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, service.secret().as_bytes()),
            signed.as_bytes(),
            &signature,
        )
        .map_err(|_| AppError::forbidden("MFA 恢复签名无效"))?;
        approver_ids.push(user_id);
        approval_ids.push(approval_id);
    }

    let account: Option<(String, i64)> =
        sqlx::query_as("SELECT username,session_version FROM public.users WHERE id=$1 FOR UPDATE")
            .bind(target_user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((username, version)) = account else {
        return Err(AppError::not_found("恢复目标账号不存在"));
    };
    let updated_version = version.checked_add(1).ok_or(AppError::Unavailable)?;
    sqlx::query(
        "UPDATE public.users SET session_version=$2,updated_at=clock_timestamp() WHERE id=$1 AND session_version=$3",
    )
    .bind(target_user_id)
    .bind(updated_version)
    .bind(version)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE public.sso_sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()) \
         WHERE user_id=$1 AND revoked_at IS NULL",
    )
    .bind(target_user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM public.auth_totp_factors WHERE user_id=$1")
        .bind(target_user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM public.auth_totp_enrollments WHERE user_id=$1")
        .bind(target_user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM public.auth_totp_recovery_codes WHERE user_id=$1")
        .bind(target_user_id)
        .execute(&mut *tx)
        .await?;
    let result = json!({
        "operationId":operation_id,
        "targetUserId":target_user_id,
        "recovered":true,
        "nextStep":"enroll_totp",
        "accountVersion":updated_version.to_string()
    });
    sqlx::query(
        "INSERT INTO public.auth_mfa_recovery_receipts(operation_id,target_user_id,request_digest,result_json) \
         VALUES($1,$2,$3,$4)",
    )
    .bind(operation_id)
    .bind(target_user_id)
    .bind(&request_digest)
    .bind(&result)
    .execute(&mut *tx)
    .await?;
    for (approval, user_id) in body.approvals.iter().zip(&approver_ids) {
        sqlx::query(
            "INSERT INTO public.auth_mfa_recovery_approvals( \
             operation_id,approver_user_id,primary_authenticated_at,mfa_verified_at,approval_digest) \
             VALUES($1,$2,to_timestamp($3),to_timestamp($4),$5)",
        )
        .bind(operation_id)
        .bind(user_id)
        .bind(approval.primary_authenticated_at)
        .bind(approval.mfa_verified_at)
        .bind(sha256_hex(&approval.signature))
        .execute(&mut *tx)
        .await?;
    }
    let detail = json!({
        "operationId":operation_id,
        "approvers":approver_ids,
        "reasonDigest":reason_digest
    })
    .to_string();
    audit::write_in_tx(
        &mut tx,
        audit::AuditInfo {
            user_id: Some(target_user_id),
            username: &username,
            action: "MFA_ADMIN_RECOVERY",
            detail: &detail,
            ip: "trusted-platform-service",
            user_agent: "AUTH_SECURITY",
        },
    )
    .await?;
    crate::sso::mfa::record_security_event(&mut tx, target_user_id, "MFA_RECOVERED").await?;
    tx.commit().await?;
    Ok(Json(result))
}

pub(crate) fn approval_message(
    operation_id: Uuid,
    target_user_id: Uuid,
    approver_user_id: Uuid,
    approval_id: Uuid,
    primary_at: i64,
    mfa_at: i64,
    reason_digest: &str,
) -> String {
    format!(
        "saas-identity/mfa-recovery-approval/1\n{operation_id}\n{target_user_id}\n{approver_user_id}\n{approval_id}\n{primary_at}\n{mfa_at}\n{reason_digest}"
    )
}

fn canonical_uuid(value: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(value).map_err(|_| AppError::bad_request("UUIDv7 无效"))?;
    if uuid7::is_uuid_v7(id) && id.to_string() == value {
        Ok(id)
    } else {
        Err(AppError::bad_request("UUIDv7 无效"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_signature_binds_two_distinct_people_and_the_recovery_reason() {
        let operation = Uuid::now_v7();
        let target = Uuid::now_v7();
        let first = Uuid::now_v7();
        let approval = Uuid::now_v7();
        let secret = "ab".repeat(32);
        let reason = sha256_hex("verified through protected support process");
        let message = approval_message(operation, target, first, approval, 100, 200, &reason);
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
            message.as_bytes(),
        );
        assert!(hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
            message.as_bytes(),
            signature.as_ref(),
        )
        .is_ok());
        assert!(hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
            approval_message(operation, target, first, approval, 100, 200, "changed").as_bytes(),
            signature.as_ref(),
        )
        .is_err());
    }
}
