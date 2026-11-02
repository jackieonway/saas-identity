use super::proof;
use crate::{
    error::AppError,
    extractors::ApiJson,
    sso::mfa as totp,
    state::AppState,
    util::{audit, uuid7},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{Duration, Utc};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CodeInput {
    code: String,
}

pub(super) async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let current = proof(&state, &headers, false).await?;
    let (enabled, recovery_count, pending): (bool, i64, bool) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM public.auth_totp_factors WHERE user_id=$1), \
         (SELECT count(*) FROM public.auth_totp_recovery_codes WHERE user_id=$1 AND consumed_at IS NULL), \
         EXISTS(SELECT 1 FROM public.auth_totp_enrollments WHERE user_id=$1 AND expires_at>clock_timestamp())",
    )
    .bind(current.session.user_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(json!({
        "enabled": enabled,
        "availableRecoveryCodes": recovery_count,
        "pendingEnrollment": pending,
        "recoveryRequiresTwoAuthorizedApprovers": true
    })))
}

pub(super) async fn start_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let current = proof(&state, &headers, true).await?;
    let secret = totp::new_secret()?;
    let ciphertext = totp::encrypt(&state, current.session.user_id, &secret)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let username = lock_current(&mut tx, &current).await?;
    require_recent_primary(&mut tx, &current).await?;
    if totp::factor_enabled(&mut tx, current.session.user_id).await? {
        return Err(AppError::conflict("此账号已启用身份验证器"));
    }
    sqlx::query(
        "INSERT INTO public.auth_totp_enrollments(user_id,secret_ciphertext,created_at,expires_at) \
         VALUES($1,$2,clock_timestamp(),clock_timestamp()+interval '10 minutes') \
         ON CONFLICT(user_id) DO UPDATE SET secret_ciphertext=EXCLUDED.secret_ciphertext, \
         created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at",
    )
    .bind(current.session.user_id)
    .bind(ciphertext)
    .execute(&mut *tx)
    .await?;
    write_audit(
        &mut tx,
        &current,
        &headers,
        "MFA_ENROLLMENT_STARTED",
        json!({"expiresInSeconds":600}),
    )
    .await?;
    tx.commit().await?;

    let secret = totp::base32(&secret);
    let label_value = format!("SaaS Identity:{username}");
    let label = utf8_percent_encode(&label_value, NON_ALPHANUMERIC);
    let issuer = utf8_percent_encode("SaaS Identity", NON_ALPHANUMERIC);
    Ok(Json(json!({
        "secret": secret,
        "otpauthUri": format!("otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"),
        "expiresAt": Utc::now() + Duration::minutes(10)
    })))
}

pub(super) async fn confirm_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<CodeInput>,
) -> Result<Json<Value>, AppError> {
    let current = proof(&state, &headers, true).await?;
    if body.code.len() > 80 {
        return Err(AppError::bad_request("验证码无效"));
    }
    let attempt_key = admit_mfa_attempt(&state, &headers, current.session.user_id)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let _username = lock_current(&mut tx, &current).await?;
    require_recent_primary(&mut tx, &current).await?;
    if totp::factor_enabled(&mut tx, current.session.user_id).await? {
        return Err(AppError::conflict("此账号已启用身份验证器"));
    }
    let enrollment: Option<(Vec<u8>, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT secret_ciphertext,expires_at FROM public.auth_totp_enrollments \
         WHERE user_id=$1 FOR UPDATE",
    )
    .bind(current.session.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((ciphertext, expires_at)) = enrollment else {
        return Err(AppError::conflict("身份验证器绑定已过期，请重新开始"));
    };
    let live: bool = sqlx::query_scalar("SELECT $1::timestamptz>clock_timestamp()")
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await?;
    if !live {
        return Err(AppError::conflict("身份验证器绑定已过期，请重新开始"));
    }
    let secret = totp::decrypt(&state, current.session.user_id, &ciphertext)?;
    let now_step: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint")
            .fetch_one(&mut *tx)
            .await?;
    let Some(step) = totp::matching_step(&secret, &body.code, now_step, 0) else {
        state.login_limits.record_failure(&attempt_key);
        return Err(AppError::unauthorized("身份验证器验证码无效"));
    };
    sqlx::query(
        "INSERT INTO public.auth_totp_factors(user_id,secret_ciphertext,enabled_at,last_accepted_step,version) \
         VALUES($1,$2,clock_timestamp(),$3,1)",
    )
    .bind(current.session.user_id)
    .bind(ciphertext)
    .bind(step)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM public.auth_totp_enrollments WHERE user_id=$1")
        .bind(current.session.user_id)
        .execute(&mut *tx)
        .await?;

    let codes = totp::recovery_codes(&state, current.session.user_id)?;
    for code in &codes {
        let digest = totp::recovery_digest(&state, current.session.user_id, code)?;
        sqlx::query(
            "INSERT INTO public.auth_totp_recovery_codes(id,user_id,code_digest) VALUES($1,$2,$3)",
        )
        .bind(uuid7::new_uuid())
        .bind(current.session.user_id)
        .bind(digest)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE public.sso_sessions SET mfa_verified_at=clock_timestamp(),mfa_method='totp' \
         WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp()",
    )
    .bind(current.session.id)
    .bind(current.session.user_id)
    .execute(&mut *tx)
    .await?;
    write_audit(
        &mut tx,
        &current,
        &headers,
        "MFA_ENABLED",
        json!({"method":"totp","recoveryCodeCount":codes.len()}),
    )
    .await?;
    totp::record_security_event(&mut tx, current.session.user_id, "MFA_ENABLED").await?;
    ensure_current_session(&mut tx, &current).await?;
    tx.commit().await?;
    state.login_limits.clear_account(&attempt_key);
    Ok(Json(json!({"enabled":true,"recoveryCodes":codes})))
}

pub(super) async fn step_up(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<CodeInput>,
) -> Result<Json<Value>, AppError> {
    let current = proof(&state, &headers, true).await?;
    if body.code.len() > 80 {
        return Err(AppError::bad_request("验证码无效"));
    }
    let attempt_key = admit_mfa_attempt(&state, &headers, current.session.user_id)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    lock_current(&mut tx, &current).await?;
    require_recent_primary(&mut tx, &current).await?;
    let method = totp::consume_code(&state, &mut tx, current.session.user_id, &body.code).await?;
    let Some(method) = method else {
        state.login_limits.record_failure(&attempt_key);
        return Err(AppError::unauthorized("身份验证器验证码无效"));
    };
    sqlx::query(
        "UPDATE public.sso_sessions SET mfa_verified_at=clock_timestamp(),mfa_method=$2 \
         WHERE id=$1 AND user_id=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp()",
    )
    .bind(current.session.id)
    .bind(method)
    .bind(current.session.user_id)
    .execute(&mut *tx)
    .await?;
    write_audit(
        &mut tx,
        &current,
        &headers,
        "MFA_STEP_UP",
        json!({"method":method}),
    )
    .await?;
    ensure_current_session(&mut tx, &current).await?;
    tx.commit().await?;
    state.login_limits.clear_account(&attempt_key);
    Ok(Json(json!({"verified":true,"verifiedAt":Utc::now()})))
}

pub(super) async fn disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<CodeInput>,
) -> Result<StatusCode, AppError> {
    let current = proof(&state, &headers, true).await?;
    if body.code.len() > 80 {
        return Err(AppError::bad_request("验证码无效"));
    }
    let attempt_key = admit_mfa_attempt(&state, &headers, current.session.user_id)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let _username = lock_current(&mut tx, &current).await?;
    require_recent_primary(&mut tx, &current).await?;
    let method = totp::consume_code(&state, &mut tx, current.session.user_id, &body.code).await?;
    let Some(method) = method else {
        state.login_limits.record_failure(&attempt_key);
        return Err(AppError::unauthorized("身份验证器验证码无效"));
    };
    if method != "totp" {
        return Err(AppError::forbidden("停用身份验证器需要新的 TOTP 验证码"));
    }
    sqlx::query("DELETE FROM public.auth_totp_factors WHERE user_id=$1")
        .bind(current.session.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM public.auth_totp_recovery_codes WHERE user_id=$1")
        .bind(current.session.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM public.auth_totp_enrollments WHERE user_id=$1")
        .bind(current.session.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE public.sso_sessions SET mfa_verified_at=NULL,mfa_method=NULL WHERE id=$1 AND user_id=$2",
    )
    .bind(current.session.id)
    .bind(current.session.user_id)
    .execute(&mut *tx)
    .await?;
    write_audit(
        &mut tx,
        &current,
        &headers,
        "MFA_DISABLED",
        json!({"method":"totp"}),
    )
    .await?;
    totp::record_security_event(&mut tx, current.session.user_id, "MFA_DISABLED").await?;
    ensure_current_session(&mut tx, &current).await?;
    tx.commit().await?;
    state.login_limits.clear_account(&attempt_key);
    Ok(StatusCode::NO_CONTENT)
}

fn admit_mfa_attempt(
    state: &AppState,
    headers: &HeaderMap,
    user_id: Uuid,
) -> Result<String, AppError> {
    if let Some(retry) = state.login_limits.admit_source(&audit::client_ip(headers)) {
        return Err(AppError::RateLimited(retry));
    }
    let key = format!("mfa:{user_id}");
    if let Some(retry) = state.login_limits.check_account(&key) {
        return Err(AppError::RateLimited(retry));
    }
    Ok(key)
}

async fn lock_current(
    tx: &mut Transaction<'_, Postgres>,
    current: &super::Proof,
) -> Result<String, AppError> {
    let account: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT username,status,session_version FROM public.users WHERE id=$1 FOR UPDATE",
    )
    .bind(current.session.user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((username, status, version)) = account else {
        return Err(AppError::unauthorized("账号认证已失效"));
    };
    if status != "ENABLED" || version != current.session.account_version {
        return Err(AppError::unauthorized("账号认证已失效"));
    }
    ensure_current_session(tx, current).await?;
    Ok(username)
}

async fn ensure_current_session(
    tx: &mut Transaction<'_, Postgres>,
    current: &super::Proof,
) -> Result<(), AppError> {
    let live: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.sso_sessions WHERE id=$1 AND user_id=$2 AND account_version=$3 \
         AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
    )
    .bind(current.session.id)
    .bind(current.session.user_id)
    .bind(current.session.account_version)
    .fetch_optional(&mut **tx)
    .await?;
    if live.is_none() {
        return Err(AppError::unauthorized("账号认证已失效"));
    }
    Ok(())
}

async fn require_recent_primary(
    tx: &mut Transaction<'_, Postgres>,
    current: &super::Proof,
) -> Result<(), AppError> {
    let fresh: bool = sqlx::query_scalar(
        "SELECT authenticated_at >= clock_timestamp()-interval '5 minutes' \
         FROM public.sso_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL \
           AND expires_at>clock_timestamp()",
    )
    .bind(current.session.id)
    .bind(current.session.user_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| AppError::unauthorized("账号认证已失效"))?;
    if fresh {
        Ok(())
    } else {
        Err(AppError::forbidden("此操作需要最近 5 分钟内的密码验证"))
    }
}

async fn write_audit(
    tx: &mut Transaction<'_, Postgres>,
    current: &super::Proof,
    headers: &HeaderMap,
    action: &'static str,
    detail: Value,
) -> Result<(), AppError> {
    audit::write_in_tx(
        tx,
        audit::AuditInfo {
            user_id: Some(current.session.user_id),
            username: &current.session.username,
            action,
            detail: &detail.to_string(),
            ip: &audit::client_ip(headers),
            user_agent: &audit::ua_of(headers),
        },
    )
    .await
}
