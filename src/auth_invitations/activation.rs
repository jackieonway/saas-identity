//! An invitation creates a new authentication account and no business identity.

use super::*;
use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accept {
    operation_id: String,
    token: String,
    username: String,
    password: String,
    verification_ref: String,
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/sso/invitations/{id}", get(page))
        .route("/sso/assets/invitation.js", get(page_script))
        .route("/api/sso/invitations/{id}/accept", post(accept))
        .layer(DefaultBodyLimit::max(4096))
        .route_layer(middleware::from_fn(bounded))
}

async fn bounded(request: Request, next: Next) -> Response {
    let mut response = if request.uri().query().is_some() {
        AppError::bad_request("邀请领取入口不接受查询参数").into_response()
    } else {
        match tokio::time::timeout(std::time::Duration::from_secs(3), next.run(request)).await {
            Ok(response) => response,
            Err(_) => AppError::Unavailable.into_response(),
        }
    };
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin"));
    response
}

fn page_enabled(state: &AppState) -> Result<(), AppError> {
    if !state.config.sso_enabled {
        return Err(AppError::not_found("统一账号认证未启用"));
    }
    state
        .config
        .sso_origin
        .as_ref()
        .ok_or(AppError::Unavailable)?;
    Ok(())
}

async fn page(
    State(state): State<AppState>,
    Path(raw): Path<String>,
) -> Result<Response, AppError> {
    page_enabled(&state)?;
    canonical_id(&raw)?;
    // The public shell never reads invitation existence, recipient or status.
    Ok((
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../static/identity/invitation.html"),
    )
        .into_response())
}

async fn page_script(State(state): State<AppState>) -> Result<Response, AppError> {
    page_enabled(&state)?;
    Ok((
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../static/identity/invitation.js"),
    )
        .into_response())
}

async fn lock_operation(
    tx: &mut Transaction<'_, Postgres>,
    operation: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,90416273))")
        .bind(operation.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn token_matches(invitation: &Invitation, token: &str) -> Result<(), AppError> {
    if invitation.purpose != "ACCOUNT_ONBOARDING"
        || !equal_digest(&invitation.token_digest, &sha256_hex(token))
    {
        return Err(AppError::forbidden("邀请领取证明无效"));
    }
    Ok(())
}

async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    invitation: &Invitation,
    operation: Uuid,
    verification: Uuid,
    digest: &str,
) -> Result<Option<Value>, AppError> {
    let receipt: Option<(Uuid, Uuid, String, i64, Value)> = sqlx::query_as(
        "SELECT invitation_id,verification_id,request_digest,key_version,result_json \
         FROM public.auth_invitation_activation_receipts WHERE operation_id=$1",
    )
    .bind(operation)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((source, verified, original, key_version, result)) = receipt else {
        return Ok(None);
    };
    if source != invitation.id
        || verified != verification
        || key_version != invitation.key_version
        || !equal_digest(&original, digest)
    {
        return Err(AppError::conflict("原领取操作已绑定另一请求"));
    }
    if result
        != json!({"operationId":operation,"invitationId":invitation.id,"status":"ACCOUNT_CREATED"})
    {
        return Err(AppError::Unavailable);
    }
    Ok(Some(result))
}

async fn username_unused(
    tx: &mut Transaction<'_, Postgres>,
    username: &str,
) -> Result<(), AppError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.users WHERE username=$1)")
            .bind(username)
            .fetch_one(&mut **tx)
            .await?;
    if exists {
        return Err(AppError::conflict("用户名已存在，请选择新的用户名"));
    }
    Ok(())
}

async fn accept(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    ApiJson(input): ApiJson<Accept>,
) -> Result<Json<Value>, AppError> {
    // Cookies do not select, merge, enable or sign in an existing account.
    crate::sso::browser_origin(&state, &headers, false)?;
    let _permit = state
        .internal_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Unavailable)?;
    let id = canonical_id(&raw)?;
    let operation = canonical_id(&input.operation_id)?;
    let verification = canonical_id(&input.verification_ref)?;
    if input.username.is_empty()
        || input.username.trim() != input.username
        || input.username.chars().count() > 100
        || input.username.len() > state.config.login_identifier_max_bytes
        || input.username.chars().any(char::is_control)
        || input.token.len() != 43
        || input.password.len() > crate::password::MAX_PASSWORD_BYTES
    {
        return Err(AppError::bad_request("邀请领取字段无效"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(&input.token)
        .map_err(|_| AppError::forbidden("邀请领取证明无效"))?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != input.token {
        return Err(AppError::forbidden("邀请领取证明无效"));
    }
    let keys = configured_keys(&state).await?;
    // Cheap proof checks and original-result recovery precede Argon2. Release
    // all database locks before the shared bounded password service runs.
    let mut preflight = state.pool.begin().await?;
    lock_operation(&mut preflight, operation).await?;
    let invitation = load(&mut preflight, id, false).await?;
    token_matches(&invitation, &input.token)?;
    let digest = keys.activation_digest(
        &invitation,
        operation,
        verification,
        &input.username,
        &input.password,
    )?;
    if let Some(result) = replay(
        &mut preflight,
        &invitation,
        operation,
        verification,
        &digest,
    )
    .await?
    {
        preflight.commit().await?;
        return Ok(Json(result));
    }
    invitation.require_active(invitation.version)?;
    trust::require_verification(&mut preflight, &invitation, verification).await?;
    username_unused(&mut preflight, &input.username).await?;
    preflight.commit().await?;
    let password = state.accounts.prepare_password(&input.password).await?;

    let mut tx = state.pool.begin().await?;
    lock_operation(&mut tx, operation).await?;
    let invitation = load(&mut tx, id, true).await?;
    token_matches(&invitation, &input.token)?;
    if !equal_digest(
        &digest,
        &keys.activation_digest(
            &invitation,
            operation,
            verification,
            &input.username,
            &input.password,
        )?,
    ) {
        return Err(AppError::conflict("邀请领取来源已变化"));
    }
    if let Some(result) = replay(&mut tx, &invitation, operation, verification, &digest).await? {
        tx.commit().await?;
        return Ok(Json(result));
    }
    invitation.require_active(invitation.version)?;
    let target = trust::require_verification(&mut tx, &invitation, verification).await?;
    username_unused(&mut tx, &input.username).await?;
    let user = uuid7::new_uuid();
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO public.users(id,username,password_hash,status,session_version) \
         VALUES($1,$2,$3,'ENABLED',1) RETURNING id",
    )
    .bind(user)
    .bind(&input.username)
    .bind(password.encoded())
    .fetch_optional(&mut *tx)
    .await?;
    if inserted != Some(user) {
        return Err(AppError::Unavailable);
    }
    let result = json!({"operationId":operation,"invitationId":id,"status":"ACCOUNT_CREATED"});
    let written = sqlx::query(
        "INSERT INTO public.auth_invitation_activation_receipts(operation_id,invitation_id,verification_id,user_id,request_digest,key_version,invitation_version,verification_version,delivery_target_id,delivery_target_version,result_json) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    ).bind(operation).bind(id).bind(verification).bind(user).bind(&digest).bind(invitation.key_version)
        .bind(invitation.version).bind(target.verification_version).bind(target.id).bind(target.version).bind(&result)
        .execute(&mut *tx).await?.rows_affected();
    if written != 1 {
        return Err(AppError::Unavailable);
    }
    audit::write_in_tx(&mut tx,audit::AuditInfo {
        user_id:Some(user),username:"INVITATION_AUTHORITY",action:"AUTH_INVITATION_ACCOUNT_CREATED",
        detail:&json!({"operationId":operation,"invitationId":id,"verificationRef":verification,
            "verificationVersion":target.verification_version,"targetId":target.id,"targetVersion":target.version,
            "invitationVersion":invitation.version}).to_string(),
        ip:"directed-invitation",user_agent:"invitation-accept/1",
    }).await?;
    trust::require_verification(&mut tx, &invitation, verification).await?;
    let consumed = sqlx::query(
        "UPDATE public.auth_invitations SET status='CONSUMED',version=version+1,consumed_at=clock_timestamp(), \
         consumed_by_service_id=NULL,verification_ref=$3,activated_account_id=$4,activation_operation_id=$5 \
         WHERE id=$1 AND version=$2 AND status='ACTIVE' AND expires_at>clock_timestamp() AND version<9223372036854775807",
    ).bind(id).bind(invitation.version).bind(verification).bind(user).bind(operation)
        .execute(&mut *tx).await?.rows_affected();
    if consumed != 1 {
        return Err(AppError::conflict("邀请已过期或已消费"));
    }
    // Target and verification locks were acquired by their narrow owner fences.
    // The invitation is now consumed by this transaction; check its exact tuple
    // and all absolute deadlines without asking an ACTIVE-only fence to replay.
    let current: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.auth_invitations invitation \
         JOIN public.auth_invitation_verifications verified ON verified.id=invitation.verification_ref \
         JOIN public.auth_delivery_targets target ON target.id=verified.delivery_target_id \
         WHERE invitation.id=$1 AND invitation.status='CONSUMED' AND invitation.activation_operation_id=$2 \
           AND invitation.activated_account_id=$3 AND invitation.expires_at>clock_timestamp() \
           AND verified.id=$4 AND verified.version=$5 AND verified.status='ACTIVE' \
           AND verified.verified_at<=clock_timestamp() AND verified.expires_at>clock_timestamp() \
           AND target.id=$6 AND target.version=$7 AND target.status='ACTIVE' \
           AND target.verified_at<=clock_timestamp() AND target.expires_at>clock_timestamp())",
    )
    .bind(id).bind(operation).bind(user).bind(verification).bind(target.verification_version).bind(target.id).bind(target.version)
    .fetch_one(&mut *tx)
    .await?;
    if !current {
        return Err(AppError::conflict("邀请已过期"));
    }
    tx.commit().await?;
    Ok(Json(result))
}

#[cfg(test)]
#[path = "activation_page_tests.rs"]
mod page_tests;
