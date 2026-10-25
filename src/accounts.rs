//! Account consumer protocol. No credential hash or platform authorization rows
//! leave this service; accepted writes and their result receipt commit together.

use axum::{
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppError, extractors::ApiJson, platform_accounts::LoginIdentifier, state::AppState,
    util::audit,
};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/internal/identity/accounts/candidates", post(candidates))
        .route("/internal/identity/accounts/verify", post(verify))
        .route("/internal/identity/accounts/login", post(record_login))
        .route("/internal/identity/accounts/commands", post(command))
        .route(
            "/internal/identity/accounts/operations/{id}",
            get(operation),
        )
        .route("/internal/identity/accounts/{id}", get(account))
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct Account {
    id: Uuid,
    username: String,
    real_name: String,
    status: String,
    #[serde(serialize_with = "serialize_version")]
    account_version: i64,
}

fn serialize_version<S: serde::Serializer>(
    version: &i64,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&version.to_string())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Candidates {
    identifier: String,
    phone: String,
    email: String,
}

async fn candidates(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Candidates>,
) -> Result<Json<Value>, AppError> {
    crate::internal::authenticate(&state, &headers, "ACCOUNT_COMMAND").await?;
    if body.identifier.len() > state.config.login_identifier_max_bytes {
        return Err(AppError::bad_request("登录标识过长"));
    }
    bounded_text(
        &body.identifier,
        state.config.login_identifier_max_bytes,
        false,
    )?;
    bounded_text(&body.phone, 1024, true)?;
    bounded_text(&body.email, 1024, true)?;
    let accounts = state
        .authentication
        .candidates(LoginIdentifier {
            identifier: &body.identifier,
            phone: &body.phone,
            email: &body.email,
        })
        .await?
        .into_iter()
        .map(|account| Account {
            id: account.id,
            username: account.username,
            real_name: account.real_name,
            status: account.status,
            account_version: account.account_version,
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"accounts": accounts})))
}

async fn account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Json<Account>, AppError> {
    crate::internal::authenticate(&state, &headers, "ACCOUNT_COMMAND").await?;
    let id = canonical_id(&raw)?;
    let account: Account = sqlx::query_as(
        "SELECT id,username,COALESCE(real_name,'') AS real_name,status,session_version AS account_version \
         FROM public.users WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("账号不存在"))?;
    Ok(Json(account))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Verify {
    id: String,
    expected_account_version: String,
    password: String,
}

async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Verify>,
) -> Result<Json<Value>, AppError> {
    crate::internal::authenticate(&state, &headers, "ACCOUNT_COMMAND").await?;
    let id = canonical_id(&body.id)?;
    let expected = version(&body.expected_account_version)?;
    let current: Option<(String, String, i64)> =
        sqlx::query_as("SELECT password_hash,status,session_version FROM public.users WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((hash, status, actual)) = current else {
        return Ok(Json(json!({"verified": false})));
    };
    let verified = status == "ENABLED"
        && actual == expected
        && state
            .passwords
            .verify(&hash, &body.password)
            .await
            .map_err(password_error)?;
    let still_current = if verified {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM public.users WHERE id=$1 AND status='ENABLED' \
             AND session_version=$2 AND password_hash=$3)",
        )
        .bind(id)
        .bind(expected)
        .bind(&hash)
        .fetch_one(&state.pool)
        .await?
    } else {
        false
    };
    Ok(Json(json!({"verified": verified && still_current})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Login {
    id: String,
    expected_account_version: String,
}

async fn record_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Login>,
) -> Result<Json<Value>, AppError> {
    crate::internal::authenticate(&state, &headers, "ACCOUNT_COMMAND").await?;
    let id = canonical_id(&body.id)?;
    let expected = version(&body.expected_account_version)?;
    let written = sqlx::query(
        "UPDATE public.users SET last_login_at=clock_timestamp(),updated_at=clock_timestamp() \
         WHERE id=$1 AND session_version=$2 AND status='ENABLED'",
    )
    .bind(id)
    .bind(expected)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if written != 1 {
        return Err(AppError::conflict("原账号认证已变化"));
    }
    Ok(Json(json!({"recorded": true})))
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Kind {
    Create,
    UpdateProfile,
    SetStatus,
    ResetPassword,
    ChangePassword,
    RevokeAll,
    Retire,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Create => "CREATE",
            Self::UpdateProfile => "UPDATE_PROFILE",
            Self::SetStatus => "SET_STATUS",
            Self::ResetPassword => "RESET_PASSWORD",
            Self::ChangePassword => "CHANGE_PASSWORD",
            Self::RevokeAll => "REVOKE_ALL",
            Self::Retire => "RETIRE",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Context {
    user_id: String,
    session_id: String,
    tenant_id: String,
    organization_id: String,
    account_version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Command {
    operation_id: String,
    target_user_id: String,
    expected_account_version: String,
    expires_at: String,
    canonical_digest: String,
    kind: Kind,
    payload: Value,
    context: Option<Context>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    username: String,
    real_name: String,
    email: String,
    phone: String,
    gender: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    real_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    gender: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reset {
    new_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Change {
    old_password: String,
    new_password: String,
}

enum Payload {
    Create(Create),
    Profile(Profile),
    Status(Status),
    Reset(Reset),
    Change(Change),
    Empty,
}

impl Payload {
    fn parse(kind: Kind, raw: Value) -> Result<Self, AppError> {
        let invalid = || AppError::bad_request("账号命令内容无效");
        let payload = match kind {
            Kind::Create => Self::Create(serde_json::from_value(raw).map_err(|_| invalid())?),
            Kind::UpdateProfile => {
                Self::Profile(serde_json::from_value(raw).map_err(|_| invalid())?)
            }
            Kind::SetStatus => Self::Status(serde_json::from_value(raw).map_err(|_| invalid())?),
            Kind::ResetPassword => Self::Reset(serde_json::from_value(raw).map_err(|_| invalid())?),
            Kind::ChangePassword => {
                Self::Change(serde_json::from_value(raw).map_err(|_| invalid())?)
            }
            Kind::RevokeAll | Kind::Retire => {
                if !raw.as_object().is_some_and(|object| object.is_empty()) {
                    return Err(invalid());
                }
                Self::Empty
            }
        };
        match &payload {
            Self::Create(body) => {
                bounded_text(&body.username, 100, false)?;
                bounded_text(&body.real_name, 100, true)?;
                bounded_text(&body.email, 100, true)?;
                bounded_text(&body.phone, 30, true)?;
                gender(&body.gender)?;
            }
            Self::Profile(body) => {
                for (value, limit) in [
                    (&body.real_name, 100),
                    (&body.email, 100),
                    (&body.phone, 30),
                ] {
                    if let Some(value) = value {
                        bounded_text(value, limit, true)?;
                    }
                }
                if let Some(value) = &body.gender {
                    gender(value)?;
                }
            }
            Self::Status(body) if !matches!(body.status.as_str(), "ENABLED" | "DISABLED") => {
                return Err(invalid());
            }
            Self::Change(body) if body.old_password.len() > crate::password::MAX_PASSWORD_BYTES => {
                return Err(invalid());
            }
            _ => {}
        }
        Ok(payload)
    }

    fn new_password(&self) -> Option<&str> {
        match self {
            Self::Create(body) => Some(&body.password),
            Self::Reset(body) => Some(&body.new_password),
            Self::Change(body) => Some(&body.new_password),
            _ => None,
        }
    }
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct Receipt {
    operation_id: Uuid,
    target_user_id: Uuid,
    canonical_digest: String,
    state: String,
    #[serde(serialize_with = "serialize_version")]
    before_version: i64,
    #[serde(serialize_with = "serialize_version")]
    after_version: i64,
    // The constrained bridge publishes the actual affected-row counts for this
    // exact generation. Identity never reads the underlying platform tables.
    revoked_sessions: i64,
    revoked_tokens: i64,
}

async fn receipt(
    tx: &mut Transaction<'_, Postgres>,
    operation: Uuid,
    service: Uuid,
    digest: &str,
) -> Result<Option<Receipt>, AppError> {
    let owner: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT service_id,canonical_digest FROM public.identity_account_command_receipts WHERE operation_id=$1",
    )
    .bind(operation)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((owner, stored)) = owner {
        if owner != service || !equal(&stored, digest) {
            return Err(AppError::conflict("操作编号或摘要冲突"));
        }
        return sqlx::query_as(
            "SELECT operation_id,target_user_id,canonical_digest,state,before_version,after_version,revoked_sessions,revoked_tokens \
             FROM public.identity_account_command_receipts WHERE operation_id=$1 AND service_id=$2",
        )
        .bind(operation)
        .bind(service)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from);
    }
    Ok(None)
}

async fn operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<Receipt>, AppError> {
    let principal = crate::internal::authenticate(&state, &headers, "ACCOUNT_COMMAND").await?;
    let operation = canonical_id(&raw)?;
    let digest = operation_digest(query.as_deref())?;
    let mut tx = state.pool.begin().await?;
    let result = receipt(&mut tx, operation, principal.id, digest)
        .await?
        .ok_or_else(|| AppError::not_found("操作结果尚未确认"))?;
    tx.commit().await?;
    Ok(Json(result))
}

fn operation_digest(query: Option<&str>) -> Result<&str, AppError> {
    query
        .and_then(|query| query.strip_prefix("digest="))
        .filter(|digest| canonical_digest(digest))
        .ok_or_else(|| AppError::bad_request("操作摘要查询无效"))
}

async fn command(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(mut raw): ApiJson<Value>,
) -> Result<Json<Receipt>, AppError> {
    let principal = crate::internal::authenticate(&state, &headers, "ACCOUNT_COMMAND").await?;
    let body = parse_command(&raw)?;
    let operation = canonical_id(&body.operation_id)?;
    let target = canonical_id(&body.target_user_id)?;
    let expected = version(&body.expected_account_version)?;
    let expires = DateTime::parse_from_rfc3339(&body.expires_at)
        .map_err(|_| AppError::bad_request("账号命令期限无效"))?
        .with_timezone(&Utc);
    if !canonical_digest(&body.canonical_digest) {
        return Err(AppError::bad_request("账号命令摘要无效"));
    }
    raw.as_object_mut()
        .ok_or_else(|| AppError::bad_request("账号命令无效"))?
        .remove("canonicalDigest");
    let canonical = canonical_json(&raw)?;
    let digest = hex::encode(hmac_sha256(principal.secret().as_bytes(), &canonical));
    drop(canonical);
    if !equal(&digest, &body.canonical_digest) {
        return Err(AppError::conflict("账号命令摘要不匹配"));
    }
    // Never retain the plaintext request in an intent, receipt, audit or log.
    drop(raw);
    let payload = Payload::parse(body.kind, body.payload)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))")
        .bind(operation.to_string())
        .execute(&mut *tx)
        .await?;
    if let Some(receipt) = receipt(&mut tx, operation, principal.id, &digest).await? {
        tx.commit().await?;
        return Ok(Json(receipt));
    }
    ensure_deadline(&mut tx, expires).await?;
    let prepared = if let Some(password) = payload.new_password() {
        Some(
            state
                .accounts
                .prepare_password(password)
                .await
                .map_err(password_error)?,
        )
    } else {
        None
    };
    let (before, current_hash, username) = if matches!(body.kind, Kind::Create) {
        if expected != 0 || body.context.is_some() {
            return Err(AppError::conflict("新账号命令前提无效"));
        }
        let present: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.users WHERE id=$1)")
                .bind(target)
                .fetch_one(&mut *tx)
                .await?;
        if present {
            return Err(AppError::conflict("账号已存在"));
        }
        let username = if let Payload::Create(account) = &payload {
            account.username.clone()
        } else {
            return Err(AppError::bad_request("账号命令内容无效"));
        };
        (0, None, username)
    } else {
        let (actual, hash, username): (i64, String, String) = sqlx::query_as(
            "SELECT session_version,password_hash,username FROM public.users WHERE id=$1 FOR UPDATE",
        )
        .bind(target)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::not_found("账号不存在"))?;
        if actual != expected {
            return Err(AppError::conflict("账号版本已变化"));
        }
        let retired: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM public.identity_account_tombstones WHERE user_id=$1)",
        )
        .bind(target)
        .fetch_one(&mut *tx)
        .await?;
        if retired {
            return Err(AppError::conflict("账号已退役"));
        }
        (actual, Some(hash), username)
    };
    let accepted: bool =
        sqlx::query_scalar("SELECT public.platform_account_command_intent_active($1,$2,$3,$4,$5)")
            .bind(operation)
            .bind(target)
            .bind(expected)
            .bind(&digest)
            .bind(body.kind.label())
            .fetch_one(&mut *tx)
            .await?;
    if !accepted {
        return Err(AppError::conflict("账号命令未获接受或已失效"));
    }
    if let Payload::Change(change) = &payload {
        let hash = current_hash.as_deref().ok_or(AppError::Unavailable)?;
        if !state
            .passwords
            .verify(hash, &change.old_password)
            .await
            .map_err(password_error)?
        {
            return Err(AppError::conflict("原密码验证失败"));
        }
        require_context(&mut tx, body.context.as_ref(), target, expected).await?;
    } else if body.context.is_some() {
        return Err(AppError::bad_request("管理命令不接受个人上下文"));
    }
    let detail = json!({"operationId":operation,"serviceId":principal.id,"kind":body.kind.label(),"beforeVersion":before.to_string()}).to_string();
    let ip = audit::client_ip(&headers);
    let user_agent = audit::ua_of(&headers);
    audit::write_in_tx(
        &mut tx,
        audit::AuditInfo {
            user_id: Some(target),
            username: &username,
            action: "ACCOUNT_COMMAND",
            detail: &detail,
            ip: &ip,
            user_agent: &user_agent,
        },
    )
    .await?;
    // Audit storage can wait. A personal command must still prove its original
    // context immediately before its own generation change retires that source.
    if matches!(body.kind, Kind::ChangePassword) {
        require_context(&mut tx, body.context.as_ref(), target, expected).await?;
    }
    ensure_deadline(&mut tx, expires).await?;
    match &payload {
        Payload::Create(account) => {
            let prepared = prepared.as_ref().ok_or(AppError::Unavailable)?;
            let written = sqlx::query(
                "INSERT INTO public.users(id,username,password_hash,real_name,email,phone,gender) VALUES($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(target).bind(&account.username).bind(prepared.encoded()).bind(&account.real_name)
            .bind(&account.email).bind(&account.phone).bind(&account.gender)
            .execute(&mut *tx).await?.rows_affected();
            if written != 1 {
                return Err(AppError::Unavailable);
            }
        }
        Payload::Profile(profile) => {
            let written = sqlx::query(
                "UPDATE public.users SET real_name=COALESCE($2,real_name),email=COALESCE($3,email), \
                 phone=COALESCE($4,phone),gender=COALESCE($5,gender),updated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(target).bind(&profile.real_name).bind(&profile.email).bind(&profile.phone)
            .bind(&profile.gender).execute(&mut *tx).await?.rows_affected();
            if written != 1 {
                return Err(AppError::Unavailable);
            }
        }
        Payload::Status(status) => {
            let written = sqlx::query(
                "UPDATE public.users SET status=$2,updated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(target)
            .bind(&status.status)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if written != 1 {
                return Err(AppError::Unavailable);
            }
        }
        Payload::Reset(_) | Payload::Change(_) => {
            let prepared = prepared.as_ref().ok_or(AppError::Unavailable)?;
            let written = sqlx::query(
                "UPDATE public.users SET password_hash=$2,session_version=session_version+1,updated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(target).bind(prepared.encoded()).execute(&mut *tx).await?.rows_affected();
            if written != 1 {
                return Err(AppError::Unavailable);
            }
        }
        Payload::Empty if matches!(body.kind, Kind::Retire) => {
            let written = sqlx::query(
                "UPDATE public.users SET status='DISABLED',session_version=session_version+1,updated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(target).execute(&mut *tx).await?.rows_affected();
            if written != 1 {
                return Err(AppError::Unavailable);
            }
            let written = sqlx::query("INSERT INTO public.identity_account_tombstones(user_id,operation_id,retired_at) VALUES($1,$2,clock_timestamp())")
                .bind(target).bind(operation).execute(&mut *tx).await?.rows_affected();
            if written != 1 {
                return Err(AppError::Unavailable);
            }
        }
        Payload::Empty => {
            let written = sqlx::query("UPDATE public.users SET session_version=session_version+1,updated_at=clock_timestamp() WHERE id=$1")
                .bind(target).execute(&mut *tx).await?.rows_affected();
            if written != 1 {
                return Err(AppError::Unavailable);
            }
        }
    }
    let after: i64 = sqlx::query_scalar("SELECT session_version FROM public.users WHERE id=$1")
        .bind(target)
        .fetch_one(&mut *tx)
        .await?;
    let (revoked_sessions, revoked_tokens) = if reads_revocation_fact(body.kind, before, after) {
        sqlx::query_as::<_, (i64, i64)>(
                "SELECT platform_session_count,oauth_token_count FROM public.identity_account_revocation_facts \
                 WHERE user_id=$1 AND account_version=$2",
            )
            .bind(target)
            .bind(after)
            .fetch_optional(&mut *tx)
            .await?
            .filter(|(sessions, tokens)| *sessions >= 0 && *tokens >= 0)
            .ok_or(AppError::Unavailable)?
    } else {
        (0, 0)
    };
    // Receipt creation follows all dependency work. Expiry cannot be silently
    // extended by an account lock, audit wait or an expensive password worker.
    ensure_deadline(&mut tx, expires).await?;
    let written = sqlx::query(
        "INSERT INTO public.identity_account_command_receipts \
         (operation_id,service_id,target_user_id,canonical_digest,state,before_version,after_version,revoked_sessions,revoked_tokens,created_at) \
         VALUES($1,$2,$3,$4,'COMPLETED',$5,$6,$7,$8,clock_timestamp())",
    )
    .bind(operation).bind(principal.id).bind(target).bind(&digest).bind(before).bind(after)
    .bind(revoked_sessions).bind(revoked_tokens)
    .execute(&mut *tx).await?.rows_affected();
    if written != 1 {
        return Err(AppError::Unavailable);
    }
    ensure_deadline(&mut tx, expires).await?;
    tx.commit().await?;
    Ok(Json(Receipt {
        operation_id: operation,
        target_user_id: target,
        canonical_digest: digest,
        state: "COMPLETED".into(),
        before_version: before,
        after_version: after,
        revoked_sessions,
        revoked_tokens,
    }))
}

fn reads_revocation_fact(kind: Kind, before: i64, after: i64) -> bool {
    !matches!(kind, Kind::Create | Kind::UpdateProfile) && after != before
}

fn parse_command(raw: &Value) -> Result<Command, AppError> {
    if !raw
        .as_object()
        .is_some_and(|object| object.contains_key("context"))
    {
        return Err(AppError::bad_request("账号命令必须声明context"));
    }
    serde_json::from_value(raw.clone()).map_err(|_| AppError::bad_request("账号命令无效"))
}

async fn require_context(
    tx: &mut Transaction<'_, Postgres>,
    context: Option<&Context>,
    target: Uuid,
    expected: i64,
) -> Result<(), AppError> {
    let context = context.ok_or_else(|| AppError::conflict("原个人上下文无效"))?;
    if canonical_id(&context.user_id)? != target || version(&context.account_version)? != expected {
        return Err(AppError::conflict("原个人上下文不匹配"));
    }
    let active: bool =
        sqlx::query_scalar("SELECT public.platform_password_context_active($1,$2,$3,$4,$5)")
            .bind(target)
            .bind(canonical_id(&context.session_id)?)
            .bind(canonical_id(&context.tenant_id)?)
            .bind(canonical_id(&context.organization_id)?)
            .bind(expected)
            .fetch_one(&mut **tx)
            .await?;
    if active {
        Ok(())
    } else {
        Err(AppError::conflict("原个人上下文已失效"))
    }
}

async fn ensure_deadline(
    tx: &mut Transaction<'_, Postgres>,
    expires: DateTime<Utc>,
) -> Result<(), AppError> {
    let valid: bool = sqlx::query_scalar(
        "SELECT $1::timestamptz>clock_timestamp() AND $1::timestamptz<=clock_timestamp()+interval '60 seconds'",
    )
    .bind(expires).fetch_one(&mut **tx).await?;
    if valid {
        Ok(())
    } else {
        Err(AppError::conflict("账号命令已过期或期限无效"))
    }
}

fn canonical_id(raw: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(raw).map_err(|_| AppError::bad_request("账号标识无效"))?;
    if !crate::util::uuid7::is_uuid_v7(id) || id.to_string() != raw {
        return Err(AppError::bad_request("账号标识必须为规范UUIDv7"));
    }
    Ok(id)
}

fn version(raw: &str) -> Result<i64, AppError> {
    raw.parse::<i64>()
        .ok()
        .filter(|value| *value >= 0 && value.to_string() == raw)
        .ok_or_else(|| AppError::bad_request("账号版本无效"))
}

fn password_error(error: AppError) -> AppError {
    match error {
        AppError::RateLimited(_) => AppError::Unavailable,
        error => error,
    }
}

fn bounded_text(raw: &str, limit: usize, empty: bool) -> Result<(), AppError> {
    if raw.chars().count() > limit
        || raw.chars().any(char::is_control)
        || (!empty && raw.trim().is_empty())
    {
        return Err(AppError::bad_request("账号字段无效或过长"));
    }
    Ok(())
}

fn gender(raw: &str) -> Result<(), AppError> {
    if matches!(raw, "MALE" | "FEMALE" | "UNKNOWN") {
        Ok(())
    } else {
        Err(AppError::bad_request("性别字段无效"))
    }
}

fn canonical_digest(raw: &str) -> bool {
    raw.len() == 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}

fn canonical_json(raw: &Value) -> Result<Vec<u8>, AppError> {
    fn sorted(raw: &Value) -> Value {
        match raw {
            Value::Object(object) => {
                let ordered = object
                    .iter()
                    .map(|(key, value)| (key.clone(), sorted(value)))
                    .collect::<std::collections::BTreeMap<_, _>>();
                Value::Object(ordered.into_iter().collect())
            }
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            value => value.clone(),
        }
    }
    serde_json::to_vec(&sorted(raw)).map_err(|_| AppError::bad_request("账号命令内容无效"))
}

pub(crate) fn hmac_sha256(secret: &[u8], value: &[u8]) -> [u8; 32] {
    let mut key = [0_u8; 64];
    if secret.len() > key.len() {
        key[..32].copy_from_slice(&Sha256::digest(secret));
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut inner_key = key;
    let mut outer_key = key;
    for byte in &mut inner_key {
        *byte ^= 0x36;
    }
    for byte in &mut outer_key {
        *byte ^= 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(value);
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner.finalize());
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_short_and_long_key_vectors() {
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex::encode(hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn canonical_command_json_sorts_recursively_without_changing_array_order() {
        let left: Value =
            serde_json::from_str(r#"{"z":[{"b":2,"a":1},3],"a":{"c":"密","b":null}}"#).unwrap();
        let right: Value =
            serde_json::from_str(r#"{"a":{"b":null,"c":"密"},"z":[{"a":1,"b":2},3]}"#).unwrap();
        assert_eq!(
            canonical_json(&left).unwrap(),
            canonical_json(&right).unwrap()
        );
        assert_eq!(
            String::from_utf8(canonical_json(&left).unwrap()).unwrap(),
            r#"{"a":{"b":null,"c":"密"},"z":[{"a":1,"b":2},3]}"#
        );
    }

    #[test]
    fn operation_lookup_accepts_only_one_exact_digest_query() {
        let digest = "a".repeat(64);
        assert_eq!(
            operation_digest(Some(&format!("digest={digest}"))).unwrap(),
            digest
        );
        for raw in [None, Some("digest=abc"), Some("digest="), Some("other=x")] {
            assert!(operation_digest(raw).is_err());
        }
        for raw in [
            format!("digest={digest}&digest={digest}"),
            format!("digest={digest}&x=1"),
            format!("digest=%61{}", "a".repeat(63)),
        ] {
            assert!(operation_digest(Some(&raw)).is_err());
        }
    }

    #[test]
    fn account_generations_and_ids_are_canonical_and_nonnegative() {
        assert_eq!(version("0").unwrap(), 0);
        assert_eq!(version("9223372036854775807").unwrap(), i64::MAX);
        for value in ["00", "01", "+1", "-1", "1.0", "9223372036854775808"] {
            assert!(version(value).is_err());
        }
        let id = Uuid::parse_str("018f0aa3-635c-7a12-98de-56789abcdef0").unwrap();
        assert_eq!(canonical_id(&id.to_string()).unwrap(), id);
        for raw in [
            Uuid::nil().to_string(),
            id.to_string().to_uppercase(),
            "f47ac10b-58cc-4372-a567-0e02b2c3d479".into(),
        ] {
            assert!(canonical_id(&raw).is_err());
        }
    }

    #[test]
    fn payloads_deny_unknown_fields_and_retirement_cannot_request_hard_delete() {
        assert!(Payload::parse(Kind::Retire, json!({})).is_ok());
        assert!(Payload::parse(Kind::Retire, json!({"delete":true})).is_err());
        assert!(Payload::parse(Kind::RevokeAll, json!([])).is_err());
        assert!(Payload::parse(
            Kind::SetStatus,
            json!({"status":"ENABLED","isSuperAdmin":true})
        )
        .is_err());
        assert!(Payload::parse(Kind::SetStatus, json!({"status":"ACTIVE"})).is_err());
        assert!(Payload::parse(Kind::UpdateProfile, json!({"passwordHash":"$argon2id$"})).is_err());
        assert!(Payload::parse(
            Kind::UpdateProfile,
            json!({"realName":"新姓名","email":"","phone":"","gender":"UNKNOWN"})
        )
        .is_ok());
    }

    #[test]
    fn command_requires_all_fields_and_denies_platform_policy_fields() {
        let mut raw = json!({"operationId":Uuid::now_v7(),"targetUserId":Uuid::now_v7(),"expectedAccountVersion":"0","expiresAt":"2026-10-25T00:00:00Z","canonicalDigest":"a".repeat(64),"kind":"REVOKE_ALL","payload":{},"context":null});
        assert!(parse_command(&raw).is_ok());
        let mut missing_context = raw.clone();
        missing_context.as_object_mut().unwrap().remove("context");
        assert!(parse_command(&missing_context).is_err());
        raw["isSuperAdmin"] = json!(true);
        assert!(parse_command(&raw).is_err());
    }

    #[test]
    fn receipt_contains_only_operation_outcome_and_decimal_versions() {
        let receipt = Receipt {
            operation_id: Uuid::now_v7(),
            target_user_id: Uuid::now_v7(),
            canonical_digest: "a".repeat(64),
            state: "COMPLETED".into(),
            before_version: 0,
            after_version: 1,
            revoked_sessions: 2,
            revoked_tokens: 3,
        };
        let raw = serde_json::to_value(receipt).unwrap();
        assert_eq!(raw.as_object().unwrap().len(), 8);
        assert_eq!(raw["beforeVersion"], "0");
        assert_eq!(raw["afterVersion"], "1");
        assert_eq!(raw["revokedSessions"], 2);
        assert_eq!(raw["revokedTokens"], 3);
    }

    #[test]
    fn only_a_new_revoking_generation_reads_its_own_bridge_fact() {
        for kind in [Kind::Create, Kind::UpdateProfile] {
            assert!(!reads_revocation_fact(kind, 0, 0));
            assert!(!reads_revocation_fact(kind, 0, 1));
        }
        for kind in [
            Kind::SetStatus,
            Kind::ResetPassword,
            Kind::ChangePassword,
            Kind::RevokeAll,
            Kind::Retire,
        ] {
            assert!(!reads_revocation_fact(kind, 4, 4));
            assert!(reads_revocation_fact(kind, 4, 5));
        }
    }
}
