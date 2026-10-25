use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    authentication::PostgresAccountTransaction, error::AppError, extractors::ApiJson,
    state::AppState, util::audit,
};

use super::{cookies, csrf_header, digest, origin, session_csrf, store};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/sso/preauth", get(preauth))
        .route("/api/sso/login", post(login))
        .route("/api/sso/session", get(session))
        .route("/api/sso/logout", post(logout))
        .route("/api/sso/password", put(password))
        .route_layer(middleware::from_fn(no_store))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = if request.uri().query().is_some_and(|query| !query.is_empty()) {
        AppError::bad_request("账号认证入口不接受查询参数").into_response()
    } else {
        next.run(request).await
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin, Cookie"));
    response
}

fn with_cookies(body: Value, values: &[String]) -> Result<Response, AppError> {
    let mut response = Json(body).into_response();
    for value in values {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(value).map_err(|_| AppError::Unavailable)?,
        );
    }
    Ok(response)
}

fn projection(session: &store::Session, csrf: &str) -> Value {
    json!({"contractVersion":"sso-session/1",
        "account":{"id":session.user_id,"username":session.username,
            "realName":session.real_name,"avatar":session.avatar},
        "authTime":session.authenticated_at,"expiresAt":session.expires_at,"csrfToken":csrf})
}

async fn preauth(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    origin(&state, &headers, true)?;
    cookies(&headers)?;
    if let Some(retry) = state.login_limits.admit_source(&audit::client_ip(&headers)) {
        return Err(AppError::RateLimited(retry));
    }
    let token = super::secret()?;
    let csrf = super::secret()?;
    store::challenge(&state, &token, &csrf).await?;
    with_cookies(
        json!({"csrfToken":csrf,"expiresIn":state.config.sso_preauth_ttl_seconds}),
        &[super::cookie(
            super::PREAUTH_COOKIE,
            &token,
            state.config.sso_preauth_ttl_seconds,
        )],
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Login>,
) -> Result<Response, AppError> {
    origin(&state, &headers, false)?;
    let parsed = cookies(&headers)?;
    let preauth = parsed
        .preauth
        .ok_or_else(|| AppError::forbidden("缺少登录 CSRF 证明"))?;
    let csrf = csrf_header(&headers)?;
    let ip = audit::client_ip(&headers);
    if let Some(retry) = state.login_limits.admit_source(&ip) {
        return Err(AppError::RateLimited(retry));
    }
    store::consume_challenge(&state, preauth, csrf).await?;
    let username = body.username.trim();
    if username.is_empty()
        || username.len() > state.config.login_identifier_max_bytes
        || body.password.is_empty()
        || body.password.len() > 1024
    {
        return Err(AppError::bad_request("登录账号或密码无效"));
    }
    let input_key = format!("input:{}", digest(username));
    if let Some(retry) = state.login_limits.check_account(&input_key) {
        return Err(AppError::RateLimited(retry));
    }
    let Some(credential) = state
        .authentication
        .by_username(username)
        .await
        .map_err(account_authority)?
    else {
        state.login_limits.record_failure(&input_key);
        return Err(AppError::unauthorized("用户名或密码错误"));
    };
    let account_key = format!("user:{}", credential.id);
    if let Some(retry) = state.login_limits.check_account(&account_key) {
        return Err(AppError::RateLimited(retry));
    }
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(state.config.login_verify_budget_ms);
    let verified = tokio::time::timeout_at(
        deadline,
        state.authentication.verify(&credential, &body.password),
    )
    .await
    .map_err(|_| AppError::RateLimited(1))??;
    if !verified || credential.status != "ENABLED" {
        state.login_limits.record_failure(&input_key);
        state.login_limits.record_failure(&account_key);
        return Err(AppError::unauthorized("用户名或密码错误"));
    }
    let token = super::secret()?;
    let csrf = session_csrf(&token);
    let hash = digest(&token);
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT session_version FROM users WHERE id=$1 AND status='ENABLED' FOR UPDATE",
    )
    .bind(credential.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AppError::Unavailable)?;
    if current != Some(credential.account_version) {
        return Err(AppError::unauthorized("账号认证状态已变更，请重新登录"));
    }
    {
        let mut accounts = PostgresAccountTransaction::new(&mut tx);
        if !state
            .authentication
            .credential_matches(&mut accounts, &credential)
            .await
            .map_err(account_authority)?
        {
            return Err(AppError::unauthorized("账号认证状态已变更，请重新登录"));
        }
    }
    sqlx::query(
        "UPDATE users SET last_login_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1",
    )
    .bind(credential.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO sso_sessions(id,user_id,token_hash,csrf_hash,account_version,authenticated_at,expires_at) \
        VALUES($1,$2,$3,$4,$5,clock_timestamp(),clock_timestamp()+$6*interval '1 second')")
        .bind(crate::util::uuid7::new_uuid()).bind(credential.id).bind(&hash).bind(digest(&csrf))
        .bind(credential.account_version).bind(state.config.sso_session_ttl_seconds as f64)
        .execute(&mut *tx).await?;
    let session = store::session(&mut *tx, &hash).await?;
    write_audit(
        &mut tx,
        &session,
        &headers,
        "SSO_LOGIN",
        json!({"authenticated":true}),
    )
    .await?;
    ensure_deadline(&mut tx, &session.expires_at).await?;
    tx.commit().await?;
    state.login_limits.clear_account(&input_key);
    state.login_limits.clear_account(&account_key);
    with_cookies(
        projection(&session, &csrf),
        &[
            super::cookie(
                super::SESSION_COOKIE,
                &token,
                state.config.sso_session_ttl_seconds,
            ),
            super::expired_cookie(super::PREAUTH_COOKIE),
        ],
    )
}

struct Proof {
    session: store::Session,
    token_hash: String,
    csrf: String,
}

async fn proof(state: &AppState, headers: &HeaderMap, write: bool) -> Result<Proof, AppError> {
    origin(state, headers, !write)?;
    let token = cookies(headers)?
        .session
        .ok_or_else(|| AppError::unauthorized("缺少账号认证 Cookie"))?;
    let token_hash = digest(token);
    let session = store::session(&state.pool, &token_hash).await?;
    let csrf = session_csrf(token);
    if !super::constant_equal(&session.csrf_hash, &digest(&csrf)) {
        return Err(AppError::unauthorized("账号认证证明无效"));
    }
    if write && !super::constant_equal(csrf_header(headers)?, &csrf) {
        return Err(AppError::forbidden("认证 CSRF 证明无效"));
    }
    Ok(Proof {
        session,
        token_hash,
        csrf,
    })
}

async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let proof = proof(&state, &headers, false).await?;
    Ok(Json(projection(&proof.session, &proof.csrf)))
}

async fn revalidate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    proof: &Proof,
) -> Result<store::Session, AppError> {
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(proof.session.user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| AppError::Unavailable)?
        .ok_or_else(|| AppError::unauthorized("账号认证已失效"))?;
    let current = store::session(&mut **tx, &proof.token_hash).await?;
    if current.id != proof.session.id
        || current.user_id != proof.session.user_id
        || current.account_version != proof.session.account_version
        || !super::constant_equal(&current.csrf_hash, &digest(&proof.csrf))
    {
        return Err(AppError::unauthorized("账号认证已变更，请重新登录"));
    }
    Ok(current)
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    let proof = proof(&state, &headers, true).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let session = revalidate(&mut tx, &proof).await?;
    let authority_deadline = proof.session.expires_at.min(session.expires_at);
    let revoked = {
        let mut accounts = PostgresAccountTransaction::new(&mut tx);
        state
            .accounts
            .revoke_all(&mut accounts, session.user_id)
            .await?
    };
    write_audit(
        &mut tx,
        &session,
        &headers,
        "SSO_LOGOUT",
        json!({"globalLogout":true,"revokedSessions":revoked}),
    )
    .await?;
    ensure_deadline(&mut tx, &authority_deadline).await?;
    tx.commit().await?;
    cleared()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Password {
    old_password: String,
    new_password: String,
}

async fn password(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Password>,
) -> Result<Response, AppError> {
    let proof = proof(&state, &headers, true).await?;
    if body.old_password.is_empty() || body.old_password.len() > 1024 {
        return Err(AppError::bad_request("原密码超出允许长度"));
    }
    state.accounts.validate_password(&body.new_password)?;
    let account_key = format!("user:{}", proof.session.user_id);
    if let Some(retry) = state.login_limits.admit_source(&audit::client_ip(&headers)) {
        return Err(AppError::RateLimited(retry));
    }
    if let Some(retry) = state.login_limits.check_account(&account_key) {
        return Err(AppError::RateLimited(retry));
    }
    let credential = state
        .authentication
        .by_user_id(proof.session.user_id)
        .await
        .map_err(account_authority)?;
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(state.config.login_verify_budget_ms);
    let verified = tokio::time::timeout_at(
        deadline,
        state.authentication.verify(&credential, &body.old_password),
    )
    .await
    .map_err(|_| AppError::RateLimited(1))??;
    if !verified {
        state.login_limits.record_failure(&account_key);
        return Err(AppError::bad_request("原密码不正确"));
    }
    let password = state.accounts.prepare_password(&body.new_password).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let session = revalidate(&mut tx, &proof).await?;
    let authority_deadline = proof.session.expires_at.min(session.expires_at);
    if credential.account_version != session.account_version {
        return Err(AppError::unauthorized("账号认证已变更，请重新登录"));
    }
    let changed = {
        let mut accounts = PostgresAccountTransaction::new(&mut tx);
        state
            .accounts
            .replace_password(&mut accounts, session.user_id, &password, Some(&credential))
            .await?
    };
    write_audit(&mut tx,&session,&headers,"SSO_UPDATE_PASSWORD",
        json!({"passwordChanged":true,"revokedSessions":changed.revoked_sessions,
            "beforeVersion":changed.before_version.to_string(),"afterVersion":changed.after_version.to_string()})).await?;
    ensure_deadline(&mut tx, &authority_deadline).await?;
    tx.commit().await?;
    state.login_limits.clear_account(&account_key);
    cleared()
}

async fn ensure_deadline(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deadline: &chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    // The account lock stabilizes revocation, but time can advance while an
    // audit or another credential row is locked. This command has revoked its
    // own session, so test the original authority deadline without reviving it.
    let live: bool = sqlx::query_scalar("SELECT $1::timestamptz>clock_timestamp()")
        .bind(deadline)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| AppError::Unavailable)?;
    if live {
        Ok(())
    } else {
        Err(AppError::unauthorized("账号认证已过期，请重新登录"))
    }
}

fn cleared() -> Result<Response, AppError> {
    with_cookies(
        json!({"ok":true}),
        &[
            super::expired_cookie(super::SESSION_COOKIE),
            super::expired_cookie(super::PREAUTH_COOKIE),
        ],
    )
}

fn account_authority(error: AppError) -> AppError {
    match error {
        AppError::RateLimited(retry) => AppError::RateLimited(retry),
        _ => AppError::Unavailable,
    }
}

async fn write_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    session: &store::Session,
    headers: &HeaderMap,
    action: &str,
    detail: Value,
) -> Result<(), AppError> {
    audit::write_in_tx(
        tx,
        audit::AuditInfo {
            user_id: Some(session.user_id),
            username: &session.username,
            action,
            detail: &detail.to_string(),
            ip: &audit::client_ip(headers),
            user_agent: &audit::ua_of(headers),
        },
    )
    .await
}
