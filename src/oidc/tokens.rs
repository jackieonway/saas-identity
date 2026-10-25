//! One-use code exchange, rotating refresh families and online account authority.

use super::{clients, invalid, invalid_grant, keys, protocol, store, OidcError, Result};
use crate::{error::AppError, sso::AccountSessionProof, state::AppState};
use axum::{
    extract::{RawForm, RawQuery, State},
    http::{header, HeaderMap},
    response::Response,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct Code {
    id: Uuid,
    grant_id: Uuid,
    redirect_uri: String,
    code_challenge: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}
#[derive(sqlx::FromRow)]
struct Refresh {
    id: Uuid,
    grant_id: Uuid,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

pub(super) fn admission(state: &AppState, headers: &HeaderMap) -> Result<()> {
    if let Some(retry) = state.record_introspection_attempt(&crate::util::audit::client_ip(headers))
    {
        return Err(AppError::RateLimited(retry as u64).into());
    }
    Ok(())
}

pub(super) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: RawQuery,
    body: RawForm,
) -> Result<Json<Value>> {
    super::authority(&state).await?;
    admission(&state, &headers)?;
    let parameters = protocol::form(body, query)?;
    let client = clients::authenticate(&state, &headers, &parameters).await?;
    let grant_type = protocol::required(&parameters, "grant_type")?;
    match grant_type {
        "authorization_code" => exchange(&state, &headers, &client, &parameters).await,
        "refresh_token" => refresh(&state, &headers, &client, &parameters).await,
        _ => Err(OidcError::Protocol(
            "unsupported_grant_type",
            "Only authorization_code and refresh_token are supported",
        )),
    }
}

async fn exchange(
    state: &AppState,
    headers: &HeaderMap,
    client: &clients::Client,
    parameters: &std::collections::BTreeMap<String, String>,
) -> Result<Json<Value>> {
    let raw = protocol::required(parameters, "code")?;
    let redirect = protocol::required(parameters, "redirect_uri")?;
    let verifier = protocol::required(parameters, "code_verifier")?;
    if !super::canonical_secret(raw)
        || !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(invalid_grant());
    }
    let hash = super::digest(raw);
    let initial: Code =
        sqlx::query_as("SELECT * FROM oidc_authorization_codes WHERE token_hash=$1")
            .bind(&hash)
            .fetch_optional(&state.pool)
            .await
            .map_err(|_| AppError::Unavailable)?
            .ok_or_else(invalid_grant)?;
    let original = store::grant(&state.pool, initial.grant_id, false)
        .await?
        .ok_or_else(invalid_grant)?;
    if original.client_id != client.id {
        return Err(invalid_grant());
    }
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    // A caller must prove client, callback and verifier before replay can revoke
    // a family. Knowing a code alone cannot cause cross-client denial of service.
    if initial.redirect_uri != redirect || !super::equal(&initial.code_challenge, &challenge) {
        return Err(invalid_grant());
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    store::lock_user(&mut tx, original.user_id).await?;
    let current_client = clients::load(&mut *tx, client.id, true)
        .await?
        .ok_or_else(invalid_grant)?;
    let grant = store::grant(&mut *tx, original.id, true)
        .await?
        .ok_or_else(invalid_grant)?;
    store::valid_grant(&grant, &current_client)?;
    let code: Code =
        sqlx::query_as("SELECT * FROM oidc_authorization_codes WHERE id=$1 FOR UPDATE")
            .bind(initial.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| AppError::Unavailable)?
            .ok_or_else(invalid_grant)?;
    if code.redirect_uri != redirect || !super::equal(&code.code_challenge, &challenge) {
        return Err(invalid_grant());
    }
    if code.consumed_at.is_some() {
        store::revoke_grant(&mut tx, grant.id).await?;
        tx.commit().await?;
        return Err(invalid_grant());
    }
    super::deadline(
        &mut tx,
        initial
            .expires_at
            .min(code.expires_at)
            .min(original.expires_at)
            .min(grant.expires_at),
    )
    .await?;
    let proof = store::session(
        &mut *tx,
        grant.session_id,
        grant.user_id,
        grant.account_version,
    )
    .await?;
    let (response, issued_expiry) =
        issue(state, &mut tx, &grant, &current_client, &proof, true).await?;
    sqlx::query("UPDATE oidc_authorization_codes SET consumed_at=clock_timestamp() WHERE id=$1")
        .bind(code.id)
        .execute(&mut *tx)
        .await?;
    store::account_audit(&mut tx, &proof, headers, "OIDC_EXCHANGE_CODE", client.id).await?;
    super::deadline(
        &mut tx,
        issued_expiry
            .min(proof.expires_at)
            .min(code.expires_at)
            .min(initial.expires_at)
            .min(original.expires_at)
            .min(grant.expires_at),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(response))
}

async fn refresh(
    state: &AppState,
    headers: &HeaderMap,
    client: &clients::Client,
    parameters: &std::collections::BTreeMap<String, String>,
) -> Result<Json<Value>> {
    let raw = protocol::required(parameters, "refresh_token")?;
    if !super::canonical_secret(raw) {
        return Err(invalid_grant());
    }
    let hash = super::digest(raw);
    let initial: Refresh = sqlx::query_as("SELECT * FROM oidc_refresh_tokens WHERE token_hash=$1")
        .bind(&hash)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| AppError::Unavailable)?
        .ok_or_else(invalid_grant)?;
    let original = store::grant(&state.pool, initial.grant_id, false)
        .await?
        .ok_or_else(invalid_grant)?;
    if original.client_id != client.id {
        return Err(invalid_grant());
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    store::lock_user(&mut tx, original.user_id).await?;
    let current_client = clients::load(&mut *tx, client.id, true)
        .await?
        .ok_or_else(invalid_grant)?;
    let mut grant = store::grant(&mut *tx, original.id, true)
        .await?
        .ok_or_else(invalid_grant)?;
    store::valid_grant(&grant, &current_client)?;
    let token: Refresh = sqlx::query_as("SELECT * FROM oidc_refresh_tokens WHERE id=$1 FOR UPDATE")
        .bind(initial.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AppError::Unavailable)?
        .ok_or_else(invalid_grant)?;
    if token.used_at.is_some() {
        store::revoke_grant(&mut tx, grant.id).await?;
        tx.commit().await?;
        return Err(invalid_grant());
    }
    if token.revoked_at.is_some()
        || !current_client.refresh_enabled
        || !grant.scope.iter().any(|scope| scope == "offline_access")
    {
        return Err(invalid_grant());
    }
    super::deadline(
        &mut tx,
        initial
            .expires_at
            .min(token.expires_at)
            .min(original.expires_at)
            .min(grant.expires_at),
    )
    .await?;
    let proof = store::session(
        &mut *tx,
        grant.session_id,
        grant.user_id,
        grant.account_version,
    )
    .await?;
    if let Some(scope) = parameters.get("scope") {
        let mut requested: Vec<String> = scope.split_whitespace().map(str::to_owned).collect();
        requested.sort();
        requested.dedup();
        if !requested.iter().any(|scope| scope == "openid")
            || requested.iter().any(|scope| !grant.scope.contains(scope))
        {
            return Err(OidcError::Protocol(
                "invalid_scope",
                "Refresh scope must be a subset of the original grant",
            ));
        }
        grant.scope = requested;
        sqlx::query("UPDATE oidc_grants SET scope=$2 WHERE id=$1")
            .bind(grant.id)
            .bind(&grant.scope)
            .execute(&mut *tx)
            .await?;
    }
    let (response, issued_expiry) =
        issue(state, &mut tx, &grant, &current_client, &proof, true).await?;
    sqlx::query("UPDATE oidc_refresh_tokens SET used_at=clock_timestamp() WHERE id=$1")
        .bind(token.id)
        .execute(&mut *tx)
        .await?;
    store::account_audit(&mut tx, &proof, headers, "OIDC_REFRESH", client.id).await?;
    super::deadline(
        &mut tx,
        issued_expiry
            .min(proof.expires_at)
            .min(initial.expires_at)
            .min(token.expires_at)
            .min(original.expires_at)
            .min(grant.expires_at),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(response))
}

async fn issue(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    grant: &store::Grant,
    client: &clients::Client,
    proof: &AccountSessionProof,
    allow_refresh: bool,
) -> Result<(Value, DateTime<Utc>)> {
    let issuer = super::enabled(state)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| AppError::Unavailable)?;
    let expiry = proof
        .expires_at
        .min(grant.expires_at)
        .min(now + chrono::Duration::seconds(state.config.oidc_token_ttl_seconds));
    let exp = expiry.timestamp();
    let iat = now.timestamp();
    if exp <= iat {
        return Err(invalid_grant());
    }
    let expiry = DateTime::from_timestamp(exp, 0).ok_or_else(invalid_grant)?;
    let access = super::secret()?;
    sqlx::query("INSERT INTO oidc_access_tokens(id,grant_id,token_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5)")
        .bind(crate::util::uuid7::new_uuid()).bind(grant.id).bind(super::digest(&access)).bind(now).bind(expiry).execute(&mut **tx).await?;
    let claims = json!({"iss":issuer,"sub":proof.user_id.to_string(),"aud":client.id.to_string(),
        "exp":exp,"iat":iat,"nonce":grant.nonce,"auth_time":grant.auth_time.timestamp(),"sid":proof.id.to_string()});
    let id_token = keys::sign(state, tx, claims, expiry).await?;
    let mut response = json!({"access_token":access,"token_type":"Bearer","expires_in":exp-iat,
        "id_token":id_token,"scope":grant.scope.join(" ")});
    if allow_refresh
        && client.refresh_enabled
        && grant.scope.iter().any(|scope| scope == "offline_access")
    {
        let refresh = super::secret()?;
        sqlx::query("INSERT INTO oidc_refresh_tokens(id,grant_id,token_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5)")
            .bind(crate::util::uuid7::new_uuid()).bind(grant.id).bind(super::digest(&refresh)).bind(now).bind(grant.expires_at.min(proof.expires_at)).execute(&mut **tx).await?;
        response["refresh_token"] = json!(refresh);
    }
    super::deadline(tx, expiry).await?;
    Ok((response, expiry))
}

#[derive(sqlx::FromRow)]
pub(super) struct LiveToken {
    pub(super) grant_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) session_id: Uuid,
    pub(super) client_id: Uuid,
    pub(super) account_version: i64,
    pub(super) client_policy_version: i64,
    pub(super) auth_time: DateTime<Utc>,
    pub(super) client_purpose: String,
    pub(super) allowed_member_types: Vec<String>,
    pub(super) scope: Vec<String>,
    pub(super) expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    pub(super) username: String,
    pub(super) real_name: String,
    pub(super) avatar: String,
}

pub(super) async fn live<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    hash: &str,
    refresh: bool,
) -> Result<Option<LiveToken>> {
    let token_table = if refresh {
        "oidc_refresh_tokens"
    } else {
        "oidc_access_tokens"
    };
    let unused = if refresh {
        " AND t.used_at IS NULL"
    } else {
        ""
    };
    let sql=format!("SELECT g.id AS grant_id,g.user_id,g.session_id,g.client_id,g.account_version,g.client_policy_version,g.auth_time,c.purpose AS client_purpose,c.allowed_member_types,g.scope,LEAST(t.expires_at,g.expires_at,s.expires_at) AS expires_at,t.created_at,u.username,COALESCE(u.real_name,'') AS real_name,COALESCE(u.avatar,'') AS avatar \
        FROM {token_table} t JOIN oidc_grants g ON g.id=t.grant_id JOIN oidc_clients c ON c.id=g.client_id \
        JOIN sso_sessions s ON s.id=g.session_id AND s.user_id=g.user_id JOIN users u ON u.id=g.user_id \
        WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp(){unused} \
        AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp() AND c.status='ENABLED' AND c.access_policy_version=g.client_policy_version \
        AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.account_version=g.account_version \
        AND u.status='ENABLED' AND u.session_version=g.account_version");
    sqlx::query_as(&sql)
        .bind(hash)
        .fetch_optional(executor)
        .await
        .map_err(|_| AppError::Unavailable.into())
}

fn bearer(headers: &HeaderMap) -> Result<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(OidcError::InvalidToken)?;
    if values.next().is_some() {
        return Err(OidcError::InvalidToken);
    }
    let (scheme, token) = value.split_once(' ').ok_or(OidcError::InvalidToken)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || !super::canonical_secret(token) {
        return Err(OidcError::InvalidToken);
    }
    Ok(token)
}

pub(super) async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>> {
    super::authority(&state).await?;
    admission(&state, &headers)?;
    if query.is_some_and(|query| !query.is_empty()) {
        return Err(invalid());
    }
    let token = bearer(&headers)?;
    let proof = live(&state.pool, &super::digest(token), false)
        .await?
        .ok_or(OidcError::InvalidToken)?;
    let mut result = json!({"sub":proof.user_id});
    if proof.scope.iter().any(|scope| scope == "profile") {
        result["preferred_username"] = json!(proof.username);
        result["name"] = json!(proof.real_name);
        if !proof.avatar.is_empty() {
            result["picture"] = json!(proof.avatar);
        }
    }
    Ok(Json(result))
}

pub(super) async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: RawQuery,
    body: RawForm,
) -> Result<Json<Value>> {
    let issuer = super::authority(&state).await?;
    admission(&state, &headers)?;
    let parameters = protocol::form(body, query)?;
    let client = clients::authenticate(&state, &headers, &parameters).await?;
    let token = protocol::required(&parameters, "token")?;
    if !super::canonical_secret(token) {
        return Ok(Json(json!({"active":false})));
    }
    let hash = super::digest(token);
    let proof = match live(&state.pool, &hash, false).await? {
        Some(proof) => Some(proof),
        None => live(&state.pool, &hash, true).await?,
    };
    match proof.filter(|proof| proof.client_id == client.id) {
        Some(proof) => Ok(Json(
            json!({"active":true,"client_id":proof.client_id,"sub":proof.user_id,"scope":proof.scope.join(" "),
            "token_type":"Bearer","exp":proof.expires_at.timestamp(),"iat":proof.created_at.timestamp(),
            "iss":issuer,"aud":proof.client_id,"sid":proof.session_id,
            "accountProof":{"contractVersion":"oidc-account-proof/1","grantId":proof.grant_id,
            "accountVersion":proof.account_version.to_string(),"clientPolicyVersion":proof.client_policy_version.to_string(),
            "clientPurpose":proof.client_purpose,"allowedMemberTypes":proof.allowed_member_types,
            "authTime":proof.auth_time.timestamp()}}),
        )),
        None => Ok(Json(json!({"active":false}))),
    }
}

pub(super) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: RawQuery,
    body: RawForm,
) -> Result<Response> {
    use axum::response::IntoResponse;
    super::authority(&state).await?;
    admission(&state, &headers)?;
    let parameters = protocol::form(body, query)?;
    let client = clients::authenticate(&state, &headers, &parameters).await?;
    let token = protocol::required(&parameters, "token")?;
    if !super::canonical_secret(token) {
        return Ok(axum::http::StatusCode::OK.into_response());
    }
    let hash = super::digest(token);
    let id:Option<Uuid>=sqlx::query_scalar("SELECT g.id FROM oidc_grants g WHERE g.client_id=$1 AND \
        (EXISTS(SELECT 1 FROM oidc_access_tokens t WHERE t.grant_id=g.id AND t.token_hash=$2) OR EXISTS(SELECT 1 FROM oidc_refresh_tokens r WHERE r.grant_id=g.id AND r.token_hash=$2)) LIMIT 1")
        .bind(client.id).bind(hash).fetch_optional(&state.pool).await.map_err(|_|AppError::Unavailable)?;
    if let Some(id) = id {
        let original = store::grant(&state.pool, id, false)
            .await?
            .ok_or_else(invalid_grant)?;
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|_| AppError::Unavailable)?;
        store::lock_user(&mut tx, original.user_id).await?;
        let current = clients::load(&mut *tx, client.id, true)
            .await?
            .ok_or(OidcError::InvalidClient)?;
        if current.status != "ENABLED"
            || current.access_policy_version != client.access_policy_version
        {
            return Err(OidcError::InvalidClient);
        }
        store::grant(&mut *tx, id, true)
            .await?
            .ok_or_else(invalid_grant)?;
        store::revoke_grant(&mut tx, id).await?;
        tx.commit().await?;
    }
    Ok(axum::http::StatusCode::OK.into_response())
}
