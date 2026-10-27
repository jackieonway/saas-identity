//! Browser-bound authorization requests; the UI never accepts a return URL.

use super::{clients, consents, context, invalid, protocol, store, OidcError, Result};
use crate::{error::AppError, extractors::ApiJson, sso::AccountSessionProof, state::AppState};
use axum::{
    extract::{Path, RawForm, RawQuery, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

const BROWSER_COOKIE: &str = "__Host-saas_oidc_browser";

fn browser(headers: &HeaderMap) -> std::result::Result<Option<String>, AppError> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE).iter() {
        let value = value
            .to_str()
            .map_err(|_| AppError::unauthorized("浏览器绑定无效"))?;
        for pair in value.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                return Err(AppError::unauthorized("浏览器绑定无效"));
            };
            if name == BROWSER_COOKIE {
                if found.is_some() || !super::canonical_secret(value) {
                    return Err(AppError::unauthorized("浏览器绑定无效"));
                }
                found = Some(value.to_owned());
            }
        }
    }
    Ok(found)
}

fn csrf(browser: &str, id: Uuid) -> String {
    super::digest(&format!("oidc-flow-csrf-v1:{browser}:{id}"))
}

fn csrf_header(headers: &HeaderMap) -> std::result::Result<&str, AppError> {
    let mut values = headers.get_all("x-csrf-token").iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::forbidden("缺少授权 CSRF 证明"))?;
    if values.next().is_some() || !super::canonical_secret(value) {
        return Err(AppError::forbidden("授权 CSRF 证明无效"));
    }
    Ok(value)
}

pub(super) async fn authorize_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response> {
    authorize(
        &state,
        &headers,
        protocol::parameters(raw.as_deref().unwrap_or(""))?,
    )
    .await
}

pub(super) async fn authorize_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: RawQuery,
    body: RawForm,
) -> Result<Response> {
    authorize(&state, &headers, protocol::form(body, query)?).await
}

fn known_error(
    client: &clients::Client,
    values: &BTreeMap<String, String>,
    issuer: &str,
    error: &'static str,
) -> Result<Response> {
    let redirect = protocol::required(values, "redirect_uri")?;
    if !client.redirect_uris.iter().any(|uri| uri == redirect) {
        return Err(invalid());
    }
    let state = values
        .get("state")
        .filter(|state| state.len() <= 512)
        .map(String::as_str)
        .unwrap_or("");
    Ok(Redirect::to(&protocol::callback(
        redirect,
        state,
        issuer,
        ("error", error),
    )?)
    .into_response())
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    values: BTreeMap<String, String>,
) -> Result<Response> {
    let issuer = super::authority(state).await?;
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(invalid());
    }
    if let Some(retry) = state
        .login_limits
        .admit_source(&crate::util::audit::client_ip(headers))
    {
        return Err(AppError::RateLimited(retry).into());
    }
    let client_id = clients::canonical_id(protocol::required(&values, "client_id")?)?;
    let initial = clients::load(&state.pool, client_id, false)
        .await?
        .ok_or_else(invalid)?;
    let redirect = protocol::required(&values, "redirect_uri")?;
    if !initial.redirect_uris.iter().any(|uri| uri == redirect) {
        return Err(invalid());
    }
    if initial.status != "ENABLED" {
        return known_error(&initial, &values, issuer, "unauthorized_client");
    }
    if values.get("response_type").map(String::as_str) != Some("code") {
        return known_error(&initial, &values, issuer, "unsupported_response_type");
    }
    let state_value = values
        .get("state")
        .filter(|value| !value.is_empty() && value.len() <= 512);
    let nonce = values
        .get("nonce")
        .filter(|value| !value.is_empty() && value.len() <= 512);
    if state_value.is_none()
        || nonce.is_none()
        || values.contains_key("request")
        || values.contains_key("request_uri")
        || values
            .get("response_mode")
            .is_some_and(|mode| mode != "query")
    {
        return known_error(&initial, &values, issuer, "invalid_request");
    }
    let mut scope: Vec<String> = values
        .get("scope")
        .map(|value| value.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    scope.sort();
    scope.dedup();
    if !scope.iter().any(|value| value == "openid")
        || scope
            .iter()
            .any(|value| !matches!(value.as_str(), "openid" | "profile" | "offline_access"))
        || (scope.iter().any(|value| value == "offline_access") && !initial.refresh_enabled)
    {
        return known_error(&initial, &values, issuer, "invalid_scope");
    }
    let challenge = values
        .get("code_challenge")
        .map(String::as_str)
        .unwrap_or("");
    let challenge_bytes = URL_SAFE_NO_PAD.decode(challenge).ok();
    if values.get("code_challenge_method").map(String::as_str) != Some("S256")
        || !challenge_bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == challenge)
    {
        return known_error(&initial, &values, issuer, "invalid_request");
    }
    let prompts: Vec<&str> = values
        .get("prompt")
        .map(|value| value.split_whitespace().collect())
        .unwrap_or_default();
    if prompts
        .iter()
        .any(|value| !matches!(*value, "none" | "login" | "consent"))
        || (prompts.contains(&"none") && prompts.len() != 1)
    {
        return known_error(&initial, &values, issuer, "invalid_request");
    }
    let max_age = match values.get("max_age") {
        None => None,
        Some(raw)
            if !raw.is_empty()
                && raw.len() <= 10
                && raw.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            match raw.parse::<i64>() {
                Ok(value) => Some(value),
                Err(_) => return known_error(&initial, &values, issuer, "invalid_request"),
            }
        }
        _ => return known_error(&initial, &values, issuer, "invalid_request"),
    };
    let original = crate::sso::browser_proof(state, headers).await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&state.pool)
        .await
        .map_err(|_| AppError::Unavailable)?;
    let force_login = prompts.contains(&"login")
        || max_age == Some(0)
        || original.as_ref().is_some_and(|proof| {
            max_age.is_some_and(|age| proof.authenticated_at + chrono::Duration::seconds(age) < now)
        });
    let proof = if force_login { None } else { original };
    if prompts.contains(&"none") && proof.is_none() {
        return known_error(&initial, &values, issuer, "login_required");
    }
    let old_browser = browser(headers)?;
    let browser = match &old_browser {
        Some(value) => value.clone(),
        None => super::secret()?,
    };
    let id = crate::util::uuid7::new_uuid();
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let proof = if let Some(proof) = proof {
        store::lock_user(&mut tx, proof.user_id).await?;
        Some(store::session(&mut *tx, proof.id, proof.user_id, proof.account_version).await?)
    } else {
        None
    };
    let client = clients::load(&mut *tx, client_id, true)
        .await?
        .ok_or_else(invalid)?;
    if client.status != "ENABLED" || client.access_policy_version != initial.access_policy_version {
        return known_error(&initial, &values, issuer, "invalid_request");
    }
    let approved = if let Some(proof) = &proof {
        consents::approved(&mut tx, proof.user_id, client.id, &scope).await?
    } else {
        false
    };
    // Approval is account/application scoped and survives global-session expiry.
    let context_required = context::required(&mut *tx, client.id).await?;
    if prompts.contains(&"none") && context_required {
        return known_error(&client, &values, issuer, "interaction_required");
    }
    let consent_required = !approved;
    if prompts.contains(&"none") && consent_required {
        return known_error(&client, &values, issuer, "consent_required");
    }
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('oidc-authorization-capacity-v1',0))",
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| AppError::Unavailable)?;
    sqlx::query("DELETE FROM oidc_authorization_requests WHERE id IN (SELECT r.id FROM oidc_authorization_requests r WHERE (r.consumed_at IS NOT NULL OR r.expires_at<=clock_timestamp()) AND NOT EXISTS(SELECT 1 FROM oidc_context_interactions c WHERE c.flow_id=r.id AND c.expires_at>clock_timestamp()) ORDER BY r.expires_at LIMIT 1024)")
        .execute(&mut *tx).await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM oidc_authorization_requests WHERE consumed_at IS NULL AND expires_at>clock_timestamp()")
        .fetch_one(&mut *tx).await.map_err(|_|AppError::Unavailable)?;
    if count >= state.config.login_max_entries as i64 {
        return Err(AppError::RateLimited(1).into());
    }
    sqlx::query("INSERT INTO oidc_authorization_requests(id,browser_hash,csrf_hash,client_id,client_policy_version,redirect_uri,scope,state,nonce,code_challenge,force_login,max_age,session_id,user_id,account_version,created_at,expires_at) \
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,clock_timestamp(),clock_timestamp()+$16*interval '1 second')")
        .bind(id).bind(super::digest(&browser)).bind(super::digest(&csrf(&browser,id))).bind(client.id).bind(client.access_policy_version)
        .bind(redirect).bind(&scope).bind(state_value.ok_or_else(invalid)?).bind(nonce.ok_or_else(invalid)?).bind(challenge)
        .bind(force_login).bind(max_age).bind(proof.as_ref().map(|proof|proof.id)).bind(proof.as_ref().map(|proof|proof.user_id))
        .bind(proof.as_ref().map(|proof|proof.account_version)).bind(state.config.oidc_interaction_ttl_seconds as f64).execute(&mut *tx).await?;
    let flow = store::flow(&mut *tx, id, false)
        .await?
        .ok_or_else(invalid)?;
    context::bind(
        &mut tx,
        &flow,
        values.get("context_request").map(String::as_str),
    )
    .await?;
    let target = if let Some(proof) = &proof {
        if !consent_required && !context_required {
            if !eligible(&mut tx, &flow, proof).await? {
                return known_error(&client, &values, issuer, "login_required");
            }
            let (code, code_expiry) = store::code(&mut tx, state, &flow, proof).await?;
            sqlx::query(
                "UPDATE oidc_authorization_requests SET consumed_at=clock_timestamp() WHERE id=$1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            store::account_audit(&mut tx, proof, headers, "OIDC_AUTHORIZE", client.id).await?;
            super::deadline(
                &mut tx,
                authentication_deadline(&flow, proof)
                    .min(flow.expires_at)
                    .min(code_expiry),
            )
            .await?;
            protocol::callback(redirect, &flow.state, issuer, ("code", &code))?
        } else {
            format!("/sso/login?flow={id}")
        }
    } else {
        format!("/sso/login?flow={id}")
    };
    tx.commit().await?;
    let mut response = Redirect::to(&target).into_response();
    if old_browser.is_none() {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "{BROWSER_COOKIE}={browser}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=86400"
            ))
            .map_err(|_| AppError::Unavailable)?,
        );
    }
    Ok(response)
}

async fn eligible(
    connection: &mut sqlx::PgConnection,
    flow: &store::Flow,
    proof: &AccountSessionProof,
) -> std::result::Result<bool, AppError> {
    sqlx::query_scalar("SELECT (NOT $1 OR $2::timestamptz >= $3::timestamptz) AND ($4::bigint IS NULL OR $4=0 OR $2::timestamptz >= clock_timestamp()-$4*interval '1 second')")
        .bind(flow.force_login).bind(proof.authenticated_at).bind(flow.created_at).bind(flow.max_age)
        .fetch_one(connection).await.map_err(|_|AppError::Unavailable)
}

fn authentication_deadline(flow: &store::Flow, proof: &AccountSessionProof) -> DateTime<Utc> {
    match flow.max_age {
        Some(age) if age > 0 => proof
            .expires_at
            .min(proof.authenticated_at + chrono::Duration::seconds(age)),
        _ => proof.expires_at,
    }
}

fn browser_match(flow: &store::Flow, browser: &str) -> std::result::Result<(), AppError> {
    if !super::equal(&flow.browser_hash, &super::digest(browser)) {
        return Err(AppError::forbidden("授权请求不属于当前浏览器"));
    }
    Ok(())
}

fn flow_error(error: OidcError) -> AppError {
    match error {
        OidcError::App(error) => error,
        _ => AppError::unauthorized("原账号认证已失效，请重新发起授权"),
    }
}

pub(super) async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> std::result::Result<Json<Value>, AppError> {
    super::authority(&state).await?;
    crate::sso::browser_origin(&state, &headers, true)?;
    let id = clients::canonical_id(&raw).map_err(|_| AppError::bad_request("授权流程 ID 无效"))?;
    let browser = browser(&headers)?.ok_or_else(|| AppError::forbidden("缺少浏览器绑定"))?;
    let initial = store::flow(&state.pool, id, false)
        .await?
        .ok_or_else(|| AppError::not_found("授权请求不存在"))?;
    browser_match(&initial, &browser)?;
    let candidate = crate::sso::browser_proof(&state, &headers).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    if let Some(proof) = &candidate {
        store::lock_user(&mut tx, proof.user_id)
            .await
            .map_err(flow_error)?;
    }
    let client = clients::load(&mut *tx, initial.client_id, true)
        .await?
        .ok_or_else(|| AppError::not_found("客户端不存在"))?;
    let mut flow = store::flow(&mut *tx, id, true)
        .await?
        .ok_or_else(|| AppError::not_found("授权请求不存在"))?;
    browser_match(&flow, &browser)?;
    super::deadline(&mut tx, flow.expires_at)
        .await
        .map_err(|_| AppError::conflict("授权请求已到期，请从应用重新发起"))?;
    if flow.consumed_at.is_some()
        || client.status != "ENABLED"
        || client.access_policy_version != flow.client_policy_version
    {
        return Err(AppError::conflict("授权请求已消费或客户端策略已变化"));
    }
    let mut account = None;
    let mut status = if flow.session_id.is_some() {
        "RESTART_REQUIRED"
    } else {
        "LOGIN_REQUIRED"
    };
    if let Some(proof) = candidate {
        match store::session(&mut *tx, proof.id, proof.user_id, proof.account_version).await {
            Ok(proof) if eligible(&mut tx, &flow, &proof).await? => {
                if flow.session_id.is_none() {
                    sqlx::query("UPDATE oidc_authorization_requests SET session_id=$2,user_id=$3,account_version=$4 WHERE id=$1 AND session_id IS NULL")
                        .bind(id).bind(proof.id).bind(proof.user_id).bind(proof.account_version).execute(&mut *tx).await?;
                    flow.session_id = Some(proof.id);
                    flow.user_id = Some(proof.user_id);
                    flow.account_version = Some(proof.account_version);
                }
                if flow.session_id == Some(proof.id)
                    && flow.user_id == Some(proof.user_id)
                    && flow.account_version == Some(proof.account_version)
                {
                    status = "CONSENT_REQUIRED";
                    account = Some(
                        json!({"id":proof.user_id,"username":proof.username,"realName":proof.real_name,"avatar":proof.avatar}),
                    );
                }
            }
            Err(OidcError::App(AppError::Unavailable)) => return Err(AppError::Unavailable),
            _ => {}
        }
    }
    if let Some(user) = flow.user_id.filter(|_| account.is_some()) {
        let approved = consents::approved(&mut tx, user, client.id, &flow.scope).await?;
        // Revalidate durable approval on every reload; stale flow state never
        // restores a user-revoked authorization.
        sqlx::query("UPDATE oidc_authorization_requests SET consented_at=CASE WHEN $2 THEN COALESCE(consented_at,clock_timestamp()) ELSE NULL END WHERE id=$1")
            .bind(flow.id).bind(approved).execute(&mut *tx).await?;
        if approved {
            flow.consented_at = Some(Utc::now());
        } else {
            flow.consented_at = None;
        }
    }
    if account.is_some()
        && flow.consented_at.is_some()
        && context::activate(&mut tx, &flow, &browser).await?.is_some()
    {
        status = "CONTEXT_SELECTION_REQUIRED";
    }
    let context_required = context::required(&mut *tx, flow.client_id).await?;
    tx.commit().await?;
    let selection = if status == "CONTEXT_SELECTION_REQUIRED" {
        context::choices(&state, &flow, &browser).await?
    } else {
        None
    };
    Ok(Json(
        json!({"status":status,"client":{"name":client.name,"purpose":client.purpose},"scopes":flow.scope,
        "csrfToken":csrf(&browser,flow.id),"account":account,"expiresAt":flow.expires_at,
        "contextSelectionRequired":context_required,"consentRemembered":flow.consented_at.is_some(),
        "contextSelection":selection.map(|s|json!({"mode":s.intent["kind"],"members":s.members,"expiresAt":s.expires_at}))}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Decision {
    action: String,
    #[serde(default, rename = "membershipId")]
    membership_id: Option<String>,
}

pub(super) async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    ApiJson(body): ApiJson<Decision>,
) -> std::result::Result<Json<Value>, AppError> {
    let issuer = super::authority(&state).await?;
    crate::sso::browser_origin(&state, &headers, false)?;
    let id = clients::canonical_id(&raw).map_err(|_| AppError::bad_request("授权流程 ID 无效"))?;
    let browser = browser(&headers)?.ok_or_else(|| AppError::forbidden("缺少浏览器绑定"))?;
    let supplied_csrf = csrf_header(&headers)?;
    if !matches!(
        body.action.as_str(),
        "consent" | "approve" | "deny" | "restart"
    ) {
        return Err(AppError::bad_request("授权操作无效"));
    }
    let initial = store::flow(&state.pool, id, false)
        .await?
        .ok_or_else(|| AppError::not_found("授权请求不存在"))?;
    browser_match(&initial, &browser)?;
    if !super::equal(&initial.csrf_hash, &super::digest(supplied_csrf))
        || !super::equal(supplied_csrf, &csrf(&browser, id))
    {
        return Err(AppError::forbidden("授权 CSRF 证明无效"));
    }
    let candidate = crate::sso::browser_proof(&state, &headers).await?;
    let membership = body
        .membership_id
        .as_deref()
        .map(clients::canonical_id)
        .transpose()
        .map_err(|_| AppError::bad_request("成员标识必须是规范 UUIDv7"))?;
    if body.action != "approve" && membership.is_some() {
        return Err(AppError::bad_request("此操作不接受成员选择"));
    }
    if body.action == "approve" {
        if context::required(&state.pool, initial.client_id).await?
            && initial.consented_at.is_none()
        {
            return Err(AppError::conflict("请先确认应用授权，再选择租户和组织"));
        }
        context::prepare(
            &state,
            &initial,
            &browser,
            candidate
                .as_ref()
                .ok_or_else(|| AppError::unauthorized("请先确认账号"))?,
            membership,
            &headers,
        )
        .await?;
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    // Approval always holds the original account lock before the client/flow.
    if matches!(body.action.as_str(), "approve" | "consent") {
        let user = initial
            .user_id
            .ok_or_else(|| AppError::unauthorized("请先登录并确认账号"))?;
        store::lock_user(&mut tx, user).await.map_err(flow_error)?;
    }
    let client = clients::load(&mut *tx, initial.client_id, true)
        .await?
        .ok_or_else(|| AppError::not_found("客户端不存在"))?;
    let flow = store::flow(&mut *tx, id, true)
        .await?
        .ok_or_else(|| AppError::not_found("授权请求不存在"))?;
    browser_match(&flow, &browser)?;
    super::deadline(&mut tx, flow.expires_at)
        .await
        .map_err(flow_error)?;
    if flow.consumed_at.is_some()
        || client.status != "ENABLED"
        || client.access_policy_version != flow.client_policy_version
    {
        return Err(AppError::conflict("授权请求已消费或客户端策略已变化"));
    }
    let target = match body.action.as_str() {
        "consent" => {
            if !context::required(&mut *tx, flow.client_id).await? || flow.consented_at.is_some() {
                return Err(AppError::conflict("当前流程不需要重复确认应用授权"));
            }
            let candidate = candidate.ok_or_else(|| AppError::unauthorized("账号认证已失效"))?;
            if flow.session_id != Some(candidate.id)
                || flow.user_id != Some(candidate.user_id)
                || flow.account_version != Some(candidate.account_version)
            {
                return Err(AppError::unauthorized("原授权账号已变化，请重新发起"));
            }
            let proof = store::session(
                &mut *tx,
                candidate.id,
                candidate.user_id,
                candidate.account_version,
            )
            .await
            .map_err(flow_error)?;
            if !eligible(&mut tx, &flow, &proof).await? {
                return Err(AppError::unauthorized("请重新认证账号"));
            }
            sqlx::query("UPDATE oidc_authorization_requests SET consented_at=clock_timestamp() WHERE id=$1 AND consented_at IS NULL")
                .bind(flow.id).execute(&mut *tx).await?;
            consents::save(&mut tx, proof.user_id, client.id, &flow.scope).await?;
            store::account_audit(&mut tx, &proof, &headers, "OIDC_CONSENT", client.id)
                .await
                .map_err(flow_error)?;
            tx.commit().await?;
            return Ok(Json(json!({"continue":true})));
        }
        "deny" => protocol::callback(
            &flow.redirect_uri,
            &flow.state,
            issuer,
            ("error", "access_denied"),
        )
        .map_err(flow_error)?,
        "restart" => {
            let next = crate::util::uuid7::new_uuid();
            sqlx::query("INSERT INTO oidc_authorization_requests(id,browser_hash,csrf_hash,client_id,client_policy_version,redirect_uri,scope,state,nonce,code_challenge,force_login,max_age,created_at,expires_at) \
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,$11,clock_timestamp(),clock_timestamp()+$12*interval '1 second')")
                .bind(next).bind(&flow.browser_hash).bind(super::digest(&csrf(&browser,next))).bind(flow.client_id).bind(flow.client_policy_version)
                .bind(&flow.redirect_uri).bind(&flow.scope).bind(&flow.state).bind(&flow.nonce).bind(&flow.code_challenge).bind(flow.max_age)
                .bind(state.config.oidc_interaction_ttl_seconds as f64).execute(&mut *tx).await?;
            context::restart(&mut tx, flow.id, next).await?;
            format!("/sso/login?flow={next}")
        }
        _ => {
            let candidate = candidate.ok_or_else(|| AppError::unauthorized("账号认证已失效"))?;
            if flow.session_id != Some(candidate.id)
                || flow.user_id != Some(candidate.user_id)
                || flow.account_version != Some(candidate.account_version)
            {
                return Err(AppError::unauthorized("原授权账号已变化，请重新发起"));
            }
            let proof = store::session(
                &mut *tx,
                candidate.id,
                candidate.user_id,
                candidate.account_version,
            )
            .await
            .map_err(flow_error)?;
            if !eligible(&mut tx, &flow, &proof).await? {
                return Err(AppError::unauthorized("请重新认证账号"));
            }
            if context::required(&mut *tx, flow.client_id).await? {
                if !consents::approved(&mut tx, proof.user_id, client.id, &flow.scope).await? {
                    return Err(AppError::conflict("应用授权已撤销，请重新确认"));
                }
            } else {
                consents::save(&mut tx, proof.user_id, client.id, &flow.scope).await?;
            }
            let (code, code_expiry) = store::code(&mut tx, &state, &flow, &proof)
                .await
                .map_err(flow_error)?;
            store::account_audit(&mut tx, &proof, &headers, "OIDC_AUTHORIZE", client.id)
                .await
                .map_err(flow_error)?;
            super::deadline(
                &mut tx,
                authentication_deadline(&flow, &proof)
                    .min(candidate.expires_at)
                    .min(code_expiry),
            )
            .await
            .map_err(flow_error)?;
            protocol::callback(&flow.redirect_uri, &flow.state, issuer, ("code", &code))
                .map_err(flow_error)?
        }
    };
    sqlx::query("UPDATE oidc_authorization_requests SET consumed_at=clock_timestamp() WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    super::deadline(&mut tx, flow.expires_at)
        .await
        .map_err(flow_error)?;
    tx.commit().await?;
    Ok(Json(json!({"redirectTo":target})))
}
