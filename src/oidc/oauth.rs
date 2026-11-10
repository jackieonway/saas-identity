//! Unified public authorization-code endpoints over the canonical `auth_*`
//! registry. This is the only public authorization and token authority.

use super::{keys, protocol, subjects, OidcError, Result};
use crate::{
    auth_consent::{self, ConsentAuditContext, ConsentState, ScopeGrant},
    error::AppError,
    sso::{self, AccountSessionProof},
    state::AppState,
    util::{audit, uuid7},
};
use axum::{
    extract::{Path, RawForm, RawQuery, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const BROWSER_COOKIE: &str = "__Host-saas_oauth_browser";

#[cfg(test)]
mod client_policy_tests;
pub(super) mod customer_proof;
pub(super) mod logout;
#[cfg(test)]
mod phase22_tests;
pub(super) mod resource_proof;
pub(super) mod unified_context;

#[derive(sqlx::FromRow, Clone)]
struct Client {
    auto_authorize: bool,
    access_token_ttl_seconds: Option<i64>,
    refresh_token_ttl_seconds: Option<i64>,
    client_token_ttl_seconds: Option<i64>,
    id: Uuid,
    client_id: String,
    name: String,
    app_purpose: String,
    ownership: String,
    approved_scopes: Vec<String>,
    client_type: String,
    runtime_kind: String,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    status: String,
    subject_mode: String,
    context_mode: Option<String>,
    allowed_member_types: Vec<String>,
    environment: String,
    policy_version: i64,
    application_id: Uuid,
    application_status: String,
    application_projection_version: i64,
}

#[derive(sqlx::FromRow)]
struct ClientRegistration {
    status: String,
    policy_version: i64,
    subject_mode: String,
    context_mode: Option<String>,
    environment: String,
    grant_types: Vec<String>,
}

#[derive(sqlx::FromRow, Clone)]
struct Scope {
    resource_id: Uuid,
    scope_id: Uuid,
    scope_name: String,
    audience: String,
    resource_key: String,
}

#[derive(sqlx::FromRow, Clone)]
struct Flow {
    id: Uuid,
    client_id: Uuid,
    user_id: Option<Uuid>,
    source_session_id: Option<Uuid>,
    account_version: Option<i64>,
    auth_time: Option<DateTime<Utc>>,
    client_policy_version: i64,
    application_projection_version: i64,
    redirect_uri: String,
    state_digest: String,
    state_value: String,
    nonce_digest: Option<String>,
    nonce_value: String,
    code_challenge: String,
    scope_ids: Vec<Uuid>,
    browser_digest: String,
    csrf_digest: String,
    force_login: bool,
    force_consent: bool,
    max_age_seconds: Option<i64>,
    prior_session_id: Option<Uuid>,
    status: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct CodeExchange {
    id: Uuid,
    request_id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    consent_id: Uuid,
    consent_generation: i64,
    consent_group_version: i64,
    code_digest: String,
    code_expires_at: DateTime<Utc>,
    code_consumed_at: Option<DateTime<Utc>>,
    redirect_uri: String,
    client_policy_version: i64,
    application_projection_version: i64,
    scope_ids: Vec<Uuid>,
    nonce_value: String,
    nonce_digest: Option<String>,
    state_value: String,
    state_digest: String,
    force_login: bool,
    created_at: DateTime<Utc>,
    source_session_id: Option<Uuid>,
    account_version: Option<i64>,
    auth_time: Option<DateTime<Utc>>,
    max_age_seconds: Option<i64>,
    status: String,
}

#[derive(sqlx::FromRow)]
struct LiveAccess {
    token_id: Uuid,
    grant_id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    consent_id: Uuid,
    consent_generation: i64,
    source_session_id: Uuid,
    account_version: i64,
    auth_time: DateTime<Utc>,
    grant_expires_at: DateTime<Utc>,
    client_policy_version: i64,
    application_projection_version: i64,
    consent_group_version: i64,
    scope_ids: Vec<Uuid>,
    context_mode: String,
    context_ref: Option<Uuid>,
    offline_access: bool,
    token_created_at: DateTime<Utc>,
    token_expires_at: DateTime<Utc>,
}

struct VerifiedUserAccess {
    live: LiveAccess,
    client: Client,
    profile: subjects::OidcProfile,
    scopes: Vec<Scope>,
    // Private account projections retain this exact validation snapshot without
    // expanding the common user/machine verification enum by the profile data.
    snapshot: Box<UserProofSnapshot>,
}

struct UserProofSnapshot {
    username: String,
    real_name: String,
    avatar: String,
    source_expires_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct LiveMachineAccess {
    token_id: Uuid,
    grant_id: Uuid,
    client_id: Uuid,
    credential_version: i64,
    client_policy_version: i64,
    application_projection_version: i64,
    scope_ids: Vec<Uuid>,
    audiences: Vec<String>,
    token_created_at: DateTime<Utc>,
    token_expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct MachineCredential {
    client: Client,
    credential_version: i64,
    secret_digest: String,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct MachineCredentialState {
    revoked_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct MachineGrantState {
    revoked_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    client_policy_version: i64,
    application_projection_version: i64,
    credential_version: Option<i64>,
    scope_ids: Vec<Uuid>,
}

struct VerifiedMachineAccess {
    live: LiveMachineAccess,
    client: Client,
    scopes: Vec<Scope>,
    expires_at: DateTime<Utc>,
}

enum VerifiedAccess {
    User(VerifiedUserAccess),
    Machine(VerifiedMachineAccess),
}

#[derive(sqlx::FromRow)]
struct GrantSnapshot {
    revoked_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    consent_group_version: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct RefreshLookup {
    token_id: Uuid,
    consumed_at: Option<DateTime<Utc>>,
    family_id: Uuid,
    grant_id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    consent_id: Option<Uuid>,
    consent_generation: Option<i64>,
    consent_group_version: Option<i64>,
    source_session_id: Option<Uuid>,
    account_version: Option<i64>,
    auth_time: Option<DateTime<Utc>>,
    client_policy_version: i64,
    application_projection_version: i64,
    scope_ids: Vec<Uuid>,
    grant_expires_at: DateTime<Utc>,
    context_mode: String,
    context_ref: Option<Uuid>,
    offline_access: bool,
}

#[derive(sqlx::FromRow)]
struct RefreshFamily {
    grant_id: Uuid,
    absolute_expires_at: DateTime<Utc>,
    idle_expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    version: i64,
}

#[derive(sqlx::FromRow)]
struct RefreshToken {
    generation: i64,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    token_digest: String,
}

#[derive(Clone, Copy, sqlx::FromRow)]
struct RefreshRevocationTarget {
    token_id: Uuid,
    family_id: Uuid,
    grant_id: Uuid,
    user_id: Option<Uuid>,
    consent_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct RefreshGrant {
    client_id: Uuid,
    user_id: Uuid,
    consent_id: Option<Uuid>,
    consent_generation: Option<i64>,
    consent_group_version: Option<i64>,
    source_session_id: Option<Uuid>,
    account_version: Option<i64>,
    auth_time: Option<DateTime<Utc>>,
    client_policy_version: i64,
    application_projection_version: i64,
    scope_ids: Vec<Uuid>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    context_mode: String,
    context_ref: Option<Uuid>,
    offline_access: bool,
}

type AccessTokenState = (Option<DateTime<Utc>>, DateTime<Utc>, DateTime<Utc>);

pub(super) async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Response> {
    let issuer = super::authority(&state).await?;
    let values = protocol::parameters(query.as_deref().unwrap_or(""))?;
    let client_id = protocol::required(&values, "client_id")?;
    protocol_client_budget(&state, client_id)?;
    let redirect_uri = protocol::required(&values, "redirect_uri")?;
    let client = client(&state, client_id).await?;
    // Validate the callback before any branch can send a protocol error there.
    if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
        return Err(super::invalid());
    }
    let context_request = values.get("context_request").map(String::as_str);
    match client.context_mode.as_deref() {
        Some("ACCOUNT_ONLY") if context_request.is_some() => return Err(super::invalid()),
        Some("PLATFORM_CONTEXT")
            if client.client_type != "CONFIDENTIAL"
                || client.runtime_kind != "WEB_BFF"
                || client.allowed_member_types.len() != 1
                || context_request.is_none_or(|value| !canonical_secret(value)) =>
        {
            return callback_error(
                redirect_uri,
                values.get("state").map(String::as_str).unwrap_or(""),
                issuer,
                "invalid_request",
            );
        }
        Some("ACCOUNT_ONLY" | "PLATFORM_CONTEXT") => {}
        _ => {
            return callback_error(
                redirect_uri,
                values.get("state").map(String::as_str).unwrap_or(""),
                issuer,
                "unauthorized_client",
            );
        }
    }
    if client.status != "ENABLED"
        || client.application_status != "APPROVED"
        || client.subject_mode != "USER"
        || !matches!(
            client.context_mode.as_deref(),
            Some("ACCOUNT_ONLY" | "PLATFORM_CONTEXT")
        )
        || client.environment != expected_environment(&state)
    {
        return callback_error(
            redirect_uri,
            values.get("state").map(String::as_str).unwrap_or(""),
            issuer,
            "unauthorized_client",
        );
    }
    if protocol::required(&values, "response_type")? != "code" {
        return callback_error(
            redirect_uri,
            values.get("state").map(String::as_str).unwrap_or(""),
            issuer,
            "unsupported_response_type",
        );
    }
    if values.contains_key("request") || values.contains_key("request_uri") {
        return callback_error(
            redirect_uri,
            values.get("state").map(String::as_str).unwrap_or(""),
            issuer,
            "invalid_request",
        );
    }
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        return callback_error(
            redirect_uri,
            values.get("state").map(String::as_str).unwrap_or(""),
            issuer,
            "unauthorized_client",
        );
    }
    let state_value = protocol::required(&values, "state")?;
    if !(16..=512).contains(&state_value.len()) {
        return Err(super::invalid());
    }
    let nonce = protocol::required(&values, "nonce")?;
    if !(8..=512).contains(&nonce.len()) {
        return Err(super::invalid());
    }
    let challenge = protocol::required(&values, "code_challenge")?;
    if challenge.len() != 43
        || !challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        || protocol::required(&values, "code_challenge_method")? != "S256"
    {
        return Err(super::invalid());
    }
    if values
        .get("response_mode")
        .is_some_and(|mode| mode != "query")
    {
        return Err(super::invalid());
    }
    let requested_scopes = requested_scopes(&values)?;
    let scopes = resolve_scopes(&state, &client, &requested_scopes).await?;
    if scopes
        .iter()
        .any(|scope| scope.scope_name == "offline_access")
        && !client
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
    {
        return callback_error(redirect_uri, state_value, issuer, "unauthorized_client");
    }
    let prompts = prompt_set(values.get("prompt").map(String::as_str))?;
    let max_age = match values.get("max_age") {
        Some(raw) if !raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit()) => {
            Some(raw.parse::<i64>().map_err(|_| super::invalid())?)
        }
        Some(_) => return Err(super::invalid()),
        None => None,
    };
    if max_age.is_some_and(|age| age > 86_400) {
        return Err(super::invalid());
    }
    let initial_proof = sso::browser_proof(&state, &headers).await?;
    let max_age_expired = initial_proof.as_ref().is_some_and(|proof| {
        max_age.is_some_and(|age| proof.authenticated_at < Utc::now() - Duration::seconds(age))
    });
    let force_login = prompts.contains("login") || max_age == Some(0) || max_age_expired;
    let proof = if force_login {
        None
    } else {
        initial_proof.clone()
    };
    if prompts.contains("none") && (force_login || proof.is_none()) {
        return callback_error(redirect_uri, state_value, issuer, "login_required");
    }

    let (browser, set_cookie) = browser_value(&headers)?;
    let flow_id = uuid7::new_uuid();
    let csrf = csrf_for(&browser, flow_id);
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let consent = if let Some(proof) = proof.as_ref() {
        Some(
            consent_coverage(
                &mut tx,
                proof,
                &client,
                &scopes,
                &headers,
                prompts.contains("consent"),
            )
            .await?,
        )
    } else {
        ensure_client_current(&mut tx, &client).await?;
        None
    };
    let sufficient = matches!(&consent, Some(ConsentState::Sufficient { .. }));
    let forced_consent = prompts.contains("consent");
    if prompts.contains("none") && (!sufficient || forced_consent) {
        tx.rollback().await.map_err(|_| AppError::Unavailable)?;
        return callback_error(redirect_uri, state_value, issuer, "consent_required");
    }
    let expires = insert_flow(
        &mut tx,
        &client,
        &scopes,
        &browser,
        &csrf,
        state_value,
        nonce,
        challenge,
        redirect_uri,
        proof.as_ref(),
        force_login,
        forced_consent,
        max_age,
        if force_login {
            initial_proof.as_ref().map(|proof| proof.id)
        } else {
            None
        },
        flow_id,
        &state,
    )
    .await?;
    unified_context::bind(
        &mut tx,
        &client,
        flow_id,
        expires,
        redirect_uri,
        state_value,
        nonce,
        challenge,
        context_request,
    )
    .await?;
    let target = if sufficient
        && !forced_consent
        && client.context_mode.as_deref() == Some("ACCOUNT_ONLY")
    {
        let ConsentState::Sufficient {
            consent_id,
            generation,
            ..
        } = consent.ok_or_else(super::invalid_grant)?
        else {
            return Err(super::invalid_grant());
        };
        let proof = proof.as_ref().ok_or_else(super::invalid_grant)?;
        let group_version = consent_group_version(&mut tx, consent_id).await?;
        let code = issue_code(
            &mut tx,
            flow_id,
            client.id,
            proof.user_id,
            consent_id,
            generation,
            group_version,
            proof.expires_at.min(expires),
        )
        .await?;
        audit_authorize(&mut tx, proof, &headers, client.id, "AUTH_AUTHORIZE_REUSED").await?;
        protocol::callback(redirect_uri, state_value, issuer, ("code", &code))?
    } else {
        format!("/oauth/login?flow={flow_id}")
    };
    tx.commit().await?;
    let mut response = Redirect::to(&target).into_response();
    if set_cookie {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "{BROWSER_COOKIE}={browser}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=86400"
            ))
            .map_err(|_| AppError::Unavailable)?,
        );
    }
    Ok(response)
}

async fn consent_coverage(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    client: &Client,
    scopes: &[Scope],
    headers: &HeaderMap,
    forced: bool,
) -> Result<ConsentState> {
    let grants = to_grants(scopes);
    let coverage = auth_consent::sufficient(tx, proof, client.id, &grants).await?;
    if matches!(coverage, ConsentState::Sufficient { .. })
        || forced
        || !client.auto_authorize
        || client.ownership != "FIRST_PARTY"
        || client.subject_mode != "USER"
        || scopes
            .iter()
            .any(|scope| scope.scope_name == "offline_access")
    {
        return Ok(coverage);
    }
    // Revalidate the live policy under the same locks used by consent checks.
    // An explicit user revocation or a shared group still requires confirmation.
    let eligible: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_clients c JOIN auth_applications a ON a.application_id=c.application_id \
         JOIN auth_consent_group_clients gc ON gc.client_id=c.id WHERE c.id=$1 AND c.auto_authorize AND c.policy_version=$3 \
         AND c.status='ENABLED' AND a.ownership='FIRST_PARTY' AND a.status='APPROVED' \
         AND (SELECT count(*) FROM auth_consent_group_clients members WHERE members.group_id=gc.group_id)=1 \
         AND NOT EXISTS(SELECT 1 FROM auth_consents consent WHERE consent.user_id=$2 AND consent.group_id=gc.group_id AND consent.status='REVOKED'))")
        .bind(client.id).bind(proof.user_id).bind(client.policy_version).fetch_one(&mut **tx).await?;
    if !eligible {
        return Ok(coverage);
    }
    let ip = audit::client_ip(headers);
    let agent = audit::ua_of(headers);
    auth_consent::approve(
        tx,
        proof,
        client.id,
        &grants,
        ConsentAuditContext {
            ip: &ip,
            user_agent: &agent,
        },
    )
    .await?;
    audit_authorize(tx, proof, headers, client.id, "AUTH_CONSENT_AUTO_APPROVE").await?;
    Ok(auth_consent::sufficient(tx, proof, client.id, &grants).await?)
}

pub(super) async fn get_interaction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let flow_id = parse_id(&id)?;
    sso::browser_origin(&state, &headers, true)?;
    let browser = browser_from_cookie(&headers)?;
    let proof = sso::browser_proof(&state, &headers).await?;
    let flow = get_flow(&state, flow_id).await?;
    ensure_flow_live(&flow)?;
    check_browser(&flow, &browser)?;
    let client = client_by_internal_id(&state, flow.client_id).await?;
    if flow.client_policy_version != client.policy_version
        || flow.application_projection_version != client.application_projection_version
        || client.status != "ENABLED"
        || client.application_status != "APPROVED"
    {
        return Err(AppError::conflict("应用授权策略已变化，请重新发起登录").into());
    }
    let platform_context = client.context_mode.as_deref() == Some("PLATFORM_CONTEXT");
    let mut status = "LOGIN_REQUIRED";
    let mut account = None;
    let mut auto_redirect = None;
    let mut context_selection = None;
    if let Some(proof) = proof
        .as_ref()
        .filter(|proof| flow_proof_acceptable(&flow, proof))
    {
        let scopes = scopes_by_ids(&state, &flow.scope_ids).await?;
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|_| AppError::Unavailable)?;
        let coverage = consent_coverage(
            &mut tx,
            proof,
            &client,
            &scopes,
            &headers,
            flow.force_consent,
        )
        .await?;
        bind_flow_user(&mut tx, &flow, proof).await?;
        match coverage {
            ConsentState::Sufficient {
                consent_id,
                generation,
                ..
            } if !flow.force_consent && !platform_context => {
                let group_version = consent_group_version(&mut tx, consent_id).await?;
                let code = issue_code(
                    &mut tx,
                    flow.id,
                    client.id,
                    proof.user_id,
                    consent_id,
                    generation,
                    group_version,
                    proof.expires_at.min(flow.expires_at),
                )
                .await?;
                audit_authorize(&mut tx, proof, &headers, client.id, "AUTH_AUTHORIZE_REUSED")
                    .await?;
                let target = protocol::callback(
                    &flow.redirect_uri,
                    &flow.state_value,
                    super::authority(&state).await?,
                    ("code", &code),
                )?;
                tx.commit().await?;
                auto_redirect = Some(target);
            }
            ConsentState::Sufficient { .. } if !flow.force_consent && platform_context => {
                let mut activated = flow.clone();
                activated.user_id = Some(proof.user_id);
                activated.source_session_id = Some(proof.id);
                activated.account_version = Some(proof.account_version);
                activated.auth_time = Some(proof.authenticated_at);
                unified_context::activate(&mut tx, &activated, &browser).await?;
                tx.commit().await?;
                let choices = unified_context::choices(&state, &activated, &browser)
                    .await?
                    .ok_or(AppError::Unavailable)?;
                status = "CONTEXT_SELECTION_REQUIRED";
                account = Some(
                    json!({"id":proof.user_id,"username":proof.username,"realName":proof.real_name}),
                );
                context_selection = Some(json!({
                    "mode":choices.intent["kind"],
                    "members":choices.members,
                    "expiresAt":choices.expires_at
                }));
            }
            _ => {
                status = "CONSENT_REQUIRED";
                account = Some(
                    json!({"id":proof.user_id,"username":proof.username,"realName":proof.real_name}),
                );
                tx.commit().await?;
            }
        }
    } else if flow.user_id.is_some() || flow.source_session_id.is_some() {
        status = "RESTART_REQUIRED";
    }
    if let Some(redirect_to) = auto_redirect {
        return Ok(Json(
            json!({"status":"AUTO_REDIRECT","redirectTo":redirect_to}),
        ));
    }
    let scope_rows = scopes_by_ids(&state, &flow.scope_ids).await?;
    let scopes = scope_rows
        .iter()
        .map(|scope| scope.scope_name.clone())
        .collect::<Vec<_>>();
    let purpose = if platform_context {
        match client.allowed_member_types.as_slice() {
            [member_type] if member_type == "EMPLOYEE" => "PLATFORM_CONSOLE",
            [member_type] if member_type == "CUSTOMER" => "CUSTOMER_PORTAL",
            _ => return Err(AppError::Unavailable.into()),
        }
    } else {
        "ACCOUNT"
    };
    Ok(Json(json!({
        "status": status,
        "client":{"name":client.name,"purpose":purpose,"purposeDescription":client.app_purpose,
            "allowedMemberTypes":client.allowed_member_types,"contextMode":client.context_mode},
        "scopes":scopes,
        "account":account,
        "contextSelection":context_selection,
        "contextSelectionRequired":platform_context && status=="CONSENT_REQUIRED",
        "csrfToken":csrf_for(&browser, flow.id),
        "expiresAt":flow.expires_at
    })))
}

pub(super) async fn submit_interaction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<InteractionInput>,
) -> Result<Json<Value>> {
    let flow_id = parse_id(&id)?;
    sso::browser_origin(&state, &headers, false)?;
    let browser = browser_from_cookie(&headers)?;
    let csrf = one_header(&headers, "x-csrf-token")?
        .ok_or_else(|| AppError::forbidden("授权 CSRF 证明无效"))?;
    let flow = get_flow(&state, flow_id).await?;
    ensure_flow_live(&flow)?;
    check_browser(&flow, &browser)?;
    if !super::equal(&flow.csrf_digest, &super::digest(csrf)) {
        return Err(AppError::forbidden("授权 CSRF 证明无效").into());
    }
    let issuer = super::authority(&state).await?;
    let client = client_by_internal_id(&state, flow.client_id).await?;
    match body.action.as_str() {
        "deny" => {
            let changed = sqlx::query(
                "UPDATE public.auth_authorization_requests SET status='DENIED',version=version+1 \
                 WHERE id=$1 AND status='PENDING' AND expires_at>clock_timestamp()",
            )
            .bind(flow.id)
            .execute(&state.pool)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(AppError::conflict("授权请求已过期或处理").into());
            }
            let callback = protocol::callback(
                &flow.redirect_uri,
                &flow.state_value,
                issuer,
                ("error", "access_denied"),
            )?;
            Ok(Json(json!({"redirectTo":callback})))
        }
        "restart" => {
            let initial = sso::browser_proof(&state, &headers).await?;
            let new_flow = uuid7::new_uuid();
            let csrf = csrf_for(&browser, new_flow);
            let scopes = scopes_by_ids(&state, &flow.scope_ids).await?;
            let mut tx = state
                .pool
                .begin()
                .await
                .map_err(|_| AppError::Unavailable)?;
            let changed = sqlx::query(
                "UPDATE public.auth_authorization_requests SET status='DENIED',version=version+1 \
                 WHERE id=$1 AND status='PENDING' AND expires_at>clock_timestamp()",
            )
            .bind(flow.id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(AppError::conflict("授权请求已过期或处理").into());
            }
            let expires = clone_flow_for_restart(
                &mut tx,
                &flow,
                &scopes,
                &browser,
                &csrf,
                new_flow,
                initial.as_ref(),
                &state,
            )
            .await?;
            if !expires {
                return Err(AppError::Unavailable.into());
            }
            unified_context::restart(&mut tx, flow.id, new_flow).await?;
            tx.commit().await?;
            Ok(Json(
                json!({"redirectTo":format!("/oauth/login?flow={new_flow}")}),
            ))
        }
        "consent" => {
            if client.context_mode.as_deref() != Some("PLATFORM_CONTEXT") {
                return Err(super::invalid());
            }
            consent_only(&state, &headers, &flow, &client).await
        }
        "approve" => {
            if client.context_mode.as_deref() == Some("PLATFORM_CONTEXT") {
                let member = body
                    .membership_id
                    .as_deref()
                    .map(parse_id)
                    .transpose()?
                    .ok_or_else(|| AppError::bad_request("请选择成员身份"))?;
                let proof = sso::browser_proof(&state, &headers)
                    .await?
                    .ok_or_else(|| AppError::unauthorized("请先登录并确认账号"))?;
                if !flow_proof_acceptable(&flow, &proof) {
                    return Err(AppError::conflict("授权账号已变化，请重新发起登录").into());
                }
                unified_context::prepare(&state, &flow, &browser, &proof, member, &headers).await?;
            } else if body.membership_id.is_some() {
                return Err(super::invalid());
            }
            approve_flow(&state, &headers, &flow, &client, issuer).await
        }
        _ => Err(super::invalid()),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct InteractionInput {
    action: String,
    #[serde(default)]
    membership_id: Option<String>,
}

async fn consent_only(
    state: &AppState,
    headers: &HeaderMap,
    flow: &Flow,
    client: &Client,
) -> Result<Json<Value>> {
    let proof = sso::browser_proof(state, headers)
        .await?
        .ok_or_else(|| AppError::unauthorized("请先登录并确认账号"))?;
    if !flow_proof_acceptable(flow, &proof) {
        return Err(AppError::conflict("授权账号已变化，请重新发起登录").into());
    }
    let scopes = scopes_by_ids(state, &flow.scope_ids).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let coverage =
        auth_consent::sufficient(&mut tx, &proof, client.id, &to_grants(&scopes)).await?;
    if !matches!(coverage, ConsentState::Sufficient { .. }) || flow.force_consent {
        let ip = audit::client_ip(headers);
        let user_agent = audit::ua_of(headers);
        auth_consent::approve(
            &mut tx,
            &proof,
            client.id,
            &to_grants(&scopes),
            ConsentAuditContext {
                ip: &ip,
                user_agent: &user_agent,
            },
        )
        .await?;
    }
    ensure_current_policy_matches_flow(&mut tx, flow, client).await?;
    bind_flow_user(&mut tx, flow, &proof).await?;
    let changed = sqlx::query(
        "UPDATE public.auth_authorization_requests \
         SET force_consent=false,version=version+1 \
         WHERE id=$1 AND status='PENDING' AND expires_at>clock_timestamp()",
    )
    .bind(flow.id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::conflict("授权请求已过期或已处理").into());
    }
    audit_authorize(
        &mut tx,
        &proof,
        headers,
        client.id,
        "AUTH_CONSENT_CONFIRMED",
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"continue":true})))
}

fn flow_proof_acceptable(flow: &Flow, proof: &AccountSessionProof) -> bool {
    if flow.force_login
        && (flow.prior_session_id == Some(proof.id) || proof.authenticated_at < flow.created_at)
    {
        return false;
    }
    if let Some(user_id) = flow.user_id {
        if flow.source_session_id != Some(proof.id)
            || flow.account_version != Some(proof.account_version)
            || flow.auth_time != Some(proof.authenticated_at)
            || user_id != proof.user_id
        {
            return false;
        }
    }
    if let Some(max_age) = flow.max_age_seconds.filter(|age| *age > 0) {
        if proof.authenticated_at < Utc::now() - Duration::seconds(max_age) {
            return false;
        }
    }
    true
}

async fn client(state: &AppState, client_id: &str) -> Result<Client> {
    let client: Client = sqlx::query_as(
        "SELECT c.id,c.client_id,a.display_name AS name,a.purpose AS app_purpose,a.ownership,a.approved_scopes, \
         c.client_type,c.runtime_kind,c.grant_types,c.token_endpoint_auth_method,c.redirect_uris,c.post_logout_redirect_uris,c.status, \
         c.subject_mode,c.context_mode,c.allowed_member_types,c.environment,c.policy_version,c.application_id, \
         c.auto_authorize,c.access_token_ttl_seconds,c.refresh_token_ttl_seconds,c.client_token_ttl_seconds, \
         a.status AS application_status,a.projection_version AS application_projection_version \
         FROM public.auth_clients c JOIN public.auth_applications a ON a.application_id=c.application_id \
         WHERE c.client_id=$1",
    )
    .bind(client_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| OidcError::Protocol("invalid_request", "Unknown client"))?;
    reviewed_client(state, client).await
}

async fn client_by_internal_id(state: &AppState, id: Uuid) -> Result<Client> {
    let client: Client = sqlx::query_as(
        "SELECT c.id,c.client_id,a.display_name AS name,a.purpose AS app_purpose,a.ownership,a.approved_scopes, \
         c.client_type,c.runtime_kind,c.grant_types,c.token_endpoint_auth_method,c.redirect_uris,c.post_logout_redirect_uris,c.status, \
         c.subject_mode,c.context_mode,c.allowed_member_types,c.environment,c.policy_version,c.application_id, \
         c.auto_authorize,c.access_token_ttl_seconds,c.refresh_token_ttl_seconds,c.client_token_ttl_seconds, \
         a.status AS application_status,a.projection_version AS application_projection_version \
         FROM public.auth_clients c JOIN public.auth_applications a ON a.application_id=c.application_id \
         WHERE c.id=$1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| OidcError::from(AppError::not_found("授权请求不存在")))?;
    reviewed_client(state, client).await
}

async fn reviewed_client(state: &AppState, mut client: Client) -> Result<Client> {
    if client.ownership != "THIRD_PARTY" {
        return Ok(client);
    }
    let account_only = client.subject_mode == "USER"
        && client.context_mode.as_deref() == Some("ACCOUNT_ONLY")
        && client.allowed_member_types.is_empty()
        && matches!(
            (client.runtime_kind.as_str(), client.client_type.as_str()),
            ("WEB_BFF", "CONFIDENTIAL") | ("SPA", "PUBLIC") | ("NATIVE", "PUBLIC")
        )
        && client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
        && client
            .grant_types
            .iter()
            .all(|grant| matches!(grant.as_str(), "authorization_code" | "refresh_token"))
        && !client.redirect_uris.is_empty();
    let approved = if account_only {
        sqlx::query_scalar::<_,bool>(
            "SELECT EXISTS(SELECT 1 FROM public.auth_application_admissions admission \
             WHERE admission.application_id=$1 AND admission.environment=$2 AND admission.status='APPROVED' \
               AND $3::text[] <@ admission.redirect_uris AND $4::text[] <@ admission.post_logout_redirect_uris \
               AND EXISTS(SELECT 1 FROM public.auth_client_permissions p JOIN public.auth_resources r ON r.id=p.resource_id \
                   JOIN public.auth_scopes s ON s.id=p.scope_id AND s.resource_id=p.resource_id \
                   WHERE p.client_id=$5 AND r.resource_key='userinfo' AND s.scope_name='openid') \
               AND NOT EXISTS(SELECT 1 FROM public.auth_client_permissions p JOIN public.auth_resources r ON r.id=p.resource_id \
                   JOIN public.auth_scopes s ON s.id=p.scope_id AND s.resource_id=p.resource_id \
                   WHERE p.client_id=$5 AND (r.resource_key<>'userinfo' OR r.status<>'ACTIVE' OR s.status<>'ACTIVE' \
                       OR NOT s.scope_name=ANY(admission.scopes) OR NOT s.scope_name=ANY(ARRAY['openid','profile']::text[]))))",
        ).bind(client.application_id).bind(&client.environment).bind(&client.redirect_uris).bind(&client.post_logout_redirect_uris).bind(client.id)
        .fetch_one(&state.pool).await?
    } else {
        false
    };
    if !approved {
        client.application_status = "SUSPENDED".to_owned();
    }
    Ok(client)
}

async fn resolve_scopes(state: &AppState, client: &Client, names: &[String]) -> Result<Vec<Scope>> {
    let scopes: Vec<Scope> = sqlx::query_as(
        "SELECT p.resource_id,p.scope_id,s.scope_name,r.audience,r.resource_key \
         FROM public.auth_client_permissions p \
         JOIN public.auth_scopes s ON s.id=p.scope_id AND s.resource_id=p.resource_id AND s.status='ACTIVE' \
         JOIN public.auth_resources r ON r.id=p.resource_id AND r.status='ACTIVE' \
         WHERE p.client_id=$1 AND s.scope_name=ANY($2) \
           AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp()) \
         ORDER BY s.scope_name,p.resource_id,p.scope_id",
    )
    .bind(client.id)
    .bind(names)
    .fetch_all(&state.pool)
    .await?;
    let found = scopes
        .iter()
        .map(|scope| scope.scope_name.clone())
        .collect::<BTreeSet<_>>();
    if names.iter().any(|name| !found.contains(name))
        || scopes
            .iter()
            .filter(|scope| scope.scope_name == "openid")
            .any(|scope| scope.resource_key != "userinfo")
        || !scopes
            .iter()
            .any(|scope| scope.scope_name == "openid" && scope.resource_key == "userinfo")
        || names
            .iter()
            .any(|name| !client.approved_scopes.iter().any(|scope| scope == name))
    {
        return Err(OidcError::Protocol(
            "invalid_scope",
            "Requested scope is not approved",
        ));
    }
    Ok(scopes)
}

fn requested_scopes(values: &BTreeMap<String, String>) -> Result<Vec<String>> {
    let raw = protocol::required(values, "scope")?;
    let names = raw
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unique = names.iter().collect::<BTreeSet<_>>();
    if names.is_empty()
        || names.len() > 128
        || names.len() != unique.len()
        || !names.iter().any(|name| name == "openid")
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > 128
                || !name.as_bytes()[0].is_ascii_lowercase()
                || !name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b':' | b'-')
                })
        })
    {
        return Err(OidcError::Protocol(
            "invalid_scope",
            "Requested scope is malformed or does not include openid",
        ));
    }
    let mut sorted = names;
    sorted.sort();
    Ok(sorted)
}

fn prompt_set(raw: Option<&str>) -> Result<BTreeSet<String>> {
    let Some(raw) = raw else {
        return Ok(BTreeSet::new());
    };
    let prompts = raw
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unique = prompts.iter().collect::<BTreeSet<_>>();
    if prompts
        .iter()
        .any(|prompt| !matches!(prompt.as_str(), "login" | "consent" | "none"))
        || prompts.len() != unique.len()
        || (prompts.iter().any(|prompt| prompt == "none") && prompts.len() != 1)
    {
        return Err(super::invalid());
    }
    Ok(prompts.into_iter().collect())
}

fn to_grants(scopes: &[Scope]) -> Vec<ScopeGrant> {
    scopes
        .iter()
        .map(|scope| ScopeGrant {
            resource_id: scope.resource_id,
            scope_id: scope.scope_id,
        })
        .collect()
}

async fn scopes_by_ids(state: &AppState, ids: &[Uuid]) -> Result<Vec<Scope>> {
    let scopes: Vec<Scope> = sqlx::query_as(
        "SELECT s.resource_id,s.id AS scope_id,s.scope_name,r.audience,r.resource_key \
         FROM public.auth_scopes s JOIN public.auth_resources r ON r.id=s.resource_id \
         WHERE s.id=ANY($1) AND s.status='ACTIVE' AND r.status='ACTIVE' \
         ORDER BY s.scope_name,s.resource_id,s.id",
    )
    .bind(ids)
    .fetch_all(&state.pool)
    .await?;
    if scopes.len() != ids.len() {
        return Err(OidcError::Protocol(
            "invalid_grant",
            "The authorization proof is invalid or expired",
        ));
    }
    Ok(scopes)
}

async fn ensure_client_current(tx: &mut Transaction<'_, Postgres>, client: &Client) -> Result<()> {
    let application: Option<(String, i64)> = sqlx::query_as(
        "SELECT status,projection_version FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(client.application_id)
    .fetch_optional(&mut **tx)
    .await?;
    let registration: Option<(String, i64, String, String, String)> = sqlx::query_as(
        "SELECT status,policy_version,subject_mode,COALESCE(context_mode,''),environment \
         FROM public.auth_clients WHERE id=$1 AND application_id=$2 FOR SHARE",
    )
    .bind(client.id)
    .bind(client.application_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((app_status, app_version)) = application else {
        return Err(AppError::forbidden("应用不可用").into());
    };
    let Some((status, policy_version, subject_mode, context_mode, environment)) = registration
    else {
        return Err(AppError::forbidden("客户端不可用").into());
    };
    if app_status != "APPROVED"
        || app_version != client.application_projection_version
        || status != "ENABLED"
        || policy_version != client.policy_version
        || subject_mode != "USER"
        || !matches!(context_mode.as_str(), "ACCOUNT_ONLY" | "PLATFORM_CONTEXT")
        || environment != client.environment
    {
        return Err(AppError::forbidden("客户端策略已变化").into());
    }
    Ok(())
}

fn expected_environment(state: &AppState) -> &'static str {
    if state.config.is_production() {
        "production"
    } else {
        "test"
    }
}

#[allow(clippy::too_many_arguments)] // Persists one immutable, validated OAuth request atomically.
async fn insert_flow(
    tx: &mut Transaction<'_, Postgres>,
    client: &Client,
    scopes: &[Scope],
    browser: &str,
    csrf: &str,
    state_value: &str,
    nonce: &str,
    challenge: &str,
    redirect_uri: &str,
    proof: Option<&AccountSessionProof>,
    force_login: bool,
    force_consent: bool,
    max_age: Option<i64>,
    prior_session_id: Option<Uuid>,
    id: Uuid,
    state: &AppState,
) -> Result<DateTime<Utc>> {
    let scope_ids = scopes
        .iter()
        .map(|scope| scope.scope_id)
        .collect::<Vec<_>>();
    let expires: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO public.auth_authorization_requests( \
           id,client_id,user_id,source_session_id,account_version,auth_time,client_policy_version, \
           application_projection_version,redirect_uri,state_digest,state_value,nonce_digest,nonce_value, \
           code_challenge,code_challenge_method,scope_ids,browser_digest,csrf_digest,force_login, \
           force_consent,max_age_seconds,prior_session_id,status,version,created_at,expires_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'S256',$15,$16,$17,$18,$19,$20,$21, \
           'PENDING',1,clock_timestamp(),LEAST(clock_timestamp()+LEAST($22,300)*interval '1 second',COALESCE($23::timestamptz,'infinity'::timestamptz))) \
         RETURNING expires_at",
    )
    .bind(id)
    .bind(client.id)
    .bind(proof.map(|proof| proof.user_id))
    .bind(proof.map(|proof| proof.id))
    .bind(proof.map(|proof| proof.account_version))
    .bind(proof.map(|proof| proof.authenticated_at))
    .bind(client.policy_version)
    .bind(client.application_projection_version)
    .bind(redirect_uri)
    .bind(super::digest(state_value))
    .bind(state_value)
    .bind(super::digest(nonce))
    .bind(nonce)
    .bind(challenge)
    .bind(scope_ids)
    .bind(super::digest(browser))
    .bind(super::digest(csrf))
    .bind(force_login)
    .bind(force_consent)
    .bind(max_age)
    .bind(prior_session_id)
    .bind(state.config.oidc_interaction_ttl_seconds)
    .bind(proof.map(|proof| proof.expires_at))
    .fetch_one(&mut **tx)
    .await?;
    Ok(expires)
}

async fn get_flow(state: &AppState, id: Uuid) -> Result<Flow> {
    sqlx::query_as(
        "SELECT id,client_id,user_id,source_session_id,account_version,auth_time,client_policy_version, \
         application_projection_version,redirect_uri,state_digest,state_value,nonce_digest,nonce_value, \
         code_challenge,scope_ids,browser_digest,csrf_digest,force_login,force_consent,max_age_seconds, \
         prior_session_id,status,created_at,expires_at,consumed_at \
         FROM public.auth_authorization_requests WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("授权请求不存在").into())
}

fn ensure_flow_live(flow: &Flow) -> Result<()> {
    if flow.status != "PENDING" || flow.consumed_at.is_some() || flow.expires_at <= Utc::now() {
        return Err(OidcError::Protocol(
            "invalid_request",
            "The authorization request is no longer active",
        ));
    }
    Ok(())
}

fn check_browser(flow: &Flow, browser: &str) -> Result<()> {
    if super::equal(&flow.browser_digest, &super::digest(browser)) {
        Ok(())
    } else {
        Err(AppError::forbidden("授权请求不属于当前浏览器").into())
    }
}

fn parse_id(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value).map_err(|_| super::invalid())?;
    if uuid7::is_uuid_v7(id) && id.to_string() == value {
        Ok(id)
    } else {
        Err(super::invalid())
    }
}

fn canonical_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(super::invalid());
    }
    value
        .map(|value| value.to_str().map_err(|_| super::invalid()))
        .transpose()
}

fn browser_value(headers: &HeaderMap) -> Result<(String, bool)> {
    let mut browser = None;
    for header_value in headers.get_all(header::COOKIE).iter() {
        let raw = header_value.to_str().map_err(|_| super::invalid())?;
        for pair in raw.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name == BROWSER_COOKIE {
                if browser.is_some() || !canonical_secret(value) {
                    return Err(super::invalid());
                }
                browser = Some(value.to_owned());
            }
        }
    }
    match browser {
        Some(browser) => Ok((browser, false)),
        None => Ok((sso::opaque_secret()?, true)),
    }
}

fn browser_from_cookie(headers: &HeaderMap) -> Result<String> {
    Ok(browser_value(headers)?.0)
}

fn csrf_for(browser: &str, flow_id: Uuid) -> String {
    super::digest(&format!("saas-identity/oauth-csrf/1:{browser}:{flow_id}"))
}

fn callback_error(redirect_uri: &str, state: &str, issuer: &str, error: &str) -> Result<Response> {
    let target = protocol::callback(redirect_uri, state, issuer, ("error", error))?;
    Ok(Redirect::to(&target).into_response())
}

async fn consent_group_version(
    tx: &mut Transaction<'_, Postgres>,
    consent_id: Uuid,
) -> Result<i64> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT c.group_version,g.version FROM public.auth_consents c \
         JOIN public.auth_consent_groups g ON g.id=c.group_id \
         WHERE c.id=$1 AND c.status='ACTIVE' AND g.status='ACTIVE' FOR SHARE OF c,g",
    )
    .bind(consent_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((confirmed, current)) = row else {
        return Err(super::invalid_grant());
    };
    if confirmed != current {
        return Err(super::invalid_grant());
    }
    Ok(current)
}

#[allow(clippy::too_many_arguments)] // Code fields mirror the consent/session fence committed in one transaction.
async fn issue_code(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    consent_id: Uuid,
    generation: i64,
    group_version: i64,
    max_expiry: DateTime<Utc>,
) -> Result<String> {
    let code = sso::opaque_secret()?;
    let inserted = sqlx::query(
        "INSERT INTO public.auth_authorization_codes( \
           id,request_id,client_id,user_id,consent_id,consent_generation,consent_group_version, \
           code_digest,expires_at,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,LEAST(clock_timestamp()+interval '60 seconds',$9),clock_timestamp())",
    )
    .bind(uuid7::new_uuid())
    .bind(request_id)
    .bind(client_id)
    .bind(user_id)
    .bind(consent_id)
    .bind(generation)
    .bind(group_version)
    .bind(super::digest(&code))
    .bind(max_expiry)
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(AppError::Unavailable.into());
    }
    let changed = sqlx::query(
        "UPDATE public.auth_authorization_requests SET status='AUTHORIZED',version=version+1 \
         WHERE id=$1 AND status='PENDING' AND user_id=$2 AND expires_at>clock_timestamp()",
    )
    .bind(request_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(super::invalid_grant());
    }
    Ok(code)
}

async fn bind_flow_user(
    tx: &mut Transaction<'_, Postgres>,
    flow: &Flow,
    proof: &AccountSessionProof,
) -> Result<()> {
    match (flow.user_id, flow.source_session_id, flow.account_version) {
        (Some(user), Some(session), Some(version))
            if user == proof.user_id && session == proof.id && version == proof.account_version =>
        {
            Ok(())
        }
        (None, None, None) => {
            let changed = sqlx::query(
                "UPDATE public.auth_authorization_requests SET user_id=$2,source_session_id=$3, \
                 account_version=$4,auth_time=$5,version=version+1 \
                 WHERE id=$1 AND status='PENDING' AND user_id IS NULL AND source_session_id IS NULL",
            )
            .bind(flow.id)
            .bind(proof.user_id)
            .bind(proof.id)
            .bind(proof.account_version)
            .bind(proof.authenticated_at)
            .execute(&mut **tx)
            .await?
            .rows_affected();
            if changed == 1 {
                Ok(())
            } else {
                Err(AppError::conflict("授权账号已变化，请重新发起登录").into())
            }
        }
        _ => Err(AppError::conflict("授权账号已变化，请重新发起登录").into()),
    }
}

async fn audit_authorize(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    headers: &HeaderMap,
    client_id: Uuid,
    action: &'static str,
) -> Result<()> {
    let detail = json!({"clientId":client_id,"protocol":"oauth-authorization-code"}).to_string();
    let ip = audit::client_ip(headers);
    let user_agent = audit::ua_of(headers);
    audit::write_in_tx(
        tx,
        audit::AuditInfo {
            user_id: Some(proof.user_id),
            username: &proof.username,
            action,
            detail: &detail,
            ip: &ip,
            user_agent: &user_agent,
        },
    )
    .await?;
    Ok(())
}

async fn audit_refresh(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    headers: &HeaderMap,
    client_id: Uuid,
    family_id: Uuid,
    generation: i64,
    reused: bool,
) -> Result<()> {
    let action = if reused {
        "OAUTH_REFRESH_REUSE"
    } else {
        "OAUTH_REFRESH"
    };
    let detail = json!({
        "clientId":client_id,
        "familyId":family_id,
        "generation":generation,
        "reused":reused
    })
    .to_string();
    let ip = audit::client_ip(headers);
    let user_agent = audit::ua_of(headers);
    audit::write_in_tx(
        tx,
        audit::AuditInfo {
            user_id: Some(proof.user_id),
            username: &proof.username,
            action,
            detail: &detail,
            ip: &ip,
            user_agent: &user_agent,
        },
    )
    .await?;
    Ok(())
}

async fn approve_flow(
    state: &AppState,
    headers: &HeaderMap,
    flow: &Flow,
    client: &Client,
    issuer: &str,
) -> Result<Json<Value>> {
    let proof = sso::browser_proof(state, headers)
        .await?
        .ok_or_else(|| AppError::unauthorized("请先登录并确认账号"))?;
    if !flow_proof_acceptable(flow, &proof) {
        return Err(AppError::conflict("授权账号已变化，请重新发起登录").into());
    }
    let scopes = scopes_by_ids(state, &flow.scope_ids).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let coverage =
        auth_consent::sufficient(&mut tx, &proof, client.id, &to_grants(&scopes)).await?;
    let consent_id = match coverage {
        ConsentState::Sufficient { consent_id, .. } if !flow.force_consent => consent_id,
        _ => {
            let ip = audit::client_ip(headers);
            let user_agent = audit::ua_of(headers);
            let context = ConsentAuditContext {
                ip: &ip,
                user_agent: &user_agent,
            };
            auth_consent::approve(&mut tx, &proof, client.id, &to_grants(&scopes), context)
                .await?
                .consent_id
        }
    };
    ensure_current_policy_matches_flow(&mut tx, flow, client).await?;
    let consent_row: (i64, i64) = sqlx::query_as(
        "SELECT generation,group_version FROM public.auth_consents WHERE id=$1 AND user_id=$2 AND status='ACTIVE' FOR SHARE",
    )
    .bind(consent_id)
    .bind(proof.user_id)
    .fetch_one(&mut *tx)
    .await?;
    let current_group = consent_group_version(&mut tx, consent_id).await?;
    if current_group != consent_row.1 {
        return Err(super::invalid_grant());
    }
    bind_flow_user(&mut tx, flow, &proof).await?;
    let selection_deadline = unified_context::selection_deadline(&mut tx, flow).await?;
    let code_deadline = selection_deadline
        .map(|deadline| deadline.min(proof.expires_at).min(flow.expires_at))
        .unwrap_or_else(|| proof.expires_at.min(flow.expires_at));
    let code = issue_code(
        &mut tx,
        flow.id,
        client.id,
        proof.user_id,
        consent_id,
        consent_row.0,
        current_group,
        code_deadline,
    )
    .await?;
    audit_authorize(
        &mut tx,
        &proof,
        headers,
        client.id,
        "AUTH_AUTHORIZE_CONFIRMED",
    )
    .await?;
    let callback = protocol::callback(
        &flow.redirect_uri,
        &flow.state_value,
        issuer,
        ("code", &code),
    )?;
    tx.commit().await?;
    Ok(Json(json!({"redirectTo":callback})))
}

async fn ensure_current_policy_matches_flow(
    tx: &mut Transaction<'_, Postgres>,
    flow: &Flow,
    client: &Client,
) -> Result<()> {
    let application: Option<(String, i64)> = sqlx::query_as(
        "SELECT status,projection_version FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(client.application_id)
    .fetch_optional(&mut **tx)
    .await?;
    let registration: Option<(String, i64)> = sqlx::query_as(
        "SELECT status,policy_version FROM public.auth_clients WHERE id=$1 FOR SHARE",
    )
    .bind(client.id)
    .fetch_optional(&mut **tx)
    .await?;
    if application != Some(("APPROVED".to_owned(), flow.application_projection_version))
        || registration != Some(("ENABLED".to_owned(), flow.client_policy_version))
    {
        return Err(AppError::conflict("应用授权策略已变化，请重新发起登录").into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Restart copies a fixed request snapshot while rebinding only browser/session state.
async fn clone_flow_for_restart(
    tx: &mut Transaction<'_, Postgres>,
    flow: &Flow,
    scopes: &[Scope],
    browser: &str,
    csrf: &str,
    new_id: Uuid,
    current_proof: Option<&AccountSessionProof>,
    state: &AppState,
) -> Result<bool> {
    let scope_ids = scopes
        .iter()
        .map(|scope| scope.scope_id)
        .collect::<Vec<_>>();
    let expires: Option<DateTime<Utc>> = sqlx::query_scalar(
        "INSERT INTO public.auth_authorization_requests( \
           id,client_id,user_id,source_session_id,account_version,auth_time,client_policy_version, \
           application_projection_version,redirect_uri,state_digest,state_value,nonce_digest,nonce_value, \
           code_challenge,code_challenge_method,scope_ids,browser_digest,csrf_digest,force_login, \
           force_consent,max_age_seconds,prior_session_id,status,version,created_at,expires_at) \
         VALUES($1,$2,NULL,NULL,NULL,NULL,$3,$4,$5,$6,$7,$8,$9,$10,'S256',$11,$12,$13,true,$14,$15,$16, \
           'PENDING',1,clock_timestamp(),clock_timestamp()+LEAST($17,300)*interval '1 second') RETURNING expires_at",
    )
    .bind(new_id)
    .bind(flow.client_id)
    .bind(flow.client_policy_version)
    .bind(flow.application_projection_version)
    .bind(&flow.redirect_uri)
    .bind(&flow.state_digest)
    .bind(&flow.state_value)
    .bind(&flow.nonce_digest)
    .bind(&flow.nonce_value)
    .bind(&flow.code_challenge)
    .bind(scope_ids)
    .bind(super::digest(browser))
    .bind(super::digest(csrf))
    .bind(flow.force_consent)
    .bind(flow.max_age_seconds)
    .bind(current_proof.map(|proof| proof.id).or(flow.source_session_id))
    .bind(state.config.oidc_interaction_ttl_seconds)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(expires.is_some())
}

pub(super) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    RawForm(form): RawForm,
) -> Result<Json<Value>> {
    super::authority(&state).await?;
    let values = protocol::form(RawForm(form), RawQuery(query))?;
    match values.get("grant_type").map(String::as_str) {
        Some("client_credentials") => {
            return client_credentials_token(&state, &headers, &values).await;
        }
        Some("refresh_token") => return refresh_token(&state, &headers, &values).await,
        Some("authorization_code") => {}
        _ => {
            return Err(OidcError::Protocol(
                "unsupported_grant_type",
                "Supported grants are authorization_code, refresh_token and client_credentials",
            ));
        }
    }
    if values.keys().any(|key| {
        !matches!(
            key.as_str(),
            "grant_type" | "code" | "redirect_uri" | "code_verifier" | "client_id"
        )
    }) {
        return Err(super::invalid());
    }
    let client = authenticate_token_client(&state, &headers, &values).await?;
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        return Err(OidcError::Protocol(
            "unauthorized_client",
            "The client is not allowed to use authorization_code",
        ));
    }
    let code = protocol::required(&values, "code")?;
    if !canonical_secret(code) {
        return Err(super::invalid_grant());
    }
    let redirect_uri = protocol::required(&values, "redirect_uri")?;
    let verifier = protocol::required(&values, "code_verifier")?;
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(super::invalid_grant());
    }
    let challenge = pkce_challenge(verifier);
    let exchange = load_code(&state, &super::digest(code)).await?;
    if exchange.client_id != client.id
        || exchange.redirect_uri != redirect_uri
        || !super::equal(&exchange.code_digest, &super::digest(code))
        || exchange
            .nonce_digest
            .as_deref()
            .is_none_or(|value| !super::equal(value, &super::digest(&exchange.nonce_value)))
        || !super::equal(
            &exchange.state_digest,
            &super::digest(&exchange.state_value),
        )
        || !super::equal(
            &exchange_client_challenge(&state, exchange.request_id).await?,
            &challenge,
        )
        || exchange.status != "AUTHORIZED"
        || exchange.code_expires_at <= Utc::now()
        || exchange.code_consumed_at.is_some()
        || exchange.client_policy_version != client.policy_version
        || exchange.application_projection_version != client.application_projection_version
    {
        return Err(super::invalid_grant());
    }
    exchange_authorization(&state, &headers, &client, code, exchange).await
}

fn client_authentication_error(error: OidcError) -> OidcError {
    match error {
        OidcError::App(
            error @ (AppError::Unavailable | AppError::RateLimited(_) | AppError::Server(_)),
        ) => OidcError::App(error),
        _ => OidcError::InvalidClient,
    }
}

fn protocol_client_budget(state: &AppState, id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 1024 {
        return Err(OidcError::InvalidClient);
    }
    state.admit_protocol_client(id).map_err(OidcError::from)
}

async fn authenticate_token_client(
    state: &AppState,
    headers: &HeaderMap,
    values: &BTreeMap<String, String>,
) -> Result<Client> {
    let authorization = one_header(headers, header::AUTHORIZATION.as_str())?;
    let client_id = if let Some(authorization) = authorization {
        let encoded = authorization
            .strip_prefix("Basic ")
            .filter(|value| value.len() <= 2048)
            .ok_or(OidcError::InvalidClient)?;
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| OidcError::InvalidClient)?;
        if STANDARD.encode(&decoded) != encoded {
            return Err(OidcError::InvalidClient);
        }
        let decoded = std::str::from_utf8(&decoded).map_err(|_| OidcError::InvalidClient)?;
        let (id, secret) = decoded.split_once(':').ok_or(OidcError::InvalidClient)?;
        let id = protocol::decode_component(id).map_err(|_| OidcError::InvalidClient)?;
        let secret = protocol::decode_component(secret).map_err(|_| OidcError::InvalidClient)?;
        if values
            .get("client_id")
            .is_some_and(|body_id| body_id != &id)
        {
            return Err(OidcError::InvalidClient);
        }
        protocol_client_budget(state, &id)?;
        let client = client(state, &id)
            .await
            .map_err(client_authentication_error)?;
        if client.client_type != "CONFIDENTIAL"
            || client.token_endpoint_auth_method != "client_secret_basic"
            || !client
                .grant_types
                .iter()
                .any(|grant| matches!(grant.as_str(), "authorization_code" | "refresh_token"))
        {
            return Err(OidcError::InvalidClient);
        }
        let digest = super::digest(&secret);
        let valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM public.auth_client_credentials credential \
             WHERE credential.client_id=$1 AND credential.secret_digest=$2 \
               AND credential.revoked_at IS NULL \
               AND credential.created_at+interval '90 days'>clock_timestamp() \
               AND (credential.expires_at IS NULL OR credential.expires_at>clock_timestamp()))",
        )
        .bind(client.id)
        .bind(&digest)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| AppError::Unavailable)?;
        if !valid {
            return Err(OidcError::InvalidClient);
        }
        id
    } else {
        let id = values.get("client_id").ok_or(OidcError::InvalidClient)?;
        protocol_client_budget(state, id)?;
        id.clone()
    };
    let client = client(state, &client_id)
        .await
        .map_err(client_authentication_error)?;
    if client.status != "ENABLED"
        || client.application_status != "APPROVED"
        || client.environment != expected_environment(state)
        || client.subject_mode != "USER"
        || !matches!(
            client.context_mode.as_deref(),
            Some("ACCOUNT_ONLY" | "PLATFORM_CONTEXT")
        )
        || !client
            .grant_types
            .iter()
            .any(|grant| matches!(grant.as_str(), "authorization_code" | "refresh_token"))
    {
        return Err(OidcError::InvalidClient);
    }
    match client.token_endpoint_auth_method.as_str() {
        "none" if client.client_type == "PUBLIC" && authorization.is_none() => {}
        "client_secret_basic"
            if client.client_type == "CONFIDENTIAL" && authorization.is_some() => {}
        _ => return Err(OidcError::InvalidClient),
    }
    Ok(client)
}

async fn authenticate_machine_client(
    state: &AppState,
    headers: &HeaderMap,
    values: &BTreeMap<String, String>,
) -> Result<MachineCredential> {
    if headers.contains_key(header::COOKIE) {
        return Err(OidcError::InvalidClient);
    }
    let authorization =
        one_header(headers, header::AUTHORIZATION.as_str())?.ok_or(OidcError::InvalidClient)?;
    let encoded = authorization
        .strip_prefix("Basic ")
        .filter(|value| value.len() <= 2048)
        .ok_or(OidcError::InvalidClient)?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| OidcError::InvalidClient)?;
    if STANDARD.encode(&decoded) != encoded {
        return Err(OidcError::InvalidClient);
    }
    let decoded = std::str::from_utf8(&decoded).map_err(|_| OidcError::InvalidClient)?;
    let (raw_client_id, raw_secret) = decoded.split_once(':').ok_or(OidcError::InvalidClient)?;
    let client_id =
        protocol::decode_component(raw_client_id).map_err(|_| OidcError::InvalidClient)?;
    let secret = protocol::decode_component(raw_secret).map_err(|_| OidcError::InvalidClient)?;
    if values
        .get("client_id")
        .is_some_and(|body_id| body_id != &client_id)
    {
        return Err(OidcError::InvalidClient);
    }
    protocol_client_budget(state, &client_id)?;
    let client = client(state, &client_id)
        .await
        .map_err(client_authentication_error)?;
    if client.client_type != "CONFIDENTIAL"
        || client.token_endpoint_auth_method != "client_secret_basic"
        || client.status != "ENABLED"
        || client.application_status != "APPROVED"
        || client.environment != expected_environment(state)
    {
        return Err(OidcError::InvalidClient);
    }
    let secret_digest = super::digest(&secret);
    let credential: Option<(i64, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT credential_version,LEAST(expires_at,created_at+interval '90 days') AS expires_at FROM public.auth_client_credentials \
         WHERE client_id=$1 AND secret_digest=$2 AND revoked_at IS NULL \
           AND created_at+interval '90 days'>clock_timestamp() \
           AND (expires_at IS NULL OR expires_at>clock_timestamp()) \
         ORDER BY credential_version DESC LIMIT 1",
    )
    .bind(client.id)
    .bind(&secret_digest)
    .fetch_optional(&state.pool)
    .await?;
    let Some((credential_version, expires_at)) = credential else {
        return Err(OidcError::InvalidClient);
    };
    if client.subject_mode != "MACHINE"
        || client.runtime_kind != "SERVICE"
        || client.context_mode.as_deref() != Some("NONE")
        || !client
            .grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
    {
        return Err(OidcError::Protocol(
            "unauthorized_client",
            "Only registered MACHINE service clients may use client_credentials",
        ));
    }
    Ok(MachineCredential {
        client,
        credential_version,
        secret_digest,
        expires_at,
    })
}

fn machine_scope_names(values: &BTreeMap<String, String>) -> Result<Vec<String>> {
    let raw = protocol::required(values, "scope")?;
    let names = raw
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unique = names.iter().collect::<BTreeSet<_>>();
    if names.is_empty()
        || names.len() > 128
        || names.len() != unique.len()
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > 128
                || !name.as_bytes()[0].is_ascii_lowercase()
                || !name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b':' | b'-')
                })
        })
    {
        return Err(OidcError::Protocol(
            "invalid_scope",
            "Machine scope is malformed or duplicated",
        ));
    }
    Ok(names)
}

async fn resolve_machine_scopes(
    tx: &mut Transaction<'_, Postgres>,
    client: &Client,
    approved_scopes: &[String],
    names: &[String],
) -> Result<Vec<Scope>> {
    let scopes: Vec<Scope> = sqlx::query_as(
        "SELECT permission.resource_id,permission.scope_id,scope.scope_name,resource.audience,resource.resource_key \
         FROM public.auth_client_permissions permission \
         JOIN public.auth_scopes scope ON scope.id=permission.scope_id \
           AND scope.resource_id=permission.resource_id AND scope.status='ACTIVE' \
         JOIN public.auth_resources resource ON resource.id=permission.resource_id AND resource.status='ACTIVE' \
         WHERE permission.client_id=$1 AND scope.scope_name=ANY($2) \
           AND (permission.expires_at IS NULL OR permission.expires_at>clock_timestamp()) \
         ORDER BY resource.audience,scope.scope_name,scope.id",
    )
    .bind(client.id)
    .bind(names)
    .fetch_all(&mut **tx)
    .await?;
    let resolved_names = scopes
        .iter()
        .map(|scope| scope.scope_name.clone())
        .collect::<BTreeSet<_>>();
    let scope_ids = scopes
        .iter()
        .map(|scope| scope.scope_id)
        .collect::<BTreeSet<_>>();
    if scopes.len() != names.len()
        || resolved_names.len() != names.len()
        || scope_ids.len() != scopes.len()
        || names
            .iter()
            .any(|name| !approved_scopes.iter().any(|approved| approved == name))
        || scopes.iter().any(|scope| {
            scope.resource_key == "userinfo"
                || matches!(
                    scope.scope_name.as_str(),
                    "openid" | "profile" | "offline_access"
                )
        })
    {
        return Err(OidcError::Protocol(
            "invalid_scope",
            "Machine scopes exceed the client's approved resource permissions",
        ));
    }
    Ok(scopes)
}

async fn client_credentials_token(
    state: &AppState,
    headers: &HeaderMap,
    values: &BTreeMap<String, String>,
) -> Result<Json<Value>> {
    if values
        .keys()
        .any(|key| !matches!(key.as_str(), "grant_type" | "client_id" | "scope"))
    {
        return Err(super::invalid());
    }
    let names = machine_scope_names(values)?;
    let credential = authenticate_machine_client(state, headers, values).await?;
    let client = &credential.client;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let application: Option<(String, i64, Vec<String>)> = sqlx::query_as(
        "SELECT status,projection_version,approved_scopes FROM public.auth_applications \
         WHERE application_id=$1 FOR SHARE",
    )
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    let registration: Option<ClientRegistration> = sqlx::query_as(
        "SELECT status,policy_version,subject_mode,context_mode,environment,grant_types \
             FROM public.auth_clients WHERE id=$1 AND application_id=$2 FOR SHARE",
    )
    .bind(client.id)
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((application_status, application_version, approved_scopes)) = application else {
        return Err(OidcError::InvalidClient);
    };
    let Some(registration) = registration else {
        return Err(OidcError::InvalidClient);
    };
    if application_status != "APPROVED"
        || application_version != client.application_projection_version
        || registration.status != "ENABLED"
        || registration.policy_version != client.policy_version
        || registration.subject_mode != "MACHINE"
        || registration.context_mode.as_deref() != Some("NONE")
        || registration.environment != client.environment
        || registration.environment != expected_environment(state)
        || !registration
            .grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
    {
        return Err(OidcError::InvalidClient);
    }
    let current_credential: Option<(i64, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT credential_version,LEAST(expires_at,created_at+interval '90 days') AS expires_at FROM public.auth_client_credentials \
         WHERE client_id=$1 AND credential_version=$2 AND secret_digest=$3 AND revoked_at IS NULL \
           AND created_at+interval '90 days'>clock_timestamp() \
           AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE",
    )
    .bind(client.id)
    .bind(credential.credential_version)
    .bind(&credential.secret_digest)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((credential_version, credential_expires_at)) = current_credential else {
        return Err(OidcError::InvalidClient);
    };
    let scopes = resolve_machine_scopes(&mut tx, client, &approved_scopes, &names).await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let mut deadline = now
        + Duration::seconds(
            client
                .client_token_ttl_seconds
                .unwrap_or(state.config.token_defaults.client_token_ttl_seconds),
        );
    if let Some(expires_at) = credential_expires_at {
        deadline = deadline.min(expires_at);
    }
    if let Some(expires_at) = credential.expires_at {
        deadline = deadline.min(expires_at);
    }
    if deadline <= now {
        return Err(super::invalid_grant());
    }
    let access_token = sso::opaque_secret()?;
    let grant_id = uuid7::new_uuid();
    let token_id = uuid7::new_uuid();
    let scope_ids = scopes
        .iter()
        .map(|scope| scope.scope_id)
        .collect::<Vec<_>>();
    let audiences = scopes
        .iter()
        .map(|scope| scope.audience.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO public.auth_grants(id,client_id,subject_mode,user_id,consent_id,consent_generation, \
         consent_group_version,source_session_id,context_mode,context_ref,account_version,client_policy_version, \
         application_projection_version,credential_version,scope_ids,audiences,auth_time,expires_at,revoked_at,created_at,version) \
         VALUES($1,$2,'MACHINE',NULL,NULL,NULL,NULL,NULL,'NONE',NULL,NULL,$3,$4,$5,$6,$7,NULL,$8,NULL,clock_timestamp(),1)",
    )
    .bind(grant_id)
    .bind(client.id)
    .bind(client.policy_version)
    .bind(client.application_projection_version)
    .bind(credential_version)
    .bind(&scope_ids)
    .bind(&audiences)
    .bind(deadline)
    .execute(&mut *tx)
    .await?;
    for scope in &scopes {
        sqlx::query(
            "INSERT INTO public.auth_grant_scopes(grant_id,resource_id,scope_id) VALUES($1,$2,$3)",
        )
        .bind(grant_id)
        .bind(scope.resource_id)
        .bind(scope.scope_id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO public.auth_access_tokens(id,grant_id,token_digest,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(token_id)
    .bind(grant_id)
    .bind(super::digest(&access_token))
    .bind(deadline)
    .execute(&mut *tx)
    .await?;
    for scope in &scopes {
        sqlx::query(
            "INSERT INTO public.auth_access_token_scopes(token_id,resource_id,scope_id) VALUES($1,$2,$3)",
        )
        .bind(token_id)
        .bind(scope.resource_id)
        .bind(scope.scope_id)
        .execute(&mut *tx)
        .await?;
    }
    let detail = json!({
        "clientId":client.id,
        "credentialVersion":credential_version,
        "audienceCount":audiences.len(),
        "scopeCount":scopes.len()
    })
    .to_string();
    audit::write_in_tx(
        &mut tx,
        audit::AuditInfo {
            user_id: None,
            username: &client.client_id,
            action: "AUTH_MACHINE_TOKEN_ISSUE",
            detail: &detail,
            ip: &audit::client_ip(headers),
            user_agent: &audit::ua_of(headers),
        },
    )
    .await?;
    super::deadline(&mut tx, deadline).await?;
    tx.commit().await?;
    let scopes = scopes
        .iter()
        .map(|scope| scope.scope_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "access_token":access_token,
        "token_type":"Bearer",
        "expires_in":(deadline-Utc::now()).num_seconds().max(0),
        "scope":scopes.join(" ")
    })))
}

async fn refresh_token(
    state: &AppState,
    headers: &HeaderMap,
    values: &BTreeMap<String, String>,
) -> Result<Json<Value>> {
    if values.keys().any(|key| {
        !matches!(
            key.as_str(),
            "grant_type" | "refresh_token" | "scope" | "client_id"
        )
    }) {
        return Err(super::invalid());
    }
    let client = authenticate_token_client(state, headers, values).await?;
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == "refresh_token")
    {
        return Err(OidcError::Protocol(
            "unauthorized_client",
            "The client is not allowed to use refresh_token",
        ));
    }
    let raw_refresh = protocol::required(values, "refresh_token")?;
    if !canonical_secret(raw_refresh) {
        return Err(super::invalid_grant());
    }
    let lookup: Option<RefreshLookup> = sqlx::query_as(
        "SELECT token.id AS token_id,token.consumed_at,family.id AS family_id,grant_row.id AS grant_id, \
         grant_row.client_id,grant_row.user_id,grant_row.consent_id,grant_row.consent_generation, \
         grant_row.consent_group_version,grant_row.source_session_id,grant_row.account_version, \
         grant_row.auth_time,grant_row.client_policy_version,grant_row.application_projection_version, \
         grant_row.scope_ids,grant_row.expires_at AS grant_expires_at, \
         grant_row.context_mode,grant_row.context_ref,EXISTS(SELECT 1 FROM public.auth_scopes scope \
           JOIN public.auth_resources resource ON resource.id=scope.resource_id \
           WHERE scope.id=ANY(grant_row.scope_ids) AND scope.scope_name='offline_access' \
             AND resource.resource_key='userinfo') AS offline_access \
         FROM public.auth_refresh_tokens token \
         JOIN public.auth_refresh_families family ON family.id=token.family_id \
         JOIN public.auth_grants grant_row ON grant_row.id=family.grant_id \
         WHERE token.token_digest=$1 AND grant_row.subject_mode='USER' AND grant_row.user_id IS NOT NULL",
    )
    .bind(super::digest(raw_refresh))
    .fetch_optional(&state.pool)
    .await?;
    let lookup = lookup.ok_or_else(super::invalid_grant)?;
    if lookup.client_id != client.id
        || !matches!(
            lookup.context_mode.as_str(),
            "ACCOUNT_ONLY" | "PLATFORM_CONTEXT"
        )
        || (lookup.context_mode == "PLATFORM_CONTEXT" && lookup.context_ref.is_none())
        || (lookup.context_mode == "ACCOUNT_ONLY" && lookup.context_ref.is_some())
    {
        return Err(super::invalid_grant());
    }
    if lookup.consumed_at.is_some() {
        // Reuse only removes authority. An expired permission or token must
        // not hide this fact while narrower access tokens are still active.
        let target = RefreshRevocationTarget {
            token_id: lookup.token_id,
            family_id: lookup.family_id,
            grant_id: lookup.grant_id,
            user_id: Some(lookup.user_id),
            consent_id: lookup.consent_id,
        };
        revoke_refresh_family(
            state,
            headers,
            &client,
            &super::digest(raw_refresh),
            target,
            true,
        )
        .await?;
        return Err(super::invalid_grant());
    }
    let original_scopes = scopes_by_ids(state, &lookup.scope_ids).await?;
    let original_scope_ids = original_scopes
        .iter()
        .map(|scope| scope.scope_id)
        .collect::<BTreeSet<_>>();
    let offline_access = original_scopes
        .iter()
        .any(|scope| scope.scope_name == "offline_access" && scope.resource_key == "userinfo");
    if original_scopes.len() != lookup.scope_ids.len()
        || original_scope_ids.len() != original_scopes.len()
        || lookup.offline_access != offline_access
        || (offline_access && lookup.context_mode != "ACCOUNT_ONLY")
        || (offline_access
            && !client
                .grant_types
                .iter()
                .any(|grant| grant == "refresh_token"))
    {
        return Err(super::invalid_grant());
    }
    let selected_scopes = refresh_scope_subset(values, &original_scopes)?;
    let source_session_id = lookup.source_session_id.ok_or_else(super::invalid_grant)?;
    let account_version = lookup.account_version.ok_or_else(super::invalid_grant)?;
    let auth_time = lookup.auth_time.ok_or_else(super::invalid_grant)?;
    let consent_id = lookup.consent_id.ok_or_else(super::invalid_grant)?;
    let consent_generation = lookup.consent_generation.ok_or_else(super::invalid_grant)?;
    let stored_group_version = lookup
        .consent_group_version
        .ok_or_else(super::invalid_grant)?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let account: Option<(String, i64, String, String, String)> = sqlx::query_as(
        "SELECT status,session_version,username,COALESCE(real_name,''),COALESCE(avatar,'') \
         FROM public.users WHERE id=$1 FOR SHARE",
    )
    .bind(lookup.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((account_status, current_account_version, username, real_name, _avatar)) = account
    else {
        return Err(super::invalid_grant());
    };
    if account_status != "ENABLED" || current_account_version != account_version {
        return Err(super::invalid_grant());
    }

    let application: Option<(String, i64)> = sqlx::query_as(
        "SELECT status,projection_version FROM public.auth_applications \
         WHERE application_id=$1 FOR SHARE",
    )
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    let registration: Option<ClientRegistration> = sqlx::query_as(
        "SELECT status,policy_version,subject_mode,context_mode,environment,grant_types \
             FROM public.auth_clients WHERE id=$1 AND application_id=$2 FOR SHARE",
    )
    .bind(client.id)
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    if application != Some(("APPROVED".to_owned(), lookup.application_projection_version))
        || registration.as_ref().is_none_or(|registration| {
            registration.status != "ENABLED"
                || registration.policy_version != lookup.client_policy_version
                || registration.subject_mode != "USER"
                || registration.context_mode.as_deref() != Some(lookup.context_mode.as_str())
                || registration.environment != client.environment
                || !registration
                    .grant_types
                    .iter()
                    .any(|grant| grant == "refresh_token")
        })
        || client.environment != expected_environment(state)
        || client.policy_version != lookup.client_policy_version
        || client.application_projection_version != lookup.application_projection_version
    {
        return Err(super::invalid_grant());
    }

    let session: Option<(DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT authenticated_at,expires_at FROM public.sso_sessions \
         WHERE id=$1 AND user_id=$2 AND account_version=$3 AND revoked_at IS NULL \
           AND ($4 OR expires_at>clock_timestamp()) FOR SHARE",
    )
    .bind(source_session_id)
    .bind(lookup.user_id)
    .bind(account_version)
    .bind(offline_access)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((session_auth_time, session_expires)) = session else {
        return Err(super::invalid_grant());
    };
    if session_auth_time != auth_time {
        return Err(super::invalid_grant());
    }
    let proof = AccountSessionProof {
        id: source_session_id,
        user_id: lookup.user_id,
        account_version,
        authenticated_at: auth_time,
        expires_at: session_expires,
        username,
        real_name,
    };
    let consent = if offline_access {
        auth_consent::sufficient_offline(&mut tx, &proof, client.id, &to_grants(&original_scopes))
            .await
    } else {
        auth_consent::sufficient(&mut tx, &proof, client.id, &to_grants(&original_scopes)).await
    }
    .map_err(|error| match error {
        AppError::Unavailable => OidcError::App(AppError::Unavailable),
        _ => super::invalid_grant(),
    })?;
    if !matches!(consent, ConsentState::Sufficient { consent_id: current_id, generation, .. }
        if current_id == consent_id && generation == consent_generation)
        || consent_group_version(&mut tx, consent_id).await? != stored_group_version
    {
        return Err(super::invalid_grant());
    }

    let current_grant: Option<RefreshGrant> = sqlx::query_as(
        "SELECT grant_row.client_id,grant_row.user_id,grant_row.consent_id, \
         grant_row.consent_generation,grant_row.consent_group_version,grant_row.source_session_id, \
         grant_row.account_version,grant_row.auth_time,grant_row.client_policy_version, \
         grant_row.application_projection_version,grant_row.scope_ids,grant_row.expires_at, \
         grant_row.revoked_at,grant_row.context_mode,grant_row.context_ref,EXISTS(SELECT 1 FROM public.auth_scopes scope \
           JOIN public.auth_resources resource ON resource.id=scope.resource_id \
           WHERE scope.id=ANY(grant_row.scope_ids) AND scope.scope_name='offline_access' \
             AND resource.resource_key='userinfo') AS offline_access \
         FROM public.auth_grants grant_row WHERE grant_row.id=$1 FOR UPDATE",
    )
    .bind(lookup.grant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current_grant) = current_grant else {
        return Err(super::invalid_grant());
    };
    if current_grant.client_id != lookup.client_id
        || current_grant.user_id != lookup.user_id
        || current_grant.consent_id != lookup.consent_id
        || current_grant.consent_generation != lookup.consent_generation
        || current_grant.consent_group_version != lookup.consent_group_version
        || current_grant.source_session_id != lookup.source_session_id
        || current_grant.account_version != lookup.account_version
        || current_grant.auth_time != lookup.auth_time
        || current_grant.client_policy_version != lookup.client_policy_version
        || current_grant.application_projection_version != lookup.application_projection_version
        || current_grant.scope_ids != lookup.scope_ids
        || current_grant.expires_at != lookup.grant_expires_at
        || current_grant.revoked_at.is_some()
        || current_grant.context_mode != lookup.context_mode
        || current_grant.context_ref != lookup.context_ref
        || current_grant.offline_access != offline_access
    {
        return Err(super::invalid_grant());
    }
    if lookup.context_mode == "PLATFORM_CONTEXT" {
        unified_context::validate_grant_binding(
            &mut tx,
            lookup.context_ref.ok_or_else(super::invalid_grant)?,
            lookup.grant_id,
            lookup.client_id,
            lookup.user_id,
            source_session_id,
            account_version,
            lookup.client_policy_version,
            lookup.application_projection_version,
        )
        .await?;
    }
    let family: Option<RefreshFamily> = sqlx::query_as(
        "SELECT grant_id,absolute_expires_at,idle_expires_at,revoked_at,version \
             FROM public.auth_refresh_families WHERE id=$1 AND grant_id=$2 FOR UPDATE",
    )
    .bind(lookup.family_id)
    .bind(lookup.grant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(RefreshFamily {
        grant_id: family_grant_id,
        absolute_expires_at,
        idle_expires_at,
        revoked_at: family_revoked_at,
        version: family_version,
    }) = family
    else {
        return Err(super::invalid_grant());
    };
    let token: Option<RefreshToken> = sqlx::query_as(
        "SELECT generation,expires_at,consumed_at,revoked_at,token_digest \
             FROM public.auth_refresh_tokens WHERE id=$1 AND family_id=$2 FOR UPDATE",
    )
    .bind(lookup.token_id)
    .bind(lookup.family_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(RefreshToken {
        generation,
        expires_at: token_expires_at,
        consumed_at,
        revoked_at: token_revoked_at,
        token_digest,
    }) = token
    else {
        return Err(super::invalid_grant());
    };
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    if family_grant_id != lookup.grant_id
        || family_revoked_at.is_some()
        || absolute_expires_at <= now
        || idle_expires_at <= now
        || idle_expires_at > absolute_expires_at
        || absolute_expires_at > current_grant.expires_at
        || current_grant.expires_at <= now
        || token_revoked_at.is_some()
        || !super::equal(&token_digest, &super::digest(raw_refresh))
    {
        return Err(super::invalid_grant());
    }
    if consumed_at.is_some() {
        sqlx::query(
            "UPDATE public.auth_refresh_families SET revoked_at=COALESCE(revoked_at,clock_timestamp()), \
             version=version+1 WHERE id=$1 AND revoked_at IS NULL",
        )
        .bind(lookup.family_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE public.auth_refresh_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) \
             WHERE family_id=$1 AND revoked_at IS NULL",
        )
        .bind(lookup.family_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE public.auth_access_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) \
             WHERE grant_id=$1 AND revoked_at IS NULL",
        )
        .bind(lookup.grant_id)
        .execute(&mut *tx)
        .await?;
        audit_refresh(
            &mut tx,
            &proof,
            headers,
            client.id,
            lookup.family_id,
            generation,
            true,
        )
        .await?;
        tx.commit().await?;
        return Err(super::invalid_grant());
    }
    // A consumed token remains evidence of reuse after its own idle deadline:
    // a later successor may have kept this same family alive in the meantime.
    if token_expires_at <= now {
        return Err(super::invalid_grant());
    }

    let idle_window = Duration::seconds(
        state
            .config
            .token_defaults
            .refresh_idle(client.refresh_token_ttl_seconds, offline_access),
    );
    let next_idle_expires_at = (now + idle_window).min(absolute_expires_at);
    let access_expires_at = (now
        + Duration::seconds(
            client
                .access_token_ttl_seconds
                .unwrap_or(state.config.token_defaults.access_token_ttl_seconds),
        ))
    .min(current_grant.expires_at)
    .min(absolute_expires_at)
    .min(if offline_access {
        absolute_expires_at
    } else {
        session_expires
    });
    if next_idle_expires_at <= now || access_expires_at <= now {
        return Err(super::invalid_grant());
    }
    let next_refresh = sso::opaque_secret()?;
    let access_token = sso::opaque_secret()?;
    let updated = sqlx::query(
        "UPDATE public.auth_refresh_families SET idle_expires_at=$2,version=version+1 \
         WHERE id=$1 AND revoked_at IS NULL AND version=$3 AND absolute_expires_at=$4",
    )
    .bind(lookup.family_id)
    .bind(next_idle_expires_at)
    .bind(family_version)
    .bind(absolute_expires_at)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(super::invalid_grant());
    }
    let consumed = sqlx::query(
        "UPDATE public.auth_refresh_tokens SET consumed_at=clock_timestamp() \
         WHERE id=$1 AND family_id=$2 AND generation=$3 AND consumed_at IS NULL \
           AND revoked_at IS NULL AND expires_at>clock_timestamp()",
    )
    .bind(lookup.token_id)
    .bind(lookup.family_id)
    .bind(generation)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if consumed != 1 {
        return Err(super::invalid_grant());
    }
    let next_generation = generation.checked_add(1).ok_or(AppError::Unavailable)?;
    sqlx::query(
        "INSERT INTO public.auth_refresh_tokens(id,family_id,token_digest,generation,expires_at) \
         VALUES($1,$2,$3,$4,$5)",
    )
    .bind(uuid7::new_uuid())
    .bind(lookup.family_id)
    .bind(super::digest(&next_refresh))
    .bind(next_generation)
    .bind(next_idle_expires_at)
    .execute(&mut *tx)
    .await?;
    let access_token_id = uuid7::new_uuid();
    sqlx::query(
        "INSERT INTO public.auth_access_tokens(id,grant_id,token_digest,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(access_token_id)
    .bind(lookup.grant_id)
    .bind(super::digest(&access_token))
    .bind(access_expires_at)
    .execute(&mut *tx)
    .await?;
    for scope in &selected_scopes {
        sqlx::query(
            "INSERT INTO public.auth_access_token_scopes(token_id,resource_id,scope_id) VALUES($1,$2,$3)",
        )
        .bind(access_token_id)
        .bind(scope.resource_id)
        .bind(scope.scope_id)
        .execute(&mut *tx)
        .await?;
    }
    audit_refresh(
        &mut tx,
        &proof,
        headers,
        client.id,
        lookup.family_id,
        next_generation,
        false,
    )
    .await?;
    super::deadline(&mut tx, access_expires_at).await?;
    tx.commit().await?;

    let scope_names = selected_scopes
        .iter()
        .map(|scope| scope.scope_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "access_token":access_token,
        "token_type":"Bearer",
        "expires_in":(access_expires_at-Utc::now()).num_seconds().max(0),
        "refresh_token":next_refresh,
        "scope":scope_names.join(" ")
    })))
}

fn refresh_scope_subset(
    values: &BTreeMap<String, String>,
    original: &[Scope],
) -> Result<Vec<Scope>> {
    let Some(raw) = values.get("scope") else {
        return Ok(original.to_vec());
    };
    let names = raw.split_ascii_whitespace().collect::<Vec<_>>();
    let requested = names.iter().copied().collect::<BTreeSet<_>>();
    let available = original
        .iter()
        .map(|scope| scope.scope_name.as_str())
        .collect::<BTreeSet<_>>();
    if names.is_empty() || names.len() != requested.len() || !requested.is_subset(&available) {
        return Err(super::invalid_grant());
    }
    let scopes = original
        .iter()
        .filter(|scope| requested.contains(scope.scope_name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if scopes.is_empty() {
        return Err(super::invalid_grant());
    }
    Ok(scopes)
}

async fn load_code(state: &AppState, digest: &str) -> Result<CodeExchange> {
    sqlx::query_as(
        "SELECT code.id,code.request_id,code.client_id,code.user_id,code.consent_id, \
         code.consent_generation,code.consent_group_version,code.code_digest,code.expires_at AS code_expires_at, \
         code.consumed_at AS code_consumed_at,request.redirect_uri,request.client_policy_version, \
         request.application_projection_version,request.scope_ids,request.nonce_value,request.nonce_digest, \
         request.state_value,request.state_digest,request.force_login,request.created_at,request.source_session_id, \
         request.account_version,request.auth_time,request.max_age_seconds,request.status \
         FROM public.auth_authorization_codes code \
         JOIN public.auth_authorization_requests request ON request.id=code.request_id \
         WHERE code.code_digest=$1",
    )
    .bind(digest)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(super::invalid_grant)
}

async fn exchange_client_challenge(state: &AppState, request_id: Uuid) -> Result<String> {
    sqlx::query_scalar("SELECT code_challenge FROM public.auth_authorization_requests WHERE id=$1")
        .bind(request_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(super::invalid_grant)
}

async fn exchange_authorization(
    state: &AppState,
    headers: &HeaderMap,
    client: &Client,
    raw_code: &str,
    exchange: CodeExchange,
) -> Result<Json<Value>> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let account: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT username,status,session_version FROM public.users WHERE id=$1 FOR SHARE",
    )
    .bind(exchange.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((username, account_status, account_version)) = account else {
        return Err(super::invalid_grant());
    };
    if account_status != "ENABLED" || Some(account_version) != exchange.account_version {
        return Err(super::invalid_grant());
    }
    let application: Option<(String, i64)> = sqlx::query_as(
        "SELECT status,projection_version FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    let registration: Option<(String, i64)> = sqlx::query_as(
        "SELECT status,policy_version FROM public.auth_clients WHERE id=$1 AND application_id=$2 FOR SHARE",
    )
    .bind(client.id)
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    if application
        != Some((
            "APPROVED".to_owned(),
            exchange.application_projection_version,
        ))
        || registration != Some(("ENABLED".to_owned(), exchange.client_policy_version))
    {
        return Err(super::invalid_grant());
    }
    let session_id = exchange
        .source_session_id
        .ok_or_else(super::invalid_grant)?;
    let auth_time = exchange.auth_time.ok_or_else(super::invalid_grant)?;
    if (exchange.force_login && auth_time < exchange.created_at)
        || exchange.max_age_seconds.is_some_and(|max_age| {
            max_age > 0 && auth_time < Utc::now() - Duration::seconds(max_age)
        })
    {
        return Err(super::invalid_grant());
    }
    let code_live: Option<(DateTime<Utc>, DateTime<Utc>, i64)> = sqlx::query_as(
        "SELECT s.authenticated_at,s.expires_at,s.account_version FROM public.sso_sessions s \
         JOIN public.users u ON u.id=s.user_id \
         WHERE s.id=$1 AND s.user_id=$2 AND s.account_version=$3 AND s.revoked_at IS NULL \
           AND s.expires_at>clock_timestamp() AND u.status='ENABLED' FOR SHARE OF s,u",
    )
    .bind(session_id)
    .bind(exchange.user_id)
    .bind(account_version)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((session_auth_time, session_expires, session_version)) = code_live else {
        return Err(super::invalid_grant());
    };
    if session_auth_time != auth_time || session_version != account_version {
        return Err(super::invalid_grant());
    }
    let proof = AccountSessionProof {
        id: session_id,
        user_id: exchange.user_id,
        account_version,
        authenticated_at: auth_time,
        expires_at: session_expires,
        username,
        real_name: sqlx::query_scalar(
            "SELECT COALESCE(real_name,'') FROM public.users WHERE id=$1",
        )
        .bind(exchange.user_id)
        .fetch_one(&mut *tx)
        .await?,
    };
    let scopes = scopes_by_ids(state, &exchange.scope_ids).await?;
    let consent = auth_consent::sufficient(&mut tx, &proof, client.id, &to_grants(&scopes)).await?;
    let ConsentState::Sufficient {
        consent_id,
        generation,
        ..
    } = consent
    else {
        return Err(super::invalid_grant());
    };
    let group_version = consent_group_version(&mut tx, consent_id).await?;
    if consent_id != exchange.consent_id
        || generation != exchange.consent_generation
        || group_version != exchange.consent_group_version
    {
        return Err(super::invalid_grant());
    }
    let code_state: Option<(DateTime<Utc>, Option<DateTime<Utc>>, String)> = sqlx::query_as(
        "SELECT expires_at,consumed_at,code_digest FROM public.auth_authorization_codes \
         WHERE id=$1 AND request_id=$2 AND client_id=$3 AND user_id=$4 FOR UPDATE",
    )
    .bind(exchange.id)
    .bind(exchange.request_id)
    .bind(client.id)
    .bind(exchange.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((expires, consumed_at, stored_digest)) = code_state else {
        return Err(super::invalid_grant());
    };
    let code_is_live: bool = sqlx::query_scalar("SELECT $1::timestamptz>clock_timestamp()")
        .bind(expires)
        .fetch_one(&mut *tx)
        .await?;
    if !code_is_live
        || consumed_at.is_some()
        || !super::equal(&stored_digest, &super::digest(raw_code))
    {
        return Err(super::invalid_grant());
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let offline_access = scopes
        .iter()
        .any(|scope| scope.scope_name == "offline_access");
    if offline_access
        && !client
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
    {
        return Err(super::invalid_grant());
    }
    if offline_access && client.context_mode.as_deref() == Some("PLATFORM_CONTEXT") {
        return Err(super::invalid_grant());
    }
    let context_ref = unified_context::context_ref(&mut tx, exchange.request_id, client).await?;
    let context_mode = if context_ref.is_some() {
        "PLATFORM_CONTEXT"
    } else {
        "ACCOUNT_ONLY"
    };
    let grant_deadline = if offline_access {
        now + Duration::days(7)
    } else {
        session_expires
    };
    let mut deadline = (now
        + Duration::seconds(
            client
                .access_token_ttl_seconds
                .unwrap_or(state.config.token_defaults.access_token_ttl_seconds),
        ))
    .min(grant_deadline);
    if !offline_access {
        deadline = deadline.min(session_expires);
    }
    if deadline <= now {
        return Err(super::invalid_grant());
    }
    let profile = subjects::profile_for_client(&mut tx, &proof, client.id).await?;
    let grant_id = uuid7::new_uuid();
    let token_id = uuid7::new_uuid();
    let access_token = sso::opaque_secret()?;
    let audiences = scopes
        .iter()
        .map(|scope| scope.audience.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO public.auth_grants(id,client_id,subject_mode,user_id,consent_id,consent_generation,consent_group_version, \
         source_session_id,context_mode,context_ref,account_version,client_policy_version, \
         application_projection_version,scope_ids,audiences,auth_time,expires_at,revoked_at,created_at,version) \
         VALUES($1,$2,'USER',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NULL,clock_timestamp(),1)",
    )
    .bind(grant_id)
    .bind(client.id)
    .bind(exchange.user_id)
    .bind(consent_id)
    .bind(generation)
    .bind(group_version)
    .bind(session_id)
    .bind(context_mode)
    .bind(context_ref)
    .bind(account_version)
    .bind(client.policy_version)
    .bind(client.application_projection_version)
    .bind(&exchange.scope_ids)
    .bind(&audiences)
    .bind(auth_time)
    .bind(grant_deadline)
    .execute(&mut *tx)
    .await?;
    for scope in &scopes {
        sqlx::query(
            "INSERT INTO public.auth_grant_scopes(grant_id,resource_id,scope_id) VALUES($1,$2,$3)",
        )
        .bind(grant_id)
        .bind(scope.resource_id)
        .bind(scope.scope_id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO public.auth_access_tokens(id,grant_id,token_digest,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(token_id)
    .bind(grant_id)
    .bind(super::digest(&access_token))
    .bind(deadline)
    .execute(&mut *tx)
    .await?;
    for scope in &scopes {
        sqlx::query(
            "INSERT INTO public.auth_access_token_scopes(token_id,resource_id,scope_id) VALUES($1,$2,$3)",
        )
        .bind(token_id)
        .bind(scope.resource_id)
        .bind(scope.scope_id)
        .execute(&mut *tx)
        .await?;
    }
    let refresh_token = if client
        .grant_types
        .iter()
        .any(|grant| grant == "refresh_token")
    {
        let family_id = uuid7::new_uuid();
        let refresh_token = sso::opaque_secret()?;
        let idle_window = Duration::seconds(
            state
                .config
                .token_defaults
                .refresh_idle(client.refresh_token_ttl_seconds, offline_access),
        );
        let idle_deadline = (now + idle_window).min(grant_deadline);
        if idle_deadline <= now {
            return Err(super::invalid_grant());
        }
        sqlx::query(
            "INSERT INTO public.auth_refresh_families(id,grant_id,absolute_expires_at,idle_expires_at) \
             VALUES($1,$2,$3,$4)",
        )
        .bind(family_id)
        .bind(grant_id)
        .bind(grant_deadline)
        .bind(idle_deadline)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO public.auth_refresh_tokens(id,family_id,token_digest,generation,expires_at) \
             VALUES($1,$2,$3,1,$4)",
        )
        .bind(uuid7::new_uuid())
        .bind(family_id)
        .bind(super::digest(&refresh_token))
        .bind(idle_deadline)
        .execute(&mut *tx)
        .await?;
        Some(refresh_token)
    } else {
        None
    };
    let userinfo_scope_names = scopes
        .iter()
        .filter(|scope| scope.resource_key == "userinfo")
        .map(|scope| scope.scope_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut claims = profile.id_token_claims(&userinfo_scope_names)?;
    let object = claims.as_object_mut().ok_or(AppError::Unavailable)?;
    let public_sub = object
        .get("sub")
        .and_then(Value::as_str)
        .ok_or(AppError::Unavailable)?
        .to_owned();
    let public_sid = sso::opaque_secret()?;
    sqlx::query("INSERT INTO public.auth_rp_sessions(grant_id,client_id,user_id,source_session_id,public_sid,public_sub) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(grant_id).bind(client.id).bind(exchange.user_id).bind(session_id)
        .bind(&public_sid).bind(public_sub).execute(&mut *tx).await?;
    object.insert("sid".into(), json!(public_sid));
    object.insert(
        "iss".into(),
        json!(state
            .config
            .oidc_issuer
            .as_deref()
            .ok_or(AppError::Unavailable)?),
    );
    object.insert("aud".into(), json!(client.client_id));
    object.insert("exp".into(), json!(deadline.timestamp()));
    object.insert("iat".into(), json!(now.timestamp()));
    object.insert("auth_time".into(), json!(auth_time.timestamp()));
    object.insert("nonce".into(), json!(exchange.nonce_value));
    let id_token = keys::sign(state, &mut tx, claims, deadline).await?;
    let consumed = sqlx::query(
        "UPDATE public.auth_authorization_codes SET consumed_at=clock_timestamp() \
         WHERE id=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()",
    )
    .bind(exchange.id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if consumed != 1 {
        return Err(super::invalid_grant());
    }
    let request_consumed = sqlx::query(
        "UPDATE public.auth_authorization_requests SET status='CONSUMED',consumed_at=clock_timestamp(),version=version+1 \
         WHERE id=$1 AND status='AUTHORIZED' AND consumed_at IS NULL",
    )
    .bind(exchange.request_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if request_consumed != 1 {
        return Err(super::invalid_grant());
    }
    let context_selection =
        unified_context::deliver_code_extension(state, &mut tx, &exchange, grant_id, context_ref)
            .await?;
    audit_authorize(&mut tx, &proof, headers, client.id, "AUTH_CODE_EXCHANGE").await?;
    super::deadline(&mut tx, deadline).await?;
    tx.commit().await?;
    let scopes = scopes
        .iter()
        .map(|scope| scope.scope_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut response = json!({
        "access_token":access_token,
        "token_type":"Bearer",
        "expires_in":(deadline-Utc::now()).num_seconds().max(0),
        "id_token":id_token,
        "scope":scopes.join(" ")
    });
    if let Some(refresh_token) = refresh_token {
        response["refresh_token"] = json!(refresh_token);
    }
    if let Some(context_selection) = context_selection {
        response["context_selection"] = context_selection;
    }
    Ok(Json(response))
}

pub(super) async fn userinfo_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>> {
    if query.as_deref().is_some_and(|query| !query.is_empty()) {
        return Err(super::invalid());
    }
    let token = bearer_token(&headers)?;
    userinfo(&state, &headers, &token).await
}

pub(super) async fn userinfo_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    RawForm(form): RawForm,
) -> Result<Json<Value>> {
    let values = protocol::form(RawForm(form), RawQuery(query))?;
    if values.keys().any(|key| key != "access_token") {
        return Err(super::invalid());
    }
    let form_token = values.get("access_token").map(String::as_str);
    let header_token = one_header(&headers, header::AUTHORIZATION.as_str())?;
    let header_token = header_token
        .map(|value| value.strip_prefix("Bearer ").ok_or(OidcError::InvalidToken))
        .transpose()?;
    if form_token.is_some() && header_token.is_some() {
        return Err(super::invalid());
    }
    let token = form_token.or(header_token).ok_or(OidcError::InvalidToken)?;
    userinfo(&state, &headers, token).await
}

fn bearer_token(headers: &HeaderMap) -> Result<String> {
    if headers.contains_key(header::COOKIE) {
        return Err(OidcError::InvalidToken);
    }
    let raw =
        one_header(headers, header::AUTHORIZATION.as_str())?.ok_or(OidcError::InvalidToken)?;
    let token = raw
        .strip_prefix("Bearer ")
        .filter(|token| canonical_secret(token))
        .ok_or(OidcError::InvalidToken)?;
    Ok(token.to_owned())
}

async fn verified_user_access(state: &AppState, token: &str) -> Result<VerifiedUserAccess> {
    if !canonical_secret(token) {
        return Err(OidcError::InvalidToken);
    }
    let live: LiveAccess = sqlx::query_as(
        "SELECT t.id AS token_id,g.id AS grant_id,g.client_id,g.user_id,g.consent_id, \
         g.consent_generation,g.source_session_id,g.account_version,g.auth_time,g.expires_at AS grant_expires_at, \
         g.client_policy_version,g.application_projection_version,g.consent_group_version, \
         g.scope_ids,g.context_mode,g.context_ref,EXISTS(SELECT 1 FROM public.auth_scopes offline_scope \
           JOIN public.auth_resources offline_resource ON offline_resource.id=offline_scope.resource_id \
           WHERE offline_scope.id=ANY(g.scope_ids) AND offline_scope.scope_name='offline_access' \
             AND offline_resource.resource_key='userinfo') AS offline_access, \
         t.created_at AS token_created_at,t.expires_at AS token_expires_at \
         FROM public.auth_access_tokens t JOIN public.auth_grants g ON g.id=t.grant_id \
         WHERE t.token_digest=$1 AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp() \
           AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp() \
           AND g.subject_mode='USER' AND g.user_id IS NOT NULL \
           AND g.consent_id IS NOT NULL AND g.consent_generation IS NOT NULL \
           AND g.source_session_id IS NOT NULL AND g.account_version IS NOT NULL AND g.auth_time IS NOT NULL \
           AND ((g.context_mode='ACCOUNT_ONLY' AND g.context_ref IS NULL) OR \
             (g.context_mode='PLATFORM_CONTEXT' AND g.context_ref IS NOT NULL AND EXISTS( \
               SELECT 1 FROM public.auth_context_interactions context \
               WHERE context.transaction_id=g.context_ref AND context.grant_id=g.id \
                 AND context.client_id=g.client_id AND context.client_policy_version=g.client_policy_version \
                 AND context.application_projection_version=g.application_projection_version \
                 AND context.selected_membership_id IS NOT NULL AND context.delivered_at IS NOT NULL \
                 AND context.credential_ciphertext IS NULL)))",
    )
    .bind(super::digest(token))
    .fetch_optional(&state.pool)
    .await?
    .ok_or(OidcError::InvalidToken)?;
    let client = client_by_internal_id(state, live.client_id).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let account: Option<(String, i64, String, String, String)> =
        sqlx::query_as("SELECT status,session_version,username,COALESCE(real_name,''),COALESCE(avatar,'') FROM public.users WHERE id=$1 FOR SHARE")
            .bind(live.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status, account_version, username, real_name, avatar)) = account else {
        return Err(OidcError::InvalidToken);
    };
    if status != "ENABLED" || account_version != live.account_version {
        return Err(OidcError::InvalidToken);
    }
    let application: Option<(String, i64)> = sqlx::query_as(
        "SELECT status,projection_version FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    let registration: Option<(String, i64)> = sqlx::query_as(
        "SELECT status,policy_version FROM public.auth_clients WHERE id=$1 FOR SHARE",
    )
    .bind(client.id)
    .fetch_optional(&mut *tx)
    .await?;
    if client.application_status != "APPROVED"
        || application != Some(("APPROVED".to_owned(), live.application_projection_version))
        || registration != Some(("ENABLED".to_owned(), live.client_policy_version))
        || client.environment != expected_environment(state)
        || client.subject_mode != "USER"
        || client.context_mode.as_deref() != Some(live.context_mode.as_str())
    {
        return Err(OidcError::InvalidToken);
    }
    let source_session: Option<(DateTime<Utc>, DateTime<Utc>, i64)> = sqlx::query_as(
        "SELECT authenticated_at,expires_at,account_version FROM public.sso_sessions \
         WHERE id=$1 AND user_id=$2 AND account_version=$3 AND revoked_at IS NULL \
           AND ($4 OR expires_at>clock_timestamp()) FOR SHARE",
    )
    .bind(live.source_session_id)
    .bind(live.user_id)
    .bind(live.account_version)
    .bind(live.offline_access)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((authenticated_at, session_expires, _)) = source_session else {
        return Err(OidcError::InvalidToken);
    };
    if authenticated_at != live.auth_time {
        return Err(OidcError::InvalidToken);
    }
    let scopes: Vec<Scope> = sqlx::query_as(
        "SELECT token_scope.resource_id,token_scope.scope_id,scope.scope_name,resource.audience,resource.resource_key \
         FROM public.auth_access_token_scopes token_scope \
         JOIN public.auth_scopes scope ON scope.id=token_scope.scope_id AND scope.status='ACTIVE' \
         JOIN public.auth_resources resource ON resource.id=token_scope.resource_id AND resource.status='ACTIVE' \
         WHERE token_scope.token_id=$1 ORDER BY scope.scope_name,scope.id,resource.id",
    )
    .bind(live.token_id)
    .fetch_all(&mut *tx)
    .await?;
    let token_scope_ids = scopes
        .iter()
        .map(|scope| scope.scope_id)
        .collect::<BTreeSet<_>>();
    let grant_scope_ids = live.scope_ids.iter().copied().collect::<BTreeSet<_>>();
    if scopes.is_empty()
        || token_scope_ids.len() != scopes.len()
        || !token_scope_ids.is_subset(&grant_scope_ids)
    {
        return Err(OidcError::InvalidToken);
    }
    let proof = AccountSessionProof {
        id: live.source_session_id,
        user_id: live.user_id,
        account_version: live.account_version,
        authenticated_at,
        expires_at: session_expires,
        username: sqlx::query_scalar("SELECT username FROM public.users WHERE id=$1")
            .bind(live.user_id)
            .fetch_one(&mut *tx)
            .await?,
        real_name: sqlx::query_scalar(
            "SELECT COALESCE(real_name,'') FROM public.users WHERE id=$1",
        )
        .bind(live.user_id)
        .fetch_one(&mut *tx)
        .await?,
    };
    let consent = if live.offline_access {
        auth_consent::sufficient_offline(&mut tx, &proof, client.id, &to_grants(&scopes)).await?
    } else {
        auth_consent::sufficient(&mut tx, &proof, client.id, &to_grants(&scopes)).await?
    };
    if !matches!(consent, ConsentState::Sufficient { consent_id, generation, .. }
        if consent_id==live.consent_id && generation==live.consent_generation)
    {
        return Err(OidcError::InvalidToken);
    }
    let group_version = consent_group_version(&mut tx, live.consent_id).await?;
    if live.context_mode == "PLATFORM_CONTEXT" {
        unified_context::validate_grant_binding(
            &mut tx,
            live.context_ref.ok_or(OidcError::InvalidToken)?,
            live.grant_id,
            live.client_id,
            live.user_id,
            live.source_session_id,
            live.account_version,
            live.client_policy_version,
            live.application_projection_version,
        )
        .await?;
    }
    let grant_state: Option<GrantSnapshot> = sqlx::query_as(
        "SELECT revoked_at,expires_at,consent_group_version FROM public.auth_grants WHERE id=$1 FOR SHARE",
    )
    .bind(live.grant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(grant_state) = grant_state else {
        return Err(OidcError::InvalidToken);
    };
    let token_state: Option<AccessTokenState> = sqlx::query_as(
        "SELECT revoked_at,expires_at,created_at FROM public.auth_access_tokens \
         WHERE id=$1 AND grant_id=$2 FOR SHARE",
    )
    .bind(live.token_id)
    .bind(live.grant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((token_revoked, token_expires, token_created)) = token_state else {
        return Err(OidcError::InvalidToken);
    };
    let active: bool = sqlx::query_scalar(
        "SELECT $1::timestamptz IS NULL AND $2::timestamptz IS NULL \
         AND $3::timestamptz>clock_timestamp() AND $4::timestamptz>clock_timestamp() \
         AND $5::timestamptz=$6::timestamptz AND $7::timestamptz=$8::timestamptz",
    )
    .bind(grant_state.revoked_at)
    .bind(token_revoked)
    .bind(grant_state.expires_at)
    .bind(token_expires)
    .bind(token_expires)
    .bind(live.token_expires_at)
    .bind(token_created)
    .bind(live.token_created_at)
    .fetch_one(&mut *tx)
    .await?;
    if !active
        || grant_state.consent_group_version != Some(group_version)
        || live.consent_group_version != group_version
    {
        return Err(OidcError::InvalidToken);
    }
    let profile = if live.offline_access {
        subjects::profile_for_offline_client(&mut tx, &proof, client.id).await?
    } else {
        subjects::profile_for_client(&mut tx, &proof, client.id).await?
    };
    tx.commit().await?;
    Ok(VerifiedUserAccess {
        live,
        client,
        profile,
        scopes,
        snapshot: Box::new(UserProofSnapshot {
            username,
            real_name,
            avatar,
            source_expires_at: session_expires,
        }),
    })
}

pub(super) async fn platform_account_proof(
    state: &AppState,
    access: &str,
    expected_client_id: Uuid,
) -> std::result::Result<Value, AppError> {
    let invalid = || AppError::unauthorized("平台账号认证证明无效或已失效");
    let verified = verified_user_access(state, access)
        .await
        .map_err(|error| match error {
            OidcError::App(error) => error,
            _ => invalid(),
        })?;
    let client = &verified.client;
    let live = &verified.live;
    let scope = verified
        .scopes
        .iter()
        .map(|scope| scope.scope_name.as_str())
        .collect::<BTreeSet<_>>();
    if client.id != expected_client_id
        || client.client_id != expected_client_id.to_string()
        || client.client_type != "CONFIDENTIAL"
        || client.runtime_kind != "WEB_BFF"
        || client.subject_mode != "USER"
        || client.context_mode.as_deref() != Some("PLATFORM_CONTEXT")
        || client.app_purpose != "PLATFORM_CONSOLE"
        || client.allowed_member_types.len() != 1
        || client.allowed_member_types[0] != "EMPLOYEE"
        || !scope.contains("openid")
        || !scope.contains("profile")
    {
        return Err(invalid());
    }
    let issuer = state
        .config
        .oidc_issuer
        .as_deref()
        .ok_or(AppError::Unavailable)?;
    let profile = verified
        .profile
        .userinfo_claims(&["openid".into(), "profile".into()])?;
    Ok(serde_json::json!({
        "contractVersion":"platform-account-proof/1",
        "issuer":issuer,
        "clientId":client.id,
        "clientPurpose":client.app_purpose,
        "contextMode":live.context_mode,
        "allowedMemberTypes":client.allowed_member_types,
        "scope":scope,
        "sub":profile.get("sub").and_then(Value::as_str).ok_or(AppError::Unavailable)?,
        "grantId":live.grant_id,
        "globalSessionId":live.source_session_id,
        "userId":live.user_id,
        "accountVersion":live.account_version.to_string(),
        "clientPolicyVersion":live.client_policy_version.to_string(),
        "applicationProjectionVersion":live.application_projection_version.to_string(),
        "authTime":live.auth_time.timestamp(),
        "expiresAt":live.token_expires_at,
        "absoluteExpiresAt":live.grant_expires_at
    }))
}

async fn verified_machine_access(state: &AppState, token: &str) -> Result<VerifiedMachineAccess> {
    if !canonical_secret(token) {
        return Err(OidcError::InvalidToken);
    }
    let live: LiveMachineAccess = sqlx::query_as(
        "SELECT token.id AS token_id,grant_row.id AS grant_id,grant_row.client_id, \
         grant_row.credential_version,grant_row.client_policy_version, \
         grant_row.application_projection_version,grant_row.scope_ids,grant_row.audiences, \
         token.created_at AS token_created_at,token.expires_at AS token_expires_at \
         FROM public.auth_access_tokens token \
         JOIN public.auth_grants grant_row ON grant_row.id=token.grant_id \
         WHERE token.token_digest=$1 AND token.revoked_at IS NULL AND token.expires_at>clock_timestamp() \
           AND grant_row.revoked_at IS NULL AND grant_row.expires_at>clock_timestamp() \
           AND grant_row.subject_mode='MACHINE' AND grant_row.user_id IS NULL \
           AND grant_row.consent_id IS NULL AND grant_row.consent_generation IS NULL \
           AND grant_row.consent_group_version IS NULL AND grant_row.source_session_id IS NULL \
           AND grant_row.account_version IS NULL AND grant_row.auth_time IS NULL \
           AND grant_row.context_mode='NONE' AND grant_row.context_ref IS NULL \
           AND grant_row.credential_version IS NOT NULL",
    )
    .bind(super::digest(token))
    .fetch_optional(&state.pool)
    .await?
    .ok_or(OidcError::InvalidToken)?;
    let client = client_by_internal_id(state, live.client_id).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    let application: Option<(String, i64, Vec<String>)> = sqlx::query_as(
        "SELECT status,projection_version,approved_scopes FROM public.auth_applications \
         WHERE application_id=$1 FOR SHARE",
    )
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    let registration: Option<ClientRegistration> = sqlx::query_as(
        "SELECT status,policy_version,subject_mode,context_mode,environment,grant_types \
             FROM public.auth_clients WHERE id=$1 AND application_id=$2 FOR SHARE",
    )
    .bind(client.id)
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((application_status, application_version, approved_scopes)) = application else {
        return Err(OidcError::InvalidToken);
    };
    let Some(registration) = registration else {
        return Err(OidcError::InvalidToken);
    };
    if client.application_status != "APPROVED"
        || application_status != "APPROVED"
        || application_version != live.application_projection_version
        || registration.status != "ENABLED"
        || registration.policy_version != live.client_policy_version
        || registration.subject_mode != "MACHINE"
        || registration.context_mode.as_deref() != Some("NONE")
        || registration.environment != expected_environment(state)
        || registration.environment != client.environment
        || client.client_type != "CONFIDENTIAL"
        || client.runtime_kind != "SERVICE"
        || !registration
            .grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
    {
        return Err(OidcError::InvalidToken);
    }
    let credential: Option<MachineCredentialState> = sqlx::query_as(
        "SELECT revoked_at,LEAST(expires_at,created_at+interval '90 days') AS expires_at FROM public.auth_client_credentials \
         WHERE client_id=$1 AND credential_version=$2 FOR SHARE",
    )
    .bind(client.id)
    .bind(live.credential_version)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(credential) = credential else {
        return Err(OidcError::InvalidToken);
    };
    let grant_state: Option<MachineGrantState> = sqlx::query_as(
        "SELECT revoked_at,expires_at,client_policy_version,application_projection_version, \
         credential_version,scope_ids FROM public.auth_grants WHERE id=$1 AND client_id=$2 FOR SHARE",
    )
    .bind(live.grant_id)
    .bind(client.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(grant_state) = grant_state else {
        return Err(OidcError::InvalidToken);
    };
    let token_state: Option<AccessTokenState> = sqlx::query_as(
        "SELECT revoked_at,expires_at,created_at FROM public.auth_access_tokens \
         WHERE id=$1 AND grant_id=$2 FOR SHARE",
    )
    .bind(live.token_id)
    .bind(live.grant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((token_revoked_at, token_expires_at, token_created_at)) = token_state else {
        return Err(OidcError::InvalidToken);
    };
    let current: bool = sqlx::query_scalar(
        "SELECT $1::timestamptz IS NULL AND $2::timestamptz IS NULL \
         AND $3::timestamptz IS NULL AND ($4::timestamptz IS NULL OR $4::timestamptz>clock_timestamp()) \
         AND $5::timestamptz>clock_timestamp() AND $6::timestamptz>clock_timestamp() \
         AND $7::timestamptz=$8::timestamptz AND $9::timestamptz=$10::timestamptz",
    )
    .bind(grant_state.revoked_at)
    .bind(token_revoked_at)
    .bind(credential.revoked_at)
    .bind(credential.expires_at)
    .bind(grant_state.expires_at)
    .bind(token_expires_at)
    .bind(token_expires_at)
    .bind(live.token_expires_at)
    .bind(token_created_at)
    .bind(live.token_created_at)
    .fetch_one(&mut *tx)
    .await?;
    if !current
        || grant_state.client_policy_version != live.client_policy_version
        || grant_state.application_projection_version != live.application_projection_version
        || grant_state.credential_version != Some(live.credential_version)
        || grant_state.scope_ids != live.scope_ids
    {
        return Err(OidcError::InvalidToken);
    }
    let scopes: Vec<Scope> = sqlx::query_as(
        "SELECT token_scope.resource_id,token_scope.scope_id,scope.scope_name,resource.audience,resource.resource_key \
         FROM public.auth_access_token_scopes token_scope \
         JOIN public.auth_scopes scope ON scope.id=token_scope.scope_id AND scope.status='ACTIVE' \
         JOIN public.auth_resources resource ON resource.id=token_scope.resource_id AND resource.status='ACTIVE' \
         WHERE token_scope.token_id=$1 ORDER BY resource.audience,scope.scope_name,scope.id",
    )
    .bind(live.token_id)
    .fetch_all(&mut *tx)
    .await?;
    let scope_ids = scopes
        .iter()
        .map(|scope| scope.scope_id)
        .collect::<BTreeSet<_>>();
    let grant_scope_ids = live.scope_ids.iter().copied().collect::<BTreeSet<_>>();
    let names = scopes
        .iter()
        .map(|scope| scope.scope_name.clone())
        .collect::<BTreeSet<_>>();
    if scopes.is_empty() || scope_ids.len() != scopes.len() || names.len() != scopes.len() {
        return Err(OidcError::InvalidToken);
    }
    let current_scopes = match resolve_machine_scopes(
        &mut tx,
        &client,
        &approved_scopes,
        &names.into_iter().collect::<Vec<_>>(),
    )
    .await
    {
        Ok(scopes) => scopes,
        Err(OidcError::Protocol(_, _)) => return Err(OidcError::InvalidToken),
        Err(error) => return Err(error),
    };
    let current_pairs = current_scopes
        .iter()
        .map(|scope| (scope.resource_id, scope.scope_id))
        .collect::<BTreeSet<_>>();
    let token_pairs = scopes
        .iter()
        .map(|scope| (scope.resource_id, scope.scope_id))
        .collect::<BTreeSet<_>>();
    let grant_pairs: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT resource_id,scope_id FROM public.auth_grant_scopes \
         WHERE grant_id=$1 ORDER BY resource_id,scope_id",
    )
    .bind(live.grant_id)
    .fetch_all(&mut *tx)
    .await?;
    let grant_pairs = grant_pairs.into_iter().collect::<BTreeSet<_>>();
    let current_audiences = current_scopes
        .iter()
        .map(|scope| scope.audience.clone())
        .collect::<BTreeSet<_>>();
    let grant_audiences = live.audiences.iter().cloned().collect::<BTreeSet<_>>();
    if scope_ids != grant_scope_ids
        || current_pairs != token_pairs
        || grant_pairs != token_pairs
        || current_audiences != grant_audiences
    {
        return Err(OidcError::InvalidToken);
    }
    tx.commit().await?;
    Ok(VerifiedMachineAccess {
        expires_at: credential.expires_at.map_or(
            live.token_expires_at.min(grant_state.expires_at),
            |deadline| {
                live.token_expires_at
                    .min(grant_state.expires_at)
                    .min(deadline)
            },
        ),
        live,
        client,
        scopes,
    })
}

async fn userinfo(state: &AppState, headers: &HeaderMap, token: &str) -> Result<Json<Value>> {
    super::authority(state).await?;
    if headers.contains_key(header::COOKIE) {
        return Err(OidcError::InvalidToken);
    }
    let verified = verified_user_access(state, token).await?;
    protocol_client_budget(state, &verified.client.client_id)?;
    let userinfo_scopes = verified
        .scopes
        .iter()
        .filter(|scope| scope.resource_key == "userinfo")
        .map(|scope| scope.scope_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !userinfo_scopes.iter().any(|scope| scope == "openid") {
        return Err(OidcError::InvalidToken);
    }
    Ok(Json(verified.profile.userinfo_claims(&userinfo_scopes)?))
}

async fn confidential_client(
    state: &AppState,
    headers: &HeaderMap,
    values: &BTreeMap<String, String>,
) -> Result<Client> {
    if headers.contains_key(header::COOKIE) {
        return Err(OidcError::InvalidClient);
    }
    let authorization =
        one_header(headers, header::AUTHORIZATION.as_str())?.ok_or(OidcError::InvalidClient)?;
    let encoded = authorization
        .strip_prefix("Basic ")
        .filter(|value| value.len() <= 2048)
        .ok_or(OidcError::InvalidClient)?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| OidcError::InvalidClient)?;
    if STANDARD.encode(&decoded) != encoded {
        return Err(OidcError::InvalidClient);
    }
    let decoded = std::str::from_utf8(&decoded).map_err(|_| OidcError::InvalidClient)?;
    let (id, secret) = decoded.split_once(':').ok_or(OidcError::InvalidClient)?;
    let id = protocol::decode_component(id).map_err(|_| OidcError::InvalidClient)?;
    let secret = protocol::decode_component(secret).map_err(|_| OidcError::InvalidClient)?;
    if values
        .get("client_id")
        .is_some_and(|body_id| body_id != &id)
    {
        return Err(OidcError::InvalidClient);
    }
    protocol_client_budget(state, &id)?;
    let client = client(state, &id)
        .await
        .map_err(client_authentication_error)?;
    if client.client_type != "CONFIDENTIAL"
        || client.token_endpoint_auth_method != "client_secret_basic"
        || client.status != "ENABLED"
        || client.application_status != "APPROVED"
        || client.environment != expected_environment(state)
    {
        return Err(OidcError::InvalidClient);
    }
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.auth_client_credentials credential \
         WHERE credential.client_id=$1 AND credential.secret_digest=$2 \
           AND credential.revoked_at IS NULL \
           AND credential.created_at+interval '90 days'>clock_timestamp() \
           AND (credential.expires_at IS NULL OR credential.expires_at>clock_timestamp()))",
    )
    .bind(client.id)
    .bind(super::digest(&secret))
    .fetch_one(&state.pool)
    .await
    .map_err(|_| AppError::Unavailable)?;
    if !valid {
        return Err(OidcError::InvalidClient);
    }
    Ok(client)
}

async fn introspection_client(
    state: &AppState,
    headers: &HeaderMap,
    values: &BTreeMap<String, String>,
) -> Result<Client> {
    let client = confidential_client(state, headers, values).await?;
    if client.subject_mode != "MACHINE"
        || client.context_mode.as_deref() != Some("NONE")
        || !client
            .grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
    {
        return Err(OidcError::InvalidClient);
    }
    Ok(client)
}

pub(super) async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    RawForm(form): RawForm,
) -> Result<Json<Value>> {
    let issuer = super::authority(&state).await?;
    let values = protocol::form(RawForm(form), RawQuery(query))?;
    if values.keys().any(|key| {
        !matches!(
            key.as_str(),
            "token" | "resource" | "token_type_hint" | "client_id"
        )
    }) {
        return Err(super::invalid());
    }
    let caller = introspection_client(&state, &headers, &values).await?;
    let token = protocol::required(&values, "token")?;
    if !canonical_secret(token) {
        return Ok(Json(json!({"active":false})));
    }
    let verified = match verified_user_access(&state, token).await {
        Ok(verified) => VerifiedAccess::User(verified),
        Err(OidcError::InvalidToken) => match verified_machine_access(&state, token).await {
            Ok(verified) => VerifiedAccess::Machine(verified),
            Err(OidcError::InvalidToken) => return Ok(Json(json!({"active":false}))),
            Err(error) => return Err(error),
        },
        Err(error) => return Err(error),
    };
    let (
        token_client_id,
        token_scopes,
        token_expires_at,
        token_created_at,
        subject,
        auth_time,
        machine,
    ) = match verified {
        VerifiedAccess::User(verified) => (
            verified.client.client_id,
            verified.scopes,
            verified.live.token_expires_at,
            verified.live.token_created_at,
            Some(
                verified
                    .profile
                    .userinfo_claims(&["openid".to_owned()])?
                    .get("sub")
                    .cloned()
                    .ok_or(AppError::Unavailable)?,
            ),
            Some(verified.live.auth_time),
            false,
        ),
        VerifiedAccess::Machine(verified) => (
            verified.client.client_id,
            verified.scopes,
            verified.live.token_expires_at,
            verified.live.token_created_at,
            None,
            None,
            true,
        ),
    };
    let requested_resource = values.get("resource");
    let permissions: Vec<Scope> = sqlx::query_as(
        "SELECT p.resource_id,p.scope_id,s.scope_name,r.audience,r.resource_key \
         FROM public.auth_client_permissions p \
         JOIN public.auth_scopes s ON s.id=p.scope_id AND s.resource_id=p.resource_id AND s.status='ACTIVE' \
         JOIN public.auth_resources r ON r.id=p.resource_id AND r.status='ACTIVE' \
         WHERE p.client_id=$1 AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp()) \
         ORDER BY r.audience,s.scope_name,s.id",
    )
    .bind(caller.id)
    .fetch_all(&state.pool)
    .await?;
    let mut token_by_resource = BTreeMap::<Uuid, Vec<&Scope>>::new();
    let mut permission_by_resource = BTreeMap::<Uuid, BTreeSet<Uuid>>::new();
    for scope in &token_scopes {
        token_by_resource
            .entry(scope.resource_id)
            .or_default()
            .push(scope);
    }
    for permission in permissions {
        permission_by_resource
            .entry(permission.resource_id)
            .or_default()
            .insert(permission.scope_id);
    }
    let mut audiences = BTreeSet::new();
    let mut scope_names = BTreeSet::new();
    for (resource_id, scopes) in token_by_resource {
        if requested_resource.is_some_and(|audience| {
            scopes
                .first()
                .is_none_or(|scope| &scope.audience != audience)
        }) {
            continue;
        }
        let authorized = permission_by_resource.get(&resource_id);
        let token_scope_ids = scopes
            .iter()
            .map(|scope| scope.scope_id)
            .collect::<BTreeSet<_>>();
        if authorized.is_some_and(|allowed| token_scope_ids.is_subset(allowed)) {
            if let Some(scope) = scopes.first() {
                audiences.insert(scope.audience.clone());
            }
            scope_names.extend(scopes.into_iter().map(|scope| scope.scope_name.clone()));
        }
    }
    if audiences.is_empty() {
        return Ok(Json(json!({"active":false})));
    }
    let mut response = json!({
        "active":true,
        "client_id":token_client_id,
        "aud":audiences,
        "scope":scope_names.into_iter().collect::<Vec<_>>().join(" "),
        "token_type":"Bearer",
        "exp":token_expires_at.timestamp(),
        "iat":token_created_at.timestamp(),
        "iss":issuer
    });
    if let Some(subject) = subject {
        response["sub"] = subject;
    }
    if let Some(auth_time) = auth_time {
        response["auth_time"] = json!(auth_time.timestamp());
    }
    if machine {
        response["subject_mode"] = json!("MACHINE");
    }
    Ok(Json(response))
}

pub(super) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    RawForm(form): RawForm,
) -> Result<Response> {
    super::authority(&state).await?;
    let values = protocol::form(RawForm(form), RawQuery(query))?;
    if values
        .keys()
        .any(|key| !matches!(key.as_str(), "token" | "token_type_hint" | "client_id"))
    {
        return Err(super::invalid());
    }
    let client = confidential_client(&state, &headers, &values).await?;
    use axum::response::IntoResponse;
    let token = protocol::required(&values, "token")?;
    if !canonical_secret(token) {
        return Ok(axum::http::StatusCode::OK.into_response());
    }
    let digest = super::digest(token);
    let refresh_target: Option<RefreshRevocationTarget> = sqlx::query_as(
        "SELECT token.id AS token_id,family.id AS family_id,grant_row.id AS grant_id,grant_row.user_id,grant_row.consent_id \
         FROM public.auth_refresh_tokens token \
         JOIN public.auth_refresh_families family ON family.id=token.family_id \
         JOIN public.auth_grants grant_row ON grant_row.id=family.grant_id \
         WHERE token.token_digest=$1 AND grant_row.client_id=$2",
    )
    .bind(&digest)
    .bind(client.id)
    .fetch_optional(&state.pool)
    .await?;
    if let Some(target) = refresh_target {
        revoke_refresh_family(&state, &headers, &client, &digest, target, false).await?;
        return Ok(axum::http::StatusCode::OK.into_response());
    }
    let target: Option<(Uuid, Uuid, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT t.id,g.id,g.user_id,g.consent_id FROM public.auth_access_tokens t \
         JOIN public.auth_grants g ON g.id=t.grant_id \
         WHERE t.token_digest=$1 AND g.client_id=$2",
    )
    .bind(&digest)
    .bind(client.id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((token_id, grant_id, user_id, consent_id)) = target else {
        return Ok(axum::http::StatusCode::OK.into_response());
    };
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    if let Some(user_id) = user_id {
        sqlx::query("SELECT id FROM public.users WHERE id=$1 FOR SHARE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    }
    sqlx::query(
        "SELECT application_id FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query("SELECT id FROM public.auth_clients WHERE id=$1 FOR SHARE")
        .bind(client.id)
        .fetch_optional(&mut *tx)
        .await?;
    if let Some(consent_id) = consent_id {
        let group_id: Option<Uuid> =
            sqlx::query_scalar("SELECT group_id FROM public.auth_consents WHERE id=$1")
                .bind(consent_id)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(group_id) = group_id {
            sqlx::query("SELECT id FROM public.auth_consent_groups WHERE id=$1 FOR SHARE")
                .bind(group_id)
                .fetch_optional(&mut *tx)
                .await?;
            sqlx::query("SELECT id FROM public.auth_consents WHERE id=$1 FOR SHARE")
                .bind(consent_id)
                .fetch_optional(&mut *tx)
                .await?;
        }
    }
    sqlx::query("SELECT id FROM public.auth_grants WHERE id=$1 FOR SHARE")
        .bind(grant_id)
        .fetch_optional(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM public.auth_access_tokens WHERE id=$1 AND grant_id=$2 FOR UPDATE")
        .bind(token_id)
        .bind(grant_id)
        .fetch_optional(&mut *tx)
        .await?;
    let revoked = sqlx::query(
        "UPDATE public.auth_access_tokens SET revoked_at=clock_timestamp() \
         WHERE id=$1 AND grant_id=$2 AND revoked_at IS NULL",
    )
    .bind(token_id)
    .bind(grant_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if revoked == 1 {
        let ip = audit::client_ip(&headers);
        let user_agent = audit::ua_of(&headers);
        audit::write_in_tx(
            &mut tx,
            audit::AuditInfo {
                user_id: None,
                username: &client.client_id,
                action: "OAUTH_ACCESS_TOKEN_REVOKED",
                detail: "The authenticated client revoked its own access token",
                ip: &ip,
                user_agent: &user_agent,
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(axum::http::StatusCode::OK.into_response())
}

async fn revoke_refresh_family(
    state: &AppState,
    headers: &HeaderMap,
    client: &Client,
    digest: &str,
    target: RefreshRevocationTarget,
    reused: bool,
) -> Result<()> {
    let RefreshRevocationTarget {
        token_id,
        family_id,
        grant_id,
        user_id,
        consent_id,
    } = target;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    if let Some(user_id) = user_id {
        sqlx::query("SELECT id FROM public.users WHERE id=$1 FOR SHARE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    }
    sqlx::query(
        "SELECT application_id FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(client.application_id)
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query("SELECT id FROM public.auth_clients WHERE id=$1 FOR SHARE")
        .bind(client.id)
        .fetch_optional(&mut *tx)
        .await?;
    if let Some(consent_id) = consent_id {
        let group_id: Option<Uuid> =
            sqlx::query_scalar("SELECT group_id FROM public.auth_consents WHERE id=$1")
                .bind(consent_id)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(group_id) = group_id {
            sqlx::query("SELECT id FROM public.auth_consent_groups WHERE id=$1 FOR SHARE")
                .bind(group_id)
                .fetch_optional(&mut *tx)
                .await?;
            sqlx::query("SELECT id FROM public.auth_consents WHERE id=$1 FOR SHARE")
                .bind(consent_id)
                .fetch_optional(&mut *tx)
                .await?;
        }
    }
    let grant: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.auth_grants WHERE id=$1 AND client_id=$2 FOR SHARE",
    )
    .bind(grant_id)
    .bind(client.id)
    .fetch_optional(&mut *tx)
    .await?;
    if grant.is_none() {
        tx.commit().await?;
        return Ok(());
    }
    let family: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.auth_refresh_families WHERE id=$1 AND grant_id=$2 FOR UPDATE",
    )
    .bind(family_id)
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await?;
    if family.is_none() {
        tx.commit().await?;
        return Ok(());
    }
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM public.auth_access_tokens WHERE grant_id=$1 ORDER BY id FOR UPDATE",
    )
    .bind(grant_id)
    .fetch_all(&mut *tx)
    .await?;
    let refresh_tokens: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.auth_refresh_tokens WHERE family_id=$1 ORDER BY generation,id FOR UPDATE",
    )
    .bind(family_id)
    .fetch_all(&mut *tx)
    .await?;
    if !refresh_tokens.contains(&token_id) {
        tx.commit().await?;
        return Ok(());
    }
    let family_changed = sqlx::query(
        "UPDATE public.auth_refresh_families SET revoked_at=COALESCE(revoked_at,clock_timestamp()), \
         version=version+1 WHERE id=$1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let access_changed = sqlx::query(
        "UPDATE public.auth_access_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) \
         WHERE grant_id=$1 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let refresh_changed = sqlx::query(
        "UPDATE public.auth_refresh_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) \
         WHERE family_id=$1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if family_changed + access_changed + refresh_changed > 0 {
        let reason = if reused {
            "refresh_reuse"
        } else {
            "client_revoked"
        };
        let detail = json!({"clientId":client.id,"familyId":family_id,"reason":reason}).to_string();
        let ip = audit::client_ip(headers);
        let user_agent = audit::ua_of(headers);
        audit::write_in_tx(
            &mut tx,
            audit::AuditInfo {
                user_id: if reused { user_id } else { None },
                username: &client.client_id,
                action: if reused {
                    "OAUTH_REFRESH_REUSE"
                } else {
                    "OAUTH_REFRESH_FAMILY_REVOKED"
                },
                detail: &detail,
                ip: &ip,
                user_agent: &user_agent,
            },
        )
        .await?;
    }
    let current_digest: Option<String> = sqlx::query_scalar(
        "SELECT token_digest FROM public.auth_refresh_tokens WHERE id=$1 AND family_id=$2",
    )
    .bind(token_id)
    .bind(family_id)
    .fetch_optional(&mut *tx)
    .await?;
    if current_digest
        .as_deref()
        .is_some_and(|stored| !super::equal(stored, digest))
    {
        return Err(super::invalid_grant());
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_scopes_accept_registered_resource_names_and_require_openid() {
        let input = BTreeMap::from([("scope".to_owned(), "profile openid".to_owned())]);
        assert_eq!(
            requested_scopes(&input).unwrap_or_else(|_| panic!("valid scope was rejected")),
            vec!["openid".to_owned(), "profile".to_owned()]
        );
        let resource_input =
            BTreeMap::from([("scope".to_owned(), "openid orders.read".to_owned())]);
        assert_eq!(
            requested_scopes(&resource_input)
                .unwrap_or_else(|_| panic!("registered resource scope was rejected")),
            vec!["openid".to_owned(), "orders.read".to_owned()]
        );
        for raw in [
            "profile",
            "openid openid",
            "openid bad/scope",
            "openid bad scope?",
        ] {
            let input = BTreeMap::from([("scope".to_owned(), raw.to_owned())]);
            assert!(requested_scopes(&input).is_err(), "{raw}");
        }
    }

    #[test]
    fn standard_prompts_reject_unknown_or_conflicting_none_values() {
        assert_eq!(
            prompt_set(Some("login consent"))
                .unwrap_or_else(|_| panic!("valid prompt was rejected"))
                .len(),
            2
        );
        assert!(prompt_set(Some("none")).is_ok());
        for raw in ["none login", "login login", "select_account"] {
            assert!(prompt_set(Some(raw)).is_err(), "{raw}");
        }
    }

    #[test]
    fn pkce_uses_the_rfc7636_s256_transform() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
