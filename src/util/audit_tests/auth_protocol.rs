//! Phase 8 canonical OIDC and MFA HTTP regressions against task-owned PostgreSQL.

use super::Database;
use anyhow::{anyhow, ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Request, StatusCode},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sha2::Digest;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tower::ServiceExt;
use uuid::Uuid;

use crate::oidc::context::bridge::{
    Choice as ContextChoice, Choices as ContextChoices, ChoicesFuture, ConfirmFuture,
    Confirmation as ContextConfirmation, SelectionPort,
};
mod customer_proof_tests;
mod resource_proof_tests;

#[derive(Clone)]
struct UnifiedSelectionFixture {
    client_id: Uuid,
    transaction_id: Uuid,
    intent: Value,
    members: Arc<Mutex<Vec<ContextChoice>>>,
    expires_at: chrono::DateTime<Utc>,
    credential: String,
    choices_calls: Arc<AtomicUsize>,
    confirm_calls: Arc<AtomicUsize>,
}

impl UnifiedSelectionFixture {
    fn new(client_id: Uuid, transaction_id: Uuid, members: Vec<ContextChoice>) -> Self {
        Self {
            client_id,
            transaction_id,
            intent: json!({"kind":"LOGIN"}),
            members: Arc::new(Mutex::new(members)),
            expires_at: Utc::now() + Duration::seconds(90),
            credential: "e7".repeat(32),
            choices_calls: Arc::new(AtomicUsize::new(0)),
            confirm_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl SelectionPort for UnifiedSelectionFixture {
    fn choices<'a>(&'a self, source: &'a str, client: Uuid) -> ChoicesFuture<'a> {
        Box::pin(async move {
            self.choices_calls.fetch_add(1, Ordering::SeqCst);
            if client != self.client_id || !context_secret(source) {
                return Err(crate::error::AppError::unauthorized(
                    "fixture selection source mismatch",
                ));
            }
            Ok(ContextChoices {
                contract_version: "context-selection/1".to_owned(),
                transaction_id: self.transaction_id,
                intent: self.intent.clone(),
                members: self
                    .members
                    .lock()
                    .map_err(|_| crate::error::AppError::Unavailable)?
                    .clone(),
                expires_at: self.expires_at,
            })
        })
    }

    fn confirm<'a>(&'a self, source: &'a str, client: Uuid, member: Uuid) -> ConfirmFuture<'a> {
        Box::pin(async move {
            self.confirm_calls.fetch_add(1, Ordering::SeqCst);
            if client != self.client_id
                || !context_secret(source)
                || !self
                    .members
                    .lock()
                    .map_err(|_| crate::error::AppError::Unavailable)?
                    .iter()
                    .any(|candidate| candidate.membership_id == member)
            {
                return Err(crate::error::AppError::unauthorized(
                    "fixture membership is no longer eligible",
                ));
            }
            Ok(ContextConfirmation {
                contract_version: "context-selection/1".to_owned(),
                transaction_id: self.transaction_id,
                credential: self.credential.clone(),
                expires_at: self.expires_at,
            })
        })
    }
}

fn context_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct KeyFixture {
    directory: PathBuf,
    keyset: PathBuf,
    modulus: String,
    exponent: String,
}

impl Drop for KeyFixture {
    fn drop(&mut self) {
        let temp = std::env::temp_dir();
        if self.directory.parent() == Some(temp.as_path())
            && self
                .directory
                .symlink_metadata()
                .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
            && self
                .directory
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("identity-phase08-test-key-"))
                .is_some_and(|suffix| {
                    Uuid::parse_str(suffix).is_ok_and(|id| {
                        crate::util::uuid7::is_uuid_v7(id) && id.to_string() == suffix
                    })
                })
            && self
                .directory
                .canonicalize()
                .ok()
                .is_some_and(|path| path.parent() == temp.canonicalize().ok().as_deref())
        {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

#[derive(Clone)]
struct AuthFixture {
    user_id: Uuid,
    application_id: Uuid,
    resource_id: Uuid,
    openid_id: Uuid,
    profile_id: Uuid,
    group_id: Uuid,
    confidential_client_id: Uuid,
    public_client_id: Uuid,
    session_id: Uuid,
    session_token: String,
    csrf: String,
    confidential_client_name: String,
    client_secret: String,
    verifier: String,
    challenge: String,
}

#[derive(Clone)]
struct UnifiedContextClient {
    id: Uuid,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

async fn add_unified_context_client(
    db: &Database,
    fixture: &AuthFixture,
    suffix: &str,
    member_type: &str,
) -> Result<UnifiedContextClient> {
    ensure!(matches!(member_type, "EMPLOYEE" | "CUSTOMER"));
    let id = Uuid::now_v7();
    let group_id = Uuid::now_v7();
    let client_id = format!("phase12-context-{suffix}");
    let client_secret = if member_type == "EMPLOYEE" {
        "92".repeat(32)
    } else {
        "93".repeat(32)
    };
    let redirect_uri = format!("https://{suffix}.saas.test/auth/callback");
    let title = format!("Phase 12 {member_type} Context Client");
    sqlx::query("INSERT INTO auth_consent_groups(id,application_id,environment,display_name,purpose,subject_mode,context_mode,status,version) VALUES($1,$2,'test',$3,'Third-party account sign-in','USER','PLATFORM_CONTEXT','ACTIVE',1)")
        .bind(group_id).bind(fixture.application_id).bind(&title).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,post_logout_redirect_uris,status,version,policy_version,created_at,updated_at) VALUES($1,$2,$3,$4,'test','CONFIDENTIAL','WEB_BFF','USER','PLATFORM_CONTEXT',ARRAY[$5]::text[],ARRAY['authorization_code','refresh_token']::text[],'client_secret_basic',ARRAY[$6]::text[],ARRAY[]::text[],'ENABLED',1,1,clock_timestamp(),clock_timestamp())")
        .bind(id).bind(&client_id).bind(&title).bind(fixture.application_id).bind(member_type).bind(&redirect_uri).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_client_permissions(client_id,resource_id,scope_id,version) VALUES($1,$2,$3,1),($1,$2,$4,1)")
        .bind(id).bind(fixture.resource_id).bind(fixture.openid_id).bind(fixture.profile_id).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_consent_group_clients(group_id,client_id,application_id,environment,subject_mode,context_mode) VALUES($1,$2,$3,'test','USER','PLATFORM_CONTEXT')")
        .bind(group_id).bind(id).bind(fixture.application_id).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_client_credentials(id,client_id,client_type,credential_version,secret_digest,created_at) VALUES($1,$2,'CONFIDENTIAL',1,$3,clock_timestamp())")
        .bind(Uuid::now_v7()).bind(id).bind(crate::util::hash::sha256_hex(&client_secret)).execute(&db.pool).await?;
    let consent_id = Uuid::now_v7();
    sqlx::query("INSERT INTO auth_consents(id,user_id,group_id,status,generation,group_version,version,authorized_at) VALUES($1,$2,$3,'ACTIVE',1,1,1,clock_timestamp())")
        .bind(consent_id).bind(fixture.user_id).bind(group_id).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_consent_scopes(consent_id,resource_id,scope_id) VALUES($1,$2,$3),($1,$2,$4)")
        .bind(consent_id).bind(fixture.resource_id).bind(fixture.openid_id).bind(fixture.profile_id).execute(&db.pool).await?;
    Ok(UnifiedContextClient {
        id,
        client_id,
        client_secret,
        redirect_uri,
    })
}

async fn add_context_source_service(db: &Database, clients: &[Uuid]) -> Result<(Uuid, String)> {
    let service_id = Uuid::now_v7();
    let secret = "ef".repeat(32);
    sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,allowed_auth_clients) VALUES($1,$2,'CONTEXT_SELECTION_SOURCE','ENABLED',$3)")
        .bind(service_id).bind(crate::util::hash::sha256_hex(&secret)).bind(clients).execute(&db.pool).await?;
    Ok((service_id, secret))
}

async fn create_context_interaction(
    app: &Router,
    client: &UnifiedContextClient,
    transaction_id: Uuid,
    state: &str,
    nonce: &str,
    challenge: &str,
) -> Result<(StatusCode, Value)> {
    let authorization = STANDARD.encode(format!("{}:{}", client.client_id, client.client_secret));
    let body = json!({
        "contractVersion":"context-selection/1",
        "transactionId":transaction_id,
        "intent":{"kind":"LOGIN"},
        "redirectUri":client.redirect_uri,
        "stateHash":crate::util::hash::sha256_hex(state),
        "nonceHash":crate::util::hash::sha256_hex(nonce),
        "codeChallenge":challenge
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/internal/identity/auth/context-interactions")
                .header(header::AUTHORIZATION, format!("Basic {authorization}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn authorize_context_client(
    app: &Router,
    client: &UnifiedContextClient,
    handle: &str,
    challenge: &str,
    state: &str,
    nonce: &str,
    cookie: &str,
) -> Result<(StatusCode, HeaderMap, String, Value)> {
    let mut url = reqwest::Url::parse("https://auth.saas.test/oauth/authorize")?;
    url.query_pairs_mut()
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", &client.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid profile")
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("context_request", handle);
    let path = format!("/oauth/authorize?{}", url.query().unwrap_or_default());
    let (status, headers, body) =
        send(app, "GET", &path, Some(cookie), None, None, None, None).await?;
    ensure!(
        status.is_redirection()
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::FORBIDDEN,
        "unexpected context authorize status {status}"
    );
    let target = if headers.contains_key(header::LOCATION) {
        location(&headers)?
    } else {
        String::new()
    };
    Ok((status, headers, target, body))
}

async fn prepare_phase08_schema(db: &Database) -> Result<()> {
    sqlx::raw_sql(
        r#"
ALTER TABLE public.sso_sessions ADD COLUMN mfa_verified_at timestamptz, ADD COLUMN mfa_method text;
ALTER TABLE public.identity_service_clients ADD COLUMN allowed_auth_clients uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE public.identity_service_clients ADD COLUMN allowed_auth_resources uuid[] NOT NULL DEFAULT '{}';
-- Mirror the canonical narrow service lock port in this identity-only fixture.
-- Deployment-owner/LOGIN-role privileges are verified by platform role tests.
CREATE FUNCTION public.identity_context_source_service_active(service_ref uuid, expected_digest text, client_ref uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog','public' AS $$
BEGIN
    PERFORM 1 FROM public.identity_service_clients service
      WHERE service.id=service_ref AND service.status='ENABLED'
        AND service.purpose='CONTEXT_SELECTION_SOURCE' AND service.secret_hash=expected_digest
        AND client_ref=ANY(service.allowed_auth_clients)
      FOR SHARE OF service;
    IF NOT FOUND THEN RETURN false; END IF;
    RETURN EXISTS(SELECT 1 FROM public.identity_service_clients service
      WHERE service.id=service_ref AND service.status='ENABLED'
        AND service.purpose='CONTEXT_SELECTION_SOURCE' AND service.secret_hash=expected_digest
        AND client_ref=ANY(service.allowed_auth_clients));
END;
$$;
ALTER TABLE public.auth_authorization_requests
    ADD COLUMN source_session_id uuid,
    ADD COLUMN account_version bigint,
    ADD COLUMN auth_time timestamptz,
    ADD COLUMN client_policy_version bigint NOT NULL DEFAULT 1,
    ADD COLUMN application_projection_version bigint NOT NULL DEFAULT 1,
    ADD COLUMN redirect_uri text,
    ADD COLUMN state_digest text,
    ADD COLUMN state_value text,
    ADD COLUMN nonce_digest text,
    ADD COLUMN nonce_value text,
    ADD COLUMN code_challenge text,
    ADD COLUMN code_challenge_method text,
    ADD COLUMN scope_ids uuid[],
    ADD COLUMN browser_digest text,
    ADD COLUMN csrf_digest text,
    ADD COLUMN force_login boolean NOT NULL DEFAULT false,
    ADD COLUMN force_consent boolean NOT NULL DEFAULT false,
    ADD COLUMN max_age_seconds bigint,
    ADD COLUMN prior_session_id uuid,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN expires_at timestamptz;
ALTER TABLE public.auth_authorization_codes ADD COLUMN consent_group_version bigint;
CREATE UNIQUE INDEX phase08_auth_codes_by_digest ON public.auth_authorization_codes(code_digest);
ALTER TABLE public.auth_grants
    ALTER COLUMN user_id DROP NOT NULL,
    ALTER COLUMN consent_id DROP NOT NULL,
    ALTER COLUMN consent_generation DROP NOT NULL;
ALTER TABLE public.auth_grants
    ADD COLUMN subject_mode text DEFAULT 'USER',
    ADD COLUMN consent_group_version bigint,
    ADD COLUMN source_session_id uuid,
    ADD COLUMN context_mode text DEFAULT 'ACCOUNT_ONLY',
    ADD COLUMN context_ref uuid,
    ADD COLUMN account_version bigint,
    ADD COLUMN client_policy_version bigint,
    ADD COLUMN application_projection_version bigint,
    ADD COLUMN credential_version bigint,
    ADD COLUMN scope_ids uuid[],
    ADD COLUMN audiences text[],
    ADD COLUMN auth_time timestamptz,
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE public.auth_access_tokens
    ADD COLUMN token_digest text,
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE UNIQUE INDEX phase08_access_tokens_by_digest ON public.auth_access_tokens(token_digest) WHERE token_digest IS NOT NULL;
CREATE TABLE public.auth_grant_scopes(
    grant_id uuid NOT NULL REFERENCES public.auth_grants(id),
    resource_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    PRIMARY KEY(grant_id,resource_id,scope_id)
);
CREATE TABLE public.auth_access_token_scopes(
    token_id uuid NOT NULL REFERENCES public.auth_access_tokens(id),
    resource_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    PRIMARY KEY(token_id,resource_id,scope_id)
);
ALTER TABLE public.auth_refresh_families
    ADD COLUMN absolute_expires_at timestamptz,
    ADD COLUMN idle_expires_at timestamptz,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE public.auth_refresh_tokens
    ADD COLUMN token_digest text,
    ADD COLUMN generation bigint,
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN consumed_at timestamptz,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE UNIQUE INDEX phase10_refresh_tokens_by_digest ON public.auth_refresh_tokens(token_digest);
CREATE UNIQUE INDEX phase10_refresh_tokens_by_family_generation ON public.auth_refresh_tokens(family_id,generation);
CREATE TABLE public.auth_totp_enrollments(
    user_id uuid PRIMARY KEY,
    secret_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL
);
CREATE TABLE public.auth_totp_factors(
    user_id uuid PRIMARY KEY,
    secret_ciphertext bytea NOT NULL,
    enabled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_accepted_step bigint NOT NULL DEFAULT 0,
    version bigint NOT NULL DEFAULT 1
);
CREATE TABLE public.auth_totp_recovery_codes(
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    code_digest text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    consumed_at timestamptz
);
CREATE TABLE public.auth_mfa_recovery_receipts(
    operation_id uuid PRIMARY KEY,
    target_user_id uuid NOT NULL,
    request_digest text NOT NULL,
    result_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.auth_mfa_recovery_approvals(
    operation_id uuid NOT NULL REFERENCES public.auth_mfa_recovery_receipts(operation_id),
    approver_user_id uuid NOT NULL,
    primary_authenticated_at timestamptz NOT NULL,
    mfa_verified_at timestamptz NOT NULL,
    approval_digest text NOT NULL,
    PRIMARY KEY(operation_id,approver_user_id)
);
CREATE TABLE public.auth_security_notification_outbox(
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    event_kind text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    delivered_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    last_error_code text
);
CREATE TABLE public.auth_context_interactions(
    transaction_id uuid PRIMARY KEY,
    request_hash text NOT NULL UNIQUE,
    client_id uuid NOT NULL REFERENCES auth_clients(id),
    client_policy_version bigint NOT NULL,
    application_id uuid NOT NULL REFERENCES auth_applications(application_id),
    application_projection_version bigint NOT NULL,
    redirect_uri text NOT NULL,
    state_digest text NOT NULL,
    nonce_digest text NOT NULL,
    code_challenge text NOT NULL,
    intent jsonb NOT NULL,
    authorization_request_id uuid UNIQUE REFERENCES auth_authorization_requests(id) ON DELETE CASCADE,
    source_digest text UNIQUE,
    selected_membership_id uuid,
    credential_ciphertext text,
    selection_expires_at timestamptz,
    grant_id uuid UNIQUE,
    delivered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL
);
ALTER TABLE public.auth_grants
    ADD CONSTRAINT phase12_auth_grants_context_ref_fk FOREIGN KEY(context_ref)
        REFERENCES public.auth_context_interactions(transaction_id),
    ADD CONSTRAINT phase12_auth_grants_id_context_ref_unique UNIQUE(id,context_ref);
ALTER TABLE public.auth_context_interactions
    ADD CONSTRAINT phase12_auth_context_grant_fk FOREIGN KEY(grant_id,transaction_id)
        REFERENCES public.auth_grants(id,context_ref);
CREATE UNIQUE INDEX phase12_auth_grants_context_ref_unique
    ON public.auth_grants(context_ref) WHERE context_ref IS NOT NULL;
"#,
    )
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn auth_fixture(db: &Database, key: &KeyFixture) -> Result<AuthFixture> {
    let user_id = db.user;
    let application_id = Uuid::now_v7();
    let resource_id = Uuid::now_v7();
    let openid_id = Uuid::now_v7();
    let profile_id = Uuid::now_v7();
    let group_id = Uuid::now_v7();
    let confidential_client_id = Uuid::now_v7();
    let public_client_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let session_token = "6b".repeat(32);
    let csrf = crate::util::hash::sha256_hex(&format!("sso-session-csrf-v1:{session_token}"));
    let confidential_client_name = "phase08-confidential".to_owned();
    let client_secret = "8a".repeat(32);
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned();
    let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));

    sqlx::query("INSERT INTO auth_applications(application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) VALUES($1,NULL,'FIRST_PARTY','APPROVED','Phase 8 Account App','Third-party account sign-in',ARRAY['openid','profile'],1,clock_timestamp())")
        .bind(application_id).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'userinfo','https://auth.saas.test/oauth/userinfo','ACTIVE',1)")
        .bind(resource_id).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$3,'openid','ACTIVE'),($2,$3,'profile','ACTIVE')")
        .bind(openid_id).bind(profile_id).bind(resource_id).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_consent_groups(id,application_id,environment,display_name,purpose,subject_mode,context_mode,status,version) VALUES($1,$2,'test','Account sign-in clients','Third-party account sign-in','USER','ACCOUNT_ONLY','ACTIVE',1)")
        .bind(group_id).bind(application_id).execute(&db.pool).await?;
    for (id, client_name, client_type, runtime, token_method, grant_types, redirect) in [
        (
            confidential_client_id,
            confidential_client_name.as_str(),
            "CONFIDENTIAL",
            "WEB_BFF",
            "client_secret_basic",
            vec!["authorization_code".to_owned()],
            "https://client.example.test/callback",
        ),
        (
            public_client_id,
            "phase08-public",
            "PUBLIC",
            "SPA",
            "none",
            vec!["authorization_code".to_owned()],
            "https://public.example.test/callback",
        ),
    ] {
        let client_id = if id == confidential_client_id {
            confidential_client_name.clone()
        } else {
            "phase08-public".to_owned()
        };
        sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,post_logout_redirect_uris,status,version,policy_version,created_at,updated_at) VALUES($1,$2,$3,$4,'test',$5,$6,'USER','ACCOUNT_ONLY',ARRAY[]::text[],$7,$8,ARRAY[$9]::text[],ARRAY[]::text[],'ENABLED',1,1,clock_timestamp(),clock_timestamp())")
            .bind(id).bind(client_id).bind(client_name).bind(application_id).bind(client_type).bind(runtime).bind(grant_types).bind(token_method).bind(redirect).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_client_permissions(client_id,resource_id,scope_id,version) VALUES($1,$2,$3,1),($1,$2,$4,1)")
            .bind(id).bind(resource_id).bind(openid_id).bind(profile_id).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_consent_group_clients(group_id,client_id,application_id,environment,subject_mode,context_mode) VALUES($1,$2,$3,'test','USER','ACCOUNT_ONLY')")
            .bind(group_id).bind(id).bind(application_id).execute(&db.pool).await?;
    }
    sqlx::query("UPDATE auth_consent_groups SET version=2 WHERE id=$1")
        .bind(group_id)
        .execute(&db.pool)
        .await?;
    sqlx::query("INSERT INTO auth_client_credentials(id,client_id,client_type,credential_version,secret_digest,created_at) VALUES($1,$2,'CONFIDENTIAL',1,$3,clock_timestamp())")
        .bind(Uuid::now_v7()).bind(confidential_client_id).bind(crate::util::hash::sha256_hex(&client_secret)).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_consents(id,user_id,group_id,status,generation,group_version,version,authorized_at) VALUES($1,$2,$3,'ACTIVE',1,1,1,clock_timestamp())")
        .bind(Uuid::now_v7()).bind(user_id).bind(group_id).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_consent_scopes(consent_id,resource_id,scope_id) SELECT id,$2,$3 FROM auth_consents WHERE user_id=$1 AND group_id=$4")
        .bind(user_id).bind(resource_id).bind(openid_id).bind(group_id).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_signing_keys(kid,n,e,published_at,active,activated_at) VALUES('phase08-test', $1,$2,clock_timestamp(),true,clock_timestamp())")
        .bind(&key.modulus).bind(&key.exponent).execute(&db.pool).await?;
    sqlx::query("INSERT INTO sso_sessions(id,user_id,token_hash,csrf_hash,account_version,authenticated_at,expires_at) VALUES($1,$2,$3,$4,1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')")
        .bind(session_id).bind(user_id).bind(crate::util::hash::sha256_hex(&session_token)).bind(crate::util::hash::sha256_hex(&csrf)).execute(&db.pool).await?;

    Ok(AuthFixture {
        user_id,
        application_id,
        resource_id,
        openid_id,
        profile_id,
        group_id,
        confidential_client_id,
        public_client_id,
        session_id,
        session_token,
        csrf,
        confidential_client_name,
        client_secret,
        verifier,
        challenge,
    })
}

async fn additional_account(db: &Database, template: &AuthFixture) -> Result<AuthFixture> {
    let mut fixture = template.clone();
    fixture.user_id = Uuid::now_v7();
    fixture.session_id = Uuid::now_v7();
    fixture.session_token = Uuid::now_v7().simple().to_string().repeat(2);
    fixture.csrf =
        crate::util::hash::sha256_hex(&format!("sso-session-csrf-v1:{}", fixture.session_token));
    let username = format!("phase10-user-{}", fixture.user_id.simple());
    sqlx::query(
        "INSERT INTO public.users(id,username,password_hash,real_name) \
         VALUES($1,$2,'unusable-phase10-test-hash','Phase 10 test account')",
    )
    .bind(fixture.user_id)
    .bind(username)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.sso_sessions(id,user_id,token_hash,csrf_hash,account_version,authenticated_at,expires_at) \
         VALUES($1,$2,$3,$4,1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')",
    )
    .bind(fixture.session_id)
    .bind(fixture.user_id)
    .bind(crate::util::hash::sha256_hex(&fixture.session_token))
    .bind(crate::util::hash::sha256_hex(&fixture.csrf))
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.auth_consents(id,user_id,group_id,status,generation,group_version,version,authorized_at) \
         SELECT $1,$2,$3,'ACTIVE',1,version,1,clock_timestamp() FROM public.auth_consent_groups WHERE id=$3",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.user_id)
    .bind(fixture.group_id)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.auth_consent_scopes(consent_id,resource_id,scope_id) \
         SELECT consent.id,$2,$3 FROM public.auth_consents consent \
         WHERE consent.user_id=$1 AND consent.group_id=$4",
    )
    .bind(fixture.user_id)
    .bind(fixture.resource_id)
    .bind(fixture.openid_id)
    .bind(fixture.group_id)
    .execute(&db.pool)
    .await?;
    Ok(fixture)
}

async fn enable_refresh_client(db: &Database, fixture: &AuthFixture) -> Result<Uuid> {
    let offline_scope_id = Uuid::now_v7();
    sqlx::query(
        "UPDATE public.auth_applications SET approved_scopes=ARRAY['openid','profile','offline_access'] \
         WHERE application_id=$1",
    )
    .bind(fixture.application_id)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "UPDATE public.auth_clients SET grant_types=ARRAY['authorization_code','refresh_token'], \
         policy_version=policy_version+1 WHERE id=$1",
    )
    .bind(fixture.confidential_client_id)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.auth_scopes(id,resource_id,scope_name,status) \
         VALUES($1,$2,'offline_access','ACTIVE')",
    )
    .bind(offline_scope_id)
    .bind(fixture.resource_id)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.auth_client_permissions(client_id,resource_id,scope_id,version) \
         VALUES($1,$2,$3,1)",
    )
    .bind(fixture.confidential_client_id)
    .bind(fixture.resource_id)
    .bind(offline_scope_id)
    .execute(&db.pool)
    .await?;
    Ok(offline_scope_id)
}

fn state_with_key(db: &Database, key: &KeyFixture) -> Result<crate::state::AppState> {
    let state = db.state()?;
    let mut config = (*state.config).clone();
    config.oidc_keys = Some(Arc::new(crate::oidc::KeySet::load(
        key.keyset
            .to_str()
            .ok_or_else(|| anyhow!("test keyset path is not UTF-8"))?,
    )?));
    config.sso_totp_encryption_key = Some([0x42; 32]);
    Ok(crate::state::AppState::new(
        db.pool.clone(),
        Arc::new(config),
    ))
}

fn state_with_context_fixture(
    db: &Database,
    key: &KeyFixture,
    port: UnifiedSelectionFixture,
) -> Result<crate::state::AppState> {
    let mut state = state_with_key(db, key)?;
    let mut config = (*state.config).clone();
    config.context_cipher = Some(Arc::new(crate::oidc::context::crypto::Keys::fixture()));
    state.config = Arc::new(config);
    state.context_platform = Arc::new(port);
    Ok(state)
}

fn context_choice(
    membership_id: Uuid,
    user_id: Uuid,
    tenant_id: Uuid,
    organization_id: Uuid,
    member_type: &str,
) -> ContextChoice {
    ContextChoice {
        membership_id,
        user_id,
        tenant_id,
        organization_id,
        member_type: member_type.to_owned(),
        identity_version: "1".to_owned(),
        tenant_name: format!("{member_type} tenant"),
        organization_name: format!("{member_type} organization"),
        organization_path: format!("/{member_type}/organization"),
    }
}

async fn context_source_call(
    app: &Router,
    service_id: Uuid,
    service_secret: &str,
    body: Value,
) -> Result<(StatusCode, Value)> {
    let authorization = STANDARD.encode(format!("{service_id}:{service_secret}"));
    let response = app
        .clone()
        .oneshot(
            Request::post("/internal/identity/auth/context-selection/source")
                .header(header::AUTHORIZATION, format!("Basic {authorization}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, value))
}

fn test_key_fixture() -> Result<KeyFixture> {
    let directory =
        std::env::temp_dir().join(format!("identity-phase08-test-key-{}", Uuid::now_v7()));
    fs::create_dir(&directory)?;
    // Own the directory before any fallible subprocess or file operation so a
    // failed constructor cannot leave key material or even an empty directory.
    let mut fixture = KeyFixture {
        keyset: directory.join("keyset.json"),
        directory,
        modulus: String::new(),
        exponent: "AQAB".into(),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700))?;
    }
    let private_path = fixture.directory.join("private.pem");
    let private_native = wsl_path(&private_path)?;
    let generated = openssl_command()
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
        ])
        .arg(&private_native)
        .output()?;
    ensure!(
        generated.status.success(),
        "temporary RSA fixture generation failed"
    );
    let modulus_output = openssl_command()
        .args(["rsa", "-in"])
        .arg(&private_native)
        .args(["-noout", "-modulus"])
        .output()?;
    ensure!(
        modulus_output.status.success(),
        "temporary RSA fixture inspection failed"
    );
    let modulus_hex = String::from_utf8(modulus_output.stdout)?
        .trim()
        .strip_prefix("Modulus=")
        .ok_or_else(|| anyhow!("temporary RSA fixture modulus is unavailable"))?
        .to_owned();
    fixture.modulus = URL_SAFE_NO_PAD.encode(hex::decode(modulus_hex)?);
    let private_key_pem = fs::read_to_string(&private_path)?;
    let keyset_json = serde_json::to_vec(&json!({
        "keys":[{"kid":"phase08-test","privateKeyPem":private_key_pem,"n":fixture.modulus,"e":fixture.exponent}]
    }))?;
    fs::write(&fixture.keyset, keyset_json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&private_path, &fixture.keyset] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(fixture)
}

fn openssl_command() -> Command {
    if cfg!(windows) {
        let mut command = Command::new("wsl.exe");
        command.args(["-e", "openssl"]);
        command
    } else {
        Command::new("openssl")
    }
}

fn wsl_path(path: &Path) -> Result<String> {
    if !cfg!(windows) {
        return Ok(path.to_string_lossy().into_owned());
    }
    let output = Command::new("wsl.exe")
        .arg("-e")
        .arg("wslpath")
        .arg("-u")
        .arg(path)
        .output()?;
    ensure!(
        output.status.success(),
        "could not map temporary test path into WSL"
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn router(state: crate::state::AppState) -> Router {
    crate::oidc::routes()
        .merge(crate::sso::routes())
        .with_state(state)
}

fn validate_test_id_token(
    token: &str,
    decoding: &jsonwebtoken::DecodingKey,
    expected_issuer: &str,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<Value> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);
    let claims = jsonwebtoken::decode::<Value>(token, decoding, &validation)?.claims;
    ensure!(claims["nonce"] == expected_nonce, "ID Token nonce mismatch");
    Ok(claims)
}

fn session_cookie(f: &AuthFixture) -> String {
    format!("__Host-saas_sso={}", f.session_token)
}

fn append_cookie(base: &str, browser_cookie: &str) -> String {
    format!("{base}; {browser_cookie}")
}

fn callback_parameter(location: &str, name: &str) -> Result<String> {
    let url = reqwest::Url::parse(location)?;
    url.query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
        .ok_or_else(|| anyhow!("authorization callback omitted {name}"))
}

fn location(response: &HeaderMap) -> Result<String> {
    Ok(response
        .get(header::LOCATION)
        .ok_or_else(|| anyhow!("OAuth response omitted Location"))?
        .to_str()?
        .to_owned())
}

#[allow(clippy::too_many_arguments)] // Shared HTTP fixture keeps cookies, Origin, CSRF and body controls explicit.
async fn send(
    app: &Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
    csrf: Option<&str>,
    content_type: Option<&str>,
    body: Option<Vec<u8>>,
) -> Result<(StatusCode, HeaderMap, Value)> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.unwrap_or_default()))?)
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}))
    };
    Ok((status, headers, value))
}

fn authorize_url(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    challenge: &str,
    prompt: Option<&str>,
) -> Result<String> {
    let mut url = reqwest::Url::parse("https://auth.saas.test/oauth/authorize")?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", scope)
            .append_pair("state", "phase08-state-value-1234567890")
            .append_pair("nonce", "phase08-nonce-value-1234567890")
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        if let Some(prompt) = prompt {
            query.append_pair("prompt", prompt);
        }
    }
    Ok(url.to_string())
}

async fn authorize(
    app: &Router,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    challenge: &str,
    prompt: Option<&str>,
    cookie: Option<&str>,
) -> Result<(HeaderMap, String)> {
    let url = authorize_url(client_id, redirect_uri, scope, challenge, prompt)?;
    let path = reqwest::Url::parse(&url)?
        .query()
        .map(|query| format!("/oauth/authorize?{query}"))
        .ok_or_else(|| anyhow!("authorization query missing"))?;
    let (status, headers, _) = send(app, "GET", &path, cookie, None, None, None, None).await?;
    ensure!(
        status.is_redirection() || status == StatusCode::BAD_REQUEST,
        "authorization returned unexpected HTTP status {status}"
    );
    Ok((
        headers.clone(),
        if headers.contains_key(header::LOCATION) {
            location(&headers)?
        } else {
            String::new()
        },
    ))
}

async fn authorize_max_age_zero(
    app: &Router,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    challenge: &str,
    cookie: &str,
) -> Result<(HeaderMap, String)> {
    let base = authorize_url(client_id, redirect_uri, scope, challenge, None)?;
    let mut url = reqwest::Url::parse(&base)?;
    url.query_pairs_mut().append_pair("max_age", "0");
    let path = url
        .query()
        .map(|query| format!("/oauth/authorize?{query}"))
        .ok_or_else(|| anyhow!("authorization query missing"))?;
    let (status, headers, _) =
        send(app, "GET", &path, Some(cookie), None, None, None, None).await?;
    ensure!(
        status.is_redirection(),
        "max_age authorization returned unexpected HTTP status {status}"
    );
    let target = location(&headers)?;
    Ok((headers, target))
}

async fn authorize_and_consent(app: &Router, fixture: &AuthFixture, scope: &str) -> Result<String> {
    let redirect_uri = "https://client.example.test/callback";
    let (authorize_headers, target) = authorize(
        app,
        &fixture.confidential_client_name,
        redirect_uri,
        scope,
        &fixture.challenge,
        None,
        Some(&session_cookie(fixture)),
    )
    .await?;
    if target.starts_with(redirect_uri) {
        return callback_parameter(&target, "code");
    }
    ensure!(
        target.starts_with("/oauth/login?flow="),
        "unexpected authorization interaction target"
    );
    let flow = target
        .split("flow=")
        .nth(1)
        .ok_or_else(|| anyhow!("authorization interaction flow missing"))?;
    let browser = browser_value(&authorize_headers)?;
    let cookie = append_cookie(
        &session_cookie(fixture),
        &format!("__Host-saas_oauth_browser={browser}"),
    );
    let (status, _, interaction) = send(
        app,
        "GET",
        &format!("/oauth/interaction/{flow}"),
        Some(&cookie),
        Some("https://auth.saas.test"),
        None,
        None,
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && interaction["status"] == "CONSENT_REQUIRED",
        "authorization did not request explicit consent"
    );
    let csrf = interaction["csrfToken"]
        .as_str()
        .ok_or_else(|| anyhow!("authorization interaction CSRF missing"))?;
    let (status, _, approval) = send(
        app,
        "POST",
        &format!("/oauth/interaction/{flow}"),
        Some(&cookie),
        Some("https://auth.saas.test"),
        Some(csrf),
        Some("application/json"),
        Some(serde_json::to_vec(&json!({"action":"approve"}))?),
    )
    .await?;
    ensure!(status == StatusCode::OK, "explicit OAuth consent failed");
    let callback = approval["redirectTo"]
        .as_str()
        .ok_or_else(|| anyhow!("authorization callback missing after consent"))?;
    callback_parameter(callback, "code")
}

fn browser_value(headers: &HeaderMap) -> Result<String> {
    let cookie = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("__Host-saas_oauth_browser="))
        .ok_or_else(|| anyhow!("OAuth browser cookie missing"))?;
    cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('=').map(|(_, value)| value.to_owned()))
        .ok_or_else(|| anyhow!("OAuth browser cookie is malformed"))
}

fn form_body(values: &[(&str, &str)]) -> Result<Vec<u8>> {
    let mut url = reqwest::Url::parse("https://form.example.test/")?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in values {
            query.append_pair(key, value);
        }
    }
    Ok(url.query().unwrap_or_default().as_bytes().to_vec())
}

async fn exchange_confidential(
    app: &Router,
    client_id: &str,
    secret: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<(StatusCode, Value)> {
    let authorization = STANDARD.encode(format!("{client_id}:{secret}"));
    let body = form_body(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ])?;
    let response = app
        .clone()
        .oneshot(
            Request::post("/oauth/token")
                .header(header::AUTHORIZATION, format!("Basic {authorization}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, value))
}

async fn refresh_confidential(
    app: &Router,
    client_id: &str,
    secret: &str,
    refresh_token: &str,
    scope: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let authorization = STANDARD.encode(format!("{client_id}:{secret}"));
    let mut fields = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    if let Some(scope) = scope {
        fields.push(("scope", scope));
    }
    let response = app
        .clone()
        .oneshot(
            Request::post("/oauth/token")
                .header(header::AUTHORIZATION, format!("Basic {authorization}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form_body(&fields)?))?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, value))
}

async fn machine_token(
    app: &Router,
    client_id: &str,
    secret: &str,
    scope: &str,
) -> Result<(StatusCode, Value)> {
    let authorization = STANDARD.encode(format!("{client_id}:{secret}"));
    let response = app
        .clone()
        .oneshot(
            Request::post("/oauth/token")
                .header(header::AUTHORIZATION, format!("Basic {authorization}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form_body(&[
                    ("grant_type", "client_credentials"),
                    ("scope", scope),
                ])?))?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, value))
}

async fn userinfo_get(app: &Router, access_token: &str) -> Result<(StatusCode, Value)> {
    let response = app
        .clone()
        .oneshot(
            Request::get("/oauth/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, value))
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL and IDENTITY_PHASE12_TEST_MARKER"]
async fn phase19_third_party_access_token_requires_current_environment_admission() -> Result<()> {
    let db = Database::create_phase12_context().await?;
    let result = async {
        prepare_phase08_schema(&db).await?;
        let key = test_key_fixture()?;
        let fixture = auth_fixture(&db, &key).await?;
        sqlx::query("UPDATE auth_applications SET ownership='THIRD_PARTY',partner_id=$2 WHERE application_id=$1")
            .bind(fixture.application_id).bind(Uuid::now_v7()).execute(&db.pool).await?;
        // The fixture models the identity-owned admission rows. Issuance and
        // access checks below use the real OAuth HTTP handlers and database.
        sqlx::query("INSERT INTO auth_application_admissions(application_id,environment,status,redirect_uris,post_logout_redirect_uris,scopes) VALUES($1,'test','APPROVED',ARRAY['https://client.example.test/callback'],ARRAY[]::text[],ARRAY['openid','profile']),($1,'production','APPROVED',ARRAY['https://production.example.test/callback'],ARRAY[]::text[],ARRAY['openid','profile'])")
            .bind(fixture.application_id).execute(&db.pool).await?;
        let app = router(state_with_key(&db, &key)?);
        let code = authorize_and_consent(&app, &fixture, "openid profile").await?;
        let (status, tokens) = exchange_confidential(
            &app, &fixture.confidential_client_name, &fixture.client_secret,
            "https://client.example.test/callback", &code, &fixture.verifier,
        ).await?;
        ensure!(status == StatusCode::OK, "reviewed third-party token issuance failed");
        let access = tokens["access_token"].as_str()
            .ok_or_else(|| anyhow!("reviewed third-party access token missing"))?;
        ensure!(userinfo_get(&app, access).await?.0 == StatusCode::OK,
            "approved current-environment token failed its control access check");
        sqlx::query("DELETE FROM auth_application_admissions WHERE application_id=$1 AND environment='test'")
            .bind(fixture.application_id).execute(&db.pool).await?;
        let unchanged: (String, i64) = sqlx::query_as(
            "SELECT status,projection_version FROM auth_applications WHERE application_id=$1",
        ).bind(fixture.application_id).fetch_one(&db.pool).await?;
        ensure!(unchanged == ("APPROVED".to_owned(), 1),
            "the admission regression accidentally invalidated the global projection");
        ensure!(userinfo_get(&app, access).await?.0 == StatusCode::UNAUTHORIZED,
            "a surviving production admission kept a token active after its test admission disappeared");
        sqlx::query("INSERT INTO auth_application_admissions(application_id,environment,status,redirect_uris,post_logout_redirect_uris,scopes) VALUES($1,'test','APPROVED',ARRAY['https://client.example.test/callback'],ARRAY[]::text[],ARRAY['openid','profile'])")
            .bind(fixture.application_id).execute(&db.pool).await?;
        ensure!(userinfo_get(&app, access).await?.0 == StatusCode::OK,
            "restored exact admission did not preserve the original live token");
        sqlx::query("UPDATE auth_application_admissions SET status='SUSPENDED' WHERE application_id=$1 AND environment='test'")
            .bind(fixture.application_id).execute(&db.pool).await?;
        ensure!(userinfo_get(&app, access).await?.0 == StatusCode::UNAUTHORIZED,
            "current-environment suspension was ignored during online access validation");
        sqlx::query("UPDATE auth_application_admissions SET status='APPROVED',redirect_uris=ARRAY['https://other.example.test/callback'] WHERE application_id=$1 AND environment='test'")
            .bind(fixture.application_id).execute(&db.pool).await?;
        ensure!(userinfo_get(&app, access).await?.0 == StatusCode::UNAUTHORIZED,
            "online access ignored callback drift outside the current reviewed admission");
        Ok::<(), anyhow::Error>(())
    }.await;
    db.finish(result).await
}

async fn exchange_public(
    app: &Router,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<(StatusCode, Value)> {
    let body = form_body(&[
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ])?;
    let response = app
        .clone()
        .oneshot(
            Request::post("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, value))
}

async fn add_resource_client(
    db: &Database,
    client_id: &str,
    display_name: &str,
    approved_scopes: &[&str],
    resource_id: Uuid,
    scope_id: Uuid,
    client_secret: &str,
) -> Result<Uuid> {
    let application_id = Uuid::now_v7();
    let client_uuid = Uuid::now_v7();
    sqlx::query("INSERT INTO auth_applications(application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) VALUES($1,NULL,'FIRST_PARTY','APPROVED',$2,'Resource API', $3,1,clock_timestamp())")
        .bind(application_id).bind(display_name).bind(approved_scopes).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,post_logout_redirect_uris,status,version,policy_version,created_at,updated_at) VALUES($1,$2,$3,$4,'test','CONFIDENTIAL','SERVICE','MACHINE','NONE',ARRAY[]::text[],ARRAY['client_credentials']::text[],'client_secret_basic',ARRAY[]::text[],ARRAY[]::text[],'ENABLED',1,1,clock_timestamp(),clock_timestamp())")
        .bind(client_uuid).bind(client_id).bind(display_name).bind(application_id).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_client_credentials(id,client_id,client_type,credential_version,secret_digest,created_at) VALUES($1,$2,'CONFIDENTIAL',1,$3,clock_timestamp())")
        .bind(Uuid::now_v7()).bind(client_uuid).bind(crate::util::hash::sha256_hex(client_secret)).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_client_permissions(client_id,resource_id,scope_id,version) VALUES($1,$2,$3,1)")
        .bind(client_uuid).bind(resource_id).bind(scope_id).execute(&db.pool).await?;
    Ok(client_uuid)
}

async fn introspect_access(
    app: &Router,
    client_id: &str,
    secret: &str,
    token: &str,
    resource: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let mut fields = vec![("token", token)];
    if let Some(resource) = resource {
        fields.push(("resource", resource));
    }
    let authorization = STANDARD.encode(format!("{client_id}:{secret}"));
    let response = app
        .clone()
        .oneshot(
            Request::post("/oauth/introspect")
                .header(header::AUTHORIZATION, format!("Basic {authorization}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form_body(&fields)?))?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn revoke_access(
    app: &Router,
    client_id: &str,
    secret: &str,
    token: &str,
) -> Result<StatusCode> {
    let authorization = STANDARD.encode(format!("{client_id}:{secret}"));
    let response = app
        .clone()
        .oneshot(
            Request::post("/oauth/revoke")
                .header(header::AUTHORIZATION, format!("Basic {authorization}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form_body(&[("token", token)])?))?,
        )
        .await?;
    Ok(response.status())
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE08_TEST_DATABASE_URL and IDENTITY_PHASE08_TEST_MARKER"]
async fn phase08_authorization_code_pkce_consent_pairwise_id_token_and_userinfo_use_one_registry(
) -> Result<()> {
    let db = Database::create_phase08().await?;
    let result = async {
        prepare_phase08_schema(&db).await?;
        let key = test_key_fixture()?;
        let fixture = auth_fixture(&db, &key).await?;
        let state = state_with_key(&db, &key)?;
        let app = router(state.clone());
        let session = session_cookie(&fixture);
        let redirect_uri = "https://client.example.test/callback";

        let (status, _, metadata) = send(
            &app,
            "GET",
            "/.well-known/openid-configuration",
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
        ensure!(status == StatusCode::OK, "OIDC discovery failed");
        ensure!(
            metadata["issuer"] == "https://auth.saas.test"
                && metadata["authorization_endpoint"]
                    == "https://auth.saas.test/oauth/authorize"
                && metadata["token_endpoint"] == "https://auth.saas.test/oauth/token"
                && metadata["userinfo_endpoint"] == "https://auth.saas.test/oauth/userinfo"
                && metadata["jwks_uri"] == "https://auth.saas.test/oauth/jwks",
            "discovery did not advertise the canonical issuer and OAuth endpoints"
        );
        ensure!(
            metadata["response_types_supported"] == json!(["code"])
                && metadata["grant_types_supported"] == json!(["authorization_code", "refresh_token", "client_credentials"])
                && metadata["subject_types_supported"] == json!(["pairwise"])
                && metadata["code_challenge_methods_supported"] == json!(["S256"])
                && metadata["scopes_supported"].as_array().is_some_and(|scopes| scopes.iter().any(|scope| scope == "offline_access")),
            "discovery does not match the implemented authorization-code contract"
        );
        ensure!(
            metadata.get("refresh_endpoint").is_none()
                && metadata["introspection_endpoint"] == "https://auth.saas.test/oauth/introspect"
                && metadata["revocation_endpoint"] == "https://auth.saas.test/oauth/revoke"
                && metadata.get("end_session_endpoint").is_none(),
            "discovery did not match implemented resource-token endpoints"
        );

        let (_, none_target) = authorize(
            &app,
            &fixture.confidential_client_name,
            redirect_uri,
            "openid profile",
            &fixture.challenge,
            Some("none"),
            Some(&session),
        )
        .await?;
        ensure!(
            callback_parameter(&none_target, "error")? == "consent_required",
            "prompt=none did not return consent_required for expanded consent"
        );
        let (bad_redirect_status, _, _) = send(
            &app,
            "GET",
            &format!(
                "/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fevil.example.test%2Fcb&response_type=code&scope=openid&state=phase08-state-value-1234567890&nonce=phase08-nonce-value-1234567890&code_challenge={}&code_challenge_method=S256",
                fixture.confidential_client_name,fixture.challenge
            ),
            Some(&session),
            None,
            None,
            None,
            None,
        )
        .await?;
        ensure!(bad_redirect_status == StatusCode::BAD_REQUEST, "unregistered callback was redirected");

        // The public authorization endpoint asks again because both the group
        // membership version and requested profile scope exceed stored consent.
        let (authorize_headers, target) = authorize(
            &app,
            &fixture.confidential_client_name,
            redirect_uri,
            "openid profile",
            &fixture.challenge,
            None,
            Some(&session),
        )
        .await?;
        ensure!(
            target.starts_with("/oauth/login?flow="),
            "insufficient consent did not enter the canonical interaction"
        );
        let flow = target
            .split("flow=")
            .nth(1)
            .ok_or_else(|| anyhow!("interaction flow missing"))?;
        let browser = browser_value(&authorize_headers)?;
        let browser_session =
            append_cookie(&session, &format!("__Host-saas_oauth_browser={browser}"));
        let (status, _, interaction) = send(
            &app,
            "GET",
            &format!("/oauth/interaction/{flow}"),
            Some(&browser_session),
            Some("https://auth.saas.test"),
            None,
            None,
            None,
        )
        .await?;
        ensure!(
            status == StatusCode::OK && interaction["status"] == "CONSENT_REQUIRED",
            "scope/group expansion was not shown for confirmation"
        );
        let csrf = interaction["csrfToken"]
            .as_str()
            .ok_or_else(|| anyhow!("interaction CSRF token missing"))?;
        let (status, _, approval) = send(
            &app,
            "POST",
            &format!("/oauth/interaction/{flow}"),
            Some(&browser_session),
            Some("https://auth.saas.test"),
            Some(csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"action":"approve"}))?),
        )
        .await?;
        ensure!(status == StatusCode::OK, "explicit consent approval failed");
        let callback = reqwest::Url::parse(
            approval["redirectTo"]
                .as_str()
                .ok_or_else(|| anyhow!("approval callback missing"))?,
        )?;
        ensure!(
            callback
                .query_pairs()
                .any(|(name, value)| name == "state" && value == "phase08-state-value-1234567890"),
            "state was not returned unchanged"
        );
        ensure!(
            callback
                .query_pairs()
                .any(|(name, value)| name == "iss" && value == "https://auth.saas.test"),
            "authorization response issuer missing"
        );
        let code = callback_parameter(approval["redirectTo"].as_str().unwrap_or_default(), "code")?;

        let (status, _) = exchange_confidential(
            &app,
            &fixture.confidential_client_name,
            &"00".repeat(32),
            redirect_uri,
            &code,
            &fixture.verifier,
        )
        .await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "CONFIDENTIAL client accepted an invalid secret");

        let bad_verifier = "v".repeat(43);
        let (status, _) = exchange_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            redirect_uri,
            &code,
            &bad_verifier,
        )
        .await?;
        ensure!(
            status == StatusCode::BAD_REQUEST,
            "wrong PKCE verifier was accepted"
        );
        let (status, tokens) = exchange_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            redirect_uri,
            &code,
            &fixture.verifier,
        )
        .await?;
        ensure!(
            status == StatusCode::OK,
            "confidential authorization code exchange failed"
        );
        let (replay_status, _) = exchange_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            redirect_uri,
            &code,
            &fixture.verifier,
        )
        .await?;
        ensure!(
            replay_status == StatusCode::BAD_REQUEST,
            "a redeemed authorization code was accepted again"
        );
        let confidential_grants: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth_grants WHERE client_id=$1 AND consent_group_version=2",
        )
        .bind(fixture.confidential_client_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(
            confidential_grants == 1,
            "confidential exchange did not persist the group-version fence"
        );
        let id_token = tokens["id_token"]
            .as_str()
            .ok_or_else(|| anyhow!("ID Token missing"))?;
        let decoding = jsonwebtoken::DecodingKey::from_rsa_components(&key.modulus, &key.exponent)?;
        ensure!(
            validate_test_id_token(
                id_token,
                &decoding,
                "https://wrong-issuer.example.test",
                &fixture.confidential_client_name,
                "phase08-nonce-value-1234567890",
            )
            .is_err(),
            "client verifier accepted an ID Token from the wrong issuer"
        );
        ensure!(
            validate_test_id_token(
                id_token,
                &decoding,
                "https://auth.saas.test",
                &fixture.confidential_client_name,
                "wrong-expected-nonce-value-1234567890",
            )
            .is_err(),
            "client verifier accepted an ID Token with the wrong nonce"
        );
        let claims = validate_test_id_token(
            id_token,
            &decoding,
            "https://auth.saas.test",
            &fixture.confidential_client_name,
            "phase08-nonce-value-1234567890",
        )?;
        ensure!(
            claims["nonce"] == "phase08-nonce-value-1234567890",
            "ID Token nonce mismatch"
        );
        ensure!(
            claims["sub"]
                .as_str()
                .is_some_and(|subject| subject != fixture.user_id.to_string()),
            "pairwise subject exposed the internal account UUID"
        );
        ensure!(
            claims["name"] == "Owned audit account",
            "profile claim is missing from ID Token"
        );
        ensure!(
            tokens["refresh_token"].is_null(),
            "Phase 8 advertised or issued a refresh token"
        );
        ensure!(
            tokens["scope"] == "openid profile",
            "token response scope mismatch"
        );

        let access_token = tokens["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("opaque access token missing"))?;
        let (status, _, _userinfo) =
            send(&app, "GET", "/oauth/userinfo", None, None, None, None, None).await?;
        ensure!(
            status == StatusCode::UNAUTHORIZED,
            "userinfo accepted a request without a bearer token"
        );
        let response = app
            .clone()
            .oneshot(
                Request::get("/oauth/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "valid access token was rejected by UserInfo"
        );
        let userinfo: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        ensure!(
            userinfo["sub"] == claims["sub"],
            "ID Token and UserInfo subject mismatch"
        );
        ensure!(
            userinfo["name"] == claims["name"],
            "ID Token and UserInfo profile mismatch"
        );
        ensure!(
            userinfo.get("user_id").is_none(),
            "UserInfo exposed an internal account UUID"
        );

        // The sibling PUBLIC client shares the explicitly versioned group. It
        // authenticates with client_id alone and has no secret record.
        let (headers, target) = authorize(
            &app,
            "phase08-public",
            "https://public.example.test/callback",
            "openid",
            &fixture.challenge,
            Some("none"),
            Some(&browser_session),
        )
        .await?;
        ensure!(
            target.starts_with("https://public.example.test/callback?"),
            "sufficient PUBLIC client consent did not reuse"
        );
        let public_code = callback_parameter(&target, "code")?;
        let (status, public_tokens) = exchange_public(
            &app,
            "phase08-public",
            "https://public.example.test/callback",
            &public_code,
            &fixture.verifier,
        )
        .await?;
        ensure!(
            status == StatusCode::OK,
            "PUBLIC client code exchange without a secret failed"
        );
        let credential_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM auth_client_credentials WHERE client_id=$1")
                .bind(fixture.public_client_id)
                .fetch_one(&db.pool)
                .await?;
        ensure!(
            credential_count == 0,
            "PUBLIC client received a stored secret"
        );

        let (_, consent_target) = authorize(
            &app,
            &fixture.confidential_client_name,
            redirect_uri,
            "openid",
            &fixture.challenge,
            Some("consent"),
            Some(&browser_session),
        )
        .await?;
        ensure!(consent_target.starts_with("/oauth/login?flow="), "prompt=consent reused a stored authorization");
        let consent_flow = consent_target.split("flow=").nth(1).ok_or_else(|| anyhow!("consent flow missing"))?;
        let (status, _, consent_interaction) = send(
            &app,
            "GET",
            &format!("/oauth/interaction/{consent_flow}"),
            Some(&browser_session),
            Some("https://auth.saas.test"),
            None,
            None,
            None,
        )
        .await?;
        ensure!(status == StatusCode::OK && consent_interaction["status"] == "CONSENT_REQUIRED", "prompt=consent did not require an explicit choice");
        let consent_csrf = consent_interaction["csrfToken"].as_str().ok_or_else(|| anyhow!("consent CSRF missing"))?;
        let (status, _, _) = send(
            &app,
            "POST",
            &format!("/oauth/interaction/{consent_flow}"),
            Some(&browser_session),
            Some("https://auth.saas.test"),
            Some(consent_csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"action":"approve"}))?),
        )
        .await?;
        ensure!(status == StatusCode::OK, "explicit prompt=consent confirmation failed");

        // Concurrent redemption serializes at the canonical code row: exactly
        // one request can commit a grant and token.
        let (_, race_target) = authorize(
            &app,
            "phase08-public",
            "https://public.example.test/callback",
            "openid",
            &fixture.challenge,
            Some("none"),
            Some(&browser_session),
        )
        .await?;
        let race_code = callback_parameter(&race_target, "code")?;
        let first = exchange_public(
            &app,
            "phase08-public",
            "https://public.example.test/callback",
            &race_code,
            &fixture.verifier,
        );
        let second = exchange_public(
            &app,
            "phase08-public",
            "https://public.example.test/callback",
            &race_code,
            &fixture.verifier,
        );
        let (first, second) = tokio::join!(first, second);
        let first = first?;
        let second = second?;
        ensure!(
            [first.0, second.0]
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count()
                == 1,
            "concurrent code redemption produced other than one success"
        );
        ensure!(
            [first.0, second.0]
                .iter()
                .filter(|status| **status == StatusCode::BAD_REQUEST)
                .count()
                == 1,
            "concurrent replay did not fail as invalid_grant: {:?} / {:?}",
            first.0,
            second.0
        );

        // Prompt and max_age semantics stay separate from consent reuse.
        let (_, login_target) = authorize(
            &app,
            &fixture.confidential_client_name,
            redirect_uri,
            "openid",
            &fixture.challenge,
            Some("login"),
            Some(&browser_session),
        )
        .await?;
        ensure!(
            login_target.starts_with("/oauth/login?flow="),
            "prompt=login reused the existing SSO session"
        );
        let no_session = authorize(
            &app,
            &fixture.confidential_client_name,
            redirect_uri,
            "openid",
            &fixture.challenge,
            Some("none"),
            None,
        )
        .await?;
        ensure!(
            callback_parameter(&no_session.1, "error")? == "login_required",
            "prompt=none did not return login_required without a session"
        );
        let (_, max_age_target) = authorize_max_age_zero(
            &app,
            &fixture.confidential_client_name,
            redirect_uri,
            "openid",
            &fixture.challenge,
            &browser_session,
        )
        .await?;
        ensure!(max_age_target.starts_with("/oauth/login?flow="), "max_age=0 reused a stale authentication session");
        let _ = (
            headers,
            public_tokens,
            fixture.application_id,
            fixture.resource_id,
            fixture.openid_id,
            fixture.profile_id,
            fixture.group_id,
            fixture.session_id,
            fixture.csrf,
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL and IDENTITY_PHASE12_TEST_MARKER"]
async fn phase12_unified_context_selection_is_source_bound_recoverable_and_one_time() -> Result<()>
{
    let db = Database::create_phase12_context().await?;
    let result = async {
        prepare_phase08_schema(&db).await?;
        let key = test_key_fixture()?;
        let fixture = auth_fixture(&db, &key).await?;
        let employee = add_unified_context_client(&db, &fixture, "employee", "EMPLOYEE").await?;
        let customer = add_unified_context_client(&db, &fixture, "customer", "CUSTOMER").await?;
        let (source_service_id, source_service_secret) =
            add_context_source_service(&db, &[employee.id, customer.id]).await?;
        let transaction_id = Uuid::now_v7();
        let member_one = Uuid::now_v7();
        let member_two = Uuid::now_v7();
        let port = UnifiedSelectionFixture::new(
            employee.id,
            transaction_id,
            vec![
                context_choice(
                    member_one,
                    fixture.user_id,
                    Uuid::now_v7(),
                    Uuid::now_v7(),
                    "EMPLOYEE",
                ),
                context_choice(
                    member_two,
                    fixture.user_id,
                    Uuid::now_v7(),
                    Uuid::now_v7(),
                    "EMPLOYEE",
                ),
            ],
        );
        let observed = port.clone();
        let state = state_with_context_fixture(&db, &key, port)?;
        let app = router(state);
        let session = session_cookie(&fixture);
        let state_value = "phase12-state-value-1234567890";
        let nonce = "phase12-nonce-value-1234567890";

        let (status, created) = create_context_interaction(
            &app,
            &employee,
            transaction_id,
            state_value,
            nonce,
            &fixture.challenge,
        )
        .await?;
        ensure!(status == StatusCode::OK, "canonical context transaction creation failed: {created}");
        let request_handle = created["contextRequest"]
            .as_str()
            .ok_or_else(|| anyhow!("canonical context request handle missing"))?;

        // ACCOUNT_ONLY rejects a platform handle and makes no platform member call.
        let mut account_url = reqwest::Url::parse(&authorize_url(
            &fixture.confidential_client_name,
            "https://client.example.test/callback",
            "openid profile",
            &fixture.challenge,
            None,
        )?)?;
        account_url
            .query_pairs_mut()
            .append_pair("context_request", request_handle);
        let account_path = format!("/oauth/authorize?{}", account_url.query().unwrap_or_default());
        let (wrong_mode_status, _, _) = send(&app, "GET", &account_path, Some(&session), None, None, None, None).await?;
        ensure!(wrong_mode_status == StatusCode::BAD_REQUEST, "ACCOUNT_ONLY accepted a platform context handle");
        let (account_headers, account_target) = authorize(
            &app,
            &fixture.confidential_client_name,
            "https://client.example.test/callback",
            "openid profile",
            &fixture.challenge,
            None,
            Some(&session),
        )
        .await?;
        ensure!(account_target.starts_with("/oauth/login?flow="), "account-only authorization did not enter its regular interaction");
        let account_flow = account_target.split("flow=").nth(1).ok_or_else(|| anyhow!("account-only flow missing"))?;
        let account_browser = browser_value(&account_headers)?;
        let account_cookie = append_cookie(&session, &format!("__Host-saas_oauth_browser={account_browser}"));
        let (status, _, account_interaction) = send(
            &app,
            "GET",
            &format!("/oauth/interaction/{account_flow}"),
            Some(&account_cookie),
            Some("https://auth.saas.test"),
            None,
            None,
            None,
        )
        .await?;
        ensure!(
            status == StatusCode::OK
                && account_interaction["status"] == "CONSENT_REQUIRED"
                && account_interaction["contextSelection"].is_null()
                && account_interaction["contextSelectionRequired"] == false
                && observed.choices_calls.load(Ordering::SeqCst) == 0,
            "ACCOUNT_ONLY called platform context selection or returned a context UI"
        );

        // A handle created for the employee client cannot be rebound to another client.
        let (wrong_client_status, wrong_client_headers, wrong_client_target, wrong_client_body) = authorize_context_client(
            &app,
            &customer,
            request_handle,
            &fixture.challenge,
            state_value,
            nonce,
            &session,
        )
        .await?;
        ensure!(
            matches!(wrong_client_status, StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN)
                && wrong_client_target.is_empty()
                && wrong_client_headers.get(header::LOCATION).is_none(),
            "context handle bound to one client was accepted by another: {wrong_client_status} {wrong_client_body}"
        );

        let (authorize_status, authorize_headers, target, authorize_body) = authorize_context_client(
            &app,
            &employee,
            request_handle,
            &fixture.challenge,
            state_value,
            nonce,
            &session,
        )
        .await?;
        ensure!(target.starts_with("/oauth/login?flow="), "PLATFORM_CONTEXT did not enter its bound interaction: {authorize_status} {target} {authorize_body}");
        let flow = target.split("flow=").nth(1).ok_or_else(|| anyhow!("platform context flow missing"))?;
        let browser = browser_value(&authorize_headers)?;
        let cookie = append_cookie(&session, &format!("__Host-saas_oauth_browser={browser}"));
        let (status, _, interaction) = send(
            &app,
            "GET",
            &format!("/oauth/interaction/{flow}"),
            Some(&cookie),
            Some("https://auth.saas.test"),
            None,
            None,
            None,
        )
        .await?;
        ensure!(
            status == StatusCode::OK
                && interaction["status"] == "CONTEXT_SELECTION_REQUIRED"
                && interaction["contextSelection"]["members"].as_array().is_some_and(|v| v.len() == 2)
                && interaction["contextSelection"]["members"].as_array().is_some_and(|members| members.iter().all(|member| member["memberType"] == "EMPLOYEE"))
                && interaction.get("credential").is_none(),
            "employee candidates were not typed, complete or private"
        );
        ensure!(observed.choices_calls.load(Ordering::SeqCst) == 1, "PLATFORM_CONTEXT did not query its selection authority exactly once");
        let source_proof = crate::util::hash::sha256_hex(&format!("auth-context-selection-source-v1:{browser}:{flow}"));
        let source_request = json!({"contractVersion":"context-selection/1","sourceProof":source_proof,"expectedClientId":employee.id});
        let (source_status, source_view) = context_source_call(
            &app,
            source_service_id,
            &source_service_secret,
            source_request.clone(),
        )
        .await?;
        ensure!(
            source_status == StatusCode::OK
                && source_view["client"]["clientRegistry"] == "AUTH"
                && source_view["client"]["subjectMode"] == "USER"
                && source_view["client"]["contextMode"] == "PLATFORM_CONTEXT"
                && source_view["client"]["allowedMemberTypes"] == json!(["EMPLOYEE"])
                && source_view["source"]["userId"] == fixture.user_id.to_string()
                && source_view.get("credential").is_none(),
            "canonical private source proof omitted its exact client/session binding: status={source_status}, code={:?}, message={:?}",source_view.get("code"),source_view.get("message")
        );
        let (wrong_source_client_status, _) = context_source_call(
            &app,
            source_service_id,
            &source_service_secret,
            json!({"contractVersion":"context-selection/1","sourceProof":source_proof,"expectedClientId":fixture.public_client_id}),
        )
        .await?;
        ensure!(wrong_source_client_status == StatusCode::FORBIDDEN, "source service accepted a client outside its auth-client allowlist");

        let csrf = interaction["csrfToken"].as_str().ok_or_else(|| anyhow!("context selection CSRF missing"))?;
        db.suppress("identity_audit_logs", "INSERT").await?;
        let failed = send(
            &app,
            "POST",
            &format!("/oauth/interaction/{flow}"),
            Some(&cookie),
            Some("https://auth.saas.test"),
            Some(csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"action":"approve","membershipId":member_one}))?),
        )
        .await?;
        db.unsuppress("identity_audit_logs").await?;
        ensure!(failed.0 == StatusCode::SERVICE_UNAVAILABLE, "selection committed without its required audit event");
        let after_failure: (Option<Uuid>, Option<String>, Option<Uuid>, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT selected_membership_id,credential_ciphertext,grant_id,delivered_at \
             FROM auth_context_interactions WHERE transaction_id=$1",
        )
        .bind(transaction_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(after_failure == (None, None, None, None), "failed selection persisted partial state");

        let (status, _, approval) = send(
            &app,
            "POST",
            &format!("/oauth/interaction/{flow}"),
            Some(&cookie),
            Some("https://auth.saas.test"),
            Some(csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"action":"approve","membershipId":member_one}))?),
        )
        .await?;
        ensure!(status == StatusCode::OK, "retry did not recover the original platform confirmation result");
        ensure!(
            observed.confirm_calls.load(Ordering::SeqCst) == 2,
            "selection retry did not query the original confirmation receipt"
        );
        let code = callback_parameter(
            approval["redirectTo"].as_str().ok_or_else(|| anyhow!("context callback missing"))?,
            "code",
        )?;
        type StoredSelection = (Option<Uuid>, Option<String>, Option<DateTime<Utc>>, Option<Uuid>, Option<DateTime<Utc>>);
        let selected: StoredSelection = sqlx::query_as(
            "SELECT selected_membership_id,credential_ciphertext,selection_expires_at,grant_id,delivered_at \
             FROM auth_context_interactions WHERE transaction_id=$1",
        )
        .bind(transaction_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(selected.0 == Some(member_one) && selected.1.is_some() && selected.2.is_some() && selected.3.is_none() && selected.4.is_none(), "recovered selection was not stored once as ciphertext");

        let (status, tokens) = exchange_confidential(
            &app,
            &employee.client_id,
            &employee.client_secret,
            &employee.redirect_uri,
            &code,
            &fixture.verifier,
        )
        .await?;
        ensure!(
            status == StatusCode::OK
                && tokens["context_selection"]["contractVersion"] == "context-selection/1"
                && tokens["context_selection"]["transactionId"] == transaction_id.to_string()
                && tokens["context_selection"]["credential"] == observed.credential,
            "the matching authorization-code exchange did not deliver the original result exactly once"
        );
        let access = tokens["access_token"].as_str().ok_or_else(|| anyhow!("context access token missing"))?.to_owned();
        let refresh = tokens["refresh_token"].as_str().ok_or_else(|| anyhow!("context refresh token missing"))?.to_owned();
        let grant_id: Uuid = sqlx::query_scalar("SELECT id FROM auth_grants WHERE client_id=$1 AND context_ref=$2")
            .bind(employee.id).bind(transaction_id).fetch_one(&db.pool).await?;
        let delivered: (Option<Uuid>, Option<Uuid>, Option<DateTime<Utc>>, Option<String>) = sqlx::query_as(
            "SELECT context.grant_id,grant_row.id,context.delivered_at,context.credential_ciphertext \
             FROM auth_context_interactions context JOIN auth_grants grant_row ON grant_row.context_ref=context.transaction_id \
             WHERE context.transaction_id=$1",
        )
        .bind(transaction_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(delivered.0 == Some(grant_id) && delivered.1 == Some(grant_id) && delivered.2.is_some() && delivered.3.is_none(), "context result was not consumed atomically with its grant");

        let (replay_status, replay) = exchange_confidential(
            &app,
            &employee.client_id,
            &employee.client_secret,
            &employee.redirect_uri,
            &code,
            &fixture.verifier,
        )
        .await?;
        ensure!(replay_status == StatusCode::BAD_REQUEST && replay["error"] == "invalid_grant" && replay.get("context_selection").is_none(), "code replay redelivered a context credential");
        let (refresh_status, refreshed) = refresh_confidential(
            &app,
            &employee.client_id,
            &employee.client_secret,
            &refresh,
            None,
        )
        .await?;
        ensure!(refresh_status == StatusCode::OK && refreshed.get("context_selection").is_none(), "refresh redelivered a one-time context result");

        let (token_source_status, token_source) = context_source_call(
            &app,
            source_service_id,
            &source_service_secret,
            json!({"contractVersion":"context-selection/1","transactionId":transaction_id,"expectedClientId":employee.id,"oidcAccessToken":access}),
        )
        .await?;
        ensure!(token_source_status == StatusCode::OK && token_source["source"]["userId"] == fixture.user_id.to_string() && token_source["sourceExpiresAt"].is_string(), "the issued token could not recover its original private source");
        let (source_replay_status, _) = context_source_call(
            &app,
            source_service_id,
            &source_service_secret,
            json!({"contractVersion":"context-selection/1","sourceProof":source_proof,"expectedClientId":employee.id}),
        )
        .await?;
        ensure!(source_replay_status == StatusCode::UNAUTHORIZED, "pre-issue source proof remained valid after result delivery");

        // A zero-candidate result remains empty and cannot be approved by guessing an ID.
        let empty_transaction = Uuid::now_v7();
        let empty_port = UnifiedSelectionFixture::new(employee.id, empty_transaction, vec![]);
        let empty_observed = empty_port.clone();
        let empty_app = router(state_with_context_fixture(&db, &key, empty_port)?);
        let empty_state = "phase12-empty-state-1234567890";
        let empty_nonce = "phase12-empty-nonce-1234567890";
        let (status, empty_created) = create_context_interaction(&empty_app, &employee, empty_transaction, empty_state, empty_nonce, &fixture.challenge).await?;
        ensure!(status == StatusCode::OK, "zero-candidate context transaction creation failed");
        let empty_handle = empty_created["contextRequest"].as_str().ok_or_else(|| anyhow!("empty context handle missing"))?;
        let (empty_status, empty_headers, empty_target, empty_body) = authorize_context_client(&empty_app, &employee, empty_handle, &fixture.challenge, empty_state, empty_nonce, &session).await?;
        ensure!(empty_status.is_redirection(), "zero-candidate authorize failed: {empty_status} {empty_body}");
        let empty_flow = empty_target.split("flow=").nth(1).ok_or_else(|| anyhow!("empty candidate flow missing"))?;
        let empty_browser = browser_value(&empty_headers)?;
        let empty_cookie = append_cookie(&session, &format!("__Host-saas_oauth_browser={empty_browser}"));
        let (status, _, empty_interaction) = send(&empty_app, "GET", &format!("/oauth/interaction/{empty_flow}"), Some(&empty_cookie), Some("https://auth.saas.test"), None, None, None).await?;
        ensure!(status == StatusCode::OK && empty_interaction["contextSelection"]["members"] == json!([]), "zero eligible members were not represented as an empty selection");
        let empty_csrf = empty_interaction["csrfToken"].as_str().ok_or_else(|| anyhow!("empty selection CSRF missing"))?;
        let (status, _, _) = send(&empty_app, "POST", &format!("/oauth/interaction/{empty_flow}"), Some(&empty_cookie), Some("https://auth.saas.test"), Some(empty_csrf), Some("application/json"), Some(serde_json::to_vec(&json!({"action":"approve","membershipId":Uuid::now_v7()}))?)).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && empty_observed.confirm_calls.load(Ordering::SeqCst) == 1, "zero-choice context accepted a forged membership");

        // Customer clients get a customer-only result. A later client-policy change invalidates its source proof.
        let customer_transaction = Uuid::now_v7();
        let customer_member = Uuid::now_v7();
        let customer_port = UnifiedSelectionFixture::new(customer.id, customer_transaction, vec![context_choice(customer_member, fixture.user_id, Uuid::now_v7(), Uuid::now_v7(), "CUSTOMER")]);
        let customer_app = router(state_with_context_fixture(&db, &key, customer_port)?);
        let customer_state = "phase12-customer-state-123456789";
        let customer_nonce = "phase12-customer-nonce-1234567";
        let (status, customer_created) = create_context_interaction(&customer_app, &customer, customer_transaction, customer_state, customer_nonce, &fixture.challenge).await?;
        ensure!(status == StatusCode::OK, "customer context transaction creation failed");
        let customer_handle = customer_created["contextRequest"].as_str().ok_or_else(|| anyhow!("customer context handle missing"))?;
        let (customer_status, customer_headers, customer_target, customer_body) = authorize_context_client(&customer_app, &customer, customer_handle, &fixture.challenge, customer_state, customer_nonce, &session).await?;
        ensure!(customer_status.is_redirection(), "customer context authorize failed: {customer_status} {customer_body}");
        let customer_flow = customer_target.split("flow=").nth(1).ok_or_else(|| anyhow!("customer flow missing"))?;
        let customer_browser = browser_value(&customer_headers)?;
        let customer_cookie = append_cookie(&session, &format!("__Host-saas_oauth_browser={customer_browser}"));
        let (status, _, customer_interaction) = send(&customer_app, "GET", &format!("/oauth/interaction/{customer_flow}"), Some(&customer_cookie), Some("https://auth.saas.test"), None, None, None).await?;
        ensure!(status == StatusCode::OK && customer_interaction["contextSelection"]["members"].as_array().is_some_and(|v| v.len() == 1) && customer_interaction["contextSelection"]["members"][0]["memberType"] == "CUSTOMER", "CUSTOMER client received an employee or untyped candidate");
        let customer_source = crate::util::hash::sha256_hex(&format!("auth-context-selection-source-v1:{customer_browser}:{customer_flow}"));
        sqlx::query("UPDATE auth_clients SET policy_version=policy_version+1 WHERE id=$1").bind(customer.id).execute(&db.pool).await?;
        let (changed_policy_status, _) = context_source_call(&customer_app, source_service_id, &source_service_secret, json!({"contractVersion":"context-selection/1","sourceProof":customer_source,"expectedClientId":customer.id})).await?;
        ensure!(changed_policy_status == StatusCode::UNAUTHORIZED, "source proof survived a client-policy version change");

        sqlx::query("UPDATE sso_sessions SET revoked_at=clock_timestamp() WHERE id=$1").bind(fixture.session_id).execute(&db.pool).await?;
        let (revoked_source_status, _) = context_source_call(&app, source_service_id, &source_service_secret, json!({"contractVersion":"context-selection/1","transactionId":transaction_id,"expectedClientId":employee.id,"oidcAccessToken":access})).await?;
        ensure!(revoked_source_status == StatusCode::UNAUTHORIZED, "revoked original SSO session remained a valid context source");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE11_TEST_DATABASE_URL and IDENTITY_PHASE11_TEST_MARKER"]
async fn phase11_credential_age_caps_authentication_machine_grants_and_introspection() -> Result<()>
{
    let db = Database::create_phase11().await?;
    let result=async {
        prepare_phase08_schema(&db).await?;
        let key=test_key_fixture()?;
        let fixture=auth_fixture(&db,&key).await?;
        let resource=Uuid::now_v7();
        let scope=Uuid::now_v7();
        let audience="https://api.saas.test/credential-age";
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'credential-age',$2,'ACTIVE',1)")
            .bind(resource).bind(audience).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,'credential-age.read','ACTIVE')")
            .bind(scope).bind(resource).execute(&db.pool).await?;
        let issuer_secret="96".repeat(32);
        let inspector_secret="97".repeat(32);
        let issuer=add_resource_client(&db,"credential-age-issuer","Aged issuer",&["credential-age.read"],resource,scope,&issuer_secret).await?;
        let inspector=add_resource_client(&db,"credential-age-inspector","Aged inspector",&["credential-age.read"],resource,scope,&inspector_secret).await?;
        let app=router(state_with_key(&db,&key)?);
        sqlx::query("UPDATE auth_client_credentials SET created_at=clock_timestamp()-interval '90 days'+interval '2 minutes' WHERE client_id=$1")
            .bind(issuer).execute(&db.pool).await?;
        let (status,issued)=machine_token(&app,"credential-age-issuer",&issuer_secret,"credential-age.read").await?;
        ensure!(status==StatusCode::OK && issued["expires_in"].as_i64().is_some_and(|seconds|(1..=120).contains(&seconds)),
            "machine grant ignored the credential's remaining 90-day lifetime");
        let token=issued["access_token"].as_str().ok_or_else(||anyhow!("age-capped machine token missing"))?.to_owned();
        let bounded:bool=sqlx::query_scalar("SELECT tok.expires_at<=credential.created_at+interval '90 days' AND grant_row.expires_at<=credential.created_at+interval '90 days' FROM auth_access_tokens tok JOIN auth_grants grant_row ON grant_row.id=tok.grant_id JOIN auth_client_credentials credential ON credential.client_id=grant_row.client_id AND credential.credential_version=grant_row.credential_version WHERE tok.token_digest=$1")
            .bind(crate::util::hash::sha256_hex(&token)).fetch_one(&db.pool).await?;
        ensure!(bounded,"issued machine token or grant outlived its source credential");
        let (status,active)=introspect_access(&app,"credential-age-inspector",&inspector_secret,&token,Some(audience)).await?;
        ensure!(status==StatusCode::OK && active["active"]==true,"still-valid aged credential did not authorize its token");
        // Set the exact absolute deadline; subsequent DB statements are at or
        // after it. No timing sleep or uncontrolled wall-clock race is needed.
        sqlx::query("UPDATE auth_client_credentials SET created_at=clock_timestamp()-interval '90 days' WHERE client_id=$1")
            .bind(issuer).execute(&db.pool).await?;
        let (status,denied)=machine_token(&app,"credential-age-issuer",&issuer_secret,"credential-age.read").await?;
        ensure!(status==StatusCode::UNAUTHORIZED && denied["error"]=="invalid_client","90-day-old current credential obtained a machine token");
        let (status,inactive)=introspect_access(&app,"credential-age-inspector",&inspector_secret,&token,Some(audience)).await?;
        ensure!(status==StatusCode::OK && inactive["active"]==false,"machine token remained active after its original credential reached 90 days");
        sqlx::query("UPDATE auth_client_credentials SET created_at=clock_timestamp()-interval '90 days' WHERE client_id=$1")
            .bind(inspector).execute(&db.pool).await?;
        let (status,denied)=introspect_access(&app,"credential-age-inspector",&inspector_secret,&token,Some(audience)).await?;
        ensure!(status==StatusCode::UNAUTHORIZED && denied["error"]=="invalid_client","expired resource credential authenticated introspection");
        let code=authorize_and_consent(&app,&fixture,"openid profile").await?;
        sqlx::query("UPDATE auth_client_credentials SET created_at=clock_timestamp()-interval '90 days' WHERE client_id=$1")
            .bind(fixture.confidential_client_id).execute(&db.pool).await?;
        let (status,denied)=exchange_confidential(&app,&fixture.confidential_client_name,&fixture.client_secret,"https://client.example.test/callback",&code,&fixture.verifier).await?;
        ensure!(status==StatusCode::UNAUTHORIZED && denied["error"]=="invalid_client","expired USER credential authenticated a code exchange");
        let status=revoke_access(&app,&fixture.confidential_client_name,&fixture.client_secret,&token).await?;
        ensure!(status==StatusCode::UNAUTHORIZED,"expired USER credential authenticated token revocation");
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE11_TEST_DATABASE_URL and IDENTITY_PHASE11_TEST_MARKER"]
async fn phase11_client_credentials_are_machine_bound_to_active_registered_permissions(
) -> Result<()> {
    let db = Database::create_phase11().await?;
    let result = async {
        prepare_phase08_schema(&db).await?;
        let key = test_key_fixture()?;
        let fixture = auth_fixture(&db, &key).await?;
        let orders_resource_id = Uuid::now_v7();
        let orders_read_id = Uuid::now_v7();
        let orders_admin_id = Uuid::now_v7();
        let orders_audience = "https://api.saas.test/orders";
        let inventory_resource_id = Uuid::now_v7();
        let inventory_read_id = Uuid::now_v7();
        let inventory_audience = "https://api.saas.test/inventory";
        sqlx::query(
            "INSERT INTO public.auth_resources(id,resource_key,audience,status,version) \
             VALUES($1,'orders',$2,'ACTIVE',1)",
        )
        .bind(orders_resource_id)
        .bind(orders_audience)
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "INSERT INTO public.auth_resources(id,resource_key,audience,status,version) \
             VALUES($1,'inventory',$2,'ACTIVE',1)",
        )
        .bind(inventory_resource_id)
        .bind(inventory_audience)
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "INSERT INTO public.auth_scopes(id,resource_id,scope_name,status) \
             VALUES($1,$3,'orders.read','ACTIVE'),($2,$3,'orders.admin','ACTIVE'), \
             ($4,$5,'inventory.read','ACTIVE')",
        )
        .bind(orders_read_id)
        .bind(orders_admin_id)
        .bind(orders_resource_id)
        .bind(inventory_read_id)
        .bind(inventory_resource_id)
        .execute(&db.pool)
        .await?;
        let issuer_secret = "95".repeat(32);
        let issuer_client_id = "phase11-machine-issuer";
        let issuer_client_uuid = add_resource_client(
            &db,
            issuer_client_id,
            "Orders machine client",
            &["orders.read", "inventory.read"],
            orders_resource_id,
            orders_read_id,
            &issuer_secret,
        )
        .await?;
        sqlx::query(
            "INSERT INTO public.auth_client_permissions(client_id,resource_id,scope_id,version) \
             VALUES($1,$2,$3,1)",
        )
        .bind(issuer_client_uuid)
        .bind(orders_resource_id)
        .bind(orders_admin_id)
        .execute(&db.pool)
        .await?;
        let inspector_secret = "96".repeat(32);
        let inspector_client_id = "phase11-machine-inspector";
        add_resource_client(
            &db,
            inspector_client_id,
            "Orders resource inspector",
            &["orders.read"],
            orders_resource_id,
            orders_read_id,
            &inspector_secret,
        )
        .await?;
        let app = router(state_with_key(&db, &key)?);

        let (status, token_response) = machine_token(
            &app,
            issuer_client_id,
            &issuer_secret,
            "orders.read",
        )
        .await?;
        ensure!(
            status == StatusCode::OK
                && token_response["token_type"] == "Bearer"
                && token_response["scope"] == "orders.read"
                && token_response["expires_in"].as_i64().is_some_and(|seconds| (1..=300).contains(&seconds))
                && token_response.get("id_token").is_none()
                && token_response.get("refresh_token").is_none()
                && token_response.get("sub").is_none(),
            "machine client did not receive a short-lived, scope-bound token without user credentials"
        );
        let access_token = token_response["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("machine access token missing"))?
            .to_owned();
        let token_binding: bool = sqlx::query_scalar(
            "SELECT grant_row.subject_mode='MACHINE' AND grant_row.user_id IS NULL \
             AND grant_row.consent_id IS NULL AND grant_row.consent_generation IS NULL \
             AND grant_row.consent_group_version IS NULL AND grant_row.source_session_id IS NULL \
             AND grant_row.account_version IS NULL AND grant_row.auth_time IS NULL \
             AND grant_row.context_mode='NONE' AND grant_row.context_ref IS NULL \
             AND grant_row.credential_version=1 AND token_scope.scope_id=$2 \
             AND token_scope.resource_id=$3 \
             FROM public.auth_access_tokens access_token \
             JOIN public.auth_grants grant_row ON grant_row.id=access_token.grant_id \
             JOIN public.auth_access_token_scopes token_scope ON token_scope.token_id=access_token.id \
             WHERE access_token.token_digest=$1",
        )
        .bind(crate::util::hash::sha256_hex(&access_token))
        .bind(orders_read_id)
        .bind(orders_resource_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(token_binding, "machine grant carried a user, consent, context or unapproved scope binding");

        let (status, introspection) = introspect_access(
            &app,
            inspector_client_id,
            &inspector_secret,
            &access_token,
            Some(orders_audience),
        )
        .await?;
        ensure!(
            status == StatusCode::OK
                && introspection["active"] == true
                && introspection["subject_mode"] == "MACHINE"
                && introspection["client_id"] == issuer_client_id
                && introspection["aud"] == json!([orders_audience])
                && introspection["scope"] == "orders.read"
                && introspection.get("sub").is_none()
                && introspection.get("auth_time").is_none(),
            "machine introspection returned the wrong resource scope or a human identity"
        );
        let (userinfo_status, _) = userinfo_get(&app, &access_token).await?;
        ensure!(
            userinfo_status == StatusCode::UNAUTHORIZED,
            "a machine token was accepted as a person at UserInfo"
        );

        let (status, out_of_permission) = machine_token(
            &app,
            issuer_client_id,
            &issuer_secret,
            "orders.admin",
        )
        .await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && out_of_permission["error"] == "invalid_scope",
            "machine client used a resource scope outside the application's approved scope list"
        );
        let (status, out_of_resource) = machine_token(
            &app,
            issuer_client_id,
            &issuer_secret,
            "inventory.read",
        )
        .await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && out_of_resource["error"] == "invalid_scope",
            "machine client used an application-approved scope outside its registered resource permissions"
        );
        let (status, user_grant) = machine_token(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            "orders.read",
        )
        .await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && user_grant["error"] == "unauthorized_client",
            "a USER client used client_credentials"
        );
        let public_body = form_body(&[
            ("grant_type", "client_credentials"),
            ("client_id", "phase08-public"),
            ("scope", "orders.read"),
        ])?;
        let public_attempt = app
            .clone()
            .oneshot(
                Request::post("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(public_body))?,
            )
            .await?;
        ensure!(
            public_attempt.status() == StatusCode::UNAUTHORIZED,
            "a PUBLIC client used client_credentials"
        );

        let credentials_path = format!(
            "/internal/identity/auth/clients/{issuer_client_uuid}/credentials"
        );
        let rotated = db
            .auth_admin_call(
                Uuid::now_v7(),
                "POST",
                &credentials_path,
                Some(json!({"expectedVersion":1})),
            )
            .await?;
        ensure!(
            rotated.status == StatusCode::OK && rotated.body["credentialVersion"] == 2,
            "machine credential rotation did not create version 2"
        );
        let rotated_secret = rotated.body["clientSecret"]
            .as_str()
            .ok_or_else(|| anyhow!("rotated machine client secret missing"))?
            .to_owned();
        let (status, old_version_still_active) = introspect_access(
            &app,
            inspector_client_id,
            &inspector_secret,
            &access_token,
            Some(orders_audience),
        )
        .await?;
        ensure!(
            status == StatusCode::OK && old_version_still_active["active"] == true,
            "credential rotation did not honor the explicit overlap for the token's source version"
        );
        let (status, rotated_token_response) = machine_token(
            &app,
            issuer_client_id,
            &rotated_secret,
            "orders.read",
        )
        .await?;
        ensure!(status == StatusCode::OK, "new machine credential could not obtain a token");
        let rotated_access_token = rotated_token_response["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("rotated credential token missing"))?
            .to_owned();
        let rotated_version: i64 = sqlx::query_scalar(
            "SELECT grant_row.credential_version FROM public.auth_access_tokens access_token \
             JOIN public.auth_grants grant_row ON grant_row.id=access_token.grant_id \
             WHERE access_token.token_digest=$1",
        )
        .bind(crate::util::hash::sha256_hex(&rotated_access_token))
        .fetch_one(&db.pool)
        .await?;
        ensure!(rotated_version == 2, "machine grant did not record the source credential version");

        let revoke_path = format!("{credentials_path}/revoke");
        let revoked = db
            .auth_admin_call(
                Uuid::now_v7(),
                "POST",
                &revoke_path,
                Some(json!({"expectedVersion":2})),
            )
            .await?;
        ensure!(
            revoked.status == StatusCode::OK && revoked.body["policyVersion"] == 2,
            "emergency machine credential revocation did not advance policy version"
        );
        for token in [&access_token, &rotated_access_token] {
            let (status, result) = introspect_access(
                &app,
                inspector_client_id,
                &inspector_secret,
                token,
                Some(orders_audience),
            )
            .await?;
            ensure!(
                status == StatusCode::OK && result["active"] == false,
                "emergency credential revocation left a machine token active"
            );
        }
        let (status, revoked_credential_attempt) = machine_token(
            &app,
            issuer_client_id,
            &rotated_secret,
            "orders.read",
        )
        .await?;
        ensure!(
            status == StatusCode::UNAUTHORIZED
                && revoked_credential_attempt["error"] == "invalid_client",
            "revoked machine credential obtained a new token"
        );
        let (status, revoked_overlap_attempt) = machine_token(
            &app,
            issuer_client_id,
            &issuer_secret,
            "orders.read",
        )
        .await?;
        ensure!(
            status == StatusCode::UNAUTHORIZED
                && revoked_overlap_attempt["error"] == "invalid_client",
            "emergency revocation left the overlapping machine credential active"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL and IDENTITY_PHASE12_TEST_MARKER"]
async fn phase12_invalid_client_context_never_redirects_to_unregistered_callback() -> Result<()> {
    let db = Database::create_phase12_context().await?;
    let result = async {
        prepare_phase08_schema(&db).await?;
        let key = test_key_fixture()?;
        let fixture = auth_fixture(&db, &key).await?;
        let employee =
            add_unified_context_client(&db, &fixture, "callback-audit", "EMPLOYEE").await?;
        let machine_name = "phase12-callback-machine";
        add_resource_client(
            &db,
            machine_name,
            "Callback rejection fixture",
            &["openid"],
            fixture.resource_id,
            fixture.openid_id,
            &"91".repeat(32),
        )
        .await?;
        let app = router(state_with_key(&db, &key)?);
        let session = session_cookie(&fixture);
        for (client_id, context_request) in [
            (employee.client_id.as_str(), None),
            (employee.client_id.as_str(), Some("malformed")),
            (machine_name, None),
        ] {
            let mut url = reqwest::Url::parse(&authorize_url(
                client_id,
                "https://unregistered.example.test/callback",
                "openid profile",
                &fixture.challenge,
                None,
            )?)?;
            if let Some(context_request) = context_request {
                url.query_pairs_mut()
                    .append_pair("context_request", context_request);
            }
            let path = format!("/oauth/authorize?{}", url.query().unwrap_or_default());
            let (status, headers, _) =
                send(&app, "GET", &path, Some(&session), None, None, None, None).await?;
            ensure!(
                status == StatusCode::BAD_REQUEST && !headers.contains_key(header::LOCATION),
                "invalid client context redirected to an unregistered callback: {client_id}"
            );
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE10_TEST_DATABASE_URL and IDENTITY_PHASE10_TEST_MARKER"]
async fn phase10_expired_consumed_refresh_still_revokes_live_family() -> Result<()> {
    verify_consumed_refresh_replay(false).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE10_TEST_DATABASE_URL and IDENTITY_PHASE10_TEST_MARKER"]
async fn phase10_scope_shrink_cannot_mask_consumed_refresh_replay() -> Result<()> {
    verify_consumed_refresh_replay(true).await
}

async fn verify_consumed_refresh_replay(permission_expired: bool) -> Result<()> {
    let db = Database::create_phase10().await?;
    let result = async {
        prepare_phase08_schema(&db).await?;
        let key = test_key_fixture()?;
        let fixture = auth_fixture(&db, &key).await?;
        enable_refresh_client(&db, &fixture).await?;
        let app = router(state_with_key(&db, &key)?);
        let code = authorize_and_consent(&app, &fixture, "openid profile").await?;
        let (status, issued) = exchange_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            "https://client.example.test/callback",
            &code,
            &fixture.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "initial code exchange failed");
        let old_refresh = issued["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("initial refresh token missing"))?;
        let (status, rotated) = refresh_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            old_refresh,
            Some("openid"),
        )
        .await?;
        ensure!(status == StatusCode::OK, "initial refresh rotation failed");
        let successor = rotated["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("successor refresh token missing"))?;
        let family_id: Uuid = sqlx::query_scalar(
            "SELECT family_id FROM public.auth_refresh_tokens \
             WHERE token_digest=$1 AND consumed_at IS NOT NULL",
        )
        .bind(crate::util::hash::sha256_hex(old_refresh))
        .fetch_one(&db.pool)
        .await?;
        if permission_expired {
            // The narrowed openid access token stays valid while the original
            // refresh scope can no longer be renewed after profile expires.
            sqlx::query(
                "UPDATE public.auth_client_permissions SET expires_at=clock_timestamp()-interval '1 second' \
                 WHERE client_id=$1 AND scope_id=$2",
            )
            .bind(fixture.confidential_client_id)
            .bind(fixture.profile_id)
            .execute(&db.pool)
            .await?;
        } else {
            // A successor can keep the family idle window open after an older,
            // already consumed token reaches its own earlier deadline.
            sqlx::query(
                "UPDATE public.auth_refresh_tokens SET created_at=clock_timestamp()-interval '1 hour', \
                 expires_at=clock_timestamp()-interval '1 second' WHERE token_digest=$1",
            )
            .bind(crate::util::hash::sha256_hex(old_refresh))
            .execute(&db.pool)
            .await?;
        }
        let access = rotated["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("rotated access token missing"))?;
        ensure!(userinfo_get(&app, access).await?.0 == StatusCode::OK, "successor access was not live before reuse");
        let (status, replay) = refresh_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            old_refresh,
            None,
        )
        .await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && replay["error"] == "invalid_grant",
            "consumed refresh replay was accepted"
        );
        let family_revoked: bool = sqlx::query_scalar(
            "SELECT family.revoked_at IS NOT NULL \
             AND NOT EXISTS(SELECT 1 FROM public.auth_refresh_tokens token \
               WHERE token.family_id=family.id AND token.revoked_at IS NULL) \
             AND NOT EXISTS(SELECT 1 FROM public.auth_access_tokens token \
               WHERE token.grant_id=family.grant_id AND token.revoked_at IS NULL) \
             FROM public.auth_refresh_families family WHERE family.id=$1",
        )
        .bind(family_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(
            family_revoked,
            "consumed refresh replay left its live family active"
        );
        ensure!(userinfo_get(&app, access).await?.0 == StatusCode::UNAUTHORIZED, "successor access remained live after reuse");
        let (status, body) = refresh_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            successor,
            None,
        )
        .await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && body["error"] == "invalid_grant",
            "successor remained usable after expired consumed refresh replay"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE10_TEST_DATABASE_URL and IDENTITY_PHASE10_TEST_MARKER"]
async fn phase10_refresh_rotation_reuse_concurrency_limits_and_offline_source_are_enforced(
) -> Result<()> {
    let db = Database::create_phase10().await?;
    let result = async {
        prepare_phase08_schema(&db).await?;
        let key = test_key_fixture()?;
        let fixture = auth_fixture(&db, &key).await?;
        let offline_scope_id = enable_refresh_client(&db, &fixture).await?;
        let app = router(state_with_key(&db, &key)?);

        let code = authorize_and_consent(&app, &fixture, "openid profile").await?;
        let (status, online_tokens) = exchange_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            "https://client.example.test/callback",
            &code,
            &fixture.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "online authorization-code exchange failed");
        let refresh_one = online_tokens["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("configured online client received no refresh token"))?
            .to_owned();
        let online_timing_ok: bool = sqlx::query_scalar(
            "SELECT f.absolute_expires_at=s.expires_at AND f.absolute_expires_at=g.expires_at \
             AND f.idle_expires_at>clock_timestamp() \
             AND f.idle_expires_at<=clock_timestamp()+interval '30 minutes' \
             FROM public.auth_refresh_families f \
             JOIN public.auth_grants g ON g.id=f.grant_id \
             JOIN public.sso_sessions s ON s.id=g.source_session_id \
             WHERE g.user_id=$1 ORDER BY f.created_at DESC LIMIT 1",
        )
        .bind(fixture.user_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(online_timing_ok, "online family exceeded its SSO absolute or 30-minute idle limit");

        let (status, narrowed) = refresh_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            &refresh_one,
            Some("openid"),
        )
        .await?;
        ensure!(
            status == StatusCode::OK
                && narrowed["scope"] == "openid"
                && narrowed["refresh_token"].as_str().is_some_and(|value| value != refresh_one),
            "refresh did not rotate and narrow the access-token scope"
        );
        let refresh_two = narrowed["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("rotated refresh token missing"))?
            .to_owned();
        let expanded = refresh_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            &refresh_two,
            Some("openid offline_access"),
        )
        .await?;
        ensure!(
            expanded.0 == StatusCode::BAD_REQUEST && expanded.1["error"] == "invalid_grant",
            "refresh expanded the online grant into offline_access"
        );

        let first = refresh_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            &refresh_two,
            None,
        );
        let second = refresh_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            &refresh_two,
            None,
        );
        let (first, second) = tokio::join!(first, second);
        let first = first?;
        let second = second?;
        let responses = [&first, &second];
        let success = responses
            .iter()
            .filter(|response| response.0 == StatusCode::OK)
            .count();
        let invalid = responses
            .iter()
            .filter(|response| {
                response.0 == StatusCode::BAD_REQUEST && response.1["error"] == "invalid_grant"
            })
            .count();
        ensure!(success == 1 && invalid == 1, "concurrent refresh did not serialize and detect reuse");
        let family_revoked: bool = sqlx::query_scalar(
            "SELECT family.revoked_at IS NOT NULL \
             AND NOT EXISTS(SELECT 1 FROM public.auth_refresh_tokens token \
               WHERE token.family_id=family.id AND token.revoked_at IS NULL) \
             AND NOT EXISTS(SELECT 1 FROM public.auth_access_tokens access_token \
               WHERE access_token.grant_id=family.grant_id AND access_token.revoked_at IS NULL) \
             FROM public.auth_refresh_families family \
             JOIN public.auth_grants grant_row ON grant_row.id=family.grant_id \
             WHERE grant_row.user_id=$1 ORDER BY family.created_at DESC LIMIT 1",
        )
        .bind(fixture.user_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(family_revoked, "replayed refresh token did not revoke its full family");

        let online_code_after_replay = authorize_and_consent(&app, &fixture, "openid profile").await?;
        let (status, expiring_online) = exchange_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            "https://client.example.test/callback",
            &online_code_after_replay,
            &fixture.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "second online authorization-code exchange failed");
        let expiring_refresh = expiring_online["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("second online refresh token missing"))?;
        sqlx::query("UPDATE public.sso_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1")
            .bind(fixture.session_id)
            .execute(&db.pool)
            .await?;
        let (status, body) = refresh_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            expiring_refresh,
            None,
        )
        .await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["error"] == "invalid_grant", "online refresh survived natural source expiry");

        let offline_account = additional_account(&db, &fixture).await?;
        let offline_code = authorize_and_consent(
            &app,
            &offline_account,
            "openid profile offline_access",
        )
        .await?;
        let (status, offline_tokens) = exchange_confidential(
            &app,
            &offline_account.confidential_client_name,
            &offline_account.client_secret,
            "https://client.example.test/callback",
            &offline_code,
            &offline_account.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "explicit offline authorization-code exchange failed");
        ensure!(
            offline_tokens["scope"].as_str().is_some_and(|scope| {
                scope.split_ascii_whitespace().any(|value| value == "offline_access")
            }),
            "offline grant omitted its explicitly consented scope"
        );
        let offline_timing_ok: bool = sqlx::query_scalar(
            "SELECT family.absolute_expires_at=grant_row.expires_at \
             AND grant_row.expires_at BETWEEN clock_timestamp()+interval '6 days 23 hours' \
               AND clock_timestamp()+interval '7 days 1 minute' \
             AND family.idle_expires_at BETWEEN clock_timestamp()+interval '23 hours' \
               AND clock_timestamp()+interval '24 hours' \
             FROM public.auth_refresh_families family \
             JOIN public.auth_grants grant_row ON grant_row.id=family.grant_id \
             WHERE grant_row.user_id=$1 ORDER BY family.created_at DESC LIMIT 1",
        )
        .bind(offline_account.user_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(offline_timing_ok, "offline family did not use its 7-day absolute and 24-hour idle limits");
        let offline_refresh = offline_tokens["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("offline grant did not receive a refresh token"))?
            .to_owned();
        let offline_access_token = offline_tokens["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("offline access token missing"))?
            .to_owned();
        sqlx::query("UPDATE public.sso_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1")
            .bind(offline_account.session_id)
            .execute(&db.pool)
            .await?;
        let (status, profile) = userinfo_get(&app, &offline_access_token).await?;
        ensure!(
            status == StatusCode::OK && profile["sub"].as_str().is_some(),
            "offline access depended on the browser session remaining unexpired: {status} {profile}"
        );
        let (status, after_natural_expiry) = refresh_confidential(
            &app,
            &offline_account.confidential_client_name,
            &offline_account.client_secret,
            &offline_refresh,
            None,
        )
        .await?;
        ensure!(status == StatusCode::OK && after_natural_expiry["refresh_token"].as_str().is_some(), "offline refresh failed after natural browser-session expiry");
        let idle_expired_refresh = after_natural_expiry["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("offline refresh rotation omitted its successor"))?
            .to_owned();
        let idle_family: Uuid = sqlx::query_scalar(
            "SELECT family_id FROM public.auth_refresh_tokens WHERE token_digest=$1",
        )
        .bind(crate::util::hash::sha256_hex(&idle_expired_refresh))
        .fetch_one(&db.pool)
        .await?;
        sqlx::query(
            "UPDATE public.auth_refresh_families SET created_at=clock_timestamp()-interval '2 days', \
             idle_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
        )
        .bind(idle_family)
        .execute(&db.pool)
        .await?;
        let (status, body) = refresh_confidential(
            &app,
            &offline_account.confidential_client_name,
            &offline_account.client_secret,
            &idle_expired_refresh,
            None,
        )
        .await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && body["error"] == "invalid_grant",
            "offline refresh survived its elapsed idle deadline"
        );

        sqlx::query("UPDATE public.sso_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1")
            .bind(offline_account.session_id)
            .execute(&db.pool)
            .await?;
        let absolute_code = authorize_and_consent(
            &app,
            &offline_account,
            "openid profile offline_access",
        )
        .await?;
        let (status, absolute_tokens) = exchange_confidential(
            &app,
            &offline_account.confidential_client_name,
            &offline_account.client_secret,
            "https://client.example.test/callback",
            &absolute_code,
            &offline_account.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "second offline grant for the absolute-expiry boundary failed");
        let absolute_refresh = absolute_tokens["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("absolute-expiry test refresh token missing"))?
            .to_owned();
        let absolute_family: Uuid = sqlx::query_scalar(
            "SELECT family_id FROM public.auth_refresh_tokens WHERE token_digest=$1",
        )
        .bind(crate::util::hash::sha256_hex(&absolute_refresh))
        .fetch_one(&db.pool)
        .await?;
        sqlx::query(
            "UPDATE public.auth_refresh_families SET created_at=clock_timestamp()-interval '2 days', \
             absolute_expires_at=clock_timestamp()-interval '1 second', \
             idle_expires_at=clock_timestamp()-interval '2 seconds' WHERE id=$1",
        )
        .bind(absolute_family)
        .execute(&db.pool)
        .await?;
        let (status, body) = refresh_confidential(
            &app,
            &offline_account.confidential_client_name,
            &offline_account.client_secret,
            &absolute_refresh,
            None,
        )
        .await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && body["error"] == "invalid_grant",
            "offline refresh survived its elapsed absolute deadline"
        );

        let logged_out_account = additional_account(&db, &fixture).await?;
        let logout_code = authorize_and_consent(
            &app,
            &logged_out_account,
            "openid profile offline_access",
        )
        .await?;
        let (status, logout_tokens) = exchange_confidential(
            &app,
            &logged_out_account.confidential_client_name,
            &logged_out_account.client_secret,
            "https://client.example.test/callback",
            &logout_code,
            &logged_out_account.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "logout fixture offline grant failed");
        let logout_refresh = logout_tokens["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("logout fixture refresh token missing"))?;
        let (logout_status, _, _) = send(
            &app,
            "POST",
            "/api/sso/logout",
            Some(&session_cookie(&logged_out_account)),
            Some("https://auth.saas.test"),
            Some(&logged_out_account.csrf),
            Some("application/json"),
            Some(b"{}".to_vec()),
        )
        .await?;
        ensure!(logout_status == StatusCode::OK, "global SSO logout did not complete");
        let (status, body) = refresh_confidential(
            &app,
            &logged_out_account.confidential_client_name,
            &logged_out_account.client_secret,
            logout_refresh,
            None,
        )
        .await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["error"] == "invalid_grant", "global logout did not invalidate offline refresh");

        let disabled_account = additional_account(&db, &fixture).await?;
        let disabled_code = authorize_and_consent(
            &app,
            &disabled_account,
            "openid profile offline_access",
        )
        .await?;
        let (status, disabled_tokens) = exchange_confidential(
            &app,
            &disabled_account.confidential_client_name,
            &disabled_account.client_secret,
            "https://client.example.test/callback",
            &disabled_code,
            &disabled_account.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "disabled-account fixture offline grant failed");
        let disabled_refresh = disabled_tokens["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("disabled-account fixture refresh token missing"))?;
        sqlx::query("UPDATE public.users SET status='DISABLED',session_version=session_version+1 WHERE id=$1")
            .bind(disabled_account.user_id)
            .execute(&db.pool)
            .await?;
        let (status, body) = refresh_confidential(
            &app,
            &disabled_account.confidential_client_name,
            &disabled_account.client_secret,
            disabled_refresh,
            None,
        )
        .await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["error"] == "invalid_grant", "account disable did not invalidate offline refresh");
        ensure!(
            revoke_access(
                &app,
                &disabled_account.confidential_client_name,
                &disabled_account.client_secret,
                disabled_refresh,
            )
            .await?
                == StatusCode::OK,
            "the authenticated client could not revoke its family after account invalidation"
        );
        let disabled_family_revoked: bool = sqlx::query_scalar(
            "SELECT family.revoked_at IS NOT NULL \
             AND NOT EXISTS(SELECT 1 FROM public.auth_refresh_tokens token \
               WHERE token.family_id=family.id AND token.revoked_at IS NULL) \
             AND NOT EXISTS(SELECT 1 FROM public.auth_access_tokens access_token \
               WHERE access_token.grant_id=family.grant_id AND access_token.revoked_at IS NULL) \
             FROM public.auth_refresh_families family \
             JOIN public.auth_grants grant_row ON grant_row.id=family.grant_id \
             WHERE grant_row.user_id=$1 ORDER BY family.created_at DESC LIMIT 1",
        )
        .bind(disabled_account.user_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(disabled_family_revoked, "refresh family revocation did not remove every family credential");

        let revoked_app_account = additional_account(&db, &fixture).await?;
        let revoked_app_code = authorize_and_consent(
            &app,
            &revoked_app_account,
            "openid profile offline_access",
        )
        .await?;
        let (status, revoked_app_tokens) = exchange_confidential(
            &app,
            &revoked_app_account.confidential_client_name,
            &revoked_app_account.client_secret,
            "https://client.example.test/callback",
            &revoked_app_code,
            &revoked_app_account.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "revoked-app fixture offline grant failed");
        let revoked_app_refresh = revoked_app_tokens["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("revoked-app fixture refresh token missing"))?;
        sqlx::query("UPDATE public.auth_applications SET status='SUSPENDED',projection_version=projection_version+1 WHERE application_id=$1")
            .bind(revoked_app_account.application_id)
            .execute(&db.pool)
            .await?;
        let (status, body) = refresh_confidential(
            &app,
            &revoked_app_account.confidential_client_name,
            &revoked_app_account.client_secret,
            revoked_app_refresh,
            None,
        )
        .await?;
        ensure!(
            status == StatusCode::UNAUTHORIZED && body["error"] == "invalid_client"
                || status == StatusCode::BAD_REQUEST && body["error"] == "invalid_grant",
            "application authorization revocation did not invalidate offline refresh: {status} {body}"
        );

        let offline_scope_permission_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM public.auth_client_permissions \
             WHERE client_id=$1 AND resource_id=$2 AND scope_id=$3)",
        )
        .bind(fixture.confidential_client_id)
        .bind(fixture.resource_id)
        .bind(offline_scope_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(offline_scope_permission_exists, "offline scope permission disappeared during lifecycle regression");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE09_TEST_DATABASE_URL and IDENTITY_PHASE09_TEST_MARKER"]
async fn phase09_resource_access_is_audience_scope_bound_and_revocation_is_token_local(
) -> Result<()> {
    let db = Database::create_phase09().await?;
    let result = async {
        prepare_phase08_schema(&db).await?;
        let key = test_key_fixture()?;
        let fixture = auth_fixture(&db, &key).await?;
        let orders_resource_id = Uuid::now_v7();
        let orders_scope_id = Uuid::now_v7();
        let orders_audience = "https://api.saas.test/orders";
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'orders','https://api.saas.test/orders','ACTIVE',1)")
            .bind(orders_resource_id).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,'orders.read','ACTIVE')")
            .bind(orders_scope_id).bind(orders_resource_id).execute(&db.pool).await?;
        sqlx::query("UPDATE auth_applications SET approved_scopes=ARRAY['openid','profile','orders.read'] WHERE application_id=$1")
            .bind(fixture.application_id).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_client_permissions(client_id,resource_id,scope_id,version) VALUES($1,$2,$3,1)")
            .bind(fixture.confidential_client_id).bind(orders_resource_id).bind(orders_scope_id).execute(&db.pool).await?;

        let orders_client_secret = "93".repeat(32);
        let orders_client_id = "phase09-orders-resource";
        add_resource_client(
            &db,
            orders_client_id,
            "Orders Resource",
            &["orders.read"],
            orders_resource_id,
            orders_scope_id,
            &orders_client_secret,
        )
        .await?;
        let unrelated_client_secret = "94".repeat(32);
        let unrelated_client_id = "phase09-userinfo-resource";
        add_resource_client(
            &db,
            unrelated_client_id,
            "Unrelated UserInfo Resource",
            &["openid"],
            fixture.resource_id,
            fixture.openid_id,
            &unrelated_client_secret,
        )
        .await?;

        let app = router(state_with_key(&db, &key)?);
        let session = session_cookie(&fixture);
        let redirect_uri = "https://client.example.test/callback";
        let bad_scope_url = authorize_url(
            &fixture.confidential_client_name,
            redirect_uri,
            "openid orders.write",
            &fixture.challenge,
            None,
        )?;
        let bad_scope_path = format!(
            "/oauth/authorize?{}",
            reqwest::Url::parse(&bad_scope_url)?
                .query()
                .ok_or_else(|| anyhow!("scope rejection query missing"))?
        );
        let (status, _, rejection) =
            send(&app, "GET", &bad_scope_path, Some(&session), None, None, None, None).await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && rejection["error"] == "invalid_scope",
            "an unregistered resource scope was accepted"
        );

        let (authorize_headers, target) = authorize(
            &app,
            &fixture.confidential_client_name,
            redirect_uri,
            "openid orders.read",
            &fixture.challenge,
            None,
            Some(&session),
        )
        .await?;
        ensure!(
            target.starts_with("/oauth/login?flow="),
            "new resource scope did not require explicit user consent"
        );
        let flow = target
            .split("flow=")
            .nth(1)
            .ok_or_else(|| anyhow!("resource consent flow missing"))?;
        let browser = browser_value(&authorize_headers)?;
        let browser_session = append_cookie(&session, &format!("__Host-saas_oauth_browser={browser}"));
        let (status, _, interaction) = send(
            &app,
            "GET",
            &format!("/oauth/interaction/{flow}"),
            Some(&browser_session),
            Some("https://auth.saas.test"),
            None,
            None,
            None,
        )
        .await?;
        ensure!(
            status == StatusCode::OK && interaction["status"] == "CONSENT_REQUIRED",
            "resource scope expansion was not presented for consent"
        );
        let csrf = interaction["csrfToken"]
            .as_str()
            .ok_or_else(|| anyhow!("resource consent CSRF missing"))?;
        let (status, _, approval) = send(
            &app,
            "POST",
            &format!("/oauth/interaction/{flow}"),
            Some(&browser_session),
            Some("https://auth.saas.test"),
            Some(csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"action":"approve"}))?),
        )
        .await?;
        ensure!(status == StatusCode::OK, "resource scope consent failed");
        let callback = approval["redirectTo"]
            .as_str()
            .ok_or_else(|| anyhow!("resource consent callback missing"))?;
        let code = callback_parameter(callback, "code")?;
        let (status, tokens) = exchange_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            redirect_uri,
            &code,
            &fixture.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "resource-scoped token exchange failed");
        ensure!(
            tokens["scope"] == "openid orders.read",
            "token response broadened or lost the granted resource scope"
        );
        let access_token = tokens["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("resource access token missing"))?
            .to_owned();
        let id_token = tokens["id_token"]
            .as_str()
            .ok_or_else(|| anyhow!("resource ID Token missing"))?;
        let decoding = jsonwebtoken::DecodingKey::from_rsa_components(&key.modulus, &key.exponent)?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["https://auth.saas.test"]);
        validation.set_audience(&[fixture.confidential_client_name.as_str()]);
        let claims = jsonwebtoken::decode::<Value>(id_token, &decoding, &validation)?.claims;
        let pairwise_sub = claims["sub"]
            .as_str()
            .ok_or_else(|| anyhow!("ID Token sub missing"))?;
        ensure!(
            pairwise_sub != fixture.user_id.to_string(),
            "resource token ID Token exposed the internal account ID"
        );

        let (status, orders_introspection) = introspect_access(
            &app,
            orders_client_id,
            &orders_client_secret,
            &access_token,
            Some(orders_audience),
        )
        .await?;
        ensure!(
            status == StatusCode::OK
                && orders_introspection["active"] == true
                && orders_introspection["aud"] == json!([orders_audience])
                && orders_introspection["scope"] == "orders.read"
                && orders_introspection["sub"] == pairwise_sub
                && orders_introspection["sub"] != fixture.user_id.to_string(),
            "resource-scoped introspection returned the wrong audience, scope or subject"
        );
        let (bad_client_status, _) = introspect_access(
            &app,
            orders_client_id,
            &"95".repeat(32),
            &access_token,
            Some(orders_audience),
        )
        .await?;
        ensure!(
            bad_client_status == StatusCode::UNAUTHORIZED,
            "introspection accepted an invalid resource-client secret"
        );
        let (status, unrelated_introspection) = introspect_access(
            &app,
            unrelated_client_id,
            &unrelated_client_secret,
            &access_token,
            Some(orders_audience),
        )
        .await?;
        ensure!(
            status == StatusCode::OK && unrelated_introspection["active"] == false,
            "a resource client without the token audience could introspect it"
        );
        let (status, wrong_audience) = introspect_access(
            &app,
            orders_client_id,
            &orders_client_secret,
            &access_token,
            Some("https://auth.saas.test/oauth/userinfo"),
        )
        .await?;
        ensure!(
            status == StatusCode::OK && wrong_audience["active"] == false,
            "resource introspection accepted an unrelated audience"
        );
        let (status, id_token_result) = introspect_access(
            &app,
            orders_client_id,
            &orders_client_secret,
            id_token,
            Some(orders_audience),
        )
        .await?;
        ensure!(
            status == StatusCode::OK && id_token_result["active"] == false,
            "ID Token was accepted as an API access token"
        );
        let id_token_userinfo = app
            .clone()
            .oneshot(
                Request::get("/oauth/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {id_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            id_token_userinfo.status() == StatusCode::UNAUTHORIZED,
            "UserInfo accepted an ID Token as an API access token"
        );

        let userinfo_response = app
            .clone()
            .oneshot(
                Request::get("/oauth/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            userinfo_response.status() == StatusCode::OK,
            "UserInfo rejected the token's explicitly granted userinfo audience"
        );
        let userinfo: Value =
            serde_json::from_slice(&to_bytes(userinfo_response.into_body(), 65536).await?)?;
        ensure!(
            userinfo["sub"] == pairwise_sub && userinfo.get("name").is_none(),
            "UserInfo returned a different subject or claims outside the userinfo scope"
        );
        let digest = crate::util::hash::sha256_hex(&access_token);
        let stored_digest: String = sqlx::query_scalar(
            "SELECT token_digest FROM auth_access_tokens WHERE token_digest=$1",
        )
        .bind(&digest)
        .fetch_one(&db.pool)
        .await?;
        ensure!(
            stored_digest == digest,
            "access token was not stored as a digest"
        );

        let (_, replay_target) = authorize(
            &app,
            &fixture.confidential_client_name,
            redirect_uri,
            "openid orders.read",
            &fixture.challenge,
            None,
            Some(&browser_session),
        )
        .await?;
        ensure!(
            replay_target.starts_with("https://client.example.test/callback?"),
            "sufficient resource consent was not reused"
        );
        let second_code = callback_parameter(&replay_target, "code")?;
        let (status, second_tokens) = exchange_confidential(
            &app,
            &fixture.confidential_client_name,
            &fixture.client_secret,
            redirect_uri,
            &second_code,
            &fixture.verifier,
        )
        .await?;
        ensure!(status == StatusCode::OK, "second resource token exchange failed");
        let second_access_token = second_tokens["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("second access token missing"))?;

        ensure!(
            revoke_access(
                &app,
                unrelated_client_id,
                &unrelated_client_secret,
                &access_token,
            )
            .await?
                == StatusCode::OK,
            "standard revoke did not keep an unknown/foreign token response indistinguishable"
        );
        let (_, still_active) = introspect_access(
            &app,
            orders_client_id,
            &orders_client_secret,
            &access_token,
            Some(orders_audience),
        )
        .await?;
        ensure!(still_active["active"] == true, "a foreign client revoked the token");
        ensure!(
            revoke_access(
                &app,
                &fixture.confidential_client_name,
                &fixture.client_secret,
                &access_token,
            )
            .await?
                == StatusCode::OK,
            "authenticated token revoke failed"
        );
        let (_, revoked) = introspect_access(
            &app,
            orders_client_id,
            &orders_client_secret,
            &access_token,
            Some(orders_audience),
        )
        .await?;
        let (_, unrelated_authorization) = introspect_access(
            &app,
            orders_client_id,
            &orders_client_secret,
            second_access_token,
            Some(orders_audience),
        )
        .await?;
        ensure!(
            revoked["active"] == false && unrelated_authorization["active"] == true,
            "revoking one access token invalidated an unrelated authorization"
        );
        sqlx::query("UPDATE sso_sessions SET revoked_at=clock_timestamp() WHERE id=$1")
            .bind(fixture.session_id)
            .execute(&db.pool)
            .await?;
        let (_, source_revoked) = introspect_access(
            &app,
            orders_client_id,
            &orders_client_secret,
            second_access_token,
            Some(orders_audience),
        )
        .await?;
        ensure!(
            source_revoked["active"] == false,
            "introspection accepted an access token after its source session was revoked"
        );
        let stale_userinfo = app
            .clone()
            .oneshot(
                Request::get("/oauth/userinfo")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {second_access_token}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            stale_userinfo.status() == StatusCode::UNAUTHORIZED,
            "UserInfo accepted an access token after its source session was revoked"
        );
        let revoked_audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM identity_audit_logs WHERE action='OAUTH_ACCESS_TOKEN_REVOKED' AND detail NOT LIKE '%' || $1 || '%'",
        )
        .bind(&access_token)
        .fetch_one(&db.pool)
        .await?;
        ensure!(revoked_audits == 1, "token revocation audit was missing or contained token material");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE08_TEST_DATABASE_URL and IDENTITY_PHASE08_TEST_MARKER"]
async fn phase08_totp_encryption_replay_recovery_and_two_person_reset_are_transactional(
) -> Result<()> {
    let db = Database::create_phase08().await?;
    let result = async {
        prepare_phase08_schema(&db).await?;
        let key = test_key_fixture()?;
        let fixture = auth_fixture(&db, &key).await?;
        let state = state_with_key(&db, &key)?;
        let app = crate::sso::routes().with_state(state.clone());
        let cookie = session_cookie(&fixture);
        let origin = "https://auth.saas.test";

        let (status, _, enrollment) = send(
            &app,
            "POST",
            "/api/sso/mfa/enrollment",
            Some(&cookie),
            Some(origin),
            Some(&fixture.csrf),
            Some("application/json"),
            Some(b"{}".to_vec()),
        )
        .await?;
        ensure!(status == StatusCode::OK, "TOTP enrollment start failed");
        ensure!(enrollment["secret"].as_str().is_some(), "one-time enrollment seed missing");
        ensure!(enrollment["otpauthUri"].as_str().is_some(), "otpauth URI missing");
        let encrypted: Vec<u8> = sqlx::query_scalar(
            "SELECT secret_ciphertext FROM auth_totp_enrollments WHERE user_id=$1",
        )
        .bind(fixture.user_id)
        .fetch_one(&db.pool)
        .await?;
        let secret = crate::sso::mfa::decrypt(&state, fixture.user_id, &encrypted)?;
        ensure!(encrypted.as_slice() != secret.as_slice(), "TOTP seed is not encrypted at rest");
        let step: i64 = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint")
            .fetch_one(&db.pool)
            .await?;
        let code = crate::sso::mfa::code_for_step(&secret, step)?;
        let (status, _, enrollment_result) = send(
            &app,
            "POST",
            "/api/sso/mfa/enrollment/confirm",
            Some(&cookie),
            Some(origin),
            Some(&fixture.csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"code":code}))?),
        )
        .await?;
        ensure!(status == StatusCode::OK, "valid TOTP did not complete enrollment");
        let recovery_codes = enrollment_result["recoveryCodes"]
            .as_array()
            .ok_or_else(|| anyhow!("recovery codes missing"))?;
        ensure!(recovery_codes.len() == 10, "wrong recovery code count");
        let recovery_code = recovery_codes[0]
            .as_str()
            .ok_or_else(|| anyhow!("recovery code is not text"))?
            .to_owned();
        let stored_digests: Vec<String> = sqlx::query_scalar(
            "SELECT code_digest FROM auth_totp_recovery_codes WHERE user_id=$1 ORDER BY id",
        )
        .bind(fixture.user_id)
        .fetch_all(&db.pool)
        .await?;
        ensure!(
            stored_digests.len() == 10 && stored_digests.iter().all(|digest| digest != &recovery_code),
            "recovery codes were not digest stored"
        );

        let (status, _, _) = send(
            &app,
            "POST",
            "/api/sso/mfa/step-up",
            Some(&cookie),
            Some(origin),
            Some(&fixture.csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"code":code}))?),
        )
        .await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "the TOTP time step was accepted twice");
        let (status, _, step_up) = send(
            &app,
            "POST",
            "/api/sso/mfa/step-up",
            Some(&cookie),
            Some(origin),
            Some(&fixture.csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"code":recovery_code}))?),
        )
        .await?;
        ensure!(status == StatusCode::OK && step_up["verified"] == true, "one-time recovery code did not step up");
        let (status, _, _) = send(
            &app,
            "POST",
            "/api/sso/mfa/step-up",
            Some(&cookie),
            Some(origin),
            Some(&fixture.csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"code":recovery_code}))?),
        )
        .await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "a consumed recovery code was reused");
        for _ in 0..4 {
            let (status, _, _) = send(
                &app,
                "POST",
                "/api/sso/mfa/step-up",
                Some(&cookie),
                Some(origin),
                Some(&fixture.csrf),
                Some("application/json"),
                Some(serde_json::to_vec(&json!({"code":"not-a-valid-code"}))?),
            )
            .await?;
            ensure!(status == StatusCode::UNAUTHORIZED, "invalid MFA guess was not rejected");
        }
        let (status, _, _) = send(
            &app,
            "POST",
            "/api/sso/mfa/step-up",
            Some(&cookie),
            Some(origin),
            Some(&fixture.csrf),
            Some("application/json"),
            Some(serde_json::to_vec(&json!({"code":"not-a-valid-code"}))?),
        )
        .await?;
        ensure!(status == StatusCode::TOO_MANY_REQUESTS, "MFA guessing was not rate limited");

        let first_approver = Uuid::now_v7();
        let second_approver = Uuid::now_v7();
        let service_id = Uuid::now_v7();
        let service_secret = "91".repeat(32);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'phase08-security-approver-one','unused'),($2,'phase08-security-approver-two','unused')")
            .bind(first_approver).bind(second_approver).execute(&db.pool).await?;
        sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status) VALUES($1,$2,'AUTH_SECURITY','ENABLED')")
            .bind(service_id).bind(crate::util::hash::sha256_hex(&service_secret)).execute(&db.pool).await?;
        let operation_id = Uuid::now_v7();
        let reason = "protected support identity verification";
        let timestamp = chrono::Utc::now().timestamp();
        let reason_digest = crate::util::hash::sha256_hex(reason.trim());
        let approvals = [first_approver, second_approver]
            .into_iter()
            .map(|user_id| {
                let approval_id = Uuid::now_v7();
                let message = crate::sso::mfa_recovery::approval_message(
                    operation_id,
                    fixture.user_id,
                    user_id,
                    approval_id,
                    timestamp,
                    timestamp,
                    &reason_digest,
                );
                let signature = ring::hmac::sign(
                    &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, service_secret.as_bytes()),
                    message.as_bytes(),
                );
                json!({
                    "userId":user_id,
                    "approvalId":approval_id,
                    "primaryAuthenticatedAt":timestamp,
                    "mfaVerifiedAt":timestamp,
                    "signature":hex::encode(signature.as_ref())
                })
            })
            .collect::<Vec<_>>();
        let recovery_request = json!({
            "operationId":operation_id,
            "targetUserId":fixture.user_id,
            "reason":reason,
            "approvals":approvals
        });
        let recovery_body = serde_json::to_vec(&recovery_request)?;
        let basic = STANDARD.encode(format!("{service_id}:{service_secret}"));
        let recovery_router = crate::internal::routes().with_state(state.clone());
        let recovery = Request::post("/internal/identity/security/mfa/recover")
            .header(header::AUTHORIZATION, format!("Basic {basic}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(recovery_body.clone()))?;
        let response = recovery_router.clone().oneshot(recovery).await?;
        ensure!(response.status() == StatusCode::OK, "two-person administrator recovery failed");
        let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        ensure!(result["recovered"] == true && result["nextStep"] == "enroll_totp", "recovery response is incomplete");
        let replay = Request::post("/internal/identity/security/mfa/recover")
            .header(header::AUTHORIZATION, format!("Basic {basic}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(recovery_body))?;
        let replay = recovery_router.oneshot(replay).await?;
        ensure!(replay.status() == StatusCode::OK, "same operation did not recover its receipt");
        let replay_result: Value = serde_json::from_slice(&to_bytes(replay.into_body(), 65536).await?)?;
        ensure!(replay_result == result, "recovery retry returned a different result");
        let (factor_count, recovery_count, approval_count, notification_count, session_version, revoked_sessions): (i64,i64,i64,i64,i64,i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM auth_totp_factors WHERE user_id=$1), \
             (SELECT count(*) FROM auth_totp_recovery_codes WHERE user_id=$1), \
             (SELECT count(*) FROM auth_mfa_recovery_approvals WHERE operation_id=$2), \
             (SELECT count(*) FROM auth_security_notification_outbox WHERE user_id=$1 AND event_kind='MFA_RECOVERED'), \
             (SELECT session_version FROM users WHERE id=$1), \
             (SELECT count(*) FROM sso_sessions WHERE user_id=$1 AND revoked_at IS NOT NULL)",
        )
        .bind(fixture.user_id)
        .bind(operation_id)
        .fetch_one(&db.pool)
        .await?;
        ensure!(factor_count == 0 && recovery_count == 0 && approval_count == 2 && notification_count == 1 && session_version == 2 && revoked_sessions == 1,
            "recovery did not reset the factor, fence sessions and atomically record two approvals/notification");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(result).await
}
