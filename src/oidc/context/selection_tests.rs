//! Real OIDC browser/code/refresh handlers and DB, with the platform port isolated.
use super::*;
use anyhow::{ensure, Context as _, Result as TestResult};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Request, StatusCode},
    Router,
};
use base64::engine::general_purpose::STANDARD;
use sqlx::PgPool;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tower::ServiceExt;

struct Platform {
    state: AppState,
    authorization: String,
    user: Uuid,
    transaction: Uuid,
    member: Uuid,
    calls: Arc<AtomicUsize>,
}
impl Platform {
    async fn verify(&self, proof: &str, client: Uuid) -> std::result::Result<(), AppError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            self.authorization
                .parse()
                .map_err(|_| AppError::Unavailable)?,
        );
        let reply = source(
            State(self.state.clone()),
            headers,
            RawQuery(None),
            ApiJson(SourceRequest {
                contract_version: VERSION.to_owned(),
                source_proof: Some(proof.to_owned()),
                transaction_id: None,
                expected_client_id: client,
                oidc_access_token: None,
            }),
        )
        .await?;
        if reply.0["source"]["userId"] != self.user.to_string() {
            return Err(AppError::Unavailable);
        }
        Ok(())
    }
}
impl bridge::SelectionPort for Platform {
    fn choices<'a>(&'a self, proof: &'a str, client: Uuid) -> bridge::ChoicesFuture<'a> {
        Box::pin(async move {
            self.verify(proof, client).await?;
            Ok(bridge::Choices {
                contract_version: VERSION.to_owned(),
                transaction_id: self.transaction,
                intent: json!({"kind":"LOGIN"}),
                expires_at: Utc::now() + chrono::Duration::seconds(90),
                members: vec![bridge::Choice {
                    membership_id: self.member,
                    user_id: self.user,
                    tenant_id: Uuid::now_v7(),
                    organization_id: Uuid::now_v7(),
                    member_type: "EMPLOYEE".to_owned(),
                    identity_version: "1".to_owned(),
                    tenant_name: "测试租户".to_owned(),
                    organization_name: "测试组织".to_owned(),
                    organization_path: "总部 / 测试组织".to_owned(),
                }],
            })
        })
    }
    fn confirm<'a>(
        &'a self,
        proof: &'a str,
        client: Uuid,
        member: Uuid,
    ) -> bridge::ConfirmFuture<'a> {
        Box::pin(async move {
            self.verify(proof, client).await?;
            if member != self.member {
                return Err(AppError::forbidden("fixture membership mismatch"));
            }
            if self.calls.fetch_add(1, Ordering::SeqCst) != 0 {
                return Err(AppError::conflict("fixture selection already issued"));
            }
            Ok(bridge::Confirmation {
                contract_version: VERSION.to_owned(),
                transaction_id: self.transaction,
                credential: "f".repeat(64),
                expires_at: Utc::now() + chrono::Duration::seconds(90),
            })
        })
    }
}

async fn json_reply(app: &Router, request: Request<Body>) -> TestResult<(StatusCode, Value)> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    ensure!(
        response
            .headers()
            .get("cache-control")
            .is_some_and(|v| v == "no-store"),
        "identity responses must be uncached"
    );
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn cases(pool: PgPool) -> TestResult<()> {
    let user = Uuid::now_v7();
    let client = Uuid::now_v7();
    let service = Uuid::now_v7();
    let sid = Uuid::now_v7();
    let transaction = Uuid::now_v7();
    let member = Uuid::now_v7();
    let sso = "a".repeat(64);
    let browser = "b".repeat(64);
    let rp_secret = "c".repeat(64);
    let source_secret = "d".repeat(64);
    let verifier = "e".repeat(64);
    let digest = super::super::digest;
    sqlx::query("INSERT INTO users(id,username,password_hash,status,session_version) VALUES($1,'selection-delivery','unused','ENABLED',1)").bind(user).execute(&pool).await?;
    sqlx::query("INSERT INTO oidc_provider_settings(singleton,issuer,created_at) VALUES(true,'https://auth.saas.test',clock_timestamp())").execute(&pool).await?;
    sqlx::query("INSERT INTO oidc_clients(id,name,purpose,secret_hash,allowed_member_types,redirect_uris,refresh_enabled,status,access_policy_version,created_at,updated_at) VALUES($1,'Selection delivery','PLATFORM_CONSOLE',$2,ARRAY['EMPLOYEE'],ARRAY['https://platform.saas.test/auth/callback'],true,'ENABLED',1,clock_timestamp(),clock_timestamp())").bind(client).bind(digest(&rp_secret)).execute(&pool).await?;
    sqlx::query("INSERT INTO oidc_context_clients(client_id) VALUES($1)")
        .bind(client)
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,created_at,allowed_oidc_clients) VALUES($1,$2,'CONTEXT_SELECTION_SOURCE','ENABLED',clock_timestamp(),ARRAY[$3]::uuid[])").bind(service).bind(digest(&source_secret)).bind(client).execute(&pool).await?;
    sqlx::query("INSERT INTO sso_sessions(id,user_id,token_hash,csrf_hash,account_version,authenticated_at,expires_at) VALUES($1,$2,$3,repeat('0',64),1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')").bind(sid).bind(user).bind(digest(&sso)).execute(&pool).await?;
    let key_path = std::env::var("CONTEXT_SELECTION_TEST_SIGNING_KEYS")
        .context("explicit disposable signing fixture required")?;
    let key_document: Value = serde_json::from_slice(&std::fs::read(&key_path)?)?;
    let key = &key_document["keys"][0];
    sqlx::query("INSERT INTO oidc_signing_keys(kid,n,e,published_at,active,activated_at) VALUES($1,$2,$3,clock_timestamp(),true,clock_timestamp())").bind(key["kid"].as_str()).bind(key["n"].as_str()).bind(key["e"].as_str()).execute(&pool).await?;
    let mut config = crate::config::Config::from_values(&HashMap::from([(
        "DATABASE_URL".to_owned(),
        "postgres://fixture@localhost/context_test".to_owned(),
    )]))?;
    config.oidc_enabled = true;
    config.sso_enabled = true;
    config.oidc_issuer = Some("https://auth.saas.test".to_owned());
    config.sso_origin = config.oidc_issuer.clone();
    config.context_cipher = Some(Arc::new(crypto::Keys::fixture()));
    config.oidc_keys = Some(Arc::new(super::super::keys::KeySet::load(&key_path)?));
    let mut state = AppState::new(pool.clone(), Arc::new(config));
    let source_authorization = format!(
        "Basic {}",
        STANDARD.encode(format!("{service}:{source_secret}"))
    );
    let calls = Arc::new(AtomicUsize::new(0));
    state.context_platform = Arc::new(Platform {
        state: state.clone(),
        authorization: source_authorization.clone(),
        user,
        transaction,
        member,
        calls: calls.clone(),
    });
    let app = super::super::protocol::routes().with_state(state.clone());
    let authorization = format!("Basic {}", STANDARD.encode(format!("{client}:{rp_secret}")));
    use sha2::{Digest, Sha256};
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let request = json!({"contractVersion":VERSION,"transactionId":transaction,"intent":{"kind":"LOGIN"},"redirectUri":"https://platform.saas.test/auth/callback","stateHash":digest("state"),"nonceHash":digest("nonce"),"codeChallenge":challenge});
    let (status, created) = json_reply(
        &app,
        Request::post("/oidc/context-interactions")
            .header("authorization", &authorization)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&request)?))?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "backend interaction creation failed"
    );
    let mut url = reqwest::Url::parse("https://auth.saas.test/oidc/authorize")?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.to_string())
        .append_pair("redirect_uri", "https://platform.saas.test/auth/callback")
        .append_pair("scope", "openid profile offline_access")
        .append_pair("state", "state")
        .append_pair("nonce", "nonce")
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &challenge)
        .append_pair(
            "context_request",
            created["contextRequest"]
                .as_str()
                .context("missing context reference")?,
        );
    let cookie = format!("__Host-saas_sso={sso}; __Host-saas_oidc_browser={browser}");
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/oidc/authorize?{}", url.query().unwrap()))
                .header("cookie", &cookie)
                .body(Body::empty())?,
        )
        .await?;
    ensure!(
        response.status() == StatusCode::SEE_OTHER,
        "authorization must redirect to the identity interaction"
    );
    let location = response.headers()["location"].to_str()?;
    let flow_id: Uuid = location
        .strip_prefix("/sso/login?flow=")
        .context("unexpected login path")?
        .parse()?;
    let path = format!("/oidc/interaction/{flow_id}");
    let (status, view) = json_reply(
        &app,
        Request::get(&path)
            .header("cookie", &cookie)
            .header("origin", "https://auth.saas.test")
            .body(Body::empty())?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && view["status"] == "CONSENT_REQUIRED"
            && view["contextSelection"].is_null(),
        "application consent must precede member lookup"
    );
    let (status, _) = json_reply(
        &app,
        Request::post(&path)
            .header("cookie", &cookie)
            .header("origin", "https://auth.saas.test")
            .header("x-csrf-token", view["csrfToken"].as_str().unwrap())
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"action":"approve","membershipId":member}).to_string(),
            ))?,
    )
    .await?;
    ensure!(
        status == StatusCode::CONFLICT && calls.load(Ordering::SeqCst) == 0,
        "selection cannot bypass consent"
    );
    let (status, consent) = json_reply(
        &app,
        Request::post(&path)
            .header("cookie", &cookie)
            .header("origin", "https://auth.saas.test")
            .header("x-csrf-token", view["csrfToken"].as_str().unwrap())
            .header("content-type", "application/json")
            .body(Body::from(json!({"action":"consent"}).to_string()))?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && consent["continue"] == true
            && consent.get("redirectTo").is_none(),
        "consent does not issue code"
    );
    let (status, view) = json_reply(
        &app,
        Request::get(&path)
            .header("cookie", &cookie)
            .header("origin", "https://auth.saas.test")
            .body(Body::empty())?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && view["status"] == "CONTEXT_SELECTION_REQUIRED",
        "consent survives reload before selection"
    );
    ensure!(
        view["contextSelection"]["members"][0]["membershipId"] == member.to_string()
            && view.get("sourceProof").is_none()
            && view.get("credential").is_none(),
        "browser view contains only selectable identity presentation"
    );
    let decision = json!({"action":"approve","membershipId":member});
    let (status, _) = json_reply(
        &app,
        Request::post(&path)
            .header("cookie", &cookie)
            .header("origin", "https://auth.saas.test")
            .header("content-type", "application/json")
            .body(Body::from(decision.to_string()))?,
    )
    .await?;
    ensure!(
        status == StatusCode::FORBIDDEN && calls.load(Ordering::SeqCst) == 0,
        "missing CSRF cannot issue a platform selection"
    );
    let (status, approved) = json_reply(
        &app,
        Request::post(&path)
            .header("cookie", &cookie)
            .header("origin", "https://auth.saas.test")
            .header("x-csrf-token", view["csrfToken"].as_str().unwrap())
            .header("content-type", "application/json")
            .body(Body::from(decision.to_string()))?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && calls.load(Ordering::SeqCst) == 1,
        "selection confirmation and authorization must complete once"
    );
    let redirect = reqwest::Url::parse(
        approved["redirectTo"]
            .as_str()
            .context("missing callback")?,
    )?;
    let pairs: HashMap<_, _> = redirect
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    ensure!(
        pairs.len() == 3
            && pairs.contains_key("code")
            && pairs.contains_key("state")
            && pairs.contains_key("iss"),
        "browser callback cannot carry a selection credential"
    );
    let encrypted: String = sqlx::query_scalar(
        "SELECT credential_ciphertext FROM oidc_context_interactions WHERE transaction_id=$1",
    )
    .bind(transaction)
    .fetch_one(&pool)
    .await?;
    ensure!(
        !encrypted.contains(&"f".repeat(64)) && encrypted.starts_with("v1."),
        "credential must be encrypted at rest"
    );
    let overwritten = sqlx::query(
        "UPDATE oidc_context_interactions SET selected_membership_id=$2 WHERE transaction_id=$1",
    )
    .bind(transaction)
    .bind(Uuid::now_v7())
    .execute(&pool)
    .await;
    ensure!(
        overwritten.is_err(),
        "confirmed member binding cannot be changed"
    );
    let extended=sqlx::query("UPDATE oidc_context_interactions SET expires_at=expires_at+interval '1 second' WHERE transaction_id=$1").bind(transaction).execute(&pool).await;
    ensure!(
        extended.is_err(),
        "selection source deadline cannot be extended"
    );
    let mut form = reqwest::Url::parse("https://test.invalid/")?;
    form.query_pairs_mut()
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &pairs["code"])
        .append_pair("redirect_uri", "https://platform.saas.test/auth/callback")
        .append_pair("code_verifier", &verifier);
    let token_request = || {
        Request::post("/oidc/token")
            .header("authorization", &authorization)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form.query().unwrap().to_owned()))
    };
    let (status, tokens) = json_reply(&app, token_request()?).await?;
    ensure!(
        status == StatusCode::OK
            && tokens["context_selection"]["transactionId"] == transaction.to_string()
            && tokens["context_selection"]["credential"] == "f".repeat(64),
        "code exchange must privately deliver the exact chosen credential"
    );
    let decoding = jsonwebtoken::DecodingKey::from_rsa_components(
        key["n"].as_str().unwrap(),
        key["e"].as_str().unwrap(),
    )?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[client.to_string()]);
    validation.set_issuer(&["https://auth.saas.test"]);
    let claims = jsonwebtoken::decode::<Value>(
        tokens["id_token"].as_str().context("missing ID token")?,
        &decoding,
        &validation,
    )?
    .claims;
    ensure!(
        claims["sub"] == user.to_string()
            && claims["sid"] == sid.to_string()
            && claims["nonce"] == "nonce",
        "OIDC account identity and original nonce remain intact"
    );
    let erased:bool=sqlx::query_scalar("SELECT credential_ciphertext IS NULL AND delivered_at IS NOT NULL FROM oidc_context_interactions WHERE transaction_id=$1").bind(transaction).fetch_one(&pool).await?;
    ensure!(
        erased,
        "delivered ciphertext must be removed in the code-consumption transaction"
    );
    let access = tokens["access_token"]
        .as_str()
        .context("missing access token")?;
    let proof_request = json!({"contractVersion":VERSION,"transactionId":transaction,"expectedClientId":client,"oidcAccessToken":access});
    let (status, _) = json_reply(
        &app,
        Request::post("/internal/identity/context-selection/source")
            .header("authorization", &source_authorization)
            .header("content-type", "application/json")
            .body(Body::from(proof_request.to_string()))?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "consumer access must prove the exact interaction grant"
    );
    let mut refresh = reqwest::Url::parse("https://test.invalid/")?;
    refresh
        .query_pairs_mut()
        .append_pair("grant_type", "refresh_token")
        .append_pair(
            "refresh_token",
            tokens["refresh_token"]
                .as_str()
                .context("missing refresh")?,
        );
    let (status, refreshed) = json_reply(
        &app,
        Request::post("/oidc/token")
            .header("authorization", &authorization)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(refresh.query().unwrap().to_owned()))?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && refreshed.get("context_selection").is_none(),
        "refresh must never redeliver or recreate a selection credential"
    );
    let (status, replay) = json_reply(&app, token_request()?).await?;
    ensure!(
        status == StatusCode::BAD_REQUEST
            && replay["error"] == "invalid_grant"
            && replay.get("context_selection").is_none(),
        "code replay cannot redeliver the credential"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned PostgreSQL, explicit baseline, and disposable CONTEXT_SELECTION_TEST_SIGNING_KEYS"]
async fn real_selection_is_encrypted_and_delivered_only_by_one_code_exchange() -> TestResult<()> {
    super::tests::owned_database(cases).await
}
