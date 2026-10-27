use super::*;
use anyhow::{anyhow, ensure, Context as _, Result as TestResult};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::engine::general_purpose::STANDARD;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tower::ServiceExt;

#[test]
fn switch_is_strict_and_never_accepts_numeric_or_noncanonical_versions() {
    assert!(
        serde_json::from_value::<Intent>(json!({"kind":"LOGIN","sessionId":Uuid::now_v7()}))
            .is_err()
    );
    for version in [
        json!(1),
        json!("01"),
        json!("0"),
        json!("-1"),
        json!("9223372036854775808"),
    ] {
        let intent = serde_json::from_value::<Intent>(
            json!({"kind":"SWITCH","sessionId":Uuid::now_v7(),"expectedVersion":version}),
        );
        assert!(intent.is_err() || !intent.unwrap().valid());
    }
}

async fn post(
    app: &Router,
    path: &str,
    authorization: &str,
    body: Value,
) -> TestResult<(StatusCode, Value)> {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("authorization", authorization)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    ensure!(
        response
            .headers()
            .get("cache-control")
            .is_some_and(|h| h == "no-store"),
        "private results must not be cached"
    );
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn cases(pool: PgPool) -> TestResult<()> {
    let user = Uuid::now_v7();
    let rp = Uuid::now_v7();
    let service = Uuid::now_v7();
    let session = Uuid::now_v7();
    let rp_secret = "c".repeat(64);
    let source_secret = "d".repeat(64);
    sqlx::query("INSERT INTO users(id,username,password_hash,status,session_version) VALUES($1,'context-test','unused','ENABLED',1)").bind(user).execute(&pool).await?;
    sqlx::query("INSERT INTO oidc_provider_settings(singleton,issuer,created_at) VALUES(true,'https://auth.saas.test',clock_timestamp())").execute(&pool).await?;
    sqlx::query("INSERT INTO oidc_clients(id,name,purpose,secret_hash,allowed_member_types,redirect_uris,status,access_policy_version,created_at,updated_at) VALUES($1,'Context test','PLATFORM_CONSOLE',$2,ARRAY['EMPLOYEE'],ARRAY['https://platform.saas.test/auth/callback'],'ENABLED',1,clock_timestamp(),clock_timestamp())")
        .bind(rp).bind(super::super::digest(&rp_secret)).execute(&pool).await?;
    sqlx::query("INSERT INTO oidc_context_clients(client_id) VALUES($1)")
        .bind(rp)
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,created_at,allowed_oidc_clients) VALUES($1,$2,'CONTEXT_SELECTION_SOURCE','ENABLED',clock_timestamp(),ARRAY[$3]::uuid[])")
        .bind(service).bind(super::super::digest(&source_secret)).bind(rp).execute(&pool).await?;
    sqlx::query("INSERT INTO sso_sessions(id,user_id,token_hash,csrf_hash,account_version,authenticated_at,expires_at) VALUES($1,$2,repeat('a',64),repeat('b',64),1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')")
        .bind(session).bind(user).execute(&pool).await?;
    let mut config = crate::config::Config::from_values(&HashMap::from([(
        "DATABASE_URL".to_owned(),
        "postgres://fixture@localhost/context_test".to_owned(),
    )]))?;
    config.oidc_enabled = true;
    config.sso_enabled = true;
    config.oidc_issuer = Some("https://auth.saas.test".to_owned());
    config.sso_origin = config.oidc_issuer.clone();
    let state = AppState::new(pool.clone(), Arc::new(config));
    let app = super::super::protocol::routes().with_state(state.clone());
    let authorization = format!("Basic {}", STANDARD.encode(format!("{rp}:{rp_secret}")));
    let source_authorization = format!(
        "Basic {}",
        STANDARD.encode(format!("{service}:{source_secret}"))
    );
    let transaction = Uuid::now_v7();
    let challenge = URL_SAFE_NO_PAD.encode([1u8; 32]);
    let request = json!({"contractVersion":VERSION,"transactionId":transaction,"intent":{"kind":"LOGIN"},"redirectUri":"https://platform.saas.test/auth/callback","stateHash":super::super::digest("state"),"nonceHash":super::super::digest("nonce"),"codeChallenge":challenge});
    let (status, created) = post(
        &app,
        "/oidc/context-interactions",
        &authorization,
        request.clone(),
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "registered RP creates backend interaction: {status}"
    );
    let handle = created["contextRequest"]
        .as_str()
        .context("missing context handle")?;
    let flow_id = Uuid::now_v7();
    sqlx::query("INSERT INTO oidc_authorization_requests(id,browser_hash,csrf_hash,client_id,client_policy_version,redirect_uri,scope,state,nonce,code_challenge,force_login,session_id,user_id,account_version,created_at,expires_at) VALUES($1,repeat('a',64),repeat('b',64),$2,2,'https://platform.saas.test/auth/callback',ARRAY['openid','profile'],'state','nonce',$3,false,$4,$5,1,clock_timestamp(),clock_timestamp()+interval '5 minutes')")
        .bind(flow_id).bind(rp).bind(&challenge).bind(session).bind(user).execute(&pool).await?;
    let flow = store::flow(&pool, flow_id, false)
        .await?
        .context("missing fixture flow")?;
    let mut tx = pool.begin().await?;
    let mut wrong = flow.clone();
    wrong.nonce = "swapped".to_owned();
    ensure!(
        bind(&mut tx, &wrong, Some(handle)).await.is_err(),
        "nonce substitution rejected"
    );
    tx.rollback().await?;
    let mut tx = pool.begin().await?;
    ensure!(
        bind(&mut tx, &flow, Some(handle))
            .await
            .map_err(|_| anyhow!("binding failed"))?,
        "RP requires context binding"
    );
    let proof_handle = activate(&mut tx, &flow, &"e".repeat(64))
        .await?
        .context("source handle missing")?;
    tx.commit().await?;
    let source_body =
        json!({"contractVersion":VERSION,"sourceProof":proof_handle,"expectedClientId":rp});
    let (status, proof) = post(
        &app,
        "/internal/identity/context-selection/source",
        &source_authorization,
        source_body.clone(),
    )
    .await?;
    ensure!(
        status == StatusCode::OK && proof["source"]["userId"] == user.to_string(),
        "exact account-only source is returned: {status}"
    );
    ensure!(
        proof.get("members").is_none() && proof.get("tenantId").is_none(),
        "identity never returns business membership"
    );
    let mut account_lock = pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .execute(&mut *account_lock)
        .await?;
    let under_lock = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        post(
            &app,
            "/internal/identity/context-selection/source",
            &source_authorization,
            source_body.clone(),
        ),
    )
    .await??;
    ensure!(
        under_lock.0 == StatusCode::OK,
        "read-only source proof must not wait for the caller's account lock"
    );
    account_lock.rollback().await?;
    let mut mixed = source_body.clone();
    mixed["transactionId"] = json!(transaction);
    mixed["oidcAccessToken"] = json!("f".repeat(64));
    ensure!(
        post(
            &app,
            "/internal/identity/context-selection/source",
            &source_authorization,
            mixed
        )
        .await?
        .0 == StatusCode::BAD_REQUEST,
        "interaction and consumption proof modes cannot be mixed"
    );
    let guessed = json!({"contractVersion":VERSION,"transactionId":transaction,"oidcAccessToken":"f".repeat(64),"expectedClientId":rp});
    ensure!(
        post(
            &app,
            "/internal/identity/context-selection/source",
            &source_authorization,
            guessed
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED,
        "transaction identity alone cannot prove the code's original grant"
    );
    let mut tx = pool.begin().await?;
    let duplicate = bind(&mut tx, &flow, Some(handle)).await;
    ensure!(duplicate.is_err(), "interaction cannot be bound twice");
    tx.rollback().await?;
    let mut other = source_body.clone();
    other["expectedClientId"] = json!(Uuid::now_v7());
    ensure!(
        post(
            &app,
            "/internal/identity/context-selection/source",
            &source_authorization,
            other
        )
        .await?
        .0 == StatusCode::FORBIDDEN,
        "service scope rejects another RP"
    );
    sqlx::query("UPDATE sso_sessions SET revoked_at=clock_timestamp() WHERE id=$1")
        .bind(session)
        .execute(&pool)
        .await?;
    ensure!(
        post(
            &app,
            "/internal/identity/context-selection/source",
            &source_authorization,
            source_body
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED,
        "SSO revocation invalidates original source"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned CONTEXT_SELECTION_TEST_ADMIN_URL and explicit CONTEXT_SELECTION_BASELINE_FILE"]
async fn real_context_interaction_source_rejects_substitution_and_revocation() -> TestResult<()> {
    owned_database(cases).await
}

pub(super) async fn owned_database<F, Fut>(case: F) -> TestResult<()>
where
    F: FnOnce(PgPool) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult<()>> + Send,
{
    let options = PgConnectOptions::from_str(&std::env::var("CONTEXT_SELECTION_TEST_ADMIN_URL")?)
        .map_err(|_| anyhow!("invalid test administration URL"))?;
    ensure!(
        options.get_database() == Some("postgres"),
        "explicit postgres administration database required"
    );
    let baseline = std::path::PathBuf::from(std::env::var("CONTEXT_SELECTION_BASELINE_FILE")?);
    ensure!(
        baseline.is_absolute(),
        "explicit absolute baseline input required"
    );
    let baseline = std::fs::read_to_string(baseline)?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await?;
    let name = format!("context_identity_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&admin)
        .await?;
    let task_name = name.clone();
    let result = tokio::spawn(async move {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(options.database(&task_name))
            .await?;
        let result = async {
            sqlx::raw_sql(&baseline).execute(&pool).await?;
            case(pool.clone()).await
        }
        .await;
        pool.close().await;
        result
    })
    .await;
    sqlx::query(&format!("DROP DATABASE \"{name}\" WITH (FORCE)"))
        .execute(&admin)
        .await?;
    admin.close().await;
    result??;
    Ok(())
}
