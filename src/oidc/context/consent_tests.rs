//! Real database and browser handlers for durable approval and account isolation.
use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use serde_json::Value;
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

async fn reply(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    csrf: Option<&str>,
    origin: &str,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", cookie)
        .header("origin", origin);
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf);
    }
    let response = app.clone().oneshot(request.body(Body::empty())?).await?;
    ensure!(response
        .headers()
        .get("cache-control")
        .is_some_and(|v| v == "no-store"));
    Ok((
        response.status(),
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?,
    ))
}

async fn cases(pool: PgPool) -> Result<()> {
    let user = Uuid::now_v7();
    let other = Uuid::now_v7();
    let client = Uuid::now_v7();
    let other_client = Uuid::now_v7();
    let sid = Uuid::now_v7();
    let grant = Uuid::now_v7();
    let flow = Uuid::now_v7();
    let token = "a".repeat(64);
    let browser = "b".repeat(64);
    let digest = super::super::digest;
    let csrf = digest(&format!("sso-session-csrf-v1:{token}"));
    sqlx::query("INSERT INTO users(id,username,password_hash,status,session_version) VALUES($1,'approval-owner','unused','ENABLED',1),($2,'another-owner','unused','ENABLED',1)").bind(user).bind(other).execute(&pool).await?;
    for id in [client, other_client] {
        sqlx::query("INSERT INTO oidc_clients(id,name,purpose,secret_hash,allowed_member_types,redirect_uris,refresh_enabled,status,access_policy_version,created_at,updated_at) VALUES($1,'Approval test','ACCOUNT',repeat('c',64),ARRAY['EMPLOYEE'],ARRAY['https://app.saas.test/auth/callback'],true,'ENABLED',1,clock_timestamp(),clock_timestamp())").bind(id).execute(&pool).await?;
    }
    sqlx::query("INSERT INTO oidc_provider_settings VALUES(true,'https://auth.saas.test',clock_timestamp())").execute(&pool).await?;
    sqlx::query("INSERT INTO sso_sessions(id,user_id,token_hash,csrf_hash,account_version,authenticated_at,expires_at) VALUES($1,$2,$3,$4,1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')").bind(sid).bind(user).bind(digest(&token)).bind(digest(&csrf)).execute(&pool).await?;
    let scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "offline_access".to_owned(),
    ];
    let mut connection = pool.acquire().await?;
    super::super::consents::save(&mut connection, user, client, &scopes).await?;
    super::super::consents::save(&mut connection, other, other_client, &scopes).await?;
    ensure!(super::super::consents::approved(&mut connection, user, client, &scopes).await?);
    ensure!(!super::super::consents::approved(&mut connection, user, other_client, &scopes).await?);
    drop(connection);
    // An expired previous login grant is deliberately irrelevant to saved consent.
    sqlx::query("INSERT INTO oidc_grants(id,client_id,client_policy_version,session_id,user_id,account_version,scope,nonce,auth_time,created_at,expires_at) VALUES($1,$2,1,$3,$4,1,$5,'fixture',clock_timestamp()-interval '2 hours',clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour')").bind(grant).bind(client).bind(sid).bind(user).bind(&scopes).execute(&pool).await?;
    let add_flow = |flow: Uuid| {
        let pool = pool.clone();
        let scopes = scopes.clone();
        let browser = browser.clone();
        async move {
            sqlx::query("INSERT INTO oidc_authorization_requests(id,browser_hash,csrf_hash,client_id,client_policy_version,redirect_uri,scope,state,nonce,code_challenge,force_login,session_id,user_id,account_version,created_at,expires_at) VALUES($1,$2,$3,$4,1,'https://app.saas.test/auth/callback',$5,'state','nonce',repeat('x',43),false,$6,$7,1,clock_timestamp(),clock_timestamp()+interval '5 minutes')")
            .bind(flow).bind(digest(&browser)).bind(digest(&digest(&format!("oidc-flow-csrf-v1:{browser}:{flow}")))).bind(client).bind(scopes).bind(sid).bind(user).execute(&pool).await
        }
    };
    add_flow(flow).await?;
    let mut config = crate::config::Config::from_values(&HashMap::from([(
        "DATABASE_URL".to_owned(),
        "postgres://fixture@localhost/consent_test".to_owned(),
    )]))?;
    config.sso_enabled = true;
    config.oidc_enabled = true;
    config.sso_origin = Some("https://auth.saas.test".to_owned());
    config.oidc_issuer = config.sso_origin.clone();
    let state = crate::state::AppState::new(pool.clone(), Arc::new(config));
    let app = crate::sso::routes()
        .merge(super::super::protocol::routes())
        .with_state(state);
    let cookie = format!("__Host-saas_sso={token}; __Host-saas_oidc_browser={browser}");
    let (status, view) = reply(
        &app,
        "GET",
        &format!("/oidc/interaction/{flow}"),
        &cookie,
        None,
        "https://auth.saas.test",
    )
    .await?;
    ensure!(
        status == StatusCode::OK && view["consentRemembered"] == true,
        "new interaction must reuse approval despite old grant expiry"
    );
    let (_, list) = reply(
        &app,
        "GET",
        "/api/sso/applications",
        &cookie,
        None,
        "https://auth.saas.test",
    )
    .await?;
    ensure!(list["applications"]
        .as_array()
        .is_some_and(|a| a.len() == 1));
    ensure!(list["applications"][0]["clientId"] == client.to_string());
    let path = format!("/api/sso/applications/{client}/revoke");
    let delete_path = format!("/api/sso/applications/{client}");
    ensure!(
        reply(
            &app,
            "DELETE",
            &delete_path,
            &cookie,
            Some(&csrf),
            "https://auth.saas.test"
        )
        .await?
        .0 == StatusCode::CONFLICT,
        "active approval cannot be deleted"
    );
    ensure!(
        reply(&app, "POST", &path, &cookie, None, "https://auth.saas.test")
            .await?
            .0
            == StatusCode::FORBIDDEN,
        "CSRF required"
    );
    ensure!(
        reply(
            &app,
            "POST",
            &path,
            &cookie,
            Some(&csrf),
            "https://evil.test"
        )
        .await?
        .0 == StatusCode::FORBIDDEN,
        "foreign origin rejected"
    );
    ensure!(
        reply(
            &app,
            "POST",
            &format!("/api/sso/applications/{other_client}/revoke"),
            &cookie,
            Some(&csrf),
            "https://auth.saas.test"
        )
        .await?
        .0 == StatusCode::NOT_FOUND,
        "cannot revoke another account's application"
    );
    ensure!(
        reply(
            &app,
            "POST",
            &path,
            &cookie,
            Some(&csrf),
            "https://auth.saas.test"
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(
        sqlx::query_scalar::<_, bool>("SELECT revoked_at IS NOT NULL FROM oidc_grants WHERE id=$1")
            .bind(grant)
            .fetch_one(&pool)
            .await?
    );
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT consumed_at IS NOT NULL FROM oidc_authorization_requests WHERE id=$1"
        )
        .bind(flow)
        .fetch_one(&pool)
        .await?,
        "stale tabs invalidated"
    );
    let mut connection = pool.acquire().await?;
    ensure!(!super::super::consents::approved(&mut connection, user, client, &scopes).await?);
    ensure!(super::super::consents::approved(&mut connection, other, other_client, &scopes).await?);
    drop(connection);
    ensure!(
        reply(
            &app,
            "DELETE",
            &delete_path,
            &cookie,
            None,
            "https://auth.saas.test"
        )
        .await?
        .0 == StatusCode::FORBIDDEN,
        "delete requires CSRF"
    );
    ensure!(
        reply(
            &app,
            "DELETE",
            &format!("/api/sso/applications/{other_client}"),
            &cookie,
            Some(&csrf),
            "https://auth.saas.test"
        )
        .await?
        .0 == StatusCode::NOT_FOUND,
        "delete cannot touch another account"
    );
    ensure!(
        reply(
            &app,
            "DELETE",
            &delete_path,
            &cookie,
            Some(&csrf),
            "https://auth.saas.test"
        )
        .await?
        .0 == StatusCode::OK,
        "revoked approval is deletable"
    );
    ensure!(
        reply(
            &app,
            "DELETE",
            &delete_path,
            &cookie,
            Some(&csrf),
            "https://auth.saas.test"
        )
        .await?
        .0 == StatusCode::NOT_FOUND,
        "deleted record stays absent"
    );
    let (_, empty) = reply(
        &app,
        "GET",
        "/api/sso/applications",
        &cookie,
        None,
        "https://auth.saas.test",
    )
    .await?;
    ensure!(
        empty["applications"].as_array().is_some_and(Vec::is_empty),
        "deletion removes history from this account's list"
    );
    ensure!(
        sqlx::query_scalar::<_, bool>("SELECT revoked_at IS NOT NULL FROM oidc_grants WHERE id=$1")
            .bind(grant)
            .fetch_one(&pool)
            .await?,
        "deleting history cannot restore old grants"
    );
    let next = Uuid::now_v7();
    add_flow(next).await?;
    let (_, view) = reply(
        &app,
        "GET",
        &format!("/oidc/interaction/{next}"),
        &cookie,
        None,
        "https://auth.saas.test",
    )
    .await?;
    ensure!(
        view["consentRemembered"] == false && view["status"] == "CONSENT_REQUIRED",
        "explicit revoke requires new approval"
    );
    let mut connection = pool.acquire().await?;
    super::super::consents::save(&mut connection, user, client, &scopes[..1]).await?;
    ensure!(super::super::consents::approved(&mut connection, user, client, &scopes[..1]).await?);
    ensure!(
        !super::super::consents::approved(&mut connection, user, client, &scopes).await?,
        "new scopes require confirmation"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned PostgreSQL and explicit baseline"]
async fn durable_approvals_are_account_scoped_reusable_and_explicitly_revocable() -> Result<()> {
    super::tests::owned_database(cases).await
}
