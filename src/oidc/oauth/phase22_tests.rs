//! Independent IdentityState instances share only canonical PostgreSQL authority.
//! No listener, container, ambient DATABASE_URL, or running HTTPS fixture is used.
use super::*;
use crate::test_support::{self, Client as RegisteredClient, Grant, KeyFixture};
use anyhow::{anyhow, ensure, Context, Result as TestResult};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{sync::Arc, time::Duration as WallDuration};
use tower::ServiceExt;

const REDIRECT: &str = "https://rp.example.test/callback";
const VERIFIER: &str = "phase22-verifier-with-independent-nodes-012345678901234567890";

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    value: Value,
}

async fn request(state: &AppState, mut request: Request<Body>) -> TestResult<Reply> {
    if request
        .extensions()
        .get::<ConnectInfo<crate::network::Peer>>()
        .is_none()
    {
        request
            .extensions_mut()
            .insert(ConnectInfo(crate::network::Peer(
                "192.0.2.10:32000".parse()?,
            )));
    }
    let response = crate::router(state.clone()).oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 65_536).await?;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).context("protocol response was not JSON")?
    };
    Ok(Reply {
        status,
        headers,
        value,
    })
}

fn basic(client: &RegisteredClient, secret: &str) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{secret}", client.id))
    )
}

fn form_request(client: &RegisteredClient, path: &str, body: String) -> TestResult<Request<Body>> {
    Ok(Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, basic(client, &client.secret))
        .body(Body::from(body))?)
}

fn refresh_request(client: &RegisteredClient, token: &str) -> TestResult<Request<Body>> {
    form_request(
        client,
        "/oauth/token",
        format!("grant_type=refresh_token&refresh_token={token}"),
    )
}

fn code_request(client: &RegisteredClient, code: &str) -> TestResult<Request<Body>> {
    let form = format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Frp.example.test%2Fcallback&code_verifier={VERIFIER}");
    form_request(client, "/oauth/token", form)
}

fn logout_form(grant: &Grant, operation: Uuid) -> String {
    format!(
        "token={}&scope=CURRENT_APP&operation_id={operation}&sid={}&sub={}",
        grant.refresh, grant.sid, grant.sub
    )
}

async fn independent_states(keys: &KeyFixture, pool: &PgPool) -> TestResult<(AppState, AppState)> {
    let first = keys.state(pool.clone(), false).await?;
    let second = AppState::new(pool.clone(), first.config.clone());
    ensure!(
        !Arc::ptr_eq(&first.login_limits, &second.login_limits)
            && !Arc::ptr_eq(&first.auth_limits, &second.auth_limits)
            && !Arc::ptr_eq(&first.auth_slots, &second.auth_slots)
            && !Arc::ptr_eq(&first.internal_slots, &second.internal_slots)
            && !Arc::ptr_eq(&first.context_slots, &second.context_slots)
            && !Arc::ptr_eq(&first.authentication, &second.authentication)
            && !Arc::ptr_eq(&first.accounts, &second.accounts)
            && !Arc::ptr_eq(&first.context_platform, &second.context_platform),
        "independent states accidentally shared in-process authority/admission objects"
    );
    Ok((first, second))
}

async fn browser_cookie(pool: &PgPool, session: Uuid) -> TestResult<String> {
    let token = crate::util::hash::sha256_hex(&format!("phase22-browser-{session}"));
    let csrf = crate::util::hash::sha256_hex(&format!("sso-session-csrf-v1:{token}"));
    sqlx::query("UPDATE public.sso_sessions SET token_hash=$2,csrf_hash=$3 WHERE id=$1")
        .bind(session)
        .bind(crate::util::hash::sha256_hex(&token))
        .bind(crate::util::hash::sha256_hex(&csrf))
        .execute(pool)
        .await?;
    Ok(format!("__Host-saas_sso={token}"))
}

async fn authorized_code(
    state: &AppState,
    client: &RegisteredClient,
    cookie: &str,
) -> TestResult<String> {
    let mut url = reqwest::Url::parse("https://auth.saas.test/oauth/authorize")?;
    url.query_pairs_mut()
        .append_pair("client_id", &client.id.to_string())
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid profile")
        .append_pair("state", "phase22-independent-browser-state")
        .append_pair("nonce", "phase22-independent-browser-nonce")
        .append_pair("code_challenge", &pkce_challenge(VERIFIER))
        .append_pair("code_challenge_method", "S256");
    let start = request(
        state,
        Request::get(format!(
            "/oauth/authorize?{}",
            url.query().context("authorize query")?
        ))
        .header(header::COOKIE, cookie)
        .body(Body::empty())?,
    )
    .await?;
    ensure!(
        start.status.is_redirection(),
        "actual authorize did not redirect"
    );
    let location = start
        .headers
        .get(header::LOCATION)
        .context("authorize location")?
        .to_str()?;
    ensure!(
        location.starts_with("/oauth/login?flow="),
        "fresh canonical client did not request consent"
    );
    let flow = location
        .strip_prefix("/oauth/login?flow=")
        .context("consent flow")?;
    let browser = start
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            value
                .split(';')
                .next()
                .filter(|pair| pair.starts_with("__Host-saas_oauth_browser="))
        })
        .context("browser binding cookie")?;
    let cookies = format!("{cookie}; {browser}");
    let interaction = request(
        state,
        Request::get(format!("/oauth/interaction/{flow}"))
            .header(header::COOKIE, &cookies)
            .header(header::ORIGIN, "https://auth.saas.test")
            .body(Body::empty())?,
    )
    .await?;
    ensure!(
        interaction.status == StatusCode::OK && interaction.value["status"] == "CONSENT_REQUIRED",
        "actual interaction did not request consent"
    );
    let csrf = interaction.value["csrfToken"]
        .as_str()
        .context("consent CSRF")?;
    let approved = request(
        state,
        Request::post(format!("/oauth/interaction/{flow}"))
            .header(header::COOKIE, &cookies)
            .header(header::ORIGIN, "https://auth.saas.test")
            .header("x-csrf-token", csrf)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"action":"approve"}).to_string()))?,
    )
    .await?;
    ensure!(
        approved.status == StatusCode::OK,
        "actual consent did not approve"
    );
    let callback = reqwest::Url::parse(
        approved.value["redirectTo"]
            .as_str()
            .context("consent callback")?,
    )?;
    callback
        .query_pairs()
        .find_map(|(name, value)| (name == "code").then(|| value.into_owned()))
        .context("consent did not issue code")
}

async fn blocked_at(pool: &PgPool, blocker: i32, expected: i64) -> TestResult<()> {
    tokio::time::timeout(WallDuration::from_secs(4), async {
        loop {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))")
                .bind(blocker).fetch_one(pool).await?;
            if count >= expected { return Ok::<(), anyhow::Error>(()); }
            tokio::time::sleep(WallDuration::from_millis(20)).await;
        }
    }).await.map_err(|_| anyhow!("two independent requests did not reach the real PostgreSQL barrier"))?
}

async fn unchanged_source(pool: &PgPool, user: Uuid, session: Uuid, grant: Uuid) -> TestResult<()> {
    let valid: bool = sqlx::query_scalar("SELECT subject.session_version=3 AND subject.status='ENABLED' AND session.revoked_at IS NULL AND grant_row.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM auth_access_tokens WHERE grant_id=$3 AND revoked_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM auth_refresh_families WHERE grant_id=$3 AND revoked_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM auth_refresh_tokens token JOIN auth_refresh_families family ON family.id=token.family_id WHERE family.grant_id=$3 AND (token.revoked_at IS NOT NULL OR token.consumed_at IS NOT NULL)) FROM users subject JOIN sso_sessions session ON session.user_id=subject.id JOIN auth_grants grant_row ON grant_row.user_id=subject.id AND grant_row.source_session_id=session.id WHERE subject.id=$1 AND session.id=$2 AND grant_row.id=$3")
        .bind(user).bind(session).bind(grant).fetch_one(pool).await?;
    ensure!(
        valid,
        "dependency/admission failure changed the original valid authority"
    );
    Ok(())
}

fn unavailable(reply: &Reply, protocol: bool) -> TestResult<()> {
    ensure!(
        reply.status == StatusCode::SERVICE_UNAVAILABLE,
        "dependency failure became {} instead of 503",
        reply.status
    );
    ensure!(
        reply.headers.get(header::WWW_AUTHENTICATE).is_none(),
        "dependency failure requested new credentials"
    );
    ensure!(
        reply
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|value| !value.to_str().unwrap_or("").contains("Max-Age=0")),
        "dependency failure cleared the browser's legal source cookie"
    );
    ensure!(
        if protocol {
            reply.value["error"] == "temporarily_unavailable"
        } else {
            reply.value["code"] == "SERVICE_UNAVAILABLE"
        },
        "dependency failure changed the documented redacted error wire"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase22 canonical PostgreSQL"]
async fn independent_nodes_redeem_one_actual_authorization_code_once() -> TestResult<()> {
    test_support::isolated_phase22(|pool| async move {
        let keys = KeyFixture::new()?;
        let (first, second) = independent_states(&keys, &pool).await?;
        let (user, session) = test_support::account(&pool).await?;
        let client = test_support::client(&pool).await?;
        let cookie = browser_cookie(&pool, session).await?;
        let code = authorized_code(&first, &client, &cookie).await?;
        let mut blocker = pool.begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE").bind(user).execute(&mut *blocker).await?;
        let left_request = code_request(&client, &code)?;
        let right_request = code_request(&client, &code)?;
        let left = tokio::spawn(async move { request(&first, left_request).await });
        let right = tokio::spawn(async move { request(&second, right_request).await });
        let barrier = blocked_at(&pool, blocker_pid, 2).await;
        blocker.rollback().await?;
        let (left, right) = tokio::join!(left, right);
        let replies = [left??, right??];
        barrier?;
        ensure!(replies.iter().filter(|reply| reply.status == StatusCode::OK).count() == 1
            && replies.iter().filter(|reply| reply.status == StatusCode::BAD_REQUEST && reply.value["error"] == "invalid_grant").count() == 1,
            "independent processes did not enforce exactly one code exchange");
        let counts: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_grants WHERE client_id=$1),(SELECT count(*) FROM auth_authorization_codes WHERE client_id=$1 AND consumed_at IS NOT NULL),(SELECT count(*) FROM auth_authorization_requests WHERE client_id=$1 AND status='CONSUMED'),(SELECT count(*) FROM identity_audit_logs WHERE action='AUTH_CODE_EXCHANGE')")
            .bind(client.id).fetch_one(&pool).await?;
        ensure!(counts == (1,1,1,1), "duplicate authority or audit escaped canonical code serialization");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase22 canonical PostgreSQL"]
async fn independent_nodes_refresh_race_detects_reuse_without_crossing_sources() -> TestResult<()> {
    test_support::isolated_phase22(|pool| async move {
        let keys = KeyFixture::new()?;
        let (first, second) = independent_states(&keys, &pool).await?;
        let recovered = AppState::new(pool.clone(), first.config.clone());
        let (user, session) = test_support::account(&pool).await?;
        let client = test_support::client(&pool).await?;
        let grant = test_support::grant(&pool,user,session,&client,false).await?;
        let separate = test_support::grant(&pool,user,session,&client,false).await?;
        let mut blocker = pool.begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE").bind(user).execute(&mut *blocker).await?;
        let left_request = refresh_request(&client,&grant.refresh)?;
        let right_request = refresh_request(&client,&grant.refresh)?;
        let left = tokio::spawn(async move { request(&first,left_request).await });
        let right = tokio::spawn(async move { request(&second,right_request).await });
        let barrier = blocked_at(&pool,blocker_pid,2).await;
        blocker.rollback().await?;
        let (left,right) = tokio::join!(left,right);
        let replies = [left??,right??];
        barrier?;
        ensure!(replies.iter().filter(|reply|reply.status==StatusCode::OK).count()==1
            && replies.iter().filter(|reply|reply.status==StatusCode::BAD_REQUEST&&reply.value["error"]=="invalid_grant").count()==1,
            "one refresh generation was issued more than once across instances");
        let counts: (i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_refresh_families WHERE grant_id=$1 AND revoked_at IS NOT NULL),(SELECT count(*) FROM auth_refresh_tokens token JOIN auth_refresh_families family ON family.id=token.family_id WHERE family.grant_id=$1),(SELECT count(*) FROM auth_refresh_tokens token JOIN auth_refresh_families family ON family.id=token.family_id WHERE family.grant_id=$1 AND token.generation=1 AND token.consumed_at IS NOT NULL),(SELECT count(*) FROM auth_access_tokens WHERE grant_id=$1 AND revoked_at IS NULL),(SELECT count(*) FROM identity_audit_logs WHERE action='OAUTH_REFRESH_REUSE')")
            .bind(grant.id).fetch_one(&pool).await?;
        ensure!(counts==(1,2,1,0,1),"replay did not revoke exactly the original rotated family/access tokens");
        unchanged_source(&pool,user,session,separate.id).await?;
        let winner = replies.iter().find(|reply|reply.status==StatusCode::OK).context("refresh winner")?;
        let rejected = request(&recovered,refresh_request(&client,winner.value["refresh_token"].as_str().context("successor token")?)?).await?;
        ensure!(rejected.status==StatusCode::BAD_REQUEST&&rejected.value["error"]=="invalid_grant","replayed family successor remained usable");
        let healthy = request(&recovered,refresh_request(&client,&separate.refresh)?).await?;
        ensure!(healthy.status==StatusCode::OK,"another original source was revoked by replay");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase22 canonical PostgreSQL"]
async fn independent_nodes_logout_operation_is_one_durable_commit() -> TestResult<()> {
    test_support::isolated_phase22(|pool| async move {
        let keys = KeyFixture::new()?;
        let (first, second) = independent_states(&keys,&pool).await?;
        let verifier = AppState::new(pool.clone(),first.config.clone());
        let (user,session) = test_support::account(&pool).await?;
        let client = test_support::client(&pool).await?;
        let grant = test_support::grant(&pool,user,session,&client,false).await?;
        let separate = test_support::grant(&pool,user,session,&client,false).await?;
        let operation = Uuid::now_v7();
        let body = logout_form(&grant,operation);
        let mut blocker = pool.begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2000662001))").bind(operation.to_string()).execute(&mut *blocker).await?;
        let left_request = form_request(&client,"/oauth/logout",body.clone())?;
        let right_request = form_request(&client,"/oauth/logout",body.clone())?;
        let left = tokio::spawn(async move { request(&first,left_request).await });
        let right = tokio::spawn(async move { request(&second,right_request).await });
        let barrier = blocked_at(&pool,blocker_pid,2).await;
        blocker.rollback().await?;
        let (left,right) = tokio::join!(left,right);
        let left=left??; let right=right??;
        barrier?;
        ensure!(left.status==StatusCode::OK&&right.status==StatusCode::OK&&left.value==right.value&&left.value["revokedGrantCount"]==1,"same original logout operation committed different outcomes");
        let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_logout_command_receipts WHERE operation_id=$1),(SELECT count(*) FROM identity_audit_logs WHERE action='AUTH_RP_LOGOUT'),(SELECT count(*) FROM auth_delivery_jobs WHERE grant_id=$2 AND kind='LOGOUT')")
            .bind(operation).bind(grant.id).fetch_one(&pool).await?;
        ensure!(counts==(1,1,1),"duplicate logout receipt, audit, or outbox row escaped DB serialization");
        unchanged_source(&pool,user,session,separate.id).await?;
        let changed = request(&verifier,form_request(&client,"/oauth/logout",body.replace("CURRENT_APP","GLOBAL"))?).await?;
        ensure!(changed.status==StatusCode::CONFLICT,"original operation was rebound to global logout");
        let lookup = request(&verifier,form_request(&client,&format!("/oauth/logout/operations/{operation}"),body)?).await?;
        ensure!(lookup.status==StatusCode::OK&&lookup.value==left.value,"independent instance could not recover original committed logout");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase22 canonical PostgreSQL"]
async fn saturated_and_closed_pools_return_503_without_clearing_legal_sources() -> TestResult<()> {
    test_support::isolated_phase22(|pool| async move {
        let keys = KeyFixture::new()?;
        let (normal, _) = independent_states(&keys, &pool).await?;
        let (user, session) = test_support::account(&pool).await?;
        let cookie = browser_cookie(&pool, session).await?;
        let client = test_support::client(&pool).await?;
        let grant = test_support::grant(&pool, user, session, &client, false).await?;
        let limited = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(WallDuration::from_millis(70))
            .connect_with(pool.connect_options().as_ref().clone())
            .await?;
        let failed = AppState::new(limited.clone(), normal.config.clone());
        let held = limited.acquire().await?;
        unavailable(
            &request(&failed, refresh_request(&client, &grant.refresh)?).await?,
            true,
        )?;
        unavailable(
            &request(
                &failed,
                Request::get("/oauth/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {}", grant.access))
                    .body(Body::empty())?,
            )
            .await?,
            true,
        )?;
        unavailable(
            &request(
                &failed,
                Request::get("/api/sso/session")
                    .header(header::COOKIE, &cookie)
                    .header(header::ORIGIN, "https://auth.saas.test")
                    .body(Body::empty())?,
            )
            .await?,
            false,
        )?;
        unchanged_source(&pool, user, session, grant.id).await?;
        drop(held);
        let restored = request(
            &failed,
            Request::get("/api/sso/session")
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "https://auth.saas.test")
                .body(Body::empty())?,
        )
        .await?;
        ensure!(
            restored.status == StatusCode::OK,
            "original SSO cookie did not recover after pool capacity returned"
        );
        limited.close().await;
        unavailable(
            &request(&failed, refresh_request(&client, &grant.refresh)?).await?,
            true,
        )?;
        unavailable(
            &request(
                &failed,
                Request::get("/oauth/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {}", grant.access))
                    .body(Body::empty())?,
            )
            .await?,
            true,
        )?;
        unavailable(
            &request(
                &failed,
                Request::get("/api/sso/session")
                    .header(header::COOKIE, &cookie)
                    .header(header::ORIGIN, "https://auth.saas.test")
                    .body(Body::empty())?,
            )
            .await?,
            false,
        )?;
        unchanged_source(&pool, user, session, grant.id).await?;
        let restored = request(&normal, refresh_request(&client, &grant.refresh)?).await?;
        ensure!(
            restored.status == StatusCode::OK,
            "another independent node could not use the unchanged original refresh"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase22 canonical PostgreSQL"]
async fn actual_client_table_lock_failure_is_503_and_preserves_original_tokens() -> TestResult<()> {
    test_support::isolated_phase22(|pool| async move {
        let keys = KeyFixture::new()?;
        let (normal, _) = independent_states(&keys, &pool).await?;
        let (user, session) = test_support::account(&pool).await?;
        let client = test_support::client(&pool).await?;
        let grant = test_support::grant(&pool, user, session, &client, false).await?;
        let bounded = PgPoolOptions::new()
            .max_connections(3)
            .acquire_timeout(WallDuration::from_millis(200))
            .connect_with(
                pool.connect_options()
                    .as_ref()
                    .clone()
                    .options([("lock_timeout", "100ms"), ("statement_timeout", "500ms")]),
            )
            .await?;
        let state = AppState::new(bounded.clone(), normal.config.clone());
        let mut blocker = pool.begin().await?;
        sqlx::query("LOCK TABLE public.auth_clients IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await?;
        let token = request(&state, refresh_request(&client, &grant.refresh)?).await;
        let info = request(
            &state,
            Request::get("/oauth/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {}", grant.access))
                .body(Body::empty())?,
        )
        .await;
        blocker.rollback().await?;
        unavailable(&token?, true)?;
        unavailable(&info?, true)?;
        unchanged_source(&pool, user, session, grant.id).await?;
        let info = request(
            &state,
            Request::get("/oauth/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {}", grant.access))
                .body(Body::empty())?,
        )
        .await?;
        ensure!(
            info.status == StatusCode::OK,
            "legal access did not recover after real lock failure"
        );
        let good = request(&state, refresh_request(&client, &grant.refresh)?).await?;
        ensure!(
            good.status == StatusCode::OK,
            "original refresh was consumed or revoked on query failure"
        );
        bounded.close().await;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase22 canonical PostgreSQL"]
async fn client_budget_cannot_be_reset_by_rotating_socket_sources() -> TestResult<()> {
    test_support::isolated_phase22(|pool| async move {
        let keys = KeyFixture::new()?;
        let base = keys.state(pool.clone(), false).await?;
        let client = test_support::client(&pool).await?;
        let mut config = base.config.as_ref().clone();
        config.auth_client_requests = 2;
        config.auth_source_requests = 100;
        let first = AppState::new(pool.clone(), Arc::new(config.clone()));
        let second = AppState::new(pool.clone(), Arc::new(config));
        ensure!(
            !Arc::ptr_eq(&first.auth_limits, &second.auth_limits),
            "quota test shared process-local limits"
        );
        let invalid_code = "c7".repeat(32);
        let mut wrong = code_request(&client, &invalid_code)?;
        wrong.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&basic(&client, "wrong-secret"))?,
        );
        let wrong = request(&first, wrong).await?;
        ensure!(
            wrong.status == StatusCode::UNAUTHORIZED && wrong.value["error"] == "invalid_client",
            "incorrect client secret must remain 401 within budget"
        );
        let valid = request(&first, code_request(&client, &invalid_code)?).await?;
        ensure!(
            valid.status == StatusCode::BAD_REQUEST && valid.value["error"] == "invalid_grant",
            "correct secret did not reach the grant check within quota"
        );
        for address in ["198.51.100.22:34000", "203.0.113.23:35000"] {
            let mut next = code_request(&client, &invalid_code)?;
            next.extensions_mut()
                .insert(ConnectInfo(crate::network::Peer(address.parse()?)));
            next.headers_mut()
                .insert("x-real-ip", HeaderValue::from_static("8.8.8.8"));
            let rejected = request(&first, next).await?;
            let retry: u64 = rejected
                .headers
                .get(header::RETRY_AFTER)
                .context("client quota Retry-After")?
                .to_str()?
                .parse()?;
            ensure!(
                rejected.status == StatusCode::TOO_MANY_REQUESTS
                    && rejected.value["error"] == "temporarily_unavailable"
                    && (1..=60).contains(&retry),
                "a different socket source bypassed the client's live budget"
            );
        }
        let other_node = request(&second, code_request(&client, &invalid_code)?).await?;
        ensure!(
            other_node.status == StatusCode::BAD_REQUEST
                && other_node.value["error"] == "invalid_grant",
            "local quota was incorrectly presented as a cluster-wide authority fence"
        );
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM auth_grants),(SELECT count(*) FROM identity_audit_logs)",
        )
        .fetch_one(&pool)
        .await?;
        ensure!(
            counts == (0, 0),
            "invalid/quota-limited requests created authority or audit claims"
        );
        Ok(())
    })
    .await
}
