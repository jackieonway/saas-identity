use super::*;
use crate::test_support::{self, Grant, KeyFixture};
use anyhow::{ensure, Result as TestResult};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

fn form(source: &Grant, scope: &str, operation: Uuid) -> String {
    format!(
        "token={}&scope={scope}&operation_id={operation}&sid={}&sub={}",
        source.refresh, source.sid, source.sub
    )
}
async fn request(
    state: &AppState,
    client: &test_support::Client,
    path: &str,
    body: String,
    cookie: bool,
) -> TestResult<(StatusCode, Value)> {
    let mut request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", client.id, client.secret))
            ),
        );
    if cookie {
        request = request.header(header::COOKIE, "not-authentication=1");
    }
    let response: Response = crate::oidc::routes()
        .with_state(state.clone())
        .oneshot(request.body(Body::from(body))?)
        .await?;
    let status = response.status();
    let raw = to_bytes(response.into_body(), 65_536).await?;
    Ok((status, serde_json::from_slice(&raw).unwrap_or(Value::Null)))
}
async fn revoked(pool: &sqlx::PgPool, grant: Uuid) -> TestResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM public.auth_grants WHERE id=$1")
            .bind(grant)
            .fetch_one(pool)
            .await?,
    )
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase20 PostgreSQL"]
async fn current_app_and_global_preserve_consent_and_original_operation() -> TestResult<()> {
    test_support::isolated(|pool|async move{
        let keys=KeyFixture::new()?;let state=keys.state(pool.clone(),false).await?;
        let (user,session)=test_support::account(&pool).await?;
        let (other,other_session)=test_support::account(&pool).await?;
        let rp=test_support::client(&pool).await?;let another_rp=test_support::client(&pool).await?;
        let first=test_support::grant(&pool,user,session,&rp,false).await?;
        let next=test_support::grant(&pool,user,session,&rp,false).await?;
        let another=test_support::grant(&pool,user,session,&another_rp,true).await?;
        let unrelated=test_support::grant(&pool,other,other_session,&rp,false).await?;
        ensure!(first.sid!=next.sid && !first.sid.contains(&session.to_string()),"public sid adopted an internal/global session identifier");
        let operation=Uuid::now_v7();let body=form(&first,"CURRENT_APP",operation).replace(&first.refresh,&first.access);
        let (missing_status,missing)=request(&state,&rp,&format!("/oauth/logout/operations/{operation}"),body.clone(),false).await?;
        ensure!(missing_status==StatusCode::NOT_FOUND&&missing["code"]=="NOT_FOUND","missing original operation did not have the fixed recovery envelope");
        let (status,result)=request(&state,&rp,"/oauth/logout",body.clone(),false).await?;
        ensure!(status==StatusCode::OK&&result["scope"]=="CURRENT_APP"&&result["state"]=="COMPLETED"&&result["revokedGrantCount"]==1&&result["revokedSsoCount"]==0&&result["notificationCount"]==1,"current-app command failed its exact scope or counters");
        ensure!(revoked(&pool,first.id).await?&&!revoked(&pool,next.id).await?&&!revoked(&pool,another.id).await?&&!revoked(&pool,unrelated.id).await?,"current app revoked another grant, RP or account");
        let preserved:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM auth_consents WHERE status<>'ACTIVE') AND NOT EXISTS(SELECT 1 FROM sso_sessions WHERE revoked_at IS NOT NULL)").fetch_one(&pool).await?;
        ensure!(preserved,"current logout changed consent or SSO");
        let (replayed_status,replayed)=request(&state,&rp,"/oauth/logout",body.clone(),false).await?;
        let (lookup_status,lookup)=request(&state,&rp,&format!("/oauth/logout/operations/{operation}"),body.clone(),false).await?;
        ensure!(replayed_status==StatusCode::OK&&lookup_status==StatusCode::OK&&replayed==result&&lookup==result,"original operation did not recover after its token was revoked");
        let (changed,_) =request(&state,&rp,"/oauth/logout",body.replace("CURRENT_APP","GLOBAL"),false).await?;
        ensure!(changed==StatusCode::CONFLICT,"operation body was rebound to broader logout scope");
        let global_operation=Uuid::now_v7();let global_body=form(&next,"GLOBAL",global_operation);
        let (global_status,global)=request(&state,&rp,"/oauth/logout",global_body.clone(),false).await?;
        ensure!(global_status==StatusCode::OK&&global["revokedGrantCount"]==2&&global["revokedSsoCount"]==1&&global["notificationCount"]==2,"global logout did not count only newly revoked sources");
        ensure!(revoked(&pool,next.id).await?&&revoked(&pool,another.id).await?&&!revoked(&pool,unrelated.id).await?,"global logout missed offline/RP sources or affected another account");
        let versions:(i64,i64)=sqlx::query_as("SELECT (SELECT session_version FROM users WHERE id=$1),(SELECT session_version FROM users WHERE id=$2)").bind(user).bind(other).fetch_one(&pool).await?;
        ensure!(versions==(4,3),"global logout did not advance exactly the original account generation");
        let (repeat_status,repeat)=request(&state,&rp,"/oauth/logout",global_body,false).await?;
        ensure!(repeat_status==StatusCode::OK&&repeat==global,"global original operation was not idempotent");
        let version:i64=sqlx::query_scalar("SELECT session_version FROM users WHERE id=$1").bind(user).fetch_one(&pool).await?;
        ensure!(version==4,"recovery advanced account generation again");
        let consents:i64=sqlx::query_scalar("SELECT count(*) FROM auth_consents WHERE status<>'ACTIVE'").fetch_one(&pool).await?;
        ensure!(consents==0,"global logout revoked persistent consent");
        let secrets:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM auth_logout_command_receipts WHERE result_json ?| ARRAY['token','sid','sub','userId','globalSessionId','password'])").fetch_one(&pool).await?;
        ensure!(secrets,"logout receipt returned internal source or token material");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase20 PostgreSQL"]
async fn logout_rejects_wrong_original_source_and_atomic_audit_failure() -> TestResult<()> {
    test_support::isolated(|pool|async move{
        let keys=KeyFixture::new()?;let state=keys.state(pool.clone(),false).await?;
        let (user,session)=test_support::account(&pool).await?;
        let rp=test_support::client(&pool).await?;let other_rp=test_support::client(&pool).await?;
        let grant=test_support::grant(&pool,user,session,&rp,false).await?;
        let operation=Uuid::now_v7();let body=form(&grant,"CURRENT_APP",operation);
        for (client,value,cookie) in [
            (&other_rp,body.clone(),false),(&rp,body.replace(&grant.sid,&"f".repeat(64)),false),
            (&rp,body.replace(&grant.sub,"another_pairwise_subject"),false),(&rp,body.clone(),true),
            (&rp,format!("{body}&scope=GLOBAL"),false),(&rp,format!("{body}&unexpected=true"),false),
        ] {
            let (status,_)=request(&state,client,"/oauth/logout",value,cookie).await?;
            ensure!(status.is_client_error(),"wrong client, sid/sub, duplicate/unknown form or Cookie was admitted");
        }
        ensure!(!revoked(&pool,grant.id).await?,"a rejected logout changed authority");
        sqlx::raw_sql("CREATE FUNCTION phase20_suppress_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='AUTH_RP_LOGOUT' THEN RETURN NULL; END IF;RETURN NEW;END $$;CREATE TRIGGER phase20_suppress_audit BEFORE INSERT ON identity_audit_logs FOR EACH ROW EXECUTE FUNCTION phase20_suppress_audit()").execute(&pool).await?;
        let (failed,_)=request(&state,&rp,"/oauth/logout",body.clone(),false).await?;
        ensure!(failed==StatusCode::SERVICE_UNAVAILABLE&&!revoked(&pool,grant.id).await?,"audit failure did not roll back grant revocation");
        let rows:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_delivery_jobs),(SELECT count(*) FROM auth_logout_command_receipts)").fetch_one(&pool).await?;
        ensure!(rows==(0,0),"audit failure left a job or successful receipt");
        sqlx::query("DROP TRIGGER phase20_suppress_audit ON identity_audit_logs").execute(&pool).await?;
        let (status,_)=request(&state,&rp,"/oauth/logout",body,false).await?;
        ensure!(status==StatusCode::OK&&revoked(&pool,grant.id).await?,"same original operation could not safely apply after a rolled-back attempt");
        let expired=test_support::grant(&pool,user,session,&rp,false).await?;
        sqlx::query("UPDATE auth_refresh_families SET revoked_at=clock_timestamp() WHERE grant_id=$1").bind(expired.id).execute(&pool).await?;
        let (status,_)=request(&state,&rp,"/oauth/logout",form(&expired,"GLOBAL",Uuid::now_v7()),false).await?;
        ensure!(status==StatusCode::BAD_REQUEST&&!revoked(&pool,expired.id).await?,"inactive original refresh family became global account authority");
        let revoked_token=test_support::grant(&pool,user,session,&rp,false).await?;
        sqlx::query("UPDATE auth_refresh_tokens SET revoked_at=clock_timestamp() WHERE token_digest=$1").bind(crate::util::hash::sha256_hex(&revoked_token.refresh)).execute(&pool).await?;
        let(status,_)=request(&state,&rp,"/oauth/logout",form(&revoked_token,"GLOBAL",Uuid::now_v7()),false).await?;
        ensure!(status==StatusCode::BAD_REQUEST&&!revoked(&pool,revoked_token.id).await?,"individually revoked original refresh token became global account authority");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase20 PostgreSQL"]
async fn simultaneous_original_operation_commits_once_and_different_operations_do_not_adopt_source(
) -> TestResult<()> {
    test_support::isolated(|pool|async move{
        let keys=KeyFixture::new()?;let state=keys.state(pool.clone(),false).await?;
        let (user,session)=test_support::account(&pool).await?;let rp=test_support::client(&pool).await?;
        let grant=test_support::grant(&pool,user,session,&rp,false).await?;
        let operation=Uuid::now_v7();let body=form(&grant,"GLOBAL",operation);
        let (first,second)=tokio::join!(request(&state,&rp,"/oauth/logout",body.clone(),false),request(&state,&rp,"/oauth/logout",body,false));
        let (first_status,first)=first?;let(second_status,second)=second?;
        ensure!(first_status==StatusCode::OK&&second_status==StatusCode::OK&&first==second,"same operation race did not recover one result");
        let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT session_version FROM users WHERE id=$1),(SELECT count(*) FROM auth_logout_command_receipts),(SELECT count(*) FROM auth_delivery_jobs)").bind(user).fetch_one(&pool).await?;
        ensure!(counts==(4,1,1),"same operation race performed duplicate global side effects");
        let (status,_)=request(&state,&rp,"/oauth/logout",form(&grant,"GLOBAL",Uuid::now_v7()),false).await?;
        ensure!(status==StatusCode::BAD_REQUEST,"new operation adopted an already retired original source");
        Ok(())
    }).await
}
