//! PostgreSQL and HTTP regressions for explicit, group-scoped user consent.

use super::Database;
use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    auth_consent::{self, ConsentAuditContext, ConsentState, ScopeGrant},
    sso::AccountSessionProof,
};

struct Fixture<'db> {
    db: &'db Database,
    group_one: Uuid,
    client_one: Uuid,
    client_sibling: Uuid,
    client_ungrouped: Uuid,
    client_other_application: Uuid,
    owner: Uuid,
    other_user: Uuid,
    resource: Uuid,
    openid: Uuid,
    profile: Uuid,
    consent_one: Uuid,
    consent_other_user: Uuid,
    consent_other_app: Uuid,
    session: Uuid,
    session_token: String,
    csrf: String,
}

async fn fixture(db: &Database) -> Result<Fixture<'_>> {
    let app_one = Uuid::now_v7();
    let app_two = Uuid::now_v7();
    let group_one = Uuid::now_v7();
    let group_two = Uuid::now_v7();
    let client_one = Uuid::now_v7();
    let client_sibling = Uuid::now_v7();
    let client_ungrouped = Uuid::now_v7();
    let client_other_application = Uuid::now_v7();
    let other_user = Uuid::now_v7();
    let resource = Uuid::now_v7();
    let openid = Uuid::now_v7();
    let profile = Uuid::now_v7();
    let consent_one = Uuid::now_v7();
    let consent_other_user = Uuid::now_v7();
    let consent_other_app = Uuid::now_v7();
    let session = Uuid::now_v7();
    let session_token = "7f".repeat(32);
    let csrf = crate::util::hash::sha256_hex(&format!("sso-session-csrf-v1:{session_token}"));

    sqlx::query("INSERT INTO users(id,username,password_hash,real_name) VALUES($1,'other-consent-user','unused','Other User')")
        .bind(other_user).execute(&db.pool).await?;
    for (id, display) in [
        (app_one, "Consent application one"),
        (app_two, "Consent application two"),
    ] {
        sqlx::query("INSERT INTO auth_applications(application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) VALUES($1,NULL,'FIRST_PARTY','APPROVED',$2,'Account sign-in',ARRAY['openid','profile'],1,clock_timestamp())")
            .bind(id).bind(display).execute(&db.pool).await?;
    }
    sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'userinfo','https://auth.saas.test/userinfo','ACTIVE',1)")
        .bind(resource).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$3,'openid','ACTIVE'),($2,$3,'profile','ACTIVE')")
        .bind(openid).bind(profile).bind(resource).execute(&db.pool).await?;
    for (group, application) in [(group_one, app_one), (group_two, app_two)] {
        sqlx::query("INSERT INTO auth_consent_groups(id,application_id,environment,display_name,purpose,subject_mode,context_mode,status,version) VALUES($1,$2,'production','Account browser clients','Account sign-in','USER','ACCOUNT_ONLY','ACTIVE',1)")
            .bind(group).bind(application).execute(&db.pool).await?;
    }
    for (id, application, name, group) in [
        (client_one, app_one, "Account web", Some(group_one)),
        (client_sibling, app_one, "Account mobile", Some(group_one)),
        (client_ungrouped, app_one, "Unassigned client", None),
        (
            client_other_application,
            app_two,
            "Separate application",
            Some(group_two),
        ),
    ] {
        sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,post_logout_redirect_uris,status,version,policy_version,created_at,updated_at) VALUES($1,$1,$2,$3,'production','CONFIDENTIAL','WEB_BFF','USER','ACCOUNT_ONLY',ARRAY[]::text[],ARRAY['authorization_code','refresh_token'],'client_secret_basic',ARRAY['https://client.example.test/callback'],ARRAY[]::text[],'ENABLED',1,1,clock_timestamp(),clock_timestamp())")
            .bind(id).bind(name).bind(application).execute(&db.pool).await?;
        if let Some(group) = group {
            sqlx::query("INSERT INTO auth_consent_group_clients(group_id,client_id,application_id,environment,subject_mode,context_mode) VALUES($1,$2,$3,'production','USER','ACCOUNT_ONLY')")
                .bind(group).bind(id).bind(application).execute(&db.pool).await?;
        }
        sqlx::query("INSERT INTO auth_client_permissions(client_id,resource_id,scope_id,version) VALUES($1,$2,$3,1),($1,$2,$4,1)")
            .bind(id).bind(resource).bind(openid).bind(profile).execute(&db.pool).await?;
    }
    sqlx::query("UPDATE auth_consent_groups SET version=3 WHERE id=$1")
        .bind(group_one)
        .execute(&db.pool)
        .await?;
    sqlx::query("UPDATE auth_consent_groups SET version=2 WHERE id=$1")
        .bind(group_two)
        .execute(&db.pool)
        .await?;
    let owner = db.user;
    sqlx::query("INSERT INTO auth_consents(id,user_id,group_id,status,generation,group_version,version,authorized_at,revoked_at) VALUES($1,$2,$3,'ACTIVE',1,3,1,clock_timestamp(),NULL),($4,$5,$6,'ACTIVE',1,3,1,clock_timestamp(),NULL),($7,$2,$8,'ACTIVE',1,2,1,clock_timestamp(),NULL)")
        .bind(consent_one).bind(owner).bind(group_one).bind(consent_other_user).bind(other_user).bind(group_one).bind(consent_other_app).bind(group_two).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_consent_scopes(consent_id,resource_id,scope_id) VALUES($1,$3,$4),($2,$3,$4),($5,$3,$4)")
        .bind(consent_one).bind(consent_other_user).bind(resource).bind(openid).bind(consent_other_app).execute(&db.pool).await?;

    let request_pending = Uuid::now_v7();
    let request_authorized = Uuid::now_v7();
    let code = Uuid::now_v7();
    let grant = Uuid::now_v7();
    let family = Uuid::now_v7();
    let access = Uuid::now_v7();
    let refresh = Uuid::now_v7();
    sqlx::query("INSERT INTO auth_authorization_requests(id,client_id,user_id,status,version) VALUES($1,$3,$4,'PENDING',1),($2,$3,$4,'AUTHORIZED',1)")
        .bind(request_pending).bind(request_authorized).bind(client_one).bind(owner).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_authorization_codes(id,request_id,client_id,user_id,consent_id,consent_generation,code_digest,expires_at) VALUES($1,$2,$3,$4,$5,1,repeat('a',64),clock_timestamp()+interval '1 minute')")
        .bind(code).bind(request_authorized).bind(client_one).bind(owner).bind(consent_one).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_grants(id,client_id,user_id,consent_id,consent_generation) VALUES($1,$2,$3,$4,1)")
        .bind(grant).bind(client_one).bind(owner).bind(consent_one).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_refresh_families(id,grant_id) VALUES($1,$2)")
        .bind(family)
        .bind(grant)
        .execute(&db.pool)
        .await?;
    sqlx::query("INSERT INTO auth_access_tokens(id,grant_id) VALUES($1,$2)")
        .bind(access)
        .bind(grant)
        .execute(&db.pool)
        .await?;
    sqlx::query("INSERT INTO auth_refresh_tokens(id,family_id) VALUES($1,$2)")
        .bind(refresh)
        .bind(family)
        .execute(&db.pool)
        .await?;
    sqlx::query("INSERT INTO sso_sessions(id,user_id,token_hash,csrf_hash,account_version,authenticated_at,expires_at) VALUES($1,$2,$3,$4,1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')")
        .bind(session).bind(owner).bind(crate::util::hash::sha256_hex(&session_token)).bind(crate::util::hash::sha256_hex(&csrf)).execute(&db.pool).await?;

    Ok(Fixture {
        db,
        group_one,
        client_one,
        client_sibling,
        client_ungrouped,
        client_other_application,
        owner,
        other_user,
        resource,
        openid,
        profile,
        consent_one,
        consent_other_user,
        consent_other_app,
        session,
        session_token,
        csrf,
    })
}

fn proof(f: &Fixture) -> AccountSessionProof {
    AccountSessionProof {
        id: f.session,
        user_id: f.owner,
        account_version: 1,
        authenticated_at: Utc::now() - Duration::minutes(1),
        expires_at: Utc::now() + Duration::hours(1),
        username: "owned-audit-account".into(),
        real_name: "Owned audit account".into(),
    }
}

async fn browser_request(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    csrf: Option<&str>,
    body: Option<Value>,
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
    let body = if let Some(body) = body {
        request = request.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&body)?)
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(request.body(body)?).await?;
    ensure!(response
        .headers()
        .get("cache-control")
        .is_some_and(|v| v == "no-store"));
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let body = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, body))
}

fn session_cookie(f: &Fixture) -> String {
    format!("__Host-saas_sso={}", f.session_token)
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase07_consent_coverage_expansion_and_group_isolation_use_canonical_authority(
) -> Result<()> {
    let db = Database::create_phase07().await?;
    let f = match fixture(&db).await {
        Ok(fixture) => fixture,
        Err(error) => return db.finish(Err(error)).await,
    };
    let first = [ScopeGrant {
        resource_id: f.resource,
        scope_id: f.openid,
    }];
    let expanded = [
        ScopeGrant {
            resource_id: f.resource,
            scope_id: f.openid,
        },
        ScopeGrant {
            resource_id: f.resource,
            scope_id: f.profile,
        },
    ];
    let positive = async {
        let mut tx = f.db.pool.begin().await?;
        let covered = auth_consent::sufficient(&mut tx, &proof(&f), f.client_one, &first).await?;
        ensure!(matches!(covered, ConsentState::Sufficient { generation: 1, .. }), "existing complete consent was not reusable");
        tx.commit().await?;
        let mut tx = f.db.pool.begin().await?;
        let expanded_state = auth_consent::sufficient(&mut tx, &proof(&f), f.client_one, &expanded).await?;
        ensure!(expanded_state == ConsentState::Missing, "an added scope bypassed confirmation");
        tx.commit().await?;
        let mut tx = f.db.pool.begin().await?;
        let sibling = auth_consent::sufficient(&mut tx, &proof(&f), f.client_sibling, &first).await?;
        ensure!(matches!(sibling, ConsentState::Sufficient { .. }), "explicit group consent did not cover its sibling client");
        tx.commit().await?;
        let mut tx = f.db.pool.begin().await?;
        let outside = auth_consent::sufficient(&mut tx, &proof(&f), f.client_ungrouped, &first).await;
        ensure!(matches!(outside, Err(crate::error::AppError::Forbidden(_))), "ungrouped client inherited consent");
        tx.rollback().await?;
        let mut tx = f.db.pool.begin().await?;
        let other_application = auth_consent::sufficient(&mut tx, &proof(&f), f.client_other_application, &expanded).await?;
        ensure!(other_application == ConsentState::Missing, "another application inherited consent scopes");
        tx.commit().await?;
        let mut tx = f.db.pool.begin().await?;
        let approval = auth_consent::approve(
            &mut tx,
            &proof(&f),
            f.client_one,
            &expanded,
            ConsentAuditContext {
                ip: "127.0.0.1",
                user_agent: "phase07-test",
            },
        )
        .await?;
        ensure!(approval.expanded && !approval.restored && approval.generation == 1 && approval.version == 2,
            "explicit scope expansion did not update consent version without broadening prior grants");
        tx.commit().await?;
        let approved_scopes: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_consent_scopes WHERE consent_id=$1").bind(f.consent_one).fetch_one(&f.db.pool).await?;
        ensure!(approved_scopes == 2, "explicit scope expansion did not preserve the prior scope");

        let member_operation=Uuid::now_v7();
        let member_path=format!("/internal/identity/auth/consent-groups/{}/clients",f.group_one);
        let added=f.db.auth_admin_call(member_operation,"POST",&member_path,Some(json!({"clientId":f.client_ungrouped,"expectedGroupVersion":3}))).await?;
        ensure!(added.status==StatusCode::OK && added.body["version"]==4,
            "explicit new client membership did not advance the consent-group policy version");
        let mut tx=f.db.pool.begin().await?;
        let before_confirmation=auth_consent::sufficient(&mut tx,&proof(&f),f.client_ungrouped,&first).await?;
        ensure!(before_confirmation==ConsentState::Missing,
            "a newly joined client inherited an earlier user consent without confirmation");
        tx.commit().await?;
        let mut tx=f.db.pool.begin().await?;
        let reapproved=auth_consent::approve(&mut tx,&proof(&f),f.client_ungrouped,&first,ConsentAuditContext{ip:"127.0.0.1",user_agent:"phase07-test"}).await?;
        ensure!(!reapproved.expanded && reapproved.generation==1 && reapproved.version==3,
            "explicit user confirmation did not acknowledge the group membership revision");
        tx.commit().await?;
        let mut tx=f.db.pool.begin().await?;
        let after_confirmation=auth_consent::sufficient(&mut tx,&proof(&f),f.client_ungrouped,&first).await?;
        ensure!(matches!(after_confirmation,ConsentState::Sufficient{..}),
            "same-group client remained blocked after explicit user confirmation");
        tx.commit().await?;
        let approvals:i64=sqlx::query_scalar("SELECT count(*) FROM identity_audit_logs WHERE user_id=$1 AND action='AUTH_CONSENT_APPROVE'")
            .bind(f.owner).fetch_one(&f.db.pool).await?;
        ensure!(approvals==2,"scope expansion and group-version reapproval were not audited");

        let app = crate::sso::routes().with_state(f.db.state()?);
        let cookie = session_cookie(&f);
        let (status, list) = browser_request(&app,"GET","/api/sso/consents",&cookie,None,None,"https://auth.saas.test").await?;
        ensure!(status==StatusCode::OK && list["consents"].as_array().is_some_and(|items| items.len()==2),
            "self-service view did not stay account-scoped across active groups: status={status}, body={list}");
        ensure!(list["consents"].as_array().unwrap().iter().any(|item| item["clients"].as_array().is_some_and(|clients| clients.len()==3)),
            "user view omitted same-group client impact");
        Ok::<(), anyhow::Error>(())
    }.await;
    drop(f);
    db.finish(positive).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase07_revoke_delete_reauthorize_and_logout_keep_generation_fences() -> Result<()> {
    let db = Database::create_phase07().await?;
    let f = match fixture(&db).await {
        Ok(fixture) => fixture,
        Err(error) => return db.finish(Err(error)).await,
    };
    let app = crate::sso::routes().with_state(f.db.state()?);
    let cookie = session_cookie(&f);
    let result = async {
        let delete_active = Uuid::now_v7();
        let (status, _) = browser_request(&app,"DELETE",&format!("/api/sso/consents/{}",f.consent_one),&cookie,Some(&f.csrf),Some(json!({"operationId":delete_active,"expectedVersion":1})),"https://auth.saas.test").await?;
        ensure!(status==StatusCode::CONFLICT,"active authorization was deletable or returned an unexpected status: {status}");
        let no_csrf = Uuid::now_v7();
        let (status, _) = browser_request(&app,"POST",&format!("/api/sso/consents/{}/revoke",f.consent_one),&cookie,None,Some(json!({"operationId":no_csrf,"expectedVersion":1})),"https://auth.saas.test").await?;
        ensure!(status==StatusCode::FORBIDDEN,"consent revoke accepted a missing CSRF proof");
        let foreign_origin = Uuid::now_v7();
        let (status, _) = browser_request(&app,"POST",&format!("/api/sso/consents/{}/revoke",f.consent_one),&cookie,Some(&f.csrf),Some(json!({"operationId":foreign_origin,"expectedVersion":1})),"https://evil.test").await?;
        ensure!(status==StatusCode::FORBIDDEN,"consent revoke accepted a foreign origin");
        let other_user_op = Uuid::now_v7();
        let (status, _) = browser_request(&app,"POST",&format!("/api/sso/consents/{}/revoke",f.consent_other_user),&cookie,Some(&f.csrf),Some(json!({"operationId":other_user_op,"expectedVersion":1})),"https://auth.saas.test").await?;
        ensure!(status==StatusCode::NOT_FOUND,"one account could revoke another account's consent");

        let audit_failure_op=Uuid::now_v7();
        f.db.suppress("identity_audit_logs","INSERT").await?;
        let audit_failure=browser_request(&app,"POST",&format!("/api/sso/consents/{}/revoke",f.consent_one),&cookie,Some(&f.csrf),Some(json!({"operationId":audit_failure_op,"expectedVersion":1})),"https://auth.saas.test").await;
        f.db.unsuppress("identity_audit_logs").await?;
        let (status, _)=audit_failure?;
        ensure!(status==StatusCode::SERVICE_UNAVAILABLE,"missing consent audit did not fail closed");
        let unchanged:(String,i64,i64,i64)=sqlx::query_as("SELECT status,generation,version,(SELECT count(*) FROM auth_consent_revocation_outbox WHERE consent_id=$1) FROM auth_consents WHERE id=$1")
            .bind(f.consent_one).fetch_one(&f.db.pool).await?;
        ensure!(unchanged==("ACTIVE".into(),1,1,0),"failed audit left a consent mutation or revocation event committed");

        let revoke_op = Uuid::now_v7();
        let revoke_body = json!({"operationId":revoke_op,"expectedVersion":1});
        let (status, revoked) = browser_request(&app,"POST",&format!("/api/sso/consents/{}/revoke",f.consent_one),&cookie,Some(&f.csrf),Some(revoke_body.clone()),"https://auth.saas.test").await?;
        ensure!(status==StatusCode::OK && revoked["revoked"]==true && revoked["generation"]==2 && revoked["affectedClients"]==2,
            "group revoke did not advance the generation across explicit members");
        let (status, replayed) = browser_request(&app,"POST",&format!("/api/sso/consents/{}/revoke",f.consent_one),&cookie,Some(&f.csrf),Some(revoke_body),"https://auth.saas.test").await?;
        ensure!(status==StatusCode::OK && replayed==revoked,"repeated command did not recover its original result");
        let invalidated:(String,bool,bool,bool,bool,i64,i64) = sqlx::query_as(
            "SELECT c.status,g.revoked_at IS NOT NULL,at.revoked_at IS NOT NULL,rt.revoked_at IS NOT NULL,f.revoked_at IS NOT NULL, \
             (SELECT count(*) FROM auth_consent_revocation_outbox WHERE consent_id=$1), \
             (SELECT count(*) FROM auth_grants WHERE consent_id=$1 AND revoked_at IS NOT NULL) \
             FROM auth_consents c JOIN auth_grants g ON g.consent_id=c.id \
             JOIN auth_access_tokens at ON at.grant_id=g.id JOIN auth_refresh_families f ON f.grant_id=g.id \
             JOIN auth_refresh_tokens rt ON rt.family_id=f.id WHERE c.id=$1",
        ).bind(f.consent_one).fetch_one(&f.db.pool).await?;
        ensure!(invalidated==("REVOKED".into(),true,true,true,true,2,1),
            "grant, access/refresh tokens, or per-client outbox was not revoked atomically");
        let requests: (i64,i64)=sqlx::query_as("SELECT count(*) FILTER(WHERE status='DENIED' AND consumed_at IS NOT NULL),count(*) FILTER(WHERE status='DENIED') FROM auth_authorization_requests WHERE user_id=$1").bind(f.owner).fetch_one(&f.db.pool).await?;
        let codes: (i64,i64)=sqlx::query_as("SELECT count(*),count(*) FILTER(WHERE consumed_at IS NOT NULL) FROM auth_authorization_codes WHERE consent_id=$1").bind(f.consent_one).fetch_one(&f.db.pool).await?;
        ensure!(requests==(2,2) && codes==(1,1),"pending or issued authorization proofs survived group revoke");
        let other_group: String=sqlx::query_scalar("SELECT status FROM auth_consents WHERE id=$1").bind(f.consent_other_app).fetch_one(&f.db.pool).await?;
        let other_account: String=sqlx::query_scalar("SELECT status FROM auth_consents WHERE id=$1").bind(f.consent_other_user).fetch_one(&f.db.pool).await?;
        ensure!(other_group=="ACTIVE" && other_account=="ACTIVE","revocation escaped its account and application group");

        let stale_delete = Uuid::now_v7();
        let (status, _) = browser_request(&app,"DELETE",&format!("/api/sso/consents/{}",f.consent_one),&cookie,Some(&f.csrf),Some(json!({"operationId":stale_delete,"expectedVersion":1})),"https://auth.saas.test").await?;
        ensure!(status==StatusCode::CONFLICT,"a stale delete crossed the revoke version");
        let delete_op = Uuid::now_v7();
        let (status, deleted) = browser_request(&app,"DELETE",&format!("/api/sso/consents/{}",f.consent_one),&cookie,Some(&f.csrf),Some(json!({"operationId":delete_op,"expectedVersion":2})),"https://auth.saas.test").await?;
        ensure!(status==StatusCode::OK && deleted["deleted"]==true,"a matching version could not hide revoked consent");
        let tombstone:(String,i64,i64) = sqlx::query_as("SELECT status,version,(SELECT count(*) FROM auth_consent_scopes WHERE consent_id=$1) FROM auth_consents WHERE id=$1").bind(f.consent_one).fetch_one(&f.db.pool).await?;
        ensure!(tombstone==("REVOKED".into(),3,0),"display deletion removed the generation fence or retained display scopes");
        let grant_still_revoked: bool=sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM auth_grants WHERE consent_id=$1").bind(f.consent_one).fetch_one(&f.db.pool).await?;
        ensure!(grant_still_revoked,"deleting the display record restored a prior grant");

        let only_openid=[ScopeGrant{resource_id:f.resource,scope_id:f.openid}];
        f.db.suppress("identity_audit_logs","INSERT").await?;
        let mut tx=f.db.pool.begin().await?;
        let failed_approval=auth_consent::approve(&mut tx,&proof(&f),f.client_one,&only_openid,ConsentAuditContext{ip:"127.0.0.1",user_agent:"phase07-test"}).await;
        tx.rollback().await?;
        f.db.unsuppress("identity_audit_logs").await?;
        ensure!(matches!(failed_approval,Err(crate::error::AppError::Unavailable)),
            "consent approval continued without its audit record");
        let unchanged_after_audit_failure:(String,i64,i64,i64)=sqlx::query_as("SELECT status,generation,version,(SELECT count(*) FROM auth_consent_scopes WHERE consent_id=$1) FROM auth_consents WHERE id=$1")
            .bind(f.consent_one).fetch_one(&f.db.pool).await?;
        ensure!(unchanged_after_audit_failure==("REVOKED".into(),2,3,0),
            "failed approval audit committed a reauthorization or scopes");
        let mut tx=f.db.pool.begin().await?;
        let approval=auth_consent::approve(&mut tx,&proof(&f),f.client_one,&only_openid,ConsentAuditContext{ip:"127.0.0.1",user_agent:"phase07-test"}).await?;
        ensure!(approval.restored && !approval.expanded && approval.generation==2 && approval.version==4,
            "reauthorization did not use the new revocation generation");
        tx.commit().await?;
        let (status, _) = browser_request(&app,"DELETE",&format!("/api/sso/consents/{}",f.consent_one),&cookie,Some(&f.csrf),Some(json!({"operationId":Uuid::now_v7(),"expectedVersion":2})),"https://auth.saas.test").await?;
        ensure!(status==StatusCode::CONFLICT,"a stale deletion request crossed the new authorization generation");
        let consent:(String,i64,i64,Option<chrono::DateTime<Utc>>) = sqlx::query_as("SELECT status,generation,version,display_deleted_at FROM auth_consents WHERE id=$1").bind(f.consent_one).fetch_one(&f.db.pool).await?;
        ensure!(consent.0=="ACTIVE" && consent.1==2 && consent.2==4 && consent.3.is_none(),"reauthorization did not revive the display row in a new generation");

        let (status, _) = browser_request(&app,"DELETE",&format!("/api/sso/consents/{}",f.consent_one),&cookie,Some(&f.csrf),Some(json!({"operationId":Uuid::now_v7(),"expectedVersion":4})),"https://auth.saas.test").await?;
        ensure!(status==StatusCode::CONFLICT,"active consent became deletable after reauthorization");
        let (status, _) = browser_request(&app,"POST","/api/sso/logout",&cookie,Some(&f.csrf),None,"https://auth.saas.test").await?;
        ensure!(status==StatusCode::OK,"current account could not log out");
        let preserved:String=sqlx::query_scalar("SELECT status FROM auth_consents WHERE id=$1").bind(f.consent_one).fetch_one(&f.db.pool).await?;
        ensure!(preserved=="ACTIVE","logout removed or revoked persisted consent");
        let accounts:i64=sqlx::query_scalar("SELECT count(*) FROM users WHERE id=$1 OR id=$2").bind(f.owner).bind(f.other_user).fetch_one(&f.db.pool).await?;
        ensure!(accounts==2,"account fixtures were lost");
        Ok::<(),anyhow::Error>(())
    }.await;
    drop(f);
    db.finish(result).await
}
