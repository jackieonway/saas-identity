//! Actual canonical schema/ACL + HTTP guard + real identity LOGIN component cases.
use super::{
    pg_fixture::{isolated, Database, ISSUER},
    *,
};
use anyhow::{ensure, Result};
use axum::http::StatusCode;
use chrono::Duration as Span;
use uuid::Uuid;

const PUBLISH: &str = "/internal/identity/auth/keys/publish";
const ACTIVATE: &str = "/internal/identity/auth/keys/activate";
async fn ok(db: &Database, path: &str, kid: &str) -> Result<Value> {
    let (status, value) = db.command("POST", path, &json!({"kid":kid})).await?;
    ensure!(
        status == StatusCode::OK,
        "key fixture command failed path={path} status={status} code={}",
        value["code"]
    );
    Ok(value)
}
async fn signed(db: &Database, exp: DateTime<Utc>) -> Result<String> {
    let mut tx = db.runtime.begin().await?;
    let token = sign(
        &db.state,
        &mut tx,
        json!({"iss":ISSUER,"sub":"owned-user","aud":"owned-rp","exp":exp.timestamp()}),
        exp,
    )
    .await?;
    tx.commit().await?;
    Ok(token)
}
fn verifies(token: &str, material: &Value) -> bool {
    let key = DecodingKey::from_rsa_components(
        material["n"].as_str().unwrap(),
        material["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&["owned-rp"]);
    jsonwebtoken::decode::<Value>(token, &key, &validation).is_ok()
}
async fn jwks(db: &Database) -> Result<Value> {
    let (status, value) = db.call("GET", "/oauth/jwks", &Value::Null, None).await?;
    ensure!(status == StatusCode::OK, "JWKS failed");
    Ok(value)
}

#[tokio::test]
#[ignore = "requires explicit owned IDENTITY_PHASE23_TEST_DATABASE_URL and cluster"]
async fn phase23_keys_publish_activate_replay_terminal_and_emergency_boundaries() -> Result<()> {
    isolated(|db|async move{
        ensure!(db.active().await?.is_empty(),"fresh fixture unexpectedly active");
        ensure!(db.command("POST",ACTIVATE,&json!({"kid":"phase23-b"})).await?.0==StatusCode::CONFLICT,"unpublished key activated");
        ok(&db,PUBLISH,"phase23-a").await?;ok(&db,ACTIVATE,"phase23-a").await?;
        let exp=DateTime::from_timestamp(Utc::now().timestamp(),0).unwrap()+Span::minutes(5);let old=signed(&db,exp).await?;
        ok(&db,PUBLISH,"phase23-b").await?;
        let public=jwks(&db).await?;
        ensure!(public["keys"].as_array().is_some_and(|v|v.len()==2)&&public["keys"].as_array().is_some_and(|rows|rows.iter().all(|key|key.as_object().is_some_and(|object|object.len()==6&&object.keys().all(|name|matches!(name.as_str(),"kty"|"use"|"alg"|"kid"|"n"|"e"))))),"prepublished JWKS missing keys or leaking material");
        let before=signed(&db,exp).await?;ensure!(jsonwebtoken::decode_header(&before)?.kid.as_deref()==Some("phase23-a"),"prepublish changed signer");
        let id=Uuid::now_v7();let body=json!({"kid":"phase23-b"});let digest=db.accept(id,"POST",ACTIVATE,&body).await?;
        let first=db.call("POST",ACTIVATE,&body,Some(id)).await?;ensure!(first.0==StatusCode::OK,"activation failed");
        sqlx::query("UPDATE platform_auth_command_intents SET accepted_at=clock_timestamp()-interval '2 minutes' WHERE id=$1").bind(id).execute(&db.owner).await?;
        let replay=db.call("POST",ACTIVATE,&body,Some(id)).await?;ensure!(replay==first,"completed operation failed exact replay after intent deadline");
        let mut other=db.clone();other.service=Uuid::now_v7();other.secret=crate::util::hash::sha256_hex(&Uuid::now_v7().to_string());
        sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,created_at) VALUES($1,$2,'KEY_ADMIN','ENABLED',clock_timestamp())").bind(other.service).bind(crate::util::hash::sha256_hex(&other.secret)).execute(&db.owner).await?;
        ensure!(other.request(&other.state,"POST",ACTIVATE,&body,Some(id),&digest,&other.secret,false).await?.0==StatusCode::CONFLICT,"different service recovered original receipt");
        ensure!(db.call("POST",PUBLISH,&body,Some(id)).await?.0==StatusCode::CONFLICT,"same operation accepted different path");
        let changed_body=json!({"kid":"phase23-a"});
        ensure!(db.call("POST",ACTIVATE,&changed_body,Some(id)).await?.0==StatusCode::CONFLICT,"original operation accepted changed body");
        let rotated=crate::util::hash::sha256_hex(&Uuid::now_v7().to_string());
        sqlx::query("UPDATE identity_service_clients SET secret_hash=$1 WHERE id=$2").bind(crate::util::hash::sha256_hex(&rotated)).bind(db.service).execute(&db.owner).await?;
        ensure!(db.request(&db.state,"POST",ACTIVATE,&body,Some(id),&digest,&rotated,false).await?.0==StatusCode::CONFLICT,"new service secret recovered old receipt");
        sqlx::query("UPDATE identity_service_clients SET secret_hash=$1 WHERE id=$2").bind(crate::util::hash::sha256_hex(&db.secret)).bind(db.service).execute(&db.owner).await?;
        let lookup=format!("/internal/identity/auth/key-operations/{id}");
        ensure!(db.request(&db.state,"GET",&lookup,&Value::Null,None,&digest,&db.secret,false).await?.0==StatusCode::BAD_REQUEST,"lookup without original digest did not fail with400");
        // Lookup uses the digest header, but does not need an operation header.
        let response=crate::router(db.state.clone()).oneshot(axum::http::Request::builder().uri(&lookup)
            .header("authorization",format!("Basic {}",base64::engine::general_purpose::STANDARD.encode(format!("{}:{}",db.service,db.secret))))
            .header("x-identity-operation-digest",&digest).body(axum::body::Body::empty())?).await?;
        ensure!(response.status()==StatusCode::OK,"original result lookup failed");
        ensure!(db.active().await?==["phase23-b"],"activation did not leave exactly B");
        let next=signed(&db,exp).await?;ensure!(jsonwebtoken::decode_header(&next)?.kid.as_deref()==Some("phase23-b")&&verifies(&old,&db.keys.material(0))&&verifies(&next,&db.keys.material(1)),"rotation broke existing A or new B cryptography");
        let mut tx=db.runtime.begin().await?;
        let logout=sign_typed(&db.state,&mut tx,json!({"exp":exp.timestamp()}),exp,"logout+jwt").await?;tx.commit().await?;
        let header=jsonwebtoken::decode_header(&logout)?;ensure!(header.kid.as_deref()==Some("phase23-b")&&header.typ.as_deref()==Some("logout+jwt"),"logout signer differs from ID signer");
        ensure!(db.command("POST",PUBLISH,&json!({"kid":"phase23-a"})).await?.0==StatusCode::CONFLICT,"new operation republished existing kid");
        for kid in ["phase23-a","phase23-b"]{ensure!(db.command("DELETE",&format!("/internal/identity/auth/keys/{kid}"),&Value::Null).await?.0==StatusCode::CONFLICT,"active or live verification window retired");}
        // C has never signed; its normal retirement needs no artificial clock change.
        ok(&db,PUBLISH,"phase23-c").await?;
        ensure!(db.command("DELETE","/internal/identity/auth/keys/phase23-c",&Value::Null).await?.0==StatusCode::OK,"unused nonactive key did not retire");
        ensure!(db.command("POST",ACTIVATE,&json!({"kid":"phase23-c"})).await?.0==StatusCode::CONFLICT,"retired kid reactivated");
        let(account,session)=crate::test_support::account(&db.owner).await?;let client=crate::test_support::client(&db.owner).await?;
        let grant=crate::test_support::grant(&db.owner,account,session,&client,false).await?;
        ensure!(db.command("POST","/internal/identity/auth/keys/phase23-a/revoke",&Value::Null).await?.0==StatusCode::OK,"emergency A revoke failed");
        ensure!(jwks(&db).await?["keys"].as_array().is_some_and(|v|v.len()==1&&v[0]["kid"]=="phase23-b"),"revoked/retired key retained in fresh JWKS");
        ensure!(verifies(&old,&db.keys.material(0)),"cached A public key unexpectedly stopped mathematical validation");
        let live:(bool,bool,bool)=sqlx::query_as("SELECT g.revoked_at IS NULL,t.revoked_at IS NULL,f.revoked_at IS NULL FROM auth_grants g JOIN auth_access_tokens t ON t.grant_id=g.id JOIN auth_refresh_families f ON f.grant_id=g.id WHERE g.id=$1").bind(grant.id).fetch_one(&db.owner).await?;
        ensure!(live==(true,true,true),"key-only revoke unexpectedly revoked opaque credentials");
        ensure!(db.command("POST",ACTIVATE,&json!({"kid":"phase23-a"})).await?.0==StatusCode::CONFLICT,"revoked kid reactivated");
        let changed=db.keys.material(1);let rewrite=sqlx::query("UPDATE auth_signing_keys SET n=$1 WHERE kid='phase23-a'").bind(changed["n"].as_str()).execute(&db.owner).await;
        ensure!(rewrite.is_err(),"immutable key material rewritten");
        ensure!(db.command("POST","/internal/identity/auth/keys/phase23-b/revoke",&Value::Null).await?.0==StatusCode::OK,"active emergency revoke failed");
        let mut tx=db.runtime.begin().await?;ensure!(sign(&db.state,&mut tx,json!({"exp":exp.timestamp()}),exp).await.is_err(),"no active key fell back");tx.rollback().await?;
        ensure!(jwks(&db).await?["keys"].as_array().is_some_and(Vec::is_empty),"all terminal keys still public");
        let receipts:i64=sqlx::query_scalar("SELECT count(*) FROM identity_auth_command_receipts WHERE operation_id=$1").bind(id).fetch_one(&db.owner).await?;ensure!(receipts==1,"replay created multiple receipts");Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit owned IDENTITY_PHASE23_TEST_DATABASE_URL and cluster"]
async fn phase23_keys_signer_highwater_transactions_serialize_activation_and_retirement(
) -> Result<()> {
    isolated(|db|async move{
        ok(&db,PUBLISH,"phase23-a").await?;ok(&db,ACTIVATE,"phase23-a").await?;ok(&db,PUBLISH,"phase23-b").await?;
        let now=DateTime::from_timestamp(Utc::now().timestamp(),0).unwrap();let long=now+Span::minutes(8);let short=now+Span::minutes(1);
        let mut tx=db.runtime.begin().await?;
        let token=sign(&db.state,&mut tx,json!({"exp":long.timestamp()}),long).await?;
        let worker=db.clone();let(channel,received)=tokio::sync::oneshot::channel();
        let task=tokio::spawn(async move{let mut second=worker.runtime.begin().await?;let pid:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *second).await?;let _=channel.send(pid);let token=sign(&worker.state,&mut second,json!({"exp":short.timestamp()}),short).await?;second.commit().await?;Ok::<_,anyhow::Error>(token)});
        db.wait_lock(received.await?).await?;tx.commit().await?;let second=task.await??;
        ensure!(jsonwebtoken::decode_header(&token)?.kid==jsonwebtoken::decode_header(&second)?.kid,"concurrent signing transactions diverged signer");
        let recorded:DateTime<Utc>=sqlx::query_scalar("SELECT last_signed_exp FROM auth_signing_keys WHERE kid='phase23-a'").fetch_one(&db.owner).await?;
        ensure!(recorded==long,"second lower expiration overwrote committed highwater");
        let mut rollback=db.runtime.begin().await?;sign(&db.state,&mut rollback,json!({"exp":(long+Span::days(1)).timestamp()}),long+Span::days(1)).await?;rollback.rollback().await?;
        ensure!(sqlx::query_scalar::<_,DateTime<Utc>>("SELECT last_signed_exp FROM auth_signing_keys WHERE kid='phase23-a'").fetch_one(&db.owner).await?==long,"rolled-back signature advanced highwater");
        let retire_exp=long+Span::seconds(5);let mut preparing=db.runtime.begin().await?;sign(&db.state,&mut preparing,json!({"exp":retire_exp.timestamp()}),retire_exp).await?;
        let retire_op=Uuid::now_v7();let retire_path="/internal/identity/auth/keys/phase23-a";db.accept(retire_op,"DELETE",retire_path,&Value::Null).await?;
        let worker=db.clone();let retiring=tokio::spawn(async move{worker.call("DELETE",retire_path,&Value::Null,Some(retire_op)).await});
        let role:String=sqlx::query_scalar("SELECT current_user::text").fetch_one(&db.runtime).await?;
        tokio::time::timeout(std::time::Duration::from_secs(3),async{loop{let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT active,(last_signed_exp%')").bind(&role).fetch_one(&db.owner).await?;if waiting{return Ok::<(),anyhow::Error>(());}tokio::task::yield_now().await;}}).await??;
        preparing.commit().await?;ensure!(retiring.await??.0==StatusCode::CONFLICT,"retirement waiting on signer did not return409");
        let recorded:DateTime<Utc>=sqlx::query_scalar("SELECT last_signed_exp FROM auth_signing_keys WHERE kid='phase23-a'").fetch_one(&db.owner).await?;ensure!(recorded==retire_exp,"concurrent retire missed last committed signer");
        let final_exp=long+Span::seconds(10);let mut in_flight=db.runtime.begin().await?;sign(&db.state,&mut in_flight,json!({"exp":final_exp.timestamp()}),final_exp).await?;
        let operation=Uuid::now_v7();let body=json!({"kid":"phase23-b"});db.accept(operation,"POST",ACTIVATE,&body).await?;
        let worker=db.clone();let task=tokio::spawn(async move{worker.call("POST",ACTIVATE,&body,Some(operation)).await});
        let role:String=sqlx::query_scalar("SELECT current_user::text").fetch_one(&db.runtime).await?;
        tokio::time::timeout(std::time::Duration::from_secs(3),async{loop{let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE 'UPDATE auth_signing_keys SET active=false%')").bind(&role).fetch_one(&db.owner).await?;if waiting{return Ok::<(),anyhow::Error>(());}tokio::task::yield_now().await;}}).await??;
        in_flight.commit().await?;ensure!(task.await??.0==StatusCode::OK,"activation failed after held signing commit");
        ensure!(db.active().await?==["phase23-b"],"concurrent activation lost single active key");
        let after:DateTime<Utc>=sqlx::query_scalar("SELECT last_signed_exp FROM auth_signing_keys WHERE kid='phase23-a'").fetch_one(&db.owner).await?;ensure!(after==final_exp,"activation missed final committed A expiration");
        ensure!(db.command("DELETE","/internal/identity/auth/keys/phase23-a",&Value::Null).await?.0==StatusCode::CONFLICT,"retirement ignored committed last A expiration");
        // A candidate instance missing B or holding a different B pair fails closed.
        let only_a=db.keys.write("only-a.json",&json!({"keys":[db.keys.material(0)]}))?;
        let mut config=(*db.state.config).clone();config.oidc_keys=Some(Arc::new(KeySet::load(only_a.to_str().unwrap())?));
        let state=crate::state::AppState::new(db.runtime.clone(),Arc::new(config));let mut tx=db.runtime.begin().await?;
        ensure!(sign(&state,&mut tx,json!({"exp":long.timestamp()}),long).await.is_err(),"missing active B private material fell back to A");tx.rollback().await?;
        let mut wrong=db.keys.material(0);wrong["kid"]=json!("phase23-b");let path=db.keys.write("wrong-b.json",&json!({"keys":[wrong]}))?;
        let mut config=(*db.state.config).clone();config.oidc_keys=Some(Arc::new(KeySet::load(path.to_str().unwrap())?));let state=crate::state::AppState::new(db.runtime.clone(),Arc::new(config));let mut tx=db.runtime.begin().await?;
        ensure!(sign(&state,&mut tx,json!({"exp":long.timestamp()}),long).await.is_err(),"mismatched B material signed");tx.rollback().await?;Ok(())
    }).await
}

use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires explicit owned IDENTITY_PHASE23_TEST_DATABASE_URL and cluster"]
async fn phase23_keys_permissions_intent_and_failed_audit_receipt_are_atomic() -> Result<()> {
    isolated(|db|async move{
        let body=json!({"kid":"phase23-c"});
        let actor_active:bool=sqlx::query_scalar("SELECT platform_identity_management_actor_active($1,$2,'system:oauth:keys',true,false)").bind(db.actor.user).bind(db.actor.session).fetch_one(&db.owner).await?;
        ensure!(actor_active,"canonical non-superadmin employee fixture inactive");
        // No authorization function or runtime grants are substituted.
        for (mutation,expected) in [
            (format!("UPDATE menus SET status='DISABLED' WHERE id='{}'",db.actor.menu),StatusCode::CONFLICT),
            (format!("UPDATE sso_sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE id='{}'",db.actor.sso),StatusCode::CONFLICT),
            (format!("UPDATE auth_grants SET revoked_at=clock_timestamp() WHERE id='{}'",db.actor.grant),StatusCode::CONFLICT),
            (format!("UPDATE identity_service_clients SET purpose='AUTH_ADMIN' WHERE id='{}'",db.service),StatusCode::FORBIDDEN),
            (format!("UPDATE identity_service_clients SET status='DISABLED' WHERE id='{}'",db.service),StatusCode::FORBIDDEN),
        ]{
            let mut fact=db.owner.begin().await?;sqlx::query(&mutation).execute(&mut *fact).await?;fact.commit().await?;
            let operation=Uuid::now_v7();db.accept(operation,"POST",PUBLISH,&body).await?;
            ensure!(db.call("POST",PUBLISH,&body,Some(operation)).await?.0==expected,"changed authorization fact returned wrong refusal");db.assert_no_commit(operation,"phase23-c").await?;
            sqlx::query("UPDATE menus SET status='ENABLED' WHERE id=$1").bind(db.actor.menu).execute(&db.owner).await?;
            sqlx::query("UPDATE sso_sessions SET mfa_verified_at=clock_timestamp() WHERE id=$1").bind(db.actor.sso).execute(&db.owner).await?;
            sqlx::query("UPDATE auth_grants SET revoked_at=NULL WHERE id=$1").bind(db.actor.grant).execute(&db.owner).await?;
            sqlx::query("UPDATE identity_service_clients SET purpose='KEY_ADMIN',status='ENABLED' WHERE id=$1").bind(db.service).execute(&db.owner).await?;
        }
        let operation=Uuid::now_v7();let digest=db.accept(operation,"POST",PUBLISH,&body).await?;
        for(secret,digest,cookie,expected)in[("a".repeat(64),digest.clone(),false,StatusCode::FORBIDDEN),(db.secret.clone(),"0".repeat(64),false,StatusCode::CONFLICT),(db.secret.clone(),digest.clone(),true,StatusCode::BAD_REQUEST)]{
            ensure!(db.request(&db.state,"POST",PUBLISH,&body,Some(operation),&digest,&secret,cookie).await?.0==expected,"wrong secret/digest/cookie returned wrong refusal");db.assert_no_commit(operation,"phase23-c").await?;
        }
        sqlx::query("UPDATE platform_auth_command_intents SET accepted_at=clock_timestamp()-interval '61 seconds' WHERE id=$1").bind(operation).execute(&db.owner).await?;
        ensure!(db.call("POST",PUBLISH,&body,Some(operation)).await?.0==StatusCode::CONFLICT,"expired intent accepted");db.assert_no_commit(operation,"phase23-c").await?;
        for table in ["identity_audit_logs","identity_auth_command_receipts"]{
            sqlx::query("CREATE FUNCTION public.phase23_reject_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'phase23 scoped fault'; END $$").execute(&db.owner).await?;
            sqlx::query(&format!("CREATE TRIGGER phase23_reject BEFORE INSERT ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.phase23_reject_write()")).execute(&db.owner).await?;
            let operation=Uuid::now_v7();db.accept(operation,"POST",PUBLISH,&body).await?;
            let expected=if table=="identity_audit_logs"{StatusCode::SERVICE_UNAVAILABLE}else{StatusCode::INTERNAL_SERVER_ERROR}; ensure!(db.call("POST",PUBLISH,&body,Some(operation)).await?.0==expected,"audit/receipt failure returned wrong refusal");db.assert_no_commit(operation,"phase23-c").await?;
            sqlx::query(&format!("DROP TRIGGER phase23_reject ON public.{table}")).execute(&db.owner).await?;
            sqlx::query("DROP FUNCTION public.phase23_reject_write()").execute(&db.owner).await?;
        }
        // Real lifecycle lock wait crosses a near-expired accepted intent.
        let operation=Uuid::now_v7();db.accept(operation,"POST",PUBLISH,&body).await?;
        sqlx::query("UPDATE platform_auth_command_intents SET accepted_at=clock_timestamp()-interval '59 seconds' WHERE id=$1").bind(operation).execute(&db.owner).await?;
        let mut barrier=db.owner.begin().await?;sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('oidc-key-lifecycle-v1',0))").execute(&mut *barrier).await?;
        let worker=db.clone();let task=tokio::spawn(async move{worker.call("POST",PUBLISH,&body,Some(operation)).await});
        let role:String=sqlx::query_scalar("SELECT current_user::text").fetch_one(&db.runtime).await?;
        tokio::time::timeout(std::time::Duration::from_secs(3),async{loop{let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%oidc-key-lifecycle-v1%')").bind(&role).fetch_one(&db.owner).await?;if waiting{return Ok::<(),anyhow::Error>(());}tokio::task::yield_now().await;}}).await??;
        let expired:bool=sqlx::query_scalar("SELECT clock_timestamp()>accepted_at+interval '60 seconds' FROM platform_auth_command_intents WHERE id=$1").bind(operation).fetch_one(&db.owner).await?;
        if !expired{tokio::time::sleep(std::time::Duration::from_millis(1100)).await;}
        let expired:bool=sqlx::query_scalar("SELECT clock_timestamp()>accepted_at+interval '60 seconds' FROM platform_auth_command_intents WHERE id=$1").bind(operation).fetch_one(&db.owner).await?;ensure!(expired,"clock did not cross accepted-intent deadline");barrier.commit().await?;ensure!(task.await??.0==StatusCode::CONFLICT,"lock-expired command did not return409");db.assert_no_commit(operation,"phase23-c").await?;
        let privilege:(bool,bool,bool)=sqlx::query_as("SELECT rolsuper,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user").fetch_one(&db.runtime).await?;ensure!(privilege==(false,false,false),"runtime has elevated privileges");
        ensure!(sqlx::query("CREATE TABLE public.phase23_forbidden(id integer)").execute(&db.runtime).await.is_err(),"runtime gained schema DDL");
        ensure!(sqlx::query("SELECT * FROM memberships").execute(&db.runtime).await.is_err(),"runtime gained raw memberships");
        ok(&db,PUBLISH,"phase23-c").await?;Ok(())
    }).await
}

async fn sign(
    state: &crate::state::AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claims: Value,
    exp: DateTime<Utc>,
) -> Result<String> {
    super::sign(state, tx, claims, exp)
        .await
        .map_err(|_| anyhow::anyhow!("component signing failed"))
}

#[tokio::test]
#[ignore = "requires explicit owned IDENTITY_PHASE23_TEST_DATABASE_URL and cluster"]
async fn phase23_consent_commands_keep_immutable_receipts_under_runtime_login() -> Result<()> {
    isolated(|db| async move {
        assert_consent_receipt_privileges(&db.runtime).await?;
        let row_lock = sqlx::query(
            "SELECT operation_id FROM public.identity_consent_command_receipts WHERE false FOR UPDATE",
        )
        .execute(&db.runtime)
        .await;
        ensure!(
            row_lock.err().and_then(|error| error
                .as_database_error()
                .and_then(|database| database.code())
                .map(|code| code.into_owned()))
                .as_deref()
                == Some("42501"),
            "immutable receipt unexpectedly allowed runtime row locking"
        );

        // Explicit account-cookie facts isolate the command/ACL regression;
        // this fixture does not claim a real password or TOTP login.
        let cookie = crate::util::hash::sha256_hex(&Uuid::now_v7().to_string());
        let csrf = crate::util::hash::sha256_hex(&format!("sso-session-csrf-v1:{cookie}"));
        sqlx::query("UPDATE public.sso_sessions SET token_hash=$2,csrf_hash=$3 WHERE id=$1")
            .bind(db.actor.sso)
            .bind(crate::util::hash::sha256_hex(&cookie))
            .bind(crate::util::hash::sha256_hex(&csrf))
            .execute(&db.owner)
            .await?;
        let (consent, version): (Uuid, i64) = sqlx::query_as(
            "SELECT c.id,c.version FROM public.auth_consents c \
             JOIN public.auth_grants g ON g.consent_id=c.id WHERE g.id=$1 AND c.status='ACTIVE'",
        )
        .bind(db.actor.grant)
        .fetch_one(&db.owner)
        .await?;
        let operation = Uuid::now_v7();
        let path = format!("/api/sso/consents/{consent}/revoke");
        let body = json!({"operationId":operation,"expectedVersion":version});
        let first = consent_browser_command(&db, &cookie, &csrf, "POST", &path, &body).await?;
        ensure!(
            first.0 == StatusCode::OK && first.1["revoked"] == true
                && first.1["version"] == version + 1,
            "limited LOGIN could not revoke its consent"
        );
        let (left, right) = tokio::join!(
            consent_browser_command(&db, &cookie, &csrf, "POST", &path, &body),
            consent_browser_command(&db, &cookie, &csrf, "POST", &path, &body),
        );
        ensure!(left? == first && right? == first, "replay changed the original result");
        let (receipt_count, original_result): (i64, Value) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM public.identity_consent_command_receipts WHERE operation_id=$1), \
             result_json FROM public.identity_consent_command_receipts WHERE operation_id=$1",
        )
        .bind(operation)
        .fetch_one(&db.owner)
        .await?;
        ensure!(receipt_count == 1 && original_result == first.1,
            "replay replaced or duplicated the immutable receipt");
        let grant_revoked: bool = sqlx::query_scalar(
            "SELECT revoked_at IS NOT NULL FROM public.auth_grants WHERE id=$1",
        )
        .bind(db.actor.grant)
        .fetch_one(&db.owner)
        .await?;
        ensure!(grant_revoked, "successful revoke left the original grant active");

        let display_path = format!("/api/sso/consents/{consent}");
        let rebound = json!({"operationId":operation,"expectedVersion":version + 1});
        ensure!(
            consent_browser_command(&db, &cookie, &csrf, "DELETE", &display_path, &rebound)
                .await?.0 == StatusCode::CONFLICT,
            "the original operation was rebound to a display deletion"
        );
        let display_operation = Uuid::now_v7();
        let display_body = json!({"operationId":display_operation,"expectedVersion":version + 1});
        let deleted = consent_browser_command(
            &db, &cookie, &csrf, "DELETE", &display_path, &display_body,
        ).await?;
        ensure!(deleted.0 == StatusCode::OK && deleted.1["deleted"] == true
            && deleted.1["version"] == version + 2,
            "limited LOGIN could not delete the revoked consent display");
        ensure!(consent_browser_command(&db, &cookie, &csrf, "DELETE", &display_path, &display_body)
            .await? == deleted, "display deletion did not replay its immutable result");
        let display_hidden: bool = sqlx::query_scalar(
            "SELECT status='REVOKED' AND display_deleted_at IS NOT NULL AND \
             NOT EXISTS(SELECT 1 FROM public.auth_consent_scopes s WHERE s.consent_id=c.id) \
             FROM public.auth_consents c WHERE c.id=$1",
        )
        .bind(consent)
        .fetch_one(&db.owner)
        .await?;
        ensure!(display_hidden, "display deletion did not preserve the revoked tombstone");
        assert_consent_receipt_privileges(&db.runtime).await?;
        Ok(())
    }).await
}

async fn assert_consent_receipt_privileges(pool: &sqlx::PgPool) -> Result<()> {
    let limited: bool = sqlx::query_scalar(
        "SELECT current_user=session_user AND rolcanlogin AND NOT rolsuper AND NOT rolinherit \
         AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolbypassrls \
         AND has_table_privilege(current_user,'public.identity_consent_command_receipts','SELECT') \
         AND has_table_privilege(current_user,'public.identity_consent_command_receipts','INSERT') \
         AND NOT has_any_column_privilege(current_user,'public.identity_consent_command_receipts','UPDATE') \
         AND NOT has_table_privilege(current_user,'public.identity_consent_command_receipts','DELETE,TRUNCATE,TRIGGER') \
         FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(pool)
    .await?;
    ensure!(
        limited,
        "consent commands must use the actual restricted LOGIN role"
    );
    Ok(())
}

async fn consent_browser_command(
    db: &Database,
    cookie: &str,
    csrf: &str,
    method: &str,
    path: &str,
    body: &Value,
) -> Result<(StatusCode, Value)> {
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request},
    };
    let response = crate::router(db.state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::ORIGIN, ISSUER)
                .header(header::COOKIE, format!("__Host-saas_sso={cookie}"))
                .header("x-csrf-token", csrf)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(body)?))?,
        )
        .await?;
    ensure!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .is_some_and(|value| value == "no-store"),
        "consent result lost no-store"
    );
    let status = response.status();
    let body = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&body)?))
}
async fn sign_typed(
    state: &crate::state::AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claims: Value,
    exp: DateTime<Utc>,
    typ: &'static str,
) -> Result<String> {
    super::sign_typed(state, tx, claims, exp, typ)
        .await
        .map_err(|_| anyhow::anyhow!("component typed signing failed"))
}
