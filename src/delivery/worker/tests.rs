use super::*;
use crate::test_support::{self, KeyFixture};
use anyhow::{ensure, Result as TestResult};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use sqlx::PgPool;

async fn revoke(pool: &PgPool, grant: Uuid) -> TestResult<()> {
    sqlx::query("UPDATE auth_grants SET revoked_at=clock_timestamp() WHERE id=$1")
        .bind(grant)
        .execute(pool)
        .await?;
    Ok(())
}
async fn job_state(pool: &PgPool, id: Uuid) -> TestResult<(String, i32, Option<String>)> {
    Ok(sqlx::query_as(
        "SELECT state,attempt_count,last_error_code FROM auth_delivery_jobs WHERE id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}
fn claims(keys: &KeyFixture, token: &str, audience: &str) -> TestResult<Value> {
    let header = jsonwebtoken::decode_header(token)?;
    ensure!(
        header.alg == Algorithm::RS256 && header.kid.as_deref() == Some("phase20-core"),
        "delivery signer changed algorithm or kid"
    );
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://auth.saas.test"]);
    validation.set_audience(&[audience]);
    Ok(jsonwebtoken::decode::<Value>(
        token,
        &DecodingKey::from_rsa_components(&keys.modulus, &keys.exponent)?,
        &validation,
    )?
    .claims)
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase20 PostgreSQL"]
async fn concurrent_leases_retry_budget_and_stale_completion_are_bounded() -> TestResult<()> {
    test_support::isolated(|pool|async move{
        let keys=KeyFixture::new()?;let state=keys.state(pool.clone(),true).await?;
        let(user,session)=test_support::account(&pool).await?;let rp=test_support::client(&pool).await?;
        test_support::backchannel(&pool,&rp).await?;
        for _ in 0..4 {let grant=test_support::grant(&pool,user,session,&rp,false).await?;revoke(&pool,grant.id).await?;}
        let(a,b)=tokio::join!(claim(&state),claim(&state));
        let mut jobs=a?;jobs.extend(b?);
        let ids:std::collections::HashSet<_>=jobs.iter().map(|job|job.id).collect();
        ensure!(jobs.len()==4&&ids.len()==4,"concurrent claims duplicated a durable lease");
        let original=jobs.pop().unwrap();
        sqlx::query("UPDATE auth_delivery_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1").bind(original.id).execute(&pool).await?;
        let mut recovered=claim(&state).await?;
        ensure!(recovered.len()==1,"expired original lease was not recovered once");
        let mut current=recovered.pop().unwrap();
        ensure!(current.id==original.id&&current.lease_id!=original.lease_id&&current.last_jti!=original.last_jti,"recovery reused a lease or logout jti");
        complete(&state,&original,Ok(())).await?;
        ensure!(job_state(&pool,current.id).await?.0=="LEASED","stale completion changed the recovered job");
        for attempt in 2..=8 {
            complete(&state,&current,Err(failed("DELIVERY_HTTP_RETRYABLE",true))).await?;
            let(status,count,code)=job_state(&pool,current.id).await?;
            ensure!(count==attempt&&code.as_deref()==Some("DELIVERY_HTTP_RETRYABLE"),"retry lost durable attempt/error metadata");
            if attempt==8 {ensure!(status=="TERMINAL","eighth failure was not terminal");break;}
            let delay:f64=sqlx::query_scalar("SELECT extract(epoch FROM available_at-clock_timestamp())::float8 FROM auth_delivery_jobs WHERE id=$1").bind(current.id).fetch_one(&pool).await?;
            let expected=(60_i32*2_i32.pow((attempt-1) as u32)).min(3600) as f64;
            ensure!(status=="PENDING"&&delay>expected-5.0&&delay<=expected,"retry backoff escaped bounded policy");
            sqlx::query("UPDATE auth_delivery_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(current.id).execute(&pool).await?;
            current=claim(&state).await?.pop().unwrap();
        }
        ensure!(claim(&state).await?.is_empty(),"a terminal job was leased again");
        for job in jobs {complete(&state,&job,Err(failed("DELIVERY_HTTP_REJECTED",false))).await?;ensure!(job_state(&pool,job.id).await?.0=="TERMINAL","permanent failure remained retryable");}
        let old=test_support::grant(&pool,user,session,&rp,false).await?;
        let target:Uuid=sqlx::query_scalar("SELECT backchannel_target_id FROM auth_clients WHERE id=$1").bind(rp.id).fetch_one(&pool).await?;
        let id=Uuid::now_v7();
        sqlx::query("INSERT INTO auth_delivery_jobs(id,kind,event_key,target_id,target_version,grant_id,created_at) VALUES($1,'LOGOUT',$2,$3,1,$4,clock_timestamp()-interval '25 hours')")
            .bind(id).bind(sha256_hex(&format!("old-{id}"))).bind(target).bind(old.id).execute(&pool).await?;
        ensure!(claim(&state).await?.is_empty()&&job_state(&pool,id).await?==(String::from("TERMINAL"),0,Some(String::from("DELIVERY_BUDGET_EXHAUSTED"))),"24-hour delivery budget was ignored");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase20 PostgreSQL"]
async fn logout_payload_is_signed_for_original_rp_and_target_generation() -> TestResult<()> {
    test_support::isolated(|pool| async move {
        let keys = KeyFixture::new()?;
        let state = keys.state(pool.clone(), true).await?;
        let (user, session) = test_support::account(&pool).await?;
        let rp = test_support::client(&pool).await?;
        let target = test_support::backchannel(&pool, &rp).await?;
        let grant = test_support::grant(&pool, user, session, &rp, false).await?;
        revoke(&pool, grant.id).await?;
        let job = claim(&state).await?.pop().unwrap();
        let prepared = prepare(&state, &job)
            .await
            .map_err(|error| anyhow::anyhow!(error.code))?;
        let body = String::from_utf8(prepared.body)?;
        let token = body.strip_prefix("logout_token=").unwrap();
        ensure!(
            prepared.content_type == "application/x-www-form-urlencoded"
                && prepared.proof.is_none(),
            "logout token transport contract changed"
        );
        ensure!(
            jsonwebtoken::decode_header(token)?.typ.as_deref() == Some("logout+jwt"),
            "logout JWT has the wrong type"
        );
        let payload = claims(&keys, token, &rp.id.to_string())?;
        ensure!(
            payload["sid"] == grant.sid
                && payload["sub"] == grant.sub
                && payload["jti"] == job.last_jti.unwrap().to_string(),
            "logout token adopted a different original RP source"
        );
        ensure!(
            payload["events"] == json!({"http://schemas.openid.net/event/backchannel-logout":{}})
                && payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap() == 120
                && payload.as_object().unwrap().len() == 8,
            "logout JWT events or strict lifetime changed"
        );
        ensure!(
            claims(&keys, token, &Uuid::now_v7().to_string()).is_err(),
            "a different RP audience accepted the signature"
        );
        let durable: String = sqlx::query_scalar(
            "SELECT row_to_json(job)::text FROM auth_delivery_jobs job WHERE id=$1",
        )
        .bind(job.id)
        .fetch_one(&pool)
        .await?;
        ensure!(
            !durable.contains(token)
                && !durable.contains(&grant.access)
                && !durable.contains(&grant.refresh)
                && !durable.contains(&grant.sid)
                && !durable.contains(&grant.sub),
            "job durably retained delivery or OAuth secret material"
        );
        sqlx::query("UPDATE auth_delivery_targets SET status='REVOKED' WHERE id=$1")
            .bind(target)
            .execute(&pool)
            .await?;
        let rejected = prepare(&state, &job).await.err().unwrap();
        ensure!(
            rejected.code == "DELIVERY_TARGET_REVOKED" && !rejected.retryable,
            "revoked owner destination was still dispatched"
        );
        complete(&state, &job, Err(rejected)).await?;
        ensure!(
            job_state(&pool, job.id).await?.0 == "TERMINAL",
            "revoked destination did not stop delivery"
        );
        let still_revoked: bool =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM auth_grants WHERE id=$1")
                .bind(grant.id)
                .fetch_one(&pool)
                .await?;
        ensure!(
            still_revoked,
            "delivery rejection undid authority revocation"
        );
        Ok(())
    })
    .await
}

async fn security_target(pool: &PgPool, user: Uuid) -> TestResult<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO auth_delivery_targets(id,purpose,status,recipient_ref,channel_purpose,url,allowed_ips,verified_reference,verified_at,expires_at) VALUES($1,'VERIFIED_CHANNEL','ACTIVE',$2,'SECURITY','https://collector.example.test:24446/security',ARRAY['127.0.0.1'],$3,clock_timestamp(),clock_timestamp()+interval '1 hour')")
        .bind(id).bind(user.to_string()).bind(Uuid::now_v7()).execute(pool).await?;
    Ok(id)
}
#[tokio::test]
#[ignore = "requires explicit isolated Phase20 PostgreSQL"]
async fn consent_and_security_sources_fanout_and_summarize_without_secret_queues() -> TestResult<()>
{
    test_support::isolated(|pool|async move{
        let keys=KeyFixture::new()?;let state=keys.state(pool.clone(),true).await?;
        let(user,session)=test_support::account(&pool).await?;let rp=test_support::client(&pool).await?;
        test_support::backchannel(&pool,&rp).await?;
        for _ in 0..2{let grant=test_support::grant(&pool,user,session,&rp,false).await?;revoke(&pool,grant.id).await?;}
        let event=Uuid::now_v7();
        sqlx::query("INSERT INTO auth_consent_revocation_outbox(id,consent_id,user_id,group_id,client_id,consent_generation,event_kind) SELECT $1,id,user_id,group_id,$2,generation,'CONSENT_REVOKED' FROM auth_consents WHERE user_id=$3 AND group_id=$4")
            .bind(event).bind(rp.id).bind(user).bind(rp.group).execute(&pool).await?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM auth_delivery_jobs WHERE consent_event_id=$1").bind(event).fetch_one(&pool).await?;
        ensure!(count==2,"consent source did not associate exact already-enqueued grant jobs");
        let mut jobs=claim(&state).await?;let success=jobs.pop().unwrap();complete(&state,&success,Ok(())).await?;
        ensure!(sqlx::query_scalar::<_,String>("SELECT delivery_state FROM auth_consent_revocation_outbox WHERE id=$1").bind(event).fetch_one(&pool).await?=="EXPANDED","partially delivered source was marked delivered");
        complete(&state,&jobs.pop().unwrap(),Err(failed("DELIVERY_HTTP_REJECTED",false))).await?;
        ensure!(sqlx::query_scalar::<_,String>("SELECT delivery_state FROM auth_consent_revocation_outbox WHERE id=$1").bind(event).fetch_one(&pool).await?=="TERMINAL","permanent fanout failure was not observable on source");
        let a=security_target(&pool,user).await?;let b=security_target(&pool,user).await?;
        let(other,_)=test_support::account(&pool).await?;security_target(&pool,other).await?;
        let security=Uuid::now_v7();sqlx::query("INSERT INTO auth_security_notification_outbox(id,user_id,event_kind) VALUES($1,$2,'MFA_ENABLED')").bind(security).bind(user).execute(&pool).await?;
        let jobs=claim(&state).await?;
        ensure!(jobs.len()==2&&jobs.iter().all(|job|[Some(a),Some(b)].contains(&job.target_id)),"security fanout crossed recipient boundaries");
        for job in jobs {
            let prepared=prepare(&state,&job).await.map_err(|error|anyhow::anyhow!(error.code))?;
            let proof=prepared.proof.as_deref().unwrap();let payload:Value=serde_json::from_slice(&prepared.body)?;
            let signed=claims(&keys,proof,&job.target_id.unwrap().to_string())?;
            ensure!(payload["recipientRef"]==user.to_string()&&payload["eventId"]==security.to_string()&&signed["bodySha256"]==sha256_hex(&String::from_utf8_lossy(&prepared.body)),"security signed proof did not bind exact recipient/event/body");
            complete(&state,&job,Ok(())).await?;
        }
        ensure!(sqlx::query_scalar::<_,String>("SELECT delivery_state FROM auth_security_notification_outbox WHERE id=$1").bind(security).fetch_one(&pool).await?=="DELIVERED","complete security fanout did not close source");
        let(unverified,_)=test_support::account(&pool).await?;let degraded=Uuid::now_v7();
        sqlx::query("INSERT INTO auth_security_notification_outbox(id,user_id,event_kind) VALUES($1,$2,'MFA_DISABLED')").bind(degraded).bind(unverified).execute(&pool).await?;
        ensure!(sqlx::query_scalar::<_,String>("SELECT delivery_state FROM auth_security_notification_outbox WHERE id=$1").bind(degraded).fetch_one(&pool).await?=="DEGRADED","unverified security recipient obtained a network destination");
        ensure!(claim(&state).await?.is_empty(),"finished or missing-channel source was leased");
        let no_jwt:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM auth_delivery_jobs WHERE row_to_json(auth_delivery_jobs)::text LIKE '%logout_token%')").fetch_one(&pool).await?;
        ensure!(no_jwt,"outbox became a reusable payload queue");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase20 PostgreSQL"]
async fn signing_lock_wait_rechecks_original_lease_before_material_leaves_database(
) -> TestResult<()> {
    test_support::isolated(|pool|async move{
        let keys=KeyFixture::new()?;let state=keys.state(pool.clone(),true).await?;
        let(user,session)=test_support::account(&pool).await?;let rp=test_support::client(&pool).await?;
        test_support::backchannel(&pool,&rp).await?;
        let grant=test_support::grant(&pool,user,session,&rp,false).await?;revoke(&pool,grant.id).await?;
        let job=claim(&state).await?.pop().unwrap();
        let mut lock=pool.begin().await?;sqlx::query("SELECT kid FROM auth_signing_keys WHERE active FOR UPDATE").execute(&mut *lock).await?;
        let task_state=state.clone();let id=job.id;let lease=job.lease_id;
        let pending=tokio::spawn(async move{prepare(&task_state,&job).await});
        // Observe the actual database wait rather than guessing a scheduling delay.
        let limit=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT kid,n,e FROM auth_signing_keys%')").fetch_one(&pool).await?;
            if waiting{break;}ensure!(tokio::time::Instant::now()<limit,"worker did not reach expected signing lock");tokio::task::yield_now().await;
        }
        sqlx::query("UPDATE auth_delivery_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1 AND lease_id=$2").bind(id).bind(lease).execute(&pool).await?;
        lock.commit().await?;
        let rejected=pending.await?.err().unwrap();
        ensure!(rejected.code=="DELIVERY_LEASE_EXPIRED","expired lease released signed notification after key wait");
        let rows:i64=sqlx::query_scalar("SELECT count(*) FROM auth_delivery_jobs WHERE id=$1 AND state='LEASED'").bind(id).fetch_one(&pool).await?;
        ensure!(rows==1,"prepare mutated outcome without current lease CAS");
        Ok(())
    }).await
}
