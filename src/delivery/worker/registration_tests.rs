use super::*;
use crate::test_support::{self, KeyFixture};
use anyhow::{ensure, Result as TestResult};
use sqlx::PgPool;

async fn waiting(pool: &PgPool, prefix: &str) -> TestResult<()> {
    let limit = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)")
            .bind(format!("{prefix}%")).fetch_one(pool).await?;
        if blocked {
            return Ok(());
        }
        ensure!(
            tokio::time::Instant::now() < limit,
            "expected registration/signing database lock was not observed"
        );
        tokio::task::yield_now().await;
    }
}
async fn queued(
    pool: &PgPool,
    rp: &test_support::Client,
    user: Uuid,
    session: Uuid,
) -> TestResult<Uuid> {
    let grant = test_support::grant(pool, user, session, rp, false).await?;
    sqlx::query("UPDATE auth_grants SET revoked_at=clock_timestamp() WHERE id=$1")
        .bind(grant.id)
        .execute(pool)
        .await?;
    Ok(grant.id)
}
#[tokio::test]
#[ignore = "requires explicit isolated Phase20 PostgreSQL"]
async fn client_cancellation_and_signing_are_serialized_before_dispatch_decision() -> TestResult<()>
{
    test_support::isolated(|pool|async move{
        let keys=KeyFixture::new()?;let state=keys.state(pool.clone(),true).await?;
        let(user,session)=test_support::account(&pool).await?;let rp=test_support::client(&pool).await?;
        test_support::backchannel(&pool,&rp).await?;queued(&pool,&rp,user,session).await?;
        let job=claim(&state).await?.pop().unwrap();
        let mut key=pool.begin().await?;sqlx::query("SELECT kid FROM auth_signing_keys WHERE active FOR UPDATE").execute(&mut *key).await?;
        let task_state=state.clone();let pending=tokio::spawn(async move{prepare(&task_state,&job).await});
        waiting(&pool,"SELECT kid,n,e FROM auth_signing_keys").await?;
        // A registry cancellation cannot commit while a prepared decision is
        // waiting on signing. It follows the exact same locked registration.
        let mut edit=pool.begin().await?;
        let blocked=sqlx::query("SELECT id FROM auth_clients WHERE id=$1 FOR UPDATE NOWAIT").bind(rp.id).execute(&mut *edit).await;
        ensure!(blocked.err().and_then(|error|error.as_database_error().and_then(|db|db.code()).map(|code|code.into_owned())).as_deref()==Some("55P03"),"signing wait did not retain its original client registration lock");
        edit.rollback().await?;key.commit().await?;
        ensure!(pending.await?.is_ok(),"unchanged registration could not prepare after signing lock release");

        let second=queued(&pool,&rp,user,session).await?;let job=claim(&state).await?.into_iter().find(|job|job.grant_id==Some(second)).unwrap();
        let mut edit=pool.begin().await?;
        sqlx::query("UPDATE auth_clients SET logout_mode='SHORT_SESSION_ONLINE_CHECK',backchannel_target_id=NULL,backchannel_logout_uri=NULL,policy_version=policy_version+1,version=version+1 WHERE id=$1").bind(rp.id).execute(&mut *edit).await?;
        let task_state=state.clone();let pending=tokio::spawn(async move{prepare(&task_state,&job).await});
        waiting(&pool,"SELECT application_id=").await?;edit.commit().await?;
        let rejected=pending.await?.err().unwrap();
        ensure!(rejected.code=="LOGOUT_TARGET_REGISTRATION_CHANGED"&&!rejected.retryable,"a cancellation committed before the dispatch decision still released the old destination JWT");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit isolated Phase20 PostgreSQL"]
async fn third_party_delivery_requires_current_approved_backchannel_admission() -> TestResult<()> {
    test_support::isolated(|pool|async move{
        let keys=KeyFixture::new()?;let state=keys.state(pool.clone(),true).await?;
        let(user,session)=test_support::account(&pool).await?;let rp=test_support::client(&pool).await?;
        test_support::backchannel(&pool,&rp).await?;
        sqlx::query("UPDATE auth_applications SET ownership='THIRD_PARTY',partner_id=$2,approved_scopes=ARRAY['openid','profile'] WHERE application_id=$1").bind(rp.application).bind(Uuid::now_v7()).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_application_admissions(application_id,environment,status,redirect_uris,scopes,requested_by,reviewed_by,contact_reference,domain_reference,review_reference,logout_mode,backchannel_logout_uri) VALUES($1,'test','APPROVED',ARRAY['https://rp.example.test/callback'],ARRAY['openid','profile'],$2,$3,$4,$5,$6,'BACK_CHANNEL','https://collector.example.test:24446/backchannel')")
            .bind(rp.application).bind(Uuid::now_v7()).bind(Uuid::now_v7()).bind(Uuid::now_v7()).bind(Uuid::now_v7()).bind(Uuid::now_v7()).execute(&pool).await?;
        queued(&pool,&rp,user,session).await?;let job=claim(&state).await?.pop().unwrap();
        ensure!(prepare(&state,&job).await.is_ok(),"exact current approved third-party backchannel registration was rejected");
        sqlx::query("UPDATE auth_application_admissions SET status='SUSPENDED',version=version+1 WHERE application_id=$1 AND environment='test'").bind(rp.application).execute(&pool).await?;
        let rejected=prepare(&state,&job).await.err().unwrap();
        ensure!(rejected.code=="LOGOUT_TARGET_REGISTRATION_CHANGED"&&!rejected.retryable,"suspended third-party admission retained a dispatch destination");
        sqlx::query("UPDATE auth_application_admissions SET status='APPROVED',logout_mode='SHORT_SESSION_ONLINE_CHECK',backchannel_logout_uri=NULL,version=version+1 WHERE application_id=$1 AND environment='test'").bind(rp.application).execute(&pool).await?;
        let rejected=prepare(&state,&job).await.err().unwrap();
        ensure!(rejected.code=="LOGOUT_TARGET_REGISTRATION_CHANGED"&&!rejected.retryable,"short-session third-party admission retained a backchannel destination");
        Ok(())
    }).await
}
