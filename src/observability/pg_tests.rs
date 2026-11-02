use super::tests::{fixture_state, scrape};
use crate::test_support;
use anyhow::{ensure, Result};
use axum::http::StatusCode;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE22_TEST_DATABASE_URL/CLUSTER_ID"]
async fn canonical_delivery_and_degraded_source_metrics_are_read_only_and_use_one_connection(
) -> Result<()> {
    test_support::isolated_phase22(|pool| async move {
        let (user, session) = test_support::account(&pool).await?;
        let rp = test_support::client(&pool).await?;
        test_support::backchannel(&pool, &rp).await?;
        let mut jobs = Vec::new();
        for _ in 0..3 {
            let grant = test_support::grant(&pool, user, session, &rp, false).await?;
            sqlx::query("UPDATE auth_grants SET revoked_at=clock_timestamp() WHERE id=$1").bind(grant.id).execute(&pool).await?;
            let id: Uuid = sqlx::query_scalar("SELECT id FROM auth_delivery_jobs WHERE grant_id=$1").bind(grant.id).fetch_one(&pool).await?;
            jobs.push(id);
        }
        sqlx::query("UPDATE auth_delivery_jobs SET state='LEASED',lease_id=$2,lease_until=clock_timestamp()-interval '1 second',attempt_count=1 WHERE id=$1")
            .bind(jobs[1]).bind(Uuid::now_v7()).execute(&pool).await?;
        sqlx::query("UPDATE auth_delivery_jobs SET state='TERMINAL',terminal_at=clock_timestamp(),last_error_code='DELIVERY_HTTP_REJECTED' WHERE id=$1")
            .bind(jobs[2]).execute(&pool).await?;
        let short = test_support::client(&pool).await?;
        let grant = test_support::grant(&pool, user, session, &short, false).await?;
        sqlx::query("UPDATE auth_grants SET revoked_at=clock_timestamp() WHERE id=$1").bind(grant.id).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_security_notification_outbox(id,user_id,event_kind) VALUES($1,$2,'MFA_ENABLED')")
            .bind(Uuid::now_v7()).bind(user).execute(&pool).await?;
        let snapshot: String = sqlx::query_scalar("SELECT jsonb_build_object('jobs',(SELECT jsonb_agg(to_jsonb(job) ORDER BY id) FROM auth_delivery_jobs job),'security',(SELECT jsonb_agg(to_jsonb(event) ORDER BY id) FROM auth_security_notification_outbox event))::text")
            .fetch_one(&pool).await?;
        // A separate pool of size one proves collection does not reserve a
        // second connection for its aggregate queries.
        let single = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(pool.connect_options().as_ref().clone()).await?;
        let state = fixture_state(single.clone(), true);
        let settings_before: (String, String, String) = sqlx::query_as("SELECT current_setting('statement_timeout'),current_setting('lock_timeout'),current_setting('transaction_read_only')")
            .fetch_one(&single).await?;
        let (status, output) = scrape(&state).await;
        ensure!(status == StatusCode::OK && output.contains("identity_database_up 1") && output.contains("identity_delivery_observation_up 1"), "canonical metrics observation failed");
        for status in ["PENDING", "LEASED", "TERMINAL", "DEGRADED"] {
            ensure!(output.contains(&format!("identity_delivery_jobs{{kind=\"LOGOUT\",state=\"{status}\"}} 1")), "delivery metric lost a canonical state");
        }
        ensure!(output.contains("identity_delivery_expired_leases{kind=\"LOGOUT\"} 1"), "expired lease was hidden");
        ensure!(output.contains("identity_delivery_source_events{kind=\"SECURITY\",state=\"DEGRADED\"} 1"), "source without a delivery target was reported healthy");
        let after: String = sqlx::query_scalar("SELECT jsonb_build_object('jobs',(SELECT jsonb_agg(to_jsonb(job) ORDER BY id) FROM auth_delivery_jobs job),'security',(SELECT jsonb_agg(to_jsonb(event) ORDER BY id) FROM auth_security_notification_outbox event))::text")
            .fetch_one(&pool).await?;
        ensure!(snapshot == after, "scraping mutated delivery source or lease authority");
        let settings_after: (String, String, String) = sqlx::query_as("SELECT current_setting('statement_timeout'),current_setting('lock_timeout'),current_setting('transaction_read_only')")
            .fetch_one(&single).await?;
        ensure!(settings_before == settings_after, "observation left connection settings behind");
        single.close().await;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE22_TEST_DATABASE_URL/CLUSTER_ID"]
async fn delivery_query_failure_and_pool_saturation_are_visible_with_a_bounded_scrape() -> Result<()>
{
    test_support::isolated_phase22(|pool| async move {
        let state = fixture_state(pool.clone(), true);
        let mut lock = pool.begin().await?;
        sqlx::query("LOCK TABLE auth_delivery_jobs IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await?;
        let started = std::time::Instant::now();
        let (_, failed) = scrape(&state).await;
        ensure!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "blocked delivery metrics escaped observation deadline"
        );
        ensure!(
            failed.contains("identity_database_up 1")
                && failed.contains("identity_delivery_observation_up 0")
                && !failed.contains("identity_delivery_jobs{"),
            "a failed delivery query fabricated a healthy zero backlog"
        );
        lock.rollback().await?;
        let single = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await?;
        let held = single.acquire().await?;
        let state = fixture_state(single.clone(), true);
        let started = std::time::Instant::now();
        let (_, failed) = scrape(&state).await;
        ensure!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "pool saturation escaped the scrape deadline"
        );
        ensure!(
            failed.contains("identity_database_up 0")
                && failed.contains("identity_delivery_observation_up 0"),
            "pool saturation was disguised as an empty queue"
        );
        drop(held);
        single.close().await;
        Ok(())
    })
    .await
}
