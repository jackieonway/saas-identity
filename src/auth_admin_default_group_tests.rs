use super::*;
use anyhow::{ensure, Result};

#[tokio::test]
#[ignore = "requires isolated IDENTITY_PHASE20_TEST_DATABASE_URL and cluster id"]
async fn login_clients_receive_isolated_private_consent_groups() -> Result<()> {
    crate::test_support::isolated(|pool| async move {
        let application = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_applications(application_id,ownership,status,display_name,purpose,approved_scopes) VALUES($1,'FIRST_PARTY','APPROVED','Client fixture','ACCOUNT',ARRAY['openid'])")
            .bind(application).execute(&pool).await?;
        let mut input: ClientInput = serde_json::from_value(json!({
            "expectedVersion":null,"applicationId":application,"environment":"test",
            "displayName":"Login client","clientType":"CONFIDENTIAL","runtimeKind":"WEB_BFF",
            "subjectMode":"USER","contextMode":"ACCOUNT_ONLY","allowedMemberTypes":[],
            "grantTypes":["authorization_code"],"tokenEndpointAuthMethod":"client_secret_basic",
            "redirectUris":["https://client.example.test/callback"],"postLogoutRedirectUris":[],
            "status":"ENABLED","consentGroupId":null,
            "permissions":[{"resourceKey":"userinfo","scopes":["openid"]}]
        }))?;
        let mut tx = pool.begin().await?;
        let first = private_consent_group(&mut tx, &input, application, "ACCOUNT", None).await?;
        let second = private_consent_group(&mut tx, &input, application, "ACCOUNT", None).await?;
        ensure!(first.is_some() && second.is_some() && first != second, "login clients shared consent");
        ensure!(private_consent_group(&mut tx, &input, application, "ACCOUNT", first).await? == first,
            "existing consent association was replaced");
        input.subject_mode = "MACHINE".into();
        ensure!(private_consent_group(&mut tx, &input, application, "ACCOUNT", None).await?.is_none(),
            "machine client received user consent");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_consent_groups WHERE application_id=$1 AND environment='test' AND purpose='ACCOUNT' AND context_mode='ACCOUNT_ONLY' AND status='ACTIVE'")
            .bind(application).fetch_one(&mut *tx).await?;
        ensure!(count == 2, "consent boundaries or group count changed");
        tx.rollback().await?;
        let remains: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_consent_groups WHERE application_id=$1")
            .bind(application).fetch_one(&pool).await?;
        ensure!(remains == 0, "failed creation left consent data behind");
        Ok(())
    }).await
}
