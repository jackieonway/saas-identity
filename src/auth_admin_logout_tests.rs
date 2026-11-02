use super::*;
use anyhow::{ensure, Result};

fn input() -> ClientInput {
    serde_json::from_value(json!({"expectedVersion":1,"applicationId":Uuid::now_v7(),"environment":"test","displayName":"Owned logout registration",
        "clientType":"CONFIDENTIAL","runtimeKind":"WEB_BFF","subjectMode":"USER","contextMode":"ACCOUNT_ONLY","allowedMemberTypes":[],
        "grantTypes":["authorization_code"],"tokenEndpointAuthMethod":"client_secret_basic","redirectUris":["https://owned.example.test/callback"],
        "postLogoutRedirectUris":[],"status":"ENABLED","consentGroupId":null,"permissions":[{"resourceKey":"userinfo","scopes":["openid"]}]})).unwrap()
}
#[test]
fn logout_defaults_and_invalid_target_combinations_are_explicit() {
    let mut minimal = input();
    assert_eq!(minimal.logout_mode, "SHORT_SESSION_ONLINE_CHECK");
    assert!(validate_input(&mut minimal, false).is_ok());
    minimal.backchannel_target_id = Some(Uuid::now_v7().to_string());
    assert!(validate_input(&mut minimal, false).is_err());
    let mut back = input();
    back.logout_mode = "BACK_CHANNEL".into();
    back.backchannel_target_id = Some(Uuid::now_v7().to_string());
    back.backchannel_logout_uri = Some("https://owned.example.test/auth/backchannel-logout".into());
    assert!(validate_input(&mut back, false).is_ok());
    for raw in [
        "http://owned.example.test/logout",
        "https://owned.example.test/logout?token=bad",
        "https://user@owned.example.test/logout",
        "https://owned.example.test/logout#token",
    ] {
        let mut invalid = input();
        invalid.logout_mode = "BACK_CHANNEL".into();
        invalid.backchannel_target_id = back.backchannel_target_id.clone();
        invalid.backchannel_logout_uri = Some(raw.into());
        assert!(validate_input(&mut invalid, false).is_err());
    }
    back.expected_version = None;
    assert!(
        validate_input(&mut back, true).is_err(),
        "new clients need an existing owner-bound target before enabling back-channel"
    );
}

#[tokio::test]
#[ignore = "requires isolated IDENTITY_PHASE20_TEST_DATABASE_URL and cluster id"]
async fn owner_target_binding_and_expired_target_pure_stop_are_canonical() -> Result<()> {
    crate::test_support::isolated(|pool| async move {
        let app = Uuid::now_v7(); let client = Uuid::now_v7(); let target = Uuid::now_v7(); let resource = Uuid::now_v7(); let scope = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_applications(application_id,ownership,status,display_name,purpose,approved_scopes) VALUES($1,'FIRST_PARTY','APPROVED','Owned logout registration','Owned fixture account login',ARRAY['openid'])").bind(app).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,status) VALUES($1,$2,'Owned logout registration',$3,'test','CONFIDENTIAL','WEB_BFF','USER','ACCOUNT_ONLY',ARRAY[]::text[],ARRAY['authorization_code'],'client_secret_basic',ARRAY['https://owned.example.test/callback'],'ENABLED')").bind(client).bind(client.to_string()).bind(app).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status) VALUES($1,'userinfo','https://auth.saas.test/oauth/userinfo','ACTIVE')").bind(resource).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,'openid','ACTIVE')").bind(scope).bind(resource).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_client_permissions(client_id,resource_id,scope_id) VALUES($1,$2,$3)").bind(client).bind(resource).bind(scope).execute(&pool).await?;
        let mut value = input(); value.application_id=app.to_string(); value.logout_mode="BACK_CHANNEL".into(); value.backchannel_target_id=Some(target.to_string()); value.backchannel_logout_uri=Some("https://owned.example.test/auth/backchannel-logout".into());
        let mut tx=pool.begin().await?; ensure!(matches!(check_logout_target(&mut tx,client,&value).await,Err(AppError::Forbidden(_))),"arbitrary UUID self-certified a target"); tx.rollback().await?;
        sqlx::query("INSERT INTO auth_delivery_targets(id,purpose,status,client_id,url,allowed_ips,verified_reference,verified_at,expires_at) VALUES($1,'BACK_CHANNEL','ACTIVE',$2,'https://owned.example.test/auth/backchannel-logout',ARRAY['8.8.8.8'],$3,clock_timestamp(),clock_timestamp()+interval '1 hour')").bind(target).bind(client).bind(Uuid::now_v7()).execute(&pool).await?;
        let mut tx=pool.begin().await?; check_logout_target(&mut tx,client,&value).await?; tx.commit().await?;
        let mut tx=pool.begin().await?; ensure!(check_logout_target(&mut tx,Uuid::now_v7(),&value).await.is_err(),"target crossed its original client"); tx.rollback().await?;
        sqlx::query("UPDATE auth_clients SET logout_mode='BACK_CHANNEL',backchannel_logout_uri=$2,backchannel_target_id=$3 WHERE id=$1").bind(client).bind(&value.backchannel_logout_uri).bind(target).execute(&pool).await?;
        sqlx::query("UPDATE auth_delivery_targets SET verified_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1").bind(target).execute(&pool).await?;
        value.status="DISABLED".into(); let mut tx=pool.begin().await?;
        ensure!(is_stop_only(&mut tx,client,&value).await?,"expired target prevented pure authority removal");
        value.backchannel_logout_uri=Some("https://owned.example.test/changed".into()); ensure!(!is_stop_only(&mut tx,client,&value).await?,"disable authority changed its destination");
        tx.rollback().await?;
        sqlx::query("UPDATE auth_clients SET status='DISABLED',version=version+1,policy_version=policy_version+1,updated_at=clock_timestamp() WHERE id=$1").bind(client).execute(&pool).await?;
        let state:String=sqlx::query_scalar("SELECT status FROM auth_clients WHERE id=$1").bind(client).fetch_one(&pool).await?; ensure!(state=="DISABLED","canonical trigger rejected pure stop with expired target");
        Ok(())
    }).await
}
