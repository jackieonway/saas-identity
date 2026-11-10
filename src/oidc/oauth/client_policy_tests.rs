use super::*;
use crate::test_support::{self, KeyFixture};
use anyhow::{ensure, Context, Result as TestResult};

#[tokio::test]
#[ignore = "requires isolated IDENTITY_PHASE20_TEST_DATABASE_URL and cluster id"]
async fn automatic_consent_obeys_policy_prompt_scope_and_revocation() -> TestResult<()> {
    test_support::isolated(|pool| async move {
        let keys = KeyFixture::new()?;
        let state = keys.state(pool.clone(), false).await?;
        let (user, session) = test_support::account(&pool).await?;
        let registration = test_support::client(&pool).await?;
        let (auth_time, expires): (DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
            "SELECT authenticated_at,expires_at FROM sso_sessions WHERE id=$1")
            .bind(session).fetch_one(&pool).await?;
        let proof = AccountSessionProof { id: session, user_id: user, account_version: 3,
            authenticated_at: auth_time, expires_at: expires, username: "owned-policy-account".into(), real_name: "".into() };
        let mut client = client_by_internal_id(&state, registration.id).await.map_err(|_| anyhow::anyhow!("client lookup failed"))?;
        let all = scopes_by_ids(&state, &registration.scopes).await.map_err(|_| anyhow::anyhow!("scope lookup failed"))?;
        let ordinary: Vec<_> = all.iter().filter(|scope| scope.scope_name != "offline_access").cloned().collect();
        let mut tx = pool.begin().await?;
        ensure!(matches!(consent_coverage(&mut tx,&proof,&client,&ordinary,&HeaderMap::new(),false).await,
            Ok(ConsentState::Missing)), "manual client approved consent automatically");
        tx.commit().await?;
        sqlx::query("UPDATE auth_clients SET auto_authorize=true WHERE id=$1").bind(client.id).execute(&pool).await?;
        client.auto_authorize=true;
        for forced in [true, false] {
            let mut tx=pool.begin().await?;
            let scopes=if forced { &ordinary } else { &all };
            ensure!(matches!(consent_coverage(&mut tx,&proof,&client,scopes,&HeaderMap::new(),forced).await,
                Ok(ConsentState::Missing)), "forced confirmation or offline consent was skipped");
            tx.commit().await?;
        }
        client.ownership="THIRD_PARTY".into();
        let mut tx=pool.begin().await?;
        ensure!(matches!(consent_coverage(&mut tx,&proof,&client,&ordinary,&HeaderMap::new(),false).await,
            Ok(ConsentState::Missing)), "third party was auto approved");
        tx.commit().await?;
        client.ownership="FIRST_PARTY".into();
        let mut tx=pool.begin().await?;
        let approved=consent_coverage(&mut tx,&proof,&client,&ordinary,&HeaderMap::new(),false).await
            .map_err(|_| anyhow::anyhow!("trusted auto approval failed"))?;
        ensure!(matches!(approved,ConsentState::Sufficient { .. }), "trusted client still required consent");
        tx.commit().await?;
        let audits:i64=sqlx::query_scalar("SELECT count(*) FROM identity_audit_logs WHERE action='AUTH_CONSENT_AUTO_APPROVE'").fetch_one(&pool).await?;
        ensure!(audits==1,"automatic approval audit missing");
        sqlx::query("UPDATE auth_consents SET status='REVOKED',revoked_at=clock_timestamp(),generation=generation+1,version=version+1 WHERE user_id=$1 AND group_id=$2")
            .bind(user).bind(registration.group).execute(&pool).await?;
        let mut tx=pool.begin().await?;
        ensure!(matches!(consent_coverage(&mut tx,&proof,&client,&ordinary,&HeaderMap::new(),false).await,
            Ok(ConsentState::Missing)), "explicit revocation was silently restored");
        tx.commit().await?;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires isolated IDENTITY_PHASE20_TEST_DATABASE_URL and cluster id"]
async fn custom_access_and_refresh_limits_are_used_by_public_token_exchange() -> TestResult<()> {
    test_support::isolated(|pool| async move {
        let keys=KeyFixture::new()?;
        let state=keys.state(pool.clone(),false).await?;
        let (user,session)=test_support::account(&pool).await?;
        let client=test_support::client(&pool).await?;
        sqlx::query("UPDATE auth_clients SET access_token_ttl_seconds=60,refresh_token_ttl_seconds=300 WHERE id=$1")
            .bind(client.id).execute(&pool).await?;
        let cookie=super::phase22_tests::browser_cookie(&pool,session).await?;
        let code=super::phase22_tests::authorized_code(&state,&client,&cookie).await?;
        let headers=HeaderMap::from_iter([(header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}",STANDARD.encode(format!("{}:{}",client.id,client.secret))))?)]);
        let values: BTreeMap<String,String>=BTreeMap::from([
            ("grant_type".into(),"authorization_code".into()),("code".into(),code),
            ("redirect_uri".into(),"https://rp.example.test/callback".into()),
            ("code_verifier".into(),super::phase22_tests::VERIFIER.into())]);
        let mut form=reqwest::Url::parse("https://form.invalid")?;
        form.query_pairs_mut().extend_pairs(&values);
        let Json(tokens)=token(axum::extract::State(state.clone()),headers.clone(),RawQuery(None),RawForm(form.query().context("form")?.as_bytes().to_vec().into())).await.map_err(|_| anyhow::anyhow!("public token exchange failed"))?;
        let ttl=tokens["expires_in"].as_i64().context("access ttl")?;
        ensure!(ttl>0 && ttl<=60,"custom access ttl ignored");
        let refresh=tokens["refresh_token"].as_str().context("refresh token")?.to_owned();
        let values=BTreeMap::from([("grant_type".into(),"refresh_token".into()),("refresh_token".into(),refresh.clone())]);
        let Json(next)=refresh_token(&state,&headers,&values).await.map_err(|_| anyhow::anyhow!("public refresh failed"))?;
        ensure!(next["refresh_token"].as_str().is_some_and(|token|token!=refresh),"refresh did not rotate");
        ensure!(next["expires_in"].as_i64().is_some_and(|ttl|ttl>0 && ttl<=60),"refresh ignored access ttl");
        let idle:i64=sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM (idle_expires_at-clock_timestamp()))::bigint FROM auth_refresh_families LIMIT 1")
            .fetch_one(&pool).await?;
        ensure!(idle>0 && idle<=300,"custom refresh idle ttl ignored");
        let _=user;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "requires isolated IDENTITY_PHASE20_TEST_DATABASE_URL and cluster id"]
async fn custom_machine_token_lifetime_is_capped_by_credential_expiry() -> TestResult<()> {
    test_support::isolated(|pool| async move {
        let keys=KeyFixture::new()?;
        let state=keys.state(pool.clone(),false).await?;
        let app=Uuid::now_v7(); let id=Uuid::now_v7(); let resource=Uuid::now_v7(); let scope=Uuid::now_v7(); let credential=Uuid::now_v7();
        let secret=crate::sso::opaque_secret()?;
        sqlx::query("INSERT INTO auth_applications(application_id,ownership,status,display_name,purpose,approved_scopes) VALUES($1,'FIRST_PARTY','APPROVED','Machine policy fixture','SERVICE',ARRAY['service.read'])").bind(app).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status) VALUES($1,'machine-policy','https://api.example.test','ACTIVE')").bind(resource).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,'service.read','ACTIVE')").bind(scope).bind(resource).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,status,client_token_ttl_seconds) VALUES($1,$1::text,'Machine policy fixture',$2,'test','CONFIDENTIAL','SERVICE','MACHINE','NONE',ARRAY[]::text[],ARRAY['client_credentials'],'client_secret_basic',ARRAY[]::text[],'ENABLED',120)").bind(id).bind(app).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_client_credentials(id,client_id,credential_version,secret_digest) VALUES($1,$2,1,$3)").bind(credential).bind(id).bind(super::super::digest(&secret)).execute(&pool).await?;
        sqlx::query("INSERT INTO auth_client_permissions(client_id,resource_id,scope_id) VALUES($1,$2,$3)").bind(id).bind(resource).bind(scope).execute(&pool).await?;
        let headers=HeaderMap::from_iter([(header::AUTHORIZATION,HeaderValue::from_str(&format!("Basic {}",STANDARD.encode(format!("{id}:{secret}"))))?)]);
        let values=BTreeMap::from([("grant_type".into(),"client_credentials".into()),("scope".into(),"service.read".into())]);
        let Json(token)=client_credentials_token(&state,&headers,&values).await.map_err(|_|anyhow::anyhow!("machine token failed"))?;
        ensure!(token["expires_in"].as_i64().is_some_and(|ttl|ttl>100 && ttl<=120),"custom machine ttl ignored");
        sqlx::query("UPDATE auth_client_credentials SET expires_at=clock_timestamp()+interval '70 seconds' WHERE id=$1").bind(credential).execute(&pool).await?;
        let Json(token)=client_credentials_token(&state,&headers,&values).await.map_err(|_|anyhow::anyhow!("credential-capped token failed"))?;
        ensure!(token["expires_in"].as_i64().is_some_and(|ttl|ttl>0 && ttl<=70),"credential expiry bypassed");
        Ok(())
    }).await
}
