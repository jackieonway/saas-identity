//! Real canonical OAuth issuance and private resource HTTP, with an explicit choice fixture.
use super::*;

const AUDIENCE: &str = "https://orders.saas.test/api";

async fn prove(
    app: &Router,
    service: Uuid,
    secret: &str,
    token: &str,
    resource: &str,
    audience: &str,
    scope: &str,
) -> Result<(StatusCode, Value)> {
    let response=app.clone().oneshot(Request::post("/internal/identity/auth/resource-access-proof")
        .header(header::AUTHORIZATION,format!("Basic {}",STANDARD.encode(format!("{service}:{secret}")))).header(header::CONTENT_TYPE,"application/json")
        .body(Body::from(serde_json::to_vec(&json!({"contractVersion":"resource-access-proof-request/1","token":token,"resource":resource,"audience":audience,"scope":scope}))?))?).await?;
    ensure!(
        response
            .headers()
            .get("cache-control")
            .is_some_and(|v| v == "no-store"),
        "resource proof became cacheable"
    );
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

#[tokio::test]
#[ignore = "requires task-owned IDENTITY_PHASE12_TEST_DATABASE_URL and IDENTITY_PHASE12_TEST_MARKER"]
async fn phase15_private_resource_proof_separates_issuer_credentials_scope_and_business_sources(
) -> Result<()> {
    let db = Database::create_phase12_context().await?;
    let result=async {
        prepare_phase08_schema(&db).await?;
        let key=test_key_fixture()?;
        let fixture=auth_fixture(&db,&key).await?;
        let employee=add_unified_context_client(&db,&fixture,"resource-employee","EMPLOYEE").await?;
        let resource=Uuid::now_v7();let read=Uuid::now_v7();let write=Uuid::now_v7();
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'orders',$2,'ACTIVE',1)").bind(resource).bind(AUDIENCE).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$3,'orders.read','ACTIVE'),($2,$3,'orders.write','ACTIVE')").bind(read).bind(write).bind(resource).execute(&db.pool).await?;
        sqlx::query("UPDATE auth_applications SET approved_scopes=approved_scopes||ARRAY['orders.read','orders.write'] WHERE application_id=$1").bind(fixture.application_id).execute(&db.pool).await?;
        for client in [employee.id,fixture.confidential_client_id] {
            for scope in [read,write] {
                sqlx::query("INSERT INTO auth_client_permissions(client_id,resource_id,scope_id,version) VALUES($1,$2,$3,1)").bind(client).bind(resource).bind(scope).execute(&db.pool).await?;
            }
        }
        sqlx::query("INSERT INTO auth_consent_scopes(consent_id,resource_id,scope_id) SELECT consent.id,$2,$3 FROM auth_consents consent JOIN auth_consent_group_clients member ON member.group_id=consent.group_id WHERE member.client_id=$1 AND consent.user_id=$4")
            .bind(employee.id).bind(resource).bind(read).bind(fixture.user_id).execute(&db.pool).await?;
        let service=Uuid::now_v7();let service_secret="c1".repeat(32);
        sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,allowed_auth_resources) VALUES($1,$2,'RESOURCE_ACCESS_PROOF','ENABLED',ARRAY[$3])")
            .bind(service).bind(crate::util::hash::sha256_hex(&service_secret)).bind(resource).execute(&db.pool).await?;
        let (app,tokens)=super::customer_proof_tests::context_tokens_with_scope(&db,&key,&fixture,&employee,"EMPLOYEE",Uuid::now_v7(),"openid profile orders.read").await?;
        let access=tokens["access_token"].as_str().ok_or_else(||anyhow!("employee resource access token missing"))?;
        let (status,proof)=prove(&app,service,&service_secret,access,"orders",AUDIENCE,"orders.read").await?;
        ensure!(status==StatusCode::OK,"USER private resource proof failed: {status} {proof}");
        let (_,userinfo)=userinfo_get(&app,access).await?;
        ensure!(proof["contractVersion"]=="resource-access-proof/1" && proof["tokenUse"]=="access_token" && proof["subjectMode"]=="USER" && proof["sub"]==userinfo["sub"] && proof["sub"]!=fixture.user_id.to_string(),"resource identity did not retain the opaque subject boundary");
        ensure!(proof["clientId"]==employee.id.to_string() && proof["applicationId"]==fixture.application_id.to_string() && proof["scope"]==json!(["orders.read"]) && proof["context"]["memberType"]=="EMPLOYEE" && proof["source"]["userId"]==fixture.user_id.to_string() && proof["source"]["accountVersion"]=="1","resource proof confused caller application, scopes or employee source");
        ensure!(proof["context"].as_object().is_some_and(|context|context.len()==2 && context.contains_key("membershipId") && context.contains_key("memberType")) && proof.get("credentialVersion").is_none(),"USER proof invented a platform member version or machine credential");
        for (target,audience,scope,expected) in [
            ("orders","https://foreign.saas.test/api","orders.read",StatusCode::FORBIDDEN),
            ("userinfo","https://auth.saas.test/oauth/userinfo","openid",StatusCode::FORBIDDEN),
            ("orders",AUDIENCE,"orders.write",StatusCode::FORBIDDEN),
            ("orders",AUDIENCE,"orders.read orders.write",StatusCode::BAD_REQUEST),
        ] {ensure!(prove(&app,service,&service_secret,access,target,audience,scope).await?.0==expected,"resource proof crossed a requested audience/resource/scope boundary");}
        let (wrong_service,wrong_secret)=add_context_source_service(&db,&[employee.id]).await?;
        ensure!(prove(&app,wrong_service,&wrong_secret,access,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::FORBIDDEN,"context-source service became a resource verifier");
        sqlx::query("UPDATE identity_service_clients SET allowed_auth_resources=ARRAY[]::uuid[] WHERE id=$1").bind(service).execute(&db.pool).await?;
        ensure!(prove(&app,service,&service_secret,access,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::FORBIDDEN,"resource service ignored its current allowlist");
        sqlx::query("UPDATE identity_service_clients SET allowed_auth_resources=ARRAY[$2] WHERE id=$1").bind(service).bind(resource).execute(&db.pool).await?;
        ensure!(prove(&app,service,&service_secret,tokens["id_token"].as_str().ok_or_else(||anyhow!("ID token missing"))?,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::BAD_REQUEST,"ID token entered the resource access-token path");
        ensure!(prove(&app,service,&service_secret,tokens["refresh_token"].as_str().ok_or_else(||anyhow!("refresh token missing"))?,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::UNAUTHORIZED,"refresh token entered the resource access-token path");
        let account_code=authorize_and_consent(&app,&fixture,"openid profile orders.read").await?;
        let (status,account_tokens)=exchange_confidential(&app,&fixture.confidential_client_name,&fixture.client_secret,"https://client.example.test/callback",&account_code,&fixture.verifier).await?;
        ensure!(status==StatusCode::OK,"ACCOUNT_ONLY fixture issuance failed: {account_tokens}");
        ensure!(prove(&app,service,&service_secret,account_tokens["access_token"].as_str().ok_or_else(||anyhow!("account access missing"))?,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::UNAUTHORIZED,"ACCOUNT_ONLY token acquired business context");
        enable_refresh_client(&db,&fixture).await?;
        sqlx::query("UPDATE auth_applications SET approved_scopes=approved_scopes||ARRAY['orders.read','orders.write'] WHERE application_id=$1").bind(fixture.application_id).execute(&db.pool).await?;
        let offline_code=authorize_and_consent(&app,&fixture,"openid profile orders.read offline_access").await?;
        let (status,offline)=exchange_confidential(&app,&fixture.confidential_client_name,&fixture.client_secret,"https://client.example.test/callback",&offline_code,&fixture.verifier).await?;
        ensure!(status==StatusCode::OK,"approved offline fixture issuance failed: {offline}");
        ensure!(prove(&app,service,&service_secret,offline["access_token"].as_str().ok_or_else(||anyhow!("offline access missing"))?,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::UNAUTHORIZED,"offline account grant acquired business context");
        let machine_secret="c2".repeat(32);
        let machine=add_resource_client(&db,"phase15-machine","Resource proof machine",&["orders.read"],resource,read,&machine_secret).await?;
        let (status,machine_tokens)=machine_token(&app,"phase15-machine",&machine_secret,"orders.read").await?;
        ensure!(status==StatusCode::OK,"MACHINE resource fixture issuance failed: {machine_tokens}");
        let machine_access=machine_tokens["access_token"].as_str().ok_or_else(||anyhow!("machine access missing"))?;
        let (status,machine_proof)=prove(&app,service,&service_secret,machine_access,"orders",AUDIENCE,"orders.read").await?;
        ensure!(status==StatusCode::OK && machine_proof["subjectMode"]=="MACHINE" && machine_proof["clientId"]==machine.to_string() && machine_proof["applicationId"]!=fixture.application_id.to_string() && machine_proof["credentialVersion"]=="1","machine proof lost its caller/credential source: {status} {machine_proof}");
        ensure!(machine_proof.get("sub").is_none() && machine_proof.get("context").is_none() && machine_proof["source"].as_object().is_some_and(|source|source.len()==3 && source.contains_key("grantId") && source.contains_key("clientPolicyVersion") && source.contains_key("applicationProjectionVersion")),"machine proof fabricated human fields");
        let credential_deadline:DateTime<Utc>=sqlx::query_scalar("UPDATE auth_client_credentials SET expires_at=clock_timestamp()+interval '45 seconds' WHERE client_id=$1 RETURNING expires_at").bind(machine).fetch_one(&db.pool).await?;
        let (status,short_machine)=prove(&app,service,&service_secret,machine_access,"orders",AUDIENCE,"orders.read").await?;
        ensure!(status==StatusCode::OK && short_machine["expiresAt"]==json!(credential_deadline),"machine proof exceeded its current credential expiry");
        sqlx::query("UPDATE auth_client_credentials SET revoked_at=clock_timestamp() WHERE client_id=$1").bind(machine).execute(&db.pool).await?;
        ensure!(prove(&app,service,&service_secret,machine_access,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::UNAUTHORIZED,"revoked machine credential still yielded resource proof");
        for mutation in [
            format!("UPDATE auth_clients SET policy_version=2 WHERE id='{}'",employee.id),
            format!("UPDATE auth_applications SET projection_version=2 WHERE application_id='{}'",fixture.application_id),
            format!("UPDATE users SET session_version=2 WHERE id='{}'",fixture.user_id),
        ] {
            sqlx::query(&mutation).execute(&db.pool).await?;
            ensure!(prove(&app,service,&service_secret,access,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::UNAUTHORIZED,"resource proof repaired a changed original source");
            sqlx::query("UPDATE auth_clients SET policy_version=1 WHERE id=$1").bind(employee.id).execute(&db.pool).await?;
            sqlx::query("UPDATE auth_applications SET projection_version=1 WHERE application_id=$1").bind(fixture.application_id).execute(&db.pool).await?;
            sqlx::query("UPDATE users SET session_version=1 WHERE id=$1").bind(fixture.user_id).execute(&db.pool).await?;
        }
        let source_deadline:DateTime<Utc>=sqlx::query_scalar("UPDATE sso_sessions SET expires_at=clock_timestamp()+interval '60 seconds' WHERE id=$1 RETURNING expires_at").bind(fixture.session_id).fetch_one(&db.pool).await?;
        let (status,short_user)=prove(&app,service,&service_secret,access,"orders",AUDIENCE,"orders.read").await?;
        ensure!(status==StatusCode::OK && short_user["expiresAt"]==json!(source_deadline),"USER resource proof exceeded its shortened SSO source");
        sqlx::query("UPDATE sso_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(fixture.session_id).execute(&db.pool).await?;
        ensure!(prove(&app,service,&service_secret,access,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::UNAUTHORIZED,"expired original SSO source still yielded a resource proof");
        sqlx::query("UPDATE sso_sessions SET expires_at=$2 WHERE id=$1").bind(fixture.session_id).bind(source_deadline).execute(&db.pool).await?;
        ensure!(revoke_access(&app,&employee.client_id,&employee.client_secret,access).await?==StatusCode::OK,"original client access revocation failed");
        ensure!(prove(&app,service,&service_secret,access,"orders",AUDIENCE,"orders.read").await?.0==StatusCode::UNAUTHORIZED,"revoked user token still yielded resource proof");
        Ok::<(),anyhow::Error>(())
    }.await;
    db.finish(result).await
}
