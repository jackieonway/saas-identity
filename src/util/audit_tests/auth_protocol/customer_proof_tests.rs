//! Real OAuth issuance and authenticated private HTTP, with a member-choice port fixture.
use super::*;

fn proof_router(state: crate::state::AppState) -> Router {
    crate::oidc::routes()
        .merge(crate::sso::routes())
        .merge(crate::internal::routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::internal::guard,
        ))
        .with_state(state)
}

async fn context_tokens(
    db: &Database,
    key: &KeyFixture,
    fixture: &AuthFixture,
    client: &UnifiedContextClient,
    member_type: &str,
    expected_customer: Uuid,
) -> Result<(Router, Value)> {
    context_tokens_with_scope(
        db,
        key,
        fixture,
        client,
        member_type,
        expected_customer,
        "openid profile",
    )
    .await
}

pub(super) async fn context_tokens_with_scope(
    db: &Database,
    key: &KeyFixture,
    fixture: &AuthFixture,
    client: &UnifiedContextClient,
    member_type: &str,
    expected_customer: Uuid,
    scopes: &str,
) -> Result<(Router, Value)> {
    let transaction = Uuid::now_v7();
    let member = Uuid::now_v7();
    let port = UnifiedSelectionFixture::new(
        client.id,
        transaction,
        vec![context_choice(
            member,
            fixture.user_id,
            Uuid::now_v7(),
            Uuid::now_v7(),
            member_type,
        )],
    );
    let mut state = state_with_context_fixture(db, key, port)?;
    let mut config = (*state.config).clone();
    config.service_expected_customer_client = Some(expected_customer);
    state.config = Arc::new(config);
    let app = proof_router(state);
    let state_value = format!("phase14-state-{transaction}");
    let nonce = format!("phase14-nonce-{transaction}");
    let (status, created) = create_context_interaction(
        &app,
        client,
        transaction,
        &state_value,
        &nonce,
        &fixture.challenge,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "customer proof fixture could not create canonical context: {created}"
    );
    let handle = created["contextRequest"]
        .as_str()
        .ok_or_else(|| anyhow!("context handle missing"))?;
    let mut target = reqwest::Url::parse("https://auth.saas.test/oauth/authorize")?;
    target
        .query_pairs_mut()
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", &client.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", scopes)
        .append_pair("state", &state_value)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &fixture.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("context_request", handle);
    let (status, headers, body) = send(
        &app,
        "GET",
        &format!("/oauth/authorize?{}", target.query().unwrap_or_default()),
        Some(&session_cookie(fixture)),
        None,
        None,
        None,
        None,
    )
    .await?;
    let target = location(&headers)?;
    ensure!(
        status.is_redirection(),
        "customer proof fixture authorization failed: {body}"
    );
    let flow = target
        .split("flow=")
        .nth(1)
        .ok_or_else(|| anyhow!("canonical flow missing"))?;
    let cookie = append_cookie(
        &session_cookie(fixture),
        &format!("__Host-saas_oauth_browser={}", browser_value(&headers)?),
    );
    let (status, _, interaction) = send(
        &app,
        "GET",
        &format!("/oauth/interaction/{flow}"),
        Some(&cookie),
        Some("https://auth.saas.test"),
        None,
        None,
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "context interaction failed: {interaction}"
    );
    let csrf = interaction["csrfToken"]
        .as_str()
        .ok_or_else(|| anyhow!("context CSRF missing"))?;
    let (status, _, approved) = send(
        &app,
        "POST",
        &format!("/oauth/interaction/{flow}"),
        Some(&cookie),
        Some("https://auth.saas.test"),
        Some(csrf),
        Some("application/json"),
        Some(serde_json::to_vec(
            &json!({"action":"approve","membershipId":member}),
        )?),
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "customer context approval failed: {approved}"
    );
    let code = callback_parameter(
        approved["redirectTo"]
            .as_str()
            .ok_or_else(|| anyhow!("context callback missing"))?,
        "code",
    )?;
    let (status, tokens) = exchange_confidential(
        &app,
        &client.client_id,
        &client.client_secret,
        &client.redirect_uri,
        &code,
        &fixture.verifier,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "customer canonical code exchange failed: {tokens}"
    );
    Ok((app, tokens))
}

async fn call_proof(
    app: &Router,
    service: Uuid,
    secret: &str,
    client: Uuid,
    token: &str,
    bff: bool,
) -> Result<(StatusCode, Value)> {
    let (path, contract) = if bff {
        (
            "/internal/identity/auth/customer-account-proof",
            "customer-account-proof-request/1",
        )
    } else {
        (
            "/internal/identity/customer-access-proof",
            "customer-access-proof-request/1",
        )
    };
    let reply=app.clone().oneshot(Request::post(path).header(header::AUTHORIZATION,format!("Basic {}",STANDARD.encode(format!("{service}:{secret}")))).header(header::CONTENT_TYPE,"application/json")
        .body(Body::from(serde_json::to_vec(&json!({"contractVersion":contract,"expectedClientId":client,"oidcAccessToken":token}))?))?).await?;
    ensure!(
        reply
            .headers()
            .get("cache-control")
            .is_some_and(|v| v == "no-store"),
        "private proof became cacheable"
    );
    let status = reply.status();
    let bytes = to_bytes(reply.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

#[tokio::test]
#[ignore = "requires task-owned IDENTITY_PHASE12_TEST_DATABASE_URL and IDENTITY_PHASE12_TEST_MARKER"]
async fn phase14_customer_bff_and_resource_proofs_are_canonical_private_and_source_bound(
) -> Result<()> {
    let db = Database::create_phase12_context().await?;
    let result=async {
        prepare_phase08_schema(&db).await?;
        let key=test_key_fixture()?;
        let fixture=auth_fixture(&db,&key).await?;
        let mut customer=add_unified_context_client(&db,&fixture,"proof-customer","CUSTOMER").await?;
        let mut employee=add_unified_context_client(&db,&fixture,"proof-employee","EMPLOYEE").await?;
        for client in [&mut customer,&mut employee] {
            client.client_id=client.id.to_string();
            sqlx::query("UPDATE auth_clients SET client_id=$2 WHERE id=$1").bind(client.id).bind(&client.client_id).execute(&db.pool).await?;
        }
        sqlx::query("UPDATE auth_applications SET purpose='CUSTOMER_PORTAL' WHERE application_id=$1").bind(fixture.application_id).execute(&db.pool).await?;
        sqlx::query("UPDATE auth_consent_groups SET purpose='CUSTOMER_PORTAL' WHERE application_id=$1").bind(fixture.application_id).execute(&db.pool).await?;
        let (bff_service,bff_secret)=add_context_source_service(&db,&[customer.id,employee.id]).await?;
        let resource_service=Uuid::now_v7();
        let resource_secret="db".repeat(32);
        sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,allowed_auth_clients) VALUES($1,$2,'CUSTOMER_ACCESS_PROOF','ENABLED',ARRAY[$3])")
            .bind(resource_service).bind(crate::util::hash::sha256_hex(&resource_secret)).bind(customer.id).execute(&db.pool).await?;
        let (app,tokens)=context_tokens(&db,&key,&fixture,&customer,"CUSTOMER",customer.id).await?;
        let access=tokens["access_token"].as_str().ok_or_else(||anyhow!("customer access token missing"))?;
        let (status,proof)=call_proof(&app,bff_service,&bff_secret,customer.id,access,true).await?;
        ensure!(status==StatusCode::OK,"canonical customer BFF proof failed: {status} {proof}");
        let (status,userinfo)=userinfo_get(&app,access).await?;
        ensure!(status==StatusCode::OK && proof["sub"]==userinfo["sub"] && proof["sub"]!=fixture.user_id.to_string() && proof["userId"]==fixture.user_id.to_string(),"private customer account ID was inferred from public sub or UserInfo differed");
        ensure!(proof["contractVersion"]=="customer-account-proof/1" && proof["clientPurpose"]=="CUSTOMER_PORTAL" && proof["allowedMemberTypes"]==json!(["CUSTOMER"]) && proof["contextMode"]=="PLATFORM_CONTEXT" && proof["applicationProjectionVersion"]=="1","customer BFF proof dimensions were incomplete");
        let (status,resource)=call_proof(&app,resource_service,&resource_secret,customer.id,access,false).await?;
        ensure!(status==StatusCode::OK && resource["contractVersion"]=="customer-access-proof/1" && resource["account"]["id"]==proof["userId"] && resource["source"]["grantId"]==proof["grantId"] && resource["source"]["expiresAt"]==proof["expiresAt"],"resource proof did not use the same canonical source");
        for (service,secret,bff) in [(resource_service,resource_secret.as_str(),true),(bff_service,bff_secret.as_str(),false)] {
            ensure!(call_proof(&app,service,secret,customer.id,access,bff).await?.0==StatusCode::FORBIDDEN,"customer BFF and resource consumer credentials crossed purposes");
        }
        ensure!(call_proof(&app,bff_service,&bff_secret,Uuid::now_v7(),access,true).await?.0==StatusCode::FORBIDDEN,"BFF service crossed its exact registered client set");
        ensure!(call_proof(&app,bff_service,&bff_secret,employee.id,access,true).await?.0==StatusCode::UNAUTHORIZED,"customer token was rebound to the employee client");
        sqlx::query("UPDATE identity_service_clients SET allowed_auth_clients=ARRAY[]::uuid[] WHERE id=$1").bind(resource_service).execute(&db.pool).await?;
        ensure!(call_proof(&app,resource_service,&resource_secret,customer.id,access,false).await?.0==StatusCode::FORBIDDEN,"reverse proof ignored exact registered customer RP");
        sqlx::query("UPDATE identity_service_clients SET allowed_auth_clients=ARRAY[$2] WHERE id=$1").bind(resource_service).bind(customer.id).execute(&db.pool).await?;
        for invalid in [tokens["refresh_token"].as_str().ok_or_else(||anyhow!("customer refresh missing"))?,"aa00000000000000000000000000000000000000000000000000000000000000"] {
            ensure!(call_proof(&app,bff_service,&bff_secret,customer.id,invalid,true).await?.0==StatusCode::UNAUTHORIZED,"non-access credential became a customer proof");
        }
        let (employee_app,employee_tokens)=context_tokens(&db,&key,&fixture,&employee,"EMPLOYEE",customer.id).await?;
        ensure!(call_proof(&employee_app,bff_service,&bff_secret,employee.id,employee_tokens["access_token"].as_str().ok_or_else(||anyhow!("employee token missing"))?,true).await?.0==StatusCode::UNAUTHORIZED,"employee token became customer proof");
        let machine_resource=Uuid::now_v7();let machine_scope=Uuid::now_v7();
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'proof-orders','https://orders.saas.test/proof','ACTIVE',1)").bind(machine_resource).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,'orders.read','ACTIVE')").bind(machine_scope).bind(machine_resource).execute(&db.pool).await?;
        let machine_secret="dc".repeat(32);
        add_resource_client(&db,"phase14-proof-machine","Proof machine",&["orders.read"],machine_resource,machine_scope,&machine_secret).await?;
        let (status,machine)=machine_token(&app,"phase14-proof-machine",&machine_secret,"orders.read").await?;
        ensure!(status==StatusCode::OK,"canonical machine issuance failed: {machine}");
        ensure!(call_proof(&app,bff_service,&bff_secret,customer.id,machine["access_token"].as_str().ok_or_else(||anyhow!("machine token missing"))?,true).await?.0==StatusCode::UNAUTHORIZED,"machine token became a customer proof");
        for mutation in [
            format!("UPDATE auth_clients SET policy_version=2 WHERE id='{}'",customer.id),
            format!("UPDATE auth_applications SET projection_version=2 WHERE application_id='{}'",fixture.application_id),
            format!("UPDATE auth_consents SET generation=2 WHERE user_id='{}' AND group_id=(SELECT group_id FROM auth_consent_group_clients WHERE client_id='{}')",fixture.user_id,customer.id),
        ] {
            sqlx::query(&mutation).execute(&db.pool).await?;
            ensure!(call_proof(&app,bff_service,&bff_secret,customer.id,access,true).await?.0==StatusCode::UNAUTHORIZED,"changed original authority still produced customer proof");
            sqlx::query("UPDATE auth_clients SET policy_version=1 WHERE id=$1").bind(customer.id).execute(&db.pool).await?;
            sqlx::query("UPDATE auth_applications SET projection_version=1 WHERE application_id=$1").bind(fixture.application_id).execute(&db.pool).await?;
            sqlx::query("UPDATE auth_consents SET generation=1 WHERE user_id=$1").bind(fixture.user_id).execute(&db.pool).await?;
        }
        let deadline:DateTime<Utc>=sqlx::query_scalar("UPDATE sso_sessions SET expires_at=clock_timestamp()+interval '90 seconds' WHERE id=$1 RETURNING expires_at").bind(fixture.session_id).fetch_one(&db.pool).await?;
        let (status,shortened)=call_proof(&app,bff_service,&bff_secret,customer.id,access,true).await?;
        ensure!(status==StatusCode::OK && shortened["expiresAt"]==json!(deadline) && shortened["absoluteExpiresAt"]==json!(deadline),"proof extended a shortened original SSO source: {status} {shortened}");
        sqlx::query("UPDATE sso_sessions SET revoked_at=clock_timestamp() WHERE id=$1").bind(fixture.session_id).execute(&db.pool).await?;
        for (service,secret,bff) in [(bff_service,bff_secret.as_str(),true),(resource_service,resource_secret.as_str(),false)] {
            ensure!(call_proof(&app,service,secret,customer.id,access,bff).await?.0==StatusCode::UNAUTHORIZED,"revoked original SSO source still produced customer proof");
        }
        Ok::<(),anyhow::Error>(())
    }.await;
    db.finish(result).await
}
