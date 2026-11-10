use super::Database;
use anyhow::{ensure, Result};
use axum::http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase04_unified_client_api_enforces_policy_paging_and_credential_lifecycle() -> Result<()>
{
    let db = Database::create_phase04().await?;
    let result = async {
        let application = Uuid::now_v7();
        let resource = Uuid::now_v7();
        let openid = Uuid::now_v7();
        let profile = Uuid::now_v7();
        let machine_resource = Uuid::now_v7();
        let machine_scope = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_applications(application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) VALUES($1,NULL,'FIRST_PARTY','APPROVED','Platform client app','Account login',ARRAY['openid','profile','service.read'],1,clock_timestamp())")
            .bind(application).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'userinfo','https://auth.saas.test/userinfo','ACTIVE',1)")
            .bind(resource).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,'openid','ACTIVE'),($3,$2,'profile','ACTIVE')")
            .bind(openid).bind(resource).bind(profile).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'machine-api','https://api.saas.test/machine','ACTIVE',1)")
            .bind(machine_resource).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,'service.read','ACTIVE')")
            .bind(machine_scope).bind(machine_resource).execute(&db.pool).await?;

        let machine_operation = Uuid::now_v7();
        let machine_input = json!({
            "expectedVersion":null,
            "applicationId":application,
            "environment":"test",
            "displayName":"Platform API machine",
            "clientType":"CONFIDENTIAL",
            "runtimeKind":"SERVICE",
            "subjectMode":"MACHINE",
            "contextMode":"NONE",
            "allowedMemberTypes":[],
            "grantTypes":["client_credentials"],
            "tokenEndpointAuthMethod":"client_secret_basic",
            "redirectUris":[],
            "postLogoutRedirectUris":[],
            "status":"DISABLED",
            "consentGroupId":null,
            "permissions":[{"resourceKey":"machine-api","scopes":["service.read"]}]
        });
        let machine = db.auth_admin_call(
            machine_operation,
            "POST",
            "/internal/identity/auth/clients",
            Some(machine_input),
        ).await?;
        ensure!(machine.status == StatusCode::OK
            && machine.body["subjectMode"] == "MACHINE"
            && machine.body["clientType"] == "CONFIDENTIAL",
            "valid machine client was not registered in the unified client authority");
        let rejected_machine_userinfo = db.auth_admin_call(
            Uuid::now_v7(),
            "POST",
            "/internal/identity/auth/clients",
            Some(json!({
                "expectedVersion":null,
                "applicationId":application,
                "environment":"test",
                "displayName":"Invalid machine profile client",
                "clientType":"CONFIDENTIAL",
                "runtimeKind":"SERVICE",
                "subjectMode":"MACHINE",
                "contextMode":"NONE",
                "allowedMemberTypes":[],
                "grantTypes":["client_credentials"],
                "tokenEndpointAuthMethod":"client_secret_basic",
                "redirectUris":[],
                "postLogoutRedirectUris":[],
                "status":"DISABLED",
                "consentGroupId":null,
                "permissions":[{"resourceKey":"userinfo","scopes":["profile"]}]
            })),
        )
        .await?;
        ensure!(
            rejected_machine_userinfo.status == StatusCode::FORBIDDEN,
            "MACHINE registration accepted the human UserInfo resource"
        );

        let partner_application = Uuid::now_v7();
        let partner = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_applications(application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) VALUES($1,$2,'THIRD_PARTY','APPROVED','Reviewed partner app','External account login',ARRAY['openid','profile'],1,clock_timestamp())")
            .bind(partner_application).bind(partner).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_application_admissions(application_id,environment,status,redirect_uris,post_logout_redirect_uris,scopes) VALUES($1,'test','APPROVED',ARRAY['https://client.example.test/callback'],ARRAY[]::text[],ARRAY['openid','profile'])")
            .bind(partner_application).execute(&db.pool).await?;

        let user_input = |expected_version: Value, status: &str| json!({
            "expectedVersion":expected_version,
            "applicationId":application,
            "environment":"TEST",
            "displayName":"Platform web client",
            "clientType":"CONFIDENTIAL",
            "runtimeKind":"WEB_BFF",
            "subjectMode":"USER",
            "contextMode":"ACCOUNT_ONLY",
            "allowedMemberTypes":[],
            "grantTypes":["authorization_code","refresh_token"],
            "tokenEndpointAuthMethod":"client_secret_basic",
            "redirectUris":["https://client.example.test/callback"],
            "postLogoutRedirectUris":[],
            "status":status,
            "consentGroupId":null,
            "permissions":[{"resourceKey":"userinfo","scopes":["openid","profile"]}]
        });

        let client_operation = Uuid::now_v7();
        let mut configured=user_input(Value::Null, "ENABLED");
        configured["autoAuthorize"]=json!(true);
        configured["accessTokenTtlSeconds"]=json!(60);
        configured["refreshTokenTtlSeconds"]=json!(300);
        let create = db.auth_admin_call(
            client_operation,
            "POST",
            "/internal/identity/auth/clients",
            Some(configured),
        ).await?;
        ensure!(create.body["autoAuthorize"]==true && create.body["accessTokenTtlSeconds"]==60
            && create.body["refreshTokenTtlSeconds"]==300 && create.body["refreshTokenStrategy"]=="ROTATE"
            && create.body["tokenDefaults"]["accessTokenTtlSeconds"]==300,
            "client policy did not persist or report inherited defaults");
        ensure!(create.status == StatusCode::OK
            && create.body["id"] == client_operation.to_string()
            && create.body["clientType"] == "CONFIDENTIAL"
            && create.body.get("clientSecret").is_none(),
            "unified client create returned wrong authority or exposed a credential");
        let third_party_operation = Uuid::now_v7();
        let mut third_party_input = user_input(Value::Null, "DISABLED");
        third_party_input["applicationId"] = json!(partner_application);
        third_party_input["displayName"] = json!("Reviewed public client");
        third_party_input["clientType"] = json!("PUBLIC");
        third_party_input["runtimeKind"] = json!("SPA");
        third_party_input["tokenEndpointAuthMethod"] = json!("none");
        third_party_input["grantTypes"] = json!(["authorization_code"]);
        let third_party_client = db.auth_admin_call(
            third_party_operation,
            "POST",
            "/internal/identity/auth/clients",
            Some(third_party_input),
        ).await?;
        ensure!(third_party_client.status == StatusCode::OK
            && third_party_client.body["subjectMode"] == "USER"
            && third_party_client.body["clientType"] == "PUBLIC"
            && third_party_client.body["ownership"] == "THIRD_PARTY"
            && third_party_client.body["partnerId"] == partner.to_string()
            && third_party_client.body["applicationName"] == "Reviewed partner app",
            "approved third-party USER client was not registered in the unified client authority");
        let second_client_operation = Uuid::now_v7();
        let second_client = db.auth_admin_call(
            second_client_operation,
            "POST",
            "/internal/identity/auth/clients",
            Some(user_input(Value::Null, "DISABLED")),
        ).await?;
        ensure!(second_client.status == StatusCode::OK,
            "second filtered client fixture failed");

        let wrong_service = db.projection_call(
            Uuid::now_v7(),
            "POST",
            "/internal/identity/auth/clients",
            Some(user_input(Value::Null, "ENABLED")),
        ).await?;
        ensure!(wrong_service.status == StatusCode::FORBIDDEN,
            "APPLICATION_PROJECTION credential was accepted for client administration");

        let escaped_scope = json!({
            "expectedVersion":null,
            "applicationId":application,
            "environment":"test",
            "displayName":"Escalated client",
            "clientType":"CONFIDENTIAL",
            "runtimeKind":"WEB_BFF",
            "subjectMode":"USER",
            "contextMode":"ACCOUNT_ONLY",
            "allowedMemberTypes":[],
            "grantTypes":["authorization_code"],
            "tokenEndpointAuthMethod":"client_secret_basic",
            "redirectUris":["https://client.example.test/callback"],
            "postLogoutRedirectUris":[],
            "status":"DISABLED",
            "consentGroupId":null,
            "permissions":[{"resourceKey":"userinfo","scopes":["openid","admin"]}]
        });
        let denied_scope = db.auth_admin_call(
            Uuid::now_v7(),
            "POST",
            "/internal/identity/auth/clients",
            Some(escaped_scope),
        ).await?;
        ensure!(denied_scope.status == StatusCode::FORBIDDEN,
            "client scope exceeded the approved application projection");
        let mut invalid_machine = user_input(Value::Null, "DISABLED");
        invalid_machine["subjectMode"] = json!("MACHINE");
        invalid_machine["contextMode"] = json!("NONE");
        invalid_machine["clientType"] = json!("PUBLIC");
        invalid_machine["runtimeKind"] = json!("SPA");
        invalid_machine["allowedMemberTypes"] = json!([]);
        invalid_machine["grantTypes"] = json!(["client_credentials"]);
        invalid_machine["tokenEndpointAuthMethod"] = json!("none");
        invalid_machine["redirectUris"] = json!([]);
        let rejected_machine = db.auth_admin_call(
            Uuid::now_v7(),
            "POST",
            "/internal/identity/auth/clients",
            Some(invalid_machine),
        ).await?;
        ensure!(rejected_machine.status == StatusCode::BAD_REQUEST,
            "illegal public machine-client combination was accepted");

        let path = format!("/internal/identity/auth/clients/{client_operation}");
        let updated = db.auth_admin_call(
            Uuid::now_v7(),
            "PATCH",
            &path,
            Some(user_input(json!(1), "DISABLED")),
        ).await?;
        ensure!(updated.status == StatusCode::OK
            && updated.body["version"] == 2
            && updated.body["policyVersion"] == 2
            && updated.body["status"] == "DISABLED",
            "client policy update did not advance version and policy generation");
        let stale_update = db.auth_admin_call(
            Uuid::now_v7(),
            "PATCH",
            &path,
            Some(user_input(json!(1), "ENABLED")),
        ).await?;
        ensure!(stale_update.status == StatusCode::CONFLICT,
            "stale client update did not conflict");

        let rotate_path = format!("{path}/credentials");
        let before_suppressed_audit: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT version FROM auth_clients WHERE id=$1), \
             (SELECT count(*) FROM auth_client_credentials WHERE client_id=$1), \
             (SELECT count(*) FROM identity_auth_command_receipts), \
             (SELECT count(*) FROM identity_audit_logs)",
        ).bind(client_operation).fetch_one(&db.pool).await?;
        db.suppress("identity_audit_logs", "INSERT").await?;
        let suppressed_operation = Uuid::now_v7();
        let suppressed_rotation = db.auth_admin_call(
            suppressed_operation,
            "POST",
            &rotate_path,
            Some(json!({"expectedVersion":2})),
        ).await?;
        db.unsuppress("identity_audit_logs").await?;
        ensure!(suppressed_rotation.status == StatusCode::SERVICE_UNAVAILABLE,
            "suppressed credential audit did not fail closed");
        let after_suppressed_audit: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT version FROM auth_clients WHERE id=$1), \
             (SELECT count(*) FROM auth_client_credentials WHERE client_id=$1), \
             (SELECT count(*) FROM identity_auth_command_receipts), \
             (SELECT count(*) FROM identity_audit_logs)",
        ).bind(client_operation).fetch_one(&db.pool).await?;
        ensure!(after_suppressed_audit == before_suppressed_audit,
            "audit failure left a credential, version or operation receipt behind");
        let suppressed_digest = super::admin_digest(
            "POST",
            &rotate_path,
            &json!({"expectedVersion":2}),
        )?;
        let suppressed_lookup = db.call(
            "AUTH_ADMIN",
            "GET",
            &format!("/internal/identity/auth/client-operations/{suppressed_operation}"),
            None,
            &[("x-identity-operation-digest", suppressed_digest)],
        ).await?;
        ensure!(suppressed_lookup.status == StatusCode::NOT_FOUND,
            "failed credential command retained a completed receipt");

        let page = db.call(
            "AUTH_ADMIN",
            "GET",
            &format!("/internal/identity/auth/clients?applicationId={application}&ownership=FIRST_PARTY&subjectMode=USER&environment=test&limit=1&offset=0"),
            None,
            &[],
        ).await?;
        ensure!(page.status == StatusCode::OK
            && page.body["records"].as_array().is_some_and(|rows| rows.len() == 1)
            && page.body["records"][0]["id"] == second_client_operation.to_string()
            && page.body["page"]["total"] == 2
            && page.body["page"]["limit"] == 1,
            "filtered stable client pagination returned wrong ordering or metadata");
        let second_page = db.call(
            "AUTH_ADMIN",
            "GET",
            &format!("/internal/identity/auth/clients?applicationId={application}&ownership=FIRST_PARTY&subjectMode=USER&environment=test&limit=1&offset=1"),
            None,
            &[],
        ).await?;
        ensure!(second_page.status == StatusCode::OK
            && second_page.body["records"].as_array().is_some_and(|rows| rows.len() == 1)
            && second_page.body["records"][0]["id"] == client_operation.to_string(),
            "stable client sort did not preserve the next page");
        let beyond = db.call(
            "AUTH_ADMIN",
            "GET",
            &format!("/internal/identity/auth/clients?applicationId={application}&ownership=FIRST_PARTY&subjectMode=USER&environment=test&limit=1&offset=9"),
            None,
            &[],
        ).await?;
        ensure!(beyond.status == StatusCode::OK
            && beyond.body["records"].as_array().is_some_and(|rows| rows.is_empty())
            && beyond.body["page"]["offset"] == 9
            && beyond.body["page"]["total"] == 2,
            "page beyond the last record did not return an empty page with metadata");
        let partner_page = db.call(
            "AUTH_ADMIN",
            "GET",
            &format!("/internal/identity/auth/clients?partnerId={partner}&ownership=THIRD_PARTY&environment=test"),
            None,
            &[],
        ).await?;
        ensure!(partner_page.status == StatusCode::OK
            && partner_page.body["records"].as_array().is_some_and(|rows| rows.len() == 1)
            && partner_page.body["records"][0]["id"] == third_party_operation.to_string(),
            "third-party client filtering did not preserve the reviewed partner boundary");
        let overflow = db.call(
            "AUTH_ADMIN",
            "GET",
            "/internal/identity/auth/clients?limit=101",
            None,
            &[],
        ).await?;
        ensure!(overflow.status == StatusCode::BAD_REQUEST,
            "out-of-range client page size was accepted");

        let first_operation = Uuid::now_v7();
        let first = db.auth_admin_call(
            first_operation,
            "POST",
            &rotate_path,
            Some(json!({"expectedVersion":2})),
        ).await?;
        ensure!(first.status == StatusCode::OK
            && first.body["credentialId"] == first_operation.to_string()
            && first.body["credentialVersion"] == 1
            && first.body["clientVersion"] == 3
            && first.body["credentialExpiresAt"].is_string()
            && first.body["clientSecret"].as_str().is_some_and(|value| value.len() == 64),
            "first credential rotation failed or omitted one-time material (status={}, code={}, message={})",
            first.status,
            first.body["code"],
            first.body["message"]
        );
        let first_secret = first.body["clientSecret"].as_str().unwrap().to_owned();
        let stored_digest: String = sqlx::query_scalar(
            "SELECT secret_digest FROM auth_client_credentials WHERE id=$1",
        ).bind(first_operation).fetch_one(&db.pool).await?;
        ensure!(stored_digest == crate::util::hash::sha256_hex(&first_secret),
            "database did not store only the generated credential digest");
        let rotation_digest = super::admin_digest(
            "POST",
            &rotate_path,
            &json!({"expectedVersion":2}),
        )?;
        let recovered = db.call(
            "AUTH_ADMIN",
            "GET",
            &format!("/internal/identity/auth/client-operations/{first_operation}"),
            None,
            &[("x-identity-operation-digest", rotation_digest)],
        ).await?;
        ensure!(recovered.status == StatusCode::OK
            && recovered.body["clientSecret"] == first_secret,
            "original operation lookup did not recover its one-time result");
        let replay = db.auth_admin_call(
            first_operation,
            "POST",
            &rotate_path,
            Some(json!({"expectedVersion":2})),
        ).await?;
        ensure!(replay.status == StatusCode::OK && replay.body == first.body,
            "same credential operation did not recover the original one-time response");
        let receipt_counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM auth_client_credentials WHERE client_id=$1), \
             (SELECT count(*) FROM identity_auth_command_receipts WHERE operation_id=$2)",
        ).bind(client_operation).bind(first_operation).fetch_one(&db.pool).await?;
        ensure!(receipt_counts == (1, 1), "credential replay created a second credential or receipt");

        let second_operation = Uuid::now_v7();
        sqlx::query("UPDATE auth_client_credentials SET created_at=clock_timestamp()-interval '90 days'+interval '2 hours' WHERE id=$1")
            .bind(first_operation).execute(&db.pool).await?;
        let second = db.auth_admin_call(
            second_operation,
            "POST",
            &rotate_path,
            Some(json!({"expectedVersion":3})),
        ).await?;
        ensure!(second.status == StatusCode::OK
            && second.body["credentialVersion"] == 2
            && second.body["previousCredentialExpiresAt"].is_string(),
            "second credential did not rotate with an explicit overlap window");
        let overlap_seconds: i64 = sqlx::query_scalar(
            "SELECT extract(epoch FROM expires_at-clock_timestamp())::bigint \
             FROM auth_client_credentials WHERE client_id=$1 AND expires_at IS NOT NULL AND revoked_at IS NULL",
        ).bind(client_operation).fetch_one(&db.pool).await?;
        ensure!((1..=86_400).contains(&overlap_seconds),
            "previous credential overlap exceeded the adopted 24-hour cap");
        let overlap: (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE revoked_at IS NULL AND expires_at IS NULL), \
             count(*) FILTER (WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())) \
             FROM auth_client_credentials WHERE client_id=$1",
        ).bind(client_operation).fetch_one(&db.pool).await?;
        ensure!(overlap == (1, 2), "old/new credential overlap is not one current plus one temporary credential");
        let capped:bool=sqlx::query_scalar("SELECT expires_at=created_at+interval '90 days' FROM auth_client_credentials WHERE id=$1")
            .bind(first_operation).fetch_one(&db.pool).await?;
        ensure!(capped,"old credential overlap extended its original 90-day absolute deadline");
        let new_deadline:chrono::DateTime<chrono::Utc>=sqlx::query_scalar("SELECT created_at+interval '90 days' FROM auth_client_credentials WHERE id=$1 AND expires_at IS NULL")
            .bind(second_operation).fetch_one(&db.pool).await?;
        ensure!(second.body["credentialExpiresAt"].as_str().and_then(|value|chrono::DateTime::parse_from_rfc3339(value).ok()).is_some_and(|value|value.with_timezone(&chrono::Utc)==new_deadline),
            "rotation response omitted or changed the new credential's fixed 90-day deadline");

        let revoke_operation = Uuid::now_v7();
        let revoke_path = format!("{path}/credentials/revoke");
        let revoked = db.auth_admin_call(
            revoke_operation,
            "POST",
            &revoke_path,
            Some(json!({"expectedVersion":4})),
        ).await?;
        ensure!(revoked.status == StatusCode::OK
            && revoked.body["revokedCredentials"] == 2
            && revoked.body["policyVersion"] == 3,
            "emergency revocation did not revoke the overlap or advance policy generation");
        let remains: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth_client_credentials WHERE client_id=$1 AND revoked_at IS NULL",
        ).bind(client_operation).fetch_one(&db.pool).await?;
        ensure!(remains == 0, "emergency credential revocation left an active secret");

        let public_operation = Uuid::now_v7();
        let mut public_input = user_input(Value::Null, "DISABLED");
        public_input["clientType"] = json!("PUBLIC");
        public_input["runtimeKind"] = json!("SPA");
        public_input["tokenEndpointAuthMethod"] = json!("none");
        public_input["grantTypes"] = json!(["authorization_code"]);
        let public_path = "/internal/identity/auth/clients";
        let public_client = db.auth_admin_call(
            public_operation,
            "POST",
            public_path,
            Some(public_input),
        ).await?;
        ensure!(public_client.status == StatusCode::OK,
            "valid public USER client was rejected");
        let public_rotate = db.auth_admin_call(
            Uuid::now_v7(),
            "POST",
            &format!("/internal/identity/auth/clients/{public_operation}/credentials"),
            Some(json!({"expectedVersion":1})),
        ).await?;
        ensure!(public_rotate.status == StatusCode::BAD_REQUEST,
            "public client was issued a shared secret");
        let leaked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM identity_auth_command_receipts WHERE result_json::text LIKE '%clientSecret%'",
        ).fetch_one(&db.pool).await?;
        ensure!(leaked == 0, "one-time client secret was persisted in an operation receipt");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase04_client_can_stop_after_application_scopes_are_withdrawn() -> Result<()> {
    let db = Database::create_phase04().await?;
    let result = async {
        let application = Uuid::now_v7();
        let resource = Uuid::now_v7();
        let openid = Uuid::now_v7();
        let profile = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_applications(application_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) VALUES($1,'FIRST_PARTY','APPROVED','Withdrawn app','Account login',ARRAY['openid','profile'],1,clock_timestamp())")
            .bind(application).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'userinfo','https://auth.saas.test/userinfo','ACTIVE',1)")
            .bind(resource).execute(&db.pool).await?;
        sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,'openid','ACTIVE'),($3,$2,'profile','ACTIVE')")
            .bind(openid).bind(resource).bind(profile).execute(&db.pool).await?;
        let client = Uuid::now_v7();
        let input = |expected_version: Value, status: &str| json!({
            "expectedVersion":expected_version,"applicationId":application,"environment":"test",
            "displayName":"Withdrawn client","clientType":"CONFIDENTIAL","runtimeKind":"WEB_BFF",
            "subjectMode":"USER","contextMode":"ACCOUNT_ONLY","allowedMemberTypes":[],
            "grantTypes":["authorization_code"],"tokenEndpointAuthMethod":"client_secret_basic",
            "redirectUris":["https://client.example.test/callback"],"postLogoutRedirectUris":[],
            "status":status,"consentGroupId":null,
            "permissions":[{"resourceKey":"userinfo","scopes":["openid"]}]
        });
        let created = db.auth_admin_call(client,"POST","/internal/identity/auth/clients",Some(input(Value::Null,"ENABLED"))).await?;
        ensure!(created.status == StatusCode::OK,"withdrawn-scope client fixture failed");
        sqlx::query("UPDATE auth_applications SET approved_scopes=ARRAY[]::text[],projection_version=projection_version+1 WHERE application_id=$1")
            .bind(application).execute(&db.pool).await?;
        let path = format!("/internal/identity/auth/clients/{client}");
        let mut expanded = input(json!(1),"DISABLED");
        expanded["permissions"][0]["scopes"] = json!(["openid","profile"]);
        let denied_expansion = db.auth_admin_call(Uuid::now_v7(),"PATCH",&path,Some(expanded)).await?;
        ensure!(denied_expansion.status == StatusCode::FORBIDDEN,
            "stopping a client allowed new withdrawn permissions");
        let mut redirected = input(json!(1),"DISABLED");
        redirected["redirectUris"] = json!(["https://other.example.test/callback"]);
        let denied_redirect = db.auth_admin_call(Uuid::now_v7(),"PATCH",&path,Some(redirected)).await?;
        ensure!(denied_redirect.status == StatusCode::FORBIDDEN,
            "stop-only exception allowed callback registration changes");
        let disabled = db.auth_admin_call(Uuid::now_v7(),"PATCH",&path,Some(input(json!(1),"DISABLED"))).await?;
        ensure!(disabled.status == StatusCode::OK && disabled.body["status"] == "DISABLED"
            && disabled.body["version"] == 2 && disabled.body["policyVersion"] == 2,
            "scope withdrawal prevented the client from being disabled");
        let denied_enable = db.auth_admin_call(Uuid::now_v7(),"PATCH",&path,Some(input(json!(2),"ENABLED"))).await?;
        ensure!(denied_enable.status == StatusCode::FORBIDDEN,
            "stop-only exception re-enabled a client with withdrawn permissions");
        let retired = db.auth_admin_call(Uuid::now_v7(),"PATCH",&path,Some(input(json!(2),"RETIRED"))).await?;
        ensure!(retired.status == StatusCode::OK && retired.body["status"] == "RETIRED"
            && retired.body["version"] == 3 && retired.body["policyVersion"] == 3,
            "scope withdrawal prevented the client from being retired");
        let permissions: Vec<Uuid> = sqlx::query_scalar("SELECT scope_id FROM auth_client_permissions WHERE client_id=$1")
            .bind(client).fetch_all(&db.pool).await?;
        ensure!(permissions == vec![openid],"stop-only update changed client permissions");
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase07_consent_groups_require_explicit_context_bound_membership() -> Result<()> {
    let db = Database::create_phase07().await?;
    let result = async {
        let application = Uuid::now_v7();
        let group_operation = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_applications(application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) VALUES($1,NULL,'FIRST_PARTY','APPROVED','Account app','Account sign-in',ARRAY['openid','profile'],1,clock_timestamp())")
            .bind(application).execute(&db.pool).await?;
        let group_input = json!({
            "applicationId":application,
            "environment":"PRODUCTION",
            "displayName":"Account browser clients",
            "purpose":"Account sign-in",
            "contextMode":"ACCOUNT_ONLY"
        });
        let path = "/internal/identity/auth/consent-groups";
        let created = db.auth_admin_call(group_operation,"POST",path,Some(group_input.clone())).await?;
        ensure!(created.status == StatusCode::OK
            && created.body["id"] == group_operation.to_string()
            && created.body["environment"] == "production"
            && created.body["subjectMode"] == "USER"
            && created.body["contextMode"] == "ACCOUNT_ONLY",
            "explicit consent group creation failed or lost identity boundaries");
        let replay = db.auth_admin_call(group_operation,"POST",path,Some(group_input)).await?;
        ensure!(replay.status == StatusCode::OK && replay.body == created.body,
            "group create operation did not replay the same receipt");

        let client = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,post_logout_redirect_uris,status,version,policy_version,created_at,updated_at) VALUES($1,$1,'Account web', $2,'production','CONFIDENTIAL','WEB_BFF','USER','ACCOUNT_ONLY',ARRAY[]::text[],ARRAY['authorization_code'],'client_secret_basic',ARRAY['https://client.example.test/callback'],ARRAY[]::text[],'DISABLED',1,1,clock_timestamp(),clock_timestamp())")
            .bind(client).bind(application).execute(&db.pool).await?;
        let member_path = format!("/internal/identity/auth/consent-groups/{group_operation}/clients");
        let member_body = json!({"clientId":client,"expectedGroupVersion":1});
        let member_operation = Uuid::now_v7();
        let attached = db.auth_admin_call(member_operation,"POST",&member_path,Some(member_body.clone())).await?;
        ensure!(attached.status == StatusCode::OK
            && attached.body["groupId"] == group_operation.to_string()
            && attached.body["clientId"] == client.to_string()
            && attached.body["version"] == 2,
            "matching USER client was not added to the explicit consent group");
        let attached_replay = db.auth_admin_call(member_operation,"POST",&member_path,Some(member_body)).await?;
        ensure!(attached_replay.status == StatusCode::OK && attached_replay.body == attached.body,
            "group membership operation replay was not idempotent");
        let stale = db.auth_admin_call(Uuid::now_v7(),"POST",&member_path,Some(json!({"clientId":client,"expectedGroupVersion":1}))).await?;
        ensure!(stale.status == StatusCode::CONFLICT,
            "stale group membership version did not conflict");

        let other_context = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,post_logout_redirect_uris,status,version,policy_version,created_at,updated_at) VALUES($1,$1,'Platform context', $2,'production','CONFIDENTIAL','WEB_BFF','USER','PLATFORM_CONTEXT',ARRAY['EMPLOYEE'],ARRAY['authorization_code'],'client_secret_basic',ARRAY['https://client.example.test/callback'],ARRAY[]::text[],'DISABLED',1,1,clock_timestamp(),clock_timestamp())")
            .bind(other_context).bind(application).execute(&db.pool).await?;
        let mismatch = db.auth_admin_call(Uuid::now_v7(),"POST",&member_path,Some(json!({"clientId":other_context,"expectedGroupVersion":2}))).await?;
        ensure!(mismatch.status == StatusCode::BAD_REQUEST,
            "ACCOUNT_ONLY consent group accepted a PLATFORM_CONTEXT client");

        let other_environment=Uuid::now_v7();
        sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,post_logout_redirect_uris,status,version,policy_version,created_at,updated_at) VALUES($1,$1,'Test client', $2,'test','CONFIDENTIAL','WEB_BFF','USER','ACCOUNT_ONLY',ARRAY[]::text[],ARRAY['authorization_code'],'client_secret_basic',ARRAY['https://client.example.test/callback'],ARRAY[]::text[],'DISABLED',1,1,clock_timestamp(),clock_timestamp())")
            .bind(other_environment).bind(application).execute(&db.pool).await?;
        let environment_mismatch = db.auth_admin_call(Uuid::now_v7(),"POST",&member_path,Some(json!({"clientId":other_environment,"expectedGroupVersion":2}))).await?;
        ensure!(environment_mismatch.status == StatusCode::BAD_REQUEST,
            "production consent group accepted a test client");

        let listed = db.auth_admin_call(Uuid::now_v7(),"GET",&format!("/internal/identity/auth/applications/{application}/consent-groups"),None).await?;
        ensure!(listed.status == StatusCode::OK
            && listed.body["groups"].as_array().is_some_and(|groups| groups.len()==1)
            && listed.body["groups"][0]["clients"].as_array().is_some_and(|clients| clients.len()==1),
            "group registry did not return its explicit client membership");
        let version: i64 = sqlx::query_scalar("SELECT version FROM auth_consent_groups WHERE id=$1").bind(group_operation).fetch_one(&db.pool).await?;
        let members: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_consent_group_clients WHERE group_id=$1").bind(group_operation).fetch_one(&db.pool).await?;
        ensure!((version,members)==(2,1),"idempotent group writes duplicated a member or version");
        Ok(())
    }
    .await;
    db.finish(result).await
}
