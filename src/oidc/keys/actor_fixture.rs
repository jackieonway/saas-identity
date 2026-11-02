//! Owner-seeded canonical source facts; no authorization predicate is replaced.
use super::pg_fixture::{Actor, ISSUER};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

struct Source {
    client: Uuid,
    grant: Uuid,
    sid: Uuid,
    digest: String,
    auth_time: i64,
    expires: DateTime<Utc>,
}

pub(super) async fn seed(pool: &PgPool) -> Result<Actor> {
    let actor = Actor {
        user: Uuid::now_v7(),
        tenant: Uuid::now_v7(),
        org: Uuid::now_v7(),
        session: Uuid::now_v7(),
        sso: Uuid::nil(),
        menu: Uuid::now_v7(),
        grant: Uuid::nil(),
    };
    let member = Uuid::now_v7();
    let application = Uuid::now_v7();
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO users(id,username,password_hash,session_version) VALUES($1,$2,'owned-unused-fixture',3)").bind(actor.user).bind(format!("phase23-{}",actor.user.simple())).execute(pool).await?;
    sqlx::query(
        "INSERT INTO tenants(id,name,code,is_platform) VALUES($1,'Phase23 owned root',$2,true)",
    )
    .bind(actor.tenant)
    .bind(format!("p23-{}", actor.tenant.simple()))
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO organizations(id,tenant_id,name) VALUES($1,$2,'Owned root')")
        .bind(actor.org)
        .bind(actor.tenant)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO memberships(id,user_id,organization_id,member_type,identity_version) VALUES($1,$2,$3,'EMPLOYEE',5)").bind(member).bind(actor.user).bind(actor.org).execute(pool).await?;
    sqlx::query("INSERT INTO applications(id,code,name) VALUES($1,'phase23-key-admin','Owned key management')").bind(application).execute(pool).await?;
    sqlx::query("INSERT INTO menus(id,application_id,title,permission) VALUES($1,$2,'Key management','system:oauth:keys')").bind(actor.menu).bind(application).execute(pool).await?;
    sqlx::query("INSERT INTO tenant_applications(tenant_id,application_id) VALUES($1,$2)")
        .bind(actor.tenant)
        .bind(application)
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO organization_applications(organization_id,application_id) VALUES($1,$2)",
    )
    .bind(actor.org)
    .bind(application)
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO tenant_menus(tenant_id,menu_id) VALUES($1,$2)")
        .bind(actor.tenant)
        .bind(actor.menu)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO organization_menus(organization_id,menu_id) VALUES($1,$2)")
        .bind(actor.org)
        .bind(actor.menu)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO roles(id,tenant_id,organization_id,name) VALUES($1,$2,$3,'Owned key operator')").bind(role).bind(actor.tenant).bind(actor.org).execute(pool).await?;
    sqlx::query("INSERT INTO user_roles(user_id,role_id,organization_id) VALUES($1,$2,$3)")
        .bind(actor.user)
        .bind(role)
        .bind(actor.org)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO role_menus(role_id,menu_id) VALUES($1,$2)")
        .bind(role)
        .bind(actor.menu)
        .execute(pool)
        .await?;
    let source = user_source(pool, actor.user, "EMPLOYEE").await?;
    let browser = Uuid::now_v7();
    let bff = Uuid::now_v7();
    let public_sid = source.digest;
    let public_sub = format!("owned-pairwise-{}", actor.user);
    sqlx::query("INSERT INTO auth_rp_sessions(grant_id,client_id,user_id,source_session_id,public_sid,public_sub) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(source.grant).bind(source.client).bind(actor.user).bind(source.sid).bind(&public_sid).bind(&public_sub).execute(pool).await?;
    sqlx::query("INSERT INTO platform_sessions(id,user_id,tenant_id,organization_id,expires_at,account_version,membership_id,member_type,identity_version,origin_issuer,origin_client_ref,origin_client_policy_version) VALUES($1,$2,$3,$4,clock_timestamp()+interval '30 minutes',3,$5,'EMPLOYEE',5,$6,$7,1)")
        .bind(actor.session).bind(actor.user).bind(actor.tenant).bind(actor.org).bind(member).bind(ISSUER).bind(source.client.to_string()).execute(pool).await?;
    sqlx::query("INSERT INTO console_browsers(id,token_hash,generation,current_session_id,created_at,expires_at) VALUES($1,$2,1,$3,clock_timestamp(),clock_timestamp()+interval '1 hour')")
        .bind(browser).bind(crate::util::hash::sha256_hex(&browser.to_string())).bind(bff).execute(pool).await?;
    sqlx::query("INSERT INTO bff_sessions(id,browser_id,token_hash,csrf_hash,user_id,account_version,global_session_id,oidc_client_id,oidc_grant_id,oidc_client_policy_version,issuer,auth_time,nonce_hash,access_ciphertext,refresh_ciphertext,access_expires_at,version,selected_session_id,created_at,expires_at,oidc_public_sid,oidc_public_sub) VALUES($1,$2,$3,$3,$4,3,$5,$6,$7,1,$8,$9,$3,'owned-fixture-only','owned-fixture-only',$10,1,$11,clock_timestamp(),clock_timestamp()+interval '30 minutes',$12,$13)")
        .bind(bff).bind(browser).bind(crate::util::hash::sha256_hex(&bff.to_string())).bind(actor.user).bind(source.sid).bind(source.client).bind(source.grant).bind(ISSUER).bind(source.auth_time).bind(source.expires).bind(actor.session).bind(public_sid).bind(public_sub).execute(pool).await?;
    sqlx::query("UPDATE platform_sessions SET bff_session_id=$1,bff_context_version=1 WHERE id=$2")
        .bind(bff)
        .bind(actor.session)
        .execute(pool)
        .await?;
    // These are explicit fixture facts, not evidence of real TOTP enrollment.
    sqlx::query("INSERT INTO auth_totp_factors(user_id,secret_ciphertext) VALUES($1,decode(repeat('ab',32),'hex'))").bind(actor.user).execute(pool).await?;
    sqlx::query(
        "UPDATE sso_sessions SET mfa_method='totp',mfa_verified_at=clock_timestamp() WHERE id=$1",
    )
    .bind(source.sid)
    .execute(pool)
    .await?;
    Ok(Actor {
        sso: source.sid,
        grant: source.grant,
        ..actor
    })
}

async fn user_source(pool: &PgPool, user: Uuid, member_type: &str) -> Result<Source> {
    let purpose = match member_type {
        "EMPLOYEE" => "PLATFORM_CONSOLE",
        "CUSTOMER" => "CUSTOMER_PORTAL",
        _ => {
            return Err(anyhow!(
                "owned source fixture requires one human member type"
            ))
        }
    };
    let app = Uuid::now_v7();
    let client = Uuid::now_v7();
    let resource = Uuid::now_v7();
    let scopes = [Uuid::now_v7(), Uuid::now_v7()];
    let group = Uuid::now_v7();
    let consent = Uuid::now_v7();
    let sid = Uuid::now_v7();
    let request = Uuid::now_v7();
    let context = Uuid::now_v7();
    let grant = Uuid::now_v7();
    let digest = crate::util::hash::sha256_hex(&Uuid::now_v7().to_string());
    sqlx::query("INSERT INTO auth_applications(application_id,ownership,status,display_name,purpose,approved_scopes) VALUES($1,'FIRST_PARTY','APPROVED','Owned canonical BFF',$2,ARRAY['openid','profile'])")
        .bind(app).bind(purpose).execute(pool).await?;
    sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,status) VALUES($1,$2,'Owned canonical BFF',$3,'test','CONFIDENTIAL','WEB_BFF','USER','PLATFORM_CONTEXT',ARRAY[$4],ARRAY['authorization_code','refresh_token'],'client_secret_basic',ARRAY['https://phase13.example.invalid/auth/callback'],'ENABLED')")
        .bind(client).bind(client.to_string()).bind(app).bind(member_type).execute(pool).await?;
    let audience = format!("https://phase13.example.invalid/userinfo/{resource}");
    // The BFF proof deliberately requires the one canonical userinfo resource.
    let actual_resource: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM auth_resources WHERE resource_key='userinfo'")
            .fetch_optional(pool)
            .await?;
    let resource = if let Some(existing) = actual_resource {
        existing
    } else {
        sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status) VALUES($1,'userinfo',$2,'ACTIVE')")
            .bind(resource).bind(&audience).execute(pool).await?;
        resource
    };
    let audience: String = sqlx::query_scalar("SELECT audience FROM auth_resources WHERE id=$1")
        .bind(resource)
        .fetch_one(pool)
        .await?;
    let mut actual_scopes = Vec::new();
    for (scope, name) in scopes.into_iter().zip(["openid", "profile"]) {
        let existing: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM auth_scopes WHERE resource_id=$1 AND scope_name=$2")
                .bind(resource)
                .bind(name)
                .fetch_optional(pool)
                .await?;
        let scope = if let Some(existing) = existing {
            existing
        } else {
            sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,$3,'ACTIVE')").bind(scope).bind(resource).bind(name).execute(pool).await?;
            scope
        };
        actual_scopes.push(scope);
        sqlx::query(
            "INSERT INTO auth_client_permissions(client_id,resource_id,scope_id) VALUES($1,$2,$3)",
        )
        .bind(client)
        .bind(resource)
        .bind(scope)
        .execute(pool)
        .await?;
    }
    sqlx::query("INSERT INTO auth_consent_groups(id,application_id,environment,display_name,purpose,context_mode,status) VALUES($1,$2,'test','Owned BFF consent',$3,'PLATFORM_CONTEXT','ACTIVE')")
        .bind(group).bind(app).bind(purpose).execute(pool).await?;
    sqlx::query("INSERT INTO auth_consent_group_clients(group_id,client_id,application_id,environment,context_mode) VALUES($1,$2,$3,'test','PLATFORM_CONTEXT')")
        .bind(group).bind(client).bind(app).execute(pool).await?;
    sqlx::query("INSERT INTO auth_consents(id,user_id,group_id,status,authorized_at) VALUES($1,$2,$3,'ACTIVE',clock_timestamp())")
        .bind(consent).bind(user).bind(group).execute(pool).await?;
    for scope in &actual_scopes {
        sqlx::query(
            "INSERT INTO auth_consent_scopes(consent_id,resource_id,scope_id) VALUES($1,$2,$3)",
        )
        .bind(consent)
        .bind(resource)
        .bind(scope)
        .execute(pool)
        .await?;
    }
    sqlx::query("INSERT INTO sso_sessions(id,user_id,token_hash,csrf_hash,account_version,authenticated_at,expires_at) VALUES($1,$2,$3,$4,3,date_trunc('second',clock_timestamp()),clock_timestamp()+interval '1 hour')")
        .bind(sid).bind(user).bind(crate::util::hash::sha256_hex(&sid.to_string())).bind(crate::util::hash::sha256_hex(&format!("csrf-{sid}"))).execute(pool).await?;
    sqlx::query("INSERT INTO auth_authorization_requests(id,client_id,user_id,source_session_id,account_version,auth_time,client_policy_version,application_projection_version,redirect_uri,state_digest,state_value,nonce_digest,nonce_value,code_challenge,code_challenge_method,scope_ids,browser_digest,csrf_digest,status,expires_at,consumed_at) SELECT $1,$2,$3,$4,3,s.authenticated_at,1,1,'https://phase13.example.invalid/auth/callback',repeat('a',64),'owned-state',repeat('b',64),'owned-nonce',repeat('c',43),'S256',$5,repeat('d',64),repeat('e',64),'CONSUMED',clock_timestamp()+interval '5 minutes',clock_timestamp() FROM sso_sessions s WHERE s.id=$4")
        .bind(request).bind(client).bind(user).bind(sid).bind(&actual_scopes).execute(pool).await?;
    let member: Uuid = sqlx::query_scalar(
        "SELECT id FROM memberships WHERE user_id=$1 AND member_type=$2 ORDER BY id LIMIT 1",
    )
    .bind(user)
    .bind(member_type)
    .fetch_one(pool)
    .await?;
    sqlx::query("INSERT INTO auth_context_interactions(transaction_id,request_hash,client_id,client_policy_version,application_id,application_projection_version,redirect_uri,state_digest,nonce_digest,code_challenge,intent,authorization_request_id,source_digest,selected_membership_id,credential_ciphertext,selection_expires_at,expires_at) VALUES($1,$2,$3,1,$4,1,'https://phase13.example.invalid/auth/callback',repeat('a',64),repeat('b',64),repeat('c',43),'{\"kind\":\"LOGIN\"}',$5,$6,$7,'owned-fixture-ciphertext',clock_timestamp()+interval '2 minutes',clock_timestamp()+interval '5 minutes')")
        .bind(context).bind(crate::util::hash::sha256_hex(&context.to_string())).bind(client).bind(app).bind(request).bind(&digest).bind(member).execute(pool).await?;
    sqlx::query("INSERT INTO auth_grants(id,client_id,subject_mode,user_id,consent_id,consent_generation,consent_group_version,source_session_id,context_mode,context_ref,account_version,client_policy_version,application_projection_version,scope_ids,audiences,auth_time,expires_at) SELECT $1,$2,'USER',$3,$4,1,1,$5,'PLATFORM_CONTEXT',$6,3,1,1,$7,ARRAY[$8],s.authenticated_at,clock_timestamp()+interval '30 minutes' FROM sso_sessions s WHERE s.id=$5")
        .bind(grant).bind(client).bind(user).bind(consent).bind(sid).bind(context).bind(&actual_scopes).bind(&audience).execute(pool).await?;
    sqlx::query("UPDATE auth_context_interactions SET grant_id=$2,delivered_at=clock_timestamp(),credential_ciphertext=NULL WHERE transaction_id=$1")
        .bind(context).bind(grant).execute(pool).await?;
    for scope in &actual_scopes {
        sqlx::query(
            "INSERT INTO auth_grant_scopes(grant_id,resource_id,scope_id) VALUES($1,$2,$3)",
        )
        .bind(grant)
        .bind(resource)
        .bind(scope)
        .execute(pool)
        .await?;
    }
    sqlx::query("INSERT INTO auth_refresh_families(id,grant_id,absolute_expires_at,idle_expires_at) VALUES($1,$2,clock_timestamp()+interval '30 minutes',clock_timestamp()+interval '20 minutes')")
        .bind(Uuid::now_v7()).bind(grant).execute(pool).await?;
    let access = Uuid::now_v7();
    sqlx::query("INSERT INTO auth_access_tokens(id,grant_id,token_digest,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '5 minutes')").bind(access).bind(grant).bind(&digest).execute(pool).await?;
    for scope in &actual_scopes {
        sqlx::query(
            "INSERT INTO auth_access_token_scopes(token_id,resource_id,scope_id) VALUES($1,$2,$3)",
        )
        .bind(access)
        .bind(resource)
        .bind(scope)
        .execute(pool)
        .await?;
    }
    let (auth_time, expires): (i64, DateTime<Utc>) = sqlx::query_as("SELECT floor(extract(epoch FROM g.auth_time))::bigint,LEAST(tok.expires_at,g.expires_at,s.expires_at) FROM auth_access_tokens tok JOIN auth_grants g ON g.id=tok.grant_id JOIN sso_sessions s ON s.id=g.source_session_id WHERE tok.id=$1").bind(access).fetch_one(pool).await?;
    Ok(Source {
        client,
        grant,
        sid,
        digest,
        auth_time,
        expires,
    })
}
