//! Canonical PostgreSQL and real private/public HTTP handlers. Platform actor
//! authority and the approved review snapshot are explicit scoped fixtures;
//! actual business roles, TOTP and release facts are tested by the platform.

use super::*;
use anyhow::{anyhow, ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    middleware,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
};
use tower::ServiceExt;

const SCHEMA: &str = include_str!("../../../saas-plateform/backend/migrations/0001_init.sql");

struct Database {
    pool: PgPool,
    admin: PgPool,
    name: String,
    url: String,
    actor: Uuid,
    session: Uuid,
    review_service: Uuid,
    admin_service: Uuid,
}

#[tokio::test]
#[ignore = "requires explicit task-owned Phase19 PostgreSQL"]
async fn phase19_auth_client_list_query_passes_private_guard_without_opening_other_routes(
) -> Result<()> {
    let db = Database::new().await?;
    let result = async {
        let application = Uuid::now_v7();
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_applications(application_id,ownership,status,display_name,purpose,approved_scopes) VALUES($1,'FIRST_PARTY','APPROVED','Guarded list fixture','Account login',ARRAY['openid','profile'])")
            .bind(application).execute(&db.pool).await?;
        for (client, age) in [(first, 2_i64), (second, 1_i64)] {
            sqlx::query("INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,post_logout_redirect_uris,status,created_at) VALUES($1,$1,'Guarded list client',$2,'test','PUBLIC','SPA','USER','ACCOUNT_ONLY',ARRAY[]::text[],ARRAY['authorization_code'],'none',ARRAY['https://client.example.test/callback'],ARRAY[]::text[],'DISABLED',clock_timestamp()-$3*interval '1 second')")
                .bind(client).bind(application).bind(age).execute(&db.pool).await?;
        }
        async fn request(db: &Database, method: &str, path: &str, body: Option<&Value>, operation: Option<Uuid>) -> Result<(StatusCode,Value)> {
            let state = db.state()?;
            let mut request = Request::builder().method(method).uri(path).header(
                header::AUTHORIZATION,format!("Basic {}",STANDARD.encode(format!("{}:{}",db.admin_service,"e".repeat(64)))));
            if let Some(operation) = operation {
                request = request.header("x-identity-operation",operation.to_string())
                    .header("x-identity-operation-digest",digest(method,path.split('?').next().unwrap(),body.unwrap_or(&Value::Null))?);
            }
            let bytes = if let Some(body) = body {
                request = request.header(header::CONTENT_TYPE,"application/json");
                serde_json::to_vec(body)?
            } else { Vec::new() };
            let response = crate::internal::routes().layer(middleware::from_fn_with_state(state.clone(),internal::guard))
                .with_state(state).oneshot(request.body(Body::from(bytes))?).await?;
            let status = response.status();
            ensure!(response.headers().get(header::CACHE_CONTROL).is_some_and(|value|value=="no-store"),"private query response lost no-store");
            let bytes = to_bytes(response.into_body(),65_536).await?;
            // Axum's strict Query extractor returns text for malformed input.
            // Error text is irrelevant to this HTTP boundary regression.
            let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            Ok((status,value))
        }
        let filters = format!("applicationId={application}&ownership=FIRST_PARTY&clientType=PUBLIC&subjectMode=USER&environment=test&status=DISABLED&limit=1");
        for (offset,expected) in [(0,second),(1,first)] {
            let (status,page) = request(&db,"GET",&format!("/internal/identity/auth/clients?{filters}&offset={offset}"),None,None).await?;
            ensure!(status==StatusCode::OK && page["page"]["total"]==2 && page["page"]["limit"]==1
                && page["page"]["offset"]==offset && page["records"].as_array().is_some_and(|rows|rows.len()==1)
                && page["records"][0]["id"]==expected.to_string(),"valid filtered pagination was rejected or returned the wrong page through the private guard");
        }
        let (status,empty) = request(&db,"GET",&format!("/internal/identity/auth/clients?applicationId={application}&status=ENABLED&limit=10&offset=0"),None,None).await?;
        ensure!(status==StatusCode::OK && empty["page"]["total"]==0 && empty["records"].as_array().is_some_and(Vec::is_empty),"client status filter did not reach the handler");
        for query in ["unexpected=true","limit=0","limit=101","limit=invalid","limit=1&limit=2","offset=-1","offset=100001","ownership=INVALID"] {
            let (status,_) = request(&db,"GET",&format!("/internal/identity/auth/clients?{query}"),None,None).await?;
            ensure!(status==StatusCode::BAD_REQUEST,"unknown or invalid client-list query was accepted");
        }
        let body = json!({"expectedVersion":null,"applicationId":application,"environment":"test",
            "displayName":"Guarded mutation","clientType":"PUBLIC","runtimeKind":"SPA","subjectMode":"USER",
            "contextMode":"ACCOUNT_ONLY","allowedMemberTypes":[],"grantTypes":["authorization_code"],
            "tokenEndpointAuthMethod":"none","redirectUris":["https://client.example.test/callback"],
            "postLogoutRedirectUris":[],"status":"DISABLED","consentGroupId":null,
            "permissions":[{"resourceKey":"userinfo","scopes":["openid"]}]});
        let operation = Uuid::now_v7();
        db.accept(operation,"AUTH_ADMIN","POST","/internal/identity/auth/clients",&body).await?;
        let (status,error) = request(&db,"POST","/internal/identity/auth/clients?limit=1",Some(&body),Some(operation)).await?;
        ensure!(status==StatusCode::BAD_REQUEST && error["message"]=="内部端口不接受Cookie或查询参数","non-GET query escaped the private guard");
        let clients:i64=sqlx::query_scalar("SELECT count(*) FROM auth_clients WHERE application_id=$1").bind(application).fetch_one(&db.pool).await?;
        let receipts:i64=sqlx::query_scalar("SELECT count(*) FROM identity_auth_command_receipts WHERE operation_id=$1").bind(operation).fetch_one(&db.pool).await?;
        ensure!(clients==2 && receipts==0,"query-bearing mutation changed a client or receipt");
        for method in ["HEAD","PUT","PATCH","DELETE"] {
            let (status,_) = request(&db,method,"/internal/identity/auth/clients?limit=1",None,None).await?;
            ensure!(status==StatusCode::BAD_REQUEST,"non-GET client-list query escaped the private guard");
        }
        for path in [format!("/internal/identity/auth/clients/{first}?limit=1"),"/internal/identity/auth/unknown?limit=1".into()] {
            let (status,error)=request(&db,"GET",&path,None,None).await?;
            ensure!(status==StatusCode::BAD_REQUEST && error["message"]=="内部端口不接受Cookie或查询参数","query allowlist expanded beyond the exact client-list path");
        }
        Ok(())
    }.await;
    db.finish(result).await
}

impl Database {
    async fn new() -> Result<Self> {
        let url = std::env::var("IDENTITY_PHASE19_TEST_DATABASE_URL")
            .map_err(|_| anyhow!("explicit IDENTITY_PHASE19_TEST_DATABASE_URL required"))?;
        let options = PgConnectOptions::from_str(&url)?;
        ensure!(
            options.get_database() == Some("postgres")
                && matches!(options.get_host(), "localhost" | "127.0.0.1" | "::1"),
            "owned loopback administration database required"
        );
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await?;
        let cluster: String =
            sqlx::query_scalar("SELECT system_identifier::text FROM pg_control_system()")
                .fetch_one(&admin)
                .await?;
        ensure!(
            cluster
                == std::env::var("IDENTITY_PHASE19_TEST_CLUSTER_ID")
                    .map_err(|_| anyhow!("explicit IDENTITY_PHASE19_TEST_CLUSTER_ID required"))?,
            "wrong task-owned review cluster"
        );
        let name = format!("identity_phase19_review_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await?;
        let pool = match PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options.database(&name))
            .await
        {
            Ok(pool) => pool,
            Err(error) => {
                sqlx::query(&format!("DROP DATABASE \"{name}\" WITH(FORCE)"))
                    .execute(&admin)
                    .await?;
                return Err(error.into());
            }
        };
        let db = Self {
            pool,
            admin,
            name,
            url,
            actor: Uuid::now_v7(),
            session: Uuid::now_v7(),
            review_service: Uuid::now_v7(),
            admin_service: Uuid::now_v7(),
        };
        let initialized=async {
            sqlx::raw_sql(SCHEMA).execute(&db.pool).await?;
            for (service,purpose,secret) in [(db.review_service,PURPOSE,"d".repeat(64)),(db.admin_service,"AUTH_ADMIN","e".repeat(64))] {
                sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,created_at) VALUES($1,$2,$3,'ENABLED',clock_timestamp())")
                    .bind(service).bind(crate::util::hash::sha256_hex(&secret)).bind(purpose).execute(&db.pool).await?;
            }
            sqlx::raw_sql("CREATE TABLE public.phase19_review_actor(actor uuid NOT NULL,session uuid NOT NULL); CREATE TABLE public.phase19_review_snapshots(operation uuid PRIMARY KEY,body jsonb NOT NULL,authorized boolean NOT NULL DEFAULT true);").execute(&db.pool).await?;
            sqlx::query("INSERT INTO public.phase19_review_actor VALUES($1,$2)").bind(db.actor).bind(db.session).execute(&db.pool).await?;
            sqlx::raw_sql("CREATE OR REPLACE FUNCTION public.platform_identity_management_actor_active(actor_ref uuid,session_ref uuid,permission_ref text,require_recent boolean,production boolean) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog,public AS $$ SELECT $3=ANY(ARRAY['system:oauth:review','system:oauth:publish','system:oauth:register','system:oauth:disable']::text[]) AND $4 AND NOT $5 AND EXISTS(SELECT 1 FROM public.phase19_review_actor WHERE actor=$1 AND session=$2) $$;").execute(&db.pool).await?;
            sqlx::raw_sql("CREATE OR REPLACE FUNCTION public.identity_auth_review_intent_active(operation_ref uuid,service_ref uuid,digest_ref text,method_ref text,path_ref text,body_ref jsonb) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog,public AS $$ SELECT public.identity_auth_command_intent_active($1,$2,$3,$4,$5) AND EXISTS(SELECT 1 FROM public.phase19_review_snapshots approved JOIN public.platform_auth_command_intents intent ON intent.id=approved.operation WHERE approved.operation=$1 AND approved.authorized AND approved.body=$6 AND intent.service_client_id=$2 AND intent.request_digest=$3 AND intent.method=$4 AND intent.path=$5 AND intent.actor_user_id=($6->>'actorUserId')::uuid AND intent.session_id=($6->>'actorSessionId')::uuid AND intent.management_permission=CASE WHEN $6->>'status'='SUSPENDED' THEN 'system:oauth:disable' WHEN $6->>'environment'='production' THEN 'system:oauth:publish' ELSE 'system:oauth:review' END) $$;").execute(&db.pool).await?;
            let resource=Uuid::now_v7();
            sqlx::query("INSERT INTO auth_resources(id,resource_key,audience,status,version) VALUES($1,'userinfo','https://auth.saas.test/oauth/userinfo','ACTIVE',1)").bind(resource).execute(&db.pool).await?;
            sqlx::query("INSERT INTO auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,'openid','ACTIVE'),($3,$2,'profile','ACTIVE')")
                .bind(Uuid::now_v7()).bind(resource).bind(Uuid::now_v7()).execute(&db.pool).await?;
            sqlx::query("INSERT INTO auth_provider_settings(singleton,issuer,created_at) VALUES(true,'https://auth.saas.test',clock_timestamp())").execute(&db.pool).await?;
            Ok::<(),anyhow::Error>(())
        }.await;
        if let Err(error) = initialized {
            return Err(match db.finish(Err(error)).await {
                Err(error) => error,
                Ok(()) => anyhow!("review initialization unexpectedly succeeded"),
            });
        }
        Ok(db)
    }

    fn state(&self) -> Result<AppState> {
        let mut config = crate::config::Config::from_values(&HashMap::from([
            ("APP_ENV".into(), "test".into()),
            ("DATABASE_URL".into(), self.url.clone()),
        ]))?;
        config.sso_enabled = true;
        config.oidc_enabled = true;
        config.sso_origin = Some("https://auth.saas.test".into());
        config.oidc_issuer = Some("https://auth.saas.test".into());
        Ok(AppState::new(self.pool.clone(), Arc::new(config)))
    }

    fn body(&self, application: Uuid, partner: Uuid) -> Value {
        let contact = Uuid::now_v7();
        let domain = Uuid::now_v7();
        json!({"applicationId":application,"environment":"test","requestId":Uuid::now_v7(),"requestVersion":1,
            "actorUserId":self.actor,"actorSessionId":self.session,"expectedProjectionVersion":null,"expectedAdmissionVersion":null,"partnerId":partner,
            "manifest":{"displayName":"Reviewed partner","purpose":"Independent account login","privacyUrl":"https://partner.example.test/privacy","domains":["partner.example.test"],"redirectUris":["https://partner.example.test/callback"],"postLogoutRedirectUris":["https://partner.example.test/bye"],"scopes":["openid","profile"],"contactReference":contact,"domainEvidenceReference":domain,"logoutMode":"SHORT_SESSION_ONLINE_CHECK"},
            "requestedBy":Uuid::now_v7(),"reviewedBy":self.actor,"publishedBy":null,"contactReference":contact,"domainReference":domain,"status":"APPROVED"})
    }

    async fn accept(
        &self,
        operation: Uuid,
        purpose: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<()> {
        let service = if purpose == PURPOSE {
            self.review_service
        } else {
            self.admin_service
        };
        let permission = if purpose == PURPOSE {
            if body["status"] == "SUSPENDED" {
                "system:oauth:disable"
            } else if body["environment"] == "production" {
                "system:oauth:publish"
            } else {
                "system:oauth:review"
            }
        } else if method == "PATCH" {
            "system:oauth:disable"
        } else {
            "system:oauth:register"
        };
        sqlx::query("INSERT INTO platform_auth_command_intents(id,actor_user_id,tenant_id,organization_id,session_id,service_client_id,request_digest,method,path,accepted_at,management_permission) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp(),$10) ON CONFLICT(id) DO NOTHING")
            .bind(operation).bind(self.actor).bind(Uuid::now_v7()).bind(Uuid::now_v7()).bind(self.session).bind(service).bind(digest(method,path,body)?).bind(method).bind(path).bind(permission).execute(&self.pool).await?;
        if purpose == PURPOSE {
            sqlx::query("INSERT INTO public.phase19_review_snapshots(operation,body) VALUES($1,$2) ON CONFLICT(operation) DO NOTHING").bind(operation).bind(body).execute(&self.pool).await?;
        }
        Ok(())
    }

    async fn call(
        &self,
        purpose: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
        operation: Option<Uuid>,
    ) -> Result<(StatusCode, Value)> {
        let (service, secret) = if purpose == PURPOSE {
            (self.review_service, "d".repeat(64))
        } else {
            (self.admin_service, "e".repeat(64))
        };
        let mut request = Request::builder().method(method).uri(path).header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{service}:{secret}"))),
        );
        if let Some(operation) = operation {
            request = request
                .header("x-identity-operation", operation.to_string())
                .header(
                    "x-identity-operation-digest",
                    digest(method, path, body.unwrap_or(&Value::Null))?,
                );
        }
        let raw = if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json");
            serde_json::to_vec(body)?
        } else {
            Vec::new()
        };
        let state = self.state()?;
        let response = crate::oidc::routes()
            .merge(crate::internal::routes())
            .layer(middleware::from_fn_with_state(
                state.clone(),
                internal::guard,
            ))
            .with_state(state)
            .oneshot(request.body(Body::from(raw))?)
            .await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 65_536).await?;
        Ok((
            status,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes)?
            },
        ))
    }

    async fn put(&self, body: &Value) -> Result<(StatusCode, Value)> {
        let path = format!(
            "{PREFIX}/{}/{}",
            body["applicationId"].as_str().unwrap(),
            body["environment"].as_str().unwrap()
        );
        let operation = Uuid::now_v7();
        self.accept(operation, PURPOSE, "PUT", &path, body).await?;
        self.call(PURPOSE, "PUT", &path, Some(body), Some(operation))
            .await
    }

    async fn finish(self, result: Result<()>) -> Result<()> {
        self.pool.close().await;
        ensure!(
            self.name.starts_with("identity_phase19_review_")
                && self.name.len() <= 63
                && self
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
            "unsafe owned review cleanup target"
        );
        sqlx::query(&format!("DROP DATABASE \"{}\" WITH(FORCE)", self.name))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        eprintln!(
            "identity_review_test_cleanup database={} removed=true assertions_ok={}",
            self.name,
            result.is_ok()
        );
        result
    }
}

fn digest(method: &str, path: &str, body: &Value) -> Result<String> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), sorted(value)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            value => value.clone(),
        }
    }
    Ok(crate::util::hash::sha256_hex(&serde_json::to_string(
        &sorted(&json!({"method":method,"path":path,"body":body})),
    )?))
}

fn registration(application: Uuid) -> Value {
    json!({"expectedVersion":null,"applicationId":application,"environment":"test","displayName":"Partner browser","clientType":"PUBLIC","runtimeKind":"SPA","subjectMode":"USER","contextMode":"ACCOUNT_ONLY","allowedMemberTypes":[],"grantTypes":["authorization_code"],"tokenEndpointAuthMethod":"none","redirectUris":["https://partner.example.test/callback"],"postLogoutRedirectUris":["https://partner.example.test/bye"],"status":"ENABLED","consentGroupId":null,"permissions":[{"resourceKey":"userinfo","scopes":["openid"]}]})
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE19_TEST_DATABASE_URL/CLUSTER_ID"]
async fn phase19_review_projection_is_versioned_private_and_source_snapshot_bound() -> Result<()> {
    let db = Database::new().await?;
    let result=async {
        let application=Uuid::now_v7();let partner=Uuid::now_v7();let body=db.body(application,partner);let path=format!("{PREFIX}/{application}/test");
        let (status,initial)=db.call(PURPOSE,"GET",&path,None,None).await?;
        ensure!(status==StatusCode::OK&&initial["status"]=="UNREGISTERED"&&initial["projectionVersion"].is_null(),"unregistered review metadata was fabricated");
        let (status,_)=db.call("AUTH_ADMIN","PUT",&path,Some(&body),None).await?;
        ensure!(status==StatusCode::FORBIDDEN,"client administrator credential approved a third-party application");
        let operation=Uuid::now_v7();db.accept(operation,PURPOSE,"PUT",&path,&body).await?;
        let (status,created)=db.call(PURPOSE,"PUT",&path,Some(&body),Some(operation)).await?;
        ensure!(status==StatusCode::OK&&created["projectionVersion"]==1&&created["admissionVersion"]==1,"approved review did not create versioned projection/admission");
        let (status,replay)=db.call(PURPOSE,"PUT",&path,Some(&body),Some(operation)).await?;
        ensure!(status==StatusCode::OK&&replay==created,"review operation replay duplicated its result");
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM identity_auth_command_receipts WHERE operation_id=$1").bind(operation).fetch_one(&db.pool).await?;
        ensure!(count==1,"review replay duplicated receipts");
        let mut update=body.clone();update["expectedProjectionVersion"]=json!(1);update["expectedAdmissionVersion"]=json!(1);update["requestVersion"]=json!(2);
        let invalid_operation=Uuid::now_v7();db.accept(invalid_operation,PURPOSE,"PUT",&path,&update).await?;
        sqlx::query("UPDATE public.phase19_review_snapshots SET body=jsonb_set(body,'{manifest,purpose}','\"Other approved purpose\"'::jsonb) WHERE operation=$1").bind(invalid_operation).execute(&db.pool).await?;
        let (status,_)=db.call(PURPOSE,"PUT",&path,Some(&update),Some(invalid_operation)).await?;
        ensure!(status==StatusCode::FORBIDDEN,"identity accepted a manifest different from the platform-approved snapshot");
        let mut transferred=update.clone();transferred["partnerId"]=json!(Uuid::now_v7());
        let (status,_)=db.put(&transferred).await?;ensure!(status==StatusCode::CONFLICT,"review transferred the existing application to another partner");
        let mut production=update.clone();production["environment"]=json!("production");production["expectedAdmissionVersion"]=Value::Null;
        let (status,_)=db.put(&production).await?;ensure!(status==StatusCode::FORBIDDEN,"production approval had no independent publisher");
        production["publishedBy"]=production["requestedBy"].clone();
        let (status,_)=db.put(&production).await?;ensure!(status==StatusCode::FORBIDDEN,"applicant self-published the production admission");
        let mut bad_domain=update.clone();bad_domain["manifest"]["redirectUris"]=json!(["https://foreign.example.test/callback"]);
        let (status,_)=db.put(&bad_domain).await?;ensure!(status==StatusCode::BAD_REQUEST,"unreviewed callback domain was accepted");
        let mut bad_scope=update.clone();bad_scope["manifest"]["scopes"]=json!(["openid","offline_access"]);
        let (status,_)=db.put(&bad_scope).await?;ensure!(status==StatusCode::BAD_REQUEST,"third-party review enabled offline or business scope");
        let mut self_approved=update.clone();self_approved["reviewedBy"]=self_approved["requestedBy"].clone();
        let (status,_)=db.put(&self_approved).await?;ensure!(status==StatusCode::FORBIDDEN,"applicant self-reviewed");
        sqlx::raw_sql("CREATE FUNCTION public.phase19_suppress_review_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='AUTH_APPLICATION_REVIEW_SYNC' THEN RETURN NULL; END IF; RETURN NEW; END $$; CREATE TRIGGER phase19_suppress_review_audit BEFORE INSERT ON identity_audit_logs FOR EACH ROW EXECUTE FUNCTION public.phase19_suppress_review_audit();").execute(&db.pool).await?;
        let (status,_)=db.put(&update).await?;ensure!(status==StatusCode::SERVICE_UNAVAILABLE,"suppressed review audit did not fail closed");
        let versions:(i64,i64)=sqlx::query_as("SELECT p.projection_version,a.version FROM auth_applications p JOIN auth_application_admissions a USING(application_id) WHERE p.application_id=$1 AND a.environment='test'").bind(application).fetch_one(&db.pool).await?;
        ensure!(versions==(1,1),"review audit failure committed partial version changes");
        sqlx::query("DROP TRIGGER phase19_suppress_review_audit ON identity_audit_logs").execute(&db.pool).await?;
        update["status"]=json!("SUSPENDED");let (status,suspended)=db.put(&update).await?;
        ensure!(status==StatusCode::OK&&suspended["projectionVersion"]==2&&suspended["admissionVersion"]==2,"suspension did not invalidate the previous application generation");
        let (status,_)=db.put(&update).await?;ensure!(status==StatusCode::CONFLICT,"stale reviewed application version was overwritten");
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE19_TEST_DATABASE_URL/CLUSTER_ID"]
async fn phase19_third_party_client_registration_and_runtime_require_current_environment_admission(
) -> Result<()> {
    let db = Database::new().await?;
    let result=async {
        let application=Uuid::now_v7();let body=db.body(application,Uuid::now_v7());let (status,_)=db.put(&body).await?;ensure!(status==StatusCode::OK,"review fixture failed");
        let client_path="/internal/identity/auth/clients";
        let create=registration(application);let client=Uuid::now_v7();db.accept(client,"AUTH_ADMIN","POST",client_path,&create).await?;
        let (status,created)=db.call("AUTH_ADMIN","POST",client_path,Some(&create),Some(client)).await?;
        ensure!(status==StatusCode::OK&&created["ownership"]=="THIRD_PARTY","approved ACCOUNT_ONLY partner client was rejected");
        for field in ["redirectUris","postLogoutRedirectUris"] {
            let mut escaped=create.clone();escaped[field]=json!(["https://foreign.example.test/callback"]);let operation=Uuid::now_v7();db.accept(operation,"AUTH_ADMIN","POST",client_path,&escaped).await?;
            let (status,_)=db.call("AUTH_ADMIN","POST",client_path,Some(&escaped),Some(operation)).await?;ensure!(status==StatusCode::FORBIDDEN,"client registered a callback outside the approved manifest");
        }
        let mut production=create.clone();production["environment"]=json!("production");let operation=Uuid::now_v7();db.accept(operation,"AUTH_ADMIN","POST",client_path,&production).await?;
        let (status,_)=db.call("AUTH_ADMIN","POST",client_path,Some(&production),Some(operation)).await?;ensure!(status==StatusCode::FORBIDDEN,"test approval registered a production client");
        let mut context=create.clone();context["clientType"]=json!("CONFIDENTIAL");context["runtimeKind"]=json!("WEB_BFF");context["tokenEndpointAuthMethod"]=json!("client_secret_basic");context["contextMode"]=json!("PLATFORM_CONTEXT");context["allowedMemberTypes"]=json!(["EMPLOYEE"]);let operation=Uuid::now_v7();db.accept(operation,"AUTH_ADMIN","POST",client_path,&context).await?;
        let (status,_)=db.call("AUTH_ADMIN","POST",client_path,Some(&context),Some(operation)).await?;ensure!(status==StatusCode::FORBIDDEN,"partner acquired platform employee context");
        let state=db.state()?;
        let mut url=reqwest::Url::parse("https://auth.saas.test/oauth/authorize")?;
        url.query_pairs_mut().append_pair("client_id",&client.to_string()).append_pair("redirect_uri","https://partner.example.test/callback").append_pair("response_type","code").append_pair("scope","openid").append_pair("state",&"s".repeat(32)).append_pair("nonce",&"n".repeat(32)).append_pair("code_challenge",&"a".repeat(43)).append_pair("code_challenge_method","S256");
        let authorize_path=format!("{}?{}",url.path(),url.query().unwrap());
        let response=crate::oidc::routes().with_state(state.clone()).oneshot(Request::get(&authorize_path).body(Body::empty())?).await?;
        let login=response.headers().get(header::LOCATION).and_then(|value|value.to_str().ok()).ok_or_else(||anyhow!("approved client did not begin a login flow"))?.to_owned();
        ensure!(response.status().is_redirection()&&login.starts_with("/oauth/login?flow="),"approved third-party registration did not reach real authorization processing");
        let browser=response.headers().get(header::SET_COOKIE).and_then(|value|value.to_str().ok()).and_then(|cookie|cookie.split(';').next()).ok_or_else(||anyhow!("approved flow browser binding missing"))?.to_owned();
        let flow=login.strip_prefix("/oauth/login?flow=").ok_or_else(||anyhow!("invalid fixture login flow"))?;
        // Exercise both external-name and internal-id client loading after a
        // manifest is closed. Neither path may issue an authorization code.
        sqlx::query("UPDATE auth_application_admissions SET status='SUSPENDED' WHERE application_id=$1 AND environment='test'").bind(application).execute(&db.pool).await?;
        let response=crate::oidc::routes().with_state(state.clone()).oneshot(Request::get(&authorize_path).body(Body::empty())?).await?;
        let rejected=response.headers().get(header::LOCATION).and_then(|value|value.to_str().ok()).map(reqwest::Url::parse).transpose()?;
        ensure!(rejected.as_ref().is_some_and(|url|url.query_pairs().any(|(key,value)|key=="error"&&value=="unauthorized_client")&&!url.query_pairs().any(|(key,_)|key=="code")),"suspended admission remained usable through public authorization");
        let interaction=crate::oidc::routes().with_state(state).oneshot(Request::get(format!("/oauth/interaction/{flow}")).header(header::ORIGIN,"https://auth.saas.test").header(header::COOKIE,browser).body(Body::empty())?).await?;
        ensure!(interaction.status().is_client_error(),"existing interaction bypassed the internal-id admission guard");
        let mut disabled=create.clone();disabled["expectedVersion"]=json!(1);disabled["status"]=json!("DISABLED");let path=format!("{client_path}/{client}");let operation=Uuid::now_v7();db.accept(operation,"AUTH_ADMIN","PATCH",&path,&disabled).await?;
        let (status,disabled_response)=db.call("AUTH_ADMIN","PATCH",&path,Some(&disabled),Some(operation)).await?;ensure!(status==StatusCode::OK&&disabled_response["status"]=="DISABLED","suspended admission prevented pure client shutdown");
        let mut enabled=disabled;enabled["expectedVersion"]=json!(2);enabled["status"]=json!("ENABLED");let operation=Uuid::now_v7();db.accept(operation,"AUTH_ADMIN","PATCH",&path,&enabled).await?;
        let (status,_)=db.call("AUTH_ADMIN","PATCH",&path,Some(&enabled),Some(operation)).await?;ensure!(status==StatusCode::FORBIDDEN,"suspended admission re-enabled its client");
        Ok(())
    }.await;
    db.finish(result).await
}
