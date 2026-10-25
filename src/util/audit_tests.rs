//! Focused real PostgreSQL regressions for mandatory transactional writes.
//! Every test creates a fresh marked database on the explicitly selected task
//! cluster. The small schema models the identity-owned persistence contracts;
//! the intent functions are consumer fakes, not deployment/authorization proof.

mod accounts;

use crate::{config::Config, error::AppError, state::AppState};
use anyhow::{anyhow, ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

const PREFIX: &str = "identity_phase12_audit_";
const CLUSTER: &str = "7700230159816609830";
const SCHEMA: &str = r#"
CREATE FUNCTION public.is_uuid_v7(value uuid) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT substring(value::text,15,1)='7' AND substring(value::text,20,1) IN ('8','9','a','b')
$$;
CREATE TABLE public.users(
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)), username text NOT NULL UNIQUE,
 password_hash text NOT NULL,real_name text NOT NULL DEFAULT '',email text NOT NULL DEFAULT '',
 phone text NOT NULL DEFAULT '',gender text NOT NULL DEFAULT 'UNKNOWN',avatar text NOT NULL DEFAULT '',
 status text NOT NULL DEFAULT 'ENABLED',session_version bigint NOT NULL DEFAULT 1,
 last_login_at timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.identity_audit_logs(
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),user_id uuid CHECK(user_id IS NULL OR public.is_uuid_v7(user_id)),
 username text NOT NULL,action text NOT NULL,detail text NOT NULL,ip text NOT NULL,user_agent text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.identity_service_clients(
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),secret_hash text NOT NULL UNIQUE,
 purpose text NOT NULL,status text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.oidc_provider_settings(singleton boolean PRIMARY KEY,issuer text NOT NULL,created_at timestamptz NOT NULL);
CREATE TABLE public.oidc_clients(
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),name text NOT NULL,purpose text NOT NULL,
 secret_hash text NOT NULL,allowed_member_types text[] NOT NULL,redirect_uris text[] NOT NULL,
 post_logout_redirect_uris text[] NOT NULL,refresh_enabled boolean NOT NULL,status text NOT NULL,
 access_policy_version bigint NOT NULL,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL
);
CREATE TABLE public.oidc_signing_keys(
 kid text PRIMARY KEY,n text NOT NULL,e text NOT NULL,published_at timestamptz NOT NULL,
 active boolean NOT NULL DEFAULT false,activated_at timestamptz,last_signed_exp timestamptz,retired_at timestamptz,revoked_at timestamptz
);
CREATE UNIQUE INDEX owned_one_active_key ON public.oidc_signing_keys((true)) WHERE active;
CREATE TABLE public.identity_account_revocation_facts(
 user_id uuid NOT NULL CHECK(public.is_uuid_v7(user_id)),account_version bigint NOT NULL,
 platform_session_count bigint NOT NULL,oauth_token_count bigint NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(user_id,account_version)
);
CREATE FUNCTION public.owned_record_revocation_fact() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.session_version IS DISTINCT FROM OLD.session_version THEN
  INSERT INTO public.identity_account_revocation_facts VALUES(NEW.id,NEW.session_version,0,0,clock_timestamp());
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER owned_account_fact AFTER UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.owned_record_revocation_fact();
CREATE TABLE public.identity_account_tombstones(
 user_id uuid PRIMARY KEY CHECK(public.is_uuid_v7(user_id)),operation_id uuid NOT NULL UNIQUE CHECK(public.is_uuid_v7(operation_id)),retired_at timestamptz NOT NULL
);
CREATE TABLE public.identity_account_command_receipts(
 operation_id uuid PRIMARY KEY CHECK(public.is_uuid_v7(operation_id)),service_id uuid NOT NULL CHECK(public.is_uuid_v7(service_id)),
 target_user_id uuid NOT NULL CHECK(public.is_uuid_v7(target_user_id)),canonical_digest text NOT NULL,state text NOT NULL,
 before_version bigint NOT NULL,after_version bigint NOT NULL,revoked_sessions bigint NOT NULL,revoked_tokens bigint NOT NULL,created_at timestamptz NOT NULL
);
CREATE TABLE public.identity_oidc_admin_receipts(
 operation_id uuid PRIMARY KEY CHECK(public.is_uuid_v7(operation_id)),service_id uuid NOT NULL CHECK(public.is_uuid_v7(service_id)),
 request_digest text NOT NULL,service_secret_hash text NOT NULL,method text NOT NULL,path text NOT NULL,
 result_json jsonb NOT NULL,returns_secret boolean NOT NULL,created_at timestamptz NOT NULL
);
CREATE FUNCTION public.platform_account_command_intent_active(uuid,uuid,bigint,text,text) RETURNS boolean LANGUAGE sql AS $$SELECT true$$;
CREATE FUNCTION public.identity_oidc_command_intent_active(uuid,uuid,text,text,text) RETURNS boolean LANGUAGE sql AS $$SELECT true$$;
CREATE FUNCTION public.owned_suppress_write() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL; END;$$;
CREATE TABLE public.owned_business_state(singleton boolean PRIMARY KEY CHECK(singleton),value integer NOT NULL);
INSERT INTO public.owned_business_state VALUES(true,0);
CREATE TABLE public.owned_operation_receipts(operation_id uuid PRIMARY KEY CHECK(public.is_uuid_v7(operation_id)),value integer NOT NULL);
"#;

struct Database {
    pool: PgPool,
    admin: PgPool,
    name: String,
    marker: String,
    url: String,
    user: Uuid,
    account_service: Uuid,
    admin_service: Uuid,
}
struct Reply {
    status: StatusCode,
    body: Value,
}

impl Database {
    async fn create() -> Result<Self> {
        let source = std::env::var("IDENTITY_PHASE12_TEST_DATABASE_URL")
            .map_err(|_| anyhow!("explicit IDENTITY_PHASE12_TEST_DATABASE_URL is required"))?;
        let options = PgConnectOptions::from_str(&source)
            .map_err(|_| anyhow!("invalid task PostgreSQL administration configuration"))?;
        let mut url =
            reqwest::Url::parse(&source).map_err(|_| anyhow!("invalid task PostgreSQL URL"))?;
        ensure!(
            options.get_database() == Some("postgres"),
            "administration must explicitly select postgres"
        );
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options.clone())
            .await
            .map_err(|_| anyhow!("task PostgreSQL administration unavailable"))?;
        let cluster: String =
            sqlx::query_scalar("SELECT system_identifier::text FROM pg_control_system()")
                .fetch_one(&admin)
                .await?;
        ensure!(
            cluster == CLUSTER,
            "refusing audit regression outside the owned task cluster"
        );
        let id = Uuid::now_v7();
        let name = format!("{PREFIX}{}", id.simple());
        let marker = format!("identity-phase12-audit/task-owned/1/{id}");
        ensure!(safe_name(&name), "unsafe owned audit database name");
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await?;
        let marked = sqlx::query(&format!("COMMENT ON DATABASE \"{name}\" IS '{marker}'"))
            .execute(&admin)
            .await;
        if marked.is_err() {
            let _ = sqlx::query(&format!("DROP DATABASE \"{name}\" WITH(FORCE)"))
                .execute(&admin)
                .await;
            admin.close().await;
            return Err(anyhow!("owned audit database marking failed"));
        }
        let pool = match PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(3))
            .connect_with(options.database(&name))
            .await
        {
            Ok(pool) => pool,
            Err(_) => {
                let _ = sqlx::query(&format!("DROP DATABASE \"{name}\" WITH(FORCE)"))
                    .execute(&admin)
                    .await;
                admin.close().await;
                return Err(anyhow!("owned audit database unavailable"));
            }
        };
        url.set_path(&format!("/{name}"));
        let db = Self {
            pool,
            admin,
            name,
            marker,
            url: url.to_string(),
            user: Uuid::now_v7(),
            account_service: Uuid::now_v7(),
            admin_service: Uuid::now_v7(),
        };
        let initialized=async {
            db.ensure_owned_empty().await?;
            sqlx::raw_sql(SCHEMA).execute(&db.pool).await?;
            sqlx::query("INSERT INTO users(id,username,password_hash,real_name) VALUES($1,'owned-audit-account','unusable-owned-test-hash','Owned audit account')").bind(db.user).execute(&db.pool).await?;
            sqlx::query("INSERT INTO oidc_provider_settings VALUES(true,'https://auth.saas.test',clock_timestamp())").execute(&db.pool).await?;
            for (id,purpose) in [(db.account_service,"ACCOUNT_COMMAND"),(db.admin_service,"OIDC_ADMIN")] {
                sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status) VALUES($1,$2,$3,'ENABLED')").bind(id).bind(super::hash::sha256_hex(&service_secret(purpose))).bind(purpose).execute(&db.pool).await?;
            }
            Ok::<(),anyhow::Error>(())
        }.await;
        if let Err(error) = initialized {
            db.finish(Ok(())).await?;
            return Err(error);
        }
        Ok(db)
    }
    async fn ensure_owned_empty(&self) -> Result<()> {
        let fresh:bool=sqlx::query_scalar("SELECT current_database()=$1 AND shobj_description((SELECT oid FROM pg_database WHERE datname=current_database()),'pg_database')=$2 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r')").bind(&self.name).bind(&self.marker).fetch_one(&self.pool).await?;
        ensure!(
            fresh,
            "fixture DDL requires the exact fresh marked database"
        );
        Ok(())
    }
    fn state(&self) -> Result<AppState> {
        let mut config = Config::from_values(&HashMap::from([
            ("DATABASE_URL".into(), self.url.clone()),
            ("APP_ENV".into(), "test".into()),
        ]))?;
        // No signing operation is exercised by this fixture. Enable the actual
        // client-management and key-retirement routes without a private keyset.
        config.sso_enabled = true;
        config.oidc_enabled = true;
        config.sso_origin = Some("https://auth.saas.test".into());
        config.oidc_issuer = Some("https://auth.saas.test".into());
        Ok(AppState::new(self.pool.clone(), Arc::new(config)))
    }
    async fn suppress(&self, table: &str, event: &str) -> Result<()> {
        ensure!(
            matches!(
                table,
                "identity_audit_logs"
                    | "identity_account_command_receipts"
                    | "identity_account_tombstones"
                    | "identity_oidc_admin_receipts"
                    | "users"
                    | "oidc_clients"
                    | "oidc_signing_keys"
            ) && matches!(event, "INSERT" | "UPDATE"),
            "unsafe suppression fixture target"
        );
        sqlx::query(&format!("CREATE TRIGGER owned_suppress BEFORE {event} ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.owned_suppress_write()" )).execute(&self.pool).await?;
        Ok(())
    }
    async fn unsuppress(&self, table: &str) -> Result<()> {
        ensure!(
            matches!(
                table,
                "identity_audit_logs"
                    | "identity_account_command_receipts"
                    | "identity_account_tombstones"
                    | "identity_oidc_admin_receipts"
                    | "users"
                    | "oidc_clients"
                    | "oidc_signing_keys"
            ),
            "unsafe suppression cleanup target"
        );
        sqlx::query(&format!("DROP TRIGGER owned_suppress ON public.{table}"))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn call(
        &self,
        purpose: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        extra: &[(&str, String)],
    ) -> Result<Reply> {
        let service = match purpose {
            "ACCOUNT_COMMAND" => self.account_service,
            "OIDC_ADMIN" => self.admin_service,
            _ => return Err(anyhow!("unknown fixture service purpose")),
        };
        let authorization = format!(
            "Basic {}",
            STANDARD.encode(format!("{service}:{}", service_secret(purpose)))
        );
        let mut request = Request::builder()
            .method(Method::from_bytes(method.as_bytes())?)
            .uri(path)
            .header(header::AUTHORIZATION, authorization);
        for (name, value) in extra {
            request = request.header(*name, value);
        }
        let payload = if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json");
            serde_json::to_vec(&body)?
        } else {
            vec![]
        };
        let router = crate::oidc::routes()
            .merge(crate::internal::routes())
            .with_state(self.state()?);
        let response = router.oneshot(request.body(Body::from(payload))?).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 65536).await?;
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok(Reply { status, body })
    }
    async fn account_call(
        &self,
        operation: Uuid,
        target: Uuid,
        expected: i64,
        kind: &str,
        payload: Value,
    ) -> Result<Reply> {
        let mut body = json!({"operationId":operation,"targetUserId":target,"expectedAccountVersion":expected.to_string(),"expiresAt":(Utc::now()+ChronoDuration::seconds(45)).to_rfc3339(),"kind":kind,"payload":payload,"context":null});
        let encoded = serde_json::to_vec(&body)?;
        body["canonicalDigest"] = json!(hex::encode(crate::accounts::hmac_sha256(
            service_secret("ACCOUNT_COMMAND").as_bytes(),
            &encoded
        )));
        self.call(
            "ACCOUNT_COMMAND",
            "POST",
            "/internal/identity/accounts/commands",
            Some(body),
            &[],
        )
        .await
    }
    async fn admin_call(
        &self,
        operation: Uuid,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Reply> {
        let digest = admin_digest(method, path, body.as_ref().unwrap_or(&Value::Null))?;
        self.call(
            "OIDC_ADMIN",
            method,
            path,
            body,
            &[
                ("x-identity-operation", operation.to_string()),
                ("x-identity-operation-digest", digest),
            ],
        )
        .await
    }
    async fn snapshot(&self) -> Result<(i64, String, i64, i64, i64)> {
        Ok(sqlx::query_as("SELECT session_version,status,(SELECT count(*) FROM identity_audit_logs),(SELECT count(*) FROM identity_account_command_receipts),(SELECT count(*) FROM identity_account_tombstones) FROM users WHERE id=$1").bind(self.user).fetch_one(&self.pool).await?)
    }
    async fn finish(self, result: Result<()>) -> Result<()> {
        ensure!(
            safe_name(&self.name),
            "refusing cleanup outside owned audit namespace"
        );
        let closed = tokio::time::timeout(Duration::from_secs(5), self.pool.close())
            .await
            .is_ok();
        let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1 AND shobj_description(oid,'pg_database')=$2)").bind(&self.name).bind(&self.marker).fetch_one(&self.admin).await?;
        if !owned {
            self.admin.close().await;
            return Err(anyhow!("refusing cleanup without exact owned audit marker"));
        }
        let removed = sqlx::query(&format!("DROP DATABASE \"{}\" WITH(FORCE)", self.name))
            .execute(&self.admin)
            .await;
        self.admin.close().await;
        eprintln!("identity_phase12_audit_cleanup database={} assertions_ok={} database_removed={} pool_closed={closed}",self.name,result.is_ok(),removed.is_ok());
        result?;
        removed?;
        ensure!(closed, "owned audit pool did not close");
        Ok(())
    }
}
fn safe_name(name: &str) -> bool {
    name.strip_prefix(PREFIX).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) && name.len() <= 63
}
fn service_secret(purpose: &str) -> String {
    if purpose == "ACCOUNT_COMMAND" {
        "a".repeat(64)
    } else {
        "b".repeat(64)
    }
}
fn admin_digest(method: &str, path: &str, body: &Value) -> Result<String> {
    Ok(super::hash::sha256_hex(&serde_json::to_string(
        &json!({"method":method,"path":path,"body":body}),
    )?))
}

async fn business_command(
    db: &Database,
    operation: Uuid,
    value: i32,
) -> std::result::Result<(), AppError> {
    let mut tx = db.pool.begin().await?;
    sqlx::query("UPDATE owned_business_state SET value=$1 WHERE singleton")
        .bind(value)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO owned_operation_receipts VALUES($1,$2)")
        .bind(operation)
        .bind(value)
        .execute(&mut *tx)
        .await?;
    super::audit::write_in_tx(
        &mut tx,
        super::audit::AuditInfo {
            user_id: Some(db.user),
            username: "owned-audit-account",
            action: "OWNED_AUDIT_REGRESSION",
            detail: "no credential material",
            ip: "127.0.0.1",
            user_agent: "owned-test",
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase12_audit_silent_insert_suppression_rolls_back_mutation_and_receipt() -> Result<()> {
    let db = Database::create().await?;
    let result=async {
        business_command(&db,Uuid::now_v7(),1).await?;
        let baseline:(i32,i64,i64)=sqlx::query_as("SELECT value,(SELECT count(*) FROM identity_audit_logs),(SELECT count(*) FROM owned_operation_receipts) FROM owned_business_state WHERE singleton").fetch_one(&db.pool).await?;
        ensure!(baseline==(1,1,1),"positive audited transaction did not commit exactly once");
        db.suppress("identity_audit_logs","INSERT").await?;
        let failed=business_command(&db,Uuid::now_v7(),2).await;
        db.unsuppress("identity_audit_logs").await?;
        ensure!(matches!(failed,Err(AppError::Unavailable)),"silent missing audit must fail unavailable");
        let after:(i32,i64,i64)=sqlx::query_as("SELECT value,(SELECT count(*) FROM identity_audit_logs),(SELECT count(*) FROM owned_operation_receipts) FROM owned_business_state WHERE singleton").fetch_one(&db.pool).await?;
        ensure!(after==baseline,"missing audit committed business state or receipt");
        business_command(&db,Uuid::now_v7(),3).await?;
        let recovered:(i32,i64,i64)=sqlx::query_as("SELECT value,(SELECT count(*) FROM identity_audit_logs),(SELECT count(*) FROM owned_operation_receipts) FROM owned_business_state WHERE singleton").fetch_one(&db.pool).await?;
        ensure!(recovered==(3,2,2),"restored auditing did not recover a clean transaction");Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase12_oidc_real_admin_paths_require_receipt_audit_and_single_target_writes() -> Result<()>
{
    let db = Database::create().await?;
    let result=async {
        let registration=json!({"name":"Owned customer","purpose":"CUSTOMER_PORTAL","allowedMemberTypes":["CUSTOMER"],"redirectUris":["https://customer.saas.test/auth/callback"],"postLogoutRedirectUris":[],"refreshEnabled":true});
        let first=Uuid::now_v7();
        let created=db.admin_call(first,"POST","/internal/identity/oidc/clients",Some(registration.clone())).await?;
        ensure!(created.status==StatusCode::OK&&created.body["id"]==first.to_string(),"positive real client creation failed");
        let baseline:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM oidc_clients),(SELECT count(*) FROM identity_audit_logs),(SELECT count(*) FROM identity_oidc_admin_receipts)").fetch_one(&db.pool).await?;
        ensure!(baseline==(1,1,1),"positive client creation was not atomic");
        for table in ["identity_oidc_admin_receipts","identity_audit_logs","oidc_clients"] {
            db.suppress(table,"INSERT").await?;
            let operation=Uuid::now_v7();
            let failed=db.admin_call(operation,"POST","/internal/identity/oidc/clients",Some(registration.clone())).await;
            db.unsuppress(table).await?;
            ensure!(failed?.status==StatusCode::SERVICE_UNAVAILABLE,"required real admin insert suppression did not fail 503");
            let after:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM oidc_clients),(SELECT count(*) FROM identity_audit_logs),(SELECT count(*) FROM identity_oidc_admin_receipts)").fetch_one(&db.pool).await?;
            ensure!(after==baseline,"admin insert suppression committed client, audit or receipt");
            let digest=admin_digest("POST","/internal/identity/oidc/clients",&registration)?;
            let lookup=db.call("OIDC_ADMIN","GET",&format!("/internal/identity/oidc/operations/{operation}"),None,&[("x-identity-operation-digest",digest)]).await?;
            ensure!(lookup.status==StatusCode::NOT_FOUND,"failed admin command retained a completed receipt");
        }
        let update=json!({"name":"Owned changed","purpose":"CUSTOMER_PORTAL","allowedMemberTypes":["CUSTOMER"],"redirectUris":["https://customer.saas.test/auth/callback"],"postLogoutRedirectUris":[],"refreshEnabled":true,"status":"DISABLED","expectedAccessPolicyVersion":1});
        let path=format!("/internal/identity/oidc/clients/{first}");
        db.suppress("oidc_clients","UPDATE").await?;
        let failed=db.admin_call(Uuid::now_v7(),"PATCH",&path,Some(update.clone())).await;
        db.unsuppress("oidc_clients").await?;
        ensure!(failed?.status==StatusCode::SERVICE_UNAVAILABLE,"suppressed client update returned success");
        let policy:(String,String,i64)=sqlx::query_as("SELECT name,status,access_policy_version FROM oidc_clients WHERE id=$1").bind(first).fetch_one(&db.pool).await?;
        ensure!(policy==("Owned customer".into(),"ENABLED".into(),1),"suppressed client update changed policy");
        let changed=db.admin_call(Uuid::now_v7(),"PATCH",&path,Some(update)).await?;
        ensure!(changed.status==StatusCode::OK&&changed.body["accessPolicyVersion"]==2,"positive client update did not recover");
        sqlx::query("INSERT INTO oidc_signing_keys(kid,n,e,published_at) VALUES('owned-key','owned-public-fixture','AQAB',clock_timestamp())").execute(&db.pool).await?;
        db.suppress("oidc_signing_keys","UPDATE").await?;
        let failed=db.admin_call(Uuid::now_v7(),"DELETE","/internal/identity/oidc/keys/owned-key",None).await;
        db.unsuppress("oidc_signing_keys").await?;
        ensure!(failed?.status==StatusCode::SERVICE_UNAVAILABLE,"suppressed exact key retirement returned success");
        let retired:bool=sqlx::query_scalar("SELECT retired_at IS NOT NULL FROM oidc_signing_keys WHERE kid='owned-key'").fetch_one(&db.pool).await?;
        ensure!(!retired,"suppressed key retirement changed key lifecycle");
        let ended=db.admin_call(Uuid::now_v7(),"DELETE","/internal/identity/oidc/keys/owned-key",None).await?;
        ensure!(ended.status==StatusCode::OK,"positive exact key retirement did not recover");
        Ok(())
    }.await;
    db.finish(result).await
}
