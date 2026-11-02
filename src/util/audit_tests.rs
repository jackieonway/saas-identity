//! Focused real PostgreSQL regressions for mandatory transactional writes.
//! Every test creates a fresh marked database on the explicitly selected task
//! cluster. The small schema models the identity-owned persistence contracts;
//! the intent functions are consumer fakes, not deployment/authorization proof.

mod accounts;
mod auth_protocol;

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
const PHASE03_PREFIX: &str = "identity_phase03_projection_";
const PHASE04_PREFIX: &str = "identity_phase04_clients_";
const PHASE07_PREFIX: &str = "identity_phase07_consent_";
const PHASE08_PREFIX: &str = "identity_phase08_oauth_";
const PHASE09_PREFIX: &str = "identity_phase09_oauth_";
const PHASE10_PREFIX: &str = "identity_phase10_refresh_";
const PHASE11_PREFIX: &str = "identity_phase11_machine_";
const PHASE12_CONTEXT_PREFIX: &str = "identity_phase12_context_";
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
CREATE TABLE public.sso_sessions(
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),user_id uuid NOT NULL REFERENCES users(id),
 token_hash text NOT NULL,csrf_hash text NOT NULL,account_version bigint NOT NULL,
 authenticated_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,revoked_at timestamptz,
 CHECK(expires_at>authenticated_at)
);
CREATE TABLE public.identity_service_clients(
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),secret_hash text NOT NULL UNIQUE,
 purpose text NOT NULL,status text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.auth_provider_settings(singleton boolean PRIMARY KEY,issuer text NOT NULL,created_at timestamptz NOT NULL);
CREATE TABLE public.auth_scopes(id uuid PRIMARY KEY,resource_id uuid NOT NULL,scope_name text NOT NULL,status text NOT NULL);
CREATE TABLE public.auth_applications(
 application_id uuid PRIMARY KEY CHECK(public.is_uuid_v7(application_id)),partner_id uuid,
 ownership text NOT NULL,status text NOT NULL,display_name text NOT NULL,purpose text NOT NULL,
 approved_scopes text[] NOT NULL,projection_version bigint NOT NULL,projected_at timestamptz NOT NULL
);
CREATE TABLE public.auth_resources(
 id uuid PRIMARY KEY,resource_key text NOT NULL UNIQUE,audience text NOT NULL UNIQUE,status text NOT NULL,version bigint NOT NULL
);
CREATE TABLE public.auth_application_admissions(
 application_id uuid NOT NULL REFERENCES auth_applications(application_id),environment text NOT NULL,
 status text NOT NULL,redirect_uris text[] NOT NULL,post_logout_redirect_uris text[] NOT NULL,
 scopes text[] NOT NULL,PRIMARY KEY(application_id,environment)
);
CREATE TABLE public.auth_clients(
 id uuid PRIMARY KEY,client_id text NOT NULL UNIQUE,display_name text NOT NULL,application_id uuid NOT NULL REFERENCES auth_applications(application_id),
 environment text NOT NULL,client_type text NOT NULL,runtime_kind text NOT NULL,subject_mode text NOT NULL,context_mode text,
 allowed_member_types text[] NOT NULL,grant_types text[] NOT NULL,token_endpoint_auth_method text NOT NULL,
 redirect_uris text[] NOT NULL,post_logout_redirect_uris text[] NOT NULL,status text NOT NULL,
 version bigint NOT NULL,policy_version bigint NOT NULL,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,
 UNIQUE(id,application_id,environment,subject_mode,context_mode)
);
-- The shared administration fixture serves current client DTOs as well as the
-- protocol tests. Keep the canonical short-session defaults in this base schema.
ALTER TABLE public.auth_clients
 ADD COLUMN IF NOT EXISTS logout_mode text NOT NULL DEFAULT 'SHORT_SESSION_ONLINE_CHECK'
   CHECK (logout_mode IN ('SHORT_SESSION_ONLINE_CHECK','BACK_CHANNEL')),
 ADD COLUMN IF NOT EXISTS backchannel_logout_uri text,
 ADD COLUMN IF NOT EXISTS backchannel_target_id uuid;
ALTER TABLE public.auth_application_admissions
 ADD COLUMN IF NOT EXISTS logout_mode text NOT NULL DEFAULT 'SHORT_SESSION_ONLINE_CHECK'
   CHECK (logout_mode IN ('SHORT_SESSION_ONLINE_CHECK','BACK_CHANNEL')),
 ADD COLUMN IF NOT EXISTS backchannel_logout_uri text;
CREATE TABLE public.auth_client_credentials(
 id uuid PRIMARY KEY,client_id uuid NOT NULL REFERENCES auth_clients(id),client_type text NOT NULL,
 credential_version bigint NOT NULL,secret_digest text,public_key_thumbprint text,created_at timestamptz NOT NULL,
 expires_at timestamptz,revoked_at timestamptz,UNIQUE(client_id,credential_version)
);
CREATE UNIQUE INDEX auth_client_credentials_one_current_idx ON auth_client_credentials(client_id)
 WHERE revoked_at IS NULL AND expires_at IS NULL;
CREATE TABLE public.auth_client_permissions(
 client_id uuid NOT NULL REFERENCES auth_clients(id),resource_id uuid NOT NULL REFERENCES auth_resources(id),scope_id uuid NOT NULL REFERENCES auth_scopes(id),
 expires_at timestamptz,version bigint NOT NULL,PRIMARY KEY(client_id,resource_id,scope_id)
);
CREATE TABLE public.auth_consent_groups(
 id uuid PRIMARY KEY,application_id uuid NOT NULL REFERENCES auth_applications(application_id),environment text NOT NULL,
 display_name text NOT NULL,purpose text NOT NULL,subject_mode text NOT NULL DEFAULT 'USER',context_mode text NOT NULL,
 status text NOT NULL,version bigint NOT NULL DEFAULT 1,
 UNIQUE(id,application_id,environment,subject_mode,context_mode)
);
CREATE TABLE public.auth_consent_group_clients(
 group_id uuid NOT NULL REFERENCES auth_consent_groups(id),client_id uuid NOT NULL UNIQUE REFERENCES auth_clients(id),
 application_id uuid NOT NULL,environment text NOT NULL,subject_mode text NOT NULL DEFAULT 'USER',context_mode text NOT NULL,
 PRIMARY KEY(group_id,client_id),
 FOREIGN KEY(group_id,application_id,environment,subject_mode,context_mode) REFERENCES auth_consent_groups(id,application_id,environment,subject_mode,context_mode),
 FOREIGN KEY(client_id,application_id,environment,subject_mode,context_mode) REFERENCES auth_clients(id,application_id,environment,subject_mode,context_mode)
);
CREATE TABLE public.auth_consents(
 id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES users(id),group_id uuid NOT NULL REFERENCES auth_consent_groups(id),
 status text NOT NULL,generation bigint NOT NULL,group_version bigint NOT NULL DEFAULT 1,version bigint NOT NULL,authorized_at timestamptz,revoked_at timestamptz,display_deleted_at timestamptz,
 UNIQUE(user_id,group_id),CHECK(display_deleted_at IS NULL OR status='REVOKED')
);
CREATE TABLE public.auth_consent_scopes(
 consent_id uuid NOT NULL REFERENCES auth_consents(id),resource_id uuid NOT NULL REFERENCES auth_resources(id),scope_id uuid NOT NULL,
 granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(consent_id,resource_id,scope_id)
);
CREATE TABLE public.auth_consent_revocation_outbox(
 id uuid PRIMARY KEY,consent_id uuid NOT NULL REFERENCES auth_consents(id),user_id uuid NOT NULL REFERENCES users(id),
 group_id uuid NOT NULL REFERENCES auth_consent_groups(id),client_id uuid NOT NULL REFERENCES auth_clients(id),
 consent_generation bigint NOT NULL,event_kind text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),delivered_at timestamptz,attempt_count integer NOT NULL DEFAULT 0,last_error_code text,
 UNIQUE(consent_id,consent_generation,client_id,event_kind)
);
CREATE TABLE public.identity_consent_command_receipts(
 operation_id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES users(id),consent_id uuid NOT NULL REFERENCES auth_consents(id),
 request_digest text NOT NULL,action text NOT NULL,expected_version bigint NOT NULL,result_json jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.auth_authorization_requests(
 id uuid PRIMARY KEY,client_id uuid NOT NULL REFERENCES auth_clients(id),user_id uuid REFERENCES users(id),status text NOT NULL,
 version bigint NOT NULL DEFAULT 1,consumed_at timestamptz
);
CREATE TABLE public.auth_authorization_codes(
 id uuid PRIMARY KEY,request_id uuid NOT NULL REFERENCES auth_authorization_requests(id),client_id uuid NOT NULL REFERENCES auth_clients(id),
 user_id uuid NOT NULL REFERENCES users(id),consent_id uuid NOT NULL REFERENCES auth_consents(id),consent_generation bigint NOT NULL,
 code_digest text NOT NULL,expires_at timestamptz NOT NULL,consumed_at timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.auth_grants(
 id uuid PRIMARY KEY,client_id uuid NOT NULL REFERENCES auth_clients(id),user_id uuid NOT NULL REFERENCES users(id),
 consent_id uuid NOT NULL REFERENCES auth_consents(id),consent_generation bigint NOT NULL,revoked_at timestamptz,
 version bigint NOT NULL DEFAULT 1
);
CREATE TABLE public.auth_rp_sessions(
 grant_id uuid PRIMARY KEY REFERENCES public.auth_grants(id),client_id uuid NOT NULL REFERENCES public.auth_clients(id),
 user_id uuid NOT NULL REFERENCES public.users(id),source_session_id uuid NOT NULL,
 public_sid text NOT NULL CHECK(public_sid ~ '^[0-9a-f]{64}$'),public_sub text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(client_id,public_sid)
);
CREATE TABLE public.auth_refresh_families(
 id uuid PRIMARY KEY,grant_id uuid NOT NULL REFERENCES auth_grants(id),revoked_at timestamptz,version bigint NOT NULL DEFAULT 1
);
CREATE TABLE public.auth_access_tokens(
 id uuid PRIMARY KEY,grant_id uuid NOT NULL REFERENCES auth_grants(id),revoked_at timestamptz
);
CREATE TABLE public.auth_refresh_tokens(
 id uuid PRIMARY KEY,family_id uuid NOT NULL REFERENCES auth_refresh_families(id),revoked_at timestamptz
);
CREATE TABLE public.auth_subject_sectors(
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),application_id uuid NOT NULL REFERENCES public.auth_applications(application_id),
 environment text NOT NULL CHECK(environment ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),status text NOT NULL CHECK(status IN ('ACTIVE','RETIRED')),
 version bigint NOT NULL DEFAULT 1 CHECK(version >= 1),UNIQUE(application_id,environment)
);
CREATE TABLE public.auth_subject_links(
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),user_id uuid NOT NULL REFERENCES public.users(id),
 sector_id uuid NOT NULL REFERENCES public.auth_subject_sectors(id),subject text NOT NULL CHECK(length(subject) BETWEEN 22 AND 256),
 retired_at timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(user_id,sector_id),UNIQUE(sector_id,subject)
);
CREATE TABLE public.auth_signing_keys(
 kid text PRIMARY KEY,n text NOT NULL,e text NOT NULL,published_at timestamptz NOT NULL,
 active boolean NOT NULL DEFAULT false,activated_at timestamptz,last_signed_exp timestamptz,retired_at timestamptz,revoked_at timestamptz
);
CREATE UNIQUE INDEX owned_one_active_key ON public.auth_signing_keys((true)) WHERE active;
CREATE TABLE public.identity_account_revocation_facts(
 user_id uuid NOT NULL CHECK(public.is_uuid_v7(user_id)),account_version bigint NOT NULL,
 platform_session_count bigint NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(user_id,account_version)
);
CREATE FUNCTION public.owned_record_revocation_fact() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.session_version IS DISTINCT FROM OLD.session_version THEN
  INSERT INTO public.identity_account_revocation_facts VALUES(NEW.id,NEW.session_version,0,clock_timestamp());
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
CREATE TABLE public.identity_auth_command_receipts(
 operation_id uuid PRIMARY KEY CHECK(public.is_uuid_v7(operation_id)),service_id uuid NOT NULL CHECK(public.is_uuid_v7(service_id)),
 request_digest text NOT NULL,service_secret_hash text NOT NULL,method text NOT NULL,path text NOT NULL,
 result_json jsonb NOT NULL,returns_secret boolean NOT NULL,created_at timestamptz NOT NULL
);
CREATE FUNCTION public.platform_account_command_intent_active(uuid,uuid,bigint,text,text) RETURNS boolean LANGUAGE sql AS $$SELECT true$$;
CREATE FUNCTION public.identity_auth_command_intent_active(uuid,uuid,text,text,text) RETURNS boolean LANGUAGE sql AS $$SELECT true$$;
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
    projection_service: Uuid,
    auth_admin_service: Uuid,
}
struct Reply {
    status: StatusCode,
    body: Value,
}

impl Database {
    async fn create() -> Result<Self> {
        Self::create_namespace(PREFIX, "identity-phase12-audit/task-owned/1", None).await
    }
    async fn create_phase03() -> Result<Self> {
        Self::create_namespace(
            PHASE03_PREFIX,
            "identity-phase03-projection/task-owned/1",
            None,
        )
        .await
    }
    async fn create_phase04() -> Result<Self> {
        Self::create_namespace(
            PHASE04_PREFIX,
            "identity-phase04-clients/task-owned/1",
            None,
        )
        .await
    }
    async fn create_phase07() -> Result<Self> {
        let marker = std::env::var("IDENTITY_PHASE07_TEST_MARKER")
            .map_err(|_| anyhow!("explicit task-owned Phase 7 database marker is required"))?;
        ensure!(
            marker.starts_with("identity-phase07-consent/task-owned/1/")
                && marker.len() <= 120
                && marker.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
                }),
            "invalid task-owned Phase 7 database marker"
        );
        Self::create_namespace(PHASE07_PREFIX, &marker, None).await
    }
    async fn create_phase08() -> Result<Self> {
        let marker = std::env::var("IDENTITY_PHASE08_TEST_MARKER")
            .map_err(|_| anyhow!("explicit task-owned Phase 8 database marker is required"))?;
        ensure!(
            marker.starts_with("identity-phase08-oauth/task-owned/1/")
                && marker.len() <= 120
                && marker.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
                }),
            "invalid owned Phase 8 database marker"
        );
        Self::create_namespace(PHASE08_PREFIX, &marker, None).await
    }
    async fn create_phase09() -> Result<Self> {
        let marker = std::env::var("IDENTITY_PHASE09_TEST_MARKER")
            .map_err(|_| anyhow!("explicit task-owned Phase 9 database marker is required"))?;
        ensure!(
            marker.starts_with("identity-phase09-oauth/task-owned/1/")
                && marker.len() <= 120
                && marker.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
                }),
            "invalid owned Phase 9 database marker"
        );
        Self::create_namespace(PHASE09_PREFIX, &marker, None).await
    }
    async fn create_phase10() -> Result<Self> {
        let marker = std::env::var("IDENTITY_PHASE10_TEST_MARKER")
            .map_err(|_| anyhow!("explicit task-owned Phase 10 database marker is required"))?;
        ensure!(
            marker.starts_with("identity-phase10-refresh/task-owned/1/")
                && marker.len() <= 120
                && marker.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
                }),
            "invalid task-owned Phase 10 database marker"
        );
        let source = std::env::var("IDENTITY_PHASE10_TEST_DATABASE_URL")
            .map_err(|_| anyhow!("explicit task-owned Phase 10 PostgreSQL URL is required"))?;
        Self::create_namespace_from(PHASE10_PREFIX, &marker, None, &source).await
    }
    async fn create_phase11() -> Result<Self> {
        let marker = std::env::var("IDENTITY_PHASE11_TEST_MARKER")
            .map_err(|_| anyhow!("explicit task-owned Phase 11 database marker is required"))?;
        ensure!(
            marker.starts_with("identity-phase11-machine/task-owned/1/")
                && marker.len() <= 120
                && marker.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
                }),
            "invalid task-owned Phase 11 database marker"
        );
        let source = std::env::var("IDENTITY_PHASE11_TEST_DATABASE_URL")
            .map_err(|_| anyhow!("explicit task-owned Phase 11 PostgreSQL URL is required"))?;
        Self::create_namespace_from(PHASE11_PREFIX, &marker, None, &source).await
    }
    async fn create_phase12_context() -> Result<Self> {
        let marker = std::env::var("IDENTITY_PHASE12_TEST_MARKER")
            .map_err(|_| anyhow!("explicit task-owned Phase 12 database marker is required"))?;
        ensure!(
            marker.starts_with("identity-phase12-context/task-owned/1/")
                && marker.len() <= 120
                && marker.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
                }),
            "invalid task-owned Phase 12 database marker"
        );
        let source = std::env::var("IDENTITY_PHASE12_TEST_DATABASE_URL")
            .map_err(|_| anyhow!("explicit task-owned Phase 12 PostgreSQL URL is required"))?;
        Self::create_namespace_from(PHASE12_CONTEXT_PREFIX, &marker, None, &source).await
    }
    async fn create_namespace(
        prefix: &str,
        marker_prefix: &str,
        expected_cluster: Option<&str>,
    ) -> Result<Self> {
        let source = std::env::var("IDENTITY_PHASE12_TEST_DATABASE_URL")
            .map_err(|_| anyhow!("explicit IDENTITY_PHASE12_TEST_DATABASE_URL is required"))?;
        Self::create_namespace_from(prefix, marker_prefix, expected_cluster, &source).await
    }
    async fn create_namespace_from(
        prefix: &str,
        marker_prefix: &str,
        expected_cluster: Option<&str>,
        source: &str,
    ) -> Result<Self> {
        let options = PgConnectOptions::from_str(source)
            .map_err(|_| anyhow!("invalid task PostgreSQL administration configuration"))?;
        let mut url =
            reqwest::Url::parse(source).map_err(|_| anyhow!("invalid task PostgreSQL URL"))?;
        ensure!(
            options.get_database() == Some("postgres")
                && matches!(options.get_host(), "127.0.0.1" | "localhost" | "::1")
                && url.port().is_some(),
            "administration must explicitly select a loopback postgres database and port"
        );
        let expected_cluster = match expected_cluster {
            Some(value) => value.to_owned(),
            None => std::env::var("IDENTITY_PHASE12_TEST_CLUSTER_ID").map_err(|_| {
                anyhow!("explicit owned audit PostgreSQL cluster identifier is required")
            })?,
        };
        ensure!(
            expected_cluster
                .parse::<u64>()
                .is_ok_and(|id| id > 0 && id.to_string() == expected_cluster),
            "invalid owned audit PostgreSQL cluster identifier"
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
            cluster == expected_cluster,
            "refusing audit regression outside the owned task cluster"
        );
        let id = Uuid::now_v7();
        let name = format!("{prefix}{}", id.simple());
        let marker = format!("{marker_prefix}/{id}");
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
            projection_service: Uuid::now_v7(),
            auth_admin_service: Uuid::now_v7(),
        };
        let initialized=async {
            db.ensure_owned_empty().await?;
            sqlx::raw_sql(SCHEMA).execute(&db.pool).await?;
            sqlx::query("INSERT INTO users(id,username,password_hash,real_name) VALUES($1,'owned-audit-account','unusable-owned-test-hash','Owned audit account')").bind(db.user).execute(&db.pool).await?;
            sqlx::query("INSERT INTO auth_provider_settings VALUES(true,'https://auth.saas.test',clock_timestamp())").execute(&db.pool).await?;
            for (id,purpose) in [(db.account_service,"ACCOUNT_COMMAND"),(db.admin_service,"KEY_ADMIN"),(db.projection_service,"APPLICATION_PROJECTION"),(db.auth_admin_service,"AUTH_ADMIN")] {
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
        // No signing operation is exercised by this fixture. Enable canonical
        // client management and key retirement without a private keyset.
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
                    | "identity_auth_command_receipts"
                    | "users"
                    | "auth_signing_keys"
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
                    | "identity_auth_command_receipts"
                    | "users"
                    | "auth_signing_keys"
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
            "KEY_ADMIN" => self.admin_service,
            "APPLICATION_PROJECTION" => self.projection_service,
            "AUTH_ADMIN" => self.auth_admin_service,
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
            "KEY_ADMIN",
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
    async fn projection_call(
        &self,
        operation: Uuid,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Reply> {
        let digest = admin_digest(method, path, body.as_ref().unwrap_or(&Value::Null))?;
        self.call(
            "APPLICATION_PROJECTION",
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
    async fn auth_admin_call(
        &self,
        operation: Uuid,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Reply> {
        let digest = admin_digest(method, path, body.as_ref().unwrap_or(&Value::Null))?;
        self.call(
            "AUTH_ADMIN",
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
        eprintln!("identity_audit_test_cleanup database={} assertions_ok={} database_removed={} pool_closed={closed}",self.name,result.is_ok(),removed.is_ok());
        result?;
        removed?;
        ensure!(closed, "owned audit pool did not close");
        Ok(())
    }
}
fn safe_name(name: &str) -> bool {
    name.strip_prefix(PREFIX)
        .or_else(|| name.strip_prefix(PHASE03_PREFIX))
        .or_else(|| name.strip_prefix(PHASE04_PREFIX))
        .or_else(|| name.strip_prefix(PHASE07_PREFIX))
        .or_else(|| name.strip_prefix(PHASE08_PREFIX))
        .or_else(|| name.strip_prefix(PHASE09_PREFIX))
        .or_else(|| name.strip_prefix(PHASE10_PREFIX))
        .or_else(|| name.strip_prefix(PHASE11_PREFIX))
        .or_else(|| name.strip_prefix(PHASE12_CONTEXT_PREFIX))
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        && name.len() <= 63
}
fn service_secret(purpose: &str) -> String {
    if purpose == "ACCOUNT_COMMAND" {
        "a".repeat(64)
    } else if purpose == "APPLICATION_PROJECTION" {
        "c".repeat(64)
    } else if purpose == "AUTH_ADMIN" {
        "d".repeat(64)
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
async fn canonical_key_retirement_requires_receipt_audit_and_single_target_write() -> Result<()> {
    let db = Database::create().await?;
    let result=async {
        let path="/internal/identity/auth/keys/owned-key";
        sqlx::query("INSERT INTO auth_signing_keys(kid,n,e,published_at) VALUES('owned-key','owned-public-fixture','AQAB',clock_timestamp())").execute(&db.pool).await?;
        let baseline:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM identity_audit_logs),(SELECT count(*) FROM identity_auth_command_receipts)").fetch_one(&db.pool).await?;
        ensure!(baseline==(0,0),"key fixture started with command side effects");
        for table in ["identity_auth_command_receipts","identity_audit_logs"] {
            db.suppress(table,"INSERT").await?;
            let operation=Uuid::now_v7();
            let failed=db.admin_call(operation,"DELETE",path,None).await;
            db.unsuppress(table).await?;
            ensure!(failed?.status==StatusCode::SERVICE_UNAVAILABLE,"required real admin insert suppression did not fail 503");
            let after:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM identity_audit_logs),(SELECT count(*) FROM identity_auth_command_receipts)").fetch_one(&db.pool).await?;
            ensure!(after==baseline,"admin insert suppression committed audit or receipt");
            let retired:bool=sqlx::query_scalar("SELECT retired_at IS NOT NULL FROM auth_signing_keys WHERE kid='owned-key'").fetch_one(&db.pool).await?;
            ensure!(!retired,"missing audit or receipt committed key retirement");
            let digest=admin_digest("DELETE",path,&Value::Null)?;
            let lookup=db.call("KEY_ADMIN","GET",&format!("/internal/identity/auth/key-operations/{operation}"),None,&[("x-identity-operation-digest",digest)]).await?;
            ensure!(lookup.status==StatusCode::NOT_FOUND,"failed admin command retained a completed receipt");
        }
        db.suppress("auth_signing_keys","UPDATE").await?;
        let failed=db.admin_call(Uuid::now_v7(),"DELETE",path,None).await;
        db.unsuppress("auth_signing_keys").await?;
        ensure!(failed?.status==StatusCode::SERVICE_UNAVAILABLE,"suppressed exact key retirement returned success");
        let retired:bool=sqlx::query_scalar("SELECT retired_at IS NOT NULL FROM auth_signing_keys WHERE kid='owned-key'").fetch_one(&db.pool).await?;
        ensure!(!retired,"suppressed key retirement changed key lifecycle");
        let operation=Uuid::now_v7();
        let ended=db.admin_call(operation,"DELETE",path,None).await?;
        ensure!(ended.status==StatusCode::OK,"positive exact key retirement did not recover");
        let replay=db.admin_call(operation,"DELETE",path,None).await?;
        ensure!(replay.status==StatusCode::OK&&replay.body==ended.body,"original key command did not recover its committed result");
        let committed:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM identity_audit_logs),(SELECT count(*) FROM identity_auth_command_receipts)").fetch_one(&db.pool).await?;
        ensure!(committed==(1,1),"key retirement did not commit exactly one audit and receipt");
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase03_application_projection_is_service_scoped_versioned_and_recoverable() -> Result<()>
{
    let db = Database::create_phase03().await?;
    let result = async {
        let application = Uuid::now_v7();
        let path = format!("/internal/identity/auth/applications/{application}");
        let initial = json!({
            "applicationId":application,
            "expectedVersion":null,
            "projection":{
                "ownership":"FIRST_PARTY",
                "partnerId":null,
                "status":"APPROVED",
                "displayName":"Owned application",
                "purpose":"First-party account application",
                "approvedScopes":[]
            }
        });
        let create_operation = Uuid::now_v7();
        let created = db
            .projection_call(create_operation, "PUT", &path, Some(initial.clone()))
            .await?;
        ensure!(
            created.status == StatusCode::OK
                && created.body["applicationId"] == application.to_string()
                && created.body["projectionVersion"] == 1,
            "first application projection did not create generation 1"
        );
        let digest = admin_digest("PUT", &path, &initial)?;
        let lookup = db
            .call(
                "APPLICATION_PROJECTION",
                "GET",
                &format!("/internal/identity/auth/operations/{create_operation}"),
                None,
                &[("x-identity-operation-digest", digest.clone())],
            )
            .await?;
        ensure!(
            lookup.status == StatusCode::OK
                && lookup.body["applicationId"] == application.to_string()
                && lookup.body["projectionVersion"] == 1,
            "unknown projection outcome could not be recovered by original operation"
        );
        let replay = db
            .projection_call(create_operation, "PUT", &path, Some(initial.clone()))
            .await?;
        ensure!(
            replay.status == StatusCode::OK && replay.body == created.body,
            "same operation replay changed the identity projection"
        );

        let after_create: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT projection_version FROM auth_applications WHERE application_id=$1), \
             (SELECT count(*) FROM identity_auth_command_receipts), \
             (SELECT count(*) FROM identity_audit_logs)",
        )
        .bind(application)
        .fetch_one(&db.pool)
        .await?;
        ensure!(after_create == (1, 1, 1), "projection replay wrote a second receipt or audit");

        let update_operation = Uuid::now_v7();
        let suspended = json!({
            "applicationId":application,
            "expectedVersion":1,
            "projection":{
                "ownership":"FIRST_PARTY",
                "partnerId":null,
                "status":"SUSPENDED",
                "displayName":"Owned application",
                "purpose":"First-party account application",
                "approvedScopes":[]
            }
        });
        let updated = db
            .projection_call(update_operation, "PUT", &path, Some(suspended.clone()))
            .await?;
        ensure!(
            updated.status == StatusCode::OK
                && updated.body["projectionVersion"] == 2
                && updated.body["status"] == "SUSPENDED",
            "approved projection was not versioned through disable"
        );
        let stale_operation = Uuid::now_v7();
        let stale = db
            .projection_call(stale_operation, "PUT", &path, Some(suspended.clone()))
            .await?;
        ensure!(stale.status == StatusCode::CONFLICT, "stale projection version was accepted");
        let after_stale: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT projection_version FROM auth_applications WHERE application_id=$1), \
             (SELECT count(*) FROM identity_auth_command_receipts), \
             (SELECT count(*) FROM identity_audit_logs)",
        )
        .bind(application)
        .fetch_one(&db.pool)
        .await?;
        ensure!(after_stale == (2, 2, 2), "version conflict changed projection or audit state");

        let wrong_purpose = db
            .admin_call(Uuid::now_v7(), "PUT", &path, Some(initial.clone()))
            .await?;
        ensure!(
            wrong_purpose.status == StatusCode::FORBIDDEN,
            "KEY_ADMIN credential was accepted for APPLICATION_PROJECTION"
        );
        let mismatched_id = Uuid::now_v7();
        let wrong_application = json!({
            "applicationId":mismatched_id,
            "expectedVersion":null,
            "projection":{
                "ownership":"FIRST_PARTY",
                "partnerId":null,
                "status":"APPROVED",
                "displayName":"Wrong application",
                "purpose":"Bound path test",
                "approvedScopes":[]
            }
        });
        let rejected = db
            .projection_call(Uuid::now_v7(), "PUT", &path, Some(wrong_application))
            .await?;
        ensure!(rejected.status == StatusCode::BAD_REQUEST, "path/body application binding was not enforced");
        let result: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT projection_version FROM auth_applications WHERE application_id=$1), \
             (SELECT count(*) FROM identity_auth_command_receipts)",
        )
        .bind(application)
        .fetch_one(&db.pool)
        .await?;
        ensure!(result == (2, 2), "wrong purpose or application expanded the projection boundary");

        let partner_application = Uuid::now_v7();
        let partner_id = Uuid::now_v7();
        let partner_path = format!("/internal/identity/auth/applications/{partner_application}");
        let pending_partner = json!({
            "applicationId":partner_application,
            "expectedVersion":null,
            "projection":{
                "ownership":"THIRD_PARTY",
                "partnerId":partner_id,
                "status":"PENDING_REVIEW",
                "displayName":"External application",
                "purpose":"Account-only external sign-in",
                "approvedScopes":[]
            }
        });
        let pending = db
            .projection_call(Uuid::now_v7(), "PUT", &partner_path, Some(pending_partner))
            .await?;
        ensure!(pending.status == StatusCode::OK && pending.body["status"] == "PENDING_REVIEW",
            "minimum third-party partner projection was not held for review");
        let attempt_approval = json!({
            "applicationId":partner_application,
            "expectedVersion":1,
            "projection":{
                "ownership":"THIRD_PARTY",
                "partnerId":partner_id,
                "status":"APPROVED",
                "displayName":"External application",
                "purpose":"Account-only external sign-in",
                "approvedScopes":[]
            }
        });
        let approval = db
            .projection_call(Uuid::now_v7(), "PUT", &partner_path, Some(attempt_approval))
            .await?;
        ensure!(approval.status == StatusCode::FORBIDDEN,
            "unreviewed third-party projection was allowed to become approved");
        let mut relabelled_partner = json!({
            "applicationId":partner_application,
            "expectedVersion":1,
            "projection":{
                "ownership":"FIRST_PARTY",
                "partnerId":null,
                "status":"APPROVED",
                "displayName":"External application",
                "purpose":"Account-only external sign-in",
                "approvedScopes":[]
            }
        });
        let relabelled = db
            .projection_call(Uuid::now_v7(), "PUT", &partner_path, Some(relabelled_partner.clone()))
            .await?;
        ensure!(relabelled.status == StatusCode::CONFLICT,
            "third-party projection bypassed review by changing its ownership");
        relabelled_partner["projection"]["ownership"] = json!("THIRD_PARTY");
        relabelled_partner["projection"]["partnerId"] = json!(Uuid::now_v7());
        relabelled_partner["projection"]["status"] = json!("PENDING_REVIEW");
        let transferred = db
            .projection_call(Uuid::now_v7(), "PUT", &partner_path, Some(relabelled_partner))
            .await?;
        ensure!(transferred.status == StatusCode::CONFLICT,
            "third-party projection was transferred to another partner");
        let unchanged_partner: (String, Option<Uuid>, String, i64) = sqlx::query_as(
            "SELECT ownership,partner_id,status,projection_version FROM auth_applications WHERE application_id=$1",
        )
        .bind(partner_application)
        .fetch_one(&db.pool)
        .await?;
        ensure!(unchanged_partner == ("THIRD_PARTY".into(), Some(partner_id), "PENDING_REVIEW".into(), 1),
            "rejected ownership changes mutated the original partner projection");
        let partners: (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE ownership='THIRD_PARTY'),count(*) FILTER (WHERE ownership='THIRD_PARTY' AND status='APPROVED') FROM auth_applications",
        )
        .fetch_one(&db.pool)
        .await?;
        ensure!(partners == (1, 0), "partner projection granted tenant authority or bypassed review");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[path = "auth_admin_tests.rs"]
mod auth_admin_tests;
#[path = "audit_tests/auth_consents.rs"]
mod auth_consents;
#[path = "audit_tests/auth_subjects.rs"]
mod auth_subjects;
