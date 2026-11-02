//! Fresh, marked databases and actual deployment LOGIN roles. Never SET ROLE.
use super::{actor_fixture, test_keys::TestKeys, KeySet};
use crate::state::AppState;
use anyhow::{anyhow, ensure, Context, Result};
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use std::{collections::HashMap, future::Future, str::FromStr, sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

pub(super) const ISSUER: &str = "https://auth.saas.test";
const CREATE: &str =
    include_str!("../../../../saas-plateform/backend/ops/identity-deployment/create-roles.sql");
const PROVISION: &str =
    include_str!("../../../../saas-plateform/backend/ops/identity-deployment/provision.sql");
const VERIFY: &str =
    include_str!("../../../../saas-plateform/backend/ops/identity-deployment/verify.sql");
const SUFFIXES: [&str; 6] = [
    "identity_runtime",
    "platform_runtime",
    "bridge_owner",
    "platform_owner",
    "identity_owner",
    "migration_owner",
];
#[derive(Clone)]
pub(super) struct Actor {
    pub user: Uuid,
    pub tenant: Uuid,
    pub org: Uuid,
    pub session: Uuid,
    pub sso: Uuid,
    pub menu: Uuid,
    pub grant: Uuid,
}
#[derive(Clone)]
pub(super) struct Database {
    pub owner: PgPool,
    pub runtime: PgPool,
    pub keys: Arc<TestKeys>,
    pub actor: Actor,
    pub service: Uuid,
    pub secret: String,
    pub state: AppState,
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn render(script: &str, values: &HashMap<&str, String>) -> Result<String> {
    let mut sql = script
        .lines()
        .filter_map(|line| {
            if line.trim() == "\\gset" {
                Some(";".to_owned())
            } else if line.trim_start().starts_with('\\') {
                None
            } else {
                Some(line.to_owned())
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    for (key, value) in values {
        sql = sql.replace(&format!(":'{key}'"), &quote(value));
    }
    ensure!(!sql.contains(":'"), "unresolved deployment SQL input");
    Ok(sql)
}
pub(super) async fn isolated<F, Fut>(case: F) -> Result<()>
where
    F: FnOnce(Database) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let url = std::env::var("IDENTITY_PHASE23_TEST_DATABASE_URL")
        .context("explicit Phase23 administration URL required")?;
    let expected = std::env::var("IDENTITY_PHASE23_TEST_CLUSTER_ID")
        .context("explicit Phase23 cluster identifier required")?;
    let options =
        PgConnectOptions::from_str(&url).map_err(|_| anyhow!("invalid Phase23 configuration"))?;
    ensure!(
        options.get_database() == Some("postgres")
            && options.get_port() == 55494
            && matches!(options.get_host(), "127.0.0.1" | "localhost" | "::1"),
        "only explicit owned 55494 loopback cluster is allowed"
    );
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .map_err(|_| anyhow!("owned Phase23 cluster unavailable"))?;
    let cluster: String =
        sqlx::query_scalar("SELECT system_identifier::text FROM pg_control_system()")
            .fetch_one(&admin)
            .await?;
    ensure!(
        !expected.is_empty() && cluster == expected,
        "wrong Phase23 cluster"
    );
    let deployment = Uuid::now_v7();
    let simple = deployment.simple().to_string();
    let name = format!("identity_phase23_keys_{simple}");
    let prefix = format!("i23k_{}", &simple[12..]);
    let keys = Arc::new(TestKeys::new()?);
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&admin)
        .await?;
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options.clone().database(&name))
        .await
    {
        Ok(pool) => pool,
        Err(_) => {
            sqlx::query(&format!("DROP DATABASE \"{name}\" WITH(FORCE)"))
                .execute(&admin)
                .await?;
            return Err(anyhow!("owned Phase23 database unavailable"));
        }
    };
    let prepared=async{
        sqlx::query(&format!("COMMENT ON DATABASE \"{name}\" IS {}",quote(&format!("identity-deployment/1/{deployment}")))).execute(&pool).await?;
        sqlx::migrate!("../saas-plateform/backend/migrations").run(&pool).await?;
        sqlx::query("INSERT INTO auth_provider_settings(singleton,issuer,created_at) VALUES(true,$1,clock_timestamp())").bind(ISSUER).execute(&pool).await?;
        let actor=actor_fixture::seed(&pool).await?;
        let service=Uuid::now_v7();let secret=crate::util::hash::sha256_hex(&Uuid::now_v7().to_string());
        sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,created_at) VALUES($1,$2,'KEY_ADMIN','ENABLED',clock_timestamp())").bind(service).bind(crate::util::hash::sha256_hex(&secret)).execute(&pool).await?;
        let values=HashMap::from([("expected_database",name.clone()),("deployment_id",deployment.to_string()),("issuer",ISSUER.into()),("role_prefix",prefix.clone())]);
        for script in [CREATE,PROVISION,VERIFY]{sqlx::raw_sql(&render(script,&values)?).execute(&pool).await?;}
        let role=format!("{prefix}_identity_runtime");let password=crate::util::hash::sha256_hex(&Uuid::now_v7().to_string());
        sqlx::query(&format!("ALTER ROLE \"{role}\" PASSWORD {}",quote(&password))).execute(&pool).await?;
        let runtime=PgPoolOptions::new().max_connections(10).connect_with(options.database(&name).username(&role).password(&password)).await.map_err(|_|anyhow!("real Phase23 LOGIN failed"))?;
        let principal:(String,String)=sqlx::query_as("SELECT current_user::text,session_user::text").fetch_one(&runtime).await?;
        ensure!(principal==(role.clone(),role),"real runtime LOGIN identity required");
        let mut config=crate::config::Config::from_values(&HashMap::from([("APP_ENV".into(),"test".into()),("DATABASE_URL".into(),"postgres://phase23@127.0.0.1/owned".into())]))?;
        config.sso_enabled=true;config.sso_origin=Some(ISSUER.into());config.oidc_enabled=true;config.oidc_issuer=Some(ISSUER.into());config.oidc_keys=Some(Arc::new(KeySet::load(keys.path_text()?)?));
        let state=AppState::new(runtime.clone(),Arc::new(config));
        Ok::<_,anyhow::Error>((runtime,actor,service,secret,state))
    }.await;
    let result = match prepared {
        Ok((runtime, actor, service, secret, state)) => {
            let db = Database {
                owner: pool.clone(),
                runtime: runtime.clone(),
                keys: keys.clone(),
                actor,
                service,
                secret,
                state,
            };
            eprintln!(
                "phase23_owned_resource database={name} role_prefix={prefix} real_login=true"
            );
            let result = match tokio::spawn(case(db)).await {
                Ok(result) => result,
                Err(_) => Err(anyhow!("Phase23 assertion panicked; cleanup follows")),
            };
            runtime.close().await;
            result
        }
        Err(error) => Err(error),
    };
    pool.close().await;
    ensure!(
        name.starts_with("identity_phase23_keys_")
            && name.len() == 54
            && prefix.starts_with("i23k_")
            && prefix.len() == 25
            && name
                .bytes()
                .chain(prefix.bytes())
                .all(|v| v.is_ascii_alphanumeric() || v == b'_'),
        "unsafe cleanup identifier"
    );
    let current: String =
        sqlx::query_scalar("SELECT system_identifier::text FROM pg_control_system()")
            .fetch_one(&admin)
            .await?;
    ensure!(current == cluster, "cleanup cluster changed");
    let marker: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=$1",
    )
    .bind(&name)
    .fetch_one(&admin)
    .await?;
    ensure!(
        marker.as_deref() == Some(format!("identity-deployment/1/{deployment}").as_str()),
        "database ownership marker changed"
    );
    sqlx::query(&format!("DROP DATABASE \"{name}\" WITH(FORCE)"))
        .execute(&admin)
        .await?;
    for suffix in SUFFIXES {
        let role = format!("{prefix}_{suffix}");
        sqlx::query(&format!("DROP ROLE IF EXISTS \"{role}\""))
            .execute(&admin)
            .await?;
    }
    let remaining:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM pg_database WHERE datname=$1)+(SELECT count(*) FROM pg_roles WHERE rolname LIKE $2)").bind(&name).bind(format!("{prefix}_%" )).fetch_one(&admin).await?;
    admin.close().await;
    ensure!(remaining == 0, "Phase23 resources remain");
    eprintln!("phase23_owned_cleanup database={name} database_roles_remaining={remaining}");
    keys.cleanup()?;
    result
}
impl Database {
    pub async fn accept(
        &self,
        operation: Uuid,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<String> {
        let digest = request_digest(method, path, body)?;
        sqlx::query("INSERT INTO platform_auth_command_intents(id,actor_user_id,tenant_id,organization_id,session_id,service_client_id,request_digest,method,path,accepted_at,management_permission) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp(),'system:oauth:keys') ON CONFLICT(id) DO NOTHING")
            .bind(operation).bind(self.actor.user).bind(self.actor.tenant).bind(self.actor.org).bind(self.actor.session).bind(self.service).bind(&digest).bind(method).bind(path).execute(&self.owner).await?;
        Ok(digest)
    }
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        operation: Option<Uuid>,
    ) -> Result<(StatusCode, Value)> {
        let digest = request_digest(method, path, body).unwrap_or_default();
        self.request(
            &self.state,
            method,
            path,
            body,
            operation,
            &digest,
            &self.secret,
            false,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn request(
        &self,
        state: &AppState,
        method: &str,
        path: &str,
        body: &Value,
        operation: Option<Uuid>,
        digest: &str,
        secret: &str,
        cookie: bool,
    ) -> Result<(StatusCode, Value)> {
        let mut request = Request::builder().method(method).uri(path).header(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{secret}", self.service))
            ),
        );
        if let Some(id) = operation {
            request = request
                .header("x-identity-operation", id.to_string())
                .header("x-identity-operation-digest", digest);
        }
        if cookie {
            request = request.header(header::COOKIE, "owned=fixture");
        }
        let raw = if method == "GET" || body.is_null() {
            Vec::new()
        } else {
            request = request.header(header::CONTENT_TYPE, "application/json");
            serde_json::to_vec(body)?
        };
        let response = crate::router(state.clone())
            .oneshot(request.body(Body::from(raw))?)
            .await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 65536).await?;
        Ok((
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ))
    }
    pub async fn command(
        &self,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<(StatusCode, Value)> {
        let id = Uuid::now_v7();
        self.accept(id, method, path, body).await?;
        self.call(method, path, body, Some(id)).await
    }
    pub async fn active(&self) -> Result<Vec<String>> {
        Ok(
            sqlx::query_scalar("SELECT kid FROM auth_signing_keys WHERE active ORDER BY kid")
                .fetch_all(&self.owner)
                .await?,
        )
    }
    pub async fn assert_no_commit(&self, operation: Uuid, kid: &str) -> Result<()> {
        let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM identity_auth_command_receipts WHERE operation_id=$1),(SELECT count(*) FROM auth_signing_keys WHERE kid=$2),(SELECT count(*) FROM identity_audit_logs WHERE action='OIDC_PUBLISH_KEY' AND detail::jsonb->>'kid'=$2)").bind(operation).bind(kid).fetch_one(&self.owner).await?;
        ensure!(
            counts == (0, 0, 0),
            "denied key command partially committed"
        );
        Ok(())
    }
    pub async fn wait_lock(&self, pid: i32) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(3),async{
            loop{let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')").bind(pid).fetch_one(&self.owner).await?;if waiting{return Ok::<(),anyhow::Error>(());}tokio::task::yield_now().await;}
        }).await.context("lock barrier did not arrive")??;
        Ok(())
    }
}

fn request_digest(method: &str, path: &str, body: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, v)| (k.clone(), sorted(v)))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            v => v.clone(),
        }
    }
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&sorted(
        &serde_json::json!({"method":method,"path":path,"body":body}),
    ))?)))
}
