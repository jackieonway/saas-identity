//! Explicitly owned canonical PostgreSQL and ephemeral signing material.
//! Not compiled into a service and never reads ambient DATABASE_URL or secrets.
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use std::{
    collections::HashMap, future::Future, path::PathBuf, process::Command, str::FromStr, sync::Arc,
};
use uuid::Uuid;

const SCHEMA: &str = include_str!("../../saas-plateform/backend/migrations/0001_init.sql");

pub(crate) async fn isolated<F, Fut>(case: F) -> Result<()>
where
    F: FnOnce(PgPool) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    isolated_in(
        "IDENTITY_PHASE20_TEST_DATABASE_URL",
        "IDENTITY_PHASE20_TEST_CLUSTER_ID",
        "identity_phase20_core_",
        case,
    )
    .await
}

pub(crate) async fn isolated_phase22<F, Fut>(case: F) -> Result<()>
where
    F: FnOnce(PgPool) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    isolated_in(
        "IDENTITY_PHASE22_TEST_DATABASE_URL",
        "IDENTITY_PHASE22_TEST_CLUSTER_ID",
        "identity_phase22_core_",
        case,
    )
    .await
}

async fn isolated_in<F, Fut>(
    url_name: &str,
    cluster_name: &str,
    prefix: &str,
    case: F,
) -> Result<()>
where
    F: FnOnce(PgPool) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let raw = std::env::var(url_name).context("explicit owned loopback cluster required")?;
    let expected =
        std::env::var(cluster_name).context("explicit owned cluster identifier required")?;
    let options = PgConnectOptions::from_str(&raw)
        .map_err(|_| anyhow!("invalid Phase20 administration configuration"))?;
    ensure!(
        options.get_database() == Some("postgres")
            && matches!(options.get_host(), "127.0.0.1" | "localhost" | "::1"),
        "explicit loopback postgres administration database required"
    );
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .map_err(|_| anyhow!("owned cluster unavailable"))?;
    let actual: String =
        sqlx::query_scalar("SELECT system_identifier::text FROM pg_control_system()")
            .fetch_one(&admin)
            .await?;
    ensure!(
        actual == expected,
        "refusing a different PostgreSQL cluster"
    );
    let name = format!("{prefix}{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&admin)
        .await?;
    let opened = PgPoolOptions::new()
        .max_connections(12)
        .connect_with(options.database(&name))
        .await;
    let result = match opened {
        Err(_) => Err(anyhow!("owned Phase20 connection failed")),
        Ok(pool) => {
            let prepared = sqlx::raw_sql(SCHEMA).execute(&pool).await;
            let result = if let Err(error) = prepared {
                Err(error.into())
            } else {
                let work = pool.clone();
                match tokio::spawn(async move { case(work).await }).await {
                    Ok(result) => result,
                    Err(_) => Err(anyhow!("owned Phase20 assertion panicked")),
                }
            };
            pool.close().await;
            result
        }
    };
    ensure!(
        name.starts_with(prefix)
            && name.len() == prefix.len() + 32
            && name[prefix.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "unsafe Phase20 cleanup identifier"
    );
    let actual: String =
        sqlx::query_scalar("SELECT system_identifier::text FROM pg_control_system()")
            .fetch_one(&admin)
            .await?;
    ensure!(actual == expected, "cleanup cluster identity changed");
    sqlx::query(&format!("DROP DATABASE \"{name}\" WITH(FORCE)"))
        .execute(&admin)
        .await?;
    let remains: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(&name)
            .fetch_one(&admin)
            .await?;
    admin.close().await;
    ensure!(!remains, "owned Phase20 database remained");
    eprintln!("owned_identity_test_cleanup database={name} removed=true");
    result
}

pub(crate) struct KeyFixture {
    directory: PathBuf,
    pub(crate) keyset: PathBuf,
    pub(crate) modulus: String,
    pub(crate) exponent: String,
}
impl Drop for KeyFixture {
    fn drop(&mut self) {
        let temp = std::env::temp_dir();
        if self.directory.parent() == Some(temp.as_path())
            && self
                .directory
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("identity-phase20-core-key-"))
            && self
                .directory
                .canonicalize()
                .ok()
                .is_some_and(|path| path.parent() == temp.canonicalize().ok().as_deref())
        {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
}
impl KeyFixture {
    pub(crate) fn new() -> Result<Self> {
        let directory =
            std::env::temp_dir().join(format!("identity-phase20-core-key-{}", Uuid::now_v7()));
        std::fs::create_dir(&directory)?;
        let mut fixture = Self {
            keyset: directory.join("keyset.json"),
            directory,
            modulus: String::new(),
            exponent: "AQAB".into(),
        };
        let private = fixture.directory.join("private.pem");
        let native = if cfg!(windows) {
            let mapped = Command::new("wsl.exe")
                .args(["-e", "wslpath", "-u"])
                .arg(&private)
                .output()?;
            ensure!(
                mapped.status.success(),
                "could not map temporary Phase20 key path"
            );
            String::from_utf8(mapped.stdout)?.trim().to_owned()
        } else {
            private.to_string_lossy().into_owned()
        };
        let mut generated = if cfg!(windows) {
            let mut command = Command::new("wsl.exe");
            command.args(["-e", "openssl"]);
            command
        } else {
            Command::new("openssl")
        };
        let status = generated
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&native)
            .output()?;
        ensure!(
            status.status.success(),
            "temporary Phase20 signing key generation failed"
        );
        let mut inspect = if cfg!(windows) {
            let mut command = Command::new("wsl.exe");
            command.args(["-e", "openssl"]);
            command
        } else {
            Command::new("openssl")
        };
        let output = inspect
            .args(["rsa", "-in"])
            .arg(&native)
            .args(["-noout", "-modulus"])
            .output()?;
        ensure!(
            output.status.success(),
            "temporary Phase20 public key inspection failed"
        );
        let text = String::from_utf8(output.stdout)?;
        let modulus = text
            .trim()
            .strip_prefix("Modulus=")
            .context("temporary RSA modulus unavailable")?;
        fixture.modulus = URL_SAFE_NO_PAD.encode(hex::decode(modulus)?);
        let pem = std::fs::read_to_string(&private)?;
        std::fs::write(
            &fixture.keyset,
            serde_json::to_vec(
                &json!({"keys":[{"kid":"phase20-core","privateKeyPem":pem,"n":fixture.modulus,"e":fixture.exponent}]}),
            )?,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&private, &fixture.keyset] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Ok(fixture)
    }
    pub(crate) async fn state(&self, pool: PgPool, worker: bool) -> Result<crate::state::AppState> {
        let env = HashMap::from([
            (
                "DATABASE_URL".into(),
                "postgres://phase20@127.0.0.1/owned_test".into(),
            ),
            ("APP_ENV".into(), "test".into()),
            ("SSO_ENABLED".into(), "true".into()),
            ("SSO_ORIGIN".into(), "https://auth.saas.test".into()),
            ("OIDC_ENABLED".into(), "true".into()),
            ("OIDC_ISSUER".into(), "https://auth.saas.test".into()),
            (
                "OIDC_KEYSET_PATH".into(),
                self.keyset.to_string_lossy().into_owned(),
            ),
            ("AUTH_DELIVERY_WORKER_ENABLED".into(), worker.to_string()),
            (
                "AUTH_DELIVERY_TEST_ORIGINS".into(),
                "https://collector.example.test:24446".into(),
            ),
        ]);
        let config = crate::config::Config::from_values(&env)?;
        sqlx::query("INSERT INTO public.auth_provider_settings(singleton,issuer,created_at) VALUES(true,'https://auth.saas.test',clock_timestamp()) ON CONFLICT(singleton) DO NOTHING").execute(&pool).await?;
        sqlx::query("INSERT INTO public.auth_signing_keys(kid,n,e,active,published_at,activated_at) VALUES('phase20-core',$1,$2,true,clock_timestamp(),clock_timestamp()) ON CONFLICT(kid) DO NOTHING").bind(&self.modulus).bind(&self.exponent).execute(&pool).await?;
        Ok(crate::state::AppState::new(pool, Arc::new(config)))
    }
}

#[derive(Clone)]
pub(crate) struct Client {
    pub(crate) id: Uuid,
    pub(crate) secret: String,
    pub(crate) application: Uuid,
    pub(crate) group: Uuid,
    pub(crate) scopes: Vec<Uuid>,
}
pub(crate) struct Grant {
    pub(crate) id: Uuid,
    pub(crate) access: String,
    pub(crate) refresh: String,
    pub(crate) sid: String,
    pub(crate) sub: String,
}

pub(crate) async fn account(pool: &PgPool) -> Result<(Uuid, Uuid)> {
    let user = Uuid::now_v7();
    let session = Uuid::now_v7();
    sqlx::query("INSERT INTO public.users(id,username,password_hash,status,session_version) VALUES($1,$2,'phase20-owned-unused-password','ENABLED',3)")
        .bind(user).bind(format!("phase20_{}",user.simple())).execute(pool).await?;
    sqlx::query("INSERT INTO public.sso_sessions(id,user_id,token_hash,csrf_hash,account_version,authenticated_at,expires_at) VALUES($1,$2,$3,$4,3,clock_timestamp(),clock_timestamp()+interval '30 minutes')")
        .bind(session).bind(user).bind(crate::util::hash::sha256_hex(&format!("session-{session}")))
        .bind(crate::util::hash::sha256_hex(&format!("csrf-{session}"))).execute(pool).await?;
    Ok((user, session))
}

pub(crate) async fn client(pool: &PgPool) -> Result<Client> {
    let id = Uuid::now_v7();
    let application = Uuid::now_v7();
    let group = Uuid::now_v7();
    let secret = crate::util::hash::sha256_hex(&format!("phase20-client-{id}"));
    sqlx::query("INSERT INTO public.auth_applications(application_id,ownership,status,display_name,purpose,approved_scopes) VALUES($1,'FIRST_PARTY','APPROVED','Owned Phase20 RP','ACCOUNT_LOGIN',ARRAY['openid','profile','offline_access'])")
        .bind(application).execute(pool).await?;
    let resource = Uuid::now_v7();
    sqlx::query("INSERT INTO public.auth_resources(id,resource_key,audience,status) VALUES($1,'userinfo','https://auth.saas.test/oauth/userinfo','ACTIVE') ON CONFLICT(resource_key) DO NOTHING").bind(resource).execute(pool).await?;
    let resource: Uuid =
        sqlx::query_scalar("SELECT id FROM public.auth_resources WHERE resource_key='userinfo'")
            .fetch_one(pool)
            .await?;
    for name in ["openid", "profile", "offline_access"] {
        sqlx::query("INSERT INTO public.auth_scopes(id,resource_id,scope_name,status) VALUES($1,$2,$3,'ACTIVE') ON CONFLICT(resource_id,scope_name) DO NOTHING")
            .bind(Uuid::now_v7()).bind(resource).bind(name).execute(pool).await?;
    }
    let scopes: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.auth_scopes WHERE resource_id=$1 ORDER BY scope_name",
    )
    .bind(resource)
    .fetch_all(pool)
    .await?;
    sqlx::query("INSERT INTO public.auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,status) VALUES($1,$1::text,'Owned Phase20 RP',$2,'test','CONFIDENTIAL','WEB_BFF','USER','ACCOUNT_ONLY',ARRAY[]::text[],ARRAY['authorization_code','refresh_token'],'client_secret_basic',ARRAY['https://rp.example.test/callback'],'ENABLED')")
        .bind(id).bind(application).execute(pool).await?;
    sqlx::query("INSERT INTO public.auth_client_credentials(id,client_id,credential_version,secret_digest) VALUES($1,$2,1,$3)")
        .bind(Uuid::now_v7()).bind(id).bind(crate::util::hash::sha256_hex(&secret)).execute(pool).await?;
    for scope in &scopes {
        sqlx::query("INSERT INTO public.auth_client_permissions(client_id,resource_id,scope_id) VALUES($1,$2,$3)").bind(id).bind(resource).bind(scope).execute(pool).await?;
    }
    sqlx::query("INSERT INTO public.auth_consent_groups(id,application_id,environment,display_name,purpose,context_mode,status) VALUES($1,$2,'test','Owned Phase20 consent','ACCOUNT_LOGIN','ACCOUNT_ONLY','ACTIVE')")
        .bind(group).bind(application).execute(pool).await?;
    sqlx::query("INSERT INTO public.auth_consent_group_clients(group_id,client_id,application_id,environment,subject_mode,context_mode) VALUES($1,$2,$3,'test','USER','ACCOUNT_ONLY')")
        .bind(group).bind(id).bind(application).execute(pool).await?;
    Ok(Client {
        id,
        secret,
        application,
        group,
        scopes,
    })
}

pub(crate) async fn backchannel(pool: &PgPool, client: &Client) -> Result<Uuid> {
    let target = Uuid::now_v7();
    sqlx::query("INSERT INTO public.auth_delivery_targets(id,purpose,status,client_id,url,allowed_ips,verified_reference,verified_at,expires_at) VALUES($1,'BACK_CHANNEL','ACTIVE',$2,'https://collector.example.test:24446/backchannel',ARRAY['127.0.0.1'],$3,clock_timestamp(),clock_timestamp()+interval '1 day')")
        .bind(target).bind(client.id).bind(Uuid::now_v7()).execute(pool).await?;
    sqlx::query("UPDATE public.auth_clients SET logout_mode='BACK_CHANNEL',backchannel_target_id=$2,backchannel_logout_uri='https://collector.example.test:24446/backchannel' WHERE id=$1")
        .bind(client.id).bind(target).execute(pool).await?;
    Ok(target)
}

pub(crate) async fn grant(
    pool: &PgPool,
    user: Uuid,
    session: Uuid,
    client: &Client,
    offline: bool,
) -> Result<Grant> {
    let consent = Uuid::now_v7();
    sqlx::query("INSERT INTO public.auth_consents(id,user_id,group_id,status,generation,group_version,version,authorized_at) VALUES($1,$2,$3,'ACTIVE',1,1,1,clock_timestamp()) ON CONFLICT(user_id,group_id) DO NOTHING")
        .bind(consent).bind(user).bind(client.group).execute(pool).await?;
    let consent: Uuid =
        sqlx::query_scalar("SELECT id FROM public.auth_consents WHERE user_id=$1 AND group_id=$2")
            .bind(user)
            .bind(client.group)
            .fetch_one(pool)
            .await?;
    let scopes: Vec<Uuid> = if offline {
        client.scopes.clone()
    } else {
        sqlx::query_scalar(
            "SELECT id FROM public.auth_scopes WHERE id=ANY($1) AND scope_name<>'offline_access'",
        )
        .bind(&client.scopes)
        .fetch_all(pool)
        .await?
    };
    for scope in &scopes {
        sqlx::query("INSERT INTO public.auth_consent_scopes(consent_id,resource_id,scope_id) SELECT $1,resource_id,id FROM public.auth_scopes WHERE id=$2 ON CONFLICT DO NOTHING").bind(consent).bind(scope).execute(pool).await?;
    }
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO public.auth_grants(id,client_id,subject_mode,user_id,consent_id,consent_generation,consent_group_version,source_session_id,context_mode,account_version,client_policy_version,application_projection_version,scope_ids,audiences,auth_time,expires_at) SELECT $1,client.id,'USER',$2,$3,1,1,$4,'ACCOUNT_ONLY',subject.session_version,client.policy_version,app.projection_version,$5,ARRAY['https://auth.saas.test/oauth/userinfo'],session.authenticated_at,clock_timestamp()+CASE WHEN $6 THEN interval '7 days' ELSE interval '30 minutes' END FROM public.auth_clients client JOIN public.auth_applications app ON app.application_id=client.application_id JOIN public.users subject ON subject.id=$2 JOIN public.sso_sessions session ON session.id=$4 AND session.user_id=subject.id WHERE client.id=$7")
        .bind(id).bind(user).bind(consent).bind(session).bind(&scopes).bind(offline).bind(client.id).execute(pool).await?;
    for scope in &scopes {
        sqlx::query("INSERT INTO public.auth_grant_scopes(grant_id,resource_id,scope_id) SELECT $1,resource_id,id FROM public.auth_scopes WHERE id=$2").bind(id).bind(scope).execute(pool).await?;
    }
    let sid = crate::util::hash::sha256_hex(&format!("sid-{id}"));
    let sub = crate::util::hash::sha256_hex(&format!("subject-{user}-{}", client.application));
    sqlx::query("INSERT INTO public.auth_rp_sessions(grant_id,client_id,user_id,source_session_id,public_sid,public_sub) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(id).bind(client.id).bind(user).bind(session).bind(&sid).bind(&sub).execute(pool).await?;
    let access = crate::util::hash::sha256_hex(&format!("access-{id}"));
    let refresh = crate::util::hash::sha256_hex(&format!("refresh-{id}"));
    let access_id = Uuid::now_v7();
    sqlx::query("INSERT INTO public.auth_access_tokens(id,grant_id,token_digest,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '5 minutes')")
        .bind(access_id).bind(id).bind(crate::util::hash::sha256_hex(&access)).execute(pool).await?;
    for scope in &scopes {
        sqlx::query("INSERT INTO public.auth_access_token_scopes(token_id,resource_id,scope_id) SELECT $1,resource_id,id FROM public.auth_scopes WHERE id=$2").bind(access_id).bind(scope).execute(pool).await?;
    }
    let family = Uuid::now_v7();
    sqlx::query("INSERT INTO public.auth_refresh_families(id,grant_id,absolute_expires_at,idle_expires_at) SELECT $1,id,expires_at,LEAST(expires_at,statement_timestamp()+interval '30 minutes') FROM public.auth_grants WHERE id=$2")
        .bind(family).bind(id).execute(pool).await?;
    sqlx::query("INSERT INTO public.auth_refresh_tokens(id,family_id,token_digest,generation,expires_at) VALUES($1,$2,$3,1,clock_timestamp()+interval '30 minutes')")
        .bind(Uuid::now_v7()).bind(family).bind(crate::util::hash::sha256_hex(&refresh)).execute(pool).await?;
    Ok(Grant {
        id,
        access,
        refresh,
        sid,
        sub,
    })
}
