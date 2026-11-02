//! Real canonical PostgreSQL + HTTP lifecycle tests. Only the consumer-defined
//! platform authorization predicate is replaced by an explicitly scoped fixture;
//! actual platform membership/MFA authorization is verified by platform tests.

use super::*;
use anyhow::{anyhow, ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    middleware,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
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
const CONSUME: &str = "AUTH_INVITATION_CONSUME";
const DELIVERY: &str = "AUTH_INVITATION_DELIVERY";

struct Database {
    pool: PgPool,
    admin: PgPool,
    name: String,
    url: String,
    actor: Uuid,
    session: Uuid,
    services: [(Uuid, &'static str, String); 3],
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
            .await
            .map_err(|_| anyhow!("owned Phase19 cluster unavailable"))?;
        let cluster: String =
            sqlx::query_scalar("SELECT system_identifier::text FROM pg_control_system()")
                .fetch_one(&admin)
                .await?;
        let expected = std::env::var("IDENTITY_PHASE19_TEST_CLUSTER_ID")
            .map_err(|_| anyhow!("explicit IDENTITY_PHASE19_TEST_CLUSTER_ID required"))?;
        ensure!(cluster == expected, "wrong Phase19 task-owned cluster");
        let name = format!("identity_phase19_invite_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await?;
        let pool = match PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options.database(&name))
            .await
        {
            Ok(pool) => pool,
            Err(_) => {
                sqlx::query(&format!("DROP DATABASE \"{name}\" WITH(FORCE)"))
                    .execute(&admin)
                    .await?;
                return Err(anyhow!("owned Phase19 database unavailable"));
            }
        };
        let db = Self {
            pool,
            admin,
            name,
            url,
            actor: Uuid::now_v7(),
            session: Uuid::now_v7(),
            services: [
                (Uuid::now_v7(), ADMIN, "a".repeat(64)),
                (Uuid::now_v7(), CONSUME, "b".repeat(64)),
                (Uuid::now_v7(), DELIVERY, "c".repeat(64)),
            ],
        };
        let initialized = async {
            sqlx::raw_sql(SCHEMA).execute(&db.pool).await?;
            for (id,purpose,secret) in &db.services {
                sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,created_at) VALUES($1,$2,$3,'ENABLED',clock_timestamp())")
                    .bind(id).bind(sha256_hex(secret)).bind(purpose).execute(&db.pool).await?;
            }
            sqlx::query("CREATE TABLE public.phase19_invitation_authorizations(actor uuid NOT NULL,session uuid NOT NULL,authorized boolean NOT NULL)").execute(&db.pool).await?;
            sqlx::query("INSERT INTO public.phase19_invitation_authorizations VALUES($1,$2,true)").bind(db.actor).bind(db.session).execute(&db.pool).await?;
            // This is the single replaced consumer dependency. Canonical
            // invitation/operation fences still bind every accepted command
            // field and require the recent-factor check. Real employee/MFA
            // evidence is supplied by the platform's canonical role tests.
            sqlx::raw_sql("CREATE OR REPLACE FUNCTION public.platform_identity_management_actor_active(actor_ref uuid,session_ref uuid,permission_ref text,require_recent boolean,production boolean) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog,public AS $$ SELECT $3='system:oauth:invite' AND $4 AND NOT $5 AND EXISTS(SELECT 1 FROM public.phase19_invitation_authorizations a WHERE a.actor=$1 AND a.session=$2 AND a.authorized) $$;").execute(&db.pool).await?;
            Ok::<(),anyhow::Error>(())
        }.await;
        if let Err(error) = initialized {
            return Err(match db.finish(Err(error)).await {
                Err(error) => error,
                Ok(()) => anyhow!("owned invitation initialization unexpectedly succeeded"),
            });
        }
        Ok(db)
    }

    fn state(&self, enabled: bool) -> Result<AppState> {
        let mut config = crate::config::Config::from_values(&HashMap::from([
            ("APP_ENV".into(), "test".into()),
            ("DATABASE_URL".into(), self.url.clone()),
        ]))?;
        if enabled {
            config.invitation_keys = Some(Arc::new(InvitationKeys::fixture()));
        }
        config.sso_enabled = true;
        config.sso_origin = Some("https://auth.saas.test".into());
        Ok(AppState::new(self.pool.clone(), Arc::new(config)))
    }

    fn issue_body(&self, recipient: &str) -> Value {
        json!({"actorUserId":self.actor,"actorSessionId":self.session,"recipientRef":recipient,"purpose":"ACCOUNT_ONBOARDING"})
    }

    async fn call(
        &self,
        purpose: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        operation: Option<Uuid>,
        authorization_and_keys: (bool, bool),
    ) -> Result<(StatusCode, Value)> {
        let (accepted, enabled) = authorization_and_keys;
        let (service, _, secret) = self
            .services
            .iter()
            .find(|(_, registered, _)| *registered == purpose)
            .ok_or_else(|| anyhow!("unknown invitation fixture purpose"))?;
        let mut request = Request::builder().method(method).uri(path).header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{service}:{secret}"))),
        );
        if let Some(operation) = operation {
            let raw = body.as_ref().unwrap_or(&Value::Null);
            let digest = request_digest(method, path, raw)?;
            if accepted {
                let actor = raw["actorUserId"]
                    .as_str()
                    .map(Uuid::parse_str)
                    .transpose()?
                    .unwrap_or(self.actor);
                let session = raw["actorSessionId"]
                    .as_str()
                    .map(Uuid::parse_str)
                    .transpose()?
                    .unwrap_or(self.session);
                sqlx::query("INSERT INTO platform_auth_command_intents(id,actor_user_id,tenant_id,organization_id,session_id,service_client_id,request_digest,method,path,accepted_at,management_permission) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp(),'system:oauth:invite') ON CONFLICT(id) DO NOTHING")
                    .bind(operation).bind(actor).bind(Uuid::now_v7()).bind(Uuid::now_v7()).bind(session).bind(service).bind(&digest).bind(method).bind(path).execute(&self.pool).await?;
            }
            request = request
                .header("x-identity-operation", operation.to_string())
                .header("x-identity-operation-digest", digest);
        }
        let bytes = if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json");
            serde_json::to_vec(&body)?
        } else {
            Vec::new()
        };
        let state = self.state(enabled)?;
        let response = crate::internal::routes()
            .layer(middleware::from_fn_with_state(
                state.clone(),
                internal::guard,
            ))
            .with_state(state)
            .oneshot(request.body(Body::from(bytes))?)
            .await?;
        ensure!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok())
                == Some("no-store"),
            "private invitation response permits caching"
        );
        let status = response.status();
        let raw = to_bytes(response.into_body(), 65_536).await?;
        let result = if raw.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&raw)?
        };
        Ok((status, result))
    }

    async fn issue(&self, recipient: &str) -> Result<(Uuid, Value)> {
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_delivery_targets WHERE purpose='VERIFIED_CHANNEL' AND channel_purpose='ACCOUNT_ONBOARDING' AND recipient_ref=$1 AND status='ACTIVE')")
            .bind(recipient).fetch_one(&self.pool).await?;
        if !exists {
            self.channel(recipient).await?;
        }
        let id = Uuid::now_v7();
        let (status, result) = self
            .call(
                ADMIN,
                "POST",
                PATH,
                Some(self.issue_body(recipient)),
                Some(id),
                (true, true),
            )
            .await?;
        ensure!(
            status == StatusCode::OK,
            "invitation fixture issuance failed: {status} code={}",
            result["code"]
        );
        Ok((id, result))
    }

    async fn material(&self, id: Uuid, recipient: &str) -> Result<String> {
        let verified = self.verification(id, recipient).await?;
        let job: Uuid = sqlx::query_scalar(
            "SELECT id FROM auth_delivery_jobs WHERE invitation_id=$1 AND kind='INVITATION'",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        let lease = Uuid::now_v7();
        sqlx::query("UPDATE auth_delivery_jobs SET state='LEASED',lease_id=$2,lease_until=clock_timestamp()+interval '1 minute',attempt_count=1 WHERE id=$1")
            .bind(job).bind(lease).execute(&self.pool).await?;
        let material = material_for_delivery(&self.state(true)?, job, lease).await?;
        ensure!(
            material.recipient_ref == recipient
                && material.invitation_id == id
                && material.purpose == "ACCOUNT_ONBOARDING"
                && material.target_version == 1
                && material.verification_ref == verified
                && material.expires_at > Utc::now(),
            "worker material lost its directed binding"
        );
        Ok(material.token)
    }

    async fn channel(&self, recipient: &str) -> Result<Uuid> {
        let target = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_delivery_targets(id,purpose,status,recipient_ref,channel_purpose,url,allowed_ips,version,verified_reference,verified_at,expires_at) VALUES($1,'VERIFIED_CHANNEL','ACTIVE',$2,'ACCOUNT_ONBOARDING','https://owned-collector.example.test/invitations',ARRAY['93.184.216.34'],1,$3,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '2 days')")
            .bind(target).bind(recipient).bind(Uuid::now_v7()).execute(&self.pool).await?;
        Ok(target)
    }

    async fn verification(&self, id: Uuid, recipient: &str) -> Result<Uuid> {
        let existing:Option<Uuid>=sqlx::query_scalar("SELECT id FROM auth_invitation_verifications WHERE invitation_id=$1 AND recipient_ref=$2 AND status='ACTIVE' ORDER BY id LIMIT 1")
            .bind(id).bind(recipient).fetch_optional(&self.pool).await?;
        if let Some(existing) = existing {
            return Ok(existing);
        }
        let (target,version):(Uuid,i64)=sqlx::query_as("SELECT target_id,target_version FROM auth_delivery_jobs WHERE invitation_id=$1 AND kind='INVITATION'")
            .bind(id).fetch_one(&self.pool).await?;
        let verification = Uuid::now_v7();
        sqlx::query("INSERT INTO auth_invitation_verifications(id,invitation_id,recipient_ref,purpose,delivery_target_id,delivery_target_version,verified_reference,verified_at,expires_at,status,version) VALUES($1,$2,$3,'ACCOUNT_ONBOARDING',$4,$5,$6,clock_timestamp(),clock_timestamp()+interval '1 hour','ACTIVE',1)")
            .bind(verification).bind(id).bind(recipient).bind(target).bind(version).bind(Uuid::now_v7()).execute(&self.pool).await?;
        Ok(verification)
    }

    async fn expired_invitation(&self, recipient: &str) -> Result<(Uuid, String, Uuid)> {
        let target = self.channel(recipient).await?;
        let id = Uuid::now_v7();
        let created_at = Utc::now() - Duration::hours(48);
        let expires_at = created_at + Duration::hours(24);
        let mut invitation = Invitation {
            id,
            service_id: self.services[0].0,
            operation_id: id,
            request_digest: sha256_hex("owned-expired-invitation-fixture"),
            recipient_ref: recipient.into(),
            purpose: "ACCOUNT_ONBOARDING".into(),
            actor_user_id: self.actor,
            actor_session_id: self.session,
            key_version: 1,
            token_digest: String::new(),
            status: "ACTIVE".into(),
            version: 1,
            created_at,
            expires_at,
            revoked_at: None,
            consumed_at: None,
            expired: true,
        };
        let token = InvitationKeys::fixture().derive(&invitation)?;
        invitation.token_digest = sha256_hex(&token);
        // Expiry is an original immutable binding. Seed the historical source
        // at INSERT; never weaken its production trigger to mutate a live one.
        sqlx::query("INSERT INTO auth_invitations(id,service_id,operation_id,request_digest,recipient_ref,purpose,actor_user_id,actor_session_id,key_version,token_digest,status,version,created_at,expires_at) VALUES($1,$2,$1,$3,$4,'ACCOUNT_ONBOARDING',$5,$6,1,$7,'ACTIVE',1,$8,$9)")
            .bind(id).bind(invitation.service_id).bind(&invitation.request_digest).bind(recipient).bind(self.actor).bind(self.session)
            .bind(&invitation.token_digest).bind(created_at).bind(expires_at).execute(&self.pool).await?;
        sqlx::query("INSERT INTO auth_delivery_jobs(id,kind,event_key,target_id,target_version,invitation_id) VALUES($1,'INVITATION',$2,$3,1,$4)")
            .bind(Uuid::now_v7()).bind(sha256_hex(&format!("auth-invitation/1\n{id}"))).bind(target).bind(id).execute(&self.pool).await?;
        let verified = self.verification(id, recipient).await?;
        Ok((id, token, verified))
    }

    async fn accept(&self, id: Uuid, body: Value) -> Result<(StatusCode, Value)> {
        self.public_call(
            &format!("/api/sso/invitations/{id}/accept"),
            body,
            Some("https://auth.saas.test"),
            true,
        )
        .await
    }

    async fn public_call(
        &self,
        path: &str,
        body: Value,
        origin: Option<&str>,
        keys: bool,
    ) -> Result<(StatusCode, Value)> {
        let state = self.state(keys)?;
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        let response = crate::internal::routes()
            .layer(middleware::from_fn_with_state(
                state.clone(),
                internal::guard,
            ))
            .with_state(state)
            .oneshot(request.body(Body::from(serde_json::to_vec(&body)?))?)
            .await?;
        ensure!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .is_some_and(|value| value == "no-store"),
            "public acceptance permits caching"
        );
        ensure!(
            !response.headers().contains_key(header::SET_COOKIE),
            "invitation automatically signed in an account"
        );
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 65_536).await?;
        Ok((
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ))
    }

    async fn lookup(
        &self,
        id: Uuid,
        original_path: &str,
        original_body: &Value,
    ) -> Result<(StatusCode, Value)> {
        let (service, _, secret) = &self.services[0];
        let state = self.state(true)?;
        let request = Request::builder()
            .method("GET")
            .uri(format!(
                "/internal/identity/auth/invitation-operations/{id}"
            ))
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(format!("{service}:{secret}"))),
            )
            .header(
                "x-identity-operation-digest",
                request_digest("POST", original_path, original_body)?,
            )
            .body(Body::empty())?;
        let response = crate::internal::routes()
            .layer(middleware::from_fn_with_state(
                state.clone(),
                internal::guard,
            ))
            .with_state(state)
            .oneshot(request)
            .await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 65_536).await?;
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    async fn finish(self, result: Result<()>) -> Result<()> {
        self.pool.close().await;
        ensure!(
            self.name.starts_with("identity_phase19_invite_")
                && self.name.len() <= 63
                && self
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "unsafe invitation cleanup target"
        );
        sqlx::query(&format!("DROP DATABASE \"{}\" WITH(FORCE)", self.name))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        eprintln!(
            "identity_invitation_test_cleanup database={} removed=true assertions_ok={}",
            self.name,
            result.is_ok()
        );
        result
    }
}

fn request_digest(method: &str, path: &str, body: &Value) -> Result<String> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(object) => Value::Object(
                object
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
    Ok(sha256_hex(&serde_json::to_string(&sorted(
        &json!({"method":method,"path":path,"body":body}),
    ))?))
}

fn acceptance(token: &str, verification: Uuid, username: &str) -> Value {
    json!({"operationId":Uuid::now_v7(),"token":token,"username":username,
        "password":"StrongDirected-Password9!","verificationRef":verification})
}

async fn unchanged(db: &Database, id: Uuid, username: &str) -> Result<()> {
    let state:(String,i64,i64,i64)=sqlx::query_as("SELECT status,version,(SELECT count(*) FROM users WHERE username=$2),(SELECT count(*) FROM auth_invitation_activation_receipts WHERE invitation_id=$1) FROM auth_invitations WHERE id=$1")
        .bind(id).bind(username).fetch_one(&db.pool).await?;
    ensure!(
        state == ("ACTIVE".into(), 1, 0, 0),
        "failed acceptance left an account, receipt or consumed invitation"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE19_TEST_DATABASE_URL/CLUSTER_ID"]
async fn phase20_invitation_issue_requires_current_owner_channel_and_only_leased_worker_gets_material(
) -> Result<()> {
    let db = Database::new().await?;
    let result=async {
        let recipient="phase20:directed-channel";
        let (status,_)=db.call(ADMIN,"POST",PATH,Some(db.issue_body(recipient)),Some(Uuid::now_v7()),(false,true)).await?;
        ensure!(status==StatusCode::CONFLICT,"invitation issuance accepted an absent platform intent");
        let mut foreign=db.issue_body(recipient);foreign["actorSessionId"]=json!(Uuid::now_v7());
        let (status,_)=db.call(ADMIN,"POST",PATH,Some(foreign),Some(Uuid::now_v7()),(true,true)).await?;
        ensure!(matches!(status,StatusCode::FORBIDDEN|StatusCode::CONFLICT),"invitation issuance accepted an unauthorized actor session");
        let (status,_)=db.call(CONSUME,"POST",PATH,Some(db.issue_body(recipient)),None,(false,true)).await?;
        ensure!(status==StatusCode::FORBIDDEN,"legacy consumer acquired invitation management authority");
        let missing=Uuid::now_v7();
        let (status,_)=db.call(ADMIN,"POST",PATH,Some(db.issue_body(recipient)),Some(missing),(true,true)).await?;
        ensure!(status==StatusCode::FORBIDDEN,"UUID recipient without owner-verified channel acquired an invitation");
        let absent:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_invitations WHERE id=$1),(SELECT count(*) FROM auth_delivery_jobs WHERE invitation_id=$1),(SELECT count(*) FROM identity_auth_command_receipts WHERE operation_id=$1)")
            .bind(missing).fetch_one(&db.pool).await?;
        ensure!(absent==(0,0,0),"missing channel committed partial issuance");
        for case in ["ambiguous","security-purpose","expired-target","future-target"] {
            let directed=format!("phase20:channel:{case}");let target=db.channel(&directed).await?;
            match case {
                "ambiguous"=>{db.channel(&directed).await?;},
                "security-purpose"=>{sqlx::query("UPDATE auth_delivery_targets SET channel_purpose='SECURITY' WHERE id=$1").bind(target).execute(&db.pool).await?;},
                "expired-target"=>{sqlx::query("UPDATE auth_delivery_targets SET verified_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1").bind(target).execute(&db.pool).await?;},
                "future-target"=>{sqlx::query("UPDATE auth_delivery_targets SET verified_at=clock_timestamp()+interval '1 hour',expires_at=clock_timestamp()+interval '2 hours' WHERE id=$1").bind(target).execute(&db.pool).await?;},
                _=>unreachable!(),
            }
            let (status,_)=db.call(ADMIN,"POST",PATH,Some(db.issue_body(&directed)),Some(Uuid::now_v7()),(true,true)).await?;
            ensure!(status==StatusCode::FORBIDDEN,"invalid directed target {case} authorized issuance");
        }
        let (id,issued)=db.issue(recipient).await?;
        ensure!(issued.get("token").is_none() && issued.get("tokenDigest").is_none(),"management exposed invitation material");
        let lifetime:i64=sqlx::query_scalar("SELECT extract(epoch FROM expires_at-created_at)::bigint FROM auth_invitations WHERE id=$1").bind(id).fetch_one(&db.pool).await?;
        ensure!(lifetime==86_400,"directed invitation did not retain its exact 24-hour limit");
        let (job,target,version,state):(Uuid,Uuid,i64,String)=sqlx::query_as("SELECT id,target_id,target_version,state FROM auth_delivery_jobs WHERE invitation_id=$1").bind(id).fetch_one(&db.pool).await?;
        ensure!(state=="PENDING" && version==1,"issuance did not atomically queue its exact channel");
        let (status,replayed)=db.call(ADMIN,"POST",PATH,Some(db.issue_body(recipient)),Some(id),(true,true)).await?;
        ensure!(status==StatusCode::OK && replayed==issued,"original issue operation changed its outcome");
        let (status,recovered)=db.lookup(id,PATH,&db.issue_body(recipient)).await?;
        ensure!(status==StatusCode::OK && recovered==issued,"original issue lookup did not recover metadata");
        let jobs:i64=sqlx::query_scalar("SELECT count(*) FROM auth_delivery_jobs WHERE invitation_id=$1").bind(id).fetch_one(&db.pool).await?;
        ensure!(jobs==1,"issue replay queued duplicate delivery jobs");
        ensure!(material_for_delivery(&db.state(true)?,job,Uuid::now_v7()).await.is_err(),"unleased job exposed token material");
        let pending_lease=Uuid::now_v7();
        sqlx::query("UPDATE auth_delivery_jobs SET state='LEASED',lease_id=$2,lease_until=clock_timestamp()+interval '1 minute',attempt_count=1 WHERE id=$1")
            .bind(job).bind(pending_lease).execute(&db.pool).await?;
        ensure!(matches!(material_for_delivery(&db.state(true)?,job,pending_lease).await,Err(AppError::Unavailable)),"missing owner verification released material or became a forged UUID fact");
        let facts:i64=sqlx::query_scalar("SELECT count(*) FROM auth_invitation_verifications WHERE invitation_id=$1").bind(id).fetch_one(&db.pool).await?;
        ensure!(facts==0,"worker created its own verification fact");
        for (purpose,suffix) in [(CONSUME,"consume"),(DELIVERY,"delivery-material")] {
            let (status,_)=db.call(purpose,"POST",&format!("{PATH}/{id}/{suffix}"),Some(json!({"verificationRef":Uuid::now_v7(),"verifiedChannelRef":Uuid::now_v7()})),None,(false,true)).await?;
            ensure!(status==StatusCode::NOT_FOUND,"legacy UUID-only token/claim route remained callable");
        }
        let token=db.material(id,recipient).await?;
        ensure!(token.len()==43 && token==db.material(id,recipient).await?,"leased worker lost deterministic in-memory token recovery");
        ensure!(material_for_delivery(&db.state(true)?,job,Uuid::now_v7()).await.is_err(),"another lease recovered the current worker's token");
        let lease:Uuid=sqlx::query_scalar("SELECT lease_id FROM auth_delivery_jobs WHERE id=$1").bind(job).fetch_one(&db.pool).await?;
        let original_fact=db.verification(id,recipient).await?;
        let duplicate=Uuid::now_v7();
        sqlx::query("INSERT INTO auth_invitation_verifications(id,invitation_id,recipient_ref,purpose,delivery_target_id,delivery_target_version,verified_reference,verified_at,expires_at,status,version) SELECT $1,invitation_id,recipient_ref,purpose,delivery_target_id,delivery_target_version,$3,verified_at,expires_at,'ACTIVE',1 FROM auth_invitation_verifications WHERE id=$2")
            .bind(duplicate).bind(original_fact).bind(Uuid::now_v7()).execute(&db.pool).await?;
        ensure!(matches!(material_for_delivery(&db.state(true)?,job,lease).await,Err(AppError::Unavailable)),"ambiguous owner verification released token material");
        sqlx::query("UPDATE auth_invitation_verifications SET status='REVOKED',version=version+1 WHERE id=$1").bind(duplicate).execute(&db.pool).await?;
        ensure!(material_for_delivery(&db.state(true)?,job,lease).await?.verification_ref==original_fact,"resolved owner fact did not restore exact proof binding");
        sqlx::query("UPDATE auth_delivery_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1").bind(job).execute(&db.pool).await?;
        ensure!(matches!(material_for_delivery(&db.state(true)?,job,lease).await,Err(AppError::Forbidden(_))),"expired lease released token material");
        let stored:String=sqlx::query_scalar("SELECT token_digest FROM auth_invitations WHERE id=$1").bind(id).fetch_one(&db.pool).await?;
        ensure!(stored==sha256_hex(&token),"invitation persisted recoverable token material");
        let (_,listed)=db.call(ADMIN,"GET",PATH,None,None,(false,true)).await?;
        ensure!(!listed.to_string().contains(&token),"management listing exposed the delivery token");
        let rollback_recipient="phase20:queue-rollback";
        db.channel(rollback_recipient).await?;
        sqlx::raw_sql("CREATE FUNCTION public.phase20_suppress_job() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER phase20_suppress_job BEFORE INSERT ON auth_delivery_jobs FOR EACH ROW EXECUTE FUNCTION public.phase20_suppress_job();").execute(&db.pool).await?;
        let failed=Uuid::now_v7();
        let (status,_)=db.call(ADMIN,"POST",PATH,Some(db.issue_body(rollback_recipient)),Some(failed),(true,true)).await?;
        ensure!(status==StatusCode::SERVICE_UNAVAILABLE,"suppressed delivery job was accepted as successful issuance");
        let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_invitations WHERE id=$1),(SELECT count(*) FROM identity_auth_command_receipts WHERE operation_id=$1)").bind(failed).fetch_one(&db.pool).await?;
        ensure!(counts==(0,0),"job suppression left an invitation or management receipt");
        sqlx::raw_sql("DROP TRIGGER phase20_suppress_job ON auth_delivery_jobs; DROP FUNCTION public.phase20_suppress_job();").execute(&db.pool).await?;
        sqlx::query("UPDATE auth_delivery_targets SET status='REVOKED',version=version+1 WHERE id=$1").bind(target).execute(&db.pool).await?;
        ensure!(db.material(id,recipient).await.is_err(),"revoked channel still released token material");
        let before:i64=sqlx::query_scalar("SELECT count(*) FROM auth_invitations").fetch_one(&db.pool).await?;
        let (status,_)=db.call(ADMIN,"POST",PATH,Some(db.issue_body(recipient)),Some(Uuid::now_v7()),(true,true)).await?;
        ensure!(status==StatusCode::FORBIDDEN,"revoked channel still authorized new issuance");
        let after:i64=sqlx::query_scalar("SELECT count(*) FROM auth_invitations").fetch_one(&db.pool).await?;
        ensure!(before==after,"rejected channel changed invitation count");
        let (status,_)=db.call(ADMIN,"POST",PATH,Some(db.issue_body(rollback_recipient)),Some(Uuid::now_v7()),(true,false)).await?;
        ensure!(status==StatusCode::SERVICE_UNAVAILABLE,"missing invitation keys did not fail closed");
        sqlx::query("INSERT INTO identity_service_clients(id,secret_hash,purpose,status,created_at) VALUES($1,$2,'AUTH_INVITATION_DELIVERY','ENABLED',clock_timestamp())")
            .bind(Uuid::now_v7()).bind(sha256_hex(&hex::encode([83u8;32]))).execute(&db.pool).await?;
        let (status,_)=db.call(ADMIN,"POST",PATH,Some(db.issue_body(rollback_recipient)),Some(Uuid::now_v7()),(true,true)).await?;
        ensure!(status==StatusCode::SERVICE_UNAVAILABLE,"invitation key reused as registered service secret was accepted");
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE19_TEST_DATABASE_URL/CLUSTER_ID"]
async fn phase20_invitation_delivery_commit_fences_original_proof_and_late_deadlines() -> Result<()>
{
    let db = Database::new().await?;
    let result = async {
        let recipient = "phase20:delivery-commit";
        let (id, _) = db.issue(recipient).await?;
        db.material(id, recipient).await?;
        let (job, lease): (Uuid, Uuid) = sqlx::query_as(
            "SELECT id,lease_id FROM auth_delivery_jobs WHERE invitation_id=$1",
        )
        .bind(id)
        .fetch_one(&db.pool)
        .await?;
        let state = db.state(true)?;
        let original = material_for_delivery(&state, job, lease).await?;
        sqlx::query("UPDATE auth_invitation_verifications SET verified_reference=$2 WHERE id=$1")
            .bind(original.verification_ref)
            .bind(Uuid::now_v7())
            .execute(&db.pool)
            .await?;
        let mut tx = db.pool.begin().await?;
        ensure!(
            matches!(
                revalidate_delivery(
                    &mut tx,
                    job,
                    lease,
                    original.verification_ref,
                    original.verification_version,
                )
                .await,
                Err(AppError::Forbidden(_))
            ),
            "delivery reused a newer owner proof generation than its in-memory material"
        );
        tx.rollback().await?;

        let current = material_for_delivery(&state, job, lease).await?;
        ensure!(
            current.verification_ref == original.verification_ref
                && current.verification_version == original.verification_version + 1,
            "material did not preserve the exact owner proof generation"
        );
        let mut tx = db.pool.begin().await?;
        revalidate_delivery(
            &mut tx,
            job,
            lease,
            current.verification_ref,
            current.verification_version,
        )
        .await?;
        // These writes use separate connections: every protected source lock
        // must survive the helper's return until the caller commits/rolls back.
        for (sql, source) in [
            ("UPDATE auth_invitations SET status='REVOKED',version=version+1,revoked_at=clock_timestamp() WHERE id=$1", id),
            ("UPDATE auth_delivery_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", job),
            ("UPDATE auth_delivery_targets SET status='REVOKED' WHERE id=$1", current.verified_channel_ref),
            ("UPDATE auth_invitation_verifications SET status='REVOKED' WHERE id=$1", current.verification_ref),
        ] {
            let mut owner = db.pool.begin().await?;
            sqlx::query("SET LOCAL lock_timeout='100ms'")
                .execute(&mut *owner)
                .await?;
            let error = sqlx::query(sql)
                .bind(source)
                .execute(&mut *owner)
                .await
                .expect_err("delivery source mutation bypassed the caller's retained lock");
            ensure!(
                error.as_database_error().and_then(|error| error.code()).as_deref()
                    == Some("55P03"),
                "delivery source mutation failed without proving the retained lock"
            );
            owner.rollback().await?;
        }
        tx.rollback().await?;

        for deadline in ["lease", "verification"] {
            let recipient = format!("phase20:delivery-wait:{deadline}");
            let (invitation, _) = db.issue(&recipient).await?;
            db.material(invitation, &recipient).await?;
            let (job, lease, proof): (Uuid, Uuid, Uuid) = sqlx::query_as(
                "SELECT job.id,job.lease_id,verified.id FROM auth_delivery_jobs job \
                 JOIN auth_invitation_verifications verified ON verified.invitation_id=job.invitation_id \
                 WHERE job.invitation_id=$1",
            )
            .bind(invitation)
            .fetch_one(&db.pool)
            .await?;
            if deadline == "verification" {
                sqlx::query("UPDATE auth_invitation_verifications SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1")
                    .bind(proof).execute(&db.pool).await?;
            }
            let material = material_for_delivery(&state, job, lease).await?;
            if deadline == "lease" {
                sqlx::query("UPDATE auth_delivery_jobs SET lease_until=clock_timestamp()+interval '2 seconds' WHERE id=$1")
                    .bind(job).execute(&db.pool).await?;
            }
            let mut owner = db.pool.begin().await?;
            let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *owner)
                .await?;
            sqlx::query("SELECT id FROM auth_delivery_targets WHERE id=$1 FOR UPDATE")
                .bind(material.verified_channel_ref)
                .execute(&mut *owner)
                .await?;
            let mut final_tx = db.pool.begin().await?;
            let waiter: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *final_tx)
                .await?;
            // Poll actual lock ownership and DB time instead of a timing sleep.
            let awaited = async {
                let validation = revalidate_delivery(
                    &mut final_tx,
                    job,
                    lease,
                    material.verification_ref,
                    material.verification_version,
                );
                let release = async {
                    tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        loop {
                            let blocked: bool = sqlx::query_scalar("SELECT $1=ANY(pg_blocking_pids($2))")
                                .bind(blocker).bind(waiter).fetch_one(&db.pool).await?;
                            if blocked { break; }
                            tokio::task::yield_now().await;
                        }
                        loop {
                            let elapsed: bool = if deadline == "lease" {
                                sqlx::query_scalar("SELECT lease_until<=clock_timestamp() FROM auth_delivery_jobs WHERE id=$1")
                                    .bind(job).fetch_one(&db.pool).await?
                            } else {
                                sqlx::query_scalar("SELECT expires_at<=clock_timestamp() FROM auth_invitation_verifications WHERE id=$1")
                                    .bind(proof).fetch_one(&db.pool).await?
                            };
                            if elapsed { break; }
                            tokio::task::yield_now().await;
                        }
                        Ok::<(), anyhow::Error>(())
                    }).await??;
                    owner.rollback().await?;
                    Ok::<(), anyhow::Error>(())
                };
                let (validation, release) = tokio::join!(validation, release);
                release?;
                ensure!(validation.is_err(), "delivery released material after {deadline} expired during owner-lock wait");
                Ok::<(), anyhow::Error>(())
            }.await;
            final_tx.rollback().await?;
            awaited?;
        }

        sqlx::query("UPDATE auth_invitations SET status='REVOKED',version=version+1,revoked_at=clock_timestamp() WHERE id=$1")
            .bind(id).execute(&db.pool).await?;
        let mut tx = db.pool.begin().await?;
        ensure!(revalidate_delivery(&mut tx, job, lease, current.verification_ref, current.verification_version).await.is_err(),
            "delivery committed material from a revoked invitation");
        tx.rollback().await?;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE19_TEST_DATABASE_URL/CLUSTER_ID"]
async fn phase20_invitation_acceptance_creates_only_new_account_and_recovers_original_operation(
) -> Result<()> {
    let db = Database::new().await?;
    let result=async {
        let recipient="phase20:verified-account";
        let (id,_)=db.issue(recipient).await?;
        let token=db.material(id,recipient).await?;
        let verified=db.verification(id,recipient).await?;
        // The trusted owner binds the current invitation to independently
        // established channel evidence; its proof may precede issuance.
        sqlx::query("UPDATE auth_invitation_verifications verified SET verified_at=target.verified_at FROM auth_delivery_targets target WHERE verified.id=$1 AND target.id=verified.delivery_target_id")
            .bind(verified).execute(&db.pool).await?;
        let body=acceptance(&token,verified,"phase20-new-account");
        let operation=canonical_id(body["operationId"].as_str().unwrap())?;
        let (status,result)=db.accept(id,body.clone()).await?;
        ensure!(status==StatusCode::OK && result==json!({"operationId":operation,"invitationId":id,"status":"ACCOUNT_CREATED"}),"directed acceptance did not return its safe original outcome");
        let (user,username,hash,status,super_admin,version):(Uuid,String,String,String,bool,i64)=sqlx::query_as("SELECT u.id,u.username,u.password_hash,u.status,u.is_super_admin,u.session_version FROM auth_invitation_activation_receipts receipt JOIN users u ON u.id=receipt.user_id WHERE receipt.operation_id=$1")
            .bind(operation).fetch_one(&db.pool).await?;
        ensure!(username=="phase20-new-account" && status=="ENABLED" && !super_admin && version==1 && hash.starts_with("$argon2id$"),"invitation did not create a fresh ordinary account");
        ensure!(db.state(true)?.passwords.verify(&hash,body["password"].as_str().unwrap()).await?,"account password did not use the existing password service");
        let forbidden:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM memberships WHERE user_id=$1)+(SELECT count(*) FROM user_roles WHERE user_id=$1)+(SELECT count(*) FROM sso_sessions WHERE user_id=$1)+(SELECT count(*) FROM auth_grants WHERE user_id=$1)")
            .bind(user).fetch_one(&db.pool).await?;
        ensure!(forbidden==0,"invitation granted membership, role, session or OAuth grant");
        let binding:(String,i64,Option<Uuid>,Option<Uuid>,Option<Uuid>,Option<Uuid>)=sqlx::query_as("SELECT status,version,consumed_by_service_id,verification_ref,activated_account_id,activation_operation_id FROM auth_invitations WHERE id=$1")
            .bind(id).fetch_one(&db.pool).await?;
        ensure!(binding==("CONSUMED".into(),2,None,Some(verified),Some(user),Some(operation)),"invitation consumption lost its account/operation binding");
        let proof_version:i64=sqlx::query_scalar("SELECT verification_version FROM auth_invitation_activation_receipts WHERE operation_id=$1").bind(operation).fetch_one(&db.pool).await?;
        ensure!(proof_version==2,"activation receipt did not retain the current owner-fact generation");
        let (status,replayed)=db.accept(id,body.clone()).await?;
        ensure!(status==StatusCode::OK && replayed==result,"same operation did not recover a lost acceptance response");
        for (field,value) in [("password",json!("OtherDirected-Password9!")),("username",json!("another-account")),("verificationRef",json!(Uuid::now_v7()))] {
            let mut changed=body.clone();changed[field]=value;
            ensure!(db.accept(id,changed).await?.0==StatusCode::CONFLICT,"original operation accepted a changed activation body");
        }
        sqlx::query("UPDATE users SET status='DISABLED',session_version=session_version+1 WHERE id=$1").bind(user).execute(&db.pool).await?;
        sqlx::query("UPDATE auth_invitation_verifications SET status='REVOKED',version=version+1 WHERE id=$1").bind(verified).execute(&db.pool).await?;
        let (status,recovered)=db.accept(id,body.clone()).await?;
        ensure!(status==StatusCode::OK && recovered==result,"original outcome could not be recovered after later security changes");
        let retained:(String,i64,String)=sqlx::query_as("SELECT status,session_version,password_hash FROM users WHERE id=$1").bind(user).fetch_one(&db.pool).await?;
        ensure!(retained==("DISABLED".into(),2,hash),"recovery enabled or changed the existing security-disabled account");
        let email="phase20-existing@example.test";
        let old=Uuid::now_v7();
        sqlx::query("INSERT INTO users(id,username,password_hash,email,status) VALUES($1,'occupied-name','fixture-unusable-hash',$2,'DISABLED')").bind(old).bind(email).execute(&db.pool).await?;
        let (other,_)=db.issue(email).await?;let other_token=db.material(other,email).await?;let other_verified=db.verification(other,email).await?;
        ensure!(db.accept(other,acceptance(&other_token,other_verified,"occupied-name")).await?.0==StatusCode::CONFLICT,"existing username was enabled or overwritten");
        unchanged(&db,other,"unused-name").await?;
        let (status,_)=db.accept(other,acceptance(&other_token,other_verified,"separate-new-name")).await?;
        ensure!(status==StatusCode::OK,"fresh username was incorrectly merged by recipient email");
        let retained:(String,String,i64)=sqlx::query_as("SELECT status,password_hash,session_version FROM users WHERE id=$1").bind(old).fetch_one(&db.pool).await?;
        ensure!(retained==("DISABLED".into(),"fixture-unusable-hash".into(),1),"invitation changed the pre-existing account");
        let new_email:String=sqlx::query_scalar("SELECT email FROM users WHERE username='separate-new-name'").fetch_one(&db.pool).await?;
        ensure!(new_email.is_empty(),"recipient reference was silently copied into an account identity alias");
        for secret in [&token,body["password"].as_str().unwrap()] {
            let leaks:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM identity_audit_logs WHERE detail LIKE '%'||$1||'%')+(SELECT count(*) FROM identity_auth_command_receipts WHERE result_json::text LIKE '%'||$1||'%')+(SELECT count(*) FROM auth_invitation_activation_receipts WHERE to_jsonb(auth_invitation_activation_receipts)::text LIKE '%'||$1||'%')+(SELECT count(*) FROM auth_delivery_jobs WHERE to_jsonb(auth_delivery_jobs)::text LIKE '%'||$1||'%')")
                .bind(secret).fetch_one(&db.pool).await?;
            ensure!(leaks==0,"activation or delivery persisted a raw token or password");
        }
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE19_TEST_DATABASE_URL/CLUSTER_ID"]
async fn phase20_invitation_acceptance_rejects_untrusted_stale_sources_and_rolls_back_mandatory_writes(
) -> Result<()> {
    let db = Database::new().await?;
    let result=async {
        for case in ["unknown-verification","wrong-invitation","bad-token","revoked-channel","old-channel-version","expired-verification","future-verification","revoked-verification","expired-invitation","revoked-invitation","weak-password","missing-keys","foreign-origin","missing-origin","query","extra-authority"] {
            let recipient=format!("phase20:negative:{case}");let username=format!("new-{case}");
            let (id,token,verified)=if case=="expired-invitation" { db.expired_invitation(&recipient).await? }
                else { let (id,_)=db.issue(&recipient).await?;let token=db.material(id,&recipient).await?;let verified=db.verification(id,&recipient).await?;(id,token,verified) };
            let mut body=acceptance(&token,verified,&username);
            let expected=match case {
                "unknown-verification"=>{body["verificationRef"]=json!(Uuid::now_v7());StatusCode::FORBIDDEN},
                "wrong-invitation"=>{let (other,_)=db.issue("phase20:other-verification").await?;body["verificationRef"]=json!(db.verification(other,"phase20:other-verification").await?);StatusCode::FORBIDDEN},
                "bad-token"=>{body["token"]=json!(URL_SAFE_NO_PAD.encode([0u8;32]));StatusCode::FORBIDDEN},
                "revoked-channel"=>{sqlx::query("UPDATE auth_delivery_targets SET status='REVOKED',version=version+1 WHERE id=(SELECT target_id FROM auth_delivery_jobs WHERE invitation_id=$1)").bind(id).execute(&db.pool).await?;StatusCode::FORBIDDEN},
                "old-channel-version"=>{sqlx::query("UPDATE auth_delivery_targets SET version=version+1 WHERE id=(SELECT target_id FROM auth_delivery_jobs WHERE invitation_id=$1)").bind(id).execute(&db.pool).await?;StatusCode::FORBIDDEN},
                "expired-verification"=>{sqlx::query("UPDATE auth_invitation_verifications SET verified_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1").bind(verified).execute(&db.pool).await?;StatusCode::FORBIDDEN},
                "future-verification"=>{sqlx::query("UPDATE auth_invitation_verifications SET verified_at=clock_timestamp()+interval '1 hour',expires_at=clock_timestamp()+interval '2 hours' WHERE id=$1").bind(verified).execute(&db.pool).await?;StatusCode::FORBIDDEN},
                "revoked-verification"=>{sqlx::query("UPDATE auth_invitation_verifications SET status='REVOKED',version=version+1 WHERE id=$1").bind(verified).execute(&db.pool).await?;StatusCode::FORBIDDEN},
                "expired-invitation"=>StatusCode::CONFLICT,
                "revoked-invitation"=>{let (status,_)=db.call(ADMIN,"POST",&format!("{PATH}/{id}/revoke"),Some(json!({"actorUserId":db.actor,"actorSessionId":db.session,"expectedVersion":1})),Some(Uuid::now_v7()),(true,true)).await?;ensure!(status==StatusCode::OK,"revoke fixture failed");StatusCode::CONFLICT},
                "weak-password"=>{body["password"]=json!("weak");StatusCode::BAD_REQUEST},
                "missing-keys"=>StatusCode::SERVICE_UNAVAILABLE,
                "foreign-origin"|"missing-origin"=>StatusCode::FORBIDDEN,
                "query"=>StatusCode::BAD_REQUEST,
                "extra-authority"=>{body["isSuperAdmin"]=json!(true);StatusCode::BAD_REQUEST},
                _=>unreachable!(),
            };
            let origin=match case {"foreign-origin"=>Some("https://other.example.test"),"missing-origin"=>None,_=>Some("https://auth.saas.test")};
            let path=format!("/api/sso/invitations/{id}/accept{}",if case=="query"{"?registration=true"}else{""});
            let (status,_)=db.public_call(&path,body,origin,case!="missing-keys").await?;
            ensure!(status==expected,"directed acceptance negative case {case} did not fail closed: {status}");
            if !matches!(case,"expired-invitation"|"revoked-invitation") { unchanged(&db,id,&username).await?; }
        }
        for table in ["identity_audit_logs","auth_invitation_activation_receipts","users","auth_invitations"] {
            let recipient=format!("phase20:rollback:{table}");let username=format!("rollback-{table}");
            let (id,_)=db.issue(&recipient).await?;let token=db.material(id,&recipient).await?;let verified=db.verification(id,&recipient).await?;
            let event=if table=="auth_invitations"{"UPDATE"}else{"INSERT"};
            sqlx::raw_sql(&format!("CREATE FUNCTION public.phase20_suppress_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER phase20_suppress_write BEFORE {event} ON {table} FOR EACH ROW EXECUTE FUNCTION public.phase20_suppress_write();")).execute(&db.pool).await?;
            let (status,_)=db.accept(id,acceptance(&token,verified,&username)).await?;
            ensure!(status.is_client_error()||status.is_server_error(),"suppressed mandatory activation write was accepted");
            sqlx::raw_sql(&format!("DROP TRIGGER phase20_suppress_write ON {table}; DROP FUNCTION public.phase20_suppress_write();")).execute(&db.pool).await?;
            unchanged(&db,id,&username).await?;
        }
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE19_TEST_DATABASE_URL/CLUSTER_ID"]
async fn phase20_invitation_concurrent_recovery_claims_and_username_collisions_create_at_most_one_account(
) -> Result<()> {
    let db = Database::new().await?;
    let result=async {
        for same_operation in [true,false] {
            let recipient=format!("phase20:race:{same_operation}");let username=format!("race-{same_operation}");
            let (id,_)=db.issue(&recipient).await?;let token=db.material(id,&recipient).await?;let verified=db.verification(id,&recipient).await?;
            let body=acceptance(&token,verified,&username);let mut other=body.clone();
            if !same_operation {other["operationId"]=json!(Uuid::now_v7());}
            let (first,second)=tokio::join!(db.accept(id,body),db.accept(id,other));let first=first?;let second=second?;
            if same_operation {ensure!(first.0==StatusCode::OK&&second.0==StatusCode::OK&&first.1==second.1,"concurrent original-operation recovery did not return one outcome");}
            else {let statuses=[first.0,second.0];ensure!(statuses.iter().filter(|s|**s==StatusCode::OK).count()==1&&statuses.iter().filter(|s|**s==StatusCode::CONFLICT).count()==1,"competing operations both claimed one invitation");}
            let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM users WHERE username=$1),(SELECT count(*) FROM auth_invitation_activation_receipts WHERE invitation_id=$2)").bind(&username).bind(id).fetch_one(&db.pool).await?;
            ensure!(counts==(1,1),"concurrent acceptance duplicated account or receipt");
        }
        let (first,_)=db.issue("phase20:username:first").await?;let first_token=db.material(first,"phase20:username:first").await?;let first_verified=db.verification(first,"phase20:username:first").await?;
        let (second,_)=db.issue("phase20:username:second").await?;let second_token=db.material(second,"phase20:username:second").await?;let second_verified=db.verification(second,"phase20:username:second").await?;
        let (a,b)=tokio::join!(db.accept(first,acceptance(&first_token,first_verified,"race-global-username")),db.accept(second,acceptance(&second_token,second_verified,"race-global-username")));
        let statuses=[a?.0,b?.0];ensure!(statuses.iter().filter(|s|**s==StatusCode::OK).count()==1&&statuses.iter().filter(|s|**s==StatusCode::CONFLICT).count()==1,"cross-invitation username race changed an existing account");
        let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM users WHERE username='race-global-username'),(SELECT count(*) FROM auth_invitations WHERE id=ANY($1) AND status='CONSUMED'),(SELECT count(*) FROM auth_invitation_activation_receipts WHERE invitation_id=ANY($1))").bind(vec![first,second]).fetch_one(&db.pool).await?;
        ensure!(counts==(1,1,1),"username collision left a partial consumed invitation or extra receipt");
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE19_TEST_DATABASE_URL/CLUSTER_ID"]
async fn phase20_invitation_runtime_login_keeps_owner_facts_read_only_and_activates_through_narrow_fences(
) -> Result<()> {
    let db = Database::new().await?;
    let role = format!("p20_invite_{}", Uuid::now_v7().simple());
    let mut runtime_pool: Option<PgPool> = None;
    let result=async {
        sqlx::raw_sql(&format!("BEGIN; CREATE ROLE \"{role}\" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; COMMENT ON ROLE \"{role}\" IS '{}'; COMMIT;",db.name)).execute(&db.pool).await?;
        sqlx::raw_sql(&format!("GRANT CONNECT ON DATABASE \"{}\" TO \"{role}\"; GRANT USAGE ON SCHEMA public TO \"{role}\";
            GRANT SELECT ON identity_service_clients,auth_delivery_targets,auth_invitation_verifications TO \"{role}\";
            GRANT SELECT(secret_digest) ON auth_client_credentials TO \"{role}\";
            GRANT SELECT,INSERT,UPDATE ON auth_invitations,auth_delivery_jobs TO \"{role}\";
            GRANT SELECT,INSERT ON identity_auth_command_receipts,auth_invitation_activation_receipts TO \"{role}\";
            GRANT INSERT ON identity_audit_logs TO \"{role}\";
            GRANT SELECT(id,username,password_hash,status,session_version) ON users TO \"{role}\";
            GRANT INSERT(id,username,password_hash,status,session_version) ON users TO \"{role}\";
            GRANT EXECUTE ON FUNCTION public.is_uuid_v7(uuid),public.identity_auth_command_intent_active(uuid,uuid,text,text,text),public.identity_auth_invitation_intent_active(uuid,uuid,text,text,text,uuid,uuid),public.identity_delivery_target_active(uuid,bigint,text,uuid,text,text),public.identity_invitation_verification_active(uuid,bigint,uuid,uuid,bigint,text,text) TO \"{role}\";",db.name)).execute(&db.pool).await?;
        let options=PgConnectOptions::from_str(&db.url)?.database(&db.name).username(&role);
        let pool=PgPoolOptions::new().max_connections(4).connect_with(options).await?;
        runtime_pool=Some(pool.clone());
        let authentic:bool=sqlx::query_scalar("SELECT current_user=session_user AND current_user=$1 AND NOT rolsuper AND NOT rolinherit AND NOT rolbypassrls FROM pg_roles WHERE rolname=current_user")
            .bind(&role).fetch_one(&pool).await?;
        ensure!(authentic,"invitation regression did not use its real limited LOGIN role");
        let mut url=reqwest::Url::parse(&db.url)?;url.set_username(&role).map_err(|_|anyhow!("invalid runtime fixture username"))?;url.set_path(&format!("/{}",db.name));
        let runtime=Database{pool:pool.clone(),admin:db.admin.clone(),name:db.name.clone(),url:url.to_string(),actor:db.actor,session:db.session,services:db.services.clone()};
        let recipient="phase20:real-runtime";let target=db.channel(recipient).await?;
        let denied=sqlx::query("SELECT id FROM auth_delivery_targets WHERE id=$1 FOR SHARE").bind(target).execute(&pool).await;
        ensure!(denied.err().and_then(|error|error.as_database_error().and_then(|db|db.code()).map(|code|code.into_owned())).as_deref()==Some("42501"),"owner fact accidentally gained UPDATE to permit row locks");
        let id=Uuid::now_v7();let body=db.issue_body(recipient);let digest=request_digest("POST",PATH,&body)?;
        sqlx::query("INSERT INTO platform_auth_command_intents(id,actor_user_id,tenant_id,organization_id,session_id,service_client_id,request_digest,method,path,accepted_at,management_permission) VALUES($1,$2,$3,$4,$5,$6,$7,'POST',$8,clock_timestamp(),'system:oauth:invite')")
            .bind(id).bind(db.actor).bind(Uuid::now_v7()).bind(Uuid::now_v7()).bind(db.session).bind(db.services[0].0).bind(digest).bind(PATH).execute(&db.pool).await?;
        let (status,_)=runtime.call(ADMIN,"POST",PATH,Some(body),Some(id),(false,true)).await?;
        ensure!(status==StatusCode::OK,"limited runtime could not issue against a read-only owner channel");
        let verified=db.verification(id,recipient).await?;
        let denied=sqlx::query("SELECT id FROM auth_invitation_verifications WHERE id=$1 FOR SHARE").bind(verified).execute(&pool).await;
        ensure!(denied.err().and_then(|error|error.as_database_error().and_then(|db|db.code()).map(|code|code.into_owned())).as_deref()==Some("42501"),"verification fact accidentally gained UPDATE to permit row locks");
        let token=runtime.material(id,recipient).await?;
        let accept=acceptance(&token,verified,"real-runtime-account");
        let (status,result)=runtime.accept(id,accept.clone()).await?;
        ensure!(status==StatusCode::OK&&result["status"]=="ACCOUNT_CREATED","read-only-fact runtime could not atomically create an account");
        ensure!(runtime.accept(id,accept).await?.1==result,"limited runtime did not recover its original outcome");
        let forbidden:bool=sqlx::query_scalar("SELECT NOT has_any_column_privilege(current_user,'auth_delivery_targets','INSERT,UPDATE,REFERENCES') AND NOT has_table_privilege(current_user,'auth_delivery_targets','DELETE,TRUNCATE,TRIGGER') AND NOT has_any_column_privilege(current_user,'auth_invitation_verifications','INSERT,UPDATE,REFERENCES') AND NOT has_table_privilege(current_user,'auth_invitation_verifications','DELETE,TRUNCATE,TRIGGER') AND NOT has_any_column_privilege(current_user,'auth_invitation_activation_receipts','UPDATE') AND NOT has_table_privilege(current_user,'auth_invitation_activation_receipts','DELETE,TRUNCATE,TRIGGER') AND NOT has_any_column_privilege(current_user,'memberships','SELECT,INSERT,UPDATE,REFERENCES') AND NOT has_column_privilege(current_user,'users','is_super_admin','SELECT,INSERT,UPDATE')")
            .fetch_one(&pool).await?;
        ensure!(forbidden,"runtime invitation flow required owner-fact writes, mutable receipts or business authority");
        drop(runtime);Ok(())
    }.await;
    if let Some(pool) = runtime_pool {
        pool.close().await;
    }
    let cleanup: Result<()> = async {
        let marker: Option<String> = sqlx::query_scalar(
            "SELECT shobj_description(oid,'pg_authid') FROM pg_roles WHERE rolname=$1",
        )
        .bind(&role)
        .fetch_optional(&db.admin)
        .await?
        .flatten();
        if let Some(marker) = marker {
            ensure!(
                marker == db.name,
                "refusing cleanup of an unmatched runtime role"
            );
            sqlx::raw_sql(&format!("DROP OWNED BY \"{role}\"; DROP ROLE \"{role}\";"))
                .execute(&db.pool)
                .await?;
        } else {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)")
                    .bind(&role)
                    .fetch_one(&db.admin)
                    .await?;
            ensure!(!exists, "runtime role has no exact ownership marker");
        }
        Ok(())
    }
    .await;
    eprintln!(
        "identity_invitation_runtime_role_cleanup role={} removed={} assertions_ok={}",
        role,
        cleanup.is_ok(),
        result.is_ok()
    );
    let result = match (result, cleanup) {
        (Err(error), Err(_)) => Err(error.context("runtime role cleanup also failed")),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), cleanup) => cleanup,
    };
    db.finish(result).await
}
