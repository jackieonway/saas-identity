use super::transport::{self, Failure, Target};
use crate::{
    error::AppError,
    state::AppState,
    util::{hash::sha256_hex, uuid7},
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
#[cfg(test)]
mod registration_tests;
#[cfg(test)]
mod tests;

#[derive(sqlx::FromRow)]
struct Job {
    id: Uuid,
    kind: String,
    target_id: Option<Uuid>,
    target_version: Option<i64>,
    grant_id: Option<Uuid>,
    invitation_id: Option<Uuid>,
    security_event_id: Option<Uuid>,
    lease_id: Option<Uuid>,
    last_jti: Option<Uuid>,
}
#[derive(sqlx::FromRow)]
struct RegisteredTarget {
    id: Uuid,
    purpose: String,
    client_id: Option<Uuid>,
    recipient_ref: Option<String>,
    channel_purpose: Option<String>,
    url: String,
    allowed_ips: Vec<String>,
    version: i64,
}
struct Prepared {
    target: Target,
    body: Vec<u8>,
    content_type: &'static str,
    proof: Option<String>,
}
fn failed(code: &'static str, retryable: bool) -> Failure {
    Failure { code, retryable }
}
fn dependency(_: AppError) -> Failure {
    failed("DELIVERY_AUTHORITY_UNAVAILABLE", true)
}
fn sql_dependency(_: sqlx::Error) -> Failure {
    failed("DELIVERY_DATABASE_UNAVAILABLE", true)
}

async fn claim(state: &AppState) -> Result<Vec<Job>, AppError> {
    let mut tx = state.pool.begin().await?;
    let expired:Vec<(Uuid,String)>=sqlx::query_as("WITH expired AS (SELECT id FROM public.auth_delivery_jobs WHERE state IN('PENDING','LEASED') AND (state='PENDING' OR lease_until<=clock_timestamp()) AND (attempt_count>=max_attempts OR created_at+interval '24 hours'<=clock_timestamp()) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 50) UPDATE public.auth_delivery_jobs job SET state='TERMINAL',terminal_at=clock_timestamp(),lease_id=NULL,lease_until=NULL,last_error_code='DELIVERY_BUDGET_EXHAUSTED' FROM expired WHERE job.id=expired.id RETURNING job.id,job.kind")
        .fetch_all(&mut *tx).await?;
    let selected:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM public.auth_delivery_jobs WHERE ((state='PENDING' AND available_at<=clock_timestamp()) OR (state='LEASED' AND lease_until<=clock_timestamp())) AND attempt_count<max_attempts AND created_at+interval '24 hours'>clock_timestamp() ORDER BY available_at,created_at,id FOR UPDATE SKIP LOCKED LIMIT 4")
        .fetch_all(&mut *tx).await?;
    let mut jobs = Vec::with_capacity(selected.len());
    for id in selected {
        let job:Job=sqlx::query_as("UPDATE public.auth_delivery_jobs SET state='LEASED',attempt_count=attempt_count+1,lease_id=$2,lease_until=clock_timestamp()+interval '30 seconds',last_jti=$3 WHERE id=$1 RETURNING id,kind,target_id,target_version,grant_id,invitation_id,security_event_id,lease_id,last_jti")
            .bind(id).bind(uuid7::new_uuid()).bind(uuid7::new_uuid()).fetch_one(&mut *tx).await?;
        jobs.push(job);
    }
    tx.commit().await?;
    for (id, kind) in expired {
        tracing::warn!(event="identity_delivery_terminal",job_id=%id,kind,error_code="DELIVERY_BUDGET_EXHAUSTED");
    }
    Ok(jobs)
}

async fn load_target(
    tx: &mut Transaction<'_, Postgres>,
    job: &Job,
) -> Result<RegisteredTarget, Failure> {
    let target:Option<RegisteredTarget>=sqlx::query_as("SELECT id,purpose,client_id,recipient_ref,channel_purpose,url,allowed_ips,version FROM public.auth_delivery_targets WHERE id=$1 AND version=$2 AND status='ACTIVE' AND verified_at<=clock_timestamp() AND expires_at>clock_timestamp()")
        .bind(job.target_id).bind(job.target_version).fetch_optional(&mut **tx).await.map_err(sql_dependency)?;
    let target = target.ok_or_else(|| failed("DELIVERY_TARGET_REVOKED", false))?;
    let active: bool =
        sqlx::query_scalar("SELECT public.identity_delivery_target_active($1,$2,$3,$4,$5,$6)")
            .bind(target.id)
            .bind(target.version)
            .bind(&target.purpose)
            .bind(target.client_id)
            .bind(&target.recipient_ref)
            .bind(&target.channel_purpose)
            .fetch_one(&mut **tx)
            .await
            .map_err(sql_dependency)?;
    if !active {
        return Err(failed("DELIVERY_TARGET_REVOKED", false));
    }
    Ok(target)
}

async fn logout_claims(
    tx: &mut Transaction<'_, Postgres>,
    job: &Job,
    target: &RegisteredTarget,
    issuer: &str,
    now: DateTime<Utc>,
) -> Result<Value, Failure> {
    let source:Option<(Uuid,String,String,String,bool)>=sqlx::query_as("SELECT client.id,client.client_id,rp.public_sid,rp.public_sub,(client.logout_mode='BACK_CHANNEL' AND client.backchannel_target_id=$2 AND client.backchannel_logout_uri=$3 AND (app.ownership='FIRST_PARTY' OR EXISTS(SELECT 1 FROM public.auth_application_admissions admission WHERE admission.application_id=client.application_id AND admission.environment=client.environment AND admission.status='APPROVED' AND admission.logout_mode='BACK_CHANNEL' AND admission.backchannel_logout_uri=$3))) FROM public.auth_rp_sessions rp JOIN public.auth_grants grant_row ON grant_row.id=rp.grant_id AND grant_row.revoked_at IS NOT NULL JOIN public.auth_clients client ON client.id=rp.client_id JOIN public.auth_applications app ON app.application_id=client.application_id WHERE rp.grant_id=$1")
        .bind(job.grant_id).bind(target.id).bind(&target.url).fetch_optional(&mut **tx).await.map_err(sql_dependency)?;
    let (client, public_client, sid, sub, registered) =
        source.ok_or_else(|| failed("LOGOUT_SOURCE_UNAVAILABLE", false))?;
    if !registered || target.purpose != "BACK_CHANNEL" || target.client_id != Some(client) {
        return Err(failed("LOGOUT_TARGET_REGISTRATION_CHANGED", false));
    }
    Ok(
        json!({"iss":issuer,"aud":public_client,"sid":sid,"sub":sub,"iat":now.timestamp(),"exp":(now+Duration::seconds(120)).timestamp(),"jti":job.last_jti.ok_or_else(||failed("DELIVERY_LEASE_INVALID",false))?,"events":{"http://schemas.openid.net/event/backchannel-logout":{}}}),
    )
}

async fn lock_logout_registration(
    tx: &mut Transaction<'_, Postgres>,
    job: &Job,
) -> Result<(), Failure> {
    let source:Option<(Uuid,Uuid,String)>=sqlx::query_as("SELECT client.id,client.application_id,client.environment FROM public.auth_rp_sessions rp JOIN public.auth_clients client ON client.id=rp.client_id WHERE rp.grant_id=$1")
        .bind(job.grant_id).fetch_optional(&mut **tx).await.map_err(sql_dependency)?;
    let (client, application, environment) =
        source.ok_or_else(|| failed("LOGOUT_SOURCE_UNAVAILABLE", false))?;
    // Match registry/review administration: application -> client -> admission
    // -> owner target. Never acquire a client lock while holding only a target
    // lock, since a registry edit takes the opposite order.
    let ownership: Option<String> = sqlx::query_scalar(
        "SELECT ownership FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(application)
    .fetch_optional(&mut **tx)
    .await
    .map_err(sql_dependency)?;
    let ownership = ownership.ok_or_else(|| failed("LOGOUT_SOURCE_UNAVAILABLE", false))?;
    let registered:Option<bool>=sqlx::query_scalar("SELECT application_id=$2 AND environment=$3 AND logout_mode='BACK_CHANNEL' AND backchannel_target_id=$4 FROM public.auth_clients WHERE id=$1 FOR SHARE")
        .bind(client).bind(application).bind(&environment).bind(job.target_id).fetch_optional(&mut **tx).await.map_err(sql_dependency)?;
    if registered != Some(true) {
        return Err(failed("LOGOUT_TARGET_REGISTRATION_CHANGED", false));
    }
    if ownership == "THIRD_PARTY" {
        let approved:Option<bool>=sqlx::query_scalar("SELECT status='APPROVED' AND logout_mode='BACK_CHANNEL' FROM public.auth_application_admissions WHERE application_id=$1 AND environment=$2 FOR SHARE")
            .bind(application).bind(environment).fetch_optional(&mut **tx).await.map_err(sql_dependency)?;
        if approved != Some(true) {
            return Err(failed("LOGOUT_TARGET_REGISTRATION_CHANGED", false));
        }
    }
    Ok(())
}

async fn invitation_body(state: &AppState, job: &Job) -> Result<(Value, Uuid, i64), Failure> {
    let lease = job
        .lease_id
        .ok_or_else(|| failed("DELIVERY_LEASE_INVALID", false))?;
    let material = crate::auth_invitations::material_for_delivery(state, job.id, lease)
        .await
        .map_err(|error| match error {
            AppError::Unavailable => failed("INVITATION_VERIFICATION_PENDING", true),
            AppError::Server(_) => failed("INVITATION_DEPENDENCY_UNAVAILABLE", true),
            _ => failed("INVITATION_SOURCE_REVOKED", false),
        })?;
    if Some(material.invitation_id) != job.invitation_id
        || Some(material.verified_channel_ref) != job.target_id
        || Some(material.target_version) != job.target_version
    {
        return Err(failed("INVITATION_TARGET_CHANGED", false));
    }
    let origin = state
        .config
        .sso_origin
        .as_deref()
        .ok_or_else(|| failed("INVITATION_ORIGIN_UNAVAILABLE", false))?;
    Ok((
        json!({"contractVersion":"account-invitation-delivery/1","invitationId":material.invitation_id,"recipientRef":material.recipient_ref,"purpose":material.purpose,"token":material.token,"expiresAt":material.expires_at,"verificationRef":material.verification_ref,"acceptUrl":format!("{origin}/sso/invitations/{}",material.invitation_id)}),
        material.verification_ref,
        material.verification_version,
    ))
}

async fn revalidate_invitation(
    tx: &mut Transaction<'_, Postgres>,
    job: &Job,
    binding: Option<(Uuid, i64)>,
) -> Result<(), Failure> {
    if let Some((reference, version)) = binding {
        crate::auth_invitations::revalidate_delivery(
            tx,
            job.id,
            job.lease_id
                .ok_or_else(|| failed("DELIVERY_LEASE_INVALID", false))?,
            reference,
            version,
        )
        .await
        .map_err(|error| match error {
            AppError::Unavailable | AppError::Server(_) => {
                failed("INVITATION_DEPENDENCY_UNAVAILABLE", true)
            }
            _ => failed("INVITATION_SOURCE_REVOKED", false),
        })?;
    }
    Ok(())
}

async fn prepare(state: &AppState, job: &Job) -> Result<Prepared, Failure> {
    // Invitation material has its own short transaction and returns no reusable
    // response object. Never hold another pool connection while obtaining it.
    let invitation = if job.kind == "INVITATION" {
        Some(invitation_body(state, job).await?)
    } else {
        None
    };
    let mut tx = state.pool.begin().await.map_err(sql_dependency)?;
    let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.auth_delivery_jobs WHERE id=$1 AND state='LEASED' AND lease_id=$2 AND lease_until>clock_timestamp())")
        .bind(job.id).bind(job.lease_id).fetch_one(&mut *tx).await.map_err(sql_dependency)?;
    if !live {
        return Err(failed("DELIVERY_LEASE_EXPIRED", false));
    }
    let invitation_binding = invitation
        .as_ref()
        .map(|(_, reference, version)| (*reference, *version));
    // Match activation's invitation-before-owner-facts lock order. Retain the
    // exact invitation/fact generations throughout signing, then recheck time.
    revalidate_invitation(&mut tx, job, invitation_binding).await?;
    if job.kind == "LOGOUT" {
        lock_logout_registration(&mut tx, job).await?;
    }
    let target = load_target(&mut tx, job).await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await
        .map_err(sql_dependency)?;
    let expires = now + Duration::seconds(120);
    let issuer = state
        .config
        .oidc_issuer
        .as_deref()
        .ok_or_else(|| failed("DELIVERY_ISSUER_UNAVAILABLE", false))?;
    let (body, content_type, proof) = if job.kind == "LOGOUT" {
        let claims = logout_claims(&mut tx, job, &target, issuer, now).await?;
        let token = crate::oidc::sign_delivery(state, &mut tx, claims, expires, true)
            .await
            .map_err(dependency)?;
        (
            format!("logout_token={token}").into_bytes(),
            "application/x-www-form-urlencoded",
            None,
        )
    } else {
        let payload = if let Some((payload, _, _)) = invitation {
            if target.purpose != "VERIFIED_CHANNEL"
                || target.channel_purpose.as_deref() != Some("ACCOUNT_ONBOARDING")
                || target.recipient_ref.as_deref() != payload["recipientRef"].as_str()
            {
                return Err(failed("INVITATION_TARGET_CHANGED", false));
            }
            payload
        } else if job.kind == "SECURITY" {
            let event:Option<(Uuid,String,DateTime<Utc>)>=sqlx::query_as("SELECT user_id,event_kind,created_at FROM public.auth_security_notification_outbox WHERE id=$1")
                .bind(job.security_event_id).fetch_optional(&mut *tx).await.map_err(sql_dependency)?;
            let (user, kind, created) =
                event.ok_or_else(|| failed("SECURITY_EVENT_UNAVAILABLE", false))?;
            if target.purpose != "VERIFIED_CHANNEL"
                || target.channel_purpose.as_deref() != Some("SECURITY")
                || target.recipient_ref.as_deref() != Some(user.to_string().as_str())
            {
                return Err(failed("SECURITY_TARGET_CHANGED", false));
            }
            json!({"contractVersion":"identity-security-delivery/1","eventId":job.security_event_id,"recipientRef":target.recipient_ref,"eventKind":kind,"occurredAt":created})
        } else {
            return Err(failed("DELIVERY_KIND_INVALID", false));
        };
        let body =
            serde_json::to_vec(&payload).map_err(|_| failed("DELIVERY_BODY_INVALID", false))?;
        let proof=crate::oidc::sign_delivery(state,&mut tx,json!({"iss":issuer,"aud":target.id.to_string(),"jti":job.last_jti,"iat":now.timestamp(),"exp":expires.timestamp(),"kind":job.kind,"eventId":job.id,"targetVersion":target.version,"bodySha256":sha256_hex(&String::from_utf8_lossy(&body))}),expires,false).await.map_err(dependency)?;
        (body, "application/json", Some(proof))
    };
    // Signing may wait on key lifecycle locks. Do not release a payload whose
    // original lease or verified destination expired during that wait.
    let final_target = load_target(&mut tx, job).await?;
    if job.kind == "LOGOUT" {
        logout_claims(&mut tx, job, &final_target, issuer, now).await?;
    }
    revalidate_invitation(&mut tx, job, invitation_binding).await?;
    let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.auth_delivery_jobs WHERE id=$1 AND state='LEASED' AND lease_id=$2 AND lease_until>clock_timestamp())")
        .bind(job.id).bind(job.lease_id).fetch_one(&mut *tx).await.map_err(sql_dependency)?;
    if !live {
        return Err(failed("DELIVERY_LEASE_EXPIRED", false));
    }
    tx.commit().await.map_err(sql_dependency)?;
    Ok(Prepared {
        target: Target {
            url: target.url,
            allowed_ips: target.allowed_ips,
        },
        body,
        content_type,
        proof,
    })
}

async fn complete(
    state: &AppState,
    job: &Job,
    outcome: Result<(), Failure>,
) -> Result<(), AppError> {
    let (success, retryable, code) = match outcome {
        Ok(()) => (true, false, None),
        Err(error) => (false, error.retryable, Some(error.code)),
    };
    let result:Option<String>=sqlx::query_scalar("UPDATE public.auth_delivery_jobs SET state=CASE WHEN $3 THEN 'DELIVERED' WHEN $4 AND attempt_count<max_attempts AND created_at+interval '24 hours'>clock_timestamp() THEN 'PENDING' ELSE 'TERMINAL' END,delivered_at=CASE WHEN $3 THEN clock_timestamp() ELSE NULL END,terminal_at=CASE WHEN NOT $3 AND NOT($4 AND attempt_count<max_attempts AND created_at+interval '24 hours'>clock_timestamp()) THEN clock_timestamp() ELSE NULL END,available_at=CASE WHEN NOT $3 AND $4 THEN clock_timestamp()+LEAST(3600,60*power(2,LEAST(attempt_count-1,6)))::integer*interval '1 second' ELSE available_at END,lease_id=NULL,lease_until=NULL,last_error_code=$5 WHERE id=$1 AND state='LEASED' AND lease_id=$2 AND lease_until>clock_timestamp() RETURNING state")
        .bind(job.id).bind(job.lease_id).bind(success).bind(retryable).bind(code).fetch_optional(&state.pool).await?;
    if result.as_deref() == Some("TERMINAL") {
        tracing::warn!(event="identity_delivery_terminal",job_id=%job.id,kind=job.kind,error_code=code.unwrap_or("DELIVERY_REJECTED"));
    }
    Ok(())
}

async fn process(state: AppState, job: Job) -> Result<(), AppError> {
    let outcome = match prepare(&state, &job).await {
        Err(error) => Err(error),
        Ok(mut prepared) => {
            let result = transport::send(
                &state.config.delivery,
                &prepared.target,
                &prepared.body,
                prepared.content_type,
                prepared.proof.as_deref(),
            )
            .await;
            prepared.body.fill(0);
            match result {
                Ok(200..=299) => Ok(()),
                Ok(408 | 429 | 500..=599) => Err(failed("DELIVERY_HTTP_RETRYABLE", true)),
                Ok(300..=399) => Err(failed("DELIVERY_REDIRECT_REJECTED", false)),
                Ok(_) => Err(failed("DELIVERY_HTTP_REJECTED", false)),
                Err(error) => Err(error),
            }
        }
    };
    complete(&state, &job, outcome).await
}

pub(super) async fn tick(state: &AppState) -> Result<usize, AppError> {
    if !state.config.delivery.worker_enabled {
        return Ok(0);
    }
    let jobs = claim(state).await?;
    let count = jobs.len();
    let mut running = tokio::task::JoinSet::new();
    for job in jobs {
        let state = state.clone();
        running.spawn(async move { process(state, job).await });
    }
    while let Some(result) = running.join_next().await {
        result.map_err(|_| AppError::Unavailable)??;
    }
    Ok(count)
}
