//! Tokens exist only in the worker's memory, after its exact current lease.

use super::*;

async fn current_source(
    tx: &mut Transaction<'_, Postgres>,
    job_id: Uuid,
    lease_id: Uuid,
) -> Result<(Invitation, Uuid, i64), AppError> {
    let source: Option<(Uuid, Uuid, i64)> = sqlx::query_as(
        "SELECT invitation_id,target_id,target_version FROM public.auth_delivery_jobs \
         WHERE id=$1 AND kind='INVITATION' AND state='LEASED' AND lease_id=$2 \
           AND lease_until>clock_timestamp() AND attempt_count BETWEEN 1 AND max_attempts FOR SHARE",
    )
    .bind(job_id)
    .bind(lease_id)
    .fetch_optional(&mut **tx)
    .await?;
    let (id, target, target_version) =
        source.ok_or_else(|| AppError::forbidden("邀请投递缺少当前任务租约"))?;
    let invitation = load(tx, id, false).await?;
    invitation.require_active(invitation.version)?;
    Ok((invitation, target, target_version))
}

/// Recheck the exact proof generation after signing or other awaited work.
/// Job, invitation and owner-fact locks remain held in the caller's transaction.
/// No token or recipient material is returned.
pub(crate) async fn revalidate_delivery(
    tx: &mut Transaction<'_, Postgres>,
    job_id: Uuid,
    lease_id: Uuid,
    verification_id: Uuid,
    verification_version: i64,
) -> Result<(), AppError> {
    let (invitation, target, target_version) = current_source(tx, job_id, lease_id).await?;
    // Owner fences lock target before verification and retain SELECT-only ACLs.
    trust::require_target(tx, &invitation, target, target_version).await?;
    let current = trust::verification_for_delivery(tx, &invitation, target, target_version).await?;
    if current != (verification_id, verification_version) {
        return Err(AppError::forbidden("邀请投递的可信核验代际已变化"));
    }
    // Re-read database time after every potentially waiting lock. The held
    // row locks fence mutations, but they cannot stop a deadline from passing.
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.auth_delivery_jobs job \
         JOIN public.auth_invitations invitation ON invitation.id=job.invitation_id \
         JOIN public.auth_delivery_targets target ON target.id=job.target_id \
         JOIN public.auth_invitation_verifications verified ON verified.id=$3 \
         WHERE job.id=$1 AND job.kind='INVITATION' AND job.state='LEASED' AND job.lease_id=$2 \
           AND job.lease_until>clock_timestamp() AND job.attempt_count BETWEEN 1 AND job.max_attempts \
           AND invitation.id=$5 AND invitation.status='ACTIVE' AND invitation.version=$6 \
           AND invitation.expires_at>clock_timestamp() \
           AND target.id=$7 AND target.version=$8 AND job.target_version=target.version \
           AND target.status='ACTIVE' AND target.purpose='VERIFIED_CHANNEL' AND target.client_id IS NULL \
           AND target.recipient_ref=invitation.recipient_ref AND target.channel_purpose=invitation.purpose \
           AND target.verified_at<=clock_timestamp() AND target.expires_at>clock_timestamp() \
           AND verified.version=$4 AND verified.invitation_id=invitation.id \
           AND verified.delivery_target_id=target.id AND verified.delivery_target_version=target.version \
           AND verified.recipient_ref=invitation.recipient_ref AND verified.purpose=invitation.purpose \
           AND verified.status='ACTIVE' AND verified.verified_at<=clock_timestamp() AND verified.expires_at>clock_timestamp() \
           AND (SELECT count(*) FROM public.auth_invitation_verifications candidate \
             WHERE candidate.invitation_id=invitation.id AND candidate.recipient_ref=invitation.recipient_ref \
               AND candidate.purpose=invitation.purpose AND candidate.delivery_target_id=target.id \
               AND candidate.delivery_target_version=target.version AND candidate.status='ACTIVE' \
               AND candidate.verified_at<=clock_timestamp() AND candidate.expires_at>clock_timestamp())=1)",
    )
    .bind(job_id)
    .bind(lease_id)
    .bind(verification_id)
    .bind(verification_version)
    .bind(invitation.id)
    .bind(invitation.version)
    .bind(target)
    .bind(target_version)
    .fetch_one(&mut **tx)
    .await?;
    if !valid {
        return Err(AppError::forbidden("邀请、核验事实或投递租约已失效"));
    }
    Ok(())
}

pub(crate) async fn material_for_delivery(
    state: &AppState,
    job_id: Uuid,
    lease_id: Uuid,
) -> Result<InvitationDeliveryMaterial, AppError> {
    let keys = configured_keys(state).await?;
    let mut tx = state.pool.begin().await?;
    let (invitation, target, target_version) = current_source(&mut tx, job_id, lease_id).await?;
    trust::require_target(&mut tx, &invitation, target, target_version).await?;
    let verification =
        trust::verification_for_delivery(&mut tx, &invitation, target, target_version).await?;
    let token = keys.derive(&invitation)?;
    if !equal_digest(&invitation.token_digest, &sha256_hex(&token)) {
        return Err(AppError::Unavailable);
    }
    record(
        &mut tx,
        &invitation,
        "AUTH_INVITATION_DELIVERY_MATERIAL",
        None,
    )
    .await?;
    revalidate_delivery(&mut tx, job_id, lease_id, verification.0, verification.1).await?;
    tx.commit().await?;
    Ok(InvitationDeliveryMaterial {
        invitation_id: invitation.id,
        recipient_ref: invitation.recipient_ref,
        purpose: invitation.purpose,
        token,
        expires_at: invitation.expires_at,
        verification_ref: verification.0,
        verification_version: verification.1,
        verified_channel_ref: target,
        target_version,
    })
}
