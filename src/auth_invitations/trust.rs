//! Owner-controlled facts. Runtime cannot invent or update a verified channel.

use super::*;

#[derive(sqlx::FromRow)]
pub(super) struct TargetBinding {
    pub id: Uuid,
    pub version: i64,
}

#[derive(sqlx::FromRow)]
pub(super) struct VerifiedBinding {
    pub id: Uuid,
    pub version: i64,
    pub verification_version: i64,
}

pub(super) async fn target_for_issue(
    tx: &mut Transaction<'_, Postgres>,
    recipient: &str,
) -> Result<TargetBinding, AppError> {
    let targets: Vec<TargetBinding> = sqlx::query_as(
        "SELECT id,version FROM public.auth_delivery_targets \
         WHERE purpose='VERIFIED_CHANNEL' AND channel_purpose='ACCOUNT_ONBOARDING' AND status='ACTIVE' AND recipient_ref=$1 \
           AND client_id IS NULL AND verified_at<=clock_timestamp() AND expires_at>clock_timestamp() \
         ORDER BY id LIMIT 2",
    )
    .bind(recipient)
    .fetch_all(&mut **tx)
    .await?;
    let [target]: [TargetBinding; 1] = targets
        .try_into()
        .map_err(|_| AppError::forbidden("邀请缺少唯一有效的已核验接收渠道"))?;
    Ok(target)
}

pub(super) async fn verification_for_delivery(
    tx: &mut Transaction<'_, Postgres>,
    invitation: &Invitation,
    target: Uuid,
    target_version: i64,
) -> Result<(Uuid, i64), AppError> {
    let verified: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.auth_invitation_verifications \
         WHERE invitation_id=$1 AND recipient_ref=$2 AND purpose=$3 \
           AND delivery_target_id=$4 AND delivery_target_version=$5 AND status='ACTIVE' \
           AND verified_at<=clock_timestamp() AND expires_at>clock_timestamp() \
         ORDER BY id LIMIT 2",
    )
    .bind(invitation.id)
    .bind(&invitation.recipient_ref)
    .bind(&invitation.purpose)
    .bind(target)
    .bind(target_version)
    .fetch_all(&mut **tx)
    .await?;
    if verified.len() == 1 {
        let binding = require_verification(tx, invitation, verified[0]).await?;
        return Ok((verified[0], binding.verification_version));
    }
    if verified.len() > 1 {
        return Err(AppError::Unavailable);
    }
    let known: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.auth_invitation_verifications WHERE invitation_id=$1)",
    )
    .bind(invitation.id)
    .fetch_one(&mut **tx)
    .await?;
    if known {
        return Err(AppError::forbidden("邀请的可信核验事实已失效或不匹配"));
    }
    Err(AppError::Unavailable)
}

pub(super) async fn require_target(
    tx: &mut Transaction<'_, Postgres>,
    invitation: &Invitation,
    target: Uuid,
    version: i64,
) -> Result<(), AppError> {
    let valid: bool = sqlx::query_scalar(
        "SELECT public.identity_delivery_target_active($1,$2,'VERIFIED_CHANNEL',NULL,$3,'ACCOUNT_ONBOARDING')",
    )
    .bind(target)
    .bind(version)
    .bind(&invitation.recipient_ref)
    .fetch_one(&mut **tx)
    .await?;
    if invitation.purpose != "ACCOUNT_ONBOARDING" || !valid {
        return Err(AppError::forbidden("邀请的已核验接收渠道已失效或不匹配"));
    }
    Ok(())
}

pub(super) async fn require_verification(
    tx: &mut Transaction<'_, Postgres>,
    invitation: &Invitation,
    verification: Uuid,
) -> Result<VerifiedBinding, AppError> {
    let target: Option<VerifiedBinding> = sqlx::query_as(
        "SELECT verified.delivery_target_id AS id,verified.delivery_target_version AS version,verified.version AS verification_version \
         FROM public.auth_invitation_verifications verified \
         JOIN public.auth_delivery_jobs job ON job.invitation_id=verified.invitation_id \
           AND job.kind='INVITATION' AND job.target_id=verified.delivery_target_id \
           AND job.target_version=verified.delivery_target_version \
         WHERE verified.id=$1 AND verified.invitation_id=$2 \
           AND verified.recipient_ref=$3 AND verified.purpose=$4 AND verified.status='ACTIVE' \
           AND verified.verified_at<=clock_timestamp() \
           AND verified.expires_at>clock_timestamp() \
         FOR SHARE OF job",
    )
    .bind(verification)
    .bind(invitation.id)
    .bind(&invitation.recipient_ref)
    .bind(&invitation.purpose)
    .fetch_optional(&mut **tx)
    .await?;
    let target = target.ok_or_else(|| AppError::forbidden("邀请缺少当前可信渠道核验事实"))?;
    // Owner-only facts keep SELECT-only ACLs. The narrow owner function locks
    // target then fact, binds this sampled version and rechecks database time.
    let valid: bool = sqlx::query_scalar(
        "SELECT public.identity_invitation_verification_active($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(verification)
    .bind(target.verification_version)
    .bind(invitation.id)
    .bind(target.id)
    .bind(target.version)
    .bind(&invitation.recipient_ref)
    .bind(&invitation.purpose)
    .fetch_one(&mut **tx)
    .await?;
    if !valid {
        return Err(AppError::forbidden("邀请缺少当前可信渠道核验事实"));
    }
    require_target(tx, invitation, target.id, target.version).await?;
    Ok(target)
}
