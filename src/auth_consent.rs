//! Durable consent checks and explicit approval for the canonical `auth_*` model.
//!
//! Every operation follows account → application → client → consent group →
//! consent. Request and token lifecycle mutation happens only after this module
//! has established the current group and client permission boundary.

use crate::{
    error::AppError,
    sso::AccountSessionProof,
    util::{audit, uuid7::new_uuid},
};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct ScopeGrant {
    pub(crate) resource_id: Uuid,
    pub(crate) scope_id: Uuid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConsentState {
    Missing,
    Sufficient {
        consent_id: Uuid,
        generation: i64,
        version: i64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConsentApproval {
    pub(crate) consent_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) version: i64,
    pub(crate) expanded: bool,
    pub(crate) restored: bool,
}

pub(crate) struct ConsentAuditContext<'a> {
    pub(crate) ip: &'a str,
    pub(crate) user_agent: &'a str,
}

#[derive(sqlx::FromRow)]
struct ClientIdentity {
    application_id: Uuid,
    environment: String,
    subject_mode: String,
    context_mode: Option<String>,
    status: String,
}

#[derive(sqlx::FromRow)]
struct ApplicationIdentity {
    status: String,
    purpose: String,
    approved_scopes: Vec<String>,
}

#[derive(sqlx::FromRow)]
struct GroupIdentity {
    application_id: Uuid,
    environment: String,
    purpose: String,
    subject_mode: String,
    context_mode: String,
    status: String,
    version: i64,
}

#[derive(sqlx::FromRow)]
struct ConsentIdentity {
    id: Uuid,
    status: String,
    generation: i64,
    version: i64,
    display_deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    group_version: i64,
}

struct Binding {
    group_id: Uuid,
    group_version: i64,
}

fn normalize_scopes(scopes: &[ScopeGrant]) -> Result<Vec<ScopeGrant>, AppError> {
    if scopes.is_empty() || scopes.len() > 128 {
        return Err(AppError::bad_request("授权资源范围无效"));
    }
    let unique = scopes.iter().copied().collect::<HashSet<_>>();
    if unique.len() != scopes.len() {
        return Err(AppError::bad_request("授权资源范围重复"));
    }
    let mut normalized = unique.into_iter().collect::<Vec<_>>();
    normalized.sort_by_key(|scope| (scope.resource_id, scope.scope_id));
    Ok(normalized)
}

async fn validate_account(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    write_lock: bool,
    allow_naturally_expired_session: bool,
) -> Result<(), AppError> {
    let lock = if write_lock {
        "FOR UPDATE"
    } else {
        "FOR SHARE"
    };
    let sql =
        format!("SELECT session_version FROM public.users WHERE id=$1 AND status='ENABLED' {lock}");
    let version: Option<i64> = sqlx::query_scalar(&sql)
        .bind(proof.user_id)
        .fetch_optional(&mut **tx)
        .await?;
    if version != Some(proof.account_version) {
        return Err(AppError::unauthorized("账号授权来源已失效"));
    }
    let source_valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.sso_sessions WHERE id=$1 AND user_id=$2 \
         AND account_version=$3 AND revoked_at IS NULL \
         AND ($4 OR (expires_at>clock_timestamp() AND $5::timestamptz>clock_timestamp())))",
    )
    .bind(proof.id)
    .bind(proof.user_id)
    .bind(proof.account_version)
    .bind(allow_naturally_expired_session)
    .bind(proof.expires_at)
    .fetch_one(&mut **tx)
    .await?;
    if !source_valid {
        return Err(AppError::unauthorized("账号授权来源已失效"));
    }
    Ok(())
}

async fn binding(
    tx: &mut Transaction<'_, Postgres>,
    client_id: Uuid,
    scopes: &[ScopeGrant],
) -> Result<Binding, AppError> {
    let application_id: Option<Uuid> =
        sqlx::query_scalar("SELECT application_id FROM public.auth_clients WHERE id=$1")
            .bind(client_id)
            .fetch_optional(&mut **tx)
            .await?;
    let application_id = application_id.ok_or_else(|| AppError::not_found("认证客户端不存在"))?;
    let application: Option<ApplicationIdentity> = sqlx::query_as(
        "SELECT status,purpose,approved_scopes FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(application_id)
    .fetch_optional(&mut **tx)
    .await?;
    let application = application.ok_or_else(|| AppError::not_found("认证应用不存在"))?;
    let client: Option<ClientIdentity> = sqlx::query_as(
        "SELECT application_id,environment,subject_mode,context_mode,status \
         FROM public.auth_clients WHERE id=$1 FOR SHARE",
    )
    .bind(client_id)
    .fetch_optional(&mut **tx)
    .await?;
    let client = client.ok_or_else(|| AppError::not_found("认证客户端不存在"))?;
    let group_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT group_id FROM public.auth_consent_group_clients WHERE client_id=$1",
    )
    .bind(client_id)
    .fetch_optional(&mut **tx)
    .await?;
    let group_id = group_id.ok_or_else(|| AppError::forbidden("认证客户端尚未加入明确同意组"))?;
    let group: Option<GroupIdentity> = sqlx::query_as(
        "SELECT application_id,environment,purpose,subject_mode,context_mode,status,version \
         FROM public.auth_consent_groups WHERE id=$1 FOR SHARE",
    )
    .bind(group_id)
    .fetch_optional(&mut **tx)
    .await?;
    let group = group.ok_or_else(|| AppError::forbidden("认证客户端同意组不可用"))?;
    if application.status != "APPROVED"
        || client.status != "ENABLED"
        || client.subject_mode != "USER"
        || group.subject_mode != "USER"
        || group.status != "ACTIVE"
        || client.application_id != application_id
        || group.application_id != application_id
        || group.environment != client.environment
        || group.purpose != application.purpose
        || Some(group.context_mode.as_str()) != client.context_mode.as_deref()
    {
        return Err(AppError::forbidden("认证客户端不满足同意组授权边界"));
    }

    let requested = normalize_scopes(scopes)?;
    let resources = requested
        .iter()
        .map(|scope| scope.resource_id)
        .collect::<Vec<_>>();
    let scope_ids = requested
        .iter()
        .map(|scope| scope.scope_id)
        .collect::<Vec<_>>();
    let matched: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "WITH requested AS (SELECT * FROM unnest($2::uuid[],$3::uuid[]) AS q(resource_id,scope_id)) \
         SELECT q.resource_id,q.scope_id,s.scope_name FROM requested q \
         JOIN public.auth_client_permissions p ON p.client_id=$1 AND p.resource_id=q.resource_id AND p.scope_id=q.scope_id \
         JOIN public.auth_resources r ON r.id=q.resource_id AND r.status='ACTIVE' \
         JOIN public.auth_scopes s ON s.id=q.scope_id AND s.resource_id=q.resource_id AND s.status='ACTIVE' \
         WHERE p.expires_at IS NULL OR p.expires_at>clock_timestamp()",
    )
    .bind(client_id)
    .bind(resources)
    .bind(scope_ids)
    .fetch_all(&mut **tx)
    .await?;
    if matched.len() != requested.len()
        || matched
            .iter()
            .any(|(_, _, scope_name)| !application.approved_scopes.contains(scope_name))
    {
        return Err(AppError::forbidden("请求范围未获此客户端批准"));
    }
    Ok(Binding {
        group_id,
        group_version: group.version,
    })
}

async fn covered(
    tx: &mut Transaction<'_, Postgres>,
    consent_id: Uuid,
    scopes: &[ScopeGrant],
) -> Result<bool, AppError> {
    let requested = normalize_scopes(scopes)?;
    let resources = requested
        .iter()
        .map(|scope| scope.resource_id)
        .collect::<Vec<_>>();
    let scope_ids = requested
        .iter()
        .map(|scope| scope.scope_id)
        .collect::<Vec<_>>();
    sqlx::query_scalar(
        "WITH requested AS (SELECT * FROM unnest($2::uuid[],$3::uuid[]) AS q(resource_id,scope_id)) \
         SELECT NOT EXISTS(SELECT 1 FROM requested q WHERE NOT EXISTS( \
           SELECT 1 FROM public.auth_consent_scopes s WHERE s.consent_id=$1 \
             AND s.resource_id=q.resource_id AND s.scope_id=q.scope_id))",
    )
    .bind(consent_id)
    .bind(resources)
    .bind(scope_ids)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// Check whether a current active user consent already covers a request. The
/// caller may reuse the login without prompting only when this returns true.
async fn sufficient_after_account_validation(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    client_id: Uuid,
    scopes: &[ScopeGrant],
) -> Result<ConsentState, AppError> {
    let binding = binding(tx, client_id, scopes).await?;
    let consent: Option<ConsentIdentity> = sqlx::query_as(
        "SELECT id,status,generation,version,display_deleted_at,group_version FROM public.auth_consents \
         WHERE user_id=$1 AND group_id=$2 FOR SHARE",
    )
    .bind(proof.user_id)
    .bind(binding.group_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(consent) = consent
        .filter(|consent| consent.status == "ACTIVE" && consent.display_deleted_at.is_none())
    else {
        return Ok(ConsentState::Missing);
    };
    if consent.group_version == binding.group_version && covered(tx, consent.id, scopes).await? {
        Ok(ConsentState::Sufficient {
            consent_id: consent.id,
            generation: consent.generation,
            version: consent.version,
        })
    } else {
        Ok(ConsentState::Missing)
    }
}

/// Check consent for an ordinary online authorization. The browser session
/// must still be live.
pub(crate) async fn sufficient(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    client_id: Uuid,
    scopes: &[ScopeGrant],
) -> Result<ConsentState, AppError> {
    // Sufficient-consent checks are read-only. A share lock preserves the
    // account-version fence without upgrading a caller's existing share lock.
    validate_account(tx, proof, false, false).await?;
    sufficient_after_account_validation(tx, proof, client_id, scopes).await
}

/// Check consent for a grant that explicitly includes the approved
/// `offline_access` scope. Natural browser-session expiry does not revoke that
/// authorization, but session revocation and account-generation changes do.
pub(crate) async fn sufficient_offline(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    client_id: Uuid,
    scopes: &[ScopeGrant],
) -> Result<ConsentState, AppError> {
    validate_account(tx, proof, false, true).await?;
    sufficient_after_account_validation(tx, proof, client_id, scopes).await
}

/// Persist the scope set explicitly approved by the user. Active scope growth
/// is additive. A revoked/deleted row starts a new active display record in the
/// generation already advanced by revocation; the former grants stay fenced.
pub(crate) async fn approve(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    client_id: Uuid,
    scopes: &[ScopeGrant],
    audit_context: ConsentAuditContext<'_>,
) -> Result<ConsentApproval, AppError> {
    // Approval serializes first consent creation and scope expansion.
    validate_account(tx, proof, true, false).await?;
    let requested = normalize_scopes(scopes)?;
    let binding = binding(tx, client_id, &requested).await?;
    let existing: Option<ConsentIdentity> = sqlx::query_as(
        "SELECT id,status,generation,version,display_deleted_at,group_version FROM public.auth_consents \
         WHERE user_id=$1 AND group_id=$2 FOR UPDATE",
    )
    .bind(proof.user_id)
    .bind(binding.group_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(consent) = existing else {
        let consent_id = new_uuid();
        sqlx::query(
            "INSERT INTO public.auth_consents(id,user_id,group_id,status,generation,group_version,version,authorized_at,revoked_at,display_deleted_at) \
             VALUES($1,$2,$3,'ACTIVE',1,$4,1,clock_timestamp(),NULL,NULL)",
        )
        .bind(consent_id)
        .bind(proof.user_id)
        .bind(binding.group_id)
        .bind(binding.group_version)
        .execute(&mut **tx)
        .await?;
        insert_scopes(tx, consent_id, &requested).await?;
        let approval = ConsentApproval {
            consent_id,
            generation: 1,
            version: 1,
            expanded: false,
            restored: false,
        };
        audit_approval(
            tx,
            proof,
            client_id,
            binding.group_id,
            &approval,
            requested.len(),
            &audit_context,
        )
        .await?;
        return Ok(approval);
    };

    let restored = consent.status == "REVOKED" || consent.display_deleted_at.is_some();
    let before_covers = if !restored {
        covered(tx, consent.id, &requested).await?
    } else {
        false
    };
    if restored {
        sqlx::query("DELETE FROM public.auth_consent_scopes WHERE consent_id=$1")
            .bind(consent.id)
            .execute(&mut **tx)
            .await?;
    }
    insert_scopes(tx, consent.id, &requested).await?;
    let expanded = !restored && !before_covers;
    let membership_changed = consent.group_version != binding.group_version;
    let changed = if restored || expanded || membership_changed {
        sqlx::query(
            "UPDATE public.auth_consents SET status='ACTIVE',group_version=$4,version=version+1,authorized_at=clock_timestamp(), \
             revoked_at=NULL,display_deleted_at=NULL WHERE id=$1 AND generation=$2 AND version=$3",
        )
        .bind(consent.id)
        .bind(consent.generation)
        .bind(consent.version)
        .bind(binding.group_version)
        .execute(&mut **tx)
        .await?
        .rows_affected()
    } else {
        // Explicit prompt=consent may repeat the current sufficient selection;
        // record that confirmation without widening the grant or generation.
        sqlx::query(
            "UPDATE public.auth_consents SET group_version=$4,version=version+1,authorized_at=clock_timestamp() \
             WHERE id=$1 AND status='ACTIVE' AND generation=$2 AND version=$3 AND display_deleted_at IS NULL",
        )
        .bind(consent.id)
        .bind(consent.generation)
        .bind(consent.version)
        .bind(binding.group_version)
        .execute(&mut **tx)
        .await?
        .rows_affected()
    };
    if changed != 1 {
        return Err(AppError::conflict("账号授权版本已变化"));
    }
    let next_version = consent
        .version
        .checked_add(1)
        .ok_or(AppError::Unavailable)?;
    let approval = ConsentApproval {
        consent_id: consent.id,
        generation: consent.generation,
        version: next_version,
        expanded,
        restored,
    };
    audit_approval(
        tx,
        proof,
        client_id,
        binding.group_id,
        &approval,
        requested.len(),
        &audit_context,
    )
    .await?;
    Ok(approval)
}

async fn audit_approval(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    client_id: Uuid,
    group_id: Uuid,
    approval: &ConsentApproval,
    scope_count: usize,
    context: &ConsentAuditContext<'_>,
) -> Result<(), AppError> {
    audit::write_in_tx(
        tx,
        audit::AuditInfo {
            user_id: Some(proof.user_id),
            username: &proof.username,
            action: "AUTH_CONSENT_APPROVE",
            detail: &json!({
                "consentId":approval.consent_id,
                "groupId":group_id,
                "clientId":client_id,
                "generation":approval.generation,
                "version":approval.version,
                "scopeCount":scope_count,
                "expanded":approval.expanded,
                "restored":approval.restored
            })
            .to_string(),
            ip: context.ip,
            user_agent: context.user_agent,
        },
    )
    .await
}

async fn insert_scopes(
    tx: &mut Transaction<'_, Postgres>,
    consent_id: Uuid,
    scopes: &[ScopeGrant],
) -> Result<(), AppError> {
    for scope in scopes {
        sqlx::query(
            "INSERT INTO public.auth_consent_scopes(consent_id,resource_id,scope_id,granted_at) \
             VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT(consent_id,resource_id,scope_id) DO NOTHING",
        )
        .bind(consent_id)
        .bind(scope.resource_id)
        .bind(scope.scope_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
