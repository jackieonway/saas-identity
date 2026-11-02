//! Pairwise OIDC subjects and the minimal consented profile projection.
//!
//! The only account input is the SSO session proof created by the trusted
//! session reader. Public requests cannot construct a subject or supply a
//! private account identifier to this module.

use serde_json::{json, Map, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppError,
    sso::{self, AccountSessionProof},
    util::uuid7,
};

struct PairwiseSubject(String);

/// A narrow source for the shared ID Token and UserInfo claims. Its fields are
/// private so internal account IDs cannot be substituted for the public sub.
pub(crate) struct OidcProfile {
    subject: PairwiseSubject,
    name: String,
    picture: Option<String>,
}

impl OidcProfile {
    /// Build only claims supported by the consented scope set. Both protocol
    /// surfaces call this same constructor to keep their sub and profile equal.
    pub(crate) fn id_token_claims(&self, consented_scopes: &[String]) -> Result<Value, AppError> {
        self.claims(consented_scopes)
    }

    pub(crate) fn userinfo_claims(&self, consented_scopes: &[String]) -> Result<Value, AppError> {
        self.claims(consented_scopes)
    }

    fn claims(&self, consented_scopes: &[String]) -> Result<Value, AppError> {
        if !consented_scopes.iter().any(|scope| scope == "openid") {
            return Err(AppError::forbidden(
                "OIDC claims require a consented openid scope",
            ));
        }
        let mut claims = Map::new();
        claims.insert("sub".into(), json!(self.subject.0));
        if consented_scopes.iter().any(|scope| scope == "profile") {
            let name = self.name.trim();
            if !name.is_empty() {
                claims.insert("name".into(), json!(name));
            }
            if let Some(picture) = &self.picture {
                claims.insert("picture".into(), json!(picture));
            }
        }
        Ok(Value::Object(claims))
    }
}

#[derive(sqlx::FromRow)]
struct AccountSubjectState {
    status: String,
    session_version: i64,
    real_name: String,
    avatar: String,
    retired: bool,
    proof_live: bool,
}

#[derive(sqlx::FromRow)]
struct ClientSubjectPolicy {
    environment: String,
    subject_mode: String,
    status: String,
}

/// Resolve a pairwise subject for an enabled USER client. Call inside the
/// token/grant transaction, after obtaining `AccountSessionProof` from SSO.
/// Locks follow account/security → application → client → subject sector/link.
pub(crate) async fn profile_for_client(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    client_id: Uuid,
) -> Result<OidcProfile, AppError> {
    profile_for_client_with_session_policy(tx, proof, client_id, false).await
}

/// Resolve the original account's pairwise profile for an explicitly consented
/// offline grant. The caller must already have revalidated the account version,
/// non-revoked source session, consent and client/app policy; natural session
/// expiry alone does not invalidate the offline proof.
pub(crate) async fn profile_for_offline_client(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    client_id: Uuid,
) -> Result<OidcProfile, AppError> {
    profile_for_client_with_session_policy(tx, proof, client_id, true).await
}

async fn profile_for_client_with_session_policy(
    tx: &mut Transaction<'_, Postgres>,
    proof: &AccountSessionProof,
    client_id: Uuid,
    allow_naturally_expired_session: bool,
) -> Result<OidcProfile, AppError> {
    if !uuid7::is_uuid_v7(proof.user_id)
        || !uuid7::is_uuid_v7(proof.id)
        || proof.account_version < 1
        || !uuid7::is_uuid_v7(client_id)
    {
        return Err(AppError::unauthorized("账号认证证明无效"));
    }

    // Account generation is first in the shared lock order. Compatible share
    // locks allow concurrent authentication; account mutation/retirement must
    // wait, or win first and make this proof fail before a subject is returned.
    let account: Option<AccountSubjectState> = sqlx::query_as(
        "SELECT u.status,u.session_version,COALESCE(u.real_name,'') AS real_name, \
         COALESCE(u.avatar,'') AS avatar, \
         EXISTS(SELECT 1 FROM public.identity_account_tombstones t WHERE t.user_id=u.id) AS retired, \
         ($2 OR $3::timestamptz > clock_timestamp()) AS proof_live \
         FROM public.users u WHERE u.id=$1 FOR SHARE OF u",
    )
    .bind(proof.user_id)
    .bind(allow_naturally_expired_session)
    .bind(proof.expires_at)
    .fetch_optional(&mut **tx)
    .await?;
    let account = account.ok_or_else(|| AppError::unauthorized("账号认证证明已失效"))?;
    if account.status != "ENABLED"
        || account.session_version != proof.account_version
        || account.retired
        || !account.proof_live
    {
        return Err(AppError::unauthorized("账号认证证明已失效"));
    }

    // Read the immutable client/application binding, then lock the application
    // before the client to match AUTH_ADMIN and projection updates.
    let application_id: Option<Uuid> =
        sqlx::query_scalar("SELECT application_id FROM public.auth_clients WHERE id=$1")
            .bind(client_id)
            .fetch_optional(&mut **tx)
            .await?;
    let application_id = application_id.ok_or_else(|| AppError::not_found("OIDC 客户端不存在"))?;
    let application_status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(application_id)
    .fetch_optional(&mut **tx)
    .await?;
    if application_status.as_deref() != Some("APPROVED") {
        return Err(AppError::forbidden("应用尚未批准或已停用"));
    }
    let client: Option<ClientSubjectPolicy> = sqlx::query_as(
        "SELECT environment,subject_mode,status FROM public.auth_clients \
         WHERE id=$1 AND application_id=$2 FOR SHARE",
    )
    .bind(client_id)
    .bind(application_id)
    .fetch_optional(&mut **tx)
    .await?;
    let client = client.ok_or_else(|| AppError::not_found("OIDC 客户端不存在"))?;
    if client.subject_mode != "USER" || client.status != "ENABLED" {
        return Err(AppError::forbidden("客户端不允许人员 OIDC subject"));
    }

    // There is one sector per approved application/environment. A retired
    // sector is terminal and the uniqueness constraint prevents recreation.
    sqlx::query(
        "INSERT INTO public.auth_subject_sectors(id,application_id,environment,status) \
         VALUES($1,$2,$3,'ACTIVE') ON CONFLICT(application_id,environment) DO NOTHING",
    )
    .bind(uuid7::new_uuid())
    .bind(application_id)
    .bind(&client.environment)
    .execute(&mut **tx)
    .await?;
    let sector: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id,status FROM public.auth_subject_sectors \
         WHERE application_id=$1 AND environment=$2 FOR SHARE",
    )
    .bind(application_id)
    .bind(&client.environment)
    .fetch_optional(&mut **tx)
    .await?;
    let (sector_id, sector_status) = sector.ok_or(AppError::Unavailable)?;
    if sector_status != "ACTIVE" {
        return Err(AppError::forbidden("应用环境的 subject sector 已退役"));
    }

    let existing: Option<(String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT subject,retired_at FROM public.auth_subject_links \
         WHERE user_id=$1 AND sector_id=$2 FOR SHARE",
    )
    .bind(proof.user_id)
    .bind(sector_id)
    .fetch_optional(&mut **tx)
    .await?;
    let subject = match existing {
        Some((_, Some(_))) => {
            return Err(AppError::forbidden("账号的 pairwise subject 已退役"));
        }
        Some((subject, None)) => subject,
        None => create_subject_link(tx, proof.user_id, sector_id).await?,
    };

    // Recheck an online proof against the database clock after the mapping
    // work. An offline caller has already established the non-revoked session
    // and account-generation fence, so natural expiry is not a revocation fact.
    let proof_live: bool = sqlx::query_scalar("SELECT $2 OR $1::timestamptz > clock_timestamp()")
        .bind(proof.expires_at)
        .bind(allow_naturally_expired_session)
        .fetch_one(&mut **tx)
        .await?;
    if !proof_live {
        return Err(AppError::unauthorized("账号认证证明已过期"));
    }

    Ok(OidcProfile {
        subject: PairwiseSubject(subject),
        name: account.real_name,
        picture: safe_picture(&account.avatar),
    })
}

async fn create_subject_link(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    sector_id: Uuid,
) -> Result<String, AppError> {
    for _ in 0..3 {
        let candidate = sso::opaque_secret()?;
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO public.auth_subject_links(id,user_id,sector_id,subject) \
             VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING subject",
        )
        .bind(uuid7::new_uuid())
        .bind(user_id)
        .bind(sector_id)
        .bind(&candidate)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(subject) = inserted {
            return Ok(subject);
        }
        let existing: Option<(String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
            "SELECT subject,retired_at FROM public.auth_subject_links \
             WHERE user_id=$1 AND sector_id=$2 FOR SHARE",
        )
        .bind(user_id)
        .bind(sector_id)
        .fetch_optional(&mut **tx)
        .await?;
        match existing {
            Some((_, Some(_))) => {
                return Err(AppError::forbidden("账号的 pairwise subject 已退役"));
            }
            Some((subject, None)) => return Ok(subject),
            None => continue, // A sector/subject collision; mint another random value.
        }
    }
    Err(AppError::Unavailable)
}

fn safe_picture(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let url = reqwest::Url::parse(value).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
    {
        return None;
    }
    Some(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(picture: Option<&str>) -> OidcProfile {
        OidcProfile {
            subject: PairwiseSubject("f".repeat(64)),
            name: "Display Name".into(),
            picture: picture.map(str::to_owned),
        }
    }

    #[test]
    fn id_token_and_userinfo_share_only_consented_profile_claims() {
        let profile = profile(Some("https://cdn.example.test/avatar.png"));
        let consented = vec!["openid".to_owned(), "profile".to_owned()];
        let id_token = profile.id_token_claims(&consented).unwrap();
        let userinfo = profile.userinfo_claims(&consented).unwrap();
        assert_eq!(id_token, userinfo);
        assert_eq!(id_token["sub"], "f".repeat(64));
        assert_eq!(id_token["name"], "Display Name");
        assert_eq!(id_token["picture"], "https://cdn.example.test/avatar.png");
        for forbidden in [
            "userId",
            "user_id",
            "preferred_username",
            "email",
            "email_verified",
            "phone_number",
            "phone_number_verified",
            "roles",
            "memberType",
        ] {
            assert!(
                id_token.get(forbidden).is_none(),
                "unexpected {forbidden} claim"
            );
        }

        let account_only = profile.userinfo_claims(&["openid".to_owned()]).unwrap();
        assert_eq!(account_only, json!({"sub":"f".repeat(64)}));
        assert!(profile.userinfo_claims(&["profile".to_owned()]).is_err());
    }

    #[test]
    fn picture_claim_requires_an_exact_https_url() {
        assert_eq!(
            safe_picture("https://cdn.example.test/avatar.png"),
            Some("https://cdn.example.test/avatar.png".into())
        );
        for value in [
            "http://cdn.example.test/avatar.png",
            "javascript:alert(1)",
            "https://user:pass@cdn.example.test/avatar.png",
            "https://cdn.example.test/avatar.png#fragment",
            "https://cdn.example.test/avatar.png/../avatar.png",
        ] {
            assert_eq!(
                safe_picture(value),
                None,
                "unsafe picture accepted: {value}"
            );
        }
    }
}
