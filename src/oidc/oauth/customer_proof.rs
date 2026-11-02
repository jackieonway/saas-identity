//! Separate private customer BFF and customer resource-consumer projections.
use super::*;

async fn verified_customer(
    state: &AppState,
    access: &str,
    expected_client: Uuid,
) -> std::result::Result<VerifiedUserAccess, AppError> {
    let invalid = || AppError::unauthorized("客户账号认证来源无效或已失效");
    let verified = verified_user_access(state, access)
        .await
        .map_err(|error| match error {
            OidcError::App(AppError::Unavailable) => AppError::Unavailable,
            OidcError::App(AppError::Server(error)) => AppError::Server(error),
            OidcError::App(AppError::RateLimited(delay)) => AppError::RateLimited(delay),
            _ => invalid(),
        })?;
    let client = &verified.client;
    if client.id != expected_client
        || client.client_id != expected_client.to_string()
        || client.client_type != "CONFIDENTIAL"
        || client.runtime_kind != "WEB_BFF"
        || client.subject_mode != "USER"
        || client.context_mode.as_deref() != Some("PLATFORM_CONTEXT")
        || client.app_purpose != "CUSTOMER_PORTAL"
        || client.allowed_member_types != ["CUSTOMER"]
        || ["openid", "profile"].iter().any(|name| {
            !verified
                .scopes
                .iter()
                .any(|scope| scope.resource_key == "userinfo" && scope.scope_name == *name)
        })
        || verified.live.offline_access
    {
        return Err(invalid());
    }
    if expires_at(&verified) <= Utc::now() {
        return Err(invalid());
    }
    Ok(verified)
}

fn expires_at(verified: &VerifiedUserAccess) -> DateTime<Utc> {
    verified
        .live
        .token_expires_at
        .min(verified.live.grant_expires_at)
        .min(verified.snapshot.source_expires_at)
}

fn issuer(state: &AppState) -> std::result::Result<&str, AppError> {
    state
        .config
        .oidc_issuer
        .as_deref()
        .ok_or(AppError::Unavailable)
}

pub(in crate::oidc) async fn account_proof(
    state: &AppState,
    access: &str,
    expected_client: Uuid,
) -> std::result::Result<Value, AppError> {
    let verified = verified_customer(state, access, expected_client).await?;
    let live = &verified.live;
    let profile = verified
        .profile
        .userinfo_claims(&["openid".into(), "profile".into()])?;
    let scopes = verified
        .scopes
        .iter()
        .map(|scope| scope.scope_name.as_str())
        .collect::<BTreeSet<_>>();
    Ok(json!({
        "contractVersion":"customer-account-proof/1",
        "issuer":issuer(state)?,
        "clientId":verified.client.id,
        "clientPurpose":"CUSTOMER_PORTAL",
        "contextMode":"PLATFORM_CONTEXT",
        "allowedMemberTypes":["CUSTOMER"],
        "scope":scopes,
        "sub":profile.get("sub").and_then(Value::as_str).ok_or(AppError::Unavailable)?,
        "userId":live.user_id,
        "globalSessionId":live.source_session_id,
        "grantId":live.grant_id,
        "accountVersion":live.account_version.to_string(),
        "clientPolicyVersion":live.client_policy_version.to_string(),
        "applicationProjectionVersion":live.application_projection_version.to_string(),
        "authTime":live.auth_time.timestamp(),
        "expiresAt":expires_at(&verified),
        "absoluteExpiresAt":live.grant_expires_at.min(verified.snapshot.source_expires_at)
    }))
}

pub(in crate::oidc) async fn access_proof(
    state: &AppState,
    access: &str,
    expected_client: Uuid,
) -> std::result::Result<Value, AppError> {
    let verified = verified_customer(state, access, expected_client).await?;
    let live = &verified.live;
    let scopes = verified
        .scopes
        .iter()
        .map(|scope| scope.scope_name.as_str())
        .collect::<BTreeSet<_>>();
    Ok(json!({
        "contractVersion":"customer-access-proof/1",
        "tokenType":"access_token",
        "clientPurpose":"CUSTOMER_PORTAL",
        "allowedMemberTypes":["CUSTOMER"],
        "scope":scopes,
        "source":{
            "issuer":issuer(state)?,
            "clientId":verified.client.id,
            "grantId":live.grant_id,
            "globalSessionId":live.source_session_id,
            "userId":live.user_id,
            "accountVersion":live.account_version.to_string(),
            "clientPolicyVersion":live.client_policy_version.to_string(),
            "authTime":live.auth_time.timestamp(),
            "expiresAt":expires_at(&verified)
        },
        "account":{"id":live.user_id,"username":verified.snapshot.username,"realName":verified.snapshot.real_name,"avatar":verified.snapshot.avatar}
    }))
}
