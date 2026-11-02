//! Private, resource-qualified projections over canonical access credentials.
use super::*;

fn invalid() -> AppError {
    AppError::unauthorized("资源访问凭据无效或原授权已失效")
}

fn failure(error: OidcError) -> AppError {
    match error {
        OidcError::App(AppError::Unavailable) => AppError::Unavailable,
        OidcError::App(AppError::Server(error)) => AppError::Server(error),
        OidcError::App(AppError::RateLimited(delay)) => AppError::RateLimited(delay),
        _ => invalid(),
    }
}

fn scope_names(
    scopes: &[Scope],
    resource: &str,
    audience: &str,
    required: &str,
) -> std::result::Result<BTreeSet<String>, AppError> {
    let names = scopes
        .iter()
        .filter(|scope| scope.resource_key == resource && scope.audience == audience)
        .map(|scope| scope.scope_name.clone())
        .collect::<BTreeSet<_>>();
    if !names.contains(required) {
        return Err(AppError::forbidden("访问凭据不含此资源所需 scope"));
    }
    Ok(names)
}

pub(in crate::oidc) async fn prove(
    state: &AppState,
    token: &str,
    resource: &str,
    audience: &str,
    required_scope: &str,
) -> std::result::Result<Value, AppError> {
    let verified = match verified_user_access(state, token).await {
        Ok(verified) => VerifiedAccess::User(verified),
        Err(OidcError::InvalidToken) => VerifiedAccess::Machine(
            verified_machine_access(state, token)
                .await
                .map_err(failure)?,
        ),
        Err(error) => return Err(failure(error)),
    };
    let issuer = state
        .config
        .oidc_issuer
        .as_deref()
        .ok_or(AppError::Unavailable)?;
    match verified {
        VerifiedAccess::User(verified) => {
            let live = &verified.live;
            if live.context_mode != "PLATFORM_CONTEXT"
                || live.offline_access
                || verified.client.context_mode.as_deref() != Some("PLATFORM_CONTEXT")
            {
                return Err(invalid());
            }
            let member_type = match verified.client.allowed_member_types.as_slice() {
                [member_type] if matches!(member_type.as_str(), "EMPLOYEE" | "CUSTOMER") => {
                    member_type
                }
                _ => return Err(invalid()),
            };
            let context = live.context_ref.ok_or_else(invalid)?;
            let member: Option<Uuid> = sqlx::query_scalar("SELECT selected_membership_id FROM public.auth_context_interactions WHERE transaction_id=$1 AND grant_id=$2 AND client_id=$3 AND client_policy_version=$4 AND application_projection_version=$5 AND delivered_at IS NOT NULL AND credential_ciphertext IS NULL")
                .bind(context).bind(live.grant_id).bind(live.client_id).bind(live.client_policy_version).bind(live.application_projection_version).fetch_optional(&state.pool).await.map_err(AppError::from)?.flatten();
            let member = member
                .filter(|id| crate::util::uuid7::is_uuid_v7(*id))
                .ok_or_else(invalid)?;
            let names = scope_names(&verified.scopes, resource, audience, required_scope)?;
            let expires = live
                .token_expires_at
                .min(live.grant_expires_at)
                .min(verified.snapshot.source_expires_at);
            if expires <= Utc::now() {
                return Err(invalid());
            }
            let profile = verified.profile.userinfo_claims(&["openid".into()])?;
            Ok(json!({
                "contractVersion":"resource-access-proof/1","issuer":issuer,"tokenUse":"access_token","subjectMode":"USER",
                "clientId":verified.client.id,"applicationId":verified.client.application_id,"resource":resource,"audience":audience,"scope":names,"expiresAt":expires,
                "sub":profile.get("sub").and_then(Value::as_str).ok_or(AppError::Unavailable)?,
                "source":{"grantId":live.grant_id,"globalSessionId":live.source_session_id,"userId":live.user_id,"accountVersion":live.account_version.to_string(),"clientPolicyVersion":live.client_policy_version.to_string(),"applicationProjectionVersion":live.application_projection_version.to_string(),"authTime":live.auth_time.timestamp(),"contextRef":context},
                "context":{"membershipId":member,"memberType":member_type}
            }))
        }
        VerifiedAccess::Machine(verified) => {
            let names = scope_names(&verified.scopes, resource, audience, required_scope)?;
            if verified.expires_at <= Utc::now() {
                return Err(invalid());
            }
            Ok(json!({
                "contractVersion":"resource-access-proof/1","issuer":issuer,"tokenUse":"access_token","subjectMode":"MACHINE",
                "clientId":verified.client.id,"applicationId":verified.client.application_id,"resource":resource,"audience":audience,"scope":names,"expiresAt":verified.expires_at,
                "credentialVersion":verified.live.credential_version.to_string(),
                "source":{"grantId":verified.live.grant_id,"clientPolicyVersion":verified.live.client_policy_version.to_string(),"applicationProjectionVersion":verified.live.application_projection_version.to_string()}
            }))
        }
    }
}
