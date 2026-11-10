use crate::{error::AppError, state::IdentityState};
use axum::{extract::State, Json};
use serde_json::{json, Value};

pub(crate) async fn live() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(json!({"status":"alive"})),
    )
}

pub(crate) async fn verify(state: &IdentityState) -> Result<(), AppError> {
    let ready:bool=sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.identity_deployment_state d JOIN pg_catalog.pg_roles r ON r.rolname=current_user \
         WHERE d.singleton AND d.schema_version=1 AND d.issuer=$1 AND d.identity_runtime=current_user \
         AND current_user=session_user AND r.rolcanlogin \
         AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls \
         AND NOT pg_catalog.pg_has_role(current_user,d.migration_owner,'MEMBER') \
         AND NOT pg_catalog.pg_has_role(current_user,d.identity_owner,'MEMBER') \
         AND NOT pg_catalog.pg_has_role(current_user,d.platform_owner,'MEMBER') \
         AND NOT pg_catalog.pg_has_role(current_user,d.revocation_bridge_owner,'MEMBER') \
         AND NOT pg_catalog.pg_has_role(current_user,d.projection_owner,'MEMBER') \
         AND NOT pg_catalog.has_schema_privilege(current_user,'public','CREATE') \
         AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'CREATE') \
         AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'TEMP') \
         AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' \
           AND pg_catalog.has_schema_privilege(current_user,n.oid,'CREATE')) \
         AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid) \
         AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace \
           WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND pg_catalog.pg_has_role(current_user,c.relowner,'MEMBER')) \
         AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace \
           WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND pg_catalog.pg_has_role(current_user,p.proowner,'MEMBER')))")
        .bind(state.config.oidc_issuer.as_deref().unwrap_or("https://auth.saas.test"))
        .fetch_one(&state.pool).await.map_err(|_|AppError::Unavailable)?;
    if !ready {
        return Err(AppError::Unavailable);
    }
    // A sealed marker does not authorize later privilege expansion. Check the
    // effective runtime capability as well as role names and object owners.
    let isolated:bool=sqlx::query_scalar(
        "SELECT pg_catalog.has_column_privilege(current_user,'public.users','password_hash','SELECT') \
         AND pg_catalog.has_column_privilege(current_user,'public.users','password_hash','UPDATE') \
         AND pg_catalog.has_column_privilege(current_user,'public.users','password_hash','INSERT') \
         AND pg_catalog.has_column_privilege(current_user,'public.users','status','SELECT') \
         AND pg_catalog.has_column_privilege(current_user,'public.users','status','UPDATE') \
         AND pg_catalog.has_column_privilege(current_user,'public.users','session_version','SELECT') \
         AND pg_catalog.has_column_privilege(current_user,'public.users','session_version','UPDATE') \
         AND NOT pg_catalog.has_column_privilege(current_user,'public.users','is_super_admin','SELECT,INSERT,UPDATE') \
         AND NOT pg_catalog.has_column_privilege(current_user,'public.users','id','UPDATE') \
         AND NOT pg_catalog.has_table_privilege(current_user,'public.users','DELETE,TRUNCATE,TRIGGER') \
         AND pg_catalog.has_column_privilege(current_user,'public.auth_clients','auto_authorize','SELECT') \
         AND pg_catalog.has_column_privilege(current_user,'public.auth_clients','access_token_ttl_seconds','SELECT') \
         AND pg_catalog.has_column_privilege(current_user,'public.auth_clients','refresh_token_ttl_seconds','SELECT') \
         AND pg_catalog.has_column_privilege(current_user,'public.auth_clients','client_token_ttl_seconds','SELECT') \
         AND pg_catalog.has_table_privilege(current_user,'public.sso_sessions','SELECT') \
         AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY[
           'auth_applications','auth_application_admissions','auth_resources','auth_scopes','auth_clients','auth_client_credentials',
           'auth_client_permissions','auth_consent_groups','auth_consent_group_clients','auth_consents',
           'auth_consent_scopes','auth_subject_sectors','auth_subject_links','auth_authorization_requests','auth_context_interactions',
           'auth_authorization_codes','auth_grants','auth_grant_scopes','auth_access_tokens',
           'auth_access_token_scopes','auth_refresh_families','auth_refresh_tokens', \
           'auth_totp_enrollments','auth_totp_factors','auth_totp_recovery_codes','auth_mfa_recovery_receipts', \
           'auth_mfa_recovery_approvals','auth_invitations']::text[]) AS target(name) \
           WHERE NOT (pg_catalog.has_table_privilege(current_user,'public.'||target.name,'SELECT') \
             AND pg_catalog.has_table_privilege(current_user,'public.'||target.name,'INSERT') \
             AND pg_catalog.has_table_privilege(current_user,'public.'||target.name,'UPDATE') \
             AND pg_catalog.has_table_privilege(current_user,'public.'||target.name,'DELETE'))) \
         AND EXISTS(SELECT 1 FROM public.identity_deployment_state d WHERE d.identity_runtime=current_user AND NOT EXISTS(
           SELECT 1 FROM unnest(ARRAY[
             'auth_applications','auth_application_admissions','auth_resources','auth_scopes','auth_clients','auth_client_credentials',
             'auth_client_permissions','auth_consent_groups','auth_consent_group_clients','auth_consents',
             'auth_consent_scopes','auth_consent_revocation_outbox','auth_subject_sectors','auth_subject_links','auth_authorization_requests','auth_context_interactions',
             'auth_authorization_codes','auth_grants','auth_grant_scopes','auth_access_tokens',
             'auth_access_token_scopes','auth_refresh_families','auth_refresh_tokens', \
             'auth_totp_enrollments','auth_totp_factors','auth_totp_recovery_codes','auth_mfa_recovery_receipts', \
             'auth_mfa_recovery_approvals','auth_security_notification_outbox','auth_invitations']::text[]) AS target(name)
             WHERE pg_catalog.has_any_column_privilege(d.platform_runtime,'public.'||target.name,'SELECT,INSERT,UPDATE,REFERENCES') \
                OR pg_catalog.has_table_privilege(d.platform_runtime,'public.'||target.name,'DELETE,TRUNCATE,TRIGGER,REFERENCES'))) \
         AND public.identity_phase20_schema_ready() \
         AND pg_catalog.has_table_privilege(current_user,'public.identity_service_clients','SELECT') \
         AND pg_catalog.has_column_privilege(current_user,'public.identity_service_clients','allowed_auth_resources','SELECT') \
         AND pg_catalog.has_table_privilege(current_user,'public.identity_audit_logs','INSERT') \
         AND pg_catalog.has_function_privilege(current_user,'public.identity_auth_invitation_intent_active(uuid,uuid,text,text,text,uuid,uuid)','EXECUTE') \
         AND pg_catalog.has_function_privilege(current_user,'public.identity_auth_review_intent_active(uuid,uuid,text,text,text,jsonb)','EXECUTE') \
         AND EXISTS(SELECT 1 FROM public.identity_deployment_state d WHERE d.identity_runtime=current_user \
           AND NOT pg_catalog.has_function_privilege(d.platform_runtime,'public.identity_auth_review_intent_active(uuid,uuid,text,text,text,jsonb)','EXECUTE') \
           AND (SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid='public.identity_auth_review_intent_active(uuid,uuid,text,text,text,jsonb)'::regprocedure) \
               =(SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname=d.platform_owner) \
           AND pg_catalog.has_function_privilege(d.platform_runtime,'public.identity_admin_assurance(uuid,uuid,uuid,bigint,uuid,bigint,text)','EXECUTE') \
           AND pg_catalog.has_table_privilege(d.platform_runtime,'public.platform_auth_release_bindings','SELECT') \
           AND NOT pg_catalog.has_any_column_privilege(d.platform_runtime,'public.platform_auth_release_bindings','INSERT,UPDATE,REFERENCES') \
           AND NOT pg_catalog.has_table_privilege(d.platform_runtime,'public.platform_auth_release_bindings','DELETE,TRUNCATE,TRIGGER')) \
         AND EXISTS(SELECT 1 FROM public.identity_deployment_state d WHERE d.identity_runtime=current_user \
           AND NOT pg_catalog.has_function_privilege(d.platform_runtime,'public.identity_auth_invitation_intent_active(uuid,uuid,text,text,text,uuid,uuid)','EXECUTE') \
           AND (SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid='public.identity_auth_invitation_intent_active(uuid,uuid,text,text,text,uuid,uuid)'::regprocedure) \
               =(SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname=d.platform_owner)) \
         AND pg_catalog.has_table_privilege(current_user,'public.identity_consent_command_receipts','SELECT') \
         AND pg_catalog.has_table_privilege(current_user,'public.identity_consent_command_receipts','INSERT') \
         AND NOT pg_catalog.has_table_privilege(current_user,'public.identity_consent_command_receipts','UPDATE,DELETE,TRUNCATE,TRIGGER') \
         AND NOT pg_catalog.has_any_column_privilege(current_user,'public.identity_service_clients','INSERT,UPDATE,REFERENCES') \
         AND NOT pg_catalog.has_table_privilege(current_user,'public.identity_service_clients','DELETE,TRUNCATE,TRIGGER') \
         AND NOT pg_catalog.has_any_column_privilege(current_user,'public.identity_deployment_state','INSERT,UPDATE,REFERENCES') \
         AND NOT pg_catalog.has_table_privilege(current_user,'public.identity_deployment_state','DELETE,TRUNCATE,TRIGGER') \
         AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['memberships','roles','menus','organizations','tenants','user_roles', \
           'applications','tenant_applications','organization_applications','platform_sessions','platform_session_refresh_tokens', \
           'console_browsers','console_login_flows','bff_sessions','customer_portal_contexts', \
           'context_selections','context_selection_services','context_selection_registrations', \
           'platform_app_capabilities','platform_resource_services','platform_resource_bindings','platform_machine_delegations', \
           'platform_auth_partners','platform_auth_applications','platform_auth_application_operators', \
           'platform_auth_application_requests','platform_auth_release_bindings','platform_auth_review_operations']::text[]) AS target(name) \
           WHERE pg_catalog.has_any_column_privilege(current_user,'public.'||target.name,'SELECT,INSERT,UPDATE,REFERENCES') \
              OR pg_catalog.has_table_privilege(current_user,'public.'||target.name,'DELETE,TRUNCATE,TRIGGER,REFERENCES'))")
        .fetch_one(&state.pool).await.map_err(|_|AppError::Unavailable)?;
    if let Some(platform) = state.config.context_platform.as_ref() {
        let reused:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identity_service_clients WHERE secret_hash=$1) OR EXISTS(SELECT 1 FROM auth_client_credentials WHERE secret_digest=$1)")
            .bind(platform.secret_digest()).fetch_one(&state.pool).await.map_err(|_|AppError::Unavailable)?;
        if reused {
            return Err(AppError::Unavailable);
        }
    }
    if isolated {
        Ok(())
    } else {
        Err(AppError::Unavailable)
    }
}
pub(crate) async fn health(State(state): State<IdentityState>) -> Result<Json<Value>, AppError> {
    verify(&state).await?;
    crate::oidc::initialize(&state).await?;
    Ok(Json(
        json!({"status":"UP","service":"saas-identity","issuer":"https://auth.saas.test"}),
    ))
}
