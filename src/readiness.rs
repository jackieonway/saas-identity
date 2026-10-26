use crate::{error::AppError, state::IdentityState};
use axum::{extract::State, Json};
use serde_json::{json, Value};

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
         AND pg_catalog.has_table_privilege(current_user,'public.sso_sessions','SELECT') \
         AND pg_catalog.has_table_privilege(current_user,'public.oidc_grants','SELECT') \
         AND pg_catalog.has_table_privilege(current_user,'public.identity_service_clients','SELECT') \
         AND pg_catalog.has_table_privilege(current_user,'public.identity_audit_logs','INSERT') \
         AND NOT pg_catalog.has_any_column_privilege(current_user,'public.identity_service_clients','INSERT,UPDATE,REFERENCES') \
         AND NOT pg_catalog.has_table_privilege(current_user,'public.identity_service_clients','DELETE,TRUNCATE,TRIGGER') \
         AND NOT pg_catalog.has_any_column_privilege(current_user,'public.identity_deployment_state','INSERT,UPDATE,REFERENCES') \
         AND NOT pg_catalog.has_table_privilege(current_user,'public.identity_deployment_state','DELETE,TRUNCATE,TRIGGER') \
         AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['memberships','roles','menus','organizations','tenants','user_roles', \
           'applications','tenant_applications','organization_applications','platform_sessions','platform_session_refresh_tokens', \
           'oauth_clients','oauth_tokens','oauth_authorization_codes','oauth_authorization_requests','oauth_device_codes', \
           'console_browsers','console_login_flows','bff_sessions','customer_portal_contexts']::text[]) AS target(name) \
           WHERE pg_catalog.has_any_column_privilege(current_user,'public.'||target.name,'SELECT,INSERT,UPDATE,REFERENCES') \
              OR pg_catalog.has_table_privilege(current_user,'public.'||target.name,'DELETE,TRUNCATE,TRIGGER,REFERENCES'))")
        .fetch_one(&state.pool).await.map_err(|_|AppError::Unavailable)?;
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
