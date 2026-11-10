//! Canonical unified-client administration over the identity-owned `auth_*` model.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

use crate::{
    error::AppError,
    extractors::ApiJson,
    internal::{self, ServicePrincipal},
    state::AppState,
    util::audit::{self, AuditInfo},
};

const AUTH_ADMIN: &str = "AUTH_ADMIN";
const CLIENTS_PATH: &str = "/internal/identity/auth/clients";
const CONSENT_GROUPS_PATH: &str = "/internal/identity/auth/consent-groups";
const MAX_PAGE_SIZE: i64 = 100;
const MAX_OFFSET: i64 = 100_000;

const CLIENT_SELECT: &str = "SELECT c.id,c.client_id,c.display_name,c.application_id, \
    a.display_name AS application_name,a.ownership,a.partner_id,c.environment, \
    c.auto_authorize,c.access_token_ttl_seconds,c.refresh_token_ttl_seconds,c.client_token_ttl_seconds, \
    c.client_type,c.runtime_kind,c.subject_mode,c.context_mode,c.allowed_member_types,c.grant_types, \
    c.token_endpoint_auth_method,c.redirect_uris,c.post_logout_redirect_uris,c.logout_mode,c.backchannel_logout_uri,c.backchannel_target_id,c.status,c.version, \
    c.policy_version,c.created_at,c.updated_at,g.group_id AS consent_group_id, \
    COALESCE((SELECT jsonb_agg(jsonb_build_object('resourceKey',p.resource_key,'audience',p.audience,'scopes',p.scopes) ORDER BY p.resource_key) \
      FROM (SELECT r.resource_key,r.audience,array_agg(s.scope_name ORDER BY s.scope_name) AS scopes \
        FROM public.auth_client_permissions cp \
        JOIN public.auth_resources r ON r.id=cp.resource_id \
        JOIN public.auth_scopes s ON s.id=cp.scope_id AND s.resource_id=cp.resource_id \
        WHERE cp.client_id=c.id GROUP BY r.resource_key,r.audience) p), '[]'::jsonb) AS permissions \
    FROM public.auth_clients c \
    JOIN public.auth_applications a ON a.application_id=c.application_id \
    LEFT JOIN public.auth_consent_group_clients g ON g.client_id=c.id";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListQuery {
    application_id: Option<String>,
    partner_id: Option<String>,
    ownership: Option<String>,
    environment: Option<String>,
    client_type: Option<String>,
    subject_mode: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct ClientRow {
    id: Uuid,
    client_id: String,
    display_name: String,
    application_id: Uuid,
    application_name: String,
    ownership: String,
    partner_id: Option<Uuid>,
    environment: String,
    client_type: String,
    runtime_kind: String,
    subject_mode: String,
    context_mode: Option<String>,
    allowed_member_types: Vec<String>,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    logout_mode: String,
    backchannel_logout_uri: Option<String>,
    backchannel_target_id: Option<Uuid>,
    status: String,
    version: i64,
    policy_version: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    consent_group_id: Option<Uuid>,
    auto_authorize: bool,
    access_token_ttl_seconds: Option<i64>,
    refresh_token_ttl_seconds: Option<i64>,
    client_token_ttl_seconds: Option<i64>,
    permissions: Value,
}

impl ClientRow {
    fn json(&self, defaults: &crate::client_policy::TokenDefaults) -> Value {
        json!({
            "id":self.id,
            "clientId":self.client_id,
            "displayName":self.display_name,
            "applicationId":self.application_id,
            "applicationName":self.application_name,
            "ownership":self.ownership,
            "partnerId":self.partner_id,
            "environment":self.environment,
            "clientType":self.client_type,
            "runtimeKind":self.runtime_kind,
            "subjectMode":self.subject_mode,
            "contextMode":self.context_mode,
            "allowedMemberTypes":self.allowed_member_types,
            "grantTypes":self.grant_types,
            "tokenEndpointAuthMethod":self.token_endpoint_auth_method,
            "redirectUris":self.redirect_uris,
            "postLogoutRedirectUris":self.post_logout_redirect_uris,
            "logoutMode":self.logout_mode,
            "backchannelLogoutUri":self.backchannel_logout_uri,
            "backchannelTargetId":self.backchannel_target_id,
            "status":self.status,
            "version":self.version,
            "policyVersion":self.policy_version,
            "createdAt":self.created_at,
            "updatedAt":self.updated_at,
            "consentGroupId":self.consent_group_id,
            "permissions":self.permissions,
            "autoAuthorize":self.auto_authorize,
            "accessTokenTtlSeconds":self.access_token_ttl_seconds,
            "refreshTokenTtlSeconds":self.refresh_token_ttl_seconds,
            "clientTokenTtlSeconds":self.client_token_ttl_seconds,
            "refreshTokenStrategy":"ROTATE",
            "tokenDefaults":defaults,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PermissionInput {
    resource_key: String,
    scopes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientInput {
    #[serde(default)]
    auto_authorize: bool,
    access_token_ttl_seconds: Option<i64>,
    refresh_token_ttl_seconds: Option<i64>,
    client_token_ttl_seconds: Option<i64>,

    expected_version: Option<i64>,
    application_id: String,
    environment: String,
    display_name: String,
    client_type: String,
    runtime_kind: String,
    subject_mode: String,
    context_mode: String,
    allowed_member_types: Vec<String>,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    #[serde(default = "short_logout_mode")]
    logout_mode: String,
    backchannel_logout_uri: Option<String>,
    backchannel_target_id: Option<String>,
    status: String,
    consent_group_id: Option<String>,
    permissions: Vec<PermissionInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialCommand {
    expected_version: i64,
}

fn short_logout_mode() -> String {
    "SHORT_SESSION_ONLINE_CHECK".into()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsentGroupInput {
    application_id: String,
    environment: String,
    display_name: String,
    purpose: String,
    context_mode: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsentGroupMemberInput {
    client_id: String,
    expected_group_version: i64,
}

#[derive(sqlx::FromRow)]
struct ApplicationPolicy {
    status: String,
    ownership: String,
    purpose: String,
    approved_scopes: Vec<String>,
}

#[derive(sqlx::FromRow)]
struct ClientVersion {
    application_id: Uuid,
    environment: String,
    version: i64,
    policy_version: i64,
    client_type: String,
    runtime_kind: String,
    subject_mode: String,
    context_mode: Option<String>,
    allowed_member_types: Vec<String>,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
    status: String,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(CLIENTS_PATH, get(list).post(create))
        .route(CONSENT_GROUPS_PATH, post(create_consent_group))
        .route(
            "/internal/identity/auth/applications/{application}/consent-groups",
            get(list_consent_groups),
        )
        .route(
            "/internal/identity/auth/consent-groups/{group}/clients",
            post(add_consent_group_client),
        )
        .route(
            "/internal/identity/auth/clients/{id}",
            get(get_client).patch(update),
        )
        .route(
            "/internal/identity/auth/clients/{id}/credentials",
            axum::routing::post(rotate_credential),
        )
        .route(
            "/internal/identity/auth/clients/{id}/credentials/revoke",
            axum::routing::post(revoke_credentials),
        )
}

fn parse_id(raw: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(raw).map_err(|_| AppError::bad_request("统一客户端标识无效"))?;
    if !crate::util::uuid7::is_uuid_v7(id) || id.to_string() != raw {
        return Err(AppError::bad_request("统一客户端标识无效"));
    }
    Ok(id)
}

async fn authorized(state: &AppState, headers: &HeaderMap) -> Result<ServicePrincipal, AppError> {
    let service = internal::authenticate(state, headers, AUTH_ADMIN).await?;
    service.require(AUTH_ADMIN)?;
    Ok(service)
}

fn validate_list(query: &ListQuery) -> Result<(Option<Uuid>, Option<Uuid>, i64, i64), AppError> {
    let application = query.application_id.as_deref().map(parse_id).transpose()?;
    let partner = query.partner_id.as_deref().map(parse_id).transpose()?;
    if query
        .ownership
        .as_deref()
        .is_some_and(|v| !matches!(v, "FIRST_PARTY" | "THIRD_PARTY"))
        || query
            .environment
            .as_deref()
            .is_some_and(|v| !valid_environment(v))
        || query
            .client_type
            .as_deref()
            .is_some_and(|v| !matches!(v, "PUBLIC" | "CONFIDENTIAL"))
        || query
            .subject_mode
            .as_deref()
            .is_some_and(|v| !matches!(v, "USER" | "MACHINE"))
        || query
            .status
            .as_deref()
            .is_some_and(|v| !matches!(v, "ENABLED" | "DISABLED" | "RETIRED"))
    {
        return Err(AppError::bad_request("统一客户端筛选条件无效"));
    }
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) || !(0..=MAX_OFFSET).contains(&offset) {
        return Err(AppError::bad_request("统一客户端分页参数超出范围"));
    }
    Ok((application, partner, limit, offset))
}

fn valid_environment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AppError> {
    authorized(&state, &headers).await?;
    let mut query = query;
    if let Some(environment) = query.environment.as_mut() {
        *environment = environment.to_ascii_lowercase();
    }
    let (application, partner, limit, offset) = validate_list(&query)?;
    let filters = " WHERE ($1::uuid IS NULL OR c.application_id=$1) AND ($2::uuid IS NULL OR a.partner_id=$2) \
        AND ($3::text IS NULL OR a.ownership=$3) AND ($4::text IS NULL OR c.environment=$4) \
        AND ($5::text IS NULL OR c.client_type=$5) AND ($6::text IS NULL OR c.subject_mode=$6) \
        AND ($7::text IS NULL OR c.status=$7)";
    let count_sql = format!(
        "SELECT count(*) FROM public.auth_clients c JOIN public.auth_applications a ON a.application_id=c.application_id{filters}"
    );
    let total: i64 = sqlx::query_scalar(&count_sql)
        .bind(application)
        .bind(partner)
        .bind(&query.ownership)
        .bind(&query.environment)
        .bind(&query.client_type)
        .bind(&query.subject_mode)
        .bind(&query.status)
        .fetch_one(&state.pool)
        .await?;
    let list_sql =
        format!("{CLIENT_SELECT}{filters} ORDER BY c.created_at DESC,c.id DESC LIMIT $8 OFFSET $9");
    let rows: Vec<ClientRow> = sqlx::query_as(&list_sql)
        .bind(application)
        .bind(partner)
        .bind(&query.ownership)
        .bind(&query.environment)
        .bind(&query.client_type)
        .bind(&query.subject_mode)
        .bind(&query.status)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(json!({
        "records":rows.iter().map(|row| row.json(&state.config.token_defaults)).collect::<Vec<_>>(),
        "page":{"limit":limit,"offset":offset,"total":total}
    })))
}

async fn get_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    authorized(&state, &headers).await?;
    let id = parse_id(&raw_id)?;
    let sql = format!("{CLIENT_SELECT} WHERE c.id=$1");
    let row: Option<ClientRow> = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    row.map(|client| Json(client.json(&state.config.token_defaults)))
        .ok_or_else(|| AppError::not_found("统一客户端不存在"))
}

fn validate_uris(values: &mut [String], allow_empty: bool) -> Result<(), AppError> {
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1])
        || (!allow_empty && values.is_empty())
        || values.len() > 16
    {
        return Err(AppError::bad_request("客户端回调地址数量或重复项无效"));
    }
    for raw in values.iter() {
        let uri = reqwest::Url::parse(raw)
            .map_err(|_| AppError::bad_request("回调地址必须是精确 HTTPS URL"))?;
        if raw.len() > 2048
            || uri.scheme() != "https"
            || uri.host_str().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.fragment().is_some()
            || uri.as_str() != raw
            || raw.contains('*')
            || uri
                .query_pairs()
                .any(|(key, _)| matches!(key.as_ref(), "code" | "state" | "error" | "iss"))
        {
            return Err(AppError::bad_request(
                "回调地址必须是规范且精确的 HTTPS URL",
            ));
        }
    }
    Ok(())
}

fn validate_input(input: &mut ClientInput, create: bool) -> Result<Uuid, AppError> {
    if !crate::client_policy::valid_optional_ttl(input.access_token_ttl_seconds, false)
        || !crate::client_policy::valid_optional_ttl(input.refresh_token_ttl_seconds, true)
        || !crate::client_policy::valid_optional_ttl(input.client_token_ttl_seconds, false)
        || (input.subject_mode == "MACHINE"
            && (input.auto_authorize
                || input.access_token_ttl_seconds.is_some()
                || input.refresh_token_ttl_seconds.is_some()))
        || (input.subject_mode == "USER" && input.client_token_ttl_seconds.is_some())
        || (input.refresh_token_ttl_seconds.is_some()
            && !input
                .grant_types
                .iter()
                .any(|grant| grant == "refresh_token"))
    {
        return Err(AppError::bad_request("客户端授权策略或令牌有效期无效"));
    }

    let application_id = parse_id(&input.application_id)?;
    input.environment = input.environment.to_ascii_lowercase();
    input.display_name = input.display_name.trim().to_owned();
    input.allowed_member_types.sort();
    input.grant_types.sort();
    input.redirect_uris.sort();
    input.post_logout_redirect_uris.sort();
    if input.display_name.is_empty()
        || input.display_name.chars().count() > 120
        || input.display_name.chars().any(char::is_control)
        || !valid_environment(&input.environment)
        || !matches!(input.client_type.as_str(), "PUBLIC" | "CONFIDENTIAL")
        || !matches!(input.subject_mode.as_str(), "USER" | "MACHINE")
        || (create && !matches!(input.status.as_str(), "ENABLED" | "DISABLED"))
        || (!create && !matches!(input.status.as_str(), "ENABLED" | "DISABLED" | "RETIRED"))
        || (create && input.expected_version.is_some())
        || (!create && input.expected_version.is_none_or(|v| v < 1))
    {
        return Err(AppError::bad_request("统一客户端字段无效"));
    }
    if input
        .allowed_member_types
        .windows(2)
        .any(|pair| pair[0] == pair[1])
        || input.grant_types.windows(2).any(|pair| pair[0] == pair[1])
        || !input
            .allowed_member_types
            .iter()
            .all(|v| matches!(v.as_str(), "EMPLOYEE" | "CUSTOMER"))
        || input.grant_types.is_empty()
    {
        return Err(AppError::bad_request("统一客户端集合字段无效"));
    }
    match input.subject_mode.as_str() {
        "MACHINE" => {
            if input.runtime_kind != "SERVICE"
                || input.client_type != "CONFIDENTIAL"
                || input.context_mode != "NONE"
                || !input.allowed_member_types.is_empty()
                || input.grant_types != ["client_credentials"]
                || input.token_endpoint_auth_method != "client_secret_basic"
                || !input.redirect_uris.is_empty()
                || !input.post_logout_redirect_uris.is_empty()
            {
                return Err(AppError::bad_request("机器客户端组合不受支持"));
            }
        }
        "USER" => {
            let runtime_type_matches = matches!(
                (input.runtime_kind.as_str(), input.client_type.as_str()),
                ("WEB_BFF", "CONFIDENTIAL") | ("SPA", "PUBLIC") | ("NATIVE", "PUBLIC")
            );
            let context_valid = match input.context_mode.as_str() {
                "ACCOUNT_ONLY" => input.allowed_member_types.is_empty(),
                "PLATFORM_CONTEXT" => input.allowed_member_types.len() == 1,
                _ => false,
            };
            let grant_valid = input.grant_types.contains(&"authorization_code".to_owned())
                && input
                    .grant_types
                    .iter()
                    .all(|v| matches!(v.as_str(), "authorization_code" | "refresh_token"));
            if !runtime_type_matches
                || !context_valid
                || (input.context_mode == "PLATFORM_CONTEXT"
                    && (input.client_type != "CONFIDENTIAL" || input.runtime_kind != "WEB_BFF"))
                || !grant_valid
                || (input.client_type == "PUBLIC" && input.token_endpoint_auth_method != "none")
                || (input.client_type == "CONFIDENTIAL"
                    && input.token_endpoint_auth_method != "client_secret_basic")
            {
                return Err(AppError::bad_request("人员客户端组合不受支持"));
            }
        }
        _ => return Err(AppError::bad_request("统一客户端主体模式无效")),
    }
    validate_uris(&mut input.redirect_uris, input.subject_mode == "MACHINE")?;
    validate_uris(&mut input.post_logout_redirect_uris, true)?;
    match input.logout_mode.as_str() {
        "SHORT_SESSION_ONLINE_CHECK"
            if input.backchannel_logout_uri.is_none() && input.backchannel_target_id.is_none() => {}
        "BACK_CHANNEL" if input.subject_mode == "USER" && input.client_type == "CONFIDENTIAL" => {
            if create {
                return Err(AppError::bad_request("先以短会话合同创建客户端，再由owner核验该客户端的投递目标后编辑启用back-channel"));
            }
            let uri = input
                .backchannel_logout_uri
                .as_ref()
                .ok_or_else(|| AppError::bad_request("back-channel需要已审核的精确HTTPS地址"))?;
            validate_uris(&mut [uri.clone()], false)?;
            if reqwest::Url::parse(uri)
                .map_err(|_| AppError::bad_request("back-channel地址无效"))?
                .query()
                .is_some()
            {
                return Err(AppError::bad_request("back-channel地址不能包含查询参数"));
            }
            let reference = input
                .backchannel_target_id
                .as_deref()
                .ok_or_else(|| AppError::bad_request("back-channel需要owner核验目标引用"))?;
            parse_id(reference)?;
        }
        _ => {
            return Err(AppError::bad_request(
                "登出方式、back-channel地址与核验目标组合无效",
            ))
        }
    }
    if input.permissions.is_empty() {
        return Err(AppError::bad_request("客户端至少需要一个获准资源权限"));
    }
    let mut resources = HashSet::new();
    for permission in &mut input.permissions {
        if permission.resource_key.is_empty()
            || permission.resource_key.len() > 64
            || !permission.resource_key.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
            })
            || permission.scopes.is_empty()
            || permission.scopes.len() > 64
        {
            return Err(AppError::bad_request("客户端资源权限无效"));
        }
        permission.scopes.sort();
        if permission.scopes.windows(2).any(|pair| pair[0] == pair[1])
            || permission.scopes.iter().any(|scope| {
                scope.is_empty()
                    || scope.len() > 128
                    || !scope.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:-".contains(&b)
                    })
            })
            || !resources.insert(permission.resource_key.clone())
        {
            return Err(AppError::bad_request("客户端 scope 或资源重复"));
        }
    }
    let group_id = input
        .consent_group_id
        .as_deref()
        .map(parse_id)
        .transpose()?;
    if let Some(group) = group_id {
        input.consent_group_id = Some(group.to_string());
    }
    Ok(application_id)
}

async fn application_policy(
    tx: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    require_approved: bool,
) -> Result<ApplicationPolicy, AppError> {
    let policy: Option<ApplicationPolicy> = sqlx::query_as(
        "SELECT status,ownership,purpose,approved_scopes FROM public.auth_applications WHERE application_id=$1 FOR SHARE",
    )
    .bind(application_id)
    .fetch_optional(&mut **tx)
    .await?;
    let policy = policy.ok_or_else(|| AppError::not_found("认证应用不存在"))?;
    if require_approved && policy.status != "APPROVED" {
        return Err(AppError::forbidden("认证应用尚未批准或已停用"));
    }
    Ok(policy)
}

async fn check_reviewed_admission(
    tx: &mut Transaction<'_, Postgres>,
    input: &ClientInput,
    application_id: Uuid,
    application: &ApplicationPolicy,
) -> Result<(), AppError> {
    if input.auto_authorize && application.ownership != "FIRST_PARTY" {
        return Err(AppError::forbidden("自动授权仅适用于自有登录客户端"));
    }
    if application.ownership != "THIRD_PARTY" {
        return Ok(());
    }
    let admission = crate::auth_review::admission(&mut **tx, application_id, &input.environment)
        .await?
        .ok_or_else(|| AppError::forbidden("第三方应用缺少当前环境的独立审核清单"))?;
    if admission.status != "APPROVED"
        || (input.logout_mode == "BACK_CHANNEL"
            && (admission.logout_mode != "BACK_CHANNEL"
                || input.backchannel_logout_uri != admission.backchannel_logout_uri))
        || input.subject_mode != "USER"
        || input.context_mode != "ACCOUNT_ONLY"
        || !input.allowed_member_types.is_empty()
        || input
            .redirect_uris
            .iter()
            .any(|uri| !admission.redirect_uris.contains(uri))
        || input
            .post_logout_redirect_uris
            .iter()
            .any(|uri| !admission.post_logout_redirect_uris.contains(uri))
        || input.permissions.iter().any(|permission| {
            permission.resource_key != "userinfo"
                || permission.scopes.iter().any(|scope| {
                    !matches!(scope.as_str(), "openid" | "profile")
                        || !admission.scopes.contains(scope)
                })
        })
    {
        return Err(AppError::forbidden(
            "第三方客户端超出已批准的账号范围、环境或精确回调清单",
        ));
    }
    Ok(())
}

async fn check_logout_target(
    tx: &mut Transaction<'_, Postgres>,
    client: Uuid,
    input: &ClientInput,
) -> Result<(), AppError> {
    if input.logout_mode != "BACK_CHANNEL" {
        return Ok(());
    }
    let target = input
        .backchannel_target_id
        .as_deref()
        .map(parse_id)
        .transpose()?
        .ok_or_else(|| AppError::forbidden("缺少owner核验的投递目标"))?;
    let fact:Option<i64> = sqlx::query_scalar("SELECT version FROM public.auth_delivery_targets WHERE id=$1 AND client_id=$2 AND purpose='BACK_CHANNEL' AND status='ACTIVE' AND url=$3 AND version>=1 AND verified_at<=clock_timestamp() AND expires_at>clock_timestamp()")
        .bind(target).bind(client).bind(&input.backchannel_logout_uri).fetch_optional(&mut **tx).await?;
    let active = if let Some(version) = fact {
        sqlx::query_scalar(
            "SELECT public.identity_delivery_target_active($1,$2,'BACK_CHANNEL',$3,NULL,NULL)",
        )
        .bind(target)
        .bind(version)
        .bind(client)
        .fetch_one(&mut **tx)
        .await?
    } else {
        false
    };
    if !active {
        return Err(AppError::forbidden(
            "back-channel目标、客户端、地址或当前核验版本不匹配；任意UUID不构成核验",
        ));
    }
    Ok(())
}

async fn check_scopes(
    tx: &mut Transaction<'_, Postgres>,
    input: &ClientInput,
    application: &ApplicationPolicy,
) -> Result<Vec<(Uuid, Uuid)>, AppError> {
    let mut result = Vec::new();
    for permission in &input.permissions {
        if input.subject_mode == "MACHINE"
            && (permission.resource_key == "userinfo"
                || permission
                    .scopes
                    .iter()
                    .any(|scope| matches!(scope.as_str(), "openid" | "profile" | "offline_access")))
        {
            return Err(AppError::forbidden(
                "机器客户端不能申请人员资料或离线用户范围",
            ));
        }
        if permission
            .scopes
            .iter()
            .any(|scope| !application.approved_scopes.contains(scope))
        {
            return Err(AppError::forbidden("客户端 scope 超出应用已批准范围"));
        }
        let rows: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
            "SELECT s.id,s.resource_id,s.scope_name,r.status FROM public.auth_scopes s \
             JOIN public.auth_resources r ON r.id=s.resource_id \
             WHERE r.resource_key=$1 AND s.scope_name=ANY($2) AND s.status='ACTIVE'",
        )
        .bind(&permission.resource_key)
        .bind(&permission.scopes)
        .fetch_all(&mut **tx)
        .await?;
        if rows.len() != permission.scopes.len()
            || rows.iter().any(|row| row.3 != "ACTIVE")
            || rows
                .iter()
                .map(|row| row.2.as_str())
                .collect::<HashSet<_>>()
                .len()
                != permission.scopes.len()
        {
            return Err(AppError::bad_request("资源或 scope 未登记、停用或不匹配"));
        }
        result.extend(rows.into_iter().map(|row| (row.0, row.1)));
    }
    if input.subject_mode == "USER"
        && !input
            .permissions
            .iter()
            .any(|permission| permission.scopes.iter().any(|scope| scope == "openid"))
    {
        return Err(AppError::bad_request(
            "人员 OIDC 客户端必须获准 openid scope",
        ));
    }
    Ok(result)
}

async fn check_consent_group(
    tx: &mut Transaction<'_, Postgres>,
    input: &ClientInput,
    application: Uuid,
    application_policy: &ApplicationPolicy,
) -> Result<Option<Uuid>, AppError> {
    let group = input
        .consent_group_id
        .as_deref()
        .map(parse_id)
        .transpose()?;
    if let Some(group_id) = group {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM public.auth_consent_groups WHERE id=$1 \
             AND application_id=$2 AND environment=$3 AND purpose=$4 \
             AND context_mode=$5 AND subject_mode='USER' AND status='ACTIVE')",
        )
        .bind(group_id)
        .bind(application)
        .bind(&input.environment)
        .bind(&application_policy.purpose)
        .bind(&input.context_mode)
        .fetch_one(&mut **tx)
        .await?;
        if !active || input.subject_mode != "USER" {
            return Err(AppError::bad_request("同意组与应用、环境或主体不匹配"));
        }
    }
    Ok(group)
}

async fn insert_permissions(
    tx: &mut Transaction<'_, Postgres>,
    client_id: Uuid,
    permission_ids: &[(Uuid, Uuid)],
) -> Result<(), AppError> {
    for (scope_id, resource_id) in permission_ids {
        sqlx::query(
            "INSERT INTO public.auth_client_permissions(client_id,resource_id,scope_id,version) \
             VALUES($1,$2,$3,1)",
        )
        .bind(client_id)
        .bind(resource_id)
        .bind(scope_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn attach_group(
    tx: &mut Transaction<'_, Postgres>,
    group_id: Option<Uuid>,
    client_id: Uuid,
    application_id: Uuid,
    environment: &str,
    context_mode: &str,
) -> Result<(), AppError> {
    if let Some(group_id) = group_id {
        let active: Option<i64> = sqlx::query_scalar(
            "SELECT version FROM public.auth_consent_groups WHERE id=$1 AND application_id=$2 \
             AND environment=$3 AND subject_mode='USER' AND context_mode=$4 AND status='ACTIVE' FOR UPDATE",
        )
        .bind(group_id)
        .bind(application_id)
        .bind(environment)
        .bind(context_mode)
        .fetch_optional(&mut **tx)
        .await?;
        if active.is_none() {
            return Err(AppError::conflict("同意组在客户端登记期间发生变化"));
        }
        sqlx::query(
            "INSERT INTO public.auth_consent_group_clients(group_id,client_id,application_id,environment,subject_mode,context_mode) \
             VALUES($1,$2,$3,$4,'USER',$5)",
        )
        .bind(group_id)
        .bind(client_id)
        .bind(application_id)
        .bind(environment)
        .bind(context_mode)
        .execute(&mut **tx)
        .await?;
        let changed = sqlx::query(
            "UPDATE public.auth_consent_groups SET version=version+1 WHERE id=$1 AND version<9223372036854775807",
        )
        .bind(group_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::Unavailable);
        }
    }
    Ok(())
}

fn normalize_environment(value: &str) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 32
        || !normalized.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        })
    {
        return Err(AppError::bad_request("同意组环境无效"));
    }
    Ok(normalized)
}

async fn create_consent_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(raw): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = authorized(&state, &headers).await?;
    let mut operation = crate::admin_operations::begin(
        &state,
        &service,
        &headers,
        "POST",
        CONSENT_GROUPS_PATH,
        &raw,
    )
    .await?;
    if let Some(replayed) = operation.replay()? {
        return Ok(Json(replayed));
    }
    let mut input: ConsentGroupInput =
        serde_json::from_value(raw).map_err(|_| AppError::bad_request("同意组登记无效"))?;
    let application_id = parse_id(&input.application_id)?;
    input.environment = normalize_environment(&input.environment)?;
    input.display_name = input.display_name.trim().to_owned();
    if input.display_name.is_empty()
        || input.display_name.len() > 120
        || input.purpose.is_empty()
        || input.purpose.len() > 2000
        || !matches!(
            input.context_mode.as_str(),
            "ACCOUNT_ONLY" | "PLATFORM_CONTEXT"
        )
    {
        return Err(AppError::bad_request("同意组用途、名称或上下文无效"));
    }
    let policy = application_policy(&mut operation.tx, application_id, true).await?;
    if input.purpose != policy.purpose {
        return Err(AppError::bad_request("同意组用途必须与已批准应用用途一致"));
    }
    let id = operation.operation_id;
    sqlx::query(
        "INSERT INTO public.auth_consent_groups(id,application_id,environment,display_name,purpose,subject_mode,context_mode,status,version) \
         VALUES($1,$2,$3,$4,$5,'USER',$6,'ACTIVE',1)",
    )
    .bind(id)
    .bind(application_id)
    .bind(&input.environment)
    .bind(&input.display_name)
    .bind(&input.purpose)
    .bind(&input.context_mode)
    .execute(&mut *operation.tx)
    .await?;
    audit::write_in_tx(
        &mut operation.tx,
        AuditInfo {
            user_id: None,
            username: &service.id.to_string(),
            action: "AUTH_CONSENT_GROUP_CREATE",
            detail: &json!({"operationId":id,"groupId":id,"applicationId":application_id,"environment":input.environment,"contextMode":input.context_mode}).to_string(),
            ip: &audit::client_ip(&headers),
            user_agent: &audit::ua_of(&headers),
        },
    )
    .await?;
    let result = json!({
        "id":id,
        "applicationId":application_id,
        "applicationName":policy_name(&mut operation.tx, application_id).await?,
        "environment":input.environment,
        "displayName":input.display_name,
        "purpose":input.purpose,
        "subjectMode":"USER",
        "contextMode":input.context_mode,
        "status":"ACTIVE",
        "version":1
    });
    Ok(Json(operation.commit(result).await?))
}

async fn policy_name(
    tx: &mut Transaction<'_, Postgres>,
    application: Uuid,
) -> Result<String, AppError> {
    sqlx::query_scalar("SELECT display_name FROM public.auth_applications WHERE application_id=$1")
        .bind(application)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::from)
}

async fn list_consent_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_application): Path<String>,
) -> Result<Json<Value>, AppError> {
    let _service = authorized(&state, &headers).await?;
    let application = parse_id(&raw_application)?;
    let groups: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',g.id,'applicationId',g.application_id,'applicationName',a.display_name, \
         'environment',g.environment,'displayName',g.display_name,'purpose',g.purpose,'subjectMode',g.subject_mode, \
         'contextMode',g.context_mode,'status',g.status,'version',g.version,'clients', \
         COALESCE((SELECT jsonb_agg(jsonb_build_object('id',c.id,'displayName',c.display_name) ORDER BY c.display_name,c.id) \
           FROM public.auth_consent_group_clients m JOIN public.auth_clients c ON c.id=m.client_id WHERE m.group_id=g.id),'[]'::jsonb)) \
         FROM public.auth_consent_groups g JOIN public.auth_applications a ON a.application_id=g.application_id \
         WHERE g.application_id=$1 ORDER BY g.environment,g.context_mode,g.display_name,g.id",
    )
    .bind(application)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({"groups":groups})))
}

async fn add_consent_group_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_group): Path<String>,
    ApiJson(raw): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = authorized(&state, &headers).await?;
    let group_id = parse_id(&raw_group)?;
    let path = format!("{CONSENT_GROUPS_PATH}/{group_id}/clients");
    let mut operation =
        crate::admin_operations::begin(&state, &service, &headers, "POST", &path, &raw).await?;
    if let Some(replayed) = operation.replay()? {
        return Ok(Json(replayed));
    }
    let input: ConsentGroupMemberInput =
        serde_json::from_value(raw).map_err(|_| AppError::bad_request("同意组成员登记无效"))?;
    if input.expected_group_version < 1 {
        return Err(AppError::bad_request("同意组版本无效"));
    }
    let client_id = parse_id(&input.client_id)?;
    let application_id: Option<Uuid> =
        sqlx::query_scalar("SELECT application_id FROM public.auth_consent_groups WHERE id=$1")
            .bind(group_id)
            .fetch_optional(&mut *operation.tx)
            .await?;
    let application_id = application_id.ok_or_else(|| AppError::not_found("同意组不存在"))?;
    let policy = application_policy(&mut operation.tx, application_id, true).await?;
    let client: Option<(Uuid, String, String, String, String)> = sqlx::query_as(
        "SELECT application_id,environment,subject_mode,COALESCE(context_mode,''),status \
         FROM public.auth_clients WHERE id=$1 FOR UPDATE",
    )
    .bind(client_id)
    .fetch_optional(&mut *operation.tx)
    .await?;
    let (client_application, environment, subject_mode, context_mode, client_status) =
        client.ok_or_else(|| AppError::not_found("统一客户端不存在"))?;
    let group: Option<(Uuid, String, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT application_id,environment,purpose,subject_mode,context_mode,status,version \
         FROM public.auth_consent_groups WHERE id=$1 FOR UPDATE",
    )
    .bind(group_id)
    .fetch_optional(&mut *operation.tx)
    .await?;
    let (
        group_application,
        group_environment,
        purpose,
        group_subject,
        group_context,
        status,
        version,
    ) = group.ok_or_else(|| AppError::not_found("同意组不存在"))?;
    if version != input.expected_group_version {
        return Err(AppError::conflict("同意组版本已变化"));
    }
    if group_application != application_id
        || client_application != application_id
        || group_environment != environment
        || group_subject != "USER"
        || subject_mode != "USER"
        || group_context != context_mode
        || purpose != policy.purpose
        || status != "ACTIVE"
        || client_status == "RETIRED"
    {
        return Err(AppError::bad_request(
            "客户端与同意组的应用、环境、用途或主体不匹配",
        ));
    }
    let next_version = version.checked_add(1).ok_or(AppError::Unavailable)?;
    sqlx::query(
        "INSERT INTO public.auth_consent_group_clients(group_id,client_id,application_id,environment,subject_mode,context_mode) \
         VALUES($1,$2,$3,$4,'USER',$5)",
    )
    .bind(group_id)
    .bind(client_id)
    .bind(application_id)
    .bind(&environment)
    .bind(&context_mode)
    .execute(&mut *operation.tx)
    .await
    .map_err(|error| match error {
        sqlx::Error::Database(ref database) if database.is_unique_violation() => {
            AppError::conflict("客户端已加入其他同意组")
        }
        other => AppError::from(other),
    })?;
    sqlx::query("UPDATE public.auth_consent_groups SET version=$2 WHERE id=$1")
        .bind(group_id)
        .bind(next_version)
        .execute(&mut *operation.tx)
        .await?;
    audit::write_in_tx(
        &mut operation.tx,
        AuditInfo {
            user_id: None,
            username: &service.id.to_string(),
            action: "AUTH_CONSENT_GROUP_CLIENT_ADD",
            detail: &json!({"operationId":operation.operation_id,"groupId":group_id,"clientId":client_id,"version":next_version}).to_string(),
            ip: &audit::client_ip(&headers),
            user_agent: &audit::ua_of(&headers),
        },
    )
    .await?;
    Ok(Json(
        operation
            .commit(json!({"groupId":group_id,"clientId":client_id,"version":next_version}))
            .await?,
    ))
}

#[cfg(test)]
#[path = "auth_admin_logout_tests.rs"]
mod logout_registration_tests;

#[cfg(test)]
#[path = "auth_admin_default_group_tests.rs"]
mod default_group_tests;

async fn private_consent_group(
    tx: &mut Transaction<'_, Postgres>,
    input: &ClientInput,
    application: Uuid,
    purpose: &str,
    existing: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    if existing.is_some() || input.subject_mode != "USER" {
        return Ok(existing);
    }
    // Each new login client owns an isolated consent record. Group management
    // is not a prerequisite for registering a functioning login client.
    let group = crate::util::uuid7::new_uuid();
    sqlx::query(
        "INSERT INTO public.auth_consent_groups(id,application_id,environment,display_name,purpose,subject_mode,context_mode,status) \
         VALUES($1,$2,$3,$4,$5,'USER',$6,'ACTIVE')",
    )
    .bind(group)
    .bind(application)
    .bind(&input.environment)
    .bind(&input.display_name)
    .bind(purpose)
    .bind(&input.context_mode)
    .execute(&mut **tx)
    .await?;
    Ok(Some(group))
}

async fn write_client_policy(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    input: &ClientInput,
) -> Result<(), AppError> {
    sqlx::query("UPDATE public.auth_clients SET auto_authorize=$2,access_token_ttl_seconds=$3,refresh_token_ttl_seconds=$4,client_token_ttl_seconds=$5 WHERE id=$1")
        .bind(id).bind(input.auto_authorize).bind(input.access_token_ttl_seconds)
        .bind(input.refresh_token_ttl_seconds).bind(input.client_token_ttl_seconds).execute(&mut **tx).await?;
    Ok(())
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(raw): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = authorized(&state, &headers).await?;
    let mut operation =
        crate::admin_operations::begin(&state, &service, &headers, "POST", CLIENTS_PATH, &raw)
            .await?;
    if let Some(replayed) = operation.replay()? {
        return Ok(Json(replayed));
    }
    let mut input: ClientInput =
        serde_json::from_value(raw).map_err(|_| AppError::bad_request("统一客户端登记无效"))?;
    let application_id = validate_input(&mut input, true)?;
    let policy = application_policy(&mut operation.tx, application_id, true).await?;
    check_reviewed_admission(&mut operation.tx, &input, application_id, &policy).await?;
    let permission_ids = check_scopes(&mut operation.tx, &input, &policy).await?;
    let group_id = check_consent_group(&mut operation.tx, &input, application_id, &policy).await?;
    let group_id = private_consent_group(
        &mut operation.tx,
        &input,
        application_id,
        &policy.purpose,
        group_id,
    )
    .await?;
    let id = operation.operation_id;
    let client_id = id.to_string();
    sqlx::query(
        "INSERT INTO public.auth_clients(id,client_id,display_name,application_id,environment,client_type, \
         runtime_kind,subject_mode,context_mode,allowed_member_types,grant_types,token_endpoint_auth_method, \
         redirect_uris,post_logout_redirect_uris,status,version,policy_version,created_at,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(id)
    .bind(&client_id)
    .bind(&input.display_name)
    .bind(application_id)
    .bind(&input.environment)
    .bind(&input.client_type)
    .bind(&input.runtime_kind)
    .bind(&input.subject_mode)
    .bind(&input.context_mode)
    .bind(&input.allowed_member_types)
    .bind(&input.grant_types)
    .bind(&input.token_endpoint_auth_method)
    .bind(&input.redirect_uris)
    .bind(&input.post_logout_redirect_uris)
    .bind(&input.status)
    .execute(&mut *operation.tx)
    .await?;
    write_client_policy(&mut operation.tx, id, &input).await?;
    insert_permissions(&mut operation.tx, id, &permission_ids).await?;
    attach_group(
        &mut operation.tx,
        group_id,
        id,
        application_id,
        &input.environment,
        &input.context_mode,
    )
    .await?;
    audit::write_in_tx(
        &mut operation.tx,
        AuditInfo {
            user_id: None,
            username: &service.id.to_string(),
            action: "AUTH_CLIENT_CREATE",
            detail: &json!({"operationId":id,"clientId":id,"applicationId":application_id,"owner":policy.ownership,"purpose":policy.purpose}).to_string(),
            ip: &audit::client_ip(&headers),
            user_agent: &audit::ua_of(&headers),
        },
    )
    .await?;
    let sql = format!("{CLIENT_SELECT} WHERE c.id=$1");
    let row: ClientRow = sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&mut *operation.tx)
        .await?;
    Ok(Json(
        operation
            .commit(row.json(&state.config.token_defaults))
            .await?,
    ))
}

async fn load_locked(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<ClientVersion, AppError> {
    sqlx::query_as(
        "SELECT application_id,environment,version,policy_version,client_type,runtime_kind,subject_mode,context_mode, \
         allowed_member_types,grant_types,token_endpoint_auth_method,status \
         FROM public.auth_clients WHERE id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| AppError::not_found("统一客户端不存在"))
}

async fn is_stop_only(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    input: &ClientInput,
) -> Result<bool, AppError> {
    if !matches!(input.status.as_str(), "DISABLED" | "RETIRED") {
        return Ok(false);
    }
    let registration: (String, Vec<String>, Vec<String>,String,Option<String>,Option<Uuid>) = sqlx::query_as(
        "SELECT display_name,redirect_uris,post_logout_redirect_uris,logout_mode,backchannel_logout_uri,backchannel_target_id FROM public.auth_clients WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await?;
    if registration.0 != input.display_name
        || registration.1 != input.redirect_uris
        || registration.2 != input.post_logout_redirect_uris
        || registration.3 != input.logout_mode
        || registration.4 != input.backchannel_logout_uri
        || registration.5
            != input
                .backchannel_target_id
                .as_deref()
                .map(parse_id)
                .transpose()?
    {
        return Ok(false);
    }
    let policy: (bool, Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT auto_authorize,access_token_ttl_seconds,refresh_token_ttl_seconds,client_token_ttl_seconds FROM auth_clients WHERE id=$1")
        .bind(id).fetch_one(&mut **tx).await?;
    if policy
        != (
            input.auto_authorize,
            input.access_token_ttl_seconds,
            input.refresh_token_ttl_seconds,
            input.client_token_ttl_seconds,
        )
    {
        return Ok(false);
    }
    let current: Vec<(String, String)> = sqlx::query_as(
        "SELECT r.resource_key,s.scope_name FROM public.auth_client_permissions p \
         JOIN public.auth_resources r ON r.id=p.resource_id \
         JOIN public.auth_scopes s ON s.id=p.scope_id AND s.resource_id=p.resource_id \
         WHERE p.client_id=$1",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    let requested: HashSet<(String, String)> = input
        .permissions
        .iter()
        .flat_map(|permission| {
            permission
                .scopes
                .iter()
                .map(|scope| (permission.resource_key.clone(), scope.clone()))
        })
        .collect();
    Ok(requested == current.into_iter().collect())
}

async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    ApiJson(raw): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = authorized(&state, &headers).await?;
    let id = parse_id(&raw_id)?;
    let path = format!("{CLIENTS_PATH}/{id}");
    let mut operation =
        crate::admin_operations::begin(&state, &service, &headers, "PATCH", &path, &raw).await?;
    if let Some(replayed) = operation.replay()? {
        return Ok(Json(replayed));
    }
    let mut input: ClientInput =
        serde_json::from_value(raw).map_err(|_| AppError::bad_request("统一客户端更新无效"))?;
    let application_id = validate_input(&mut input, false)?;
    let policy = application_policy(&mut operation.tx, application_id, false).await?;
    let mut tx = operation.tx;
    let existing = load_locked(&mut tx, id).await?;
    if input.expected_version != Some(existing.version) {
        return Err(AppError::conflict("统一客户端版本已变化"));
    }
    if existing.status == "RETIRED" {
        return Err(AppError::conflict("客户端归属不可变或已退役"));
    }
    if application_id != existing.application_id
        || input.environment != existing.environment
        || input.client_type != existing.client_type
        || input.runtime_kind != existing.runtime_kind
        || input.subject_mode != existing.subject_mode
        || input.context_mode != existing.context_mode.as_deref().unwrap_or_default()
        || input.allowed_member_types != existing.allowed_member_types
        || input.grant_types != existing.grant_types
        || input.token_endpoint_auth_method != existing.token_endpoint_auth_method
    {
        return Err(AppError::conflict(
            "客户端应用、环境、主体与授权模式不可原地变更",
        ));
    }
    let group_id = input
        .consent_group_id
        .as_deref()
        .map(parse_id)
        .transpose()?;
    let original_group: Option<Uuid> = sqlx::query_scalar(
        "SELECT group_id FROM public.auth_consent_group_clients WHERE client_id=$1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    // Group binding is an internal client attribute after group administration
    // retirement. An omitted value on edit retains the existing association.
    let group_id = group_id.or(original_group);
    input.consent_group_id = group_id.map(|group| group.to_string());
    if original_group != group_id {
        return Err(AppError::conflict("客户端同意组不可原地变更"));
    }
    // Revoked application scopes must not prevent removal of client authority.
    // The exception changes only status; callbacks, metadata and exact resource
    // permissions remain fixed, and enabling always rechecks current approval.
    let permission_ids = if is_stop_only(&mut tx, id, &input).await? {
        None
    } else {
        check_reviewed_admission(&mut tx, &input, application_id, &policy).await?;
        check_logout_target(&mut tx, id, &input).await?;
        let permissions = check_scopes(&mut tx, &input, &policy).await?;
        check_consent_group(&mut tx, &input, application_id, &policy).await?;
        Some(permissions)
    };
    let enabled = input.status == "ENABLED";
    if enabled && policy.status != "APPROVED" {
        return Err(AppError::forbidden("未批准应用的客户端不能启用"));
    }
    let new_version = existing
        .version
        .checked_add(1)
        .ok_or(AppError::Unavailable)?;
    let new_policy_version = existing
        .policy_version
        .checked_add(1)
        .ok_or(AppError::Unavailable)?;
    sqlx::query(
        "UPDATE public.auth_clients SET display_name=$2,redirect_uris=$3,post_logout_redirect_uris=$4, \
         status=$5,version=$6,policy_version=$7,logout_mode=$8,backchannel_logout_uri=$9,backchannel_target_id=$10,updated_at=clock_timestamp() WHERE id=$1",
    )
    .bind(id)
    .bind(&input.display_name)
    .bind(&input.redirect_uris)
    .bind(&input.post_logout_redirect_uris)
    .bind(&input.status)
    .bind(new_version)
    .bind(new_policy_version)
    .bind(&input.logout_mode)
    .bind(&input.backchannel_logout_uri)
    .bind(input.backchannel_target_id.as_deref().map(parse_id).transpose()?)
    .execute(&mut *tx)
    .await?;
    write_client_policy(&mut tx, id, &input).await?;
    let recheck_target = permission_ids.is_some();
    if let Some(permission_ids) = permission_ids {
        sqlx::query("DELETE FROM public.auth_client_permissions WHERE client_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        insert_permissions(&mut tx, id, &permission_ids).await?;
    }
    if recheck_target {
        check_logout_target(&mut tx, id, &input).await?;
    }
    audit::write_in_tx(
        &mut tx,
        AuditInfo {
            user_id: None,
            username: &service.id.to_string(),
            action: "AUTH_CLIENT_UPDATE",
            detail: &json!({"operationId":operation.operation_id,"clientId":id,"version":new_version,"policyVersion":new_policy_version,"status":input.status}).to_string(),
            ip: &audit::client_ip(&headers),
            user_agent: &audit::ua_of(&headers),
        },
    )
    .await?;
    let sql = format!("{CLIENT_SELECT} WHERE c.id=$1");
    let row: ClientRow = sqlx::query_as(&sql).bind(id).fetch_one(&mut *tx).await?;
    operation.tx = tx;
    Ok(Json(
        operation
            .commit(row.json(&state.config.token_defaults))
            .await?,
    ))
}

async fn rotate_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    ApiJson(raw): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = authorized(&state, &headers).await?;
    let id = parse_id(&raw_id)?;
    let path = format!("{CLIENTS_PATH}/{id}/credentials");
    let mut operation =
        crate::admin_operations::begin(&state, &service, &headers, "POST", &path, &raw).await?;
    if let Some(replayed) = operation.replay()? {
        return Ok(Json(replayed));
    }
    let request: CredentialCommand =
        serde_json::from_value(raw).map_err(|_| AppError::bad_request("客户端凭据轮换无效"))?;
    let existing = load_locked(&mut operation.tx, id).await?;
    if existing.version != request.expected_version {
        return Err(AppError::conflict("统一客户端版本已变化"));
    }
    if existing.client_type != "CONFIDENTIAL" || existing.status == "RETIRED" {
        return Err(AppError::bad_request("仅有效机密客户端支持凭据轮换"));
    }
    let secret = operation.auth_client_secret();
    let version: Option<i64> = sqlx::query_scalar(
        "SELECT max(credential_version) FROM public.auth_client_credentials WHERE client_id=$1",
    )
    .bind(id)
    .fetch_one(&mut *operation.tx)
    .await?;
    let credential_version = version
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(AppError::Unavailable)?;
    let previous_expiry: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "UPDATE public.auth_client_credentials SET expires_at=LEAST(created_at+interval '90 days',clock_timestamp()+interval '24 hours') \
         WHERE client_id=$1 AND revoked_at IS NULL AND expires_at IS NULL \
         RETURNING expires_at",
    )
    .bind(id)
    .fetch_optional(&mut *operation.tx)
    .await?;
    let credential_expires_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "INSERT INTO public.auth_client_credentials(id,client_id,client_type,credential_version,secret_digest,created_at) \
         VALUES($1,$2,'CONFIDENTIAL',$3,$4,clock_timestamp()) RETURNING created_at+interval '90 days'",
    )
    .bind(operation.operation_id)
    .bind(id)
    .bind(credential_version)
    .bind(crate::util::hash::sha256_hex(&secret))
    .fetch_optional(&mut *operation.tx)
    .await?
    .ok_or(AppError::Unavailable)?;
    let next_version = existing
        .version
        .checked_add(1)
        .ok_or(AppError::Unavailable)?;
    sqlx::query(
        "UPDATE public.auth_clients SET version=$2,updated_at=clock_timestamp() WHERE id=$1",
    )
    .bind(id)
    .bind(next_version)
    .execute(&mut *operation.tx)
    .await?;
    audit::write_in_tx(
        &mut operation.tx,
        AuditInfo {
            user_id: None,
            username: &service.id.to_string(),
            action: "AUTH_CLIENT_CREDENTIAL_ROTATE",
            detail: &json!({"operationId":operation.operation_id,"clientId":id,"credentialVersion":credential_version,"credentialExpiresAt":credential_expires_at,"previousCredentialExpiresAt":previous_expiry}).to_string(),
            ip: &audit::client_ip(&headers),
            user_agent: &audit::ua_of(&headers),
        },
    )
    .await?;
    let result = json!({
        "clientId":id,
        "credentialId":operation.operation_id,
        "credentialVersion":credential_version,
        "clientVersion":next_version,
        "credentialExpiresAt":credential_expires_at,
        "previousCredentialExpiresAt":previous_expiry,
        "clientSecret":secret
    });
    Ok(Json(operation.commit(result).await?))
}

async fn revoke_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    ApiJson(raw): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = authorized(&state, &headers).await?;
    let id = parse_id(&raw_id)?;
    let path = format!("{CLIENTS_PATH}/{id}/credentials/revoke");
    let mut operation =
        crate::admin_operations::begin(&state, &service, &headers, "POST", &path, &raw).await?;
    if let Some(replayed) = operation.replay()? {
        return Ok(Json(replayed));
    }
    let request: CredentialCommand =
        serde_json::from_value(raw).map_err(|_| AppError::bad_request("客户端凭据撤销无效"))?;
    let existing = load_locked(&mut operation.tx, id).await?;
    if existing.version != request.expected_version {
        return Err(AppError::conflict("统一客户端版本已变化"));
    }
    if existing.client_type != "CONFIDENTIAL" || existing.status == "RETIRED" {
        return Err(AppError::bad_request("仅有效机密客户端支持凭据撤销"));
    }
    let revoked: i64 = sqlx::query(
        "UPDATE public.auth_client_credentials SET revoked_at=clock_timestamp() \
         WHERE client_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())",
    )
    .bind(id)
    .execute(&mut *operation.tx)
    .await?
    .rows_affected() as i64;
    let version = existing
        .version
        .checked_add(1)
        .ok_or(AppError::Unavailable)?;
    let policy_version = existing
        .policy_version
        .checked_add(1)
        .ok_or(AppError::Unavailable)?;
    sqlx::query(
        "UPDATE public.auth_clients SET version=$2,policy_version=$3,updated_at=clock_timestamp() WHERE id=$1",
    )
    .bind(id)
    .bind(version)
    .bind(policy_version)
    .execute(&mut *operation.tx)
    .await?;
    audit::write_in_tx(
        &mut operation.tx,
        AuditInfo {
            user_id: None,
            username: &service.id.to_string(),
            action: "AUTH_CLIENT_CREDENTIAL_REVOKE",
            detail: &json!({"operationId":operation.operation_id,"clientId":id,"revokedCredentials":revoked,"version":version,"policyVersion":policy_version}).to_string(),
            ip: &audit::client_ip(&headers),
            user_agent: &audit::ua_of(&headers),
        },
    )
    .await?;
    Ok(Json(
        operation
            .commit(json!({"clientId":id,"revokedCredentials":revoked,"version":version,"policyVersion":policy_version}))
            .await?,
    ))
}
