//! Reviewed third-party application admissions received through the platform's
//! private command fence. Identity never reads platform review/member tables.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
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
    internal,
    state::AppState,
    util::{audit, uuid7},
};

const PURPOSE: &str = "AUTH_REVIEW";
const PREFIX: &str = "/internal/identity/auth/review/applications";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    display_name: String,
    purpose: String,
    privacy_url: String,
    domains: Vec<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    scopes: Vec<String>,
    contact_reference: String,
    domain_evidence_reference: String,
    logout_mode: String,
    backchannel_logout_uri: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Review {
    application_id: String,
    environment: String,
    request_id: String,
    request_version: i64,
    actor_user_id: String,
    actor_session_id: String,
    expected_projection_version: Option<i64>,
    expected_admission_version: Option<i64>,
    partner_id: String,
    manifest: Manifest,
    requested_by: String,
    reviewed_by: String,
    published_by: Option<String>,
    contact_reference: String,
    domain_reference: String,
    status: String,
}

#[derive(sqlx::FromRow)]
pub(crate) struct Admission {
    pub(crate) status: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) post_logout_redirect_uris: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) logout_mode: String,
    pub(crate) backchannel_logout_uri: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ExistingApplication {
    ownership: String,
    partner_id: Option<Uuid>,
    status: String,
    projection_version: i64,
}

struct Identifiers {
    application: Uuid,
    partner: Uuid,
    request: Uuid,
    actor: Uuid,
    session: Uuid,
    requested_by: Uuid,
    reviewed_by: Uuid,
    published_by: Option<Uuid>,
    contact: Uuid,
    domain: Uuid,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route(
        "/internal/identity/auth/review/applications/{application}/{environment}",
        get(current).put(sync),
    )
}

fn id(raw: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(raw).map_err(|_| AppError::bad_request("审核标识必须为规范UUIDv7"))?;
    if id.to_string() != raw || !uuid7::is_uuid_v7(id) {
        return Err(AppError::bad_request("审核标识必须为规范UUIDv7"));
    }
    Ok(id)
}

fn environment(raw: &str) -> Result<(), AppError> {
    if !matches!(raw, "test" | "production") {
        return Err(AppError::bad_request("审核环境必须为test或production"));
    }
    Ok(())
}

fn https(raw: &str, callback: bool) -> Result<reqwest::Url, AppError> {
    let url = reqwest::Url::parse(raw)
        .map_err(|_| AppError::bad_request("审核地址必须为精确HTTPS URL"))?;
    if raw.len() > 2048
        || url.scheme() != "https"
        || url.host_str().is_none()
        || url.as_str() != raw
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || raw.contains('*')
        || (callback
            && url
                .query_pairs()
                .any(|(key, _)| matches!(key.as_ref(), "code" | "state" | "error" | "iss")))
    {
        return Err(AppError::bad_request("审核地址必须为精确HTTPS URL"));
    }
    Ok(url)
}

fn validate(application: Uuid, env: &str, input: &Review) -> Result<Identifiers, AppError> {
    environment(env)?;
    let manifest = &input.manifest;
    if input.application_id != application.to_string()
        || input.environment != env
        || input.request_version < 1
        || input
            .expected_projection_version
            .is_some_and(|version| version < 1)
        || input
            .expected_admission_version
            .is_some_and(|version| version < 1)
        || !matches!(input.status.as_str(), "APPROVED" | "SUSPENDED")
        || manifest.display_name.trim() != manifest.display_name
        || manifest.display_name.is_empty()
        || manifest.display_name.chars().count() > 120
        || manifest.purpose.trim() != manifest.purpose
        || manifest.purpose.is_empty()
        || manifest.purpose.chars().count() > 2000
        || manifest.display_name.chars().any(char::is_control)
        || manifest.purpose.chars().any(char::is_control)
        || matches!(
            manifest.purpose.to_ascii_uppercase().as_str(),
            "PLATFORM_CONSOLE" | "CUSTOMER_PORTAL"
        )
        || !matches!(
            manifest.logout_mode.as_str(),
            "SHORT_SESSION_ONLINE_CHECK" | "BACK_CHANNEL"
        )
        || manifest.domains.is_empty()
        || manifest.domains.len() > 16
        || manifest.redirect_uris.is_empty()
        || manifest.redirect_uris.len() > 16
        || manifest.post_logout_redirect_uris.len() > 16
        || manifest.scopes.is_empty()
        || manifest.scopes.len() > 2
        || !manifest.scopes.iter().any(|scope| scope == "openid")
        || manifest
            .scopes
            .iter()
            .any(|scope| !matches!(scope.as_str(), "openid" | "profile"))
        || manifest.scopes.iter().collect::<HashSet<_>>().len() != manifest.scopes.len()
        || input.contact_reference != manifest.contact_reference
        || input.domain_reference != manifest.domain_evidence_reference
    {
        return Err(AppError::bad_request("第三方审核清单无效或超出首版范围"));
    }
    https(&manifest.privacy_url, false)?;
    let mut domains = HashSet::new();
    for domain in &manifest.domains {
        if domain.is_empty()
            || domain.len() > 253
            || domain.starts_with('.')
            || domain.ends_with('.')
            || domain.parse::<std::net::IpAddr>().is_ok()
            || !domain.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
            || !domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            })
            || !domains.insert(domain.as_str())
        {
            return Err(AppError::bad_request(
                "审核域名必须为规范且唯一的明确DNS域名",
            ));
        }
    }
    for callbacks in [&manifest.redirect_uris, &manifest.post_logout_redirect_uris] {
        let mut seen = HashSet::new();
        for callback in callbacks {
            let url = https(callback, true)?;
            if !domains.contains(url.host_str().unwrap_or_default()) || !seen.insert(callback) {
                return Err(AppError::bad_request("回调地址不属于审核域名或重复"));
            }
        }
    }
    match manifest.logout_mode.as_str() {
        "SHORT_SESSION_ONLINE_CHECK" if manifest.backchannel_logout_uri.is_none() => {}
        "BACK_CHANNEL" => {
            let raw = manifest
                .backchannel_logout_uri
                .as_deref()
                .ok_or_else(|| AppError::bad_request("back-channel审核必须有精确HTTPS地址"))?;
            let uri = https(raw, true)?;
            if uri.query().is_some() || !domains.contains(uri.host_str().unwrap_or_default()) {
                return Err(AppError::bad_request(
                    "back-channel地址必须无查询参数并属于当前审核域名",
                ));
            }
        }
        _ => {
            return Err(AppError::bad_request(
                "登出方式与back-channel审核地址不匹配",
            ))
        }
    }
    let ids = Identifiers {
        application,
        partner: id(&input.partner_id)?,
        request: id(&input.request_id)?,
        actor: id(&input.actor_user_id)?,
        session: id(&input.actor_session_id)?,
        requested_by: id(&input.requested_by)?,
        reviewed_by: id(&input.reviewed_by)?,
        published_by: input.published_by.as_deref().map(id).transpose()?,
        contact: id(&input.contact_reference)?,
        domain: id(&input.domain_reference)?,
    };
    if ids.requested_by == ids.reviewed_by
        || ids.published_by == Some(ids.requested_by)
        || (env == "production" && input.status == "APPROVED" && ids.published_by.is_none())
    {
        return Err(AppError::forbidden(
            "申请人不可自批，生产启用必须绑定独立发布人",
        ));
    }
    Ok(ids)
}

pub(crate) async fn admission<'e, E>(
    executor: E,
    application: Uuid,
    env: &str,
) -> Result<Option<Admission>, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as("SELECT status,redirect_uris,post_logout_redirect_uris,scopes,logout_mode,backchannel_logout_uri FROM public.auth_application_admissions WHERE application_id=$1 AND environment=$2")
        .bind(application).bind(env).fetch_optional(executor).await.map_err(AppError::from)
}

async fn current(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw, env)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    internal::authenticate(&state, &headers, PURPOSE).await?;
    let application = id(&raw)?;
    environment(&env)?;
    let projection: Option<i64> = sqlx::query_scalar(
        "SELECT projection_version FROM public.auth_applications WHERE application_id=$1",
    )
    .bind(application)
    .fetch_optional(&state.pool)
    .await?;
    let admitted:Option<(i64,String)>=sqlx::query_as("SELECT version,status FROM public.auth_application_admissions WHERE application_id=$1 AND environment=$2").bind(application).bind(&env).fetch_optional(&state.pool).await?;
    Ok(Json(
        json!({"applicationId":application,"environment":env,"projectionVersion":projection,"admissionVersion":admitted.as_ref().map(|value|value.0),"status":admitted.as_ref().map(|value|value.1.as_str()).unwrap_or("UNREGISTERED")}),
    ))
}

async fn fence(
    tx: &mut Transaction<'_, Postgres>,
    operation: Uuid,
    service: Uuid,
    digest: &str,
    path: &str,
    body: &Value,
) -> Result<(), AppError> {
    let accepted: bool = sqlx::query_scalar(
        "SELECT public.identity_auth_review_intent_active($1,$2,$3,'PUT',$4,$5)",
    )
    .bind(operation)
    .bind(service)
    .bind(digest)
    .bind(path)
    .bind(body)
    .fetch_one(&mut **tx)
    .await?;
    if !accepted {
        return Err(AppError::forbidden(
            "审核来源、当前版本、分工或近期二次认证未获确认",
        ));
    }
    Ok(())
}

async fn sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw, env)): Path<(String, String)>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = internal::authenticate(&state, &headers, PURPOSE).await?;
    let application = id(&raw)?;
    environment(&env)?;
    let input: Review = serde_json::from_value(body.clone())
        .map_err(|_| AppError::bad_request("审核投影请求无效"))?;
    let ids = validate(application, &env, &input)?;
    let path = format!("{PREFIX}/{application}/{env}");
    let mut operation =
        crate::admin_operations::begin(&state, &service, &headers, "PUT", &path, &body).await?;
    if let Some(result) = operation.replay()? {
        return Ok(Json(result));
    }
    let digest = headers
        .get("x-identity-operation-digest")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unavailable)?;
    fence(
        &mut operation.tx,
        operation.operation_id,
        service.id,
        digest,
        &path,
        &body,
    )
    .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("auth-reviewed-application/1:{application}"))
        .execute(&mut *operation.tx)
        .await?;
    let existing:Option<ExistingApplication>=sqlx::query_as("SELECT ownership,partner_id,status,projection_version FROM public.auth_applications WHERE application_id=$1 FOR UPDATE").bind(application).fetch_optional(&mut *operation.tx).await?;
    let projection_version = match existing {
        None if input.expected_projection_version.is_none() && input.status == "APPROVED" => 1,
        Some(current)
            if current.ownership == "THIRD_PARTY"
                && current.partner_id == Some(ids.partner)
                && current.status != "RETIRED"
                && input.expected_projection_version == Some(current.projection_version) =>
        {
            current
                .projection_version
                .checked_add(1)
                .ok_or(AppError::Unavailable)?
        }
        _ => return Err(AppError::conflict("应用归属、投影版本或退役状态已变化")),
    };
    if projection_version == 1 {
        sqlx::query("INSERT INTO public.auth_applications(application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) VALUES($1,$2,'THIRD_PARTY','APPROVED',$3,$4,$5,1,clock_timestamp())")
            .bind(application).bind(ids.partner).bind(&input.manifest.display_name).bind(&input.manifest.purpose).bind(&input.manifest.scopes).execute(&mut *operation.tx).await?;
    }
    let prior:Option<i64>=sqlx::query_scalar("SELECT version FROM public.auth_application_admissions WHERE application_id=$1 AND environment=$2 FOR UPDATE").bind(application).bind(&env).fetch_optional(&mut *operation.tx).await?;
    let admission_version = match (prior, input.expected_admission_version) {
        (None, None) => 1,
        (Some(current), Some(expected)) if current == expected => {
            current.checked_add(1).ok_or(AppError::Unavailable)?
        }
        _ => return Err(AppError::conflict("应用环境审核版本已变化")),
    };
    let changed=sqlx::query("INSERT INTO public.auth_application_admissions(application_id,environment,status,redirect_uris,post_logout_redirect_uris,scopes,requested_by,reviewed_by,published_by,contact_reference,domain_reference,review_reference,version,logout_mode,backchannel_logout_uri,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,clock_timestamp()) ON CONFLICT(application_id,environment) DO UPDATE SET status=EXCLUDED.status,redirect_uris=EXCLUDED.redirect_uris,post_logout_redirect_uris=EXCLUDED.post_logout_redirect_uris,scopes=EXCLUDED.scopes,requested_by=EXCLUDED.requested_by,reviewed_by=EXCLUDED.reviewed_by,published_by=EXCLUDED.published_by,contact_reference=EXCLUDED.contact_reference,domain_reference=EXCLUDED.domain_reference,review_reference=EXCLUDED.review_reference,version=EXCLUDED.version,logout_mode=EXCLUDED.logout_mode,backchannel_logout_uri=EXCLUDED.backchannel_logout_uri,updated_at=EXCLUDED.updated_at")
        .bind(application).bind(&env).bind(&input.status).bind(&input.manifest.redirect_uris).bind(&input.manifest.post_logout_redirect_uris).bind(&input.manifest.scopes)
        .bind(ids.requested_by).bind(ids.reviewed_by).bind(ids.published_by).bind(ids.contact).bind(ids.domain).bind(ids.request).bind(admission_version).bind(&input.manifest.logout_mode).bind(&input.manifest.backchannel_logout_uri)
        .execute(&mut *operation.tx).await?.rows_affected();
    if changed != 1 {
        return Err(AppError::Unavailable);
    }
    let approved:Vec<String>=sqlx::query_scalar("SELECT DISTINCT scope FROM public.auth_application_admissions admission CROSS JOIN LATERAL unnest(admission.scopes) scope WHERE application_id=$1 AND status='APPROVED' ORDER BY scope").bind(application).fetch_all(&mut *operation.tx).await?;
    let status = if approved.is_empty() {
        "SUSPENDED"
    } else {
        "APPROVED"
    };
    let changed=sqlx::query("UPDATE public.auth_applications SET display_name=$2,purpose=$3,status=$4,approved_scopes=$5,projection_version=$6,projected_at=clock_timestamp() WHERE application_id=$1")
        .bind(application).bind(&input.manifest.display_name).bind(&input.manifest.purpose).bind(status).bind(approved).bind(projection_version).execute(&mut *operation.tx).await?.rows_affected();
    if changed != 1 {
        return Err(AppError::Unavailable);
    }
    audit::write_in_tx(&mut operation.tx,audit::AuditInfo {user_id:Some(ids.actor),username:"AUTH_REVIEW_AUTHORITY",action:"AUTH_APPLICATION_REVIEW_SYNC",detail:&json!({"applicationId":ids.application,"environment":env,"requestId":ids.request,"requestVersion":input.request_version,"actorSessionId":ids.session,"reviewedBy":ids.reviewed_by,"publishedBy":ids.published_by,"projectionVersion":projection_version,"admissionVersion":admission_version,"status":input.status}).to_string(),ip:"trusted-private-service",user_agent:PURPOSE}).await?;
    fence(
        &mut operation.tx,
        operation.operation_id,
        service.id,
        digest,
        &path,
        &body,
    )
    .await?;
    Ok(Json(operation.commit(json!({"applicationId":application,"environment":env,"projectionVersion":projection_version,"admissionVersion":admission_version,"status":input.status,"requestId":ids.request,"requestVersion":input.request_version})).await?))
}

#[cfg(test)]
mod tests;
