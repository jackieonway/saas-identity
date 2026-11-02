//! Minimal platform-owned application projection over the private identity API.

use axum::{
    extract::{Path, RawQuery, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use uuid::Uuid;

use crate::{
    error::AppError,
    extractors::ApiJson,
    internal,
    state::AppState,
    util::audit::{self, AuditInfo},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyncCommand {
    application_id: String,
    expected_version: Option<i64>,
    projection: Projection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Projection {
    ownership: String,
    partner_id: Option<String>,
    status: String,
    display_name: String,
    purpose: String,
    approved_scopes: Vec<String>,
}

#[derive(sqlx::FromRow)]
struct Existing {
    projection_version: i64,
    status: String,
    ownership: String,
    partner_id: Option<Uuid>,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route(
        "/internal/identity/auth/applications/{id}",
        get(get_projection).put(sync_projection),
    )
}

fn canonical_application_id(raw: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(raw).map_err(|_| AppError::bad_request("应用投影标识无效"))?;
    if !crate::util::uuid7::is_uuid_v7(id) || id.to_string() != raw {
        return Err(AppError::bad_request("应用投影标识必须为规范UUIDv7"));
    }
    Ok(id)
}

fn validate(id: Uuid, body: &SyncCommand) -> Result<(), AppError> {
    if body.application_id != id.to_string()
        || !matches!(
            body.projection.ownership.as_str(),
            "FIRST_PARTY" | "THIRD_PARTY"
        )
        || !matches!(
            body.projection.status.as_str(),
            "DRAFT" | "PENDING_REVIEW" | "APPROVED" | "SUSPENDED" | "RETIRED"
        )
        || body.projection.display_name.trim().is_empty()
        || body.projection.display_name.chars().count() > 200
        || body.projection.purpose.trim().is_empty()
        || body.projection.purpose.chars().count() > 2000
        || ((body.projection.ownership == "THIRD_PARTY") != body.projection.partner_id.is_some())
        || body.expected_version.is_some_and(|version| version < 1)
        || body.projection.approved_scopes.len() > 64
    {
        return Err(AppError::bad_request("认证应用投影无效"));
    }
    if let Some(partner) = &body.projection.partner_id {
        canonical_application_id(partner)
            .map_err(|_| AppError::bad_request("合作方投影标识无效"))?;
    }
    let mut seen = HashSet::new();
    for scope in &body.projection.approved_scopes {
        if scope.is_empty()
            || scope.len() > 128
            || !scope
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:-".contains(&b))
            || !seen.insert(scope)
        {
            return Err(AppError::bad_request("应用获准 scope 无效"));
        }
    }
    Ok(())
}

async fn get_projection(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(raw_id): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, AppError> {
    let service = internal::authenticate(&state, &headers, "APPLICATION_PROJECTION").await?;
    service.require("APPLICATION_PROJECTION")?;
    if query.is_some() {
        return Err(AppError::bad_request("应用投影查询不接受查询参数"));
    }
    let id = canonical_application_id(&raw_id)?;
    let projection = sqlx::query_as::<_, (Uuid, Option<Uuid>, String, String, String, String, Vec<String>, i64)>(
        "SELECT application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version \
         FROM public.auth_applications WHERE application_id=$1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("认证应用投影不存在"))?;
    Ok(Json(json!({
        "applicationId":projection.0,
        "partnerId":projection.1,
        "ownership":projection.2,
        "status":projection.3,
        "displayName":projection.4,
        "purpose":projection.5,
        "approvedScopes":projection.6,
        "projectionVersion":projection.7
    })))
}

async fn sync_projection(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(raw_id): Path<String>,
    ApiJson(raw): ApiJson<Value>,
) -> Result<Json<Value>, AppError> {
    let service = internal::authenticate(&state, &headers, "APPLICATION_PROJECTION").await?;
    let id = canonical_application_id(&raw_id)?;
    let body: SyncCommand = serde_json::from_value(raw.clone())
        .map_err(|_| AppError::bad_request("认证应用投影无效"))?;
    validate(id, &body)?;
    if body.projection.ownership == "THIRD_PARTY" && body.projection.status == "APPROVED" {
        return Err(AppError::forbidden("第三方应用须先完成独立合作方审核"));
    }
    let path = format!("/internal/identity/auth/applications/{id}");
    let mut command =
        crate::admin_operations::begin(&state, &service, &headers, "PUT", &path, &raw).await?;
    if let Some(replayed) = command.replay()? {
        return Ok(Json(replayed));
    }
    let scopes_registered: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM unnest($1::text[]) requested(scope_name) \
         WHERE NOT EXISTS(SELECT 1 FROM public.auth_scopes s WHERE s.scope_name=requested.scope_name AND s.status='ACTIVE'))",
    )
    .bind(&body.projection.approved_scopes)
    .fetch_one(&mut *command.tx)
    .await?;
    if !scopes_registered {
        return Err(AppError::bad_request("应用投影包含未登记或停用的 scope"));
    }

    let partner_id = body
        .projection
        .partner_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| AppError::bad_request("合作方投影标识无效"))?;
    let before: Option<Existing> = sqlx::query_as(
        "SELECT projection_version,status,ownership,partner_id FROM public.auth_applications WHERE application_id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *command.tx)
    .await?;
    if before.as_ref().is_some_and(|current| {
        current.ownership != body.projection.ownership || current.partner_id != partner_id
    }) {
        return Err(AppError::conflict("认证应用所有权和合作方归属不可原地变更"));
    }
    let (next_version, prior_status) = match (before, body.expected_version) {
        (None, None) => (1_i64, None),
        (Some(current), Some(expected)) if current.projection_version == expected => (
            expected
                .checked_add(1)
                .ok_or_else(|| AppError::bad_request("投影版本超出范围"))?,
            Some(current.status),
        ),
        _ => return Err(AppError::conflict("认证应用投影版本已变化")),
    };
    if prior_status.as_deref() == Some("RETIRED") && body.projection.status != "RETIRED" {
        return Err(AppError::conflict("已退役的认证应用不能恢复"));
    }
    if prior_status.is_some() {
        sqlx::query(
            "UPDATE public.auth_applications SET partner_id=$2,ownership=$3,status=$4,display_name=$5, \
             purpose=$6,approved_scopes=$7,projection_version=$8,projected_at=clock_timestamp() \
             WHERE application_id=$1",
        )
        .bind(id)
        .bind(partner_id)
        .bind(&body.projection.ownership)
        .bind(&body.projection.status)
        .bind(&body.projection.display_name)
        .bind(&body.projection.purpose)
        .bind(&body.projection.approved_scopes)
        .bind(next_version)
        .execute(&mut *command.tx)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO public.auth_applications(application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,1,clock_timestamp())",
        )
        .bind(id)
        .bind(partner_id)
        .bind(&body.projection.ownership)
        .bind(&body.projection.status)
        .bind(&body.projection.display_name)
        .bind(&body.projection.purpose)
        .bind(&body.projection.approved_scopes)
        .execute(&mut *command.tx)
        .await?;
    }
    let status = body.projection.status;
    let result = json!({"applicationId":id,"projectionVersion":next_version,"status":status});
    let detail = json!({"applicationId":id,"projectionVersion":next_version,"status":status});
    let audit_detail = detail.to_string();
    audit::write_in_tx(
        &mut command.tx,
        AuditInfo {
            user_id: None,
            username: "APPLICATION_PROJECTION_SERVICE",
            action: "AUTH_APPLICATION_PROJECTION",
            detail: &audit_detail,
            ip: "unknown",
            user_agent: "private-service",
        },
    )
    .await?;
    Ok(Json(command.commit(result).await?))
}
