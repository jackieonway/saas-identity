//! Canonical authenticated RP logout. A durable receipt and the original RP
//! tuple make uncertain retries safe even after this command revoked its token.
use super::*;
use crate::authentication::PostgresAccountTransaction;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    CurrentApp,
    Global,
}
impl Scope {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "CURRENT_APP" => Ok(Self::CurrentApp),
            "GLOBAL" => Ok(Self::Global),
            _ => Err(super::super::invalid()),
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::CurrentApp => "CURRENT_APP",
            Self::Global => "GLOBAL",
        }
    }
}
struct Input {
    operation: Uuid,
    token_digest: String,
    credential_digest: String,
    scope: Scope,
    sid: String,
    sub: String,
    digest: String,
}

#[derive(sqlx::FromRow)]
struct Receipt {
    client_id: Uuid,
    token_digest: String,
    request_digest: String,
    public_sid: String,
    public_sub: String,
    scope: String,
    result_json: Value,
}

#[derive(sqlx::FromRow)]
struct Source {
    grant_id: Uuid,
    user_id: Uuid,
    source_session_id: Uuid,
    public_sid: String,
    public_sub: String,
    token_kind: String,
}

fn operation_id(raw: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(raw).map_err(|_| super::super::invalid())?;
    if !uuid7::is_uuid_v7(id) || id.to_string() != raw {
        return Err(super::super::invalid());
    }
    Ok(id)
}

fn input(
    client: &Client,
    headers: &HeaderMap,
    values: &BTreeMap<String, String>,
    operation: Option<Uuid>,
) -> Result<Input> {
    if values.keys().any(|key| {
        !matches!(
            key.as_str(),
            "token" | "scope" | "operation_id" | "sid" | "sub" | "client_id"
        )
    }) {
        return Err(super::super::invalid());
    }
    let body_operation = values
        .get("operation_id")
        .map(|value| operation_id(value))
        .transpose()?;
    let operation = match (operation, body_operation) {
        (Some(path), Some(body)) if path != body => return Err(super::super::invalid()),
        (Some(path), _) => path,
        (None, Some(body)) => body,
        _ => return Err(super::super::invalid()),
    };
    let token = protocol::required(values, "token")?;
    let sid = protocol::required(values, "sid")?;
    let sub = protocol::required(values, "sub")?;
    if !canonical_secret(token)
        || !canonical_secret(sid)
        || sub.is_empty()
        || sub.len() > 256
        || !sub.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(super::super::invalid());
    }
    let scope = Scope::parse(protocol::required(values, "scope")?)?;
    let authorization = one_header(headers, header::AUTHORIZATION.as_str())?
        .and_then(|value| value.strip_prefix("Basic "))
        .ok_or(OidcError::InvalidClient)?;
    let decoded = STANDARD
        .decode(authorization)
        .map_err(|_| OidcError::InvalidClient)?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| OidcError::InvalidClient)?;
    let (_, secret) = decoded.split_once(':').ok_or(OidcError::InvalidClient)?;
    let secret = protocol::decode_component(secret).map_err(|_| OidcError::InvalidClient)?;
    let token_digest = super::super::digest(token);
    let digest = super::super::digest(
        &json!({"clientId":client.id,"tokenDigest":token_digest,
        "scope":scope.as_str(),"sid":sid,"sub":sub})
        .to_string(),
    );
    Ok(Input {
        operation,
        token_digest,
        credential_digest: super::super::digest(&secret),
        scope,
        sid: sid.to_owned(),
        sub: sub.to_owned(),
        digest,
    })
}

async fn lock_operation(tx: &mut Transaction<'_, Postgres>, operation: Uuid) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2000662001))")
        .bind(operation.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn credential_current(
    tx: &mut Transaction<'_, Postgres>,
    client: &Client,
    input: &Input,
) -> Result<()> {
    ensure_client_current(tx, client).await?;
    let credential: Option<Uuid> = sqlx::query_scalar("SELECT id FROM public.auth_client_credentials WHERE client_id=$1 AND secret_digest=$2 AND revoked_at IS NULL AND created_at+interval '90 days'>clock_timestamp() AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE")
        .bind(client.id).bind(&input.credential_digest).fetch_optional(&mut **tx).await?;
    if credential.is_none() {
        return Err(OidcError::InvalidClient);
    }
    Ok(())
}

async fn receipt(
    tx: &mut Transaction<'_, Postgres>,
    client: &Client,
    input: &Input,
) -> Result<Option<Value>> {
    let existing: Option<Receipt> = sqlx::query_as("SELECT client_id,token_digest,request_digest,public_sid,public_sub,scope,result_json FROM public.auth_logout_command_receipts WHERE operation_id=$1")
        .bind(input.operation).fetch_optional(&mut **tx).await?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.client_id != client.id
        || existing.scope != input.scope.as_str()
        || !super::super::equal(&existing.token_digest, &input.token_digest)
        || !super::super::equal(&existing.request_digest, &input.digest)
        || existing.public_sid != input.sid
        || existing.public_sub != input.sub
    {
        return Err(AppError::conflict("原登出操作已绑定另一RP或来源").into());
    }
    credential_current(tx, client, input).await?;
    Ok(Some(existing.result_json))
}

async fn source(
    tx: &mut Transaction<'_, Postgres>,
    client: &Client,
    input: &Input,
) -> Result<Source> {
    let rows: Vec<Source> = sqlx::query_as("SELECT grant_row.id AS grant_id,grant_row.user_id,grant_row.source_session_id,rp.public_sid,rp.public_sub,original.token_kind FROM (SELECT grant_id,'ACCESS'::text AS token_kind FROM public.auth_access_tokens WHERE token_digest=$1 UNION ALL SELECT family.grant_id,'REFRESH'::text FROM public.auth_refresh_tokens token JOIN public.auth_refresh_families family ON family.id=token.family_id WHERE token.token_digest=$1) original JOIN public.auth_grants grant_row ON grant_row.id=original.grant_id JOIN public.auth_rp_sessions rp ON rp.grant_id=grant_row.id AND rp.client_id=grant_row.client_id AND rp.user_id=grant_row.user_id AND rp.source_session_id=grant_row.source_session_id WHERE grant_row.client_id=$2 AND grant_row.subject_mode='USER' AND grant_row.user_id IS NOT NULL AND grant_row.source_session_id IS NOT NULL")
        .bind(&input.token_digest).bind(client.id).fetch_all(&mut **tx).await?;
    if rows.len() != 1 {
        return Err(super::super::invalid_grant());
    }
    let source = rows
        .into_iter()
        .next()
        .ok_or_else(super::super::invalid_grant)?;
    if source.public_sid != input.sid || source.public_sub != input.sub {
        return Err(super::super::invalid_grant());
    }
    Ok(source)
}

async fn active_source(
    tx: &mut Transaction<'_, Postgres>,
    client: &Client,
    input: &Input,
    source: &Source,
) -> Result<DateTime<Utc>> {
    let deadline:Option<DateTime<Utc>>=sqlx::query_scalar("SELECT LEAST(grant_row.expires_at,CASE WHEN $4='ACCESS' THEN (SELECT token.expires_at FROM public.auth_access_tokens token WHERE token.grant_id=grant_row.id AND token.token_digest=$2 AND token.revoked_at IS NULL AND token.expires_at>clock_timestamp()) ELSE (SELECT LEAST(token.expires_at,family.absolute_expires_at,family.idle_expires_at) FROM public.auth_refresh_tokens token JOIN public.auth_refresh_families family ON family.id=token.family_id WHERE family.grant_id=grant_row.id AND token.token_digest=$2 AND token.consumed_at IS NULL AND token.revoked_at IS NULL AND token.expires_at>clock_timestamp() AND family.revoked_at IS NULL AND family.absolute_expires_at>clock_timestamp() AND family.idle_expires_at>clock_timestamp()) END) FROM public.auth_grants grant_row JOIN public.users subject ON subject.id=grant_row.user_id JOIN public.sso_sessions session ON session.id=grant_row.source_session_id AND session.user_id=grant_row.user_id AND session.account_version=grant_row.account_version AND session.authenticated_at=grant_row.auth_time JOIN public.auth_consents consent ON consent.id=grant_row.consent_id AND consent.user_id=grant_row.user_id AND consent.status='ACTIVE' AND consent.generation=grant_row.consent_generation AND consent.group_version=grant_row.consent_group_version JOIN public.auth_consent_groups consent_group ON consent_group.id=consent.group_id AND consent_group.status='ACTIVE' AND consent_group.version=grant_row.consent_group_version JOIN public.auth_consent_group_clients member ON member.group_id=consent.group_id AND member.client_id=grant_row.client_id WHERE grant_row.id=$1 AND grant_row.client_id=$3 AND grant_row.user_id=$5 AND grant_row.source_session_id=$6 AND grant_row.revoked_at IS NULL AND grant_row.expires_at>clock_timestamp() AND subject.status='ENABLED' AND subject.session_version=grant_row.account_version AND grant_row.client_policy_version=$7 AND grant_row.application_projection_version=$8 AND (grant_row.context_mode IN ('ACCOUNT_ONLY','PLATFORM_CONTEXT')) AND (EXISTS(SELECT 1 FROM public.auth_scopes scope JOIN public.auth_resources resource ON resource.id=scope.resource_id WHERE scope.id=ANY(grant_row.scope_ids) AND scope.scope_name='offline_access' AND resource.resource_key='userinfo' AND grant_row.context_mode='ACCOUNT_ONLY') OR (session.revoked_at IS NULL AND session.expires_at>clock_timestamp())) AND CASE WHEN $4='ACCESS' THEN EXISTS(SELECT 1 FROM public.auth_access_tokens token WHERE token.grant_id=grant_row.id AND token.token_digest=$2 AND token.revoked_at IS NULL AND token.expires_at>clock_timestamp()) ELSE EXISTS(SELECT 1 FROM public.auth_refresh_tokens token JOIN public.auth_refresh_families family ON family.id=token.family_id WHERE family.grant_id=grant_row.id AND token.token_digest=$2 AND token.consumed_at IS NULL AND token.revoked_at IS NULL AND token.expires_at>clock_timestamp() AND family.revoked_at IS NULL AND family.absolute_expires_at>clock_timestamp() AND family.idle_expires_at>clock_timestamp()) END")
        .bind(source.grant_id).bind(&input.token_digest).bind(client.id).bind(&source.token_kind)
        .bind(source.user_id).bind(source.source_session_id).bind(client.policy_version)
        .bind(client.application_projection_version).fetch_optional(&mut **tx).await?;
    deadline.ok_or_else(super::super::invalid_grant)
}

pub(in crate::oidc) async fn command(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: RawQuery,
    body: RawForm,
) -> Result<Json<Value>> {
    super::super::authority(&state).await?;
    let values = protocol::form(body, query)?;
    let client = confidential_client(&state, &headers, &values).await?;
    if client.subject_mode != "USER" {
        return Err(OidcError::InvalidClient);
    }
    let input = input(&client, &headers, &values, None)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    lock_operation(&mut tx, input.operation).await?;
    if let Some(result) = receipt(&mut tx, &client, &input).await? {
        tx.commit().await?;
        return Ok(Json(result));
    }
    let source = source(&mut tx, &client, &input).await?;
    let username: Option<String> =
        sqlx::query_scalar("SELECT username FROM public.users WHERE id=$1 FOR UPDATE")
            .bind(source.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let username = username.ok_or_else(super::super::invalid_grant)?;
    credential_current(&mut tx, &client, &input).await?;
    sqlx::query("SELECT id FROM public.auth_grants WHERE id=$1 FOR UPDATE")
        .bind(source.grant_id)
        .fetch_one(&mut *tx)
        .await?;
    let deadline = active_source(&mut tx, &client, &input, &source).await?;
    let global = input.scope == Scope::Global;
    let grant_count:i64=sqlx::query_scalar("SELECT count(*) FROM public.auth_grants WHERE user_id=$1 AND subject_mode='USER' AND revoked_at IS NULL AND ($2 OR id=$3)")
        .bind(source.user_id).bind(global).bind(source.grant_id).fetch_one(&mut *tx).await?;
    let sso_count: i64 = if global {
        sqlx::query_scalar(
            "SELECT count(*) FROM public.sso_sessions WHERE user_id=$1 AND revoked_at IS NULL",
        )
        .bind(source.user_id)
        .fetch_one(&mut *tx)
        .await?
    } else {
        0
    };
    let notifications_before: i64 = sqlx::query_scalar("SELECT count(*) FROM public.auth_delivery_jobs job JOIN public.auth_grants grant_row ON grant_row.id=job.grant_id WHERE job.kind='LOGOUT' AND grant_row.user_id=$1 AND ($2 OR grant_row.id=$3)")
        .bind(source.user_id).bind(global).bind(source.grant_id).fetch_one(&mut *tx).await?;
    if global {
        let mut accounts = PostgresAccountTransaction::new(&mut tx);
        state
            .accounts
            .revoke_all(&mut accounts, source.user_id)
            .await?;
    }
    sqlx::query("UPDATE public.auth_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE user_id=$1 AND subject_mode='USER' AND ($2 OR id=$3)")
        .bind(source.user_id).bind(global).bind(source.grant_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE public.auth_access_tokens token SET revoked_at=COALESCE(token.revoked_at,clock_timestamp()) FROM public.auth_grants grant_row WHERE token.grant_id=grant_row.id AND grant_row.user_id=$1 AND ($2 OR grant_row.id=$3)")
        .bind(source.user_id).bind(global).bind(source.grant_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE public.auth_refresh_families family SET revoked_at=COALESCE(family.revoked_at,clock_timestamp()) FROM public.auth_grants grant_row WHERE family.grant_id=grant_row.id AND grant_row.user_id=$1 AND ($2 OR grant_row.id=$3)")
        .bind(source.user_id).bind(global).bind(source.grant_id).execute(&mut *tx).await?;
    let notifications:i64=sqlx::query_scalar("SELECT count(*) FROM public.auth_delivery_jobs job JOIN public.auth_grants grant_row ON grant_row.id=job.grant_id WHERE job.kind='LOGOUT' AND grant_row.user_id=$1 AND ($2 OR grant_row.id=$3)")
        .bind(source.user_id).bind(global).bind(source.grant_id).fetch_one(&mut *tx).await?;
    let notifications = notifications
        .checked_sub(notifications_before)
        .ok_or(AppError::Unavailable)?;
    let result = json!({"operationId":input.operation,"scope":input.scope.as_str(),"state":"COMPLETED","revokedGrantCount":grant_count,"revokedSsoCount":sso_count,"notificationCount":notifications});
    sqlx::query("INSERT INTO public.auth_logout_command_receipts(operation_id,client_id,grant_id,user_id,token_digest,scope,public_sid,public_sub,request_digest,result_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(input.operation).bind(client.id).bind(source.grant_id).bind(source.user_id).bind(&input.token_digest)
        .bind(input.scope.as_str()).bind(&input.sid).bind(&input.sub).bind(&input.digest).bind(&result).execute(&mut *tx).await?;
    audit::write_in_tx(&mut tx,audit::AuditInfo{user_id:Some(source.user_id),username:&username,action:"AUTH_RP_LOGOUT",detail:&json!({"operationId":input.operation,"clientId":client.id,"scope":input.scope.as_str(),"revokedGrantCount":grant_count,"revokedSsoCount":sso_count,"notificationCount":notifications}).to_string(),ip:&audit::client_ip(&headers),user_agent:&audit::ua_of(&headers)}).await?;
    credential_current(&mut tx, &client, &input).await?;
    super::super::deadline(&mut tx, deadline).await?;
    tx.commit().await?;
    Ok(Json(result))
}

pub(in crate::oidc) async fn operation(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    headers: HeaderMap,
    query: RawQuery,
    body: RawForm,
) -> Result<Json<Value>> {
    super::super::authority(&state).await?;
    let values = protocol::form(body, query)?;
    let client = confidential_client(&state, &headers, &values).await?;
    if client.subject_mode != "USER" {
        return Err(OidcError::InvalidClient);
    }
    let input = input(&client, &headers, &values, Some(operation_id(&raw)?))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    lock_operation(&mut tx, input.operation).await?;
    let result = receipt(&mut tx, &client, &input)
        .await?
        .ok_or_else(|| AppError::not_found("原登出操作尚未提交"))?;
    tx.commit().await?;
    Ok(Json(result))
}
