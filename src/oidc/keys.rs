//! Fixed-algorithm signing, externally provisioned private keys and durable public lifecycle.

use std::{collections::HashSet, path::Path, sync::Arc};

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{error::AppError, extractors::ApiJson, internal::ServicePrincipal, state::AppState};

use super::Result;
use crate::util::audit;
use sqlx::{Postgres, Transaction};

async fn require_admin(
    state: &AppState,
    user: &ServicePrincipal,
) -> std::result::Result<(), AppError> {
    super::authority(state).await?;
    user.require("KEY_ADMIN")
}
async fn admin_audit(
    tx: &mut Transaction<'_, Postgres>,
    user: &ServicePrincipal,
    headers: &HeaderMap,
    action: &str,
    detail: &str,
) -> std::result::Result<(), AppError> {
    audit::write_in_tx(
        tx,
        audit::AuditInfo {
            user_id: None,
            username: &user.id.to_string(),
            action,
            detail,
            ip: &audit::client_ip(headers),
            user_agent: &audit::ua_of(headers),
        },
    )
    .await
}

#[cfg(test)]
mod actor_fixture;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod pg_fixture;
#[cfg(test)]
mod test_keys;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvisionedKey {
    kid: String,
    private_key_pem: String,
    n: String,
    e: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionedKeys {
    keys: Vec<ProvisionedKey>,
}

struct Material {
    kid: String,
    encoding: EncodingKey,
    n: String,
    e: String,
}

/// Contains private signing material, deliberately without Debug or Serialize.
pub(crate) struct KeySet {
    keys: Vec<Material>,
}

impl KeySet {
    pub(crate) fn load(path: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            Path::new(path).is_absolute(),
            "OIDC_KEYSET_PATH must be absolute"
        );
        let bytes =
            std::fs::read(path).map_err(|_| anyhow::anyhow!("OIDC_KEYSET_PATH cannot be read"))?;
        anyhow::ensure!(bytes.len() <= 512 * 1024, "OIDC keyset is too large");
        let provisioned: ProvisionedKeys = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("OIDC keyset JSON is invalid"))?;
        anyhow::ensure!(
            !provisioned.keys.is_empty() && provisioned.keys.len() <= 8,
            "OIDC key count must be 1..8"
        );
        let mut seen = HashSet::new();
        let mut keys = Vec::new();
        for key in provisioned.keys {
            anyhow::ensure!(
                valid_kid(&key.kid) && seen.insert(key.kid.clone()),
                "OIDC kid must be unique and canonical"
            );
            let modulus = URL_SAFE_NO_PAD
                .decode(&key.n)
                .map_err(|_| anyhow::anyhow!("OIDC RSA modulus is invalid"))?;
            let bits = modulus
                .first()
                .map(|first| modulus.len() * 8 - first.leading_zeros() as usize)
                .unwrap_or(0);
            anyhow::ensure!(
                (2048..=4096).contains(&bits)
                    && modulus.first() != Some(&0)
                    && URL_SAFE_NO_PAD.encode(&modulus) == key.n
                    && key.e == "AQAB",
                "OIDC requires canonical 2048..4096 bit RSA and exponent 65537"
            );
            anyhow::ensure!(
                key.private_key_pem.len() <= 16384,
                "OIDC private key is too large"
            );
            let encoding = EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes())
                .map_err(|_| anyhow::anyhow!("OIDC private RSA key is invalid"))?;
            let decoding = DecodingKey::from_rsa_components(&key.n, &key.e)
                .map_err(|_| anyhow::anyhow!("OIDC public RSA key is invalid"))?;
            let probe = json!({"sub":"oidc-key-pair-check","exp":Utc::now().timestamp()+60});
            let signed = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &probe, &encoding)
                .map_err(|_| anyhow::anyhow!("OIDC private RSA key cannot sign"))?;
            jsonwebtoken::decode::<Value>(&signed, &decoding, &Validation::new(Algorithm::RS256))
                .map_err(|_| anyhow::anyhow!("OIDC RSA key pair does not match"))?;
            keys.push(Material {
                kid: key.kid,
                encoding,
                n: key.n,
                e: key.e,
            });
        }
        Ok(Self { keys })
    }
    fn material(&self, kid: &str) -> Option<&Material> {
        self.keys.iter().find(|key| key.kid == kid)
    }
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 80
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn configured(state: &AppState) -> std::result::Result<&Arc<KeySet>, AppError> {
    super::enabled(state)?;
    state.config.oidc_keys.as_ref().ok_or(AppError::Unavailable)
}

pub(super) async fn jwks(State(state): State<AppState>) -> Result<Json<Value>> {
    super::authority(&state).await?;
    let rows:Vec<(String,String,String)>=sqlx::query_as(
        "SELECT kid,n,e FROM auth_signing_keys WHERE retired_at IS NULL AND revoked_at IS NULL ORDER BY kid")
        .fetch_all(&state.pool).await.map_err(|_|AppError::Unavailable)?;
    Ok(Json(
        json!({"keys":rows.into_iter().map(|(kid,n,e)|json!({"kty":"RSA","use":"sig","alg":"RS256","kid":kid,"n":n,"e":e})).collect::<Vec<_>>()}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyCommand {
    kid: String,
}

pub(super) async fn publish(
    State(state): State<AppState>,
    user: ServicePrincipal,
    headers: HeaderMap,
    ApiJson(raw_body): ApiJson<Value>,
) -> std::result::Result<Json<Value>, AppError> {
    let body: KeyCommand = serde_json::from_value(raw_body.clone())
        .map_err(|_| AppError::bad_request("OIDC密钥请求无效"))?;
    require_admin(&state, &user).await?;
    let mut command = crate::admin_operations::begin(
        &state,
        &user,
        &headers,
        "POST",
        "/internal/identity/auth/keys/publish",
        &raw_body,
    )
    .await?;
    if let Some(result) = command.replay()? {
        return Ok(Json(result));
    }
    let keys = configured(&state)?;
    let material = keys
        .material(&body.kid)
        .ok_or_else(|| AppError::bad_request("kid 未在已验证的密钥配置中登记"))?;
    key_lock(&mut command.tx).await?;
    let existing: Option<(String, String)> =
        sqlx::query_as("SELECT n,e FROM auth_signing_keys WHERE kid=$1 FOR UPDATE")
            .bind(&body.kid)
            .fetch_optional(&mut *command.tx)
            .await
            .map_err(|_| AppError::Unavailable)?;
    if let Some((n, e)) = existing {
        if n != material.n || e != material.e {
            return Err(AppError::conflict("kid 的公钥不可改写"));
        }
        return Err(AppError::conflict("kid 已登记，请继续其现有生命周期"));
    }
    let inserted = sqlx::query(
        "INSERT INTO auth_signing_keys(kid,n,e,published_at) VALUES($1,$2,$3,clock_timestamp())",
    )
    .bind(&material.kid)
    .bind(&material.n)
    .bind(&material.e)
    .execute(&mut *command.tx)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(AppError::Unavailable);
    }
    admin_audit(
        &mut command.tx,
        &user,
        &headers,
        "OIDC_PUBLISH_KEY",
        &json!({"kid":body.kid}).to_string(),
    )
    .await?;
    Ok(Json(
        command
            .commit(json!({"kid":body.kid,"status":"PUBLISHED"}))
            .await?,
    ))
}

pub(super) async fn activate(
    State(state): State<AppState>,
    user: ServicePrincipal,
    headers: HeaderMap,
    ApiJson(raw_body): ApiJson<Value>,
) -> std::result::Result<Json<Value>, AppError> {
    let body: KeyCommand = serde_json::from_value(raw_body.clone())
        .map_err(|_| AppError::bad_request("OIDC密钥请求无效"))?;
    require_admin(&state, &user).await?;
    let mut command = crate::admin_operations::begin(
        &state,
        &user,
        &headers,
        "POST",
        "/internal/identity/auth/keys/activate",
        &raw_body,
    )
    .await?;
    if let Some(result) = command.replay()? {
        return Ok(Json(result));
    }
    let keys = configured(&state)?;
    let material = keys
        .material(&body.kid)
        .ok_or_else(|| AppError::bad_request("kid 未在已验证的密钥配置中登记"))?;
    key_lock(&mut command.tx).await?;
    let current:Option<(String,String)>=sqlx::query_as(
        "SELECT n,e FROM auth_signing_keys WHERE kid=$1 AND retired_at IS NULL AND revoked_at IS NULL FOR UPDATE")
        .bind(&body.kid).fetch_optional(&mut *command.tx).await.map_err(|_|AppError::Unavailable)?;
    if current.as_ref() != Some(&(material.n.clone(), material.e.clone())) {
        return Err(AppError::conflict(
            "必须先发布相同公钥，且不能重新启用已退役或撤销的 kid",
        ));
    }
    sqlx::query("UPDATE auth_signing_keys SET active=false WHERE active")
        .execute(&mut *command.tx)
        .await?;
    let selected = sqlx::query(
        "UPDATE auth_signing_keys SET active=true,activated_at=clock_timestamp() WHERE kid=$1",
    )
    .bind(&body.kid)
    .execute(&mut *command.tx)
    .await?;
    if selected.rows_affected() != 1 {
        return Err(AppError::Unavailable);
    }
    // Clearing a previous active set may legitimately affect zero rows. The
    // selected key must nevertheless be the only active, usable key afterward.
    let unique_active:bool=sqlx::query_scalar("SELECT count(*)=1 AND COALESCE(bool_and(kid=$1 AND retired_at IS NULL AND revoked_at IS NULL),false) FROM auth_signing_keys WHERE active")
        .bind(&body.kid).fetch_one(&mut *command.tx).await?;
    if !unique_active {
        return Err(AppError::Unavailable);
    }
    admin_audit(
        &mut command.tx,
        &user,
        &headers,
        "OIDC_ACTIVATE_KEY",
        &json!({"kid":body.kid}).to_string(),
    )
    .await?;
    Ok(Json(
        command
            .commit(json!({"kid":body.kid,"status":"ACTIVE"}))
            .await?,
    ))
}

async fn key_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> std::result::Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('oidc-key-lifecycle-v1',0))")
        .execute(&mut **tx)
        .await
        .map_err(|_| AppError::Unavailable)?;
    Ok(())
}

pub(super) async fn retire(
    State(state): State<AppState>,
    user: ServicePrincipal,
    headers: HeaderMap,
    AxumPath(kid): AxumPath<String>,
    body: Bytes,
) -> std::result::Result<Json<Value>, AppError> {
    empty_command_body(&body)?;
    finish(&state, &user, &headers, &kid, false).await
}

pub(super) async fn revoke(
    State(state): State<AppState>,
    user: ServicePrincipal,
    headers: HeaderMap,
    AxumPath(kid): AxumPath<String>,
    body: Bytes,
) -> std::result::Result<Json<Value>, AppError> {
    empty_command_body(&body)?;
    finish(&state, &user, &headers, &kid, true).await
}

fn empty_command_body(body: &[u8]) -> std::result::Result<(), AppError> {
    if body.is_empty() || serde_json::from_slice::<Value>(body).ok() == Some(Value::Null) {
        Ok(())
    } else {
        Err(AppError::bad_request("此OIDC命令不接受请求字段"))
    }
}

async fn finish(
    state: &AppState,
    user: &ServicePrincipal,
    headers: &HeaderMap,
    kid: &str,
    emergency: bool,
) -> std::result::Result<Json<Value>, AppError> {
    super::enabled(state)?;
    require_admin(state, user).await?;
    if !valid_kid(kid) {
        return Err(AppError::bad_request("kid 无效"));
    }
    let (method, path) = if emergency {
        ("POST", format!("/internal/identity/auth/keys/{kid}/revoke"))
    } else {
        ("DELETE", format!("/internal/identity/auth/keys/{kid}"))
    };
    let mut command =
        crate::admin_operations::begin(state, user, headers, method, &path, &Value::Null).await?;
    if let Some(result) = command.replay()? {
        return Ok(Json(result));
    }
    key_lock(&mut command.tx).await?;
    let row:Option<(bool,bool)>=sqlx::query_as(
        "SELECT active,(last_signed_exp IS NULL OR last_signed_exp+interval '60 seconds'<clock_timestamp()) \
         FROM auth_signing_keys WHERE kid=$1 AND retired_at IS NULL AND revoked_at IS NULL FOR UPDATE")
        .bind(kid).fetch_optional(&mut *command.tx).await.map_err(|_|AppError::Unavailable)?;
    let Some((active, safe)) = row else {
        return Err(AppError::not_found("kid 不存在或已结束生命周期"));
    };
    if !emergency && (active || !safe) {
        return Err(AppError::conflict(
            "活动密钥或仍在 token 验证窗口内的公钥不能退役",
        ));
    }
    let sql = if emergency {
        "UPDATE auth_signing_keys SET active=false,revoked_at=clock_timestamp() WHERE kid=$1"
    } else {
        "UPDATE auth_signing_keys SET retired_at=clock_timestamp() WHERE kid=$1"
    };
    let updated = sqlx::query(sql).bind(kid).execute(&mut *command.tx).await?;
    if updated.rows_affected() != 1 {
        return Err(AppError::Unavailable);
    }
    admin_audit(
        &mut command.tx,
        user,
        headers,
        if emergency {
            "OIDC_REVOKE_KEY"
        } else {
            "OIDC_RETIRE_KEY"
        },
        &json!({"kid":kid}).to_string(),
    )
    .await?;
    Ok(Json(
        command
            .commit(json!({"kid":kid,"status":if emergency{"REVOKED"}else{"RETIRED"}}))
            .await?,
    ))
}

/// The key row stays locked until the token transaction commits. Retirement
/// cannot miss a token whose signature has been prepared but not yet returned.
pub(super) async fn sign(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claims: Value,
    expires: DateTime<Utc>,
) -> Result<String> {
    sign_typed(state, tx, claims, expires, "JWT").await
}

pub(super) async fn sign_typed(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claims: Value,
    expires: DateTime<Utc>,
    token_type: &'static str,
) -> Result<String> {
    let configured = configured(state)?;
    let row:Option<(String,String,String)>=sqlx::query_as(
        "SELECT kid,n,e FROM auth_signing_keys WHERE active AND revoked_at IS NULL AND retired_at IS NULL FOR UPDATE")
        .fetch_optional(&mut **tx).await.map_err(|_|AppError::Unavailable)?;
    let (kid, n, e) = row.ok_or(AppError::Unavailable)?;
    let material = configured
        .material(&kid)
        .filter(|key| key.n == n && key.e == e)
        .ok_or(AppError::Unavailable)?;
    let encoding = material.encoding.clone();
    let signing_kid = kid.clone();
    let token = tokio::task::spawn_blocking(move || {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(signing_kid);
        header.typ = Some(token_type.to_owned());
        jsonwebtoken::encode(&header, &claims, &encoding)
    })
    .await
    .map_err(|_| AppError::Unavailable)?
    .map_err(|_| AppError::Unavailable)?;
    let recorded=sqlx::query("UPDATE auth_signing_keys SET last_signed_exp=GREATEST(COALESCE(last_signed_exp,$2),$2) WHERE kid=$1")
        .bind(kid).bind(expires).execute(&mut **tx).await?;
    if recorded.rows_affected() != 1 {
        return Err(AppError::Unavailable.into());
    }
    Ok(token)
}
