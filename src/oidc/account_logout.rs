//! Authenticated account-wide logout extension for confidential clients.
//!
//! This is a back-channel command, not an OIDC end-session endpoint. A receipt
//! records a committed command so an uncertain HTTP outcome can be retried
//! without adopting another session or elevating the account generation again.

use super::{clients, invalid, invalid_grant, protocol, store, tokens, OidcError, Result};
use crate::{
    authentication::PostgresAccountTransaction, error::AppError, state::AppState, util::audit,
};
use axum::{
    extract::{RawForm, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct Receipt {
    client_id: Uuid,
    grant_id: Uuid,
    user_id: Uuid,
    token_hash: String,
    account_version: i64,
}

async fn receipt<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    request: Uuid,
) -> Result<Option<Receipt>> {
    sqlx::query_as("SELECT client_id,grant_id,user_id,token_hash,account_version FROM oidc_account_logout_receipts WHERE id=$1")
        .bind(request)
        .fetch_optional(executor)
        .await
        .map_err(|_| AppError::Unavailable.into())
}

fn same_client(current: &clients::Client, authenticated: &clients::Client) -> Result<()> {
    if current.id != authenticated.id
        || current.status != "ENABLED"
        || current.access_policy_version != authenticated.access_policy_version
        || !super::equal(&current.secret_hash, &authenticated.secret_hash)
    {
        return Err(OidcError::InvalidClient);
    }
    Ok(())
}

pub(super) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: RawQuery,
    body: RawForm,
) -> Result<Response> {
    super::authority(&state).await?;
    tokens::admission(&state, &headers)?;
    let parameters = protocol::form(body, query)?;
    let client = clients::authenticate(&state, &headers, &parameters).await?;
    if parameters
        .keys()
        .any(|key| !matches!(key.as_str(), "token" | "request_id" | "client_id"))
    {
        return Err(invalid());
    }
    let token = protocol::required(&parameters, "token")?;
    let request = clients::canonical_id(protocol::required(&parameters, "request_id")?)?;
    if !super::canonical_secret(token) {
        return Err(invalid_grant());
    }
    let hash = super::digest(token);
    let original = match tokens::live(&state.pool, &hash, false).await? {
        Some(proof) => Some((proof, false)),
        None => tokens::live(&state.pool, &hash, true)
            .await?
            .map(|proof| (proof, true)),
    };
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::Unavailable)?;
    // Serialize one request ID across processes before reading its receipt.
    // The namespace is separate from admission locks. Hash collisions merely
    // serialize unrelated commands; receipt identity still uses the full UUID.
    sqlx::query("SELECT pg_advisory_xact_lock(1869562732,hashtext($1))")
        .bind(request.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::Unavailable)?;
    if let Some(committed) = receipt(&mut *tx, request).await? {
        if committed.client_id != client.id || !super::equal(&committed.token_hash, &hash) {
            return Err(invalid());
        }
        // A receipt proves the earlier commit, including its now-revoked token.
        // Reauthenticate the client under the same user -> client -> grant lock
        // order, without requiring the generation this command itself retired.
        store::lock_user(&mut tx, committed.user_id).await?;
        let current_client = clients::load(&mut *tx, client.id, true)
            .await?
            .ok_or(OidcError::InvalidClient)?;
        same_client(&current_client, &client)?;
        let grant = store::grant(&mut *tx, committed.grant_id, true)
            .await?
            .ok_or_else(invalid_grant)?;
        if grant.client_id != committed.client_id
            || grant.user_id != committed.user_id
            || grant.account_version != committed.account_version
        {
            return Err(invalid());
        }
        tx.commit().await?;
        return Ok(StatusCode::OK.into_response());
    }

    let (original, refresh) = original.ok_or_else(invalid_grant)?;
    if original.client_id != client.id {
        return Err(invalid_grant());
    }
    store::lock_user(&mut tx, original.user_id).await?;
    let current_client = clients::load(&mut *tx, client.id, true)
        .await?
        .ok_or(OidcError::InvalidClient)?;
    same_client(&current_client, &client)?;
    let grant = store::grant(&mut *tx, original.grant_id, true)
        .await?
        .ok_or_else(invalid_grant)?;
    store::valid_grant(&grant, &current_client)?;
    // A new statement after every authority lock sees committed changes made
    // while waiting. Keep the original token kind, sid and generations rather
    // than turning a stale proof into the account's newest authentication.
    let current = tokens::live(&mut *tx, &hash, refresh)
        .await?
        .ok_or_else(invalid_grant)?;
    if current.grant_id != original.grant_id
        || current.session_id != original.session_id
        || current.user_id != original.user_id
        || current.client_id != original.client_id
        || current.client_id != client.id
        || current.account_version != original.account_version
        || current.client_policy_version != original.client_policy_version
        || current.client_policy_version != client.access_policy_version
        || current.auth_time != original.auth_time
    {
        return Err(invalid_grant());
    }
    let session = store::session(
        &mut *tx,
        original.session_id,
        original.user_id,
        original.account_version,
    )
    .await?;
    let deadline = original
        .expires_at
        .min(current.expires_at)
        .min(session.expires_at)
        .min(grant.expires_at);
    let revoked = {
        let mut accounts = PostgresAccountTransaction::new(&mut tx);
        state
            .accounts
            .revoke_all(&mut accounts, original.user_id)
            .await?
    };
    audit::write_in_tx(
        &mut tx,
        audit::AuditInfo {
            user_id: Some(session.user_id),
            username: &session.username,
            action: "OIDC_ACCOUNT_LOGOUT",
            detail: &serde_json::json!({
                "clientId":client.id,"grantId":grant.id,"requestId":request,
                "scope":"OIDC_ACCOUNT","globalLogout":true,
                "beforeVersion":original.account_version.to_string(),"revokedSessions":revoked
            })
            .to_string(),
            ip: &audit::client_ip(&headers),
            user_agent: &audit::ua_of(&headers),
        },
    )
    .await?;
    sqlx::query("INSERT INTO oidc_account_logout_receipts(id,client_id,grant_id,user_id,token_hash,account_version,created_at) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp())")
        .bind(request).bind(client.id).bind(grant.id).bind(original.user_id)
        .bind(&hash).bind(original.account_version).execute(&mut *tx).await?;
    // Our own revocation made the live query false. Check the earliest original
    // deadline instead, so an audit/credential wait cannot outlive authorization.
    super::deadline(&mut tx, deadline).await?;
    tx.commit().await?;
    Ok(StatusCode::OK.into_response())
}
