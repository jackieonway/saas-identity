//! Account-only SSO authentication. Cookies never establish platform authority.

mod routes;
mod store;

pub(crate) use routes::routes;

/// Narrow, account-only proof consumed by the OIDC provider. No Cookie secret or
/// membership authority crosses this boundary.
#[derive(Clone)]
pub(crate) struct AccountSessionProof {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub account_version: i64,
    pub authenticated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub username: String,
    pub real_name: String,
    pub avatar: String,
}

pub(crate) fn opaque_secret() -> Result<String, AppError> {
    secret()
}

pub(crate) fn browser_origin(
    state: &AppState,
    headers: &HeaderMap,
    read: bool,
) -> Result<(), AppError> {
    origin(state, headers, read)
}

pub(crate) async fn browser_proof(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AccountSessionProof>, AppError> {
    let parsed = cookies(headers)?;
    let Some(cookie) = parsed.session else {
        return Ok(None);
    };
    match store::session(&state.pool, &digest(cookie)).await {
        Ok(session) => Ok(Some(AccountSessionProof {
            id: session.id,
            user_id: session.user_id,
            account_version: session.account_version,
            authenticated_at: session.authenticated_at,
            expires_at: session.expires_at,
            username: session.username,
            real_name: session.real_name,
            avatar: session.avatar,
        })),
        Err(AppError::Unauthorized(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

use axum::http::{header, HeaderMap};
use rand::RngCore;

use crate::{error::AppError, state::AppState};

const SESSION_COOKIE: &str = "__Host-saas_sso";
const PREAUTH_COOKIE: &str = "__Host-saas_sso_preauth";

fn secret() -> Result<String, AppError> {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AppError::Unavailable)?;
    Ok(hex::encode(bytes))
}

fn digest(value: &str) -> String {
    crate::util::hash::sha256_hex(value)
}

fn session_csrf(cookie: &str) -> String {
    digest(&format!("sso-session-csrf-v1:{cookie}"))
}

fn canonical_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn constant_equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |different, (left, right)| different | (left ^ right))
            == 0
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, AppError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(AppError::forbidden("认证请求头重复"));
    }
    value
        .map(|value| {
            value
                .to_str()
                .map_err(|_| AppError::forbidden("认证请求头无效"))
        })
        .transpose()
}

fn origin(state: &AppState, headers: &HeaderMap, read: bool) -> Result<(), AppError> {
    if !state.config.sso_enabled {
        return Err(AppError::not_found("统一账号认证未启用"));
    }
    let expected = state
        .config
        .sso_origin
        .as_deref()
        .ok_or(AppError::Unavailable)?;
    match unique_header(headers, "origin")? {
        Some(value) if value == expected => {}
        None if read => {
            // Browsers omit Origin on same-origin GET. Fetch metadata plus the
            // exact configured authority gives a narrow, browser-owned fallback.
            if unique_header(headers, "sec-fetch-site")? != Some("same-origin")
                || !unique_header(headers, "host")?.is_some_and(|host| {
                    host.eq_ignore_ascii_case(expected.strip_prefix("https://").unwrap_or(""))
                })
            {
                return Err(AppError::forbidden("认证请求来源无效"));
            }
        }
        _ => return Err(AppError::forbidden("认证请求来源无效")),
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(AppError::unauthorized("此入口只接受认证 Cookie"));
    }
    Ok(())
}

struct Cookies<'a> {
    session: Option<&'a str>,
    preauth: Option<&'a str>,
}

fn cookies(headers: &HeaderMap) -> Result<Cookies<'_>, AppError> {
    let mut parsed = Cookies {
        session: None,
        preauth: None,
    };
    for header in headers.get_all(header::COOKIE).iter() {
        let header = header
            .to_str()
            .map_err(|_| AppError::unauthorized("认证 Cookie 无效"))?;
        for pair in header.split(';') {
            let (name, value) = pair
                .trim()
                .split_once('=')
                .ok_or_else(|| AppError::unauthorized("认证 Cookie 无效"))?;
            let slot = match name {
                SESSION_COOKIE => &mut parsed.session,
                PREAUTH_COOKIE => &mut parsed.preauth,
                _ => continue,
            };
            if slot.is_some() || !canonical_secret(value) {
                return Err(AppError::unauthorized("认证 Cookie 无效"));
            }
            *slot = Some(value);
        }
    }
    Ok(parsed)
}

fn csrf_header(headers: &HeaderMap) -> Result<&str, AppError> {
    unique_header(headers, "x-csrf-token")?
        .filter(|value| canonical_secret(value))
        .ok_or_else(|| AppError::forbidden("认证 CSRF 证明无效"))
}

fn cookie(name: &str, token: &str, max_age: i64) -> String {
    format!("{name}={token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}")
}

fn expired_cookie(name: &str) -> String {
    cookie(name, "", 0)
}
