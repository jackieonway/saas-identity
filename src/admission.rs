//! Admission precedes authority work; proxy identity comes from the socket.
use crate::{network::Peer, state::AppState};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request, State},
    http::{header::HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

fn bounded_error(
    oauth: bool,
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    retry: Option<u64>,
) -> Response {
    let payload = if oauth {
        json!({"error":if status==StatusCode::TOO_MANY_REQUESTS{"temporarily_unavailable"}else{"invalid_request"},"error_description":message})
    } else {
        json!({"code":code,"message":message})
    };
    let mut response = (status, Json(payload)).into_response();
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    if let Some(retry) = retry {
        if let Ok(value) = HeaderValue::from_str(&retry.to_string()) {
            response.headers_mut().insert("retry-after", value);
        }
    }
    response
}

pub(crate) async fn source(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<Peer>>()
        .map(|info| info.0 .0.ip().to_canonical());
    let trusted = peer.is_some_and(|ip| state.config.trusted_proxy_ips.contains(&ip));
    let forwarded = if trusted && request.headers().get_all("x-real-ip").iter().count() == 1 {
        request
            .headers()
            .get("x-real-ip")
            .and_then(|raw| raw.to_str().ok())
            .and_then(|raw| raw.parse::<std::net::IpAddr>().ok())
            .map(|ip| ip.to_canonical())
    } else {
        None
    };
    let selected = forwarded
        .or(peer)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    for name in [
        "x-real-ip",
        "x-forwarded-for",
        "forwarded",
        "x-forwarded-proto",
    ] {
        request.headers_mut().remove(name);
    }
    if let Ok(value) = HeaderValue::from_str(&selected) {
        request.headers_mut().insert("x-real-ip", value);
    }
    next.run(request).await
}

pub(crate) async fn bounded(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let oauth = path.starts_with("/oauth/") || path == "/.well-known/openid-configuration";
    if !(path.starts_with("/oauth/")
        || path.starts_with("/api/sso/")
        || path == "/.well-known/openid-configuration")
    {
        return next.run(request).await;
    }
    let _permit = match state.auth_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return bounded_error(
                oauth,
                StatusCode::TOO_MANY_REQUESTS,
                "TOO_MANY_REQUESTS",
                "Authentication request capacity exceeded",
                Some(1),
            )
        }
    };
    if let Some(retry) = state
        .auth_limits
        .admit_source(&crate::util::audit::client_ip(request.headers()))
    {
        return bounded_error(
            oauth,
            StatusCode::TOO_MANY_REQUESTS,
            "TOO_MANY_REQUESTS",
            "Authentication request rate limit exceeded",
            Some(retry),
        );
    }
    // Only ingress buffering is timed. No authorization future is cancelled
    // after it can have committed an operation with an unknown transport result.
    let request = if matches!(
        *request.method(),
        axum::http::Method::POST
            | axum::http::Method::PATCH
            | axum::http::Method::PUT
            | axum::http::Method::DELETE
    ) {
        let (parts, body) = request.into_parts();
        match tokio::time::timeout(
            std::time::Duration::from_millis(state.config.auth_body_timeout_ms),
            to_bytes(body, 32768),
        )
        .await
        {
            Ok(Ok(body)) => Request::from_parts(parts, Body::from(body)),
            Ok(Err(_)) => {
                return bounded_error(
                    oauth,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "REQUEST_BODY_REJECTED",
                    "Authentication body rejected or too large",
                    None,
                )
            }
            Err(_) => {
                return bounded_error(
                    oauth,
                    StatusCode::REQUEST_TIMEOUT,
                    "REQUEST_BODY_TIMEOUT",
                    "Authentication body read deadline exceeded",
                    None,
                )
            }
        }
    } else {
        request
    };
    next.run(request).await
}

#[cfg(test)]
mod tests;
