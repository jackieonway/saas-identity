use super::registry;
use crate::{error::AppError, state::AppState};
use axum::{
    extract::{MatchedPath, RawQuery, Request, State},
    http::{header, HeaderMap, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use sqlx::Acquire;
use std::{
    fmt::Write,
    time::{Duration, Instant},
};

const PATH: &str = "/internal/identity/metrics";
const KINDS: [&str; 3] = ["LOGOUT", "INVITATION", "SECURITY"];
const STATES: [&str; 6] = [
    "PENDING",
    "LEASED",
    "DELIVERED",
    "TERMINAL",
    "DEGRADED",
    "EXPANDED",
];
const SOURCE_KINDS: [&str; 2] = ["CONSENT", "SECURITY"];

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route(PATH, get(metrics))
}

struct RequestTimer {
    route: usize,
    method: usize,
    started: Instant,
    status: Option<u16>,
}
impl Drop for RequestTimer {
    fn drop(&mut self) {
        registry::request(
            self.route,
            self.method,
            self.status,
            self.started.elapsed().as_secs_f64(),
        );
    }
}

pub(crate) async fn observe_request(
    State(_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let template = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    // Scrapes do not count themselves. Never inspect a URI, query, header or
    // body here; only the router-supplied template and fixed method labels.
    if template == Some(PATH) {
        return next.run(request).await;
    }
    let mut timer = RequestTimer {
        route: registry::route(template),
        method: registry::method(request.method().as_str()),
        started: Instant::now(),
        status: None,
    };
    let response = next.run(request).await;
    timer.status = Some(response.status().as_u16());
    response
}

fn authorize(state: &AppState, headers: &HeaderMap, query: RawQuery) -> Result<(), AppError> {
    if !state.config.telemetry.enabled() {
        return Err(AppError::not_found("运行指标未启用"));
    }
    if headers.contains_key(header::COOKIE) || query.0.is_some() {
        return Err(AppError::bad_request("指标入口不接受Cookie或查询参数"));
    }
    let mut credentials = headers.get_all(header::AUTHORIZATION).iter();
    let supplied = credentials
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if credentials.next().is_some()
        || !supplied.is_some_and(|token| state.config.telemetry.accepts(token))
    {
        return Err(AppError::unauthorized("运行指标需要独立运维凭据"));
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct JobObservation {
    kind: String,
    state: String,
    jobs: i64,
    pending_age: f64,
    expired_leases: i64,
}
#[derive(sqlx::FromRow)]
struct SourceObservation {
    kind: String,
    state: String,
    events: i64,
}
#[derive(Default)]
struct DatabaseObservation {
    database_up: bool,
    delivery: Option<(Vec<JobObservation>, Vec<SourceObservation>)>,
}

async fn database(state: &AppState) -> DatabaseObservation {
    let mut result = DatabaseObservation::default();
    // One acquisition and one aggregate deadline cover the entire observation.
    // An unhealthy observation never invents an empty queue or touches facts.
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        let mut connection = state.pool.acquire().await?;
        let mut tx = connection.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await?;
        sqlx::query("SET LOCAL statement_timeout='400ms'").execute(&mut *tx).await?;
        sqlx::query("SET LOCAL lock_timeout='250ms'").execute(&mut *tx).await?;
        let ping: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&mut *tx).await?;
        result.database_up = ping == 1;
        let jobs: Vec<JobObservation> = sqlx::query_as(
            "SELECT kind,state,count(*)::bigint AS jobs, \
             COALESCE(max(GREATEST(extract(epoch FROM clock_timestamp()-created_at),0)) FILTER(WHERE state='PENDING'),0)::float8 AS pending_age, \
             count(*) FILTER(WHERE state='LEASED' AND lease_until<=clock_timestamp())::bigint AS expired_leases \
             FROM public.auth_delivery_jobs GROUP BY kind,state")
            .fetch_all(&mut *tx).await?;
        let sources: Vec<SourceObservation> = sqlx::query_as(
            "SELECT 'CONSENT'::text AS kind,delivery_state AS state,count(*)::bigint AS events FROM public.auth_consent_revocation_outbox GROUP BY delivery_state \
             UNION ALL SELECT 'SECURITY'::text,delivery_state,count(*)::bigint FROM public.auth_security_notification_outbox GROUP BY delivery_state")
            .fetch_all(&mut *tx).await?;
        tx.commit().await?;
        if jobs.iter().all(|row| KINDS.contains(&row.kind.as_str()) && STATES[..5].contains(&row.state.as_str()) && row.jobs >= 0 && row.pending_age.is_finite() && row.pending_age >= 0.0 && row.expired_leases >= 0)
            && sources.iter().all(|row| SOURCE_KINDS.contains(&row.kind.as_str()) && STATES.contains(&row.state.as_str()) && row.events >= 0) {
            result.delivery = Some((jobs, sources));
        }
        Ok::<(), sqlx::Error>(())
    }).await;
    result
}

fn gauge(output: &mut String, name: &str, value: impl std::fmt::Display) {
    let _ = writeln!(output, "# TYPE {name} gauge\n{name} {value}");
}

fn render(state: &AppState, observation: DatabaseObservation) -> String {
    let mut output = registry::render();
    gauge(&mut output, "identity_service_up", 1);
    gauge(
        &mut output,
        "identity_tcp_connections",
        crate::network::active_connections(),
    );
    gauge(
        &mut output,
        "identity_tcp_connection_limit",
        state.config.maximum_connections,
    );
    gauge(
        &mut output,
        "identity_tcp_idle_timeout_seconds",
        state.config.connection_idle_timeout_ms as f64 / 1000.0,
    );
    gauge(
        &mut output,
        "identity_database_up",
        u8::from(observation.database_up),
    );
    gauge(
        &mut output,
        "identity_delivery_observation_up",
        u8::from(observation.delivery.is_some()),
    );
    gauge(&mut output, "identity_db_pool_size", state.pool.size());
    gauge(&mut output, "identity_db_pool_idle", state.pool.num_idle());
    gauge(
        &mut output,
        "identity_db_pool_capacity",
        state.pool.options().get_max_connections(),
    );
    let (running, queued) = state.passwords.operational_counts();
    gauge(&mut output, "identity_password_running", running);
    gauge(&mut output, "identity_password_queued", queued);
    gauge(
        &mut output,
        "identity_password_concurrency",
        state.config.password_concurrency,
    );
    gauge(
        &mut output,
        "identity_password_queue_capacity",
        state.config.password_queue_capacity,
    );
    if let Some((jobs, sources)) = observation.delivery {
        output.push_str("# TYPE identity_delivery_jobs gauge\n# TYPE identity_delivery_oldest_pending_seconds gauge\n# TYPE identity_delivery_expired_leases gauge\n# TYPE identity_delivery_source_events gauge\n");
        for kind in KINDS {
            for status in &STATES[..5] {
                let count = jobs
                    .iter()
                    .find(|row| row.kind == kind && row.state == *status)
                    .map_or(0, |row| row.jobs);
                let _ = writeln!(
                    output,
                    "identity_delivery_jobs{{kind=\"{kind}\",state=\"{status}\"}} {count}"
                );
            }
            let age = jobs
                .iter()
                .filter(|row| row.kind == kind)
                .fold(0.0_f64, |age, row| age.max(row.pending_age));
            let expired: i64 = jobs
                .iter()
                .filter(|row| row.kind == kind)
                .map(|row| row.expired_leases)
                .sum();
            let _ = writeln!(output, "identity_delivery_oldest_pending_seconds{{kind=\"{kind}\"}} {age}\nidentity_delivery_expired_leases{{kind=\"{kind}\"}} {expired}");
        }
        for kind in SOURCE_KINDS {
            for status in STATES.iter().filter(|status| **status != "LEASED") {
                let count = sources
                    .iter()
                    .find(|row| row.kind == kind && row.state == *status)
                    .map_or(0, |row| row.events);
                let _ = writeln!(
                    output,
                    "identity_delivery_source_events{{kind=\"{kind}\",state=\"{status}\"}} {count}"
                );
            }
        }
    }
    output
}

async fn metrics(State(state): State<AppState>, headers: HeaderMap, query: RawQuery) -> Response {
    let mut response = match authorize(&state, &headers, query) {
        Err(error) => error.into_response(),
        Ok(()) => {
            let observation = database(&state).await;
            (
                [(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                render(&state, observation),
            )
                .into_response()
        }
    };
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
    response
}
