use super::{Outcome, Stage};
use std::{
    collections::BTreeMap,
    fmt::Write,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
};

// All labels come from these arrays. Unlisted templates, paths, methods and
// response codes collapse into fixed labels instead of growing cardinality.
pub(super) const ROUTES: &[&str] = &[
    "other",
    "/api/sso/preauth",
    "/api/sso/login",
    "/api/sso/logout",
    "/api/sso/password",
    "/api/sso/session",
    "/api/sso/mfa/step-up",
    "/api/sso/mfa/enrollment",
    "/api/sso/mfa/enrollment/confirm",
    "/api/sso/mfa/disable",
    "/api/sso/consents",
    "/api/sso/consents/{consent}/revoke",
    "/api/sso/invitations/{id}/accept",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/userinfo",
    "/oauth/introspect",
    "/oauth/revoke",
    "/oauth/logout",
    "/oauth/logout/operations/{operation}",
    "/internal/identity/auth/resource-access-proof",
    "/internal/identity/auth/customer-account-proof",
    "/internal/identity/auth/clients",
    "/internal/identity/auth/invitations",
    "/internal/identity/auth/context-selection/source",
    "/healthz",
    "/readyz",
    "/health",
    "/ready",
    "/health/ready",
];
const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "other"];
const STATUSES: [u16; 34] = [
    0, 1, 2, 3, 4, 5, 600, 200, 201, 202, 204, 301, 302, 303, 304, 307, 308, 400, 401, 403, 404,
    405, 408, 409, 410, 413, 415, 422, 428, 429, 500, 502, 503, 504,
];
const BUCKETS: [f64; 13] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0,
];
pub(super) const REQUEST_SERIES_LIMIT: usize = ROUTES.len() * METHODS.len() * STATUSES.len();
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
static AUDIT_FAILURES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Default)]
pub(super) struct Histogram {
    count: u64,
    sum: f64,
    buckets: [u64; 13],
}
impl Histogram {
    fn record(&mut self, seconds: f64) {
        self.count = self.count.saturating_add(1);
        self.sum += seconds;
        for (bound, count) in BUCKETS.iter().zip(&mut self.buckets) {
            if seconds <= *bound {
                *count = count.saturating_add(1);
            }
        }
    }
    fn render(&self, output: &mut String, name: &str, labels: &str) {
        for (bound, count) in BUCKETS.iter().zip(self.buckets) {
            let _ = writeln!(output, "{name}_bucket{{{labels},le=\"{bound}\"}} {count}");
        }
        let _ = writeln!(
            output,
            "{name}_bucket{{{labels},le=\"+Inf\"}} {}",
            self.count
        );
        let _ = writeln!(output, "{name}_count{{{labels}}} {}", self.count);
        let _ = writeln!(output, "{name}_sum{{{labels}}} {}", self.sum);
    }
}

#[derive(Clone, Default)]
pub(super) struct Registry {
    requests: BTreeMap<(usize, usize, usize), Histogram>,
    stages: [[Histogram; 6]; 3],
}
pub(super) fn route(template: Option<&str>) -> usize {
    template
        .and_then(|template| ROUTES.iter().position(|known| *known == template))
        .unwrap_or(0)
}
pub(super) fn method(raw: &str) -> usize {
    METHODS
        .iter()
        .position(|known| *known == raw)
        .unwrap_or(METHODS.len() - 1)
}
fn status(raw: Option<u16>) -> usize {
    let Some(raw) = raw else {
        return 0;
    };
    STATUSES
        .iter()
        .position(|known| *known == raw)
        .or_else(|| STATUSES.iter().position(|known| *known == raw / 100))
        .unwrap_or(6)
}
fn response_outcome(status: u16) -> Outcome {
    match status {
        0 => Outcome::Cancelled,
        408 | 504 => Outcome::Timeout,
        429 => Outcome::Saturated,
        4 | 400..=499 => Outcome::Denied,
        5 | 500..=600 => Outcome::Failed,
        _ => Outcome::Ok,
    }
}
impl Registry {
    pub(super) fn request(&mut self, route: usize, method: usize, code: Option<u16>, seconds: f64) {
        if route >= ROUTES.len() || method >= METHODS.len() || !seconds.is_finite() || seconds < 0.0
        {
            return;
        }
        let key = (route, method, status(code));
        if self.requests.len() < REQUEST_SERIES_LIMIT || self.requests.contains_key(&key) {
            self.requests.entry(key).or_default().record(seconds);
        }
    }
    pub(super) fn render(&self) -> String {
        let mut output = String::from("# TYPE identity_http_requests_total counter\n# TYPE identity_http_request_duration_seconds histogram\n");
        for ((route, method, status), histogram) in &self.requests {
            let code = STATUSES[*status];
            let label = match code {
                0 => "cancelled".to_owned(),
                600 => "other".to_owned(),
                1..=5 => format!("{code}xx"),
                _ => code.to_string(),
            };
            let labels = format!(
                "route=\"{}\",method=\"{}\",status=\"{label}\",outcome=\"{}\"",
                ROUTES[*route],
                METHODS[*method],
                response_outcome(code).label()
            );
            let _ = writeln!(
                output,
                "identity_http_requests_total{{{labels}}} {}",
                histogram.count
            );
            histogram.render(
                &mut output,
                "identity_http_request_duration_seconds",
                &labels,
            );
        }
        output.push_str("# TYPE identity_password_stage_duration_seconds histogram\n");
        for stage in Stage::ALL {
            for outcome in Outcome::ALL {
                self.stages[stage.index()][outcome.index()].render(
                    &mut output,
                    "identity_password_stage_duration_seconds",
                    &format!(
                        "stage=\"{}\",outcome=\"{}\"",
                        stage.label(),
                        outcome.label()
                    ),
                );
            }
        }
        output
    }
}
fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}
pub(super) fn request(route: usize, method: usize, status: Option<u16>, seconds: f64) {
    registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .request(route, method, status, seconds);
}
pub(super) fn stage(stage: Stage, outcome: Outcome, seconds: f64) {
    registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .stages[stage.index()][outcome.index()]
    .record(seconds);
}
pub(super) fn audit_failure() {
    let _ = AUDIT_FAILURES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(1))
    });
}
pub(super) fn render() -> String {
    let snapshot = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let mut output = snapshot.render();
    let _ = writeln!(output, "# TYPE identity_audit_write_failures_total counter\nidentity_audit_write_failures_total {}", AUDIT_FAILURES.load(Ordering::Relaxed));
    output
}
