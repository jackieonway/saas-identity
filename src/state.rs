use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(crate) struct IdentityState {
    pub(crate) pool: sqlx::PgPool,
    pub(crate) config: Arc<crate::config::Config>,
    pub(crate) passwords: crate::password::PasswordService,
    pub(crate) authentication: Arc<dyn crate::platform_accounts::AuthenticationPort>,
    pub(crate) accounts: Arc<dyn crate::platform_accounts::AccountAdministrationPort>,
    pub(crate) login_limits: Arc<crate::login_limits::LoginLimits>,
    introspection_attempts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    pub(crate) internal_slots: Arc<tokio::sync::Semaphore>,
    pub(crate) context_platform: Arc<dyn crate::oidc::context::bridge::SelectionPort>,
    pub(crate) context_slots: Arc<tokio::sync::Semaphore>,
}

// Local protocol modules retain a short state alias; it contains only authority
// capabilities and has no dependency on the platform application state.
pub(crate) type AppState = IdentityState;

impl IdentityState {
    pub(crate) fn new(pool: sqlx::PgPool, config: Arc<crate::config::Config>) -> Self {
        let passwords = crate::password::PasswordService::new(
            config.password_concurrency,
            config.password_queue_capacity,
            Duration::from_millis(config.password_queue_timeout_ms),
            Duration::from_millis(config.password_execution_timeout_ms),
        );
        let (authentication, accounts) =
            crate::authentication::new(pool.clone(), passwords.clone(), config.clone());
        Self {
            context_platform: crate::oidc::context::bridge::configured(
                config.context_platform.clone(),
            ),
            context_slots: Arc::new(tokio::sync::Semaphore::new(16)),
            pool,
            authentication,
            accounts,
            passwords,
            login_limits: Arc::new(crate::login_limits::LoginLimits::new(
                crate::login_limits::LoginLimitOptions {
                    max_entries: config.login_max_entries,
                    ttl: Duration::from_secs(config.login_window_seconds),
                    source_limit: config.login_source_requests,
                    user_failure_limit: config.login_user_failures,
                },
            )),
            config,
            introspection_attempts: Arc::new(Mutex::new(HashMap::new())),
            internal_slots: Arc::new(tokio::sync::Semaphore::new(16)),
        }
    }

    pub(crate) fn record_introspection_attempt(&self, key: &str) -> Option<i64> {
        let now = Instant::now();
        let Ok(mut map) = self.introspection_attempts.lock() else {
            return Some(60);
        };
        if map.len() >= 4096 && !map.contains_key(key) {
            map.retain(|_, entries| {
                entries
                    .iter()
                    .any(|old| now.duration_since(*old) < Duration::from_secs(60))
            });
            if map.len() >= 4096 {
                return Some(60);
            }
        }
        let entries = map.entry(key.to_owned()).or_default();
        entries.retain(|old| now.duration_since(*old) < Duration::from_secs(60));
        if entries.len() >= self.config.oauth_introspection_attempts_per_minute {
            Some(1)
        } else {
            entries.push(now);
            None
        }
    }
}
