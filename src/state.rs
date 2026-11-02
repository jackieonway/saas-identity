use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub(crate) struct IdentityState {
    pub(crate) pool: sqlx::PgPool,
    pub(crate) config: Arc<crate::config::Config>,
    pub(crate) passwords: crate::password::PasswordService,
    pub(crate) authentication: Arc<dyn crate::platform_accounts::AuthenticationPort>,
    pub(crate) accounts: Arc<dyn crate::platform_accounts::AccountAdministrationPort>,
    pub(crate) login_limits: Arc<crate::login_limits::LoginLimits>,
    pub(crate) auth_limits: Arc<crate::login_limits::LoginLimits>,
    pub(crate) auth_slots: Arc<tokio::sync::Semaphore>,
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
            auth_limits: Arc::new(crate::login_limits::LoginLimits::new(
                crate::login_limits::LoginLimitOptions {
                    max_entries: config.auth_rate_max_entries,
                    ttl: Duration::from_secs(config.auth_rate_window_seconds),
                    source_limit: config.auth_source_requests,
                    user_failure_limit: config.auth_client_requests,
                },
            )),
            auth_slots: Arc::new(tokio::sync::Semaphore::new(config.auth_request_concurrency)),
            config,
            internal_slots: Arc::new(tokio::sync::Semaphore::new(16)),
        }
    }

    pub(crate) fn admit_protocol_client(&self, client: &str) -> Result<(), crate::error::AppError> {
        match self.auth_limits.record_failure(client) {
            Some(retry) => Err(crate::error::AppError::RateLimited(retry)),
            None => Ok(()),
        }
    }
}
