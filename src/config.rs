use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

const ISSUER: &str = "https://auth.saas.test";

/// Identity runtime configuration intentionally does not implement Debug.
#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) app_env: String,
    pub(crate) database_url: String,
    pub(crate) bind_addr: String,
    pub(crate) sso_enabled: bool,
    pub(crate) sso_origin: Option<String>,
    pub(crate) sso_session_ttl_seconds: i64,
    pub(crate) sso_preauth_ttl_seconds: i64,
    pub(crate) oidc_enabled: bool,
    pub(crate) oidc_issuer: Option<String>,
    pub(crate) oidc_keys: Option<Arc<crate::oidc::KeySet>>,
    pub(crate) oidc_code_ttl_seconds: i64,
    pub(crate) oidc_token_ttl_seconds: i64,
    pub(crate) oidc_refresh_ttl_seconds: i64,
    pub(crate) oidc_interaction_ttl_seconds: i64,
    pub(crate) password_concurrency: usize,
    pub(crate) password_queue_capacity: usize,
    pub(crate) password_queue_timeout_ms: u64,
    pub(crate) password_execution_timeout_ms: u64,
    pub(crate) login_max_entries: usize,
    pub(crate) login_window_seconds: u64,
    pub(crate) login_source_requests: u32,
    pub(crate) login_user_failures: u32,
    pub(crate) login_identifier_max_bytes: usize,
    pub(crate) login_verify_budget_ms: u64,
    pub(crate) oauth_introspection_attempts_per_minute: usize,
    pub(crate) service_expected_customer_client: Option<uuid::Uuid>,
    pub(crate) context_platform: Option<Arc<crate::oidc::context::bridge::Settings>>,
    pub(crate) context_cipher: Option<Arc<crate::oidc::context::crypto::Keys>>,
}

impl Config {
    /// Only explicit process environment is read; this service never loads .env.
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let values = std::env::vars_os()
            .map(|(key, value)| {
                let invalid = || anyhow::anyhow!("CONFIGURATION_VALUES_MUST_BE_UTF8");
                Ok((
                    key.into_string().map_err(|_| invalid())?,
                    value.into_string().map_err(|_| invalid())?,
                ))
            })
            .collect::<anyhow::Result<HashMap<_, _>>>()?;
        Self::from_values(&values)
    }

    pub(crate) fn from_values(env: &HashMap<String, String>) -> anyhow::Result<Self> {
        let app_env = value(env, "APP_ENV", "development");
        anyhow::ensure!(
            matches!(app_env.as_str(), "development" | "test" | "production"),
            "APP_ENV must be development, test, or production"
        );
        let database_url = required(env, "DATABASE_URL")?;
        validate_database_url(&database_url)?;
        let bind_addr = value(env, "BIND_ADDR", "0.0.0.0:3041");
        anyhow::ensure!(
            bind_addr.parse::<SocketAddr>().is_ok(),
            "BIND_ADDR must be an IP socket address"
        );
        let sso_enabled = boolean(env, "SSO_ENABLED", false)?;
        let oidc_enabled = boolean(env, "OIDC_ENABLED", false)?;
        let sso_origin = fixed_origin(env, "SSO_ORIGIN")?;
        let oidc_issuer = fixed_origin(env, "OIDC_ISSUER")?;
        if sso_enabled {
            anyhow::ensure!(sso_origin.is_some(), "SSO_ORIGIN_REQUIRED");
        }
        if oidc_enabled {
            anyhow::ensure!(sso_enabled, "OIDC_REQUIRES_SSO");
            anyhow::ensure!(oidc_issuer.is_some(), "OIDC_ISSUER_REQUIRED");
        }
        let context_platform = crate::oidc::context::bridge::Settings::load(env)?.map(Arc::new);
        let context_cipher = optional(env, "CONTEXT_SELECTION_KEY_FILE")
            .map(|path| crate::oidc::context::crypto::Keys::load(&path))
            .transpose()?
            .map(Arc::new);
        anyhow::ensure!(
            context_platform.is_some() == context_cipher.is_some(),
            "CONTEXT_SELECTION_PLATFORM_AND_KEY_REQUIRED"
        );
        Ok(Self {
            context_platform,
            context_cipher,
            app_env,
            database_url,
            bind_addr,
            sso_enabled,
            sso_origin,
            sso_session_ttl_seconds: number(env, "SSO_SESSION_TTL_SECONDS", 43200, 1, 86400)?,
            sso_preauth_ttl_seconds: number(env, "SSO_PREAUTH_TTL_SECONDS", 300, 30, 600)?,
            oidc_enabled,
            oidc_issuer,
            oidc_keys: if oidc_enabled {
                Some(Arc::new(crate::oidc::KeySet::load(&required(
                    env,
                    "OIDC_KEYSET_PATH",
                )?)?))
            } else {
                None
            },
            oidc_code_ttl_seconds: number(env, "OIDC_CODE_TTL_SECONDS", 120, 1, 300)?,
            oidc_token_ttl_seconds: number(env, "OIDC_TOKEN_TTL_SECONDS", 300, 1, 600)?,
            oidc_refresh_ttl_seconds: number(env, "OIDC_REFRESH_TTL_SECONDS", 43200, 1, 86400)?,
            oidc_interaction_ttl_seconds: number(
                env,
                "OIDC_INTERACTION_TTL_SECONDS",
                300,
                30,
                600,
            )?,
            password_concurrency: number(env, "PASSWORD_CONCURRENCY", 2, 1, 32)? as usize,
            password_queue_capacity: number(env, "PASSWORD_QUEUE_CAPACITY", 8, 0, 1024)? as usize,
            password_queue_timeout_ms: number(env, "PASSWORD_QUEUE_TIMEOUT_MS", 250, 1, 30000)?
                as u64,
            password_execution_timeout_ms: number(
                env,
                "PASSWORD_EXECUTION_TIMEOUT_MS",
                10000,
                1,
                120000,
            )? as u64,
            login_max_entries: number(env, "LOGIN_MAX_ENTRIES", 4096, 3, 1000000)? as usize,
            login_window_seconds: number(env, "LOGIN_WINDOW_SECONDS", 600, 1, 86400)? as u64,
            login_source_requests: number(env, "LOGIN_SOURCE_REQUESTS", 60, 1, 100000)? as u32,
            login_user_failures: number(env, "LOGIN_USER_FAILURES", 5, 1, 1000)? as u32,
            login_identifier_max_bytes: number(env, "LOGIN_IDENTIFIER_MAX_BYTES", 320, 1, 1024)?
                as usize,
            login_verify_budget_ms: number(env, "LOGIN_VERIFY_BUDGET_MS", 10000, 1, 120000)? as u64,
            oauth_introspection_attempts_per_minute: number(
                env,
                "OAUTH_INTROSPECTION_ATTEMPTS_PER_MINUTE",
                3000,
                1,
                1000000,
            )? as usize,
            service_expected_customer_client: optional_v7(env, "CUSTOMER_PORTAL_OIDC_CLIENT_ID")?,
        })
    }

    pub(crate) fn is_production(&self) -> bool {
        self.app_env == "production"
    }
}

fn value(env: &HashMap<String, String>, key: &str, fallback: &str) -> String {
    optional(env, key).unwrap_or_else(|| fallback.into())
}

fn optional(env: &HashMap<String, String>, key: &str) -> Option<String> {
    env.get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
}

fn required(env: &HashMap<String, String>, key: &str) -> anyhow::Result<String> {
    optional(env, key).ok_or_else(|| anyhow::anyhow!("{key}_REQUIRED"))
}

fn fixed_origin(env: &HashMap<String, String>, key: &str) -> anyhow::Result<Option<String>> {
    let origin = optional(env, key);
    if let Some(origin) = &origin {
        anyhow::ensure!(origin == ISSUER, "{key} must equal {ISSUER}");
    }
    Ok(origin)
}

fn optional_v7(env: &HashMap<String, String>, key: &str) -> anyhow::Result<Option<uuid::Uuid>> {
    env.get(key)
        .map(|raw| {
            let id = uuid::Uuid::parse_str(raw)
                .map_err(|_| anyhow::anyhow!("{key} must be a canonical UUIDv7"))?;
            anyhow::ensure!(
                id.get_version_num() == 7
                    && id.get_variant() == uuid::Variant::RFC4122
                    && id.to_string() == *raw,
                "{key} must be a canonical UUIDv7"
            );
            Ok(id)
        })
        .transpose()
}

fn boolean(env: &HashMap<String, String>, key: &str, fallback: bool) -> anyhow::Result<bool> {
    match optional(env, key).map(|raw| raw.trim().to_ascii_lowercase()) {
        None => Ok(fallback),
        Some(raw) if matches!(raw.as_str(), "true" | "1" | "yes" | "on") => Ok(true),
        Some(raw) if matches!(raw.as_str(), "false" | "0" | "no" | "off") => Ok(false),
        _ => anyhow::bail!("{key} must be a boolean"),
    }
}

fn number(
    env: &HashMap<String, String>,
    key: &str,
    fallback: i64,
    min: i64,
    max: i64,
) -> anyhow::Result<i64> {
    let parsed = value(env, key, &fallback.to_string())
        .trim()
        .parse::<i64>()
        .map_err(|_| anyhow::anyhow!("{key} must be an integer"))?;
    anyhow::ensure!(
        (min..=max).contains(&parsed),
        "{key} is outside the supported range"
    );
    Ok(parsed)
}

fn validate_database_url(raw: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(raw)
        .map_err(|_| anyhow::anyhow!("DATABASE_URL must be an explicit PostgreSQL URL"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "postgres" | "postgresql")
            && url.host_str().is_some()
            && !url.username().is_empty()
            && url.path().len() > 1
            && !url.path()[1..].contains('/')
            && url.fragment().is_none(),
        "DATABASE_URL must specify PostgreSQL host, user, and business database"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> HashMap<String, String> {
        HashMap::from([(
            "DATABASE_URL".into(),
            "postgresql://identity_runtime@localhost/identity_task".into(),
        )])
    }

    #[test]
    fn runtime_defaults_disable_provider_and_customer_binding() {
        let config = Config::from_values(&base()).unwrap();
        assert!(!config.sso_enabled);
        assert!(!config.oidc_enabled);
        assert!(config.oidc_keys.is_none());
        assert!(config.service_expected_customer_client.is_none());
        assert_eq!(config.bind_addr, "0.0.0.0:3041");
    }

    #[test]
    fn issuer_and_origin_never_follow_a_task_or_internal_host() {
        for key in ["SSO_ORIGIN", "OIDC_ISSUER"] {
            for invalid in [
                "https://auth-phase12.saas.test",
                "http://auth.saas.test",
                "https://auth.saas.test/",
                "https://auth.saas.test:443",
                "https://auth.saas.test/path",
                "https://user@auth.saas.test",
            ] {
                let mut env = base();
                env.insert(key.into(), invalid.into());
                assert!(Config::from_values(&env).is_err(), "{key}");
            }
            let mut env = base();
            env.insert(key.into(), ISSUER.into());
            assert!(Config::from_values(&env).is_ok());
        }
    }

    #[test]
    fn customer_registration_uses_a_canonical_uuidv7() {
        let key = "CUSTOMER_PORTAL_OIDC_CLIENT_ID";
        let mut env = base();
        env.insert(key.into(), uuid::Uuid::now_v7().to_string());
        assert!(Config::from_values(&env).is_ok());
        for raw in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        ] {
            env.insert(key.into(), raw.into());
            assert!(Config::from_values(&env).is_err());
        }
    }

    #[test]
    fn password_login_and_provider_budgets_reject_invalid_bounds() {
        for (key, raw) in [
            ("PASSWORD_CONCURRENCY", "0"),
            ("PASSWORD_CONCURRENCY", "33"),
            ("PASSWORD_QUEUE_CAPACITY", "1025"),
            ("PASSWORD_QUEUE_TIMEOUT_MS", "0"),
            ("PASSWORD_EXECUTION_TIMEOUT_MS", "120001"),
            ("LOGIN_MAX_ENTRIES", "2"),
            ("LOGIN_WINDOW_SECONDS", "86401"),
            ("LOGIN_SOURCE_REQUESTS", "0"),
            ("LOGIN_USER_FAILURES", "0"),
            ("LOGIN_IDENTIFIER_MAX_BYTES", "1025"),
            ("LOGIN_VERIFY_BUDGET_MS", "0"),
            ("SSO_SESSION_TTL_SECONDS", "86401"),
            ("OIDC_TOKEN_TTL_SECONDS", "601"),
        ] {
            let mut env = base();
            env.insert(key.into(), raw.into());
            assert!(Config::from_values(&env).is_err(), "{key}");
        }
        let mut no_queue = base();
        no_queue.insert("PASSWORD_QUEUE_CAPACITY".into(), "0".into());
        assert!(Config::from_values(&no_queue).is_ok());
    }

    #[test]
    fn database_is_explicit_and_provider_requires_the_account_origin() {
        assert!(Config::from_values(&HashMap::new()).is_err());
        for invalid in [
            "postgresql:///task",
            "postgresql://localhost/task",
            "postgresql://identity@localhost/",
        ] {
            let mut env = base();
            env.insert("DATABASE_URL".into(), invalid.into());
            assert!(Config::from_values(&env).is_err());
        }
        let mut env = base();
        env.insert("SSO_ENABLED".into(), "true".into());
        assert!(Config::from_values(&env).is_err());
        env.insert("SSO_ORIGIN".into(), ISSUER.into());
        assert!(Config::from_values(&env).is_ok());
        env.insert("OIDC_ENABLED".into(), "true".into());
        assert!(Config::from_values(&env).is_err());
    }
}
