//! Bounded client token policy. Source and credential deadlines remain upper bounds.
use std::collections::HashMap;

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TokenDefaults {
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    pub offline_refresh_token_ttl_seconds: i64,
    pub client_token_ttl_seconds: i64,
}

impl TokenDefaults {
    pub fn load(env: &HashMap<String, String>) -> anyhow::Result<Self> {
        let read = |key: &str, default: i64, min: i64, max: i64| -> anyhow::Result<i64> {
            let value = env
                .get(key)
                .map(|raw| raw.parse::<i64>())
                .transpose()
                .map_err(|_| anyhow::anyhow!("{key} must be an integer"))?
                .unwrap_or(default);
            anyhow::ensure!(
                (min..=max).contains(&value),
                "{key} is outside the supported range"
            );
            Ok(value)
        };
        Ok(Self {
            access_token_ttl_seconds: read("OIDC_ACCESS_TOKEN_TTL_SECONDS", 300, 60, 3600)?,
            refresh_token_ttl_seconds: read(
                "OIDC_REFRESH_TOKEN_IDLE_TTL_SECONDS",
                1800,
                300,
                604800,
            )?,
            offline_refresh_token_ttl_seconds: read(
                "OIDC_OFFLINE_REFRESH_TOKEN_IDLE_TTL_SECONDS",
                86400,
                300,
                604800,
            )?,
            client_token_ttl_seconds: read("OIDC_CLIENT_TOKEN_TTL_SECONDS", 300, 60, 3600)?,
        })
    }
    pub fn refresh_idle(&self, custom: Option<i64>, offline: bool) -> i64 {
        custom.unwrap_or(if offline {
            self.offline_refresh_token_ttl_seconds
        } else {
            self.refresh_token_ttl_seconds
        })
    }
}

pub(crate) fn valid_optional_ttl(value: Option<i64>, refresh: bool) -> bool {
    value.is_none_or(|ttl| {
        if refresh {
            (300..=604800).contains(&ttl)
        } else {
            (60..=3600).contains(&ttl)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inheritance_and_custom_limits_are_finite() {
        let defaults = TokenDefaults::load(&HashMap::new()).unwrap();
        assert_eq!(defaults.access_token_ttl_seconds, 300);
        assert_eq!(defaults.refresh_idle(None, false), 1800);
        assert_eq!(defaults.refresh_idle(None, true), 86400);
        assert_eq!(defaults.refresh_idle(Some(600), true), 600);
        for invalid in [-1, 0, 59, 3601] {
            assert!(!valid_optional_ttl(Some(invalid), false));
        }
        for invalid in [-1, 0, 299, 604801] {
            assert!(!valid_optional_ttl(Some(invalid), true));
        }
        assert!(TokenDefaults::load(&HashMap::from([(
            "OIDC_ACCESS_TOKEN_TTL_SECONDS".into(),
            "-1".into()
        )]))
        .is_err());
    }
}
