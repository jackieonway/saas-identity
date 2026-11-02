use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A separate operational credential, deliberately without Debug or Serialize.
pub(crate) struct Settings {
    digest: Option<[u8; 32]>,
}

impl Settings {
    pub(crate) fn load(env: &HashMap<String, String>, app_env: &str) -> anyhow::Result<Self> {
        let Some(raw) = env
            .get("IDENTITY_METRICS_TOKEN")
            .filter(|raw| !raw.is_empty())
        else {
            return Ok(Self { digest: None });
        };
        anyhow::ensure!(
            (16..=256).contains(&raw.len()) && raw.bytes().all(|byte| byte.is_ascii_graphic()),
            "IDENTITY_METRICS_TOKEN_INVALID"
        );
        if app_env == "production" {
            let folded = raw.to_ascii_lowercase();
            let distinct = raw.bytes().collect::<std::collections::BTreeSet<_>>().len();
            anyhow::ensure!(
                raw.len() >= 32
                    && distinct >= 8
                    && ![
                        "changeme",
                        "change-me",
                        "change_me",
                        "replace",
                        "example",
                        "default",
                        "password",
                        "fixture",
                        "dev-secret"
                    ]
                    .iter()
                    .any(|marker| folded.contains(marker)),
                "IDENTITY_METRICS_TOKEN_WEAK"
            );
        }
        let independent = env.iter().all(|(name, value)| {
            name == "IDENTITY_METRICS_TOKEN"
                || !(name.ends_with("_SECRET")
                    || name.ends_with("_TOKEN")
                    || name.ends_with("_PASSWORD")
                    || name.ends_with("_KEY"))
                || raw != value
        });
        anyhow::ensure!(independent, "IDENTITY_METRICS_TOKEN_MUST_BE_INDEPENDENT");
        Ok(Self {
            digest: Some(Sha256::digest(raw.as_bytes()).into()),
        })
    }

    pub(super) fn enabled(&self) -> bool {
        self.digest.is_some()
    }

    pub(super) fn accepts(&self, token: &str) -> bool {
        let Some(expected) = self.digest.as_ref() else {
            return false;
        };
        if !(16..=256).contains(&token.len()) || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return false;
        }
        let supplied: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        expected
            .iter()
            .zip(supplied)
            .fold(0u8, |different, (left, right)| different | (left ^ right))
            == 0
    }
}
