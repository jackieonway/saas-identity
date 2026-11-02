//! Dedicated invitation derivation keys; no token material is persisted.

use super::Invitation;
use crate::error::AppError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use serde::Deserialize;
use std::{collections::HashSet, io::Read, path::Path};

const PURPOSE: &str = "saas-identity/auth-invitation/1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document {
    purpose: String,
    active_version: i64,
    keys: Vec<Material>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    version: i64,
    key: String,
}

/// Startup-loaded, purpose-separated invitation keys. Secret bytes deliberately
/// implement neither Debug nor serialization.
pub(crate) struct InvitationKeys {
    pub(super) active_version: i64,
    keys: Vec<(i64, [u8; 32])>,
}

impl InvitationKeys {
    pub(crate) fn load(path: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            Path::new(path).is_absolute(),
            "AUTH_INVITATION_KEYSET_PATH_MUST_BE_ABSOLUTE"
        );
        let file = std::fs::File::open(path)
            .map_err(|_| anyhow::anyhow!("AUTH_INVITATION_KEYSET_UNREADABLE"))?;
        let mut bytes = Vec::new();
        file.take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("AUTH_INVITATION_KEYSET_UNREADABLE"))?;
        anyhow::ensure!(bytes.len() <= 65_536, "AUTH_INVITATION_KEYSET_TOO_LARGE");
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let document: Document = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("AUTH_INVITATION_KEYSET_INVALID"))?;
        anyhow::ensure!(
            document.purpose == PURPOSE
                && document.active_version > 0
                && !document.keys.is_empty()
                && document.keys.len() <= 16,
            "AUTH_INVITATION_KEYSET_INVALID"
        );
        let mut versions = HashSet::new();
        let mut materials = HashSet::new();
        let mut keys = Vec::with_capacity(document.keys.len());
        for material in document.keys {
            let decoded = URL_SAFE_NO_PAD
                .decode(&material.key)
                .map_err(|_| anyhow::anyhow!("AUTH_INVITATION_KEY_INVALID"))?;
            anyhow::ensure!(
                material.version > 0
                    && versions.insert(material.version)
                    && decoded.len() == 32
                    && decoded.iter().any(|byte| *byte != 0)
                    && URL_SAFE_NO_PAD.encode(&decoded) == material.key
                    && materials.insert(decoded.clone()),
                "AUTH_INVITATION_KEY_INVALID"
            );
            let key = decoded
                .try_into()
                .map_err(|_| anyhow::anyhow!("AUTH_INVITATION_KEY_INVALID"))?;
            keys.push((material.version, key));
        }
        anyhow::ensure!(
            versions.contains(&document.active_version),
            "AUTH_INVITATION_ACTIVE_KEY_MISSING"
        );
        Ok(Self {
            active_version: document.active_version,
            keys,
        })
    }

    pub(super) fn uses_material(&self, material: &[u8; 32]) -> bool {
        self.keys.iter().any(|(_, key)| key == material)
    }

    pub(super) fn service_secret_digests(&self) -> Vec<String> {
        self.keys
            .iter()
            .map(|(_, key)| crate::util::hash::sha256_hex(&hex::encode(key)))
            .collect()
    }

    pub(super) fn derive(&self, invitation: &Invitation) -> Result<String, AppError> {
        let (_, key) = self
            .keys
            .iter()
            .find(|(version, _)| *version == invitation.key_version)
            .ok_or(AppError::Unavailable)?;
        let binding = format!(
            "{PURPOSE}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            invitation.key_version,
            invitation.id,
            invitation.operation_id,
            invitation.request_digest,
            invitation.recipient_ref,
            invitation.purpose,
            invitation.created_at.timestamp_micros(),
            invitation.expires_at.timestamp_micros(),
        );
        Ok(URL_SAFE_NO_PAD.encode(
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), binding.as_bytes()).as_ref(),
        ))
    }

    pub(super) fn activation_digest(
        &self,
        invitation: &Invitation,
        operation: uuid::Uuid,
        verification: uuid::Uuid,
        username: &str,
        password: &str,
    ) -> Result<String, AppError> {
        let (_, key) = self
            .keys
            .iter()
            .find(|(version, _)| *version == invitation.key_version)
            .ok_or(AppError::Unavailable)?;
        let mut context = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, key));
        context.update(b"saas-identity/auth-invitation-activation/1\0");
        for value in [
            invitation.id.as_bytes().as_slice(),
            operation.as_bytes(),
            verification.as_bytes(),
            invitation.token_digest.as_bytes(),
            username.as_bytes(),
            password.as_bytes(),
        ] {
            context.update(&(value.len() as u64).to_be_bytes());
            context.update(value);
        }
        Ok(hex::encode(context.sign().as_ref()))
    }

    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self::from_bytes(
            serde_json::to_vec(&serde_json::json!({
                "purpose":PURPOSE,"activeVersion":1,
                "keys":[{"version":1,"key":URL_SAFE_NO_PAD.encode([83u8;32])}]
            }))
            .unwrap()
            .as_slice(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_keyset_enforces_purpose_versions_and_independent_material() {
        let valid = serde_json::json!({
            "purpose":PURPOSE,"activeVersion":1,
            "keys":[{"version":1,"key":URL_SAFE_NO_PAD.encode([17u8;32])}]
        });
        assert!(InvitationKeys::from_bytes(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for invalid in [
            serde_json::json!({"purpose":"oidc-signing","activeVersion":1,"keys":valid["keys"]}),
            serde_json::json!({"purpose":PURPOSE,"activeVersion":2,"keys":valid["keys"]}),
            serde_json::json!({"purpose":PURPOSE,"activeVersion":1,"keys":[{"version":1,"key":URL_SAFE_NO_PAD.encode([0u8;32])}]}),
            serde_json::json!({"purpose":PURPOSE,"activeVersion":1,"keys":[valid["keys"][0].clone(),valid["keys"][0].clone()]}),
            serde_json::json!({"purpose":PURPOSE,"activeVersion":1,"keys":[{"version":1,"key":URL_SAFE_NO_PAD.encode([17u8;32])},{"version":2,"key":URL_SAFE_NO_PAD.encode([17u8;32])}]}),
        ] {
            assert!(InvitationKeys::from_bytes(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        assert!(InvitationKeys::load("relative-invitation-keyset.json").is_err());
    }
}
