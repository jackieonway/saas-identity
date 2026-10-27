//! Identity-owned AEAD envelope for the short-lived platform selection secret.
use crate::error::AppError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::Deserialize;
use std::{collections::HashSet, path::Path};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    kid: String,
    key: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document {
    active_kid: String,
    keys: Vec<Material>,
}

pub(crate) struct Keys {
    active: String,
    keys: Vec<(String, LessSafeKey)>,
}

fn kid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

impl Keys {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            Path::new(path).is_absolute(),
            "CONTEXT_SELECTION_KEY_FILE_MUST_BE_ABSOLUTE"
        );
        let bytes = std::fs::read(path)
            .map_err(|_| anyhow::anyhow!("CONTEXT_SELECTION_KEY_FILE_UNREADABLE"))?;
        anyhow::ensure!(bytes.len() <= 32768, "CONTEXT_SELECTION_KEY_FILE_TOO_LARGE");
        let document: Document = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("CONTEXT_SELECTION_KEY_FILE_INVALID"))?;
        Self::from_document(document)
    }

    fn from_document(document: Document) -> anyhow::Result<Self> {
        anyhow::ensure!(
            kid(&document.active_kid) && !document.keys.is_empty() && document.keys.len() <= 8,
            "CONTEXT_SELECTION_KEYRING_INVALID"
        );
        let mut seen = HashSet::new();
        let mut keys = Vec::new();
        for material in document.keys {
            anyhow::ensure!(
                kid(&material.kid) && seen.insert(material.kid.clone()),
                "CONTEXT_SELECTION_KID_INVALID"
            );
            let bytes = URL_SAFE_NO_PAD
                .decode(&material.key)
                .map_err(|_| anyhow::anyhow!("CONTEXT_SELECTION_KEY_INVALID"))?;
            anyhow::ensure!(
                bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == material.key,
                "CONTEXT_SELECTION_KEY_INVALID"
            );
            let key = UnboundKey::new(&AES_256_GCM, &bytes)
                .map_err(|_| anyhow::anyhow!("CONTEXT_SELECTION_KEY_INVALID"))?;
            keys.push((material.kid, LessSafeKey::new(key)));
        }
        anyhow::ensure!(
            seen.contains(&document.active_kid),
            "CONTEXT_SELECTION_ACTIVE_KEY_MISSING"
        );
        Ok(Self {
            active: document.active_kid,
            keys,
        })
    }

    fn aad(transaction: Uuid, flow: Uuid, client: Uuid, issuer: &str) -> String {
        format!("identity-context-selection-aead/1\0{transaction}\0{flow}\0{client}\0{issuer}")
    }

    pub fn seal(
        &self,
        transaction: Uuid,
        flow: Uuid,
        client: Uuid,
        issuer: &str,
        credential: &str,
    ) -> Result<String, AppError> {
        if !super::super::canonical_secret(credential) {
            return Err(AppError::Unavailable);
        }
        let (_, key) = self
            .keys
            .iter()
            .find(|(kid, _)| kid == &self.active)
            .ok_or(AppError::Unavailable)?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| AppError::Unavailable)?;
        let mut bytes = credential.as_bytes().to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(Self::aad(transaction, flow, client, issuer).as_bytes()),
            &mut bytes,
        )
        .map_err(|_| AppError::Unavailable)?;
        let mut envelope = nonce.to_vec();
        envelope.extend(bytes);
        Ok(format!(
            "v1.{}.{}",
            self.active,
            URL_SAFE_NO_PAD.encode(envelope)
        ))
    }

    pub fn open(
        &self,
        transaction: Uuid,
        flow: Uuid,
        client: Uuid,
        issuer: &str,
        envelope: &str,
    ) -> Result<String, AppError> {
        let mut parts = envelope.split('.');
        if parts.next() != Some("v1") {
            return Err(AppError::Unavailable);
        }
        let kid = parts.next().ok_or(AppError::Unavailable)?;
        let raw = parts.next().ok_or(AppError::Unavailable)?;
        if parts.next().is_some() || raw.len() > 256 {
            return Err(AppError::Unavailable);
        }
        let (_, key) = self
            .keys
            .iter()
            .find(|(id, _)| id == kid)
            .ok_or(AppError::Unavailable)?;
        let mut bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| AppError::Unavailable)?;
        if bytes.len() != 92 || URL_SAFE_NO_PAD.encode(&bytes) != raw {
            return Err(AppError::Unavailable);
        }
        let nonce: [u8; 12] = bytes[..12].try_into().map_err(|_| AppError::Unavailable)?;
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(Self::aad(transaction, flow, client, issuer).as_bytes()),
                &mut bytes[12..],
            )
            .map_err(|_| AppError::Unavailable)?;
        let plain = std::str::from_utf8(plain).map_err(|_| AppError::Unavailable)?;
        if !super::super::canonical_secret(plain) {
            return Err(AppError::Unavailable);
        }
        Ok(plain.to_owned())
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self::from_document(Document {
            active_kid: "fixture".into(),
            keys: vec![Material {
                kid: "fixture".into(),
                key: URL_SAFE_NO_PAD.encode([71u8; 32]),
            }],
        })
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_is_authenticated_and_bound_to_the_exact_interaction() {
        let keys = Keys::fixture();
        let t = Uuid::now_v7();
        let f = Uuid::now_v7();
        let c = Uuid::now_v7();
        let issuer = "https://auth.saas.test";
        let credential = "a".repeat(64);
        let encrypted = keys.seal(t, f, c, issuer, &credential).unwrap();
        assert_eq!(keys.open(t, f, c, issuer, &encrypted).unwrap(), credential);
        assert_ne!(keys.seal(t, f, c, issuer, &credential).unwrap(), encrypted);
        for (tx, flow, client, origin) in [
            (Uuid::now_v7(), f, c, issuer),
            (t, Uuid::now_v7(), c, issuer),
            (t, f, Uuid::now_v7(), issuer),
            (t, f, c, "https://other.saas.test"),
        ] {
            assert!(keys.open(tx, flow, client, origin, &encrypted).is_err());
        }
        let mut parts: Vec<_> = encrypted.split('.').map(str::to_owned).collect();
        let mut bytes = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
        bytes[20] ^= 1;
        parts[2] = URL_SAFE_NO_PAD.encode(bytes);
        assert!(keys.open(t, f, c, issuer, &parts.join(".")).is_err());
    }
}
