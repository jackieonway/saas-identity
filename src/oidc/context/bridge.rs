//! Purpose-limited HTTPS client for platform-owned choices and confirmation.
use crate::error::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    path::Path,
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

pub(crate) struct Settings {
    client: reqwest::Client,
    origin: String,
    id: Uuid,
    secret: String,
}
impl Settings {
    pub fn secret_digest(&self) -> String {
        crate::util::hash::sha256_hex(&self.secret)
    }
    pub fn load(env: &HashMap<String, String>) -> anyhow::Result<Option<Self>> {
        let names = [
            "CONTEXT_PLATFORM_ORIGIN",
            "CONTEXT_PLATFORM_SERVICE_ID",
            "CONTEXT_PLATFORM_SERVICE_SECRET",
            "CONTEXT_PLATFORM_CA_FILE",
        ];
        let values: Vec<_> = names
            .iter()
            .map(|k| env.get(*k).filter(|v| !v.is_empty()))
            .collect();
        if values.iter().all(|v| v.is_none()) {
            return Ok(None);
        }
        anyhow::ensure!(
            values.iter().all(|v| v.is_some()),
            "CONTEXT_PLATFORM_CONFIGURATION_INCOMPLETE"
        );
        let origin =
            values[0].ok_or_else(|| anyhow::anyhow!("CONTEXT_PLATFORM_ORIGIN_REQUIRED"))?;
        let url = reqwest::Url::parse(origin)
            .map_err(|_| anyhow::anyhow!("CONTEXT_PLATFORM_ORIGIN_INVALID"))?;
        anyhow::ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.origin().ascii_serialization() == *origin,
            "CONTEXT_PLATFORM_ORIGIN_INVALID"
        );
        let id = super::super::canonical_id(
            values[1].ok_or_else(|| anyhow::anyhow!("CONTEXT_PLATFORM_SERVICE_ID_REQUIRED"))?,
        )
        .map_err(|_| anyhow::anyhow!("CONTEXT_PLATFORM_SERVICE_ID_INVALID"))?;
        let secret =
            values[2].ok_or_else(|| anyhow::anyhow!("CONTEXT_PLATFORM_SERVICE_SECRET_REQUIRED"))?;
        anyhow::ensure!(
            super::super::canonical_secret(secret),
            "CONTEXT_PLATFORM_SERVICE_SECRET_INVALID"
        );
        let path = values[3].ok_or_else(|| anyhow::anyhow!("CONTEXT_PLATFORM_CA_FILE_REQUIRED"))?;
        anyhow::ensure!(
            Path::new(path).is_absolute(),
            "CONTEXT_PLATFORM_CA_FILE_MUST_BE_ABSOLUTE"
        );
        let bytes = std::fs::read(path)
            .map_err(|_| anyhow::anyhow!("CONTEXT_PLATFORM_CA_FILE_UNREADABLE"))?;
        anyhow::ensure!(
            !bytes.is_empty() && bytes.len() <= 1048576,
            "CONTEXT_PLATFORM_CA_FILE_INVALID"
        );
        let certificates = reqwest::Certificate::from_pem_bundle(&bytes)
            .map_err(|_| anyhow::anyhow!("CONTEXT_PLATFORM_CA_FILE_INVALID"))?;
        anyhow::ensure!(!certificates.is_empty(), "CONTEXT_PLATFORM_CA_FILE_INVALID");
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(3));
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
        Ok(Some(Self {
            client: builder
                .build()
                .map_err(|_| anyhow::anyhow!("CONTEXT_PLATFORM_TRANSPORT_INVALID"))?,
            origin: origin.clone(),
            id,
            secret: secret.clone(),
        }))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Choice {
    #[serde(deserialize_with = "super::canonical_id")]
    pub membership_id: Uuid,
    #[serde(deserialize_with = "super::canonical_id")]
    pub user_id: Uuid,
    #[serde(deserialize_with = "super::canonical_id")]
    pub tenant_id: Uuid,
    #[serde(deserialize_with = "super::canonical_id")]
    pub organization_id: Uuid,
    pub member_type: String,
    pub identity_version: String,
    pub tenant_name: String,
    pub organization_name: String,
    pub organization_path: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Choices {
    pub contract_version: String,
    #[serde(deserialize_with = "super::canonical_id")]
    pub transaction_id: Uuid,
    pub intent: Value,
    pub members: Vec<Choice>,
    pub expires_at: DateTime<Utc>,
}
impl Choices {
    pub fn validate(&self, user: Uuid, member_type: &str) -> Result<(), AppError> {
        let mut ids = HashSet::new();
        if self.contract_version != "context-selection/1"
            || self.members.len() > 256
            || self.expires_at <= Utc::now()
        {
            return Err(AppError::Unavailable);
        }
        for member in &self.members {
            if member.user_id != user
                || member.member_type != member_type
                || !ids.insert(member.membership_id)
                || !member
                    .identity_version
                    .parse::<i64>()
                    .is_ok_and(|v| v >= 1 && v.to_string() == member.identity_version)
                || member.tenant_name.is_empty()
                || member.tenant_name.chars().count() > 200
                || member.organization_name.is_empty()
                || member.organization_name.chars().count() > 200
                || member.organization_path.chars().count() > 4096
            {
                return Err(AppError::Unavailable);
            }
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Confirmation {
    pub contract_version: String,
    #[serde(deserialize_with = "super::canonical_id")]
    pub transaction_id: Uuid,
    pub credential: String,
    pub expires_at: DateTime<Utc>,
}

pub(crate) type ChoicesFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Choices, AppError>> + Send + 'a>>;
pub(crate) type ConfirmFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Confirmation, AppError>> + Send + 'a>>;
pub(crate) trait SelectionPort: Send + Sync {
    fn choices<'a>(&'a self, proof: &'a str, client: Uuid) -> ChoicesFuture<'a>;
    fn confirm<'a>(&'a self, proof: &'a str, client: Uuid, member: Uuid) -> ConfirmFuture<'a>;
}
struct Remote(Option<Arc<Settings>>);
pub(crate) fn configured(settings: Option<Arc<Settings>>) -> Arc<dyn SelectionPort> {
    Arc::new(Remote(settings))
}
impl Remote {
    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        operation: &str,
        body: Value,
    ) -> Result<T, AppError> {
        let settings = self.0.as_ref().ok_or(AppError::Unavailable)?;
        let mut response = settings
            .client
            .post(format!(
                "{}/internal/platform/context-selection/{operation}",
                settings.origin
            ))
            .basic_auth(settings.id.to_string(), Some(&settings.secret))
            .json(&body)
            .send()
            .await
            .map_err(|_| AppError::Unavailable)?;
        match response.status().as_u16() {
            200 => {}
            400 => return Err(AppError::bad_request("身份选择请求无效")),
            401 | 403 => return Err(AppError::unauthorized("当前账号无法使用此成员身份")),
            409 | 410 => return Err(AppError::conflict("身份选择已变化，请返回应用重新发起")),
            _ => return Err(AppError::Unavailable),
        }
        if response.content_length().is_some_and(|v| v > 65536)
            || !response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(';').next() == Some("application/json"))
        {
            return Err(AppError::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| AppError::Unavailable)? {
            if bytes.len() + chunk.len() > 65536 {
                return Err(AppError::Unavailable);
            }
            bytes.extend(chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| AppError::Unavailable)
    }
}
impl SelectionPort for Remote {
    fn choices<'a>(&'a self, proof: &'a str, client: Uuid) -> ChoicesFuture<'a> {
        Box::pin(async move {
            self.send("choices",json!({"contractVersion":"context-selection/1","sourceProof":proof,"expectedClientId":client})).await
        })
    }
    fn confirm<'a>(&'a self, proof: &'a str, client: Uuid, member: Uuid) -> ConfirmFuture<'a> {
        Box::pin(async move {
            self.send("confirm",json!({"contractVersion":"context-selection/1","sourceProof":proof,"expectedClientId":client,"membershipId":member})).await
        })
    }
}
