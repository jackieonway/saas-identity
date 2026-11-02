//! Private HTTPS context-selection port and task-bound credential encryption.
//! Public context interactions are implemented only by the canonical OAuth module.

pub(crate) mod bridge;
pub(crate) mod crypto;

fn canonical_id<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> std::result::Result<uuid::Uuid, D::Error> {
    let raw = <String as serde::Deserialize>::deserialize(de)?;
    super::canonical_id(&raw).map_err(|_| serde::de::Error::custom("canonical UUIDv7 required"))
}
