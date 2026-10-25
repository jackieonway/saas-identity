use sha2::{Digest, Sha256};
/// One-way credential digest; raw secrets never enter durable records.
pub(crate) fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}
