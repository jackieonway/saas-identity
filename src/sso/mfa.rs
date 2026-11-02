//! Account TOTP storage and verification. Seeds are encrypted at rest with a
//! dedicated process key; raw TOTP/recovery values never enter audit records.

use chrono::{DateTime, Utc};
use rand::RngCore;
use ring::{aead, hmac};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

const RECOVERY_CODE_COUNT: usize = 10;

pub(crate) fn new_secret() -> Result<[u8; 20], AppError> {
    let mut secret = [0_u8; 20];
    rand::rngs::OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|_| AppError::Unavailable)?;
    Ok(secret)
}

pub(crate) fn base32(secret: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity(secret.len().div_ceil(5) * 8);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in secret {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    output
}

fn key(state: &AppState) -> Result<&[u8; 32], AppError> {
    state
        .config
        .sso_totp_encryption_key
        .as_ref()
        .ok_or(AppError::Unavailable)
}

pub(crate) fn encrypt(state: &AppState, user_id: Uuid, secret: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut nonce_bytes = [0_u8; 12];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| AppError::Unavailable)?;
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key(state)?)
        .map_err(|_| AppError::Unavailable)?;
    let cipher = aead::LessSafeKey::new(unbound);
    let mut ciphertext = secret.to_vec();
    cipher
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce_bytes),
            aead::Aad::from(aad(user_id)),
            &mut ciphertext,
        )
        .map_err(|_| AppError::Unavailable)?;
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub(crate) fn decrypt(
    state: &AppState,
    user_id: Uuid,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    if !(28..=128).contains(&ciphertext.len()) {
        return Err(AppError::Unavailable);
    }
    let nonce_bytes: [u8; 12] = ciphertext[..12]
        .try_into()
        .map_err(|_| AppError::Unavailable)?;
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key(state)?)
        .map_err(|_| AppError::Unavailable)?;
    let cipher = aead::LessSafeKey::new(unbound);
    let mut plaintext = ciphertext[12..].to_vec();
    let clear = cipher
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce_bytes),
            aead::Aad::from(aad(user_id)),
            &mut plaintext,
        )
        .map_err(|_| AppError::Unavailable)?;
    Ok(clear.to_vec())
}

fn aad(user_id: Uuid) -> Vec<u8> {
    format!("saas-identity/totp-seed/1:{user_id}").into_bytes()
}

pub(crate) fn code_for_step(secret: &[u8], step: i64) -> Result<String, AppError> {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let signed = hmac::sign(&key, &step.to_be_bytes());
    let bytes = signed.as_ref();
    let offset = usize::from(bytes[bytes.len() - 1] & 0x0f);
    let value = (u32::from(bytes[offset] & 0x7f) << 24)
        | (u32::from(bytes[offset + 1]) << 16)
        | (u32::from(bytes[offset + 2]) << 8)
        | u32::from(bytes[offset + 3]);
    Ok(format!("{:06}", value % 1_000_000))
}

pub(crate) fn matching_step(
    secret: &[u8],
    code: &str,
    now_step: i64,
    last_step: i64,
) -> Option<i64> {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    [-1_i64, 0, 1]
        .into_iter()
        .map(|delta| now_step.saturating_add(delta))
        .filter(|step| *step >= 0 && *step > last_step)
        .filter(|step| {
            code_for_step(secret, *step).is_ok_and(|expected| constant_equal(code, &expected))
        })
        .max()
}

fn constant_equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
            == 0
}

pub(crate) async fn factor_enabled(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.auth_totp_factors WHERE user_id=$1)")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// Consume one TOTP step or one random recovery code in the caller's account
/// transaction. The account row must already be locked before this function.
pub(crate) async fn consume_code(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    raw_code: &str,
) -> Result<Option<&'static str>, AppError> {
    if raw_code.len() > 80 {
        return Ok(None);
    }
    let code = raw_code.trim();
    if code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()) {
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT secret_ciphertext,last_accepted_step FROM public.auth_totp_factors \
             WHERE user_id=$1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((ciphertext, last_step)) = row else {
            return Ok(None);
        };
        let secret = decrypt(state, user_id, &ciphertext)?;
        let now_step: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint")
                .fetch_one(&mut **tx)
                .await?;
        let Some(step) = matching_step(&secret, code, now_step, last_step) else {
            return Ok(None);
        };
        let updated = sqlx::query(
            "UPDATE public.auth_totp_factors SET last_accepted_step=$2,version=version+1 \
             WHERE user_id=$1 AND last_accepted_step=$3",
        )
        .bind(user_id)
        .bind(step)
        .bind(last_step)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if updated == 1 {
            Ok(Some("totp"))
        } else {
            Ok(None)
        }
    } else {
        let normalized = code
            .chars()
            .filter(|character| *character != '-' && *character != ' ')
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if normalized.len() != 32
            || !normalized
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Ok(None);
        }
        let digest = recovery_digest(state, user_id, &normalized)?;
        let consumed = sqlx::query(
            "UPDATE public.auth_totp_recovery_codes SET consumed_at=clock_timestamp() \
             WHERE user_id=$1 AND code_digest=$2 AND consumed_at IS NULL RETURNING id",
        )
        .bind(user_id)
        .bind(digest)
        .fetch_optional(&mut **tx)
        .await?;
        Ok(consumed.map(|_| "recovery_code"))
    }
}

pub(crate) fn recovery_digest(
    state: &AppState,
    user_id: Uuid,
    code: &str,
) -> Result<String, AppError> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key(state)?);
    let value = format!("saas-identity/recovery-code/1:{user_id}:{code}");
    Ok(hex::encode(hmac::sign(&key, value.as_bytes()).as_ref()))
}

pub(crate) fn recovery_codes(state: &AppState, _user_id: Uuid) -> Result<Vec<String>, AppError> {
    let mut result = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut bytes = [0_u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| AppError::Unavailable)?;
        let raw = hex::encode(bytes);
        result.push(raw);
    }
    // Fail closed if configuration is unavailable before starting a write.
    let _ = key(state)?;
    Ok(result)
}

pub(crate) async fn record_security_event(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    event_kind: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO public.auth_security_notification_outbox(id,user_id,event_kind) VALUES($1,$2,$3)",
    )
    .bind(crate::util::uuid7::new_uuid())
    .bind(user_id)
    .bind(event_kind)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) fn recent_enough(value: DateTime<Utc>, now: DateTime<Utc>, seconds: i64) -> bool {
    value <= now && value >= now - chrono::Duration::seconds(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_uses_rfc6238_sha1_six_digit_vectors_and_blocks_replay() {
        // RFC 6238's SHA-1 test seed, narrowed to the service's six digit profile.
        let secret = b"12345678901234567890";
        assert_eq!(code_for_step(secret, 1).unwrap(), "287082");
        assert_eq!(code_for_step(secret, 37_037_036).unwrap(), "081804");
        assert_eq!(matching_step(secret, "287082", 1, 0), Some(1));
        assert_eq!(matching_step(secret, "287082", 1, 1), None);
        assert_eq!(matching_step(secret, "287082", 1, 2), None);
        assert_eq!(matching_step(secret, "28x082", 1, 0), None);
    }

    #[test]
    fn base32_seed_has_no_padding_and_rounds_up() {
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
    }
}
