use super::{test_keys::TestKeys, KeySet};
use anyhow::{ensure, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};

#[test]
fn phase23_keyset_rejects_invalid_configuration_and_mismatched_private_material() -> Result<()> {
    let keys = TestKeys::new()?;
    let loaded = KeySet::load(keys.path_text()?)?;
    ensure!(
        loaded.keys.len() == 3,
        "valid independent key set was rejected"
    );
    ensure!(
        KeySet::load("relative-keyset.json").is_err(),
        "relative private material path accepted"
    );
    ensure!(
        KeySet::load(
            keys.path
                .with_file_name("missing.json")
                .to_str()
                .unwrap_or_default()
        )
        .is_err(),
        "missing absolute material file accepted"
    );
    let a = keys.material(0);
    let b = keys.material(1);
    let mut invalid = Vec::new();
    invalid.push(("empty", json!({"keys":[]})));
    invalid.push((
        "unknown-top-field",
        json!({"keys":[a.clone()],"unexpected":true}),
    ));
    invalid.push(("duplicate-kid", json!({"keys":[a.clone(),a.clone()]})));
    invalid.push((
        "too-many",
        json!({"keys":(0..9).map(|i| {
        let mut key=a.clone(); key["kid"]=json!(format!("key-{i}")); key
    }).collect::<Vec<_>>()}),
    ));
    for (label, field, value) in [
        ("invalid-kid", "kid", json!("not/a/canonical/kid")),
        ("long-kid", "kid", json!("x".repeat(81))),
        ("wrong-exponent", "e", json!("Aw")),
        (
            "padded-modulus",
            "n",
            json!(format!("{}=", a["n"].as_str().unwrap_or_default())),
        ),
        (
            "short-modulus",
            "n",
            json!(URL_SAFE_NO_PAD.encode([0xff; 128])),
        ),
        (
            "oversized-modulus",
            "n",
            json!(URL_SAFE_NO_PAD.encode([0xff; 513])),
        ),
        (
            "invalid-private",
            "privateKeyPem",
            json!("invalid RSA material"),
        ),
        (
            "oversized-private",
            "privateKeyPem",
            json!("x".repeat(16385)),
        ),
        (
            "wrong-private-pair",
            "privateKeyPem",
            b["privateKeyPem"].clone(),
        ),
    ] {
        let mut material = a.clone();
        material[field] = value;
        invalid.push((label, json!({"keys":[material]})));
    }
    let mut extra = a.clone();
    extra["unexpected"] = Value::Bool(true);
    invalid.push(("unknown-key-field", json!({"keys":[extra]})));
    let mut leading = vec![0];
    leading.extend(URL_SAFE_NO_PAD.decode(a["n"].as_str().unwrap_or_default())?);
    let mut material = a.clone();
    material["n"] = json!(URL_SAFE_NO_PAD.encode(leading));
    invalid.push(("leading-zero-modulus", json!({"keys":[material]})));
    let rng = ring::rand::SystemRandom::new();
    let ed = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow::anyhow!("owned alternate-algorithm fixture generation failed"))?;
    let mut non_rsa = a.clone();
    non_rsa["privateKeyPem"] = json!(format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(ed.as_ref())
    ));
    invalid.push(("non-rsa-private", json!({"keys":[non_rsa]})));
    for (label, value) in invalid {
        let path = keys.write(&format!("{label}.json"), &value)?;
        let result = KeySet::load(path.to_str().unwrap_or_default());
        ensure!(
            result.is_err(),
            "invalid key configuration accepted: {label}"
        );
        let error = result.err().map(|e| e.to_string()).unwrap_or_default();
        ensure!(
            !error.contains("PRIVATE KEY") && !error.contains("privateKeyPem"),
            "key loader disclosed material"
        );
    }
    let malformed = keys.write_bytes("invalid-json.json", b"{")?;
    ensure!(
        KeySet::load(malformed.to_str().unwrap_or_default()).is_err(),
        "malformed key JSON accepted"
    );
    let oversized = keys.write_bytes("large-file.json", &vec![b' '; 512 * 1024 + 1])?;
    ensure!(
        KeySet::load(oversized.to_str().unwrap_or_default()).is_err(),
        "oversized material file accepted"
    );
    keys.cleanup()
}
