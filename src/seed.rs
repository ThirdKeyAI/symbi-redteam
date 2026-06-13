//! Signed validation-seed verification.
//!
//! redteam may ingest *signed validation objectives* from a private upstream
//! analysis pipeline (e.g. CodeRed). A seed only proposes objectives — it grants
//! no authority — but before any objective is acted on, its signature must
//! verify against a **pinned producer key**.
//!
//! ## Canonical signing recipe (the contract both sides implement)
//!
//! 1. The producer builds the seed JSON object with its `signature` field set to
//!    the JSON string `""`.
//! 2. Canonical bytes = `serde_json::to_string(&value)` — compact, keys sorted
//!    (serde_json's `Map` is a `BTreeMap`).
//! 3. The producer signs those bytes (Ed25519) with a long-lived producer key,
//!    then replaces `signature` with the envelope
//!    `{"alg":"Ed25519","key_id":"…","sig":"<hex>"}`.
//!
//! Verification reverses step 3: set `signature` back to `""`, re-serialize
//! compact, and verify the envelope's `sig` against the pinned key named by
//! `key_id`. Setting the field to `""` (rather than removing it) is deliberate —
//! it reproduces the exact bytes the producer signed.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;
use thiserror::Error;

use crate::crypto::{verify_with_pubkey_hex, CryptoError};

#[derive(Debug, Error)]
pub enum SeedError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("malformed seed: {0}")]
    Malformed(String),
    #[error("unsupported signature alg: {0} (expected Ed25519)")]
    UnsupportedAlg(String),
    #[error("unknown key_id: {0} — not in the pinned producer keyring")]
    UnknownKeyId(String),
    #[error("signature verification failed: {0}")]
    BadSignature(#[from] CryptoError),
}

/// Pinned producer public keys, keyed by `key_id`. Public keys are not secret —
/// they may be committed (`keys/producers.toml`) or passed via env.
#[derive(Debug, Default, Clone)]
pub struct ProducerKeyring {
    keys: HashMap<String, String>,
}

impl ProducerKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key_id: impl Into<String>, pubkey_hex: impl Into<String>) {
        self.keys.insert(key_id.into(), pubkey_hex.into());
    }

    pub fn get(&self, key_id: &str) -> Option<&str> {
        self.keys.get(key_id).map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Parse `CODERED_PRODUCER_PUBKEYS` of the form `key_id=hex,key_id2=hex2`.
    pub fn from_env_var(value: &str) -> Result<Self, SeedError> {
        let mut kr = Self::new();
        for pair in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (id, hex) = pair
                .split_once('=')
                .ok_or_else(|| SeedError::Malformed(format!("bad keyring entry: {pair:?}")))?;
            kr.insert(id.trim(), hex.trim());
        }
        Ok(kr)
    }

    /// Load from a TOML file with a `[producers]` table of `key_id = "hex"`.
    pub fn from_toml_file(path: &Path) -> Result<Self, SeedError> {
        let text = std::fs::read_to_string(path)?;
        let doc: toml::Value =
            toml::from_str(&text).map_err(|e| SeedError::Malformed(e.to_string()))?;
        let mut kr = Self::new();
        if let Some(tbl) = doc.get("producers").and_then(|v| v.as_table()) {
            for (id, v) in tbl {
                let hex = v
                    .as_str()
                    .ok_or_else(|| SeedError::Malformed(format!("producer {id} is not a string")))?;
                kr.insert(id.clone(), hex.to_string());
            }
        }
        Ok(kr)
    }

    /// Resolve a keyring from the standard sources: the env var
    /// `CODERED_PRODUCER_PUBKEYS` and/or a TOML file (entries merge; env wins).
    pub fn resolve(env: Option<&str>, toml_path: Option<&Path>) -> Result<Self, SeedError> {
        let mut kr = Self::new();
        if let Some(p) = toml_path {
            if p.exists() {
                kr.keys.extend(Self::from_toml_file(p)?.keys);
            }
        }
        if let Some(v) = env {
            kr.keys.extend(Self::from_env_var(v)?.keys);
        }
        Ok(kr)
    }
}

/// A seed that passed signature verification. Objectives are kept as raw JSON to
/// avoid over-coupling to the producer's evolving schema; callers read the
/// fields they need.
pub struct VerifiedSeed {
    pub seed_version: String,
    pub producer: String,
    pub engagement_id: Option<String>,
    pub key_id: String,
    pub objectives: Vec<Value>,
}

/// Canonical bytes the signature is computed over: the seed with `signature`
/// reset to the JSON string `""`, serialized compactly.
pub fn canonical_signing_bytes(seed: &Value) -> Result<Vec<u8>, SeedError> {
    let mut v = seed.clone();
    let obj = v
        .as_object_mut()
        .ok_or_else(|| SeedError::Malformed("seed must be a JSON object".into()))?;
    obj.insert("signature".into(), Value::String(String::new()));
    Ok(serde_json::to_string(&v)?.into_bytes())
}

/// Verify a parsed seed value against the pinned keyring. Returns the verified
/// objectives only on success; any failure means **do not act on the seed**.
pub fn verify_seed(seed: &Value, keyring: &ProducerKeyring) -> Result<VerifiedSeed, SeedError> {
    let obj = seed
        .as_object()
        .ok_or_else(|| SeedError::Malformed("seed must be a JSON object".into()))?;

    let sig = obj
        .get("signature")
        .and_then(|v| v.as_object())
        .ok_or_else(|| SeedError::Malformed("missing signature envelope".into()))?;
    let alg = sig.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "Ed25519" {
        return Err(SeedError::UnsupportedAlg(alg.to_string()));
    }
    let key_id = sig
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SeedError::Malformed("signature.key_id missing".into()))?;
    let sig_hex = sig
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SeedError::Malformed("signature.sig missing".into()))?;

    let pubkey = keyring
        .get(key_id)
        .ok_or_else(|| SeedError::UnknownKeyId(key_id.to_string()))?;

    let bytes = canonical_signing_bytes(seed)?;
    verify_with_pubkey_hex(pubkey, &bytes, sig_hex)?;

    Ok(VerifiedSeed {
        seed_version: obj
            .get("seed_version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        producer: obj.get("producer").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        engagement_id: obj.get("engagement_id").and_then(|v| v.as_str()).map(str::to_string),
        key_id: key_id.to_string(),
        objectives: obj
            .get("objectives")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
    })
}

/// Convenience: read a seed file and verify it.
pub fn verify_seed_file(path: &Path, keyring: &ProducerKeyring) -> Result<VerifiedSeed, SeedError> {
    let text = std::fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&text)?;
    verify_seed(&value, keyring)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_and_persist_in;
    use serde_json::json;
    use tempfile::TempDir;

    /// Build a producer-signed seed exactly as the producer must: signature ""
    /// during signing, then the envelope re-inserted.
    fn signed_seed(kp: &crate::crypto::EngagementKeypair, key_id: &str) -> Value {
        let mut seed = json!({
            "seed_version": "1",
            "producer": "test-pipeline",
            "engagement_id": "eng-1",
            "objectives": [
                {"id": "obj-1", "title": "Validate exposed admin interface", "risk": "medium-high"}
            ],
            "signature": ""
        });
        let bytes = canonical_signing_bytes(&seed).unwrap();
        let sig = kp.sign_hex(&bytes);
        seed.as_object_mut().unwrap().insert(
            "signature".into(),
            json!({ "alg": "Ed25519", "key_id": key_id, "sig": sig }),
        );
        seed
    }

    fn keyring_with(kp: &crate::crypto::EngagementKeypair, key_id: &str) -> ProducerKeyring {
        let mut kr = ProducerKeyring::new();
        kr.insert(key_id, kp.public_hex());
        kr
    }

    #[test]
    fn valid_seed_verifies_and_yields_objectives() {
        let dir = TempDir::new().unwrap();
        let kp = generate_and_persist_in(dir.path(), "producer").unwrap();
        let seed = signed_seed(&kp, "producer-key-1");
        let kr = keyring_with(&kp, "producer-key-1");

        let v = verify_seed(&seed, &kr).expect("must verify");
        assert_eq!(v.producer, "test-pipeline");
        assert_eq!(v.key_id, "producer-key-1");
        assert_eq!(v.objectives.len(), 1);
        assert_eq!(v.objectives[0]["id"], "obj-1");
    }

    #[test]
    fn tampered_objective_fails() {
        let dir = TempDir::new().unwrap();
        let kp = generate_and_persist_in(dir.path(), "producer").unwrap();
        let mut seed = signed_seed(&kp, "producer-key-1");
        let kr = keyring_with(&kp, "producer-key-1");
        // Mutate an objective after signing.
        seed["objectives"][0]["title"] = json!("Exfiltrate everything");
        assert!(matches!(verify_seed(&seed, &kr), Err(SeedError::BadSignature(_))));
    }

    #[test]
    fn unknown_key_id_fails() {
        let dir = TempDir::new().unwrap();
        let kp = generate_and_persist_in(dir.path(), "producer").unwrap();
        let seed = signed_seed(&kp, "producer-key-99");
        let kr = keyring_with(&kp, "producer-key-1"); // different id
        assert!(matches!(verify_seed(&seed, &kr), Err(SeedError::UnknownKeyId(_))));
    }

    #[test]
    fn wrong_key_fails() {
        let dir = TempDir::new().unwrap();
        let kp = generate_and_persist_in(dir.path(), "producer").unwrap();
        let other = generate_and_persist_in(dir.path(), "other").unwrap();
        let seed = signed_seed(&kp, "producer-key-1");
        let mut kr = ProducerKeyring::new();
        kr.insert("producer-key-1", other.public_hex()); // right id, wrong key
        assert!(matches!(verify_seed(&seed, &kr), Err(SeedError::BadSignature(_))));
    }

    #[test]
    fn keyring_from_env_parses() {
        let kr = ProducerKeyring::from_env_var("k1=aa,k2=bb").unwrap();
        assert_eq!(kr.get("k1"), Some("aa"));
        assert_eq!(kr.get("k2"), Some("bb"));
    }

    #[test]
    fn canonical_bytes_are_signature_independent() {
        // The exact envelope value must not change the signed bytes.
        let a = json!({"a":1,"signature":""});
        let b = json!({"a":1,"signature":{"alg":"Ed25519","key_id":"x","sig":"deadbeef"}});
        assert_eq!(canonical_signing_bytes(&a).unwrap(), canonical_signing_bytes(&b).unwrap());
    }
}
