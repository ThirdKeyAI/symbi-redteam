//! Ed25519 signing primitives.
//!
//! Ported from the codered `signing.rs` substrate. Two roles share this module:
//!
//! * **Producer / self-signing** — an engagement gets its own keypair, persisted
//!   under `.symbiont/keys/{engagement_id}.{priv,pub}` (private key mode 0600).
//!   redteam uses this to *seal* its own audit journal ([`crate::audit_seal`]).
//! * **Consumer / verify-only** — verifying a signature against a public key we
//!   hold but did not generate (e.g. a pinned CodeRed producer key). See
//!   [`verify_with_pubkey_hex`], which needs no private key material.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("ed25519: {0}")]
    Ed25519(String),
    #[error("key/signature shape: {0}")]
    Shape(String),
}

/// A per-engagement Ed25519 keypair (both halves).
pub struct EngagementKeypair {
    pub engagement_id: String,
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl EngagementKeypair {
    /// Sign `bytes`, returning the 64-byte signature hex-encoded.
    pub fn sign_hex(&self, bytes: &[u8]) -> String {
        let sig: Signature = self.signing.sign(bytes);
        hex::encode(sig.to_bytes())
    }

    /// Verify `hex_sig` over `bytes` with this keypair's public half.
    pub fn verify_hex(&self, bytes: &[u8], hex_sig: &str) -> Result<(), CryptoError> {
        verify_with_pubkey_hex(&hex::encode(self.verifying.to_bytes()), bytes, hex_sig)
    }

    /// This keypair's public key, hex-encoded (safe to publish / pin).
    pub fn public_hex(&self) -> String {
        hex::encode(self.verifying.to_bytes())
    }
}

/// Verify a hex signature over `bytes` against a hex-encoded Ed25519 public key.
/// The consumer path: no private key required.
pub fn verify_with_pubkey_hex(
    pubkey_hex: &str,
    bytes: &[u8],
    sig_hex: &str,
) -> Result<(), CryptoError> {
    let pub_bytes = hex::decode(pubkey_hex.trim())?;
    let pub_arr: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Shape("public key must be 32 bytes".into()))?;
    let verifying =
        VerifyingKey::from_bytes(&pub_arr).map_err(|e| CryptoError::Ed25519(e.to_string()))?;

    let sig_bytes = hex::decode(sig_hex.trim())?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Shape("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_arr);

    verifying
        .verify(bytes, &sig)
        .map_err(|e| CryptoError::Ed25519(e.to_string()))
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from(".symbiont/keys")
}

/// Generate a fresh keypair for `engagement_id` and persist it under the default
/// `.symbiont/keys/` directory.
pub fn generate_and_persist(engagement_id: &str) -> Result<EngagementKeypair, CryptoError> {
    generate_and_persist_in(&default_keys_dir(), engagement_id)
}

/// Load a previously persisted keypair from the default `.symbiont/keys/`.
pub fn load(engagement_id: &str) -> Result<EngagementKeypair, CryptoError> {
    load_from(&default_keys_dir(), engagement_id)
}

pub fn generate_and_persist_in(
    dir: &Path,
    engagement_id: &str,
) -> Result<EngagementKeypair, CryptoError> {
    fs::create_dir_all(dir)?;

    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();

    let priv_path = dir.join(format!("{engagement_id}.priv"));
    let pub_path = dir.join(format!("{engagement_id}.pub"));
    fs::write(&priv_path, hex::encode(signing.to_bytes()))?;
    fs::write(&pub_path, hex::encode(verifying.to_bytes()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&priv_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&priv_path, perms)?;
    }

    Ok(EngagementKeypair { engagement_id: engagement_id.to_string(), signing, verifying })
}

pub fn load_from(dir: &Path, engagement_id: &str) -> Result<EngagementKeypair, CryptoError> {
    let priv_hex = fs::read_to_string(dir.join(format!("{engagement_id}.priv")))?;
    let pub_hex = fs::read_to_string(dir.join(format!("{engagement_id}.pub")))?;
    let priv_bytes = hex::decode(priv_hex.trim())?;
    let pub_bytes = hex::decode(pub_hex.trim())?;

    let priv_arr: [u8; 32] = priv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Shape("signing key must be 32 bytes".into()))?;
    let pub_arr: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Shape("verifying key must be 32 bytes".into()))?;

    let signing = SigningKey::from_bytes(&priv_arr);
    let verifying =
        VerifyingKey::from_bytes(&pub_arr).map_err(|e| CryptoError::Ed25519(e.to_string()))?;
    Ok(EngagementKeypair { engagement_id: engagement_id.to_string(), signing, verifying })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_then_load_yields_identical_keys() {
        let dir = TempDir::new().unwrap();
        let a = generate_and_persist_in(dir.path(), "eng-1").unwrap();
        let b = load_from(dir.path(), "eng-1").unwrap();
        assert_eq!(a.signing.to_bytes(), b.signing.to_bytes());
        assert_eq!(a.verifying.to_bytes(), b.verifying.to_bytes());
    }

    #[test]
    fn sign_then_verify_succeeds_for_matching_bytes() {
        let dir = TempDir::new().unwrap();
        let kp = generate_and_persist_in(dir.path(), "eng-1").unwrap();
        let sig = kp.sign_hex(b"canonical seed JSON");
        kp.verify_hex(b"canonical seed JSON", &sig).expect("must verify");
        // verify-only path with the published public key agrees.
        verify_with_pubkey_hex(&kp.public_hex(), b"canonical seed JSON", &sig).unwrap();
    }

    #[test]
    fn verify_fails_for_tampered_bytes() {
        let dir = TempDir::new().unwrap();
        let kp = generate_and_persist_in(dir.path(), "eng-1").unwrap();
        let sig = kp.sign_hex(b"original");
        assert!(kp.verify_hex(b"tampered", &sig).is_err());
    }

    #[test]
    fn private_key_is_mode_0600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = TempDir::new().unwrap();
            generate_and_persist_in(dir.path(), "eng-1").unwrap();
            let mode = fs::metadata(dir.path().join("eng-1.priv")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
