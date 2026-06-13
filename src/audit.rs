//! Audit-journal integrity: hash-chain *linkage* checking and cryptographic
//! *sealing*.
//!
//! The Symbiont runtime writes the hash-chained JSONL journal; this crate does
//! not author entries, so it cannot sign them individually. Instead it offers
//! two integrity layers a consumer can run after the fact:
//!
//! * [`verify_chain_linkage`] — confirms each entry's `previous_hash` references
//!   the prior entry's `event_hash` (detects truncation / reordering / edits
//!   that don't recompute the chain). Used by the web viewer's audit badge.
//! * [`seal_journal`] / [`verify_seal`] — signs the chain *head* with the
//!   engagement keypair, producing one signature that attests the whole journal.
//!   A recomputed-but-forged chain still fails the seal, because the attacker
//!   lacks the engagement private key.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{self, CryptoError, EngagementKeypair};

#[derive(Debug, Error)]
pub enum SealError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("journal has no verifiable hash chain")]
    NoChain,
}

/// Result of a hash-chain linkage check over a journal file.
pub enum Linkage {
    /// Chain links cleanly; carries entry count and the head `event_hash`.
    Linked { entries: usize, head_hash: String },
    /// A `previous_hash` did not match the prior entry's `event_hash`.
    Broken,
    /// File present but not in the expected `{event_hash, previous_hash}` shape.
    Indeterminate,
}

/// Walk the JSONL journal, confirming `previous_hash[i] == event_hash[i-1]`.
pub fn verify_chain_linkage(path: &Path) -> Linkage {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Linkage::Indeterminate,
    };
    let mut prev_hash: Option<String> = None;
    let mut head: Option<String> = None;
    let mut n = 0usize;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Linkage::Indeterminate,
        };
        let event_hash = match v.get("event_hash").and_then(|x| x.as_str()) {
            Some(h) => h.to_string(),
            None => return Linkage::Indeterminate,
        };
        let previous_hash = v.get("previous_hash").and_then(|x| x.as_str());
        if let Some(prev) = &prev_hash {
            if previous_hash != Some(prev.as_str()) {
                return Linkage::Broken;
            }
        }
        prev_hash = Some(event_hash.clone());
        head = Some(event_hash);
        n += 1;
    }
    match head {
        Some(head_hash) if n > 0 => Linkage::Linked { entries: n, head_hash },
        _ => Linkage::Indeterminate,
    }
}

/// The signed attestation over a journal's chain head.
#[derive(Debug, Serialize, Deserialize)]
pub struct Seal {
    pub engagement_id: String,
    pub head_hash: String,
    pub entries: usize,
    pub created_at: String,
    /// Public half of the engagement key, hex-encoded (for offline verification).
    pub pubkey: String,
    /// Ed25519 signature over the canonical payload, hex-encoded.
    pub sig: String,
}

/// The exact bytes signed: a compact JSON object of the binding fields only.
fn seal_payload_bytes(engagement_id: &str, head_hash: &str, entries: usize) -> Vec<u8> {
    // Hand-built compact JSON keeps the signed bytes stable and obvious.
    format!(
        r#"{{"engagement_id":"{engagement_id}","entries":{entries},"head_hash":"{head_hash}"}}"#
    )
    .into_bytes()
}

/// Verify the journal links cleanly, then sign its head with `kp`.
pub fn seal_journal(
    journal: &Path,
    kp: &EngagementKeypair,
    created_at: &str,
) -> Result<Seal, SealError> {
    let (entries, head_hash) = match verify_chain_linkage(journal) {
        Linkage::Linked { entries, head_hash } => (entries, head_hash),
        _ => return Err(SealError::NoChain),
    };
    let bytes = seal_payload_bytes(&kp.engagement_id, &head_hash, entries);
    Ok(Seal {
        engagement_id: kp.engagement_id.clone(),
        head_hash,
        entries,
        created_at: created_at.to_string(),
        pubkey: kp.public_hex(),
        sig: kp.sign_hex(&bytes),
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum SealStatus {
    /// Seal signature valid AND it matches the journal's current head.
    Valid,
    /// Signature valid but the journal head/entries no longer match the seal.
    HeadMismatch,
    /// Signature did not verify against the seal's public key.
    BadSignature,
    /// Journal could not be linkage-checked.
    JournalUnreadable,
}

/// Verify a seal against the current state of its journal.
pub fn verify_seal(journal: &Path, seal: &Seal) -> SealStatus {
    let bytes = seal_payload_bytes(&seal.engagement_id, &seal.head_hash, seal.entries);
    if crypto::verify_with_pubkey_hex(&seal.pubkey, &bytes, &seal.sig).is_err() {
        return SealStatus::BadSignature;
    }
    match verify_chain_linkage(journal) {
        Linkage::Linked { entries, head_hash } => {
            if entries == seal.entries && head_hash == seal.head_hash {
                SealStatus::Valid
            } else {
                SealStatus::HeadMismatch
            }
        }
        _ => SealStatus::JournalUnreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_and_persist_in;
    use std::io::Write;
    use tempfile::TempDir;

    /// Write a minimal valid hash-chained journal (linkage-only; hashes are
    /// arbitrary but consistent).
    fn write_journal(path: &Path, hashes: &[(&str, &str)]) {
        let mut f = std::fs::File::create(path).unwrap();
        for (prev, ev) in hashes {
            writeln!(f, r#"{{"previous_hash":"{prev}","event_hash":"{ev}"}}"#).unwrap();
        }
    }

    #[test]
    fn linkage_detects_good_and_broken_chains() {
        let dir = TempDir::new().unwrap();
        let good = dir.path().join("good.jsonl");
        write_journal(&good, &[("0", "a"), ("a", "b"), ("b", "c")]);
        assert!(matches!(
            verify_chain_linkage(&good),
            Linkage::Linked { entries: 3, .. }
        ));

        let bad = dir.path().join("bad.jsonl");
        write_journal(&bad, &[("0", "a"), ("WRONG", "b")]);
        assert!(matches!(verify_chain_linkage(&bad), Linkage::Broken));
    }

    #[test]
    fn seal_then_verify_roundtrip() {
        let dir = TempDir::new().unwrap();
        let journal = dir.path().join("audit.jsonl");
        write_journal(&journal, &[("0", "a"), ("a", "b")]);
        let kp = generate_and_persist_in(dir.path(), "eng-1").unwrap();

        let seal = seal_journal(&journal, &kp, "2026-06-13T00:00:00Z").unwrap();
        assert_eq!(seal.head_hash, "b");
        assert_eq!(verify_seal(&journal, &seal), SealStatus::Valid);
    }

    #[test]
    fn appending_to_journal_invalidates_seal() {
        let dir = TempDir::new().unwrap();
        let journal = dir.path().join("audit.jsonl");
        write_journal(&journal, &[("0", "a"), ("a", "b")]);
        let kp = generate_and_persist_in(dir.path(), "eng-1").unwrap();
        let seal = seal_journal(&journal, &kp, "2026-06-13T00:00:00Z").unwrap();

        // A new (validly linked) entry moves the head — seal no longer matches.
        write_journal(&journal, &[("0", "a"), ("a", "b"), ("b", "c")]);
        assert_eq!(verify_seal(&journal, &seal), SealStatus::HeadMismatch);
    }

    #[test]
    fn forged_signature_fails() {
        let dir = TempDir::new().unwrap();
        let journal = dir.path().join("audit.jsonl");
        write_journal(&journal, &[("0", "a")]);
        let kp = generate_and_persist_in(dir.path(), "eng-1").unwrap();
        let mut seal = seal_journal(&journal, &kp, "2026-06-13T00:00:00Z").unwrap();
        seal.sig = "00".repeat(64);
        assert_eq!(verify_seal(&journal, &seal), SealStatus::BadSignature);
    }
}
