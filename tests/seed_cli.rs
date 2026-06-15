//! End-to-end test for the `redteam-seed` verifier CLI: produce a
//! producer-signed seed exactly as the upstream pipeline would, pin the
//! producer key, and drive the real binary as a subprocess.

use std::process::Command;

use serde_json::json;
use symbi_redteam::crypto::generate_and_persist_in;
use symbi_redteam::seed::canonical_signing_bytes;

/// Write a producer keypair, a signed seed, and a keyring toml into `dir`.
/// Returns (seed_path, keyring_path).
fn fixture(dir: &std::path::Path, key_id: &str, tamper: bool) -> (std::path::PathBuf, std::path::PathBuf) {
    let kp = generate_and_persist_in(dir, "producer").unwrap();

    let mut seed = json!({
        "seed_version": "1",
        "producer": "codered-pipeline",
        "engagement_id": "eng-1",
        "objectives": [
            {"id": "obj-1", "title": "Validate exposed admin interface", "risk": "medium-high"}
        ],
        "signature": ""
    });
    let sig = kp.sign_hex(&canonical_signing_bytes(&seed).unwrap());
    seed.as_object_mut().unwrap().insert(
        "signature".into(),
        json!({ "alg": "Ed25519", "key_id": key_id, "sig": sig }),
    );
    if tamper {
        seed["objectives"][0]["risk"] = json!("highest");
    }

    let seed_path = dir.join("seed.json");
    std::fs::write(&seed_path, serde_json::to_string_pretty(&seed).unwrap()).unwrap();

    let keyring_path = dir.join("producers.toml");
    std::fs::write(
        &keyring_path,
        format!("[producers]\n{key_id} = \"{}\"\n", kp.public_hex()),
    )
    .unwrap();

    (seed_path, keyring_path)
}

fn run_verify(seed: &std::path::Path, keyring: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_redteam-seed"))
        .args(["verify", "--seed", seed.to_str().unwrap(), "--keyring", keyring.to_str().unwrap()])
        .env_remove("CODERED_PRODUCER_PUBKEYS") // isolate from the host env
        .output()
        .unwrap()
}

#[test]
fn valid_signed_seed_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let (seed, keyring) = fixture(dir.path(), "producer-key-1", false);

    let out = run_verify(&seed, &keyring);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("OK: seed v1"), "stdout: {stdout}");
    assert!(stdout.contains("obj-1"), "stdout: {stdout}");
}

#[test]
fn tampered_seed_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (seed, keyring) = fixture(dir.path(), "producer-key-1", true);

    let out = run_verify(&seed, &keyring);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("REJECTED"));
}
