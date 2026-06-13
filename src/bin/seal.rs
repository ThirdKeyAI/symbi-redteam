//! `redteam-seal` — cryptographically seal an engagement's audit journal, or
//! verify an existing seal. Sealing signs the hash-chain *head* with the
//! engagement keypair, so one signature attests the whole journal; a
//! forged-but-relinked journal still fails verification.

use std::path::PathBuf;
use std::process::ExitCode;

use chrono::Utc;
use clap::{Parser, Subcommand};

use symbi_redteam::audit::{seal_journal, verify_seal, Seal, SealStatus};
use symbi_redteam::crypto;

#[derive(Parser, Debug)]
#[command(name = "redteam-seal", about = "Seal / verify an audit journal")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Sign the journal head with the engagement key, writing `<eng>.seal`.
    Create {
        #[arg(long)]
        engagement: String,
        /// Hash-chained JSONL audit journal.
        #[arg(long, default_value = ".symbiont/audit/audit.jsonl")]
        journal: PathBuf,
        /// Directory holding the engagement keypair. Generated if absent.
        #[arg(long, default_value = ".symbiont/keys")]
        keys: PathBuf,
        /// Output seal path. Defaults next to the journal as `<eng>.seal`.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a seal against the current journal state.
    Verify {
        #[arg(long)]
        seal: PathBuf,
        #[arg(long, default_value = ".symbiont/audit/audit.jsonl")]
        journal: PathBuf,
    },
}

fn run() -> anyhow::Result<ExitCode> {
    match Args::parse().cmd {
        Cmd::Create { engagement, journal, keys, out } => {
            // Load the engagement keypair, or generate one on first seal.
            let kp = match crypto::load_from(&keys, &engagement) {
                Ok(kp) => kp,
                Err(_) => {
                    eprintln!("redteam-seal: generating new engagement keypair in {}", keys.display());
                    crypto::generate_and_persist_in(&keys, &engagement)?
                }
            };
            let seal = seal_journal(&journal, &kp, &Utc::now().to_rfc3339())?;
            let out = out.unwrap_or_else(|| {
                journal
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join(format!("{engagement}.seal"))
            });
            std::fs::write(&out, serde_json::to_string_pretty(&seal)?)?;
            println!(
                "sealed {} entries (head {}…) -> {}",
                seal.entries,
                &seal.head_hash.chars().take(12).collect::<String>(),
                out.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Verify { seal, journal } => {
            let seal: Seal = serde_json::from_str(&std::fs::read_to_string(&seal)?)?;
            match verify_seal(&journal, &seal) {
                SealStatus::Valid => {
                    println!("VALID: seal matches journal head ({} entries)", seal.entries);
                    Ok(ExitCode::SUCCESS)
                }
                SealStatus::HeadMismatch => {
                    eprintln!("MISMATCH: journal head/entries differ from the seal");
                    Ok(ExitCode::FAILURE)
                }
                SealStatus::BadSignature => {
                    eprintln!("BAD SIGNATURE: seal did not verify against its public key");
                    Ok(ExitCode::FAILURE)
                }
                SealStatus::JournalUnreadable => {
                    eprintln!("UNREADABLE: journal has no verifiable hash chain");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
