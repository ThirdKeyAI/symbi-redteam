//! `redteam-seed` — verify a signed validation seed against pinned producer
//! keys before any objective is acted on. A seed grants no authority; this is
//! the gate that confirms it actually came from a trusted producer (e.g.
//! CodeRed) and was not tampered with in transit.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use symbi_redteam::seed::{verify_seed_file, ProducerKeyring};

#[derive(Parser, Debug)]
#[command(name = "redteam-seed", about = "Verify signed validation seeds")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Verify a seed file's signature against the pinned producer keyring.
    Verify {
        /// Path to the seed JSON.
        #[arg(long)]
        seed: PathBuf,
        /// TOML keyring file with a `[producers]` table (key_id = "hex").
        /// Defaults to `keys/producers.toml` if present.
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    match args.cmd {
        Cmd::Verify { seed, keyring } => {
            let toml_path = keyring.unwrap_or_else(|| PathBuf::from("keys/producers.toml"));
            let env = std::env::var("CODERED_PRODUCER_PUBKEYS").ok();
            let kr = match ProducerKeyring::resolve(env.as_deref(), Some(&toml_path)) {
                Ok(kr) => kr,
                Err(e) => {
                    eprintln!("keyring error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if kr.is_empty() {
                eprintln!(
                    "no producer keys pinned — set CODERED_PRODUCER_PUBKEYS or provide {}",
                    toml_path.display()
                );
                return ExitCode::FAILURE;
            }
            match verify_seed_file(&seed, &kr) {
                Ok(v) => {
                    println!(
                        "OK: seed v{} from {:?} (key_id={}) — {} objective(s)",
                        v.seed_version,
                        v.producer,
                        v.key_id,
                        v.objectives.len()
                    );
                    for o in &v.objectives {
                        let id = o.get("id").and_then(|x| x.as_str()).unwrap_or("?");
                        let title = o.get("title").and_then(|x| x.as_str()).unwrap_or("");
                        let risk = o.get("risk").and_then(|x| x.as_str()).unwrap_or("?");
                        println!("  - [{risk}] {id}: {title}");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("REJECTED: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
