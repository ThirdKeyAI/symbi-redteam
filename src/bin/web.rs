//! `redteam-web` — start the local, read-only engagement web viewer (see the
//! `web` module in the `symbi_redteam` crate). Read-only and unauthenticated:
//! bind to localhost and do not expose it to a network.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use symbi_redteam::web::{resolve_engagement, serve, AppState};

#[derive(Parser, Debug)]
#[command(name = "redteam-web", about = "Read-only web viewer for one pen-test engagement")]
struct Args {
    /// Engagement SQLite database to serve (opened read-only).
    #[arg(long, default_value = "data/redteam.db")]
    db: PathBuf,

    /// Engagement id to serve. Optional when the DB holds exactly one.
    #[arg(long)]
    engagement: Option<String>,

    /// Port to bind.
    #[arg(long, default_value_t = 8088)]
    port: u16,

    /// Address to bind. Defaults to localhost — there is no auth layer.
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Hash-chained audit journal, for the integrity badge. Auto-located at
    /// `.symbiont/audit/audit.jsonl` next to the DB when omitted.
    #[arg(long)]
    journal: Option<PathBuf>,

    /// `report.md` to render on the Report page. Auto-located under `reports/`
    /// when omitted.
    #[arg(long)]
    report: Option<PathBuf>,
}

fn auto_journal(db: &std::path::Path) -> Option<PathBuf> {
    let base = db.parent().unwrap_or_else(|| std::path::Path::new("."));
    [
        base.join(".symbiont/audit/audit.jsonl"),
        base.join("../.symbiont/audit/audit.jsonl"),
        PathBuf::from(".symbiont/audit/audit.jsonl"),
        PathBuf::from("audit-logs/audit.jsonl"),
    ]
    .into_iter()
    .find(|cand| cand.exists())
}

fn auto_report(eng: &str) -> Option<PathBuf> {
    [
        PathBuf::from(format!("reports/{eng}/report.md")),
        PathBuf::from("reports/report.md"),
    ]
    .into_iter()
    .find(|cand| cand.exists())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let engagement_id = resolve_engagement(&args.db, args.engagement)
        .with_context(|| format!("resolving engagement in {}", args.db.display()))?;

    let journal_path = args.journal.or_else(|| auto_journal(&args.db));
    let report_path = args.report.or_else(|| auto_report(&engagement_id));

    println!("redteam-web: engagement {engagement_id} from {}", args.db.display());
    if journal_path.is_none() {
        eprintln!("redteam-web: no audit journal located — integrity badge will show UNKNOWN");
    }

    let state = AppState {
        db_path: args.db,
        engagement_id,
        journal_path,
        report_path,
    };
    serve(state, &args.bind, args.port)
}
