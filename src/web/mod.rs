//! `redteam-web` — a local, read-only web viewer for one pen-test engagement.
//!
//! The `redteam-web` binary (`src/bin/web.rs`) builds an [`AppState`] and calls
//! [`serve`]. Everything here is read-only: the SQLite connection is opened with
//! `SQLITE_OPEN_READ_ONLY` and no route mutates the database. There is no auth
//! layer — bind to `127.0.0.1` (the default) and do not expose this to a
//! network. Ported from the `symbi-codered-web` viewer, reworked for the pen-test
//! schema (findings, tool runs, validate-agent verifications, knowledge triples).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rusqlite::{Connection, OpenFlags};
use tower_http::set_header::SetResponseHeaderLayer;

pub mod assets;
pub mod handlers;
pub mod query;
pub mod render;

/// Content-Security-Policy applied to every response. `script-src 'self'` means
/// an injected inline `<script>` (e.g. a hostile finding title that reached the
/// DOM, or planted HTML inside the rendered report) cannot execute. Inline
/// `style=` attributes (severity bars) need `'unsafe-inline'` for styles only,
/// which cannot run JS.
const CSP: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
     object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

/// Shared, cloneable state. Holds only paths + the resolved engagement id; a
/// fresh read-only connection is opened per request (read-only opens are cheap
/// and sidestep shared-mutable-state / Send+Sync concerns).
#[derive(Clone)]
pub struct AppState {
    pub db_path: PathBuf,
    /// Engagement ids in this schema are arbitrary TEXT (e.g.
    /// `eng-juiceshop-001`), not UUIDs.
    pub engagement_id: String,
    /// Hash-chained audit journal, for the evidence-integrity badge. Best
    /// effort: `None` (or a missing file) renders the badge as "unknown".
    pub journal_path: Option<PathBuf>,
    /// Path to `report.md`. `None` => the report page shows a generate notice.
    pub report_path: Option<PathBuf>,
}

impl AppState {
    /// Open a fresh read-only connection to the engagement DB.
    pub fn conn(&self) -> rusqlite::Result<Connection> {
        Connection::open_with_flags(
            &self.db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
    }
}

/// Resolve which engagement to serve: the `override_id` if given (verified to
/// exist), else the sole engagement in the DB, else an error listing the
/// candidates.
pub fn resolve_engagement(db_path: &Path, override_id: Option<String>) -> Result<String> {
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening {} read-only", db_path.display()))?;
    let mut stmt = conn
        .prepare("SELECT id FROM engagements ORDER BY created_at")
        .context("reading engagements")?;
    let ids: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();
    match override_id {
        Some(id) => {
            if ids.iter().any(|s| s == &id) {
                Ok(id)
            } else {
                bail!("engagement {id} not found in {}", db_path.display());
            }
        }
        None => match ids.as_slice() {
            [] => bail!("no engagements in {}", db_path.display()),
            [only] => Ok(only.clone()),
            many => bail!(
                "multiple engagements; pass --engagement <id>:\n  {}",
                many.join("\n  ")
            ),
        },
    }
}

async fn healthz() -> &'static str {
    "ok"
}

/// Build the axum router (exposed for tests via `tower::ServiceExt::oneshot`).
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handlers::overview))
        .route("/findings", get(handlers::findings))
        .route("/findings/:id", get(handlers::finding_detail))
        .route("/knowledge", get(handlers::knowledge))
        .route("/evidence", get(handlers::evidence))
        .route("/graph", get(handlers::graph))
        .route("/report", get(handlers::report))
        .route("/help", get(handlers::help))
        .route("/api/graph", get(handlers::api_graph))
        .route("/assets/htmx.min.js", get(assets::htmx))
        .route("/assets/app.css", get(assets::css))
        .route("/assets/app.js", get(assets::app_js))
        .route("/assets/cytoscape.min.js", get(assets::cytoscape))
        .route("/assets/fcose-bundle.js", get(assets::fcose))
        .route("/assets/graph.js", get(assets::graph_js))
        .route("/assets/fonts/:file", get(assets::font))
        .route("/healthz", get(healthz))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .with_state(state)
}

/// Serve the viewer (blocking; builds its own tokio runtime).
pub fn serve(state: AppState, bind: &str, port: u16) -> Result<()> {
    // Fail fast on a bad DB / engagement before binding.
    let _ = state.conn().context("opening engagement DB read-only")?;
    let addr: SocketAddr = format!("{bind}:{port}")
        .parse()
        .with_context(|| format!("invalid bind address {bind}:{port}"))?;
    let app = build_router(state);

    let rt = tokio::runtime::Runtime::new().context("building tokio runtime for serve")?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr}"))?;
        println!("redteam-web: read-only viewer on http://{addr}");
        axum::serve(listener, app).await.context("axum serve")
    })
}

// ---------------------------------------------------------------------------
// Error type: any handler returns Result<Markup, AppError>.
// ---------------------------------------------------------------------------

pub enum AppError {
    NotFound(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e)
    }
}
impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::NotFound(what) => {
                (StatusCode::NOT_FOUND, render::error_page("Not found", &what)).into_response()
            }
            AppError::Internal(e) => {
                tracing::error!("web handler error: {e:#}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    render::error_page("Internal error", "An error occurred (see server logs)."),
                )
                    .into_response()
            }
        }
    }
}
