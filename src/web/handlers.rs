//! axum handlers: extract params, run a read-only query, render with
//! [`crate::web::render`].

use axum::extract::{Path, Query, State};
use axum::Json;
use maud::Markup;
use serde_json::Value;

use crate::web::query::{self, FindingsQuery, Linkage};
use crate::web::render::{self, AuditInfo, AuditStatus};
use crate::web::{AppError, AppState};

/// Check the hash-chain linkage of the audit journal for the integrity badge.
/// Best effort: a missing/foreign journal renders as "unknown".
fn audit_info(state: &AppState) -> AuditInfo {
    match &state.journal_path {
        Some(p) if p.exists() => match query::verify_chain_linkage(p) {
            Linkage::Linked(n) => AuditInfo { status: AuditStatus::Intact, entries: n },
            Linkage::Broken => AuditInfo { status: AuditStatus::Broken, entries: 0 },
            Linkage::Indeterminate => AuditInfo::unknown(),
        },
        _ => AuditInfo::unknown(),
    }
}

pub async fn overview(State(state): State<AppState>) -> Result<Markup, AppError> {
    let conn = state.conn()?;
    let o = query::overview(&conn, &state.engagement_id)?;
    Ok(render::overview(&o, &audit_info(&state)))
}

pub async fn findings(
    State(state): State<AppState>,
    Query(q): Query<FindingsQuery>,
) -> Result<Markup, AppError> {
    let conn = state.conn()?;
    let page = query::findings_page(&conn, &state.engagement_id, &q)?;
    Ok(render::findings(
        &page,
        q.phase.as_deref().unwrap_or(""),
        q.severity.as_deref().unwrap_or(""),
        q.tool.as_deref().unwrap_or(""),
        &audit_info(&state),
    ))
}

pub async fn finding_detail(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Markup, AppError> {
    let conn = state.conn()?;
    match query::finding_detail(&conn, &state.engagement_id, &id)? {
        Some(d) => Ok(render::finding_detail(&d, &audit_info(&state))),
        None => Err(AppError::NotFound(format!("finding {id}"))),
    }
}

pub async fn knowledge(State(state): State<AppState>) -> Result<Markup, AppError> {
    let conn = state.conn()?;
    let triples = query::knowledge(&conn, &state.engagement_id)?;
    Ok(render::knowledge(&triples, &audit_info(&state)))
}

pub async fn evidence(State(state): State<AppState>) -> Result<Markup, AppError> {
    let conn = state.conn()?;
    let rows = query::tool_runs(&conn, &state.engagement_id)?;
    Ok(render::evidence(&rows, &audit_info(&state)))
}

pub async fn graph(State(state): State<AppState>) -> Markup {
    render::graph(&audit_info(&state))
}

pub async fn report(State(state): State<AppState>) -> Result<Markup, AppError> {
    let html = match &state.report_path {
        Some(p) if p.exists() => {
            let md = std::fs::read_to_string(p).map_err(|e| AppError::Internal(e.into()))?;
            // report.md content is partly derived from untrusted scan output
            // (finding titles/descriptions). Neutralise raw HTML by demoting
            // Html/InlineHtml events to Text so the renderer escapes them.
            use pulldown_cmark::Event;
            let parser = pulldown_cmark::Parser::new(&md).map(|ev| match ev {
                Event::Html(h) => Event::Text(h),
                Event::InlineHtml(h) => Event::Text(h),
                other => other,
            });
            let mut out = String::new();
            pulldown_cmark::html::push_html(&mut out, parser);
            Some(out)
        }
        _ => None,
    };
    Ok(render::report(html, &audit_info(&state)))
}

pub async fn help(State(state): State<AppState>) -> Markup {
    render::help(&audit_info(&state))
}

/// Whole-engagement graph (findings + knowledge concepts as nodes, knowledge
/// relations as edges) for the cluster view.
pub async fn api_graph(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let conn = state.conn()?;
    Ok(Json(query::graph(&conn, &state.engagement_id)?))
}
