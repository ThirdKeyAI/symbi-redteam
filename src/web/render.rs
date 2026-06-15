//! maud rendering: the page shell plus per-view markup. Handlers fetch data
//! (via [`crate::web::query`]) and pass it here; nothing in this module touches
//! the database.
//!
//! Visual system is inherited from the codered "Signal" theme (`assets/app.css`):
//! mono chrome (JetBrains Mono), outline severity badges, status as colored
//! text + glyph (never color alone), audit-integrity badge in the chrome on
//! every page.

use maud::{html, Markup, PreEscaped, DOCTYPE};

use crate::web::query::{
    target_label, FindingDetail, FindingsPage, Overview, ToolRunRow, TripleRow,
};

/// Nav entries as `(path, label)`; `path` is also the active-highlight key.
const NAV: &[(&str, &str)] = &[
    ("/", "Overview"),
    ("/findings", "Findings"),
    ("/graph", "Graph"),
    ("/knowledge", "Knowledge"),
    ("/evidence", "Evidence"),
    ("/report", "Report"),
    ("/help", "Help"),
];

// ---------------------------------------------------------------------------
// Audit integrity (hash-chain linkage badge in chrome, panel on Overview /
// Evidence). Handlers compute this from `query::verify_chain_linkage`.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub enum AuditStatus {
    /// Chain links AND a valid Ed25519 seal attests the current head.
    Sealed,
    /// Chain links cleanly, but no valid seal is present.
    Intact,
    Broken,
    Unknown,
}

#[derive(Clone, Copy)]
pub struct AuditInfo {
    pub status: AuditStatus,
    pub entries: usize,
}

impl AuditInfo {
    pub fn unknown() -> Self {
        AuditInfo { status: AuditStatus::Unknown, entries: 0 }
    }
}

fn audit_badge(a: &AuditInfo) -> Markup {
    match a.status {
        AuditStatus::Sealed => html! {
            span class="audit-badge audit-badge--intact" title="The hash-chained journal links cleanly AND a valid Ed25519 seal attests the current chain head." {
                "✓ AUDIT SEALED · " (a.entries)
            }
        },
        AuditStatus::Intact => html! {
            span class="audit-badge audit-badge--intact" title="The hash-chained audit journal links cleanly from genesis (each entry references the prior entry's hash)." {
                "✓ AUDIT LINKED · " (a.entries)
            }
        },
        AuditStatus::Broken => html! {
            span class="audit-badge audit-badge--broken" title="The audit chain failed linkage — an entry was reordered, altered, or is missing." { "✕ CHAIN BROKEN" }
        },
        AuditStatus::Unknown => html! {
            span class="audit-badge audit-badge--unknown" title="No hash-chained audit journal located for this engagement." { "— AUDIT UNKNOWN" }
        },
    }
}

fn audit_panel(a: &AuditInfo) -> Markup {
    let broken = matches!(a.status, AuditStatus::Broken);
    let (glyph, head, sub) = match a.status {
        AuditStatus::Sealed => (
            "✓",
            format!("AUDIT CHAIN SEALED — {} ENTRIES", a.entries),
            "The hash-chained journal links cleanly from genesis AND a valid Ed25519 seal signs the current chain head. A forged-but-relinked journal would fail this seal, because the attacker lacks the engagement private key.".to_string(),
        ),
        AuditStatus::Intact => (
            "✓",
            format!("AUDIT CHAIN LINKED — {} ENTRIES", a.entries),
            "Every gated action is appended to a hash-chained journal; each entry references the previous entry's hash. This view re-checks that linkage from genesis on every load. For full cryptographic verification run `symbi audit verify`.".to_string(),
        ),
        AuditStatus::Broken => (
            "✕",
            "AUDIT CHAIN BROKEN".to_string(),
            "The hash chain failed linkage — an entry was altered, reordered, or is missing. Treat every finding and verdict in this engagement as untrusted until the journal is restored.".to_string(),
        ),
        AuditStatus::Unknown => (
            "—",
            "AUDIT CHAIN UNKNOWN".to_string(),
            "No hash-chained audit journal was located for this engagement, so integrity cannot be checked here. Pass --journal to point at one.".to_string(),
        ),
    };
    html! {
        div class=(if broken { "audit-panel audit-panel--broken" } else { "audit-panel" }) {
            div class="glyph" { (glyph) }
            div style="flex:1" {
                div style="font-family:var(--mono);font-size:12px;font-weight:600;letter-spacing:0.08em" class=(if broken {"st--neutral"} else {"st--ok"}) { (head) }
                div class="muted" style="font-size:12.5px;line-height:1.55;margin-top:6px;max-width:860px" { (sub) }
            }
        }
    }
}

/// A small circled-"i" hint with a native hover tooltip (`title`).
pub fn info(hint: &str) -> Markup {
    html! { span class="info" title=(hint) { "i" } }
}

// ---------------------------------------------------------------------------
// Shared status components
// ---------------------------------------------------------------------------

fn sev_class_label(sev: &str) -> (&'static str, &'static str) {
    match sev {
        "critical" => ("crit", "CRIT"),
        "high" => ("high", "HIGH"),
        "medium" => ("med", "MED"),
        "low" => ("low", "LOW"),
        _ => ("info", "INFO"),
    }
}

fn sev_badge(sev: &str) -> Markup {
    let (c, l) = sev_class_label(sev);
    html! { span class=(format!("badge-sev badge-sev--{c}")) { (l) } }
}

/// Validate-agent verification state as colored text + glyph (never color
/// alone). A finding is `verified`, `false_positive`, or still pending.
fn verif_st(verified: bool, false_positive: bool) -> Markup {
    let (cls, txt) = if verified {
        ("st--ok", "✓ verified")
    } else if false_positive {
        ("st--neutral", "✕ false positive")
    } else {
        ("st--none", "— unverified")
    };
    html! { span class=(format!("st {cls}")) { (txt) } }
}

fn phase_chip(phase: &str) -> Markup {
    html! { span class="chip" { (phase) } }
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

/// The full HTML shell. `active` is the nav path to highlight; `audit` rides in
/// the chrome on every page.
pub fn shell(active: &str, title: &str, audit: &AuditInfo, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "symbi-redteam · " (title) }
                link rel="stylesheet" href="/assets/app.css";
                // app.js loads in <head> so the stored theme/density apply pre-paint.
                script src="/assets/app.js" {}
                script src="/assets/htmx.min.js" {}
            }
            body id="top" {
                header class="site-header" {
                    div class="inner" {
                        a href="/" class="wordmark" style="text-decoration:none;color:inherit" { "symbi" b { "redteam" } }
                        nav class="nav" {
                            @for (path, label) in NAV {
                                a href=(path) class=(if *path == active { "active" } else { "" }) { (label) }
                            }
                        }
                        (audit_badge(audit))
                        button id="theme-toggle" class="theme-toggle" type="button" title="Toggle light / dark" { "☀" }
                    }
                }
                main { (body) }
                a id="totop" href="#top" class="totop" title="Back to top" { "↑" }
                footer class="site-footer" {
                    "© 2026 "
                    a href="https://thirdkey.ai" target="_blank" rel="noopener noreferrer" { "ThirdKey.ai" }
                    " · powered by "
                    a href="https://symbiont.dev" target="_blank" rel="noopener noreferrer" { "Symbiont" }
                }
            }
        }
    }
}

pub fn error_page(title: &str, msg: &str) -> Markup {
    let code = title.split_whitespace().next().unwrap_or("error");
    shell(
        "",
        title,
        &AuditInfo::unknown(),
        html! {
            div class="error-page" {
                div class="code" { (code) }
                div class="msg" { (msg) }
                a href="/" class="btn btn--primary" style="margin-top:8px;text-decoration:none" { "← back to overview" }
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

pub fn overview(o: &Overview, audit: &AuditInfo) -> Markup {
    let total_sev: i64 = o.severity.iter().map(|(_, n)| n).sum::<i64>().max(1);
    let tile = |n: i64, label: &str, sub: Markup| {
        html! { div class="tile" { div class="n" { (n) } div class="label" { (label) } div class="sub" { (sub) } } }
    };
    shell(
        "/",
        "Overview",
        audit,
        html! {
            div style="display:flex;flex-direction:column;gap:20px" {
                div class="eng-head" {
                    div {
                        div class="eyebrow" { "ENGAGEMENT" }
                        div class="eng-title" { (o.client) " " span class="sub" { "— pen-test engagement" } }
                        div class="eng-meta" {
                            span class="chip" { "status: " (o.status) }
                            span { (o.start_date) " → " (o.end_date) }
                            span { "created " (o.created_at) }
                        }
                    }
                    (audit_panel(audit))
                }

                div class="tiles" {
                    (tile(o.total_findings, "FINDINGS", html!{ span class="st--ok" { (o.verified) " verified" } }))
                    (tile(o.false_positive, "FALSE POSITIVES", html!{ "adjudicated by validate" }))
                    (tile(o.pending, "UNVERIFIED", html!{ "awaiting validate" }))
                    (tile(o.tool_runs, "TOOL RUNS", html!{ "Cedar-gated executions" }))
                    (tile(o.knowledge, "KNOWLEDGE", html!{ "reflector triples" }))
                    (tile(o.retests, "RETESTS", html!{ "remediation deltas" }))
                }

                div class="breakdowns" {
                    div class="tile" {
                        div class="panel__title" style="margin-bottom:12px" { "SEVERITY" }
                        div style="display:flex;flex-direction:column;gap:9px" {
                            @if o.severity.is_empty() { div class="muted" style="font-size:12px" { "no findings yet" } }
                            @for (sev, n) in &o.severity {
                                @let pct = (*n as f64 / total_sev as f64 * 100.0).round();
                                @let (c, _) = sev_class_label(sev);
                                div class="label-row" {
                                    (sev_badge(sev))
                                    span class="mono" style="text-align:right;font-size:11px" { (n) }
                                    div class="bar" { span style=(format!("width:{pct}%;background:var(--{c})")) {} }
                                }
                            }
                        }
                    }
                    div class="tile" {
                        div class="panel__title" style="margin-bottom:12px" { "PHASE" }
                        div style="display:flex;flex-direction:column;gap:9px" {
                            @if o.phases.is_empty() { div class="muted" style="font-size:12px" { "no findings yet" } }
                            @for (ph, n) in &o.phases {
                                div style="display:flex;justify-content:space-between;align-items:center" {
                                    (phase_chip(ph))
                                    span class="mono" style="font-size:11px" { (n) }
                                }
                            }
                        }
                        div class="sub" style="margin-top:12px;border-top:1px solid var(--border-subtle);padding-top:9px" { "recon → enum → vuln → exploit → post_exploit" }
                    }
                    div class="tile" {
                        div class="panel__title" style="margin-bottom:12px" { "CEDAR DECISIONS" }
                        div style="display:flex;flex-direction:column;gap:7px" {
                            @if o.cedar.is_empty() { div class="muted" style="font-size:12px" { "no tool runs recorded" } }
                            @for (k, n) in &o.cedar {
                                @let cls = match k.as_str() { "Allow" | "allow" | "permit" => "st--ok", "Deny" | "deny" | "forbid" => "st--neutral", _ => "st--none" };
                                div style="display:flex;justify-content:space-between;align-items:center" {
                                    span class=(format!("st {cls}")) { (k) }
                                    span class="mono" style="font-size:11px" { (n) }
                                }
                            }
                        }
                        div class="sub" style="margin-top:12px;border-top:1px solid var(--border-subtle);padding-top:9px" { "every tool run gated at the ORGA loop" }
                    }
                }
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

fn findings_fragment(p: &FindingsPage) -> Markup {
    let last = if p.page_size == 0 { 0 } else { (p.total - 1).max(0) / p.page_size as i64 };
    let from = p.page as i64 * p.page_size as i64 + 1;
    let to = (from + p.rows.len() as i64 - 1).max(0);
    html! {
        div class="data-table-wrap" id="findings-table" {
            table class="data-table" {
                thead { tr {
                    th { "ID" } th { "SEV ↓" } th { "TITLE" } th { "TARGET" }
                    th { "PHASE" } th { "TOOL" } th { "CVSS" } th { "VALIDATE" }
                } }
                tbody {
                    @for f in &p.rows {
                        tr {
                            td class="id" { a href=(format!("/findings/{}", f.id)) { (f.id) } }
                            td { (sev_badge(&f.severity)) }
                            td { (f.title) }
                            td class="mono muted" style="font-size:10.5px" {
                                (target_label(f.target_ip.as_deref(), f.target_port, f.service.as_deref()))
                            }
                            td { (phase_chip(&f.phase)) }
                            td class="mono muted" style="font-size:10.5px" { (f.tool) }
                            td class="mono" style="font-size:11px" {
                                (f.cvss_score.map(|c| format!("{c:.1}")).unwrap_or_else(|| "—".into()))
                            }
                            td { (verif_st(f.verified, f.false_positive)) }
                        }
                    }
                    @if p.rows.is_empty() { tr { td colspan="8" class="muted" { "no findings match" } } }
                }
            }
        }
        div style="display:flex;justify-content:space-between;align-items:center;font-family:var(--mono);font-size:10.5px;color:var(--faint);margin-top:12px" {
            span { "showing " (from) "–" (to) " of " (p.total) " · sorted by severity" }
            div class="pagination" {
                @if p.page > 0 { a href=(format!("?page={}", p.page - 1)) { "‹ prev" } }
                @else { span class="disabled" { "‹ prev" } }
                span class="current" { (p.page + 1) }
                @if (p.page as i64) < last { a href=(format!("?page={}", p.page + 1)) { "next ›" } }
                @else { span class="disabled" { "next ›" } }
            }
        }
    }
}

pub fn findings(
    p: &FindingsPage,
    sel_phase: &str,
    sel_sev: &str,
    sel_tool: &str,
    audit: &AuditInfo,
) -> Markup {
    let verified = p.rows.iter().filter(|f| f.verified).count();
    shell(
        "/findings",
        "Findings",
        audit,
        html! {
            div style="display:flex;flex-direction:column;gap:14px" {
                div style="display:flex;align-items:baseline;gap:12px" {
                    h1 style="margin:0;font-size:var(--fs-h2)" { "Findings" }
                    span class="mono faint" style="font-size:11px" { (p.total) " total · " (verified) " verified on this page" }
                }
                form class="filterbar" method="get" action="/findings" {
                    select class="select" name="phase" {
                        option value="" { "phase: any" }
                        @for ph in &p.phases { option value=(ph) selected[ph == sel_phase] { "phase: " (ph) } }
                    }
                    select class="select" name="severity" {
                        option value="" { "severity: any" }
                        @for s in &p.severities { option value=(s) selected[s == sel_sev] { "severity: " (s) } }
                    }
                    select class="select" name="tool" {
                        option value="" { "tool: any" }
                        @for t in &p.tools { option value=(t) selected[t == sel_tool] { "tool: " (t) } }
                    }
                    button class="btn btn--primary" type="submit" { "filter" }
                    @if !sel_phase.is_empty() || !sel_sev.is_empty() || !sel_tool.is_empty() {
                        a href="/findings" class="btn" style="text-decoration:none" { "clear" }
                    }
                    span style="flex:1" {}
                    div class="segmented" {
                        button type="button" class="active" data-density="compact" { "COMPACT" }
                        button type="button" data-density="comfortable" { "COMFORTABLE" }
                    }
                }
                (findings_fragment(p))
            }
        },
    )
}

pub fn finding_detail(d: &FindingDetail, audit: &AuditInfo) -> Markup {
    shell(
        "/findings",
        &format!("Finding {}", d.id),
        audit,
        html! {
            div style="display:flex;flex-direction:column;gap:16px" {
                div class="breadcrumb" { a href="/findings" { "Findings" } " / " (d.id) }
                div style="display:flex;justify-content:space-between;align-items:flex-start;gap:24px" {
                    div style="display:flex;flex-direction:column;gap:10px" {
                        div style="display:flex;align-items:center;gap:10px" {
                            (sev_badge(&d.severity))
                            span class="mono" style="font-size:12px;color:var(--link)" { (d.id) }
                            (verif_st(d.verified, d.false_positive))
                        }
                        div style="font-size:21px;font-weight:650;line-height:1.3;max-width:940px" { (d.title) }
                    }
                }
                div class="meta-grid" {
                    div {
                        div class="eyebrow" style="margin-bottom:6px" { "TARGET" }
                        div class="mono" style="font-size:12px" {
                            (target_label(d.target_ip.as_deref(), d.target_port, d.service.as_deref()))
                        }
                    }
                    div {
                        div class="eyebrow" style="margin-bottom:6px" { "PHASE / TOOL" }
                        div style="display:flex;gap:6px" { (phase_chip(&d.phase)) span class="chip" { (d.tool) } }
                    }
                    div {
                        div class="eyebrow" style="margin-bottom:6px" { "CVSS / CVE" }
                        div class="mono" style="font-size:12px" {
                            (d.cvss_score.map(|c| format!("{c:.1}")).unwrap_or_else(|| "—".into()))
                            @if let Some(cve) = d.cve_ids.as_deref().filter(|s| !s.is_empty()) { " · " (cve) }
                        }
                    }
                    div {
                        div class="eyebrow" style="margin-bottom:6px" { "EVIDENCE" }
                        div class="mono" style="font-size:10.5px;color:var(--link);word-break:break-all" {
                            (d.evidence_path.clone().unwrap_or_else(|| "—".into()))
                        }
                    }
                }
                div class="panel" style="padding:16px 18px" {
                    div class="eyebrow" style="margin-bottom:10px" { "DESCRIPTION" }
                    div style="font-size:13.5px;line-height:1.65;color:var(--muted);max-width:1080px;white-space:pre-wrap" { (d.description) }
                }
                @if let Some(rem) = d.remediation.as_deref().filter(|s| !s.is_empty()) {
                    div class="panel" style="padding:16px 18px" {
                        div class="eyebrow" style="margin-bottom:10px" { "REMEDIATION" }
                        div style="font-size:13.5px;line-height:1.65;color:var(--muted);max-width:1080px;white-space:pre-wrap" { (rem) }
                    }
                }
                // Validate-agent adjudication history — the separation-of-duties trail.
                div class="panel" {
                    div class="eyebrow" style="padding:14px 18px 10px" { "VALIDATE-AGENT ADJUDICATION · " (d.verifications.len()) }
                    div class="data-table-wrap" style="border:0;border-top:1px solid var(--border);border-radius:0" {
                        table class="data-table" {
                            thead { tr { th { "VERDICT" } th { "VERIFIER" } th { "RATIONALE" } th { "WHEN" } } }
                            tbody {
                                @for v in &d.verifications {
                                    @let cls = if v.verdict == "verified" { "st--ok" } else { "st--neutral" };
                                    tr {
                                        td { span class=(format!("st {cls}")) { (v.verdict) } }
                                        td class="mono muted" style="font-size:10.5px" { (v.verifier) }
                                        td class="muted" { (v.rationale) }
                                        td class="mono faint" style="font-size:10px" { (v.created_at) }
                                    }
                                }
                                @if d.verifications.is_empty() {
                                    tr { td colspan="4" class="muted" { "not yet adjudicated by the validate agent" } }
                                }
                            }
                        }
                    }
                }
                div style="font-family:var(--mono);font-size:10px;color:var(--faint)" { "discovered: " (d.created_at) }
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Knowledge
// ---------------------------------------------------------------------------

pub fn knowledge(triples: &[TripleRow], audit: &AuditInfo) -> Markup {
    shell(
        "/knowledge",
        "Knowledge",
        audit,
        html! {
            div style="display:flex;flex-direction:column;gap:14px" {
                div style="display:flex;align-items:baseline;gap:12px" {
                    h1 style="margin:0;font-size:var(--fs-h2)" { "Knowledge triples" }
                    span class="mono faint" style="font-size:11px" { (triples.len()) " facts distilled by the reflector between phases" }
                }
                div class="data-table-wrap" {
                    table class="data-table" {
                        thead { tr { th { "SUBJECT" } th { "PREDICATE" } th { "OBJECT" } th { "CONF ↓" } th { "PHASE" } th { "SOURCE" } } }
                        tbody {
                            @for (s, pred, obj, conf, src, phase) in triples {
                                tr {
                                    td class="mono" style="font-size:10.5px;line-height:1.45" { (s) }
                                    td { span class="chip" { (pred) } }
                                    td class="mono muted" style="font-size:10.5px;line-height:1.45" { (obj) }
                                    td {
                                        span class="mono" style="font-size:11px" { (format!("{conf:.2}")) }
                                        span class="bar" style="width:64px;height:3px;margin-top:5px" { span style=(format!("width:{}%;background:var(--muted)", (conf * 100.0).round())) {} }
                                    }
                                    td { (phase_chip(phase)) }
                                    td class="faint" style="font-size:11px" { (src.clone().unwrap_or_else(|| "—".into())) }
                                }
                            }
                            @if triples.is_empty() { tr { td colspan="6" class="muted" { "no knowledge triples" } } }
                        }
                    }
                }
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Evidence = tool_runs
// ---------------------------------------------------------------------------

pub fn evidence(rows: &[ToolRunRow], audit: &AuditInfo) -> Markup {
    shell(
        "/evidence",
        "Evidence",
        audit,
        html! {
            div style="display:flex;flex-direction:column;gap:16px" {
                div style="display:flex;align-items:baseline;gap:12px" {
                    h1 style="margin:0;font-size:var(--fs-h2)" { "Evidence — tool runs" }
                    span class="mono faint" style="font-size:11px" { (rows.len()) " Cedar-gated executions" }
                }
                (audit_panel(audit))
                div class="data-table-wrap" {
                    table class="data-table" {
                        thead { tr { th { "TOOL" } th { "COMMAND" } th { "EXIT" } th { "MS" } th { "CEDAR" } th { "APPROVED BY" } th { "WHEN ↓" } } }
                        tbody {
                            @for e in rows {
                                @let dec = e.cedar_decision.clone().unwrap_or_else(|| "—".into());
                                @let dcls = match dec.as_str() { "Allow" | "allow" | "permit" => "st--ok", "Deny" | "deny" | "forbid" => "st--neutral", _ => "st--none" };
                                tr {
                                    td class="mono" style="font-size:10.5px" { (e.tool) }
                                    td class="mono muted" style="font-size:10px;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title=(e.command) { (e.command) }
                                    td class="mono" style="font-size:10.5px" { (e.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "—".into())) }
                                    td class="mono faint" style="font-size:10px" { (e.duration_ms.map(|d| d.to_string()).unwrap_or_else(|| "—".into())) }
                                    td { span class=(format!("st {dcls}")) { (dec) }
                                        @if let Some(pol) = e.cedar_policy.as_deref().filter(|s| !s.is_empty()) { " " span class="faint mono" style="font-size:9px" { (pol) } }
                                    }
                                    td class="mono faint" style="font-size:10px" { (e.approved_by.clone().unwrap_or_else(|| "—".into())) }
                                    td class="mono faint" style="font-size:10px" { (e.created_at) }
                                }
                            }
                            @if rows.is_empty() { tr { td colspan="7" class="muted" { "no tool runs recorded" } } }
                        }
                    }
                }
                div class="mono faint" style="font-size:10.5px" { "every execution is recorded before the next tool can run (evidence-chain integrity)" }
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

pub fn graph(audit: &AuditInfo) -> Markup {
    shell(
        "/graph",
        "Graph",
        audit,
        html! {
            div style="display:flex;flex-direction:column;gap:14px" {
                div style="display:flex;align-items:baseline;gap:12px" {
                    h1 style="margin:0;font-size:var(--fs-h2)" { "Engagement graph" }
                    span class="muted" style="font-size:12px" {
                        "Findings cluster under their target host; edges are reflector "
                        a href="/knowledge" { "knowledge" } " relationships. Click a finding node to open it."
                    }
                }
                div class="graph-full" {
                    div class="graph-controls" {
                        label { "cluster by"
                            select id="cluster-by" {
                                option value="host" selected { "host" }
                                option value="severity" { "severity" }
                                option value="phase" { "phase" }
                                option value="none" { "none" }
                            }
                        }
                        label { "color by"
                            select id="color-by" {
                                option value="severity" selected { "severity" }
                                option value="status" { "validate status" }
                                option value="phase" { "phase" }
                                option value="tool" { "tool" }
                            }
                        }
                        button id="graph-relayout" class="btn btn--primary" type="button" { "re-layout" }
                        button id="graph-fit" class="btn" type="button" { "fit" }
                        span id="graph-status" {}
                    }
                    div class="graph-wrap" {
                        div id="cy" {}
                        div id="cy-legend" class="graph-legend" {}
                    }
                }
                script src="/assets/cytoscape.min.js" {}
                script src="/assets/fcose-bundle.js" {}
                script src="/assets/graph.js" {}
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

pub fn report(html_body: Option<String>, audit: &AuditInfo) -> Markup {
    shell(
        "/report",
        "Report",
        audit,
        html! {
            div style="display:flex;flex-direction:column;gap:18px;align-items:center" {
                @match html_body {
                    Some(h) => div class="prose" { (PreEscaped(h)) },
                    None => p class="muted" { "No report.md found. Generate one with the reporter agent (or pass --report <path>)." },
                }
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

pub fn help(audit: &AuditInfo) -> Markup {
    const TERMS: &[(&str, &str)] = &[
        ("Finding", "A single potential issue discovered in a phase (recon, enum, vuln, exploit, post_exploit) by a specific tool."),
        ("Severity", "Impact ranking: critical > high > medium > low > info. Always shown as a labeled badge, never color alone."),
        ("Validate status", "The validate agent adjudicates each finding: ✓ verified (evidence supports it), ✕ false positive, or — unverified (not yet adjudicated). It is the only principal allowed to flip these."),
        ("Tool run", "A single Cedar-gated tool execution, recorded with its command, exit code, and the policy decision (allow/deny) that authorized it."),
        ("Cedar decision", "The ORGA Gate's verdict for a tool run. Every offensive action is policy-checked before it executes; denials are expected behavior, not errors."),
        ("Knowledge triple", "A reusable (subject, predicate, object) fact the reflector distilled between phases, e.g. (smb_null_session, enabled_on, 10.0.2.15:445)."),
        ("Retest", "A delta against a baseline engagement: remediated, persistent, regressed, or new."),
        ("Audit chain", "The hash-chained JSONL journal of every gated action. ✓ linked means each entry references the prior entry's hash with no gaps. Full cryptographic verification is done by `symbi audit verify`."),
    ];
    shell(
        "/help",
        "Help",
        audit,
        html! {
            div style="display:flex;flex-direction:column;gap:14px" {
                h1 style="margin:0;font-size:var(--fs-h2)" { "Help & glossary" }
                p class="muted" style="font-size:13px;margin:0" { "A read-only viewer for one pen-test engagement. Hover the " (info("example hint")) " icons throughout the UI for inline explanations." }
                div class="glossary" {
                    @for (term, def) in TERMS { div { dt { (term) } dd { (def) } } }
                }
            }
        },
    )
}
