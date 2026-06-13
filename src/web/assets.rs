//! Static assets embedded in the binary (no external files at runtime, no JS
//! build step). htmx / cytoscape / fcose are vendored under `assets/`.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

const HTMX: &str = include_str!("../../assets/htmx.min.js");
const CSS: &str = include_str!("../../assets/app.css");
const APP_JS: &str = include_str!("../../assets/app.js");
const CYTOSCAPE: &str = include_str!("../../assets/cytoscape.min.js");
// layout-base + cose-base + cytoscape-fcose concatenated (UMD globals, in
// dependency order) — the fcose layout used for compound/cluster graphs.
const FCOSE: &str = include_str!("../../assets/fcose-bundle.js");
const GRAPH_JS: &str = include_str!("../../assets/graph.js");

const JS: &str = "application/javascript; charset=utf-8";

pub async fn htmx() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, JS)], HTMX)
}

pub async fn css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], CSS)
}

pub async fn app_js() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, JS)], APP_JS)
}

pub async fn cytoscape() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, JS)], CYTOSCAPE)
}

pub async fn fcose() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, JS)], FCOSE)
}

pub async fn graph_js() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, JS)], GRAPH_JS)
}

// Vendored JetBrains Mono (latin subset, 4 weights) for the mono-forward chrome.
const FONT_REGULAR: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-Regular.woff2");
const FONT_MEDIUM: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-Medium.woff2");
const FONT_SEMIBOLD: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-SemiBold.woff2");
const FONT_BOLD: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-Bold.woff2");

pub async fn font(Path(file): Path<String>) -> Response {
    let body: &'static [u8] = match file.as_str() {
        "JetBrainsMono-Regular.woff2" => FONT_REGULAR,
        "JetBrainsMono-Medium.woff2" => FONT_MEDIUM,
        "JetBrainsMono-SemiBold.woff2" => FONT_SEMIBOLD,
        "JetBrainsMono-Bold.woff2" => FONT_BOLD,
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
        .into_response()
}
