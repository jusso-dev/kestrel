//! Embedded operator UI. The SvelteKit build lives in `web/build`.
//!
//! When the `embed-ui` feature is off, or the build directory has no file for
//! a path, a small placeholder is served so the binary still has the routes.

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;

const PLACEHOLDER: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Kestrel</title></head>
<body><p>Kestrel UI build is not embedded. Run <code>npm run build</code> in <code>web/</code>.</p></body>
</html>"#;

pub fn router() -> Router {
    Router::new()
        .fallback(ui)
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
}

async fn ui(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") || path.starts_with("v1/") || path == "api" || path == "v1" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let asset = if path.is_empty() { "index.html" } else { path };
    if let Some((bytes, mime)) = read_asset(asset) {
        return response(bytes, &mime);
    }
    if let Some((bytes, mime)) = read_asset("index.html") {
        return response(bytes, &mime);
    }
    response(PLACEHOLDER.as_bytes().to_vec(), "text/html; charset=utf-8")
}

fn response(bytes: Vec<u8>, mime: &str) -> Response {
    let value =
        HeaderValue::from_str(mime).unwrap_or(HeaderValue::from_static("application/octet-stream"));
    ([(header::CONTENT_TYPE, value)], Body::from(bytes)).into_response()
}

#[cfg(feature = "embed-ui")]
#[derive(rust_embed::Embed)]
#[folder = "../../web/build"]
struct Assets;

fn read_asset(path: &str) -> Option<(Vec<u8>, String)> {
    embedded_asset(path)
}

#[cfg(feature = "embed-ui")]
fn embedded_asset(path: &str) -> Option<(Vec<u8>, String)> {
    let file = Assets::get(path)?;
    let mime = mime_guess::from_path(path)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .to_string();
    Some((file.data.into_owned(), mime))
}

#[cfg(not(feature = "embed-ui"))]
fn embedded_asset(path: &str) -> Option<(Vec<u8>, String)> {
    let _ = path;
    None
}
