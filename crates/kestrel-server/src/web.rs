//! Embedded operator UI. The SvelteKit build lives in `web/build`.
//!
//! When the `embed-ui` feature is off, or the build directory has no file for
//! a path, a small placeholder is served so the binary still has the routes.

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const PLACEHOLDER: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Kestrel</title></head>
<body><p>Kestrel UI build is not embedded. Run <code>npm run build</code> in <code>web/</code>.</p></body>
</html>"#;

// SvelteKit's route announcer is generated in its app entry module. Allow its
// exact accessibility style rather than arbitrary inline styles or scripts.
const ANNOUNCER_STYLE: &str = "position: absolute; left: 0; top: 0; clip: rect(0 0 0 0); clip-path: inset(50%); overflow: hidden; white-space: nowrap; width: 1px; height: 1px";

pub fn router() -> Router {
    Router::new()
        .fallback(ui)
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
            ),
        )
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
        return response(bytes, &mime, asset.starts_with("_app/immutable/"));
    }
    if let Some((bytes, mime)) = read_asset("index.html") {
        return response(bytes, &mime, false);
    }
    response(
        PLACEHOLDER.as_bytes().to_vec(),
        "text/html; charset=utf-8",
        false,
    )
}

fn content_security_policy(html: &str) -> String {
    static SCRIPTS: OnceLock<regex::Regex> = OnceLock::new();
    let scripts = SCRIPTS.get_or_init(|| {
        regex::Regex::new(r"(?is)<script(?:\s[^>]*)?>(.*?)</script\s*>")
            .expect("static script regex")
    });
    let mut policy = "default-src 'self'; frame-ancestors 'none'; script-src 'self'".to_string();
    for script in scripts.captures_iter(html) {
        // HTML parsing normalizes newlines before CSP hashes script text.
        let source = script[1].replace("\r\n", "\n").replace('\r', "\n");
        let digest = Sha256::digest(source.as_bytes());
        policy.push_str(&format!(
            " 'sha256-{}'",
            data_encoding::BASE64.encode(&digest)
        ));
    }
    policy.push_str(&format!(
        "; style-src-attr 'unsafe-hashes' 'sha256-{}'",
        data_encoding::BASE64.encode(&Sha256::digest(ANNOUNCER_STYLE.as_bytes()))
    ));
    policy
}

fn response(bytes: Vec<u8>, mime: &str, immutable: bool) -> Response {
    let value =
        HeaderValue::from_str(mime).unwrap_or(HeaderValue::from_static("application/octet-stream"));
    let policy = if mime.starts_with("text/html") {
        std::str::from_utf8(&bytes)
            .ok()
            .map(content_security_policy)
    } else {
        None
    };
    let mut response = ([(header::CONTENT_TYPE, value)], Body::from(bytes)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    if let Some(policy) = policy.and_then(|policy| HeaderValue::from_str(&policy).ok()) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, policy);
    }
    response
}

#[cfg(all(feature = "embed-ui", kestrel_ui_assets))]
#[derive(rust_embed::Embed)]
#[folder = "../../web/build"]
struct Assets;

fn read_asset(path: &str) -> Option<(Vec<u8>, String)> {
    embedded_asset(path)
}

#[cfg(all(feature = "embed-ui", kestrel_ui_assets))]
fn embedded_asset(path: &str) -> Option<(Vec<u8>, String)> {
    let file = Assets::get(path)?;
    let mime = mime_guess::from_path(path)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .to_string();
    Some((file.data.into_owned(), mime))
}

#[cfg(not(all(feature = "embed-ui", kestrel_ui_assets)))]
fn embedded_asset(path: &str) -> Option<(Vec<u8>, String)> {
    let _ = path;
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn spa_bootstrap_has_exact_csp_hash_and_safe_caching() {
        let server = axum_test::TestServer::new(router()).unwrap();
        let response = server.get("/hosts/example").await;
        response.assert_status_ok();
        response.assert_header(header::X_FRAME_OPTIONS, "DENY");
        response.assert_header(header::CACHE_CONTROL, "no-cache");
        let html = response.text();
        response.assert_header(
            header::CONTENT_SECURITY_POLICY,
            content_security_policy(&html),
        );
        #[cfg(all(feature = "embed-ui", kestrel_ui_assets))]
        assert!(response
            .header(header::CONTENT_SECURITY_POLICY)
            .to_str()
            .unwrap()
            .contains("'sha256-"));
        server.get("/api/unknown").await.assert_status_not_found();
    }

    #[test]
    fn only_exact_trusted_inline_scripts_are_allowed() {
        let script = "\nconsole.log('bootstrap');\n";
        let html = format!("<script>{script}</script>");
        let policy = content_security_policy(&html);
        assert!(policy.contains(&format!(
            "'sha256-{}'",
            data_encoding::BASE64.encode(&Sha256::digest(script.as_bytes()))
        )));
        assert!(!policy.contains("unsafe-inline"));
        assert_ne!(
            policy,
            content_security_policy("<script>console.log('changed')</script>")
        );
        assert_eq!(policy, content_security_policy(&html.replace('\n', "\r\n")));
    }
}
