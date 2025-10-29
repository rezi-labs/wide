use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_reverse_proxy::ReverseProxy;
use std::sync::Arc;
use tracing::{debug, info};

use crate::certificate::CertificateManager;
use crate::config::ProxyConfig;

pub async fn handle_http_request(
    req: Request,
    _config: ProxyConfig,
    cert_manager: Arc<tokio::sync::Mutex<CertificateManager>>,
) -> Response {
    let uri = req.uri();
    let path = uri.path();

    if path.starts_with("/.well-known/acme-challenge/") {
        // Extract the token from the path
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
            debug!("ACME challenge request for token: {}", token);

            // Lock the certificate manager to get the challenge response
            let manager = cert_manager.lock().await;
            if let Some(key_auth) = manager.get_challenge_response(token) {
                info!("Serving ACME challenge response for token: {}", token);
                return (StatusCode::OK, key_auth.clone()).into_response();
            } else {
                debug!("ACME challenge token not found: {}", token);
            }
        } else {
            debug!("Invalid ACME challenge path: {}", path);
        }
        return (StatusCode::NOT_FOUND, "Challenge not found").into_response();
    }

    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let https_url = format!(
        "https://{}{}",
        host,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("")
    );

    Redirect::permanent(&https_url).into_response()
}

pub async fn proxy_handler(req: Request, config: ProxyConfig) -> Response {
    let host = match req.headers().get("host") {
        Some(host_header) => match host_header.to_str() {
            Ok(host_str) => host_str,
            Err(_) => {
                eprintln!("Invalid host header");
                return (StatusCode::BAD_REQUEST, "Invalid host header").into_response();
            }
        },
        None => {
            eprintln!("No host header found");
            return (StatusCode::BAD_REQUEST, "No host header").into_response();
        }
    };

    let host = host.split(':').next().unwrap_or(host);

    let backend = match config.routes.get(host) {
        Some(b) => b,
        None => {
            eprintln!("No backend configured for host: {host}");
            return (StatusCode::NOT_FOUND, "Host not found").into_response();
        }
    };

    let reverse_proxy = ReverseProxy::new("/", backend);

    match reverse_proxy.proxy_request(req).await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Proxy error: {e:?}");
            (StatusCode::BAD_GATEWAY, "Backend error").into_response()
        }
    }
}
