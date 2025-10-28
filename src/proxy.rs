use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

use crate::certificate::CertificateManager;
use crate::config::ProxyConfig;

pub async fn handle_http_request(
    req: Request,
    _config: ProxyConfig,
    _cert_manager: Arc<tokio::sync::Mutex<CertificateManager>>,
) -> Response {
    let uri = req.uri();
    let path = uri.path();

    if path.starts_with("/.well-known/acme-challenge/") {
        // In a real implementation, you would serve the challenge response here
        // For now, return 404
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

    let service = match axum_proxy::builder_http(backend.clone()) {
        Ok(builder) => builder.build(axum_proxy::Static("/")),
        Err(e) => {
            eprintln!("Failed to build proxy for {backend}: {e}");
            return (StatusCode::BAD_GATEWAY, "Backend unavailable").into_response();
        }
    };

    match service.oneshot(req).await {
        Ok(Ok(response)) => {
            let (parts, body) = response.into_parts();
            let stream = body.into_data_stream();
            Response::from_parts(parts, Body::from_stream(stream))
        }
        Ok(Err(e)) => {
            eprintln!("Proxy error: {e:?}");
            (StatusCode::BAD_GATEWAY, "Backend error").into_response()
        }
        Err(e) => {
            eprintln!("Service error: {e:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}
