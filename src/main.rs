use axum::{Router, extract::Request};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tracing::info;

mod certificate;
mod config;
mod proxy;

use certificate::{CertificateManager, create_dynamic_tls_config};
use config::{ProxyConfig, load_config};
use proxy::{handle_http_request, proxy_handler};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    tracing_subscriber::fmt::init();

    let https_disabled = std::env::var("DISABLE_HTTPS")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    let yaml_config = load_config().await;
    let config = ProxyConfig::from(yaml_config);

    if https_disabled {
        info!("HTTPS/Let's Encrypt disabled via DISABLE_HTTPS environment variable");
        run_http_only(config).await?;
    } else {
        info!("Starting reverse proxy with Let's Encrypt support");
        run_with_https(config).await?;
    }

    Ok(())
}

async fn run_http_only(config: ProxyConfig) -> Result<()> {
    let http_port = config.server.http_port;
    let app = Router::new().fallback(move |req: Request| proxy_handler(req, config.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], http_port));
    info!("HTTP-only reverse proxy listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn run_with_https(config: ProxyConfig) -> Result<()> {
    let cert_manager = Arc::new(tokio::sync::Mutex::new(
        CertificateManager::new(config.acme.clone()).await?,
    ));

    let http_config = config.clone();
    let http_port = http_config.server.http_port;
    let http_cert_manager = cert_manager.clone();
    tokio::spawn(async move {
        let app = Router::new().fallback(move |req: Request| {
            handle_http_request(req, http_config.clone(), http_cert_manager.clone())
        });

        let addr = SocketAddr::from(([0, 0, 0, 0], http_port));
        info!("HTTP server (redirects/ACME) listening on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    let https_config = config.clone();
    let https_port = https_config.server.https_port;
    let _https_cert_manager = cert_manager.clone();

    let tls_config = create_dynamic_tls_config(cert_manager.clone()).await?;

    let app = Router::new().fallback(move |req: Request| proxy_handler(req, https_config.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], https_port));
    info!("HTTPS reverse proxy listening on {}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
