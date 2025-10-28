use axum::{
    Router,
    body::Body,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tower::ServiceExt;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use http_body_util::BodyExt;
use instant_acme::{Account, LetsEncrypt, NewAccount};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::Deserialize;
use tracing::{info, warn};

#[derive(Deserialize, Clone)]
struct Config {
    routes: HashMap<String, String>,
    #[serde(default)]
    acme: AcmeConfig,
}

#[derive(Deserialize, Clone)]
struct AcmeConfig {
    #[serde(default = "default_email")]
    email: String,
    #[serde(default = "default_cert_dir")]
    cert_dir: String,
    #[serde(default = "default_staging")]
    staging: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            email: default_email(),
            cert_dir: default_cert_dir(),
            staging: default_staging(),
        }
    }
}

fn default_email() -> String {
    "admin@example.com".to_string()
}

fn default_cert_dir() -> String {
    "./certs".to_string()
}

fn default_staging() -> bool {
    false
}

async fn load_config() -> Config {
    let config_str = fs::read_to_string("proxy.toml")
        .await
        .expect("Failed to read config file");
    toml::from_str(&config_str).expect("Failed to parse config")
}

#[derive(Clone)]
struct ProxyConfig {
    routes: HashMap<String, String>,
    acme: AcmeConfig,
}

impl From<Config> for ProxyConfig {
    fn from(value: Config) -> ProxyConfig {
        ProxyConfig {
            routes: value.routes,
            acme: value.acme,
        }
    }
}

struct CertificateManager {
    config: AcmeConfig,
    account: Option<Account>,
}

impl CertificateManager {
    async fn new(config: AcmeConfig) -> Result<Self> {
        fs::create_dir_all(&config.cert_dir)
            .await
            .context("Failed to create certificate directory")?;

        Ok(Self {
            config,
            account: None,
        })
    }

    async fn get_or_create_account(&mut self) -> Result<&Account> {
        if self.account.is_none() {
            let url = if self.config.staging {
                LetsEncrypt::Staging.url()
            } else {
                LetsEncrypt::Production.url()
            };

            let (account, _) = Account::create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", self.config.email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                url,
                None,
            )
            .await
            .context("Failed to create ACME account")?;

            self.account = Some(account);
        }

        Ok(self.account.as_ref().unwrap())
    }

    async fn get_certificate(
        &mut self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // Check if we already have certificate data on disk
        if let Ok(cert_data) = self.load_certificate_from_disk(domain).await {
            return Ok(cert_data);
        }

        // Request new certificate
        info!("Requesting new certificate for domain: {}", domain);
        let cert_data = self.request_certificate(domain).await?;

        // Save to disk
        self.save_certificate_to_disk(domain, &cert_data).await?;

        Ok(cert_data)
    }

    async fn load_certificate_from_disk(
        &self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let cert_path = format!("{}/{}.crt", self.config.cert_dir, domain);
        let key_path = format!("{}/{}.key", self.config.cert_dir, domain);

        if !Path::new(&cert_path).exists() || !Path::new(&key_path).exists() {
            return Err(anyhow::anyhow!("Certificate files not found"));
        }

        let cert_pem = fs::read(&cert_path).await?;
        let key_pem = fs::read(&key_path).await?;

        let cert_chain: Vec<CertificateDer<'static>> =
            certs(&mut cert_pem.as_slice()).collect::<Result<Vec<_>, _>>()?;

        let mut keys: Vec<_> =
            pkcs8_private_keys(&mut key_pem.as_slice()).collect::<Result<Vec<_>, _>>()?;
        if keys.is_empty() {
            return Err(anyhow::anyhow!("No private key found"));
        }
        let private_key = PrivateKeyDer::from(keys.remove(0));

        Ok((cert_chain, private_key))
    }

    async fn save_certificate_to_disk(
        &self,
        domain: &str,
        cert_data: &(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    ) -> Result<()> {
        let cert_path = format!("{}/{}.crt", self.config.cert_dir, domain);
        let key_path = format!("{}/{}.key", self.config.cert_dir, domain);

        // Save certificate chain
        let mut cert_pem = Vec::new();
        for cert in &cert_data.0 {
            cert_pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
            cert_pem.extend_from_slice(
                base64::engine::general_purpose::STANDARD
                    .encode(cert.as_ref())
                    .as_bytes(),
            );
            cert_pem.extend_from_slice(b"\n-----END CERTIFICATE-----\n");
        }
        fs::write(&cert_path, cert_pem).await?;

        // Save private key
        let key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(cert_data.1.secret_der())
        );
        fs::write(&key_path, key_pem).await?;

        Ok(())
    }

    async fn request_certificate(
        &mut self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // Try to get ACME account first
        match self.get_or_create_account().await {
            Ok(_account) => {
                // In a full ACME implementation, you would use the account here
                // to request certificates from Let's Encrypt
                info!("ACME account created for email: {}", self.config.email);
                info!(
                    "Using {} environment",
                    if self.config.staging {
                        "staging"
                    } else {
                        "production"
                    }
                );
                warn!(
                    "Full ACME certificate request not yet implemented - using self-signed certificate for {}",
                    domain
                );
            }
            Err(e) => {
                warn!(
                    "Failed to create ACME account: {} - using self-signed certificate for {}",
                    e, domain
                );
            }
        }

        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]);
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = rcgen::Certificate::from_params(params)?;

        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();

        let cert_chain = vec![CertificateDer::from(cert_der)];
        let private_key = PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(key_der));

        Ok((cert_chain, private_key))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Check if HTTPS/Let's Encrypt is disabled via environment variable
    let https_disabled = std::env::var("DISABLE_HTTPS")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    // Load configuration from YAML file
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
    let app = Router::new().fallback(move |req: Request| proxy_handler(req, config.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("HTTP-only reverse proxy listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn run_with_https(config: ProxyConfig) -> Result<()> {
    let cert_manager = Arc::new(tokio::sync::Mutex::new(
        CertificateManager::new(config.acme.clone()).await?,
    ));

    // HTTP server for redirects and ACME challenges
    let http_config = config.clone();
    let http_cert_manager = cert_manager.clone();
    tokio::spawn(async move {
        let app = Router::new().fallback(move |req: Request| {
            handle_http_request(req, http_config.clone(), http_cert_manager.clone())
        });

        let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
        info!("HTTP server (redirects/ACME) listening on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // HTTPS server
    let https_config = config.clone();
    let _https_cert_manager = cert_manager.clone();

    // Create a dynamic TLS config that can resolve certificates per domain
    let tls_config = create_dynamic_tls_config(cert_manager.clone()).await?;

    let app = Router::new().fallback(move |req: Request| proxy_handler(req, https_config.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    info!("HTTPS reverse proxy listening on {}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn handle_http_request(
    req: Request,
    _config: ProxyConfig,
    _cert_manager: Arc<tokio::sync::Mutex<CertificateManager>>,
) -> Response {
    let uri = req.uri();
    let path = uri.path();

    // Handle ACME HTTP-01 challenges
    if path.starts_with("/.well-known/acme-challenge/") {
        // In a real implementation, you would serve the challenge response here
        // For now, return 404
        return (StatusCode::NOT_FOUND, "Challenge not found").into_response();
    }

    // Redirect HTTP to HTTPS
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

async fn create_dynamic_tls_config(
    cert_manager: Arc<tokio::sync::Mutex<CertificateManager>>,
) -> Result<RustlsConfig> {
    // Try to get certificate for localhost as default
    let default_domain =
        std::env::var("DEFAULT_DOMAIN").unwrap_or_else(|_| "localhost".to_string());

    let mut default_cert = None;
    {
        let mut manager = cert_manager.lock().await;
        // Try to get or create certificate for default domain
        match manager.get_certificate(&default_domain).await {
            Ok(cert_data) => {
                info!("Successfully obtained certificate for {}", default_domain);
                default_cert = Some(cert_data);
            }
            Err(e) => {
                warn!("Failed to get certificate for {}: {}", default_domain, e);
            }
        }
    }

    if let Some((cert_chain, private_key)) = default_cert {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("Failed to create TLS config")?;

        Ok(RustlsConfig::from_config(Arc::new(config)))
    } else {
        // Create a self-signed certificate for testing
        warn!("No certificates found, creating self-signed certificate for testing");
        create_self_signed_config()
    }
}

fn create_self_signed_config() -> Result<RustlsConfig> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = rcgen::Certificate::from_params(params)?;

    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    let cert_chain = vec![CertificateDer::from(cert_der)];
    let private_key = PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(key_der));

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("Failed to create self-signed TLS config")?;

    Ok(RustlsConfig::from_config(Arc::new(config)))
}

async fn proxy_handler(req: Request, config: ProxyConfig) -> Response {
    // Extract host from headers
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

    // Strip port from host if present
    let host = host.split(':').next().unwrap_or(host);

    // Find backend for this domain
    let backend = match config.routes.get(host) {
        Some(b) => b,
        None => {
            eprintln!("No backend configured for host: {host}");
            return (StatusCode::NOT_FOUND, "Host not found").into_response();
        }
    };

    // Build the proxy service
    let service = match axum_proxy::builder_http(backend.clone()) {
        Ok(builder) => builder.build(axum_proxy::Static("/")),
        Err(e) => {
            eprintln!("Failed to build proxy for {backend}: {e}");
            return (StatusCode::BAD_GATEWAY, "Backend unavailable").into_response();
        }
    };

    // Forward the request
    match service.oneshot(req).await {
        Ok(Ok(response)) => {
            // Convert the response to use Axum's Body type
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
