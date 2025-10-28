use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use instant_acme::{Account, LetsEncrypt, NewAccount};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tracing::{info, warn};

use crate::config::AcmeConfig;

pub struct CertificateManager {
    config: AcmeConfig,
    account: Option<Account>,
}

impl CertificateManager {
    pub async fn new(config: AcmeConfig) -> Result<Self> {
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

    pub async fn get_certificate(
        &mut self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        if let Ok(cert_data) = self.load_certificate_from_disk(domain).await {
            return Ok(cert_data);
        }

        info!("Requesting new certificate for domain: {}", domain);
        let cert_data = self.request_certificate(domain).await?;

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

pub async fn create_dynamic_tls_config(
    cert_manager: Arc<tokio::sync::Mutex<CertificateManager>>,
) -> Result<RustlsConfig> {
    let default_domain =
        std::env::var("DEFAULT_DOMAIN").unwrap_or_else(|_| "localhost".to_string());

    let mut default_cert = None;
    {
        let mut manager = cert_manager.lock().await;
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
        warn!("No certificates found, creating self-signed certificate for testing");
        create_self_signed_config()
    }
}

pub fn create_self_signed_config() -> Result<RustlsConfig> {
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
