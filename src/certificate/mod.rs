use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tracing::{debug, error, info, warn};

use crate::config::AcmeConfig;

pub struct CertificateManager {
    config: AcmeConfig,
    account: Option<Account>,
    challenge_tokens: HashMap<String, String>,
}

impl CertificateManager {
    pub async fn new(config: AcmeConfig) -> Result<Self> {
        fs::create_dir_all(&config.cert_dir)
            .await
            .context("Failed to create certificate directory")?;

        Ok(Self {
            config,
            account: None,
            challenge_tokens: HashMap::new(),
        })
    }

    async fn get_or_create_account(&mut self) -> Result<&Account> {
        if self.account.is_none() {
            let url = if self.config.staging {
                LetsEncrypt::Staging.url()
            } else {
                LetsEncrypt::Production.url()
            };

            let (account, _credentials) = Account::create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", self.config.email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                url,
                None, // External account key not needed for Let's Encrypt
            )
            .await
            .context("Failed to create ACME account")?;

            self.account = Some(account);
        }

        Ok(self.account.as_ref().unwrap())
    }

    pub fn store_challenge_token(&mut self, token: String, key_auth: String) {
        info!("Storing ACME challenge token: {}", token);
        self.challenge_tokens.insert(token, key_auth);
    }

    pub fn get_challenge_response(&self, token: &str) -> Option<&String> {
        self.challenge_tokens.get(token)
    }

    pub fn remove_challenge_token(&mut self, token: &str) {
        if self.challenge_tokens.remove(token).is_some() {
            info!("Removed ACME challenge token: {}", token);
        }
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
        info!("Starting ACME certificate request for domain: {}", domain);

        // Store config values before borrowing self mutably
        let email = self.config.email.clone();
        let staging = self.config.staging;

        let account = match self.get_or_create_account().await {
            Ok(account) => {
                info!("ACME account ready for email: {}", email);
                info!(
                    "Using {} environment",
                    if staging { "staging" } else { "production" }
                );
                account
            }
            Err(e) => {
                error!("Failed to create ACME account: {}", e);
                warn!("Falling back to self-signed certificate for {}", domain);
                return self.create_self_signed_certificate(domain);
            }
        };

        // Step 1: Create a new order
        info!("Creating new ACME order for domain: {}", domain);
        let identifier = Identifier::Dns(domain.to_string());
        let mut order = match account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await
        {
            Ok(order) => order,
            Err(e) => {
                error!("Failed to create ACME order: {}", e);
                warn!("Falling back to self-signed certificate for {}", domain);
                return self.create_self_signed_certificate(domain);
            }
        };

        info!("ACME order created with URL: {}", order.url());

        // Step 2: Process authorizations
        let authorizations = match order.authorizations().await {
            Ok(auths) => auths,
            Err(e) => {
                error!("Failed to get authorizations: {}", e);
                return self.create_self_signed_certificate(domain);
            }
        };

        for authz in &authorizations {
            if authz.status == AuthorizationStatus::Valid {
                info!(
                    "Authorization already valid for identifier: {:?}",
                    authz.identifier
                );
                continue;
            }

            info!(
                "Processing authorization for identifier: {:?}",
                authz.identifier
            );

            // Find HTTP-01 challenge
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge found"))?;

            let key_auth = order.key_authorization(challenge).as_str().to_string();
            info!("Storing challenge token: {}", challenge.token);

            // Store the challenge token and key authorization
            self.store_challenge_token(challenge.token.clone(), key_auth);

            // Step 3: Signal to Let's Encrypt that we're ready
            info!("Signaling readiness for challenge: {}", challenge.token);
            if let Err(e) = order.set_challenge_ready(&challenge.url).await {
                error!("Failed to signal challenge readiness: {}", e);
                self.remove_challenge_token(&challenge.token);
                return self.create_self_signed_certificate(domain);
            }
        }

        // Step 4: Wait for all challenges to be validated (order becomes ready)
        info!("Waiting for challenge validation...");
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 30; // 5 minutes at 10-second intervals
        let mut delay = Duration::from_secs(5);

        loop {
            tokio::time::sleep(delay).await;
            attempts += 1;

            let state = match order.refresh().await {
                Ok(state) => state,
                Err(e) => {
                    error!("Failed to refresh order: {}", e);
                    return self.create_self_signed_certificate(domain);
                }
            };

            match state.status {
                OrderStatus::Ready => {
                    info!("Order is ready - all challenges validated successfully!");
                    break;
                }
                OrderStatus::Invalid => {
                    error!("Order invalid - challenge validation failed!");
                    return self.create_self_signed_certificate(domain);
                }
                OrderStatus::Pending => {
                    debug!(
                        "Order still pending (attempt {}/{})",
                        attempts, MAX_ATTEMPTS
                    );
                    if attempts >= MAX_ATTEMPTS {
                        error!("Challenge validation timed out");
                        return self.create_self_signed_certificate(domain);
                    }
                    // Exponential backoff like in the example
                    delay = std::cmp::min(delay * 2, Duration::from_secs(30));
                }
                _ => {
                    debug!("Order status: {:?}", state.status);
                }
            }
        }

        // Step 5: Generate CSR and finalize order
        info!("All challenges validated, generating certificate...");

        // Generate a private key for the certificate
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]);
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert_key = rcgen::Certificate::from_params(params)?;
        let csr_der = cert_key.serialize_request_der()?;

        // Finalize the order
        if let Err(e) = order.finalize(&csr_der).await {
            error!("Failed to finalize ACME order: {}", e);
            return self.create_self_signed_certificate(domain);
        }
        info!("Order finalized successfully");

        // Step 6: Wait for certificate to be ready
        info!("Waiting for certificate to be issued...");
        let mut attempts = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            attempts += 1;

            let state = match order.refresh().await {
                Ok(state) => state,
                Err(e) => {
                    error!("Failed to refresh order: {}", e);
                    return self.create_self_signed_certificate(domain);
                }
            };

            match state.status {
                OrderStatus::Valid => {
                    info!("Certificate issued successfully!");
                    break;
                }
                OrderStatus::Invalid => {
                    error!("Certificate order failed!");
                    return self.create_self_signed_certificate(domain);
                }
                OrderStatus::Processing => {
                    debug!("Certificate still processing (attempt {})", attempts);
                    if attempts >= 30 {
                        // 1 minute timeout
                        error!("Certificate issuance timed out");
                        return self.create_self_signed_certificate(domain);
                    }
                }
                _ => {
                    debug!("Order status: {:?}", state.status);
                }
            }
        }

        // Step 7: Download the certificate
        let cert_chain_pem = match order.certificate().await {
            Ok(Some(cert)) => cert,
            Ok(None) => {
                error!("Certificate not available");
                return self.create_self_signed_certificate(domain);
            }
            Err(e) => {
                error!("Failed to download certificate: {}", e);
                return self.create_self_signed_certificate(domain);
            }
        };

        // Parse the certificate chain
        let cert_chain: Vec<CertificateDer<'static>> =
            certs(&mut cert_chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;

        if cert_chain.is_empty() {
            error!("Certificate chain is empty");
            return self.create_self_signed_certificate(domain);
        }

        // Use the private key we generated for the CSR
        let private_key_der = cert_key.serialize_private_key_der();
        let private_key =
            PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(private_key_der));

        info!(
            "Successfully obtained Let's Encrypt certificate for {}",
            domain
        );
        Ok((cert_chain, private_key))
    }

    fn create_self_signed_certificate(
        &self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        info!("Creating self-signed certificate for {}", domain);

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
