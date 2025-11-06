use serde::Deserialize;
use std::collections::HashMap;
use tokio::fs;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub routes: HashMap<String, String>,
    #[serde(default)]
    pub acme: AcmeConfig,
    #[serde(default)]
    pub server: ServerConfig,
}

#[derive(Deserialize, Clone, Debug)]
pub struct AcmeConfig {
    #[serde(default = "default_email")]
    pub email: String,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: String,
    #[serde(default = "default_staging")]
    pub staging: bool,
}

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_https_port")]
    pub https_port: u16,
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

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_port: default_http_port(),
            https_port: default_https_port(),
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

fn default_http_port() -> u16 {
    std::env::var("HTTP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(80)
}

fn default_https_port() -> u16 {
    std::env::var("HTTPS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(443)
}

pub async fn load_config() -> Config {
    let config_str = fs::read_to_string("proxy.toml")
        .await
        .expect("Failed to read config file");
    toml::from_str(&config_str).expect("Failed to parse config")
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub routes: HashMap<String, String>,
    pub acme: AcmeConfig,
    pub server: ServerConfig,
}

impl From<Config> for ProxyConfig {
    fn from(value: Config) -> ProxyConfig {
        ProxyConfig {
            routes: value.routes,
            acme: value.acme,
            server: value.server,
        }
    }
}
