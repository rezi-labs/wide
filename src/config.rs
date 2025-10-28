use serde::Deserialize;
use std::collections::HashMap;
use tokio::fs;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub routes: HashMap<String, String>,
    #[serde(default)]
    pub acme: AcmeConfig,
}

#[derive(Deserialize, Clone)]
pub struct AcmeConfig {
    #[serde(default = "default_email")]
    pub email: String,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: String,
    #[serde(default = "default_staging")]
    pub staging: bool,
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
}

impl From<Config> for ProxyConfig {
    fn from(value: Config) -> ProxyConfig {
        ProxyConfig {
            routes: value.routes,
            acme: value.acme,
        }
    }
}
