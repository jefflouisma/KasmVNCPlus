use serde::Deserialize;
use std::path::Path;

/// Session controller configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ControllerConfig {
    pub database: DatabaseConfig,
    pub server: ServerConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub kubernetes: KubernetesConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_bind")]
    pub bind_address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Keycloak OIDC issuer URL for JWT validation
    pub issuer_url: String,
    /// Admin role name in Keycloak
    #[serde(default = "default_admin_role")]
    pub admin_role: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct KubernetesConfig {
    /// Namespace for session pods
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Default session pod image
    #[serde(default = "default_session_image")]
    pub session_image: String,
    /// Service account for session pods
    #[serde(default = "default_service_account")]
    pub service_account: String,
}

fn default_port() -> u16 { 9090 }
fn default_bind() -> String { "0.0.0.0".into() }
fn default_max_connections() -> u32 { 10 }
fn default_admin_role() -> String { "admin".into() }
fn default_namespace() -> String { "kasmvnc".into() }
fn default_session_image() -> String { "kasmvncplus:hardened".into() }
fn default_service_account() -> String { "kasmvnc-session".into() }

impl ControllerConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }
}
