use serde::Deserialize;
use std::path::Path;

/// Simplified OAuth configuration — just what openidconnect needs
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    pub provider: ProviderConfig,
    pub client: ClientConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub recorder: RecorderConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    /// OIDC issuer URL (e.g., http://localhost:8089/realms/kasmvnc)
    pub issuer_url: String,
    /// Internal issuer URL for server-to-server (e.g., http://host.docker.internal:8089/realms/kasmvnc)
    #[serde(default)]
    pub internal_issuer_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_bind")]
    pub bind_address: String,
    /// KasmVNC upstream URL to reverse proxy to
    #[serde(default = "default_vnc_upstream")]
    pub vnc_upstream: String,
    /// Cookie secret for session encryption
    #[serde(default)]
    pub cookie_secret: Option<String>,
    /// Session timeout in minutes (default: 30)
    #[serde(default = "default_session_timeout")]
    pub session_timeout_minutes: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RecorderConfig {
    /// Directory to write recordings + metadata
    #[serde(default = "default_recordings_dir")]
    pub output_dir: String,
    /// Path to the record-session.sh script
    #[serde(default = "default_recorder_script")]
    pub script_path: String,
}

fn default_port() -> u16 { 8443 }
fn default_bind() -> String { "0.0.0.0".into() }
fn default_vnc_upstream() -> String { "https://127.0.0.1:8444".into() }
fn default_scopes() -> Vec<String> { vec!["openid".into(), "profile".into(), "email".into()] }
fn default_recordings_dir() -> String { "/recordings".into() }
fn default_recorder_script() -> String { "/opt/kasmweb/bin/record-session.sh".into() }
fn default_session_timeout() -> u64 { 30 }

impl OAuthConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// The issuer URL to use for server-to-server OIDC discovery
    pub fn discovery_issuer_url(&self) -> &str {
        self.provider
            .internal_issuer_url
            .as_deref()
            .unwrap_or(&self.provider.issuer_url)
    }
}