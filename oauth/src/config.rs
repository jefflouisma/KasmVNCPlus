use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use std::env;
use crate::error::{OAuthError, Result};
use url;
use regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub provider: String,
    pub endpoints: OAuthEndpoints,
    pub client: OAuthClient,
    pub security: SecurityConfig,
    pub tokens: TokenConfig,
    pub session: SessionConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthEndpoints {
    pub issuer: String,
    pub authorization: String,
    pub token: String,
    pub jwks: String,
    pub userinfo: String,
    #[serde(default)]
    pub discovery: String,
    #[serde(default)]
    pub revocation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_true")]
    pub use_pkce: bool,
    #[serde(default = "default_pkce_method")]
    pub pkce_method: String,
    #[serde(default = "default_true")]
    pub require_state: bool,
    pub token_validation: TokenValidation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidation {
    #[serde(default = "default_true")]
    pub verify_signature: bool,
    #[serde(default = "default_true")]
    pub verify_issuer: bool,
    #[serde(default = "default_true")]
    pub verify_audience: bool,
    #[serde(default = "default_true")]
    pub verify_expiration: bool,
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    #[serde(default = "default_access_token_lifetime")]
    pub access_token_lifetime: u64,
    #[serde(default = "default_refresh_token_lifetime")]
    pub refresh_token_lifetime: u64,
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    #[serde(default = "default_session_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_true")]
    pub allow_multiple_sessions: bool,
    #[serde(default = "default_max_sessions")]
    pub max_sessions_per_user: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub log_tokens: bool,
    #[serde(default = "default_true")]
    pub log_claims: bool,
}

// Default value functions
fn default_true() -> bool { true }
fn default_scope() -> String { "openid profile email".to_string() }
fn default_pkce_method() -> String { "S256".to_string() }
fn default_clock_skew() -> u64 { 60 }
fn default_access_token_lifetime() -> u64 { 3600 }
fn default_refresh_token_lifetime() -> u64 { 7776000 }
fn default_jwks_cache_ttl() -> u64 { 86400 }
fn default_session_timeout() -> u64 { 28800 }
fn default_idle_timeout() -> u64 { 3600 }
fn default_max_sessions() -> usize { 5 }
fn default_log_level() -> String { "info".to_string() }

impl OAuthConfig {
    /// Load configuration from TOML file
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| OAuthError::Config(format!("Failed to read config file: {}", e)))?;

        let mut config: Self = toml::from_str(&content)
            .map_err(|e| OAuthError::Config(format!("Failed to parse config: {}", e)))?;

        // Replace environment variables
        config.replace_env_vars()?;

        // Auto-configure from discovery if provided
        if !config.endpoints.discovery.is_empty() {
            config.load_from_discovery().await?;
        }

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Replace environment variables in configuration
    fn replace_env_vars(&mut self) -> Result<()> {
        self.client.client_id = Self::expand_env_var(&self.client.client_id);
        self.client.client_secret = Self::expand_env_var(&self.client.client_secret);
        self.client.redirect_uri = Self::expand_env_var(&self.client.redirect_uri);
        self.endpoints.issuer = Self::expand_env_var(&self.endpoints.issuer);
        self.endpoints.authorization = Self::expand_env_var(&self.endpoints.authorization);
        self.endpoints.token = Self::expand_env_var(&self.endpoints.token);
        self.endpoints.jwks = Self::expand_env_var(&self.endpoints.jwks);
        self.endpoints.userinfo = Self::expand_env_var(&self.endpoints.userinfo);
        Ok(())
    }

    /// Expand environment variables in string
    fn expand_env_var(input: &str) -> String {
        let mut result = input.to_string();

        // Find ${VAR_NAME} patterns and replace with env var values
        let re = regex::Regex::new(r"\$\{([^}]+)\}").unwrap();
        for cap in re.captures_iter(input) {
            if let Some(var_name) = cap.get(1) {
                if let Ok(value) = env::var(var_name.as_str()) {
                    result = result.replace(&cap[0], &value);
                }
            }
        }

        result
    }

    /// Load configuration from OIDC Discovery endpoint
    async fn load_from_discovery(&mut self) -> Result<()> {
        #[derive(Deserialize)]
        struct DiscoveryDocument {
            issuer: String,
            authorization_endpoint: String,
            token_endpoint: String,
            jwks_uri: String,
            userinfo_endpoint: String,
            revocation_endpoint: Option<String>,
        }

        let client = reqwest::Client::new();
        let discovery: DiscoveryDocument = client
            .get(&self.endpoints.discovery)
            .send()
            .await?
            .json()
            .await?;

        self.endpoints.issuer = discovery.issuer;
        self.endpoints.authorization = discovery.authorization_endpoint;
        self.endpoints.token = discovery.token_endpoint;
        self.endpoints.jwks = discovery.jwks_uri;
        self.endpoints.userinfo = discovery.userinfo_endpoint;
        self.endpoints.revocation = discovery.revocation_endpoint;

        Ok(())
    }

    /// Validate configuration
    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.client.client_id.is_empty() {
            return Err(OAuthError::Config("client_id is required".to_string()));
        }

        if self.client.redirect_uri.is_empty() {
            return Err(OAuthError::Config("redirect_uri is required".to_string()));
        }

        if self.endpoints.issuer.is_empty() {
            return Err(OAuthError::Config("issuer is required".to_string()));
        }

        // Validate redirect_uri is HTTPS (except localhost)
        let uri = url::Url::parse(&self.client.redirect_uri)
            .map_err(|e| OAuthError::Config(format!("Invalid redirect_uri: {}", e)))?;

        if uri.scheme() != "https" && !uri.host_str().map_or(false, |h| h == "localhost" || h == "127.0.0.1") {
            return Err(OAuthError::Config(
                "redirect_uri must use HTTPS (except for localhost)".to_string()
            ));
        }

        Ok(())
    }
}