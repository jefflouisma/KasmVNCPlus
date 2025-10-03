use serde::Deserialize;

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub provider: String,
    pub endpoints: OAuthEndpoints,
    pub client: OAuthClient,
    pub security: SecurityConfig,
    pub tokens: TokenConfig,
    pub session: SessionConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct OAuthEndpoints {
    pub issuer: String,
    pub authorization: String,
    pub token: String,
    pub jwks: String,
    pub userinfo: String,
    pub discovery: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct SecurityConfig {
    pub use_pkce: bool,
    pub pkce_method: String,
    pub require_state: bool,
    pub verify_signature: bool,
    pub verify_issuer: bool,
    pub verify_audience: bool,
    pub verify_expiration: bool,
    pub clock_skew_seconds: i64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            use_pkce: true,
            pkce_method: "S256".to_string(),
            require_state: true,
            verify_signature: true,
            verify_issuer: true,
            verify_audience: true,
            verify_expiration: true,
            clock_skew_seconds: 60,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct TokenConfig {
    pub access_token_lifetime: i64,
    pub refresh_token_lifetime: i64,
    pub jwks_cache_ttl: u64,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            access_token_lifetime: 3600,
            refresh_token_lifetime: 7776000,
            jwks_cache_ttl: 86400,
        }
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct SessionConfig {
    pub timeout_seconds: i64,
    pub idle_timeout_seconds: i64,
    pub allow_multiple_sessions: bool,
}
