use crate::config::OAuthConfig;
use crate::error::{OAuthError, Result};
use crate::pkce::{generate_state, PkceChallenge};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub authorization_url: String,
    pub state: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenError {
    pub error: String,
    pub error_description: Option<String>,
}

/// OAuth 2.0 Flow Handler
pub struct OAuthHandler {
    config: Arc<OAuthConfig>,
    client: reqwest::Client,
    pending_requests: Arc<RwLock<HashMap<String, PkceChallenge>>>,
}

impl OAuthHandler {
    /// Create new OAuth handler
    pub fn new(config: Arc<OAuthConfig>) -> Self {
        OAuthHandler {
            config,
            client: reqwest::Client::new(),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate authorization URL with PKCE
    pub async fn generate_auth_url(&self) -> Result<AuthorizationRequest> {
        let pkce = PkceChallenge::new();
        let state = generate_state();

        // Store PKCE verifier for later use
        {
            let mut pending = self.pending_requests.write().await;
            pending.insert(state.clone(), pkce.clone());
        }

        // Build authorization URL
        let mut url = Url::parse(&self.config.endpoints.authorization)?;
        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.config.client.client_id);
            params.append_pair("redirect_uri", &self.config.client.redirect_uri);
            params.append_pair("scope", &self.config.client.scope);
            params.append_pair("state", &state);

            if self.config.security.use_pkce {
                params.append_pair("code_challenge", &pkce.challenge);
                params.append_pair("code_challenge_method", &pkce.method);
            }

            // Add nonce for additional security
            params.append_pair("nonce", &generate_state());
        }

        Ok(AuthorizationRequest {
            authorization_url: url.to_string(),
            state,
            code_verifier: pkce.verifier,
        })
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(&self, code: &str, state: &str) -> Result<TokenResponse> {
        // Retrieve and validate PKCE verifier
        let pkce = {
            let mut pending = self.pending_requests.write().await;
            pending.remove(state).ok_or(OAuthError::InvalidState)?
        };

        // Build token request
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.client.redirect_uri),
            ("client_id", &self.config.client.client_id),
        ];

        if !self.config.client.client_secret.is_empty() {
            params.push(("client_secret", &self.config.client.client_secret));
        }

        if self.config.security.use_pkce {
            params.push(("code_verifier", &pkce.verifier));
        }

        // Send token request
        let response = self
            .client
            .post(&self.config.endpoints.token)
            .form(&params)
            .send()
            .await?;

        if response.status().is_success() {
            let token_response: TokenResponse = response.json().await?;
            Ok(token_response)
        } else {
            let error: TokenError = response.json().await?;
            match error.error.as_str() {
                "invalid_grant" => Err(OAuthError::InvalidAuthCode),
                "invalid_request" => Err(OAuthError::InvalidState),
                _ => Err(OAuthError::Config(format!(
                    "Token exchange failed: {} - {}",
                    error.error,
                    error.error_description.unwrap_or_default()
                ))),
            }
        }
    }

    /// Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let mut params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.config.client.client_id.as_str()),
        ];

        if !self.config.client.client_secret.is_empty() {
            params.push(("client_secret", &self.config.client.client_secret));
        }

        let response = self
            .client
            .post(&self.config.endpoints.token)
            .form(&params)
            .send()
            .await?;

        if response.status().is_success() {
            let token_response: TokenResponse = response.json().await?;
            Ok(token_response)
        } else {
            let error: TokenError = response.json().await?;
            Err(OAuthError::Config(format!(
                "Token refresh failed: {} - {}",
                error.error,
                error.error_description.unwrap_or_default()
            )))
        }
    }

    /// Revoke token
    pub async fn revoke_token(&self, token: &str, token_type_hint: Option<&str>) -> Result<()> {
        if let Some(revocation_endpoint) = &self.config.endpoints.revocation {
            let mut params = vec![
                ("token", token),
                ("client_id", &self.config.client.client_id.as_str()),
            ];

            if let Some(hint) = token_type_hint {
                params.push(("token_type_hint", hint));
            }

            if !self.config.client.client_secret.is_empty() {
                params.push(("client_secret", &self.config.client.client_secret));
            }

            self.client
                .post(revocation_endpoint)
                .form(&params)
                .send()
                .await?;
        }

        Ok(())
    }

    /// Get user info
    pub async fn get_user_info(&self, access_token: &str) -> Result<serde_json::Value> {
        let response = self
            .client
            .get(&self.config.endpoints.userinfo)
            .bearer_auth(access_token)
            .send()
            .await?;

        if response.status().is_success() {
            let user_info = response.json().await?;
            Ok(user_info)
        } else {
            Err(OAuthError::Config("Failed to get user info".to_string()))
        }
    }
}
