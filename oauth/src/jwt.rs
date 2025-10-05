use std::sync::Arc;
use jsonwebtoken::{decode, decode_header, Validation, TokenData};
use serde::{Deserialize, Serialize};
use crate::error::{OAuthError, Result};
use crate::jwks::JwksCache;
use base64::{engine::general_purpose, Engine as _};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    // Standard claims
    pub iss: String,  // Issuer
    pub sub: String,  // Subject (user ID)
    pub aud: Vec<String>,  // Audience
    pub exp: i64,     // Expiration time
    pub nbf: Option<i64>,   // Not before
    pub iat: Option<i64>,   // Issued at

    // OpenID Connect claims
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,

    // Custom claims
    #[serde(default)]
    pub scope: String,
    #[serde(flatten)]
    pub custom: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub claims: Option<Claims>,
    pub error: Option<String>,
}

/// JWT Token Validator
pub struct JwtValidator {
    issuer: String,
    audience: String,
    jwks_cache: Arc<JwksCache>,
    clock_skew_seconds: i64,
}

impl JwtValidator {
    /// Create new JWT validator
    pub fn new(
        issuer: String,
        audience: String,
        jwks_cache: Arc<JwksCache>,
        clock_skew_seconds: u64,
    ) -> Self {
        JwtValidator {
            issuer,
            audience,
            jwks_cache,
            clock_skew_seconds: clock_skew_seconds as i64,
        }
    }

    /// Validate JWT token
    pub async fn validate(&self, token: &str) -> Result<ValidationResult> {
        // Decode header to get kid
        let header = decode_header(token)?;

        let kid = header.kid
            .ok_or_else(|| OAuthError::TokenValidation(
                jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
                )
            ))?;

        // Get public key from JWKS cache
        let decoding_key = self.jwks_cache.get_key(&kid).await?;

        // Setup validation
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.algorithms = vec![
            jsonwebtoken::Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512,
        ];
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.leeway = self.clock_skew_seconds as u64;

        // Decode and validate token
        match decode::<Claims>(token, &decoding_key, &validation) {
            Ok(token_data) => {
                // Additional validation
                if let Err(e) = self.validate_claims(&token_data.claims) {
                    Ok(ValidationResult {
                        valid: false,
                        claims: None,
                        error: Some(e.to_string()),
                    })
                } else {
                    Ok(ValidationResult {
                        valid: true,
                        claims: Some(token_data.claims),
                        error: None,
                    })
                }
            }
            Err(e) => Ok(ValidationResult {
                valid: false,
                claims: None,
                error: Some(e.to_string()),
            })
        }
    }

    /// Additional claim validation
    fn validate_claims(&self, claims: &Claims) -> Result<()> {
        // Check expiration
        let now = chrono::Utc::now().timestamp();
        if claims.exp < now - self.clock_skew_seconds {
            return Err(OAuthError::TokenExpired);
        }

        // Check not before
        if let Some(nbf) = claims.nbf {
            if nbf > now + self.clock_skew_seconds {
                return Err(OAuthError::TokenValidation(
                    jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::ImmatureSignature
                    )
                ));
            }
        }

        Ok(())
    }

    /// Extract claims without validation (for debugging only)
    pub fn extract_claims_unsafe(token: &str) -> Result<Claims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(OAuthError::TokenValidation(
                jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken
                )
            ));
        }

        let payload = general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| OAuthError::TokenValidation(
                jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken
                )
            ))?;

        let claims: Claims = serde_json::from_slice(&payload)
            .map_err(|_| OAuthError::TokenValidation(
                jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken
                )
            ))?;

        Ok(claims)
    }
}