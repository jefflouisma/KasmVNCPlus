use crate::error::{OAuthError, Result};
use jsonwebtoken::{Algorithm, DecodingKey};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    pub kty: String,         // Key type (RSA, EC, oct)
    pub kid: String,         // Key ID
    pub alg: Option<String>, // Algorithm
    #[serde(rename = "use")]
    pub use_: Option<String>, // Key use ("sig" or "enc")

    // RSA specific
    pub n: Option<String>, // Modulus
    pub e: Option<String>, // Exponent

    // EC specific
    pub crv: Option<String>, // Curve
    pub x: Option<String>,   // X coordinate
    pub y: Option<String>,   // Y coordinate

    // Symmetric key
    pub k: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<JwksKey>,
}

/// JWKS (JSON Web Key Set) Cache
pub struct JwksCache {
    jwks_uri: String,
    cache: Cache<String, Arc<DecodingKey>>,
    client: reqwest::Client,
}

impl JwksCache {
    /// Create new JWKS cache
    pub fn new(jwks_uri: String, ttl_seconds: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_seconds))
            .build();

        JwksCache {
            jwks_uri,
            cache,
            client: reqwest::Client::new(),
        }
    }

    /// Get decoding key by key ID
    pub async fn get_key(&self, kid: &str) -> Result<Arc<DecodingKey>> {
        // Check cache first
        if let Some(key) = self.cache.get(kid).await {
            return Ok(key);
        }

        // Fetch JWKS and update cache
        self.refresh().await?;

        // Try again after refresh
        self.cache
            .get(kid)
            .await
            .ok_or_else(|| OAuthError::JwksKeyNotFound(kid.to_string()))
    }

    /// Refresh JWKS from endpoint
    pub async fn refresh(&self) -> Result<()> {
        let jwks: JwksDocument = self.client.get(&self.jwks_uri).send().await?.json().await?;

        for key in jwks.keys {
            if let Some(decoding_key) = self.jwk_to_decoding_key(&key)? {
                self.cache
                    .insert(key.kid.clone(), Arc::new(decoding_key))
                    .await;
            }
        }

        Ok(())
    }

    /// Convert JWK to DecodingKey
    fn jwk_to_decoding_key(&self, jwk: &JwksKey) -> Result<Option<DecodingKey>> {
        if let Some(use_) = &jwk.use_ {
            if use_ != "sig" {
                return Ok(None);
            }
        }

        match jwk.kty.as_str() {
            "RSA" => {
                // RSA key
                let (n, e) = jwk.n.as_ref().zip(jwk.e.as_ref()).ok_or_else(|| {
                    OAuthError::Config("RSA key missing modulus or exponent".into())
                })?;

                let key = DecodingKey::from_rsa_components(n, e)?;
                Ok(Some(key))
            }
            "EC" => {
                let (x, y) = jwk
                    .x
                    .as_ref()
                    .zip(jwk.y.as_ref())
                    .ok_or_else(|| OAuthError::Config("EC key missing coordinates".into()))?;

                let key = DecodingKey::from_ec_components(x, y)?;
                Ok(Some(key))
            }
            "oct" => {
                let secret = jwk
                    .k
                    .as_ref()
                    .ok_or_else(|| OAuthError::Config("Symmetric key missing secret".into()))?;

                let key = DecodingKey::from_base64_secret(secret)?;
                Ok(Some(key))
            }
            other => Err(OAuthError::Config(format!(
                "Unsupported JWK key type: {}",
                other
            ))),
        }
    }

    /// Get algorithm from JWK
    #[allow(dead_code)]
    pub fn get_algorithm(jwk: &JwksKey) -> Algorithm {
        jwk.alg
            .as_ref()
            .and_then(|alg| match alg.as_str() {
                "RS256" => Some(Algorithm::RS256),
                "RS384" => Some(Algorithm::RS384),
                "RS512" => Some(Algorithm::RS512),
                "ES256" => Some(Algorithm::ES256),
                "ES384" => Some(Algorithm::ES384),
                _ => None,
            })
            .unwrap_or(Algorithm::RS256)
    }
}
