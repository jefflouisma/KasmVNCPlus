use std::sync::Arc;
use std::time::Duration;
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{DecodingKey, Algorithm};
use crate::error::{OAuthError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    pub kty: String,  // Key type (RSA, EC, oct)
    pub kid: String,  // Key ID
    pub alg: Option<String>,  // Algorithm
    #[serde(rename = "use")]
    pub use_: Option<String>, // Key use ("sig" or "enc")

    // RSA specific
    pub n: Option<String>,  // Modulus
    pub e: Option<String>,  // Exponent

    // EC specific
    pub crv: Option<String>,  // Curve
    pub x: Option<String>,    // X coordinate
    pub y: Option<String>,    // Y coordinate
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
        self.cache.get(kid).await
            .ok_or_else(|| OAuthError::JwksKeyNotFound(kid.to_string()))
    }

    /// Refresh JWKS from endpoint
    pub async fn refresh(&self) -> Result<()> {
        let jwks: JwksDocument = self.client
            .get(&self.jwks_uri)
            .send()
            .await?
            .json()
            .await?;

        for key in jwks.keys {
            if let Some(decoding_key) = self.jwk_to_decoding_key(&key)? {
                self.cache.insert(key.kid.clone(), Arc::new(decoding_key)).await;
            }
        }

        Ok(())
    }

    /// Convert JWK to DecodingKey
    fn jwk_to_decoding_key(&self, jwk: &JwksKey) -> Result<Option<DecodingKey>> {
        match jwk.kty.as_str() {
            "RSA" => {
                // RSA key
                if let (Some(n), Some(e)) = (&jwk.n, &jwk.e) {
                    let key = DecodingKey::from_rsa_components(n, e)?;
                    Ok(Some(key))
                } else {
                    Ok(None)
                }
            }
            "EC" => {
                // Elliptic Curve key
                // Note: jsonwebtoken crate has limited EC support
                // You may need to implement custom handling
                Ok(None)
            }
            "oct" => {
                // Symmetric key (HMAC)
                // Generally not used in OIDC
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Get algorithm from JWK
    pub fn get_algorithm(jwk: &JwksKey) -> Algorithm {
        jwk.alg.as_ref().and_then(|alg| {
            match alg.as_str() {
                "RS256" => Some(Algorithm::RS256),
                "RS384" => Some(Algorithm::RS384),
                "RS512" => Some(Algorithm::RS512),
                "ES256" => Some(Algorithm::ES256),
                "ES384" => Some(Algorithm::ES384),
                _ => None,
            }
        }).unwrap_or(Algorithm::RS256)
    }
}