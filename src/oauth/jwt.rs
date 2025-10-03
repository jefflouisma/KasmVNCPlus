use crate::oauth::config::OAuthConfig;
use async_oidc_jwt_validator::{OidcConfig, OidcValidator};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub exp: usize,
}

#[derive(Clone)]
pub struct JwtValidator {
    validator: OidcValidator,
}

impl JwtValidator {
    pub async fn new(config: OAuthConfig) -> Result<Self, anyhow::Error> {
        let oidc_config = OidcConfig::new_with_discovery(
            config.endpoints.issuer.clone(),
            config.client.client_id.clone(),
        )
        .await?;
        let validator = OidcValidator::new(oidc_config);
        Ok(Self { validator })
    }

    pub async fn validate(&self, token: &str) -> Result<Claims, anyhow::Error> {
        let claims = self.validator.validate::<Claims>(token).await?;
        Ok(claims)
    }
}