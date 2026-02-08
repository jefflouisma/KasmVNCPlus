use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims from Keycloak token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub realm_access: Option<RealmAccess>,
    pub exp: u64,
    pub iss: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

/// Extractor that validates admin JWT from Authorization header
#[derive(Debug, Clone)]
pub struct AdminUser {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

impl AdminUser {
    fn validate_token(token: &str) -> Result<Self, StatusCode> {
        // Decode JWT (in production, use JWKS from Keycloak discovery)
        // For now, use insecure validation that checks structure only
        // TODO: Fetch JWKS from issuer_url/.well-known/openid-configuration
        let mut validation = Validation::new(Algorithm::RS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = true;
        validation.validate_aud = false;

        let token_data = decode::<AdminClaims>(
            token,
            &DecodingKey::from_secret(b"unused"), // signature validation disabled
            &validation,
        )
        .map_err(|e| {
            tracing::warn!("JWT validation failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

        let claims = token_data.claims;

        // Check admin role
        let has_admin = claims
            .realm_access
            .as_ref()
            .map(|ra| ra.roles.iter().any(|r| r == "admin"))
            .unwrap_or(false);

        if !has_admin {
            tracing::warn!(
                "User {} does not have admin role",
                claims.preferred_username.as_deref().unwrap_or(&claims.sub)
            );
            return Err(StatusCode::FORBIDDEN);
        }

        Ok(AdminUser {
            sub: claims.sub,
            email: claims.email,
            name: claims.name,
        })
    }
}

impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        _state: &'life1 S,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        Box::pin(async move {
            let header_str = auth_header.ok_or(StatusCode::UNAUTHORIZED)?;
            let token = header_str
                .strip_prefix("Bearer ")
                .ok_or(StatusCode::UNAUTHORIZED)?;
            Self::validate_token(token)
        })
    }
}
