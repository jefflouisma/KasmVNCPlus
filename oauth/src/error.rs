use thiserror::Error;
use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;
use reqwest;
use jsonwebtoken;
use url;

#[derive(Error, Debug)]
pub enum OAuthError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Token validation failed: {0}")]
    TokenValidation(#[from] jsonwebtoken::errors::Error),

    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),

    #[error("Invalid authorization code")]
    InvalidAuthCode,

    #[error("Invalid state parameter")]
    InvalidState,

    #[error("Token expired")]
    TokenExpired,

    #[error("JWKS key not found: {0}")]
    JwksKeyNotFound(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Internal server error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            OAuthError::Config(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            OAuthError::TokenValidation(err) => (StatusCode::UNAUTHORIZED, err.to_string()),
            OAuthError::InvalidAuthCode => (StatusCode::BAD_REQUEST, "Invalid authorization code".to_string()),
            OAuthError::InvalidState => (StatusCode::BAD_REQUEST, "Invalid state parameter".to_string()),
            OAuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired".to_string()),
            OAuthError::SessionNotFound(id) => (StatusCode::NOT_FOUND, format!("Session {} not found", id)),
            OAuthError::UrlParse(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        let body = serde_json::json!({
            "error": error_message,
            "status": status.as_u16(),
        });

        (status, axum::Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, OAuthError>;