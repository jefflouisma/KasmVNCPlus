use axum::response::IntoResponse;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("OIDC error: {0}")]
    Oidc(String),

    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            AppError::NotAuthenticated => axum::http::StatusCode::UNAUTHORIZED,
            AppError::Config(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Oidc(_) => axum::http::StatusCode::BAD_REQUEST,
            AppError::Internal(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}