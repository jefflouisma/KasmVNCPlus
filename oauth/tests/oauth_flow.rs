use kasmvnc_oauth::config::{
    LoggingConfig, OAuthClient, OAuthConfig, OAuthEndpoints, SecurityConfig, SessionConfig,
    TokenConfig, TokenValidation,
};
use kasmvnc_oauth::handler::OAuthHandler;
use std::sync::Arc;
use wiremock::MockServer;
#[tokio::test]
async fn test_authorization_url_generation() {
    // Setup mock OAuth server
    let mock_server = MockServer::start().await;

    // Configure OAuth handler with mock server URL
    let config = OAuthConfig {
        enabled: true,
        provider: "test".to_string(),
        endpoints: OAuthEndpoints {
            issuer: mock_server.uri(),
            authorization: format!("{}/authorize", mock_server.uri()),
            token: format!("{}/token", mock_server.uri()),
            jwks: format!("{}/jwks", mock_server.uri()),
            userinfo: format!("{}/userinfo", mock_server.uri()),
            discovery: String::new(),
            revocation: None,
        },
        client: OAuthClient {
            client_id: "test-client".to_string(),
            client_secret: String::new(),
            redirect_uri: "http://localhost:8080/callback".to_string(),
            scope: "openid profile".to_string(),
        },
        security: SecurityConfig {
            use_pkce: true,
            pkce_method: "S256".to_string(),
            require_state: true,
            token_validation: TokenValidation {
                verify_signature: true,
                verify_issuer: true,
                verify_audience: true,
                verify_expiration: true,
                clock_skew_seconds: 60,
            },
        },
        tokens: TokenConfig {
            access_token_lifetime: 3600,
            refresh_token_lifetime: 7776000,
            jwks_cache_ttl: 86400,
        },
        session: SessionConfig {
            timeout_seconds: 28800,
            idle_timeout_seconds: 3600,
            allow_multiple_sessions: true,
            max_sessions_per_user: 5,
        },
        logging: LoggingConfig {
            level: "info".to_string(),
            log_tokens: false,
            log_claims: true,
        },
    };

    let handler = OAuthHandler::new(Arc::new(config));
    let auth_request = handler.generate_auth_url().await.unwrap();

    assert!(!auth_request.authorization_url.is_empty());
    assert!(!auth_request.state.is_empty());
    assert!(!auth_request.code_verifier.is_empty());
    assert!(auth_request
        .authorization_url
        .contains("response_type=code"));
    assert!(auth_request.authorization_url.contains("code_challenge="));
}
