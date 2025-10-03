mod config;
mod error;
mod handler;
mod jwt;
mod jwks;
mod pkce;
mod session;
mod websocket;

use std::sync::Arc;
use std::net::SocketAddr;
use axum::{
    Router,
    extract::{Query, State},
    response::{Html, Redirect, IntoResponse},
    routing::{get, post},
    Json,
    http::StatusCode,
};
use serde::{Deserialize};
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use crate::config::OAuthConfig;
use crate::handler::OAuthHandler;
use crate::jwt::JwtValidator;
use crate::jwks::JwksCache;
use crate::session::SessionManager;
use crate::websocket::{WebSocketState, handle_websocket};

#[derive(Clone)]
struct AppState {
    config: Arc<OAuthConfig>,
    oauth_handler: Arc<OAuthHandler>,
    jwt_validator: Arc<JwtValidator>,
    session_manager: Arc<SessionManager>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config_path = std::env::var("OAUTH_CONFIG")
        .unwrap_or_else(|_| "config/oauth.toml".to_string());

    let config = Arc::new(OAuthConfig::from_file(&config_path).await?);

    if !config.enabled {
        tracing::info!("OAuth is disabled in configuration");
        return Ok(());
    }

    // Initialize components
    let jwks_cache = Arc::new(JwksCache::new(
        config.endpoints.jwks.clone(),
        config.tokens.jwks_cache_ttl,
    ));

    let jwt_validator = Arc::new(JwtValidator::new(
        config.endpoints.issuer.clone(),
        config.client.client_id.clone(),
        jwks_cache,
        config.security.token_validation.clock_skew_seconds,
    ));

    let oauth_handler = Arc::new(OAuthHandler::new(config.clone()));

    let session_manager = Arc::new(SessionManager::new(
        config.session.max_sessions_per_user,
    ));

    let app_state = AppState {
        config: config.clone(),
        oauth_handler,
        jwt_validator: jwt_validator.clone(),
        session_manager: session_manager.clone(),
    };

    // WebSocket state
    let ws_state = Arc::new(WebSocketState {
        jwt_validator,
        session_manager,
    });

    // Build router
    let app = Router::new()
        .route("/", get(index))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/auth/refresh", post(refresh))
        .route("/api/session", get(get_session))
        .route("/ws", get(handle_websocket).with_state(ws_state))
        .layer(CorsLayer::permissive())
        .with_state(app_state.clone());

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    tracing::info!("OAuth server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Index page
async fn index() -> Html<&'static str> {
    Html(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>KasmVNC OAuth</title>
        </head>
        <body>
            <h1>KasmVNC OAuth Authentication</h1>
            <a href="/auth/login">Login with OAuth</a>
        </body>
        </html>
    "#)
}

/// Initiate OAuth login
async fn login(State(state): State<AppState>) -> impl IntoResponse {
    match state.oauth_handler.generate_auth_url().await {
        Ok(auth_request) => {
            // In production, store state in Redis or session
            Redirect::permanent(&auth_request.authorization_url).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to generate auth URL: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate auth URL: {}", e)).into_response()
        }
    }
}

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

/// OAuth callback
async fn callback(
    Query(params): Query<CallbackParams>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.oauth_handler.exchange_code(&params.code, &params.state).await {
        Ok(token_response) => {
            // Create session and return JWT to client
            Html(format!(r#"
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Successful</title>
                    <script>
                        // Store token and redirect to VNC
                        localStorage.setItem('access_token', '{}');
                        window.location.href = '/vnc';
                    </script>
                </head>
                <body>
                    <h1>Login successful, redirecting...</h1>
                </body>
                </html>
            "#, token_response.access_token)).into_response()
        }
        Err(e) => {
            tracing::error!("Token exchange failed: {}", e);
            Html("<h1>Authentication failed</h1>").into_response()
        }
    }
}

/// Logout
async fn logout() -> impl IntoResponse {
    // In production, revoke token and clear session
    StatusCode::OK
}

/// Refresh token
async fn refresh() -> impl IntoResponse {
    // Implementation for token refresh
    StatusCode::OK
}

/// Get session info
async fn get_session() -> impl IntoResponse {
    // Return current session information
    Json(serde_json::json!({
        "status": "ok"
    }))
}