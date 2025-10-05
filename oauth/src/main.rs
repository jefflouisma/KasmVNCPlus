mod config;
mod error;
mod handler;
mod jwks;
mod jwt;
mod pkce;
mod session;
mod websocket;

use crate::config::OAuthConfig;
use crate::error::OAuthError;
use crate::handler::OAuthHandler;
use crate::jwks::JwksCache;
use crate::jwt::JwtValidator;
use crate::session::SessionManager;
use crate::websocket::{handle_websocket, WebSocketState};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::{Duration as ChronoDuration, Utc};
use cookie::time::Duration as CookieDuration;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{interval, Duration as TokioDuration, MissedTickBehavior};
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const SESSION_COOKIE_NAME: &str = "kasmvnc_session";
const VNC_REDIRECT_PATH: &str = "/vnc";

#[derive(Clone)]
struct AppState {
    config: Arc<OAuthConfig>,
    oauth_handler: Arc<OAuthHandler>,
    jwt_validator: Arc<JwtValidator>,
    session_manager: Arc<SessionManager>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config_path =
        std::env::var("OAUTH_CONFIG").unwrap_or_else(|_| "config/oauth.toml".to_string());

    let config = Arc::new(OAuthConfig::from_file(&config_path).await?);

    if !config.enabled {
        tracing::info!("OAuth is disabled in configuration");
        return Ok(());
    }

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
        config.session.allow_multiple_sessions,
        config.session.timeout_seconds,
        config.session.idle_timeout_seconds,
    ));

    let cleanup_manager = session_manager.clone();
    tokio::spawn(async move {
        let mut ticker = interval(TokioDuration::from_secs(60));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            cleanup_manager.cleanup_expired().await;
        }
    });

    let app_state = AppState {
        config: config.clone(),
        oauth_handler,
        jwt_validator: jwt_validator.clone(),
        session_manager: session_manager.clone(),
    };

    let ws_state = Arc::new(WebSocketState {
        jwt_validator,
        session_manager,
    });

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

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    tracing::info!("OAuth server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(
        r#"
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
    "#,
    )
}

async fn login(State(state): State<AppState>) -> impl IntoResponse {
    match state.oauth_handler.generate_auth_url().await {
        Ok(auth_request) => Redirect::temporary(&auth_request.authorization_url).into_response(),
        Err(e) => {
            tracing::error!("Failed to generate auth URL: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate auth URL: {}", e),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

async fn callback(
    Query(params): Query<CallbackParams>,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, OAuthError> {
    let token_response = state
        .oauth_handler
        .exchange_code(&params.code, &params.state)
        .await?;

    let now = Utc::now();
    let fallback_lifetime = clamp_to_i64(state.config.tokens.access_token_lifetime);
    let expires_in = duration_from_seconds(token_response.expires_in, fallback_lifetime);
    let mut access_token_scopes = token_response.scope.clone().unwrap_or_default();

    let (user_id, email, scopes_source) = if let Some(id_token) = &token_response.id_token {
        let validation = state.jwt_validator.validate(id_token).await?;
        if !validation.valid {
            let reason = validation
                .error
                .unwrap_or_else(|| "Token validation failed".to_string());
            tracing::warn!("ID token validation failed: {}", reason);
            return Err(OAuthError::TokenValidation(
                jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken),
            ));
        }

        let claims = validation.claims.ok_or_else(|| {
            OAuthError::TokenValidation(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ))
        })?;

        if !claims.scope.is_empty() {
            access_token_scopes = claims.scope.clone();
        }

        (claims.sub, claims.email, access_token_scopes.clone())
    } else {
        let user_info = state
            .oauth_handler
            .get_user_info(&token_response.access_token)
            .await?;

        let user_id = user_info
            .get("sub")
            .and_then(|value| value.as_str())
            .ok_or_else(|| OAuthError::Config("User info response missing `sub`".into()))?
            .to_string();
        let email = user_info
            .get("email")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        (user_id, email, access_token_scopes.clone())
    };

    let scopes_string = if scopes_source.trim().is_empty() {
        state.config.client.scope.clone()
    } else {
        scopes_source
    };
    let scopes: Vec<String> = scopes_string
        .split_whitespace()
        .map(|scope| scope.to_string())
        .collect();

    let expiry = now + expires_in;

    let session = state
        .session_manager
        .create_session(
            user_id,
            email,
            scopes,
            expiry,
            Some(token_response.access_token.clone()),
            token_response.refresh_token.clone(),
        )
        .await?;

    let session_id = {
        let session_guard = session.read().await;
        session_guard.id.clone()
    };

    let cookie_max_age = clamp_to_i64(state.config.session.timeout_seconds);
    let session_cookie = Cookie::build((SESSION_COOKIE_NAME, session_id))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(CookieDuration::seconds(cookie_max_age))
        .build();

    let jar = jar.add(session_cookie);

    Ok((jar, Redirect::to(VNC_REDIRECT_PATH)))
}

async fn logout(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        let session_id = cookie.value().to_string();

        if let Some(session) = state.session_manager.get_session(&session_id).await {
            let (refresh_token, access_token) = {
                let guard = session.read().await;
                (guard.refresh_token.clone(), guard.access_token.clone())
            };

            if let Some(token) = refresh_token {
                if let Err(error) = state
                    .oauth_handler
                    .revoke_token(&token, Some("refresh_token"))
                    .await
                {
                    tracing::warn!(
                        "Failed to revoke refresh token for session {}: {}",
                        session_id,
                        error
                    );
                }
            } else if let Some(token) = access_token {
                if let Err(error) = state
                    .oauth_handler
                    .revoke_token(&token, Some("access_token"))
                    .await
                {
                    tracing::warn!(
                        "Failed to revoke access token for session {}: {}",
                        session_id,
                        error
                    );
                }
            }
        }

        if let Err(error) = state.session_manager.terminate_session(&session_id).await {
            tracing::warn!("Failed to terminate session {}: {}", session_id, error);
        }
    }

    let jar = remove_invalid_session_cookie(jar);
    (jar, StatusCode::NO_CONTENT)
}

async fn refresh(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        if let Some(session) = state.session_manager.get_session(cookie.value()).await {
            let refresh_token = {
                let guard = session.read().await;
                guard.refresh_token.clone()
            };

            if let Some(refresh_token) = refresh_token {
                match state.oauth_handler.refresh_token(&refresh_token).await {
                    Ok(response) => {
                        let fallback_lifetime =
                            clamp_to_i64(state.config.tokens.access_token_lifetime);
                        let expires_in =
                            duration_from_seconds(response.expires_in, fallback_lifetime);

                        {
                            let mut guard = session.write().await;
                            guard.access_token = Some(response.access_token.clone());
                            guard.refresh_token = response
                                .refresh_token
                                .clone()
                                .or_else(|| Some(refresh_token.clone()));
                            guard.token_expiry = Utc::now() + expires_in;
                            if let Some(scope) = response.scope.clone() {
                                guard.scopes = scope
                                    .split_whitespace()
                                    .map(|scope| scope.to_string())
                                    .collect();
                            }
                        }

                        let _ = state.session_manager.update_activity(cookie.value()).await;

                        return (
                            jar,
                            (StatusCode::OK, Json(json!({ "status": "refreshed" }))),
                        );
                    }
                    Err(error) => {
                        tracing::error!("Token refresh failed: {}", error);
                        return (
                            jar,
                            (
                                StatusCode::BAD_GATEWAY,
                                Json(json!({ "error": "Token refresh failed" })),
                            ),
                        );
                    }
                }
            } else {
                return (
                    jar,
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "No refresh token available" })),
                    ),
                );
            }
        } else {
            let jar = remove_invalid_session_cookie(jar);
            return (
                jar,
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Session not found" })),
                ),
            );
        }
    }

    (
        jar,
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Not authenticated" })),
        ),
    )
}

async fn get_session(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        if let Some(session) = state.session_manager.get_session(cookie.value()).await {
            if let Err(error) = state.session_manager.update_activity(cookie.value()).await {
                tracing::warn!("Failed to update session activity: {}", error);
            }

            let snapshot = session.read().await;
            let response = Json(json!({
                "session_id": snapshot.id,
                "user_id": snapshot.user_id,
                "email": snapshot.email,
                "scopes": snapshot.scopes,
                "created_at": snapshot.created_at,
                "last_activity": snapshot.last_activity,
                "expires_at": snapshot.token_expiry,
                "vnc_display": snapshot.vnc_display,
                "vnc_port": snapshot.vnc_port,
                "permissions": {
                    "can_view": snapshot.permissions.can_view,
                    "can_control": snapshot.permissions.can_control,
                    "can_clipboard": snapshot.permissions.can_clipboard,
                    "can_file_transfer": snapshot.permissions.can_file_transfer,
                }
            }));

            return (jar, (StatusCode::OK, response));
        } else {
            let jar = remove_invalid_session_cookie(jar);
            return (
                jar,
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Session not found" })),
                ),
            );
        }
    }

    (
        jar,
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Not authenticated" })),
        ),
    )
}

fn remove_invalid_session_cookie(jar: CookieJar) -> CookieJar {
    let removal_cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(CookieDuration::seconds(0))
        .build();
    jar.remove(removal_cookie)
}

fn clamp_to_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn duration_from_seconds(seconds: Option<i64>, fallback_seconds: i64) -> ChronoDuration {
    seconds
        .filter(|value| *value > 0)
        .map(ChronoDuration::seconds)
        .unwrap_or_else(|| ChronoDuration::seconds(fallback_seconds))
}
