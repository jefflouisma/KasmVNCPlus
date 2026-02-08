use axum::{
    extract::{Query, State, WebSocketUpgrade},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl,
    Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

mod config;
mod error;

use config::OAuthConfig;
use error::AppError;

// ─── Session & State ────────────────────────────────────────────────────────

#[derive(Clone, Debug, serde::Serialize)]
struct UserSession {
    sub: String,
    email: Option<String>,
    name: Option<String>,
    access_token: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// PkceCodeVerifier can't be cloned, so we wrap in Option and take() on use
struct PendingAuth {
    pkce_verifier: Option<PkceCodeVerifier>,
    nonce: Nonce,
    created_at: chrono::DateTime<chrono::Utc>,
}

struct AppState {
    oidc_client: CoreClient,
    config: OAuthConfig,
    /// CSRF state → pending auth (cleaned up after 10 min)
    pending: RwLock<HashMap<String, PendingAuth>>,
    /// Session ID (cookie) → user session
    sessions: RwLock<HashMap<String, UserSession>>,
    /// HTTP client for reverse proxy
    http_client: reqwest::Client,
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Load config
    let config_path = std::env::var("OAUTH_CONFIG")
        .unwrap_or_else(|_| "/etc/kasmvnc/oauth.toml".into());
    let config = OAuthConfig::from_file(&config_path)?;
    info!("Loaded config from {}", config_path);

    // OIDC discovery (use internal URL for server-to-server)
    let discovery_url = config.discovery_issuer_url();
    info!("Discovering OIDC provider at {}", discovery_url);
    let issuer_url = IssuerUrl::new(discovery_url.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid issuer URL: {}", e))?;

    let provider_metadata =
        CoreProviderMetadata::discover_async(issuer_url, async_http_client)
            .await
            .map_err(|e| anyhow::anyhow!("OIDC discovery failed: {}", e))?;

    info!("OIDC discovery successful");

    // Fix the SSO Hostname Paradox: discovery uses the internal Docker URL
    // (host.docker.internal) but Keycloak's tokens contain the public URL
    // (localhost) as issuer. Override the provider metadata's issuer to the
    // public URL so token validation accepts the `iss` claim.
    let provider_metadata = if config.provider.internal_issuer_url.is_some() {
        let public_issuer = IssuerUrl::new(config.provider.issuer_url.clone())
            .map_err(|e| anyhow::anyhow!("Invalid public issuer URL: {}", e))?;
        info!("Overriding issuer for token validation: {}", config.provider.issuer_url);
        provider_metadata.set_issuer(public_issuer)
    } else {
        provider_metadata
    };

    // Create OIDC client
    let oidc_client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.client.client_id.clone()),
        Some(ClientSecret::new(config.client.client_secret.clone())),
    )
    .set_redirect_uri(
        RedirectUrl::new(config.client.redirect_uri.clone())
            .map_err(|e| anyhow::anyhow!("Invalid redirect URI: {}", e))?,
    );

    // HTTP client for reverse proxy (skip cert verification for self-signed KasmVNC)
    // Force HTTP/1.1 — KasmVNC doesn't support HTTP/2 ALPN negotiation properly
    let proxy_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .build()?;

    let state = Arc::new(AppState {
        oidc_client,
        config: config.clone(),
        pending: RwLock::new(HashMap::new()),
        sessions: RwLock::new(HashMap::new()),
        http_client: proxy_client,
    });

    // Spawn session reaper — cleans expired sessions every 60s
    let reaper_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let mut sessions = reaper_state.sessions.write().await;
            let now = chrono::Utc::now();
            let before = sessions.len();
            sessions.retain(|_, s| s.expires_at > now);
            let expired = before - sessions.len();
            if expired > 0 {
                info!("Session reaper: removed {} expired sessions ({} active)", expired, sessions.len());
                // Write session_expired trigger for entrypoint
                if sessions.is_empty() {
                    let _ = tokio::fs::write("/tmp/session_expired", "all sessions expired").await;
                }
            }
        }
    });

    // Routes
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", get(logout))
        .route("/api/session", get(get_session))
        .route("/admin/{page}", get(admin_page))
        .route("/admin", get(admin_dashboard))
        .fallback(reverse_proxy)
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("{}:{}", config.server.bind_address, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("OAuth server listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

// ─── Handlers ───────────────────────────────────────────────────────────────

async fn index() -> Result<Html<String>, StatusCode> {
    // Serve the Stitch-generated enterprise login page
    let login_html = tokio::fs::read_to_string("/opt/kasmvnc/admin-dashboard/pages/login.html")
        .await
        .unwrap_or_else(|_| {
            // Fallback: minimal login page
            r#"<!DOCTYPE html>
<html><head><title>KasmVNC Plus</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#0f111a;color:#fff;margin:0}
.card{background:rgba(24,24,27,0.8);padding:3rem;border-radius:1rem;text-align:center;border:1px solid rgba(255,255,255,0.1)}
a{display:inline-block;margin-top:1.5rem;padding:0.75rem 2rem;background:linear-gradient(135deg,#1337ec,#6366f1);color:#fff;text-decoration:none;border-radius:0.5rem;font-weight:600}</style>
</head><body><div class="card"><h1>KasmVNC <span style="color:#6366f1">Plus</span></h1>
<p>Enterprise Secure Browser</p><a href="/auth/login">Sign in with SSO</a></div></body></html>"#.to_string()
        });

    // Inject the actual SSO login URL into the login page
    let html = login_html.replace(
        "href=\"#\"",
        "href=\"/auth/login\"",
    );

    Ok(Html(html))
}

/// Admin dashboard — serves the overview page (requires auth)
async fn admin_dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Html<String>, StatusCode> {
    extract_session(&state, &headers)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    serve_admin_page("dashboard").await
}

/// Admin dashboard subpages — serves specific pages (requires auth)
async fn admin_page(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(page): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Result<Html<String>, StatusCode> {
    extract_session(&state, &headers)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    serve_admin_page(&page).await
}

/// Serve an admin dashboard HTML page from the filesystem
async fn serve_admin_page(page: &str) -> Result<Html<String>, StatusCode> {
    // Sanitize page name — only alphanumeric + hyphens allowed
    if !page.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(StatusCode::BAD_REQUEST);
    }

    let path = format!("/opt/kasmvnc/admin-dashboard/pages/{}.html", page);
    let html = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Html(html))
}

/// Liveness probe — returns 200 if the process is alive
async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Readiness probe — returns 200 only after SSO login + VNC started
async fn readyz() -> StatusCode {
    if std::path::Path::new("/tmp/sso_ready").exists() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Step 1: Generate authorization URL and redirect to Keycloak
async fn login(State(state): State<Arc<AppState>>) -> Result<Redirect, AppError> {
    // Clean up expired pending auths (> 10 min old)
    {
        let mut pending = state.pending.write().await;
        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(10);
        pending.retain(|_, v| v.created_at > cutoff);
    }

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_request = state.oidc_client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    // Add configured scopes
    for scope in &state.config.client.scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (auth_url, csrf_token, nonce) = auth_request
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store pending auth for callback verification
    state.pending.write().await.insert(
        csrf_token.secret().clone(),
        PendingAuth {
            pkce_verifier: Some(pkce_verifier),
            nonce,
            created_at: chrono::Utc::now(),
        },
    );

    // Replace internal URL with public URL in the redirect
    let auth_url_str = auth_url.to_string();
    let public_url = if let Some(ref internal) = state.config.provider.internal_issuer_url {
        auth_url_str.replace(internal, &state.config.provider.issuer_url)
    } else {
        auth_url_str
    };

    info!("Redirecting to OIDC provider");
    Ok(Redirect::temporary(&public_url))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

/// Step 2: Exchange authorization code for tokens, extract user info
async fn callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    // Verify CSRF state and get pending auth
    let mut pending = state
        .pending
        .write()
        .await
        .remove(&query.state)
        .ok_or_else(|| AppError::Oidc("Invalid or expired state parameter".into()))?;

    let pkce_verifier = pending
        .pkce_verifier
        .take()
        .ok_or_else(|| AppError::Oidc("PKCE verifier already consumed".into()))?;

    // Exchange code for tokens (async)
    let token_response = state
        .oidc_client
        .exchange_code(AuthorizationCode::new(query.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            error!("Token exchange failed: {}", e);
            AppError::Oidc(format!("Token exchange failed: {}", e))
        })?;

    // Extract claims from ID token
    let id_token = token_response
        .id_token()
        .ok_or_else(|| AppError::Oidc("No ID token in response".into()))?;

    let id_token_verifier = state.oidc_client.id_token_verifier();
    let claims = id_token
        .claims(&id_token_verifier, &pending.nonce)
        .map_err(|e| AppError::Oidc(format!("ID token validation failed: {}", e)))?;

    let sub = claims.subject().to_string();
    let email = claims
        .email()
        .map(|e| e.to_string());
    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.to_string());

    info!("User authenticated: sub={}, email={:?}, name={:?}", sub, email, name);

    // Create session with expiry
    let session_id = uuid::Uuid::new_v4().to_string();
    let timeout_minutes = state.config.server.session_timeout_minutes;
    let now = chrono::Utc::now();
    let session = UserSession {
        sub: sub.clone(),
        email: email.clone(),
        name: name.clone(),
        access_token: token_response.access_token().secret().clone(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(timeout_minutes as i64),
    };

    state.sessions.write().await.insert(session_id.clone(), session.clone());

    // Write user metadata for recorder
    write_user_metadata(&state.config.recorder.output_dir, &session).await;

    // Write SSO ready trigger — signals entrypoint to start VNC + Chromium + Recorder
    write_sso_trigger(&session).await;

    // Set session cookie and redirect to VNC
    let cookie_value = format!("session_id={}; HttpOnly; Path=/; SameSite=Lax", session_id);
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, cookie_value.parse().unwrap());
    headers.insert(header::LOCATION, "/vnc/".parse().unwrap());

    Ok((StatusCode::TEMPORARY_REDIRECT, headers, "").into_response())
}

/// Get current session info
async fn get_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    if let Some(session) = extract_session(&state, &headers).await {
        Ok(axum::Json(serde_json::json!({
            "authenticated": true,
            "sub": session.sub,
            "email": session.email,
            "name": session.name,
        })))
    } else {
        Ok(axum::Json(serde_json::json!({
            "authenticated": false,
        })))
    }
}

/// Logout: clear session and redirect to Keycloak logout
async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    // Remove session
    if let Some(session_id) = extract_session_id(&headers) {
        state.sessions.write().await.remove(&session_id);
    }

    let clear_cookie = "session_id=; HttpOnly; Path=/; Max-Age=0";
    let redirect_uri = format!("http://localhost:{}", state.config.server.port);
    let logout_url = format!(
        "{}/protocol/openid-connect/logout?redirect_uri={}",
        state.config.provider.issuer_url,
        urlencoding::encode(&redirect_uri),
    );

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, clear_cookie.parse().unwrap());
    resp_headers.insert(header::LOCATION, logout_url.parse().unwrap());

    (StatusCode::TEMPORARY_REDIRECT, resp_headers, "").into_response()
}

// ─── Reverse Proxy + WebSocket ──────────────────────────────────────────────

/// Reverse proxy all other requests to KasmVNC (requires authentication).
/// WebSocket upgrade requests are detected and handled with bidirectional relay.
async fn reverse_proxy(
    State(state): State<Arc<AppState>>,
    ws_upgrade: Option<WebSocketUpgrade>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Result<Response, AppError> {
    // Check authentication (and reject expired sessions)
    let session = extract_session(&state, &headers)
        .await
        .ok_or(AppError::NotAuthenticated)?;

    // Audit log: log every proxied request with user context
    let user_email = session.email.as_deref().unwrap_or("unknown");
    info!(
        target: "audit",
        "proxy_request: method={} uri={} user={}",
        method, uri, user_email
    );

    // ─── WebSocket Upgrade Path ─────────────────────────────────────────────
    if let Some(ws) = ws_upgrade {
        let upstream = state.config.server.vnc_upstream.clone();
        let raw_path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        // Strip /vnc prefix — KasmVNC serves at /
        let path = raw_path.strip_prefix("/vnc").unwrap_or(raw_path);

        // Build upstream WebSocket URL (replace http:// with ws://)
        let ws_upstream = upstream
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let ws_url = format!("{}{}", ws_upstream, path);

        info!("WebSocket upgrade: proxying to {}", ws_url);

        return Ok(ws.protocols(["binary"]).on_upgrade(move |client_socket| async move {
            if let Err(e) = handle_websocket(client_socket, &ws_url).await {
                error!("WebSocket proxy error: {}", e);
            }
        }));
    }

    // ─── Regular HTTP Proxy Path ────────────────────────────────────────────
    let upstream = &state.config.server.vnc_upstream;
    let raw_path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    // Strip /vnc prefix — KasmVNC serves at /
    let path = raw_path.strip_prefix("/vnc").unwrap_or(raw_path);
    let upstream_url = format!("{}{}", upstream, path);

    // Collect body bytes for forwarding
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|e| AppError::Internal(format!("Body read error: {}", e)))?;

    // Forward request to KasmVNC
    let req_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|e| AppError::Internal(format!("Invalid method: {}", e)))?;

    let mut proxy_req = state.http_client.request(req_method, &upstream_url);

    // Forward relevant headers (convert types manually due to http crate version mismatch)
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if name_str != "host" && name_str != "cookie" {
            if let Ok(val_str) = value.to_str() {
                proxy_req = proxy_req.header(name_str, val_str);
            }
        }
    }

    let resp = proxy_req
        .body(body_bytes.to_vec())
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Proxy error: {}", e)))?;

    // Convert response back to axum types
    let status = StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response = Response::builder().status(status);

    for (name, value) in resp.headers().iter() {
        if let Ok(val_str) = value.to_str() {
            response = response.header(name.as_str(), val_str);
        }
    }

    // Stream the response body directly (avoids buffering and TLS EOF errors)
    let resp_body = axum::body::Body::from_stream(resp.bytes_stream());

    Ok(response.body(resp_body).unwrap())
}

/// Bidirectional WebSocket relay between browser and KasmVNC
async fn handle_websocket(
    client_socket: axum::extract::ws::WebSocket,
    upstream_url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::extract::ws::Message as AxumMsg;
    use tokio_tungstenite::tungstenite::Message as TungMsg;

    // Connect to upstream KasmVNC WebSocket (accept self-signed certs)
    let mut ws_request = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(upstream_url)?;
    // KasmVNC requires Origin and Sec-WebSocket-Protocol headers for WebSocket validation
    ws_request.headers_mut().insert(
        "Origin",
        upstream_url.parse().unwrap_or_else(|_| "https://127.0.0.1:8444".parse().unwrap()),
    );
    ws_request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "binary".parse().unwrap(),
    );

    // Build a TLS connector that accepts self-signed certs
    let tls = tokio_tungstenite::Connector::NativeTls(
        native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?
    );

    let (upstream_socket, _) = tokio_tungstenite::connect_async_tls_with_config(
        ws_request,
        None,
        false,
        Some(tls),
    ).await?;
    info!("Connected to upstream WebSocket: {}", upstream_url);

    let (mut client_tx, mut client_rx) = client_socket.split();
    let (mut upstream_tx, mut upstream_rx) = upstream_socket.split();

    // Client → Upstream
    let client_to_upstream = async {
        while let Some(msg) = client_rx.next().await {
            match msg {
                Ok(AxumMsg::Text(text)) => {
                    if upstream_tx.send(TungMsg::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Ok(AxumMsg::Binary(data)) => {
                    if upstream_tx.send(TungMsg::Binary(data.into())).await.is_err() {
                        break;
                    }
                }
                Ok(AxumMsg::Ping(data)) => {
                    if upstream_tx.send(TungMsg::Ping(data.into())).await.is_err() {
                        break;
                    }
                }
                Ok(AxumMsg::Pong(data)) => {
                    if upstream_tx.send(TungMsg::Pong(data.into())).await.is_err() {
                        break;
                    }
                }
                Ok(AxumMsg::Close(_)) | Err(_) => break,
            }
        }
        let _ = upstream_tx.close().await;
    };

    // Upstream → Client
    let upstream_to_client = async {
        while let Some(msg) = upstream_rx.next().await {
            match msg {
                Ok(TungMsg::Text(text)) => {
                    if client_tx.send(AxumMsg::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Ok(TungMsg::Binary(data)) => {
                    if client_tx.send(AxumMsg::Binary(data.into())).await.is_err() {
                        break;
                    }
                }
                Ok(TungMsg::Ping(data)) => {
                    if client_tx.send(AxumMsg::Ping(data.into())).await.is_err() {
                        break;
                    }
                }
                Ok(TungMsg::Pong(data)) => {
                    if client_tx.send(AxumMsg::Pong(data.into())).await.is_err() {
                        break;
                    }
                }
                Ok(TungMsg::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
        let _ = client_tx.close().await;
    };

    // Run both directions concurrently — when one ends, the other is dropped
    tokio::select! {
        _ = client_to_upstream => info!("Client disconnected"),
        _ = upstream_to_client => info!("Upstream disconnected"),
    }

    Ok(())
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("session_id=") {
            return Some(value.to_string());
        }
    }
    None
}

async fn extract_session(state: &AppState, headers: &HeaderMap) -> Option<UserSession> {
    let session_id = extract_session_id(headers)?;
    let sessions = state.sessions.read().await;
    let session = sessions.get(&session_id)?;
    // Reject expired sessions
    if session.expires_at <= chrono::Utc::now() {
        return None;
    }
    Some(session.clone())
}

/// Write user metadata JSON to the recordings directory
async fn write_user_metadata(output_dir: &str, session: &UserSession) {
    let metadata = serde_json::json!({
        "sub": session.sub,
        "email": session.email,
        "name": session.name,
        "login_time": session.created_at.to_rfc3339(),
    });

    let metadata_path = format!("{}/current_user.json", output_dir);
    if let Err(e) = tokio::fs::create_dir_all(output_dir).await {
        warn!("Failed to create recordings dir: {}", e);
        return;
    }
    if let Err(e) = tokio::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata).unwrap()).await {
        warn!("Failed to write user metadata: {}", e);
    } else {
        info!("Wrote user metadata to {}", metadata_path);
    }
}

/// Write SSO trigger file — signals the entrypoint to start VNC + Chromium + Recorder
/// Contains user identity so entrypoint can configure watermark before VNC starts
async fn write_sso_trigger(session: &UserSession) {
    let trigger = serde_json::json!({
        "sub": session.sub,
        "email": session.email,
        "name": session.name,
        "login_time": session.created_at.to_rfc3339(),
    });

    let trigger_path = "/tmp/sso_ready";
    if let Err(e) = tokio::fs::write(trigger_path, serde_json::to_string_pretty(&trigger).unwrap()).await {
        warn!("Failed to write SSO trigger: {}", e);
    } else {
        info!("SSO trigger written to {} — VNC + Chromium + Recorder will start", trigger_path);
    }
}

// URL encoding helper
mod urlencoding {
    pub fn encode(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }
}