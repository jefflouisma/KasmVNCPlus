use crate::oauth::config::OAuthConfig;
use crate::oauth::jwt::JwtValidator;
use crate::oauth::pkce::{generate_code_challenge, generate_code_verifier, generate_state};
use crate::oauth::session::SessionManager;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade
    },
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use reqwest::Client;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<OAuthConfig>,
    pub jwt_validator: Arc<JwtValidator>,
    pub session_manager: Arc<SessionManager>,
    pub pkce_store: Arc<RwLock<HashMap<String, String>>>, // state -> code_verifier
    pub http_client: Client,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { Html("<h1>KasmVNC OAuth Server</h1><a href=\"/login\">Login</a>") }))
        .route("/login", get(login_handler))
        .route("/auth/callback", get(auth_callback_handler))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

#[axum::debug_handler]
async fn login_handler(State(state): State<AppState>) -> impl IntoResponse {
    let code_verifier = generate_code_verifier();
    let code_challenge = generate_code_challenge(&code_verifier);
    let state_val = generate_state();

    state.pkce_store.write().await.insert(state_val.clone(), code_verifier);

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        state.config.endpoints.authorization,
        state.config.client.client_id,
        state.config.client.redirect_uri,
        state.config.client.scope,
        state_val,
        code_challenge
    );

    Redirect::to(&auth_url)
}

#[derive(Debug, Deserialize)]
pub struct AuthCallbackParams {
    code: String,
    state: String,
}

#[derive(Debug, Serialize)]
struct TokenRequest<'a> {
    grant_type: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    code_verifier: &'a str,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: Option<String>,
}

#[axum::debug_handler]
async fn auth_callback_handler(
    Query(params): Query<AuthCallbackParams>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let code_verifier = match state.pkce_store.write().await.remove(&params.state) {
        Some(verifier) => verifier,
        None => return Html("Invalid state parameter".to_string()).into_response(),
    };

    let token_request = TokenRequest {
        grant_type: "authorization_code",
        code: &params.code,
        redirect_uri: &state.config.client.redirect_uri,
        client_id: &state.config.client.client_id,
        client_secret: &state.config.client.client_secret,
        code_verifier: &code_verifier,
    };

    let token_res = state.http_client
        .post(&state.config.endpoints.token)
        .form(&token_request)
        .send()
        .await;

    let token_response: TokenResponse = match token_res {
        Ok(res) => match res.json().await {
            Ok(json) => json,
            Err(e) => return Html(format!("Failed to parse token response: {e}")).into_response(),
        },
        Err(e) => return Html(format!("Token exchange request failed: {e}")).into_response(),
    };

    let token_to_validate = token_response.id_token.as_ref().unwrap_or(&token_response.access_token);
    let claims = match state.jwt_validator.validate(token_to_validate).await {
        Ok(claims) => claims,
        Err(e) => return Html(format!("Token validation failed: {e}")).into_response(),
    };

    let _session = state.session_manager.create_session(claims.sub, claims.email).await;

    Html(format!(r#"
        <h1>Authentication Successful</h1>
        <p>You can now connect to the WebSocket with this access token.</p>
        <textarea id="token" rows="10" cols="80">{}</textarea>
        <script>
            document.getElementById('token').select();
            document.execCommand('copy');
            alert('Access Token copied to clipboard!');
        </script>
    "#, token_response.access_token)).into_response()
}

#[derive(Deserialize)]
struct AuthMessage {
    token: String,
}

#[axum::debug_handler]
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let claims = match socket.recv().await {
        Some(Ok(Message::Text(text))) => {
            let auth_msg: AuthMessage = match serde_json::from_str(&text) {
                Ok(msg) => msg,
                Err(_) => {
                    let _ = socket.send(Message::Text("Invalid auth message format".into())).await;
                    let _ = socket.close().await;
                    return;
                }
            };
            match state.jwt_validator.validate(&auth_msg.token).await {
                Ok(claims) => claims,
                Err(_) => {
                    let _ = socket.send(Message::Text("Invalid token".into())).await;
                    let _ = socket.close().await;
                    return;
                }
            }
        }
        _ => {
            let _ = socket.close().await;
            return;
        }
    };

    let session = match state.session_manager.create_session(claims.sub, claims.email).await {
        Ok(session) => session,
        Err(e) => {
            let _ = socket.send(Message::Text(format!("Failed to create session: {e}"))).await;
            let _ = socket.close().await;
            return;
        }
    };

    let vnc_address = format!("127.0.0.1:{}", session.vnc_port);
    let vnc_socket = match TcpStream::connect(vnc_address).await {
        Ok(socket) => socket,
        Err(e) => {
            let _ = socket.send(Message::Text(format!("Failed to connect to VNC server: {e}"))).await;
            let _ = state.session_manager.terminate_session(&session.id).await;
            let _ = socket.close().await;
            return;
        }
    };

    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (mut vnc_reader, mut vnc_writer) = tokio::io::split(vnc_socket);

    let session_id_clone = session.id;
    let session_manager_clone = state.session_manager.clone();

    let ws_to_vnc = async {
        while let Some(Ok(msg)) = ws_receiver.next().await {
            if let Message::Binary(data) = msg {
                if tokio::io::AsyncWriteExt::write_all(&mut vnc_writer, &data).await.is_err() {
                    break;
                }
            }
        }
    };

    let vnc_to_ws = async {
        let mut buffer = vec![0u8; 4096];
        while let Ok(n) = tokio::io::AsyncReadExt::read(&mut vnc_reader, &mut buffer).await {
            if n == 0 || ws_sender.send(Message::Binary(buffer[..n].to_vec())).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = ws_to_vnc => {},
        _ = vnc_to_ws => {},
    }

    let _ = session_manager_clone.terminate_session(&session_id_clone).await;
}