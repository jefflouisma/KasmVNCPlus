use crate::error::{OAuthError, Result};
use crate::jwt::JwtValidator;
use crate::session::{SessionManager, SharedSession};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::response::Response;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsMessage {
    #[serde(rename = "auth")]
    Auth {
        token: String,
        #[serde(default)]
        method: String,
    },
    #[serde(rename = "auth_required")]
    AuthRequired { methods: Vec<String>, timeout: u32 },
    #[serde(rename = "auth_success")]
    AuthSuccess {
        session_id: String,
        user_id: String,
        email: Option<String>,
        vnc_display: Option<i32>,
        vnc_port: Option<u16>,
    },
    #[serde(rename = "auth_error")]
    AuthError { error: String },
    #[serde(rename = "vnc_data")]
    VncData { data: Vec<u8> },
}

pub struct WebSocketState {
    pub jwt_validator: Arc<JwtValidator>,
    pub session_manager: Arc<SessionManager>,
}

/// Handle WebSocket upgrade request
pub async fn handle_websocket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    tracing::info!("WebSocket connection from {}", addr);

    ws.on_upgrade(move |socket| handle_socket(socket, state, addr))
}

/// Handle WebSocket connection
async fn handle_socket(socket: WebSocket, state: Arc<WebSocketState>, addr: SocketAddr) {
    let (mut tx, mut rx) = socket.split();

    // Send authentication required message
    let auth_required = WsMessage::AuthRequired {
        methods: vec!["bearer".to_string()],
        timeout: 10,
    };

    if let Ok(json) = serde_json::to_string(&auth_required) {
        let _ = tx.send(Message::Text(json)).await;
    }

    // Set authentication timeout
    let auth_timeout = tokio::time::sleep(tokio::time::Duration::from_secs(10));
    tokio::pin!(auth_timeout);

    let mut authenticated = false;
    let mut session: Option<SharedSession> = None;

    loop {
        tokio::select! {
            _ = &mut auth_timeout => {
                if !authenticated {
                    tracing::warn!("Authentication timeout for {}", addr);
                    let _ = tx.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code: 4001,
                        reason: std::borrow::Cow::from("Authentication timeout"),
                    }))).await;
                    break;
                }
            }

            msg = rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if !authenticated {
                            // Handle authentication
                            match handle_auth_message(&text, &state).await {
                                Ok(auth_session) => {
                                    let snapshot = auth_session.read().await.clone();
                                    authenticated = true;
                                    session = Some(auth_session.clone());

                                    let success = WsMessage::AuthSuccess {
                                        session_id: snapshot.id.clone(),
                                        user_id: snapshot.user_id.clone(),
                                        email: snapshot.email.clone(),
                                        vnc_display: snapshot.vnc_display,
                                        vnc_port: snapshot.vnc_port,
                                    };

                                    if let Ok(json) = serde_json::to_string(&success) {
                                        let _ = tx.send(Message::Text(json)).await;
                                    }

                                    tracing::info!("WebSocket authenticated: user={}", snapshot.user_id);
                                }
                                Err(e) => {
                                    let error = WsMessage::AuthError {
                                        error: e.to_string(),
                                    };

                                    if let Ok(json) = serde_json::to_string(&error) {
                                        let _ = tx.send(Message::Text(json)).await;
                                    }

                                    let _ = tx.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                        code: 4002,
                                        reason: std::borrow::Cow::from("Authentication failed"),
                                    }))).await;
                                    break;
                                }
                            }
                        } else {
                            // Handle VNC messages
                            if let Some(ref session) = session {
                                handle_vnc_message(&text, session, &mut tx).await;
                            }
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        if authenticated {
                            // Forward binary VNC data
                            if let Some(ref session) = session {
                                handle_vnc_binary(&data, session, &mut tx).await;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::info!("WebSocket closed by client: {}", addr);
                        break;
                    }
                    Some(Err(e)) => {
                        tracing::error!("WebSocket error: {}", e);
                        break;
                    }
                    None => break,
                    _ => {}
                }
            }
        }
    }

    // Clean up session
    if let Some(session) = session {
        let session_id = {
            let guard = session.read().await;
            guard.id.clone()
        };
        let _ = state.session_manager.terminate_session(&session_id).await;
    }
}

/// Handle authentication message
async fn handle_auth_message(message: &str, state: &WebSocketState) -> Result<SharedSession> {
    let msg: WsMessage = serde_json::from_str(message)
        .map_err(|e| OAuthError::WebSocket(format!("Invalid message: {}", e)))?;

    match msg {
        WsMessage::Auth { token, .. } => {
            // Validate JWT
            let validation_result = state.jwt_validator.validate(&token).await?;

            if !validation_result.valid {
                return Err(OAuthError::WebSocket(
                    validation_result
                        .error
                        .unwrap_or_else(|| "Token validation failed".to_string()),
                ));
            }

            let claims = validation_result
                .claims
                .ok_or_else(|| OAuthError::WebSocket("No claims in token".to_string()))?;

            // Check expiration
            let expiry = chrono::DateTime::from_timestamp(claims.exp, 0)
                .ok_or_else(|| OAuthError::WebSocket("Invalid expiration".to_string()))?;

            if expiry < Utc::now() {
                return Err(OAuthError::TokenExpired);
            }

            // Create session
            let scopes: Vec<String> = claims.scope.split_whitespace().map(String::from).collect();

            let session = state
                .session_manager
                .create_session(
                    claims.sub,
                    claims.email,
                    scopes,
                    expiry,
                    Some(token.clone()),
                    None,
                )
                .await?;

            Ok(session)
        }
        _ => Err(OAuthError::WebSocket(
            "First message must be authentication".to_string(),
        )),
    }
}

/// Handle VNC message
async fn handle_vnc_message(
    message: &str,
    session: &SharedSession,
    _tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) {
    {
        let mut guard = session.write().await;
        guard.last_activity = Utc::now();
        tracing::debug!("VNC message for session {}: {}", guard.id, message);
    }
}

/// Handle VNC binary data
async fn handle_vnc_binary(
    data: &[u8],
    session: &SharedSession,
    _tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) {
    // Forward to actual VNC server
    let guard = session.read().await;
    tracing::debug!(
        "VNC binary data for session {}: {} bytes",
        guard.id,
        data.len()
    );
}
