use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use crate::error::{OAuthError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub email: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub token_expiry: DateTime<Utc>,
    pub vnc_display: Option<i32>,
    pub vnc_port: Option<u16>,
    pub authenticated: bool,
    pub permissions: SessionPermissions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPermissions {
    pub can_view: bool,
    pub can_control: bool,
    pub can_clipboard: bool,
    pub can_file_transfer: bool,
}

impl Default for SessionPermissions {
    fn default() -> Self {
        SessionPermissions {
            can_view: true,
            can_control: true,
            can_clipboard: true,
            can_file_transfer: false,
        }
    }
}

/// Session Manager
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<Session>>>>,
    user_sessions: Arc<RwLock<HashMap<String, Vec<String>>>>,
    next_display: Arc<RwLock<i32>>,
    max_sessions_per_user: usize,
}

impl SessionManager {
    /// Create new session manager
    pub fn new(max_sessions_per_user: usize) -> Self {
        SessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            next_display: Arc::new(RwLock::new(1)),
            max_sessions_per_user,
        }
    }

    /// Create new session
    pub async fn create_session(
        &self,
        user_id: String,
        email: Option<String>,
        scopes: Vec<String>,
        token_expiry: DateTime<Utc>,
    ) -> Result<Arc<Session>> {
        // Check max sessions per user
        {
            let user_sessions = self.user_sessions.read().await;
            if let Some(sessions) = user_sessions.get(&user_id) {
                if sessions.len() >= self.max_sessions_per_user {
                    return Err(OAuthError::Config(
                        format!("Maximum sessions ({}) reached for user", self.max_sessions_per_user)
                    ));
                }
            }
        }

        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Allocate VNC display
        let vnc_display = {
            let mut next = self.next_display.write().await;
            let display = *next;
            *next += 1;
            display
        };

        let vnc_port = 5900 + vnc_display as u16;

        // Parse permissions from scopes
        let permissions = SessionPermissions {
            can_view: true,
            can_control: scopes.iter().any(|s| s.contains("control")),
            can_clipboard: scopes.iter().any(|s| s.contains("clipboard")),
            can_file_transfer: scopes.iter().any(|s| s.contains("files")),
        };

        let session = Arc::new(Session {
            id: session_id.clone(),
            user_id: user_id.clone(),
            email,
            scopes,
            created_at: now,
            last_activity: now,
            token_expiry,
            vnc_display: Some(vnc_display),
            vnc_port: Some(vnc_port),
            authenticated: true,
            permissions,
        });

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session.clone());
        }

        // Track user session
        {
            let mut user_sessions = self.user_sessions.write().await;
            user_sessions.entry(user_id).or_insert_with(Vec::new).push(session_id);
        }

        // Start VNC server (in production, actually spawn process)
        self.start_vnc_server(&session).await?;

        Ok(session)
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<Arc<Session>> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Update session activity
    pub async fn update_activity(&self, session_id: &str) {
        let sessions = self.sessions.read().await;
        if let Some(_session) = sessions.get(session_id) {
            // In production, update mutable field
            // For now, we're using Arc so this is immutable
            // You'd need Arc<RwLock<Session>> for mutable sessions
        }
    }

    /// Terminate session
    pub async fn terminate_session(&self, session_id: &str) -> Result<()> {
        let session = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id)
        };

        if let Some(session) = session {
            // Stop VNC server
            self.stop_vnc_server(&session).await?;

            // Remove from user sessions
            let mut user_sessions = self.user_sessions.write().await;
            if let Some(sessions) = user_sessions.get_mut(&session.user_id) {
                sessions.retain(|id| id != session_id);
                if sessions.is_empty() {
                    user_sessions.remove(&session.user_id);
                }
            }
        }

        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        let mut to_remove = Vec::new();

        {
            let sessions = self.sessions.read().await;
            for (id, session) in sessions.iter() {
                if session.token_expiry < now {
                    to_remove.push(id.clone());
                }
            }
        }

        for id in to_remove {
            let _ = self.terminate_session(&id).await;
        }
    }

    /// Start VNC server for session
    async fn start_vnc_server(&self, session: &Session) -> Result<()> {
        // In production, spawn actual Xvnc process
        // For now, just log
        tracing::info!(
            "Starting VNC server for session {} on display :{}",
            session.id, session.vnc_display.unwrap_or(0)
        );

        // Example command that would be executed:
        // Xvnc :{display} -geometry 1920x1080 -depth 24 -rfbport {port}

        Ok(())
    }

    /// Stop VNC server for session
    async fn stop_vnc_server(&self, session: &Session) -> Result<()> {
        tracing::info!(
            "Stopping VNC server for session {} on display :{}",
            session.id, session.vnc_display.unwrap_or(0)
        );

        // In production, kill Xvnc process

        Ok(())
    }
}