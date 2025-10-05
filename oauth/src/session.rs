use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

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
    #[serde(skip_serializing, skip_deserializing)]
    pub access_token: Option<String>,
    #[serde(skip_serializing, skip_deserializing)]
    pub refresh_token: Option<String>,
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

pub type SharedSession = Arc<RwLock<Session>>;

/// Session Manager
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, SharedSession>>>,
    user_sessions: Arc<RwLock<HashMap<String, Vec<String>>>>,
    next_display: Arc<RwLock<i32>>,
    max_sessions_per_user: usize,
    allow_multiple_sessions: bool,
    absolute_timeout: Duration,
    idle_timeout: Duration,
}

impl SessionManager {
    /// Create new session manager
    pub fn new(
        max_sessions_per_user: usize,
        allow_multiple_sessions: bool,
        absolute_timeout_seconds: u64,
        idle_timeout_seconds: u64,
    ) -> Self {
        let absolute_timeout =
            Duration::seconds(absolute_timeout_seconds.min(i64::MAX as u64) as i64);
        let idle_timeout = Duration::seconds(idle_timeout_seconds.min(i64::MAX as u64) as i64);

        SessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            next_display: Arc::new(RwLock::new(1)),
            max_sessions_per_user,
            allow_multiple_sessions,
            absolute_timeout,
            idle_timeout,
        }
    }

    /// Create new session
    pub async fn create_session(
        &self,
        user_id: String,
        email: Option<String>,
        scopes: Vec<String>,
        token_expiry: DateTime<Utc>,
        access_token: Option<String>,
        refresh_token: Option<String>,
    ) -> Result<SharedSession> {
        if !self.allow_multiple_sessions {
            let existing_sessions = {
                let user_sessions = self.user_sessions.read().await;
                user_sessions.get(&user_id).cloned().unwrap_or_default()
            };

            for session_id in existing_sessions {
                self.terminate_session(&session_id).await?;
            }
        } else {
            let user_sessions = self.user_sessions.read().await;
            if let Some(sessions) = user_sessions.get(&user_id) {
                if sessions.len() >= self.max_sessions_per_user {
                    return Err(OAuthError::Config(format!(
                        "Maximum sessions ({}) reached for user",
                        self.max_sessions_per_user
                    )));
                }
            }
        }

        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let absolute_deadline = now + self.absolute_timeout;
        let effective_expiry = token_expiry.min(absolute_deadline);
        if effective_expiry <= now {
            return Err(OAuthError::TokenExpired);
        }

        let vnc_display = {
            let mut next = self.next_display.write().await;
            let display = *next;
            *next += 1;
            display
        };

        let vnc_port = 5900 + vnc_display as u16;

        let permissions = SessionPermissions {
            can_view: true,
            can_control: scopes.iter().any(|s| s.contains("control")),
            can_clipboard: scopes.iter().any(|s| s.contains("clipboard")),
            can_file_transfer: scopes.iter().any(|s| s.contains("files")),
        };

        let session = Arc::new(RwLock::new(Session {
            id: session_id.clone(),
            user_id: user_id.clone(),
            email,
            scopes,
            created_at: now,
            last_activity: now,
            token_expiry: effective_expiry,
            vnc_display: Some(vnc_display),
            vnc_port: Some(vnc_port),
            authenticated: true,
            permissions,
            access_token,
            refresh_token,
        }));

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session.clone());
        }

        {
            let mut user_sessions = self.user_sessions.write().await;
            user_sessions
                .entry(user_id)
                .or_insert_with(Vec::new)
                .push(session_id);
        }

        {
            let session_guard = session.read().await;
            self.start_vnc_server(&session_guard).await?;
        }

        Ok(session)
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<SharedSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Update session activity
    pub async fn update_activity(&self, session_id: &str) -> Result<()> {
        let session = {
            let sessions = self.sessions.read().await;
            sessions.get(session_id).cloned()
        }
        .ok_or_else(|| OAuthError::SessionNotFound(session_id.to_string()))?;

        let mut guard = session.write().await;
        guard.last_activity = Utc::now();
        Ok(())
    }

    /// Terminate session
    pub async fn terminate_session(&self, session_id: &str) -> Result<()> {
        let session = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id)
        };

        if let Some(session) = session {
            let user_id = {
                let session_guard = session.read().await;
                self.stop_vnc_server(&session_guard).await?;
                session_guard.user_id.clone()
            };

            let mut user_sessions = self.user_sessions.write().await;
            if let Some(sessions) = user_sessions.get_mut(&user_id) {
                sessions.retain(|id| id != session_id);
                if sessions.is_empty() {
                    user_sessions.remove(&user_id);
                }
            }
        }

        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        let sessions: Vec<(String, SharedSession)> = {
            let sessions_guard = self.sessions.read().await;
            sessions_guard
                .iter()
                .map(|(id, session)| (id.clone(), session.clone()))
                .collect()
        };

        for (id, session) in sessions {
            let should_terminate = {
                let guard = session.read().await;
                guard.token_expiry <= now
                    || now - guard.last_activity > self.idle_timeout
                    || guard.created_at + self.absolute_timeout <= now
            };

            if should_terminate {
                let _ = self.terminate_session(&id).await;
            }
        }
    }

    /// Start VNC server for session
    async fn start_vnc_server(&self, session: &Session) -> Result<()> {
        tracing::info!(
            "Starting VNC server for session {} on display :{}",
            session.id,
            session.vnc_display.unwrap_or(0)
        );

        Ok(())
    }

    /// Stop VNC server for session
    async fn stop_vnc_server(&self, session: &Session) -> Result<()> {
        tracing::info!(
            "Stopping VNC server for session {} on display :{}",
            session.id,
            session.vnc_display.unwrap_or(0)
        );

        Ok(())
    }
}
