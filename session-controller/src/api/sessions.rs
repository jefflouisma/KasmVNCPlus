use axum::{extract::State, Json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::error::ApiError;

// ─── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: String,
    pub user_email: Option<String>,
    pub user_name: Option<String>,
    pub pod_name: Option<String>,
    pub node_name: Option<String>,
    pub image: String,
    pub status: String,
    pub policy_id: Option<Uuid>,
    pub recording_path: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub idle_since: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateSessionRequest {
    pub user_id: String,
    pub user_email: Option<String>,
    pub user_name: Option<String>,
    pub image: Option<String>,
    pub policy_id: Option<Uuid>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ListSessionsQuery {
    pub status: Option<String>,
    pub user_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ─── Handlers ───────────────────────────────────────────────────────────────

/// GET /api/v1/sessions — list all sessions (filterable)
pub async fn list_sessions(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Query(query): axum::extract::Query<ListSessionsQuery>,
) -> Result<Json<Vec<Session>>, ApiError> {
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);

    let sessions = match (&query.status, &query.user_id) {
        (Some(status), Some(user_id)) => {
            sqlx::query_as::<_, Session>(
                "SELECT * FROM sessions WHERE status = $1 AND user_id = $2 ORDER BY started_at DESC LIMIT $3 OFFSET $4"
            )
            .bind(status)
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&pool)
            .await?
        }
        (Some(status), None) => {
            sqlx::query_as::<_, Session>(
                "SELECT * FROM sessions WHERE status = $1 ORDER BY started_at DESC LIMIT $2 OFFSET $3"
            )
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(&pool)
            .await?
        }
        (None, Some(user_id)) => {
            sqlx::query_as::<_, Session>(
                "SELECT * FROM sessions WHERE user_id = $1 ORDER BY started_at DESC LIMIT $2 OFFSET $3"
            )
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&pool)
            .await?
        }
        (None, None) => {
            sqlx::query_as::<_, Session>(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&pool)
            .await?
        }
    };

    Ok(Json(sessions))
}

/// GET /api/v1/sessions/:id — get session details
pub async fn get_session(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<Session>, ApiError> {
    let session = sqlx::query_as::<_, Session>(
        "SELECT * FROM sessions WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Session not found".into()))?;

    Ok(Json(session))
}

/// POST /api/v1/sessions — create new session (spawns K8s pod)
pub async fn create_session(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<(axum::http::StatusCode, Json<Session>), ApiError> {
    let image = req.image.unwrap_or_else(|| "kasmvncplus:hardened".into());

    let session = sqlx::query_as::<_, Session>(
        "INSERT INTO sessions (user_id, user_email, user_name, image, policy_id, status)
         VALUES ($1, $2, $3, $4, $5, 'pending')
         RETURNING *"
    )
    .bind(&req.user_id)
    .bind(&req.user_email)
    .bind(&req.user_name)
    .bind(&image)
    .bind(&req.policy_id)
    .fetch_one(&pool)
    .await?;

    // TODO: Spawn K8s pod for this session (Phase 5 integration)
    tracing::info!("Session created: id={}, user={}", session.id, session.user_id);

    Ok((axum::http::StatusCode::CREATED, Json(session)))
}

/// DELETE /api/v1/sessions/:id — terminate session
pub async fn delete_session(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<axum::http::StatusCode, ApiError> {
    let result = sqlx::query(
        "UPDATE sessions SET status = 'terminated', ended_at = NOW() WHERE id = $1 AND status != 'terminated'"
    )
    .bind(id)
    .execute(&pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("Session not found or already terminated".into()));
    }

    // TODO: Delete K8s pod for this session
    tracing::info!("Session terminated: id={}", id);

    Ok(axum::http::StatusCode::NO_CONTENT)
}
