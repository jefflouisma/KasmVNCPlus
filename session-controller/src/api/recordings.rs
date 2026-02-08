use axum::{extract::State, Json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::error::ApiError;

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct Recording {
    pub id: Uuid,
    pub session_id: Option<Uuid>,
    pub user_id: String,
    pub user_email: Option<String>,
    pub file_path: String,
    pub file_size_bytes: i64,
    pub duration_seconds: i32,
    pub format: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ListRecordingsQuery {
    pub user_id: Option<String>,
    pub session_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// GET /api/v1/recordings
pub async fn list_recordings(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Query(query): axum::extract::Query<ListRecordingsQuery>,
) -> Result<Json<Vec<Recording>>, ApiError> {
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);

    let recordings = match &query.user_id {
        Some(user_id) => {
            sqlx::query_as::<_, Recording>(
                "SELECT * FROM recordings WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
            )
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, Recording>(
                "SELECT * FROM recordings ORDER BY created_at DESC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&pool)
            .await?
        }
    };

    Ok(Json(recordings))
}

/// GET /api/v1/recordings/:id
pub async fn get_recording(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<Recording>, ApiError> {
    let recording = sqlx::query_as::<_, Recording>(
        "SELECT * FROM recordings WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Recording not found".into()))?;
    Ok(Json(recording))
}

/// DELETE /api/v1/recordings/:id
pub async fn delete_recording(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<axum::http::StatusCode, ApiError> {
    // Get recording to find file path
    let recording = sqlx::query_as::<_, Recording>(
        "SELECT * FROM recordings WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Recording not found".into()))?;

    // Delete file from disk
    if let Err(e) = tokio::fs::remove_file(&recording.file_path).await {
        tracing::warn!("Failed to delete recording file {}: {}", recording.file_path, e);
    }

    // Delete from database
    sqlx::query("DELETE FROM recordings WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}
