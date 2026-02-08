use axum::{extract::State, Json};
use sqlx::PgPool;

use crate::auth::AdminUser;
use crate::error::ApiError;

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct Setting {
    pub key: String,
    pub value: serde_json::Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateSettingRequest {
    pub value: serde_json::Value,
}

/// GET /api/v1/settings — list all settings
pub async fn list_settings(
    _admin: AdminUser,
    State(pool): State<PgPool>,
) -> Result<Json<Vec<Setting>>, ApiError> {
    let settings = sqlx::query_as::<_, Setting>(
        "SELECT * FROM settings ORDER BY key"
    )
    .fetch_all(&pool)
    .await?;
    Ok(Json(settings))
}

/// GET /api/v1/settings/:key
pub async fn get_setting(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(key): axum::extract::Path<String>,
) -> Result<Json<Setting>, ApiError> {
    let setting = sqlx::query_as::<_, Setting>(
        "SELECT * FROM settings WHERE key = $1"
    )
    .bind(&key)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Setting not found".into()))?;
    Ok(Json(setting))
}

/// PUT /api/v1/settings/:key — upsert setting
pub async fn update_setting(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Json(req): Json<UpdateSettingRequest>,
) -> Result<Json<Setting>, ApiError> {
    let setting = sqlx::query_as::<_, Setting>(
        "INSERT INTO settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
         RETURNING *"
    )
    .bind(&key)
    .bind(&req.value)
    .fetch_one(&pool)
    .await?;
    Ok(Json(setting))
}

/// GET /api/v1/stats — dashboard statistics
pub async fn dashboard_stats(
    _admin: AdminUser,
    State(pool): State<PgPool>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let active_sessions: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions WHERE status = 'active'"
    )
    .fetch_one(&pool)
    .await?;

    let total_users: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT user_id) FROM sessions"
    )
    .fetch_one(&pool)
    .await?;

    let total_recordings: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM recordings"
    )
    .fetch_one(&pool)
    .await?;

    let recent_events: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&pool)
    .await?;

    Ok(Json(serde_json::json!({
        "active_sessions": active_sessions.0,
        "total_users": total_users.0,
        "total_recordings": total_recordings.0,
        "recent_audit_events_24h": recent_events.0,
    })))
}
