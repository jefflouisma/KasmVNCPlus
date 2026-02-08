use axum::{extract::State, Json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::error::ApiError;

// ─── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub url_allowlist: Vec<String>,
    pub url_blocklist: Vec<String>,
    pub clipboard_enabled: bool,
    pub downloads_enabled: bool,
    pub printing_enabled: bool,
    pub devtools_enabled: bool,
    pub session_timeout_minutes: i32,
    pub recording_enabled: bool,
    pub watermark_enabled: bool,
    pub assigned_groups: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub url_allowlist: Option<Vec<String>>,
    pub url_blocklist: Option<Vec<String>>,
    pub clipboard_enabled: Option<bool>,
    pub downloads_enabled: Option<bool>,
    pub printing_enabled: Option<bool>,
    pub devtools_enabled: Option<bool>,
    pub session_timeout_minutes: Option<i32>,
    pub recording_enabled: Option<bool>,
    pub watermark_enabled: Option<bool>,
    pub assigned_groups: Option<Vec<String>>,
}

// ─── Handlers ───────────────────────────────────────────────────────────────

/// GET /api/v1/policies — list all policies
pub async fn list_policies(
    _admin: AdminUser,
    State(pool): State<PgPool>,
) -> Result<Json<Vec<Policy>>, ApiError> {
    let policies = sqlx::query_as::<_, Policy>(
        "SELECT * FROM policies ORDER BY name"
    )
    .fetch_all(&pool)
    .await?;
    Ok(Json(policies))
}

/// GET /api/v1/policies/:id
pub async fn get_policy(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<Policy>, ApiError> {
    let policy = sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE id = $1")
        .bind(id)
        .fetch_optional(&pool)
        .await?
        .ok_or(ApiError::NotFound("Policy not found".into()))?;
    Ok(Json(policy))
}

/// POST /api/v1/policies — create policy
pub async fn create_policy(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(axum::http::StatusCode, Json<Policy>), ApiError> {
    let policy = sqlx::query_as::<_, Policy>(
        "INSERT INTO policies (name, url_allowlist, url_blocklist, clipboard_enabled, downloads_enabled, printing_enabled, devtools_enabled, session_timeout_minutes, recording_enabled, watermark_enabled, assigned_groups)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING *"
    )
    .bind(&req.name)
    .bind(req.url_allowlist.unwrap_or_default())
    .bind(req.url_blocklist.unwrap_or_default())
    .bind(req.clipboard_enabled.unwrap_or(false))
    .bind(req.downloads_enabled.unwrap_or(false))
    .bind(req.printing_enabled.unwrap_or(false))
    .bind(req.devtools_enabled.unwrap_or(false))
    .bind(req.session_timeout_minutes.unwrap_or(30))
    .bind(req.recording_enabled.unwrap_or(true))
    .bind(req.watermark_enabled.unwrap_or(true))
    .bind(req.assigned_groups.unwrap_or_default())
    .fetch_one(&pool)
    .await?;

    Ok((axum::http::StatusCode::CREATED, Json(policy)))
}

/// PUT /api/v1/policies/:id — update policy
pub async fn update_policy(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<Policy>, ApiError> {
    let policy = sqlx::query_as::<_, Policy>(
        "UPDATE policies SET name = $1, url_allowlist = $2, url_blocklist = $3, clipboard_enabled = $4, downloads_enabled = $5, printing_enabled = $6, devtools_enabled = $7, session_timeout_minutes = $8, recording_enabled = $9, watermark_enabled = $10, assigned_groups = $11, updated_at = NOW()
         WHERE id = $12 RETURNING *"
    )
    .bind(&req.name)
    .bind(req.url_allowlist.unwrap_or_default())
    .bind(req.url_blocklist.unwrap_or_default())
    .bind(req.clipboard_enabled.unwrap_or(false))
    .bind(req.downloads_enabled.unwrap_or(false))
    .bind(req.printing_enabled.unwrap_or(false))
    .bind(req.devtools_enabled.unwrap_or(false))
    .bind(req.session_timeout_minutes.unwrap_or(30))
    .bind(req.recording_enabled.unwrap_or(true))
    .bind(req.watermark_enabled.unwrap_or(true))
    .bind(req.assigned_groups.unwrap_or_default())
    .bind(id)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Policy not found".into()))?;

    Ok(Json(policy))
}

/// DELETE /api/v1/policies/:id
pub async fn delete_policy(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<axum::http::StatusCode, ApiError> {
    let result = sqlx::query("DELETE FROM policies WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("Policy not found".into()));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}
