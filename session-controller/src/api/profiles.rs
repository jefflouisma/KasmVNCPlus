use axum::{extract::State, Json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::error::ApiError;

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct UserProfile {
    pub id: Uuid,
    pub user_id: String,
    pub user_email: Option<String>,
    pub user_name: Option<String>,
    pub profile_storage_path: Option<String>,
    pub profile_size_bytes: i64,
    pub preferences: serde_json::Value,
    pub default_policy_id: Option<Uuid>,
    pub total_sessions: i32,
    pub total_session_minutes: i32,
    pub last_session_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateProfileRequest {
    pub user_id: String,
    pub user_email: Option<String>,
    pub user_name: Option<String>,
    pub preferences: Option<serde_json::Value>,
    pub default_policy_id: Option<Uuid>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateProfileRequest {
    pub user_email: Option<String>,
    pub user_name: Option<String>,
    pub preferences: Option<serde_json::Value>,
    pub default_policy_id: Option<Uuid>,
    pub profile_storage_path: Option<String>,
}

/// GET /api/v1/profiles — List all user profiles
pub async fn list_profiles(
    _admin: AdminUser,
    State(pool): State<PgPool>,
) -> Result<Json<Vec<UserProfile>>, ApiError> {
    let profiles = sqlx::query_as::<_, UserProfile>(
        "SELECT * FROM user_profiles ORDER BY last_session_at DESC NULLS LAST"
    )
    .fetch_all(&pool)
    .await?;
    Ok(Json(profiles))
}

/// GET /api/v1/profiles/:user_id — Get profile by user_id (SSO subject)
pub async fn get_profile(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<UserProfile>, ApiError> {
    let profile = sqlx::query_as::<_, UserProfile>(
        "SELECT * FROM user_profiles WHERE user_id = $1"
    )
    .bind(&user_id)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Profile not found".into()))?;
    Ok(Json(profile))
}

/// POST /api/v1/profiles — Create or upsert a profile (called on session start)
pub async fn upsert_profile(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    Json(req): Json<CreateProfileRequest>,
) -> Result<(axum::http::StatusCode, Json<UserProfile>), ApiError> {
    let profile = sqlx::query_as::<_, UserProfile>(
        "INSERT INTO user_profiles (user_id, user_email, user_name, preferences, default_policy_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id) DO UPDATE SET
             user_email = COALESCE(EXCLUDED.user_email, user_profiles.user_email),
             user_name = COALESCE(EXCLUDED.user_name, user_profiles.user_name),
             total_sessions = user_profiles.total_sessions + 1,
             last_session_at = NOW(),
             updated_at = NOW()
         RETURNING *"
    )
    .bind(&req.user_id)
    .bind(&req.user_email)
    .bind(&req.user_name)
    .bind(req.preferences.unwrap_or(serde_json::json!({})))
    .bind(&req.default_policy_id)
    .fetch_one(&pool)
    .await?;

    Ok((axum::http::StatusCode::OK, Json(profile)))
}

/// PUT /api/v1/profiles/:user_id — Update a profile
pub async fn update_profile(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<UserProfile>, ApiError> {
    let profile = sqlx::query_as::<_, UserProfile>(
        "UPDATE user_profiles SET
            user_email = COALESCE($2, user_email),
            user_name = COALESCE($3, user_name),
            preferences = COALESCE($4, preferences),
            default_policy_id = COALESCE($5, default_policy_id),
            profile_storage_path = COALESCE($6, profile_storage_path),
            updated_at = NOW()
         WHERE user_id = $1
         RETURNING *"
    )
    .bind(&user_id)
    .bind(&req.user_email)
    .bind(&req.user_name)
    .bind(&req.preferences)
    .bind(&req.default_policy_id)
    .bind(&req.profile_storage_path)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Profile not found".into()))?;

    Ok(Json(profile))
}

/// DELETE /api/v1/profiles/:user_id — Delete a profile (and queue storage cleanup)
pub async fn delete_profile(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    let result = sqlx::query("DELETE FROM user_profiles WHERE user_id = $1")
        .bind(&user_id)
        .execute(&pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("Profile not found".into()));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// POST /api/v1/profiles/:user_id/sync — Record profile sync (after session ends, saves size)
pub async fn sync_profile(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(req): Json<SyncProfileRequest>,
) -> Result<Json<UserProfile>, ApiError> {
    let profile = sqlx::query_as::<_, UserProfile>(
        "UPDATE user_profiles SET
            profile_storage_path = $2,
            profile_size_bytes = $3,
            total_session_minutes = total_session_minutes + $4,
            updated_at = NOW()
         WHERE user_id = $1
         RETURNING *"
    )
    .bind(&user_id)
    .bind(&req.storage_path)
    .bind(req.size_bytes)
    .bind(req.session_minutes)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Profile not found".into()))?;

    Ok(Json(profile))
}

#[derive(Debug, serde::Deserialize)]
pub struct SyncProfileRequest {
    pub storage_path: String,
    pub size_bytes: i64,
    pub session_minutes: i32,
}
