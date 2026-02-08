use axum::{extract::State, Json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::error::ApiError;

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct WorkspaceImage {
    pub id: Uuid,
    pub name: String,
    pub image: String,
    pub description: String,
    pub thumbnail_url: Option<String>,
    pub enabled: bool,
    pub cpu_limit: String,
    pub memory_limit: String,
    pub categories: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateImageRequest {
    pub name: String,
    pub image: String,
    pub description: Option<String>,
    pub thumbnail_url: Option<String>,
    pub cpu_limit: Option<String>,
    pub memory_limit: Option<String>,
    pub categories: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateImageRequest {
    pub name: Option<String>,
    pub image: Option<String>,
    pub description: Option<String>,
    pub thumbnail_url: Option<String>,
    pub cpu_limit: Option<String>,
    pub memory_limit: Option<String>,
    pub categories: Option<Vec<String>>,
}

/// GET /api/v1/images
pub async fn list_images(
    _admin: AdminUser,
    State(pool): State<PgPool>,
) -> Result<Json<Vec<WorkspaceImage>>, ApiError> {
    let images = sqlx::query_as::<_, WorkspaceImage>(
        "SELECT * FROM workspace_images ORDER BY name"
    )
    .fetch_all(&pool)
    .await?;
    Ok(Json(images))
}

/// POST /api/v1/images
pub async fn create_image(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    Json(req): Json<CreateImageRequest>,
) -> Result<(axum::http::StatusCode, Json<WorkspaceImage>), ApiError> {
    let image = sqlx::query_as::<_, WorkspaceImage>(
        "INSERT INTO workspace_images (name, image, description, thumbnail_url, cpu_limit, memory_limit, categories)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *"
    )
    .bind(&req.name)
    .bind(&req.image)
    .bind(req.description.unwrap_or_default())
    .bind(&req.thumbnail_url)
    .bind(req.cpu_limit.unwrap_or_else(|| "1000m".into()))
    .bind(req.memory_limit.unwrap_or_else(|| "1Gi".into()))
    .bind(req.categories.unwrap_or_default())
    .fetch_one(&pool)
    .await?;

    Ok((axum::http::StatusCode::CREATED, Json(image)))
}

/// PUT /api/v1/images/:id — Update image metadata
pub async fn update_image(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    Json(req): Json<UpdateImageRequest>,
) -> Result<Json<WorkspaceImage>, ApiError> {
    let image = sqlx::query_as::<_, WorkspaceImage>(
        "UPDATE workspace_images SET
            name = COALESCE($2, name),
            image = COALESCE($3, image),
            description = COALESCE($4, description),
            thumbnail_url = COALESCE($5, thumbnail_url),
            cpu_limit = COALESCE($6, cpu_limit),
            memory_limit = COALESCE($7, memory_limit),
            categories = COALESCE($8, categories)
         WHERE id = $1
         RETURNING *"
    )
    .bind(id)
    .bind(&req.name)
    .bind(&req.image)
    .bind(&req.description)
    .bind(&req.thumbnail_url)
    .bind(&req.cpu_limit)
    .bind(&req.memory_limit)
    .bind(&req.categories)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Image not found".into()))?;

    Ok(Json(image))
}

/// POST /api/v1/images/:id/toggle — Enable/disable an image
pub async fn toggle_image(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<WorkspaceImage>, ApiError> {
    let image = sqlx::query_as::<_, WorkspaceImage>(
        "UPDATE workspace_images SET enabled = NOT enabled WHERE id = $1 RETURNING *"
    )
    .bind(id)
    .fetch_optional(&pool)
    .await?
    .ok_or(ApiError::NotFound("Image not found".into()))?;

    Ok(Json(image))
}

/// DELETE /api/v1/images/:id
pub async fn delete_image(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<axum::http::StatusCode, ApiError> {
    let result = sqlx::query("DELETE FROM workspace_images WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("Image not found".into()));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}
