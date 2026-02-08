use axum::{extract::State, Json};
use sqlx::PgPool;

use crate::auth::AdminUser;
use crate::error::ApiError;

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: i64,
    pub event_type: String,
    pub actor_id: Option<String>,
    pub actor_email: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Deserialize)]
pub struct AuditQuery {
    pub event_type: Option<String>,
    pub actor_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// GET /api/v1/audit — list audit log entries
pub async fn list_audit(
    _admin: AdminUser,
    State(pool): State<PgPool>,
    axum::extract::Query(query): axum::extract::Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    let limit = query.limit.unwrap_or(100).min(500);
    let offset = query.offset.unwrap_or(0);

    let entries = match &query.event_type {
        Some(event_type) => {
            sqlx::query_as::<_, AuditEntry>(
                "SELECT id, event_type, actor_id, actor_email, target_type, target_id, details, ip_address::TEXT, created_at FROM audit_log WHERE event_type = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
            )
            .bind(event_type)
            .bind(limit)
            .bind(offset)
            .fetch_all(&pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, AuditEntry>(
                "SELECT id, event_type, actor_id, actor_email, target_type, target_id, details, ip_address::TEXT, created_at FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&pool)
            .await?
        }
    };

    Ok(Json(entries))
}

/// Helper: write audit log entry programmatically
pub async fn write_audit_entry(
    pool: &PgPool,
    event_type: &str,
    actor_id: Option<&str>,
    actor_email: Option<&str>,
    target_type: Option<&str>,
    target_id: Option<&str>,
    details: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (event_type, actor_id, actor_email, target_type, target_id, details) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(event_type)
    .bind(actor_id)
    .bind(actor_email)
    .bind(target_type)
    .bind(target_id)
    .bind(details)
    .execute(pool)
    .await?;
    Ok(())
}
