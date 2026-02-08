mod config;
mod error;
mod auth;
mod api;

use std::sync::Arc;
use axum::{routing::{get, delete}, Router};
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use config::ControllerConfig;

/// Shared application state
#[derive(Clone)]
struct AppState {
    config: Arc<ControllerConfig>,
    db: sqlx::PgPool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    // Load configuration
    let config_path = std::env::var("CONTROLLER_CONFIG")
        .unwrap_or_else(|_| "/etc/kasmvnc/controller.toml".into());
    let config = ControllerConfig::from_file(&config_path)?;
    info!("Loaded config from {}", config_path);

    // Connect to PostgreSQL
    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;
    info!("Connected to database");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await?;
    info!("Database migrations complete");

    let state = AppState {
        config: Arc::new(config.clone()),
        db: pool.clone(),
    };

    // Build router with all API routes
    let app = Router::new()
        // Health checks
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get({
            let p = pool.clone();
            move || {
                let p = p.clone();
                async move {
                    match sqlx::query("SELECT 1").execute(&p).await {
                        Ok(_) => (axum::http::StatusCode::OK, "ready"),
                        Err(_) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready"),
                    }
                }
            }
        }))
        // Dashboard stats
        .route("/api/v1/stats", get(api::settings::dashboard_stats))
        // Sessions CRUD
        .route("/api/v1/sessions", get(api::sessions::list_sessions).post(api::sessions::create_session))
        .route("/api/v1/sessions/:id", get(api::sessions::get_session).delete(api::sessions::delete_session))
        // Policies CRUD
        .route("/api/v1/policies", get(api::policies::list_policies).post(api::policies::create_policy))
        .route("/api/v1/policies/:id", get(api::policies::get_policy).put(api::policies::update_policy).delete(api::policies::delete_policy))
        // Recordings
        .route("/api/v1/recordings", get(api::recordings::list_recordings))
        .route("/api/v1/recordings/:id", get(api::recordings::get_recording).delete(api::recordings::delete_recording))
        // Audit log
        .route("/api/v1/audit", get(api::audit::list_audit))
        // Workspace images
        .route("/api/v1/images", get(api::images::list_images).post(api::images::create_image))
        .route("/api/v1/images/:id", get(api::images::list_images).put(api::images::update_image).delete(api::images::delete_image))
        .route("/api/v1/images/:id/toggle", axum::routing::post(api::images::toggle_image))
        // User profiles
        .route("/api/v1/profiles", get(api::profiles::list_profiles).post(api::profiles::upsert_profile))
        .route("/api/v1/profiles/:user_id", get(api::profiles::get_profile).put(api::profiles::update_profile).delete(api::profiles::delete_profile))
        .route("/api/v1/profiles/:user_id/sync", axum::routing::post(api::profiles::sync_profile))
        // Settings
        .route("/api/v1/settings", get(api::settings::list_settings))
        .route("/api/v1/settings/:key", get(api::settings::get_setting).put(api::settings::update_setting))
        // Middleware
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(pool);

    // Start server
    let addr = format!("{}:{}", config.server.bind_address, config.server.port);
    info!("Session controller listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
