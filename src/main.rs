use novnc_recorder::{
    config::read_config,
    oauth::{
        handlers::{create_router, AppState},
        jwt::JwtValidator,
        session::SessionManager,
    },
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // 1. Load configuration
    let config = match read_config() {
        Ok(cfg) => cfg,
        Err(e) => return Err(anyhow::anyhow!("Failed to read configuration: {e}")),
    };

    let oauth_config = config.oauth.clone().unwrap_or_default();

    if !oauth_config.enabled {
        log::error!("OAuth is not enabled in the configuration. The server will not start.");
        return Ok(());
    }

    // 2. Initialize components
    let jwt_validator = Arc::new(JwtValidator::new(oauth_config.clone()).await?);
    let session_manager = Arc::new(SessionManager::new(config.clone()));
    let pkce_store = Arc::new(RwLock::new(HashMap::new()));
    let http_client = reqwest::Client::new();

    let app_state = AppState {
        config: Arc::new(oauth_config),
        jwt_validator,
        session_manager,
        pkce_store,
        http_client,
    };

    // 3. Create and run the web server
    let app = create_router(app_state);
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    log::info!("Starting server, listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}