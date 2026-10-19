//! Query Mines server: REST API over the deterministic optimizer core, the
//! configured database drivers and the Groq-backed AI layer.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::http::{HeaderValue, Method};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

mod api;
mod collector;
mod config;
mod state;

use config::AppConfig;
use state::{AppState, ConnSlot, Rules};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn,tokio_postgres=warn".into()),
        )
        .init();

    let config_path: PathBuf = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("QM_CONFIG").ok())
        .unwrap_or_else(|| "config/query-mines.yaml".into())
        .into();
    let cfg = AppConfig::load(&config_path)?;

    let yaml = std::fs::read_to_string(&cfg.rules_path)
        .with_context(|| format!("reading rules file {}", cfg.rules_path.display()))?;
    let engine = qm_core::rules::RuleEngine::from_yaml(&yaml)?;
    tracing::info!(rules = engine.set.rules.len(), "rules loaded");

    let ai = qm_ai::AiClient::from_env(cfg.ai.clone());
    match &ai {
        Some(a) => tracing::info!(model = %a.config().model, "AI layer enabled (Groq)"),
        None => tracing::warn!("AI layer disabled (set GROQ_API_KEY to enable)"),
    }

    let connections = cfg
        .connections
        .iter()
        .map(|c| {
            (
                c.id.clone(),
                ConnSlot {
                    cfg: c.clone(),
                    driver: None,
                    info: None,
                    last_error: None,
                    last_attempt: None,
                },
            )
        })
        .collect::<HashMap<_, _>>();

    let state = Arc::new(AppState {
        rules: RwLock::new(Rules {
            engine,
            yaml,
            path: cfg.rules_path.clone(),
        }),
        connections: RwLock::new(connections),
        ai,
        telemetry: RwLock::new(HashMap::new()),
        cfg: cfg.clone(),
    });

    let ids: Vec<String> = cfg.connections.iter().map(|c| c.id.clone()).collect();
    futures_join_all(state.clone(), ids).await;
    collector::spawn(state.clone());

    let origins: Vec<HeaderValue> = cfg.server.cors_origins.iter().filter_map(|o| o.parse().ok()).collect();
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    let mut app = api::router(state.clone());
    if cfg.server.static_dir.join("index.html").exists() {
        let index = cfg.server.static_dir.join("index.html");
        app = app.fallback_service(ServeDir::new(&cfg.server.static_dir).not_found_service(ServeFile::new(index)));
        tracing::info!(dir = %cfg.server.static_dir.display(), "serving frontend");
    }
    let app = app.layer(cors).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&cfg.server.bind)
        .await
        .with_context(|| format!("binding {}", cfg.server.bind))?;
    tracing::info!("listening on http://{}", cfg.server.bind);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn futures_join_all(state: state::SharedState, ids: Vec<String>) {
    let mut set = tokio::task::JoinSet::new();
    for id in ids {
        let st = state.clone();
        set.spawn(async move { st.try_connect(&id).await });
    }
    while set.join_next().await.is_some() {}
}
