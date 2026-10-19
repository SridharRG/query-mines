use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use qm_ai::AiClient;
use qm_core::rules::RuleEngine;
use qm_drivers::{ConnectionConfig, DatabaseDriver, ServerInfo, TelemetrySample};
use tokio::sync::RwLock;

use crate::api::ApiError;
use crate::config::AppConfig;

pub struct ConnSlot {
    pub cfg: ConnectionConfig,
    pub driver: Option<Arc<dyn DatabaseDriver>>,
    pub info: Option<ServerInfo>,
    pub last_error: Option<String>,
    pub last_attempt: Option<Instant>,
}

pub struct Rules {
    pub engine: RuleEngine,
    pub yaml: String,
    pub path: PathBuf,
}

pub struct AppState {
    pub cfg: AppConfig,
    pub connections: RwLock<HashMap<String, ConnSlot>>,
    pub rules: RwLock<Rules>,
    pub ai: Option<AiClient>,
    pub telemetry: RwLock<HashMap<String, VecDeque<TelemetrySample>>>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub async fn driver(&self, id: &str) -> Result<Arc<dyn DatabaseDriver>, ApiError> {
        let conns = self.connections.read().await;
        let slot = conns
            .get(id)
            .ok_or_else(|| ApiError::not_found(format!("unknown connection `{id}`")))?;
        slot.driver.clone().ok_or_else(|| {
            ApiError::unavailable(format!(
                "connection `{id}` is not connected: {}",
                slot.last_error.clone().unwrap_or_else(|| "connecting…".into())
            ))
        })
    }

    /// Connect (or reconnect) a slot; errors are recorded on the slot.
    pub async fn try_connect(&self, id: &str) {
        let cfg = {
            let mut conns = self.connections.write().await;
            let Some(slot) = conns.get_mut(id) else { return };
            slot.last_attempt = Some(Instant::now());
            slot.cfg.clone()
        };
        let result = qm_drivers::connect(&cfg).await;
        let info = match &result {
            Ok(d) => d.server_info().await.ok(),
            Err(_) => None,
        };
        let mut conns = self.connections.write().await;
        if let Some(slot) = conns.get_mut(id) {
            match result {
                Ok(d) => {
                    tracing::info!(connection = id, version = ?info.as_ref().map(|i| &i.version), "connected");
                    slot.driver = Some(d);
                    slot.info = info;
                    slot.last_error = None;
                }
                Err(e) => {
                    tracing::warn!(connection = id, error = %e, "connection failed");
                    slot.last_error = Some(e.to_string());
                }
            }
        }
    }
}
