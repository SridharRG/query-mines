use axum::extract::State;
use axum::Json;
use qm_core::rules::{RuleEngine, RuleSet};
use serde::{Deserialize, Serialize};

use super::{ApiError, ApiResult};
use crate::state::SharedState;

#[derive(Serialize)]
pub struct RulesResponse {
    pub path: String,
    pub yaml: String,
    pub rules: RuleSet,
}

pub async fn get_rules(State(state): State<SharedState>) -> Json<RulesResponse> {
    let r = state.rules.read().await;
    Json(RulesResponse {
        path: r.path.display().to_string(),
        yaml: r.yaml.clone(),
        rules: r.engine.set.clone(),
    })
}

#[derive(Deserialize)]
pub struct RulesBody {
    pub yaml: String,
}

#[derive(Serialize)]
pub struct ValidateResponse {
    pub ok: bool,
    pub error: Option<String>,
    pub rules: Option<RuleSet>,
}

pub async fn validate_rules(Json(body): Json<RulesBody>) -> Json<ValidateResponse> {
    Json(match RuleEngine::from_yaml(&body.yaml) {
        Ok(e) => ValidateResponse {
            ok: true,
            error: None,
            rules: Some(e.set),
        },
        Err(e) => ValidateResponse {
            ok: false,
            error: Some(e.to_string()),
            rules: None,
        },
    })
}

/// Validate, persist to the rules file and hot-swap the engine.
pub async fn put_rules(State(state): State<SharedState>, Json(body): Json<RulesBody>) -> ApiResult<RulesResponse> {
    let engine = RuleEngine::from_yaml(&body.yaml)?;
    let mut r = state.rules.write().await;
    tokio::fs::write(&r.path, &body.yaml)
        .await
        .map_err(|e| ApiError::new(axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("saving rules: {e}")))?;
    tracing::info!(rules = engine.set.rules.len(), path = %r.path.display(), "rules reloaded");
    r.engine = engine;
    r.yaml = body.yaml;
    Ok(Json(RulesResponse {
        path: r.path.display().to_string(),
        yaml: r.yaml.clone(),
        rules: r.engine.set.clone(),
    }))
}
