use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::state::SharedState;

mod analyze;
mod diagnostics;
mod rules;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/api/health", get(diagnostics::health))
        .route("/api/connections", get(diagnostics::connections))
        .route("/api/connections/{id}/reconnect", post(diagnostics::reconnect))
        .route("/api/connections/{id}/overview", get(diagnostics::overview))
        .route("/api/connections/{id}/timeseries", get(diagnostics::timeseries))
        .route("/api/connections/{id}/top-queries", get(diagnostics::top_queries))
        .route("/api/connections/{id}/vacuum", get(diagnostics::vacuum))
        .route("/api/connections/{id}/activity", get(diagnostics::activity))
        .route("/api/connections/{id}/locks", get(diagnostics::locks))
        .route("/api/connections/{id}/schema", get(diagnostics::schema))
        .route("/api/connections/{id}/tables/{table}", get(diagnostics::table_detail))
        .route("/api/connections/{id}/index-health", get(diagnostics::index_health))
        .route("/api/connections/{id}/workload-advisor", post(analyze::workload_advisor))
        .route("/api/analyze", post(analyze::analyze))
        .route("/api/ai/impact", post(analyze::ai_impact))
        .route("/api/ai/rewrite", post(analyze::ai_rewrite))
        .route("/api/rules", get(rules::get_rules).put(rules::put_rules))
        .route("/api/rules/validate", post(rules::validate_rules))
        .with_state(state)
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, m)
    }
    pub fn unavailable(m: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, m)
    }
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.message })).into_response()
    }
}

impl From<qm_drivers::DriverError> for ApiError {
    fn from(e: qm_drivers::DriverError) -> Self {
        use qm_drivers::DriverError::*;
        let status = match &e {
            Connection(_) => StatusCode::SERVICE_UNAVAILABLE,
            NotFound(_) => StatusCode::NOT_FOUND,
            Unsupported { .. } => StatusCode::NOT_IMPLEMENTED,
            Query(_) => StatusCode::UNPROCESSABLE_ENTITY,
        };
        Self::new(status, e.to_string())
    }
}

impl From<qm_core::CoreError> for ApiError {
    fn from(e: qm_core::CoreError) -> Self {
        Self::bad_request(e.to_string())
    }
}

impl From<qm_ai::AiError> for ApiError {
    fn from(e: qm_ai::AiError) -> Self {
        let status = match e {
            qm_ai::AiError::Disabled => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_GATEWAY,
        };
        Self::new(status, e.to_string())
    }
}

pub type ApiResult<T> = Result<Json<T>, ApiError>;
