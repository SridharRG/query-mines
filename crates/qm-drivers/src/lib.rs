//! Database driver abstraction. Each engine implements [`DatabaseDriver`];
//! which driver backs a connection is decided purely by configuration.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use qm_core::model::*;

mod mysql;
mod postgres;

pub use mysql::MySqlDriver;
pub use postgres::PostgresDockerDriver;

#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("{0}")]
    Query(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("not supported by {engine}: {what}")]
    Unsupported { engine: &'static str, what: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub engine: Engine,
    /// `postgres://user:pass@host:port/db`, `host=/var/run/postgresql dbname=x`
    /// or `mysql://user:pass@host:port/db`. `${ENV}` references are expanded
    /// by the server's config loader.
    pub url: String,
    /// Docker container backing this connection (informational).
    #[serde(default)]
    pub docker_container: Option<String>,
    #[serde(default = "default_pool")]
    pub pool_size: usize,
    #[serde(default = "default_timeout")]
    pub statement_timeout_ms: u64,
    /// Allow EXPLAIN ANALYZE (executes the statement inside a rolled-back transaction).
    #[serde(default = "yes")]
    pub allow_analyze: bool,
    /// Hide the tool's own catalog queries from top-query listings.
    #[serde(default = "yes")]
    pub hide_internal_queries: bool,
}

fn default_pool() -> usize {
    4
}
fn default_timeout() -> u64 {
    15_000
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExplainOptions {
    /// Execute the statement (EXPLAIN ANALYZE) inside a transaction that is rolled back.
    pub analyze: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TopQueryOrder {
    #[default]
    TotalTime,
    MeanTime,
    Calls,
    Io,
    Rows,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypotheticalIndex {
    pub id: String,
    pub ddl: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypotheticalResult {
    pub id: String,
    pub cost_after: f64,
    pub used: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypotheticalReport {
    pub baseline_cost: f64,
    pub combined_cost: Option<f64>,
    pub combined_plan: Option<serde_json::Value>,
    pub indexes: Vec<HypotheticalResult>,
}

#[async_trait]
pub trait DatabaseDriver: Send + Sync {
    fn engine(&self) -> Engine;
    fn config(&self) -> &ConnectionConfig;

    async fn server_info(&self) -> Result<ServerInfo, DriverError>;
    async fn fetch_explain_plan(&self, query: &str, opts: &ExplainOptions) -> Result<serde_json::Value, DriverError>;
    async fn fetch_table_indexes(&self, table_name: &str) -> Result<Vec<IndexMetadata>, DriverError>;
    async fn fetch_table_stats(&self, table_name: &str) -> Result<TableStats, DriverError>;
    /// Estimated distinct values; 0 when the engine has no statistics for the column.
    async fn fetch_column_cardinality(&self, table_name: &str, column_name: &str) -> Result<u64, DriverError>;
    async fn fetch_table_columns(&self, table_name: &str) -> Result<Vec<ColumnMetadata>, DriverError>;
    async fn fetch_slow_queries(&self, limit: usize) -> Result<Vec<SlowQueryLog>, DriverError> {
        self.fetch_top_queries(limit, TopQueryOrder::TotalTime).await
    }
    async fn fetch_top_queries(&self, limit: usize, order: TopQueryOrder) -> Result<Vec<SlowQueryLog>, DriverError>;

    async fn fetch_database_overview(&self) -> Result<DatabaseOverview, DriverError>;
    async fn fetch_schema_overview(&self) -> Result<Vec<TableOverview>, DriverError>;
    async fn fetch_index_usage(&self) -> Result<Vec<IndexUsage>, DriverError>;
    async fn fetch_vacuum_stats(&self) -> Result<Vec<VacuumStat>, DriverError>;
    async fn fetch_activity(&self) -> Result<Vec<ActivityRow>, DriverError>;
    async fn fetch_blocking_locks(&self) -> Result<Vec<BlockingLock>, DriverError>;
    async fn sample_telemetry(&self) -> Result<TelemetrySample, DriverError>;

    /// What-if costing with hypothetical indexes (HypoPG). `Ok(None)` when unavailable.
    async fn hypothetical_costs(
        &self,
        _query: &str,
        _indexes: &[HypotheticalIndex],
    ) -> Result<Option<HypotheticalReport>, DriverError> {
        Ok(None)
    }
}

/// Build the driver configured for a connection.
pub async fn connect(cfg: &ConnectionConfig) -> Result<Arc<dyn DatabaseDriver>, DriverError> {
    Ok(match cfg.engine {
        Engine::Postgresql => Arc::new(PostgresDockerDriver::connect(cfg.clone()).await?),
        Engine::Mysql => Arc::new(MySqlDriver::connect(cfg.clone()).await?),
    })
}

/// Split `schema.table` (either part may be absent).
pub(crate) fn split_table(name: &str) -> (Option<&str>, &str) {
    match name.rsplit_once('.') {
        Some((s, t)) => (Some(s), t),
        None => (None, name),
    }
}

pub(crate) fn strip_statement(query: &str) -> String {
    query.trim().trim_end_matches(';').trim().to_string()
}
