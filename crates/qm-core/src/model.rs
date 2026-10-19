//! Types shared between the analysis core, the database drivers and the API.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    #[default]
    #[serde(alias = "postgres", alias = "pg")]
    Postgresql,
    #[serde(alias = "mariadb")]
    Mysql,
}

impl Engine {
    pub fn label(&self) -> &'static str {
        match self {
            Engine::Postgresql => "PostgreSQL",
            Engine::Mysql => "MySQL/MariaDB",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TableStats {
    pub total_rows: u64,
    pub table_size_bytes: u64,
    pub index_size_bytes: u64,
    #[serde(default)]
    pub seq_scan: Option<u64>,
    #[serde(default)]
    pub idx_scan: Option<u64>,
    #[serde(default)]
    pub dead_rows: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndexMetadata {
    pub name: String,
    pub columns: Vec<String>,
    pub is_unique: bool,
    #[serde(default)]
    pub is_primary: bool,
    #[serde(default)]
    pub include_columns: Vec<String>,
    /// btree, hash, gin, gist, brin, FULLTEXT ...
    #[serde(default)]
    pub method: String,
    /// Partial indexes and expression indexes can't be compared column-by-column.
    #[serde(default)]
    pub is_partial: bool,
    #[serde(default)]
    pub has_expressions: bool,
    #[serde(default)]
    pub definition: Option<String>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub scans: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ColumnMetadata {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    /// Estimated number of distinct values (already resolved from fractional
    /// statistics such as Postgres' negative `n_distinct`).
    #[serde(default)]
    pub distinct_values: Option<u64>,
    #[serde(default)]
    pub null_fraction: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SlowQueryLog {
    pub query_id: Option<String>,
    pub query: String,
    pub calls: u64,
    pub total_exec_time_ms: f64,
    pub mean_exec_time_ms: f64,
    pub max_exec_time_ms: Option<f64>,
    pub rows: u64,
    pub shared_blks_hit: u64,
    pub shared_blks_read: u64,
    /// Share of the database's total statement time (0..1).
    pub time_share: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VacuumStat {
    pub schema: String,
    pub table: String,
    pub live_rows: u64,
    pub dead_rows: u64,
    pub dead_pct: f64,
    pub last_vacuum: Option<String>,
    pub last_autovacuum: Option<String>,
    pub last_analyze: Option<String>,
    pub last_autoanalyze: Option<String>,
    pub table_size_bytes: u64,
    pub autovacuum_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActivityRow {
    pub pid: i64,
    pub user: Option<String>,
    pub database: Option<String>,
    pub client: Option<String>,
    pub application: Option<String>,
    pub state: Option<String>,
    pub wait_event: Option<String>,
    pub query: Option<String>,
    /// Seconds since the current query (or transaction for idle-in-tx) started.
    pub duration_s: Option<f64>,
    pub xact_duration_s: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockingLock {
    pub blocked_pid: i64,
    pub blocked_user: Option<String>,
    pub blocked_query: Option<String>,
    pub blocked_duration_s: Option<f64>,
    pub blocking_pid: i64,
    pub blocking_user: Option<String>,
    pub blocking_query: Option<String>,
    pub blocking_state: Option<String>,
    pub lock_type: Option<String>,
    pub relation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TableOverview {
    pub schema: String,
    pub name: String,
    pub rows: u64,
    pub table_size_bytes: u64,
    pub index_size_bytes: u64,
    pub total_size_bytes: u64,
    pub seq_scan: u64,
    pub seq_tup_read: u64,
    pub idx_scan: u64,
    pub dead_rows: u64,
    pub index_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndexUsage {
    pub schema: String,
    pub table: String,
    pub index: String,
    pub columns: Vec<String>,
    pub definition: Option<String>,
    pub scans: u64,
    pub size_bytes: u64,
    pub is_unique: bool,
    pub is_primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DatabaseOverview {
    pub engine: Engine,
    pub server_version: String,
    pub database: String,
    pub database_size_bytes: u64,
    pub table_count: u64,
    pub index_count: u64,
    pub total_statement_calls: Option<u64>,
    pub total_statement_time_ms: Option<f64>,
    pub cache_hit_ratio: Option<f64>,
    pub connections_total: u64,
    pub connections_active: u64,
    pub max_connections: Option<u64>,
    pub seq_scans: u64,
    pub idx_scans: u64,
    pub dead_rows: u64,
    pub xact_commit: Option<u64>,
    pub xact_rollback: Option<u64>,
    pub deadlocks: Option<u64>,
    pub uptime_s: Option<f64>,
    pub stats_extension: bool,
    pub hypothetical_indexes: bool,
}

/// One point of the background telemetry sampler.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetrySample {
    pub ts: i64,
    pub statement_calls: Option<u64>,
    pub statement_time_ms: Option<f64>,
    pub connections_active: u64,
    pub connections_idle: u64,
    pub connections_idle_in_tx: u64,
    pub connections_other: u64,
    pub seq_scans: u64,
    pub idx_scans: u64,
    pub blks_hit: u64,
    pub blks_read: u64,
    pub xact_commit: u64,
    pub xact_rollback: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerInfo {
    pub engine: Engine,
    pub version: String,
    pub version_num: u32,
    pub database: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    #[serde(alias = "info", alias = "LOW", alias = "low")]
    #[default]
    Info,
    #[serde(alias = "warning", alias = "MEDIUM", alias = "medium")]
    Warning,
    #[serde(alias = "high")]
    High,
    #[serde(alias = "critical")]
    Critical,
}

impl Severity {
    pub fn penalty(self) -> u32 {
        match self {
            Severity::Critical => 25,
            Severity::High => 15,
            Severity::Warning => 8,
            Severity::Info => 2,
        }
    }
}
