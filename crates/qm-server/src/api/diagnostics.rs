use axum::extract::{Path, Query, State};
use axum::Json;
use qm_core::health::{index_health as compute_health, IndexHealth};
use qm_drivers::{
    ActivityRow, BlockingLock, ColumnMetadata, DatabaseOverview, Engine, IndexMetadata, SlowQueryLog, TableOverview,
    TableStats, TopQueryOrder, VacuumStat,
};
use serde::{Deserialize, Serialize};

use super::ApiResult;
use crate::state::{ConnSlot, SharedState};

#[derive(Serialize)]
pub struct Health {
    pub status: &'static str,
    pub version: &'static str,
    pub ai_enabled: bool,
    pub ai_model: Option<String>,
    pub connections: usize,
}

pub async fn health(State(state): State<SharedState>) -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        ai_enabled: state.ai.is_some(),
        ai_model: state.ai.as_ref().map(|a| a.config().model.clone()),
        connections: state.connections.read().await.len(),
    })
}

#[derive(Serialize, Clone)]
pub struct ConnectionSummary {
    pub id: String,
    pub name: String,
    pub engine: Engine,
    /// host:port/database, without credentials.
    pub target: String,
    pub docker_container: Option<String>,
    pub connected: bool,
    pub version: Option<String>,
    pub database: Option<String>,
    pub error: Option<String>,
    pub allow_analyze: bool,
}

fn redact(url: &str) -> String {
    match url.split_once("://") {
        Some((_, rest)) => rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest).split('?').next().unwrap_or("").into(),
        None => url
            .split_whitespace()
            .filter(|kv| !kv.starts_with("password"))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

pub fn summary(id: &str, s: &ConnSlot) -> ConnectionSummary {
    ConnectionSummary {
        id: id.to_string(),
        name: s.cfg.name.clone().unwrap_or_else(|| id.to_string()),
        engine: s.cfg.engine,
        target: redact(&s.cfg.url),
        docker_container: s.cfg.docker_container.clone(),
        connected: s.driver.is_some(),
        version: s.info.as_ref().map(|i| i.version.clone()),
        database: s.info.as_ref().map(|i| i.database.clone()),
        error: s.last_error.clone(),
        allow_analyze: s.cfg.allow_analyze,
    }
}

pub async fn connections(State(state): State<SharedState>) -> Json<Vec<ConnectionSummary>> {
    let conns = state.connections.read().await;
    let mut out: Vec<ConnectionSummary> = conns.iter().map(|(id, s)| summary(id, s)).collect();
    let order: Vec<&String> = state.cfg.connections.iter().map(|c| &c.id).collect();
    out.sort_by_key(|c| order.iter().position(|id| **id == c.id).unwrap_or(usize::MAX));
    Json(out)
}

pub async fn reconnect(State(state): State<SharedState>, Path(id): Path<String>) -> ApiResult<ConnectionSummary> {
    state.try_connect(&id).await;
    let conns = state.connections.read().await;
    let slot = conns
        .get(&id)
        .ok_or_else(|| super::ApiError::not_found(format!("unknown connection `{id}`")))?;
    Ok(Json(summary(&id, slot)))
}

#[derive(Serialize)]
pub struct OverviewResponse {
    pub overview: DatabaseOverview,
    pub top_tables: Vec<TableOverview>,
}

pub async fn overview(State(state): State<SharedState>, Path(id): Path<String>) -> ApiResult<OverviewResponse> {
    let d = state.driver(&id).await?;
    let (overview, tables) = tokio::join!(d.fetch_database_overview(), d.fetch_schema_overview());
    let mut top_tables = tables.unwrap_or_default();
    top_tables.truncate(8);
    Ok(Json(OverviewResponse {
        overview: overview?,
        top_tables,
    }))
}

#[derive(Deserialize)]
pub struct WindowQuery {
    /// Seconds of history to return.
    #[serde(default = "default_window")]
    pub window: i64,
}

fn default_window() -> i64 {
    900
}

#[derive(Serialize)]
pub struct SeriesPoint {
    pub ts: i64,
    pub qps: Option<f64>,
    pub mean_latency_ms: Option<f64>,
    pub tps: Option<f64>,
    pub cache_hit: Option<f64>,
    pub seq_scans_per_s: Option<f64>,
    pub idx_scans_per_s: Option<f64>,
    pub active: u64,
    pub idle: u64,
    pub idle_in_tx: u64,
    pub other: u64,
}

#[derive(Serialize)]
pub struct TimeseriesResponse {
    pub interval_secs: u64,
    pub points: Vec<SeriesPoint>,
}

fn rate(now: u64, prev: u64, dt: f64) -> Option<f64> {
    (now >= prev && dt > 0.0).then(|| (now - prev) as f64 / dt)
}

pub async fn timeseries(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<WindowQuery>,
) -> ApiResult<TimeseriesResponse> {
    let cutoff = chrono::Utc::now().timestamp_millis() - q.window.clamp(10, 86_400) * 1000;
    let t = state.telemetry.read().await;
    let samples: Vec<_> = t.get(&id).map(|b| b.iter().cloned().collect()).unwrap_or_default();
    let mut points = Vec::new();
    for w in samples.windows(2) {
        let (p, n) = (&w[0], &w[1]);
        if n.ts < cutoff {
            continue;
        }
        let dt = (n.ts - p.ts) as f64 / 1000.0;
        let dcalls = match (n.statement_calls, p.statement_calls) {
            (Some(a), Some(b)) if a >= b => Some(a - b),
            _ => None,
        };
        let dtime = match (n.statement_time_ms, p.statement_time_ms) {
            (Some(a), Some(b)) if a >= b => Some(a - b),
            _ => None,
        };
        let dhit = n.blks_hit.saturating_sub(p.blks_hit);
        let dread = n.blks_read.saturating_sub(p.blks_read);
        points.push(SeriesPoint {
            ts: n.ts,
            qps: dcalls.map(|c| c as f64 / dt.max(0.001)),
            mean_latency_ms: match (dcalls, dtime) {
                (Some(c), Some(t)) if c > 0 => Some(t / c as f64),
                (Some(_), Some(_)) => Some(0.0),
                _ => None,
            },
            tps: rate(n.xact_commit + n.xact_rollback, p.xact_commit + p.xact_rollback, dt),
            cache_hit: (dhit + dread > 0).then(|| dhit as f64 / (dhit + dread) as f64),
            seq_scans_per_s: rate(n.seq_scans, p.seq_scans, dt),
            idx_scans_per_s: rate(n.idx_scans, p.idx_scans, dt),
            active: n.connections_active,
            idle: n.connections_idle,
            idle_in_tx: n.connections_idle_in_tx,
            other: n.connections_other,
        });
    }
    Ok(Json(TimeseriesResponse {
        interval_secs: state.cfg.telemetry.interval_secs,
        points,
    }))
}

#[derive(Deserialize)]
pub struct TopQuery {
    #[serde(default = "default_top")]
    pub limit: usize,
    #[serde(default)]
    pub order: TopQueryOrder,
}

fn default_top() -> usize {
    10
}

pub async fn top_queries(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<TopQuery>,
) -> ApiResult<Vec<SlowQueryLog>> {
    let d = state.driver(&id).await?;
    Ok(Json(d.fetch_top_queries(q.limit.clamp(1, 100), q.order).await?))
}

pub async fn vacuum(State(state): State<SharedState>, Path(id): Path<String>) -> ApiResult<Vec<VacuumStat>> {
    let d = state.driver(&id).await?;
    Ok(Json(d.fetch_vacuum_stats().await?))
}

#[derive(Serialize)]
pub struct GroupCount {
    pub key: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct ActivityResponse {
    pub sessions: Vec<ActivityRow>,
    pub by_state: Vec<GroupCount>,
    pub by_user: Vec<GroupCount>,
    pub by_client: Vec<GroupCount>,
    pub idle_in_transaction: Vec<ActivityRow>,
    pub max_connections: Option<u64>,
}

fn group(rows: &[ActivityRow], key: impl Fn(&ActivityRow) -> String) -> Vec<GroupCount> {
    let mut m: std::collections::BTreeMap<String, usize> = Default::default();
    for r in rows {
        *m.entry(key(r)).or_default() += 1;
    }
    let mut v: Vec<GroupCount> = m.into_iter().map(|(key, count)| GroupCount { key, count }).collect();
    v.sort_by(|a, b| b.count.cmp(&a.count));
    v
}

pub async fn activity(State(state): State<SharedState>, Path(id): Path<String>) -> ApiResult<ActivityResponse> {
    let d = state.driver(&id).await?;
    let sessions = d.fetch_activity().await?;
    let max_connections = d.fetch_database_overview().await.ok().and_then(|o| o.max_connections);
    let idle_in_transaction = sessions
        .iter()
        .filter(|s| s.state.as_deref().map(|st| st.starts_with("idle in transaction")).unwrap_or(false))
        .cloned()
        .collect();
    Ok(Json(ActivityResponse {
        by_state: group(&sessions, |r| r.state.clone().unwrap_or_else(|| "unknown".into())),
        by_user: group(&sessions, |r| r.user.clone().unwrap_or_else(|| "?".into())),
        by_client: group(&sessions, |r| r.client.clone().unwrap_or_else(|| "?".into())),
        idle_in_transaction,
        sessions,
        max_connections,
    }))
}

pub async fn locks(State(state): State<SharedState>, Path(id): Path<String>) -> ApiResult<Vec<BlockingLock>> {
    let d = state.driver(&id).await?;
    Ok(Json(d.fetch_blocking_locks().await?))
}

pub async fn schema(State(state): State<SharedState>, Path(id): Path<String>) -> ApiResult<Vec<TableOverview>> {
    let d = state.driver(&id).await?;
    Ok(Json(d.fetch_schema_overview().await?))
}

#[derive(Serialize)]
pub struct TableDetail {
    pub table: String,
    pub stats: TableStats,
    pub columns: Vec<ColumnMetadata>,
    pub indexes: Vec<IndexMetadata>,
}

pub async fn table_detail(
    State(state): State<SharedState>,
    Path((id, table)): Path<(String, String)>,
) -> ApiResult<TableDetail> {
    let d = state.driver(&id).await?;
    let (stats, columns, indexes) =
        tokio::join!(d.fetch_table_stats(&table), d.fetch_table_columns(&table), d.fetch_table_indexes(&table));
    Ok(Json(TableDetail {
        table,
        stats: stats?,
        columns: columns?,
        indexes: indexes?,
    }))
}

pub async fn index_health(State(state): State<SharedState>, Path(id): Path<String>) -> ApiResult<IndexHealth> {
    let d = state.driver(&id).await?;
    let (usage, tables) = tokio::join!(d.fetch_index_usage(), d.fetch_schema_overview());
    Ok(Json(compute_health(&usage?, &tables.unwrap_or_default(), d.engine() == Engine::Mysql)))
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn redacts_credentials() {
        assert_eq!(redact("postgres://qm:secret@127.0.0.1:54329/schooldb"), "127.0.0.1:54329/schooldb");
        assert_eq!(redact("host=/tmp dbname=x password=y"), "host=/tmp dbname=x");
    }
}
