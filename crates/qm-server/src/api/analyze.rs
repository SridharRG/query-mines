use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::Json;
use qm_ai::{AiAnswer, AiRewrite, QueryContext};
use qm_core::advisor::{fmt_count, IndexAction, IndexRecommendation, TableContext, TableContexts};
use qm_core::analysis::{self, AnalysisInput, AnalysisReport};
use qm_core::facts::{bare_name, SchemaCatalog};
use qm_drivers::{DatabaseDriver, Engine, ExplainOptions, HypotheticalIndex, HypotheticalReport};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ApiError, ApiResult};
use crate::api::diagnostics::{summary, ConnectionSummary};
use crate::state::SharedState;

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    pub sql: String,
    #[serde(default)]
    pub connection_id: Option<String>,
    /// Engine used when no connection is given.
    #[serde(default)]
    pub engine: Option<Engine>,
    /// Run EXPLAIN ANALYZE (inside a rolled-back transaction).
    #[serde(default = "yes")]
    pub analyze: bool,
    /// Cost recommendations with HypoPG when available.
    #[serde(default = "yes")]
    pub hypothetical: bool,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Default)]
pub struct Timings {
    pub metadata_ms: u64,
    pub explain_ms: u64,
    pub analysis_ms: u64,
    pub hypothetical_ms: u64,
    pub total_ms: u64,
}

#[derive(Serialize)]
pub struct AnalyzeResponse {
    pub report: AnalysisReport,
    pub connection: Option<ConnectionSummary>,
    pub tables: TableContexts,
    pub plan_json: Option<Value>,
    pub hypothetical: Option<HypotheticalReport>,
    pub ai_available: bool,
    pub timings: Timings,
}

pub struct Metadata {
    pub tables: TableContexts,
    pub catalog: SchemaCatalog,
    pub warnings: Vec<String>,
}

/// Columns, indexes and statistics for each referenced table.
pub async fn gather_metadata(
    driver: &Arc<dyn DatabaseDriver>,
    tables: &[String],
    cache: &mut HashMap<String, TableContext>,
) -> Metadata {
    let mut out = Metadata {
        tables: HashMap::new(),
        catalog: HashMap::new(),
        warnings: Vec::new(),
    };
    for t in tables {
        let ctx = match cache.get(t) {
            Some(c) => c.clone(),
            None => {
                let (cols, idx, stats) = tokio::join!(
                    driver.fetch_table_columns(t),
                    driver.fetch_table_indexes(t),
                    driver.fetch_table_stats(t)
                );
                let cols = match cols {
                    Ok(c) => c,
                    Err(e) => {
                        out.warnings.push(format!("{t}: {e}"));
                        continue;
                    }
                };
                let ctx = TableContext {
                    stats: stats.ok(),
                    indexes: idx.ok(),
                    columns: cols,
                };
                cache.insert(t.clone(), ctx.clone());
                ctx
            }
        };
        let names: Vec<String> = ctx.columns.iter().map(|c| c.name.to_lowercase()).collect();
        out.catalog.insert(t.clone(), names.clone());
        out.catalog.entry(bare_name(t).to_string()).or_insert(names);
        out.tables.insert(t.clone(), ctx);
    }
    out
}

fn explainable(kind: &str) -> bool {
    matches!(kind, "SELECT" | "UPDATE" | "DELETE" | "INSERT")
}

async fn hypothetical(
    driver: &Arc<dyn DatabaseDriver>,
    sql: &str,
    recs: &mut [IndexRecommendation],
) -> Option<HypotheticalReport> {
    let candidates: Vec<HypotheticalIndex> = recs
        .iter()
        .filter(|r| r.method == "btree" && !matches!(r.action, IndexAction::Covered { .. }))
        .filter_map(|r| {
            r.ddl.iter().find(|d| d.starts_with("CREATE INDEX")).map(|d| HypotheticalIndex {
                id: r.id.clone(),
                ddl: d.clone(),
            })
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    match driver.hypothetical_costs(sql, &candidates).await {
        Ok(Some(report)) => {
            for r in recs.iter_mut() {
                if let Some(h) = report.indexes.iter().find(|h| h.id == r.id) {
                    r.cost_before = Some(report.baseline_cost);
                    r.cost_after = Some(h.cost_after);
                    if !h.used && h.error.is_none() {
                        r.rationale.push(
                            "HypoPG: the planner did not pick this index for this query on its own; it may still help \
                             other queries or after the rewrite."
                                .into(),
                        );
                    }
                }
            }
            Some(report)
        }
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(error = %e, "hypothetical costing failed");
            None
        }
    }
}

pub async fn run_analysis(
    state: &SharedState,
    req: &AnalyzeRequest,
    cache: &mut HashMap<String, TableContext>,
) -> Result<AnalyzeResponse, ApiError> {
    let started = Instant::now();
    let mut timings = Timings::default();
    let sql = req.sql.trim();
    if sql.is_empty() {
        return Err(ApiError::bad_request("sql is empty"));
    }
    let driver = match &req.connection_id {
        Some(id) if !id.is_empty() => Some(state.driver(id).await?),
        _ => None,
    };
    let engine = driver.as_ref().map(|d| d.engine()).or(req.engine).unwrap_or_default();
    let prepared = analysis::prepare(sql, engine)?;

    let mut warnings = Vec::new();
    let (tables, catalog) = match &driver {
        Some(d) => {
            let t = Instant::now();
            let md = gather_metadata(d, &prepared.tables, cache).await;
            timings.metadata_ms = t.elapsed().as_millis() as u64;
            warnings.extend(md.warnings);
            (md.tables, Some(md.catalog))
        }
        None => (HashMap::new(), None),
    };

    let mut plan_json = None;
    if let Some(d) = &driver {
        if explainable(&prepared.statement_kind) {
            let t = Instant::now();
            match d.fetch_explain_plan(sql, &ExplainOptions { analyze: req.analyze }).await {
                Ok(p) => plan_json = Some(p),
                Err(e) => warnings.push(format!("EXPLAIN failed: {e}")),
            }
            timings.explain_ms = t.elapsed().as_millis() as u64;
        }
    }

    let server_version_num = match &driver {
        Some(d) => d.server_info().await.ok().map(|i| i.version_num),
        None => None,
    };
    let t = Instant::now();
    let mut report = {
        let rules = state.rules.read().await;
        analysis::analyze(AnalysisInput {
            sql,
            engine,
            catalog: catalog.as_ref(),
            tables: &tables,
            plan_json: plan_json.as_ref(),
            rules: &rules.engine,
            server_version_num,
            ai_cost_threshold: state.cfg.ai.cost_threshold,
        })?
    };
    timings.analysis_ms = t.elapsed().as_millis() as u64;
    report.warnings.extend(warnings);

    let mut hypo = None;
    if let (Some(d), true) = (&driver, req.hypothetical) {
        let t = Instant::now();
        let target = report.rewritten_sql.clone().filter(|_| report.advisor_source == "rewritten");
        hypo = hypothetical(d, target.as_deref().unwrap_or(sql), &mut report.recommendations).await;
        timings.hypothetical_ms = t.elapsed().as_millis() as u64;
    }

    let connection = match &req.connection_id {
        Some(id) if !id.is_empty() => {
            let conns = state.connections.read().await;
            conns.get(id).map(|s| summary(id, s))
        }
        _ => None,
    };
    timings.total_ms = started.elapsed().as_millis() as u64;
    Ok(AnalyzeResponse {
        report,
        connection,
        tables,
        plan_json,
        hypothetical: hypo,
        ai_available: state.ai.is_some(),
        timings,
    })
}

pub async fn analyze(State(state): State<SharedState>, Json(req): Json<AnalyzeRequest>) -> ApiResult<AnalyzeResponse> {
    let mut cache = HashMap::new();
    Ok(Json(run_analysis(&state, &req, &mut cache).await?))
}

// ---------------------------------------------------------------------------
// AI

#[derive(Deserialize)]
pub struct AiRequest {
    pub sql: String,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub engine: Option<Engine>,
    #[serde(default)]
    pub plan_json: Option<Value>,
    #[serde(default)]
    pub ddl: Vec<String>,
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub deterministic_rewrite: Option<String>,
}

fn describe_schema(tables: &TableContexts) -> Option<String> {
    if tables.is_empty() {
        return None;
    }
    let mut names: Vec<&String> = tables.keys().collect();
    names.sort();
    let mut out = String::new();
    for name in names {
        let t = &tables[name];
        let rows = t.stats.as_ref().map(|s| format!("~{} rows", fmt_count(s.total_rows))).unwrap_or_else(|| "rows unknown".into());
        let size = t
            .stats
            .as_ref()
            .map(|s| format!(", {:.1} MB heap", s.table_size_bytes as f64 / 1_048_576.0))
            .unwrap_or_default();
        out.push_str(&format!("- {name} ({rows}{size})\n  columns: "));
        out.push_str(
            &t.columns
                .iter()
                .map(|c| match c.distinct_values {
                    Some(d) => format!("{} {} [~{} distinct]", c.name, c.data_type, fmt_count(d)),
                    None => format!("{} {}", c.name, c.data_type),
                })
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push('\n');
        if let Some(idx) = &t.indexes {
            out.push_str("  indexes: ");
            out.push_str(
                &idx.iter()
                    .map(|i| {
                        format!(
                            "{} ({}){}{}",
                            i.name,
                            i.columns.join(", "),
                            if i.is_primary { " PK" } else if i.is_unique { " UNIQUE" } else { "" },
                            if i.method != "btree" && !i.method.is_empty() { format!(" {}", i.method) } else { String::new() }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; "),
            );
            out.push('\n');
        }
    }
    Some(out)
}

async fn ai_context(state: &SharedState, req: &AiRequest) -> Result<QueryContext, ApiError> {
    let driver = match &req.connection_id {
        Some(id) if !id.is_empty() => Some(state.driver(id).await?),
        _ => None,
    };
    let engine = driver.as_ref().map(|d| d.engine()).or(req.engine).unwrap_or_default();
    let schema = match &driver {
        Some(d) => {
            let prepared = analysis::prepare(&req.sql, engine)?;
            let md = gather_metadata(d, &prepared.tables, &mut HashMap::new()).await;
            describe_schema(&md.tables)
        }
        None => None,
    };
    Ok(QueryContext {
        engine,
        sql: req.sql.clone(),
        schema,
        explain_json: req.plan_json.clone(),
        recommended_ddl: req.ddl.clone(),
        findings: req.findings.clone(),
        deterministic_rewrite: req.deterministic_rewrite.clone(),
    })
}

pub async fn ai_impact(State(state): State<SharedState>, Json(req): Json<AiRequest>) -> ApiResult<AiAnswer> {
    let ai = state.ai.clone().ok_or(qm_ai::AiError::Disabled)?;
    let ctx = ai_context(&state, &req).await?;
    Ok(Json(ai.impact_summary(&ctx).await?))
}

pub async fn ai_rewrite(State(state): State<SharedState>, Json(req): Json<AiRequest>) -> ApiResult<AiRewrite> {
    let ai = state.ai.clone().ok_or(qm_ai::AiError::Disabled)?;
    let ctx = ai_context(&state, &req).await?;
    Ok(Json(ai.rewrite(&ctx).await?))
}

// ---------------------------------------------------------------------------
// Workload advisor: run the pipeline over the top statements.

#[derive(Deserialize)]
pub struct WorkloadRequest {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    15
}

#[derive(Serialize)]
pub struct WorkloadQuery {
    pub query_id: Option<String>,
    pub query: String,
    pub calls: u64,
    pub total_exec_time_ms: f64,
    pub mean_exec_time_ms: f64,
}

#[derive(Serialize)]
pub struct WorkloadRecommendation {
    pub recommendation: IndexRecommendation,
    pub queries: Vec<WorkloadQuery>,
    pub total_exec_time_ms: f64,
    pub calls: u64,
}

#[derive(Serialize)]
pub struct Skipped {
    pub query: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct WorkloadResponse {
    pub analyzed: usize,
    pub skipped: Vec<Skipped>,
    pub recommendations: Vec<WorkloadRecommendation>,
    pub covered: Vec<WorkloadRecommendation>,
    pub rule_hits: HashMap<String, usize>,
}

pub async fn workload_advisor(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(req): Json<WorkloadRequest>,
) -> ApiResult<WorkloadResponse> {
    let driver = state.driver(&id).await?;
    let top = driver.fetch_top_queries(req.limit.clamp(1, 50), Default::default()).await?;
    let mut cache = HashMap::new();
    let mut analyzed = 0;
    let mut skipped = Vec::new();
    let mut by_id: Vec<WorkloadRecommendation> = Vec::new();
    let mut rule_hits: HashMap<String, usize> = HashMap::new();
    for q in top {
        let request = AnalyzeRequest {
            sql: q.query.clone(),
            connection_id: Some(id.clone()),
            engine: None,
            analyze: false,
            hypothetical: false,
        };
        let resp = match run_analysis(&state, &request, &mut cache).await {
            Ok(r) => r,
            Err(e) => {
                skipped.push(Skipped {
                    query: q.query.clone(),
                    reason: e.message().to_string(),
                });
                continue;
            }
        };
        if !matches!(resp.report.statement_kind.as_str(), "SELECT" | "UPDATE" | "DELETE") {
            skipped.push(Skipped {
                query: q.query.clone(),
                reason: format!("{} statements are not index candidates", resp.report.statement_kind),
            });
            continue;
        }
        analyzed += 1;
        for h in &resp.report.rule_hits {
            *rule_hits.entry(h.rule_id.clone()).or_default() += 1;
        }
        for rec in resp.report.recommendations {
            let wq = WorkloadQuery {
                query_id: q.query_id.clone(),
                query: q.query.clone(),
                calls: q.calls,
                total_exec_time_ms: q.total_exec_time_ms,
                mean_exec_time_ms: q.mean_exec_time_ms,
            };
            match by_id.iter_mut().find(|w| w.recommendation.id == rec.id) {
                Some(w) => {
                    w.total_exec_time_ms += q.total_exec_time_ms;
                    w.calls += q.calls;
                    qm_core::advisor::merge_into(&mut w.recommendation, rec);
                    w.queries.push(wq);
                }
                None => by_id.push(WorkloadRecommendation {
                    total_exec_time_ms: q.total_exec_time_ms,
                    calls: q.calls,
                    recommendation: rec,
                    queries: vec![wq],
                }),
            }
        }
    }
    by_id.sort_by(|a, b| b.total_exec_time_ms.total_cmp(&a.total_exec_time_ms));
    let (covered, recommendations): (Vec<_>, Vec<_>) = by_id
        .into_iter()
        .partition(|w| matches!(w.recommendation.action, IndexAction::Covered { .. }));
    Ok(Json(WorkloadResponse {
        analyzed,
        skipped,
        recommendations,
        covered,
        rule_hits,
    }))
}
