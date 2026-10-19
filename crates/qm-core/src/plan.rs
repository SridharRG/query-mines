//! EXPLAIN JSON → normalized plan tree + findings.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

use crate::model::{Engine, Severity};

#[derive(Debug, Clone, Serialize, Default)]
pub struct PlanNode {
    pub id: usize,
    pub node_type: String,
    pub relation: Option<String>,
    pub alias: Option<String>,
    pub index_name: Option<String>,
    pub join_type: Option<String>,
    pub startup_cost: Option<f64>,
    pub total_cost: Option<f64>,
    pub plan_rows: Option<f64>,
    pub actual_rows: Option<f64>,
    pub actual_loops: Option<f64>,
    pub actual_total_ms: Option<f64>,
    /// Time spent in this node alone (inclusive time minus children), all loops.
    pub self_ms: Option<f64>,
    pub filter: Option<String>,
    pub index_cond: Option<String>,
    pub rows_removed_by_filter: Option<f64>,
    pub shared_hit_blocks: Option<f64>,
    pub shared_read_blocks: Option<f64>,
    pub temp_written_blocks: Option<f64>,
    pub sort_key: Option<String>,
    pub sort_method: Option<String>,
    pub sort_space_type: Option<String>,
    pub hash_batches: Option<f64>,
    pub flags: Vec<String>,
    pub children: Vec<PlanNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanFinding {
    pub code: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub relation: Option<String>,
    pub node_id: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PlanSummary {
    pub analyzed: bool,
    pub total_cost: Option<f64>,
    pub plan_rows: Option<f64>,
    pub actual_rows: Option<f64>,
    pub planning_ms: Option<f64>,
    pub execution_ms: Option<f64>,
    pub node_count: usize,
    pub seq_scans: Vec<String>,
    pub index_scans: Vec<String>,
    pub shared_hit_blocks: f64,
    pub shared_read_blocks: f64,
    pub hotspot_node: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PlanAnalysis {
    pub engine: Engine,
    pub root: Option<PlanNode>,
    pub summary: PlanSummary,
    pub findings: Vec<PlanFinding>,
}

impl PlanAnalysis {
    pub fn has_disk_sort(&self) -> bool {
        self.findings.iter().any(|f| f.code == "DISK_SORT")
    }
    pub fn max_misestimate(&self) -> Option<f64> {
        let mut best: Option<f64> = None;
        if let Some(root) = &self.root {
            walk(root, &mut |n| {
                if let (Some(p), Some(a)) = (n.plan_rows, n.actual_rows) {
                    // Small absolute errors (65 estimated vs 0 actual) are noise.
                    if p.max(a) >= MISESTIMATE_MIN_ROWS {
                        let r = ratio(p, a);
                        best = Some(best.map_or(r, |b: f64| b.max(r)));
                    }
                }
            });
        }
        best
    }
    /// Relations read with a full table scan, with the rows scanned when known.
    pub fn full_scans(&self) -> Vec<(String, Option<f64>)> {
        let mut out = Vec::new();
        if let Some(root) = &self.root {
            walk(root, &mut |n| {
                if n.flags.iter().any(|f| f == "full_scan") {
                    if let Some(r) = &n.relation {
                        out.push((r.clone(), rows_scanned(n)));
                    }
                }
            });
        }
        out
    }
}

#[derive(Debug, Clone, Default)]
pub struct PlanContext {
    /// Table → total rows, used when the plan was not ANALYZEd.
    pub table_rows: HashMap<String, u64>,
    pub seq_scan_row_threshold: u64,
}

const MISESTIMATE_MIN_ROWS: f64 = 1000.0;

fn walk<'a>(n: &'a PlanNode, f: &mut impl FnMut(&'a PlanNode)) {
    f(n);
    for c in &n.children {
        walk(c, f);
    }
}

fn ratio(a: f64, b: f64) -> f64 {
    let (a, b) = (a.max(1.0), b.max(1.0));
    if a > b {
        a / b
    } else {
        b / a
    }
}

fn rows_scanned(n: &PlanNode) -> Option<f64> {
    let loops = n.actual_loops.unwrap_or(1.0);
    n.actual_rows
        .map(|r| (r + n.rows_removed_by_filter.unwrap_or(0.0)) * loops)
}

pub fn analyze_plan(engine: Engine, json: &Value, ctx: &PlanContext) -> PlanAnalysis {
    match engine {
        Engine::Postgresql => analyze_pg(json, ctx),
        Engine::Mysql => analyze_mysql(json, ctx),
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL

fn f(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(|x| x.as_f64())
}
fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| match x {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => Some(a.iter().filter_map(|i| i.as_str()).collect::<Vec<_>>().join(", ")),
        _ => None,
    })
}

fn analyze_pg(json: &Value, ctx: &PlanContext) -> PlanAnalysis {
    let top = match json {
        Value::Array(a) => a.first().cloned().unwrap_or(Value::Null),
        other => other.clone(),
    };
    let Some(plan) = top.get("Plan") else {
        return PlanAnalysis {
            engine: Engine::Postgresql,
            ..Default::default()
        };
    };
    let mut counter = 0usize;
    let root = pg_node(plan, &mut counter, false);
    let analyzed = root.actual_rows.is_some();
    let mut summary = PlanSummary {
        analyzed,
        total_cost: root.total_cost,
        plan_rows: root.plan_rows,
        actual_rows: root.actual_rows,
        planning_ms: f(&top, "Planning Time"),
        execution_ms: f(&top, "Execution Time"),
        node_count: counter,
        ..Default::default()
    };
    let mut findings = Vec::new();
    let mut hotspot: Option<(usize, f64)> = None;
    collect_pg(&root, None, ctx, &mut summary, &mut findings, &mut hotspot);
    if let Some((id, ms)) = hotspot {
        summary.hotspot_node = Some(id);
        if let Some(total) = summary.execution_ms {
            if total > 0.0 && ms / total > 0.5 && total > 5.0 {
                if let Some(node) = find_node(&root, id) {
                    findings.push(PlanFinding {
                        code: "HOTSPOT".into(),
                        severity: Severity::Info,
                        title: format!("{} dominates execution", node.node_type),
                        detail: format!(
                            "{:.0}% of {:.1} ms is spent in this {}{}.",
                            ms / total * 100.0,
                            total,
                            node.node_type,
                            node.relation.as_ref().map(|r| format!(" on {r}")).unwrap_or_default()
                        ),
                        relation: node.relation.clone(),
                        node_id: Some(id),
                    });
                }
            }
        }
    }
    let mut root = root;
    if let Some(id) = summary.hotspot_node {
        mark(&mut root, id, "hotspot");
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    PlanAnalysis {
        engine: Engine::Postgresql,
        root: Some(root),
        summary,
        findings,
    }
}

fn find_node(n: &PlanNode, id: usize) -> Option<&PlanNode> {
    if n.id == id {
        return Some(n);
    }
    n.children.iter().find_map(|c| find_node(c, id))
}

fn mark(n: &mut PlanNode, id: usize, flag: &str) {
    if n.id == id {
        n.flags.push(flag.into());
        return;
    }
    for c in &mut n.children {
        mark(c, id, flag);
    }
}

/// `in_parallel`: below a Gather node, where `Actual Total Time` is a
/// per-worker average and `Actual Loops` counts workers running concurrently.
fn pg_node(v: &Value, counter: &mut usize, in_parallel: bool) -> PlanNode {
    let id = *counter;
    *counter += 1;
    let mut n = PlanNode {
        id,
        node_type: s(v, "Node Type").unwrap_or_default(),
        relation: s(v, "Relation Name").map(|r| match s(v, "Schema") {
            Some(schema) if schema != "public" => format!("{schema}.{r}"),
            _ => r,
        }),
        alias: s(v, "Alias"),
        index_name: s(v, "Index Name"),
        join_type: s(v, "Join Type"),
        startup_cost: f(v, "Startup Cost"),
        total_cost: f(v, "Total Cost"),
        plan_rows: f(v, "Plan Rows"),
        actual_rows: f(v, "Actual Rows"),
        actual_loops: f(v, "Actual Loops"),
        actual_total_ms: f(v, "Actual Total Time"),
        filter: s(v, "Filter").or_else(|| s(v, "Join Filter")),
        index_cond: s(v, "Index Cond")
            .or_else(|| s(v, "Recheck Cond"))
            .or_else(|| s(v, "Hash Cond"))
            .or_else(|| s(v, "Merge Cond")),
        rows_removed_by_filter: f(v, "Rows Removed by Filter").or_else(|| f(v, "Rows Removed by Join Filter")),
        shared_hit_blocks: f(v, "Shared Hit Blocks"),
        shared_read_blocks: f(v, "Shared Read Blocks"),
        temp_written_blocks: f(v, "Temp Written Blocks"),
        sort_key: s(v, "Sort Key"),
        sort_method: s(v, "Sort Method"),
        sort_space_type: s(v, "Sort Space Type"),
        hash_batches: f(v, "Hash Batches"),
        ..Default::default()
    };
    let child_parallel = in_parallel || n.node_type.starts_with("Gather");
    if let Some(Value::Array(children)) = v.get("Plans") {
        n.children = children.iter().map(|c| pg_node(c, counter, child_parallel)).collect();
    }
    let wall = |time: Option<f64>, loops: Option<f64>, parallel: bool| -> Option<f64> {
        Some(time? * if parallel { 1.0 } else { loops? })
    };
    if let Some(mine) = wall(n.actual_total_ms, n.actual_loops, in_parallel) {
        let kids: f64 = n
            .children
            .iter()
            .filter_map(|c| wall(c.actual_total_ms, c.actual_loops, child_parallel))
            .sum();
        n.self_ms = Some((mine - kids).max(0.0));
    }
    match n.node_type.as_str() {
        "Seq Scan" | "Parallel Seq Scan" => n.flags.push("full_scan".into()),
        "Index Scan" | "Index Only Scan" | "Bitmap Index Scan" | "Bitmap Heap Scan" => n.flags.push("index".into()),
        _ => {}
    }
    n
}

fn collect_pg(
    n: &PlanNode,
    parent: Option<&PlanNode>,
    ctx: &PlanContext,
    summary: &mut PlanSummary,
    findings: &mut Vec<PlanFinding>,
    hotspot: &mut Option<(usize, f64)>,
) {
    summary.shared_hit_blocks += n.shared_hit_blocks.unwrap_or(0.0);
    summary.shared_read_blocks += n.shared_read_blocks.unwrap_or(0.0);
    if let Some(ms) = n.self_ms {
        if hotspot.map(|(_, h)| ms > h).unwrap_or(true) {
            *hotspot = Some((n.id, ms));
        }
    }
    let rel = n.relation.clone();

    if n.flags.iter().any(|f| f == "full_scan") {
        if let Some(r) = &rel {
            summary.seq_scans.push(r.clone());
            let scanned = rows_scanned(n).or_else(|| {
                ctx.table_rows
                    .get(r)
                    .or_else(|| ctx.table_rows.get(crate::facts::bare_name(r)))
                    .map(|v| *v as f64)
            });
            let threshold = ctx.seq_scan_row_threshold.max(1) as f64;
            if let Some(rows) = scanned {
                if rows >= threshold {
                    let removed = n.rows_removed_by_filter.unwrap_or(0.0);
                    let kept = n.actual_rows.unwrap_or(0.0);
                    findings.push(PlanFinding {
                        code: "SEQ_SCAN_LARGE".into(),
                        severity: if rows >= 1_000_000.0 { Severity::Critical } else { Severity::High },
                        title: format!("Sequential scan on {r}"),
                        detail: format!(
                            "Reads ~{} rows{}{}.",
                            fmt_rows(rows),
                            n.filter.as_ref().map(|f| format!(" to evaluate `{f}`")).unwrap_or_default(),
                            if removed > 0.0 {
                                format!(", discarding {:.1}% of them", removed / (removed + kept).max(1.0) * 100.0)
                            } else {
                                String::new()
                            }
                        ),
                        relation: Some(r.clone()),
                        node_id: Some(n.id),
                    });
                }
            }
        }
    }
    if n.flags.iter().any(|f| f == "index") {
        if let Some(r) = &rel {
            summary.index_scans.push(format!(
                "{r}{}",
                n.index_name.as_ref().map(|i| format!(" ({i})")).unwrap_or_default()
            ));
        }
    }

    if let (Some(removed), Some(kept)) = (n.rows_removed_by_filter, n.actual_rows) {
        let loops = n.actual_loops.unwrap_or(1.0);
        let total = (removed + kept) * loops;
        if total > 10_000.0 && removed / (removed + kept).max(1.0) > 0.9 && !n.flags.iter().any(|f| f == "full_scan") {
            findings.push(PlanFinding {
                code: "FILTER_INEFFICIENT".into(),
                severity: Severity::Warning,
                title: format!("{} discards most rows it reads", n.node_type),
                detail: format!(
                    "{:.1}% of ~{} rows are removed by `{}` after being fetched; the filter columns are not part of \
                     the index condition.",
                    removed / (removed + kept).max(1.0) * 100.0,
                    fmt_rows(total),
                    n.filter.clone().unwrap_or_default()
                ),
                relation: rel.clone(),
                node_id: Some(n.id),
            });
        }
    }

    if let (Some(p), Some(a)) = (n.plan_rows, n.actual_rows) {
        let r = ratio(p, a);
        if r >= 10.0 && p.max(a) >= MISESTIMATE_MIN_ROWS {
            findings.push(PlanFinding {
                code: "ROW_MISESTIMATE".into(),
                severity: if r >= 100.0 { Severity::High } else { Severity::Warning },
                title: format!("Row estimate off by {:.0}×", r),
                detail: format!(
                    "{}{} expected {} rows but produced {}. Stale statistics (run ANALYZE{}) or correlated \
                     columns the planner treats as independent (CREATE STATISTICS ... (dependencies, ndistinct)).",
                    n.node_type,
                    rel.as_ref().map(|r| format!(" on {r}")).unwrap_or_default(),
                    fmt_rows(p),
                    fmt_rows(a),
                    rel.as_ref().map(|r| format!(" {r}")).unwrap_or_default()
                ),
                relation: rel.clone(),
                node_id: Some(n.id),
            });
        }
    }

    if n.sort_space_type.as_deref() == Some("Disk") {
        findings.push(PlanFinding {
            code: "DISK_SORT".into(),
            severity: Severity::High,
            title: "Sort spilled to disk".into(),
            detail: format!(
                "{} used an on-disk {}. Add an index matching `{}` or raise work_mem for this session.",
                n.node_type,
                n.sort_method.clone().unwrap_or_else(|| "sort".into()),
                n.sort_key.clone().unwrap_or_default()
            ),
            relation: rel.clone(),
            node_id: Some(n.id),
        });
    }
    if n.hash_batches.map(|b| b > 1.0).unwrap_or(false) {
        findings.push(PlanFinding {
            code: "HASH_SPILL".into(),
            severity: Severity::Warning,
            title: "Hash table split into batches".into(),
            detail: format!(
                "Hash used {} batches because it didn't fit in work_mem.",
                n.hash_batches.unwrap_or(0.0)
            ),
            relation: rel.clone(),
            node_id: Some(n.id),
        });
    }
    if n.node_type == "Nested Loop" {
        if let Some(inner) = n.children.get(1) {
            let loops = inner.actual_loops.unwrap_or(0.0);
            if inner.flags.iter().any(|f| f == "full_scan") && (loops > 1.0 || !summary.analyzed) {
                findings.push(PlanFinding {
                    code: "NESTED_LOOP_SEQ_SCAN".into(),
                    severity: Severity::High,
                    title: "Nested loop rescans a table".into(),
                    detail: format!(
                        "The inner side ({}) is a sequential scan executed {} times. Index the join column.",
                        inner.relation.clone().unwrap_or_else(|| "?".into()),
                        if loops > 0.0 { format!("{loops:.0}") } else { "once per outer row".into() }
                    ),
                    relation: inner.relation.clone(),
                    node_id: Some(inner.id),
                });
            }
        }
    }
    if n.temp_written_blocks.map(|b| b > 0.0).unwrap_or(false) && n.sort_space_type.as_deref() != Some("Disk") {
        findings.push(PlanFinding {
            code: "TEMP_IO".into(),
            severity: Severity::Info,
            title: "Temporary files written".into(),
            detail: format!("{} wrote {:.0} temp blocks.", n.node_type, n.temp_written_blocks.unwrap_or(0.0)),
            relation: rel.clone(),
            node_id: Some(n.id),
        });
    }
    let _ = parent;
    for c in &n.children {
        collect_pg(c, Some(n), ctx, summary, findings, hotspot);
    }
}

fn fmt_rows(r: f64) -> String {
    crate::advisor::fmt_count(r.max(0.0).round() as u64)
}

// ---------------------------------------------------------------------------
// MySQL / MariaDB (EXPLAIN FORMAT=JSON)

fn analyze_mysql(json: &Value, ctx: &PlanContext) -> PlanAnalysis {
    let block = json.get("query_block").unwrap_or(json);
    let mut counter = 0usize;
    let root = mysql_node(block, "query_block", &mut counter);
    let mut summary = PlanSummary {
        analyzed: false,
        total_cost: block
            .get("cost_info")
            .and_then(|c| c.get("query_cost"))
            .and_then(|q| q.as_str().and_then(|s| s.parse().ok()).or_else(|| q.as_f64()))
            .or_else(|| block.get("cost").and_then(|c| c.as_f64())),
        node_count: counter,
        ..Default::default()
    };
    let mut findings = Vec::new();
    collect_mysql(&root, ctx, &mut summary, &mut findings);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    PlanAnalysis {
        engine: Engine::Mysql,
        root: Some(root),
        summary,
        findings,
    }
}

fn mysql_node(v: &Value, label: &str, counter: &mut usize) -> PlanNode {
    let id = *counter;
    *counter += 1;
    let mut n = PlanNode {
        id,
        node_type: label.to_string(),
        ..Default::default()
    };
    if let Some(t) = v.get("table_name").and_then(|t| t.as_str()) {
        let access = v.get("access_type").and_then(|a| a.as_str()).unwrap_or("?");
        n.node_type = match access {
            "ALL" => "Full Table Scan".into(),
            "index" => "Full Index Scan".into(),
            "range" => "Index Range Scan".into(),
            "ref" | "eq_ref" | "ref_or_null" => "Index Lookup".into(),
            "const" | "system" => "Constant Lookup".into(),
            other => format!("Access ({other})"),
        };
        n.relation = Some(t.to_string());
        n.index_name = v.get("key").and_then(|k| k.as_str()).map(String::from);
        n.plan_rows = v
            .get("rows_examined_per_scan")
            .or_else(|| v.get("rows"))
            .and_then(|r| r.as_f64());
        n.actual_rows = v.get("r_rows").and_then(|r| r.as_f64());
        n.filter = v.get("attached_condition").and_then(|c| c.as_str()).map(String::from);
        n.total_cost = v
            .get("cost_info")
            .and_then(|c| c.get("prefix_cost"))
            .and_then(|q| q.as_str().and_then(|s| s.parse().ok()));
        if access == "ALL" {
            n.flags.push("full_scan".into());
        } else if access != "index" {
            n.flags.push("index".into());
        }
        if v.get("using_filesort").and_then(|b| b.as_bool()).unwrap_or(false) {
            n.flags.push("filesort".into());
        }
    }
    if v.get("using_filesort").and_then(|b| b.as_bool()).unwrap_or(false) && !n.flags.contains(&"filesort".to_string()) {
        n.flags.push("filesort".into());
    }
    if v.get("using_temporary_table").and_then(|b| b.as_bool()).unwrap_or(false) {
        n.flags.push("temporary".into());
    }
    if let Some(obj) = v.as_object() {
        for (k, child) in obj {
            match (k.as_str(), child) {
                ("table", c) if c.is_object() => n.children.push(mysql_node(c, "table", counter)),
                ("nested_loop", Value::Array(items)) => {
                    let mut nl = PlanNode {
                        id: *counter,
                        node_type: "Nested Loop".into(),
                        ..Default::default()
                    };
                    *counter += 1;
                    for item in items {
                        let inner = item.get("table").unwrap_or(item);
                        nl.children.push(mysql_node(inner, "table", counter));
                    }
                    n.children.push(nl);
                }
                (
                    "ordering_operation" | "grouping_operation" | "duplicates_removal" | "filesort" | "temporary_table"
                    | "materialized_from_subquery" | "query_block",
                    c,
                ) if c.is_object() => {
                    let label = k.replace('_', " ");
                    let mut child_node = mysql_node(c, &label, counter);
                    child_node.node_type = title_case(&label);
                    n.children.push(child_node);
                }
                _ => {}
            }
        }
    }
    if n.relation.is_none() && n.children.len() == 1 && n.node_type == "table" {
        return n.children.remove(0);
    }
    n
}

fn title_case(s: &str) -> String {
    s.split(' ')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn collect_mysql(n: &PlanNode, ctx: &PlanContext, summary: &mut PlanSummary, findings: &mut Vec<PlanFinding>) {
    if n.flags.iter().any(|f| f == "full_scan") {
        if let Some(r) = &n.relation {
            summary.seq_scans.push(r.clone());
            let rows = n.plan_rows.or_else(|| ctx.table_rows.get(r).map(|v| *v as f64)).unwrap_or(0.0);
            if rows >= ctx.seq_scan_row_threshold.max(1) as f64 {
                findings.push(PlanFinding {
                    code: "SEQ_SCAN_LARGE".into(),
                    severity: if rows >= 1_000_000.0 { Severity::Critical } else { Severity::High },
                    title: format!("Full table scan on {r}"),
                    detail: format!(
                        "access_type=ALL examines ~{} rows{}.",
                        fmt_rows(rows),
                        n.filter.as_ref().map(|f| format!(" to evaluate `{f}`")).unwrap_or_default()
                    ),
                    relation: Some(r.clone()),
                    node_id: Some(n.id),
                });
            }
        }
    }
    if n.flags.iter().any(|f| f == "index") {
        if let Some(r) = &n.relation {
            summary.index_scans.push(format!(
                "{r}{}",
                n.index_name.as_ref().map(|i| format!(" ({i})")).unwrap_or_default()
            ));
        }
    }
    if n.flags.iter().any(|f| f == "filesort") {
        findings.push(PlanFinding {
            code: "FILESORT".into(),
            severity: Severity::Warning,
            title: "Using filesort".into(),
            detail: "Rows are sorted after retrieval. An index whose trailing columns match ORDER BY avoids it.".into(),
            relation: n.relation.clone(),
            node_id: Some(n.id),
        });
    }
    if n.flags.iter().any(|f| f == "temporary") {
        findings.push(PlanFinding {
            code: "TEMP_TABLE".into(),
            severity: Severity::Warning,
            title: "Using temporary table".into(),
            detail: "GROUP BY / DISTINCT materialises an internal temporary table.".into(),
            relation: n.relation.clone(),
            node_id: Some(n.id),
        });
    }
    for c in &n.children {
        collect_mysql(c, ctx, summary, findings);
    }
}

/// Total cost of the plan's root node (used for hypothetical comparisons).
pub fn plan_total_cost(engine: Engine, json: &Value) -> Option<f64> {
    analyze_plan(engine, json, &PlanContext::default()).summary.total_cost
}
