//! Orchestrates the deterministic pipeline for one query. Pure: callers
//! gather catalog metadata and EXPLAIN output first (see [`prepare`]).

use serde::Serialize;
use serde_json::Value;

use crate::advisor::{self, AdvisorOptions, IndexRecommendation, RecommendationKind, TableContexts};
use crate::facts::{self, bare_name, QueryFacts, SchemaCatalog};
use crate::model::{Engine, Severity};
use crate::plan::{self, PlanAnalysis, PlanContext};
use crate::rewrite::{self, RewriteFinding};
use crate::rules::{RuleContext, RuleEngine, RuleHit};
use crate::CoreError;

#[derive(Debug, Clone, Serialize)]
pub struct PreparedQuery {
    pub statement_kind: String,
    pub tables: Vec<String>,
    pub placeholders: usize,
    pub normalized_sql: String,
}

/// Parse once to learn which tables need metadata.
pub fn prepare(sql: &str, engine: Engine) -> Result<PreparedQuery, CoreError> {
    let (stmt, facts) = facts::extract_facts(sql, engine, None)?;
    Ok(PreparedQuery {
        statement_kind: facts.statement_kind,
        tables: facts.tables,
        placeholders: facts.placeholders,
        normalized_sql: format!("{stmt:#}"),
    })
}

pub struct AnalysisInput<'a> {
    pub sql: &'a str,
    pub engine: Engine,
    pub catalog: Option<&'a SchemaCatalog>,
    pub tables: &'a TableContexts,
    pub plan_json: Option<&'a Value>,
    pub rules: &'a RuleEngine,
    pub server_version_num: Option<u32>,
    pub ai_cost_threshold: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiDecision {
    pub recommended: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub engine: Engine,
    pub statement_kind: String,
    pub normalized_sql: String,
    pub facts: QueryFacts,
    pub rewrites: Vec<RewriteFinding>,
    pub rewritten_sql: Option<String>,
    pub recommendations: Vec<IndexRecommendation>,
    /// "original" or "rewritten": which SQL the index advisor analysed.
    pub advisor_source: String,
    pub plan: Option<PlanAnalysis>,
    pub rule_hits: Vec<RuleHit>,
    pub score: u32,
    pub grade: String,
    pub ai: AiDecision,
    pub warnings: Vec<String>,
}

pub fn analyze(input: AnalysisInput) -> Result<AnalysisReport, CoreError> {
    let (stmt, facts) = facts::extract_facts(input.sql, input.engine, input.catalog)?;
    let mut warnings = Vec::new();
    if !facts.unresolved_columns.is_empty() {
        warnings.push(format!(
            "Could not attribute these columns to a table (qualify them with an alias{}): {}",
            if input.catalog.is_none() { " or connect a database" } else { "" },
            facts.unresolved_columns.join(", ")
        ));
    }

    let rw = rewrite::rewrite(&stmt, &facts, input.engine);

    // Advise on the rewritten statement when one exists: e.g. a YEAR() filter
    // only becomes indexable after the range rewrite.
    let (advisor_facts, advisor_source) = match &rw.rewritten_sql {
        Some(sql) => match facts::extract_facts(sql, input.engine, input.catalog) {
            Ok((_, f)) => (f, "rewritten"),
            Err(e) => {
                warnings.push(format!("Rewritten SQL failed to re-parse ({e}); advising on the original."));
                (facts.clone(), "original")
            }
        },
        None => (facts.clone(), "original"),
    };

    let plan_ctx = PlanContext {
        table_rows: input
            .tables
            .iter()
            .filter_map(|(t, c)| c.stats.as_ref().map(|s| (t.clone(), s.total_rows)))
            .collect(),
        seq_scan_row_threshold: rule_row_threshold(input.rules).unwrap_or(10_000),
    };
    let plan = input
        .plan_json
        .map(|j| plan::analyze_plan(input.engine, j, &plan_ctx))
        .filter(|p| p.root.is_some());

    let opts = input.rules.advisor_options(AdvisorOptions {
        engine: input.engine,
        server_version_num: input.server_version_num,
        ..Default::default()
    });
    let mut recs = advisor::recommend(&advisor_facts, input.tables, &opts);

    let rule_hits = input.rules.evaluate(&RuleContext {
        sql: input.sql,
        facts: &facts,
        plan: plan.as_ref(),
        tables: input.tables,
    });
    link_rules(&rule_hits, &mut recs);
    recs.sort_by(|a, b| {
        let covered = |r: &IndexRecommendation| matches!(r.action, advisor::IndexAction::Covered { .. });
        covered(a).cmp(&covered(b)).then(b.severity.cmp(&a.severity))
    });

    let (score, grade) = score(&rule_hits, plan.as_ref(), &rw.findings);
    let ai = ai_decision(&facts, plan.as_ref(), &rule_hits, input.ai_cost_threshold);

    Ok(AnalysisReport {
        engine: input.engine,
        statement_kind: facts.statement_kind.clone(),
        normalized_sql: format!("{stmt:#}"),
        facts,
        rewrites: rw.findings,
        rewritten_sql: rw.rewritten_sql,
        recommendations: recs,
        advisor_source: advisor_source.into(),
        plan,
        rule_hits,
        score,
        grade,
        ai,
        warnings,
    })
}

fn rule_row_threshold(rules: &RuleEngine) -> Option<u64> {
    rules
        .enabled()
        .filter_map(|r| r.condition.as_ref())
        .filter(|c| c.has_full_table_scan == Some(true))
        .filter_map(|c| c.min_row_threshold)
        .min()
}

fn link_rules(hits: &[RuleHit], recs: &mut [IndexRecommendation]) {
    for hit in hits {
        for (table, cols) in &hit.index_targets {
            for r in recs.iter_mut() {
                if r.table != *table && bare_name(&r.table) != bare_name(table) {
                    continue;
                }
                if matches!(r.action, advisor::IndexAction::Covered { .. }) {
                    continue;
                }
                let matches = if cols.is_empty() {
                    r.kind == RecommendationKind::Composite
                } else {
                    r.key_columns.iter().zip(cols.iter()).all(|(k, c)| k.name.eq_ignore_ascii_case(c))
                        && r.key_columns.len() >= cols.len()
                };
                if matches {
                    if !r.rule_ids.contains(&hit.rule_id) {
                        r.rule_ids.push(hit.rule_id.clone());
                    }
                    r.severity = r.severity.max(hit.severity);
                }
            }
        }
    }
}

fn score(hits: &[RuleHit], plan: Option<&PlanAnalysis>, rewrites: &[RewriteFinding]) -> (u32, String) {
    let mut penalty: u32 = hits.iter().map(|h| h.severity.penalty()).sum();
    let ruled_tables: Vec<&String> = hits
        .iter()
        .filter(|h| h.rule_id.contains("COMPOSITE"))
        .flat_map(|h| h.tables.iter())
        .collect();
    if let Some(p) = plan {
        for f in &p.findings {
            if f.code == "SEQ_SCAN_LARGE"
                && f.relation.as_ref().map(|r| ruled_tables.iter().any(|t| bare_name(t) == bare_name(r))).unwrap_or(false)
            {
                continue;
            }
            penalty += f.severity.penalty();
        }
    }
    penalty += rewrites.iter().map(|r| r.severity.penalty() / 2).sum::<u32>();
    let score = 100u32.saturating_sub(penalty);
    let grade = match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    };
    (score, grade.into())
}

fn ai_decision(facts: &QueryFacts, plan: Option<&PlanAnalysis>, hits: &[RuleHit], threshold: f64) -> AiDecision {
    let mut reasons = Vec::new();
    if let Some(cost) = plan.and_then(|p| p.summary.total_cost) {
        if cost >= threshold {
            reasons.push(format!("plan cost {cost:.0} exceeds the AI threshold ({threshold:.0})"));
        }
    }
    if facts.recursive_cte {
        reasons.push("recursive CTE".into());
    }
    if facts.subquery_count >= 3 {
        reasons.push(format!("{} nested subqueries", facts.subquery_count));
    }
    if facts.tables.len() >= 4 {
        reasons.push(format!("{}-table join", facts.tables.len()));
    }
    if hits.iter().any(|h| h.severity == Severity::Critical) {
        reasons.push("critical rule violation".into());
    }
    AiDecision {
        recommended: !reasons.is_empty(),
        reasons,
    }
}
