//! Config-driven optimizer rules (YAML), evaluated against query facts,
//! the EXPLAIN analysis and catalog metadata — no recompilation needed.

use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::advisor::{AdvisorOptions, TableContexts};
use crate::facts::{bare_name, JoinKind, PredicateKind, QueryFacts};
use crate::model::Severity;
use crate::plan::PlanAnalysis;
use crate::CoreError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub version: String,
    #[serde(default)]
    pub engine: Option<String>,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub condition: Option<RuleCondition>,
    /// `LIKE '%...'` (built-in detector) or `regex:<pattern>` / plain regex on the SQL text.
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub recommendation: Option<String>,
    #[serde(default)]
    pub action: Option<RuleAction>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleCondition {
    // table-scoped
    pub has_full_table_scan: Option<bool>,
    pub min_row_threshold: Option<u64>,
    /// LEFT_JOIN, INNER_JOIN, RIGHT_JOIN, FULL_JOIN, ANY
    pub join_type: Option<String>,
    pub foreign_key_indexed: Option<bool>,
    // statement-scoped
    pub has_leading_wildcard: Option<bool>,
    pub has_select_star: Option<bool>,
    pub has_function_on_column: Option<bool>,
    pub has_or_across_columns: Option<bool>,
    pub has_not_in_subquery: Option<bool>,
    pub has_order_by_random: Option<bool>,
    pub min_offset: Option<u64>,
    pub has_disk_sort: Option<bool>,
    pub min_total_cost: Option<f64>,
    pub min_row_misestimate: Option<f64>,
    pub statement_type: Option<String>,
    pub missing_where: Option<bool>,
    pub min_tables: Option<usize>,
    pub min_subqueries: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleAction {
    #[serde(default)]
    pub recommend_index: Option<IndexActionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndexActionSpec {
    pub equality_first: Option<bool>,
    pub range_second: Option<bool>,
    pub include_sort_columns: Option<bool>,
    pub include_covering_columns: Option<bool>,
    pub max_key_columns: Option<usize>,
    /// `right_table` (joined side) or a literal table name.
    pub target_table: Option<String>,
    /// `foreign_key_id` = the join column of the target table, or literal names.
    pub columns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleHit {
    pub rule_id: String,
    pub name: String,
    pub severity: Severity,
    pub message: String,
    pub recommendation: Option<String>,
    pub tables: Vec<String>,
    /// For index actions: (table, leading columns) the rule wants indexed.
    #[serde(skip)]
    pub index_targets: Vec<(String, Vec<String>)>,
    pub heuristic: bool,
}

/// A loaded rule set with compiled patterns.
#[derive(Debug, Clone)]
pub struct RuleEngine {
    pub set: RuleSet,
    patterns: HashMap<String, Regex>,
}

pub const LEADING_WILDCARD_PATTERN: &str = "LIKE '%...'";

impl RuleEngine {
    pub fn from_yaml(yaml: &str) -> Result<Self, CoreError> {
        let set: RuleSet = serde_yaml::from_str(yaml).map_err(|e| CoreError::Rules(e.to_string()))?;
        let mut ids = HashSet::new();
        let mut patterns = HashMap::new();
        for r in &set.rules {
            if !ids.insert(r.id.clone()) {
                return Err(CoreError::Rules(format!("duplicate rule id {}", r.id)));
            }
            if let Some(p) = &r.pattern {
                if p != LEADING_WILDCARD_PATTERN {
                    let raw = p.strip_prefix("regex:").unwrap_or(p);
                    let re = Regex::new(&format!("(?is){raw}"))
                        .map_err(|e| CoreError::Rules(format!("rule {}: invalid pattern: {e}", r.id)))?;
                    patterns.insert(r.id.clone(), re);
                }
            }
            if r.condition.is_none() && r.pattern.is_none() {
                return Err(CoreError::Rules(format!("rule {} needs a condition or a pattern", r.id)));
            }
        }
        Ok(Self { set, patterns })
    }

    pub fn enabled(&self) -> impl Iterator<Item = &RuleSpec> {
        self.set.rules.iter().filter(|r| r.enabled)
    }

    /// Fold `recommend_index` ordering flags of enabled rules into advisor options.
    pub fn advisor_options(&self, mut base: AdvisorOptions) -> AdvisorOptions {
        for r in self.enabled() {
            if let Some(spec) = r.action.as_ref().and_then(|a| a.recommend_index.as_ref()) {
                if let Some(v) = spec.equality_first {
                    base.equality_first = v;
                }
                if let Some(v) = spec.range_second {
                    base.range_second = v;
                }
                if let Some(v) = spec.include_sort_columns {
                    base.include_sort_columns = v;
                }
                if let Some(v) = spec.include_covering_columns {
                    base.include_covering_columns = v;
                }
                if let Some(v) = spec.max_key_columns {
                    base.max_key_columns = v;
                }
            }
        }
        base
    }

    pub fn evaluate(&self, ctx: &RuleContext) -> Vec<RuleHit> {
        self.enabled().filter_map(|r| self.evaluate_rule(r, ctx)).collect()
    }

    fn evaluate_rule(&self, rule: &RuleSpec, ctx: &RuleContext) -> Option<RuleHit> {
        let mut evidence: Vec<String> = Vec::new();
        let mut heuristic = false;

        if let Some(p) = &rule.pattern {
            if p == LEADING_WILDCARD_PATTERN {
                let preds: Vec<String> = ctx
                    .facts
                    .blocks
                    .iter()
                    .flat_map(|b| b.predicates.iter())
                    .filter(|p| p.kind == PredicateKind::LeadingWildcard)
                    .map(|p| format!("`{}`", p.sql))
                    .collect();
                if preds.is_empty() {
                    return None;
                }
                evidence.push(preds.join(", "));
            } else if let Some(re) = self.patterns.get(&rule.id) {
                let m = re.find(ctx.sql)?;
                evidence.push(format!("matched `{}`", m.as_str()));
            }
        }

        let cond = rule.condition.clone().unwrap_or_default();
        let facts = ctx.facts;

        // ---- statement-scoped conditions
        macro_rules! check {
            ($opt:expr, $actual:expr, $label:expr) => {
                if let Some(want) = $opt {
                    let actual: bool = $actual;
                    if actual != want {
                        return None;
                    }
                    if actual {
                        evidence.push($label.to_string());
                    }
                }
            };
        }
        let preds = || facts.blocks.iter().flat_map(|b| b.predicates.iter());
        check!(
            cond.has_leading_wildcard,
            preds().any(|p| p.kind == PredicateKind::LeadingWildcard),
            "leading wildcard LIKE"
        );
        check!(cond.has_select_star, facts.blocks.iter().any(|b| b.select_star), "SELECT *");
        check!(
            cond.has_function_on_column,
            preds().any(|p| p.kind == PredicateKind::FunctionWrapped),
            "function applied to a filtered column"
        );
        check!(
            cond.has_or_across_columns,
            facts.blocks.iter().any(|b| b
                .or_groups
                .iter()
                .any(|g| g.iter().map(|c| &c.column).collect::<HashSet<_>>().len() > 1)),
            "OR across different columns"
        );
        check!(
            cond.has_not_in_subquery,
            preds().any(|p| p.kind == PredicateKind::NotInSubquery),
            "NOT IN (subquery)"
        );
        check!(cond.has_order_by_random, facts.order_by_random, "ORDER BY random()");
        check!(cond.has_disk_sort, ctx.plan.map(|p| p.has_disk_sort()).unwrap_or(false), "sort spilled to disk");
        check!(
            cond.missing_where,
            matches!(facts.statement_kind.as_str(), "UPDATE" | "DELETE")
                && facts.blocks.first().map(|b| b.predicates.is_empty() && b.joins.is_empty()).unwrap_or(false),
            "no WHERE clause"
        );
        if let Some(min) = cond.min_offset {
            let off = facts.blocks.iter().filter_map(|b| b.offset).max()?;
            if off < min {
                return None;
            }
            evidence.push(format!("OFFSET {off}"));
        }
        if let Some(min) = cond.min_total_cost {
            let cost = ctx.plan.and_then(|p| p.summary.total_cost)?;
            if cost < min {
                return None;
            }
            evidence.push(format!("plan cost {cost:.0}"));
        }
        if let Some(min) = cond.min_row_misestimate {
            let r = ctx.plan.and_then(|p| p.max_misestimate())?;
            if r < min {
                return None;
            }
            evidence.push(format!("row estimate off by {r:.0}×"));
        }
        if let Some(t) = &cond.statement_type {
            if !facts.statement_kind.eq_ignore_ascii_case(t) {
                return None;
            }
        }
        if let Some(min) = cond.min_tables {
            if facts.tables.len() < min {
                return None;
            }
            evidence.push(format!("{} tables", facts.tables.len()));
        }
        if let Some(min) = cond.min_subqueries {
            if facts.subquery_count < min {
                return None;
            }
            evidence.push(format!("{} subqueries", facts.subquery_count));
        }

        // ---- table-scoped conditions
        let mut tables: Vec<String> = Vec::new();
        let mut index_targets: Vec<(String, Vec<String>)> = Vec::new();
        let table_scoped = cond.has_full_table_scan.is_some()
            || cond.min_row_threshold.is_some()
            || cond.join_type.is_some()
            || cond.foreign_key_indexed.is_some();

        if table_scoped {
            let candidates: Vec<(String, Option<String>)> = if cond.join_type.is_some() || cond.foreign_key_indexed.is_some() {
                // (joined table, join column)
                let want = cond.join_type.as_deref().map(|s| s.to_uppercase());
                let mut v = Vec::new();
                for b in &facts.blocks {
                    for j in &b.joins {
                        let kind_ok = match want.as_deref() {
                            None | Some("ANY") => true,
                            Some("LEFT_JOIN") | Some("LEFT") => j.kind == JoinKind::Left,
                            Some("RIGHT_JOIN") | Some("RIGHT") => j.kind == JoinKind::Right,
                            Some("INNER_JOIN") | Some("INNER") => {
                                matches!(j.kind, JoinKind::Inner | JoinKind::Implicit)
                            }
                            Some("FULL_JOIN") | Some("FULL") => j.kind == JoinKind::Full,
                            Some(_) => false,
                        };
                        if !kind_ok {
                            continue;
                        }
                        let side = match (&j.joined_table, j.kind) {
                            (Some(t), JoinKind::Right) => [&j.left, &j.right].into_iter().find(|c| c.table.as_ref() != Some(t)),
                            (Some(t), _) => [&j.left, &j.right].into_iter().find(|c| c.table.as_ref() == Some(t)),
                            (None, _) => Some(&j.right),
                        };
                        if let Some(c) = side {
                            if let Some(t) = &c.table {
                                v.push((t.clone(), Some(c.column.clone())));
                            }
                        }
                    }
                }
                v
            } else {
                facts.tables.iter().map(|t| (t.clone(), None)).collect()
            };

            let full_scans = full_scan_tables(ctx, &mut heuristic);
            for (table, join_col) in candidates {
                if let Some(want) = cond.has_full_table_scan {
                    let is_full = full_scans.iter().any(|t| t == &table || bare_name(t) == bare_name(&table));
                    if is_full != want {
                        continue;
                    }
                }
                if let Some(min) = cond.min_row_threshold {
                    match ctx.table_rows(&table) {
                        Some(rows) if rows >= min => {}
                        Some(_) => continue,
                        None => {
                            heuristic = true;
                        }
                    }
                }
                if let (Some(want), Some(col)) = (cond.foreign_key_indexed, &join_col) {
                    match ctx.leading_indexed(&table, col) {
                        Some(indexed) if indexed != want => continue,
                        None => heuristic = true,
                        _ => {}
                    }
                }
                if !tables.contains(&table) {
                    tables.push(table.clone());
                }
                if let Some(spec) = rule.action.as_ref().and_then(|a| a.recommend_index.as_ref()) {
                    let cols: Vec<String> = match &spec.columns {
                        Some(cs) => cs
                            .iter()
                            .filter_map(|c| {
                                if c == "foreign_key_id" || c == "join_column" {
                                    join_col.clone()
                                } else {
                                    Some(c.clone())
                                }
                            })
                            .collect(),
                        None => join_col.clone().into_iter().collect(),
                    };
                    let target = match spec.target_table.as_deref() {
                        None | Some("right_table") | Some("joined_table") => table.clone(),
                        Some(t) => t.to_string(),
                    };
                    index_targets.push((target, cols));
                }
            }
            if tables.is_empty() {
                return None;
            }
            if cond.has_full_table_scan == Some(true) {
                evidence.push(format!("full table scan on {}", tables.join(", ")));
            }
            if let Some(min) = cond.min_row_threshold {
                let sizes: Vec<String> = tables
                    .iter()
                    .filter_map(|t| ctx.table_rows(t).map(|r| format!("{} ~{} rows", bare_name(t), crate::advisor::fmt_count(r))))
                    .collect();
                if !sizes.is_empty() {
                    evidence.push(format!("{} (threshold {})", sizes.join(", "), crate::advisor::fmt_count(min)));
                }
            }
            if cond.foreign_key_indexed == Some(false) {
                evidence.push(format!("join column not indexed on {}", tables.join(", ")));
            }
        }

        let message = if evidence.is_empty() {
            rule.description.clone().unwrap_or_else(|| rule.name.clone())
        } else {
            evidence.join("; ")
        };
        Some(RuleHit {
            rule_id: rule.id.clone(),
            name: rule.name.clone(),
            severity: rule.severity,
            message,
            recommendation: rule.recommendation.clone().or_else(|| rule.description.clone()),
            tables,
            index_targets,
            heuristic,
        })
    }
}

pub struct RuleContext<'a> {
    pub sql: &'a str,
    pub facts: &'a QueryFacts,
    pub plan: Option<&'a PlanAnalysis>,
    pub tables: &'a TableContexts,
}

impl RuleContext<'_> {
    fn table_rows(&self, table: &str) -> Option<u64> {
        self.tables
            .get(table)
            .or_else(|| self.tables.iter().find(|(k, _)| bare_name(k) == bare_name(table)).map(|(_, v)| v))
            .and_then(|c| c.stats.as_ref().map(|s| s.total_rows))
    }

    /// Some(true) if an index on `table` leads with `column`; None if unknown.
    fn leading_indexed(&self, table: &str, column: &str) -> Option<bool> {
        let ctx = self.tables.get(table)?;
        let idx = ctx.indexes.as_ref()?;
        Some(idx.iter().any(|i| {
            i.columns
                .first()
                .map(|c| c.eq_ignore_ascii_case(column))
                .unwrap_or(false)
        }))
    }
}

/// Tables read by a full scan: from the plan when available, otherwise
/// inferred from predicates vs. known indexes.
fn full_scan_tables(ctx: &RuleContext, heuristic: &mut bool) -> Vec<String> {
    if let Some(plan) = ctx.plan {
        if plan.root.is_some() {
            return plan.full_scans().into_iter().map(|(t, _)| t).collect();
        }
    }
    *heuristic = true;
    let mut out = Vec::new();
    for t in &ctx.facts.tables {
        let cols: Vec<&str> = ctx
            .facts
            .blocks
            .iter()
            .flat_map(|b| b.predicates.iter())
            .filter(|p| p.sargable && p.column.table.as_deref().map(|x| bare_name(x) == bare_name(t)).unwrap_or(ctx.facts.tables.len() == 1))
            .map(|p| p.column.column.as_str())
            .collect();
        let indexed = ctx
            .tables
            .get(t)
            .and_then(|c| c.indexes.as_ref())
            .map(|idx| {
                idx.iter().any(|i| {
                    i.columns
                        .first()
                        .map(|c| cols.iter().any(|x| c.eq_ignore_ascii_case(x)))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if !indexed {
            out.push(t.clone());
        }
    }
    out
}

pub const DEFAULT_RULES_YAML: &str = include_str!("../../../config/rules/default.yaml");
