//! Rule-based index recommendation.
//!
//! Composite key order: equality columns (most selective first) → range / IN
//! columns → ORDER BY / GROUP BY columns, then `INCLUDE` covering columns on
//! PostgreSQL. Each proposal is compared against the table's existing indexes
//! to decide between CREATE, REPLACE (existing index is a prefix) and
//! "already covered".

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::facts::{bare_name, ColumnRef, JoinKind, Predicate, PredicateKind, QueryFacts, SelectBlock};
use crate::model::{ColumnMetadata, Engine, IndexMetadata, Severity, TableStats};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TableContext {
    pub stats: Option<TableStats>,
    pub indexes: Option<Vec<IndexMetadata>>,
    pub columns: Vec<ColumnMetadata>,
}

impl TableContext {
    fn distinct(&self, column: &str) -> Option<u64> {
        self.columns
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(column))
            .and_then(|c| c.distinct_values)
            .filter(|d| *d > 0)
    }
    fn null_fraction(&self, column: &str) -> Option<f64> {
        self.columns
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(column))
            .and_then(|c| c.null_fraction)
    }
}

pub type TableContexts = HashMap<String, TableContext>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorOptions {
    pub engine: Engine,
    pub equality_first: bool,
    pub range_second: bool,
    pub include_sort_columns: bool,
    pub include_covering_columns: bool,
    pub max_key_columns: usize,
    pub max_include_columns: usize,
    pub concurrently: bool,
    /// Server version number (e.g. 180000); INCLUDE needs PostgreSQL 11+.
    pub server_version_num: Option<u32>,
}

impl Default for AdvisorOptions {
    fn default() -> Self {
        Self {
            engine: Engine::Postgresql,
            equality_first: true,
            range_second: true,
            include_sort_columns: true,
            include_covering_columns: true,
            max_key_columns: 5,
            max_include_columns: 4,
            concurrently: true,
            server_version_num: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ColumnRole {
    Equality,
    Join,
    Range,
    Sort,
    Group,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexColumn {
    pub name: String,
    pub role: ColumnRole,
    pub distinct_values: Option<u64>,
    pub descending: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationKind {
    Composite,
    JoinKey,
    Trigram,
    Expression,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IndexAction {
    Create,
    Replace { drop_index: String },
    Covered { by_index: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexRecommendation {
    pub id: String,
    pub table: String,
    pub kind: RecommendationKind,
    pub key_columns: Vec<IndexColumn>,
    pub include_columns: Vec<String>,
    /// Expression for expression indexes (`lower(email)`).
    pub expression: Option<String>,
    pub method: String,
    pub action: IndexAction,
    pub index_name: String,
    pub ddl: Vec<String>,
    pub rollback_ddl: Vec<String>,
    pub rationale: Vec<String>,
    pub source_predicates: Vec<String>,
    pub severity: Severity,
    pub total_rows: Option<u64>,
    pub selectivity: Option<f64>,
    pub estimated_rows: Option<u64>,
    pub rule_ids: Vec<String>,
    /// Filled in by hypothetical-index evaluation (HypoPG) when available.
    pub cost_before: Option<f64>,
    pub cost_after: Option<f64>,
}

pub fn recommend(facts: &QueryFacts, tables: &TableContexts, opts: &AdvisorOptions) -> Vec<IndexRecommendation> {
    let mut recs: Vec<IndexRecommendation> = Vec::new();
    for block in &facts.blocks {
        let single_table = block.real_tables().count() == 1 && block.tables.len() == 1;
        let block_tables: Vec<String> = block.real_tables().map(|t| t.name.clone()).collect();
        for table in &block_tables {
            let ctx = tables.get(table).cloned().unwrap_or_default();
            let preds: Vec<&Predicate> = block
                .predicates
                .iter()
                .filter(|p| belongs(&p.column, table, single_table))
                .collect();

            if let Some(r) = composite(block, table, &preds, &ctx, opts, single_table) {
                recs.push(r);
            }
            for p in &preds {
                match p.kind {
                    PredicateKind::LeadingWildcard => recs.push(trigram(table, p, &ctx, opts)),
                    PredicateKind::FunctionWrapped => {
                        if let Some(r) = expression(table, p, &ctx, opts) {
                            recs.push(r);
                        }
                    }
                    _ => {}
                }
            }
        }
        recs.extend(join_keys(block, tables, opts, &recs));
    }
    dedupe(recs)
}

fn belongs(c: &ColumnRef, table: &str, single_table: bool) -> bool {
    match &c.table {
        Some(t) => t == table || bare_name(t) == bare_name(table),
        None => single_table,
    }
}

fn composite(
    block: &SelectBlock,
    table: &str,
    preds: &[&Predicate],
    ctx: &TableContext,
    opts: &AdvisorOptions,
    single_table: bool,
) -> Option<IndexRecommendation> {
    let mut rationale = Vec::new();
    let mut sources = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut eq: Vec<(usize, IndexColumn)> = Vec::new();
    let mut range: Vec<(usize, IndexColumn)> = Vec::new();
    for (pos, p) in preds.iter().enumerate() {
        if !p.sargable {
            continue;
        }
        let is_eq = p.kind.is_equality_like() || p.kind == PredicateKind::InSubquery;
        let is_range = p.kind.is_range_like();
        if !(is_eq || is_range) {
            continue;
        }
        sources.push(p.sql.clone());
        if !seen.insert(p.column.column.clone()) {
            continue;
        }
        let col = IndexColumn {
            name: p.column.column.clone(),
            role: if is_eq { ColumnRole::Equality } else { ColumnRole::Range },
            distinct_values: ctx.distinct(&p.column.column),
            descending: false,
        };
        if is_eq {
            eq.push((pos, col));
        } else {
            range.push((pos, col));
        }
    }
    if eq.is_empty() && range.is_empty() {
        return None;
    }

    // Most selective (highest distinct count) first; unknown cardinality keeps query order.
    let by_selectivity = |v: &mut Vec<(usize, IndexColumn)>| {
        v.sort_by(|(pa, a), (pb, b)| match (a.distinct_values, b.distinct_values) {
            (Some(x), Some(y)) => y.cmp(&x).then(pa.cmp(pb)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => pa.cmp(pb),
        })
    };
    by_selectivity(&mut eq);
    by_selectivity(&mut range);

    let mut key: Vec<IndexColumn> = if opts.equality_first && opts.range_second {
        eq.iter().chain(range.iter()).map(|(_, c)| c.clone()).collect()
    } else {
        let mut all: Vec<(usize, IndexColumn)> = eq.iter().chain(range.iter()).cloned().collect();
        all.sort_by_key(|(p, _)| *p);
        all.into_iter().map(|(_, c)| c).collect()
    };

    if !eq.is_empty() {
        let known = eq.iter().all(|(_, c)| c.distinct_values.is_some());
        rationale.push(format!(
            "Equality columns lead the key{}: {}.",
            if known { ", most selective first" } else { "" },
            eq.iter()
                .map(|(_, c)| match c.distinct_values {
                    Some(d) => format!("{} (~{} distinct)", c.name, fmt_count(d)),
                    None => c.name.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !range.is_empty() {
        rationale.push(format!(
            "Range / IN columns follow the equality prefix: {}. Only the first range column bounds the scan; later \
             ones are checked inside the index.",
            range.iter().map(|(_, c)| c.name.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }

    // Sort / group columns.
    if opts.include_sort_columns {
        let order_cols: Vec<_> = block.order_by.iter().collect();
        let all_order_here = !order_cols.is_empty() && order_cols.iter().all(|o| belongs(&o.column, table, single_table));
        let all_group_here =
            !block.group_by.is_empty() && block.group_by.iter().all(|c| belongs(c, table, single_table));
        let (cols, role): (Vec<(String, bool)>, ColumnRole) = if all_order_here {
            (
                order_cols.iter().map(|o| (o.column.column.clone(), o.descending)).collect(),
                ColumnRole::Sort,
            )
        } else if all_group_here {
            (block.group_by.iter().map(|c| (c.column.clone(), false)).collect(), ColumnRole::Group)
        } else {
            (Vec::new(), ColumnRole::Sort)
        };
        let eq_names: HashSet<String> = eq.iter().map(|(_, c)| c.name.clone()).collect();
        let tail: Vec<(String, bool)> = cols.into_iter().filter(|(c, _)| !eq_names.contains(c)).collect();
        if !tail.is_empty() {
            if range.is_empty() {
                for (c, desc) in &tail {
                    if !key.iter().any(|k| &k.name == c) {
                        key.push(IndexColumn {
                            name: c.clone(),
                            role,
                            distinct_values: ctx.distinct(c),
                            descending: *desc && opts.engine == Engine::Postgresql && tail.len() > 1,
                        });
                    }
                }
                rationale.push(format!(
                    "{} columns appended so rows come out of the index already ordered (no Sort node): {}.",
                    if role == ColumnRole::Sort { "ORDER BY" } else { "GROUP BY" },
                    tail.iter().map(|(c, _)| c.as_str()).collect::<Vec<_>>().join(", ")
                ));
            } else {
                rationale.push(
                    "ORDER BY / GROUP BY columns are not appended: a range predicate precedes them, so the index \
                     can't deliver that order."
                        .into(),
                );
            }
        }
    }

    if key.len() > opts.max_key_columns {
        let dropped: Vec<String> = key.drain(opts.max_key_columns..).map(|c| c.name).collect();
        rationale.push(format!(
            "Key truncated to {} columns; dropped: {}.",
            opts.max_key_columns,
            dropped.join(", ")
        ));
    }

    // Covering columns.
    let mut include = Vec::new();
    let supports_include =
        opts.engine == Engine::Postgresql && opts.server_version_num.map(|v| v >= 110000).unwrap_or(true);
    let star_here = block.select_star && (block.star_tables.is_empty() || block.star_tables.iter().any(|t| t == table));
    if opts.include_covering_columns && supports_include {
        if star_here {
            rationale.push("SELECT * prevents an index-only scan, so no INCLUDE columns are proposed.".into());
        } else {
            let key_names: HashSet<&str> = key.iter().map(|k| k.name.as_str()).collect();
            let extra: Vec<String> = block
                .referenced
                .iter()
                .filter(|c| belongs(c, table, single_table) && !key_names.contains(c.column.as_str()))
                .map(|c| c.column.clone())
                .collect::<Vec<_>>();
            let mut extra_dedup = Vec::new();
            for c in extra {
                if !extra_dedup.contains(&c) {
                    extra_dedup.push(c);
                }
            }
            if !extra_dedup.is_empty() && extra_dedup.len() <= opts.max_include_columns {
                rationale.push(format!(
                    "INCLUDE ({}) makes the index covering, enabling an Index Only Scan without heap lookups.",
                    extra_dedup.join(", ")
                ));
                include = extra_dedup;
            } else if extra_dedup.len() > opts.max_include_columns {
                rationale.push(format!(
                    "{} other columns are read from this table; too many to include without bloating the index.",
                    extra_dedup.len()
                ));
            }
        }
    }

    let eq_count = key.iter().filter(|k| k.role == ColumnRole::Equality).count();
    let (action, reordered) = decide_action(ctx.indexes.as_deref(), &mut key, eq_count, &mut rationale);
    if reordered {
        rationale.push("Equality columns reordered to start with the existing index's columns so it can be dropped.".into());
    }

    let (selectivity, estimated) = estimate(&key, preds, ctx);
    let total_rows = ctx.stats.as_ref().map(|s| s.total_rows);
    let mut rec = finish(
        table,
        RecommendationKind::Composite,
        key,
        include,
        None,
        "btree",
        action,
        rationale,
        sources,
        total_rows,
        selectivity,
        estimated,
        opts,
    );
    if block.depth > 0 {
        rec.rationale.push(format!("Derived from a {} block.", block.context));
    }
    Some(rec)
}

fn trigram(table: &str, p: &Predicate, ctx: &TableContext, opts: &AdvisorOptions) -> IndexRecommendation {
    let col = p.column.column.clone();
    let existing = ctx.indexes.as_deref().and_then(|idx| {
        idx.iter()
            .find(|i| i.method.eq_ignore_ascii_case("gin") && i.definition.as_deref().map(|d| d.contains("trgm") && d.contains(&col)).unwrap_or(false))
    });
    let action = match existing {
        Some(i) => IndexAction::Covered { by_index: i.name.clone() },
        None => IndexAction::Create,
    };
    let rationale = match opts.engine {
        Engine::Postgresql => vec![
            format!("`{}` has a leading wildcard; B-tree indexes can't serve it.", p.sql),
            "A pg_trgm GIN index supports LIKE/ILIKE with arbitrary wildcards.".into(),
        ],
        Engine::Mysql => vec![
            format!("`{}` has a leading wildcard; B-tree indexes can't serve it.", p.sql),
            "Consider a FULLTEXT index (MATCH ... AGAINST) or a reversed generated column for suffix search.".into(),
        ],
    };
    finish(
        table,
        RecommendationKind::Trigram,
        vec![IndexColumn {
            name: col,
            role: ColumnRole::Range,
            distinct_values: ctx.distinct(&p.column.column),
            descending: false,
        }],
        Vec::new(),
        None,
        if opts.engine == Engine::Postgresql { "gin" } else { "fulltext" },
        action,
        rationale,
        vec![p.sql.clone()],
        ctx.stats.as_ref().map(|s| s.total_rows),
        None,
        None,
        opts,
    )
}

fn expression(table: &str, p: &Predicate, ctx: &TableContext, opts: &AdvisorOptions) -> Option<IndexRecommendation> {
    let func = p.function.as_deref()?;
    // Date wrappers are fixed by the range rewrite instead; casts and arithmetic
    // are better fixed in the query than with an expression index.
    let plain_function = func.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !plain_function || matches!(func, "year" | "date" | "date_part" | "date_trunc" | "cast" | "collate") {
        return None;
    }
    let target = p.target_sql.clone()?;
    if target.contains('$') || target.contains('?') {
        return None; // normalized statement text: the expression isn't concrete
    }
    if opts.engine == Engine::Mysql && func == "ilike" {
        return None;
    }
    let expr = if func == "ilike" {
        format!("lower({})", p.column.column)
    } else {
        target
    };
    let existing = ctx.indexes.as_deref().and_then(|idx| {
        idx.iter().find(|i| {
            i.has_expressions
                && i.definition
                    .as_deref()
                    .map(|d| d.replace(' ', "").to_lowercase().contains(&expr.replace(' ', "").to_lowercase()))
                    .unwrap_or(false)
        })
    });
    let action = match existing {
        Some(i) => IndexAction::Covered { by_index: i.name.clone() },
        None => IndexAction::Create,
    };
    let mut rationale = vec![format!(
        "`{}` filters on an expression, so only an index on exactly `{}` can serve it.",
        p.sql, expr
    )];
    if func == "ilike" {
        rationale.push("Rewrite `col ILIKE 'x%'` as `lower(col) LIKE lower('x%')` to use this index.".into());
    }
    Some(finish(
        table,
        RecommendationKind::Expression,
        vec![IndexColumn {
            name: p.column.column.clone(),
            role: ColumnRole::Equality,
            distinct_values: ctx.distinct(&p.column.column),
            descending: false,
        }],
        Vec::new(),
        Some(expr),
        "btree",
        action,
        rationale,
        vec![p.sql.clone()],
        ctx.stats.as_ref().map(|s| s.total_rows),
        None,
        None,
        opts,
    ))
}

fn join_keys(
    block: &SelectBlock,
    tables: &TableContexts,
    opts: &AdvisorOptions,
    so_far: &[IndexRecommendation],
) -> Vec<IndexRecommendation> {
    let mut out: Vec<IndexRecommendation> = Vec::new();
    let real: HashSet<String> = block.real_tables().map(|t| t.name.clone()).collect();
    for j in &block.joins {
        if j.kind == JoinKind::Cross {
            continue;
        }
        let mut sides: Vec<&ColumnRef> = Vec::new();
        match (j.kind, &j.joined_table) {
            // Only the nullable side of an outer join is probed.
            (JoinKind::Left, Some(t)) => sides.extend([&j.left, &j.right].into_iter().filter(|c| c.table.as_ref() == Some(t))),
            (JoinKind::Right, Some(t)) => sides.extend([&j.left, &j.right].into_iter().filter(|c| c.table.as_ref() != Some(t))),
            _ => sides.extend([&j.left, &j.right]),
        }
        for c in sides {
            let Some(table) = c.table.clone() else { continue };
            if !real.contains(&table) {
                continue;
            }
            // Already led by this column in a composite recommendation?
            let led = so_far.iter().chain(out.iter()).any(|r| {
                r.table == table
                    && r.kind != RecommendationKind::Trigram
                    && r.key_columns.first().map(|k| k.name == c.column).unwrap_or(false)
            });
            if led {
                continue;
            }
            let ctx = tables.get(&table).cloned().unwrap_or_default();
            let mut key = vec![IndexColumn {
                name: c.column.clone(),
                role: ColumnRole::Join,
                distinct_values: ctx.distinct(&c.column),
                descending: false,
            }];
            let other = if c == &j.left { &j.right } else { &j.left };
            let mut rationale = vec![format!(
                "Join key `{}` = `{}` ({:?} join): an index lets the planner probe {} per outer row (nested loop) \
                 instead of hashing or scanning it.",
                c,
                other,
                j.kind,
                bare_name(&table)
            )];
            let (action, _) = decide_action(ctx.indexes.as_deref(), &mut key, 1, &mut rationale);
            let total = ctx.stats.as_ref().map(|s| s.total_rows);
            let mut rec = finish(
                &table,
                RecommendationKind::JoinKey,
                key,
                Vec::new(),
                None,
                "btree",
                action,
                rationale,
                vec![j.sql.clone()],
                total,
                ctx.distinct(&c.column).map(|d| 1.0 / d as f64),
                ctx.distinct(&c.column).and_then(|d| total.map(|t| (t / d.max(1)).max(1))),
                opts,
            );
            if matches!(j.kind, JoinKind::Left) {
                rec.rationale.push("Unindexed foreign keys on the nullable side of LEFT JOINs are a common hotspot.".into());
            }
            out.push(rec);
        }
    }
    out
}

/// Compare the proposed key with existing indexes. May reorder equality
/// columns so that an existing narrower index becomes a strict prefix.
fn decide_action(
    existing: Option<&[IndexMetadata]>,
    key: &mut [IndexColumn],
    eq_count: usize,
    rationale: &mut Vec<String>,
) -> (IndexAction, bool) {
    let Some(existing) = existing else {
        rationale.push("Existing indexes unknown (no database connection) — verify before creating.".into());
        return (IndexAction::Create, false);
    };
    let names: Vec<String> = key.iter().map(|k| k.name.to_lowercase()).collect();
    let eq_set: HashSet<&str> = names[..eq_count].iter().map(|s| s.as_str()).collect();
    let comparable = |i: &&IndexMetadata| {
        !i.is_partial && !i.has_expressions && (i.method.is_empty() || i.method.eq_ignore_ascii_case("btree"))
    };

    // Covered: existing starts with the proposed key (equality block may be permuted).
    for idx in existing.iter().filter(comparable) {
        let e: Vec<String> = idx.columns.iter().map(|c| c.to_lowercase()).collect();
        if e.len() < names.len() {
            continue;
        }
        let head: HashSet<&str> = e[..eq_count].iter().map(|s| s.as_str()).collect();
        if head == eq_set && e[eq_count..names.len()] == names[eq_count..] {
            rationale.push(format!(
                "Existing index `{}` ({}) already starts with these columns.",
                idx.name,
                idx.columns.join(", ")
            ));
            return (IndexAction::Covered { by_index: idx.name.clone() }, false);
        }
    }

    // Replace: an existing non-unique index is a strict prefix of the proposal.
    let mut best: Option<(&IndexMetadata, bool)> = None;
    for idx in existing.iter().filter(comparable) {
        let e: Vec<String> = idx.columns.iter().map(|c| c.to_lowercase()).collect();
        if e.is_empty() || e.len() >= names.len() {
            continue;
        }
        let n = e.len();
        let (is_prefix, needs_reorder) = if n <= eq_count {
            let all_eq = e.iter().all(|c| eq_set.contains(c.as_str()));
            (all_eq, all_eq && names[..n] != e[..])
        } else {
            let head: HashSet<&str> = e[..eq_count].iter().map(|s| s.as_str()).collect();
            (head == eq_set && e[eq_count..] == names[eq_count..n], names[..eq_count] != e[..eq_count])
        };
        if is_prefix && best.map(|(b, _)| b.columns.len() < n).unwrap_or(true) {
            best = Some((idx, needs_reorder));
        }
    }
    if let Some((idx, reorder)) = best {
        if reorder {
            let e: Vec<String> = idx.columns.iter().map(|c| c.to_lowercase()).collect();
            let eq_part = &mut key[..eq_count];
            eq_part.sort_by_key(|k| e.iter().position(|c| *c == k.name.to_lowercase()).unwrap_or(usize::MAX));
        }
        if idx.is_unique || idx.is_primary {
            rationale.push(format!(
                "`{}` is a prefix of this index but enforces uniqueness, so it is kept.",
                idx.name
            ));
            return (IndexAction::Create, reorder);
        }
        rationale.push(format!(
            "Existing index `{}` ({}) is a prefix of the proposal; the wider index serves every query the old one \
             did, so replace it instead of adding a duplicate.",
            idx.name,
            idx.columns.join(", ")
        ));
        return (IndexAction::Replace { drop_index: idx.name.clone() }, reorder);
    }

    let partial: Vec<String> = existing
        .iter()
        .filter(comparable)
        .filter(|i| i.columns.first().map(|c| names.first() == Some(&c.to_lowercase())).unwrap_or(false))
        .map(|i| format!("`{}` ({})", i.name, i.columns.join(", ")))
        .collect();
    if !partial.is_empty() {
        rationale.push(format!(
            "Partially served today by {}, which only matches the leading column.",
            partial.join(", ")
        ));
    }
    (IndexAction::Create, false)
}

fn estimate(key: &[IndexColumn], preds: &[&Predicate], ctx: &TableContext) -> (Option<f64>, Option<u64>) {
    let Some(total) = ctx.stats.as_ref().map(|s| s.total_rows) else {
        return (None, None);
    };
    let mut sel = 1.0f64;
    let mut any = false;
    for k in key {
        let Some(p) = preds.iter().find(|p| p.column.column == k.name) else {
            continue;
        };
        let d = ctx.distinct(&k.name).map(|d| d as f64);
        let s = match p.kind {
            PredicateKind::Equality | PredicateKind::InSubquery => d.map(|d| 1.0 / d),
            PredicateKind::IsNull => Some(ctx.null_fraction(&k.name).unwrap_or(0.05)),
            PredicateKind::InList => d.map(|d| (p.value_count.unwrap_or(3) as f64 / d).min(1.0)),
            PredicateKind::Range => Some(1.0 / 3.0),
            PredicateKind::PrefixLike => Some(0.05),
            _ => None,
        };
        if let Some(s) = s {
            sel *= s;
            any = true;
        }
    }
    if !any {
        return (None, None);
    }
    (Some(sel), Some(((total as f64) * sel).ceil().max(1.0) as u64))
}

#[allow(clippy::too_many_arguments)]
fn finish(
    table: &str,
    kind: RecommendationKind,
    key: Vec<IndexColumn>,
    include: Vec<String>,
    expression: Option<String>,
    method: &str,
    action: IndexAction,
    rationale: Vec<String>,
    sources: Vec<String>,
    total_rows: Option<u64>,
    selectivity: Option<f64>,
    estimated_rows: Option<u64>,
    opts: &AdvisorOptions,
) -> IndexRecommendation {
    let suffix = match kind {
        RecommendationKind::Trigram => "_trgm",
        RecommendationKind::Expression => "_expr",
        _ => "",
    };
    let index_name = index_name(table, &key.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(), suffix);
    let (ddl, rollback) = ddl(table, &index_name, kind, &key, &include, expression.as_deref(), &action, opts);
    let severity = match &action {
        IndexAction::Covered { .. } => Severity::Info,
        _ => match total_rows {
            Some(r) if r >= 1_000_000 => Severity::Critical,
            Some(r) if r >= 100_000 => Severity::High,
            Some(r) if r >= 10_000 => Severity::Warning,
            Some(_) => Severity::Info,
            None => Severity::Warning,
        },
    };
    // Composite and join-key proposals with the same columns are the same physical index.
    let kind_tag = match kind {
        RecommendationKind::Composite | RecommendationKind::JoinKey => "btree",
        RecommendationKind::Trigram => "trgm",
        RecommendationKind::Expression => "expr",
    };
    let id = format!(
        "{:08x}",
        fnv(&format!(
            "{table}|{kind_tag}|{}|{}|{}",
            key.iter().map(|k| k.name.as_str()).collect::<Vec<_>>().join(","),
            include.join(","),
            expression.clone().unwrap_or_default()
        ))
    );
    IndexRecommendation {
        id,
        table: table.to_string(),
        kind,
        key_columns: key,
        include_columns: include,
        expression,
        method: method.to_string(),
        action,
        index_name,
        ddl,
        rollback_ddl: rollback,
        rationale,
        source_predicates: sources,
        severity,
        total_rows,
        selectivity,
        estimated_rows,
        rule_ids: Vec::new(),
        cost_before: None,
        cost_after: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn ddl(
    table: &str,
    name: &str,
    kind: RecommendationKind,
    key: &[IndexColumn],
    include: &[String],
    expression: Option<&str>,
    action: &IndexAction,
    opts: &AdvisorOptions,
) -> (Vec<String>, Vec<String>) {
    if let IndexAction::Covered { .. } = action {
        return (Vec::new(), Vec::new());
    }
    let schema_prefix = table.rsplit_once('.').map(|(s, _)| format!("{}.", quote(s, opts.engine))).unwrap_or_default();
    let qtable = table.split('.').map(|p| quote(p, opts.engine)).collect::<Vec<_>>().join(".");
    let cols = key
        .iter()
        .map(|k| format!("{}{}", quote(&k.name, opts.engine), if k.descending { " DESC" } else { "" }))
        .collect::<Vec<_>>()
        .join(", ");
    let mut ddl = Vec::new();
    let mut rollback = Vec::new();
    match opts.engine {
        Engine::Postgresql => {
            let conc = if opts.concurrently { "CONCURRENTLY " } else { "" };
            let body = match kind {
                RecommendationKind::Trigram => {
                    ddl.push("CREATE EXTENSION IF NOT EXISTS pg_trgm;".to_string());
                    format!("USING gin ({} gin_trgm_ops)", quote(&key[0].name, opts.engine))
                }
                RecommendationKind::Expression => format!("(({}))", expression.unwrap_or(&cols)),
                _ => {
                    let inc = if include.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " INCLUDE ({})",
                            include.iter().map(|c| quote(c, opts.engine)).collect::<Vec<_>>().join(", ")
                        )
                    };
                    format!("({cols}){inc}")
                }
            };
            ddl.push(format!("CREATE INDEX {conc}IF NOT EXISTS {} ON {qtable} {body};", quote(name, opts.engine)));
            if let IndexAction::Replace { drop_index } = action {
                ddl.push(format!(
                    "DROP INDEX {conc}IF EXISTS {schema_prefix}{};",
                    quote(drop_index, opts.engine)
                ));
            }
            rollback.push(format!("DROP INDEX {conc}IF EXISTS {schema_prefix}{};", quote(name, opts.engine)));
        }
        Engine::Mysql => {
            let body = match kind {
                RecommendationKind::Trigram => format!("ADD FULLTEXT INDEX {} ({cols})", quote(name, opts.engine)),
                RecommendationKind::Expression => {
                    format!("ADD INDEX {} (({}))", quote(name, opts.engine), expression.unwrap_or(&cols))
                }
                _ => format!("ADD INDEX {} ({cols})", quote(name, opts.engine)),
            };
            let drop = match action {
                IndexAction::Replace { drop_index } => format!("DROP INDEX {}, ", quote(drop_index, opts.engine)),
                _ => String::new(),
            };
            ddl.push(format!("ALTER TABLE {qtable} {drop}{body}, ALGORITHM=INPLACE, LOCK=NONE;"));
            rollback.push(format!("ALTER TABLE {qtable} DROP INDEX {};", quote(name, opts.engine)));
        }
    }
    (ddl, rollback)
}

fn index_name(table: &str, cols: &[&str], suffix: &str) -> String {
    let base = format!("idx_{}_{}{}", bare_name(table), cols.join("_"), suffix)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c.to_ascii_lowercase() } else { '_' })
        .collect::<String>();
    if base.len() <= 63 {
        return base;
    }
    format!("{}_{:08x}", &base[..54], fnv(&base))
}

const PG_RESERVED: &[&str] = &[
    "all", "analyse", "analyze", "and", "any", "array", "as", "asc", "both", "case", "cast", "check", "collate",
    "column", "constraint", "create", "default", "desc", "distinct", "do", "else", "end", "except", "false", "for",
    "foreign", "from", "grant", "group", "having", "in", "into", "leading", "limit", "not", "null", "offset", "on",
    "only", "or", "order", "primary", "references", "select", "table", "then", "to", "true", "union", "unique",
    "user", "using", "when", "where", "with", "window", "key", "index",
];

fn quote(ident: &str, engine: Engine) -> String {
    let simple = ident
        .chars()
        .enumerate()
        .all(|(i, c)| c == '_' || c.is_ascii_lowercase() || (i > 0 && c.is_ascii_digit()));
    if simple && !PG_RESERVED.contains(&ident) {
        return ident.to_string();
    }
    match engine {
        Engine::Postgresql => format!("\"{}\"", ident.replace('"', "\"\"")),
        Engine::Mysql => format!("`{}`", ident.replace('`', "``")),
    }
}

fn fnv(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in s.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

pub fn fmt_count(n: u64) -> String {
    match n {
        n if n >= 1_000_000 => format!("{:.1}M", n as f64 / 1e6),
        n if n >= 10_000 => format!("{:.0}K", n as f64 / 1e3),
        n if n >= 1_000 => format!("{:.1}K", n as f64 / 1e3),
        n => n.to_string(),
    }
}

/// Fold `other` (same physical index) into `into`.
pub fn merge_into(into: &mut IndexRecommendation, other: IndexRecommendation) {
    if into.kind == RecommendationKind::JoinKey && other.kind == RecommendationKind::Composite {
        into.kind = RecommendationKind::Composite;
    }
    into.severity = into.severity.max(other.severity);
    for (dst, src) in [
        (&mut into.source_predicates, other.source_predicates),
        (&mut into.rationale, other.rationale),
        (&mut into.rule_ids, other.rule_ids),
    ] {
        for item in src {
            if !dst.contains(&item) {
                dst.push(item);
            }
        }
    }
}

/// Merge identical recommendations coming from several blocks.
fn dedupe(recs: Vec<IndexRecommendation>) -> Vec<IndexRecommendation> {
    let mut out: Vec<IndexRecommendation> = Vec::new();
    for r in recs {
        if let Some(existing) = out.iter_mut().find(|o| o.id == r.id) {
            merge_into(existing, r);
            continue;
        }
        out.push(r);
    }
    // A composite whose key is a strict prefix of another composite on the same table is redundant.
    let snapshot = out.clone();
    out.retain(|r| {
        if r.kind != RecommendationKind::Composite && r.kind != RecommendationKind::JoinKey {
            return true;
        }
        let names: Vec<&str> = r.key_columns.iter().map(|k| k.name.as_str()).collect();
        !snapshot.iter().any(|o| {
            o.id != r.id
                && o.table == r.table
                && o.kind == RecommendationKind::Composite
                && o.key_columns.len() > names.len()
                && o.key_columns.iter().take(names.len()).map(|k| k.name.as_str()).eq(names.iter().copied())
        })
    });
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.table.cmp(&b.table)));
    out
}
