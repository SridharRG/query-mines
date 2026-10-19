//! Static anti-pattern detection and AST rewrites.
//!
//! Rewrites operate on a clone of the parsed statement and are rendered back
//! to SQL with sqlparser's pretty printer. Each rewrite is conservative: when
//! a transformation could change semantics in a way we can't verify it is
//! reported as a finding without being applied.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use chrono::{Datelike, NaiveDate};
use serde::Serialize;
use sqlparser::ast::*;

use crate::facts::{norm_ident, norm_object_name, JoinKind, PredicateKind, QueryFacts};
use crate::model::{Engine, Severity};

#[derive(Debug, Clone, Serialize)]
pub struct RewriteFinding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    /// The offending SQL fragment.
    pub fragment: Option<String>,
    /// What the fragment was (or should be) replaced with.
    pub replacement: Option<String>,
    pub applied: bool,
    pub caveat: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RewriteResult {
    pub findings: Vec<RewriteFinding>,
    pub rewritten_sql: Option<String>,
}

pub fn rewrite(statement: &Statement, facts: &QueryFacts, engine: Engine) -> RewriteResult {
    let mut findings = Vec::new();
    let mut stmt = statement.clone();
    let mut changed = false;

    // 1. Date functions on columns → half-open ranges.
    let mut dates = DateRangeRewriter::default();
    let _ = VisitMut::visit(&mut stmt, &mut dates);
    for (from, to) in dates.applied {
        changed = true;
        findings.push(RewriteFinding {
            id: "RW_DATE_FUNCTION_RANGE".into(),
            title: "Function on indexed date column".into(),
            severity: Severity::High,
            description: "Wrapping the column in a date function hides it from B-tree indexes. A half-open range \
                          on the raw column is equivalent and SARGable."
                .into(),
            fragment: Some(from),
            replacement: Some(to),
            applied: true,
            caveat: None,
        });
    }

    // 2. IN / NOT IN (subquery) → EXISTS / NOT EXISTS.
    if let Statement::Query(q) = &mut stmt {
        let mut out = Vec::new();
        rewrite_in_subqueries_query(q, &mut out);
        if !out.is_empty() {
            changed = true;
        }
        findings.extend(out);
    }

    // 3. OR across different columns → UNION ALL (top-level SELECT only).
    if let Statement::Query(q) = &mut stmt {
        match or_to_union_all(q) {
            OrRewrite::Applied { fragment, branches } => {
                changed = true;
                findings.push(RewriteFinding {
                    id: "RW_OR_TO_UNION_ALL".into(),
                    title: "OR across different columns".into(),
                    severity: Severity::Warning,
                    description: format!(
                        "An OR spanning different columns usually prevents a single index range scan. Split into \
                         {branches} UNION ALL branches so each branch can use its own index; later branches exclude \
                         rows already returned with `IS NOT TRUE`, so no duplicates are introduced."
                    ),
                    fragment: Some(fragment),
                    replacement: None,
                    applied: true,
                    caveat: Some(match engine {
                        Engine::Postgresql => "PostgreSQL can often combine indexes with a BitmapOr on its own; keep \
                                               the rewrite only if EXPLAIN still shows a Seq Scan."
                            .into(),
                        Engine::Mysql => "MySQL's index_merge union may already handle simple cases; compare plans."
                            .into(),
                    }),
                });
            }
            OrRewrite::Skipped { fragment, reason } => findings.push(RewriteFinding {
                id: "RW_OR_TO_UNION_ALL".into(),
                title: "OR across different columns".into(),
                severity: Severity::Warning,
                description: "An OR spanning different columns usually prevents a single index range scan. Consider \
                              UNION ALL branches with one index each."
                    .into(),
                fragment: Some(fragment),
                replacement: None,
                applied: false,
                caveat: Some(reason),
            }),
            OrRewrite::NotFound => {}
        }
    }

    detect_flags(facts, engine, &mut findings);

    let rewritten_sql = changed.then(|| format!("{stmt:#}"));
    RewriteResult {
        findings,
        rewritten_sql,
    }
}

// ---------------------------------------------------------------------------
// Static flags (no rewrite).

fn detect_flags(facts: &QueryFacts, engine: Engine, out: &mut Vec<RewriteFinding>) {
    let mut seen: HashSet<String> = HashSet::new();
    let mut push = |f: RewriteFinding, out: &mut Vec<RewriteFinding>| {
        let key = format!("{}|{}", f.id, f.fragment.clone().unwrap_or_default());
        if seen.insert(key) {
            out.push(f);
        }
    };

    for block in &facts.blocks {
        let real_tables = block.real_tables().count();
        if block.select_star {
            let mut cols: Vec<String> = block.referenced.iter().map(|c| c.to_string()).collect();
            cols.sort();
            push(
                RewriteFinding {
                    id: "RW_SELECT_STAR".into(),
                    title: "SELECT * projection".into(),
                    severity: if real_tables > 1 { Severity::Warning } else { Severity::Info },
                    description: format!(
                        "SELECT * fetches every column{}, defeats index-only scans and widens sort/hash memory. \
                         Columns this query actually references: {}.",
                        if real_tables > 1 { " of every joined table" } else { "" },
                        if cols.is_empty() { "(none besides the projection)".into() } else { cols.join(", ") }
                    ),
                    fragment: Some("SELECT *".into()),
                    replacement: None,
                    applied: false,
                    caveat: Some("Project only the columns the caller reads.".into()),
                },
                out,
            );
        }

        for p in &block.predicates {
            match p.kind {
                PredicateKind::LeadingWildcard => push(
                    RewriteFinding {
                        id: "RW_LEADING_WILDCARD".into(),
                        title: "Leading wildcard in LIKE".into(),
                        severity: Severity::Warning,
                        description: format!(
                            "`{}` starts with a wildcard, so a B-tree index on {} cannot be used.",
                            p.sql, p.column
                        ),
                        fragment: Some(p.sql.clone()),
                        replacement: None,
                        applied: false,
                        caveat: Some(match engine {
                            Engine::Postgresql => "Use a pg_trgm GIN index, or store a reversed column for suffix \
                                                   searches."
                                .into(),
                            Engine::Mysql => "Use a FULLTEXT index or a reversed generated column for suffix \
                                              searches."
                                .into(),
                        }),
                    },
                    out,
                ),
                PredicateKind::FunctionWrapped if !is_date_function(p.function.as_deref()) => push(
                    RewriteFinding {
                        id: "RW_NON_SARGABLE_FUNCTION".into(),
                        title: "Function applied to a filtered column".into(),
                        severity: Severity::Warning,
                        description: format!(
                            "`{}` applies {} to {}, which hides the column from plain indexes.",
                            p.sql,
                            p.function.clone().unwrap_or_else(|| "an expression".into()),
                            p.column
                        ),
                        fragment: Some(p.sql.clone()),
                        replacement: None,
                        applied: false,
                        caveat: Some(
                            "Compare the raw column instead, or create an expression index matching the exact \
                             expression."
                                .into(),
                        ),
                    },
                    out,
                ),
                PredicateKind::NotEqual | PredicateKind::NotIn => push(
                    RewriteFinding {
                        id: "RW_NEGATIVE_PREDICATE".into(),
                        title: "Negative predicate".into(),
                        severity: Severity::Info,
                        description: format!(
                            "`{}` matches most of the table, so it is evaluated as a filter, not an index condition.",
                            p.sql
                        ),
                        fragment: Some(p.sql.clone()),
                        replacement: None,
                        applied: false,
                        caveat: None,
                    },
                    out,
                ),
                _ => {}
            }
        }

        if let Some(offset) = block.offset {
            if offset >= 1000 {
                push(
                    RewriteFinding {
                        id: "RW_LARGE_OFFSET".into(),
                        title: "Deep OFFSET pagination".into(),
                        severity: Severity::Warning,
                        description: format!(
                            "OFFSET {offset} reads and discards {offset} rows on every page. Keyset pagination \
                             (`WHERE (sort_col, id) > (:last_sort, :last_id)`) stays constant-time."
                        ),
                        fragment: Some(format!("OFFSET {offset}")),
                        replacement: None,
                        applied: false,
                        caveat: None,
                    },
                    out,
                );
            }
        }

        // Cartesian products: tables in the block not connected by any join key.
        if real_tables > 1 {
            let names: Vec<String> = block.tables.iter().map(|t| t.name.clone()).collect();
            let mut parent: HashMap<String, String> = names.iter().map(|n| (n.clone(), n.clone())).collect();
            fn find(p: &mut HashMap<String, String>, x: &str) -> String {
                let px = p.get(x).cloned().unwrap_or_else(|| x.to_string());
                if px == x {
                    return px;
                }
                let r = find(p, &px);
                p.insert(x.to_string(), r.clone());
                r
            }
            for j in &block.joins {
                if let (Some(a), Some(b)) = (&j.left.table, &j.right.table) {
                    if parent.contains_key(a) && parent.contains_key(b) {
                        let ra = find(&mut parent, a);
                        let rb = find(&mut parent, b);
                        parent.insert(ra, rb);
                    }
                }
            }
            let roots: HashSet<String> = names.iter().map(|n| find(&mut parent, n)).collect();
            let has_cross = block.joins.iter().any(|j| j.kind == JoinKind::Cross);
            if roots.len() > 1 && !has_cross && block.or_groups.is_empty() {
                push(
                    RewriteFinding {
                        id: "RW_CARTESIAN_PRODUCT".into(),
                        title: "Possible Cartesian product".into(),
                        severity: Severity::High,
                        description: format!(
                            "No equality join links all of: {}. Every row of one side is paired with every row of \
                             the other.",
                            names.join(", ")
                        ),
                        fragment: None,
                        replacement: None,
                        applied: false,
                        caveat: Some("Add the missing join condition, or use an explicit CROSS JOIN if intended.".into()),
                    },
                    out,
                );
            }
        }

        if block.distinct && !block.joins.is_empty() {
            push(
                RewriteFinding {
                    id: "RW_DISTINCT_ON_JOIN".into(),
                    title: "DISTINCT used over a join".into(),
                    severity: Severity::Info,
                    description: "DISTINCT after a join often hides row fan-out. If the joined table only filters, \
                                  an EXISTS semi-join avoids producing and then de-duplicating the extra rows."
                        .into(),
                    fragment: Some("SELECT DISTINCT".into()),
                    replacement: None,
                    applied: false,
                    caveat: None,
                },
                out,
            );
        }

        if (block.context == "update" || block.context == "delete") && block.predicates.is_empty() && block.joins.is_empty()
        {
            push(
                RewriteFinding {
                    id: "RW_UNBOUNDED_DML".into(),
                    title: format!("{} without WHERE", block.context.to_uppercase()),
                    severity: Severity::Critical,
                    description: "This statement touches every row of the table.".into(),
                    fragment: None,
                    replacement: None,
                    applied: false,
                    caveat: Some("Batch large changes by primary-key ranges to limit lock time and WAL volume.".into()),
                },
                out,
            );
        }
    }

    if facts.order_by_random {
        push(
            RewriteFinding {
                id: "RW_ORDER_BY_RANDOM".into(),
                title: "ORDER BY random()".into(),
                severity: Severity::Warning,
                description: "Sorting by a random value reads and sorts the full result set. Sample with \
                              TABLESAMPLE or pick random ids from a known key range instead."
                    .into(),
                fragment: Some("ORDER BY random()".into()),
                replacement: None,
                applied: false,
                caveat: None,
            },
            out,
        );
    }

    if facts.recursive_cte {
        push(
            RewriteFinding {
                id: "RW_RECURSIVE_CTE".into(),
                title: "Recursive CTE".into(),
                severity: Severity::Info,
                description: "Recursive CTEs execute iteratively; make sure the recursive join column is indexed \
                              and the recursion has a depth bound. The AI layer can propose structural rewrites."
                    .into(),
                fragment: None,
                replacement: None,
                applied: false,
                caveat: None,
            },
            out,
        );
    }
}

fn is_date_function(f: Option<&str>) -> bool {
    matches!(
        f,
        Some("year") | Some("date") | Some("date_part") | Some("extract(YEAR)") | Some("cast") | Some("date_trunc")
    )
}

// ---------------------------------------------------------------------------
// Date function → range.

#[derive(Default)]
struct DateRangeRewriter {
    applied: Vec<(String, String)>,
}

impl VisitorMut for DateRangeRewriter {
    type Break = ();

    fn post_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
        if let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = expr
        {
            let replacement = date_equality_range(left, right).or_else(|| date_equality_range(right, left));
            if let Some(new) = replacement {
                let from = expr.to_string();
                let to = new.to_string();
                *expr = Expr::Nested(Box::new(new));
                self.applied.push((from, to));
            }
        }
        ControlFlow::Continue(())
    }
}

/// `YEAR(col) = 2026`, `EXTRACT(YEAR FROM col) = 2026`, `date_part('year', col) = 2026`,
/// `DATE(col) = '2026-01-05'`, `col::date = '2026-01-05'`
fn date_equality_range(func_side: &Expr, value_side: &Expr) -> Option<Expr> {
    let (unit, column) = date_function_target(func_side)?;
    let (start, end) = match unit {
        DateUnit::Year => {
            let year: i32 = literal_number(value_side)?;
            if !(1..=9998).contains(&year) {
                return None;
            }
            (
                NaiveDate::from_ymd_opt(year, 1, 1)?,
                NaiveDate::from_ymd_opt(year + 1, 1, 1)?,
            )
        }
        DateUnit::Day => {
            let d = NaiveDate::parse_from_str(&literal_string(value_side)?, "%Y-%m-%d").ok()?;
            (d, d.succ_opt()?)
        }
    };
    let _ = start.year();
    let lit = |d: NaiveDate| Expr::Value(Value::SingleQuotedString(d.format("%Y-%m-%d").to_string()).with_empty_span());
    Some(Expr::BinaryOp {
        left: Box::new(Expr::BinaryOp {
            left: Box::new(column.clone()),
            op: BinaryOperator::GtEq,
            right: Box::new(lit(start)),
        }),
        op: BinaryOperator::And,
        right: Box::new(Expr::BinaryOp {
            left: Box::new(column),
            op: BinaryOperator::Lt,
            right: Box::new(lit(end)),
        }),
    })
}

enum DateUnit {
    Year,
    Day,
}

fn is_column(e: &Expr) -> bool {
    matches!(e, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
}

fn date_function_target(e: &Expr) -> Option<(DateUnit, Expr)> {
    match e {
        Expr::Function(f) => {
            let name = f.name.to_string().to_lowercase();
            let args: Vec<&Expr> = match &f.args {
                FunctionArguments::List(l) => l
                    .args
                    .iter()
                    .filter_map(|a| match a {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => Some(e),
                        _ => None,
                    })
                    .collect(),
                _ => return None,
            };
            match (name.as_str(), args.as_slice()) {
                ("year", [col]) if is_column(col) => Some((DateUnit::Year, (*col).clone())),
                ("date", [col]) if is_column(col) => Some((DateUnit::Day, (*col).clone())),
                ("date_part", [unit, col]) if is_column(col) => {
                    (literal_string(unit)?.eq_ignore_ascii_case("year")).then(|| (DateUnit::Year, (*col).clone()))
                }
                _ => None,
            }
        }
        Expr::Extract { field, expr, .. } if is_column(expr) => {
            matches!(field, DateTimeField::Year).then(|| (DateUnit::Year, (**expr).clone()))
        }
        Expr::Cast { expr, data_type, .. } if is_column(expr) => {
            matches!(data_type, DataType::Date).then(|| (DateUnit::Day, (**expr).clone()))
        }
        Expr::Nested(inner) => date_function_target(inner),
        _ => None,
    }
}

fn literal_number(e: &Expr) -> Option<i32> {
    match e {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.to_string().parse().ok(),
            Value::SingleQuotedString(s) => s.parse().ok(),
            _ => None,
        },
        _ => None,
    }
}

fn literal_string(e: &Expr) -> Option<String> {
    match e {
        Expr::Value(v) => match &v.value {
            Value::SingleQuotedString(s) | Value::DoubleQuotedString(s) => Some(s.clone()),
            _ => None,
        },
        Expr::TypedString(ts) => match &ts.value.value {
            Value::SingleQuotedString(s) => Some(s.clone()),
            _ => None,
        },
        Expr::Cast { expr, .. } => literal_string(expr),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// IN / NOT IN (subquery) → EXISTS / NOT EXISTS

fn rewrite_in_subqueries_query(q: &mut Query, out: &mut Vec<RewriteFinding>) {
    if let Some(with) = &mut q.with {
        for cte in &mut with.cte_tables {
            rewrite_in_subqueries_query(&mut cte.query, out);
        }
    }
    rewrite_in_subqueries_set(&mut q.body, out);
}

fn rewrite_in_subqueries_set(body: &mut SetExpr, out: &mut Vec<RewriteFinding>) {
    match body {
        SetExpr::Select(s) => rewrite_in_subqueries_select(s, out),
        SetExpr::Query(q) => rewrite_in_subqueries_query(q, out),
        SetExpr::SetOperation { left, right, .. } => {
            rewrite_in_subqueries_set(left, out);
            rewrite_in_subqueries_set(right, out);
        }
        _ => {}
    }
}

fn split_and(e: Expr, out: &mut Vec<Expr>) {
    match e {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            split_and(*left, out);
            split_and(*right, out);
        }
        other => out.push(other),
    }
}

fn join_and(mut parts: Vec<Expr>) -> Option<Expr> {
    if parts.is_empty() {
        return None;
    }
    let first = parts.remove(0);
    Some(parts.into_iter().fold(first, |acc, e| Expr::BinaryOp {
        left: Box::new(acc),
        op: BinaryOperator::And,
        right: Box::new(e),
    }))
}

/// The single table of a FROM clause as (name, qualifier to use).
fn single_from_table(s: &Select) -> Option<(String, String)> {
    if s.from.len() != 1 || !s.from[0].joins.is_empty() {
        return None;
    }
    match &s.from[0].relation {
        TableFactor::Table { name, alias, .. } => {
            let n = norm_object_name(name);
            let q = alias.as_ref().map(|a| a.name.to_string()).unwrap_or_else(|| name.to_string());
            Some((n, q))
        }
        _ => None,
    }
}

fn select_qualifiers(s: &Select) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut add = |f: &TableFactor| {
        if let TableFactor::Table { name, alias, .. } = f {
            out.insert(norm_object_name(name));
            if let Some(last) = name.0.last().and_then(|p| p.as_ident()) {
                out.insert(norm_ident(last));
            }
            if let Some(a) = alias {
                out.insert(norm_ident(&a.name));
            }
        }
    };
    for twj in &s.from {
        add(&twj.relation);
        for j in &twj.joins {
            add(&j.relation);
        }
    }
    out
}

fn rewrite_in_subqueries_select(s: &mut Select, out: &mut Vec<RewriteFinding>) {
    // Recurse into derived tables first.
    for twj in &mut s.from {
        if let TableFactor::Derived { subquery, .. } = &mut twj.relation {
            rewrite_in_subqueries_query(subquery, out);
        }
        for j in &mut twj.joins {
            if let TableFactor::Derived { subquery, .. } = &mut j.relation {
                rewrite_in_subqueries_query(subquery, out);
            }
        }
    }
    let Some(selection) = s.selection.take() else {
        return;
    };
    let outer_single = single_from_table(s);
    let outer_quals = select_qualifiers(s);
    let mut parts = Vec::new();
    split_and(selection, &mut parts);
    let mut new_parts = Vec::with_capacity(parts.len());
    for part in parts {
        match part {
            Expr::InSubquery {
                expr,
                mut subquery,
                negated,
            } => match in_to_exists(&expr, &mut subquery, negated, outer_single.as_ref(), &outer_quals) {
                Ok(exists) => {
                    let from = format!(
                        "{} {}IN ({})",
                        expr,
                        if negated { "NOT " } else { "" },
                        subquery_summary(&subquery)
                    );
                    out.push(RewriteFinding {
                        id: if negated { "RW_NOT_IN_TO_NOT_EXISTS" } else { "RW_IN_TO_EXISTS" }.into(),
                        title: if negated {
                            "NOT IN (subquery)"
                        } else {
                            "IN (subquery)"
                        }
                        .into(),
                        severity: if negated { Severity::High } else { Severity::Warning },
                        description: if negated {
                            "NOT IN against a subquery blocks anti-join planning and returns no rows at all if the \
                             subquery yields a NULL. NOT EXISTS plans as a hash/merge anti-join."
                                .into()
                        } else {
                            "A correlated EXISTS lets the planner use a semi-join and stop at the first match, and \
                             avoids materialising the subquery result."
                                .into()
                        },
                        fragment: Some(from),
                        replacement: Some(exists.to_string()),
                        applied: true,
                        caveat: negated.then(|| {
                            "Semantics differ only when the subquery column can be NULL: NOT IN would return no \
                             rows, NOT EXISTS ignores the NULLs (usually what was intended)."
                                .to_string()
                        }),
                    });
                    new_parts.push(exists);
                }
                Err(reason) => {
                    out.push(RewriteFinding {
                        id: if negated { "RW_NOT_IN_TO_NOT_EXISTS" } else { "RW_IN_TO_EXISTS" }.into(),
                        title: if negated { "NOT IN (subquery)" } else { "IN (subquery)" }.into(),
                        severity: if negated { Severity::High } else { Severity::Info },
                        description: "Consider rewriting to a correlated EXISTS / NOT EXISTS.".into(),
                        fragment: Some(format!("{} {}IN (...)", expr, if negated { "NOT " } else { "" })),
                        replacement: None,
                        applied: false,
                        caveat: Some(reason),
                    });
                    rewrite_in_subqueries_query(&mut subquery, out);
                    new_parts.push(Expr::InSubquery {
                        expr,
                        subquery,
                        negated,
                    });
                }
            },
            Expr::Exists { mut subquery, negated } => {
                rewrite_in_subqueries_query(&mut subquery, out);
                new_parts.push(Expr::Exists { subquery, negated });
            }
            other => new_parts.push(other),
        }
    }
    s.selection = join_and(new_parts);
}

fn subquery_summary(q: &Query) -> String {
    let s = q.to_string();
    if s.len() > 80 {
        format!("{}…", &s[..s.char_indices().take_while(|(i, _)| *i < 80).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0)])
    } else {
        s
    }
}

fn in_to_exists(
    outer_expr: &Expr,
    subquery: &mut Query,
    negated: bool,
    outer_single: Option<&(String, String)>,
    outer_quals: &HashSet<String>,
) -> Result<Expr, String> {
    if subquery.with.is_some() || subquery.limit_clause.is_some() || subquery.fetch.is_some() {
        return Err("subquery uses WITH/LIMIT; left unchanged".into());
    }
    let SetExpr::Select(inner) = subquery.body.as_mut() else {
        return Err("subquery is a set operation; left unchanged".into());
    };
    if inner.projection.len() != 1 {
        return Err("subquery returns more than one column".into());
    }
    if !matches!(inner.group_by, GroupByExpr::Expressions(ref v, _) if v.is_empty()) || inner.having.is_some() {
        return Err("subquery aggregates; left unchanged".into());
    }
    let inner_expr = match &inner.projection[0] {
        SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => e.clone(),
        _ => return Err("subquery projection is a wildcard".into()),
    };
    let inner_quals = select_qualifiers(inner);
    if inner_quals.is_empty() {
        return Err("subquery has no FROM table".into());
    }

    // Qualify the outer column so it cannot be captured by the inner scope.
    let outer = match outer_expr {
        Expr::Identifier(id) => {
            let (_, qual) = outer_single.ok_or_else(|| {
                "outer column is unqualified and the outer query has several tables; qualify it to enable the \
                 rewrite"
                    .to_string()
            })?;
            if inner_quals.contains(&qual.to_lowercase()) {
                return Err(format!(
                    "outer and inner queries both reference `{qual}`; add a table alias to enable the rewrite"
                ));
            }
            Expr::CompoundIdentifier(vec![Ident::new(qual.clone()), id.clone()])
        }
        Expr::CompoundIdentifier(parts) => {
            let q = parts[..parts.len() - 1].iter().map(norm_ident).collect::<Vec<_>>().join(".");
            if inner_quals.contains(&q) {
                return Err(format!(
                    "qualifier `{q}` is visible in both queries; alias the inner table to enable the rewrite"
                ));
            }
            if !outer_quals.contains(&q) {
                return Err(format!("unknown qualifier `{q}`"));
            }
            outer_expr.clone()
        }
        _ => return Err("left side of IN is an expression; left unchanged".into()),
    };

    let correlation = Expr::BinaryOp {
        left: Box::new(inner_expr),
        op: BinaryOperator::Eq,
        right: Box::new(outer),
    };
    inner.projection = vec![SelectItem::UnnamedExpr(Expr::Value(
        Value::Number("1".parse().unwrap(), false).with_empty_span(),
    ))];
    inner.distinct = None;
    inner.selection = Some(match inner.selection.take() {
        Some(w) => Expr::BinaryOp {
            left: Box::new(maybe_nest(w)),
            op: BinaryOperator::And,
            right: Box::new(correlation),
        },
        None => correlation,
    });
    subquery.order_by = None;
    Ok(Expr::Exists {
        subquery: Box::new(subquery.clone()),
        negated,
    })
}

fn maybe_nest(e: Expr) -> Expr {
    match e {
        Expr::BinaryOp {
            op: BinaryOperator::Or, ..
        } => Expr::Nested(Box::new(e)),
        other => other,
    }
}

// ---------------------------------------------------------------------------
// OR across columns → UNION ALL

enum OrRewrite {
    Applied { fragment: String, branches: usize },
    Skipped { fragment: String, reason: String },
    NotFound,
}

fn or_disjuncts(e: &Expr, out: &mut Vec<Expr>) {
    match e {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => {
            or_disjuncts(left, out);
            or_disjuncts(right, out);
        }
        Expr::Nested(inner) if matches!(**inner, Expr::BinaryOp { op: BinaryOperator::Or, .. }) => {
            or_disjuncts(inner, out)
        }
        other => out.push(other.clone()),
    }
}

/// The single column a simple predicate filters on.
fn predicate_column(e: &Expr) -> Option<String> {
    let col = |x: &Expr| match x {
        Expr::Identifier(i) => Some(norm_ident(i)),
        Expr::CompoundIdentifier(p) => Some(p.iter().map(norm_ident).collect::<Vec<_>>().join(".")),
        _ => None,
    };
    match e {
        Expr::BinaryOp { left, op, right }
            if matches!(
                op,
                BinaryOperator::Eq | BinaryOperator::Gt | BinaryOperator::Lt | BinaryOperator::GtEq | BinaryOperator::LtEq
            ) =>
        {
            match (col(left), col(right)) {
                (Some(c), None) | (None, Some(c)) => Some(c),
                _ => None,
            }
        }
        Expr::InList { expr, negated: false, .. }
        | Expr::Between { expr, negated: false, .. }
        | Expr::Like { expr, negated: false, .. }
        | Expr::IsNull(expr) => col(expr),
        Expr::Nested(inner) => predicate_column(inner),
        _ => None,
    }
}

fn or_to_union_all(q: &mut Query) -> OrRewrite {
    let SetExpr::Select(select) = q.body.as_ref() else {
        return OrRewrite::NotFound;
    };
    let Some(selection) = &select.selection else {
        return OrRewrite::NotFound;
    };
    let mut parts = Vec::new();
    split_and(selection.clone(), &mut parts);

    let mut target = None;
    for (i, p) in parts.iter().enumerate() {
        let inner = match p {
            Expr::Nested(x) => x.as_ref(),
            x => x,
        };
        if matches!(inner, Expr::BinaryOp { op: BinaryOperator::Or, .. }) {
            let mut ds = Vec::new();
            or_disjuncts(inner, &mut ds);
            let cols: Option<Vec<String>> = ds.iter().map(predicate_column).collect();
            if let Some(cols) = cols {
                let distinct: HashSet<&String> = cols.iter().collect();
                if distinct.len() >= 2 {
                    target = Some((i, ds));
                    break;
                }
            }
        }
    }
    let Some((idx, disjuncts)) = target else {
        return OrRewrite::NotFound;
    };
    let fragment = parts[idx].to_string();

    let has_aggregate = select.projection.iter().any(|item| {
        let s = item.to_string().to_lowercase();
        ["count(", "sum(", "avg(", "min(", "max("].iter().any(|a| s.contains(a))
    });
    let blockers = [
        (select.distinct.is_some(), "SELECT DISTINCT"),
        (!matches!(select.group_by, GroupByExpr::Expressions(ref v, _) if v.is_empty()), "GROUP BY"),
        (has_aggregate, "aggregate functions"),
        (q.order_by.is_some(), "ORDER BY"),
        (q.limit_clause.is_some() || q.fetch.is_some(), "LIMIT"),
        (q.with.is_some(), "WITH"),
        (disjuncts.len() > 4, "more than 4 OR branches"),
    ];
    if let Some((_, what)) = blockers.iter().find(|(b, _)| *b) {
        return OrRewrite::Skipped {
            fragment,
            reason: format!("Not rewritten automatically because the query uses {what}."),
        };
    }

    let rest: Vec<Expr> = parts.iter().enumerate().filter(|(i, _)| *i != idx).map(|(_, e)| e.clone()).collect();
    let mut branches: Vec<SetExpr> = Vec::new();
    for (i, d) in disjuncts.iter().enumerate() {
        let mut conds = rest.clone();
        conds.push(maybe_nest(d.clone()));
        for prev in &disjuncts[..i] {
            conds.push(Expr::IsNotTrue(Box::new(Expr::Nested(Box::new(prev.clone())))));
        }
        let mut s = select.as_ref().clone();
        s.selection = join_and(conds);
        branches.push(SetExpr::Select(Box::new(s)));
    }
    let count = branches.len();
    let mut iter = branches.into_iter();
    let first = iter.next().unwrap();
    let body = iter.fold(first, |acc, b| SetExpr::SetOperation {
        left: Box::new(acc),
        op: SetOperator::Union,
        set_quantifier: SetQuantifier::All,
        right: Box::new(b),
    });
    q.body = Box::new(body);
    OrRewrite::Applied {
        fragment,
        branches: count,
    }
}
