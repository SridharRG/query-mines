//! SQL → structured query facts.
//!
//! Every `SELECT` (including subqueries, CTE bodies and UNION branches) becomes
//! its own [`SelectBlock`] with its own alias scope, so predicates from
//! different blocks never get merged into one composite index.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use serde::Serialize;
use sqlparser::ast::*;
use sqlparser::dialect::{MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser;

use crate::model::Engine;
use crate::CoreError;

/// Lower-cased table name → lower-cased column names. Keys are both the
/// qualified (`public.users`) and bare (`users`) forms.
pub type SchemaCatalog = HashMap<String, Vec<String>>;

pub fn parse_sql(sql: &str, engine: Engine) -> Result<Vec<Statement>, CoreError> {
    let result = match engine {
        Engine::Postgresql => Parser::parse_sql(&PostgreSqlDialect {}, sql),
        Engine::Mysql => Parser::parse_sql(&MySqlDialect {}, sql),
    };
    let statements = result.map_err(|e| CoreError::Parse(e.to_string()))?;
    if statements.is_empty() {
        return Err(CoreError::Parse("no SQL statement found".into()));
    }
    Ok(statements)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TableRef {
    pub name: String,
    pub alias: Option<String>,
    pub is_cte: bool,
    pub is_derived: bool,
}

impl TableRef {
    pub fn is_real(&self) -> bool {
        !self.is_cte && !self.is_derived
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ColumnRef {
    pub table: Option<String>,
    pub column: String,
}

impl std::fmt::Display for ColumnRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.table {
            Some(t) => write!(f, "{t}.{}", self.column),
            None => f.write_str(&self.column),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PredicateKind {
    Equality,
    InList,
    Range,
    /// `LIKE 'abc%'` — usable as a range scan.
    PrefixLike,
    /// `LIKE '%abc'` — cannot use a B-tree.
    LeadingWildcard,
    IsNull,
    NotEqual,
    NotIn,
    /// The column is wrapped in a function/cast/expression (`lower(email) = ..`).
    FunctionWrapped,
    InSubquery,
    NotInSubquery,
}

impl PredicateKind {
    pub fn is_equality_like(self) -> bool {
        matches!(self, PredicateKind::Equality | PredicateKind::IsNull)
    }
    pub fn is_range_like(self) -> bool {
        matches!(
            self,
            PredicateKind::Range | PredicateKind::InList | PredicateKind::PrefixLike
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Predicate {
    pub column: ColumnRef,
    pub kind: PredicateKind,
    pub sargable: bool,
    /// For [`PredicateKind::FunctionWrapped`]: the wrapping function.
    pub function: Option<String>,
    /// For [`PredicateKind::FunctionWrapped`]: the wrapped expression (`lower(email)`).
    pub target_sql: Option<String>,
    /// Number of values for IN lists.
    pub value_count: Option<usize>,
    /// Compared against a column of an outer query (correlated subquery).
    pub correlated: bool,
    /// True when the predicate came from a JOIN ... ON clause.
    pub from_join: bool,
    pub sql: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JoinKind {
    Inner,
    Left,
    Right,
    Full,
    Cross,
    /// `FROM a, b WHERE a.x = b.y`
    Implicit,
    Semi,
    Anti,
}

#[derive(Debug, Clone, Serialize)]
pub struct JoinKey {
    pub kind: JoinKind,
    pub left: ColumnRef,
    pub right: ColumnRef,
    /// The table introduced by the JOIN clause (right-hand side), if known.
    pub joined_table: Option<String>,
    pub sql: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrderColumn {
    pub column: ColumnRef,
    pub descending: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SelectBlock {
    pub id: usize,
    pub depth: usize,
    /// main, subquery, derived, cte:<name>, union-branch, update, delete ...
    pub context: String,
    pub tables: Vec<TableRef>,
    pub predicates: Vec<Predicate>,
    pub joins: Vec<JoinKey>,
    pub group_by: Vec<ColumnRef>,
    pub order_by: Vec<OrderColumn>,
    pub projections: Vec<ColumnRef>,
    pub select_star: bool,
    /// Tables expanded by `t.*` (empty + select_star = bare `*`).
    pub star_tables: Vec<String>,
    pub has_aggregates: bool,
    pub distinct: bool,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    /// Columns that appear together inside one OR expression.
    pub or_groups: Vec<Vec<ColumnRef>>,
    /// Every column referenced anywhere in the block.
    pub referenced: Vec<ColumnRef>,
}

impl SelectBlock {
    pub fn real_tables(&self) -> impl Iterator<Item = &TableRef> {
        self.tables.iter().filter(|t| t.is_real())
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct QueryFacts {
    pub statement_kind: String,
    pub blocks: Vec<SelectBlock>,
    /// Distinct physical tables referenced anywhere.
    pub tables: Vec<String>,
    pub ctes: Vec<String>,
    pub recursive_cte: bool,
    pub subquery_count: usize,
    pub set_operations: usize,
    pub unresolved_columns: Vec<String>,
    pub order_by_random: bool,
    pub placeholders: usize,
}

impl QueryFacts {
    pub fn main_block(&self) -> Option<&SelectBlock> {
        self.blocks.iter().find(|b| b.depth == 0)
    }
}

/// Extract facts from the first statement of `sql`.
pub fn extract_facts(
    sql: &str,
    engine: Engine,
    catalog: Option<&SchemaCatalog>,
) -> Result<(Statement, QueryFacts), CoreError> {
    let statement = parse_sql(sql, engine)?.remove(0);
    let facts = facts_for_statement(&statement, catalog);
    Ok((statement, facts))
}

pub fn facts_for_statement(statement: &Statement, catalog: Option<&SchemaCatalog>) -> QueryFacts {
    let mut ex = Extractor {
        catalog,
        ctes: HashSet::new(),
        facts: QueryFacts::default(),
    };
    ex.statement(statement);

    let mut placeholders = PlaceholderCounter::default();
    let _ = statement.visit(&mut placeholders);
    ex.facts.placeholders = placeholders.0;

    let mut seen = HashSet::new();
    let mut tables = Vec::new();
    for b in &ex.facts.blocks {
        for t in b.real_tables() {
            if seen.insert(t.name.clone()) {
                tables.push(t.name.clone());
            }
        }
    }
    ex.facts.tables = tables;
    ex.facts.blocks.sort_by_key(|b| b.id);
    ex.facts.unresolved_columns.sort();
    ex.facts.unresolved_columns.dedup();
    ex.facts
}

// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Scope {
    tables: Vec<TableRef>,
}

impl Scope {
    fn find_qualifier(&self, qualifier: &str) -> Option<&TableRef> {
        self.tables
            .iter()
            .find(|t| t.alias.as_deref() == Some(qualifier))
            .or_else(|| self.tables.iter().find(|t| t.alias.is_none() && t.name == qualifier))
            .or_else(|| {
                self.tables
                    .iter()
                    .find(|t| t.alias.is_none() && bare_name(&t.name) == qualifier)
            })
    }
}

struct Extractor<'a> {
    catalog: Option<&'a SchemaCatalog>,
    ctes: HashSet<String>,
    facts: QueryFacts,
}

struct QueryTail<'q> {
    order_by: Option<&'q OrderBy>,
    limit: Option<u64>,
    offset: Option<u64>,
}

impl<'a> Extractor<'a> {
    fn statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Query(q) => {
                self.facts.statement_kind = "SELECT".into();
                self.query(q, &[], "main", 0);
            }
            Statement::Update(u) => {
                self.facts.statement_kind = "UPDATE".into();
                let mut froms = vec![&u.table];
                if let Some(kind) = &u.from {
                    match kind {
                        UpdateTableFromKind::BeforeSet(v) | UpdateTableFromKind::AfterSet(v) => {
                            froms.extend(v.iter())
                        }
                    }
                }
                self.dml_block("update", &froms, u.selection.as_ref());
            }
            Statement::Delete(d) => {
                self.facts.statement_kind = "DELETE".into();
                let mut froms: Vec<&TableWithJoins> = match &d.from {
                    FromTable::WithFromKeyword(v) | FromTable::WithoutKeyword(v) => v.iter().collect(),
                };
                if let Some(using) = &d.using {
                    froms.extend(using.iter());
                }
                self.dml_block("delete", &froms, d.selection.as_ref());
            }
            Statement::Insert(i) => {
                self.facts.statement_kind = "INSERT".into();
                if let Some(src) = &i.source {
                    self.query(src, &[], "insert-source", 0);
                }
            }
            Statement::Explain { statement, .. } => self.statement(statement),
            other => {
                self.facts.statement_kind = statement_kind_label(other);
            }
        }
    }

    fn dml_block(&mut self, context: &str, froms: &[&TableWithJoins], selection: Option<&Expr>) {
        let id = self.reserve_block();
        let mut block = SelectBlock {
            id,
            depth: 0,
            context: context.into(),
            ..Default::default()
        };
        let mut scope = Scope::default();
        for twj in froms {
            self.add_table_with_joins(twj, &mut scope, &[], 0);
        }
        block.tables = scope.tables.clone();
        let scopes = vec![scope];
        for twj in froms {
            self.process_joins(twj, &mut block, &scopes, 0);
        }
        if let Some(sel) = selection {
            self.where_expr(sel, &mut block, &scopes, 0, None);
        }
        self.finish_block(block);
    }

    fn reserve_block(&mut self) -> usize {
        let id = self.facts.blocks.len();
        self.facts.blocks.push(SelectBlock {
            id,
            ..Default::default()
        });
        id
    }

    fn finish_block(&mut self, mut block: SelectBlock) {
        let mut referenced: Vec<ColumnRef> = Vec::new();
        let mut push = |c: &ColumnRef| {
            if !referenced.contains(c) {
                referenced.push(c.clone());
            }
        };
        block.projections.iter().for_each(&mut push);
        block.predicates.iter().for_each(|p| push(&p.column));
        block.joins.iter().for_each(|j| {
            push(&j.left);
            push(&j.right);
        });
        block.group_by.iter().for_each(&mut push);
        block.order_by.iter().for_each(|o| push(&o.column));
        block.referenced = referenced;
        let id = block.id;
        self.facts.blocks[id] = block;
    }

    fn query(&mut self, q: &Query, outer: &[Scope], context: &str, depth: usize) {
        if let Some(with) = &q.with {
            if with.recursive {
                self.facts.recursive_cte = true;
            }
            for cte in &with.cte_tables {
                let name = norm_ident(&cte.alias.name);
                self.ctes.insert(name.clone());
                self.facts.ctes.push(name.clone());
            }
            for cte in &with.cte_tables {
                let name = norm_ident(&cte.alias.name);
                self.query(&cte.query, outer, &format!("cte:{name}"), depth + 1);
            }
        }
        let (limit, offset) = limit_offset(q.limit_clause.as_ref());
        let tail = QueryTail {
            order_by: q.order_by.as_ref(),
            limit,
            offset,
        };
        self.set_expr(&q.body, outer, context, depth, Some(tail));
    }

    fn set_expr(
        &mut self,
        body: &SetExpr,
        outer: &[Scope],
        context: &str,
        depth: usize,
        tail: Option<QueryTail>,
    ) {
        match body {
            SetExpr::Select(s) => self.select(s, outer, context, depth, tail),
            SetExpr::Query(q) => self.query(q, outer, context, depth),
            SetExpr::SetOperation { left, right, .. } => {
                self.facts.set_operations += 1;
                self.set_expr(left, outer, "union-branch", depth, None);
                self.set_expr(right, outer, "union-branch", depth, None);
            }
            _ => {}
        }
    }

    fn select(
        &mut self,
        s: &Select,
        outer: &[Scope],
        context: &str,
        depth: usize,
        tail: Option<QueryTail>,
    ) {
        let id = self.reserve_block();
        let mut block = SelectBlock {
            id,
            depth,
            context: context.into(),
            distinct: s.distinct.is_some(),
            ..Default::default()
        };

        let mut scope = Scope::default();
        for twj in &s.from {
            self.add_table_with_joins(twj, &mut scope, outer, depth);
        }
        block.tables = scope.tables.clone();

        let mut scopes = Vec::with_capacity(outer.len() + 1);
        scopes.push(scope);
        scopes.extend(outer.iter().cloned());

        for twj in &s.from {
            self.process_joins(twj, &mut block, &scopes, depth);
        }
        if let Some(sel) = &s.selection {
            self.where_expr(sel, &mut block, &scopes, depth, None);
        }

        for item in &s.projection {
            match item {
                SelectItem::UnnamedExpr(e)
                | SelectItem::ExprWithAlias { expr: e, .. }
                | SelectItem::ExprWithAliases { expr: e, .. } => {
                    let scan = scan_expr(e);
                    block.has_aggregates |= scan.has_aggregate;
                    for c in scan.columns {
                        if let Some((col, 0)) = self.resolve(&c, &scopes) {
                            if !block.projections.contains(&col) {
                                block.projections.push(col);
                            }
                        }
                    }
                    for sq in scan.subqueries {
                        self.facts.subquery_count += 1;
                        self.query(&sq, &scopes, "subquery", depth + 1);
                    }
                }
                SelectItem::Wildcard(_) => block.select_star = true,
                SelectItem::QualifiedWildcard(kind, _) => {
                    block.select_star = true;
                    if let SelectItemQualifiedWildcardKind::ObjectName(name) = kind {
                        let q = norm_object_name(name);
                        let t = scopes[0].find_qualifier(&q).map(|t| t.name.clone()).unwrap_or(q);
                        block.star_tables.push(t);
                    }
                }
            }
        }

        if let GroupByExpr::Expressions(exprs, _) = &s.group_by {
            for e in exprs {
                if let Some((c, 0)) = self.resolve(e, &scopes) {
                    block.group_by.push(c);
                }
            }
        }
        if let Some(having) = &s.having {
            let scan = scan_expr(having);
            block.has_aggregates |= scan.has_aggregate;
            for sq in scan.subqueries {
                self.facts.subquery_count += 1;
                self.query(&sq, &scopes, "subquery", depth + 1);
            }
        }

        if let Some(tail) = tail {
            block.limit = tail.limit;
            block.offset = tail.offset;
            if let Some(OrderBy {
                kind: OrderByKind::Expressions(exprs),
                ..
            }) = tail.order_by
            {
                for ob in exprs {
                    if is_random_call(&ob.expr) {
                        self.facts.order_by_random = true;
                        continue;
                    }
                    if let Some((c, 0)) = self.resolve(&ob.expr, &scopes) {
                        block.order_by.push(OrderColumn {
                            column: c,
                            descending: matches!(ob.options.sort, Some(OrderBySort::Desc)),
                        });
                    }
                }
            }
        }

        self.finish_block(block);
    }

    fn add_table_with_joins(&mut self, twj: &TableWithJoins, scope: &mut Scope, outer: &[Scope], depth: usize) {
        self.add_factor(&twj.relation, scope, outer, depth);
        for j in &twj.joins {
            self.add_factor(&j.relation, scope, outer, depth);
        }
    }

    fn add_factor(&mut self, f: &TableFactor, scope: &mut Scope, outer: &[Scope], depth: usize) {
        match f {
            TableFactor::Table { name, alias, .. } => {
                let n = norm_object_name(name);
                let is_cte = self.ctes.contains(&n);
                scope.tables.push(TableRef {
                    name: n,
                    alias: alias.as_ref().map(|a| norm_ident(&a.name)),
                    is_cte,
                    is_derived: false,
                });
            }
            TableFactor::Derived {
                lateral,
                subquery,
                alias,
                ..
            } => {
                self.facts.subquery_count += 1;
                let mut lateral_scopes: Vec<Scope> = Vec::new();
                if *lateral {
                    lateral_scopes.push(scope.clone());
                }
                lateral_scopes.extend(outer.iter().cloned());
                self.query(subquery, &lateral_scopes, "derived", depth + 1);
                let alias = alias.as_ref().map(|a| norm_ident(&a.name));
                scope.tables.push(TableRef {
                    name: alias.clone().unwrap_or_else(|| "(derived)".into()),
                    alias,
                    is_cte: false,
                    is_derived: true,
                });
            }
            TableFactor::NestedJoin { table_with_joins, .. } => {
                self.add_table_with_joins(table_with_joins, scope, outer, depth);
            }
            _ => {}
        }
    }

    fn process_joins(&mut self, twj: &TableWithJoins, block: &mut SelectBlock, scopes: &[Scope], depth: usize) {
        if let TableFactor::NestedJoin { table_with_joins, .. } = &twj.relation {
            self.process_joins(table_with_joins, block, scopes, depth);
        }
        let mut previous = factor_name(&twj.relation, &scopes[0]);
        for j in &twj.joins {
            if let TableFactor::NestedJoin { table_with_joins, .. } = &j.relation {
                self.process_joins(table_with_joins, block, scopes, depth);
            }
            let joined = factor_name(&j.relation, &scopes[0]);
            let (kind, constraint) = join_kind(&j.join_operator);
            match constraint {
                Some(JoinConstraint::On(expr)) => {
                    self.where_expr(expr, block, scopes, depth, Some((kind, joined.clone())));
                }
                Some(JoinConstraint::Using(cols)) => {
                    for c in cols {
                        let col = norm_object_name(c);
                        block.joins.push(JoinKey {
                            kind,
                            left: ColumnRef {
                                table: previous.clone(),
                                column: col.clone(),
                            },
                            right: ColumnRef {
                                table: joined.clone(),
                                column: col.clone(),
                            },
                            joined_table: joined.clone(),
                            sql: format!("USING ({col})"),
                        });
                    }
                }
                _ => {}
            }
            previous = joined;
        }
    }

    /// Walk a WHERE / ON expression, splitting on AND.
    fn where_expr(
        &mut self,
        e: &Expr,
        block: &mut SelectBlock,
        scopes: &[Scope],
        depth: usize,
        join: Option<(JoinKind, Option<String>)>,
    ) {
        let mut parts = Vec::new();
        conjuncts(e, &mut parts);
        for part in parts {
            self.classify(part, block, scopes, depth, join.as_ref());
        }
    }

    fn classify(
        &mut self,
        e: &Expr,
        block: &mut SelectBlock,
        scopes: &[Scope],
        depth: usize,
        join: Option<&(JoinKind, Option<String>)>,
    ) {
        let from_join = join.is_some();
        let sql = e.to_string();
        match e {
            Expr::BinaryOp { left, op, right } if comparison_kind(op).is_some() => {
                let kind = comparison_kind(op).unwrap();
                let l = self.resolve(left, scopes);
                let r = self.resolve(right, scopes);
                match (l, r) {
                    (Some((lc, 0)), Some((rc, 0))) => {
                        if kind == PredicateKind::Equality && lc.table != rc.table {
                            let (jk, joined) = match join {
                                Some((k, t)) => (*k, t.clone()),
                                None => (JoinKind::Implicit, None),
                            };
                            block.joins.push(JoinKey {
                                kind: jk,
                                left: lc,
                                right: rc,
                                joined_table: joined,
                                sql,
                            });
                        }
                    }
                    (Some((c, 0)), other) => {
                        let correlated = matches!(other, Some((_, d)) if d > 0);
                        if correlated || self.is_constant(right, scopes) {
                            push_pred(block, c, kind, correlated, from_join, &sql);
                        }
                    }
                    (other, Some((c, 0))) => {
                        let correlated = matches!(other, Some((_, d)) if d > 0);
                        if correlated || self.is_constant(left, scopes) {
                            push_pred(block, c, kind, correlated, from_join, &sql);
                        }
                    }
                    _ => {
                        // Function-wrapped column compared with a constant?
                        if let Some((func, c)) = self.function_column(left, scopes) {
                            if self.is_constant(right, scopes) {
                                block.predicates.push(fw_pred(c, func, left, None, from_join, &sql));
                            }
                        } else if let Some((func, c)) = self.function_column(right, scopes) {
                            if self.is_constant(left, scopes) {
                                block.predicates.push(fw_pred(c, func, right, None, from_join, &sql));
                            }
                        }
                    }
                }
                self.subqueries_in(e, scopes, depth);
            }
            Expr::AnyOp { left, .. } => {
                if let Some((c, 0)) = self.resolve(left, scopes) {
                    push_pred(block, c, PredicateKind::InList, false, from_join, &sql);
                }
                self.subqueries_in(e, scopes, depth);
            }
            Expr::InList { expr, list, negated } => {
                if let Some((c, 0)) = self.resolve(expr, scopes) {
                    let kind = if *negated {
                        PredicateKind::NotIn
                    } else {
                        PredicateKind::InList
                    };
                    block.predicates.push(Predicate {
                        column: c,
                        kind,
                        sargable: !*negated,
                        function: None,
                        target_sql: None,
                        value_count: Some(list.len()),
                        correlated: false,
                        from_join,
                        sql,
                    });
                } else if let Some((func, c)) = self.function_column(expr, scopes) {
                    block.predicates.push(fw_pred(c, func, expr, Some(list.len()), from_join, &sql));
                }
            }
            Expr::InSubquery {
                expr,
                subquery,
                negated,
            } => {
                if let Some((c, 0)) = self.resolve(expr, scopes) {
                    let kind = if *negated {
                        PredicateKind::NotInSubquery
                    } else {
                        PredicateKind::InSubquery
                    };
                    block.predicates.push(Predicate {
                        column: c,
                        kind,
                        sargable: !*negated,
                        function: None,
                        target_sql: None,
                        value_count: None,
                        correlated: false,
                        from_join,
                        sql,
                    });
                }
                self.facts.subquery_count += 1;
                self.query(subquery, scopes, "in-subquery", depth + 1);
            }
            Expr::Between { expr, negated, .. } => {
                if let Some((c, 0)) = self.resolve(expr, scopes) {
                    let kind = if *negated {
                        PredicateKind::NotEqual
                    } else {
                        PredicateKind::Range
                    };
                    push_pred(block, c, kind, false, from_join, &sql);
                } else if let Some((func, c)) = self.function_column(expr, scopes) {
                    block.predicates.push(fw_pred(c, func, expr, None, from_join, &sql));
                }
            }
            Expr::Like {
                expr,
                pattern,
                negated,
                ..
            }
            | Expr::ILike {
                expr,
                pattern,
                negated,
                ..
            } => {
                let case_insensitive = matches!(e, Expr::ILike { .. });
                if let Some((c, 0)) = self.resolve(expr, scopes) {
                    let leading = leading_literal(pattern)
                        .map(|s| s.starts_with('%') || s.starts_with('_'))
                        .unwrap_or(false);
                    let (kind, sargable) = if *negated {
                        (PredicateKind::NotEqual, false)
                    } else if leading {
                        (PredicateKind::LeadingWildcard, false)
                    } else if case_insensitive {
                        (PredicateKind::FunctionWrapped, false)
                    } else {
                        (PredicateKind::PrefixLike, true)
                    };
                    block.predicates.push(Predicate {
                        column: c,
                        kind,
                        sargable,
                        function: case_insensitive.then(|| "ilike".to_string()),
                        target_sql: None,
                        value_count: None,
                        correlated: false,
                        from_join,
                        sql,
                    });
                } else if let Some((func, c)) = self.function_column(expr, scopes) {
                    block.predicates.push(fw_pred(c, func, expr, None, from_join, &sql));
                }
            }
            Expr::IsNull(inner) => {
                if let Some((c, 0)) = self.resolve(inner, scopes) {
                    push_pred(block, c, PredicateKind::IsNull, false, from_join, &sql);
                }
            }
            Expr::Nested(inner) => self.classify(inner, block, scopes, depth, join),
            Expr::BinaryOp {
                op: BinaryOperator::Or,
                ..
            } => {
                let mut group: Vec<ColumnRef> = Vec::new();
                for c in scan_expr(e).columns {
                    if let Some((col, 0)) = self.resolve(&c, scopes) {
                        if !group.contains(&col) {
                            group.push(col);
                        }
                    }
                }
                if !group.is_empty() {
                    block.or_groups.push(group);
                }
                self.subqueries_in(e, scopes, depth);
            }
            Expr::Exists { subquery, .. } => {
                self.facts.subquery_count += 1;
                self.query(subquery, scopes, "exists", depth + 1);
            }
            _ => self.subqueries_in(e, scopes, depth),
        }
    }

    /// No column of the current block is referenced (outer refs count as constants).
    fn is_constant(&mut self, e: &Expr, scopes: &[Scope]) -> bool {
        let scan = scan_expr(e);
        scan.columns
            .iter()
            .all(|c| !matches!(self.resolve_quiet(c, scopes), Some((_, 0))))
    }

    fn subqueries_in(&mut self, e: &Expr, scopes: &[Scope], depth: usize) {
        for sq in scan_expr(e).subqueries {
            self.facts.subquery_count += 1;
            self.query(&sq, scopes, "subquery", depth + 1);
        }
    }

    /// `lower(email)`, `YEAR(created_at)`, `created_at::date`, `price * 2` → (function, column)
    fn function_column(&mut self, e: &Expr, scopes: &[Scope]) -> Option<(String, ColumnRef)> {
        match e {
            Expr::Function(f) => {
                let name = f
                    .name
                    .0
                    .last()
                    .and_then(|p| p.as_ident())
                    .map(|i| i.value.to_lowercase())
                    .unwrap_or_default();
                if let FunctionArguments::List(list) = &f.args {
                    for arg in &list.args {
                        let a = match arg {
                            FunctionArg::Unnamed(FunctionArgExpr::Expr(a)) => a,
                            FunctionArg::Named {
                                arg: FunctionArgExpr::Expr(a),
                                ..
                            } => a,
                            _ => continue,
                        };
                        if let Some((c, 0)) = self.resolve(a, scopes) {
                            return Some((name, c));
                        }
                        if let Some((_, c)) = self.function_column(a, scopes) {
                            return Some((name, c));
                        }
                    }
                }
                None
            }
            Expr::Extract { field, expr, .. } => self
                .resolve(expr, scopes)
                .filter(|(_, d)| *d == 0)
                .map(|(c, _)| (format!("extract({field})"), c)),
            Expr::Cast { expr, .. } => self
                .resolve(expr, scopes)
                .filter(|(_, d)| *d == 0)
                .map(|(c, _)| ("cast".to_string(), c))
                .or_else(|| self.function_column(expr, scopes)),
            Expr::Nested(inner) => self.function_column(inner, scopes),
            Expr::Collate { expr, .. } => self
                .resolve(expr, scopes)
                .filter(|(_, d)| *d == 0)
                .map(|(c, _)| ("collate".to_string(), c)),
            Expr::Substring { expr, .. } | Expr::Trim { expr, .. } | Expr::Ceil { expr, .. } | Expr::Floor { expr, .. } => self
                .resolve(expr, scopes)
                .filter(|(_, d)| *d == 0)
                .map(|(c, _)| (expr_function_label(e), c)),
            Expr::BinaryOp { left, right, op } if is_arithmetic(op) => {
                for side in [left, right] {
                    if let Some((c, 0)) = self.resolve(side, scopes) {
                        return Some((format!("expression ({op})"), c));
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn resolve_quiet(&mut self, e: &Expr, scopes: &[Scope]) -> Option<(ColumnRef, usize)> {
        let before = self.facts.unresolved_columns.len();
        let r = self.resolve(e, scopes);
        self.facts.unresolved_columns.truncate(before);
        r
    }

    /// Resolve a column expression to (column, scope depth). Depth 0 = current block.
    fn resolve(&mut self, e: &Expr, scopes: &[Scope]) -> Option<(ColumnRef, usize)> {
        match e {
            Expr::Identifier(id) => self.resolve_unqualified(norm_ident(id), scopes),
            Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
                let column = norm_ident(parts.last().unwrap());
                let qualifier = parts[..parts.len() - 1]
                    .iter()
                    .map(norm_ident)
                    .collect::<Vec<_>>()
                    .join(".");
                for (depth, scope) in scopes.iter().enumerate() {
                    if let Some(t) = scope.find_qualifier(&qualifier) {
                        return Some((
                            ColumnRef {
                                table: Some(t.name.clone()),
                                column,
                            },
                            depth,
                        ));
                    }
                }
                Some((
                    ColumnRef {
                        table: Some(qualifier),
                        column,
                    },
                    0,
                ))
            }
            Expr::Nested(inner) => self.resolve(inner, scopes),
            _ => None,
        }
    }

    fn resolve_unqualified(&mut self, column: String, scopes: &[Scope]) -> Option<(ColumnRef, usize)> {
        for (depth, scope) in scopes.iter().enumerate() {
            if scope.tables.is_empty() {
                continue;
            }
            if let Some(cat) = self.catalog {
                let owners: Vec<&TableRef> = scope
                    .tables
                    .iter()
                    .filter(|t| catalog_has(cat, &t.name, &column))
                    .collect();
                if owners.len() == 1 {
                    return Some((
                        ColumnRef {
                            table: Some(owners[0].name.clone()),
                            column,
                        },
                        depth,
                    ));
                }
                if owners.len() > 1 {
                    self.facts.unresolved_columns.push(format!("{column} (ambiguous)"));
                    return Some((ColumnRef { table: None, column }, depth));
                }
                // Not in any catalogued table here: maybe it belongs to a CTE /
                // derived table of this scope, otherwise look outward.
                let unknown: Vec<&TableRef> = scope
                    .tables
                    .iter()
                    .filter(|t| !catalog_knows(cat, &t.name))
                    .collect();
                if unknown.len() == 1 {
                    return Some((
                        ColumnRef {
                            table: Some(unknown[0].name.clone()),
                            column,
                        },
                        depth,
                    ));
                }
                if depth + 1 < scopes.len() {
                    continue;
                }
            }
            if scope.tables.len() == 1 {
                return Some((
                    ColumnRef {
                        table: Some(scope.tables[0].name.clone()),
                        column,
                    },
                    depth,
                ));
            }
            self.facts.unresolved_columns.push(column.clone());
            return Some((ColumnRef { table: None, column }, depth));
        }
        None
    }
}

fn fw_pred(column: ColumnRef, func: String, target: &Expr, value_count: Option<usize>, from_join: bool, sql: &str) -> Predicate {
    Predicate {
        column,
        kind: PredicateKind::FunctionWrapped,
        sargable: false,
        function: Some(func),
        target_sql: Some(target.to_string()),
        value_count,
        correlated: false,
        from_join,
        sql: sql.to_string(),
    }
}

fn push_pred(block: &mut SelectBlock, c: ColumnRef, kind: PredicateKind, correlated: bool, from_join: bool, sql: &str) {
    block.predicates.push(Predicate {
        column: c,
        kind,
        sargable: !matches!(kind, PredicateKind::NotEqual),
        function: None,
        target_sql: None,
        value_count: None,
        correlated,
        from_join,
        sql: sql.to_string(),
    });
}

fn comparison_kind(op: &BinaryOperator) -> Option<PredicateKind> {
    Some(match op {
        BinaryOperator::Eq | BinaryOperator::Spaceship => PredicateKind::Equality,
        BinaryOperator::Gt | BinaryOperator::Lt | BinaryOperator::GtEq | BinaryOperator::LtEq => PredicateKind::Range,
        BinaryOperator::NotEq => PredicateKind::NotEqual,
        _ => return None,
    })
}

fn is_arithmetic(op: &BinaryOperator) -> bool {
    matches!(
        op,
        BinaryOperator::Plus
            | BinaryOperator::Minus
            | BinaryOperator::Multiply
            | BinaryOperator::Divide
            | BinaryOperator::Modulo
            | BinaryOperator::StringConcat
    )
}

fn expr_function_label(e: &Expr) -> String {
    match e {
        Expr::Substring { .. } => "substring",
        Expr::Trim { .. } => "trim",
        Expr::Ceil { .. } => "ceil",
        Expr::Floor { .. } => "floor",
        _ => "expression",
    }
    .into()
}

fn conjuncts<'e>(e: &'e Expr, out: &mut Vec<&'e Expr>) {
    match e {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            conjuncts(left, out);
            conjuncts(right, out);
        }
        Expr::Nested(inner) if matches!(**inner, Expr::BinaryOp { op: BinaryOperator::And, .. }) => {
            conjuncts(inner, out)
        }
        other => out.push(other),
    }
}

/// The leftmost string literal of a LIKE pattern (handles `'%' || $1`).
fn leading_literal(e: &Expr) -> Option<String> {
    match e {
        Expr::Value(v) => match &v.value {
            Value::SingleQuotedString(s) | Value::DoubleQuotedString(s) | Value::EscapedStringLiteral(s) => {
                Some(s.clone())
            }
            _ => None,
        },
        Expr::BinaryOp {
            left,
            op: BinaryOperator::StringConcat,
            ..
        } => leading_literal(left),
        Expr::Function(f) => {
            let name = f.name.to_string().to_lowercase();
            if name == "concat" {
                if let FunctionArguments::List(list) = &f.args {
                    if let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(first))) = list.args.first() {
                        return leading_literal(first);
                    }
                }
            }
            None
        }
        Expr::Nested(inner) => leading_literal(inner),
        _ => None,
    }
}

fn is_random_call(e: &Expr) -> bool {
    if let Expr::Function(f) = e {
        let n = f.name.to_string().to_lowercase();
        return n == "random" || n == "rand";
    }
    false
}

fn join_kind(op: &JoinOperator) -> (JoinKind, Option<&JoinConstraint>) {
    match op {
        JoinOperator::Join(c) | JoinOperator::Inner(c) => (JoinKind::Inner, Some(c)),
        JoinOperator::Left(c) | JoinOperator::LeftOuter(c) => (JoinKind::Left, Some(c)),
        JoinOperator::Right(c) | JoinOperator::RightOuter(c) => (JoinKind::Right, Some(c)),
        JoinOperator::FullOuter(c) => (JoinKind::Full, Some(c)),
        JoinOperator::CrossJoin(c) => (JoinKind::Cross, Some(c)),
        JoinOperator::Semi(c) | JoinOperator::LeftSemi(c) | JoinOperator::RightSemi(c) => (JoinKind::Semi, Some(c)),
        JoinOperator::Anti(c) | JoinOperator::LeftAnti(c) | JoinOperator::RightAnti(c) => (JoinKind::Anti, Some(c)),
        _ => (JoinKind::Inner, None),
    }
}

fn factor_name(f: &TableFactor, scope: &Scope) -> Option<String> {
    match f {
        TableFactor::Table { name, alias, .. } => {
            if let Some(a) = alias {
                let a = norm_ident(&a.name);
                if let Some(t) = scope.find_qualifier(&a) {
                    return Some(t.name.clone());
                }
            }
            Some(norm_object_name(name))
        }
        TableFactor::Derived { alias, .. } => alias.as_ref().map(|a| norm_ident(&a.name)),
        _ => None,
    }
}

fn limit_offset(lc: Option<&LimitClause>) -> (Option<u64>, Option<u64>) {
    let num = |e: &Expr| -> Option<u64> {
        if let Expr::Value(v) = e {
            if let Value::Number(n, _) = &v.value {
                return n.to_string().parse().ok();
            }
        }
        None
    };
    match lc {
        Some(LimitClause::LimitOffset { limit, offset, .. }) => {
            (limit.as_ref().and_then(num), offset.as_ref().and_then(|o| num(&o.value)))
        }
        Some(LimitClause::OffsetCommaLimit { offset, limit }) => (num(limit), num(offset)),
        None => (None, None),
    }
}

pub(crate) fn norm_ident(id: &Ident) -> String {
    if id.quote_style.is_some() {
        id.value.clone()
    } else {
        id.value.to_lowercase()
    }
}

pub(crate) fn norm_object_name(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|p| match p.as_ident() {
            Some(i) => norm_ident(i),
            None => p.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

pub fn bare_name(table: &str) -> &str {
    table.rsplit('.').next().unwrap_or(table)
}

fn catalog_knows(cat: &SchemaCatalog, table: &str) -> bool {
    cat.contains_key(table) || cat.contains_key(bare_name(table))
}

fn catalog_has(cat: &SchemaCatalog, table: &str, column: &str) -> bool {
    cat.get(table)
        .or_else(|| cat.get(bare_name(table)))
        .map(|cols| cols.iter().any(|c| c == column))
        .unwrap_or(false)
}

fn statement_kind_label(stmt: &Statement) -> String {
    let s = stmt.to_string();
    s.split_whitespace().next().unwrap_or("UNKNOWN").to_uppercase()
}

// ---------------------------------------------------------------------------
// Expression scanning (stops at subquery boundaries).

#[derive(Default)]
struct ExprScan {
    columns: Vec<Expr>,
    subqueries: Vec<Query>,
    has_aggregate: bool,
}

struct ScanVisitor {
    depth: usize,
    scan: ExprScan,
}

const AGGREGATES: &[&str] = &[
    "count", "sum", "avg", "min", "max", "array_agg", "string_agg", "json_agg", "jsonb_agg", "group_concat",
    "bool_and", "bool_or", "stddev", "variance", "percentile_cont", "percentile_disc",
];

impl Visitor for ScanVisitor {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        if self.depth == 0 {
            self.scan.subqueries.push(query.clone());
        }
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        if self.depth > 0 {
            return ControlFlow::Continue(());
        }
        match expr {
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => self.scan.columns.push(expr.clone()),
            Expr::Function(f) => {
                let n = f.name.to_string().to_lowercase();
                if AGGREGATES.contains(&n.as_str()) {
                    self.scan.has_aggregate = true;
                }
            }
            _ => {}
        }
        ControlFlow::Continue(())
    }
}

fn scan_expr(e: &Expr) -> ExprScan {
    let mut v = ScanVisitor {
        depth: 0,
        scan: ExprScan::default(),
    };
    let _ = e.visit(&mut v);
    v.scan
}

#[derive(Default)]
struct PlaceholderCounter(usize);

impl Visitor for PlaceholderCounter {
    type Break = ();
    fn pre_visit_value(&mut self, value: &ValueWithSpan) -> ControlFlow<()> {
        if matches!(value.value, Value::Placeholder(_)) {
            self.0 += 1;
        }
        ControlFlow::Continue(())
    }
}
