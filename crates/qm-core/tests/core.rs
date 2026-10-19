use std::collections::HashMap;

use qm_core::advisor::{IndexAction, RecommendationKind, TableContext, TableContexts};
use qm_core::analysis::{analyze, AnalysisInput, AnalysisReport};
use qm_core::facts::{extract_facts, PredicateKind};
use qm_core::model::{ColumnMetadata, Engine, IndexMetadata, TableStats};
use qm_core::plan::{analyze_plan, PlanContext};
use qm_core::rules::{RuleEngine, DEFAULT_RULES_YAML};

fn col(name: &str, distinct: u64) -> ColumnMetadata {
    ColumnMetadata {
        name: name.into(),
        data_type: "bigint".into(),
        nullable: false,
        distinct_values: Some(distinct),
        null_fraction: Some(0.0),
    }
}

fn idx(name: &str, cols: &[&str], unique: bool) -> IndexMetadata {
    IndexMetadata {
        name: name.into(),
        columns: cols.iter().map(|c| c.to_string()).collect(),
        is_unique: unique,
        is_primary: unique,
        method: "btree".into(),
        ..Default::default()
    }
}

fn school_tables() -> TableContexts {
    let mut t = HashMap::new();
    t.insert(
        "test_results".to_string(),
        TableContext {
            stats: Some(TableStats {
                total_rows: 800_000,
                ..Default::default()
            }),
            indexes: Some(vec![
                idx("test_results_pkey", &["id"], true),
                idx("idx_test_results_school", &["school_id"], false),
            ]),
            columns: vec![
                col("id", 800_000),
                col("student_id", 200_000),
                col("school_id", 2_501),
                col("master_combined_test_id", 60),
                col("academic_year_id", 4),
                col("status", 3),
                col("score", 10_000),
                col("taken_at", 1_400),
            ],
        },
    );
    t.insert(
        "students".to_string(),
        TableContext {
            stats: Some(TableStats {
                total_rows: 200_000,
                ..Default::default()
            }),
            indexes: Some(vec![idx("students_pkey", &["id"], true), idx("idx_students_email", &["email"], false)]),
            columns: vec![col("id", 200_000), col("school_id", 2_501), col("email", 200_000), col("status", 3)],
        },
    );
    t
}

fn catalog(tables: &TableContexts) -> HashMap<String, Vec<String>> {
    tables
        .iter()
        .map(|(k, v)| (k.clone(), v.columns.iter().map(|c| c.name.clone()).collect()))
        .collect()
}

fn run(sql: &str, tables: &TableContexts) -> AnalysisReport {
    let rules = RuleEngine::from_yaml(DEFAULT_RULES_YAML).unwrap();
    let cat = catalog(tables);
    analyze(AnalysisInput {
        sql,
        engine: Engine::Postgresql,
        catalog: Some(&cat),
        tables,
        plan_json: None,
        rules: &rules,
        server_version_num: Some(180000),
        ai_cost_threshold: 10_000.0,
    })
    .unwrap()
}

#[test]
fn spec_composite_order_equality_then_range_with_replace() {
    let tables = school_tables();
    let sql = "SELECT student_id, score FROM test_results \
               WHERE school_id = '1836876' AND master_combined_test_id = '3' AND status = 'active' \
               AND academic_year_id IN ('5554', '5132') ORDER BY taken_at DESC";
    let report = run(sql, &tables);
    let rec = report
        .recommendations
        .iter()
        .find(|r| r.kind == RecommendationKind::Composite)
        .expect("composite recommendation");
    let key: Vec<&str> = rec.key_columns.iter().map(|k| k.name.as_str()).collect();
    assert_eq!(key, ["school_id", "master_combined_test_id", "status", "academic_year_id"]);
    assert_eq!(rec.include_columns, ["student_id", "score", "taken_at"]);
    assert_eq!(
        rec.action,
        IndexAction::Replace {
            drop_index: "idx_test_results_school".into()
        }
    );
    assert!(rec.index_name.len() <= 63, "{}", rec.index_name);
    assert!(rec.ddl[0].starts_with(&format!("CREATE INDEX CONCURRENTLY IF NOT EXISTS {} ON test_results (school_id, master_combined_test_id, status, academic_year_id)", rec.index_name)), "{}", rec.ddl[0]);
    assert!(rec.ddl[0].contains("INCLUDE (student_id, score, taken_at)"), "{}", rec.ddl[0]);
    assert!(rec.ddl[1].starts_with("DROP INDEX CONCURRENTLY IF EXISTS idx_test_results_school"));
    assert!(rec.estimated_rows.unwrap() < 10);
}

#[test]
fn equality_columns_sorted_by_selectivity_and_sort_appended() {
    let tables = school_tables();
    let report = run(
        "SELECT id FROM test_results WHERE status = 'active' AND master_combined_test_id = 3 ORDER BY taken_at",
        &tables,
    );
    let rec = &report.recommendations[0];
    let key: Vec<&str> = rec.key_columns.iter().map(|k| k.name.as_str()).collect();
    assert_eq!(key, ["master_combined_test_id", "status", "taken_at"]);
    assert_eq!(rec.action, IndexAction::Create);
}

#[test]
fn covered_by_existing_index() {
    let tables = school_tables();
    let report = run("SELECT * FROM students WHERE email = 'a@b.c'", &tables);
    let rec = &report.recommendations[0];
    assert!(matches!(rec.action, IndexAction::Covered { .. }));
    assert!(rec.ddl.is_empty());
}

#[test]
fn year_function_rewritten_to_range_and_indexed() {
    let tables = school_tables();
    let report = run("SELECT id FROM test_results WHERE YEAR(taken_at) = 2026 AND school_id = 7", &tables);
    let rw = report.rewritten_sql.as_deref().unwrap();
    assert!(rw.contains("taken_at >= '2026-01-01' AND taken_at < '2027-01-01'"), "{rw}");
    assert_eq!(report.advisor_source, "rewritten");
    let rec = report.recommendations.iter().find(|r| r.kind == RecommendationKind::Composite).unwrap();
    let key: Vec<&str> = rec.key_columns.iter().map(|k| k.name.as_str()).collect();
    assert_eq!(key, ["school_id", "taken_at"]);
}

#[test]
fn not_in_subquery_becomes_not_exists() {
    let tables = school_tables();
    let report = run(
        "SELECT s.id FROM students s WHERE s.id NOT IN (SELECT student_id FROM test_results WHERE status = 'archived')",
        &tables,
    );
    let rw = report.rewritten_sql.as_deref().unwrap().replace('\n', " ");
    assert!(rw.contains("NOT EXISTS"), "{rw}");
    assert!(rw.contains("student_id = s.id"), "{rw}");
    assert!(report.rule_hits.iter().any(|h| h.rule_id == "RULE_004_NOT_IN_SUBQUERY"));
}

#[test]
fn unqualified_not_in_with_same_table_is_not_rewritten() {
    let tables = school_tables();
    let report = run(
        "SELECT id FROM students WHERE id NOT IN (SELECT id FROM students WHERE status = 'x')",
        &tables,
    );
    let f = report.rewrites.iter().find(|r| r.id == "RW_NOT_IN_TO_NOT_EXISTS").unwrap();
    assert!(!f.applied);
}

#[test]
fn or_across_columns_becomes_union_all() {
    let tables = school_tables();
    let report = run("SELECT id FROM students WHERE email = 'x' OR school_id = 4", &tables);
    let rw = report.rewritten_sql.as_deref().unwrap().replace('\n', " ");
    assert!(rw.contains("UNION ALL"), "{rw}");
    assert!(rw.contains("IS NOT TRUE"), "{rw}");
}

#[test]
fn left_join_unindexed_fk_hits_rule_003() {
    let tables = school_tables();
    let report = run(
        "SELECT s.id, avg(r.score) FROM students s LEFT JOIN test_results r ON r.student_id = s.id \
         WHERE s.school_id = 12 GROUP BY s.id",
        &tables,
    );
    let hit = report.rule_hits.iter().find(|h| h.rule_id == "RULE_003_MISSING_FOREIGN_KEY_INDEX").unwrap();
    assert_eq!(hit.tables, ["test_results"]);
    let rec = report
        .recommendations
        .iter()
        .find(|r| r.kind == RecommendationKind::JoinKey && r.table == "test_results")
        .unwrap();
    assert_eq!(rec.key_columns[0].name, "student_id");
    assert!(rec.rule_ids.contains(&"RULE_003_MISSING_FOREIGN_KEY_INDEX".to_string()));
    // students.id is the PK — no join recommendation needed on that side of a LEFT JOIN.
    assert!(!report.recommendations.iter().any(|r| r.table == "students" && r.kind == RecommendationKind::JoinKey));
}

#[test]
fn leading_wildcard_gets_trigram() {
    let tables = school_tables();
    let report = run("SELECT id FROM students WHERE email LIKE '%@example.edu'", &tables);
    assert!(report.rule_hits.iter().any(|h| h.rule_id == "RULE_002_LEADING_WILDCARD"));
    let rec = report.recommendations.iter().find(|r| r.kind == RecommendationKind::Trigram).unwrap();
    assert!(rec.ddl.iter().any(|d| d.contains("gin_trgm_ops")));
}

#[test]
fn facts_resolve_aliases_and_subquery_scopes() {
    let sql = "SELECT a.id FROM students a JOIN test_results b ON b.student_id = a.id \
               WHERE a.status = 'active' AND EXISTS (SELECT 1 FROM schools sc WHERE sc.id = a.school_id AND sc.state = 'CA')";
    let (_, facts) = extract_facts(sql, Engine::Postgresql, None).unwrap();
    assert_eq!(facts.tables, ["students", "test_results", "schools"]);
    let main = facts.main_block().unwrap();
    assert_eq!(main.joins.len(), 1);
    let sub = facts.blocks.iter().find(|b| b.context == "exists").unwrap();
    let correlated = sub.predicates.iter().find(|p| p.column.column == "id").unwrap();
    assert!(correlated.correlated);
    assert_eq!(correlated.column.table.as_deref(), Some("schools"));
    assert!(sub.predicates.iter().any(|p| p.column.column == "state" && p.kind == PredicateKind::Equality));
}

#[test]
fn pg_plan_findings() {
    let plan = serde_json::json!([{
        "Plan": {
            "Node Type": "Sort", "Startup Cost": 100.0, "Total Cost": 120.0, "Plan Rows": 10, "Plan Width": 8,
            "Actual Total Time": 95.0, "Actual Rows": 4000, "Actual Loops": 1,
            "Sort Key": ["taken_at"], "Sort Method": "external merge", "Sort Space Type": "Disk",
            "Plans": [{
                "Node Type": "Seq Scan", "Relation Name": "test_results", "Schema": "public", "Alias": "test_results",
                "Total Cost": 18000.0, "Plan Rows": 10, "Actual Total Time": 90.0, "Actual Rows": 4000, "Actual Loops": 1,
                "Filter": "(school_id = 7)", "Rows Removed by Filter": 796000
            }]
        },
        "Planning Time": 0.2, "Execution Time": 96.0
    }]);
    let a = analyze_plan(Engine::Postgresql, &plan, &PlanContext { seq_scan_row_threshold: 10_000, ..Default::default() });
    let codes: Vec<&str> = a.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(codes.contains(&"SEQ_SCAN_LARGE"), "{codes:?}");
    assert!(codes.contains(&"DISK_SORT"));
    assert!(codes.contains(&"ROW_MISESTIMATE"));
    assert_eq!(a.summary.seq_scans, ["test_results"]);
    assert_eq!(a.full_scans()[0].1, Some(800_000.0));
}

#[test]
fn mysql_plan_full_scan() {
    let plan = serde_json::json!({"query_block": {"select_id": 1, "cost_info": {"query_cost": "8123.50"},
        "ordering_operation": {"using_filesort": true,
            "table": {"table_name": "orders", "access_type": "ALL", "rows_examined_per_scan": 50000, "attached_condition": "(`orders`.`status` = 'x')"}}}});
    let a = analyze_plan(Engine::Mysql, &plan, &PlanContext { seq_scan_row_threshold: 10_000, ..Default::default() });
    assert_eq!(a.summary.total_cost, Some(8123.5));
    assert!(a.findings.iter().any(|f| f.code == "SEQ_SCAN_LARGE"));
    assert!(a.findings.iter().any(|f| f.code == "FILESORT"));
}

#[test]
fn rules_reject_bad_yaml() {
    assert!(RuleEngine::from_yaml("version: '1'\nrules:\n  - id: X\n    name: x\n    severity: HIGH\n").is_err());
    assert!(RuleEngine::from_yaml(
        "version: '1'\nrules:\n  - id: X\n    name: x\n    severity: HIGH\n    condition:\n      bogus: 1\n"
    )
    .is_err());
    let custom = RuleEngine::from_yaml(
        "version: '1'\nrules:\n  - id: NO_SELECT_FOR_UPDATE\n    name: Locking read\n    severity: WARNING\n    pattern: 'regex:for\\s+update'\n",
    )
    .unwrap();
    let tables = school_tables();
    let cat = catalog(&tables);
    let report = analyze(AnalysisInput {
        sql: "SELECT id FROM students WHERE id = 1 FOR UPDATE",
        engine: Engine::Postgresql,
        catalog: Some(&cat),
        tables: &tables,
        plan_json: None,
        rules: &custom,
        server_version_num: None,
        ai_cost_threshold: 1e9,
    })
    .unwrap();
    assert_eq!(report.rule_hits.len(), 1);
}

#[test]
fn mysql_ddl_uses_alter_table() {
    let tables = school_tables();
    let rules = RuleEngine::from_yaml(DEFAULT_RULES_YAML).unwrap();
    let cat = catalog(&tables);
    let report = analyze(AnalysisInput {
        sql: "SELECT id FROM test_results WHERE master_combined_test_id = 3 AND taken_at > '2025-01-01'",
        engine: Engine::Mysql,
        catalog: Some(&cat),
        tables: &tables,
        plan_json: None,
        rules: &rules,
        server_version_num: None,
        ai_cost_threshold: 1e9,
    })
    .unwrap();
    let rec = &report.recommendations[0];
    assert!(rec.ddl[0].starts_with("ALTER TABLE test_results ADD INDEX"), "{}", rec.ddl[0]);
    assert!(rec.include_columns.is_empty());
}
