//! Index hygiene from catalog statistics: unused, duplicate and
//! prefix-redundant indexes, plus tables that are mostly sequentially scanned.

use serde::Serialize;

use crate::model::{IndexUsage, TableOverview};

#[derive(Debug, Clone, Serialize)]
pub struct IndexIssue {
    pub kind: String,
    pub table: String,
    pub index: String,
    pub columns: Vec<String>,
    pub size_bytes: u64,
    pub scans: u64,
    /// The index that makes this one unnecessary (duplicates / prefixes).
    pub superseded_by: Option<String>,
    pub detail: String,
    pub ddl: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeqScanTable {
    pub table: String,
    pub rows: u64,
    pub seq_scan: u64,
    pub idx_scan: u64,
    pub seq_tup_read: u64,
    pub seq_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct IndexHealth {
    pub unused: Vec<IndexIssue>,
    pub duplicates: Vec<IndexIssue>,
    pub redundant_prefixes: Vec<IndexIssue>,
    pub seq_scan_heavy: Vec<SeqScanTable>,
    pub reclaimable_bytes: u64,
}

fn qualified(schema: &str, name: &str) -> String {
    if schema.is_empty() || schema == "public" {
        name.to_string()
    } else {
        format!("{schema}.{name}")
    }
}

pub fn index_health(indexes: &[IndexUsage], tables: &[TableOverview], mysql: bool) -> IndexHealth {
    let mut h = IndexHealth::default();
    let drop_ddl = |i: &IndexUsage| {
        Some(if mysql {
            format!("ALTER TABLE {} DROP INDEX {};", i.table, i.index)
        } else {
            format!("DROP INDEX CONCURRENTLY IF EXISTS {};", qualified(&i.schema, &i.index))
        })
    };
    let droppable = |i: &IndexUsage| !i.is_primary && !i.is_unique;
    let is_expr = |i: &IndexUsage| i.columns.iter().any(|c| c == "(expr)");

    let mut flagged: Vec<&str> = Vec::new();
    for (pos, a) in indexes.iter().enumerate() {
        for b in indexes.iter().skip(pos + 1) {
            if a.schema != b.schema || a.table != b.table || is_expr(a) || is_expr(b) || a.columns != b.columns {
                continue;
            }
            // Keep the constraint-backing / more used index.
            let (keep, drop) = if droppable(b) && (!droppable(a) || a.scans >= b.scans) { (a, b) } else { (b, a) };
            if !droppable(drop) || flagged.contains(&drop.index.as_str()) {
                continue;
            }
            flagged.push(&drop.index);
            h.duplicates.push(IndexIssue {
                kind: "duplicate".into(),
                table: qualified(&drop.schema, &drop.table),
                index: drop.index.clone(),
                columns: drop.columns.clone(),
                size_bytes: drop.size_bytes,
                scans: drop.scans,
                superseded_by: Some(keep.index.clone()),
                detail: format!("Same columns as `{}`; every write maintains both.", keep.index),
                ddl: drop_ddl(drop),
            });
        }
    }

    for a in indexes {
        if !droppable(a) || is_expr(a) || flagged.contains(&a.index.as_str()) {
            continue;
        }
        let wider = indexes.iter().find(|b| {
            b.index != a.index
                && b.schema == a.schema
                && b.table == a.table
                && !is_expr(b)
                && b.columns.len() > a.columns.len()
                && b.columns[..a.columns.len()] == a.columns[..]
        });
        if let Some(b) = wider {
            flagged.push(&a.index);
            h.redundant_prefixes.push(IndexIssue {
                kind: "redundant_prefix".into(),
                table: qualified(&a.schema, &a.table),
                index: a.index.clone(),
                columns: a.columns.clone(),
                size_bytes: a.size_bytes,
                scans: a.scans,
                superseded_by: Some(b.index.clone()),
                detail: format!(
                    "({}) is a leading prefix of `{}` ({}), which can serve the same lookups.",
                    a.columns.join(", "),
                    b.index,
                    b.columns.join(", ")
                ),
                ddl: drop_ddl(a),
            });
        }
    }

    for a in indexes {
        if a.scans == 0 && droppable(a) && !flagged.contains(&a.index.as_str()) {
            h.unused.push(IndexIssue {
                kind: "unused".into(),
                table: qualified(&a.schema, &a.table),
                index: a.index.clone(),
                columns: a.columns.clone(),
                size_bytes: a.size_bytes,
                scans: 0,
                superseded_by: None,
                detail: "Never used since statistics were last reset. Check replicas before dropping.".into(),
                ddl: drop_ddl(a),
            });
        }
    }

    for t in tables {
        let total = t.seq_scan + t.idx_scan;
        if t.rows >= 10_000 && total > 0 && t.seq_scan > 0 {
            let ratio = t.seq_scan as f64 / total as f64;
            if ratio >= 0.5 {
                h.seq_scan_heavy.push(SeqScanTable {
                    table: qualified(&t.schema, &t.name),
                    rows: t.rows,
                    seq_scan: t.seq_scan,
                    idx_scan: t.idx_scan,
                    seq_tup_read: t.seq_tup_read,
                    seq_ratio: ratio,
                });
            }
        }
    }
    h.seq_scan_heavy.sort_by(|a, b| b.seq_tup_read.cmp(&a.seq_tup_read));
    h.reclaimable_bytes = h
        .unused
        .iter()
        .chain(h.duplicates.iter())
        .chain(h.redundant_prefixes.iter())
        .map(|i| i.size_bytes)
        .sum();
    h
}
