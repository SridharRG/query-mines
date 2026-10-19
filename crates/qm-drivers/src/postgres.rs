//! PostgreSQL driver. Works against a container (published TCP port), a
//! local server, or a Unix socket — anything `tokio-postgres` accepts.

use std::str::FromStr;

use async_trait::async_trait;
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod};
use tokio::sync::OnceCell;
use tokio_postgres::{NoTls, SimpleQueryMessage};

use crate::*;

pub struct PostgresDockerDriver {
    cfg: ConnectionConfig,
    pool: Pool,
    info: OnceCell<ServerInfo>,
}

fn q(e: tokio_postgres::Error) -> DriverError {
    match e.as_db_error() {
        Some(db) => DriverError::Query(match db.hint() {
            Some(h) => format!("{} (hint: {h})", db.message()),
            None => db.message().to_string(),
        }),
        None => DriverError::Query(e.to_string()),
    }
}

/// Quote each part of `schema.table` so `to_regclass` keeps the exact case.
fn regclass_literal(table: &str) -> String {
    table
        .split('.')
        .map(|p| format!("\"{}\"", p.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(".")
}

const INTERNAL_QUERY_FILTER: &str = "query !~* '(pg_stat_|pg_catalog|information_schema|hypopg|to_regclass|pg_class|pg_index|pg_am\\b|pg_database|pg_extension|pg_settings|pg_blocking_pids|pg_locks)' \
     AND query !~* '^\\s*(EXPLAIN|BEGIN|ROLLBACK|COMMIT|SET |SHOW |RESET )'";

impl PostgresDockerDriver {
    pub async fn connect(cfg: ConnectionConfig) -> Result<Self, DriverError> {
        let mut pg = tokio_postgres::Config::from_str(&cfg.url).map_err(|e| DriverError::Connection(e.to_string()))?;
        pg.application_name("query-mines");
        pg.connect_timeout(std::time::Duration::from_secs(5));
        let mgr = Manager::from_config(
            pg,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(mgr)
            .max_size(cfg.pool_size.max(1))
            .build()
            .map_err(|e| DriverError::Connection(e.to_string()))?;
        let driver = Self {
            cfg,
            pool,
            info: OnceCell::new(),
        };
        driver.server_info().await?;
        Ok(driver)
    }

    async fn client(&self) -> Result<Object, DriverError> {
        self.pool.get().await.map_err(|e| DriverError::Connection(e.to_string()))
    }

    async fn version_num(&self) -> u32 {
        self.server_info().await.map(|i| i.version_num).unwrap_or(0)
    }

    async fn has_extension(&self, name: &str) -> bool {
        let Ok(c) = self.client().await else { return false };
        c.query_opt("SELECT 1 FROM pg_extension WHERE extname = $1", &[&name])
            .await
            .map(|r| r.is_some())
            .unwrap_or(false)
    }

    /// Run a single EXPLAIN through the simple-query protocol (so `$1`
    /// placeholders are allowed with GENERIC_PLAN) and parse its JSON.
    async fn explain_simple(client: &Object, sql: &str) -> Result<serde_json::Value, DriverError> {
        let msgs = client.simple_query(sql).await.map_err(q)?;
        for m in msgs {
            if let SimpleQueryMessage::Row(row) = m {
                let text = row.get(0).unwrap_or("null");
                return serde_json::from_str(text).map_err(|e| DriverError::Query(format!("bad EXPLAIN JSON: {e}")));
            }
        }
        Err(DriverError::Query("EXPLAIN returned no rows".into()))
    }

    async fn explain_options(&self, query: &str, analyze: bool) -> Result<String, DriverError> {
        let has_params = regex_lite_has_placeholder(query);
        if has_params {
            if analyze {
                return Err(DriverError::Query(
                    "the query has $n parameters; substitute literal values to run EXPLAIN ANALYZE".into(),
                ));
            }
            if self.version_num().await < 160000 {
                return Err(DriverError::Query(
                    "the query has $n parameters; EXPLAIN (GENERIC_PLAN) needs PostgreSQL 16+".into(),
                ));
            }
            return Ok("GENERIC_PLAN, FORMAT JSON".into());
        }
        Ok(if analyze {
            "ANALYZE, BUFFERS, FORMAT JSON".into()
        } else {
            "FORMAT JSON".into()
        })
    }
}

fn regex_lite_has_placeholder(q: &str) -> bool {
    let b = q.as_bytes();
    let mut in_str = false;
    for i in 0..b.len() {
        match b[i] {
            b'\'' => in_str = !in_str,
            b'$' if !in_str && i + 1 < b.len() && b[i + 1].is_ascii_digit() => return true,
            _ => {}
        }
    }
    false
}

fn plan_cost(v: &serde_json::Value) -> Option<f64> {
    v.get(0)?.get("Plan")?.get("Total Cost")?.as_f64()
}

/// HypoPG wants a plain `CREATE INDEX ON t (...)`.
fn hypopg_ddl(ddl: &str) -> String {
    let s = ddl.trim().trim_end_matches(';');
    let s = s.replacen("CONCURRENTLY ", "", 1).replacen("IF NOT EXISTS ", "", 1);
    // Drop the index name: "CREATE INDEX name ON ..." -> "CREATE INDEX ON ..."
    if let Some(rest) = s.strip_prefix("CREATE INDEX ") {
        if let Some(pos) = rest.find(" ON ") {
            return format!("CREATE INDEX ON {}", &rest[pos + 4..]);
        }
    }
    s
}

#[async_trait]
impl DatabaseDriver for PostgresDockerDriver {
    fn engine(&self) -> Engine {
        Engine::Postgresql
    }

    fn config(&self) -> &ConnectionConfig {
        &self.cfg
    }

    async fn server_info(&self) -> Result<ServerInfo, DriverError> {
        self.info
            .get_or_try_init(|| async {
                let c = self.client().await?;
                let row = c
                    .query_one(
                        "SELECT current_setting('server_version'), current_setting('server_version_num')::int4, current_database()",
                        &[],
                    )
                    .await
                    .map_err(q)?;
                Ok(ServerInfo {
                    engine: Engine::Postgresql,
                    version: row.get(0),
                    version_num: row.get::<_, i32>(1) as u32,
                    database: row.get(2),
                })
            })
            .await
            .cloned()
    }

    async fn fetch_explain_plan(&self, query: &str, opts: &ExplainOptions) -> Result<serde_json::Value, DriverError> {
        let query = strip_statement(query);
        let analyze = opts.analyze && self.cfg.allow_analyze;
        let options = self.explain_options(&query, analyze).await?;
        let c = self.client().await?;
        c.batch_execute(&format!(
            "BEGIN; SET LOCAL statement_timeout = {}; SET LOCAL lock_timeout = 2000",
            self.cfg.statement_timeout_ms
        ))
        .await
        .map_err(q)?;
        let res = Self::explain_simple(&c, &format!("EXPLAIN ({options}) {query}")).await;
        // Always roll back: EXPLAIN ANALYZE really executes the statement.
        let _ = c.batch_execute("ROLLBACK").await;
        res
    }

    async fn fetch_table_indexes(&self, table_name: &str) -> Result<Vec<IndexMetadata>, DriverError> {
        let c = self.client().await?;
        let rows = c
            .query(
                "SELECT i.relname::text, ix.indisunique, ix.indisprimary, am.amname::text,
                        ix.indpred IS NOT NULL, ix.indexprs IS NOT NULL,
                        pg_get_indexdef(ix.indexrelid), pg_relation_size(ix.indexrelid)::int8,
                        COALESCE(s.idx_scan, 0)::int8,
                        ARRAY(SELECT COALESCE(a.attname::text, '(expr)')
                              FROM unnest(ix.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                              LEFT JOIN pg_attribute a ON a.attrelid = ix.indrelid AND a.attnum = k.attnum
                              WHERE k.ord <= ix.indnkeyatts ORDER BY k.ord),
                        ARRAY(SELECT a.attname::text
                              FROM unnest(ix.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                              JOIN pg_attribute a ON a.attrelid = ix.indrelid AND a.attnum = k.attnum
                              WHERE k.ord > ix.indnkeyatts ORDER BY k.ord)
                 FROM pg_index ix
                 JOIN pg_class i ON i.oid = ix.indexrelid
                 JOIN pg_am am ON am.oid = i.relam
                 LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = ix.indexrelid
                 WHERE ix.indrelid = to_regclass($1)
                 ORDER BY ix.indisprimary DESC, i.relname",
                &[&regclass_literal(table_name)],
            )
            .await
            .map_err(q)?;
        Ok(rows
            .iter()
            .map(|r| IndexMetadata {
                name: r.get(0),
                is_unique: r.get(1),
                is_primary: r.get(2),
                method: r.get(3),
                is_partial: r.get(4),
                has_expressions: r.get(5),
                definition: Some(r.get(6)),
                size_bytes: Some(r.get::<_, i64>(7) as u64),
                scans: Some(r.get::<_, i64>(8) as u64),
                columns: r.get(9),
                include_columns: r.get(10),
            })
            .collect())
    }

    async fn fetch_table_stats(&self, table_name: &str) -> Result<TableStats, DriverError> {
        let c = self.client().await?;
        let row = c
            .query_opt(
                "SELECT GREATEST(c.reltuples, COALESCE(s.n_live_tup, 0))::int8,
                        pg_table_size(c.oid)::int8, pg_indexes_size(c.oid)::int8,
                        s.seq_scan::int8, s.idx_scan::int8, s.n_dead_tup::int8
                 FROM pg_class c LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
                 WHERE c.oid = to_regclass($1)",
                &[&regclass_literal(table_name)],
            )
            .await
            .map_err(q)?
            .ok_or_else(|| DriverError::NotFound(format!("table {table_name}")))?;
        Ok(TableStats {
            total_rows: row.get::<_, i64>(0).max(0) as u64,
            table_size_bytes: row.get::<_, i64>(1) as u64,
            index_size_bytes: row.get::<_, i64>(2) as u64,
            seq_scan: row.get::<_, Option<i64>>(3).map(|v| v as u64),
            idx_scan: row.get::<_, Option<i64>>(4).map(|v| v as u64),
            dead_rows: row.get::<_, Option<i64>>(5).map(|v| v as u64),
        })
    }

    async fn fetch_column_cardinality(&self, table_name: &str, column_name: &str) -> Result<u64, DriverError> {
        let cols = self.fetch_table_columns(table_name).await?;
        Ok(cols
            .iter()
            .find(|c| c.name == column_name)
            .ok_or_else(|| DriverError::NotFound(format!("column {table_name}.{column_name}")))?
            .distinct_values
            .unwrap_or(0))
    }

    async fn fetch_table_columns(&self, table_name: &str) -> Result<Vec<ColumnMetadata>, DriverError> {
        let c = self.client().await?;
        let rows = c
            .query(
                "SELECT a.attname::text, format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
                        s.n_distinct::float8, s.null_frac::float8, GREATEST(c.reltuples, 0)::float8
                 FROM pg_attribute a
                 JOIN pg_class c ON c.oid = a.attrelid
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                 LEFT JOIN pg_stats s ON s.schemaname = n.nspname AND s.tablename = c.relname
                                      AND s.attname = a.attname AND NOT s.inherited
                 WHERE a.attrelid = to_regclass($1) AND a.attnum > 0 AND NOT a.attisdropped
                 ORDER BY a.attnum",
                &[&regclass_literal(table_name)],
            )
            .await
            .map_err(q)?;
        if rows.is_empty() {
            return Err(DriverError::NotFound(format!("table {table_name}")));
        }
        Ok(rows
            .iter()
            .map(|r| {
                let nd: Option<f64> = r.get(3);
                let tuples: f64 = r.get(5);
                ColumnMetadata {
                    name: r.get(0),
                    data_type: r.get(1),
                    nullable: r.get(2),
                    distinct_values: nd.map(|d| if d >= 0.0 { d } else { -d * tuples }.round() as u64),
                    null_fraction: r.get(4),
                }
            })
            .collect())
    }

    async fn fetch_top_queries(&self, limit: usize, order: TopQueryOrder) -> Result<Vec<SlowQueryLog>, DriverError> {
        if !self.has_extension("pg_stat_statements").await {
            return Err(DriverError::Unsupported {
                engine: "PostgreSQL",
                what: "pg_stat_statements is not installed (CREATE EXTENSION pg_stat_statements; and add it to \
                       shared_preload_libraries)"
                    .into(),
            });
        }
        let order_col = match order {
            TopQueryOrder::TotalTime => "total_exec_time",
            TopQueryOrder::MeanTime => "mean_exec_time",
            TopQueryOrder::Calls => "calls",
            TopQueryOrder::Io => "shared_blks_read",
            TopQueryOrder::Rows => "rows",
        };
        let filter = if self.cfg.hide_internal_queries {
            format!("AND {INTERNAL_QUERY_FILTER}")
        } else {
            String::new()
        };
        let sql = format!(
            "SELECT queryid::text, query, calls::int8, total_exec_time::float8, mean_exec_time::float8,
                    max_exec_time::float8, rows::int8, shared_blks_hit::int8, shared_blks_read::int8,
                    (total_exec_time / NULLIF(sum(total_exec_time) OVER (), 0))::float8
             FROM pg_stat_statements
             WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) {filter}
             ORDER BY {order_col} DESC NULLS LAST
             LIMIT $1"
        );
        let c = self.client().await?;
        let rows = c.query(&sql, &[&(limit as i64)]).await.map_err(q)?;
        Ok(rows
            .iter()
            .map(|r| SlowQueryLog {
                query_id: r.get(0),
                query: r.get(1),
                calls: r.get::<_, i64>(2) as u64,
                total_exec_time_ms: r.get(3),
                mean_exec_time_ms: r.get(4),
                max_exec_time_ms: r.get(5),
                rows: r.get::<_, i64>(6) as u64,
                shared_blks_hit: r.get::<_, i64>(7) as u64,
                shared_blks_read: r.get::<_, i64>(8) as u64,
                time_share: r.get(9),
            })
            .collect())
    }

    async fn fetch_database_overview(&self) -> Result<DatabaseOverview, DriverError> {
        let info = self.server_info().await?;
        let c = self.client().await?;
        let r = c
            .query_one(
                "SELECT pg_database_size(current_database())::int8,
                        (SELECT count(*) FROM pg_stat_user_tables)::int8,
                        (SELECT count(*) FROM pg_stat_user_indexes)::int8,
                        (SELECT (blks_hit::float8 / NULLIF(blks_hit + blks_read, 0)) FROM pg_stat_database WHERE datname = current_database()),
                        (SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend')::int8,
                        (SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend' AND state = 'active' AND pid <> pg_backend_pid())::int8,
                        current_setting('max_connections')::int8,
                        (SELECT COALESCE(sum(seq_scan), 0) FROM pg_stat_user_tables)::int8,
                        (SELECT COALESCE(sum(idx_scan), 0) FROM pg_stat_user_tables)::int8,
                        (SELECT COALESCE(sum(n_dead_tup), 0) FROM pg_stat_user_tables)::int8,
                        d.xact_commit::int8, d.xact_rollback::int8, d.deadlocks::int8,
                        extract(epoch FROM now() - pg_postmaster_start_time())::float8,
                        EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'),
                        EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'hypopg')
                 FROM pg_stat_database d WHERE d.datname = current_database()",
                &[],
            )
            .await
            .map_err(q)?;
        let stats_ext: bool = r.get(14);
        let (calls, time) = if stats_ext {
            let s = c
                .query_one(
                    "SELECT COALESCE(sum(calls), 0)::int8, COALESCE(sum(total_exec_time), 0)::float8
                     FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())",
                    &[],
                )
                .await
                .map_err(q)?;
            (Some(s.get::<_, i64>(0) as u64), Some(s.get::<_, f64>(1)))
        } else {
            (None, None)
        };
        Ok(DatabaseOverview {
            engine: Engine::Postgresql,
            server_version: info.version,
            database: info.database,
            database_size_bytes: r.get::<_, i64>(0) as u64,
            table_count: r.get::<_, i64>(1) as u64,
            index_count: r.get::<_, i64>(2) as u64,
            total_statement_calls: calls,
            total_statement_time_ms: time,
            cache_hit_ratio: r.get(3),
            connections_total: r.get::<_, i64>(4) as u64,
            connections_active: r.get::<_, i64>(5) as u64,
            max_connections: Some(r.get::<_, i64>(6) as u64),
            seq_scans: r.get::<_, i64>(7) as u64,
            idx_scans: r.get::<_, i64>(8) as u64,
            dead_rows: r.get::<_, i64>(9) as u64,
            xact_commit: Some(r.get::<_, i64>(10) as u64),
            xact_rollback: Some(r.get::<_, i64>(11) as u64),
            deadlocks: Some(r.get::<_, i64>(12) as u64),
            uptime_s: r.get(13),
            stats_extension: stats_ext,
            hypothetical_indexes: r.get(15),
        })
    }

    async fn fetch_schema_overview(&self) -> Result<Vec<TableOverview>, DriverError> {
        let c = self.client().await?;
        let rows = c
            .query(
                "SELECT t.schemaname::text, t.relname::text, GREATEST(t.n_live_tup, c.reltuples)::int8,
                        pg_table_size(t.relid)::int8, pg_indexes_size(t.relid)::int8, pg_total_relation_size(t.relid)::int8,
                        COALESCE(t.seq_scan, 0)::int8, COALESCE(t.seq_tup_read, 0)::int8, COALESCE(t.idx_scan, 0)::int8,
                        t.n_dead_tup::int8, (SELECT count(*) FROM pg_index i WHERE i.indrelid = t.relid)::int8
                 FROM pg_stat_user_tables t JOIN pg_class c ON c.oid = t.relid
                 ORDER BY pg_total_relation_size(t.relid) DESC",
                &[],
            )
            .await
            .map_err(q)?;
        Ok(rows
            .iter()
            .map(|r| TableOverview {
                schema: r.get(0),
                name: r.get(1),
                rows: r.get::<_, i64>(2).max(0) as u64,
                table_size_bytes: r.get::<_, i64>(3) as u64,
                index_size_bytes: r.get::<_, i64>(4) as u64,
                total_size_bytes: r.get::<_, i64>(5) as u64,
                seq_scan: r.get::<_, i64>(6) as u64,
                seq_tup_read: r.get::<_, i64>(7) as u64,
                idx_scan: r.get::<_, i64>(8) as u64,
                dead_rows: r.get::<_, i64>(9) as u64,
                index_count: r.get::<_, i64>(10) as u64,
            })
            .collect())
    }

    async fn fetch_index_usage(&self) -> Result<Vec<IndexUsage>, DriverError> {
        let c = self.client().await?;
        let rows = c
            .query(
                "SELECT s.schemaname::text, s.relname::text, s.indexrelname::text, COALESCE(s.idx_scan, 0)::int8,
                        pg_relation_size(s.indexrelid)::int8, ix.indisunique, ix.indisprimary, pg_get_indexdef(s.indexrelid),
                        ARRAY(SELECT COALESCE(a.attname::text, '(expr)')
                              FROM unnest(ix.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                              LEFT JOIN pg_attribute a ON a.attrelid = ix.indrelid AND a.attnum = k.attnum
                              WHERE k.ord <= ix.indnkeyatts ORDER BY k.ord)
                 FROM pg_stat_user_indexes s JOIN pg_index ix ON ix.indexrelid = s.indexrelid
                 ORDER BY s.relname, s.indexrelname",
                &[],
            )
            .await
            .map_err(q)?;
        Ok(rows
            .iter()
            .map(|r| IndexUsage {
                schema: r.get(0),
                table: r.get(1),
                index: r.get(2),
                scans: r.get::<_, i64>(3) as u64,
                size_bytes: r.get::<_, i64>(4) as u64,
                is_unique: r.get(5),
                is_primary: r.get(6),
                definition: Some(r.get(7)),
                columns: r.get(8),
            })
            .collect())
    }

    async fn fetch_vacuum_stats(&self) -> Result<Vec<VacuumStat>, DriverError> {
        let c = self.client().await?;
        let ts = |col: &str| format!("to_char({col} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')");
        let sql = format!(
            "SELECT t.schemaname::text, t.relname::text, t.n_live_tup::int8, t.n_dead_tup::int8,
                    COALESCE(round(t.n_dead_tup::numeric / NULLIF(t.n_live_tup + t.n_dead_tup, 0) * 100, 2), 0)::float8,
                    {}, {}, {}, {}, pg_table_size(t.relid)::int8,
                    COALESCE((SELECT option_value FROM pg_options_to_table(c.reloptions)
                              WHERE option_name = 'autovacuum_enabled'), 'true') NOT IN ('false', 'off', '0')
             FROM pg_stat_user_tables t JOIN pg_class c ON c.oid = t.relid
             ORDER BY t.n_dead_tup DESC, t.relname",
            ts("t.last_vacuum"),
            ts("t.last_autovacuum"),
            ts("t.last_analyze"),
            ts("t.last_autoanalyze")
        );
        let rows = c.query(&sql, &[]).await.map_err(q)?;
        Ok(rows
            .iter()
            .map(|r| VacuumStat {
                schema: r.get(0),
                table: r.get(1),
                live_rows: r.get::<_, i64>(2) as u64,
                dead_rows: r.get::<_, i64>(3) as u64,
                dead_pct: r.get(4),
                last_vacuum: r.get(5),
                last_autovacuum: r.get(6),
                last_analyze: r.get(7),
                last_autoanalyze: r.get(8),
                table_size_bytes: r.get::<_, i64>(9) as u64,
                autovacuum_enabled: r.get(10),
            })
            .collect())
    }

    async fn fetch_activity(&self) -> Result<Vec<ActivityRow>, DriverError> {
        let c = self.client().await?;
        let rows = c
            .query(
                "SELECT pid::int8, usename::text, datname::text,
                        COALESCE(host(client_addr), CASE WHEN client_port = -1 THEN 'unix socket' END, 'local'),
                        application_name, state,
                        CASE WHEN wait_event IS NOT NULL THEN wait_event_type || ':' || wait_event END,
                        left(query, 4000),
                        extract(epoch FROM now() - COALESCE(state_change, query_start))::float8,
                        extract(epoch FROM now() - xact_start)::float8
                 FROM pg_stat_activity
                 WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()
                 ORDER BY state = 'active' DESC, xact_start NULLS LAST",
                &[],
            )
            .await
            .map_err(q)?;
        Ok(rows
            .iter()
            .map(|r| ActivityRow {
                pid: r.get(0),
                user: r.get(1),
                database: r.get(2),
                client: r.get(3),
                application: r.get(4),
                state: r.get(5),
                wait_event: r.get(6),
                query: r.get(7),
                duration_s: r.get(8),
                xact_duration_s: r.get(9),
            })
            .collect())
    }

    async fn fetch_blocking_locks(&self) -> Result<Vec<BlockingLock>, DriverError> {
        let c = self.client().await?;
        let rows = c
            .query(
                "SELECT blocked.pid::int8, blocked.usename::text, left(blocked.query, 2000),
                        extract(epoch FROM now() - blocked.query_start)::float8,
                        blocking.pid::int8, blocking.usename::text, left(blocking.query, 2000), blocking.state,
                        wl.locktype, wl.relation::regclass::text
                 FROM pg_stat_activity blocked
                 CROSS JOIN LATERAL unnest(pg_blocking_pids(blocked.pid)) AS b(pid)
                 JOIN pg_stat_activity blocking ON blocking.pid = b.pid
                 LEFT JOIN LATERAL (SELECT locktype, relation FROM pg_locks l
                                    WHERE l.pid = blocked.pid AND NOT l.granted LIMIT 1) wl ON true
                 ORDER BY blocked.query_start",
                &[],
            )
            .await
            .map_err(q)?;
        Ok(rows
            .iter()
            .map(|r| BlockingLock {
                blocked_pid: r.get(0),
                blocked_user: r.get(1),
                blocked_query: r.get(2),
                blocked_duration_s: r.get(3),
                blocking_pid: r.get(4),
                blocking_user: r.get(5),
                blocking_query: r.get(6),
                blocking_state: r.get(7),
                lock_type: r.get(8),
                relation: r.get(9),
            })
            .collect())
    }

    async fn sample_telemetry(&self) -> Result<TelemetrySample, DriverError> {
        let c = self.client().await?;
        let r = c
            .query_one(
                "SELECT count(*) FILTER (WHERE a.state = 'active')::int8,
                        count(*) FILTER (WHERE a.state = 'idle')::int8,
                        count(*) FILTER (WHERE a.state LIKE 'idle in transaction%')::int8,
                        count(*) FILTER (WHERE a.state IS NULL OR a.state NOT IN ('active', 'idle')
                                         AND a.state NOT LIKE 'idle in transaction%')::int8,
                        (SELECT COALESCE(sum(seq_scan), 0) FROM pg_stat_user_tables)::int8,
                        (SELECT COALESCE(sum(idx_scan), 0) FROM pg_stat_user_tables)::int8,
                        (SELECT blks_hit FROM pg_stat_database WHERE datname = current_database())::int8,
                        (SELECT blks_read FROM pg_stat_database WHERE datname = current_database())::int8,
                        (SELECT xact_commit FROM pg_stat_database WHERE datname = current_database())::int8,
                        (SELECT xact_rollback FROM pg_stat_database WHERE datname = current_database())::int8,
                        EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')
                 FROM pg_stat_activity a
                 WHERE a.backend_type = 'client backend' AND a.pid <> pg_backend_pid()",
                &[],
            )
            .await
            .map_err(q)?;
        let (calls, time) = if r.get::<_, bool>(10) {
            let s = c
                .query_one(
                    "SELECT COALESCE(sum(calls), 0)::int8, COALESCE(sum(total_exec_time), 0)::float8
                     FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())",
                    &[],
                )
                .await
                .map_err(q)?;
            (Some(s.get::<_, i64>(0) as u64), Some(s.get::<_, f64>(1)))
        } else {
            (None, None)
        };
        Ok(TelemetrySample {
            ts: chrono::Utc::now().timestamp_millis(),
            statement_calls: calls,
            statement_time_ms: time,
            connections_active: r.get::<_, i64>(0) as u64,
            connections_idle: r.get::<_, i64>(1) as u64,
            connections_idle_in_tx: r.get::<_, i64>(2) as u64,
            connections_other: r.get::<_, i64>(3) as u64,
            seq_scans: r.get::<_, i64>(4) as u64,
            idx_scans: r.get::<_, i64>(5) as u64,
            blks_hit: r.get::<_, i64>(6) as u64,
            blks_read: r.get::<_, i64>(7) as u64,
            xact_commit: r.get::<_, i64>(8) as u64,
            xact_rollback: r.get::<_, i64>(9) as u64,
        })
    }

    async fn hypothetical_costs(
        &self,
        query: &str,
        indexes: &[HypotheticalIndex],
    ) -> Result<Option<HypotheticalReport>, DriverError> {
        if indexes.is_empty() || !self.has_extension("hypopg").await {
            return Ok(None);
        }
        let query = strip_statement(query);
        let options = self.explain_options(&query, false).await?;
        let explain = format!("EXPLAIN ({options}) {query}");
        // Hypothetical indexes live in the backend session, so pin one connection.
        let c = self.client().await?;
        c.batch_execute("SELECT hypopg_reset()").await.map_err(q)?;
        let baseline = Self::explain_simple(&c, &explain).await?;
        let baseline_cost = plan_cost(&baseline).unwrap_or(0.0);

        let mut results = Vec::new();
        let mut created = 0;
        for idx in indexes {
            let ddl = hypopg_ddl(&idx.ddl);
            let res: Result<HypotheticalResult, DriverError> = async {
                let row = c
                    .query_one("SELECT indexrelid::int8, indexname::text FROM hypopg_create_index($1)", &[&ddl])
                    .await
                    .map_err(q)?;
                let oid: i64 = row.get(0);
                let name: String = row.get(1);
                let plan = Self::explain_simple(&c, &explain).await?;
                c.execute("SELECT hypopg_drop_index($1::oid)", &[&(oid as u32)]).await.map_err(q)?;
                Ok(HypotheticalResult {
                    id: idx.id.clone(),
                    cost_after: plan_cost(&plan).unwrap_or(baseline_cost),
                    used: plan.to_string().contains(&name),
                    error: None,
                })
            }
            .await;
            results.push(res.unwrap_or_else(|e| HypotheticalResult {
                id: idx.id.clone(),
                cost_after: baseline_cost,
                used: false,
                error: Some(e.to_string()),
            }));
        }
        for idx in indexes {
            if c.query_one("SELECT 1 FROM hypopg_create_index($1)", &[&hypopg_ddl(&idx.ddl)]).await.is_ok() {
                created += 1;
            }
        }
        let combined = if created > 0 {
            Self::explain_simple(&c, &explain).await.ok()
        } else {
            None
        };
        let _ = c.batch_execute("SELECT hypopg_reset()").await;
        Ok(Some(HypotheticalReport {
            baseline_cost,
            combined_cost: combined.as_ref().and_then(plan_cost),
            combined_plan: combined,
            indexes: results,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hypopg_ddl_strips_options() {
        assert_eq!(
            hypopg_ddl("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON public.t (a, b) INCLUDE (c);"),
            "CREATE INDEX ON public.t (a, b) INCLUDE (c)"
        );
    }

    #[test]
    fn placeholder_detection_ignores_strings() {
        assert!(regex_lite_has_placeholder("select * from t where a = $1"));
        assert!(!regex_lite_has_placeholder("select '$1' from t"));
    }
}
