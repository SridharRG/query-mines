//! MySQL / MariaDB driver (information_schema + performance_schema).

use std::collections::HashMap;

use async_trait::async_trait;
use mysql_async::prelude::*;
use mysql_async::{Conn, Opts, OptsBuilder, Pool, PoolConstraints, PoolOpts, Row};
use tokio::sync::OnceCell;

use crate::*;

pub struct MySqlDriver {
    cfg: ConnectionConfig,
    pool: Pool,
    info: OnceCell<ServerInfo>,
}

fn q(e: mysql_async::Error) -> DriverError {
    DriverError::Query(e.to_string())
}

fn s(r: &Row, i: usize) -> Option<String> {
    r.get_opt::<Option<String>, _>(i).and_then(|v| v.ok()).flatten()
}
fn u(r: &Row, i: usize) -> u64 {
    r.get_opt::<Option<f64>, _>(i)
        .and_then(|v| v.ok())
        .flatten()
        .map(|v| v.max(0.0) as u64)
        .unwrap_or(0)
}
fn f(r: &Row, i: usize) -> Option<f64> {
    r.get_opt::<Option<f64>, _>(i).and_then(|v| v.ok()).flatten()
}

impl MySqlDriver {
    pub async fn connect(cfg: ConnectionConfig) -> Result<Self, DriverError> {
        let opts = Opts::from_url(&cfg.url).map_err(|e| DriverError::Connection(e.to_string()))?;
        let constraints = PoolConstraints::new(1, cfg.pool_size.max(1)).unwrap_or_default();
        let opts = OptsBuilder::from_opts(opts).pool_opts(PoolOpts::default().with_constraints(constraints));
        let pool = Pool::new(opts);
        let driver = Self {
            cfg,
            pool,
            info: OnceCell::new(),
        };
        driver.server_info().await?;
        Ok(driver)
    }

    async fn conn(&self) -> Result<Conn, DriverError> {
        self.pool.get_conn().await.map_err(|e| DriverError::Connection(e.to_string()))
    }

    async fn status(&self, conn: &mut Conn) -> Result<HashMap<String, f64>, DriverError> {
        let rows: Vec<(String, String)> = conn.query("SHOW GLOBAL STATUS").await.map_err(q)?;
        Ok(rows
            .into_iter()
            .filter_map(|(k, v)| v.parse::<f64>().ok().map(|n| (k.to_lowercase(), n)))
            .collect())
    }

    fn split<'a>(&self, table: &'a str) -> (String, &'a str) {
        let (schema, t) = split_table(table);
        (
            schema.map(String::from).unwrap_or_else(|| "DATABASE()".to_string()),
            t,
        )
    }

    fn schema_expr(&self, schema: &str) -> String {
        if schema == "DATABASE()" {
            schema.to_string()
        } else {
            format!("'{}'", schema.replace('\'', "''"))
        }
    }
}

#[async_trait]
impl DatabaseDriver for MySqlDriver {
    fn engine(&self) -> Engine {
        Engine::Mysql
    }

    fn config(&self) -> &ConnectionConfig {
        &self.cfg
    }

    async fn server_info(&self) -> Result<ServerInfo, DriverError> {
        self.info
            .get_or_try_init(|| async {
                let mut c = self.conn().await?;
                let row: Option<(String, Option<String>)> =
                    c.query_first("SELECT VERSION(), DATABASE()").await.map_err(q)?;
                let (version, db) = row.unwrap_or_default();
                let num = version
                    .split(|c: char| !c.is_ascii_digit())
                    .filter(|p| !p.is_empty())
                    .take(3)
                    .filter_map(|p| p.parse::<u32>().ok())
                    .fold(0u32, |acc, p| acc * 100 + p);
                Ok(ServerInfo {
                    engine: Engine::Mysql,
                    version,
                    version_num: num,
                    database: db.unwrap_or_default(),
                })
            })
            .await
            .cloned()
    }

    async fn fetch_explain_plan(&self, query: &str, _opts: &ExplainOptions) -> Result<serde_json::Value, DriverError> {
        let mut c = self.conn().await?;
        let text: Option<String> = c
            .query_first(format!("EXPLAIN FORMAT=JSON {}", strip_statement(query)))
            .await
            .map_err(q)?;
        let text = text.ok_or_else(|| DriverError::Query("EXPLAIN returned no rows".into()))?;
        serde_json::from_str(&text).map_err(|e| DriverError::Query(format!("bad EXPLAIN JSON: {e}")))
    }

    async fn fetch_table_indexes(&self, table_name: &str) -> Result<Vec<IndexMetadata>, DriverError> {
        let (schema, table) = self.split(table_name);
        let mut c = self.conn().await?;
        let rows: Vec<Row> = c
            .exec(
                format!(
                    "SELECT INDEX_NAME, NON_UNIQUE, INDEX_TYPE, COLUMN_NAME, SEQ_IN_INDEX, SUB_PART
                     FROM information_schema.STATISTICS
                     WHERE TABLE_SCHEMA = {} AND TABLE_NAME = ?
                     ORDER BY INDEX_NAME, SEQ_IN_INDEX",
                    self.schema_expr(&schema)
                ),
                (table,),
            )
            .await
            .map_err(q)?;
        let mut out: Vec<IndexMetadata> = Vec::new();
        for r in rows {
            let name = s(&r, 0).unwrap_or_default();
            let col = s(&r, 3);
            let entry = match out.iter_mut().find(|i| i.name == name) {
                Some(e) => e,
                None => {
                    out.push(IndexMetadata {
                        is_primary: name == "PRIMARY",
                        is_unique: u(&r, 1) == 0,
                        method: s(&r, 2).unwrap_or_default().to_lowercase(),
                        name: name.clone(),
                        ..Default::default()
                    });
                    out.last_mut().unwrap()
                }
            };
            match col {
                Some(c) => entry.columns.push(c),
                None => {
                    entry.has_expressions = true;
                    entry.columns.push("(expr)".into());
                }
            }
            if f(&r, 5).is_some() {
                entry.is_partial = true; // prefix index: only part of the column is indexed
            }
        }
        Ok(out)
    }

    async fn fetch_table_stats(&self, table_name: &str) -> Result<TableStats, DriverError> {
        let (schema, table) = self.split(table_name);
        let mut c = self.conn().await?;
        let row: Option<Row> = c
            .exec_first(
                format!(
                    "SELECT TABLE_ROWS, DATA_LENGTH, INDEX_LENGTH FROM information_schema.TABLES
                     WHERE TABLE_SCHEMA = {} AND TABLE_NAME = ?",
                    self.schema_expr(&schema)
                ),
                (table,),
            )
            .await
            .map_err(q)?;
        let r = row.ok_or_else(|| DriverError::NotFound(format!("table {table_name}")))?;
        Ok(TableStats {
            total_rows: u(&r, 0),
            table_size_bytes: u(&r, 1),
            index_size_bytes: u(&r, 2),
            ..Default::default()
        })
    }

    async fn fetch_column_cardinality(&self, table_name: &str, column_name: &str) -> Result<u64, DriverError> {
        let cols = self.fetch_table_columns(table_name).await?;
        Ok(cols
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(column_name))
            .and_then(|c| c.distinct_values)
            .unwrap_or(0))
    }

    async fn fetch_table_columns(&self, table_name: &str) -> Result<Vec<ColumnMetadata>, DriverError> {
        let (schema, table) = self.split(table_name);
        let schema = self.schema_expr(&schema);
        let mut c = self.conn().await?;
        // Index cardinality of the leading column is the only per-column
        // distinct estimate MySQL keeps without histograms.
        let rows: Vec<Row> = c
            .exec(
                format!(
                    "SELECT c.COLUMN_NAME, c.COLUMN_TYPE, c.IS_NULLABLE = 'YES',
                            (SELECT MAX(s.CARDINALITY) FROM information_schema.STATISTICS s
                             WHERE s.TABLE_SCHEMA = c.TABLE_SCHEMA AND s.TABLE_NAME = c.TABLE_NAME
                               AND s.COLUMN_NAME = c.COLUMN_NAME AND s.SEQ_IN_INDEX = 1)
                     FROM information_schema.COLUMNS c
                     WHERE c.TABLE_SCHEMA = {schema} AND c.TABLE_NAME = ?
                     ORDER BY c.ORDINAL_POSITION"
                ),
                (table,),
            )
            .await
            .map_err(q)?;
        if rows.is_empty() {
            return Err(DriverError::NotFound(format!("table {table_name}")));
        }
        Ok(rows
            .iter()
            .map(|r| ColumnMetadata {
                name: s(r, 0).unwrap_or_default(),
                data_type: s(r, 1).unwrap_or_default(),
                nullable: u(r, 2) == 1,
                distinct_values: f(r, 3).map(|v| v as u64).filter(|v| *v > 0),
                null_fraction: None,
            })
            .collect())
    }

    async fn fetch_top_queries(&self, limit: usize, order: TopQueryOrder) -> Result<Vec<SlowQueryLog>, DriverError> {
        let order_col = match order {
            TopQueryOrder::TotalTime => "SUM_TIMER_WAIT",
            TopQueryOrder::MeanTime => "AVG_TIMER_WAIT",
            TopQueryOrder::Calls => "COUNT_STAR",
            TopQueryOrder::Io => "SUM_ROWS_EXAMINED",
            TopQueryOrder::Rows => "SUM_ROWS_SENT",
        };
        let filter = if self.cfg.hide_internal_queries {
            "AND DIGEST_TEXT NOT REGEXP '(information_schema|performance_schema|^SHOW |^EXPLAIN|^SET |@@)'"
        } else {
            ""
        };
        let mut c = self.conn().await?;
        let rows: Vec<Row> = c
            .exec(
                format!(
                    "SELECT DIGEST, DIGEST_TEXT, COUNT_STAR, SUM_TIMER_WAIT / 1e9, AVG_TIMER_WAIT / 1e9,
                            MAX_TIMER_WAIT / 1e9, SUM_ROWS_SENT, SUM_ROWS_EXAMINED,
                            SUM_TIMER_WAIT / NULLIF((SELECT SUM(SUM_TIMER_WAIT) FROM performance_schema.events_statements_summary_by_digest
                                                    WHERE SCHEMA_NAME = DATABASE()), 0)
                     FROM performance_schema.events_statements_summary_by_digest
                     WHERE SCHEMA_NAME = DATABASE() AND DIGEST_TEXT IS NOT NULL {filter}
                     ORDER BY {order_col} DESC LIMIT ?"
                ),
                (limit as u64,),
            )
            .await
            .map_err(|e| DriverError::Unsupported {
                engine: "MySQL",
                what: format!("performance_schema digests unavailable: {e}"),
            })?;
        Ok(rows
            .iter()
            .map(|r| SlowQueryLog {
                query_id: s(r, 0),
                query: s(r, 1).unwrap_or_default(),
                calls: u(r, 2),
                total_exec_time_ms: f(r, 3).unwrap_or(0.0),
                mean_exec_time_ms: f(r, 4).unwrap_or(0.0),
                max_exec_time_ms: f(r, 5),
                rows: u(r, 6),
                shared_blks_hit: 0,
                shared_blks_read: u(r, 7),
                time_share: f(r, 8),
            })
            .collect())
    }

    async fn fetch_database_overview(&self) -> Result<DatabaseOverview, DriverError> {
        let info = self.server_info().await?;
        let mut c = self.conn().await?;
        let r: Option<Row> = c
            .query_first(
                "SELECT (SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()),
                        (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'),
                        (SELECT COUNT(DISTINCT TABLE_NAME, INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()),
                        @@max_connections",
            )
            .await
            .map_err(q)?;
        let r = r.ok_or_else(|| DriverError::Query("overview returned no rows".into()))?;
        let st = self.status(&mut c).await?;
        let g = |k: &str| st.get(k).copied().unwrap_or(0.0);
        let reads = g("innodb_buffer_pool_read_requests");
        let digests: Option<(Option<f64>, Option<f64>)> = c
            .query_first(
                "SELECT SUM(COUNT_STAR), SUM(SUM_TIMER_WAIT) / 1e9 FROM performance_schema.events_statements_summary_by_digest WHERE SCHEMA_NAME = DATABASE()",
            )
            .await
            .ok()
            .flatten();
        Ok(DatabaseOverview {
            engine: Engine::Mysql,
            server_version: info.version,
            database: info.database,
            database_size_bytes: u(&r, 0),
            table_count: u(&r, 1),
            index_count: u(&r, 2),
            total_statement_calls: digests.and_then(|d| d.0).map(|v| v as u64),
            total_statement_time_ms: digests.and_then(|d| d.1),
            cache_hit_ratio: (reads > 0.0).then(|| 1.0 - g("innodb_buffer_pool_reads") / reads),
            connections_total: g("threads_connected") as u64,
            connections_active: (g("threads_running") as u64).saturating_sub(1),
            max_connections: Some(u(&r, 3)),
            seq_scans: g("select_scan") as u64,
            idx_scans: (g("handler_read_key")) as u64,
            dead_rows: 0,
            xact_commit: Some(g("com_commit") as u64),
            xact_rollback: Some(g("com_rollback") as u64),
            deadlocks: st.get("innodb_deadlocks").map(|v| *v as u64),
            uptime_s: Some(g("uptime")),
            stats_extension: digests.is_some(),
            hypothetical_indexes: false,
        })
    }

    async fn fetch_schema_overview(&self) -> Result<Vec<TableOverview>, DriverError> {
        let mut c = self.conn().await?;
        let rows: Vec<Row> = c
            .query(
                "SELECT t.TABLE_SCHEMA, t.TABLE_NAME, t.TABLE_ROWS, t.DATA_LENGTH, t.INDEX_LENGTH,
                        (SELECT COUNT(DISTINCT s.INDEX_NAME) FROM information_schema.STATISTICS s
                         WHERE s.TABLE_SCHEMA = t.TABLE_SCHEMA AND s.TABLE_NAME = t.TABLE_NAME)
                 FROM information_schema.TABLES t
                 WHERE t.TABLE_SCHEMA = DATABASE() AND t.TABLE_TYPE = 'BASE TABLE'
                 ORDER BY t.DATA_LENGTH + t.INDEX_LENGTH DESC",
            )
            .await
            .map_err(q)?;
        // Per-table read counters from performance_schema (rows with no index = full scans).
        let io: Vec<Row> = c
            .query(
                "SELECT OBJECT_NAME, SUM(CASE WHEN INDEX_NAME IS NULL THEN COUNT_FETCH ELSE 0 END),
                        SUM(CASE WHEN INDEX_NAME IS NOT NULL THEN COUNT_FETCH ELSE 0 END)
                 FROM performance_schema.table_io_waits_summary_by_index_usage
                 WHERE OBJECT_SCHEMA = DATABASE() GROUP BY OBJECT_NAME",
            )
            .await
            .unwrap_or_default();
        let io: HashMap<String, (u64, u64)> = io.iter().map(|r| (s(r, 0).unwrap_or_default(), (u(r, 1), u(r, 2)))).collect();
        Ok(rows
            .iter()
            .map(|r| {
                let name = s(r, 1).unwrap_or_default();
                let (seq, idx) = io.get(&name).copied().unwrap_or((0, 0));
                TableOverview {
                    schema: s(r, 0).unwrap_or_default(),
                    rows: u(r, 2),
                    table_size_bytes: u(r, 3),
                    index_size_bytes: u(r, 4),
                    total_size_bytes: u(r, 3) + u(r, 4),
                    seq_scan: 0,
                    seq_tup_read: seq,
                    idx_scan: idx,
                    dead_rows: 0,
                    index_count: u(r, 5),
                    name,
                }
            })
            .collect())
    }

    async fn fetch_index_usage(&self) -> Result<Vec<IndexUsage>, DriverError> {
        let mut c = self.conn().await?;
        let rows: Vec<Row> = c
            .query(
                "SELECT s.TABLE_SCHEMA, s.TABLE_NAME, s.INDEX_NAME, GROUP_CONCAT(s.COLUMN_NAME ORDER BY s.SEQ_IN_INDEX),
                        MIN(s.NON_UNIQUE), COALESCE(MAX(io.COUNT_STAR), 0)
                 FROM information_schema.STATISTICS s
                 LEFT JOIN performance_schema.table_io_waits_summary_by_index_usage io
                   ON io.OBJECT_SCHEMA = s.TABLE_SCHEMA AND io.OBJECT_NAME = s.TABLE_NAME AND io.INDEX_NAME = s.INDEX_NAME
                 WHERE s.TABLE_SCHEMA = DATABASE()
                 GROUP BY s.TABLE_SCHEMA, s.TABLE_NAME, s.INDEX_NAME
                 ORDER BY s.TABLE_NAME, s.INDEX_NAME",
            )
            .await
            .map_err(q)?;
        Ok(rows
            .iter()
            .map(|r| {
                let index = s(r, 2).unwrap_or_default();
                IndexUsage {
                    schema: s(r, 0).unwrap_or_default(),
                    table: s(r, 1).unwrap_or_default(),
                    columns: s(r, 3).unwrap_or_default().split(',').map(String::from).collect(),
                    is_unique: u(r, 4) == 0,
                    is_primary: index == "PRIMARY",
                    scans: u(r, 5),
                    size_bytes: 0,
                    definition: None,
                    index,
                }
            })
            .collect())
    }

    async fn fetch_vacuum_stats(&self) -> Result<Vec<VacuumStat>, DriverError> {
        Err(DriverError::Unsupported {
            engine: "MySQL",
            what: "InnoDB purges old row versions automatically; there is no VACUUM. Use OPTIMIZE TABLE to reclaim space."
                .into(),
        })
    }

    async fn fetch_activity(&self) -> Result<Vec<ActivityRow>, DriverError> {
        let mut c = self.conn().await?;
        let rows: Vec<Row> = c
            .query(
                "SELECT p.ID, p.USER, p.DB, p.HOST, p.COMMAND, p.STATE, p.INFO, p.TIME, trx.secs
                 FROM information_schema.PROCESSLIST p
                 LEFT JOIN (SELECT trx_mysql_thread_id AS tid, TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS secs
                            FROM information_schema.INNODB_TRX) trx ON trx.tid = p.ID
                 WHERE p.ID <> CONNECTION_ID() AND p.COMMAND <> 'Daemon'
                 ORDER BY p.TIME DESC",
            )
            .await
            .map_err(q)?;
        Ok(rows
            .iter()
            .map(|r| {
                let command = s(r, 4).unwrap_or_default();
                let in_tx = f(r, 8).is_some();
                let state = match command.as_str() {
                    "Sleep" if in_tx => "idle in transaction",
                    "Sleep" => "idle",
                    "Query" | "Execute" => "active",
                    other => other,
                };
                ActivityRow {
                    pid: u(r, 0) as i64,
                    user: s(r, 1),
                    database: s(r, 2),
                    client: s(r, 3),
                    application: None,
                    state: Some(state.to_string()),
                    wait_event: s(r, 5).filter(|v| !v.is_empty()),
                    query: s(r, 6),
                    duration_s: f(r, 7),
                    xact_duration_s: f(r, 8),
                }
            })
            .collect())
    }

    async fn fetch_blocking_locks(&self) -> Result<Vec<BlockingLock>, DriverError> {
        let mut c = self.conn().await?;
        let rows: Vec<Row> = c
            .query(
                "SELECT waiting_pid, waiting_query, wait_age_secs, blocking_pid, blocking_query, locked_type, locked_table
                 FROM sys.innodb_lock_waits",
            )
            .await
            .unwrap_or_default();
        Ok(rows
            .iter()
            .map(|r| BlockingLock {
                blocked_pid: u(r, 0) as i64,
                blocked_user: None,
                blocked_query: s(r, 1),
                blocked_duration_s: f(r, 2),
                blocking_pid: u(r, 3) as i64,
                blocking_user: None,
                blocking_query: s(r, 4),
                blocking_state: None,
                lock_type: s(r, 5),
                relation: s(r, 6),
            })
            .collect())
    }

    async fn sample_telemetry(&self) -> Result<TelemetrySample, DriverError> {
        let mut c = self.conn().await?;
        let st = self.status(&mut c).await?;
        let g = |k: &str| st.get(k).copied().unwrap_or(0.0) as u64;
        let states: Vec<(String, u64)> = c
            .query(
                "SELECT CASE WHEN COMMAND = 'Sleep' AND trx.tid IS NOT NULL THEN 'idle_tx'
                             WHEN COMMAND = 'Sleep' THEN 'idle'
                             WHEN COMMAND IN ('Query', 'Execute') THEN 'active' ELSE 'other' END, COUNT(*)
                 FROM information_schema.PROCESSLIST p
                 LEFT JOIN (SELECT trx_mysql_thread_id AS tid FROM information_schema.INNODB_TRX) trx ON trx.tid = p.ID
                 WHERE p.ID <> CONNECTION_ID() AND p.COMMAND <> 'Daemon' GROUP BY 1",
            )
            .await
            .unwrap_or_default();
        let count = |k: &str| states.iter().find(|(s, _)| s == k).map(|(_, n)| *n).unwrap_or(0);
        let digests: Option<(Option<f64>, Option<f64>)> = c
            .query_first(
                "SELECT SUM(COUNT_STAR), SUM(SUM_TIMER_WAIT) / 1e9 FROM performance_schema.events_statements_summary_by_digest WHERE SCHEMA_NAME = DATABASE()",
            )
            .await
            .ok()
            .flatten();
        Ok(TelemetrySample {
            ts: chrono::Utc::now().timestamp_millis(),
            statement_calls: digests.and_then(|d| d.0).map(|v| v as u64),
            statement_time_ms: digests.and_then(|d| d.1),
            connections_active: count("active"),
            connections_idle: count("idle"),
            connections_idle_in_tx: count("idle_tx"),
            connections_other: count("other"),
            seq_scans: g("select_scan"),
            idx_scans: g("handler_read_key"),
            blks_hit: g("innodb_buffer_pool_read_requests").saturating_sub(g("innodb_buffer_pool_reads")),
            blks_read: g("innodb_buffer_pool_reads"),
            xact_commit: g("com_commit"),
            xact_rollback: g("com_rollback"),
        })
    }
}
