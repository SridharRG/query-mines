//! Deterministic query-analysis core: parsing, predicate extraction, index
//! advice, anti-pattern rewrites, EXPLAIN plan analysis and the YAML rule
//! engine. Nothing in this crate performs I/O.

pub mod advisor;
pub mod analysis;
pub mod facts;
pub mod health;
pub mod model;
pub mod plan;
pub mod rewrite;
pub mod rules;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("SQL parse error: {0}")]
    Parse(String),
    #[error("rules error: {0}")]
    Rules(String),
}
