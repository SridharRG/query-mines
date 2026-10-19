use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use qm_ai::AiConfig;
use qm_drivers::ConnectionConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default = "default_rules_path")]
    pub rules_path: PathBuf,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub connections: Vec<ConnectionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Built frontend (`web/dist`) served at `/` when present.
    #[serde(default = "default_static")]
    pub static_dir: PathBuf,
    #[serde(default = "default_origins")]
    pub cors_origins: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            static_dir: default_static(),
            cors_origins: default_origins(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Samples kept per connection (ring buffer).
    #[serde(default = "default_retention")]
    pub retention: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval(),
            retention: default_retention(),
        }
    }
}

fn default_rules_path() -> PathBuf {
    "config/rules/default.yaml".into()
}
fn default_bind() -> String {
    "127.0.0.1:8787".into()
}
fn default_static() -> PathBuf {
    "web/dist".into()
}
fn default_origins() -> Vec<String> {
    vec!["http://localhost:5173".into(), "http://127.0.0.1:5173".into()]
}
fn default_interval() -> u64 {
    5
}
fn default_retention() -> usize {
    720
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let expanded = expand_env(&raw)?;
        let cfg: AppConfig = serde_yaml::from_str(&expanded).with_context(|| format!("parsing {}", path.display()))?;
        let mut ids = std::collections::HashSet::new();
        for c in &cfg.connections {
            anyhow::ensure!(ids.insert(c.id.clone()), "duplicate connection id `{}`", c.id);
        }
        Ok(cfg)
    }
}

/// Expand `${VAR}` and `${VAR:-default}` (comment lines are left alone).
fn expand_env(input: &str) -> Result<String> {
    input
        .split_inclusive('\n')
        .map(|line| {
            if line.trim_start().starts_with('#') {
                Ok(line.to_string())
            } else {
                expand_line(line)
            }
        })
        .collect()
}

fn expand_line(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').context("unterminated ${ in config")?;
        let expr = &after[..end];
        let (name, default) = match expr.split_once(":-") {
            Some((n, d)) => (n, Some(d)),
            None => (expr, None),
        };
        match (std::env::var(name), default) {
            (Ok(v), _) => out.push_str(&v),
            (Err(_), Some(d)) => out.push_str(d),
            (Err(_), None) => anyhow::bail!("config references ${{{name}}} but it is not set"),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_defaults() {
        std::env::set_var("QM_TEST_X", "abc");
        assert_eq!(expand_env("a ${QM_TEST_X} ${QM_TEST_MISSING:-d}").unwrap(), "a abc d");
        assert!(expand_env("${QM_TEST_MISSING_2}").is_err());
        assert_eq!(expand_env("# ${NOPE}\nx: 1").unwrap(), "# ${NOPE}\nx: 1");
    }
}
