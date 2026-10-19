//! AI reasoning layer: `rig` + Groq. The model never guesses indexes from
//! raw SQL — it receives the parsed facts, schema metadata, the EXPLAIN plan
//! and the deterministic engine's recommendations, and explains / extends them.

use std::time::Instant;

use qm_core::model::Engine;
use rig_core::completion::CompletionRequest;
use rig_core::providers::groq;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_model")]
    pub model: String,
    /// Tried in order when the primary model errors (decommissioned, rate-limited...).
    #[serde(default = "default_fallbacks")]
    pub fallback_models: Vec<String>,
    #[serde(default = "default_temperature")]
    pub temperature: f64,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u64,
    /// EXPLAIN JSON is truncated to this many characters before prompting.
    #[serde(default = "default_plan_chars")]
    pub max_plan_chars: usize,
    /// Plans costing at least this much are flagged for AI review.
    #[serde(default = "default_cost_threshold")]
    pub cost_threshold: f64,
}

fn yes() -> bool {
    true
}
fn default_model() -> String {
    "openai/gpt-oss-120b".into()
}
fn default_fallbacks() -> Vec<String> {
    vec!["qwen/qwen3.8-27b".into(), "openai/gpt-oss-20b".into()]
}
fn default_temperature() -> f64 {
    0.2
}
fn default_max_tokens() -> u64 {
    4096
}
fn default_plan_chars() -> usize {
    14_000
}
fn default_cost_threshold() -> f64 {
    10_000.0
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model: default_model(),
            fallback_models: default_fallbacks(),
            temperature: default_temperature(),
            max_tokens: default_max_tokens(),
            max_plan_chars: default_plan_chars(),
            cost_threshold: default_cost_threshold(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("AI is disabled or GROQ_API_KEY is not set")]
    Disabled,
    #[error("Groq request failed: {0}")]
    Provider(String),
    #[error("model returned an unusable answer: {0}")]
    BadAnswer(String),
}

/// Everything the model gets to see about one query.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QueryContext {
    pub engine: Engine,
    pub sql: String,
    /// Compact schema description: tables, columns with distinct counts, indexes, row counts.
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub explain_json: Option<serde_json::Value>,
    #[serde(default)]
    pub recommended_ddl: Vec<String>,
    /// Deterministic findings (rule hits, plan findings, rewrites) as short lines.
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub deterministic_rewrite: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiAnswer {
    pub text: String,
    pub model: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiRewrite {
    pub rewritten_sql: Option<String>,
    pub explanation: String,
    #[serde(default)]
    pub changes: Vec<String>,
    /// "exact" or "conditional"
    #[serde(default)]
    pub equivalence: Option<String>,
    #[serde(default)]
    pub conditions: Option<String>,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub elapsed_ms: u64,
    /// Whether the rewritten SQL parsed successfully.
    #[serde(default)]
    pub parses: bool,
}

#[derive(Clone)]
pub struct AiClient {
    client: rig_core::providers::openai::OpenAI,
    cfg: AiConfig,
}

const IMPACT_PREAMBLE: &str = "You are a principal Database Reliability Engineer and query optimizer. \
Analyze the provided EXPLAIN JSON, SQL query, schema statistics and the recommended index DDL produced by a \
deterministic rule engine. Write a concise, highly technical performance impact statement in Markdown with \
these sections: **Current plan** (scan types, row estimates vs actuals, the dominant cost), **Why this index \
order** (equality → range → sort reasoning, selectivity), **Expected impact** (which plan nodes change and an \
order-of-magnitude estimate), **Risks** (write amplification, index size, locking — CONCURRENTLY). Under 250 \
words. Never invent tables, columns or numbers that are not in the input; say 'unknown' instead.";

const REWRITE_PREAMBLE: &str = "You are a senior query optimizer. Propose a semantically equivalent rewrite of \
the given SQL that is cheaper to execute on the stated engine, using the schema statistics and EXPLAIN plan. \
Focus on structure the rule engine cannot handle: recursive CTEs, correlated subqueries in SELECT lists, \
repeated subqueries, window-function replacements for self-joins, pushing predicates into CTEs/derived tables, \
replacing DISTINCT with EXISTS. Keep all output columns, their order and their names identical. If no \
worthwhile rewrite exists, return rewritten_sql = null. Respond with ONLY a JSON object, no prose, no code \
fences: {\"rewritten_sql\": string|null, \"explanation\": string, \"changes\": [string], \
\"equivalence\": \"exact\"|\"conditional\", \"conditions\": string|null}";

impl AiClient {
    /// Builds a client from `GROQ_API_KEY`; `None` when disabled or unset.
    pub fn from_env(cfg: AiConfig) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let key = std::env::var("GROQ_API_KEY").ok().filter(|k| !k.trim().is_empty())?;
        Some(Self {
            client: groq::new(key),
            cfg,
        })
    }

    pub fn config(&self) -> &AiConfig {
        &self.cfg
    }

    async fn complete(&self, preamble: &str, prompt: String) -> Result<AiAnswer, AiError> {
        let started = Instant::now();
        let mut last_err = String::new();
        let models = std::iter::once(&self.cfg.model).chain(self.cfg.fallback_models.iter());
        for model_id in models {
            let model = self.client.completion(model_id.clone());
            let req = CompletionRequest::new(prompt.clone())
                .preamble(preamble)
                .temperature(self.cfg.temperature)
                .max_tokens(self.cfg.max_tokens);
            match model.call(req).await {
                Ok(resp) => {
                    let text = resp.text().trim().to_string();
                    if text.is_empty() {
                        last_err = format!("{model_id}: empty response");
                        continue;
                    }
                    return Ok(AiAnswer {
                        text,
                        model: model_id.clone(),
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    });
                }
                Err(e) => {
                    tracing::warn!(model = %model_id, error = %e, "Groq completion failed, trying fallback");
                    last_err = format!("{model_id}: {e}");
                }
            }
        }
        Err(AiError::Provider(last_err))
    }

    fn render_context(&self, ctx: &QueryContext) -> String {
        let mut p = format!("Engine: {}\n\nSQL Query:\n{}\n", ctx.engine.label(), ctx.sql.trim());
        if let Some(schema) = &ctx.schema {
            p.push_str(&format!("\nSchema & statistics:\n{schema}\n"));
        }
        if let Some(plan) = &ctx.explain_json {
            let mut s = serde_json::to_string(plan).unwrap_or_default();
            if s.len() > self.cfg.max_plan_chars {
                let cut = (0..=self.cfg.max_plan_chars).rev().find(|i| s.is_char_boundary(*i)).unwrap_or(0);
                s.truncate(cut);
                s.push_str("…(truncated)");
            }
            p.push_str(&format!("\nEXPLAIN Plan JSON:\n{s}\n"));
        } else {
            p.push_str("\nEXPLAIN Plan JSON: unavailable (no database connection)\n");
        }
        if !ctx.findings.is_empty() {
            p.push_str("\nDeterministic findings:\n");
            for f in &ctx.findings {
                p.push_str(&format!("- {f}\n"));
            }
        }
        if let Some(rw) = &ctx.deterministic_rewrite {
            p.push_str(&format!("\nRule-engine rewrite already applied:\n{rw}\n"));
        }
        p
    }

    pub async fn impact_summary(&self, ctx: &QueryContext) -> Result<AiAnswer, AiError> {
        let mut prompt = self.render_context(ctx);
        if ctx.recommended_ddl.is_empty() {
            prompt.push_str("\nProposed DDL: none (the rule engine found no index to add).\n");
        } else {
            prompt.push_str(&format!("\nProposed DDL:\n{}\n", ctx.recommended_ddl.join("\n")));
        }
        self.complete(IMPACT_PREAMBLE, prompt).await
    }

    pub async fn rewrite(&self, ctx: &QueryContext) -> Result<AiRewrite, AiError> {
        let prompt = self.render_context(ctx);
        let answer = self.complete(REWRITE_PREAMBLE, prompt).await?;
        let json = extract_json(&answer.text).ok_or_else(|| AiError::BadAnswer(answer.text.clone()))?;
        let mut rw: AiRewrite =
            serde_json::from_value(json).map_err(|e| AiError::BadAnswer(format!("{e}: {}", answer.text)))?;
        rw.model = answer.model;
        rw.elapsed_ms = answer.elapsed_ms;
        if let Some(sql) = &rw.rewritten_sql {
            let sql = sql.trim().to_string();
            rw.parses = qm_core::facts::parse_sql(&sql, ctx.engine).is_ok();
            rw.rewritten_sql = Some(sql);
        }
        Ok(rw)
    }
}

/// Pull the first JSON object out of a model answer (tolerates code fences / prose).
fn extract_json(text: &str) -> Option<serde_json::Value> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&text[start..=end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_json_from_fenced_answer() {
        let v = extract_json("```json\n{\"rewritten_sql\": null, \"explanation\": \"none\"}\n```").unwrap();
        assert_eq!(v["explanation"], "none");
    }
}
