//! Top-level orchestrator: glue the parser, rule engine, RIS, and (optionally)
//! the optimizer into one `Report`.
//!
//! Two entry points:
//! * [`Report::build_security`]  — parser + rules + RIS only. This is the
//!   `<10ms` static-analysis hot path; the optimization pass is skipped so the
//!   `scan` and `bench` subcommands stay snappy.
//! * [`Report::build_full`] / [`Report::build_full_with`] — adds the
//!   description-optimization pass. Used by `ironcontext optimize`.

use serde::{Deserialize, Serialize};

use crate::manifest::Manifest;
use crate::optimizer::{DescriptionOptimizer, HeuristicOptimizer, OptimizationOutcome};
use crate::ris::{score_manifest, RisScore};
use crate::rules::{run_all, Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub server_name: String,
    pub server_version: String,
    pub findings: Vec<Finding>,
    pub tools: Vec<ToolReport>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolReport {
    pub name: String,
    pub ris: RisScore,
    /// `None` for security-only scans; `Some(_)` when the optimizer pass ran.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub optimization: Option<OptimizationOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total_tools: usize,
    pub total_findings: usize,
    pub findings_by_severity: std::collections::BTreeMap<String, usize>,
    pub mean_ris: f32,
    /// `None` when the optimizer was skipped.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mean_token_reduction_pct: Option<f32>,
}

impl Report {
    /// Build the security-only report (parser + rules + RIS). The hot path
    /// that meets the `<10ms` latency target.
    pub fn build_security(manifest: &Manifest) -> Self {
        Self::assemble(manifest, None::<&HeuristicOptimizer>)
    }

    /// Build the full report including the optimization pass with the default
    /// heuristic optimizer.
    pub fn build_full(manifest: &Manifest) -> Self {
        Self::assemble(manifest, Some(&HeuristicOptimizer::default()))
    }

    /// Build a full report using a caller-supplied optimizer (e.g. an LLM-backed
    /// implementation of [`DescriptionOptimizer`]).
    pub fn build_full_with<O: DescriptionOptimizer>(manifest: &Manifest, opt: &O) -> Self {
        Self::assemble(manifest, Some(opt))
    }

    /// Backward-compatible alias for the security-only path.
    pub fn build(manifest: &Manifest) -> Self {
        Self::build_security(manifest)
    }

    fn assemble<O: DescriptionOptimizer>(manifest: &Manifest, opt: Option<&O>) -> Self {
        let findings = run_all(manifest);
        let ris_scores = score_manifest(manifest);

        let tools: Vec<ToolReport> = manifest
            .tools
            .iter()
            .zip(ris_scores.into_iter())
            .map(|(t, r)| ToolReport {
                name: t.name.clone(),
                ris: r,
                optimization: opt.map(|o| o.rewrite(t)),
            })
            .collect();

        let total_tools = manifest.tools.len();
        let total_findings = findings.len();

        let mut by_sev: std::collections::BTreeMap<String, usize> = Default::default();
        for f in &findings {
            *by_sev.entry(severity_key(f.severity).to_string()).or_default() += 1;
        }

        let mean_ris = if tools.is_empty() {
            0.0
        } else {
            tools.iter().map(|t| t.ris.score as f32).sum::<f32>() / tools.len() as f32
        };
        let mean_reduction = if opt.is_some() && !tools.is_empty() {
            Some(
                tools
                    .iter()
                    .filter_map(|t| t.optimization.as_ref().map(|o| o.reduction_pct))
                    .sum::<f32>()
                    / tools.len() as f32,
            )
        } else {
            None
        };

        Report {
            schema_version: 1,
            server_name: manifest.server.name.clone(),
            server_version: manifest.server.version.clone(),
            findings,
            tools,
            summary: Summary {
                total_tools,
                total_findings,
                findings_by_severity: by_sev,
                mean_ris,
                mean_token_reduction_pct: mean_reduction,
            },
        }
    }

    /// Exit code suitable for CI: 0 if clean, non-zero if any high+ findings.
    pub fn exit_code(&self) -> i32 {
        let bad = self
            .findings
            .iter()
            .any(|f| matches!(f.severity, Severity::High | Severity::Critical));
        if bad {
            1
        } else {
            0
        }
    }
}

fn severity_key(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
