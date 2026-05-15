//! IronContext — security & optimization engine for the Model Context Protocol.
//!
//! `ironcontext-core` is the pure-CPU, offline-by-default library that powers the
//! `sentinel` CLI, the Python wrapper and the GitHub Action.  It exposes four
//! cohesive subsystems:
//!
//! * [`manifest`] — strict deserializer for MCP `initialize` / `tools/list` payloads.
//! * [`rules`]    — May 2026 CVE pattern detectors (SEN-001 … SEN-010).
//! * [`ris`]      — the Reasoning-Impact Score (0..100 hallucination grade).
//! * [`optimizer`] — heuristic description pruner + pluggable LLM trait.
//!
//! Everything is glued together by [`report::Report`] / [`scan`].

pub mod manifest;
pub mod optimizer;
pub mod report;
pub mod ris;
pub mod rules;
pub mod sarif;

use thiserror::Error;

pub use manifest::{Manifest, Tool};
pub use optimizer::{DescriptionOptimizer, HeuristicOptimizer, OptimizationOutcome};
pub use report::{Report, ToolReport};
pub use ris::{RisBreakdown, RisScore};
pub use rules::{Finding, RuleId, Severity};

/// Errors surfaced by the library.
#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("invalid MCP manifest: {0}")]
    InvalidManifest(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience: parse an MCP manifest from raw JSON bytes and produce a full report.
pub fn scan(bytes: &[u8]) -> Result<Report, SentinelError> {
    let manifest = manifest::Manifest::from_slice(bytes)?;
    Ok(Report::build(&manifest))
}

/// Convenience: parse + run only the optimizer pass.
pub fn optimize(bytes: &[u8]) -> Result<Vec<OptimizationOutcome>, SentinelError> {
    let manifest = manifest::Manifest::from_slice(bytes)?;
    let opt = HeuristicOptimizer::default();
    Ok(manifest
        .tools
        .iter()
        .map(|t| opt.rewrite(t))
        .collect::<Vec<_>>())
}
