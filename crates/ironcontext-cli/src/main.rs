//! IronContext CLI — `ironcontext <subcommand>`.
//!
//! Subcommands:
//!   scan      → parser + rules + RIS report; non-zero exit on high+ findings.
//!   score     → print RIS only.
//!   optimize  → run the description-pruning pass on every tool.
//!   bench     → in-process latency benchmark with a configurable budget.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use ironcontext_core::sarif;
use ironcontext_core::{
    optimizer::HeuristicOptimizer, DescriptionOptimizer, Manifest, Report,
};

#[derive(Debug, Parser)]
#[command(
    name = "ironcontext",
    version,
    about = "IronContext by Altrusian Computer — security & optimization engine for the Model Context Protocol"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the security scan (parser + rule engine + RIS) on a manifest file.
    Scan {
        /// Path to the manifest JSON. `-` reads from stdin.
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
        /// Also run the optimizer pass and include token reductions in the report.
        #[arg(long)]
        with_optimizer: bool,
        /// Exit 0 even on findings (informational mode).
        #[arg(long)]
        no_fail: bool,
    },
    /// Print the Reasoning-Impact Score for every tool.
    Score {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
    },
    /// Run the description optimizer pass and print before/after token counts.
    Optimize {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
        /// Fail with a non-zero exit if the aggregate reduction is below this percentage.
        #[arg(long)]
        require_reduction_pct: Option<f32>,
        /// Fail if the minimum per-tool semantic_similarity falls below this floor.
        #[arg(long, default_value_t = 0.95)]
        require_similarity: f32,
    },
    /// Self-benchmark: run N security scans and report median + p95 latency.
    Bench {
        path: PathBuf,
        #[arg(long, default_value_t = 500)]
        iterations: u32,
        /// Fail if median latency exceeds this threshold (milliseconds).
        #[arg(long, default_value_t = 10)]
        budget_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Scan {
            path,
            format,
            with_optimizer,
            no_fail,
        } => run_scan(&path, format, with_optimizer, no_fail),
        Cmd::Score { path, format } => run_score(&path, format),
        Cmd::Optimize {
            path,
            format,
            require_reduction_pct,
            require_similarity,
        } => run_optimize(&path, format, require_reduction_pct, require_similarity),
        Cmd::Bench {
            path,
            iterations,
            budget_ms,
        } => run_bench(&path, iterations, budget_ms),
    }
}

fn read_bytes(path: &PathBuf) -> Result<Vec<u8>> {
    if path.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).context("read stdin")?;
        Ok(buf)
    } else {
        fs::read(path).with_context(|| format!("read {}", path.display()))
    }
}

fn run_scan(path: &PathBuf, format: Format, with_optimizer: bool, no_fail: bool) -> Result<()> {
    let bytes = read_bytes(path)?;
    let manifest = Manifest::from_slice(&bytes).context("parse manifest")?;
    let report = if with_optimizer {
        Report::build_full(&manifest)
    } else {
        Report::build_security(&manifest)
    };
    match format {
        Format::Human => print_human(&report),
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        Format::Sarif => {
            let s = sarif::to_sarif(&report.findings, &path.display().to_string());
            println!("{}", serde_json::to_string_pretty(&s)?);
        }
    }
    if !no_fail {
        std::process::exit(report.exit_code());
    }
    Ok(())
}

fn run_score(path: &PathBuf, format: Format) -> Result<()> {
    let bytes = read_bytes(path)?;
    let manifest = Manifest::from_slice(&bytes)?;
    let scores = ironcontext_core::ris::score_manifest(&manifest);
    match format {
        Format::Human => {
            println!("RIS scores ({} tools):", scores.len());
            for s in &scores {
                println!(
                    "  {:>4}/100  [{}]  {}  (dominant: {})",
                    s.score,
                    band_label(s.band),
                    s.tool,
                    s.breakdown.dominant
                );
            }
        }
        Format::Json | Format::Sarif => println!("{}", serde_json::to_string_pretty(&scores)?),
    }
    Ok(())
}

fn run_optimize(
    path: &PathBuf,
    format: Format,
    gate: Option<f32>,
    similarity_floor: f32,
) -> Result<()> {
    let bytes = read_bytes(path)?;
    let manifest = Manifest::from_slice(&bytes)?;
    let opt = HeuristicOptimizer::default();
    let outcomes: Vec<_> = manifest.tools.iter().map(|t| opt.rewrite(t)).collect();
    let total_before: usize = outcomes.iter().map(|o| o.original_tokens).sum();
    let total_after: usize = outcomes.iter().map(|o| o.rewritten_tokens).sum();
    let total_pct = if total_before == 0 {
        0.0
    } else {
        (total_before as f32 - total_after as f32) / total_before as f32 * 100.0
    };
    match format {
        Format::Human => {
            for o in &outcomes {
                println!(
                    "  {} : {} -> {} tokens  ({:.1}% reduction, jaccard {:.2}) [{}]",
                    o.tool,
                    o.original_tokens,
                    o.rewritten_tokens,
                    o.reduction_pct,
                    o.semantic_similarity,
                    o.applied_rules.join(",")
                );
            }
            println!(
                "\nTOTAL: {} -> {} tokens  ({:.1}% reduction)",
                total_before, total_after, total_pct
            );
        }
        Format::Json | Format::Sarif => println!("{}", serde_json::to_string_pretty(&outcomes)?),
    }
    if let Some(gate) = gate {
        if total_pct < gate {
            anyhow::bail!(
                "aggregate token reduction {:.1}% below required {:.1}%",
                total_pct,
                gate
            );
        }
    }
    let min_sim = outcomes
        .iter()
        .map(|o| o.semantic_similarity)
        .fold(1.0_f32, f32::min);
    if min_sim < similarity_floor {
        anyhow::bail!(
            "minimum per-tool semantic_similarity {:.3} below required {:.3}",
            min_sim,
            similarity_floor
        );
    }
    Ok(())
}

fn run_bench(path: &PathBuf, iters: u32, budget_ms: u64) -> Result<()> {
    let bytes = read_bytes(path)?;
    // Warm-up parse so the regex caches are primed before timing.
    let warm = Manifest::from_slice(&bytes)?;
    let _ = Report::build_security(&warm);

    let mut full_us: Vec<u128> = Vec::with_capacity(iters as usize);
    let mut parse_us: Vec<u128> = Vec::with_capacity(iters as usize);
    let mut rules_us: Vec<u128> = Vec::with_capacity(iters as usize);
    let mut ris_us: Vec<u128> = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        let t0 = Instant::now();
        let m = Manifest::from_slice(&bytes)?;
        let t_parsed = t0.elapsed().as_micros();

        let t1 = Instant::now();
        let _findings = ironcontext_core::rules::run_all(&m);
        let t_rules = t1.elapsed().as_micros();

        let t2 = Instant::now();
        let _scores = ironcontext_core::ris::score_manifest(&m);
        let t_ris = t2.elapsed().as_micros();

        full_us.push(t0.elapsed().as_micros());
        parse_us.push(t_parsed);
        rules_us.push(t_rules);
        ris_us.push(t_ris);
    }
    let median = |v: &mut Vec<u128>| {
        v.sort_unstable();
        v[v.len() / 2]
    };
    let m_full = median(&mut full_us);
    let m_parse = median(&mut parse_us);
    let m_rules = median(&mut rules_us);
    let m_ris = median(&mut ris_us);
    println!(
        "scan median: {:.3}ms   parse: {:.3}ms   rules: {:.3}ms   ris: {:.3}ms   iters: {}",
        m_full as f64 / 1000.0,
        m_parse as f64 / 1000.0,
        m_rules as f64 / 1000.0,
        m_ris as f64 / 1000.0,
        iters
    );
    if m_full > (budget_ms as u128) * 1000 {
        anyhow::bail!(
            "median latency {:.3}ms exceeds budget {}ms",
            m_full as f64 / 1000.0,
            budget_ms
        );
    }
    Ok(())
}

fn band_label(b: ironcontext_core::ris::RisBand) -> &'static str {
    match b {
        ironcontext_core::ris::RisBand::Low => "low",
        ironcontext_core::ris::RisBand::Medium => "medium",
        ironcontext_core::ris::RisBand::High => "high",
        ironcontext_core::ris::RisBand::Severe => "severe",
    }
}

fn print_human(report: &Report) {
    println!(
        "IronContext report — {} tool(s), {} finding(s)",
        report.summary.total_tools, report.summary.total_findings
    );
    if !report.server_name.is_empty() {
        println!("server: {} {}", report.server_name, report.server_version);
    }
    if let Some(pct) = report.summary.mean_token_reduction_pct {
        println!(
            "mean RIS: {:.1}/100   mean token reduction: {:.1}%",
            report.summary.mean_ris, pct
        );
    } else {
        println!("mean RIS: {:.1}/100", report.summary.mean_ris);
    }
    if !report.findings.is_empty() {
        println!("\nfindings:");
        for f in &report.findings {
            println!(
                "  [{}] {} on `{}` — {}",
                severity_tag(f.severity),
                f.rule.code(),
                f.tool,
                f.message
            );
            if let Some(ex) = &f.excerpt {
                println!("      excerpt: {}", ex);
            }
        }
    }
    println!("\nper-tool:");
    for t in &report.tools {
        if let Some(o) = &t.optimization {
            println!(
                "  {:>4}/100 ris  |  {:>4}% reduction  |  {}",
                t.ris.score,
                o.reduction_pct.round() as i32,
                t.name
            );
        } else {
            println!("  {:>4}/100 ris  |  {}", t.ris.score, t.name);
        }
    }
}

fn severity_tag(s: ironcontext_core::rules::Severity) -> &'static str {
    match s {
        ironcontext_core::rules::Severity::Info => "INFO",
        ironcontext_core::rules::Severity::Low => "LOW ",
        ironcontext_core::rules::Severity::Medium => "MED ",
        ironcontext_core::rules::Severity::High => "HIGH",
        ironcontext_core::rules::Severity::Critical => "CRIT",
    }
}
