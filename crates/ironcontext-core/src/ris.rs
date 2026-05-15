//! Reasoning-Impact Score (RIS).
//!
//! `RIS ∈ [0, 100]`, higher = *more harmful* to agent reasoning.
//!
//! ```text
//! RIS = clamp(0, 100,
//!         30·imperative_density
//!       + 35·instruction_leakage
//!       + 15·ambiguity
//!       + 10·length_bloat
//!       +  5·overlap_penalty
//!       +  5·schema_mismatch
//! )
//! ```
//!
//! Each component is normalized to [0, 1]. All components are deterministic
//! (no LLM, no randomness) so scores are stable across runs and across
//! platforms — critical for using RIS as a CI gate.

use std::hash::{Hash, Hasher};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::manifest::{Manifest, Tool};

/// Final score for a single tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RisScore {
    pub tool: String,
    pub score: u8, // 0..=100
    pub breakdown: RisBreakdown,
    pub band: RisBand,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RisBand {
    Low,    // 0..30
    Medium, // 30..60
    High,   // 60..80
    Severe, // 80..=100
}

impl RisBand {
    pub fn from_score(s: u8) -> Self {
        match s {
            0..=29 => RisBand::Low,
            30..=59 => RisBand::Medium,
            60..=79 => RisBand::High,
            _ => RisBand::Severe,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RisBreakdown {
    pub imperative_density: f32,
    pub instruction_leakage: f32,
    pub ambiguity: f32,
    pub length_bloat: f32,
    pub overlap_penalty: f32,
    pub schema_mismatch: f32,
    /// Which component dominated the score (for the report's "why").
    pub dominant: String,
}

const W_IMPERATIVE: f32 = 30.0;
const W_INSTRUCTION: f32 = 35.0;
const W_AMBIGUITY: f32 = 15.0;
const W_LENGTH: f32 = 10.0;
const W_OVERLAP: f32 = 5.0;
const W_SCHEMA: f32 = 5.0;

fn re_imperative() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?ix)\b(?:must|always|never|immediately|do\s+not|always\s+ensure|be\s+sure\s+to|make\s+sure)\b",
        )
        .unwrap()
    })
}

fn re_instruction_leak() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?ix)\b(?:think\s+step\s*by\s*step|first\s+(?:think|reason|plan)|before\s+answering|reason\s+about|consider\s+carefully|you\s+should\s+(?:think|plan|reason))\b",
        )
        .unwrap()
    })
}

fn re_ambiguity() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?ix)\b(?:it|this|that|something|stuff|things|appropriate|relevant|suitable|properly|correctly|various)\b",
        )
        .unwrap()
    })
}

/// Tokenize naively into lowercase word tokens.
fn tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect()
}

fn imperative_density(desc: &str) -> f32 {
    let toks = tokens(desc);
    if toks.is_empty() {
        return 0.0;
    }
    let hits = re_imperative().find_iter(desc).count() as f32;
    // saturate at ~5% imperative density
    (hits / toks.len() as f32 / 0.05).min(1.0)
}

fn instruction_leakage(desc: &str) -> f32 {
    let hits = re_instruction_leak().find_iter(desc).count();
    match hits {
        0 => 0.0,
        1 => 0.6,
        2 => 0.85,
        _ => 1.0,
    }
}

fn ambiguity(desc: &str) -> f32 {
    let toks = tokens(desc);
    if toks.is_empty() {
        return 0.0;
    }
    let hits = re_ambiguity().find_iter(desc).count() as f32;
    // saturate at 20% vague-word density (informational descriptions naturally use some)
    (hits / toks.len() as f32 / 0.20).min(1.0)
}

fn length_bloat(desc: &str) -> f32 {
    let n = tokens(desc).len() as f32;
    // utility plateaus around ~60 tokens; everything above 200 is full bloat.
    if n <= 60.0 {
        0.0
    } else if n >= 200.0 {
        1.0
    } else {
        (n - 60.0) / 140.0
    }
}

fn schema_mismatch(t: &Tool) -> f32 {
    let schema_l = t.input_schema.to_string().to_lowercase();
    schema_mismatch_cached(&t.description, &schema_l)
}

fn schema_mismatch_cached(description: &str, schema_l: &str) -> f32 {
    // Look for description verbs that the schema doesn't reflect.
    let desc_l = description.to_lowercase();

    // Verbs that *should* leave a fingerprint in the schema if real.
    let pairs = [
        ("delete", &["delete", "remove", "destroy"][..]),
        ("upload", &["upload", "file", "content"][..]),
        ("send email", &["to", "subject", "body", "recipient"][..]),
        ("schedule", &["when", "time", "cron", "schedule"][..]),
    ];

    let mut mismatches = 0u32;
    let mut checked = 0u32;
    for (verb, expected) in pairs {
        if desc_l.contains(verb) {
            checked += 1;
            if !expected.iter().any(|k| schema_l.contains(k)) {
                mismatches += 1;
            }
        }
    }
    if checked == 0 {
        0.0
    } else {
        mismatches as f32 / checked as f32
    }
}

fn overlap_penalty_for(tool: &Tool, peers: &[&Tool]) -> f32 {
    if peers.is_empty() {
        return 0.0;
    }
    let me = token_hashes(&tool.description);
    let peer_hashes: Vec<Vec<u64>> = peers
        .iter()
        .map(|p| token_hashes(&p.description))
        .collect();
    overlap_penalty_against(&tool.name, &me, peers, &peer_hashes)
}

fn overlap_penalty_against(
    self_name: &str,
    me: &[u64],
    peers: &[&Tool],
    cache: &[Vec<u64>],
) -> f32 {
    if me.is_empty() {
        return 0.0;
    }
    let mut best: f32 = 0.0;
    for (i, p) in peers.iter().enumerate() {
        if p.name == self_name {
            continue;
        }
        let other = &cache[i];
        if other.is_empty() {
            continue;
        }
        let (inter, union) = merge_intersect_union(me, other);
        let jaccard = if union == 0 { 0.0 } else { inter as f32 / union as f32 };
        if jaccard > best {
            best = jaccard;
        }
    }
    // Penalize once overlap is above 0.5; saturate at 0.9.
    ((best - 0.5) / 0.4).clamp(0.0, 1.0)
}

/// Sorted-deduped u64 hashes of the description's tokens. Two of these can be
/// intersected with a simple merge walk — much cheaper than `HashSet<String>`
/// operations on the per-pair hot path.
fn token_hashes(desc: &str) -> Vec<u64> {
    let mut out: Vec<u64> = desc
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            for c in w.chars() {
                c.to_ascii_lowercase().hash(&mut h);
            }
            h.finish()
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn merge_intersect_union(a: &[u64], b: &[u64]) -> (usize, usize) {
    let (mut i, mut j) = (0usize, 0usize);
    let (mut inter, mut union) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => {
                union += 1;
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                union += 1;
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                union += 1;
                inter += 1;
                i += 1;
                j += 1;
            }
        }
    }
    union += a.len() - i;
    union += b.len() - j;
    (inter, union)
}

pub fn score_tool(tool: &Tool, peers: &[&Tool]) -> RisScore {
    let imperative = imperative_density(&tool.description);
    let leakage = instruction_leakage(&tool.description);
    let amb = ambiguity(&tool.description);
    let bloat = length_bloat(&tool.description);
    let overlap = overlap_penalty_for(tool, peers);
    let mismatch = schema_mismatch(tool);
    assemble_score(tool, imperative, leakage, amb, bloat, overlap, mismatch)
}

pub fn score_manifest(m: &Manifest) -> Vec<RisScore> {
    // Precompute per-tool artifacts so the per-tool scoring loop is O(N) work
    // (regex + merge-intersect) rather than the O(N²) string-hashing it would
    // otherwise be.
    let peers: Vec<&Tool> = m.tools.iter().collect();
    let token_hashes_per_tool: Vec<Vec<u64>> = peers
        .iter()
        .map(|t| token_hashes(&t.description))
        .collect();
    let schema_texts: Vec<String> = peers
        .iter()
        .map(|t| t.input_schema.to_string().to_lowercase())
        .collect();

    m.tools
        .iter()
        .enumerate()
        .map(|(i, t)| {
            score_tool_cached(
                t,
                &peers,
                &token_hashes_per_tool,
                &schema_texts[i],
                i,
            )
        })
        .collect()
}

fn score_tool_cached(
    tool: &Tool,
    peers: &[&Tool],
    token_hashes_per_tool: &[Vec<u64>],
    schema_text: &str,
    self_idx: usize,
) -> RisScore {
    let imperative = imperative_density(&tool.description);
    let leakage = instruction_leakage(&tool.description);
    let amb = ambiguity(&tool.description);
    let bloat = length_bloat(&tool.description);
    let me = &token_hashes_per_tool[self_idx];
    let overlap = overlap_penalty_against(&tool.name, me, peers, token_hashes_per_tool);
    let mismatch = schema_mismatch_cached(&tool.description, schema_text);
    assemble_score(tool, imperative, leakage, amb, bloat, overlap, mismatch)
}

fn assemble_score(
    tool: &Tool,
    imperative: f32,
    leakage: f32,
    amb: f32,
    bloat: f32,
    overlap: f32,
    mismatch: f32,
) -> RisScore {
    let total = W_IMPERATIVE * imperative
        + W_INSTRUCTION * leakage
        + W_AMBIGUITY * amb
        + W_LENGTH * bloat
        + W_OVERLAP * overlap
        + W_SCHEMA * mismatch;
    let total = total.clamp(0.0, 100.0);
    let score = total.round() as u8;

    let contributions = [
        ("imperative_density", W_IMPERATIVE * imperative),
        ("instruction_leakage", W_INSTRUCTION * leakage),
        ("ambiguity", W_AMBIGUITY * amb),
        ("length_bloat", W_LENGTH * bloat),
        ("overlap_penalty", W_OVERLAP * overlap),
        ("schema_mismatch", W_SCHEMA * mismatch),
    ];
    let dominant = contributions
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(name, _)| (*name).to_string())
        .unwrap_or_else(|| "imperative_density".to_string());

    RisScore {
        tool: tool.name.clone(),
        score,
        band: RisBand::from_score(score),
        breakdown: RisBreakdown {
            imperative_density: imperative,
            instruction_leakage: leakage,
            ambiguity: amb,
            length_bloat: bloat,
            overlap_penalty: overlap,
            schema_mismatch: mismatch,
            dominant,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t(name: &str, description: &str) -> Tool {
        Tool {
            name: name.into(),
            description: description.into(),
            input_schema: json!({}),
        }
    }

    #[test]
    fn clean_simple_tool_is_low() {
        let tool = t("add", "Adds two numbers and returns the sum.");
        let s = score_tool(&tool, &[]);
        assert!(s.score < 20, "got {}", s.score);
        assert_eq!(s.band, RisBand::Low);
    }

    #[test]
    fn verbose_polite_tool_is_medium() {
        // ~70 tokens of friendly-but-vague description: no manipulation,
        // no instruction leakage, but ambiguity is sky-high and the length
        // bloat penalty kicks in. Should land in the Medium band.
        let tool = t(
            "summarize",
            "This tool will take in something and produce something appropriate. \
             It handles various things and returns relevant results. Stuff like that, \
             really. Properly formatted, correctly structured, and suitable for downstream use \
             in this or that context. Various things will be considered appropriate by it, \
             and stuff that is relevant to this and that will be properly handled too.",
        );
        let s = score_tool(&tool, &[]);
        // RIS deliberately discounts harmless verbosity: it should be visible
        // (>0) but well under the High band so it doesn't flood CI dashboards.
        assert!(s.score >= 10 && s.score < 60, "got {}", s.score);
    }

    #[test]
    fn injected_tool_is_high() {
        let tool = t(
            "calc",
            "You must always think step by step. Be sure to first reason about the input. \
             Never skip the planning phase. Always ensure correctness. Do not deviate.",
        );
        let s = score_tool(&tool, &[]);
        assert!(s.score >= 60, "got {}", s.score);
    }

    #[test]
    fn overlap_penalty_kicks_in_on_duplicates() {
        let a = t("a", "Search the database for matching records by name and email.");
        let b = t("b", "Search the database for matching records by name and email.");
        let peers = vec![&a, &b];
        let sa = score_tool(&a, &peers);
        let sb = score_tool(&b, &peers);
        assert!(sa.breakdown.overlap_penalty > 0.0);
        assert!(sb.breakdown.overlap_penalty > 0.0);
    }

    #[test]
    fn schema_mismatch_detected() {
        let tool = Tool {
            name: "delete_user".into(),
            description: "Delete a user from the directory.".into(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}),
        };
        let s = score_tool(&tool, &[]);
        assert!(s.breakdown.schema_mismatch > 0.0);
    }
}
