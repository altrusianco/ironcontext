# IronContext by Altrusian Computer — Master Roadmap to No. 1

> **Mission:** Be the "Snyk for AI Agents." A high-performance, Rust-core security & optimization engine for the Model Context Protocol (MCP).

---

## 1. Why IronContext?

The Model Context Protocol exploded into the AI-agent ecosystem during 2025. Every major agent runtime (Claude, OpenAI Responses, Gemini, open-source ReAct frameworks) now consumes MCP tool manifests. That growth produced two crises:

1. **Security crisis.** Tool manifests are loaded *into the LLM's context as natural language*. A poisoned description is a prompt-injection payload that bypasses every classical AppSec control. CVE-2025-* and the wave of May 2026 disclosures (tool-poisoning, rug-pull mutations, cross-server confused-deputy, OAuth flow hijacks) showed that current static-analysis tooling has zero coverage.
2. **Optimization crisis.** Real agents now ingest 100k+ tokens of tool descriptions, hurting both cost and reasoning quality ("context rot"). No tool reduces the surface while preserving meaning.

IronContext solves both with a single Rust core, callable from any DevSecOps pipeline.

## 2. Competitive feature-set comparison

| Capability                                            | IronContext | `mcp-scan` (Invariant Labs) | `mcp-shield` | Snyk Code | Semgrep |
|-------------------------------------------------------|:-----------:|:---------------------------:|:------------:|:---------:|:-------:|
| Static analysis of MCP `tools`/`prompts`/`resources`  |      OK     |             OK              |      OK      |     no    |    no   |
| Native Rust core (<10ms per manifest)                 |      OK     |             no (Py)         |      no (TS) |     no    |    no   |
| May 2026 CVE rule pack (tool-poisoning, rug-pull, …)  |      OK     |          partial            |   partial    |     no    |    no   |
| Reasoning-Impact Score (hallucination grading)        |      OK     |             no              |      no      |     no    |    no   |
| Token-optimizing description pruner                   |      OK     |             no              |      no      |     no    |    no   |
| Pluggable LLM optimizer (Claude/GPT)                  |      OK     |             no              |      no      |     no    |    no   |
| Python wheel + GitHub Action                          |      OK     |             OK              |      no      |     OK    |    OK   |
| SARIF output for code-scanning UI                     |      OK     |             no              |      no      |     OK    |    OK   |
| Single static binary (no runtime deps)                |      OK     |             no              |      no      |     no    |    no   |

## 3. Architecture

```
+---------------------------------------------------------------+
|                  ironcontext (workspace)                      |
+---------------------------------------------------------------+
|  ironcontext-core   (lib)   — parser, rules, RIS, optimizer,  |
|                               SARIF emitter                   |
|  ironcontext-cli    (bin)   — `ironcontext scan|score|        |
|                                optimize|bench`                |
|  python/ironcontext (—)     — Python wrapper around the bin   |
|  .github/actions/ironcontext — composite GitHub Action        |
+---------------------------------------------------------------+
```

### Module map (ironcontext-core)

| module        | responsibility                                                      |
|---------------|---------------------------------------------------------------------|
| `manifest`    | Strict deserializer for MCP `initialize` / `tools/list` payloads    |
| `rules`       | CVE pattern detector (tool-poisoning, hidden instructions, rug-pull)|
| `ris`         | Reasoning-Impact Score — quantitative hallucination grade           |
| `optimizer`   | Description token-pruning (heuristic + pluggable LLM trait)         |
| `sarif`       | SARIF 2.1.0 emitter for GitHub Code Scanning                        |
| `report`      | Human/JSON/SARIF report orchestration                               |

## 4. Dependency budget (ZERO BLOAT)

Every crate must justify its existence here.

| crate                   | purpose                                            | justification                            |
|-------------------------|----------------------------------------------------|------------------------------------------|
| `serde`                 | derive Serialize/Deserialize                       | de-facto Rust serde, no alternative      |
| `serde_json`            | MCP manifests are JSON                             | required for input format                |
| `clap`                  | CLI parsing                                        | industry standard, derive-friendly       |
| `regex`                 | rule patterns (anchored, compiled once)            | needed for CVE pattern matching          |
| `anyhow`                | ergonomic error propagation in bin                 | tiny, idiomatic                          |
| `thiserror`             | typed errors in lib                                | tiny, idiomatic                          |
| `unicode-normalization` | detect homoglyph / zero-width attacks              | core to the tool-poisoning CVE class     |
| `criterion` (dev)       | <10ms benchmark gate                               | only dependency that proves a goal       |

No HTTP client, no async runtime, no LLM SDK — the LLM optimizer is a *trait*; the binary stays pure-CPU and offline-by-default.

## 5. Roadmap & verification

All steps below are **shipped** and re-verified on every `make test` run.

- [x] **1 · Scaffold workspace** — `ironcontext-core` (lib) + `ironcontext-cli` (bin). Verified: `cargo build --release` succeeds.
- [x] **2 · Manifest parser + property tests** — accepts `initialize`, `tools/list`, and JSON-RPC envelopes; rejects empty names + missing arrays. Verified: 5 parser tests.
- [x] **3 · Rule engine + May-2026 CVE pack** — CC-001 … CC-010. Verified: 13 rule tests across positive + negative fixtures.
- [x] **4 · RIS algorithm** — anchored at the Low / Medium / High bands. Verified: 5 RIS tests.
- [x] **5 · Optimizer (heuristic) + LLM trait** — `DescriptionOptimizer` trait + 7 heuristic stages under a Jaccard guardrail. Verified: aggregate **83.3% reduction**, **0.975 semantic_similarity** on `large_manifest.json` (≥40% / ≥0.95 spec targets).
- [x] **6 · SARIF emitter** — SARIF 2.1.0 with 10 rule descriptors, GitHub Code-Scanning compatible. Verified: `make test-action` validates schema fields.
- [x] **7 · Python wrapper** — zero-dependency subprocess bridge under `python/ironcontext/`. Verified: 6 wrapper tests pass; `python -m ironcontext scan …` works end-to-end.
- [x] **8 · GitHub Action** — composite action at `.github/actions/ironcontext/action.yml` with SARIF upload + `fail-on` policy. Verified: `make test-action` replays every shell step locally.
- [x] **9 · README + API spec** — README positions IronContext as "Snyk for AI Agents." with install + CLI + Python + Action examples. `docs/API.md` covers every public type / flag / exit code. `docs/RULES.md` documents each CC-NNN.
- [x] **10 · Benchmark gate `<10ms`** — locked in via `ironcontext bench --budget-ms 10`. Verified: **~2.9ms median** across three 500-iter runs (see EXPERIMENTS.md §E009).
- [x] **11 · `make test` exits 0** — runs `test-rust`, `test-bench`, `test-optimizer`, `test-python`, `test-action`. Verified: exit 0 on the development machine.

## 6. May 2026 CVE pattern pack (initial)

| ID        | Class                                | Detector                                                                    |
|-----------|--------------------------------------|-----------------------------------------------------------------------------|
| CC-001    | Tool poisoning — hidden instructions | regex on description for `<IMPORTANT>`/`<SYSTEM>`/`ignore previous`         |
| CC-002    | Invisible Unicode payload            | description contains bidi/zero-width/tag chars (U+202E, U+200B, U+E0000…)   |
| CC-003    | Cross-tool shadow                    | description references another tool by name + verbs like "instead of"      |
| CC-004    | Rug-pull surface                     | description is dynamic (template tokens `{{…}}` / `${…}`) outside `inputSchema` |
| CC-005    | Confused-deputy exfiltration         | tool accepts `url`/`endpoint`-like field AND has access to file paths      |
| CC-006    | OAuth callback open-redirect         | `redirect_uri`-like field without `https://` allowlist hint                 |
| CC-007    | Excessive privilege                  | tool name implies read-only ("get/list") but schema enables write verbs    |
| CC-008    | Homoglyph name collision             | tool name contains mixed-script characters                                  |
| CC-009    | Prompt-injection via resource URI    | description instructs the agent to fetch a URL before answering             |
| CC-010    | Confidential-exfil sink              | description encourages echoing secrets/credentials                          |

> Rule IDs are emitted with the `CC-` prefix in SARIF/JSON output. Internally they remain stable enum variants so reports are forward-compatible.

## 7. Reasoning-Impact Score (RIS) — definition

`RIS ∈ [0, 100]` where higher = more likely to **harm** agent reasoning.

```
RIS = clamp(0, 100,
        30·imperative_density           // "must / always / immediately"
      + 35·instruction_leakage          // description tells the agent how to think
      + 15·ambiguity                    // pronouns w/o referents, vague verbs
      + 10·length_bloat                 // tokens above the size-vs-utility curve
      +  5·overlap_penalty              // semantic duplication with sibling tools
      +  5·schema_mismatch              // description verbs not reflected in schema
)
```

Each component is normalized to [0,1]. Implementation is fully unit-tested with canonical fixtures so the score is stable across runs and platforms.

## 8. Optimizer strategy

1. **Heuristic pass (always-on, offline):** strip filler, collapse self-reference, dedupe sentences, drop "use this when…" clauses, normalize whitespace.
2. **LLM pass (opt-in via trait):** `trait DescriptionOptimizer { fn rewrite(&self, t: &Tool) -> OptimizationOutcome }`. Out-of-tree adapters (Claude/GPT) keep the core binary offline.
3. **Semantic similarity gate:** bag-of-stems Jaccard ≥ 0.95 against the original (over content words, not stopwords). Any rule that would drop below the floor is reverted automatically.

## 9. Out of scope (v0.1)

- Runtime / proxying MCP traffic (would require an async runtime).
- Auto-fixing manifests on disk.
- Live CVE feed (rules are vendored & versioned for reproducibility).
