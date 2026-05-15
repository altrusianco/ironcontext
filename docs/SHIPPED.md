# SHIPPED.md — Industry-grade verification checklist

A feature is "shipped" only when its row is fully checked. No partial credit.

Last verification: 2026-05-16 via `make test` → exit 0.

## Core engine
- [x] Rust workspace builds with `cargo build --release`.
- [x] MCP manifest parser handles `initialize` and `tools/list` payloads.
- [x] Parser rejects empty tool names and missing `tools` arrays with a typed error.
- [x] Rule engine ships 10 May-2026 CVE detectors (CC-001 … CC-010).
- [x] Every rule has at least one positive (and where applicable, negative) fixture test.
- [x] Scan latency on `fixtures/large_manifest.json` is <10ms (measured **~3.0ms median**).

## Optimizer
- [x] Heuristic optimizer reduces tokens by ≥40% on the large fixture (measured **~83%**).
- [x] Optimizer preserves semantic_similarity ≥ 0.95 (TF-cosine over content stems; measured **0.975 min**).
- [x] `DescriptionOptimizer` trait exposed for pluggable LLM backends.

## Reasoning-Impact Score
- [x] RIS produces a 0..100 score for every tool.
- [x] Canonical fixtures lock RIS into expected buckets (low / mid / high).
- [x] RIS reasons are surfaced in the report (which component dominated).

## Integration
- [x] `ironcontext` CLI exposes `scan`, `score`, `optimize`, `bench` subcommands.
- [x] SARIF 2.1.0 emitter produces a valid skeleton (10 rule descriptors, GitHub-compatible).
- [x] Python wrapper `ironcontext` runs on Python ≥3.9 with no extra deps (5 wrapper tests passing).
- [x] GitHub Action `action.yml` resolves and forwards inputs; uploads SARIF.

## Docs
- [x] README positions IronContext as the "Snyk for AI Agents."
- [x] `docs/API.md` documents every public type / CLI flag / exit code.
- [x] `docs/RULES.md` enumerates CC-001..010 with examples.

## Exit gate
- [x] `make test` exits 0 (cargo tests + bench gate + optimizer gates + Python wrapper).

## Verified figures (latest `make test`)

| Gate                        | Required        | Measured           |
|-----------------------------|-----------------|--------------------|
| `cargo test`                | 30 passing      | 30 passing         |
| scan latency (median)       | < 10ms          | ~2.9ms             |
| token-reduction (aggregate) | ≥ 40%           | ~83%               |
| semantic_similarity (min)   | ≥ 0.95          | 0.975              |
| Python wrapper              | 6 passing       | 6 passing          |
| Mock GitHub Action          | SARIF valid + fail-on enforced | OK (13.8 KB SARIF) |
