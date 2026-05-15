# `ironcontext-core`

> The pure-Rust security & optimization engine that powers [IronContext](https://github.com/altrusianco/ironcontext) — the "Snyk for AI Agents."

Library crate. Parses MCP manifests, runs the May 2026 CVE pattern pack
(CC-001 … CC-010), produces a Reasoning-Impact Score (RIS) per tool, and
optionally prunes verbose descriptions through a pluggable
`DescriptionOptimizer` trait. Offline, no async runtime, no LLM SDK in the
dependency tree.

```rust
use ironcontext_core::{Manifest, Report};

let bytes = std::fs::read("manifest.json")?;
let manifest = Manifest::from_slice(&bytes)?;
let report = Report::build_security(&manifest);
println!("findings: {}", report.findings.len());
println!("mean RIS: {:.1}/100", report.summary.mean_ris);
```

See the workspace README and `docs/API.md` in the repository for the full
API surface and the CLI / Python / GitHub-Action wrappers built on top of
this crate.

License: Apache-2.0
