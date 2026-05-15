# `ironcontext` (CLI)

> Command-line wrapper around [`ironcontext-core`](https://crates.io/crates/ironcontext-core). The "Snyk for AI Agents" engine, packaged as a single static binary.

```bash
cargo install ironcontext-cli

# Scan an MCP manifest — exits non-zero on high+ findings.
ironcontext scan path/to/manifest.json

# Same scan, SARIF output for GitHub Code Scanning.
ironcontext scan path/to/manifest.json --format sarif > out.sarif

# Reasoning-Impact Score per tool.
ironcontext score path/to/manifest.json

# Description optimizer (>=40% reduction, >=0.95 semantic similarity).
ironcontext optimize path/to/manifest.json --require-reduction-pct 40

# Latency benchmark with a configurable budget.
ironcontext bench path/to/manifest.json --iterations 500 --budget-ms 10
```

See the [project README](https://github.com/altrusianco/ironcontext) and
`docs/API.md` for the full reference and the Python / GitHub-Action
integrations built on top of this binary.

License: Apache-2.0
