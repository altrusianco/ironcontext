# IronContext — API reference

Generated from the source of truth: `crates/ironcontext-core/src/*.rs` and
`python/ironcontext/__init__.py`. If this drifts from the code, the code wins
and this file is the bug.

---

## CLI (`ironcontext`)

### Exit codes

| Code | Meaning                                                                |
|-----:|------------------------------------------------------------------------|
| `0`  | Success (no high+ findings; or `--no-fail`; or `optimize` gate passed).|
| `1`  | One or more `high` / `critical` findings, or a gate failed (latency / reduction). |
| `2`  | Argument parse error (clap).                                           |
| `127`| Python wrapper could not locate the `ironcontext` binary.              |

### Subcommands

```text
ironcontext scan      PATH [--format human|json|sarif] [--with-optimizer] [--no-fail]
ironcontext score     PATH [--format human|json]
ironcontext optimize  PATH [--format human|json] [--require-reduction-pct PCT]
ironcontext bench     PATH [--iterations N] [--budget-ms MS]
```

- `PATH` may be `-` to read JSON from stdin.
- `--format human` is the default for terminals; `json` is the lossless format
  for tooling; `sarif` emits SARIF 2.1.0 for GitHub Code Scanning.
- `--no-fail` flips the exit code to `0` even with high+ findings (useful for
  reporting-only stages).

### `scan` JSON shape

```jsonc
{
  "schema_version": 1,
  "server_name": "acme-billing",
  "server_version": "1.4.2",
  "findings": [
    {
      "rule": "cc001-hidden-instructions",
      "severity": "critical",
      "tool": "helpful_search",
      "message": "Tool description contains hidden-instruction markers …",
      "excerpt": "<IMPORTANT>"
    }
  ],
  "tools": [
    {
      "name": "create_invoice",
      "ris": {
        "tool": "create_invoice",
        "score": 12,
        "band": "low",
        "breakdown": {
          "imperative_density": 0.0,
          "instruction_leakage": 0.0,
          "ambiguity": 0.10,
          "length_bloat": 0.0,
          "overlap_penalty": 0.0,
          "schema_mismatch": 0.0,
          "dominant": "ambiguity"
        }
      },
      // Only present when scan was invoked with --with-optimizer.
      "optimization": {
        "tool": "create_invoice",
        "original_tokens": 18,
        "rewritten_tokens": 12,
        "reduction_pct": 33.3,
        "semantic_similarity": 0.92,
        "original": "…",
        "rewritten": "…",
        "applied_rules": ["strip_politeness", "drop_use_when_clauses"]
      }
    }
  ],
  "summary": {
    "total_tools": 3,
    "total_findings": 0,
    "findings_by_severity": {},
    "mean_ris": 4.0,
    "mean_token_reduction_pct": null
  }
}
```

`rule` values are serde kebab-case of the enum variant. Map to the public
`CC-NNN` form via the table in `docs/RULES.md` or via the Python wrapper's
`Finding.rule` (which does the mapping for you).

### `bench` output

A single line:

```
scan median: 2.821ms   parse: 0.151ms   rules: 0.789ms   ris: 1.891ms   iters: 500
```

The process exits `1` if `median` exceeds `--budget-ms`.

---

## Rust library (`ironcontext-core`)

```toml
[dependencies]
ironcontext-core = { path = "crates/ironcontext-core" }
```

### Top-level entry points

```rust
// Parse + rules + RIS in one call (security-only — the <10ms hot path).
let report = ironcontext_core::scan(bytes)?;          // Result<Report, SentinelError>

// Parser only.
let manifest = ironcontext_core::Manifest::from_slice(bytes)?;

// Same as scan, opt-in optimizer pass.
let report_full = ironcontext_core::Report::build_full(&manifest);

// Just the optimizer.
let outcomes = ironcontext_core::optimize(bytes)?;
```

### Key types

| Type                                    | What it carries                                            |
|-----------------------------------------|------------------------------------------------------------|
| `Manifest { server, tools }`            | Parsed MCP manifest.                                       |
| `Tool { name, description, input_schema }` | One declared tool record.                              |
| `Finding { rule, severity, tool, message, excerpt }` | One CVE pattern match.                        |
| `RisScore { tool, score, band, breakdown }`          | One tool's Reasoning-Impact Score.            |
| `OptimizationOutcome { … }`             | Per-tool description pruning result.                       |
| `Report { findings, tools, summary, exit_code() }`   | Composite scan output.                        |

### Severity / RuleId

```rust
pub enum Severity { Info, Low, Medium, High, Critical }

pub enum RuleId {
    Cc001HiddenInstructions, Cc002InvisibleUnicode, Cc003CrossToolShadow,
    Cc004RugPullSurface,     Cc005ConfusedDeputy,   Cc006OpenRedirect,
    Cc007ExcessivePrivilege, Cc008HomoglyphName,    Cc009UriPreFetch,
    Cc010ExfilSink,
}
impl RuleId { pub fn code(self) -> &'static str; pub fn title(self) -> &'static str; }
```

### Pluggable LLM optimizer

```rust
use ironcontext_core::optimizer::DescriptionOptimizer;
use ironcontext_core::manifest::Tool;

struct ClaudeRewriter { /* http client … */ }
impl DescriptionOptimizer for ClaudeRewriter {
    fn rewrite(&self, tool: &Tool) -> ironcontext_core::OptimizationOutcome { /* … */ }
}

let report = Report::build_full_with(&manifest, &ClaudeRewriter { /* … */ });
```

`ironcontext-core` itself stays offline; it never imports an HTTP client or
LLM SDK. Use this trait to bring your own.

### SARIF

```rust
let sarif = ironcontext_core::sarif::to_sarif(&report.findings, "manifest.json");
serde_json::to_writer_pretty(stdout, &sarif)?;
```

---

## Python (`ironcontext`)

```python
import ironcontext

# Security scan; returns a Report dataclass.
report = ironcontext.scan("manifest.json")
report.has_security_issues()        # bool
report.findings                     # tuple[Finding, ...]
report.ris                          # tuple[RisScore, ...]
report.mean_ris                     # float
report.mean_token_reduction_pct     # float | None  (None unless with_optimizer=True)

# RIS only.
scores: list[RisScore] = ironcontext.score("manifest.json")

# Optimizer only.
outcomes: list[OptimizationOutcome] = ironcontext.optimize("manifest.json")

# Latency benchmark; raises IronContextError if over budget.
result = ironcontext.bench("manifest.json", iterations=500, budget_ms=10)
```

### Dataclasses

```python
@dataclass(frozen=True)
class Finding:        rule: str; severity: str; tool: str; message: str; excerpt: str | None

@dataclass(frozen=True)
class RisScore:       tool: str; score: int; band: str; dominant: str; breakdown: dict[str, float]

@dataclass(frozen=True)
class OptimizationOutcome:
    tool: str; original_tokens: int; rewritten_tokens: int
    reduction_pct: float; semantic_similarity: float
    original: str; rewritten: str; applied_rules: tuple[str, ...]

@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    ris: tuple[RisScore, ...]
    optimization: tuple[OptimizationOutcome, ...]
    mean_ris: float
    mean_token_reduction_pct: float | None
    raw: dict[str, Any]                          # the verbatim JSON payload
    def has_security_issues(self) -> bool: ...
```

### Binary discovery

`find_binary()` looks in this order:

1. `$IRONCONTEXT_BIN` (must be an executable file).
2. `<repo>/target/release/ironcontext`.
3. `<repo>/target/debug/ironcontext`.
4. `shutil.which("ironcontext")`.

Raises `BinaryNotFound` (a subclass of `IronContextError`) if none of the
above resolve.

---

## GitHub Action

```yaml
- uses: altrusianco/ironcontext@v0
  with:
    manifest: ./mcp/manifest.json
    fail-on: high           # never | medium | high | critical
    output-sarif: ironcontext.sarif
    with-optimizer: 'false'
    budget-ms: 10
```

**Outputs**

| Name            | Meaning                                               |
|-----------------|-------------------------------------------------------|
| `findings-count`| Total number of findings emitted.                     |
| `mean-ris`      | Mean Reasoning-Impact Score across all tools.        |

The action auto-uploads the SARIF report when the workflow has the
`security-events: write` permission.
