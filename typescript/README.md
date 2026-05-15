# `ironcontext` (TypeScript wrapper)

Thin, **zero-runtime-dependency** TypeScript bridge to the IronContext Rust engine.

```ts
import { scan, hasSecurityIssues, ruleCode } from "ironcontext";

const report = scan("path/to/manifest.json");
if (hasSecurityIssues(report)) {
  for (const f of report.findings) {
    console.log(`[${f.severity}] ${ruleCode(f)} on ${f.tool} — ${f.message}`);
  }
}
console.log(`Mean RIS: ${report.summary.mean_ris.toFixed(1)}/100`);
```

## Install

```bash
npm install ironcontext
```

You also need the `ironcontext` Rust binary on the host. Get it from:

```bash
cargo install ironcontext-cli                    # crates.io
# or build from source:
git clone https://github.com/altrusianco/ironcontext
cd ironcontext && cargo build --release
```

The wrapper resolves the binary in this order:

1. `$IRONCONTEXT_BIN` (an explicit absolute path).
2. `<repo>/target/release/ironcontext` (in-repo development build).
3. `<repo>/target/debug/ironcontext`.
4. `which ironcontext` (anywhere on `$PATH`).

## API surface

```ts
scan(path: string, opts?: { withOptimizer?: boolean }): ScanReport
score(path: string): RisScore[]
optimize(path: string): OptimizationResult[]
bench(path: string, opts?: { iterations?: number; budgetMs?: number }): BenchResult
findBinary(): string
hasSecurityIssues(report: ScanReport): boolean
ruleCode(finding: { rule: string }): string  // e.g. "cc001-hidden-instructions" → "CC-001"
```

All response shapes are strongly typed — see `dist/index.d.ts` after `npm run build`.

## Why no runtime dependencies?

Same reason `ironcontext-core` has eight crate deps total: heavy frameworks are a habit, not a requirement. This package uses only `node:child_process`, `node:fs`, `node:path`, and `node:url` — every one of them ships with Node ≥ 20.

Tests use `node:test` and `node:assert/strict`. No Jest, no Mocha, no Vitest.

## License

Apache-2.0 © Altrusian Computer.
