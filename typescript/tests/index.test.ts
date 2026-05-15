// End-to-end smoke tests for @altrusianco/ironcontext.
//
// These deliberately exercise the spawnSync bridge against the real
// `ironcontext` binary built in this repo (target/release/ironcontext).
// We use Node's built-in `node:test` runner — no Jest, no Mocha, no Vitest.
// `npm test` compiles src+tests with tsconfig.test.json then runs `node --test`
// over the compiled output, so there's nothing to install at consumer time.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  scan,
  score,
  optimize,
  bench,
  findBinary,
  hasSecurityIssues,
  ruleCode,
  BinaryNotFound,
  type Finding,
} from "../src/index.js";

// ─── Test fixtures ─────────────────────────────────────────────────────────

const HERE = path.dirname(fileURLToPath(import.meta.url));
// dist-test/tests -> dist-test -> typescript -> repo root
const REPO_ROOT = path.resolve(HERE, "..", "..", "..");
const CLEAN = path.join(REPO_ROOT, "fixtures", "demo", "clean_server.json");
const POISONED = path.join(REPO_ROOT, "fixtures", "demo", "poisoned_server.json");
const LARGE = path.join(REPO_ROOT, "fixtures", "large_manifest.json");

function requireBuiltBinary(): void {
  const expected = path.join(REPO_ROOT, "target", "release", "ironcontext");
  if (!existsSync(expected)) {
    throw new Error(
      `Required binary not found at ${expected}. Run 'cargo build --release' first.`
    );
  }
}

// ─── findBinary ────────────────────────────────────────────────────────────

test("findBinary resolves to a path inside this repo's target/", () => {
  requireBuiltBinary();
  const resolved = findBinary();
  assert.ok(
    resolved.endsWith("/target/release/ironcontext") ||
      resolved.endsWith("/target/debug/ironcontext"),
    `unexpected binary path: ${resolved}`
  );
});

test("findBinary throws BinaryNotFound when IRONCONTEXT_BIN points nowhere", () => {
  const prev = process.env["IRONCONTEXT_BIN"];
  process.env["IRONCONTEXT_BIN"] = "/definitely/not/a/real/path/ironcontext";
  try {
    assert.throws(() => findBinary(), BinaryNotFound);
  } finally {
    if (prev === undefined) delete process.env["IRONCONTEXT_BIN"];
    else process.env["IRONCONTEXT_BIN"] = prev;
  }
});

// ─── scan ──────────────────────────────────────────────────────────────────

test("scan() on the clean fixture yields zero findings", () => {
  requireBuiltBinary();
  const report = scan(CLEAN);
  assert.equal(report.findings.length, 0);
  assert.equal(hasSecurityIssues(report), false);
  assert.ok(report.tools.length >= 1);
});

test("scan() on the poisoned fixture flags CC-001 and CC-010", () => {
  requireBuiltBinary();
  const report = scan(POISONED);
  const codes = new Set<string>(report.findings.map((f: Finding) => ruleCode(f)));
  assert.ok(codes.has("CC-001"), `missing CC-001; got ${[...codes].join(",")}`);
  assert.ok(codes.has("CC-010"), `missing CC-010; got ${[...codes].join(",")}`);
  assert.equal(hasSecurityIssues(report), true);
});

test("scan({ withOptimizer: true }) populates per-tool optimization", () => {
  requireBuiltBinary();
  const report = scan(CLEAN, { withOptimizer: true });
  for (const t of report.tools) {
    assert.ok(t.optimization, `tool ${t.name} has no optimization field`);
    assert.ok(t.optimization!.semantic_similarity >= 0);
    assert.ok(t.optimization!.semantic_similarity <= 1);
  }
});

// ─── score ─────────────────────────────────────────────────────────────────

test("score() returns one RisScore per tool with sane bounds", () => {
  requireBuiltBinary();
  const scores = score(CLEAN);
  assert.ok(scores.length >= 1);
  for (const s of scores) {
    assert.ok(typeof s.tool === "string" && s.tool.length > 0);
    assert.ok(Number.isInteger(s.score));
    assert.ok(s.score >= 0 && s.score <= 100, `score out of range: ${s.score}`);
    assert.ok(["low", "medium", "high", "severe"].includes(s.band));
  }
});

// ─── optimize ──────────────────────────────────────────────────────────────

test("optimize() on the clean fixture reduces tokens by >= 40% in aggregate", () => {
  requireBuiltBinary();
  const outcomes = optimize(CLEAN);
  assert.ok(outcomes.length >= 1);
  const totalBefore = outcomes.reduce((a, o) => a + o.original_tokens, 0);
  const totalAfter = outcomes.reduce((a, o) => a + o.rewritten_tokens, 0);
  const pct = ((totalBefore - totalAfter) / totalBefore) * 100;
  assert.ok(pct >= 40, `aggregate reduction only ${pct.toFixed(1)}%`);
});

test("optimize() preserves per-tool semantic_similarity >= 0.95", () => {
  requireBuiltBinary();
  const outcomes = optimize(CLEAN);
  for (const o of outcomes) {
    assert.ok(
      o.semantic_similarity >= 0.95,
      `tool ${o.tool} dropped similarity to ${o.semantic_similarity}`
    );
  }
});

// ─── bench ─────────────────────────────────────────────────────────────────

test("bench() reports median < 10ms on the 100-tool fixture", () => {
  requireBuiltBinary();
  const result = bench(LARGE, { iterations: 200, budgetMs: 10 });
  assert.equal(result.iterations, 200);
  assert.ok(result.median_ms < 10, `median ${result.median_ms}ms over budget`);
  assert.ok(result.parse_ms < result.median_ms);
  assert.ok(result.rules_ms < result.median_ms);
  assert.ok(result.ris_ms < result.median_ms);
});

// ─── ruleCode mapping ──────────────────────────────────────────────────────

test("ruleCode maps every serde variant to its CC-NNN code", () => {
  const cases: ReadonlyArray<[string, string]> = [
    ["cc001-hidden-instructions", "CC-001"],
    ["cc002-invisible-unicode", "CC-002"],
    ["cc010-exfil-sink", "CC-010"],
  ];
  for (const [variant, code] of cases) {
    assert.equal(ruleCode({ rule: variant }), code);
  }
  // Unknown rule passes through untouched (forward-compat with future variants).
  assert.equal(ruleCode({ rule: "future-rule" }), "future-rule");
});
