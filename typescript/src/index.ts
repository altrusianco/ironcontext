// @altrusianco/ironcontext — TypeScript wrapper around the IronContext Rust
// engine. Zero runtime dependencies: the wrapper locates the `ironcontext`
// binary on the host (env var → repo target dir → $PATH) and forwards
// subcommands through `child_process.spawnSync`. The shape of every response
// is pinned with strict interfaces below — drift between this and the Rust
// CLI's JSON output is a bug in this file.

import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { existsSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// ─── Errors ────────────────────────────────────────────────────────────────

export class IronContextError extends Error {
  public readonly cause?: Error;
  public readonly stderr: string;
  public readonly exitCode: number | null;
  constructor(message: string, opts: { stderr?: string; exitCode?: number | null; cause?: Error } = {}) {
    super(message);
    this.name = "IronContextError";
    this.stderr = opts.stderr ?? "";
    this.exitCode = opts.exitCode ?? null;
    if (opts.cause) this.cause = opts.cause;
  }
}

export class BinaryNotFound extends IronContextError {
  constructor(message: string) {
    super(message);
    this.name = "BinaryNotFound";
  }
}

// ─── Domain types (must mirror Rust serde output) ──────────────────────────

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type RisBand = "low" | "medium" | "high" | "severe";

export interface RisBreakdown {
  imperative_density: number;
  instruction_leakage: number;
  ambiguity: number;
  length_bloat: number;
  overlap_penalty: number;
  schema_mismatch: number;
  /** Name of the component that contributed the most to the score. */
  dominant: string;
}

export interface RisScore {
  tool: string;
  /** 0..=100. */
  score: number;
  band: RisBand;
  breakdown: RisBreakdown;
}

export interface OptimizationResult {
  tool: string;
  original_tokens: number;
  rewritten_tokens: number;
  reduction_pct: number;
  /** TF-cosine over content stems, vs. the original description. */
  semantic_similarity: number;
  original: string;
  rewritten: string;
  applied_rules: ReadonlyArray<string>;
}

export interface Finding {
  /** Kebab-case serde variant; e.g. "cc001-hidden-instructions". */
  rule: string;
  severity: Severity;
  tool: string;
  message: string;
  excerpt?: string | null;
}

export interface ToolReport {
  name: string;
  ris: RisScore;
  /** Present only when scan was invoked with `withOptimizer: true`. */
  optimization?: OptimizationResult;
}

export interface Summary {
  total_tools: number;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  mean_ris: number;
  /** `null` when the optimizer pass did not run. */
  mean_token_reduction_pct: number | null;
}

export interface ScanReport {
  schema_version: number;
  server_name: string;
  server_version: string;
  findings: ReadonlyArray<Finding>;
  tools: ReadonlyArray<ToolReport>;
  summary: Summary;
}

export interface BenchResult {
  /** Median full-pipeline latency (ms). */
  median_ms: number;
  /** Parse phase median (ms). */
  parse_ms: number;
  /** Rule-engine phase median (ms). */
  rules_ms: number;
  /** RIS phase median (ms). */
  ris_ms: number;
  iterations: number;
  /** Raw stdout line as emitted by the CLI, for diagnostics. */
  raw: string;
}

// ─── Rule-code mapping ─────────────────────────────────────────────────────

/** Map a serde kebab-case rule variant to the public `CC-NNN` code. */
const RULE_CODE_FROM_VARIANT: ReadonlyMap<string, string> = new Map([
  ["cc001-hidden-instructions", "CC-001"],
  ["cc002-invisible-unicode",   "CC-002"],
  ["cc003-cross-tool-shadow",   "CC-003"],
  ["cc004-rug-pull-surface",    "CC-004"],
  ["cc005-confused-deputy",     "CC-005"],
  ["cc006-open-redirect",       "CC-006"],
  ["cc007-excessive-privilege", "CC-007"],
  ["cc008-homoglyph-name",      "CC-008"],
  ["cc009-uri-pre-fetch",       "CC-009"],
  ["cc010-exfil-sink",          "CC-010"],
]);

export function ruleCode(finding: Pick<Finding, "rule">): string {
  return RULE_CODE_FROM_VARIANT.get(finding.rule) ?? finding.rule;
}

/** True if any finding's severity is `high` or `critical`. */
export function hasSecurityIssues(report: ScanReport): boolean {
  for (const f of report.findings) {
    if (f.severity === "high" || f.severity === "critical") return true;
  }
  return false;
}

// ─── Binary discovery ──────────────────────────────────────────────────────

const BIN_ENV = "IRONCONTEXT_BIN";

function repoRootFromHere(): string {
  // Walk up from this file looking for a Cargo.toml. Works both when running
  // from the in-repo build (typescript/dist/index.js) and from a node_modules
  // install (where Cargo.toml won't be found and we fall through to $PATH).
  let cur = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 10; i++) {
    if (existsSync(path.join(cur, "Cargo.toml"))) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return process.cwd();
}

function searchPathForBinary(name: string): string | null {
  const PATH = process.env["PATH"] ?? "";
  if (!PATH) return null;
  for (const dir of PATH.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, name);
    if (existsSync(candidate)) return candidate;
    // Windows: also try .exe
    if (process.platform === "win32") {
      const withExe = candidate + ".exe";
      if (existsSync(withExe)) return withExe;
    }
  }
  return null;
}

/**
 * Locate the `ironcontext` binary. Resolution order:
 *   1. `$IRONCONTEXT_BIN` (must be an executable file path).
 *   2. `<repo>/target/release/ironcontext` (in-repo development build).
 *   3. `<repo>/target/debug/ironcontext`.
 *   4. Whatever `$PATH` resolves `ironcontext` to.
 */
export function findBinary(): string {
  const override = process.env[BIN_ENV];
  if (override) {
    if (existsSync(override)) return override;
    throw new BinaryNotFound(
      `${BIN_ENV}=${override} is set but is not an existing file`
    );
  }
  const repo = repoRootFromHere();
  const exe = process.platform === "win32" ? "ironcontext.exe" : "ironcontext";
  for (const sub of ["target/release", "target/debug"]) {
    const candidate = path.join(repo, sub, exe);
    if (existsSync(candidate)) return candidate;
  }
  const onPath = searchPathForBinary("ironcontext");
  if (onPath) return onPath;
  throw new BinaryNotFound(
    `Could not find the 'ironcontext' binary. Set ${BIN_ENV}, run ` +
      "`cargo build --release` from the repo, or `cargo install ironcontext-cli`."
  );
}

// ─── Subprocess plumbing ───────────────────────────────────────────────────

interface RunOptions {
  /** Bytes to feed on stdin; useful for `path === "-"`. */
  input?: string | Buffer;
  /** Override the resolved binary path (used by tests). */
  binary?: string;
}

function run(args: ReadonlyArray<string>, opts: RunOptions = {}): SpawnSyncReturns<string> {
  const binary = opts.binary ?? findBinary();
  const result = spawnSync(binary, args, {
    encoding: "utf8",
    input: opts.input,
    // 50 MB stdout buffer covers SARIF output on very large manifests.
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) {
    throw new IronContextError(
      `Failed to spawn '${binary}': ${result.error.message}`,
      { cause: result.error }
    );
  }
  // `scan` returns 1 when there are high+ findings; that is NOT a failure
  // for the wrapper — callers inspect `hasSecurityIssues(report)`.
  if (result.status !== 0 && result.status !== 1) {
    throw new IronContextError(
      `ironcontext ${args[0] ?? "<no-subcommand>"} exited with code ${result.status}`,
      { stderr: result.stderr ?? "", exitCode: result.status }
    );
  }
  return result;
}

function parseJson<T>(stdout: string, subcommand: string): T {
  if (!stdout.trim()) {
    throw new IronContextError(`ironcontext ${subcommand} produced no output`);
  }
  try {
    return JSON.parse(stdout) as T;
  } catch (e) {
    throw new IronContextError(
      `ironcontext ${subcommand} returned unparseable JSON: ${(e as Error).message}`,
      { cause: e as Error }
    );
  }
}

// ─── Public API ────────────────────────────────────────────────────────────

export interface ScanOptions {
  /** Run the description optimizer in the same pass. Default: `false`. */
  withOptimizer?: boolean;
  /** Override the binary path; primarily for tests. */
  binary?: string;
}

/** Run the security scan and return a parsed `ScanReport`. */
export function scan(manifestPath: string, opts: ScanOptions = {}): ScanReport {
  const args = ["scan", manifestPath, "--format", "json", "--no-fail"];
  if (opts.withOptimizer) args.push("--with-optimizer");
  const proc = run(args, { binary: opts.binary });
  return parseJson<ScanReport>(proc.stdout, "scan");
}

/** Compute the Reasoning-Impact Score for each tool in the manifest. */
export function score(manifestPath: string, opts: { binary?: string } = {}): RisScore[] {
  const proc = run(["score", manifestPath, "--format", "json"], { binary: opts.binary });
  return parseJson<RisScore[]>(proc.stdout, "score");
}

/** Run the description optimizer on every tool in the manifest. */
export function optimize(manifestPath: string, opts: { binary?: string } = {}): OptimizationResult[] {
  const proc = run(["optimize", manifestPath, "--format", "json"], { binary: opts.binary });
  return parseJson<OptimizationResult[]>(proc.stdout, "optimize");
}

export interface BenchOptions {
  /** Number of timed iterations. Default: 500. */
  iterations?: number;
  /** Fail if the measured median latency exceeds this many milliseconds. Default: 10. */
  budgetMs?: number;
  binary?: string;
}

/**
 * Run the in-process latency benchmark. Returns the parsed timings. Throws if
 * the median exceeded `budgetMs` (the binary returns a non-zero exit there).
 */
export function bench(manifestPath: string, opts: BenchOptions = {}): BenchResult {
  const iterations = opts.iterations ?? 500;
  const budgetMs = opts.budgetMs ?? 10;
  const proc = run(
    [
      "bench",
      manifestPath,
      "--iterations",
      String(iterations),
      "--budget-ms",
      String(budgetMs),
    ],
    { binary: opts.binary }
  );
  if (proc.status !== 0) {
    throw new IronContextError(
      `bench failed (rc=${proc.status}): ${(proc.stderr || "").trim()}`,
      { stderr: proc.stderr ?? "", exitCode: proc.status }
    );
  }
  const raw = (proc.stdout || "").trim();
  // Line format: `scan median: 2.821ms   parse: 0.151ms   rules: 0.789ms   ris: 1.891ms   iters: 500`
  const pickMs = (label: string): number => {
    const re = new RegExp(`${label}:\\s+([0-9]+(?:\\.[0-9]+)?)ms`);
    const m = raw.match(re);
    if (!m || m[1] === undefined) {
      throw new IronContextError(`bench output missing '${label}' field: ${raw}`);
    }
    return Number.parseFloat(m[1]);
  };
  const pickInt = (label: string): number => {
    const re = new RegExp(`${label}:\\s+([0-9]+)`);
    const m = raw.match(re);
    if (!m || m[1] === undefined) {
      throw new IronContextError(`bench output missing '${label}' field: ${raw}`);
    }
    return Number.parseInt(m[1], 10);
  };
  return {
    median_ms: pickMs("median"),
    parse_ms: pickMs("parse"),
    rules_ms: pickMs("rules"),
    ris_ms: pickMs("ris"),
    iterations: pickInt("iters"),
    raw,
  };
}

// ─── Re-exports (named, not default — better tree-shake & IDE) ─────────────

export const __VERSION__ = "0.1.0";
