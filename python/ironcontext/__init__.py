"""IronContext — Python wrapper around the `ironcontext` Rust binary.

The wrapper is a thin, dependency-free bridge: it locates the `ironcontext`
binary (built from this repo's Rust workspace, or installed on PATH), invokes
the requested subcommand, and returns parsed JSON for programmatic use.

Why a subprocess bridge instead of pyo3 bindings? Three reasons:
* Zero compile-step at install time — works on every Python 3.9+ without a Rust
  toolchain on the consuming machine, once the binary is published.
* No GIL / FFI / safety footguns; the Rust binary already exits with a CI-ready
  status code.
* GitHub Actions runners can call the binary directly OR via this wrapper.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "BinaryNotFound",
    "IronContextError",
    "Finding",
    "RisScore",
    "OptimizationOutcome",
    "Report",
    "find_binary",
    "scan",
    "score",
    "optimize",
    "bench",
]

__version__ = "0.1.0"


class IronContextError(RuntimeError):
    """Raised when the underlying binary returns an unexpected error."""


class BinaryNotFound(IronContextError):
    """Raised when we cannot locate the `ironcontext` binary on this system."""


# ---------------------------------------------------------------------------
# Typed result objects (lightweight; built on dataclasses, no pydantic dep).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    tool: str
    message: str
    excerpt: str | None = None

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Finding":
        rule = d.get("rule")
        rule_str = _rule_code(rule)
        return cls(
            rule=rule_str,
            severity=d.get("severity", "info"),
            tool=d.get("tool", ""),
            message=d.get("message", ""),
            excerpt=d.get("excerpt"),
        )


@dataclass(frozen=True)
class RisScore:
    tool: str
    score: int
    band: str
    dominant: str
    breakdown: dict[str, float]

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "RisScore":
        bd = d.get("breakdown", {})
        return cls(
            tool=d["tool"],
            score=int(d["score"]),
            band=d.get("band", "low"),
            dominant=bd.get("dominant", ""),
            breakdown={k: v for k, v in bd.items() if k != "dominant"},
        )


@dataclass(frozen=True)
class OptimizationOutcome:
    tool: str
    original_tokens: int
    rewritten_tokens: int
    reduction_pct: float
    semantic_similarity: float
    original: str
    rewritten: str
    applied_rules: tuple[str, ...]

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "OptimizationOutcome":
        return cls(
            tool=d["tool"],
            original_tokens=int(d["original_tokens"]),
            rewritten_tokens=int(d["rewritten_tokens"]),
            reduction_pct=float(d["reduction_pct"]),
            semantic_similarity=float(d["semantic_similarity"]),
            original=d["original"],
            rewritten=d["rewritten"],
            applied_rules=tuple(d.get("applied_rules", [])),
        )


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    ris: tuple[RisScore, ...]
    optimization: tuple[OptimizationOutcome, ...]
    mean_ris: float
    mean_token_reduction_pct: float | None
    raw: dict[str, Any]

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Report":
        findings = tuple(Finding.from_json(f) for f in d.get("findings", []))
        ris = tuple(
            RisScore.from_json(t["ris"]) for t in d.get("tools", [])
        )
        opt = tuple(
            OptimizationOutcome.from_json(t["optimization"])
            for t in d.get("tools", [])
            if t.get("optimization")
        )
        s = d.get("summary", {})
        return cls(
            findings=findings,
            ris=ris,
            optimization=opt,
            mean_ris=float(s.get("mean_ris", 0.0)),
            mean_token_reduction_pct=(
                float(s["mean_token_reduction_pct"])
                if s.get("mean_token_reduction_pct") is not None
                else None
            ),
            raw=d,
        )

    def has_security_issues(self) -> bool:
        return any(f.severity in ("high", "critical") for f in self.findings)


# ---------------------------------------------------------------------------
# Binary lookup and subprocess plumbing.
# ---------------------------------------------------------------------------


def find_binary() -> Path:
    """Locate the `ironcontext` binary. Looks at, in order:
    1. `$IRONCONTEXT_BIN` env var.
    2. `./target/release/ironcontext` (this repo, after `cargo build --release`).
    3. `./target/debug/ironcontext`.
    4. Whatever `which ironcontext` finds on PATH.
    """
    override = os.environ.get("IRONCONTEXT_BIN")
    if override:
        p = Path(override)
        if p.is_file() and os.access(p, os.X_OK):
            return p
        raise BinaryNotFound(
            f"IRONCONTEXT_BIN={override} is not an executable file"
        )

    repo_root = _find_repo_root()
    candidates: Iterable[Path] = (
        repo_root / "target" / "release" / "ironcontext",
        repo_root / "target" / "debug" / "ironcontext",
    )
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c

    on_path = shutil.which("ironcontext")
    if on_path:
        return Path(on_path)

    raise BinaryNotFound(
        "Could not find the `ironcontext` binary. Build it with "
        "`cargo build --release` or set IRONCONTEXT_BIN."
    )


def _find_repo_root() -> Path:
    """Walk up from this file to find a directory containing Cargo.toml."""
    here = Path(__file__).resolve().parent
    for parent in (here, *here.parents):
        if (parent / "Cargo.toml").exists():
            return parent
    return here


def _run(args: list[str], input_bytes: bytes | None = None) -> str:
    binary = find_binary()
    try:
        proc = subprocess.run(
            [str(binary), *args],
            input=input_bytes,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as e:
        raise BinaryNotFound(str(e)) from e
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace")
    # `scan` exits non-zero on high+ findings; treat that as a success path
    # for the wrapper — callers can inspect `report.has_security_issues()`.
    if proc.returncode not in (0, 1):
        raise IronContextError(
            f"ironcontext {args[0]} failed (rc={proc.returncode}): {stderr.strip()}"
        )
    if not stdout.strip():
        raise IronContextError(
            f"ironcontext {args[0]} produced no output (rc={proc.returncode}); stderr={stderr.strip()}"
        )
    return stdout


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def scan(path: str | os.PathLike[str], *, with_optimizer: bool = False) -> Report:
    """Run the security scan and return a parsed `Report`."""
    args = ["scan", str(path), "--format", "json", "--no-fail"]
    if with_optimizer:
        args.append("--with-optimizer")
    return Report.from_json(json.loads(_run(args)))


def score(path: str | os.PathLike[str]) -> list[RisScore]:
    out = _run(["score", str(path), "--format", "json"])
    return [RisScore.from_json(d) for d in json.loads(out)]


def optimize(path: str | os.PathLike[str]) -> list[OptimizationOutcome]:
    out = _run(["optimize", str(path), "--format", "json"])
    return [OptimizationOutcome.from_json(d) for d in json.loads(out)]


def bench(
    path: str | os.PathLike[str],
    *,
    iterations: int = 500,
    budget_ms: int = 10,
) -> dict[str, Any]:
    """Run the latency benchmark and return the parsed result line.

    Raises `IronContextError` if the median exceeds `budget_ms` (mirrors the
    binary's exit code so this can be a CI gate).
    """
    binary = find_binary()
    proc = subprocess.run(
        [
            str(binary),
            "bench",
            str(path),
            "--iterations",
            str(iterations),
            "--budget-ms",
            str(budget_ms),
        ],
        capture_output=True,
        check=False,
    )
    line = (proc.stdout or b"").decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        raise IronContextError(
            f"bench failed (rc={proc.returncode}): {(proc.stderr or b'').decode('utf-8', 'replace').strip()}"
        )
    # Format: "scan median: 2.821ms   parse: 0.151ms   rules: 0.789ms   ris: 1.891ms   iters: 500"
    parts: dict[str, Any] = {}
    for chunk in line.split():
        if ":" in chunk:
            key = chunk.rstrip(":")
            parts.setdefault("_keys", []).append(key)
    # Robust parse: walk pairs of (label, "Xms" | "N").
    tokens = line.replace(":", "").split()
    i = 0
    while i < len(tokens) - 1:
        label, value = tokens[i], tokens[i + 1]
        if value.endswith("ms"):
            parts[label] = float(value[:-2])
            i += 2
        elif value.isdigit():
            parts[label] = int(value)
            i += 2
        else:
            i += 1
    return parts


# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------


_RULE_VARIANT_TO_CODE = {
    "cc001-hidden-instructions": "CC-001",
    "cc002-invisible-unicode": "CC-002",
    "cc003-cross-tool-shadow": "CC-003",
    "cc004-rug-pull-surface": "CC-004",
    "cc005-confused-deputy": "CC-005",
    "cc006-open-redirect": "CC-006",
    "cc007-excessive-privilege": "CC-007",
    "cc008-homoglyph-name": "CC-008",
    "cc009-uri-pre-fetch": "CC-009",
    "cc010-exfil-sink": "CC-010",
}


def _rule_code(value: Any) -> str:
    if isinstance(value, str):
        return _RULE_VARIANT_TO_CODE.get(value, value)
    return str(value)
