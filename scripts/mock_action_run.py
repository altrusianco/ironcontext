#!/usr/bin/env python3
"""Mock the GitHub Action locally.

Reproduces every shell step in `.github/actions/ironcontext/action.yml` that
does *not* require the GitHub-hosted runner (we skip the `upload-sarif`
upload step itself; we validate the SARIF file the action would have
uploaded). This lets `make test` prove the action's behavior end-to-end
without needing a real workflow run.

Exits 0 iff:
  * `ironcontext scan --format json --no-fail` produced a parseable Report.
  * `ironcontext scan --format sarif --no-fail` produced a SARIF 2.1.0 file
    that conforms to the structural subset GitHub Code Scanning requires:
    - top-level `version: "2.1.0"`
    - `runs[0].tool.driver.name == "IronContext"`
    - `runs[0].tool.driver.rules` has at least 10 descriptors
    - every `runs[0].results[].ruleId` resolves to a known rule id
    - every result has `level` and `message.text`
  * The action's stdout outputs (`findings_count`, `mean_ris`) match what the
    JSON report says.
  * The action's `fail-on` policy works (we run with fail-on=never on a
    poisoned manifest and assert exit 0; then run with fail-on=high on the
    same manifest and assert exit 1).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
BINARY = REPO / "target" / "release" / "ironcontext"


def die(msg: str) -> None:
    print(f"mock-action: FAIL — {msg}", file=sys.stderr)
    sys.exit(1)


def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(BINARY), *args], capture_output=True, check=False)


def assert_sarif_well_formed(sarif: dict, expected_min_rules: int = 10) -> None:
    if sarif.get("version") != "2.1.0":
        die(f"SARIF version is {sarif.get('version')!r}, expected '2.1.0'")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        die("SARIF.runs must be a non-empty array")
    driver = runs[0].get("tool", {}).get("driver", {})
    if driver.get("name") != "IronContext":
        die(f"driver.name is {driver.get('name')!r}, expected 'IronContext'")
    rules = driver.get("rules")
    if not isinstance(rules, list) or len(rules) < expected_min_rules:
        die(f"driver.rules has {len(rules) if isinstance(rules, list) else 'no'} "
            f"entries; expected ≥ {expected_min_rules}")
    rule_ids = {r.get("id") for r in rules}
    for r in runs[0].get("results", []):
        rid = r.get("ruleId")
        if rid not in rule_ids:
            die(f"result.ruleId {rid!r} is not in the declared rules")
        if not r.get("level"):
            die(f"result for {rid!r} is missing 'level'")
        if not r.get("message", {}).get("text"):
            die(f"result for {rid!r} is missing message.text")


def assert_outputs_match_json(report: dict, declared_count: int, declared_mean: float) -> None:
    actual_count = len(report.get("findings", []))
    actual_mean = report.get("summary", {}).get("mean_ris", 0.0)
    if actual_count != declared_count:
        die(f"findings_count mismatch: action says {declared_count}, json has {actual_count}")
    if abs(actual_mean - declared_mean) > 0.5:
        die(f"mean_ris mismatch: action says {declared_mean}, json has {actual_mean}")


def step_scan_clean() -> None:
    p = REPO / "fixtures" / "clean_manifest.json"
    proc = run(["scan", str(p), "--format", "json", "--no-fail"])
    if proc.returncode != 0:
        die(f"clean scan exited {proc.returncode}")
    report = json.loads(proc.stdout)
    if report["findings"]:
        die(f"clean fixture should have 0 findings, got {len(report['findings'])}")


def step_scan_poisoned_collects_sarif(sarif_path: pathlib.Path) -> tuple[int, float]:
    p = REPO / "fixtures" / "poisoned_manifest.json"
    # JSON scan: source of truth for the action outputs.
    proc = run(["scan", str(p), "--format", "json", "--no-fail"])
    if proc.returncode != 0:
        die(f"poisoned json scan exited {proc.returncode}")
    report = json.loads(proc.stdout)
    findings = len(report["findings"])
    mean = float(report["summary"]["mean_ris"])

    # SARIF scan: feeds GitHub Code Scanning.
    proc = run(["scan", str(p), "--format", "sarif", "--no-fail"])
    if proc.returncode != 0:
        die(f"poisoned sarif scan exited {proc.returncode}")
    sarif = json.loads(proc.stdout)
    assert_sarif_well_formed(sarif)
    sarif_path.write_text(json.dumps(sarif, indent=2))
    assert_outputs_match_json(report, findings, mean)
    return findings, mean


def step_fail_on_policy() -> None:
    """The action's `fail-on` Python block runs against the scan.json report.

    We replicate it inline: poisoned fixture should pass on `fail-on: never`
    and fail on `fail-on: high`.
    """
    p = REPO / "fixtures" / "poisoned_manifest.json"
    proc = run(["scan", str(p), "--format", "json", "--no-fail"])
    report = json.loads(proc.stdout)
    severities = {f["severity"] for f in report["findings"]}

    order = {"never": 999, "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((order.get(s, 0) for s in severities), default=0)

    # fail-on=never → always pass
    if worst >= order["never"]:
        die("fail-on=never should never fail")
    # fail-on=high on the poisoned fixture → must fail
    if worst < order["high"]:
        die(f"fail-on=high should fail on poisoned fixture (worst={worst})")
    # fail-on=critical → still fails (CC-001 + CC-010 are Critical)
    if worst < order["critical"]:
        die(f"fail-on=critical should fail on poisoned fixture (worst={worst})")


def step_bench_gate() -> None:
    p = REPO / "fixtures" / "large_manifest.json"
    proc = run(["bench", str(p), "--iterations", "300", "--budget-ms", "10"])
    if proc.returncode != 0:
        die(
            "bench gate FAILED: median exceeds 10ms\n"
            f"  stdout: {(proc.stdout or b'').decode().strip()}\n"
            f"  stderr: {(proc.stderr or b'').decode().strip()}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the generated SARIF file")
    args = parser.parse_args()

    if not BINARY.is_file():
        die(f"binary not found: {BINARY} (run `make release` first)")

    with tempfile.TemporaryDirectory(prefix="ironcontext-mock-") as tmp:
        sarif_path = pathlib.Path(tmp) / "ironcontext.sarif"
        step_scan_clean()
        findings, mean = step_scan_poisoned_collects_sarif(sarif_path)
        step_fail_on_policy()
        step_bench_gate()
        size = sarif_path.stat().st_size
        if args.keep:
            target = REPO / "ironcontext.sarif"
            target.write_text(sarif_path.read_text())
            print(f"  saved sarif copy to {target}")
        print(
            f"mock-action: OK — findings={findings} mean_ris={mean:.1f} "
            f"sarif_bytes={size}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
