"""Smoke tests for the Python wrapper. Exercise every public entry point against
the two canonical fixtures.

These are deliberately not unit tests — they invoke the built Rust binary, so
they double as end-to-end integration coverage for the FFI boundary.
"""

from __future__ import annotations

import json
import pathlib
import unittest

import ironcontext

REPO = pathlib.Path(__file__).resolve().parents[2]
CLEAN = REPO / "fixtures" / "clean_manifest.json"
POISONED = REPO / "fixtures" / "poisoned_manifest.json"
LARGE = REPO / "fixtures" / "large_manifest.json"


class ScanTests(unittest.TestCase):
    def test_clean_manifest_has_no_findings(self) -> None:
        report = ironcontext.scan(CLEAN)
        self.assertEqual(report.findings, ())
        self.assertFalse(report.has_security_issues())

    def test_poisoned_manifest_triggers_all_categories(self) -> None:
        report = ironcontext.scan(POISONED)
        codes = {f.rule for f in report.findings}
        # At minimum every CC-NNN rule should fire on the poisoned fixture.
        for expected in (f"CC-{n:03d}" for n in range(1, 11)):
            self.assertIn(expected, codes, msg=f"missing {expected}")
        self.assertTrue(report.has_security_issues())


class ScoreTests(unittest.TestCase):
    def test_score_returns_one_entry_per_tool(self) -> None:
        scores = ironcontext.score(CLEAN)
        self.assertEqual(len(scores), 3)
        for s in scores:
            self.assertGreaterEqual(s.score, 0)
            self.assertLessEqual(s.score, 100)


class OptimizeTests(unittest.TestCase):
    def test_optimizer_meets_40_percent_on_large_fixture(self) -> None:
        outcomes = ironcontext.optimize(LARGE)
        total_before = sum(o.original_tokens for o in outcomes)
        total_after = sum(o.rewritten_tokens for o in outcomes)
        reduction = (total_before - total_after) / total_before * 100
        self.assertGreaterEqual(reduction, 40.0, msg=f"only {reduction:.1f}%")

    def test_optimizer_preserves_semantic_similarity_over_0_95(self) -> None:
        outcomes = ironcontext.optimize(LARGE)
        worst = min(o.semantic_similarity for o in outcomes)
        self.assertGreaterEqual(
            worst, 0.95, msg=f"worst-case semantic_similarity {worst:.3f} < 0.95"
        )


class BenchTests(unittest.TestCase):
    def test_bench_under_10ms(self) -> None:
        result = ironcontext.bench(LARGE, iterations=200, budget_ms=10)
        # `bench` raises if over budget; reaching here means the gate held.
        self.assertIn("median", result)
        self.assertLess(result["median"], 10.0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
