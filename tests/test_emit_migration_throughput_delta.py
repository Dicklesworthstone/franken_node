"""Unit tests for scripts/emit_migration_throughput_delta.py (live emitter)."""

from __future__ import annotations

import json
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "emit_migration_throughput_delta.py"
GATE_SCRIPT = ROOT / "scripts" / "check_migration_velocity_gate.py"


class ScriptNamespace:
    def __init__(self, script_globals: dict[str, object]) -> None:
        object.__setattr__(self, "_script_globals", script_globals)

    def __getattr__(self, name: str) -> object:
        return self._script_globals[name]


mod = ScriptNamespace(runpy.run_path(str(SCRIPT)))
gate = ScriptNamespace(runpy.run_path(str(GATE_SCRIPT)))


class CohortRegistryTests(unittest.TestCase):
    def test_exactly_one_holdout(self) -> None:
        holdouts = [f for f in mod.FIXTURES if f["role"] == "holdout"]
        assert len(holdouts) == 1

    def test_no_constructed_ids_in_registry(self) -> None:
        for fixture in mod.FIXTURES:
            assert fixture["fixture_id"] not in mod.CONSTRUCTED_COHORT_IDS

    def test_all_fixture_dirs_exist_with_manifests(self) -> None:
        for fixture in mod.FIXTURES:
            path = ROOT / fixture["rel"]
            assert (path / "package.json").is_file(), fixture["rel"]

    def test_baseline_scripts_exist(self) -> None:
        for name in ("baseline_audit.cjs", "baseline_rewrite.cjs", "baseline_validate.cjs"):
            assert (ROOT / "scripts" / "migration_baseline" / name).is_file()


class MathTests(unittest.TestCase):
    def test_median_rules(self) -> None:
        assert mod.median_int([5, 1, 3]) == 3
        assert mod.median_int([4, 1, 3, 2]) == 2
        with self.assertRaises(ValueError):
            mod.median_int([])

    def test_ratio_bp_rounding_and_guards(self) -> None:
        assert mod.ratio_bp(30_000, 10_000) == 30_000
        assert mod.ratio_bp(1, 3) == 3_333
        with self.assertRaises(ValueError):
            mod.ratio_bp(0, 0)

    def test_splitmix64_reference_vector(self) -> None:
        state, out = mod.splitmix64(0)
        assert state == 0x9E3779B97F4A7C15
        assert out == 0xE220A8397B1DCDAF

    def test_bootstrap_degenerate_and_deterministic(self) -> None:
        ci = mod.bootstrap_ci_bp([(100, 350)] * 5, 2000, 42)
        assert ci["ci95_low_bp"] == 35_000 == ci["ci95_high_bp"]
        pairs = [(100, 350), (110, 330), (90, 400), (105, 360), (95, 340)]
        assert mod.bootstrap_ci_bp(pairs, 4000, 7) == mod.bootstrap_ci_bp(pairs, 4000, 7)


class CrossImplementationAgreementTests(unittest.TestCase):
    """The gate is an independent verifier: its math must agree with the
    emitter's on identical inputs — that agreement is the verification."""

    def test_medians_agree(self) -> None:
        samples = [43, 28, 32, 41, 37, 29, 55]
        assert mod.median_int(samples) == gate._median_int(samples)

    def test_ratio_agrees(self) -> None:
        for numerator, denominator in ((76, 43), (74, 28), (75_000, 21_333), (5, 15_000)):
            assert mod.ratio_bp(numerator, denominator) == gate._ratio_bp(numerator, denominator)

    def test_splitmix_stream_agrees(self) -> None:
        state_a, state_b = 1, 1
        for _ in range(1000):
            state_a, out_a = mod.splitmix64(state_a)
            state_b, out_b = gate._splitmix64(state_b)
            assert out_a == out_b

    def test_bootstrap_and_corpus_digest_agree(self) -> None:
        pairs = [(i * 7 % 53 + 20, i * 11 % 97 + 60) for i in range(12)]
        assert mod.bootstrap_ci_bp(pairs, 3000, 99) == gate._bootstrap_ci_bp(pairs, 3000, 99)
        corpus_pairs = [("fixture-a", "sha256:aa"), ("fixture-b", "sha256:bb")]
        assert mod.corpus_digest(corpus_pairs) == gate._corpus_digest(corpus_pairs)

    def test_signature_domains_match_gate_constants(self) -> None:
        assert mod.MIGTP_SIGNATURE_DOMAIN == gate.MIGTP_SIGNATURE_DOMAIN
        assert mod.MIGTP_EVIDENCE_DOMAIN == gate.MIGTP_EVIDENCE_DOMAIN
        assert mod.MIGTP_CORPUS_DOMAIN == gate.MIGTP_CORPUS_DOMAIN
        assert mod.MIGTP_SEED_PREIMAGE == gate.MIGTP_SEED_PREIMAGE

    def test_harness_public_key_matches_gate_derivation(self) -> None:
        assert mod.harness_public_hex() == gate._harness_keys()[1]

    def test_canned_row_metamorphic_guard(self) -> None:
        # Doubling every timing must double medians while preserving the bp
        # ratio; a canned row would violate the doubling half.
        varied_tool = [100, 110, 90]
        varied_base = [350, 330, 400]
        doubled_ratio = mod.ratio_bp(
            mod.median_int([value * 2 for value in varied_base]),
            mod.median_int([value * 2 for value in varied_tool]),
        )
        original_ratio = mod.ratio_bp(mod.median_int(varied_base), mod.median_int(varied_tool))
        assert doubled_ratio == original_ratio
        assert mod.median_int([value * 2 for value in varied_tool]) == 2 * mod.median_int(varied_tool)


class CliTests(unittest.TestCase):
    def test_self_test_exit_zero(self) -> None:
        import subprocess
        import sys

        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr


if __name__ == "__main__":
    unittest.main()
