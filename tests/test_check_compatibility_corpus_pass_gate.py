"""Unit tests for scripts/check_compatibility_corpus_pass_gate.py."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_compatibility_corpus_pass_gate as mod  # noqa: E402


def successful_observation(elapsed_ms: int = 1) -> dict:
    empty_digest = "sha256:" + hashlib.sha256(b"").hexdigest()
    return {
        "stdout_digest": empty_digest,
        "stderr_digest": empty_digest,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "exit_code": 0,
        "termination_kind": "exited",
        "timed_out": False,
        "elapsed_ms": elapsed_ms,
    }


def refresh_runtime_observations_digest(report: dict) -> None:
    report["corpus"]["runtime_observations_digest"] = (
        mod.compute_runtime_observations_digest(report)
    )


def passing_report(total: int = 1000) -> dict:
    families = sorted(mod.REQUIRED_FAMILIES)
    bands = sorted(mod.REQUIRED_BANDS)
    risk_bands = sorted(mod.REQUIRED_RISK_BANDS)
    per_test_results = [
        {
            "test_id": f"synthetic::{index:04d}",
            "api_family": families[index % len(families)],
            "band": bands[index % len(bands)],
            "risk_band": risk_bands[index % len(risk_bands)],
            "status": "pass",
            "runtime_observations": {
                "bun": successful_observation(index + 1),
                "franken-engine-native": successful_observation(index + 2),
            },
        }
        for index in range(total)
    ]
    report = {
        "corpus": {
            "provenance": mod.ONLINE_PROVENANCE,
            "result_digest": mod.compute_result_digest(per_test_results),
            "runtime_observations_schema_version": (
                mod.RUNTIME_OBSERVATIONS_SCHEMA_VERSION
            ),
            "lockstep_topology": "dyad",
            "reference_runtimes": [
                {
                    "runtime_id": "bun",
                    "runtime_name": "bun",
                    "version": "1.3.14-test",
                    "is_reference": True,
                }
            ],
            "product_runtime": {
                "runtime_id": "franken-engine-native",
                "runtime_name": "franken-engine-native",
                "version": "0.1.0-test",
                "is_reference": False,
            },
        },
        "totals": {
            "total_test_cases": total,
            "passed_test_cases": total,
            "failed_test_cases": 0,
            "errored_test_cases": 0,
            "skipped_test_cases": 0,
            "overall_pass_rate_pct": 100.0,
        },
        "per_test_results": per_test_results,
        "api_families": [{"family": family} for family in families],
        "bands": [{"band": band} for band in bands],
        "thresholds": {
            "overall_pass_rate_min_pct": 95.0,
            "per_family_pass_rate_min_pct": 80.0,
            "band_pass_rate_min_pct": {
                "core": 99.0,
                "high-value": 95.0,
                "edge": 90.0,
            },
        },
        "previous_release": {"overall_pass_rate_pct": 99.0},
        "ci_gate": {
            "threshold_met": True,
            "release_blocked": False,
            "regression_detected": False,
        },
        "failing_tests_tracking": [],
        "event_codes": list(mod.REQUIRED_EVENT_CODES),
        "reproducibility": {
            "deterministic_seed": "synthetic-release-gate",
            "same_inputs_same_digest": True,
            "external_repro_command": "synthetic fixture",
        },
    }
    refresh_runtime_observations_digest(report)
    return report


def write_report(path: Path, report: dict) -> None:
    path.write_text(json.dumps(report), encoding="utf-8")


def named_check(result: dict, name: str) -> dict:
    return next(check for check in result["checks"] if check["check"] == name)


class TestConstants(unittest.TestCase):
    def test_bead_section_and_default_contract_size(self):
        self.assertEqual(mod.BEAD_ID, "bd-28sz")
        self.assertEqual(mod.SECTION, "13")
        self.assertEqual(mod.DEFAULT_MIN_CASES, 500)

    def test_required_event_codes(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 4)

    def test_required_families(self):
        self.assertEqual(len(mod.REQUIRED_FAMILIES), 16)

    def test_required_risk_bands(self):
        self.assertEqual(mod.REQUIRED_RISK_BANDS, {"critical", "high", "medium", "low"})


class TestFileAndContractChecks(unittest.TestCase):
    def test_checked_in_contract_and_report_exist(self):
        self.assertTrue(mod.check_file(mod.CONTRACT, "contract")["pass"])
        self.assertTrue(mod.check_file(mod.REPORT, "report")["pass"])

    def test_contract_passes(self):
        for check in mod.check_contract():
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")


class TestHelpers(unittest.TestCase):
    def test_pass_rate(self):
        self.assertEqual(mod.pass_rate(95, 100), 95.0)
        self.assertEqual(mod.pass_rate(0, 0), 0.0)

    def test_aggregate_by_key(self):
        rows = [
            {"api_family": "fs", "status": "pass"},
            {"api_family": "fs", "status": "fail"},
            {"api_family": "http", "status": "pass"},
        ]
        aggregate = mod.aggregate_by_key(rows, "api_family")
        self.assertEqual(aggregate["fs"]["total"], 2)
        self.assertEqual(aggregate["fs"]["passed"], 1)
        self.assertEqual(aggregate["http"]["total"], 1)

    def test_runtime_observation_digest_cross_language_pin(self):
        report = passing_report(1)
        self.assertEqual(
            report["corpus"]["runtime_observations_digest"],
            "sha256:1ab42659e6407b492f5f57af96cf5fece52a61573d47e39c18c668c182ffe47e",
        )


class TestSyntheticReportGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.report_path = Path(self.temp_dir.name) / "compatibility-report.json"

    def run_report(self, report: dict, minimum_cases: int = 1000) -> dict:
        write_report(self.report_path, report)
        return mod.run_checks(self.report_path, minimum_cases)

    def test_complete_synthetic_report_passes_release_minimum(self):
        result = self.run_report(passing_report())
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["minimum_cases"], 1000)
        self.assertEqual(result["summary"]["failing"], 0)

    def test_missing_report_fails_closed(self):
        result = mod.run_checks(self.report_path, 1000)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "report: exists")["pass"])

    def test_malformed_report_fails_closed(self):
        self.report_path.write_text("{not-json", encoding="utf-8")
        result = mod.run_checks(self.report_path, 1000)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "report: valid json")["pass"])

    def test_wrong_provenance_fails_closed(self):
        report = passing_report()
        report["corpus"]["provenance"] = "authored-sample"
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(result, "provenance: corpus attests a genuine oracle run")["pass"]
        )

    def test_digest_mismatch_fails_closed(self):
        report = passing_report()
        report["corpus"]["result_digest"] = f"sha256:{'0' * 64}"
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(
                result,
                "provenance: result_digest recomputes from per_test_results",
            )["pass"]
        )

    def test_release_minimum_rejects_999_cases(self):
        result = self.run_report(passing_report(999))
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "corpus: total test cases >= 1000")["pass"])

    def test_below_threshold_report_fails_closed(self):
        report = passing_report()
        for row in report["per_test_results"][:100]:
            row["status"] = "fail"
        report["totals"].update(
            passed_test_cases=900,
            failed_test_cases=100,
            overall_pass_rate_pct=90.0,
        )
        report["corpus"]["result_digest"] = mod.compute_result_digest(
            report["per_test_results"]
        )
        refresh_runtime_observations_digest(report)
        report["failing_tests_tracking"] = [
            {
                "test_id": row["test_id"],
                "investigation_bead_id": "bd-synthetic-failure",
                "investigation_status": "open",
            }
            for row in report["per_test_results"][:100]
        ]
        report["ci_gate"].update(threshold_met=False, release_blocked=True)
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "gate: overall threshold >=95 met")["pass"])

    def test_runtime_observation_tamper_fails_closed(self):
        report = passing_report()
        report["per_test_results"][0]["runtime_observations"]["bun"][
            "elapsed_ms"
        ] += 1
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(
                result,
                "provenance: runtime observations are topology-bound and digest-bound",
            )["pass"]
        )

    def test_runtime_observation_topology_gap_fails_closed(self):
        report = passing_report()
        del report["per_test_results"][0]["runtime_observations"]["bun"]
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(
                result,
                "provenance: runtime observations are topology-bound and digest-bound",
            )["pass"]
        )

    def test_regression_fails_closed(self):
        report = passing_report()
        report["previous_release"]["overall_pass_rate_pct"] = 100.01
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(result, "regression: no pass-rate decrease vs previous release")["pass"]
        )

    def test_cli_accepts_explicit_report_and_minimum(self):
        write_report(self.report_path, passing_report())
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_compatibility_corpus_pass_gate.py"),
                "--report",
                str(self.report_path),
                "--min-cases",
                "1000",
                "--json",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["report_path"], str(self.report_path))
        self.assertEqual(payload["minimum_cases"], 1000)
        self.assertTrue(payload["overall_pass"])

    def test_adversarial_threshold_check_is_present(self):
        checks = mod.check_report(copy.deepcopy(passing_report()), 1000)
        item = next(
            check
            for check in checks
            if check["check"] == "adversarial: threshold drop blocks release"
        )
        self.assertTrue(item["pass"])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)


if __name__ == "__main__":
    unittest.main()
