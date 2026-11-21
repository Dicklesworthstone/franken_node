#!/usr/bin/env python3
"""Unit and live-runtime E2E tests for scripts/check_lockstep_validation.py (bd-1w78 / bd-2djfa)."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_lockstep_validation.py"

sys.path.insert(0, str(ROOT / "scripts"))
import check_lockstep_validation as clv


class TestConstants(unittest.TestCase):
    """Verify module-level constants."""

    def test_bead_id(self):
        self.assertEqual(clv.BEAD_ID, "bd-1w78")

    def test_event_codes(self):
        self.assertEqual(clv.EVENT_CODES, ["CLV-001", "CLV-002", "CLV-003", "CLV-004"])

    def test_invariants(self):
        expected = [
            "INV-CLV-CONTINUOUS",
            "INV-CLV-COVERAGE",
            "INV-CLV-REGRESSION",
            "INV-CLV-CORPUS",
        ]
        self.assertEqual(clv.INVARIANTS, expected)

    def test_required_files_count(self):
        self.assertEqual(len(clv.REQUIRED_FILES), 4)


class TestCheckFunctions(unittest.TestCase):
    """Verify each policy check function returns the expected structure."""

    def _assert_check_structure(self, result):
        self.assertIsInstance(result, dict)
        self.assertIn("name", result)
        self.assertIn("passed", result)
        self.assertIn("detail", result)
        self.assertIsInstance(result["name"], str)
        self.assertIsInstance(result["passed"], bool)
        self.assertIsInstance(result["detail"], str)

    def test_check_files_exist(self):
        result = clv.check_files_exist()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "files_exist")

    def test_check_spec_completeness(self):
        result = clv.check_spec_completeness()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "spec_completeness")

    def test_check_lockstep_architecture(self):
        result = clv.check_lockstep_architecture()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "lockstep_architecture")

    def test_check_ci_integration(self):
        result = clv.check_ci_integration()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "ci_integration")

    def test_check_corpus_requirements(self):
        result = clv.check_corpus_requirements()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "corpus_requirements")

    def test_check_divergence_classification(self):
        result = clv.check_divergence_classification()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "divergence_classification")

    def test_check_event_codes(self):
        result = clv.check_event_codes()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "event_codes")

    def test_check_invariants(self):
        result = clv.check_invariants()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "invariants")

    def test_check_targets(self):
        result = clv.check_targets()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "targets")

    def test_check_alerting_policy(self):
        result = clv.check_alerting_policy()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "alerting_policy")


class TestRunAll(unittest.TestCase):
    """Verify the run_all() aggregation function."""

    def test_run_all_structure(self):
        result = clv.run_all()
        self.assertIn("bead_id", result)
        self.assertIn("passed", result)
        self.assertIn("total", result)
        self.assertIn("all_passed", result)
        self.assertIn("checks", result)

    def test_run_all_bead_id(self):
        result = clv.run_all()
        self.assertEqual(result["bead_id"], "bd-1w78")

    def test_run_all_counts(self):
        result = clv.run_all()
        self.assertEqual(result["total"], len(clv.ALL_CHECKS))
        self.assertGreaterEqual(result["passed"], 0)
        self.assertLessEqual(result["passed"], result["total"])

    def test_run_all_checks_list(self):
        result = clv.run_all()
        self.assertIsInstance(result["checks"], list)
        self.assertEqual(len(result["checks"]), len(clv.ALL_CHECKS))

    def test_all_passed_consistency(self):
        result = clv.run_all()
        self.assertEqual(result["all_passed"], result["passed"] == result["total"])


class TestExecutableLockstepPrimitives(unittest.TestCase):
    """Unit tests for normalization, classification, receipts, timing, baseline, and corpus evaluation."""

    def test_normalization_and_harmless_vs_blocking_classification(self):
        ref = {"stdout": "ok /tmp/run-1/a.js 2026-11-20T00:00:00Z\r\n", "stderr": "", "exit_code": 0, "elapsed_ms": 12.0}
        harmless = {"stdout": "ok /tmp/run-2/b.js 2026-11-20T01:02:03Z\n", "stderr": "", "exit_code": 0, "elapsed_ms": 18.0}
        res = clv.classify_lockstep_case("case-harmless", "fs", {"node": ref, "franken-node": harmless})
        self.assertEqual(res["class"], "harmless")
        self.assertTrue(res["passed"])

        side_effect_diff = {
            **ref,
            "side_effects": {"fs_created": ["leaked.txt"], "fs_modified": [], "fs_deleted": [], "network_targets": []},
        }
        blocked = clv.classify_lockstep_case("case-side-effect", "fs", {"node": ref, "franken-node": side_effect_diff})
        self.assertEqual(blocked["class"], "blocking")
        self.assertFalse(blocked["passed"])
        self.assertIn("side-effect mismatch", blocked["reason"])

    def test_timing_anomaly_100ms_and_receipt_validation(self):
        now = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
        obs = {
            "node": {"stdout": "same\n", "stderr": "", "exit_code": 0, "elapsed_ms": 10.0},
            "franken-node": {"stdout": "same\n", "stderr": "", "exit_code": 0, "elapsed_ms": 165.0},
        }
        blocked = clv.classify_lockstep_case("case-slow", "timers", obs, timing_budget_ms=100.0, now_utc=now)
        self.assertEqual(blocked["class"], "blocking")
        self.assertTrue(blocked["timing_anomaly"])
        self.assertGreater(blocked["timing_delta_ms"], 100.0)

        # Receipt without allows_timing_anomaly fails closed
        bad_receipt = {
            "receipt_id": "rcpt-1",
            "case_id": "case-slow",
            "family": "timers",
            "divergence_sha256": blocked["divergence_sha256"],
            "approver": "ops-lead",
            "reason": "known cold-start overhead",
            "expires_at_utc": (now + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
            "allows_timing_anomaly": False,
        }
        still_blocked = clv.classify_lockstep_case(
            "case-slow", "timers", obs, receipts_by_case={"case-slow": bad_receipt}, now_utc=now
        )
        self.assertEqual(still_blocked["class"], "blocking")

        # Expired receipt fails closed
        expired_receipt = {**bad_receipt, "allows_timing_anomaly": True, "expires_at_utc": "2026-01-01T00:00:00Z"}
        expired_res = clv.classify_lockstep_case(
            "case-slow", "timers", obs, receipts_by_case={"case-slow": expired_receipt}, now_utc=now
        )
        self.assertEqual(expired_res["class"], "blocking")
        self.assertIn("expired", expired_res["receipt_detail"])

        # Valid receipt admits acceptable divergence
        valid_receipt = {**bad_receipt, "allows_timing_anomaly": True}
        admitted = clv.classify_lockstep_case(
            "case-slow", "timers", obs, receipts_by_case={"case-slow": valid_receipt}, now_utc=now
        )
        self.assertEqual(admitted["class"], "acceptable")
        self.assertTrue(admitted["passed"])
        self.assertTrue(admitted["receipt_verified"])

    def test_baseline_regression_detection(self):
        baseline = {
            "overall_pass_rate_pct": 97.5,
            "per_family_scores": {"fs": {"pass_rate_pct": 96.0}, "net": {"pass_rate_pct": 95.0}},
        }
        self.assertEqual(clv.compare_against_baseline(97.5, {"fs": 96.0, "net": 95.0}, baseline), [])
        regs = clv.compare_against_baseline(96.0, {"fs": 94.0, "net": 95.0}, baseline)
        self.assertEqual(len(regs), 2)
        self.assertTrue(any("overall pass rate regressed" in r for r in regs))
        self.assertTrue(any("family `fs` regressed" in r for r in regs))

    def test_checked_in_corpus_digest_and_honest_core_floor_gate(self):
        report = clv.evaluate_corpus_artifact(clv.DEFAULT_CORPUS_RESULTS_PATH)
        # Digest matches recomputed SHA-256 over all 560 rows
        self.assertEqual(report["total_cases"], 560)
        self.assertFalse(any("result_digest" in r for r in report["blocking_reasons"]))
        self.assertGreaterEqual(report["overall_pass_rate_pct"], 95.0)
        # Honest gate: core band is currently 98.03% < 99.0%, so gate MUST report FAIL (never weaken threshold)
        if report["per_band_scores"]["core"]["pass_rate_pct"] < 99.0:
            self.assertFalse(report["passed"])
            self.assertTrue(any("band `core`" in r for r in report["blocking_reasons"]))

    def test_corpus_gate_fails_closed_on_tampered_digest_and_undersized_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus_file = Path(tmp) / "corpus.json"
            rows = [
                {"test_id": f"tc::fs::{i:04d}", "api_family": "fs", "band": "core", "risk_band": "critical", "status": "pass"}
                for i in range(5)
            ]
            doc = {
                "corpus": {
                    "provenance": "lockstep-oracle-run",
                    "result_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "reference_runtimes": [{"runtime_id": "node"}, {"runtime_id": "bun"}],
                    "product_runtime": {"runtime_id": "franken-engine-native"},
                },
                "per_test_results": rows,
            }
            corpus_file.write_text(json.dumps(doc), encoding="utf-8")
            report = clv.evaluate_corpus_artifact(corpus_file, min_corpus_cases=500)
            self.assertFalse(report["passed"])
            self.assertTrue(any("undersized corpus" in r for r in report["blocking_reasons"]))
            self.assertTrue(any("result_digest integrity mismatch" in r for r in report["blocking_reasons"]))

    def test_missing_runtime_fails_closed(self):
        report = clv.run_live_lockstep_fixtures(
            [{"case_id": "c1", "family": "core", "source": "console.log(1);"}],
            runtime_commands={"node": ["/nonexistent/runtime/node"], "franken-node": None},
        )
        self.assertFalse(report["passed"])
        self.assertTrue(any("missing required runtime" in r for r in report["blocking_reasons"]))


class TestLiveRuntimeLockstepE2E(unittest.TestCase):
    """End-to-end tests executing real subprocesses over passing, harmless, blocking, slow, and receipted fixtures."""

    def _make_runtime_shim(self, path: Path, mode: str) -> Path:
        script = f"""#!/usr/bin/env python3
import sys, time
src = open(sys.argv[1], encoding="utf-8").read()
if "CASE_PASS" in src:
    print("value=42")
elif "CASE_HARMLESS" in src:
    print("path=/tmp/run-{mode}/x.js 2026-11-20T0{'1' if mode == 'prod' else '0'}:00:00Z")
elif "CASE_BLOCKING" in src:
    print("{'prod-wrong' if mode == 'prod' else 'node-right'}")
elif "CASE_SLOW" in src:
    if "{mode}" == "prod":
        time.sleep(0.14)
    print("slow-ok")
elif "CASE_ACCEPTABLE" in src:
    print("{'prod-waived' if mode == 'prod' else 'node-orig'}")
"""
        path.write_text(script, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_live_e2e_covers_all_five_fixture_classes_and_all_lifecycle_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ref_bin = self._make_runtime_shim(tmp_path / "ref_rt.py", "ref")
            prod_bin = self._make_runtime_shim(tmp_path / "prod_rt.py", "prod")
            artifact = tmp_path / "lockstep_report.json"
            jsonl_log = tmp_path / "lockstep_events.jsonl"

            fixtures = [
                {"case_id": "f-pass", "family": "core", "source": "// CASE_PASS"},
                {"case_id": "f-harmless", "family": "core", "source": "// CASE_HARMLESS"},
                {"case_id": "f-blocking", "family": "core", "source": "// CASE_BLOCKING"},
                {"case_id": "f-slow", "family": "timers", "source": "// CASE_SLOW"},
                {"case_id": "f-acceptable", "family": "fs", "source": "// CASE_ACCEPTABLE"},
            ]

            # 1. Without receipts: blocking + slow fixtures fail closed
            first = clv.run_live_lockstep_fixtures(
                fixtures,
                runtime_commands={"node": [str(ref_bin)], "franken-node": [str(prod_bin)]},
                timing_budget_ms=100.0,
                jsonl_log_path=jsonl_log,
                output_artifact_path=artifact,
            )
            self.assertFalse(first["passed"])
            by_id = {c["case_id"]: c for c in first["cases"]}
            self.assertEqual(by_id["f-pass"]["class"], "agree")
            self.assertEqual(by_id["f-harmless"]["class"], "harmless")
            self.assertEqual(by_id["f-blocking"]["class"], "blocking")
            self.assertEqual(by_id["f-slow"]["class"], "blocking")
            self.assertTrue(by_id["f-slow"]["timing_anomaly"])
            self.assertEqual(by_id["f-acceptable"]["class"], "blocking")

            # 2. Provide valid receipts for f-acceptable and f-slow; remove f-blocking -> gate PASSES
            now = datetime.now(timezone.utc)
            expires = (now + timedelta(days=7)).isoformat().replace("+00:00", "Z")
            receipts = {
                "f-acceptable": {
                    "receipt_id": "rcpt-accept-1",
                    "case_id": "f-acceptable",
                    "family": "fs",
                    "divergence_sha256": by_id["f-acceptable"]["divergence_sha256"],
                    "approver": "release-eng",
                    "reason": "documented intentional security policy divergence",
                    "expires_at_utc": expires,
                },
                "f-slow": {
                    "receipt_id": "rcpt-slow-1",
                    "case_id": "f-slow",
                    "family": "timers",
                    "divergence_sha256": by_id["f-slow"]["divergence_sha256"],
                    "approver": "perf-eng",
                    "reason": "waived cold-start fixture",
                    "expires_at_utc": expires,
                    "allows_timing_anomaly": True,
                },
            }
            passing_fixtures = [f for f in fixtures if f["case_id"] != "f-blocking"]
            second = clv.run_live_lockstep_fixtures(
                passing_fixtures,
                runtime_commands={"node": [str(ref_bin)], "franken-node": [str(prod_bin)]},
                receipts_by_case=receipts,
                timing_budget_ms=100.0,
                jsonl_log_path=jsonl_log,
                output_artifact_path=artifact,
            )
            self.assertTrue(second["passed"], second["blocking_reasons"])
            self.assertTrue(artifact.is_file())
            self.assertTrue(jsonl_log.is_file())

            # Assert all 8 required bd-2djfa lifecycle events were emitted to JSONL
            emitted = [json.loads(line) for line in jsonl_log.read_text(encoding="utf-8").splitlines() if line.strip()]
            emitted_names = {ev["event"] for ev in emitted}
            for req in clv.LIFECYCLE_EVENTS:
                self.assertIn(req, emitted_names, f"missing lifecycle event {req}")
            for ev in emitted:
                for key in ("trace_id", "case_id", "runtime", "family", "class", "artifact_path"):
                    self.assertIn(key, ev)

    def test_real_node_bun_franken_node_live_lockstep_smoke(self):
        node_cmd = clv._resolve_runtime_command("node")
        bun_cmd = clv._resolve_runtime_command("bun")
        franken_cmd = clv._resolve_runtime_command("franken-node")
        if not (node_cmd and bun_cmd and franken_cmd):
            self.skipTest("node, bun, and built franken-node required for real triad smoke")
        report = clv.run_live_lockstep_fixtures(
            [
                {
                    "case_id": "triad-pure-js",
                    "family": "core",
                    "source": "console.log([1,2,3].map(x => x * 2).join(','));\n",
                }
            ],
            runtime_commands={"node": node_cmd, "bun": bun_cmd, "franken-node": franken_cmd},
            timing_budget_ms=5000.0,
        )
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["cases"][0]["class"], "agree")


class TestJsonOutput(unittest.TestCase):
    """Verify the script produces valid JSON with --json flag."""

    def test_json_output(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout.strip()
        self.assertTrue(len(output) > 0, "no output produced")
        data = json.loads(output)
        self.assertEqual(data["bead_id"], "bd-1w78")
        self.assertIn("checks", data)


class TestSelfTest(unittest.TestCase):
    """Verify the built-in self_test() runs successfully."""

    def test_self_test_passes(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"self_test failed:\n{proc.stderr}")


if __name__ == "__main__":
    unittest.main()
