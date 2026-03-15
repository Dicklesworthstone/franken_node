"""Unit tests for scripts/check_verifier_sdk_capsule.py (bd-nbwo)."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_verifier_sdk_capsule.py"

spec = importlib.util.spec_from_file_location("check_verifier_sdk_capsule", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestVerdict(unittest.TestCase):
    def test_gate_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failures[:10])


class TestResultShape(unittest.TestCase):
    def test_required_fields(self):
        result = mod.run_all()
        for key in [
            "schema_version", "bead_id", "section", "verdict",
            "checks", "event_codes", "error_codes", "invariants",
            "capsule_contract", "events", "summary", "timestamp",
        ]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-nbwo")
        self.assertEqual(result["section"], "10.17")

    def test_schema_version(self):
        result = mod.run_all()
        self.assertEqual(result["schema_version"], "verifier-sdk-capsule-v1.0")


class TestChecks(unittest.TestCase):
    def test_minimum_check_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 25)

    def test_all_checks_have_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)

    def test_no_failures(self):
        result = mod.run_all()
        failures = [c for c in result["checks"] if not c["passed"]]
        self.assertEqual(len(failures), 0,
                         "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in failures[:10]))


class TestArtifactConsistencyGuards(unittest.TestCase):
    def test_artifact_consistency_checks_pass_with_matching_live_counts(self):
        base_checks = [
            {"check": "alpha", "passed": True, "detail": "ok"},
            {"check": "beta", "passed": True, "detail": "ok"},
        ]
        evidence_doc = {
            "checker": {"passed_checks": 5, "failed_checks": 0, "exit_code": 0},
            "unit_tests": {"passed_tests": 2, "failed_tests": 0, "exit_code": 0},
        }
        summary_src = (
            "- Check script: `scripts/check_verifier_sdk_capsule.py` -- 5/5 checks PASS\n"
            "- Unit tests: `tests/test_check_verifier_sdk_capsule.py` -- 2/2 tests PASS\n"
        )
        unit_test_src = "    def test_one(self): pass\n    def test_two(self): pass\n"

        checks = mod._artifact_consistency_checks(
            base_checks,
            evidence_doc,
            summary_src,
            unit_test_src,
        )

        self.assertTrue(all(check["passed"] for check in checks))

    def test_artifact_consistency_checks_fail_closed_on_stale_counts(self):
        base_checks = [
            {"check": "alpha", "passed": True, "detail": "ok"},
            {"check": "beta", "passed": True, "detail": "ok"},
        ]
        evidence_doc = {
            "checker": {"passed_checks": 4, "failed_checks": 0, "exit_code": 1},
            "unit_tests": {"passed_tests": 1, "failed_tests": 0, "exit_code": 1},
        }
        summary_src = (
            "- Check script: `scripts/check_verifier_sdk_capsule.py` -- 4/5 checks PASS\n"
            "- Unit tests: `tests/test_check_verifier_sdk_capsule.py` -- 1/1 tests PASS\n"
        )
        unit_test_src = "    def test_one(self): pass\n    def test_two(self): pass\n"

        checks = mod._artifact_consistency_checks(
            base_checks,
            evidence_doc,
            summary_src,
            unit_test_src,
        )
        by_name = {check["check"]: check for check in checks}

        self.assertFalse(
            by_name["Verification evidence checker counts match live checker results"]["passed"]
        )
        self.assertFalse(
            by_name["Verification evidence unit test counts match live checker results"]["passed"]
        )
        self.assertFalse(
            by_name["Verification summary counts match live checker results"]["passed"]
        )


class TestCapsuleContract(unittest.TestCase):
    def test_contract_present(self):
        result = mod.run_all()
        contract = result["capsule_contract"]
        self.assertTrue(contract["capsule_replay_deterministic"])
        self.assertTrue(contract["no_privileged_access"])
        self.assertTrue(contract["schema_versioned"])
        self.assertTrue(contract["signature_bound"])
        self.assertTrue(contract["workspace_sdk_structural_only_posture_explicit"])
        self.assertTrue(contract["connector_signature_authority_explicit"])
        self.assertTrue(contract["workspace_manifest_binding_explicit"])

    def test_doc_and_metadata_checks_present(self):
        result = mod.run_all()
        check_names = {check["check"] for check in result["checks"]}
        self.assertIn("Public docs distinguish structural-only workspace SDK", check_names)
        self.assertIn(
            "Public docs describe connector detached Ed25519 signature authority",
            check_names,
        )
        self.assertIn("SDK package metadata marks structural-only posture", check_names)
        self.assertIn("SDK package metadata avoids signed-capsule overclaim", check_names)
        self.assertIn("Public docs pin sha256-shaped expected_output_hash", check_names)
        self.assertIn("Public docs pin exact input_refs to inputs binding", check_names)
        self.assertIn(
            "Workspace replay capsule rejects malformed expected_output_hash",
            check_names,
        )
        self.assertIn("Replay capsule validators reject empty created_at", check_names)
        self.assertIn(
            "Workspace replay capsule uses constant-time expected_output_hash comparison",
            check_names,
        )
        self.assertIn(
            "Workspace replay capsule binds declared input_refs to inputs",
            check_names,
        )

    def test_structural_only_contract_fails_closed_when_required_check_missing(self):
        baseline = mod.run_all_checks()
        mutated_checks = [
            check
            for check in baseline
            if check["check"] != "Workspace SDK structural-only posture explicit"
        ]

        with mock.patch.object(mod, "run_all_checks", return_value=mutated_checks):
            contract = mod.run_all()["capsule_contract"]

        self.assertFalse(contract["workspace_sdk_structural_only_posture_explicit"])

    def test_connector_authority_contract_fails_closed_when_required_check_missing(self):
        baseline = mod.run_all_checks()
        mutated_checks = [
            check
            for check in baseline
            if check["check"]
            != "Public docs describe connector detached Ed25519 signature authority"
        ]

        with mock.patch.object(mod, "run_all_checks", return_value=mutated_checks):
            contract = mod.run_all()["capsule_contract"]

        self.assertFalse(contract["connector_signature_authority_explicit"])

    def test_manifest_binding_contract_fails_closed_when_required_check_missing(self):
        baseline = mod.run_all_checks()
        mutated_checks = [
            check
            for check in baseline
            if check["check"]
            != "Workspace replay capsule binds declared input_refs to inputs"
        ]

        with mock.patch.object(mod, "run_all_checks", return_value=mutated_checks):
            contract = mod.run_all()["capsule_contract"]

        self.assertFalse(contract["workspace_manifest_binding_explicit"])

    def test_manifest_binding_contract_fails_closed_when_constant_time_check_missing(self):
        baseline = mod.run_all_checks()
        mutated_checks = [
            check
            for check in baseline
            if check["check"]
            != "Workspace replay capsule uses constant-time expected_output_hash comparison"
        ]

        with mock.patch.object(mod, "run_all_checks", return_value=mutated_checks):
            contract = mod.run_all()["capsule_contract"]

        self.assertFalse(contract["workspace_manifest_binding_explicit"])

    def test_manifest_binding_contract_fails_closed_when_created_at_check_missing(self):
        baseline = mod.run_all_checks()
        mutated_checks = [
            check
            for check in baseline
            if check["check"] != "Replay capsule validators reject empty created_at"
        ]

        with mock.patch.object(mod, "run_all_checks", return_value=mutated_checks):
            contract = mod.run_all()["capsule_contract"]

        self.assertFalse(contract["workspace_manifest_binding_explicit"])


class TestEvents(unittest.TestCase):
    def test_events_present(self):
        result = mod.run_all()
        self.assertIsInstance(result["events"], list)
        self.assertGreater(len(result["events"]), 0)

    def test_events_have_codes(self):
        result = mod.run_all()
        codes = [e["code"] for e in result["events"]]
        for expected in mod.REQUIRED_EVENT_CODES:
            self.assertIn(expected, codes)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS",
                         f"Failures: {[c for c in st['checks'] if not c['passed']]}")


class TestCli(unittest.TestCase):
    def test_json_output_parseable(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-nbwo")

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
