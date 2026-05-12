"""Unit tests for scripts/check_anti_entropy_reconciliation.py (bd-390)."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_anti_entropy_reconciliation as checker  # noqa: E402


def run_main(args: list[str]) -> tuple[int, str]:
    old_argv = sys.argv
    stdout = io.StringIO()
    try:
        sys.argv = ["check_anti_entropy_reconciliation.py", *args]
        with contextlib.redirect_stdout(stdout):
            try:
                checker.main()
            except SystemExit as exc:
                return int(exc.code), stdout.getvalue()
    finally:
        sys.argv = old_argv
    return 0, stdout.getvalue()


class TestSelfTest(unittest.TestCase):
    def test_self_test_runs(self):
        ok = checker.self_test()
        self.assertTrue(ok)


class TestRunAllStructure(unittest.TestCase):
    def test_structure(self):
        result = checker.run_all()
        for key in ("bead_id", "section", "checks", "verdict",
                     "passed", "failed", "total", "all_passed", "status"):
            self.assertIn(key, result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-390")
        self.assertEqual(result["replacement_bead_id"], "bd-23x2")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.11")

    def test_title(self):
        result = checker.run_all()
        self.assertEqual(result["title"], "Anti-Entropy Reconciliation")

    def test_all_checks_have_required_keys(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_pass_values_are_bool(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIsInstance(check["passed"], bool)

    def test_verdict_consistency(self):
        result = checker.run_all()
        if result["failed"] == 0:
            self.assertEqual(result["verdict"], "PASS")
            self.assertTrue(result["all_passed"])
        else:
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["all_passed"])


class TestSpecChecks(unittest.TestCase):
    def test_spec_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "spec_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_event_codes_in_spec(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_event:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_invariants_in_spec(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_invariant:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_error_codes_in_spec(self):
        result = checker.run_all()
        for code in checker.ERROR_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_error:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")


class TestRustModuleChecks(unittest.TestCase):
    def test_module_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_module_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_module_registered(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_module_registered")
        self.assertTrue(check["passed"], check["detail"])

    def test_structs(self):
        result = checker.run_all()
        for s in checker.REQUIRED_STRUCTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_struct:{s}")
            self.assertTrue(check["passed"], f"{s}: {check['detail']}")

    def test_methods(self):
        result = checker.run_all()
        for m in checker.REQUIRED_METHODS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_method:{m}")
            self.assertTrue(check["passed"], f"{m}: {check['detail']}")

    def test_event_codes_in_rust(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_event:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_invariants_in_rust(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_invariant:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_error_codes_in_rust(self):
        result = checker.run_all()
        for code in checker.ERROR_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_error:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_test_count(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_test_count")
        self.assertTrue(check["passed"], check["detail"])

    def test_two_phase(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_two_phase")
        self.assertTrue(check["passed"], check["detail"])

    def test_cancellation(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_cancellation")
        self.assertTrue(check["passed"], check["detail"])

    def test_mmr_proof(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_mmr_proof")
        self.assertTrue(check["passed"], check["detail"])

    def test_epoch_enforcement(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_epoch_enforcement")
        self.assertTrue(check["passed"], check["detail"])

    def test_canonical_mmr_verifier(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "bd_23x2_canonical_mmr_verifier")
        self.assertTrue(check["passed"], check["detail"])

    def test_replacement_evidence_files(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "bd_23x2_evidence_files")
        self.assertTrue(check["passed"], check["detail"])

    def test_operator_e2e_telemetry(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "bd_23x2_operator_e2e_telemetry")
        self.assertTrue(check["passed"], check["detail"])

    def test_completion_debt_obligations_present(self):
        contract = checker.completion_debt_contract()
        self.assertEqual(contract["completion_bead"], "bd-23x2.1")
        obligations = {
            obligation["spec_item"]: obligation
            for obligation in contract["coverage_obligations"]
        }
        self.assertEqual(
            set(obligations),
            {
                "tests.unit.primary",
                "tests.integration.primary",
                "tests.e2e.primary",
            },
        )
        self.assertIn(
            "tests/e2e/anti_entropy_operator_suite.sh",
            obligations["tests.e2e.primary"]["evidence_paths"],
        )
        self.assertIn(
            "tests/conformance/mmr_proof_verification.rs",
            obligations["tests.integration.primary"]["evidence_paths"],
        )
        self.assertIn("root_digest", obligations["tests.e2e.primary"]["required_fields"])

    def test_completion_debt_missing_spec_item_fails(self):
        original = checker.COMPLETION_DEBT_OBLIGATIONS
        checker.COMPLETION_DEBT_OBLIGATIONS = [
            obligation
            for obligation in original
            if obligation["spec_item"] != "tests.e2e.primary"
        ]
        try:
            result = checker.check_completion_debt_coverage()
        finally:
            checker.COMPLETION_DEBT_OBLIGATIONS = original
        self.assertEqual(result["name"], "bd_23x2_1_completion_debt")
        self.assertFalse(result["passed"])
        self.assertIn("tests.e2e.primary", result["detail"])

    def test_completion_debt_missing_evidence_path_fails(self):
        original = checker.COMPLETION_DEBT_OBLIGATIONS
        mutated = [dict(obligation) for obligation in original]
        mutated[0] = dict(mutated[0])
        mutated[0]["evidence_paths"] = list(mutated[0]["evidence_paths"]) + [
            "artifacts/replacement_gap/bd-23x2/missing-completion-debt.json"
        ]
        checker.COMPLETION_DEBT_OBLIGATIONS = mutated
        try:
            result = checker.check_completion_debt_coverage()
        finally:
            checker.COMPLETION_DEBT_OBLIGATIONS = original
        self.assertEqual(result["name"], "bd_23x2_1_completion_debt")
        self.assertFalse(result["passed"])
        self.assertIn("missing-completion-debt.json", result["detail"])


class TestConstants(unittest.TestCase):
    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 8)

    def test_invariant_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_error_code_count(self):
        self.assertEqual(len(checker.ERROR_CODES), 6)

    def test_struct_count(self):
        self.assertEqual(len(checker.REQUIRED_STRUCTS), 7)

    def test_method_count(self):
        self.assertEqual(len(checker.REQUIRED_METHODS), 13)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        returncode, stdout = run_main(["--json"])
        self.assertEqual(returncode, 0)
        data = json.JSONDecoder().decode(stdout)
        self.assertEqual(data["bead_id"], "bd-390")
        self.assertEqual(data["replacement_bead_id"], "bd-23x2")
        self.assertIn("checks", data)
        self.assertEqual(data["completion_debt"]["completion_bead"], "bd-23x2.1")

    def test_cli_self_test(self):
        returncode, stdout = run_main(["--self-test"])
        self.assertEqual(returncode, 0)
        self.assertIn("self_test passed", stdout)


class TestOverallVerdict(unittest.TestCase):
    def test_all_pass(self):
        result = checker.run_all()
        failing = [c["name"] for c in result["checks"] if not c["passed"]]
        self.assertEqual(result["verdict"], "PASS",
                         f"Failed checks: {failing}")


if __name__ == "__main__":
    unittest.main()
