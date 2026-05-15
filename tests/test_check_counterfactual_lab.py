"""Unit tests for scripts/check_counterfactual_lab.py."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_counterfactual_lab.py"

spec = importlib.util.spec_from_file_location("check_counterfactual_lab", SCRIPT)
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
        for key in ["schema_version", "bead_id", "section", "verdict", "checks",
                     "event_codes", "error_codes", "invariants"]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-383z")
        self.assertEqual(result["section"], "10.17")


class TestChecks(unittest.TestCase):
    def test_minimum_check_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 20)

    def test_all_checks_have_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS")


class TestLabContract(unittest.TestCase):
    def test_lab_contract_fields(self):
        result = mod.run_all()
        contract = result.get("lab_contract", {})
        self.assertTrue(contract.get("requires_signed_rollout"))
        self.assertTrue(contract.get("requires_rollback_contract"))
        self.assertTrue(contract.get("requires_positive_loss_delta"))
        self.assertTrue(contract.get("requires_trace_integrity"))


class TestCli(unittest.TestCase):
    def test_json_output_parseable(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-383z")

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestCommentOnlyRegression(unittest.TestCase):
    def test_comment_only_source_markers_fail_closed(self):
        impl_tokens = [
            "struct IncidentTrace",
            "struct MitigationCandidate",
            "struct RolloutContract",
            "struct RollbackContract",
            "struct PromotedMitigation",
            "struct IncidentLab",
            "fn load_trace",
            "fn replay_baseline",
            "fn synthesize_mitigation",
            "fn compare_replay",
            "fn promote_mitigation",
            "fn run_full_workflow",
            "struct LabDecision",
            "struct ReplayComparison",
            "struct LabConfig",
        ]
        commented_impl = "\n".join(
            [
                *(f"// {token}" for token in impl_tokens),
                *(f"// {code}" for code in mod.REQUIRED_EVENT_CODES),
                *(f"// {code}" for code in mod.REQUIRED_ERROR_CODES),
                *(f"// {invariant}" for invariant in mod.REQUIRED_INVARIANTS),
                "/*",
                *("// #[test]\n// fn commented_test() {}" for _ in range(8)),
                "*/",
            ]
        )
        commented_lab_tests = "\n".join(
            f"// #[test]\n// fn commented_lab_test_{idx}() {{}}" for idx in range(10)
        )

        original_impl = mod.IMPL_FILE
        original_mod = mod.MOD_FILE
        original_lib = mod.LIB_FILE
        original_lab = mod.LAB_TEST
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            impl_path = tmp / "mitigation_synthesis.rs"
            mod_path = tmp / "mod.rs"
            lib_path = tmp / "lib.rs"
            lab_path = tmp / "counterfactual_mitigation_eval.rs"
            impl_path.write_text(commented_impl, encoding="utf-8")
            mod_path.write_text("// pub mod mitigation_synthesis;\n", encoding="utf-8")
            lib_path.write_text("// pub mod ops;\n", encoding="utf-8")
            lab_path.write_text(commented_lab_tests, encoding="utf-8")

            try:
                mod.IMPL_FILE = impl_path
                mod.MOD_FILE = mod_path
                mod.LIB_FILE = lib_path
                mod.LAB_TEST = lab_path
                result = mod.run_all()
            finally:
                mod.IMPL_FILE = original_impl
                mod.MOD_FILE = original_mod
                mod.LIB_FILE = original_lib
                mod.LAB_TEST = original_lab

        checks = {check["check"]: check["passed"] for check in result["checks"]}
        self.assertTrue(checks["Spec file exists"])
        self.assertTrue(checks["Implementation file exists"])
        self.assertTrue(checks["Ops mod file exists"])
        self.assertTrue(checks["Lab test exists"])
        self.assertTrue(checks["Python checker unit test exists"])

        expected_failures = [
            "Library module wired",
            "Ops mod exports mitigation_synthesis",
            "Rust unit tests >= 8",
            "Lab test has >= 10 tests",
        ]
        expected_failures.extend(f"Impl token '{token}'" for token in impl_tokens)
        expected_failures.extend(f"Event code {code}" for code in mod.REQUIRED_EVENT_CODES)
        expected_failures.extend(f"Error code {code}" for code in mod.REQUIRED_ERROR_CODES)
        expected_failures.extend(f"Invariant {invariant}" for invariant in mod.REQUIRED_INVARIANTS)
        for check_name in expected_failures:
            self.assertIn(check_name, checks)
            self.assertFalse(checks[check_name], check_name)

        spec_src = mod._read(mod.SPEC_FILE)
        for marker in mod.REQUIRED_EVENT_CODES + mod.REQUIRED_ERROR_CODES + mod.REQUIRED_INVARIANTS:
            self.assertIn(marker, spec_src)


if __name__ == "__main__":
    unittest.main()
