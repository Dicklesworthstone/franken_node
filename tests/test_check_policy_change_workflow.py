#!/usr/bin/env python3
"""Unit tests for check_policy_change_workflow.py verification script."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_policy_change_workflow as checker  # noqa: E402


class TestCheckFileHelper(unittest.TestCase):
    def test_file_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = checker.check_file(Path("/nonexistent/file.rs"), "missing")
        self.assertFalse(result["pass"])

    def test_detail_on_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertIn("exists:", result["detail"])

    def test_detail_on_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertIn("MISSING", result["detail"])


class TestCheckContentHelper(unittest.TestCase):
    def test_found(self):
        results = checker.check_content(checker.IMPL, ["pub enum RiskAssessment"], "type")
        self.assertTrue(results[0]["pass"])

    def test_not_found(self):
        results = checker.check_content(checker.IMPL, ["NONEXISTENT_XYZ"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = checker.check_content(Path("/nonexistent"), ["pattern"], "cat")
        self.assertFalse(results[0]["pass"])

    def test_multiple(self):
        results = checker.check_content(
            checker.IMPL,
            ["pub enum RiskAssessment", "pub enum ProposalState"],
            "type",
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["pass"] for r in results))


class TestRustCommentStripping(unittest.TestCase):
    def test_preserves_string_literals_while_stripping_comments(self):
        source = "\n".join(
            [
                'const CODE: &str = "POLICY_CHANGE_PROPOSED";',
                "// pub struct PolicyChangeEngine",
                'const RAW: &str = r#"ERR_AUDIT_CHAIN_BROKEN"#;',
                "/* #[test] */",
            ]
        )

        stripped = checker.strip_rust_comments(source)

        self.assertIn('"POLICY_CHANGE_PROPOSED"', stripped)
        self.assertIn('r#"ERR_AUDIT_CHAIN_BROKEN"#', stripped)
        self.assertNotIn("pub struct PolicyChangeEngine", stripped)
        self.assertNotIn("#[test]", stripped)


class TestCheckModuleRegistered(unittest.TestCase):
    def test_registered(self):
        result = checker.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTestCount(unittest.TestCase):
    def test_minimum_20(self):
        result = checker.check_test_count()
        self.assertTrue(result["pass"])
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 20)


class TestCheckSerdeDerive(unittest.TestCase):
    def test_serde(self):
        result = checker.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckHashChain(unittest.TestCase):
    def test_hash_chain_checks(self):
        results = checker.check_hash_chain()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_sha256_present(self):
        results = checker.check_hash_chain()
        sha_check = [r for r in results if "SHA-256" in r["check"]]
        self.assertTrue(len(sha_check) > 0)
        self.assertTrue(sha_check[0]["pass"])


class TestCheckRoleSeparation(unittest.TestCase):
    def test_role_separation_checks(self):
        results = checker.check_role_separation()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestCheckRollbackMechanism(unittest.TestCase):
    def test_rollback_checks(self):
        results = checker.check_rollback_mechanism()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestCheckSpecInvariants(unittest.TestCase):
    def test_all_invariants(self):
        results = checker.check_spec_invariants()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_invariant_count(self):
        self.assertGreaterEqual(len(checker.INVARIANTS), 8)


class TestRunChecks(unittest.TestCase):
    def test_full_run(self):
        result = checker.run_checks()
        self.assertIn("checks", result)
        self.assertIn("summary", result)

    def test_all_checks_pass(self):
        result = checker.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}",
        )

    def test_verdict_is_pass(self):
        result = checker.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_title_field(self):
        result = checker.run_checks()
        self.assertIn("approval", result["title"].lower())

    def test_test_count_field(self):
        result = checker.run_checks()
        count = int(result["test_count"])
        self.assertGreaterEqual(count, 20)

    def test_check_count_reasonable(self):
        result = checker.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 70)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = checker.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = checker.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestRequiredConstants(unittest.TestCase):
    def test_types_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TYPES), 10)

    def test_methods_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_METHODS), 9)

    def test_event_codes_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 8)

    def test_error_codes_count(self):
        self.assertEqual(len(checker.ERROR_CODES), 7)

    def test_invariants_count(self):
        self.assertEqual(len(checker.INVARIANTS), 8)

    def test_states_count(self):
        self.assertEqual(len(checker.PROPOSAL_STATES), 6)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TESTS), 20)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_checks()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_policy_change_workflow.py"), "--json"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_policy_change_workflow.py")],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


class TestCommentOnlyRustRegression(unittest.TestCase):
    """Commented Rust markers must not satisfy implementation checks."""

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            impl = tmp_path / "approval_workflow.rs"
            mod_rs = tmp_path / "mod.rs"
            impl.write_text(
                "\n".join(f"// {marker}" for marker in COMMENT_ONLY_MARKERS)
                + "\n/*\n"
                + "\n".join("#[test]" for _ in range(20))
                + "\nSerialize\nDeserialize\nSha256\nprev_hash\ncompute_entry_hash\n"
                + "verify_audit_chain\nERR_SOLE_APPROVER\nproposed_by\n"
                + "non_proposer_approvals\nold_value: d.new_value\n"
                + "rollback_of\nrollback_command\n"
                + "\n*/\n",
                encoding="utf-8",
            )
            mod_rs.write_text("// pub mod approval_workflow;\n", encoding="utf-8")

            with (
                mock.patch.object(checker, "IMPL", impl),
                mock.patch.object(checker, "MOD_RS", mod_rs),
            ):
                result = checker.run_checks()

        by_name = {check["check"]: check for check in result["checks"]}
        self.assertTrue(by_name["file: implementation"]["pass"])
        self.assertTrue(by_name["file: spec contract"]["pass"])

        rust_backed_checks = [
            check["check"]
            for check in result["checks"]
            if check["check"] == "module registered in mod.rs"
            or check["check"] == "unit test count"
            or check["check"] == "Serialize/Deserialize derives"
            or check["check"].startswith(
                (
                    "type: ",
                    "method: ",
                    "event_code: ",
                    "error_code: ",
                    "state: ",
                    "test: ",
                    "hash chain: ",
                    "role separation: ",
                    "rollback: ",
                )
            )
        ]
        self.assertTrue(rust_backed_checks)
        passing_markers = [name for name in rust_backed_checks if by_name[name]["pass"]]
        self.assertEqual(passing_markers, [])


COMMENT_ONLY_MARKERS = (
    ["pub mod approval_workflow;"]
    + checker.REQUIRED_TYPES
    + checker.REQUIRED_METHODS
    + checker.EVENT_CODES
    + checker.ERROR_CODES
    + checker.PROPOSAL_STATES
    + [f"fn {test_name}" for test_name in checker.REQUIRED_TESTS]
    + [
        "Sha256",
        "prev_hash",
        "compute_entry_hash",
        "verify_audit_chain",
        "ERR_SOLE_APPROVER",
        "proposed_by",
        "non_proposer_approvals",
        "old_value: d.new_value",
        "rollback_of",
        "rollback_command",
    ]
)


if __name__ == "__main__":
    unittest.main()
