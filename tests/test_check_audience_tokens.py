"""Unit tests for scripts/check_audience_tokens.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_audience_tokens as mod  # noqa: E402


class TestConstants(unittest.TestCase):
    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 7)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 30)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_error_codes_count(self):
        self.assertEqual(len(mod.ERROR_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_action_scopes_count(self):
        self.assertEqual(len(mod.ACTION_SCOPES), 5)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 50)

    def test_token_fields_count(self):
        self.assertEqual(len(mod.TOKEN_FIELDS), 10)


class TestCheckFiles(unittest.TestCase):
    def test_all_files_exist(self):
        results = mod.check_files()
        for r in results:
            self.assertTrue(r["pass"], f"File missing: {r['check']}")

    def test_file_count(self):
        results = mod.check_files()
        self.assertEqual(len(results), 4)


class TestRustCommentStripping(unittest.TestCase):
    def test_preserves_string_literals_while_stripping_comments(self):
        source = "\n".join(
            [
                'const CODE: &str = "ABT-001";',
                "// pub struct AudienceBoundToken",
                'const RAW: &str = r#"ERR_ABT_REPLAY_DETECTED"#;',
                "/* #[test] */",
            ]
        )

        stripped = mod.strip_rust_comments(source)

        self.assertIn('"ABT-001"', stripped)
        self.assertIn('r#"ERR_ABT_REPLAY_DETECTED"#', stripped)
        self.assertNotIn("pub struct AudienceBoundToken", stripped)
        self.assertNotIn("#[test]", stripped)


class TestCheckModule(unittest.TestCase):
    def test_module_registered(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTypes(unittest.TestCase):
    def test_all_types_found(self):
        results = mod.check_types()
        for r in results:
            self.assertTrue(r["pass"], f"Type missing: {r['check']}")


class TestCheckMethods(unittest.TestCase):
    def test_all_methods_found(self):
        results = mod.check_methods()
        for r in results:
            self.assertTrue(r["pass"], f"Method missing: {r['check']}")


class TestCheckEventCodes(unittest.TestCase):
    def test_all_event_codes_found(self):
        results = mod.check_event_codes()
        for r in results:
            self.assertTrue(r["pass"], f"Event code missing: {r['check']}")


class TestCheckErrorCodes(unittest.TestCase):
    def test_all_error_codes_found(self):
        results = mod.check_error_codes()
        for r in results:
            self.assertTrue(r["pass"], f"Error code missing: {r['check']}")


class TestCheckInvariants(unittest.TestCase):
    def test_all_invariants_found(self):
        results = mod.check_invariants()
        for r in results:
            self.assertTrue(r["pass"], f"Invariant missing: {r['check']}")


class TestCheckActionScopes(unittest.TestCase):
    def test_all_scopes_found(self):
        results = mod.check_action_scopes()
        for r in results:
            self.assertTrue(r["pass"], f"Action scope missing: {r['check']}")


class TestCheckTokenFields(unittest.TestCase):
    def test_all_fields_found(self):
        results = mod.check_token_fields()
        for r in results:
            self.assertTrue(r["pass"], f"Token field missing: {r['check']}")


class TestCheckTests(unittest.TestCase):
    def test_all_tests_found(self):
        results = mod.check_tests()
        for r in results:
            self.assertTrue(r["pass"], f"Test missing: {r['check']}")


class TestCheckTestCount(unittest.TestCase):
    def test_sufficient_tests(self):
        result = mod.check_test_count()
        self.assertTrue(result["pass"], result["detail"])


class TestCheckSerde(unittest.TestCase):
    def test_serde_derives(self):
        result = mod.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckSha256(unittest.TestCase):
    def test_sha256_usage(self):
        result = mod.check_sha256_usage()
        self.assertTrue(result["pass"])


class TestCheckSendSync(unittest.TestCase):
    def test_send_sync_assertions(self):
        result = mod.check_send_sync()
        self.assertTrue(result["pass"])


class TestCheckSpec(unittest.TestCase):
    def test_spec_sections(self):
        results = mod.check_spec_sections()
        for r in results:
            self.assertTrue(r["pass"], f"Spec section missing: {r['check']}")


class TestCheckPolicy(unittest.TestCase):
    def test_policy_sections(self):
        results = mod.check_policy_sections()
        for r in results:
            self.assertTrue(r["pass"], f"Policy section missing: {r['check']}")


class TestCheckAdversarial(unittest.TestCase):
    def test_adversarial_tests(self):
        results = mod.check_adversarial_tests()
        for r in results:
            self.assertTrue(r["pass"], f"Adversarial test missing: {r['check']}")


class TestCheckDepthCoverage(unittest.TestCase):
    def test_depth_coverage(self):
        results = mod.check_depth_coverage()
        for r in results:
            self.assertTrue(r["pass"], f"Depth coverage missing: {r['check']}")


class TestValidateToken(unittest.TestCase):
    def test_valid_token_accepted(self):
        token = {
            "token_id": "tok-1", "issuer": "issuer-1",
            "audience": ["kernel-A"], "capabilities": ["Migrate"],
            "issued_at": 1000, "expires_at": 100000,
            "nonce": "nonce-1", "parent_token_hash": None,
            "signature": "sig-1", "max_delegation_depth": 3,
        }
        ok, detail = mod.validate_token(token)
        self.assertTrue(ok, detail)

    def test_missing_field_rejected(self):
        token = {
            "token_id": "tok-1", "issuer": "issuer-1",
            "audience": ["kernel-A"], "capabilities": ["Migrate"],
            "issued_at": 1000, "expires_at": 100000,
            "parent_token_hash": None,
            "signature": "sig-1", "max_delegation_depth": 3,
        }
        ok, detail = mod.validate_token(token)
        self.assertFalse(ok)
        self.assertIn("nonce", detail)

    def test_non_list_audience_rejected(self):
        token = {
            "token_id": "tok-1", "issuer": "issuer-1",
            "audience": "kernel-A", "capabilities": ["Migrate"],
            "issued_at": 1000, "expires_at": 100000,
            "nonce": "nonce-1", "parent_token_hash": None,
            "signature": "sig-1", "max_delegation_depth": 3,
        }
        ok, detail = mod.validate_token(token)
        self.assertFalse(ok)
        self.assertIn("audience", detail)

    def test_invalid_window_rejected(self):
        token = {
            "token_id": "tok-1", "issuer": "issuer-1",
            "audience": ["kernel-A"], "capabilities": ["Migrate"],
            "issued_at": 100000, "expires_at": 1000,
            "nonce": "nonce-1", "parent_token_hash": None,
            "signature": "sig-1", "max_delegation_depth": 3,
        }
        ok, detail = mod.validate_token(token)
        self.assertFalse(ok)
        self.assertIn("issued_at", detail)

    def test_non_numeric_issued_at_rejected(self):
        token = {
            "token_id": "tok-1", "issuer": "issuer-1",
            "audience": ["kernel-A"], "capabilities": ["Migrate"],
            "issued_at": "not_a_number", "expires_at": 100000,
            "nonce": "nonce-1", "parent_token_hash": None,
            "signature": "sig-1", "max_delegation_depth": 3,
        }
        ok, detail = mod.validate_token(token)
        self.assertFalse(ok)
        self.assertIn("numeric", detail)


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"], self._failing(result))

    def test_verdict_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead(self):
        result = mod.run_checks()
        self.assertEqual(result["bead"], "bd-1r2")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.10")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing_checks"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total_checks"], 140)

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestRunAll(unittest.TestCase):
    def test_run_all_alias(self):
        result = mod.run_all()
        self.assertEqual(result["bead"], "bd-1r2")
        self.assertEqual(result["verdict"], "PASS")


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead"], "bd-1r2")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)

    def test_summary_fields(self):
        result = mod.run_checks()
        for key in ["passing_checks", "failing_checks", "total_checks"]:
            self.assertIn(key, result["summary"])

    def test_check_fields(self):
        result = mod.run_checks()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)


class TestModuleAttributes(unittest.TestCase):
    def test_has_all_checks(self):
        self.assertTrue(hasattr(mod, "ALL_CHECKS"))

    def test_has_results(self):
        self.assertTrue(hasattr(mod, "RESULTS"))

    def test_has_safe_rel(self):
        self.assertTrue(callable(mod._safe_rel))

    def test_safe_rel_inside_root(self):
        p = mod.ROOT / "some" / "file.txt"
        self.assertEqual(mod._safe_rel(p), "some/file.txt")

    def test_safe_rel_outside_root(self):
        p = Path("/tmp/outside.txt")
        self.assertEqual(mod._safe_rel(p), "/tmp/outside.txt")


class TestCommentOnlyRustRegression(unittest.TestCase):
    """Commented Rust markers must not satisfy implementation checks."""

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            impl = tmp_path / "audience_token.rs"
            mod_rs = tmp_path / "mod.rs"
            impl.write_text(
                "\n".join(f"// {marker}" for marker in COMMENT_ONLY_MARKERS)
                + "\n/*\n"
                + "\n".join("#[test]" for _ in range(50))
                + "\nSerialize\nDeserialize\nSha256\nassert_send\nassert_sync\n"
                + "\n*/\n",
                encoding="utf-8",
            )
            mod_rs.write_text("// pub mod audience_token;\n", encoding="utf-8")

            with (
                mock.patch.object(mod, "IMPL", impl),
                mock.patch.object(mod, "MOD_RS", mod_rs),
            ):
                result = mod.run_checks()

        by_name = {check["check"]: check for check in result["checks"]}
        self.assertTrue(by_name["file: implementation"]["pass"])
        self.assertTrue(by_name["file: control_plane mod.rs"]["pass"])

        rust_backed_checks = [
            check["check"]
            for check in result["checks"]
            if check["check"] == "module registered in mod.rs"
            or check["check"].startswith(
                (
                    "type: ",
                    "method: ",
                    "event_code: ",
                    "error_code: ",
                    "invariant: ",
                    "action_scope: ",
                    "token_field: ",
                    "test: ",
                    "adversarial: ",
                    "depth: ",
                )
            )
            or check["check"] in {
                "test count >= 50",
                "Serialize/Deserialize derives",
                "SHA-256 usage",
                "Send+Sync assertions",
            }
        ]
        self.assertTrue(rust_backed_checks)
        passing_markers = [name for name in rust_backed_checks if by_name[name]["pass"]]
        self.assertEqual(passing_markers, [])


COMMENT_ONLY_MARKERS = (
    ["pub mod audience_token;"]
    + mod.REQUIRED_TYPES
    + mod.REQUIRED_METHODS
    + mod.EVENT_CODES
    + mod.ERROR_CODES
    + mod.INVARIANTS
    + mod.ACTION_SCOPES
    + [f"pub {field}:" for field in mod.TOKEN_FIELDS]
    + [f"fn {test_name}" for test_name in mod.REQUIRED_TESTS]
    + [
        "forged",
        "scope_escalation",
        "audience_escalation",
        "cross_audience_replay",
        "expired_intermediate",
        "depth_limit_exceeded",
    ]
)


if __name__ == "__main__":
    unittest.main()
