"""Unit tests for scripts/check_key_role_separation.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_key_role_separation as mod  # noqa: E402


class TestConstants(unittest.TestCase):
    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 4)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 8)

    def test_error_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_ERROR_CODES), 4)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 4)

    def test_required_roles_count(self):
        self.assertEqual(len(mod.REQUIRED_ROLES), 4)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 30)


class TestCheckFile(unittest.TestCase):
    def test_existing(self):
        result = mod.check_file(mod.IMPL, "test")
        self.assertTrue(result["pass"])

    def test_missing(self):
        result = mod.check_file(Path("/nonexistent/file.rs"), "ghost")
        self.assertFalse(result["pass"])


class TestCheckContent(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, ["pub enum KeyRole"], "type")
        self.assertTrue(results[0]["pass"])

    def test_missing(self):
        results = mod.check_content(mod.IMPL, ["NONEXISTENT_PATTERN_XYZ"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = mod.check_content(Path("/no"), ["anything"], "type")
        self.assertFalse(results[0]["pass"])


class TestRustCommentStripping(unittest.TestCase):
    def test_preserves_string_literals_while_stripping_comments(self):
        source = "\n".join(
            [
                'pub const URL: &str = "https://example.test//kept"; // pub enum KeyRole',
                'pub const BLOCKY: &str = "not /* a comment */"; /* fn bind() {} */',
                'pub const RAW: &str = r#"raw // kept /* kept */"#;',
                "/* outer /* nested */ still comment */ pub struct RealMarker;",
            ]
        )

        stripped = mod._strip_rust_comments(source)

        self.assertIn('"https://example.test//kept"', stripped)
        self.assertIn('"not /* a comment */"', stripped)
        self.assertIn('r#"raw // kept /* kept */"#', stripped)
        self.assertIn("pub struct RealMarker;", stripped)
        self.assertNotIn("pub enum KeyRole", stripped)
        self.assertNotIn("fn bind()", stripped)
        self.assertNotIn("nested", stripped)


class TestCommentOnlyRustRegression(unittest.TestCase):
    def test_comment_only_rust_markers_fail_closed(self):
        original_impl = mod.IMPL
        original_mod = mod.MOD_RS
        markers = (
            mod.REQUIRED_TYPES
            + mod.REQUIRED_METHODS
            + mod.REQUIRED_ERROR_CODES
            + mod.REQUIRED_EVENT_CODES
            + mod.REQUIRED_INVARIANTS
            + mod.REQUIRED_ROLES
            + mod.REQUIRED_TESTS
            + [marker for markers in mod.INVARIANT_IMPLEMENTATION_MARKERS.values() for marker in markers]
            + [
                "pub key_id",
                "pub role",
                "pub public_key_bytes",
                "pub bound_at",
                "pub bound_by",
                "pub max_validity_seconds",
                "0x00, 0x01",
                "0x00, 0x02",
                "0x00, 0x03",
                "0x00, 0x04",
            ]
        )
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                fake_impl = Path(tmpdir) / "key_role_separation.rs"
                fake_mod = Path(tmpdir) / "mod.rs"
                fake_impl.write_text(
                    "\n".join(f"// {marker}" for marker in markers)
                    + "\n/*\n"
                    + "\n".join("#[test]" for _ in range(30))
                    + "\n*/\n",
                    encoding="utf-8",
                )
                fake_mod.write_text("// pub mod key_role_separation;\n", encoding="utf-8")
                mod.IMPL = fake_impl
                mod.MOD_RS = fake_mod

                result = mod.run_checks()
        finally:
            mod.IMPL = original_impl
            mod.MOD_RS = original_mod

        by_name = {check["check"]: check for check in result["checks"]}
        self.assertTrue(by_name["file: implementation"]["pass"])
        self.assertFalse(by_name["module registered in mod.rs"]["pass"])

        rust_check_prefixes = (
            "type: ",
            "method: ",
            "error_code: ",
            "event_code: ",
            "invariant: ",
            "role: ",
            "role tag: ",
            "binding field: ",
            "test: ",
        )
        rust_check_names = [
            check["check"]
            for check in result["checks"]
            if check["check"].startswith(rust_check_prefixes)
            or check["check"] == "unit test count"
        ]
        self.assertTrue(rust_check_names)
        self.assertTrue(all(not by_name[name]["pass"] for name in rust_check_names))


class TestCheckModuleRegistered(unittest.TestCase):
    def test_registered(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTestCount(unittest.TestCase):
    def test_meets_minimum(self):
        result = mod.check_test_count(mod.IMPL)
        self.assertTrue(result["pass"], result["detail"])


class TestCheckRoleTags(unittest.TestCase):
    def test_all_tags_found(self):
        results = mod.check_role_tags(mod.IMPL)
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")


class TestCheckBindingFields(unittest.TestCase):
    def test_all_fields_found(self):
        results = mod.check_binding_fields(mod.IMPL)
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing_details(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead"], "bd-364")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.10")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing_checks"], 0,
                         self._failing_details(result))

    def test_has_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total_checks"], 60)

    def _failing_details(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.JSONDecoder().decode(json.dumps(result))
        self.assertEqual(parsed["bead"], "bd-364")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead", "title", "section", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


class TestAllTypes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TYPES, "type")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllMethods(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_METHODS, "method")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllErrorCodes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_ERROR_CODES, "error_code")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllEventCodes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_EVENT_CODES, "event_code")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllInvariants(unittest.TestCase):
    def test_found(self):
        results = mod.check_invariants(mod.IMPL)
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllRequiredTests(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TESTS, "test")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestSpecContent(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.SPEC, mod.SPEC_CONTENT, "spec")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestPolicyContent(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.POLICY, mod.POLICY_CONTENT, "policy")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


if __name__ == "__main__":
    unittest.main()
