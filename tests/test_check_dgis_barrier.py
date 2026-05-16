"""Unit tests for check_dgis_barrier.py verification script."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import check_dgis_barrier as mod  # noqa: E402

SCRIPT = ROOT / "scripts" / "check_dgis_barrier.py"


def run_script(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def run_json_script() -> dict:
    result = run_script("--json")
    try:
        return json.JSONDecoder().decode(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON output: {result.stdout}\n{result.stderr}") from exc


class TestRustCommentStripping(unittest.TestCase):
    def test_preserves_string_literals_while_stripping_comments(self):
        source = "\n".join(
            [
                'pub const URL: &str = "https://example.test//kept"; // SandboxEscalation',
                'pub const BLOCKY: &str = "not /* a comment */"; /* fn override_barrier() {} */',
                'pub const RAW: &str = r#"raw // kept /* kept */"#;',
                "/* outer /* nested */ still comment */ pub struct RealBarrier;",
            ]
        )

        stripped = mod._strip_rust_comments(source)

        self.assertIn('"https://example.test//kept"', stripped)
        self.assertIn('"not /* a comment */"', stripped)
        self.assertIn('r#"raw // kept /* kept */"#', stripped)
        self.assertIn("pub struct RealBarrier;", stripped)
        self.assertNotIn("SandboxEscalation", stripped)
        self.assertNotIn("fn override_barrier()", stripped)
        self.assertNotIn("nested", stripped)


class TestCommentOnlyRustRegression(unittest.TestCase):
    def test_comment_only_rust_markers_fail_closed(self):
        original_paths = (mod.BARRIER_SRC, mod.DGIS_MOD, mod.SECURITY_MOD)
        receipt_fields = [
            "receipt_id",
            "event_code",
            "barrier_id",
            "node_id",
            "barrier_type",
            "action",
            "timestamp",
            "trace_id",
        ]
        rust_markers = (
            mod.REQUIRED_BARRIER_TYPES
            + [f"pub struct {name}" for name in mod.REQUIRED_STRUCTS]
            + [f"pub enum {name}" for name in mod.REQUIRED_STRUCTS]
            + mod.REQUIRED_TEST_PATTERNS
            + [f'"DGIS-BARRIER-{idx:03d}"' for idx in range(1, 12)]
            + [f"pub {field}:" for field in receipt_fields]
            + [
                "pub mod dgis",
                "principal_identity",
                "signature_hex",
                "fn validate(",
                "fn override_barrier(",
                "check_composition_validity",
                "CompositionConflict",
                "fn apply_to(",
                "source_plan_id",
                "export_audit_log_jsonl",
            ]
        )

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                fake_barrier = tmp / "barrier_primitives.rs"
                fake_dgis_mod = tmp / "dgis_mod.rs"
                fake_security_mod = tmp / "security_mod.rs"
                comment_blob = "\n".join(f"// {marker}" for marker in rust_markers)
                fake_barrier.write_text(comment_blob, encoding="utf-8")
                fake_dgis_mod.write_text("// pub mod barrier_primitives;\n", encoding="utf-8")
                fake_security_mod.write_text("// pub mod dgis;\n", encoding="utf-8")

                mod.BARRIER_SRC = fake_barrier
                mod.DGIS_MOD = fake_dgis_mod
                mod.SECURITY_MOD = fake_security_mod
                results = {check.name: check for check in mod.run_all_checks()}
        finally:
            mod.BARRIER_SRC, mod.DGIS_MOD, mod.SECURITY_MOD = original_paths

        self.assertTrue(results["source_exists"].passed)
        for name, check in results.items():
            if name != "source_exists":
                self.assertFalse(check.passed, name)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        result = run_script("--self-test")
        self.assertEqual(result.returncode, 0, f"self_test failed: {result.stdout}\n{result.stderr}")
        self.assertIn("PASS", result.stdout)


class TestJsonOutput(unittest.TestCase):
    def test_json_output_is_valid(self):
        data = run_json_script()
        self.assertIn("gate", data)
        self.assertEqual(data["gate"], "dgis_barrier_primitives")
        self.assertEqual(data["bead"], "bd-1tnu")
        self.assertEqual(data["section"], "10.20")
        self.assertIn("verdict", data)
        self.assertIn("checks", data)
        self.assertIsInstance(data["checks"], list)
        self.assertGreaterEqual(len(data["checks"]), 10)

    def test_json_checks_have_required_fields(self):
        data = run_json_script()
        for check in data["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("message", check)
            self.assertIsInstance(check["passed"], bool)


class TestSourceChecks(unittest.TestCase):
    def _check(self, name: str) -> dict:
        data = run_json_script()
        return next(c for c in data["checks"] if c["name"] == name)

    def test_source_exists_check(self):
        self.assertTrue(self._check("source_exists")["passed"])

    def test_module_wiring_check(self):
        self.assertTrue(self._check("module_wiring")["passed"])

    def test_barrier_types_check(self):
        self.assertTrue(self._check("barrier_types")["passed"])

    def test_event_codes_check(self):
        codes_check = self._check("event_codes")
        self.assertTrue(codes_check["passed"])
        self.assertGreaterEqual(len(codes_check.get("details", {}).get("codes", [])), 10)

    def test_structs_check(self):
        self.assertTrue(self._check("structs")["passed"])

    def test_test_coverage_check(self):
        self.assertTrue(self._check("test_coverage")["passed"])

    def test_override_mechanism_check(self):
        self.assertTrue(self._check("override_mechanism")["passed"])

    def test_composition_check(self):
        self.assertTrue(self._check("composition")["passed"])


class TestHumanOutput(unittest.TestCase):
    def test_human_output_format(self):
        result = run_script()
        self.assertTrue("[PASS]" in result.stdout or "[FAIL]" in result.stdout)
        self.assertIn("checks passed", result.stdout)


class TestOverallVerdict(unittest.TestCase):
    def test_overall_verdict_pass(self):
        data = run_json_script()
        self.assertEqual(
            data["verdict"],
            "PASS",
            f"Failed checks: {[c for c in data['checks'] if not c['passed']]}",
        )
        self.assertEqual(data["passed"], data["total"])


if __name__ == "__main__":
    unittest.main()
