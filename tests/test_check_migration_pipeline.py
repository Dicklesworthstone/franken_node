"""Unit tests for scripts/check_migration_pipeline.py (bd-3j4)."""

import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_migration_pipeline.py"


class ScriptNamespace:
    def __init__(self, script_globals):
        object.__setattr__(self, "_script_globals", script_globals["run_all"].__globals__)

    def __getattr__(self, name):
        return self._script_globals[name]

    def __setattr__(self, name, value):
        self._script_globals[name] = value


mod = ScriptNamespace(runpy.run_path(str(SCRIPT_PATH)))


class TestVerdict(unittest.TestCase):
    """Test that the overall verdict is PASS."""

    def test_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestBeadId(unittest.TestCase):
    """Test that bead_id is correct."""

    def test_bead_id_correct(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-3j4")


class TestNoFailures(unittest.TestCase):
    """Test that there are no failing checks."""

    def test_no_failures(self):
        result = mod.run_all()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestEvents(unittest.TestCase):
    """Test that events are present."""

    def test_events_present(self):
        result = mod.run_all()
        self.assertIn("events", result)
        self.assertIsInstance(result["events"], list)
        self.assertGreater(len(result["events"]), 0)


class TestAllChecksPass(unittest.TestCase):
    """Test that every individual check passes."""

    def test_all_checks_pass(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertTrue(c["passed"], f"Check failed: {c['check']}: {c['detail']}")


class TestCommentOnlyRustRegression(unittest.TestCase):
    """Commented Rust markers must not satisfy implementation checks."""

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            impl_file = tmp_path / "migration_pipeline.rs"
            mod_file = tmp_path / "mod.rs"

            markers = (
                mod.REQUIRED_STAGE_TYPES
                + mod.REQUIRED_PIPELINE_OPS
                + mod.REQUIRED_EVENT_CODES
                + mod.REQUIRED_ERROR_CODES
                + mod.REQUIRED_INVARIANTS
                + ["pub struct " + name for name in mod.REQUIRED_STRUCTS]
                + [
                    "pub enum PipelineStage",
                    "pub enum TransformAction",
                    "pipe-v1.0",
                    "BTreeMap",
                    "Serialize",
                    "Deserialize",
                    "test_deterministic",
                    "test_idempotency",
                    "test_rollback",
                    "test_verification_threshold",
                    "test_receipt_signed",
                ]
            )

            impl_file.write_text(
                "\n".join(f"// {marker}" for marker in markers)
                + "\n/*\n"
                + "\n".join("#[test]" for _ in range(25))
                + "\n*/\n",
                encoding="utf-8",
            )
            mod_file.write_text("// pub mod migration_pipeline;\n", encoding="utf-8")

            original_impl = mod.IMPL_FILE
            original_mod = mod.MOD_FILE
            mod.IMPL_FILE = impl_file
            mod.MOD_FILE = mod_file
            try:
                checks = mod._checks()
            finally:
                mod.IMPL_FILE = original_impl
                mod.MOD_FILE = original_mod

        by_name = {check["check"]: check for check in checks}
        self.assertTrue(by_name["Rust module exists"]["passed"])
        self.assertFalse(by_name["Wired into connector/mod.rs"]["passed"])

        rust_marker_prefixes = (
            "Stage type ",
            "Pipeline operation ",
            "Event code ",
            "Error code ",
            "Invariant ",
            "Struct/enum ",
        )
        rust_marker_names = [
            check["check"]
            for check in checks
            if check["check"].startswith(rust_marker_prefixes)
            or check["check"]
            in {
                "PipelineStage enum defined",
                "TransformAction enum defined",
                "Schema version pipe-v1.0",
                "BTreeMap usage for determinism",
                "Serialize/Deserialize derives",
                "Deterministic pipeline test",
                "Idempotency test",
                "Rollback test",
                "95% threshold test",
                "Receipt signing test",
            }
            or check["check"].startswith("Rust unit tests")
        ]
        self.assertTrue(rust_marker_names)
        self.assertTrue(all(not by_name[name]["passed"] for name in rust_marker_names))


class TestMinimumCheckCount(unittest.TestCase):
    """Test that there is a minimum number of checks."""

    def test_minimum_checks(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 20)


class TestCheckStructure(unittest.TestCase):
    """Test that each check has the required structure."""

    def test_check_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)
            self.assertIsInstance(c["check"], str)
            self.assertIsInstance(c["passed"], bool)
            self.assertIsInstance(c["detail"], str)


class TestJsonCliOutput(unittest.TestCase):
    """Test that --json CLI output is valid JSON."""

    def test_json_output(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-3j4")
        self.assertIn("verdict", parsed)
        self.assertIn("checks", parsed)


class TestSelfTestCliExit(unittest.TestCase):
    """Test that --self-test exits 0."""

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"self-test failed:\n{proc.stdout}\n{proc.stderr}")


class TestMissingEvidenceCausesFail(unittest.TestCase):
    """Test that missing evidence file would cause FAIL verdict."""

    def test_missing_evidence_fails(self):
        # Temporarily point to non-existent evidence
        original = mod.EVIDENCE_FILE
        mod.EVIDENCE_FILE = ROOT / "artifacts" / "section_10_12" / "bd-3j4" / "nonexistent.json"
        try:
            result = mod.run_all()
            # At least the evidence check should fail
            evidence_checks = [c for c in result["checks"] if "evidence" in c["check"].lower() or "Evidence" in c["check"]]
            self.assertTrue(
                any(not c["passed"] for c in evidence_checks),
                "Missing evidence should cause at least one check failure",
            )
        finally:
            mod.EVIDENCE_FILE = original


class TestResultFields(unittest.TestCase):
    """Test that run_all returns all required fields."""

    def test_required_fields(self):
        result = mod.run_all()
        for key in [
            "bead_id",
            "title",
            "section",
            "verdict",
            "total",
            "passed",
            "failed",
            "checks",
            "events",
            "summary",
            "timestamp",
        ]:
            self.assertIn(key, result, f"Missing field: {key}")


class TestSelfTestFunction(unittest.TestCase):
    """Test self_test function directly."""

    def test_self_test_passes(self):
        result = mod.self_test()
        self.assertEqual(
            result["verdict"],
            "PASS",
            f"self_test failed: {[c for c in result['checks'] if not c['passed']]}",
        )


if __name__ == "__main__":
    unittest.main()
