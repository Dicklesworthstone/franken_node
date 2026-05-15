"""Unit tests for check_control_epoch.py (bd-3hdv)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_control_epoch.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "control_epoch.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-3hdv_contract.md"

sys.path.insert(0, str(ROOT / "scripts"))
import check_control_epoch as cce  # noqa: E402


class TestFileExistence(unittest.TestCase):
    def test_implementation_exists(self):
        self.assertTrue(IMPL.is_file(), f"Missing: {IMPL}")

    def test_spec_exists(self):
        self.assertTrue(SPEC.is_file(), f"Missing: {SPEC}")

    def test_check_script_exists(self):
        self.assertTrue(SCRIPT.is_file(), f"Missing: {SCRIPT}")


class TestTypePresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text(encoding="utf-8")

    def test_control_epoch_struct(self):
        self.assertIn("pub struct ControlEpoch", self.content)

    def test_epoch_transition_struct(self):
        self.assertIn("pub struct EpochTransition", self.content)

    def test_epoch_store_struct(self):
        self.assertIn("pub struct EpochStore", self.content)

    def test_epoch_error_enum(self):
        self.assertIn("pub enum EpochError", self.content)


class TestMethodPresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text(encoding="utf-8")

    def test_epoch_advance(self):
        self.assertIn("fn epoch_advance(", self.content)

    def test_epoch_read(self):
        self.assertIn("fn epoch_read(", self.content)

    def test_epoch_set(self):
        self.assertIn("fn epoch_set(", self.content)

    def test_recover(self):
        self.assertIn("fn recover(", self.content)

    def test_verify(self):
        self.assertIn("fn verify(", self.content)


class TestInvariants(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text(encoding="utf-8")

    def test_monotonic_invariant(self):
        self.assertIn("INV-EPOCH-MONOTONIC", self.content)

    def test_durable_invariant(self):
        self.assertIn("INV-EPOCH-DURABLE", self.content)

    def test_signed_event_invariant(self):
        self.assertIn("INV-EPOCH-SIGNED-EVENT", self.content)

    def test_no_gap_invariant(self):
        self.assertIn("INV-EPOCH-NO-GAP", self.content)


class TestErrorCodes(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text(encoding="utf-8")

    def test_regression_code(self):
        self.assertIn("EPOCH_REGRESSION", self.content)

    def test_overflow_code(self):
        self.assertIn("EPOCH_OVERFLOW", self.content)

    def test_invalid_manifest_code(self):
        self.assertIn("EPOCH_INVALID_MANIFEST", self.content)


class TestRequiredTests(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text(encoding="utf-8")

    def test_monotonicity_tests(self):
        for name in ["thousand_advances_monotonic", "sequential_advances", "single_advance"]:
            self.assertIn(name, self.content, f"Missing test: {name}")

    def test_regression_tests(self):
        for name in ["regression_same_value_rejected", "regression_lower_value_rejected"]:
            self.assertIn(name, self.content, f"Missing test: {name}")

    def test_crash_recovery_tests(self):
        self.assertIn("crash_recovery_preserves_committed", self.content)

    def test_transition_verification_tests(self):
        for name in ["transition_event_verifiable", "transition_event_tamper_detected"]:
            self.assertIn(name, self.content, f"Missing test: {name}")

    def test_overflow_test(self):
        self.assertIn("epoch_at_max_overflows_on_advance", self.content)


class TestSpecContent(unittest.TestCase):
    def setUp(self):
        self.content = SPEC.read_text(encoding="utf-8")

    def test_control_epoch_mentioned(self):
        self.assertIn("ControlEpoch", self.content)

    def test_epoch_store_mentioned(self):
        self.assertIn("EpochStore", self.content)

    def test_monotonic_invariant(self):
        self.assertIn("INV-EPOCH-MONOTONIC", self.content)

    def test_durable_invariant(self):
        self.assertIn("INV-EPOCH-DURABLE", self.content)

    def test_crash_recovery_mentioned(self):
        self.assertIn("crash recovery", self.content)


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test_passes(self):
        result = cce.self_test()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_cli_json_output(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(ROOT),
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.JSONDecoder().decode(completed.stdout)
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["bead"], "bd-3hdv")

    def test_cli_human_readable(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(ROOT),
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("bd-3hdv", completed.stdout)


class TestRunChecks(unittest.TestCase):
    def test_all_checks_pass(self):
        result = cce.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}"
        )

    def test_result_structure(self):
        result = cce.run_checks()
        self.assertIn("bead", result)
        self.assertIn("section", result)
        self.assertEqual(result["section"], "10.14")
        self.assertIn("verdict", result)
        self.assertIn("summary", result)
        self.assertIn("checks", result)


class TestCommentOnlyRustRegression(unittest.TestCase):
    """Commented Rust markers must not satisfy implementation checks."""

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            impl = tmp_path / "control_epoch.rs"
            mod_rs = tmp_path / "mod.rs"

            impl.write_text(
                "\n".join(f"// {marker}" for marker in REQUIRED_RUST_MARKERS)
                + "\n/*\n"
                + "\n".join("#[test]" for _ in range(20))
                + "\n*/\n",
                encoding="utf-8",
            )
            mod_rs.write_text("// pub mod control_epoch;\n", encoding="utf-8")

            with mock.patch.object(cce, "IMPL", impl), mock.patch.object(cce, "MOD_RS", mod_rs):
                result = cce.run_checks()

        by_name = {check["check"]: check for check in result["checks"]}
        self.assertTrue(by_name["file: implementation"]["pass"])

        rust_backed_checks = [
            check["check"]
            for check in result["checks"]
            if check["check"] == "module registered in mod.rs"
            or check["check"].startswith(
                ("type: ", "method: ", "error_code: ", "event_code: ", "invariant: ", "trait: ", "test: ")
            )
            or check["check"] == "unit test count"
        ]
        self.assertTrue(rust_backed_checks)
        passing_markers = [name for name in rust_backed_checks if by_name[name]["pass"]]
        self.assertEqual(passing_markers, [])


REQUIRED_RUST_MARKERS = (
    cce.REQUIRED_TYPES
    + cce.REQUIRED_METHODS
    + cce.REQUIRED_ERROR_CODES
    + cce.REQUIRED_EVENT_CODES
    + cce.REQUIRED_INVARIANTS
    + cce.REQUIRED_TESTS
    + cce.REQUIRED_TRAITS
    + [
        "pub mod control_epoch;",
        "if attempted <= self.current",
        "EpochError::EpochRegression",
        "self.current = new_epoch;",
        "committed: ControlEpoch",
        "current: ControlEpoch::new(committed_epoch)",
        "self.committed = new_epoch;",
        "pub fn committed_epoch(&self) -> ControlEpoch",
        "pub struct EpochTransition",
        "fn compute_mac(",
        "let event_mac =",
        "constant_time::ct_eq(&self.event_mac, &expected)",
        "pub fn next(self) -> Option<Self>",
        "self.0.checked_add(1).map(Self)",
        ".next()",
        "EpochError::EpochOverflow",
    ]
)


if __name__ == "__main__":
    unittest.main()
