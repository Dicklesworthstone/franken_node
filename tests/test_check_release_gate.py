"""Unit tests for scripts/check_release_gate.py (bd-h93z)."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_release_gate",
    ROOT / "scripts" / "check_release_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestReleaseGate(unittest.TestCase):
    def test_repo_artifacts_pass(self) -> None:
        # Ensure fixture exists first.
        mod.write_sample_report()
        report = mod.run_checks()
        self.assertEqual(report["bead_id"], "bd-h93z")
        self.assertEqual(report["verdict"], "PASS")

    def test_tampered_signature_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-h93z-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(base, tamper_signature=True)
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "signature verification" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_missing_artifact_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-h93z-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(base, missing_artifact=True)
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "artifact dpor_results" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_expired_waiver_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-h93z-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(base, expired_waiver=True)
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "waiver validity" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_self_test(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    unittest.main()
