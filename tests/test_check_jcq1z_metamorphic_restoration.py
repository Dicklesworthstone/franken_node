"""Unit tests for scripts/check_jcq1z_metamorphic_restoration.py."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_jcq1z_metamorphic_restoration as mod  # noqa: E402


def _write(root: Path, rel_path: str, text: str) -> None:
    target = root / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _minimal_root(root: Path) -> None:
    _write(
        root,
        "crates/franken-node/Cargo.toml",
        """[package]
name = "frankenengine-node"
autotests = false
""",
    )
    for rel_path in mod.LEGACY_TEST_FILES:
        _write(
            root,
            rel_path,
            """//! Historical unregistered test draft.
fn historical_source_only_fixture() {}
""",
        )
    _write(root, ".ubsignore", "\n".join(mod.LEGACY_TEST_FILES) + "\n")
    _write(
        root,
        ".beads/issues.jsonl",
        json.dumps(
            {
                "id": mod.RESTORATION_BEAD,
                "title": f"[follow-up] {mod.RESTORATION_TITLE_FRAGMENT}",
                "status": "open",
                "dependencies": [
                    {
                        "issue_id": mod.RESTORATION_BEAD,
                        "depends_on_id": mod.PARENT_BEAD,
                        "type": "parent-child",
                    }
                ],
            }
        )
        + "\n",
    )


class RealRepositoryTests(unittest.TestCase):
    def test_real_repository_guard_passes(self) -> None:
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertEqual(result["restoration_bead_id"], mod.RESTORATION_BEAD)
        self.assertEqual(len(result["legacy_test_files"]), 7)

    def _failures(self, result: dict[str, object]) -> str:
        checks = result["checks"]
        if not isinstance(checks, list):
            return f"checks field is not a list: {checks!r}"
        return "\n".join(
            f"{check['check_id']}: {check['detail']}"
            for check in checks
            if isinstance(check, dict) and not check["pass"]
        )


class FixtureFailureTests(unittest.TestCase):
    def test_cargo_registration_of_legacy_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _minimal_root(root)
            crate_path = mod._crate_test_path(mod.LEGACY_TEST_FILES[0])
            _write(
                root,
                "crates/franken-node/Cargo.toml",
                f"""[package]
name = "frankenengine-node"
autotests = false

[[test]]
name = "bad_legacy_registration"
path = "{crate_path}"
""",
            )

            result = mod.run_checks(root)

        self.assertEqual(result["verdict"], "FAIL")
        failing = [
            check
            for check in result["checks"]
            if not check["pass"] and "not registered in Cargo" in check["check_id"]
        ]
        self.assertEqual(len(failing), 1)

    def test_missing_follow_up_bead_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _minimal_root(root)
            _write(root, ".beads/issues.jsonl", "")

            result = mod.run_checks(root)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any(
            check["check_id"] == "follow-up bead exists" and not check["pass"]
            for check in result["checks"]
        ))

    def test_missing_ubsignore_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _minimal_root(root)
            _write(root, ".ubsignore", "\n".join(mod.LEGACY_TEST_FILES[:-1]) + "\n")

            result = mod.run_checks(root)

        self.assertEqual(result["verdict"], "FAIL")
        failing_ids = {
            check["check_id"]
            for check in result["checks"]
            if not check["pass"]
        }
        self.assertIn(
            f"legacy test excluded from UBS live-code scan: {mod.LEGACY_TEST_FILES[-1]}",
            failing_ids,
        )


if __name__ == "__main__":
    unittest.main()
