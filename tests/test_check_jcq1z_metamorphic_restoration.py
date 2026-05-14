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
        json.dumps(_restoration_bead("open"))
        + "\n",
    )


def _restoration_bead(status: str) -> dict[str, object]:
    return {
        "id": mod.RESTORATION_BEAD,
        "title": f"[follow-up] {mod.RESTORATION_TITLE_FRAGMENT}",
        "status": status,
        "dependencies": [
            {
                "issue_id": mod.RESTORATION_BEAD,
                "depends_on_id": mod.PARENT_BEAD,
                "type": "parent-child",
            }
        ],
    }


def _replacement_bead(spec: dict[str, object], status: str = "open") -> dict[str, object]:
    legacy_files = tuple(str(path) for path in spec["legacy_files"])
    return {
        "id": spec["id"],
        "title": f"[bd-jcq1z split] {spec['title_fragment']}",
        "description": (
            "Replacement split with rch proof required; source-only drafts are "
            f"not cited as passing coverage. Covers: {' '.join(legacy_files)}"
        ),
        "status": status,
        "dependencies": [
            {
                "issue_id": spec["id"],
                "depends_on_id": mod.RESTORATION_BEAD,
                "type": "parent-child",
            }
        ],
    }


def _write_beads(root: Path, beads: list[dict[str, object]]) -> None:
    _write(
        root,
        ".beads/issues.jsonl",
        "".join(json.dumps(bead) + "\n" for bead in beads),
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

    def test_closed_follow_up_with_replacement_split_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _minimal_root(root)
            _write_beads(
                root,
                [_restoration_bead("closed")]
                + [_replacement_bead(spec) for spec in mod.REPLACEMENT_BEADS],
            )

            result = mod.run_checks(root)

        self.assertEqual(result["verdict"], "PASS", result)

    def test_completed_replacement_bead_still_satisfies_parent_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _minimal_root(root)
            replacement_beads = []
            for index, spec in enumerate(mod.REPLACEMENT_BEADS):
                replacement_beads.append(
                    _replacement_bead(spec, status="closed" if index == 0 else "open")
                )
            _write_beads(root, [_restoration_bead("closed")] + replacement_beads)

            result = mod.run_checks(root)

        self.assertEqual(result["verdict"], "PASS", result)

    def test_closed_follow_up_missing_replacement_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _minimal_root(root)
            _write_beads(
                root,
                [_restoration_bead("closed")]
                + [_replacement_bead(spec) for spec in mod.REPLACEMENT_BEADS[:-1]],
            )

            result = mod.run_checks(root)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any(
            check["check_id"] == "replacement bead exists: bd-jcq1z.2.4"
            and not check["pass"]
            for check in result["checks"]
        ))


if __name__ == "__main__":
    unittest.main()
