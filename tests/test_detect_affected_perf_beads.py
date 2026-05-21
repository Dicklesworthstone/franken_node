"""Unit tests for scripts/detect_affected_perf_beads.py (bd-98xo5.15.2).

Tests the mapping-table logic directly (without running git diff) so
they remain hermetic. Each case constructs a temporary repo root,
plants the necessary tests/perf_beads/*.sh files, and asserts that
detect() returns the expected scripts for a given changed-files list.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts/detect_affected_perf_beads.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("detect_affected_perf_beads", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["detect_affected_perf_beads"] = module
    spec.loader.exec_module(module)
    return module


class TestDetectAffectedPerfBeads(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def _plant_scripts(self, root: Path, scripts: list[str]) -> None:
        for rel in scripts:
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("#!/usr/bin/env bash\necho test\n")

    def test_no_changed_files_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._plant_scripts(root, ["tests/perf_beads/bd-98xo5.1.sh"])
            self.assertEqual(self.mod.detect([], root), [])

    def test_unrelated_change_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._plant_scripts(root, ["tests/perf_beads/bd-98xo5.1.sh"])
            self.assertEqual(self.mod.detect(["README.md", "docs/index.md"], root), [])

    def test_threshold_sig_change_maps_to_bd1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._plant_scripts(root, ["tests/perf_beads/bd-98xo5.1.sh"])
            scripts = self.mod.detect(
                ["crates/franken-node/src/security/threshold_sig.rs"], root
            )
            self.assertEqual(scripts, ["tests/perf_beads/bd-98xo5.1.sh"])

    def test_crypto_schemes_change_maps_to_bd1_and_bd2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._plant_scripts(
                root,
                [
                    "tests/perf_beads/bd-98xo5.1.sh",
                    "tests/perf_beads/bd-98xo5.2.sh",
                ],
            )
            scripts = self.mod.detect(["crates/franken-node/src/crypto/schemes.rs"], root)
            self.assertEqual(
                scripts,
                ["tests/perf_beads/bd-98xo5.1.sh", "tests/perf_beads/bd-98xo5.2.sh"],
            )

    def test_missing_script_file_is_silently_skipped(self) -> None:
        # bd-98xo5.4.sh is forward-declared in AFFECTED_MAP but not yet
        # authored; touching trust_card.rs must not break CI by referring
        # to a non-existent script.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Plant nothing.
            scripts = self.mod.detect(
                ["crates/franken-node/src/supply_chain/trust_card.rs"], root
            )
            self.assertEqual(scripts, [])

    def test_harness_self_check_runs_when_harness_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._plant_scripts(root, ["tests/perf_beads/_self_check.sh"])
            scripts = self.mod.detect(["scripts/render_perf_test_summary.py"], root)
            self.assertEqual(scripts, ["tests/perf_beads/_self_check.sh"])

    def test_declaration_order_is_preserved(self) -> None:
        # Multiple matches must return in AFFECTED_MAP declaration order
        # so the workflow matrix is reproducible.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._plant_scripts(
                root,
                [
                    "tests/perf_beads/bd-98xo5.1.sh",
                    "tests/perf_beads/bd-98xo5.2.sh",
                    "tests/perf_beads/_self_check.sh",
                ],
            )
            scripts = self.mod.detect(
                [
                    "scripts/render_perf_test_summary.py",
                    "crates/franken-node/src/crypto/schemes.rs",
                ],
                root,
            )
            # bd-98xo5.1 row appears before bd-98xo5.2 row before
            # _self_check.sh row in AFFECTED_MAP — the result must reflect
            # that ordering regardless of changed-files input order.
            self.assertEqual(
                scripts,
                [
                    "tests/perf_beads/bd-98xo5.1.sh",
                    "tests/perf_beads/bd-98xo5.2.sh",
                    "tests/perf_beads/_self_check.sh",
                ],
            )


if __name__ == "__main__":
    unittest.main()
