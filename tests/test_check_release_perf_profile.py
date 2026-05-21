"""Unit tests for scripts/check_release_perf_profile.py (bd-98xo5.11.2).

These exercise the gate that asserts [profile.release-perf] stays
canonical in workspace Cargo.toml. The tests are isolated — they
never mutate the real workspace Cargo.toml — by writing a fixture
Cargo.toml into a TemporaryDirectory and pointing the checker at it
via the `--cargo-toml` flag.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_release_perf_profile.py"

CANONICAL_PROFILE = """
[profile.release-perf]
inherits = "release"
opt-level = 3
lto = "thin"
codegen-units = 1
debug = "line-tables-only"
strip = false
"""

MISSING_PROFILE = """
[workspace]
members = []
"""

WRONG_LTO = """
[profile.release-perf]
inherits = "release"
opt-level = 3
lto = "fat"
codegen-units = 1
debug = "line-tables-only"
strip = false
"""

WRONG_STRIP = """
[profile.release-perf]
inherits = "release"
opt-level = 3
lto = "thin"
codegen-units = 1
debug = "line-tables-only"
strip = true
"""


def _run_checker(cargo_toml: Path, ci: bool = True) -> subprocess.CompletedProcess[str]:
    args = [sys.executable, str(SCRIPT), "--cargo-toml", str(cargo_toml)]
    if ci:
        args.append("--ci")
    return subprocess.run(args, capture_output=True, text=True, check=False)


class TestReleasePerfProfileGate(unittest.TestCase):
    def test_canonical_profile_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cargo = Path(tmp) / "Cargo.toml"
            cargo.write_text(CANONICAL_PROFILE)
            result = _run_checker(cargo)
            self.assertEqual(
                result.returncode,
                0,
                f"canonical profile must exit 0; stdout={result.stdout!r} stderr={result.stderr!r}",
            )
            self.assertIn("OK", result.stdout)

    def test_missing_profile_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cargo = Path(tmp) / "Cargo.toml"
            cargo.write_text(MISSING_PROFILE)
            result = _run_checker(cargo)
            self.assertNotEqual(result.returncode, 0, "missing profile must exit non-zero")
            self.assertIn("missing", result.stdout.lower())
            self.assertIn("docs/dev/profiling.md", result.stdout)

    def test_wrong_lto_value_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cargo = Path(tmp) / "Cargo.toml"
            cargo.write_text(WRONG_LTO)
            result = _run_checker(cargo)
            self.assertNotEqual(result.returncode, 0, "wrong lto must exit non-zero")
            self.assertIn("lto", result.stdout)

    def test_wrong_strip_value_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cargo = Path(tmp) / "Cargo.toml"
            cargo.write_text(WRONG_STRIP)
            result = _run_checker(cargo)
            self.assertNotEqual(result.returncode, 0, "strip=true must exit non-zero")
            self.assertIn("strip", result.stdout)

    def test_real_workspace_cargo_toml_passes(self) -> None:
        """Sanity-check that the actual repo state is canonical."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--ci"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"real workspace Cargo.toml must be canonical; stdout={result.stdout!r}",
        )


if __name__ == "__main__":
    unittest.main()
