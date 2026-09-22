"""Contract test for release distribution matrix (bd-tenx3.4).

Verifies that documented platforms, installer asset naming contracts,
and workflow build matrix targets in .github/workflows/dist.yml stay in lockstep.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README_PATH = ROOT / "README.md"
DIST_YML_PATH = ROOT / ".github" / "workflows" / "dist.yml"
INSTALL_SH_PATH = ROOT / "install.sh"
INSTALL_PS1_PATH = ROOT / "install.ps1"


class TestReleaseMatrixContract(unittest.TestCase):
    def test_readme_documents_all_three_platforms(self) -> None:
        self.assertTrue(README_PATH.is_file(), "README.md must exist")
        content = README_PATH.read_text(encoding="utf-8")

        self.assertIn("Linux x86_64", content)
        self.assertIn("macOS Apple\nSilicon (arm64)", content)
        self.assertIn("Windows x86_64", content)
        self.assertIn("install.sh", content)
        self.assertIn("install.ps1", content)

    def test_install_ps1_target_conventions(self) -> None:
        self.assertTrue(INSTALL_PS1_PATH.is_file(), "install.ps1 must exist")
        content = INSTALL_PS1_PATH.read_text(encoding="utf-8")

        self.assertIn('x86_64-pc-windows-msvc', content)
        self.assertIn('franken-node-x86_64-pc-windows-msvc.zip', content)
        self.assertIn('.sha256', content)
        self.assertIn('.sigstore.json', content)

    def test_install_sh_target_conventions(self) -> None:
        self.assertTrue(INSTALL_SH_PATH.is_file(), "install.sh must exist")
        content = INSTALL_SH_PATH.read_text(encoding="utf-8")

        self.assertIn('.tar.xz', content)
        self.assertIn('.sha256', content)
        self.assertIn('.sigstore.json', content)

    def test_dist_workflow_matrix_includes_all_targets(self) -> None:
        self.assertTrue(DIST_YML_PATH.is_file(), "dist.yml must exist")
        content = DIST_YML_PATH.read_text(encoding="utf-8")

        # Must include all 3 targets in matrix
        self.assertIn("x86_64-unknown-linux-gnu", content)
        self.assertIn("aarch64-apple-darwin", content)
        self.assertIn("x86_64-pc-windows-msvc", content)

        # Must include OS runners
        self.assertIn("ubuntu-latest", content)
        self.assertIn("macos-14", content)
        self.assertIn("windows-latest", content)

        # Must produce zip for windows and tar.xz for unix
        self.assertIn("franken-node-$target.zip", content)
        self.assertIn("TARBALL=\"franken-node-${{ matrix.target }}.tar.xz\"", content)

        # Cosign signing loop must sign both tar.xz and zip
        self.assertRegex(
            content,
            r"for f in .*franken-node-\*\.tar\.xz.*franken-node-\*\.zip",
            "Cosign release signing must cover both .tar.xz and .zip archives",
        )

    def test_dist_workflow_smoke_testing(self) -> None:
        content = DIST_YML_PATH.read_text(encoding="utf-8")

        # Smoke testing for Unix and Windows
        self.assertIn("Smoke test binary (Unix)", content)
        self.assertIn("Smoke test binary (Windows)", content)
        self.assertIn("--version", content)
        self.assertIn("--help", content)


if __name__ == "__main__":
    unittest.main()
