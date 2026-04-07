from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SCRIPT = ROOT / "install.sh"


def run_bash(script: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        ["bash", "-lc", script],
        cwd=ROOT,
        env=merged_env,
        text=True,
        capture_output=True,
        check=False,
    )


class TestInstallScript(unittest.TestCase):
    def test_help_mentions_prefix_and_method(self) -> None:
        result = subprocess.run(
            ["bash", str(INSTALL_SCRIPT), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("--prefix PATH", result.stdout)
        self.assertIn("--method auto|release|source", result.stdout)

    def test_bash_syntax_is_valid(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(INSTALL_SCRIPT)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_platform_normalization_helpers(self) -> None:
        result = run_bash(
            "source ./install.sh; "
            "printf '%s %s %s %s\\n' "
            "\"$(normalize_os Linux)\" "
            "\"$(normalize_os Darwin)\" "
            "\"$(normalize_arch x86_64)\" "
            "\"$(normalize_arch aarch64)\""
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip(), "linux darwin amd64 arm64")

    def test_detect_helpers_honor_test_overrides(self) -> None:
        result = run_bash(
            "source ./install.sh; printf '%s %s\\n' \"$(detect_os)\" \"$(detect_arch)\"",
            env={
                "FRANKEN_NODE_UNAME_S": "Linux",
                "FRANKEN_NODE_UNAME_M": "arm64e",
            },
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip(), "linux arm64")

    def test_release_asset_name_matches_formula_convention(self) -> None:
        result = run_bash(
            "source ./install.sh; release_asset_name v0.1.0 linux amd64"
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "franken-node-v0.1.0-linux_amd64.tar.gz",
        )

    def test_manifest_extractors_find_expected_sha_and_size(self) -> None:
        with tempfile.TemporaryDirectory(prefix="franken-node-install-test-") as tmp:
            manifest = Path(tmp) / "SHA256SUMS"
            manifest.write_text(
                "0123456789abcdef  franken-node-v0.1.0-linux_amd64.tar.gz  1234\n"
                "fedcba9876543210  other-asset.tar.gz  55\n",
                encoding="utf-8",
            )

            result = run_bash(
                f"source ./install.sh; "
                f"printf '%s %s\\n' "
                f"\"$(extract_manifest_sha franken-node-v0.1.0-linux_amd64.tar.gz {manifest})\" "
                f"\"$(extract_manifest_size franken-node-v0.1.0-linux_amd64.tar.gz {manifest})\""
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip(), "0123456789abcdef 1234")

    def test_compute_sha256_matches_python_hashlib(self) -> None:
        with tempfile.TemporaryDirectory(prefix="franken-node-install-test-") as tmp:
            payload_path = Path(tmp) / "payload.txt"
            payload_path.write_text("franken-node\n", encoding="utf-8")
            expected = hashlib.sha256(payload_path.read_bytes()).hexdigest()

            result = run_bash(
                f"source ./install.sh; compute_sha256 {payload_path}"
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip(), expected)


if __name__ == "__main__":
    unittest.main()
