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
        self.assertIn("--method MODE", result.stdout)
        self.assertIn("Values: auto|release|source", result.stdout)
        self.assertIn("--enable-process-spawn", result.stdout)

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

    def test_default_install_never_probes_process_spawn_backend(self) -> None:
        with tempfile.TemporaryDirectory(prefix="franken-node-install-test-") as tmp:
            temp = Path(tmp)
            marker = temp / "probed"
            binary = temp / "franken-node"
            binary.write_text(
                f"#!/usr/bin/env bash\ntouch {marker}\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            result = run_bash(
                f"source ./install.sh; DEST_DIR={temp}; ENABLE_PROCESS_SPAWN=0; "
                "verify_process_spawn_backend"
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertFalse(marker.exists(), "default install must not probe Bubblewrap")

    def test_requested_process_spawn_backend_failure_aborts_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="franken-node-install-test-") as tmp:
            temp = Path(tmp)
            binary = temp / "franken-node"
            binary.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
            binary.chmod(0o755)
            result = run_bash(
                f"source ./install.sh; DEST_DIR={temp}; ENABLE_PROCESS_SPAWN=1; "
                "verify_process_spawn_backend"
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("process-spawn support requested", result.stderr)

    def test_requested_process_spawn_backend_success_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="franken-node-install-test-") as tmp:
            temp = Path(tmp)
            args_file = temp / "doctor-args"
            binary = temp / "franken-node"
            binary.write_text(
                f'#!/usr/bin/env bash\nprintf "%s\\n" "$*" > {args_file}\n',
                encoding="utf-8",
            )
            binary.chmod(0o755)
            result = run_bash(
                f"source ./install.sh; DEST_DIR={temp}; ENABLE_PROCESS_SPAWN=1; "
                "verify_process_spawn_backend"
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertEqual(
                args_file.read_text(encoding="utf-8").strip(),
                "doctor process-spawn-readiness --json",
            )

    def test_enable_process_spawn_flag_sets_explicit_opt_in(self) -> None:
        result = run_bash(
            "source ./install.sh; ENABLE_PROCESS_SPAWN=0; "
            "parse_args --enable-process-spawn; printf '%s\\n' \"$ENABLE_PROCESS_SPAWN\""
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip(), "1")


if __name__ == "__main__":
    unittest.main()
