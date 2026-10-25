"""Contract test for release distribution matrix (bd-tenx3.4).

Verifies that documented platforms, installer asset naming contracts,
and workflow build matrix targets in .github/workflows/dist.yml stay in lockstep.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
README_PATH = ROOT / "README.md"
DIST_YML_PATH = ROOT / ".github" / "workflows" / "dist.yml"
INSTALL_SH_PATH = ROOT / "install.sh"
INSTALL_PS1_PATH = ROOT / "install.ps1"
SMOKE_PATH = ROOT / "scripts/smoke_installed_release.py"
SPEC = importlib.util.spec_from_file_location("installed_release_smoke", SMOKE_PATH)
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


def workflow_step(name: str) -> str:
    lines = DIST_YML_PATH.read_text(encoding="utf-8").splitlines()
    marker = f"      - name: {name}"
    if lines.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow step: {name}")
    start = lines.index(marker)
    end = next((index for index in range(start + 1, len(lines))
                if lines[index].startswith("      - ")), len(lines))
    return "\n".join(lines[start:end])


class TestReleaseMatrixContract(unittest.TestCase):
    def test_readme_documents_all_three_platforms(self) -> None:
        self.assertTrue(README_PATH.is_file(), "README.md must exist")
        content = README_PATH.read_text(encoding="utf-8")

        self.assertIn("Linux x86_64", content)
        # Accept the current documented platform spelling, while retaining
        # the architecture requirement (not arbitrary mentions of macOS).
        self.assertRegex(content, r"macOS (?:arm64|Apple\s+Silicon \(arm64\))")
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

    def test_every_native_package_is_installed_and_exercised_before_upload(self):
        step = workflow_step("Qualify the installed package on its native host")
        self.assertNotIn("        if:", step)
        self.assertIn("python scripts/smoke_installed_release.py", step)
        self.assertIn('--archive "dist/franken-node-$TARGET.$ARCHIVE_EXTENSION"', step)
        self.assertIn('--expected-binary "target/$TARGET/release/franken-node$suffix"', step)
        self.assertNotIn("--NoVerify", step)
        content = DIST_YML_PATH.read_text(encoding="utf-8")
        self.assertLess(content.index("Create zip archive (Windows)"), content.index(step))
        self.assertLess(content.index(step), content.index("      - name: Upload artifact"))

    def test_smoke_failure_logs_survive_without_uploading_private_state(self):
        step = workflow_step("Retain installed-package acceptance streams, including failures")
        self.assertIn("if: always()", step)
        self.assertIn("franken-release-smoke/*.json", step)
        self.assertIn("franken-release-smoke/*.stdout", step)
        self.assertIn("franken-release-smoke/*.stderr", step)
        self.assertNotIn("franken-release-smoke/**", step)
        self.assertNotIn("franken-release-smoke/\n", step)
        content = DIST_YML_PATH.read_text(encoding="utf-8")
        selected = re.search(r"pattern: '([^']+)'", content).group(1)
        self.assertEqual(set(selected.strip("{}").split(",")), {
            "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc", "release-certification-bundle"})

    def test_release_compiler_matches_repository_toolchain(self):
        expected = re.search(r'channel = "([^"]+)"', (ROOT / "rust-toolchain.toml").read_text()).group(1)
        configured = re.findall(r"^\s+toolchain: (\S+)$", DIST_YML_PATH.read_text(), re.MULTILINE)
        self.assertEqual(configured, [expected, expected])


# This executable deliberately models the CLI protocol, not native JavaScript.
# Its positives prove harness plumbing only; planted violations must be refused.
PROTOCOL_CANDIDATE = r'''
import json, pathlib, sys
mode, *args = sys.argv[1:]
root = pathlib.Path.cwd()
active = root / "active"
if args[0] in ("--version", "--help"):
    print("protocol test double")
elif args[0] == "init":
    secret = "release-protocol-fixture-private-api-key"
    (root / "franken_node.toml").write_text(
        'profile = "balanced"\n[security]\nauthorized_api_keys = ["' + secret + '"]\n')
    if "--json" in args:
        print(json.dumps({"bootstrap_synthesis": {"authorized_api_keys_generated": [secret]}}))
    else:
        print("bootstrap_synthesis: registry_signing_key_generated=true authorized_api_keys_generated=1")
elif args[:2] == ["safe-mode", "enter"]:
    active.write_text("active")
elif args[:2] == ["safe-mode", "exit"]:
    if mode != "no-recovery":
        active.rename(root / "retired")
elif args[0] == "run":
    if args[1] == "write.cjs":
        if mode == "writes-then-denies":
            (root / "forbidden.txt").write_text("unauthorized")
        print("capability denied: fs:write", file=sys.stderr)
        sys.exit(1)
    if active.exists() and mode != "ignores-safe-mode":
        if mode == "runs-then-refuses":
            print("release-native-ok")
        print("run blocked by active safe mode", file=sys.stderr)
        sys.exit(1)
    if args[1] == "main.cjs":
        print("local:41" if mode == "wrong-local" else "local:42")
    else:
        print("wrong" if mode == "wrong-hello" else "release-native-ok")
else:
    sys.exit(2)
'''


class TestInstalledReleaseProbe(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="release-protocol-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.py"
        self.candidate.write_text(PROTOCOL_CANDIDATE, encoding="utf-8")

    def probe(self, name):
        probe = SMOKE.Probe(self.root / name)
        return probe

    def test_protocol_positive_reaches_execution_containment_and_recovery(self):
        probe = self.probe("positive")
        SMOKE.exercise(probe, [sys.executable, str(self.candidate), "normal"])
        self.assertEqual(len(probe.steps), 10)
        self.assertTrue(all(step["passed"] for step in probe.steps))
        self.assertEqual(probe.steps[-1]["name"], "native-after-recovery")
        self.assertFalse((probe.workspace / "forbidden.txt").exists())

    def test_generated_bootstrap_keys_stay_out_of_public_acceptance_streams(self):
        probe = self.probe("private-bootstrap")
        SMOKE.exercise(probe, [sys.executable, str(self.candidate), "normal"])
        secret = b"release-protocol-fixture-private-api-key"
        self.assertIn(secret, (probe.workspace / "franken_node.toml").read_bytes())
        self.assertEqual(len(probe.steps), 10)
        self.assertTrue(all(step["passed"] for step in probe.steps))
        public = [path for path in probe.evidence.iterdir()
                  if path.is_file() and path.suffix in {".json", ".stdout", ".stderr"}]
        self.assertTrue(public)
        for path in public:
            with self.subTest(artifact=path.name):
                self.assertNotIn(secret, path.read_bytes())

    def test_inherited_xdg_config_is_not_visible_to_the_candidate(self):
        operator_config = self.root / "operator-config"
        operator_config.mkdir()
        marker = operator_config / "operator.marker"
        marker.write_bytes(b"private operator configuration")
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(operator_config)}):
            probe = self.probe("isolated-config")
            probe.run(
                "observe-config-root",
                [sys.executable, "-c",
                 "import os,pathlib; p=pathlib.Path(os.environ['XDG_CONFIG_HOME'])/'operator.marker'; "
                 "print('inherited' if p.is_file() else 'isolated')"],
                stdout=b"isolated\n",
            )
        self.assertEqual(marker.read_bytes(), b"private operator configuration")

    def test_planted_wrong_output_effects_and_false_containment_are_refused(self):
        for mode, failed_step in (("wrong-hello", "native-hello"), ("wrong-local", "native-local-import"),
                                  ("ignores-safe-mode", "safe-mode-blocks-native"),
                                  ("runs-then-refuses", "safe-mode-blocks-native"),
                                  ("no-recovery", "native-after-recovery")):
            with self.subTest(mode=mode):
                probe = self.probe(mode)
                with self.assertRaises(SMOKE.SmokeFailure):
                    SMOKE.exercise(probe, [sys.executable, str(self.candidate), mode])
                self.assertEqual(probe.steps[-1]["name"], failed_step)
                self.assertFalse(probe.steps[-1]["passed"])
                self.assertTrue(list(probe.evidence.glob("*.stdout")))

    def test_a_denial_cannot_hide_a_committed_write(self):
        probe = self.probe("writes-then-denies")
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "wrote forbidden.txt"):
            SMOKE.exercise(probe, [sys.executable, str(self.candidate), "writes-then-denies"])
        self.assertTrue((probe.workspace / "forbidden.txt").exists())

    def test_evidence_directory_cannot_be_reused(self):
        self.probe("retained")
        with self.assertRaises(FileExistsError):
            SMOKE.Probe(self.root / "retained")

    def test_missing_executable_retains_typed_failed_step(self):
        probe = self.probe("missing")
        with self.assertRaises(SMOKE.SmokeFailure):
            probe.run("missing", [str(self.root / "absent")])
        detail = json.loads((probe.evidence / "00-missing.json").read_text())
        self.assertIsNone(detail["returncode"])
        self.assertFalse(detail["passed"])
        self.assertIsNotNone(detail["error"])

    def test_signal_is_not_a_policy_refusal(self):
        if os.name == "nt":
            self.skipTest("POSIX signal exit status control")
        probe = self.probe("signal")
        with self.assertRaises(SMOKE.SmokeFailure):
            probe.run("signal", [sys.executable, "-c", "import os,signal; os.kill(os.getpid(),signal.SIGTERM)"],
                      expected_exit=1)
        self.assertLess(probe.steps[-1]["returncode"], 0)

    def test_usage_failure_with_policy_text_is_not_a_refusal(self):
        probe = self.probe("usage")
        with self.assertRaises(SMOKE.SmokeFailure):
            probe.run("usage", [sys.executable, "-c", "import sys; print('run blocked by active safe mode'); sys.exit(2)"],
                      expected_exit=1, diagnostic=b"run blocked by active safe mode")
        self.assertEqual(probe.steps[-1]["returncode"], 2)


if __name__ == "__main__":
    unittest.main()
