"""Real tar/filesystem/installer tests; fixture executables are not Franken builds.

No external network, Rust toolchain, or native-engine compatibility claims. Downloader,
copy and rename failures are injected at their shell boundaries; archive parsing,
checksum computation, candidate execution and file replacement remain real.
"""
from __future__ import annotations

import functools
import hashlib
import http.server
import io
import os
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SCRIPT = ROOT / "install.sh"
OLD = b"#!/bin/sh\n# KEEP_PREVIOUS_INSTALL\necho 'franken-node 0.1.0'\n"
GOOD = b"#!/bin/sh\ncase \"$1\" in --version) echo 'franken-node 0.2.0';; *) exit 1;; esac\n"


class ReleaseInstallation(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="franken-installer-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.tmp = self.root / "tmp"
        self.dest = self.root / "install with spaces"
        for path in (self.home, self.tmp, self.dest):
            path.mkdir()
        self.target = self.dest / "franken-node"
        self.target.write_bytes(OLD)
        self.target.chmod(0o755)
        self.work = self.tmp / "franken-node-install.test"
        self.work.mkdir()
        self.source = self.root / "new executable"
        self.source.write_bytes(GOOD)
        self.source.chmod(0o755)

    def run_shell(self, command: str, *, prelude: str = "") -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ, HOME=str(self.home), TMPDIR=str(self.tmp),
                           TEST_ROOT=str(self.root), TEST_DEST=str(self.dest),
                           TEST_SOURCE=str(self.source), TEST_WORK=str(self.work))
        script = f"source {shlex.quote(str(INSTALL_SCRIPT))}; " + (
            'QUIET=1; NO_GUM=1; DEST_DIR="$TEST_DEST"; WORK_DIR="$TEST_WORK"; '
        ) + prelude + "\n" + command
        return subprocess.run([os.environ.get("INSTALL_TEST_BASH", "bash"), "-c", script], env=environment, cwd=ROOT,
                              text=True, capture_output=True, timeout=20, check=False)

    def archive(self, members: list[tuple[str, bytes | str, bytes, int]] | None = None) -> Path:
        path = self.root / "release archive.tar.xz"
        if members is None:
            members = [("franken-node", GOOD, tarfile.REGTYPE, 0o755)]
        with tarfile.open(path, "w:xz") as output:
            for name, data, kind, mode in members:
                entry = tarfile.TarInfo(name)
                entry.type, entry.mode = kind, mode
                if kind == tarfile.REGTYPE:
                    assert isinstance(data, bytes)
                    entry.size = len(data)
                    output.addfile(entry, io.BytesIO(data))
                else:
                    assert isinstance(data, str)
                    entry.linkname = data
                    output.addfile(entry)
        self.sidecar(path)
        return path

    @staticmethod
    def sidecar(path: Path, digest: str | None = None) -> Path:
        sidecar = Path(str(path) + ".sha256")
        digest = digest or hashlib.sha256(path.read_bytes()).hexdigest()
        sidecar.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
        return sidecar

    def assert_preserved(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.target.read_bytes(), OLD)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o755)
        self.assertEqual(list(self.dest.glob(".franken-node.install.*")), [])
        self.assertNotIn("Installed franken-node", result.stdout)

    def test_install_checks_staged_copy_while_previous_install_is_still_usable(self) -> None:
        self.source.write_text(
            '#!/bin/sh\n'
            'grep -q KEEP_PREVIOUS_INSTALL "$TEST_DEST/franken-node" || exit 41\n'
            '[ "$0" != "$TEST_DEST/franken-node" ] || exit 42\n'
            'printf "%s\\n" "$0" > "$TEST_ROOT/probed-path"\n'
            'echo "franken-node 0.2.0"\n', encoding="utf-8")
        # An open reader of the old inode continues to see the old executable.
        with self.target.open("rb") as running_image:
            result = self.run_shell('install_binary "$TEST_SOURCE"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(running_image.read(), OLD)
        self.assertEqual(self.target.read_bytes(), self.source.read_bytes())
        self.assertIn(".franken-node.install.", (self.root / "probed-path").read_text())
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o755)
        self.assertEqual(list(self.dest.glob(".franken-node.install.*")), [])

    def test_wrong_format_binary_preserves_working_install(self) -> None:
        self.source.write_bytes(b"\x7fELF" + b"\0" * 256)
        result = self.run_shell('install_binary "$TEST_SOURCE"')
        self.assert_preserved(result)
        self.assertIn("candidate cannot run", result.stderr)

    def test_nonzero_version_probe_cannot_be_ignored_by_release_fallback(self) -> None:
        self.source.write_text("#!/bin/sh\nexit 72\n", encoding="utf-8")
        result = self.run_shell('if install_binary "$TEST_SOURCE"; then echo FALSE_SUCCESS; fi')
        self.assert_preserved(result)
        self.assertNotIn("FALSE_SUCCESS", result.stdout)

    def test_copy_failure_is_fatal_even_inside_conditional_call(self) -> None:
        result = self.run_shell('if install_binary "$TEST_SOURCE"; then echo FALSE_SUCCESS; fi',
                                prelude='install() { return 73; };')
        self.assert_preserved(result)
        self.assertIn("cannot stage binary", result.stderr)

    def test_rename_failure_keeps_previous_binary_and_cleans_staging(self) -> None:
        result = self.run_shell('if install_binary "$TEST_SOURCE"; then echo FALSE_SUCCESS; fi',
                                prelude='mv() { return 74; };')
        self.assert_preserved(result)
        self.assertIn("cannot publish binary", result.stderr)

    def test_requested_readiness_runs_on_candidate_before_promotion(self) -> None:
        self.source.write_text(
            '#!/bin/sh\n'
            '[ "$1" = --version ] && { echo "franken-node 0.2.0"; exit 0; }\n'
            'printf "%s\\n" "$*" > "$TEST_ROOT/readiness-args"\nexit 1\n', encoding="utf-8")
        result = self.run_shell('ENABLE_PROCESS_SPAWN=1; install_binary "$TEST_SOURCE"')
        self.assert_preserved(result)
        self.assertEqual((self.root / "readiness-args").read_text().strip(),
                         "doctor process-spawn-readiness --json")

    def test_default_install_does_not_probe_process_spawn(self) -> None:
        result = self.run_shell('install_binary "$TEST_SOURCE"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), GOOD)

    def test_signal_cancels_instead_of_cleaning_then_continuing_install(self) -> None:
        for signal, expected in (("TERM", 143), ("INT", 130)):
            with self.subTest(signal=signal):
                result = self.run_shell('if install_binary "$TEST_SOURCE"; then echo FALSE_SUCCESS; fi',
                    prelude=f'install() {{ command install "$@"; kill -{signal} "$$"; }};')
                self.assert_preserved(result)
                self.assertEqual(result.returncode, expected)
                self.assertNotIn("FALSE_SUCCESS", result.stdout)

    def test_destination_symlink_is_not_followed_or_replaced(self) -> None:
        outside = self.root / "outside"
        self.target.rename(outside)
        self.target.symlink_to(outside)
        result = self.run_shell('install_binary "$TEST_SOURCE"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlinked install target", result.stderr)
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(outside.read_bytes(), OLD)
        self.assertEqual(list(self.dest.glob(".franken-node.install.*")), [])

    def test_destination_directory_is_not_treated_as_a_move_destination(self) -> None:
        self.target.rename(self.root / "original")
        self.target.mkdir()
        result = self.run_shell('install_binary "$TEST_SOURCE"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a regular file", result.stderr)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_unique_nested_binary_is_streamed_without_extracting_other_members(self) -> None:
        archive = self.archive([
            ("bundle with spaces/bin/franken-node", GOOD, tarfile.REGTYPE, 0o755),
            ("bundle with spaces/unused.txt", b"not needed", tarfile.REGTYPE, 0o644),
            ("bundle with spaces/link", "../../elsewhere", tarfile.SYMTYPE, 0o777),
        ])
        result = self.run_shell(f'extract_and_install {shlex.quote(str(archive))}; '
                                'test ! -e "$TEST_WORK/bundle with spaces"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), GOOD)

    def test_dot_prefixed_tar_member_is_supported(self) -> None:
        archive = self.archive([("./franken-node", GOOD, tarfile.REGTYPE, 0o755)])
        result = self.run_shell(f'extract_and_install {shlex.quote(str(archive))}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), GOOD)

    def test_multiple_binaries_do_not_select_an_arbitrary_first_match(self) -> None:
        archive = self.archive([
            ("a/franken-node", GOOD, tarfile.REGTYPE, 0o755),
            ("b/franken-node", GOOD, tarfile.REGTYPE, 0o755),
        ])
        result = self.run_shell(f'extract_and_install {shlex.quote(str(archive))}')
        self.assert_preserved(result)
        self.assertIn("exactly one", result.stderr)

    def test_duplicate_member_cannot_concatenate_executable_payloads(self) -> None:
        archive = self.archive([
            ("franken-node", GOOD, tarfile.REGTYPE, 0o755),
            ("franken-node", b"exit 0\n", tarfile.REGTYPE, 0o755),
        ])
        self.assert_preserved(self.run_shell(f'extract_and_install {shlex.quote(str(archive))}'))

    def test_link_entries_cannot_be_used_as_the_binary(self) -> None:
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                self.work.mkdir(exist_ok=True)
                archive = self.archive([("franken-node", "target", kind, 0o755)])
                result = self.run_shell(f'extract_and_install {shlex.quote(str(archive))}')
                self.assert_preserved(result)
                self.assertIn("regular owner-executable", result.stderr)

    def test_nonexecutable_archive_member_is_refused(self) -> None:
        archive = self.archive([("franken-node", GOOD, tarfile.REGTYPE, 0o644)])
        result = self.run_shell(f'extract_and_install {shlex.quote(str(archive))}')
        self.assert_preserved(result)
        self.assertIn("owner-executable", result.stderr)

    def test_parent_and_absolute_archive_members_never_write_outside_staging(self) -> None:
        outside = self.root / "escaped"
        for name in ("../escaped", str(outside), "nested/../../escaped", "bad\\path"):
            with self.subTest(name=name):
                self.work.mkdir(exist_ok=True)
                archive = self.archive([
                    ("franken-node", GOOD, tarfile.REGTYPE, 0o755),
                    (name, b"must not be written", tarfile.REGTYPE, 0o644),
                ])
                result = self.run_shell(f'extract_and_install {shlex.quote(str(archive))}')
                self.assert_preserved(result)
                self.assertFalse(outside.exists())

    def test_empty_and_oversized_extracted_binaries_are_refused(self) -> None:
        for data in (b"", GOOD + b"#padding\n" * 128):
            with self.subTest(size=len(data)):
                self.work.mkdir(exist_ok=True)
                archive = self.archive([("franken-node", data, tarfile.REGTYPE, 0o755)])
                result = self.run_shell(f'MAX_BINARY_BYTES=128; extract_and_install {shlex.quote(str(archive))}')
                self.assert_preserved(result)

    def test_archive_extract_failure_cannot_report_a_success(self) -> None:
        archive = self.archive()
        result = self.run_shell(f'if extract_and_install {shlex.quote(str(archive))}; then echo FALSE_SUCCESS; fi',
            prelude='tar() { if [ "$1" = -xOf ]; then return 75; else command tar "$@"; fi; };')
        self.assert_preserved(result)
        self.assertIn("cannot read bounded", result.stderr)

    def test_offline_requires_checksum_before_running_payload(self) -> None:
        archive = self.archive()
        Path(str(archive) + ".sha256").rename(self.root / "saved-checksum")
        result = self.run_shell(f'OFFLINE_TARBALL={shlex.quote(str(archive))}; install_from_offline')
        self.assert_preserved(result)
        self.assertIn("sidecar not found", result.stderr)

    def test_offline_corrupt_or_malformed_checksum_preserves_install(self) -> None:
        archive = self.archive()
        for digest in ("0" * 64, "not-a-digest"):
            with self.subTest(digest=digest):
                self.work.mkdir(exist_ok=True)
                self.sidecar(archive, digest)
                result = self.run_shell(f'OFFLINE_TARBALL={shlex.quote(str(archive))}; install_from_offline')
                self.assert_preserved(result)
                self.assertIn("SHA-256", result.stderr)

    def test_offline_uppercase_checksum_is_accepted(self) -> None:
        archive = self.archive()
        self.sidecar(archive, hashlib.sha256(archive.read_bytes()).hexdigest().upper())
        result = self.run_shell(f'OFFLINE_TARBALL={shlex.quote(str(archive))}; install_from_offline')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), GOOD)

    def test_no_verify_does_not_bypass_candidate_execution_check(self) -> None:
        archive = self.archive([("franken-node", b"#!/bin/sh\nexit 1\n", tarfile.REGTYPE, 0o755)])
        self.sidecar(archive, "wrong")
        result = self.run_shell(f'NO_CHECKSUM=1; OFFLINE_TARBALL={shlex.quote(str(archive))}; install_from_offline')
        self.assert_preserved(result)
        self.assertIn("candidate cannot run", result.stderr)

    def test_no_verify_does_not_download_or_invoke_signature_verifier(self) -> None:
        result = self.run_shell('NO_CHECKSUM=1; verify_sigstore unused unused', prelude=(
            'download_file() { echo BAD_DOWNLOAD; return 71; }; '
            'cosign() { echo BAD_SIGNATURE_CALL; return 72; };'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("BAD_", result.stdout)

    def test_post_install_verify_failure_returns_error(self) -> None:
        self.target.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        result = self.run_shell('VERIFY=1; self_test')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Self-test could not run", result.stderr)

    def test_full_offline_main_needs_no_curl_and_uses_no_network_or_source_build(self) -> None:
        archive = self.archive()
        prelude = (
            'command_exists() { [ "$1" != curl ] && command -v "$1" >/dev/null 2>&1; }; '
            'download_file() { echo BAD_NETWORK; return 80; }; '
            'install_from_source() { echo BAD_SOURCE_BUILD; return 81; }; '
        )
        result = self.run_shell(f'main --offline {shlex.quote(str(archive))} '
            f'--dest {shlex.quote(str(self.dest))} --quiet --no-gum --verify', prelude=prelude)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("BAD_", result.stdout)
        self.assertEqual(self.target.read_bytes(), GOOD)

    def test_linux_arm_aliases_select_only_the_arm64_gnu_asset(self) -> None:
        for arch in ("aarch64", "arm64", "arm64e"):
            with self.subTest(arch=arch):
                result = self.run_shell('detect_platform; printf "%s|%s\\n" "$TARGET" "$TARGET_FALLBACK"',
                    prelude=f'uname() {{ if [ "$1" = -s ]; then echo Linux; else echo {arch}; fi; }};')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "aarch64-unknown-linux-gnu|")

    def test_arm64_release_path_checks_checksum_and_installs_without_source_fallback(self) -> None:
        archive = self.archive()
        prelude = (
            'uname() { if [ "$1" = -s ]; then echo Linux; else echo aarch64; fi; }; '
            'command_exists() { [ "$1" != cosign ] && command -v "$1" >/dev/null 2>&1; }; '
            'install_from_source() { echo BAD_SOURCE_BUILD; return 81; }; '
            'download_file() { printf "%s\\n" "$1" >> "$TEST_ROOT/urls"; '
            'case "$1" in '
            f'*/franken-node-aarch64-unknown-linux-gnu.tar.xz) cp {shlex.quote(str(archive))} "$2";; '
            f'*/franken-node-aarch64-unknown-linux-gnu.tar.xz.sha256) cp {shlex.quote(str(archive) + ".sha256")} "$2";; '
            '*) return 22;; esac; }; '
        )
        result = self.run_shell(f'main --method release --version v0.2.0 --dest {shlex.quote(str(self.dest))} '
                                '--quiet --no-gum --verify', prelude=prelude)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), GOOD)
        urls = (self.root / "urls").read_text().splitlines()
        self.assertEqual(len(urls), 2)
        self.assertTrue(urls[0].endswith("/v0.2.0/franken-node-aarch64-unknown-linux-gnu.tar.xz"))
        self.assertEqual(urls[1], urls[0] + ".sha256")
        self.assertNotIn("BAD_SOURCE_BUILD", result.stdout)

    def test_missing_arm64_release_fails_without_installing_an_x86_payload(self) -> None:
        result = self.run_shell(f'main --method release --version v0.2.0 --dest {shlex.quote(str(self.dest))} --quiet',
            prelude='uname() { if [ "$1" = -s ]; then echo Linux; else echo arm64; fi; }; '
                    'download_file() { echo "$1" >> "$TEST_ROOT/urls"; return 22; }; '
                    'install_from_source() { echo BAD_SOURCE_BUILD; return 81; };')
        self.assert_preserved(result)
        self.assertNotIn("x86_64", (self.root / "urls").read_text())
        self.assertNotIn("BAD_SOURCE_BUILD", result.stdout)


class PowerShellInstallation(unittest.TestCase):
    """Real PowerShell/ZIP/HTTP/file operations, not native Franken proof.

    A host utility supplies runnable fixture bytes; malformed payloads and
    executable fixtures exercise installer mechanics only.
    """

    def setUp(self):
        self.pwsh = shutil.which(os.environ.get("INSTALL_TEST_POWERSHELL", "pwsh"))
        if not self.pwsh:
            if os.environ.get("REQUIRE_POWERSHELL_INSTALL_TESTS") == "1":
                self.fail("required PowerShell executable is unavailable")
            self.skipTest("PowerShell is not installed")
        self.temporary = tempfile.TemporaryDirectory(prefix="powershell-installer-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dest = self.root / "install with spaces"
        self.dest.mkdir()
        self.target = self.dest / "franken-node.exe"
        self.old = self.runnable_payload() if os.name == "nt" else OLD
        self.target.write_bytes(self.old)
        self.target.chmod(0o755)
        self.downloads = self.root / "downloads"
        self.downloads.mkdir()
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(self.downloads))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def archive(self, payload: bytes, *, names=("franken-node.exe",)) -> Path:
        path = self.downloads / "franken-node-x86_64-pc-windows-msvc.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name in names:
                info = zipfile.ZipInfo(name)
                info.external_attr = (0o100755 << 16)
                archive.writestr(info, payload)
        return path

    def run_installer(self, archive, *options, checksum=None):
        environment = dict(os.environ)
        for name in ("HOME", "USERPROFILE", "LOCALAPPDATA", "TMPDIR", "TMP", "TEMP"):
            directory = self.root / name
            directory.mkdir(exist_ok=True)
            environment[name] = str(directory)
        return subprocess.run([
            self.pwsh, "-NoProfile", "-File", str(ROOT / "install.ps1"),
            "-Dest", str(self.dest), "-Version", "v-test", "-ArtifactUrl",
            f"http://127.0.0.1:{self.server.server_port}/{archive.name}",
            "-Checksum", checksum or hashlib.sha256(archive.read_bytes()).hexdigest(), *options,
        ], cwd=self.root, env=environment, capture_output=True, text=True, timeout=35, check=False)

    def assert_preserved(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.target.read_bytes(), self.old)
        previous = subprocess.run([str(self.target), "--version"], capture_output=True, text=True,
                                  timeout=5, check=False)
        self.assertEqual(previous.returncode, 0, previous.stdout + previous.stderr)
        self.assertNotIn("Installed franken-node", result.stdout)
        self.assertNotIn("Self-test passed", result.stdout)
        self.assertNotIn("Done. franken-node installed", result.stdout)

    def test_broken_candidate_is_checked_before_replacing_the_previous_install(self):
        result = self.run_installer(self.archive(b"not an executable\n"))
        self.assert_preserved(result)

    def test_verify_cannot_print_success_after_an_unlaunchable_candidate(self):
        result = self.run_installer(self.archive(b"not an executable\n"), "-Verify")
        self.assert_preserved(result)

    def runnable_payload(self):
        source = (Path(os.environ["SystemRoot"]) / "System32/curl.exe"
                  if os.name == "nt" else Path("/usr/bin/true"))
        self.assertTrue(source.is_file(), f"required host utility fixture is missing: {source}")
        return source.read_bytes()

    def test_successful_upgrade_preserves_previous_bytes_as_a_backup(self):
        payload = self.runnable_payload()
        result = self.run_installer(self.archive(payload), "-Verify")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.target.read_bytes(), payload)
        backups = list(self.dest.glob(".franken-node.previous.*.exe"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.old)
        self.assertIn("Self-test passed", result.stdout)

    def test_successful_first_install_needs_no_existing_destination(self):
        self.target.rename(self.root / "old-fixture")
        payload = self.runnable_payload()
        result = self.run_installer(self.archive(payload), "-Verify")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.target.read_bytes(), payload)
        self.assertEqual(list(self.dest.glob(".franken-node.previous.*.exe")), [])

    def test_multiple_archive_binaries_cannot_select_an_arbitrary_candidate(self):
        archive = self.archive(self.runnable_payload(), names=("first/franken-node.exe", "second/franken-node.exe"))
        result = self.run_installer(archive)
        self.assert_preserved(result)
        self.assertIn("exactly one", result.stdout + result.stderr)

    def test_skip_checksums_does_not_skip_candidate_validation(self):
        result = self.run_installer(self.archive(b"not an executable\n"), "-NoVerify")
        self.assert_preserved(result)

    def test_nonzero_version_probe_preserves_the_previous_install(self):
        source = (Path(os.environ["SystemRoot"]) / "System32/findstr.exe"
                  if os.name == "nt" else Path("/usr/bin/false"))
        self.assertTrue(source.is_file())
        result = self.run_installer(self.archive(source.read_bytes()), "-Verify")
        self.assert_preserved(result)
        self.assertIn("version probe exited", result.stdout + result.stderr)

    def test_checksum_mismatch_never_reaches_candidate_promotion(self):
        result = self.run_installer(self.archive(self.runnable_payload()), checksum="0" * 64)
        self.assert_preserved(result)
        self.assertIn("Checksum mismatch", result.stdout + result.stderr)

    def test_archive_without_a_binary_preserves_the_previous_install(self):
        result = self.run_installer(self.archive(b"", names=()))
        self.assert_preserved(result)
        self.assertIn("exactly one", result.stdout + result.stderr)

    def run_functions(self, body):
        # Parse the actual shipped helper functions rather than reimplementing
        # promotion. Individual process failures can be planted at that boundary;
        # locks, stage copies, hashes, backups and replacements remain real.
        source = self.root / "candidate.exe"
        source.write_bytes(self.runnable_payload())
        source.chmod(0o755)
        driver = self.root / "driver.ps1"
        driver.write_text(r'''
param([string]$Installer, [string]$Source, [string]$Destination)
$ErrorActionPreference = "Stop"
$BinaryName = "franken-node"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "Installer parse failed" }
foreach ($function in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
  . ([scriptblock]::Create($function.Extent.Text))
}
''' + body, encoding="utf-8")
        return subprocess.run([self.pwsh, "-NoProfile", "-File", str(driver),
                               "-Installer", str(ROOT / "install.ps1"), "-Source", str(source),
                               "-Destination", str(self.dest)], cwd=self.root,
                              capture_output=True, text=True, timeout=20, check=False)

    def test_post_install_process_failure_restores_old_bytes_and_retains_the_failed_candidate(self):
        result = self.run_functions(r'''
$script:checks = 0
function Assert-InstallBinary {
  param([string]$Path)
  $script:checks++
  if ($script:checks -eq 2) { throw "planted post-install failure" }
}
Install-VerifiedBinary -Source $Source -Destination $Destination -PostVerify
''')
        self.assert_preserved(result)
        failed = list(self.dest.glob(".franken-node.failed.*.exe"))
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].read_bytes(), self.runnable_payload())
        self.assertIn("prior installation restored", result.stderr)

    def test_first_install_post_verify_failure_withholds_and_retains_the_candidate(self):
        self.target.rename(self.root / "old-fixture")
        result = self.run_functions(r'''
$script:checks = 0
function Assert-InstallBinary {
  param([string]$Path)
  $script:checks++
  if ($script:checks -eq 2) { throw "planted post-install failure" }
}
Install-VerifiedBinary -Source $Source -Destination $Destination -PostVerify
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.target.exists())
        failed = list(self.dest.glob(".franken-node.failed.*.exe"))
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].read_bytes(), self.runnable_payload())
        self.assertIn("candidate withheld", result.stderr)

    def test_exclusive_installer_lock_refuses_a_competing_writer_without_staging(self):
        result = self.run_functions(r'''
$lockPath = Join-Path $Destination ".franken-node.install.lock"
$held = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate,
  [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try { Install-VerifiedBinary -Source $Source -Destination $Destination }
finally { $held.Dispose() }
''')
        self.assert_preserved(result)
        self.assertEqual(list(self.dest.glob(".franken-node.install.*.exe")), [])
        # A second invocation must reuse the stable lock after the owner exits.
        successful = self.run_functions("Install-VerifiedBinary -Source $Source -Destination $Destination")
        self.assertEqual(successful.returncode, 0, successful.stdout + successful.stderr)

    def test_candidate_mutation_during_validation_is_not_promoted(self):
        result = self.run_functions(r'''
function Assert-InstallBinary {
  param([string]$Path)
  [System.IO.File]::WriteAllText($Path, "planted candidate mutation")
}
Install-VerifiedBinary -Source $Source -Destination $Destination
''')
        self.assert_preserved(result)
        self.assertIn("changed during validation", result.stderr)

    def test_directory_target_cannot_consume_the_candidate_as_a_child(self):
        self.target.rename(self.root / "old-fixture")
        self.target.mkdir()
        result = self.run_functions("Install-VerifiedBinary -Source $Source -Destination $Destination")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.target.is_dir())
        self.assertEqual(list(self.target.iterdir()), [])
        self.assertEqual((self.root / "old-fixture").read_bytes(), self.old)

    def test_source_copy_failure_never_replaces_the_existing_install(self):
        result = self.run_functions('Install-VerifiedBinary -Source "$Source.absent" -Destination $Destination')
        self.assert_preserved(result)
        self.assertEqual(list(self.dest.glob(".franken-node.previous.*.exe")), [])

    def test_locked_windows_destination_fails_promotion_and_preserves_old_bytes(self):
        if os.name != "nt":
            self.skipTest("Windows prohibits replacement of a file held without delete sharing")
        result = self.run_functions(r'''
$held = [System.IO.File]::Open((Join-Path $Destination "franken-node.exe"),
  [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try { Install-VerifiedBinary -Source $Source -Destination $Destination }
finally { $held.Dispose() }
''')
        self.assert_preserved(result)
        staged = list(self.dest.glob(".franken-node.install.*.exe"))
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0].read_bytes(), self.runnable_payload())

    def test_version_probe_timeout_is_bounded_and_does_not_replace_old_install(self):
        if os.name == "nt":
            self.skipTest("POSIX sleeper fixture; native Windows process timeout awaits its own executable fixture")
        result = self.run_functions(r'''
[System.IO.File]::WriteAllText($Source, "#!/bin/sh`nexec sleep 30`n")
Assert-InstallBinary -Path $Source -TimeoutMillis 100
''')
        self.assert_preserved(result)
        self.assertIn("timed out", result.stderr)


if __name__ == "__main__":
    unittest.main()
