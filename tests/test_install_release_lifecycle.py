"""Real tar/filesystem/installer tests; fixture executables are not Franken builds.

No network, Rust toolchain, or native-engine compatibility claims. Downloader,
copy and rename failures are injected at their shell boundaries; archive parsing,
checksum computation, candidate execution and file replacement remain real.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
