"""Real process evidence for opt-in migration bundles, not native parity."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / "scripts/migration_validation_runner.py"
SPEC = importlib.util.spec_from_file_location("migration_bundle_runner", SOURCE)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class ReplayBundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="migration-bundle-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.before = self.root / "before"
        self.after = self.root / "after"
        self.before.mkdir()
        self.after.mkdir()
        self.bundle = self.root / "failure.fnmigration"
        self.command = [sys.executable, "{test}"]
        for root in (self.before, self.after):
            (root / "case.test.js").write_text("print('same')\n")

    def execute(self, **kwargs):
        return runner.validate_project(self.before, migrated_project=self.after,
            baseline_command=self.command, migration_command=self.command,
            timeout_seconds=5, total_timeout_seconds=30, bundle_path=self.bundle, **kwargs)

    def read(self):
        with zipfile.ZipFile(self.bundle) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            objects = {name: archive.read(f"objects/{name}") for name in manifest["objects"]}
        return manifest, objects

    def test_failure_bundle_keeps_exact_sources_binary_input_and_both_streams(self):
        source = "import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\nsys.stderr.buffer.write(b'\\x00\\xffdiagnostic')\nprint(VALUE)\n"
        for root, value in ((self.before, "reference"), (self.after, "candidate")):
            (root / "case.test.js").write_text(f"VALUE={value!r}\n" + source)
            (root / "input.bin").write_bytes(bytes(range(256)))
            config = root / ".franken-node"
            config.mkdir()
            (config / "migration-tests.json").write_text(json.dumps({
                "schema_version": runner.MIGRATION_TEST_SCHEMA, "tests": ["case.test.js"],
                "execution": {"case.test.js": {"stdin": "input.bin"}}}))
        report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "FAIL", report)
        self.assertEqual(report["validation_results"][0]["divergences"],
                         [{"channel": "stdout", "reason": "byte_mismatch"}])
        manifest, objects = self.read()
        self.assertEqual(manifest["schema_version"], runner.REPLAY_BUNDLE_SCHEMA)
        self.assertEqual(manifest["report"]["summary"], report["summary"])
        for observation, value in zip(manifest["observations"], (b"reference", b"candidate")):
            self.assertEqual(objects[observation["stdout"]], bytes(range(256)) + value + b"\n")
            self.assertEqual(objects[observation["stderr"]], b"\x00\xffdiagnostic")
        for role, root in (("baseline", self.before), ("migration", self.after)):
            entry = next(x for x in manifest["snapshots"][role] if x["path"] == "case.test.js")
            self.assertEqual(objects[entry["blob"]], (root / "case.test.js").read_bytes())
        self.assertNotIn("replay_bundle", manifest["report"])
        self.assertNotIn("stdout", report["validation_results"][0]["baseline"])
        self.assertFalse(report["replay_bundle"]["authenticated"])
        self.assertFalse(report["replay_bundle"]["ambient_effects_replayable"])

    def test_deduplication_hashes_and_private_stored_archive(self):
        report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        manifest, objects = self.read()
        # One shared source, one shared output and one shared empty stderr.
        self.assertEqual(len(objects), 3)
        for digest, data in objects.items():
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertEqual(len(data), manifest["objects"][digest])
        self.assertEqual(report["replay_bundle"]["sha256"], hashlib.sha256(self.bundle.read_bytes()).hexdigest())
        self.assertEqual(report["replay_bundle"]["bytes"], self.bundle.stat().st_size)
        self.assertEqual(stat.S_IMODE(self.bundle.stat().st_mode), 0o600)
        with zipfile.ZipFile(self.bundle) as archive:
            self.assertEqual(len(archive.namelist()), 4)
            self.assertTrue(all(member.compress_type == zipfile.ZIP_STORED for member in archive.infolist()))

    def test_files_directories_links_and_executable_modes_are_preserved(self):
        for root in (self.before, self.after):
            (root / "empty-dir").mkdir(mode=0o750)
            (root / "tool").write_text("#!/bin/sh\nexit 0\n")
            (root / "tool").chmod(0o755)
            (root / "tool-link").symlink_to("tool")
        report = self.execute(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        manifest, _ = self.read()
        entries = {entry["path"]: entry for entry in manifest["snapshots"]["baseline"]}
        self.assertEqual(entries["empty-dir"], {"path": "empty-dir", "kind": "directory", "mode": 0o750})
        self.assertEqual(entries["tool"]["mode"], 0o755)
        self.assertEqual(entries["tool-link"]["target"], "tool")
        self.assertEqual(entries["tool-link"]["kind"], "link")

    def test_inherited_secrets_are_hashed_not_exported(self):
        secret = "PRIVATE-AMBIENT-CREDENTIAL-812abc"
        with patch.dict(os.environ, {"APP_PRIVATE_SECRET": secret}):
            expected = runner.environment_digest(runner._test_environment(dict(os.environ), runner.ExecutionSettings()))
            report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        manifest, _ = self.read()
        self.assertEqual(manifest["environment_sha256"], {"case.test.js": expected})
        self.assertNotIn(secret.encode(), self.bundle.read_bytes())

    def test_original_tree_changes_do_not_replace_already_captured_inputs(self):
        real_run = runner.run_command
        calls = 0
        def run_and_change(*args, **kwargs):
            nonlocal calls
            result = real_run(*args, **kwargs)
            calls += 1
            if calls == 1:
                (self.after / "case.test.js").write_text("raise SystemExit(91)\n")
            return result
        with patch.object(runner, "run_command", side_effect=run_and_change):
            report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        manifest, objects = self.read()
        entry = next(x for x in manifest["snapshots"]["migration"] if x["path"] == "case.test.js")
        self.assertEqual(objects[entry["blob"]], b"print('same')\n")
        self.assertEqual((self.after / "case.test.js").read_text(), "raise SystemExit(91)\n")

    def test_completed_leg_survives_later_execution_error(self):
        real_run = runner.run_command
        calls = 0
        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected candidate launch failure")
            return real_run(*args, **kwargs)
        with patch.object(runner, "run_command", side_effect=fail_second):
            report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "ERROR", report)
        manifest, objects = self.read()
        self.assertEqual(len(manifest["observations"]), 1)
        self.assertEqual(objects[manifest["observations"][0]["stdout"]], b"same\n")
        self.assertEqual(manifest["report"]["summary"]["verdict"], "ERROR")

    def test_truncated_output_keeps_only_retained_bytes_and_no_false_pass(self):
        for root in (self.before, self.after):
            (root / "case.test.js").write_text("print('x'*100000)\n")
        report = self.execute(max_output_bytes=64)
        self.assertEqual(report["summary"]["verdict"], "FAIL", report)
        manifest, objects = self.read()
        for observation in manifest["observations"]:
            self.assertEqual(objects[observation["stdout"]], b"x"*64)
            stream = manifest["report"]["validation_results"][0][observation["leg"]]["streams"]["stdout"]
            self.assertFalse(stream["complete"])
            self.assertGreater(stream["bytes_observed"], stream["retained_bytes"])

    def test_existing_destination_is_untouched_and_no_test_runs(self):
        self.bundle.write_bytes(b"existing evidence")
        with patch.object(runner, "run_command", side_effect=AssertionError("must not run")):
            report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(self.bundle.read_bytes(), b"existing evidence")

    def test_destination_inside_either_input_is_rejected_before_execution(self):
        for root in (self.before, self.after):
            self.bundle = root / "result.fnmigration"
            with patch.object(runner, "run_command", side_effect=AssertionError("must not run")):
                report = self.execute()
            self.assertEqual(report["summary"]["verdict"], "ERROR")
            self.assertFalse(self.bundle.exists())

    def test_concurrent_destination_creation_cannot_be_overwritten(self):
        real_link = os.link
        def race(source, destination, *args, **kwargs):
            if Path(destination) == self.bundle:
                self.bundle.write_bytes(b"concurrent evidence")
            return real_link(source, destination, *args, **kwargs)
        with patch.object(runner.os, "link", side_effect=race):
            report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(self.bundle.read_bytes(), b"concurrent evidence")
        self.assertNotIn("replay_bundle", report)

    def test_object_budget_fails_closed_before_execution(self):
        with patch.object(runner, "MAX_REPLAY_OBJECTS", 0), patch.object(
                runner, "run_command", side_effect=AssertionError("must not run")):
            report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertFalse(self.bundle.exists())

    def test_manifest_budget_fails_closed_without_partial_publication(self):
        with patch.object(runner, "MAX_REPLAY_MANIFEST_BYTES", 1):
            report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertFalse(self.bundle.exists())
        self.assertEqual(report["validation_results"][0]["status"], "PASS")
        self.assertNotIn("replay_bundle", report)

    def test_bundle_is_opt_in(self):
        report = runner.validate_project(self.before, baseline_command=self.command,
            migration_command=self.command, timeout_seconds=5, total_timeout_seconds=30)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertNotIn("replay_bundle", report)
        self.assertFalse(self.bundle.exists())

    def test_cli_exports_bundle_and_report_for_a_real_mismatch(self):
        (self.after / "case.test.js").write_text("print('changed')\n")
        destination = self.root / "report.json"
        completed = subprocess.run([sys.executable, str(SOURCE), str(self.before),
            "--migrated-project", str(self.after), "--bundle", str(self.bundle),
            "--out", str(destination), "--baseline-command", json.dumps(self.command),
            "--migration-command", json.dumps(self.command), "--timeout-seconds", "5", "--json"],
            capture_output=True, timeout=25, check=False)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report, json.loads(destination.read_text()))
        self.assertEqual(report["replay_bundle"]["sha256"], hashlib.sha256(self.bundle.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
