"""Source-fix verification with real Node processes and immutable reference data.

Node/Node pairs validate the replay workflow, not native Franken compatibility.
Admission fault injection never substitutes successful execution observations.
"""

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import failure_replay as replay

runner = replay.runner


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "real Node and POSIX required")
class SourceFixTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="migration-source-fix-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.before, self.after, self.fixed = [self.root / name for name in ("before", "after", "fixed")]
        self.command = [shutil.which("node"), "{test}", "{arguments}"]
        self.good = "exports.run = bytes => 'ok:' + bytes.toString('hex') + '\\n';\nexports.stable = 'unchanged';\n"
        self.bad = self.good.replace("'ok:'", "'wrong:'")
        harness = ("const fs = require('node:fs'), assert = require('node:assert');\n"
                   "assert.deepStrictEqual(process.argv.slice(2), ['two words', '']);\n"
                   "assert.strictEqual(process.env.APP_MODE, 'migration');\n"
                   "const result = require('./lib.cjs').run(fs.readFileSync(0));\n"
                   "process.stdout.write(result); fs.writeFileSync('result.bin', result);\n")
        for project, source in ((self.before, self.good), (self.after, self.bad), (self.fixed, self.good)):
            project.mkdir()
            (project / "probe.cjs").write_text(harness)
            (project / "passing.cjs").write_text("console.log(require('./lib.cjs').stable);\n")
            (project / "lib.cjs").write_text(source)
            (project / "fixtures").mkdir()
            (project / "fixtures/request.bin").write_bytes(b"\0\xff")
            (project / "fixtures/golden.bin").write_bytes(b"ok:00ff\n")
            (project / "fixtures/empty.bin").write_bytes(b"")
            (project / "fixtures/passing.bin").write_bytes(b"unchanged\n")
            (project / ".franken-node").mkdir()
            self.manifest(project)

    def manifest(self, project, transform=None):
        value = {"schema_version": runner.MIGRATION_TEST_SCHEMA,
                 "max_concurrent_tests": 2, "tests": ["probe.cjs", "passing.cjs"],
                 "execution": {"probe.cjs": {"arguments": ["two words", ""],
                     "stdin": "fixtures/request.bin", "stdin_mode": "file",
                     "environment": {"APP_MODE": "migration"}}},
                 "expectations": {
                     "probe.cjs": {"stdout": "fixtures/golden.bin", "stderr": "fixtures/empty.bin",
                                   "files": {"result.bin": "fixtures/golden.bin"}},
                     "passing.cjs": {"stdout": "fixtures/passing.bin"}}}
        if transform:
            transform(value)
        (project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(value))

    def capture(self, **options):
        return replay.capture_migration(self.before, migrated_project=self.after,
            baseline_command=self.command, migration_command=self.command,
            timeout_seconds=options.pop("timeout_seconds", 2), total_timeout_seconds=30, **options)

    def verify(self, artifact, **options):
        return replay.replay_migration(artifact, execute=True, verify_fix=True,
            baseline_command=self.command, migration_command=options.pop("migration_command", self.command),
            expected_sha256=artifact["content_sha256"], candidate_project=self.fixed, **options)

    def test_repaired_library_passes_all_captured_cases_with_original_reference(self):
        artifact = self.capture(compare_filesystem=True)
        original = copy.deepcopy(artifact)
        result = self.verify(artifact)
        self.assertEqual(result["verdict"], "FIX_VERIFIED", result)
        self.assertEqual(result["execution"]["summary"]["passed"], 2)
        self.assertEqual(result["execution"]["scheduling"]["max_concurrent_tests"], 2)
        self.assertEqual(result["execution"]["inputs"]["baseline_sha256"], artifact["expected"]["inputs"]["baseline_sha256"])
        self.assertNotEqual(result["execution"]["inputs"]["migration_sha256"], artifact["expected"]["inputs"]["migration_sha256"])
        self.assertEqual(result["source_fix"]["source_changes"]["changed_paths"], 1)
        self.assertEqual(result["reference_drift_tests"], [])
        self.assertEqual(result["recorded_validation_verdict"], "FAIL")
        self.assertEqual(artifact, original)
        for project, source in ((self.before, self.good), (self.after, self.bad), (self.fixed, self.good)):
            self.assertEqual((project / "lib.cjs").read_text(), source)
            self.assertFalse((project / "result.bin").exists())
        probe = next(row for row in result["execution"]["validation_results"] if row["test"] == "probe.cjs")
        self.assertEqual(probe["migration"]["stdin_transport"], "file")

    def test_missing_original_projects_are_not_recaptured(self):
        artifact = self.capture()
        self.before.rename(self.root / "before-unavailable")
        self.after.rename(self.root / "after-unavailable")
        self.assertEqual(self.verify(artifact)["verdict"], "FIX_VERIFIED")

    def test_incorrect_source_and_previously_passing_regression_do_not_verify(self):
        artifact = self.capture()
        for source in (self.bad, self.good.replace("'unchanged'", "'regression'")):
            with self.subTest(source=source):
                (self.fixed / "lib.cjs").write_text(source)
                result = self.verify(artifact)
                self.assertEqual(result["verdict"], "FIX_NOT_VERIFIED", result)
                self.assertEqual(result["reference_drift_tests"], [])

    def test_matching_output_with_nonzero_exit_or_timeout_never_verifies(self):
        artifact = self.capture(timeout_seconds=0.5)
        for source in (self.good + "process.exitCode = 9;\n", self.good + "setInterval(() => {}, 1000);\n"):
            with self.subTest(source=source):
                (self.fixed / "lib.cjs").write_text(source)
                result = self.verify(artifact)
                self.assertEqual(result["verdict"], "FIX_NOT_VERIFIED", result)
                self.assertGreater(result["execution"]["summary"]["failed"], 0)

    def test_candidate_requires_fix_mode_pin_and_execution_consent(self):
        artifact = self.capture()
        for options in ({"verify_fix": False, "execute": True, "expected_sha256": artifact["content_sha256"]},
                        {"verify_fix": True, "execute": True},
                        {"verify_fix": True, "execute": False, "expected_sha256": artifact["content_sha256"]}):
            with self.subTest(options=options), mock.patch.object(runner, "capture_project") as capture:
                with self.assertRaises(ValueError):
                    replay.replay_migration(artifact, candidate_project=self.fixed, **options)
                capture.assert_not_called()

    def test_wrong_pin_and_invalid_original_bindings_fail_before_runtime_lookup(self):
        artifact = self.capture()
        with mock.patch.object(replay, "runtime_bindings") as lookup:
            with self.assertRaisesRegex(ValueError, "pinned"):
                replay.replay_migration(artifact, execute=True, verify_fix=True,
                    candidate_project=self.fixed, expected_sha256="0" * 64)
            for leg in replay.LEGS:
                altered = copy.deepcopy(artifact)
                altered["expected"]["inputs"][f"{leg}_sha256"] = "0" * 64
                with self.subTest(leg=leg), self.assertRaisesRegex(ValueError, "input digest"):
                    self.verify(replay.seal(altered))
            lookup.assert_not_called()

    def test_selected_test_bytes_modes_and_replaced_tests_are_protected(self):
        artifact = self.capture()
        path = self.fixed / "probe.cjs"
        original = path.read_bytes()
        mode = path.stat().st_mode & 0o777
        with mock.patch.object(replay, "runtime_bindings") as lookup:
            path.write_text("console.log('ok:00ff');\n")
            with self.assertRaisesRegex(ValueError, "protected test"):
                self.verify(artifact)
            path.write_bytes(original)
            path.chmod(mode ^ 0o100)
            with self.assertRaisesRegex(ValueError, "protected test"):
                self.verify(artifact)
            path.chmod(mode)
            path.rename(self.fixed / "saved-harness.cjs")
            path.symlink_to("saved-harness.cjs")
            with self.assertRaises(ValueError):
                self.verify(artifact)
            lookup.assert_not_called()

    def test_candidate_cannot_shrink_inventory_or_change_request_contract(self):
        artifact = self.capture()
        changes = [lambda raw: raw.update(tests=["probe.cjs"]),
                   lambda raw: raw.update(max_concurrent_tests=1),
                   lambda raw: raw["execution"]["probe.cjs"].update(arguments=["changed"]),
                   lambda raw: raw["execution"]["probe.cjs"].update(stdin_mode="pipe"),
                   lambda raw: raw["execution"]["probe.cjs"].update(environment={"APP_MODE": "changed"}),
                   lambda raw: raw.update(expectations={})]
        for change in changes:
            with self.subTest(change=changes.index(change)), mock.patch.object(replay, "runtime_bindings") as lookup:
                self.manifest(self.fixed, change)
                with self.assertRaises(ValueError):
                    self.verify(artifact)
                lookup.assert_not_called()

    def test_request_and_golden_bytes_and_permissions_are_not_fixable_source(self):
        artifact = self.capture()
        for name in ("request.bin", "golden.bin", "passing.bin"):
            path = self.fixed / "fixtures" / name
            original = path.read_bytes()
            mode = path.stat().st_mode & 0o777
            with self.subTest(name=name), mock.patch.object(replay, "runtime_bindings") as lookup:
                path.write_bytes(b"changed-private-fixture")
                with self.assertRaises(ValueError) as error:
                    self.verify(artifact)
                self.assertNotIn("changed-private-fixture", str(error.exception))
                path.write_bytes(original)
                path.chmod(mode ^ 0o100)
                with self.assertRaisesRegex(ValueError, "protected test"):
                    self.verify(artifact)
                path.chmod(mode)
                lookup.assert_not_called()

    def test_fabricated_recorded_case_inventory_is_not_accepted(self):
        artifact = self.capture()
        artifact["expected"]["cases"] = [case for case in artifact["expected"]["cases"] if case["test"] == "probe.cjs"]
        with mock.patch.object(replay, "runtime_bindings") as lookup, self.assertRaisesRegex(ValueError, "capsule observation inventory differs from captured tests"):
            self.verify(replay.seal(artifact))
        lookup.assert_not_called()

    def test_missing_candidate_and_unsafe_files_fail_before_runtime_lookup(self):
        artifact = self.capture()
        with mock.patch.object(replay, "runtime_bindings") as lookup:
            os.mkfifo(self.fixed / "fifo")
            with self.assertRaisesRegex(ValueError, "nonregular"):
                self.verify(artifact)
            (self.fixed / "fifo").rename(self.root / "saved-fifo")
            (self.fixed / "escape").symlink_to(self.root / "saved-fifo")
            with self.assertRaises(ValueError):
                self.verify(artifact)
            self.fixed.rename(self.root / "fixed-unavailable")
            with self.assertRaises(FileNotFoundError):
                self.verify(artifact)
            lookup.assert_not_called()

    def test_capsule_combined_byte_bound_applies_to_repaired_tree(self):
        artifact = self.capture()
        snapshots = replay.validate_capsule(artifact)
        old_size = sum(len(entry.data or b"") for entries in snapshots.values() for entry in entries)
        # Each individual blob fits; only the combined snapshot exceeds the
        # lowered allowance. This exercises the expansion limit specifically.
        (self.fixed / "extra.bin").write_bytes(b"x" * 2048)
        with mock.patch.object(replay, "MAX_EXPANDED_BYTES", old_size + 1024), \
             mock.patch.object(replay, "runtime_bindings") as lookup, self.assertRaisesRegex(ValueError, "bytes exceed"):
            self.verify(artifact)
        lookup.assert_not_called()

    def test_candidate_runtime_must_remain_outside_candidate_tree(self):
        artifact = self.capture()
        # A real executable script need not be launched for this admission test.
        path = self.fixed / "runtime"
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o700)
        with mock.patch.object(runner, "run_command") as launch, self.assertRaisesRegex(ValueError, "outside"):
            self.verify(artifact, migration_command=[str(path), "{test}", "{arguments}"])
        launch.assert_not_called()

    def test_changed_reference_binary_binding_cannot_be_waived_by_source_fix(self):
        artifact = self.capture()
        artifact["runtime_bindings"]["baseline"]["executable_sha256"] = "0" * 64
        with mock.patch.object(runner, "run_command") as launch, self.assertRaisesRegex(ValueError, "provenance"):
            self.verify(replay.seal(artifact))
        launch.assert_not_called()

    def test_late_live_source_change_cannot_replace_the_captured_candidate(self):
        artifact = self.capture()
        binding = replay.runtime_bindings
        expected_digest = runner.capture_project(self.fixed, time.monotonic() + 5)[1]
        def mutate_after_capture(*args, **kwargs):
            (self.fixed / "lib.cjs").write_text(self.bad)
            return binding(*args, **kwargs)
        with mock.patch.object(replay, "runtime_bindings", side_effect=mutate_after_capture):
            result = self.verify(artifact)
        self.assertEqual(result["verdict"], "FIX_VERIFIED", result)
        self.assertEqual(result["source_fix"]["candidate_migration_sha256"], expected_digest)
        self.assertEqual((self.fixed / "lib.cjs").read_text(), self.bad)

    def test_reference_drift_defeats_agreement_of_both_current_runtimes(self):
        ambient = self.root / "ambient.txt"
        ambient.write_text("old\n")
        source = f"exports.run = () => require('node:fs').readFileSync({json.dumps(str(ambient))});\nexports.stable = 'unchanged';\n"
        (self.before / "lib.cjs").write_text(source)
        (self.fixed / "lib.cjs").write_text(source)
        for project in (self.before, self.after, self.fixed):
            self.manifest(project, lambda raw: raw.update(expectations={}))
        artifact = self.capture()
        ambient.write_text("new\n")
        result = self.verify(artifact)
        self.assertEqual(result["execution"]["summary"]["verdict"], "PASS", result)
        self.assertEqual(result["verdict"], "REFERENCE_DRIFT", result)
        self.assertEqual(result["reference_drift_tests"], ["probe.cjs"])

    def test_original_passing_capsule_or_failed_reference_oracle_is_not_a_fix_seed(self):
        (self.after / "lib.cjs").write_text(self.good)
        passing = self.capture()
        (self.before / "lib.cjs").write_text(self.bad)
        failed_reference = self.capture()
        for artifact in (passing, failed_reference):
            with self.subTest(verdict=artifact["expected"]["validation_verdict"]), \
                 mock.patch.object(replay, "runtime_bindings") as lookup, self.assertRaisesRegex(ValueError, "successful complete reference"):
                self.verify(artifact)
            lookup.assert_not_called()

    def test_existing_replay_and_runtime_only_fix_paths_remain_available(self):
        artifact = self.capture()
        ordinary = replay.replay_migration(artifact, execute=True,
            baseline_command=self.command, migration_command=self.command)
        self.assertEqual(ordinary["verdict"], "REPRODUCED", ordinary)
        runtime_only = replay.replay_migration(artifact, execute=True, verify_fix=True,
            baseline_command=self.command, migration_command=self.command)
        self.assertEqual(runtime_only["verdict"], "FIX_NOT_VERIFIED", runtime_only)
        self.assertNotIn("source_fix", runtime_only)

    def test_cli_source_fix_writes_private_report_without_modifying_capsule(self):
        artifact = self.capture()
        capsule, report = self.root / "failure.json", self.root / "verified.json"
        replay.write_capsule(artifact, capsule)
        before_hash = hashlib.sha256(capsule.read_bytes()).hexdigest()
        command = [sys.executable, replay.__file__, "--replay", str(capsule), "--execute", "--verify-fix",
                   "--expected-sha256", artifact["content_sha256"], "--candidate-project", str(self.fixed),
                   "--baseline-command", json.dumps(self.command), "--migration-command", json.dumps(self.command),
                   "--out", str(report), "--json"]
        completed = subprocess.run(command, capture_output=True, timeout=30, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual(result["verdict"], "FIX_VERIFIED")
        self.assertEqual(json.loads(report.read_text()), result)
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        self.assertEqual(hashlib.sha256(capsule.read_bytes()).hexdigest(), before_hash)
        self.assertNotIn(self.good, report.read_text())


if __name__ == "__main__":
    unittest.main()
