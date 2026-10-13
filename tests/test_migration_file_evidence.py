"""Real-process regressions for asserted file evidence in portable replay.

Node/Node exercises the runner and is not evidence of native-engine parity.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import migration_validation_runner as runner


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "real Node and POSIX required")
class FileEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="file-evidence-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "fixtures").mkdir()
        (self.project / "fixtures/expected").write_bytes(b"expected")
        (self.project / ".franken-node").mkdir()
        self.external = self.root / "external-input"
        self.external.write_bytes(b"wrong-one")
        (self.project / "probe.cjs").write_text(
            "const fs = require('fs');\n"
            f"fs.writeFileSync('output', fs.readFileSync({json.dumps(str(self.external))}));\n")
        self.manifest = {
            "schema_version": runner.MIGRATION_TEST_SCHEMA,
            "tests": ["probe.cjs"],
            "expectations": {"probe.cjs": {"files": {"output": "fixtures/expected"}}},
        }
        self.save_manifest()
        self.command = (shutil.which("node"), "{test}", "{arguments}")
        self.bundle_path = self.root / "capture.fnmigration"

    def save_manifest(self):
        (self.project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(self.manifest))

    def capture(self):
        return runner.validate_project(self.project,
            baseline_command=self.command, migration_command=self.command,
            timeout_seconds=3, total_timeout_seconds=30, bundle_path=self.bundle_path)

    def replay(self, report):
        return runner.replay_captured_bundle(self.bundle_path,
            expected_sha256=report["replay_bundle"]["sha256"],
            baseline_command=self.command, migration_command=self.command)

    def evidence(self, report, role="baseline", target="output"):
        return report["validation_results"][0][role]["file_outputs"][target]

    def test_different_wrong_file_is_changed_not_reproduced(self):
        report = self.capture()
        self.assertEqual(report["summary"]["verdict"], "FAIL", report)
        self.external.write_bytes(b"wrong-two")
        result = self.replay(report)
        self.assertEqual(result["replay_outcome"], "CHANGED", result)
        self.assertEqual(result["execution"]["summary"]["verdict"], "FAIL")
        self.assertEqual(report["validation_results"][0]["divergences"],
                         result["execution"]["validation_results"][0]["divergences"])

    def rewrite_bundle(self, report, mutate):
        bundle = runner.read_replay_bundle(self.bundle_path,
            expected_sha256=report["replay_bundle"]["sha256"])
        manifest = copy.deepcopy(bundle.manifest)
        mutate(manifest)
        path = self.root / f"edited-{time.monotonic_ns()}.fnmigration"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(runner.ReplayBundleWriter._member("manifest.json"), json.dumps(manifest))
            for digest, data in bundle.objects.items():
                archive.writestr(runner.ReplayBundleWriter._member(f"objects/{digest}"), data)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_wrong_file_is_fully_measured_and_same_failure_reproduces_after_move(self):
        payload = b"\0\xffprivate-file-content\r\n" * 1000
        self.external.write_bytes(payload)
        report = self.capture()
        expected = {"state": "regular", "bytes_observed": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(), "complete": True}
        for role in ("baseline", "migration"):
            self.assertEqual(self.evidence(report, role), expected)
        self.assertNotIn("private-file-content", json.dumps(report))
        self.project.rename(self.root / "original-project-unavailable")
        replay = self.replay(report)
        self.assertEqual(replay["replay_outcome"], "REPRODUCED", replay)
        self.assertEqual(replay["execution"]["summary"]["verdict"], "FAIL")
        self.assertEqual(hashlib.sha256(self.bundle_path.read_bytes()).hexdigest(),
                         report["replay_bundle"]["sha256"])

    def test_empty_short_and_exact_limit_actual_files_are_completely_hashed(self):
        for payload in (b"", b"x", b"x" * runner.MAX_EXPECTATION_BYTES):
            with self.subTest(size=len(payload)):
                self.bundle_path = self.root / f"capture-{len(payload)}.fnmigration"
                self.external.write_bytes(payload)
                report = self.capture()
                self.assertEqual(report["summary"]["verdict"], "FAIL", report)
                observed = self.evidence(report)
                self.assertEqual(observed["bytes_observed"], len(payload))
                self.assertEqual(observed["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertTrue(observed["complete"])

    def test_correct_file_still_passes_exact_assertion_and_replay(self):
        self.external.write_bytes(b"expected")
        report = self.capture()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertEqual(self.replay(report)["replay_outcome"], "REPRODUCED")

    def test_missing_file_is_an_observed_absence_not_empty_file(self):
        (self.project / "probe.cjs").write_text("// no output file\n")
        report = self.capture()
        self.assertEqual(self.evidence(report), {"state": "missing", "bytes_observed": 0,
                         "sha256": None, "complete": True})
        self.assertEqual(self.replay(report)["replay_outcome"], "REPRODUCED")

    def test_missing_to_wrong_file_changes_even_when_assertion_still_fails(self):
        (self.project / "probe.cjs").write_text(
            "const fs=require('fs');\n"
            f"if (fs.readFileSync({json.dumps(str(self.external))},'utf8') === 'create') "
            "fs.writeFileSync('output','wrong');\n")
        report = self.capture()
        self.external.write_text("create")
        self.assertEqual(self.replay(report)["replay_outcome"], "CHANGED")

    def test_oversized_file_is_not_read_or_certified_as_reproduced(self):
        self.external.write_bytes(b"x" * (runner.MAX_EXPECTATION_BYTES + 1))
        report = self.capture()
        self.assertEqual(report["summary"]["verdict"], "FAIL", report)
        self.assertEqual(self.evidence(report), {"state": "over_limit", "bytes_observed": 0,
                         "sha256": None, "complete": False})
        with mock.patch.object(runner, "run_command") as launch:
            result = self.replay(report)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("incomplete file", result["errors"][0]["message"])

    def test_new_incomplete_output_cannot_earn_reproduction(self):
        report = self.capture()
        self.external.write_bytes(b"x" * (runner.MAX_EXPECTATION_BYTES + 1))
        result = self.replay(report)
        self.assertEqual(result["replay_outcome"], "ERROR", result)
        self.assertIn("execution", result)

    def test_unsafe_output_kinds_are_failures_not_complete_file_observations(self):
        sources = [
            ("require('fs').mkdirSync('output');", "not_regular"),
            ("require('fs').symlinkSync('fixtures/expected','output');", "unavailable"),
            ("require('fs').linkSync('fixtures/expected','output');", "multiple_links"),
        ]
        for index, (source, state) in enumerate(sources):
            with self.subTest(state=state):
                self.bundle_path = self.root / f"unsafe-{index}.fnmigration"
                (self.project / "probe.cjs").write_text(source)
                report = self.capture()
                self.assertEqual(report["summary"]["verdict"], "FAIL", report)
                self.assertEqual(self.evidence(report)["state"], state)
                self.assertFalse(self.evidence(report)["complete"])
                runner.read_replay_bundle(self.bundle_path)
                self.assertEqual(self.replay(report)["replay_outcome"], "ERROR")

    def test_fifo_is_never_read(self):
        workspace = self.root / "fifo-workspace"
        workspace.mkdir()
        os.mkfifo(workspace / "output")
        descriptor = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        observed = {}
        with mock.patch.object(os, "read") as read:
            self.assertFalse(runner._matches_output_file(descriptor, "output", b"expected",
                time.monotonic() + 5, None, observation=observed))
        read.assert_not_called()
        self.assertEqual(observed["state"], "not_regular")

    def test_missing_historical_evidence_is_inspectable_but_not_reproducible(self):
        report = self.capture()
        def remove(manifest):
            for row in manifest["report"]["validation_results"]:
                for role in ("baseline", "migration"):
                    row[role].pop("file_outputs")
        path, digest = self.rewrite_bundle(report, remove)
        self.assertTrue(runner.inspect_replay_bundle(path)["integrity_verified"])
        with mock.patch.object(runner, "run_command") as launch:
            result = runner.replay_captured_bundle(path, expected_sha256=digest,
                baseline_command=self.command, migration_command=self.command)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("recapture", result["errors"][0]["message"])

    def test_forged_measurements_and_inventory_are_rejected_offline(self):
        report = self.capture()
        def output(manifest):
            return manifest["report"]["validation_results"][0]["baseline"]["file_outputs"]
        mutations = [
            lambda m: output(m).update(extra=copy.deepcopy(output(m)["output"])),
            lambda m: output(m).clear(),
            lambda m: output(m)["output"].update(sha256="not-a-digest"),
            lambda m: output(m)["output"].update(bytes_observed=True),
            lambda m: output(m)["output"].update(bytes_observed=runner.MAX_EXPECTATION_BYTES + 2),
            lambda m: output(m)["output"].update(complete=1),
            lambda m: output(m)["output"].update(complete=False),
            lambda m: output(m)["output"].update(state="missing"),
            lambda m: output(m)["output"].update(state="unavailable"),
            lambda m: output(m)["output"].update(unexpected="value"),
            # A recomputed expected-fixture digest must not excuse a recorded mismatch.
            lambda m: output(m)["output"].update(bytes_observed=8,
                sha256=hashlib.sha256(b"expected").hexdigest()),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                path, digest = self.rewrite_bundle(report, mutation)
                with self.assertRaises(ValueError):
                    runner.read_replay_bundle(path, expected_sha256=digest)

    def test_interrupted_file_collection_retains_prior_evidence(self):
        (self.project / "probe.cjs").write_text(
            "const fs=require('fs'); fs.writeFileSync('output','expected'); "
            "fs.writeFileSync('z-output','expected');\n")
        self.manifest["expectations"]["probe.cjs"]["files"]["z-output"] = "fixtures/expected"
        self.save_manifest()
        original = runner._matches_output_file
        def interrupt(workspace, target, *args, **kwargs):
            if target == "z-output":
                raise TimeoutError("injected collection deadline")
            return original(workspace, target, *args, **kwargs)
        with mock.patch.object(runner, "_matches_output_file", side_effect=interrupt):
            report = self.capture()
        self.assertEqual(report["summary"]["verdict"], "ERROR", report)
        self.assertTrue(self.evidence(report)["complete"])
        bundle = runner.read_replay_bundle(self.bundle_path)
        self.assertEqual(bundle.manifest["report"]["validation_results"][0]["baseline"]["file_outputs"],
                         report["validation_results"][0]["baseline"]["file_outputs"])
        self.assertEqual(self.replay(report)["replay_outcome"], "ERROR")

    def test_file_change_during_read_is_incomplete(self):
        path = self.project / "output"
        path.write_bytes(b"original")
        descriptor = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        original_read = os.read
        changed = False
        def read(fd, size):
            nonlocal changed
            chunk = original_read(fd, size)
            if not changed:
                changed = True
                path.write_bytes(b"modified")
            return chunk
        observed = {}
        with mock.patch.object(os, "read", side_effect=read):
            self.assertFalse(runner._matches_output_file(descriptor, "output", b"original",
                time.monotonic() + 5, None, observation=observed))
        self.assertEqual(observed["state"], "changed")
        self.assertFalse(observed["complete"])

    def test_growing_file_cannot_exceed_the_read_bound(self):
        path = self.project / "output"
        path.write_bytes(b"original")
        descriptor = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        original_read = os.read
        grew = False
        def read(fd, size):
            nonlocal grew
            chunk = original_read(fd, size)
            if not grew:
                grew = True
                with path.open("ab") as stream:
                    stream.write(b"x" * (runner.MAX_EXPECTATION_BYTES + 1))
            return chunk
        observed = {}
        with mock.patch.object(os, "read", side_effect=read):
            self.assertFalse(runner._matches_output_file(descriptor, "output", b"original",
                time.monotonic() + 5, None, observation=observed))
        self.assertEqual(observed["state"], "over_limit")
        self.assertEqual(observed["bytes_observed"], runner.MAX_EXPECTATION_BYTES + 1)
        self.assertFalse(observed["complete"])

    def test_deadline_and_cancellation_are_not_file_mismatches(self):
        descriptor = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        for deadline, cancellation, error in [
            (0, None, TimeoutError),
            (time.monotonic() + 5, runner.CancellationState(signum=15), runner.ExecutionCancelled),
        ]:
            with self.assertRaises(error):
                runner._matches_output_file(descriptor, "fixtures/expected", b"expected",
                    deadline, cancellation, observation={})

    def test_read_error_preserves_partial_count_and_never_becomes_observed_absence(self):
        path = self.project / "output"
        path.write_bytes(b"expected")
        descriptor = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        entries, _ = runner.capture_project(self.project, time.monotonic() + 5)
        by_path = {entry.path: entry for entry in entries}
        expectations = runner.OutputExpectations(files=(("output", "fixtures/expected"),))
        original_read = os.read
        for error in (FileNotFoundError("read failed after opening"), OSError("partial read failure")):
            with self.subTest(error=type(error).__name__):
                calls = 0
                def read(fd, size):
                    nonlocal calls
                    calls += 1
                    if calls > 1:
                        raise error
                    return original_read(fd, size)
                capture = {}
                with mock.patch.object(os, "read", side_effect=read):
                    mismatches = runner._check_output_expectations(expectations, by_path,
                        capture, descriptor, time.monotonic() + 5, "baseline")
                actual = capture["file_outputs"]["output"]
                self.assertEqual(actual["state"], "unavailable")
                self.assertFalse(actual["complete"])
                self.assertEqual(actual["bytes_observed"], 8)
                self.assertEqual(actual["sha256"], hashlib.sha256(b"expected").hexdigest())
                self.assertEqual(len(mismatches), 1)

    def test_concurrent_file_observations_survive_worker_collection(self):
        tests = [f"case-{index}.cjs" for index in range(4)]
        self.manifest = {"schema_version": runner.MIGRATION_TEST_SCHEMA,
            "max_concurrent_tests": 4, "tests": tests, "expectations": {}}
        for index, name in enumerate(tests):
            (self.project / name).write_text(f"require('fs').writeFileSync('output','value-{index}');\n")
            self.manifest["expectations"][name] = {"files": {"output": "fixtures/expected"}}
        self.save_manifest()
        report = self.capture()
        self.assertEqual(report["summary"]["failed"], 4, report)
        for index, row in enumerate(report["validation_results"]):
            for role in ("baseline", "migration"):
                self.assertEqual(row[role]["file_outputs"]["output"]["sha256"],
                    hashlib.sha256(f"value-{index}".encode()).hexdigest())
        self.assertEqual(self.replay(report)["replay_outcome"], "REPRODUCED")


if __name__ == "__main__":
    unittest.main()
