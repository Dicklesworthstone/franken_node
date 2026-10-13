"""JSON replay must preserve actual generated files, not just mismatch labels.

Actual Node processes exercise capture/replay/source-fix orchestration. These
are not native-engine compatibility or independent-runtime measurements.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import failure_replay as replay

runner = replay.runner


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "real Node and POSIX required")
class CapsuleFileEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="capsule-file-evidence-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.baseline = self.root / "baseline"
        self.migration = self.root / "migration"
        self.ambient = self.root / "ambient"
        self.ambient.write_bytes(b"wrong-one")
        self.command = (shutil.which("node"), "{test}", "{arguments}")
        self.manifest = {"schema_version": runner.MIGRATION_TEST_SCHEMA,
            "tests": ["probe.cjs"], "expectations": {
                "probe.cjs": {"files": {"output": "fixtures/expected"}}}}
        self.harness = "require('fs').writeFileSync('output',require('./helper.cjs'));\n"
        for project in (self.baseline, self.migration):
            project.mkdir()
            (project / "fixtures").mkdir()
            (project / "fixtures/expected").write_bytes(b"expected")
            (project / ".franken-node").mkdir()
            (project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(self.manifest))
            (project / "probe.cjs").write_text(self.harness)
            (project / "helper.cjs").write_text(
                f"module.exports=require('fs').readFileSync({json.dumps(str(self.ambient))});\n")

    def capture(self):
        return replay.capture_migration(self.baseline, migrated_project=self.migration,
            baseline_command=self.command, migration_command=self.command,
            timeout_seconds=3, total_timeout_seconds=30)

    def run_capsule(self, artifact, **kwargs):
        return replay.replay_migration(artifact, execute=True,
            expected_sha256=artifact["content_sha256"], baseline_command=self.command,
            migration_command=self.command, **kwargs)

    def reference_correct(self):
        (self.baseline / "helper.cjs").write_text("module.exports='expected';\n")

    def candidate(self):
        path = self.root / "repaired"
        shutil.copytree(self.migration, path)
        (path / "helper.cjs").write_text("module.exports='expected';\n")
        return path

    def test_different_wrong_file_is_diverged_in_json_replay(self):
        artifact = self.capture()
        self.ambient.write_bytes(b"wrong-two")
        result = self.run_capsule(artifact)
        self.assertEqual(result["verdict"], "DIVERGED", result)
        self.assertEqual(result["mismatched_tests"], ["probe.cjs"])
        self.assertEqual(result["execution"]["validation_results"][0]["divergences"],
                         artifact["expected"]["cases"][0]["divergences"])

    def test_same_wrong_file_is_measured_and_replays_after_relocation(self):
        artifact = self.capture()
        observed = artifact["expected"]["cases"][0]["baseline"]["file_outputs"]["output"]
        self.assertEqual(observed, {"state": "regular", "bytes_observed": 9,
            "sha256": hashlib.sha256(b"wrong-one").hexdigest(), "complete": True})
        self.baseline.rename(self.root / "old-baseline")
        self.migration.rename(self.root / "old-migration")
        self.assertEqual(self.run_capsule(artifact)["verdict"], "REPRODUCED")
        self.assertNotIn("wrong-one", json.dumps(artifact["expected"]))

    def test_file_only_reference_drift_blocks_source_fix(self):
        self.ambient.write_bytes(b"expected")
        (self.migration / "helper.cjs").write_text("module.exports='incorrect';\n")
        artifact = self.capture()
        self.ambient.write_bytes(b"changed-reference")
        result = self.run_capsule(artifact, verify_fix=True, candidate_project=self.candidate())
        self.assertEqual(result["verdict"], "REFERENCE_DRIFT", result)
        self.assertEqual(result["reference_drift_tests"], ["probe.cjs"])
        self.assertEqual(result["execution"]["validation_results"][0]["baseline"]["streams"],
                         artifact["expected"]["cases"][0]["baseline"]["streams"])

    def test_source_fix_passes_with_unchanged_file_reference(self):
        self.reference_correct()
        artifact = self.capture()
        result = self.run_capsule(artifact, verify_fix=True, candidate_project=self.candidate())
        self.assertEqual(result["verdict"], "FIX_VERIFIED", result)
        self.assertEqual(result["reference_drift_tests"], [])
        self.assertEqual(result["execution"]["validation_results"][0]["baseline"]["file_outputs"],
                         artifact["expected"]["cases"][0]["baseline"]["file_outputs"])
        self.assertNotEqual(result["execution"]["inputs"]["migration_sha256"],
                            artifact["expected"]["inputs"]["migration_sha256"])

    def test_missing_and_empty_files_are_not_equivalent(self):
        for project in (self.baseline, self.migration):
            (project / "probe.cjs").write_text(
                f"if(require('fs').readFileSync({json.dumps(str(self.ambient))},'utf8')==='create') "
                "require('fs').writeFileSync('output','');\n")
        artifact = self.capture()
        self.ambient.write_bytes(b"create")
        self.assertEqual(self.run_capsule(artifact)["verdict"], "DIVERGED")

    def test_historical_file_evidence_is_inspectable_but_not_executable(self):
        artifact = self.capture()
        for leg in replay.LEGS:
            artifact["expected"]["cases"][0][leg].pop("file_outputs", None)
        artifact = replay.seal(artifact)
        self.assertEqual(replay.inspect_capsule(artifact)["verdict"], "INTEGRITY_VALID")
        with mock.patch.object(replay, "runtime_bindings") as lookup:
            with self.assertRaisesRegex(ValueError, "measured file output evidence"):
                self.run_capsule(artifact)
        lookup.assert_not_called()

    def test_fix_cannot_use_historical_unmeasured_reference(self):
        self.reference_correct()
        artifact = self.capture()
        artifact["expected"]["cases"][0]["baseline"].pop("file_outputs", None)
        with mock.patch.object(replay, "runtime_bindings") as lookup:
            with self.assertRaisesRegex(ValueError, "measured file output evidence"):
                self.run_capsule(replay.seal(artifact), verify_fix=True)
        lookup.assert_not_called()

    def test_incomplete_original_is_preserved_but_cannot_certify_reproduction(self):
        self.ambient.write_bytes(b"x" * (runner.MAX_EXPECTATION_BYTES + 1))
        artifact = self.capture()
        self.assertEqual(replay.inspect_capsule(artifact)["verdict"], "INTEGRITY_VALID")
        with mock.patch.object(replay, "execute_snapshots") as execute:
            with self.assertRaisesRegex(ValueError, "incomplete file output"):
                self.run_capsule(artifact)
        execute.assert_not_called()

    def test_new_incomplete_observation_returns_error_with_execution_evidence(self):
        artifact = self.capture()
        self.ambient.write_bytes(b"x" * (runner.MAX_EXPECTATION_BYTES + 1))
        result = self.run_capsule(artifact)
        self.assertEqual(result["verdict"], "ERROR", result)
        self.assertIn("incomplete file output", result["error"])
        self.assertIn("execution", result)

    def test_incomplete_candidate_can_be_repaired_without_relaxing_reference(self):
        self.reference_correct()
        self.ambient.write_bytes(b"x" * (runner.MAX_EXPECTATION_BYTES + 1))
        artifact = self.capture()
        result = self.run_capsule(artifact, verify_fix=True, candidate_project=self.candidate())
        self.assertEqual(result["verdict"], "FIX_VERIFIED", result)
        still_broken = self.run_capsule(artifact, verify_fix=True)
        self.assertEqual(still_broken["verdict"], "FIX_NOT_VERIFIED", still_broken)

    def test_malformed_or_contradictory_file_evidence_is_rejected_offline(self):
        original = self.capture()
        for changes in ({"bytes_observed": True}, {"complete": 1}, {"sha256": "invalid"},
                        {"complete": False}, {"state": "missing"}, {"state": []},
                        {"bytes_observed": runner.MAX_EXPECTATION_BYTES + 2},
                        {"bytes_observed": 8, "sha256": hashlib.sha256(b"expected").hexdigest()}):
            with self.subTest(changes=changes):
                artifact = copy.deepcopy(original)
                value = artifact["expected"]["cases"][0]["baseline"]["file_outputs"]["output"]
                value.update(changes)
                with mock.patch.object(replay, "runtime_bindings") as lookup:
                    with self.assertRaises(ValueError):
                        replay.inspect_capsule(replay.seal(artifact))
                lookup.assert_not_called()

    def test_missing_or_unexpected_file_inventory_is_rejected_offline(self):
        original = self.capture()
        for contents in ({}, {"unselected": {}}):
            artifact = copy.deepcopy(original)
            artifact["expected"]["cases"][0]["baseline"]["file_outputs"] = contents
            with self.assertRaises(ValueError):
                replay.inspect_capsule(replay.seal(artifact))

    def test_cannot_remove_selected_case_from_capsule(self):
        for project in (self.baseline, self.migration):
            manifest = copy.deepcopy(self.manifest)
            manifest["tests"].append("sibling.cjs")
            (project / "sibling.cjs").write_text("console.log('sibling');\n")
            (project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(manifest))
        artifact = self.capture()
        artifact["expected"]["cases"] = artifact["expected"]["cases"][:1]
        with mock.patch.object(replay, "execute_snapshots") as execute:
            with self.assertRaisesRegex(ValueError, "inventory"):
                self.run_capsule(replay.seal(artifact))
        execute.assert_not_called()

    def test_ordinary_no_file_expectations_keep_historical_behavior(self):
        for project in (self.baseline, self.migration):
            manifest = copy.deepcopy(self.manifest)
            manifest.pop("expectations")
            (project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(manifest))
        artifact = self.capture()
        self.assertNotIn("file_outputs", artifact["expected"]["cases"][0]["baseline"])
        self.assertEqual(self.run_capsule(artifact)["verdict"], "REPRODUCED")

    def test_reduction_projection_retains_files_and_rejects_incomplete_measurements(self):
        artifact = self.capture()
        result = self.run_capsule(artifact)
        observed = replay.execution_observation(result["execution"])
        self.assertEqual(observed, artifact["expected"])
        report = copy.deepcopy(result["execution"])
        report["validation_results"][0]["migration"]["file_outputs"]["output"] = {
            "state": "over_limit", "bytes_observed": 0, "sha256": None, "complete": False}
        with self.assertRaisesRegex(ValueError, "incomplete file output"):
            replay.execution_observation(report)
        retained = replay.execution_observation(report, complete_file_roles=())
        self.assertFalse(retained["cases"][0]["migration"]["file_outputs"]["output"]["complete"])

    def test_json_cli_reports_file_drift_and_preserves_capsule(self):
        artifact = self.capture()
        path = self.root / "original.json"
        replay.write_capsule(artifact, path)
        original_bytes = path.read_bytes()
        self.ambient.write_bytes(b"wrong-two")
        result = subprocess.run([sys.executable, replay.__file__, "--replay", str(path),
            "--execute", "--expected-sha256", artifact["content_sha256"],
            "--baseline-command", json.dumps(self.command),
            "--migration-command", json.dumps(self.command), "--json"],
            capture_output=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["verdict"], "DIVERGED")
        self.assertEqual(path.read_bytes(), original_bytes)


if __name__ == "__main__":
    unittest.main()
