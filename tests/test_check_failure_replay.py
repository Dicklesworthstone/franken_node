#!/usr/bin/env python3
"""Diagnostic-note and real-process regression coverage for migration replay."""

import base64
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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import failure_replay as replay


class TestCaptureFailure(unittest.TestCase):
    def test_has_replay_id(self):
        a = replay.capture_failure("test", "fixture:x:y:z", {}, {}, {})
        self.assertTrue(a["replay_id"].startswith("REPLAY-"))

    def test_has_context(self):
        a = replay.capture_failure("test", "fixture:x:y:z", {"a": 1}, {"b": 2}, {"c": 3})
        self.assertEqual(a["context"]["input"], {"a": 1})
        self.assertEqual(a["context"]["expected_output"], {"b": 2})
        self.assertEqual(a["context"]["actual_output"], {"c": 3})

    def test_includes_env(self):
        a = replay.capture_failure("test", "fx:x:y:z", {}, {}, {}, env={"KEY": "val"})
        self.assertEqual(a["context"]["environment"]["KEY"], "val")

    def test_unique_ids_and_nonexecutable_notes(self):
        a = replay.capture_failure("test", "fixture", {}, {}, {})
        b = replay.capture_failure("test", "fixture", {}, {}, {})
        self.assertNotEqual(a["replay_id"], b["replay_id"])
        self.assertFalse(a["executable"])
        with self.assertRaisesRegex(ValueError, "not an executable"):
            replay.replay_migration(a, execute=True)


class TestGenerateHints(unittest.TestCase):
    def test_return_value_hint(self):
        self.assertTrue(any("Return value" in h for h in replay.generate_hints({"return_value": "a"}, {"return_value": "b"})))

    def test_error_hint(self):
        self.assertTrue(any("Error" in h for h in replay.generate_hints({"error": None}, {"error": {"code": "ERR"}})))

    def test_no_divergence_hint(self):
        self.assertTrue(any("manual" in h.lower() for h in replay.generate_hints({"return_value": "a"}, {"return_value": "a"})))


class TestSaveAndLoad(unittest.TestCase):
    def test_roundtrip(self):
        artifact = replay.capture_failure("test", "fx:x:y:z", {}, {}, {})
        with tempfile.TemporaryDirectory() as tmpdir:
            path = replay.save_replay(artifact, Path(tmpdir))
            loaded = replay.load_replay(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                replay.save_replay(artifact, Path(tmpdir))
        self.assertEqual(loaded, artifact)


class TestValidateArtifact(unittest.TestCase):
    def test_valid_artifact_no_errors(self):
        a = replay.capture_failure("test", "fx:x:y:z", {}, {}, {})
        self.assertEqual(replay.validate_replay_artifact(a), [])

    def test_missing_fields_errors(self):
        for value in ({}, [], None, {"context": None}):
            with self.subTest(value=value):
                self.assertTrue(replay.validate_replay_artifact(value))

    def test_note_identifier_cannot_escape_output_directory(self):
        note = replay.capture_failure("test", "fixture", {}, {}, {})
        note["replay_id"] = "../../outside"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "identifier"):
                replay.save_replay(note, Path(temporary))
            self.assertEqual(list(Path(temporary).iterdir()), [])


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = replay.self_test()
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("REPLAY-EXECUTION", {check["id"] for check in result["checks"]})


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "requires POSIX and real Node.js")
class TestExecutableReplay(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="replay-tests-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.before, self.after = self.root / "before", self.root / "after"
        self.before.mkdir()
        self.after.mkdir()
        self.command = [shutil.which("node"), "{test}"]
        (self.before / "app.test.js").write_text("console.log('expected');", encoding="utf-8")
        (self.after / "app.test.js").write_text("console.log('actual');", encoding="utf-8")

    def capture(self, **options):
        return replay.capture_migration(self.before, migrated_project=self.after,
                                         baseline_command=self.command, migration_command=self.command,
                                         **options)

    def execute(self, artifact, **options):
        return replay.replay_migration(artifact, execute=True, baseline_command=self.command,
                                       migration_command=self.command, **options)

    def test_real_failure_is_reexecuted_and_reproduced(self):
        artifact = self.capture()
        result = self.execute(artifact)
        self.assertEqual(artifact["expected"]["validation_verdict"], "FAIL")
        self.assertEqual(result["verdict"], "REPRODUCED")
        self.assertEqual(result["observed_validation_verdict"], "FAIL")
        self.assertEqual(result["mismatched_tests"], [])
        self.assertFalse(result["release_certification"])
        self.assertFalse(result["environment_reproduced"])
        self.assertGreater(result["execution"]["validation_results"][0]["baseline"]["streams"]["stdout"]["bytes_observed"], 0)

    def test_replay_never_reads_original_trees_after_capture(self):
        artifact = self.capture()
        (self.before / "app.test.js").write_text("process.exit(17);", encoding="utf-8")
        (self.after / "app.test.js").write_text("process.exit(18);", encoding="utf-8")
        self.assertEqual(self.execute(artifact)["verdict"], "REPRODUCED")

    def test_expected_output_mutation_cannot_self_compare_to_success(self):
        artifact = self.capture()
        artifact["expected"]["cases"][0]["migration"]["streams"]["stdout"]["sha256"] = "0" * 64
        artifact = replay.seal(artifact)
        result = self.execute(artifact)
        self.assertEqual(result["verdict"], "DIVERGED")
        self.assertEqual(result["mismatched_tests"], ["app.test.js"])

    def test_input_mutation_without_resealing_is_rejected(self):
        artifact = self.capture()
        artifact["options"]["compare_filesystem"] = True
        with self.assertRaisesRegex(ValueError, "content hash mismatch"):
            self.execute(artifact)

    def test_pinned_hash_rejects_resealed_capsule(self):
        artifact = self.capture()
        pinned = artifact["content_sha256"]
        artifact["expected"]["validation_verdict"] = "PASS"
        artifact = replay.seal(artifact)
        with self.assertRaisesRegex(ValueError, "independently pinned"):
            self.execute(artifact, expected_sha256=pinned)

    def test_blob_digest_verified_even_if_outer_digest_recomputed(self):
        artifact = self.capture()
        blob = next(iter(artifact["blobs"]))
        artifact["blobs"][blob] = base64.b64encode(b"process.exit(99);").decode()
        with self.assertRaisesRegex(ValueError, "blob hash mismatch"):
            self.execute(replay.seal(artifact))

    def test_unknown_blob_or_unused_blob_is_rejected(self):
        artifact = self.capture()
        altered = copy.deepcopy(artifact)
        altered["snapshots"]["baseline"][0]["blob"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "missing content blob"):
            self.execute(replay.seal(altered))
        data = b"not used by either workspace"
        artifact["blobs"][hashlib.sha256(data).hexdigest()] = base64.b64encode(data).decode()
        with self.assertRaisesRegex(ValueError, "unreferenced"):
            self.execute(replay.seal(artifact))

    def test_paths_are_validated_before_any_execution(self):
        artifact = self.capture()
        for path in ("../escape", "/absolute", "a//b", "a/./b", ".git/config", "a\\b", "a\0b"):
            with self.subTest(path=path):
                altered = copy.deepcopy(artifact)
                altered["snapshots"]["baseline"][0]["path"] = path
                with self.assertRaises(ValueError):
                    self.execute(replay.seal(altered))

    def test_duplicate_paths_and_file_parents_are_rejected(self):
        artifact = self.capture()
        altered = copy.deepcopy(artifact)
        altered["snapshots"]["baseline"].append(copy.deepcopy(altered["snapshots"]["baseline"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate capsule path"):
            self.execute(replay.seal(altered))
        node = copy.deepcopy(artifact["snapshots"]["baseline"][0])
        node["path"] = "app.test.js/child"
        artifact["snapshots"]["baseline"].append(node)
        with self.assertRaisesRegex(ValueError, "parent must"):
            self.execute(replay.seal(artifact))

    def test_external_cycle_and_parent_symlinks_are_rejected(self):
        artifact = self.capture()
        for target in ("/etc/passwd", "../outside", "link", ".git/config", "absent"):
            with self.subTest(target=target):
                altered = copy.deepcopy(artifact)
                altered["snapshots"]["baseline"].append({"path": "link", "kind": "symlink", "mode": 0o777, "target": target})
                with self.assertRaises(ValueError):
                    self.execute(replay.seal(altered))
        artifact["snapshots"]["baseline"].extend([
            {"path": "link", "kind": "symlink", "mode": 0o777, "target": "."},
            {"path": "link/child", "kind": "directory", "mode": 0o755}])
        with self.assertRaisesRegex(ValueError, "parent must"):
            self.execute(replay.seal(artifact))

    def test_missing_input_digest_binding_is_rejected(self):
        artifact = self.capture()
        artifact["expected"]["inputs"]["baseline_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "restored input digest mismatch"):
            self.execute(replay.seal(artifact))

    def test_requires_explicit_execution_approval(self):
        artifact = self.capture()
        with self.assertRaisesRegex(ValueError, "explicit"):
            replay.replay_migration(artifact, baseline_command=self.command, migration_command=self.command)

    def test_embedded_commands_never_execute(self):
        artifact = self.capture()
        marker = self.root / "must-not-exist"
        artifact["recorded_commands"] = {"baseline": ["sh", "-c", f"touch {marker}"], "migration": ["sh", "-c", f"touch {marker}"]}
        result = self.execute(replay.seal(artifact))
        self.assertEqual(result["verdict"], "REPRODUCED")
        self.assertFalse(marker.exists())

    def test_dependencies_binary_files_and_symlinks_survive_portable_roundtrip(self):
        for directory in (self.before, self.after):
            package = directory / "node_modules/fixture"
            package.mkdir(parents=True)
            (package / "index.js").write_text("module.exports='dependency';", encoding="utf-8")
            (directory / "binary").write_bytes(bytes(range(256)))
            (directory / "alias").symlink_to("binary")
            (directory / "app.test.js").write_text("console.log(require('fixture')); console.log(require('fs').readFileSync('alias').toString('hex'));", encoding="utf-8")
        artifact = self.capture(compare_filesystem=True)
        self.assertEqual(artifact["expected"]["validation_verdict"], "PASS")
        path = replay.save_replay(artifact, self.root)
        self.assertEqual(self.execute(replay.load_replay(path))["verdict"], "REPRODUCED")
        self.assertLess(len(artifact["blobs"]), sum(len(v) for v in artifact["snapshots"].values()))

    def test_filesystem_only_failure_is_reproduced(self):
        (self.before / "app.test.js").write_text("require('fs').writeFileSync('result','one');", encoding="utf-8")
        (self.after / "app.test.js").write_text("require('fs').writeFileSync('result','two');", encoding="utf-8")
        artifact = self.capture(compare_filesystem=True)
        expected = artifact["expected"]["cases"][0]
        self.assertEqual(expected["divergences"], [{"channel": "filesystem", "reason": "workspace_delta_mismatch"}])
        result = self.execute(artifact)
        self.assertEqual(result["verdict"], "REPRODUCED")
        self.assertFalse((self.before / "result").exists())

    def test_empty_and_infrastructure_failed_runs_cannot_be_captured_as_replays(self):
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaisesRegex(ValueError, "complete nonempty"):
            replay.capture_migration(empty, baseline_command=self.command, migration_command=self.command)
        with self.assertRaisesRegex(ValueError, "runtime executable not found"):
            replay.capture_migration(self.before, baseline_command=["/absent/node", "{test}"], migration_command=self.command)

    def test_duplicate_json_and_nonfinite_values_rejected(self):
        path = self.root / "invalid.json"
        for text in ('{"schema_version":1,"schema_version":2}', '{"x":NaN}', '{"x":Infinity}'):
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                replay.load_replay(path)

    def test_special_or_symlink_capsule_file_is_refused(self):
        target = self.root / "target.json"
        target.write_text("{}", encoding="utf-8")
        alias = self.root / "alias.json"
        alias.symlink_to(target)
        with self.assertRaises(OSError):
            replay.load_replay(alias)
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular file"):
            replay.load_replay(fifo)

    def test_snapshot_metadata_modes_and_option_validation(self):
        artifact = self.capture()
        for mode in (True, -1, 0o4755, "755"):
            altered = copy.deepcopy(artifact)
            altered["snapshots"]["baseline"][0]["mode"] = mode
            with self.assertRaises(ValueError):
                self.execute(replay.seal(altered))
        for options in ({"timeout_seconds": 0}, {"execute": True}, {"compare_filesystem": "yes"}, {"band": "waived"}):
            with self.assertRaises(ValueError):
                replay.checked_options(options)

    def test_replay_cli_returns_zero_for_reproduced_failure_not_migration_pass(self):
        artifact = self.capture()
        capsule = replay.save_replay(artifact, self.root)
        command = [sys.executable, replay.__file__, "--replay", str(capsule), "--execute", "--json",
                   "--baseline-command", json.dumps(self.command), "--migration-command", json.dumps(self.command),
                   "--expected-sha256", artifact["content_sha256"]]
        result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["verdict"], "REPRODUCED")
        self.assertEqual(report["observed_validation_verdict"], "FAIL")

    def test_capture_cli_reports_failure_and_saves_replayable_capsule(self):
        capsule = self.root / "capture.json"
        command = [sys.executable, replay.__file__, "--capture", str(self.before),
                   "--migrated-project", str(self.after), "--out", str(capsule), "--json",
                   "--baseline-command", json.dumps(self.command), "--migration-command", json.dumps(self.command)]
        result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["verdict"], "CAPTURED")
        self.assertEqual(self.execute(replay.load_replay(capsule))["verdict"], "REPRODUCED")

    def test_cli_refuses_unapproved_replay(self):
        capsule = replay.save_replay(self.capture(), self.root)
        result = subprocess.run([sys.executable, replay.__file__, "--replay", str(capsule), "--json"],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"requires --execute", result.stderr)

    def test_runtime_argv_drift_is_not_ordinary_replay(self):
        artifact = self.capture()
        with self.assertRaisesRegex(ValueError, "runtime provenance mismatch"):
            replay.replay_migration(artifact, execute=True, baseline_command=self.command,
                                    migration_command=[self.command[0], "--no-warnings", "{test}"])

    def test_validator_drift_is_not_ordinary_replay(self):
        artifact = self.capture()
        artifact["runtime_bindings"]["validators"]["runner_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "runtime provenance mismatch"):
            self.execute(replay.seal(artifact))

    def test_changed_executable_bytes_are_rejected_before_launch(self):
        wrapper = self.root / "node-launcher"
        code = f"#!{sys.executable}\nimport os,sys\nos.execv({self.command[0]!r}, [{self.command[0]!r}, *sys.argv[1:]])\n"
        wrapper.write_text(code, encoding="utf-8")
        wrapper.chmod(0o755)
        command = [str(wrapper), "{test}"]
        artifact = replay.capture_migration(self.before, migrated_project=self.after,
                                             baseline_command=command, migration_command=command)
        marker = self.root / "changed-binary-must-not-run"
        wrapper.write_text(f"#!{sys.executable}\nopen({str(marker)!r},'w').write('bad')\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "runtime provenance mismatch"):
            replay.replay_migration(artifact, execute=True, baseline_command=command, migration_command=command)
        self.assertFalse(marker.exists())

    def test_byte_identical_executable_can_relocate(self):
        code = f"#!{sys.executable}\nimport os,sys\nos.execv({self.command[0]!r}, [{self.command[0]!r}, *sys.argv[1:]])\n"
        first, second = self.root / "first-launcher", self.root / "relocated-launcher"
        for path in (first, second):
            path.write_text(code, encoding="utf-8")
            path.chmod(0o755)
        artifact = replay.capture_migration(self.before, migrated_project=self.after,
                                             baseline_command=[str(first), "{test}"], migration_command=self.command)
        result = replay.replay_migration(artifact, execute=True, baseline_command=[str(second), "{test}"],
                                         migration_command=self.command)
        self.assertEqual(result["verdict"], "REPRODUCED")

    def capture_argument_failure(self):
        for directory in (self.before, self.after):
            (directory / "app.test.js").write_text("console.log(process.argv[2]);", encoding="utf-8")
        baseline = [self.command[0], "{test}", "expected"]
        candidate = [self.command[0], "{test}", "wrong"]
        artifact = replay.capture_migration(self.before, migrated_project=self.after,
                                             baseline_command=baseline, migration_command=candidate)
        return artifact, baseline, candidate

    def test_fix_verification_executes_new_candidate_against_unchanged_reference(self):
        artifact, baseline, _ = self.capture_argument_failure()
        result = replay.replay_migration(artifact, execute=True, verify_fix=True,
                                         baseline_command=baseline, migration_command=baseline)
        self.assertEqual(result["verdict"], "FIX_VERIFIED")
        self.assertEqual(result["recorded_validation_verdict"], "FAIL")
        self.assertEqual(result["observed_validation_verdict"], "PASS")
        self.assertEqual(result["reference_drift_tests"], [])
        self.assertEqual(result["mode"], "fix-verification")
        self.assertFalse(result["release_certification"])

    def test_unchanged_failure_does_not_verify_a_fix(self):
        artifact, baseline, candidate = self.capture_argument_failure()
        result = replay.replay_migration(artifact, execute=True, verify_fix=True,
                                         baseline_command=baseline, migration_command=candidate)
        self.assertEqual(result["verdict"], "FIX_NOT_VERIFIED")
        self.assertEqual(result["observed_validation_verdict"], "FAIL")

    def test_changing_reference_command_is_forbidden_even_in_fix_mode(self):
        artifact, _, candidate = self.capture_argument_failure()
        with self.assertRaisesRegex(ValueError, "runtime provenance mismatch"):
            replay.replay_migration(artifact, execute=True, verify_fix=True,
                                    baseline_command=candidate, migration_command=candidate)

    def test_reference_output_drift_blocks_false_fix_when_current_legs_agree(self):
        key = "FRANKEN_REPLAY_TEST_REFERENCE_DRIFT"
        old = os.environ.pop(key, None)
        try:
            (self.before / "app.test.js").write_text(f"console.log(process.env.{key} || 'expected');", encoding="utf-8")
            artifact = self.capture()
            os.environ[key] = "actual"
            result = self.execute(artifact, verify_fix=True)
            self.assertEqual(result["observed_validation_verdict"], "PASS")
            self.assertEqual(result["verdict"], "REFERENCE_DRIFT")
            self.assertEqual(result["reference_drift_tests"], ["app.test.js"])
        finally:
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old

    def test_failed_reference_cannot_authorize_fix_verification(self):
        (self.before / "app.test.js").write_text("process.exit(2);", encoding="utf-8")
        artifact = self.capture()
        with self.assertRaisesRegex(ValueError, "successful complete reference"):
            self.execute(artifact, verify_fix=True)

    def test_inspection_is_offline_and_does_not_expose_project_contents(self):
        (self.before / ".env").write_text("VERY_PRIVATE_SECRET=value", encoding="utf-8")
        artifact = self.capture()
        result = replay.inspect_capsule(artifact, artifact["content_sha256"])
        self.assertEqual(result["verdict"], "INTEGRITY_VALID")
        self.assertFalse(result["executed"])
        self.assertTrue(result["independently_pinned"])
        self.assertNotIn("VERY_PRIVATE_SECRET", json.dumps(result))
        self.assertNotIn("blobs", result)

    def test_inspect_cli_does_not_require_available_runtime_commands(self):
        capsule = replay.save_replay(self.capture(), self.root)
        result = subprocess.run([sys.executable, replay.__file__, "--inspect", str(capsule), "--json",
                                 "--baseline-command", '["/absent/runtime","{test}"]'],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["executed"])

    def test_fix_cli_reports_success_only_for_fixed_captured_cases(self):
        artifact, baseline, _ = self.capture_argument_failure()
        capsule = replay.save_replay(artifact, self.root)
        result = subprocess.run([sys.executable, replay.__file__, "--replay", str(capsule), "--execute",
                                 "--verify-fix", "--json", "--baseline-command", json.dumps(baseline),
                                 "--migration-command", json.dumps(baseline)],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["verdict"], "FIX_VERIFIED")


if __name__ == "__main__":
    unittest.main()
