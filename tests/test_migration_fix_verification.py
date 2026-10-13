"""Execute captured failures against replacement runtimes, retaining the oracle.

Explicit Node/Node commands and unbranded local wrappers test orchestration;
these tests are not a native compatibility or independent-runtime benchmark.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import migration_validation_runner as runner


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "real Node and POSIX required")
class FixVerificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="verify-migration-fix-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "fixtures").mkdir()
        (self.project / "fixtures/stdout").write_bytes(b"ok")
        (self.project / "fixtures/file").write_bytes(b"expected")
        (self.project / "fixtures/stdin").write_bytes(b"\0\xffrequest")
        (self.project / ".franken-node").mkdir()
        self.source = (
            "const fs=require('fs');\n"
            "const reference=process.execArgv.includes('--conditions=reference');\n"
            "const fixed=process.execArgv.includes('--conditions=fixed');\n"
            "const good=reference||fixed;\n"
            "if(!fs.fstatSync(0).isFile()) throw Error('stdin mode changed');\n"
            "if(fs.readFileSync(0).toString('hex')!=='00ff72657175657374') throw Error('stdin changed');\n"
            "if(JSON.stringify(process.argv.slice(2))!==JSON.stringify(['','--policy','雪'])) throw Error('argv changed');\n"
            "if(process.env.APP_MODE!=='captured') throw Error('environment changed');\n"
            "fs.writeFileSync('output',good?'expected':'incorrect');\n"
            "process.stdout.write(good?'ok':'wrong');\n")
        self.write_source()
        self.manifest = {"schema_version": runner.MIGRATION_TEST_SCHEMA, "tests": ["probe.cjs"],
            "execution": {"probe.cjs": {"arguments": ["", "--policy", "雪"],
                "stdin": "fixtures/stdin", "stdin_mode": "file", "environment": {"APP_MODE": "captured"}}},
            "expectations": {"probe.cjs": {"stdout": "fixtures/stdout", "files": {"output": "fixtures/file"}}}}
        self.save_manifest()
        self.node = shutil.which("node")
        self.baseline = (self.node, "--conditions=reference", "{test}", "{arguments}")
        self.broken = (self.node, "{test}", "{arguments}")
        self.fixed = (self.node, "--conditions=fixed", "{test}", "{arguments}")
        self.path = self.root / "capture.fnmigration"

    def write_source(self):
        (self.project / "probe.cjs").write_text(self.source, encoding="utf-8")

    def save_manifest(self):
        (self.project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(self.manifest))

    def capture(self, **options):
        report = runner.validate_project(self.project, baseline_command=self.baseline,
            migration_command=options.pop("migration_command", self.broken),
            timeout_seconds=options.pop("timeout_seconds", 3), total_timeout_seconds=30,
            bundle_path=self.path, **options)
        self.assertIn("replay_bundle", report, report)
        return report

    def verify(self, report, **options):
        return runner.replay_captured_bundle(self.path,
            expected_sha256=options.pop("expected_sha256", report["replay_bundle"]["sha256"]),
            baseline_command=options.pop("baseline_command", self.baseline),
            migration_command=options.pop("migration_command", self.fixed),
            verify_fix=options.pop("verify_fix", True), **options)

    def wrapper(self, path, condition):
        path.write_text(f"#!/bin/sh\nexec {shlex.quote(self.node)} --conditions={condition} \"$@\"\n")
        path.chmod(0o700)
        return (str(path), "{test}", "{arguments}")

    def test_actual_fix_preserves_inputs_oracles_and_relocation(self):
        report = self.capture(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "FAIL", report)
        self.project.rename(self.root / "original-unavailable")
        result = self.verify(report)
        self.assertEqual(result["replay_outcome"], "FIX_VERIFIED", result)
        self.assertEqual(result["mode"], "fix-verification")
        self.assertEqual(result["execution"]["summary"]["verdict"], "PASS")
        self.assertEqual(result["execution"]["inputs"], report["inputs"])
        self.assertEqual(result["reference_drift_tests"], [])
        self.assertTrue(result["reference_observations_match"])
        self.assertFalse(result["release_certification"])
        self.assertNotIn("observations_match", result)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), report["replay_bundle"]["sha256"])

    def test_still_broken_runtime_is_not_verified(self):
        result = self.verify(self.capture(), migration_command=self.broken)
        self.assertEqual(result["replay_outcome"], "FIX_NOT_VERIFIED", result)
        self.assertTrue(result["reference_observations_match"])

    def test_changed_candidate_executable_is_allowed_and_measured(self):
        path = self.root / "candidate-wrapper.sh"
        command = self.wrapper(path, "broken")
        report = self.capture(migration_command=command)
        original = report["runtime_identities"]["migration"]["sha256"]
        self.wrapper(path, "fixed")
        result = self.verify(report, migration_command=command)
        self.assertEqual(result["replay_outcome"], "FIX_VERIFIED", result)
        self.assertNotEqual(result["execution"]["runtime_identities"]["migration"]["sha256"], original)
        self.assertEqual(result["recorded_runtime_identities"]["migration"]["sha256"], original)
        self.assertTrue(result["execution"]["runtime_identity_rechecked"])

    def test_ordinary_replay_still_refuses_replacement_arguments_before_launch(self):
        report = self.capture()
        with mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report, verify_fix=False)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("command arguments differ", result["errors"][0]["message"])

    def test_ordinary_replay_still_refuses_replaced_executable_before_launch(self):
        path = self.root / "candidate-wrapper.sh"
        command = self.wrapper(path, "broken")
        report = self.capture(migration_command=command)
        self.wrapper(path, "fixed")
        with mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report, verify_fix=False, migration_command=command)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("executable identity", result["errors"][0]["message"])

    def test_reference_arguments_cannot_change_in_fix_mode(self):
        report = self.capture()
        with mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report, baseline_command=self.fixed)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("command arguments differ", result["errors"][0]["message"])

    def test_reference_executable_cannot_change_in_fix_mode(self):
        path = self.root / "reference-wrapper.sh"
        self.baseline = self.wrapper(path, "reference")
        report = self.capture()
        with path.open("a") as stream:
            stream.write("# replaced executable identity\n")
        with mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("executable identity", result["errors"][0]["message"])

    def test_effective_environment_drift_rejects_before_launch(self):
        with mock.patch.dict(os.environ, {"APP_EXTERNAL": "original"}):
            report = self.capture()
        with mock.patch.dict(os.environ, {"APP_EXTERNAL": "changed"}), \
             mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("environment differs", result["errors"][0]["message"])

    def test_reference_drift_cannot_be_a_fix_when_current_runtimes_agree(self):
        ambient = self.root / "ambient"
        ambient.write_text("before")
        self.source = self.source.replace("process.stdout.write(good?'ok':'wrong');",
            f"process.stdout.write(good?fs.readFileSync({json.dumps(str(ambient))},'utf8'):'wrong');")
        self.write_source()
        self.manifest["expectations"]["probe.cjs"].pop("stdout")
        self.save_manifest()
        report = self.capture()
        ambient.write_text("after")
        result = self.verify(report)
        self.assertEqual(result["execution"]["summary"]["verdict"], "PASS", result)
        self.assertEqual(result["replay_outcome"], "REFERENCE_DRIFT")
        self.assertEqual(result["reference_drift_tests"], ["probe.cjs"])
        self.assertFalse(result["reference_observations_match"])

    def test_file_only_reference_drift_is_detected_without_workspace_comparison(self):
        ambient = self.root / "ambient"
        ambient.write_text("expected")
        self.source = self.source.replace("good?'expected':'incorrect'",
            f"good?fs.readFileSync({json.dumps(str(ambient))}):'incorrect'")
        self.write_source()
        report = self.capture()
        ambient.write_text("different")
        result = self.verify(report)
        self.assertFalse(result["execution"]["filesystem_comparison"])
        self.assertEqual(result["replay_outcome"], "REFERENCE_DRIFT", result)
        self.assertEqual(result["reference_drift_tests"], ["probe.cjs"])
        old = report["validation_results"][0]["baseline"]
        new = result["execution"]["validation_results"][0]["baseline"]
        self.assertEqual(old["streams"], new["streams"])
        self.assertNotEqual(old["file_outputs"], new["file_outputs"])

    def test_unasserted_workspace_drift_is_checked_when_requested(self):
        ambient = self.root / "ambient"
        ambient.write_text("original")
        self.source += f"fs.writeFileSync('extra',fs.readFileSync({json.dumps(str(ambient))}));\n"
        self.write_source()
        report = self.capture(compare_filesystem=True)
        ambient.write_text("changed")
        result = self.verify(report)
        self.assertEqual(result["execution"]["summary"]["verdict"], "PASS", result)
        self.assertEqual(result["replay_outcome"], "REFERENCE_DRIFT")

    def test_passing_sibling_must_not_regress_in_replacement_runtime(self):
        self.manifest["tests"].append("sibling.cjs")
        (self.project / "sibling.cjs").write_text(
            "process.stdout.write(process.execArgv.includes('--conditions=fixed')?'regression':'ok');\n")
        self.manifest["max_concurrent_tests"] = 2
        self.save_manifest()
        report = self.capture()
        self.assertEqual(report["summary"]["passed"], 1, report)
        result = self.verify(report)
        self.assertEqual(result["replay_outcome"], "FIX_NOT_VERIFIED", result)
        self.assertEqual(result["execution"]["summary"]["passed"], 1)
        self.assertEqual(result["execution"]["summary"]["failed"], 1)
        self.assertEqual(result["execution"]["scheduling"], report["scheduling"])

    def test_successful_original_is_not_relabelled_as_a_fixed_failure(self):
        report = self.capture(migration_command=self.fixed)
        with mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("recorded failing", result["errors"][0]["message"])

    def test_original_reference_nonzero_exit_is_rejected(self):
        self.source += "if(reference) process.exit(7);\n"
        self.write_source()
        report = self.capture()
        with mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("successful complete reference", result["errors"][0]["message"])

    def test_original_reference_output_oracle_must_have_passed(self):
        (self.project / "fixtures/stdout").write_bytes(b"never-produced")
        report = self.capture()
        with mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("reference violates", result["errors"][0]["message"])

    def test_original_reference_file_oracle_must_have_passed(self):
        (self.project / "fixtures/file").write_bytes(b"never-produced")
        report = self.capture()
        with mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("reference violates", result["errors"][0]["message"])

    def test_original_candidate_timeout_can_be_fixed_without_excusing_new_timeout(self):
        self.source += "if(!good) setInterval(()=>{},1000);\n"
        self.write_source()
        report = self.capture(timeout_seconds=0.5)
        self.assertEqual(report["validation_results"][0]["migration"]["termination"], "timeout")
        self.assertEqual(self.verify(report)["replay_outcome"], "FIX_VERIFIED")
        self.assertEqual(self.verify(report, migration_command=self.broken)["replay_outcome"], "FIX_NOT_VERIFIED")

    def test_candidate_change_after_admission_before_launch_is_rejected(self):
        report = self.capture()
        path = self.root / "candidate-wrapper.sh"
        command = self.wrapper(path, "fixed")
        original_stage = runner.stage_project
        changed = False
        def stage(*args, **kwargs):
            nonlocal changed
            value = original_stage(*args, **kwargs)
            if not changed:
                changed = True
                self.wrapper(path, "broken")
            return value
        with mock.patch.object(runner, "stage_project", side_effect=stage), \
             mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report, migration_command=command)
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("executable identity", result["errors"][0]["message"])

    def test_candidate_change_during_execution_cannot_authorize_a_fix(self):
        path = self.root / "candidate-wrapper.sh"
        command = self.wrapper(path, "fixed")
        self.source += f"if(fixed) fs.appendFileSync({json.dumps(str(path))},'# changed\\n');\n"
        self.write_source()
        report = self.capture()
        result = self.verify(report, migration_command=command)
        self.assertEqual(result["replay_outcome"], "ERROR", result)
        self.assertFalse(result["execution"]["runtime_identity_rechecked"])

    def test_trusted_digest_and_boolean_fix_mode_are_not_optional(self):
        report = self.capture()
        for options in ({"expected_sha256": "0" * 64}, {"verify_fix": "true"}, {"verify_fix": 1}):
            with self.subTest(options=options), mock.patch.object(runner, "run_command") as launch:
                result = self.verify(report, **options)
                launch.assert_not_called()
                self.assertEqual(result["replay_outcome"], "ERROR")

    def test_precancelled_verification_launches_nothing(self):
        report = self.capture()
        with mock.patch.object(runner, "run_command") as launch:
            result = self.verify(report, cancellation=runner.CancellationState(signum=15))
        launch.assert_not_called()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertEqual(result["cancellation"]["signal"], 15)

    def cli(self, report, candidate=None, extra=()):
        return [sys.executable, runner.__file__, "--replay-bundle", str(self.path), "--verify-fix",
            "--expected-bundle-sha256", report["replay_bundle"]["sha256"],
            "--baseline-command", json.dumps(self.baseline),
            "--migration-command", json.dumps(candidate or self.fixed), "--json", *extra]

    def test_cli_writes_verified_result_and_has_distinct_failure_exit(self):
        report = self.capture()
        output = self.root / "fix-result.json"
        result = subprocess.run(self.cli(report, extra=("--out", str(output))),
                                capture_output=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["replay_outcome"], "FIX_VERIFIED", parsed)
        self.assertEqual(json.loads(output.read_bytes()), parsed)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        failed = subprocess.run(self.cli(report, self.broken), capture_output=True, timeout=20, check=False)
        self.assertEqual(failed.returncode, 1, failed.stderr + failed.stdout)
        self.assertEqual(json.loads(failed.stdout)["replay_outcome"], "FIX_NOT_VERIFIED")

    def test_cli_rejects_fix_mode_outside_replay_and_never_overwrites_bundle(self):
        for args in (("--self-test",), ("--inspect-bundle", "missing.fnmigration"), (str(self.project),)):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, runner.__file__, *args, "--verify-fix"],
                                        capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"--verify-fix requires --replay-bundle", result.stderr)
        report = self.capture()
        result = subprocess.run(self.cli(report, extra=("--out", str(self.path))),
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), report["replay_bundle"]["sha256"])


if __name__ == "__main__":
    unittest.main()
