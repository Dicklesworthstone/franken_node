#!/usr/bin/env python3
"""Execution-backed minimizer regressions. Node/Node tests are NOT Franken parity."""

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
import minimize_migration_failure as minimizer


class TestReducerAlgorithm(unittest.TestCase):
    def test_reduces_to_the_required_lines(self):
        lines = [b"noise\n", b"needed\n", b"other\n", b"also-needed\n"]
        result = minimizer.reduce_lines(lines, lambda value: b"needed\n" in value and b"also-needed\n" in value)
        self.assertEqual(result, [b"needed\n", b"also-needed\n"])

    def test_empty_is_tested_and_can_be_the_smallest_input(self):
        self.assertEqual(minimizer.reduce_lines([b"noise\n"], lambda _: True), [])

    def test_irreducible_input_is_preserved(self):
        lines = [b"one\n", b"two\n", b"three\n"]
        self.assertEqual(minimizer.reduce_lines(lines, lambda value: value == lines), lines)

    def test_input_is_not_mutated(self):
        lines = [b"one\n", b"two\n"]
        minimizer.reduce_lines(lines, lambda _: True)
        self.assertEqual(lines, [b"one\n", b"two\n"])

    def test_budget_stops_instead_of_returning_untested_input(self):
        def no_budget(_):
            raise minimizer.ReductionBudgetExhausted("execution_budget")
        with self.assertRaises(minimizer.ReductionBudgetExhausted):
            minimizer.reduce_lines([b"one\n"], no_budget)


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "Node.js and POSIX required")
class TestExecutedMinimization(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="minimize-tests-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.before, self.after = self.root / "before", self.root / "after"
        self.before.mkdir()
        self.after.mkdir()
        self.command = [shutil.which("node"), "{test}"]

    def sources(self, before=None, after=None, filename="app.test.js"):
        noise = "// irrelevant comment\nconst unused = 42;\n\n"
        before = before if before is not None else noise + "console.log('original');\n"
        after = after if after is not None else noise + "console.log('rewritten');\n"
        (self.before / filename).write_text(before, encoding="utf-8")
        (self.after / filename).write_text(after if after is not None else before, encoding="utf-8")

    def capture(self, **options):
        return replay.capture_migration(self.before, migrated_project=self.after,
                                         baseline_command=self.command, migration_command=self.command,
                                         timeout_seconds=2, total_timeout_seconds=20, **options)

    def minimize(self, artifact, **options):
        return minimizer.minimize_migration(artifact, execute=True,
                                             baseline_command=self.command, migration_command=self.command,
                                             seconds=30, **options)

    def test_reduction_removes_irrelevant_code_and_replays_as_original_failure(self):
        self.sources()
        artifact = self.capture()
        before = copy.deepcopy(artifact)
        result = self.minimize(artifact)
        self.assertEqual(artifact, before)
        self.assertTrue(result["minimized"])
        self.assertEqual(result["minimization"]["final_confirmations"], 2)
        self.assertTrue(result["minimization"]["search_complete"])
        self.assertFalse(result["minimization"]["global_minimum_claimed"])
        snapshots = replay.validate_capsule(result)
        self.assertEqual(snapshots["baseline"][0].data, b"console.log('original');\n")
        self.assertEqual(snapshots["migration"][0].data, b"console.log('rewritten');\n")
        self.assertEqual(minimizer.behavior(result["expected"]), minimizer.behavior(artifact["expected"]))
        self.assertNotEqual(result["expected"]["inputs"], artifact["expected"]["inputs"])
        rerun = replay.replay_migration(result, execute=True, baseline_command=self.command,
                                        migration_command=self.command)
        self.assertEqual(rerun["verdict"], "REPRODUCED")
        self.assertEqual(rerun["observed_validation_verdict"], "FAIL")
        self.assertEqual(result["minimization"]["parent_content_sha256"], artifact["content_sha256"])

    def test_new_syntax_errors_or_reference_crashes_are_not_reductions(self):
        self.sources("const important = 'original';\nconsole.log(important);\n",
                     "const important = 'rewritten';\nconsole.log(important);\n")
        artifact = self.capture()
        result = self.minimize(artifact)
        self.assertFalse(result["minimized"])
        self.assertEqual(result["expected"], artifact["expected"])
        self.assertGreater(result["minimization"]["stats"]["rejected"], 0)

    def test_passing_suite_cases_are_preserved_too(self):
        self.sources()
        self.sources("console.log('still-passing');\n", "console.log('still-passing');\n", "other.test.js")
        artifact = self.capture()
        result = self.minimize(artifact)
        self.assertEqual(len(result["expected"]["cases"]), 2)
        self.assertEqual(minimizer.behavior(result["expected"]), minimizer.behavior(artifact["expected"]))
        self.assertEqual(result["minimization"]["source_files"], ["app.test.js"])

    def test_filesystem_only_failure_is_preserved(self):
        self.sources("// noise\nrequire('fs').writeFileSync('out.txt', 'original');\n",
                     "// noise\nrequire('fs').writeFileSync('out.txt', 'rewritten');\n")
        artifact = self.capture(compare_filesystem=True)
        result = self.minimize(artifact)
        self.assertTrue(result["minimized"])
        self.assertTrue(result["options"]["compare_filesystem"])
        self.assertEqual(result["expected"]["cases"], artifact["expected"]["cases"])

    def test_can_reduce_shared_dependency_instead_of_a_test_file(self):
        self.sources("console.log(require('./helper.js'));\n", "console.log(require('./helper.js'));\n")
        self.sources("// noise\nmodule.exports = 'original';\n",
                     "// noise\nmodule.exports = 'rewritten';\n", "helper.js")
        artifact = self.capture()
        result = self.minimize(artifact, source_files=["helper.js"])
        self.assertTrue(result["minimized"])
        for leg in replay.LEGS:
            old = {entry.path: entry for entry in replay.validate_capsule(artifact)[leg]}
            new = {entry.path: entry for entry in replay.validate_capsule(result)[leg]}
            self.assertEqual(new["app.test.js"], old["app.test.js"])
            self.assertNotEqual(new["helper.js"].data, old["helper.js"].data)

    def test_never_modifies_original_projects_or_dependency_configuration(self):
        self.sources()
        for root in (self.before, self.after):
            (root / "package.json").write_text('{"private":true}', encoding="utf-8")
            (root / ".env").write_text("SENSITIVE=keep-private", encoding="utf-8")
        artifact = self.capture()
        originals = {root: (root / "app.test.js").read_bytes() for root in (self.before, self.after)}
        result = self.minimize(artifact)
        for root, content in originals.items():
            self.assertEqual((root / "app.test.js").read_bytes(), content)
        for leg in replay.LEGS:
            old = {entry.path: entry for entry in replay.validate_capsule(artifact)[leg]}
            new = {entry.path: entry for entry in replay.validate_capsule(result)[leg]}
            self.assertEqual(new["package.json"], old["package.json"])
            self.assertEqual(new[".env"], old[".env"])
        self.assertNotIn("SENSITIVE=keep-private", json.dumps(result["minimization"]))

    def test_execution_budget_returns_verified_partial_without_minimality_claim(self):
        self.sources()
        result = self.minimize(self.capture(), max_executions=8)
        metadata = result["minimization"]
        self.assertEqual(metadata["budget_exhausted"], "execution_budget")
        self.assertFalse(metadata["search_complete"])
        self.assertLessEqual(metadata["stats"]["executions"], 8)
        self.assertEqual(metadata["final_confirmations"], 2)
        self.assertEqual(replay.replay_migration(result, execute=True, baseline_command=self.command,
                                                  migration_command=self.command)["verdict"], "REPRODUCED")

    def test_budget_reserved_for_initial_and_final_verification(self):
        self.sources()
        result = self.minimize(self.capture(), max_executions=4)
        self.assertFalse(result["minimized"])
        self.assertEqual(result["minimization"]["stats"]["executions"], 4)
        self.assertEqual(result["minimization"]["budget_exhausted"], "execution_budget")

    def test_execution_consent_is_required(self):
        with self.assertRaisesRegex(ValueError, "consent"):
            minimizer.minimize_migration({})

    def test_validates_budgets_before_execution(self):
        for options in ({"seconds": float("nan")}, {"seconds": float("inf")}, {"seconds": -1},
                        {"max_executions": True}, {"max_executions": 3}, {"max_executions": 4097},
                        {"confirmations": 1}, {"confirmations": True}, {"confirmations": 9}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                minimizer.minimize_migration({}, execute=True, **options)

    def test_wrong_pinned_hash_is_refused(self):
        self.sources()
        with self.assertRaisesRegex(ValueError, "pinned"):
            self.minimize(self.capture(), expected_sha256="0" * 64)

    def test_passing_capsule_is_not_a_reduction_seed(self):
        self.sources("console.log('same');\n", "console.log('same');\n")
        with self.assertRaisesRegex(ValueError, "failing migration"):
            self.minimize(self.capture())

    def test_changed_expected_output_is_rejected_by_actual_execution(self):
        self.sources()
        artifact = self.capture()
        artifact["expected"]["cases"][0]["migration"]["streams"]["stdout"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "does not reproduce"):
            self.minimize(replay.seal(artifact))

    def test_reference_must_have_succeeded(self):
        self.sources("process.exit(5);\n", "process.exit(7);\n")
        with self.assertRaisesRegex(ValueError, "successful reference"):
            self.minimize(self.capture())

    def test_truncated_or_timeout_seed_is_refused(self):
        self.sources()
        artifact = self.capture()
        artifact["expected"]["cases"][0]["migration"]["streams"]["stdout"]["complete"] = False
        with self.assertRaisesRegex(ValueError, "complete"):
            self.minimize(replay.seal(artifact))

    def test_runtime_arguments_cannot_change_during_reduction(self):
        self.sources()
        with self.assertRaisesRegex(ValueError, "provenance"):
            minimizer.minimize_migration(self.capture(), execute=True, baseline_command=self.command,
                                          migration_command=[self.command[0], "--no-warnings", "{test}"])

    def test_recorded_commands_are_not_executed(self):
        self.sources()
        artifact = self.capture()
        artifact["recorded_commands"] = {"migration": ["/not-a-real-command", "{test}"]}
        result = self.minimize(replay.seal(artifact), max_executions=4)
        self.assertEqual(result["recorded_commands"]["migration"], self.command)

    def test_non_source_config_and_unsafe_paths_are_refused(self):
        self.sources()
        artifact = self.capture()
        for files in ([".env"], ["package.json"], ["../app.test.js"], ["absent.js"], [],
                      ["app.test.js", "app.test.js"], "app.test.js"):
            with self.subTest(files=files), self.assertRaises(ValueError):
                self.minimize(artifact, source_files=files)

    def test_byte_and_line_bounds_are_checked_before_runtime_resolution(self):
        self.sources()
        artifact = self.capture()
        snapshots = replay.validate_capsule(artifact)
        for data in (b"//" + b"x" * minimizer.MAX_SOURCE_BYTES,
                     b"\n" * (minimizer.MAX_SOURCE_LINES + 1)):
            with self.subTest(length=len(data)):
                changed = copy.deepcopy(snapshots)
                changed["baseline"][0] = minimizer.replace(changed["baseline"][0], data=data)
                manifests, blobs = replay.encode_snapshots(changed)
                invalid = replay.seal({**artifact, "snapshots": manifests, "blobs": blobs})
                with self.assertRaisesRegex(ValueError, "bound"):
                    self.minimize(invalid)

    def test_symlink_sources_are_refused(self):
        self.sources()
        for root in (self.before, self.after):
            (root / "alias.js").symlink_to("app.test.js")
        with self.assertRaisesRegex(ValueError, "regular files"):
            self.minimize(self.capture(), source_files=["alias.js"])

    def test_environment_drift_prevents_starting_reduction(self):
        external = self.root / "ambient.txt"
        external.write_text("initial", encoding="utf-8")
        read = f"console.log(require('fs').readFileSync({json.dumps(str(external))},'utf8'));\n"
        self.sources(read + "console.log('original');\n", read + "console.log('rewritten');\n")
        artifact = self.capture()
        external.write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not reproduce"):
            self.minimize(artifact)

    def test_cli_creates_private_replayable_capsule_and_does_not_overwrite(self):
        self.sources()
        artifact = self.capture()
        original, output = self.root / "original.json", self.root / "reduced.json"
        replay.write_capsule(artifact, original)
        command = [sys.executable, minimizer.__file__, str(original), "--execute", "--json", "--out", str(output),
                   "--baseline-command", json.dumps(self.command), "--migration-command", json.dumps(self.command)]
        result = subprocess.run(command, capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["verdict"], "REDUCED")
        self.assertEqual(summary["validation_verdict"], "FAIL")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(replay.inspect_capsule(replay.load_replay(output))["verdict"], "INTEGRITY_VALID")
        existing = output.read_bytes()
        refused = subprocess.run(command, capture_output=True, timeout=10, check=False)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("already exists", json.loads(refused.stdout)["error"])
        self.assertEqual(output.read_bytes(), existing)


if __name__ == "__main__":
    unittest.main()
