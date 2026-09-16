#!/usr/bin/env python3
"""Unit and real-process tests for migration_validation_runner.py."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import migration_validation_runner as runner


class TestDiscoverTests(unittest.TestCase):
    def test_finds_test_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "app.test.js").write_text("")
            (project / "lib.spec.ts").write_text("")
            (project / "util.js").write_text("")
            tests = runner.discover_tests(project)
        self.assertEqual(len(tests), 2)

    def test_ignores_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            nm = project / "node_modules" / "pkg"
            nm.mkdir(parents=True)
            (nm / "index.test.js").write_text("")
            (project / "app.test.js").write_text("")
            tests = runner.discover_tests(project)
        self.assertEqual(len(tests), 1)

    def test_empty_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tests = runner.discover_tests(Path(tmpdir))
        self.assertEqual(len(tests), 0)


class TestCanonicalizeOutput(unittest.TestCase):
    def test_replaces_timestamps(self):
        self.assertIn("<TIMESTAMP>", runner.canonicalize_output("at 2024-01-15T10:30:00"))

    def test_replaces_pids(self):
        self.assertIn("pid=<PID>", runner.canonicalize_output("pid=12345"))

    def test_replaces_abs_paths(self):
        self.assertIn("<ABS_PATH>", runner.canonicalize_output("/home/user/project/file.js"))

    def test_preserves_normal_text(self):
        self.assertEqual(runner.canonicalize_output("hello world"), "hello world")


class TestCompareOutputs(unittest.TestCase):
    def test_identical(self):
        comparison = runner.compare_outputs("a\nb\nc", "a\nb\nc")
        self.assertTrue(comparison["identical"])
        self.assertEqual(comparison["divergence_count"], 0)

    def test_divergent(self):
        comparison = runner.compare_outputs("a\nb", "a\nc")
        self.assertFalse(comparison["identical"])
        self.assertEqual(comparison["divergence_count"], 1)

    def test_different_lengths(self):
        self.assertFalse(runner.compare_outputs("a\nb\nc", "a\nb")["identical"])

    def test_canonicalizes_before_compare(self):
        self.assertTrue(runner.compare_outputs(
            "at 2024-01-01T00:00:00 pid=1",
            "at 2025-12-31T23:59:59 pid=999",
        )["identical"])

    def test_missing_line_is_not_a_literal_missing_sentinel(self):
        self.assertFalse(runner.compare_outputs("a\n<missing>", "a")["identical"])


class TestClassifyDivergenceSeverity(unittest.TestCase):
    def test_core_is_critical(self):
        self.assertEqual(runner.classify_divergence_severity([{}], "core"), "critical")

    def test_high_value_is_high(self):
        self.assertEqual(runner.classify_divergence_severity([{}], "high-value"), "high")

    def test_edge_is_informational(self):
        self.assertEqual(runner.classify_divergence_severity([{}], "edge"), "informational")

    def test_no_divergences_is_none(self):
        self.assertEqual(runner.classify_divergence_severity([], "core"), "none")


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(runner.self_test()["verdict"], "PASS")

    def test_cites_primary_implementations(self):
        result = runner.self_test()
        self.assertEqual(result["evidence_paths"]["migration_validation_runner"],
                         "scripts/migration_validation_runner.py")
        self.assertEqual(result["evidence_paths"]["lockstep_harness"],
                         "crates/franken-node/src/runtime/lockstep_harness.rs")
        self.assertIn("VALIDATE-IMPL", {check["id"] for check in result["checks"]})

    def test_checked_in_evidence_cites_primary_implementations(self):
        evidence = json.loads((Path(__file__).resolve().parent.parent /
                               "artifacts/section_10_3/bd-2st/verification_evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["evidence_paths"]["migration_validation_runner"],
                         "scripts/migration_validation_runner.py")
        self.assertEqual(evidence["evidence_paths"]["lockstep_harness"],
                         "crates/franken-node/src/runtime/lockstep_harness.rs")


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "real Node.js and POSIX required")
class TestLiveMigrationValidation(unittest.TestCase):
    """Real Node processes exercise orchestration, not Franken parity claims.

    No subprocess or filesystem mocks. Custom commands deliberately use Node
    for both legs; the artifact records those commands and is not a release
    certificate. Native Franken compatibility remains a separate runtime gate.
    """
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="migration-tests-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.before = self.root / "before project"
        self.after = self.root / "after project"
        self.before.mkdir()
        self.after.mkdir()
        self.node = shutil.which("node")

    def write_case(self, before="console.log('ok');", after=None, name="app.test.js"):
        (self.before / name).write_text(before, encoding="utf-8")
        (self.after / name).write_text(before if after is None else after, encoding="utf-8")

    def validate(self, **kwargs):
        options = {"migrated_project": self.after,
                   "baseline_command": [self.node, "{test}"],
                   "migration_command": [self.node, "{test}"],
                   "timeout_seconds": 2, "total_timeout_seconds": 20}
        options.update(kwargs)
        return runner.validate_project(self.before, **options)

    def test_real_execution_passes_and_records_nonempty_measurements(self):
        self.write_case()
        report = self.validate()
        self.assertEqual(report["summary"], {"total_tests": 1, "passed": 1,
                                            "failed": 0, "skipped": 0, "errored": 0, "verdict": "PASS"})
        self.assertEqual(report["phase"], "execution")
        self.assertFalse(report["release_certification"])
        self.assertEqual(report["comparison_mode"], "exact-bytes")
        row = report["validation_results"][0]
        self.assertEqual(row["baseline"]["streams"]["stdout"]["bytes_observed"], 3)
        self.assertEqual(row["baseline"]["streams"], row["migration"]["streams"])
        self.assertNotIn("stdout", row["baseline"])

    def test_same_tree_runs_twice_without_contaminating_input(self):
        self.write_case("require('fs').writeFileSync('created.txt','bytes'); console.log('ok');")
        self.assertEqual(self.validate(migrated_project=None)["summary"]["verdict"], "PASS")
        self.assertFalse((self.before / "created.txt").exists())

    def test_each_test_and_leg_starts_from_fresh_snapshot(self):
        code = "const fs=require('fs'); console.log(fs.readFileSync('counter','utf8')); fs.writeFileSync('counter','changed');"
        self.write_case(code, name="a.test.js")
        self.write_case(code, name="b.test.js")
        for root in (self.before, self.after):
            (root / "counter").write_text("original", encoding="utf-8")
        report = self.validate()
        self.assertEqual(report["summary"]["passed"], 2)
        digests = [row["baseline"]["streams"]["stdout"]["sha256"] for row in report["validation_results"]]
        self.assertEqual(digests[0], digests[1])
        for root in (self.before, self.after):
            self.assertEqual((root / "counter").read_text(), "original")

    def test_support_files_and_dependencies_are_staged_but_not_discovered_as_tests(self):
        self.write_case("console.log(require('fixture-pkg'));")
        for root in (self.before, self.after):
            package = root / "node_modules/fixture-pkg"
            package.mkdir(parents=True)
            (package / "index.js").write_text("module.exports='from-dependency';", encoding="utf-8")
            (package / "internal.test.js").write_text("process.exit(9);", encoding="utf-8")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "PASS")
        self.assertEqual(report["summary"]["total_tests"], 1)

    def test_internal_file_and_directory_symlinks_are_preserved(self):
        self.write_case("console.log(require('fs').readFileSync('alias.txt','utf8'));")
        for root in (self.before, self.after):
            (root / "data").mkdir()
            (root / "data/value.txt").write_text("value", encoding="utf-8")
            (root / "directory-link").symlink_to("data")
            (root / "alias.txt").symlink_to(root / "directory-link/value.txt")
        self.assertEqual(self.validate()["summary"]["verdict"], "PASS")

    def test_external_symlink_fails_before_execution(self):
        self.write_case()
        target = self.root / "external.txt"
        target.write_text("outside", encoding="utf-8")
        (self.before / "outside-link").symlink_to(target)
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("external workspace symlink", report["errors"][0]["message"])
        self.assertEqual(report["validation_results"], [])

    def test_fifo_fails_without_blocking_capture(self):
        self.write_case()
        os.mkfifo(self.before / "pipe")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("nonregular", report["errors"][0]["message"])

    def test_original_and_rewritten_trees_are_compared(self):
        self.write_case("console.log(41+1);", "console.log(6*7);")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "PASS")
        self.assertNotEqual(report["inputs"]["baseline_sha256"], report["inputs"]["migration_sha256"])

    def test_stdout_divergence_fails(self):
        self.write_case("console.log('before');", "console.log('after');")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        self.assertIn({"channel": "stdout", "reason": "byte_mismatch"}, report["validation_results"][0]["divergences"])
        self.assertEqual(report["validation_results"][0]["severity"], "critical")

    def test_stderr_divergence_fails_even_when_stdout_matches(self):
        self.write_case("console.log('ok'); console.error('first');", "console.log('ok'); console.error('second');")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        self.assertIn({"channel": "stderr", "reason": "byte_mismatch"}, report["validation_results"][0]["divergences"])

    def test_identical_nonzero_exits_are_not_a_pass(self):
        self.write_case("process.exit(7);")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        row = report["validation_results"][0]
        self.assertEqual(row["baseline"]["exit_code"], 7)
        self.assertEqual(row["migration"]["exit_code"], 7)

    def test_signal_termination_is_not_a_pass(self):
        self.write_case("process.kill(process.pid,'SIGTERM');")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        self.assertEqual(report["validation_results"][0]["baseline"]["termination"], "signal")

    def test_missing_runtime_is_error_not_skip_or_pass(self):
        self.write_case()
        report = self.validate(migration_command=[str(self.root / "no-runtime"), "{test}"])
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(report["summary"]["passed"], 0)
        self.assertEqual(report["summary"]["skipped"], 1)
        self.assertIn("runtime executable not found", report["errors"][0]["message"])

    def test_missing_project_is_error(self):
        report = runner.validate_project(self.root / "absent")
        self.assertEqual(report["summary"]["verdict"], "ERROR")

    def test_empty_project_is_no_tests_not_pass(self):
        self.assertEqual(self.validate()["summary"]["verdict"], "NO_TESTS")

    def test_missing_migrated_case_is_error(self):
        (self.before / "app.test.js").write_text("console.log('ok');", encoding="utf-8")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("missing test", report["errors"][0]["message"])

    def test_timeouts_are_bounded_and_fail_even_if_both_match(self):
        self.write_case("setInterval(()=>{},1000);")
        started = time.monotonic()
        report = self.validate(timeout_seconds=0.15)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        row = report["validation_results"][0]
        self.assertEqual(row["baseline"]["termination"], "timeout")
        self.assertEqual(row["migration"]["termination"], "timeout")

    def test_pipe_inheriting_descendant_cannot_hang_the_runner(self):
        self.write_case("require('child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'}); process.exit(0);")
        started = time.monotonic()
        report = self.validate(timeout_seconds=0.2)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        self.assertEqual(report["validation_results"][0]["baseline"]["termination"], "timeout")

    def test_output_limit_is_not_a_truncated_prefix_pass(self):
        self.write_case("process.stdout.write('x'.repeat(100000));")
        report = self.validate(max_output_bytes=1024)
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        stream = report["validation_results"][0]["baseline"]["streams"]["stdout"]
        self.assertEqual(stream["retained_bytes"], 1024)
        self.assertGreater(stream["bytes_observed"], 1024)
        self.assertFalse(stream["complete"])

    def test_stderr_output_limit_is_enforced(self):
        self.write_case("process.stderr.write('x'.repeat(100000));")
        report = self.validate(max_output_bytes=1024)
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        self.assertEqual(report["validation_results"][0]["migration"]["termination"], "output_limit")

    def test_total_budget_is_distinct_from_per_leg_timeout(self):
        self.write_case("setInterval(()=>{},1000);")
        report = self.validate(timeout_seconds=10, total_timeout_seconds=0.15)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("budget exhausted", report["errors"][0]["message"])
        self.assertEqual(report["summary"]["errored"], 1)
        self.assertEqual(report["validation_results"][0]["baseline"]["termination"], "timeout")
        self.assertEqual(report["validation_results"][0]["status"], "ERROR")

    def test_exact_bytes_keep_trailing_newlines_and_invalid_utf8_distinct(self):
        for before, after in [("process.stdout.write('ok\\n');", "process.stdout.write('ok');"),
                              ("process.stdout.write(Buffer.from([255]));", "process.stdout.write(Buffer.from([254]));")]:
            with self.subTest(before=before):
                self.write_case(before, after)
                self.assertEqual(self.validate()["summary"]["verdict"], "FAIL")

    def test_diagnostic_normalization_never_hides_live_differences(self):
        self.write_case("console.log('pid=1 at 2024-01-01T00:00:00');",
                        "console.log('pid=2 at 2025-01-01T00:00:00');")
        self.assertEqual(self.validate()["summary"]["verdict"], "FAIL")

    def test_metacharacters_in_test_names_do_not_invoke_a_shell(self):
        name = "case;touch SHOULD_NOT_EXIST.test.js"
        self.write_case(name=name)
        self.assertEqual(self.validate()["summary"]["verdict"], "PASS")
        self.assertFalse((self.before / "SHOULD_NOT_EXIST.test.js").exists())

    def test_nonfinite_or_invalid_limits_are_rejected(self):
        self.write_case()
        for options in ({"timeout_seconds": float("nan")}, {"timeout_seconds": float("inf")},
                        {"timeout_seconds": 0}, {"total_timeout_seconds": -1},
                        {"max_output_bytes": 0}, {"max_output_bytes": True}):
            with self.subTest(options=options):
                self.assertEqual(self.validate(**options)["summary"]["verdict"], "ERROR")

    def test_invalid_command_shapes_are_rejected(self):
        self.write_case()
        for command in ([], "node {test}", ["node"], ["{test}"], ["node", "{test}", "{test}"], ["node", 1, "{test}"]):
            with self.subTest(command=command):
                self.assertEqual(self.validate(migration_command=command)["summary"]["verdict"], "ERROR")

    def test_edge_divergence_is_classified_but_never_silently_passed(self):
        self.write_case("console.log('one');", "console.log('two');")
        report = self.validate(band="edge")
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        self.assertEqual(report["validation_results"][0]["severity"], "informational")

    def test_input_digest_is_stable_and_binds_file_contents(self):
        self.write_case()
        first = self.validate()["inputs"]
        self.assertEqual(first, self.validate()["inputs"])
        (self.after / "support.txt").write_text("additional input", encoding="utf-8")
        changed = self.validate()["inputs"]
        self.assertEqual(first["baseline_sha256"], changed["baseline_sha256"])
        self.assertNotEqual(first["migration_sha256"], changed["migration_sha256"])

    def test_cli_exit_code_tracks_real_verdict(self):
        for candidate, expected in (("console.log('ok');", 0), ("process.exit(1);", 1)):
            with self.subTest(expected=expected):
                self.write_case(after=candidate)
                command = [sys.executable, str(Path(runner.__file__)), str(self.before),
                           "--migrated-project", str(self.after), "--json",
                           "--baseline-command", json.dumps([self.node, "{test}"]),
                           "--migration-command", json.dumps([self.node, "{test}"])]
                result = subprocess.run(command, capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, expected, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["summary"]["verdict"], "PASS" if expected == 0 else "FAIL")

    def test_added_migration_tests_are_not_silently_ignored(self):
        self.write_case()
        (self.after / "extra.test.js").write_text("process.exit(8);", encoding="utf-8")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(report["test_discovery"]["missing_baseline"], ["extra.test.js"])
        self.assertEqual(report["validation_results"], [])

    def test_removed_tests_fail_before_any_runtime_starts(self):
        self.write_case()
        (self.before / "extra.test.js").write_text("process.exit(8);", encoding="utf-8")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(report["test_discovery"]["missing_migration"], ["extra.test.js"])
        self.assertEqual(report["validation_results"], [])

    def test_workspaces_do_not_accumulate_across_cases(self):
        code = ("const fs=require('fs'),p=require('path'); "
                "console.log(fs.readdirSync(p.dirname(p.dirname(process.cwd())))"
                ".filter(x=>x.startsWith('case-')).length);")
        for name in ("a.test.js", "b.test.js", "c.test.js"):
            self.write_case(code, name=name)
        report = self.validate()
        self.assertEqual(report["summary"]["passed"], 3)
        expected = runner.hashlib.sha256(b"1\n").hexdigest()
        for row in report["validation_results"]:
            self.assertEqual(row["baseline"]["streams"]["stdout"]["sha256"], expected)
            self.assertEqual(row["migration"]["streams"]["stdout"]["sha256"], expected)

    def test_report_export_is_private_and_contains_the_executed_result(self):
        self.write_case()
        report = self.validate()
        destination = self.root / "report.json"
        destination.write_text("old report", encoding="utf-8")
        runner.write_report(report, destination)
        self.assertEqual(json.loads(destination.read_text()), report)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.root.glob(".report.json.*")), [])

    def test_cli_report_export_preserves_failure_exit(self):
        self.write_case(after="process.exit(1);")
        destination = self.root / "report.json"
        command = [sys.executable, str(Path(runner.__file__)), str(self.before),
                   "--migrated-project", str(self.after), "--json", "--out", str(destination),
                   "--baseline-command", json.dumps([self.node, "{test}"]),
                   "--migration-command", json.dumps([self.node, "{test}"])]
        result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout), json.loads(destination.read_text()))

    def test_report_write_failure_is_nonzero_without_losing_previous_file(self):
        destination = self.root / "existing-dir"
        destination.mkdir()
        with self.assertRaises(OSError):
            runner.write_report({"ok": True}, destination)
        self.assertTrue(destination.is_dir())
        self.assertEqual(list(self.root.glob(".existing-dir.*")), [])

    def test_cli_no_tests_is_nonzero_json(self):
        result = subprocess.run([sys.executable, str(Path(runner.__file__)), str(self.before), "--json"],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["summary"]["verdict"], "NO_TESTS")

    def test_cli_missing_runtime_is_nonzero_json(self):
        self.write_case()
        result = subprocess.run([sys.executable, str(Path(runner.__file__)), str(self.before), "--json",
                                 "--migration-command", json.dumps([str(self.root / "absent"), "{test}"])],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["summary"]["verdict"], "ERROR")

    def test_filesystem_comparison_catches_same_output_different_writes(self):
        self.write_case("require('fs').writeFileSync('result.txt','one');",
                        "require('fs').writeFileSync('result.txt','two');")
        self.assertEqual(self.validate()["summary"]["verdict"], "PASS")
        report = self.validate(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        self.assertEqual(report["validation_scope"], "test-process-and-workspace-delta")
        self.assertIn({"channel": "filesystem", "reason": "workspace_delta_mismatch"},
                      report["validation_results"][0]["divergences"])

    def test_equivalent_writes_pass_despite_different_original_source(self):
        self.write_case("require('fs').writeFileSync('result.txt',String(6*7));",
                        "require('fs').writeFileSync('result.txt',String(41+1));")
        report = self.validate(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "PASS")
        row = report["validation_results"][0]
        self.assertEqual(row["baseline"]["workspace_delta"], row["migration"]["workspace_delta"])
        self.assertEqual(row["baseline"]["workspace_delta"]["changed_paths"], 1)
        observed = row["baseline"]["workspace_delta"]["changes"]["result.txt"]["after"]
        self.assertEqual(set(observed), {"kind", "mode", "sha256"})
        self.assertEqual(observed["sha256"], runner.hashlib.sha256(b"42").hexdigest())

    def test_workspace_deletion_and_mode_changes_are_observed(self):
        for operation in ("unlinkSync('data.txt')", "chmodSync('data.txt',0o600)"):
            with self.subTest(operation=operation):
                self.write_case(f"require('fs').{operation};", "// No effect")
                for root in (self.before, self.after):
                    (root / "data.txt").write_text("unchanged content", encoding="utf-8")
                    (root / "data.txt").chmod(0o644)
                report = self.validate(compare_filesystem=True)
                self.assertEqual(report["summary"]["verdict"], "FAIL")
                self.assertEqual(report["validation_results"][0]["baseline"]["workspace_delta"]["changed_paths"], 1)
                self.assertEqual((self.before / "data.txt").stat().st_mode & 0o777, 0o644)

    def test_workspace_delta_preview_cap_does_not_hide_a_late_difference(self):
        code = "const fs=require('fs'); for(let i=0;i<25;i++) fs.writeFileSync('result-'+i,'same');"
        self.write_case(code, code + "fs.writeFileSync('result-9','different');")
        report = self.validate(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        delta = report["validation_results"][0]["baseline"]["workspace_delta"]
        self.assertEqual(delta["changed_paths"], 25)
        self.assertTrue(delta["details_truncated"])
        self.assertEqual(len(delta["changes"]), 20)
        self.assertNotIn("result-9", delta["changes"])

    def test_filesystem_cli_option_is_wired_to_the_verdict(self):
        self.write_case("require('fs').writeFileSync('data','one');",
                        "require('fs').writeFileSync('data','two');")
        command = [sys.executable, str(Path(runner.__file__)), str(self.before),
                   "--migrated-project", str(self.after), "--json", "--compare-filesystem",
                   "--baseline-command", json.dumps([self.node, "{test}"]),
                   "--migration-command", json.dumps([self.node, "{test}"])]
        result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(json.loads(result.stdout)["filesystem_comparison"])

    def test_symlink_chain_retargeting_keeps_original_semantics(self):
        code = ("const fs=require('fs'); fs.unlinkSync('middle'); fs.symlinkSync('second','middle'); "
                "console.log(fs.readFileSync('alias','utf8'));")
        self.write_case(code)
        for root in (self.before, self.after):
            (root / "first").write_text("first", encoding="utf-8")
            (root / "second").write_text("second", encoding="utf-8")
            (root / "middle").symlink_to("first")
            (root / "alias").symlink_to("middle")
        report = self.validate(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "PASS")
        row = report["validation_results"][0]
        self.assertEqual(row["baseline"]["streams"]["stdout"]["sha256"], runner.hashlib.sha256(b"second\n").hexdigest())
        self.assertEqual(row["baseline"]["workspace_delta"]["changed_paths"], 1)


if __name__ == "__main__":
    unittest.main()
