#!/usr/bin/env python3
"""Assessment and real-process report/capture integration tests."""

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
import migrate_report
import failure_replay as replay


class TestGenerateFullReport(unittest.TestCase):
    def test_report_has_all_sections(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "app.js").write_text("const p = process.env.HOME;\n")
            report = migrate_report.generate_full_report(project)
        for section in ["executive_summary", "scan", "risk_assessment",
                        "rewrite_suggestions", "rollout_plan", "confidence"]:
            self.assertIn(section, report)

    def test_executive_summary_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "index.js").write_text("require('fs');\n")
            report = migrate_report.generate_full_report(project)
        executive = report["executive_summary"]
        self.assertIn("go_decision", executive)
        self.assertIn("confidence_score", executive)
        self.assertIn("risk_score", executive)
        self.assertIn(executive["go_decision"], ["GO", "NO-GO"])

    def test_empty_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = migrate_report.generate_full_report(Path(tmpdir))
        self.assertEqual(report["executive_summary"]["apis_detected"], 0)

    def test_report_version_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = migrate_report.generate_full_report(Path(tmpdir))
        self.assertEqual(report["report_version"], "1.0")


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = migrate_report.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test_checks_live_rust_cli_contract(self):
        result = migrate_report.self_test()
        ids = {check["id"] for check in result["checks"]}
        for name in ("COMMAND", "DISPATCH", "RENDERER", "E2E", "DETERMINISM-BOUNDARY"):
            self.assertIn(f"RUST-CLI-MIGRATE-REPORT-{name}", ids)

    def test_rust_cli_contract_fails_for_missing_checkout_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            checks = migrate_report.check_rust_cli_contract(Path(tmpdir))
        self.assertEqual({check["status"] for check in checks}, {"FAIL"})


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "real Node and POSIX required")
class TestMeasuredReport(unittest.TestCase):
    """Real Node/Node tests of orchestration, not claims of Franken parity."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="report-integration-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.original = self.root / "original"
        self.candidate = self.root / "candidate"
        self.original.mkdir()
        self.candidate.mkdir()
        self.node = shutil.which("node")
        self.command = [self.node, "{test}"]

    def sources(self, original="console.log(42);", candidate=None):
        for root, text in ((self.original, original), (self.candidate, original if candidate is None else candidate)):
            (root / "app.test.js").write_text(text, encoding="utf-8")

    def generate(self, **options):
        args = {"migrated_project": self.candidate, "execute": True,
                "baseline_command": self.command, "migration_command": self.command,
                "timeout_seconds": 2, "total_timeout_seconds": 15}
        args.update(options)
        return migrate_report.generate_full_report(self.original, **args)

    def assert_blocked(self, report):
        self.assertEqual(report["executive_summary"]["go_decision"], "NO-GO")
        self.assertNotEqual(migrate_report.report_exit_code(report), 0)

    def cli(self, *args):
        command = [sys.executable, str(Path(migrate_report.__file__)), str(self.original),
                   "--migrated-project", str(self.candidate), "--json",
                   "--baseline-command", json.dumps(self.command), "--migration-command", json.dumps(self.command), *args]
        process = subprocess.run(command, capture_output=True, timeout=15, check=False)
        return process, json.loads(process.stdout)

    def test_static_assessment_does_not_launch_a_runtime_or_recommend_go(self):
        marker = self.root / "executed"
        self.sources(f"require('fs').writeFileSync({json.dumps(str(marker))},'bad');")
        result = self.generate(execute=False, migration_command=[str(self.root / "missing"), "{test}"])
        self.assertEqual(result["workflow_status"], "ASSESSED")
        self.assertIsNone(result["validation"])
        self.assertFalse(marker.exists())
        self.assert_blocked(result)

    def test_passing_project_connects_observations_to_scoped_decision(self):
        self.sources("console.log(6*7);", "console.log(41+1);")
        result = self.generate()
        self.assertEqual(result["workflow_status"], "VALIDATED", result["errors"])
        self.assertEqual(result["executive_summary"]["go_decision"], "GO")
        self.assertTrue(result["input_binding_verified"])
        self.assertEqual(result["inputs"], result["validation"]["inputs"])
        self.assertEqual(result["confidence"]["data_inputs"]["validation_pass_rate"], 1)
        self.assertFalse(result["release_certification"])
        self.assertFalse(result["rollout_plan"]["execution_authorized"])
        self.assertEqual([p["status"] for p in result["rollout_plan"]["phases"]],
                         ["eligible_for_evaluation", "not_evaluated", "not_evaluated", "not_evaluated"])

    def test_console_divergence_overrides_clean_static_assessment(self):
        self.sources("console.log('reference');", "console.log('wrong');")
        result = self.generate()
        self.assertEqual(result["workflow_status"], "BLOCKED")
        self.assertEqual(result["validation"]["summary"]["failed"], 1)
        self.assertFalse(result["confidence"]["go_decision"]["proceed"])
        self.assert_blocked(result)

    def test_filesystem_only_failure_is_captured_and_replays(self):
        self.sources("require('fs').writeFileSync('data','one');",
                     "require('fs').writeFileSync('data','two');")
        result = self.generate(compare_filesystem=True, failure_dir=self.root / "failures")
        self.assert_blocked(result)
        artifact = result["failure_artifact"]
        self.assertEqual(artifact["status"], "captured", result["errors"])
        path = Path(artifact["path"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        capsule = replay.load_replay(path)
        self.assertEqual(capsule["expected"]["inputs"], result["inputs"])
        repeated = replay.replay_migration(capsule, execute=True, baseline_command=self.command,
                                           migration_command=self.command, expected_sha256=artifact["content_sha256"])
        self.assertEqual(repeated["verdict"], "REPRODUCED")
        self.assertEqual(repeated["observed_validation_verdict"], "FAIL")
        self.assertFalse((self.original / "data").exists())
        self.assertFalse((self.candidate / "data").exists())

    def test_no_failure_capture_for_a_passing_run(self):
        self.sources()
        result = self.generate(failure_dir=self.root / "failures")
        self.assertEqual(result["workflow_status"], "VALIDATED")
        self.assertEqual(result["failure_artifact"]["status"], "not_needed")
        self.assertFalse((self.root / "failures").exists())

    def test_no_tests_cannot_produce_go_or_a_fake_capsule(self):
        result = self.generate(failure_dir=self.root / "failures")
        self.assertEqual(result["validation"]["summary"]["verdict"], "NO_TESTS")
        self.assertEqual(result["failure_artifact"]["status"], "unavailable")
        self.assert_blocked(result)

    def test_missing_runtime_retains_assessment_and_fails_closed(self):
        self.sources()
        result = self.generate(migration_command=[str(self.root / "absent"), "{test}"])
        self.assertEqual(result["workflow_status"], "ERROR")
        self.assertIn("scan", result)
        self.assertIn("not found", result["errors"][0]["message"])
        self.assert_blocked(result)

    def test_failed_execution_with_matching_empty_output_never_passes(self):
        self.sources("process.exit(7);")
        result = self.generate()
        self.assertEqual(result["validation"]["summary"]["verdict"], "FAIL")
        self.assert_blocked(result)

    def test_timeout_keeps_execution_evidence_but_cannot_pass(self):
        self.sources("setInterval(()=>{},1000);")
        result = self.generate(timeout_seconds=.15)
        self.assertEqual(result["validation"]["validation_results"][0]["baseline"]["termination"], "timeout")
        self.assert_blocked(result)

    def test_output_limit_cannot_become_a_matching_prefix_pass(self):
        self.sources("process.stdout.write('x'.repeat(100000));")
        result = self.generate(max_output_bytes=1024)
        self.assertEqual(result["validation"]["validation_results"][0]["migration"]["termination"], "output_limit")
        self.assert_blocked(result)

    def test_critical_candidate_risk_still_blocks_with_passing_tests(self):
        self.sources("console.log(42);", "console.log(eval('42'));")
        result = self.generate()
        self.assertEqual(result["validation"]["summary"]["verdict"], "PASS")
        self.assertGreater(result["candidate_assessment"]["scan"]["summary"]["risk_distribution"]["critical"], 0)
        self.assert_blocked(result)

    def test_review_gate_agrees_across_confidence_executive_and_rollout(self):
        self.sources("console.log(process.env.NODE_ENV);")
        result = self.generate()
        self.assertEqual(result["validation"]["summary"]["verdict"], "PASS")
        self.assertGreaterEqual(result["confidence"]["confidence"]["confidence_score"], 50)
        self.assert_blocked(result)
        self.assertFalse(result["confidence"]["go_decision"]["proceed"])
        self.assertFalse(result["rollout_plan"]["validation_gate"]["passed"])
        self.assertEqual(result["executive_summary"]["blocking_reasons"],
                         result["confidence"]["go_decision"]["blocking_reasons"])

    def test_failure_capsule_uses_pre_execution_not_later_source_tree(self):
        source = self.candidate / "app.test.js"
        # A deliberate absolute-path side effect demonstrates the documented
        # non-sandbox boundary without changing the captured execution input.
        mutation = f"require('fs').writeFileSync({json.dumps(str(source))},'console.log(1);'); console.log(2);"
        self.sources("console.log(1);", mutation)
        result = self.generate(failure_dir=self.root / "failures")
        self.assert_blocked(result)
        self.assertEqual(source.read_text(), "console.log(1);")
        capsule = replay.load_replay(Path(result["failure_artifact"]["path"]))
        snapshots = replay.validate_capsule(capsule)
        saved = next(entry.data for entry in snapshots["migration"] if entry.path == "app.test.js")
        self.assertEqual(saved, mutation.encode())
        repeated = replay.replay_migration(capsule, execute=True, baseline_command=self.command,
                                           migration_command=self.command)
        self.assertEqual(repeated["verdict"], "REPRODUCED")

    def test_candidate_risk_not_obsolete_original_risk_governs_decision(self):
        self.sources("console.log(eval('42'));", "console.log(42);")
        result = self.generate()
        self.assertGreater(result["scan"]["summary"]["risk_distribution"]["critical"], 0)
        self.assertEqual(result["candidate_assessment"]["scan"]["summary"]["risk_distribution"]["critical"], 0)
        self.assertEqual(result["workflow_status"], "VALIDATED")
        self.assertFalse(result["rewrite_suggestions"]["applied"])

    def test_monorepo_native_optional_dependency_blocks_readiness(self):
        self.sources()
        package = self.candidate / "packages/worker"
        package.mkdir(parents=True)
        (package / "package.json").write_text(json.dumps({"optionalDependencies": {"sharp": "1"}}))
        result = self.generate()
        self.assertEqual(result["validation"]["summary"]["verdict"], "PASS")
        dependency = result["candidate_assessment"]["scan"]["dependencies"][0]
        self.assertEqual(dependency["manifest"], "packages/worker/package.json")
        self.assertTrue(dependency["has_native_addon"])
        self.assert_blocked(result)

    def test_malformed_package_manifest_is_not_silently_scored_clean(self):
        self.sources()
        for content in ('{bad}', '[]', '{"dependencies":[]}', '{"dependencies":{"x":1}}',
                        '{"dependencies":{},"dependencies":{}}'):
            with self.subTest(content=content):
                (self.candidate / "package.json").write_text(content)
                result = self.generate()
                self.assertEqual(result["workflow_status"], "ERROR")
                self.assertIsNone(result["validation"])
                self.assert_blocked(result)

    def test_unreadable_source_encoding_does_not_disappear_from_assessment(self):
        self.sources()
        (self.candidate / "broken.js").write_bytes(b"\xff")
        result = self.generate()
        self.assertEqual(result["workflow_status"], "ERROR")
        self.assert_blocked(result)

    def test_failure_capture_requires_execution_consent(self):
        self.sources()
        result = self.generate(execute=False, failure_dir=self.root / "failures")
        self.assertEqual(result["workflow_status"], "ERROR")
        self.assertFalse((self.root / "failures").exists())

    def test_existing_failure_directory_is_refused_before_execution(self):
        marker = self.root / "executed"
        self.sources(f"require('fs').writeFileSync({json.dumps(str(marker))},'bad');")
        directory = self.root / "failures"
        directory.mkdir()
        (directory / "keep").write_text("precious")
        result = self.generate(failure_dir=directory)
        self.assertEqual(result["workflow_status"], "ERROR")
        self.assertFalse(marker.exists())
        self.assertEqual((directory / "keep").read_text(), "precious")

    def test_output_inside_project_is_refused_before_execution(self):
        self.sources()
        result = self.generate(failure_dir=self.original / "new-evidence")
        self.assertEqual(result["workflow_status"], "ERROR")
        self.assertIn("outside captured", result["errors"][0]["message"])

    def test_raw_guest_output_is_not_embedded_in_enterprise_report(self):
        secret = "REPORT-PRIVATE-CONTENT-7ef98bb1"
        self.sources(f"console.log('{secret}');")
        result = self.generate()
        self.assertNotIn(secret, json.dumps(result))
        observed = result["validation"]["validation_results"][0]["baseline"]["streams"]["stdout"]
        self.assertEqual(observed["sha256"], hashlib.sha256((secret + "\n").encode()).hexdigest())

    def test_cli_html_report_is_private_escaped_and_retains_failure_exit(self):
        self.sources("console.log(1);", "console.log(2);")
        output = self.root / "report.html"
        process, report = self.cli("--execute", "--format", "html", "--out", str(output))
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertIn("NO-GO", output.read_text())
        report["executive_summary"]["project"] = '<script>alert("x")</script>'
        rendered = migrate_report.render_html(report)
        self.assertNotIn('<script>', rendered)
        self.assertIn('&lt;script&gt;', rendered)

    def test_cli_passes_only_after_execution(self):
        self.sources()
        process, report = self.cli()
        self.assertEqual(process.returncode, 2)
        self.assertEqual(report["workflow_status"], "ASSESSED")
        process, report = self.cli("--execute")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(report["workflow_status"], "VALIDATED")

    def test_cli_output_preflight_precedes_guest_execution(self):
        marker = self.root / "executed"
        self.sources(f"require('fs').writeFileSync({json.dumps(str(marker))},'bad');")
        output = self.root / "existing.json"
        output.write_text("preserve me")
        process, report = self.cli("--execute", "--out", str(output))
        self.assertEqual(process.returncode, 2)
        self.assertFalse(marker.exists())
        self.assertEqual(output.read_text(), "preserve me")

    def test_publish_race_cannot_overwrite_a_newly_created_destination(self):
        self.sources()
        report = self.generate()
        path = self.root / "report.json"
        migrate_report.preflight_destinations([self.original, self.candidate], path)
        path.write_text("another writer")
        with self.assertRaises(FileExistsError):
            migrate_report.write_new_report(report, path)
        self.assertEqual(path.read_text(), "another writer")

    def test_cli_overlapping_destinations_are_refused(self):
        self.sources()
        destination = self.root / "shared"
        process, report = self.cli("--execute", "--out", str(destination), "--failure-dir", str(destination))
        self.assertEqual(process.returncode, 2)
        self.assertIn("non-overlapping", report["error"])
        self.assertFalse(destination.exists())

    def test_bad_input_inventory_preserves_validation_error(self):
        self.sources()
        (self.candidate / "extra.test.js").write_text("console.log(1);")
        result = self.generate(failure_dir=self.root / "failures")
        self.assertEqual(result["workflow_status"], "ERROR")
        self.assertEqual(result["validation"]["test_discovery"]["missing_baseline"], ["extra.test.js"])
        self.assertEqual(result["failure_artifact"]["status"], "unavailable")
        self.assert_blocked(result)


if __name__ == "__main__":
    unittest.main()
