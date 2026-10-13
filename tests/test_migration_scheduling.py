"""Bounded migration scheduling with real processes and portable evidence.

Python/Python and Node/Node pairs test orchestration, not native-engine parity.
Rendezvous fixtures use explicit external test directories; this is not a sandbox.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import migration_validation_runner as runner

COMMAND = (sys.executable, "{test}", "{arguments}")


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="migration-scheduler-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()

    def setup_project(self, *, count=4, concurrency=2, source="print('ok')\n", project=None):
        project = project or self.project
        project.mkdir(exist_ok=True)
        tests = [f"case-{index}.cjs" for index in range(count)]
        for index, test in enumerate(tests):
            (project / test).write_text(source(index) if callable(source) else source, encoding="utf-8")
        (project / ".franken-node").mkdir(exist_ok=True)
        manifest = {"schema_version": runner.MIGRATION_TEST_SCHEMA, "tests": tests}
        if concurrency is not None:
            manifest["max_concurrent_tests"] = concurrency
        self.set_manifest(manifest, project)
        return manifest

    def set_manifest(self, manifest, project=None):
        ((project or self.project) / runner.MIGRATION_TEST_MANIFEST).write_text(
            json.dumps(manifest), encoding="utf-8")

    def validate(self, **kwargs):
        return runner.validate_project(self.project,
            baseline_command=kwargs.pop("baseline_command", COMMAND),
            migration_command=kwargs.pop("migration_command", COMMAND),
            timeout_seconds=kwargs.pop("timeout_seconds", 4),
            total_timeout_seconds=kwargs.pop("total_timeout_seconds", 20), **kwargs)

    def assert_accounting(self, report):
        summary = report["summary"]
        self.assertEqual(summary["total_tests"], sum(summary[name] for name in
                         ("passed", "failed", "errored", "skipped")))
        self.assertEqual(len(report["validation_results"]), summary["total_tests"] - summary["skipped"])
        for status, counter in (("PASS", "passed"), ("FAIL", "failed"), ("ERROR", "errored")):
            self.assertEqual(summary[counter], sum(row["status"] == status for row in report["validation_results"]))
        self.assertEqual([row["test"] for row in report["validation_results"]],
                         sorted(row["test"] for row in report["validation_results"]))

    def test_default_schedule_preserves_serial_pair_order(self):
        self.setup_project(count=3, concurrency=None)
        calls = []
        original = runner.run_command
        def observe(command, cwd, **kwargs):
            calls.append((Path(command[1]).name, cwd.name))
            return original(command, cwd, **kwargs)
        with mock.patch.object(runner, "run_command", side_effect=observe):
            report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertEqual(calls, [(f"case-{i}.cjs", leg) for i in range(3) for leg in ("baseline", "migration")])
        self.assertEqual(report["scheduling"]["max_concurrent_tests"], 1)
        self.assert_accounting(report)

    def test_invalid_concurrency_never_launches_and_never_coerces_bool(self):
        for value in [0, -1, 5, 999999, True, False, 2.0, "2", [], {}]:
            with self.subTest(value=value):
                manifest = self.setup_project(count=1)
                manifest["max_concurrent_tests"] = value
                self.set_manifest(manifest)
                with mock.patch.object(runner, "run_command") as launch:
                    report = self.validate()
                launch.assert_not_called()
                self.assertEqual(report["summary"]["verdict"], "ERROR")
                self.assertIn("max_concurrent_tests", report["errors"][0]["message"])

    def test_null_concurrency_is_not_omission(self):
        manifest = self.setup_project(count=1)
        manifest["max_concurrent_tests"] = None
        self.set_manifest(manifest)
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "ERROR")

    def test_candidate_cannot_change_permission_to_overlap_tests(self):
        self.setup_project(count=1, concurrency=1)
        candidate = self.root / "candidate"
        self.setup_project(count=1, concurrency=2, project=candidate)
        with mock.patch.object(runner, "run_command") as launch:
            report = self.validate(migrated_project=candidate)
        launch.assert_not_called()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("concurrency differs", report["errors"][0]["message"])

    def test_late_invalid_arguments_are_rejected_before_parallel_admission(self):
        manifest = self.setup_project(count=4, concurrency=4)
        manifest["execution"] = {"case-3.cjs": {"arguments": ["request"]}}
        self.set_manifest(manifest)
        with mock.patch.object(runner, "run_command") as launch:
            report = self.validate(migration_command=(sys.executable, "{test}"))
        launch.assert_not_called()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(report["validation_results"], [])

    @unittest.skipUnless(shutil.which("node"), "real Node executable unavailable")
    def test_real_node_processes_rendezvous_only_with_actual_overlap(self):
        rendezvous = self.root / "rendezvous"
        rendezvous.mkdir()
        source = lambda index: (
            "const fs = require('node:fs');\n"
            f"const root = {json.dumps(str(rendezvous))};\n"
            "const role = require('node:path').basename(process.cwd());\n"
            f"fs.writeFileSync(root + '/' + role + '-{index}', 'ready');\n"
            "const until = Date.now() + 2500;\n"
            "while (fs.readdirSync(root).filter(p => p.startsWith(role)).length < 2) {\n"
            " if (Date.now() >= until) throw new Error('no concurrent peer');\n"
            " Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);\n"
            "}\nconsole.log('both running');\n")
        self.setup_project(count=2, concurrency=2, source=source)
        command = (shutil.which("node"), "{test}", "{arguments}")
        report = self.validate(baseline_command=command, migration_command=command)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertEqual(len(list(rendezvous.iterdir())), 4)
        for row in report["validation_results"]:
            self.assertEqual(row["baseline"]["streams"]["stdout"]["sha256"],
                             hashlib.sha256(b"both running\n").hexdigest())
        self.assert_accounting(report)

    def test_worker_limit_and_test_pair_order_hold_across_replenished_windows(self):
        self.setup_project(count=8, concurrency=4)
        barrier = threading.Barrier(4)
        lock = threading.Lock()
        active = 0
        peak = 0
        phases = {}
        original = runner.run_command
        def observe(command, cwd, **kwargs):
            nonlocal active, peak
            test = Path(command[1]).name
            with lock:
                active += 1
                peak = max(peak, active)
                phases.setdefault(test, []).append(cwd.name)
            try:
                if cwd.name == "baseline":
                    barrier.wait(timeout=4)
                return original(command, cwd, **kwargs)
            finally:
                with lock:
                    active -= 1
        with mock.patch.object(runner, "run_command", side_effect=observe):
            report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertEqual(peak, 4)
        self.assertEqual(active, 0)
        self.assertTrue(all(order == ["baseline", "migration"] for order in phases.values()))
        self.assertEqual(len(phases), 8)
        self.assert_accounting(report)

    def test_out_of_order_completion_retains_lexical_result_identity(self):
        self.setup_project(concurrency=4, source=lambda i: f"import time\ntime.sleep({(3-i)*0.04})\nprint({i})\n")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assert_accounting(report)
        for i, row in enumerate(report["validation_results"]):
            self.assertEqual(row["baseline"]["streams"]["stdout"]["sha256"],
                             hashlib.sha256(f"{i}\n".encode()).hexdigest())

    def test_parallel_workspaces_arguments_environment_stdin_and_oracles_remain_isolated(self):
        manifest = self.setup_project(count=4, concurrency=4, source=lambda i:
            "import os, pathlib, sys\n"
            f"assert sys.argv[1:] == ['{i}', '']\n"
            f"assert os.environ['APP_CASE'] == '{i}'\n"
            "assert sys.stdin.buffer.read() == b'\\x00\\xffinput'\n"
            "assert not pathlib.Path('out').exists()\n"
            f"pathlib.Path('out').write_text('{i}')\nprint({i})\n")
        (self.project / "input").write_bytes(b"\0\xffinput")
        manifest["execution"] = {}
        manifest["expectations"] = {}
        for i in range(4):
            (self.project / f"stdout-{i}").write_text(f"{i}\n")
            (self.project / f"file-{i}").write_text(str(i))
            manifest["execution"][f"case-{i}.cjs"] = {"arguments": [str(i), ""], "stdin": "input",
                                                       "environment": {"APP_CASE": str(i)}}
            manifest["expectations"][f"case-{i}.cjs"] = {"stdout": f"stdout-{i}", "files": {"out": f"file-{i}"}}
        self.set_manifest(manifest)
        report = self.validate(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertFalse((self.project / "out").exists())
        self.assert_accounting(report)

    def test_ordinary_failures_do_not_hide_later_tests_or_turn_agreement_green(self):
        manifest = self.setup_project(count=5, concurrency=2)
        (self.project / "expected").write_bytes(b"different\n")
        manifest["expectations"] = {"case-0.cjs": {"stdout": "expected"}}
        self.set_manifest(manifest)
        report = self.validate()
        self.assertEqual(report["summary"], {"total_tests": 5, "passed": 4, "failed": 1,
                                           "errored": 0, "skipped": 0, "verdict": "FAIL"})
        self.assertEqual(len(report["validation_results"][0]["divergences"]), 2)
        self.assert_accounting(report)

    def test_first_infrastructure_failure_stops_refill_but_keeps_other_results(self):
        self.setup_project(count=6, concurrency=2)
        original = runner.run_command
        def fail_first(command, cwd, **kwargs):
            if command[1] == "./case-0.cjs":
                raise OSError("injected launch failure")
            time.sleep(0.06)
            return original(command, cwd, **kwargs)
        with mock.patch.object(runner, "run_command", side_effect=fail_first):
            report = self.validate(bundle_path=self.root / "partial.fnmigration")
        self.assertEqual(report["summary"]["verdict"], "ERROR", report)
        self.assertEqual(report["summary"]["skipped"], 4)
        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["summary"]["errored"], 1)
        self.assert_accounting(report)
        inspected = runner.inspect_replay_bundle(self.root / "partial.fnmigration")
        self.assertEqual(inspected["original_summary"], report["summary"])

    def test_later_leg_failure_retains_measured_baseline_and_other_pairs(self):
        self.setup_project(count=2, concurrency=2)
        original = runner.run_command
        def fail_second(command, cwd, **kwargs):
            if command[1] == "./case-0.cjs" and cwd.name == "migration":
                raise OSError("injected candidate failure")
            return original(command, cwd, **kwargs)
        path = self.root / "partial.fnmigration"
        with mock.patch.object(runner, "run_command", side_effect=fail_second):
            report = self.validate(bundle_path=path)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("baseline", report["validation_results"][0])
        self.assertNotIn("migration", report["validation_results"][0])
        self.assertEqual(len(runner.read_replay_bundle(path).manifest["observations"]), 3)
        self.assert_accounting(report)

    def test_per_leg_timeout_remains_failure_and_does_not_shrink_suite(self):
        self.setup_project(count=3, concurrency=2, source=lambda i:
                           "import time\ntime.sleep(2)\n" if i == 0 else "print('ok')\n")
        # Skip unrelated interpreter site initialization in a deliberately
        # short supervisor fixture; the sleeping guest still exceeds its cap.
        command = (sys.executable, "-S", "{test}", "{arguments}")
        report = self.validate(timeout_seconds=0.75, baseline_command=command,
                               migration_command=command)
        self.assertEqual(report["summary"]["verdict"], "FAIL", report)
        self.assertEqual(report["summary"]["passed"], 2)
        for leg in ("baseline", "migration"):
            outcome = report["validation_results"][0][leg]
            self.assertEqual(outcome["termination"], "timeout")
            self.assertFalse(outcome["streams"]["stdout"]["complete"])
        self.assert_accounting(report)

    def test_one_shared_deadline_stops_future_admission(self):
        self.setup_project(count=8, concurrency=2, source="import time\ntime.sleep(3)\n")
        report = self.validate(total_timeout_seconds=0.25, timeout_seconds=3)
        self.assertEqual(report["summary"]["verdict"], "ERROR", report)
        self.assertGreaterEqual(report["summary"]["skipped"], 6)
        self.assert_accounting(report)

    def test_parallel_bundle_replays_after_original_moves_and_keeps_contract(self):
        self.setup_project(count=4, concurrency=3)
        path = self.root / "capture.fnmigration"
        report = self.validate(bundle_path=path)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        digest = report["replay_bundle"]["sha256"]
        bundle = runner.read_replay_bundle(path, expected_sha256=digest)
        self.assertEqual(len(bundle.manifest["observations"]), 8)
        self.project.rename(self.root / "unavailable")
        replay = runner.replay_captured_bundle(path, expected_sha256=digest,
                    baseline_command=COMMAND, migration_command=COMMAND)
        self.assertEqual(replay["replay_outcome"], "REPRODUCED", replay)
        self.assertEqual(replay["execution"]["scheduling"], report["scheduling"])
        self.assertFalse(replay["execution"]["scheduling"]["interleaving_replayable"])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_advertised_schedule_cannot_be_forged_or_omitted_from_concurrent_evidence(self):
        self.setup_project(count=2, concurrency=2)
        path = self.root / "capture.fnmigration"
        report = self.validate(bundle_path=path)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        bundle = runner.read_replay_bundle(path)
        invalid = [None, {}, {**report["scheduling"], "max_concurrent_tests": 1},
                   {**report["scheduling"], "max_concurrent_tests": True},
                   {**report["scheduling"], "interleaving_replayable": True},
                   {**report["scheduling"], "unknown": 1}]
        for value in invalid:
            manifest = copy.deepcopy(bundle.manifest)
            manifest["report"]["scheduling"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner._validate_bundle_manifest(manifest, bundle.objects)
        manifest = copy.deepcopy(bundle.manifest)
        del manifest["report"]["scheduling"]
        with self.assertRaises(ValueError):
            runner._validate_bundle_manifest(manifest, bundle.objects)

    def test_historical_serial_evidence_is_not_relabelled_concurrent(self):
        self.setup_project(count=1, concurrency=None)
        path = self.root / "capture.fnmigration"
        report = self.validate(bundle_path=path)
        bundle = runner.read_replay_bundle(path)
        original = copy.deepcopy(bundle.manifest)
        del original["report"]["scheduling"]
        runner._validate_bundle_manifest(original, bundle.objects)
        self.assertEqual(runner._observation_projection(original["report"]),
                         runner._observation_projection(report))

    def test_collection_failure_joins_workers_and_refuses_partial_archive(self):
        self.setup_project(count=4, concurrency=2)
        path = self.root / "never-published.fnmigration"
        with mock.patch.object(runner.ReplayBundleWriter, "record", side_effect=OSError("disk full")):
            report = self.validate(bundle_path=path)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertFalse(path.exists())
        self.assertFalse(any(t.name.startswith("migration-test") for t in threading.enumerate()))
        self.assert_accounting(report)

    def test_identity_recheck_and_publication_happen_after_workers_join(self):
        self.setup_project(count=4, concurrency=2)
        measure = runner.measure_runtime_identities
        publish = runner.ReplayBundleWriter.publish
        phases = []
        def measured(*args):
            self.assertFalse(any(t.name.startswith("migration-test") for t in threading.enumerate()))
            phases.append("measurement")
            return measure(*args)
        def published(writer, report):
            self.assertFalse(any(t.name.startswith("migration-test") for t in threading.enumerate()))
            phases.append("publication")
            return publish(writer, report)
        with mock.patch.object(runner, "measure_runtime_identities", side_effect=measured), \
             mock.patch.object(runner.ReplayBundleWriter, "publish", published):
            report = self.validate(bundle_path=self.root / "capture.fnmigration")
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertEqual(phases, ["measurement", "measurement", "publication"])

    def test_cli_signal_drains_all_active_children_and_keeps_partial_bundle(self):
        marker = self.root / "started"
        marker.mkdir()
        self.setup_project(count=6, concurrency=2, source=lambda i:
            "import os, pathlib, time\n"
            f"pathlib.Path({str(marker / str(i))!r}).write_text(str(os.getpid()))\n"
            "print('prefix-before-cancel', flush=True)\ntime.sleep(30)\n")
        bundle = self.root / "cancelled.fnmigration"
        report_path = self.root / "cancelled.json"
        command = [sys.executable, str(Path(runner.__file__)), str(self.project),
                   "--baseline-command", json.dumps(COMMAND), "--migration-command", json.dumps(COMMAND),
                   "--bundle", str(bundle), "--out", str(report_path), "--json"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            until = time.monotonic() + 8
            while len(list(marker.iterdir())) < 2 and time.monotonic() < until and process.poll() is None:
                time.sleep(0.01)
            self.assertEqual(len(list(marker.iterdir())), 2)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 143, stderr)
            report = json.loads(stdout)
            self.assertEqual(report, json.loads(report_path.read_text()))
            self.assertEqual(report["summary"]["verdict"], "ERROR")
            self.assertEqual(report["summary"]["skipped"], 4)
            self.assert_accounting(report)
            for row in report["validation_results"]:
                self.assertEqual(row["baseline"]["termination"], "cancelled")
                self.assertFalse(row["baseline"]["streams"]["stdout"]["complete"])
                self.assertNotIn("migration", row)
            evidence = runner.read_replay_bundle(bundle)
            self.assertEqual(len(evidence.manifest["observations"]), 2)
            for entry in marker.iterdir():
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(entry.read_text()), 0)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=8)


if __name__ == "__main__":
    unittest.main()
