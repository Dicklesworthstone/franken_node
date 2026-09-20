"""Real process evidence for opt-in migration bundles, not native parity."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import shutil
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

    def replay(self, digest=None, **kwargs):
        return runner.replay_captured_bundle(self.bundle,
            expected_sha256=digest or hashlib.sha256(self.bundle.read_bytes()).hexdigest(),
            baseline_command=kwargs.pop("baseline_command", self.command),
            migration_command=kwargs.pop("migration_command", self.command), **kwargs)

    def rewrite_archive(self, transform):
        with zipfile.ZipFile(self.bundle) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        manifest = json.loads(members["manifest.json"])
        transform(manifest, members)
        members["manifest.json"] = json.dumps(manifest).encode()
        with zipfile.ZipFile(self.bundle, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, content in members.items():
                archive.writestr(name, content)

    def test_round_trip_reexecutes_failure_after_original_projects_are_gone(self):
        (self.after / "case.test.js").write_text("print('different')\n")
        report = self.execute(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        self.before.rename(self.root / "retired-before")
        self.after.rename(self.root / "retired-after")
        result = self.replay(report["replay_bundle"]["sha256"])
        self.assertEqual(result["replay_outcome"], "REPRODUCED", result)
        self.assertEqual(result["execution"]["summary"]["verdict"], "FAIL")
        self.assertEqual(result["execution"]["inputs"], report["inputs"])
        self.assertTrue(result["execution"]["runtime_identity_rechecked"])
        self.assertFalse(result["release_certification"])

    def test_reexecution_observes_new_external_effects_not_just_recorded_results(self):
        marker = self.root / "external-counter"
        marker.write_text("0")
        source = ("from pathlib import Path\n" + f"p=Path({str(marker)!r})\n"
                  "n=int(p.read_text())+1\np.write_text(str(n))\nprint(n)\n")
        for root in (self.before, self.after):
            (root / "case.test.js").write_text(source)
        report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "FAIL")
        self.assertEqual(marker.read_text(), "2")
        result = self.replay()
        self.assertEqual(marker.read_text(), "4")
        self.assertEqual(result["replay_outcome"], "CHANGED", result)
        self.assertFalse(result["ambient_effects_replayable"])

    def test_matching_nonzero_exits_reproduce_failure_not_compatibility_success(self):
        for root in (self.before, self.after):
            (root / "case.test.js").write_text("raise SystemExit(7)\n")
        self.assertEqual(self.execute()["summary"]["verdict"], "FAIL")
        result = self.replay()
        self.assertEqual(result["replay_outcome"], "REPRODUCED", result)
        self.assertEqual(result["execution"]["summary"]["passed"], 0)
        self.assertEqual(result["execution"]["summary"]["verdict"], "FAIL")

    def test_replay_restores_binary_stdin_environment_cwd_and_workspace_effects(self):
        for root in (self.before, self.after):
            (root / "package").mkdir()
            (root / "package/check.js").write_text("import os,sys\nfrom pathlib import Path\n"
                "data=sys.stdin.buffer.read()\nPath('result').write_bytes(data)\n"
                "sys.stdout.buffer.write(data)\nprint(os.getenv('APP_MODE'))\n")
            (root / "input").write_bytes(b"\x00\xff\n")
            (root / ".franken-node").mkdir()
            (root / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps({
                "schema_version": runner.MIGRATION_TEST_SCHEMA, "tests": ["package/check.js"],
                "execution": {"package/check.js": {"cwd": "package", "stdin": "input",
                                                       "environment": {"APP_MODE": "captured"}}}}))
        self.assertEqual(self.execute(compare_filesystem=True)["summary"]["verdict"], "PASS")
        result = self.replay()
        self.assertEqual(result["replay_outcome"], "REPRODUCED", result)
        self.assertEqual(result["execution"]["summary"]["verdict"], "PASS")
        self.assertFalse((self.before / "package/result").exists())

    def test_contained_symlink_chain_and_directory_link_replay(self):
        for root in (self.before, self.after):
            (root / "package").mkdir()
            (root / "package/data").write_bytes(b"payload")
            (root / "first").symlink_to("package/data")
            (root / "second").symlink_to("first")
            (root / "dirlink").symlink_to("package", target_is_directory=True)
            (root / "rootlink").symlink_to(".", target_is_directory=True)
            (root / "case.test.js").write_text("from pathlib import Path\n"
                "assert Path('second').read_bytes()==Path('dirlink/data').read_bytes()\n"
                "assert Path('rootlink/first').read_bytes()==b'payload'\nprint('ok')\n")
        self.assertEqual(self.execute()["summary"]["verdict"], "PASS")
        result = self.replay()
        self.assertEqual(result["replay_outcome"], "REPRODUCED", result)

    def test_wrong_or_missing_external_digest_prevents_staging_and_execution(self):
        self.execute()
        with patch.object(runner, "stage_project", side_effect=AssertionError("must not stage")):
            for digest in ("0" * 64, "bad", None):
                result = runner.replay_captured_bundle(self.bundle, expected_sha256=digest,
                    baseline_command=self.command, migration_command=self.command)
                self.assertEqual(result["replay_outcome"], "ERROR", result)

    def test_environment_drift_is_rejected_before_any_guest_execution(self):
        self.execute()
        with patch.dict(os.environ, {"APP_NEW_ENVIRONMENT": "different"}), patch.object(
                runner, "run_command", side_effect=AssertionError("must not execute")):
            result = self.replay()
        self.assertEqual(result["replay_outcome"], "ERROR", result)
        self.assertIn("environment differs", result["errors"][0]["message"])

    def test_caller_cannot_change_runtime_arguments_while_calling_it_replay(self):
        self.execute()
        with patch.object(runner, "run_command", side_effect=AssertionError("must not execute")):
            result = self.replay(baseline_command=[sys.executable, "-S", "{test}"])
        self.assertEqual(result["replay_outcome"], "ERROR", result)
        self.assertIn("arguments differ", result["errors"][0]["message"])

    def test_relocated_runtime_bytes_are_accepted_but_changed_runtime_is_not(self):
        runtime = self.root / "runtime"
        runtime.write_text("#!/bin/sh\nexec " + sys.executable + " \"$@\"\n")
        runtime.chmod(0o700)
        self.command = [str(runtime), "{test}"]
        self.assertEqual(self.execute()["summary"]["verdict"], "PASS")
        moved = self.root / "relocated-runtime"
        runtime.rename(moved)
        relocated = [str(moved), "{test}"]
        self.assertEqual(self.replay(baseline_command=relocated, migration_command=relocated)["replay_outcome"], "REPRODUCED")
        moved.write_text(moved.read_text() + "# changed binary bytes\n")
        with patch.object(runner, "run_command", side_effect=AssertionError("must not execute")):
            result = self.replay(baseline_command=relocated, migration_command=relocated)
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("executable identity differs", result["errors"][0]["message"])

    def test_inspection_never_runs_commands_or_exposes_raw_output(self):
        self.execute()
        with patch.object(runner, "run_command", side_effect=AssertionError("must not execute")):
            result = runner.inspect_replay_bundle(self.bundle)
        self.assertTrue(result["integrity_verified"])
        self.assertFalse(result["matches_expected_digest"])
        self.assertFalse(result["authenticated"])
        self.assertNotIn("same", json.dumps(result))

    def test_inspectable_incomplete_suite_is_not_reexecuted_as_complete_evidence(self):
        with patch.object(runner, "run_command", side_effect=OSError("launch failed")):
            self.execute()
        self.assertEqual(runner.inspect_replay_bundle(self.bundle)["original_summary"]["verdict"], "ERROR")
        with patch.object(runner, "run_command", side_effect=AssertionError("must not execute")):
            result = self.replay()
        self.assertEqual(result["replay_outcome"], "ERROR")

    def test_changed_object_bytes_are_rejected_even_with_a_new_outer_digest(self):
        self.execute()
        def change(manifest, members):
            digest = manifest["observations"][0]["stdout"]
            members[f"objects/{digest}"] = b"evil\n"
        self.rewrite_archive(change)
        with patch.object(runner, "stage_project", side_effect=AssertionError("must not stage")):
            result = self.replay()
        self.assertEqual(result["replay_outcome"], "ERROR", result)
        self.assertIn("content hash mismatch", result["errors"][0]["message"])

    def test_traversal_absolute_duplicate_and_missing_parent_paths_fail_closed(self):
        self.execute()
        original = self.bundle.read_bytes()
        for path in ("../outside", "/absolute", "a/../../outside", "missing/child", "./case.test.js"):
            self.bundle.write_bytes(original)
            self.rewrite_archive(lambda manifest, members: manifest["snapshots"]["baseline"][0].update(path=path))
            with self.subTest(path=path), patch.object(runner, "stage_project", side_effect=AssertionError("must not stage")):
                self.assertEqual(self.replay()["replay_outcome"], "ERROR")
        self.bundle.write_bytes(original)
        self.rewrite_archive(lambda manifest, members: manifest["snapshots"]["baseline"].append(manifest["snapshots"]["baseline"][0]))
        self.assertEqual(self.replay()["replay_outcome"], "ERROR")

    def test_escaping_cyclic_missing_and_file_traversing_links_fail_before_staging(self):
        self.execute()
        original = self.bundle.read_bytes()
        for target in ("../outside", "/tmp/outside", "badlink", "missing", ".git", "case.test.js/../case.test.js"):
            self.bundle.write_bytes(original)
            self.rewrite_archive(lambda manifest, members: manifest["snapshots"]["baseline"].append(
                {"path": "badlink", "mode": 0o777, "kind": "link", "target": target}))
            with self.subTest(target=target), patch.object(runner, "stage_project", side_effect=AssertionError("must not stage")):
                self.assertEqual(self.replay()["replay_outcome"], "ERROR")

    def test_child_beneath_a_symlink_is_rejected_before_staging(self):
        self.execute()
        def change(manifest, members):
            entries = manifest["snapshots"]["baseline"]
            entries.extend([{"path": "alias", "mode": 0o777, "kind": "link", "target": "."},
                            {**entries[0], "path": "alias/child.js"}])
        self.rewrite_archive(change)
        with patch.object(runner, "stage_project", side_effect=AssertionError("must not stage")):
            self.assertEqual(self.replay()["replay_outcome"], "ERROR")

    def test_reordered_or_changed_captured_inputs_fail_the_recorded_identity(self):
        self.execute()
        self.rewrite_archive(lambda manifest, members: manifest["snapshots"]["baseline"][0].update(mode=0o700))
        with patch.object(runner, "stage_project", side_effect=AssertionError("must not stage")):
            result = self.replay()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("snapshot identity mismatch", result["errors"][0]["message"])

    def test_output_accounting_and_extra_objects_cannot_be_smuggled(self):
        self.execute()
        original = self.bundle.read_bytes()
        self.rewrite_archive(lambda manifest, members: manifest["report"]["validation_results"][0]["baseline"]["streams"]["stdout"].update(retained_bytes=1))
        self.assertEqual(self.replay()["replay_outcome"], "ERROR")
        self.bundle.write_bytes(original)
        def add_object(manifest, members):
            data = b"unreferenced hidden object"
            digest = hashlib.sha256(data).hexdigest()
            manifest["objects"][digest] = len(data)
            members[f"objects/{digest}"] = data
        self.rewrite_archive(add_object)
        self.assertEqual(self.replay()["replay_outcome"], "ERROR")

    def test_zip_duplicates_compression_and_trailing_data_are_rejected(self):
        self.execute()
        original = self.bundle.read_bytes()
        with zipfile.ZipFile(self.bundle) as archive:
            entries = [(name, archive.read(name)) for name in archive.namelist()]
        for variant in ("duplicate", "compressed", "trailing"):
            with self.subTest(variant=variant):
                with zipfile.ZipFile(self.bundle, "w", compression=zipfile.ZIP_DEFLATED if variant == "compressed" else zipfile.ZIP_STORED) as archive:
                    for name, data in entries:
                        archive.writestr(name, data)
                    if variant == "duplicate":
                        with self.assertWarns(UserWarning):
                            archive.writestr(entries[0][0], entries[0][1])
                if variant == "trailing":
                    with self.bundle.open("ab") as stream:
                        stream.write(b"trailing")
                self.assertEqual(self.replay()["replay_outcome"], "ERROR")
        self.bundle.write_bytes(original)

    def test_zip_directory_budget_is_checked_before_zipfile_allocation(self):
        self.execute()
        with patch.object(runner, "MAX_REPLAY_OBJECTS", 0), patch.object(
                runner.zipfile, "ZipFile", side_effect=AssertionError("must not parse archive")):
            with self.assertRaises(ValueError):
                runner.read_replay_bundle(self.bundle)

    def test_duplicate_json_keys_and_nonfinite_manifest_values_are_rejected(self):
        self.execute()
        with zipfile.ZipFile(self.bundle) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        for raw in (b'{"objects":{},"objects":{}}', b'{"objects":NaN}', b'['*1100+b']'*1100):
            with zipfile.ZipFile(self.bundle, "w") as archive:
                for name, data in entries.items():
                    archive.writestr(name, raw if name == "manifest.json" else data)
            self.assertEqual(self.replay()["replay_outcome"], "ERROR")

    def test_cli_requires_explicit_execution_authority_and_preserves_failure_verdict(self):
        (self.after / "case.test.js").write_text("print('changed')\n")
        report = self.execute()
        prefix = [sys.executable, str(SOURCE), "--replay-bundle", str(self.bundle), "--json"]
        missing = subprocess.run(prefix, capture_output=True, check=False, timeout=10)
        self.assertEqual(missing.returncode, 2)
        full = prefix + ["--expected-bundle-sha256", report["replay_bundle"]["sha256"],
            "--baseline-command", json.dumps(self.command), "--migration-command", json.dumps(self.command)]
        completed = subprocess.run(full, capture_output=True, check=False, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["replay_outcome"], "REPRODUCED", result)
        self.assertEqual(result["execution"]["summary"]["verdict"], "FAIL")
        blocked = subprocess.run(full + ["--out", str(self.bundle)], capture_output=True, check=False, timeout=10)
        self.assertEqual(blocked.returncode, 2)

    def test_inspection_cli_verifies_without_a_runtime_and_rejects_corruption(self):
        self.execute()
        command = [sys.executable, str(SOURCE), "--inspect-bundle", str(self.bundle), "--json"]
        completed = subprocess.run(command, capture_output=True, check=False, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(json.loads(completed.stdout)["executable"])
        self.bundle.write_bytes(b"not an archive")
        completed = subprocess.run(command, capture_output=True, check=False, timeout=10)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["errors"])

    def test_output_budget_exhaustion_does_not_publish_an_unreadable_partial_archive(self):
        # One shared source fits; the first distinct output cannot fit.
        with patch.object(runner, "MAX_REPLAY_OBJECTS", 1):
            result = self.execute()
        self.assertEqual(result["summary"]["verdict"], "ERROR")
        self.assertFalse(self.bundle.exists())
        self.assertNotIn("replay_bundle", result)
        self.assertEqual(result["validation_results"][0]["baseline"]["exit_code"], 0)

    def test_bundle_reader_refuses_symlink_and_fifo_inputs_without_blocking(self):
        self.execute()
        alias = self.root / "bundle-link"
        alias.symlink_to(self.bundle)
        with self.assertRaises(OSError):
            runner.read_replay_bundle(alias)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            runner.read_replay_bundle(fifo)

    def test_summary_cannot_claim_more_successes_than_recorded_cases(self):
        self.execute()
        self.rewrite_archive(lambda manifest, members: manifest["report"]["summary"].update(passed=999))
        with patch.object(runner, "run_command", side_effect=AssertionError("must not execute")):
            self.assertEqual(self.replay()["replay_outcome"], "ERROR")

    def test_same_runtime_name_with_different_bytes_is_not_accepted_by_recorded_name(self):
        self.execute()
        self.rewrite_archive(lambda manifest, members: manifest["report"]["runtime_identities"]["baseline"].update(sha256="0"*64))
        with patch.object(runner, "run_command", side_effect=AssertionError("must not execute")):
            result = self.replay()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("executable identity differs", result["errors"][0]["message"])

    def test_environment_is_checked_again_after_staging_before_first_launch(self):
        self.execute()
        real_stage = runner.stage_project
        def stage_and_change(*args, **kwargs):
            real_stage(*args, **kwargs)
            os.environ["APP_LATE_ENV_DRIFT"] = "changed during recovery"
        with patch.dict(os.environ), patch.object(runner, "stage_project", side_effect=stage_and_change), patch.object(
                runner, "run_command", side_effect=AssertionError("must not execute")):
            result = self.replay()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("environment differs", result["errors"][0]["message"])

    @unittest.skipUnless(shutil.which("node"), "real Node executable required")
    def test_real_javascript_reexecutes_from_captured_code_and_dependencies(self):
        self.command = [shutil.which("node"), "{test}"]
        for root, value in ((self.before, "before"), (self.after, "after")):
            dependency = root / "node_modules/local-dependency"
            dependency.mkdir(parents=True)
            (dependency / "index.js").write_text(f"module.exports={value!r};\n")
            (root / "case.test.js").write_text("const fs=require('fs');"
                "const value=require('local-dependency');fs.writeFileSync('output',value);console.log(value);\n")
        report = self.execute(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "FAIL", report)
        (self.before / "node_modules/local-dependency/index.js").write_text("throw Error('live dependency used')")
        result = self.replay()
        self.assertEqual(result["replay_outcome"], "REPRODUCED", result)
        self.assertEqual(result["execution"]["summary"]["verdict"], "FAIL")
        self.assertTrue(result["execution"]["filesystem_comparison"])

    def test_snapshot_byte_limit_counts_repeated_content_not_only_unique_objects(self):
        (self.before / "a").write_bytes(b"123456789")
        (self.after / "a").write_bytes(b"123456789")
        self.execute()
        with patch.object(runner, "MAX_PROJECT_BYTES", 18):
            result = self.replay()
        self.assertEqual(result["replay_outcome"], "ERROR")
        self.assertIn("snapshot exceeds", result["errors"][0]["message"])

    def test_cli_null_command_is_not_silently_replaced_by_a_default_runtime(self):
        for option in ("--baseline-command", "--migration-command"):
            completed = subprocess.run([sys.executable, str(SOURCE), str(self.before), option, "null", "--json"],
                capture_output=True, check=False, timeout=10)
            self.assertEqual(completed.returncode, 2)
            self.assertIn(b"JSON argv array", completed.stderr)
            self.assertEqual(completed.stdout, b"")


if __name__ == "__main__":
    unittest.main()