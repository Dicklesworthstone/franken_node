#!/usr/bin/env python3
"""Unit tests for scripts/check_verification_targets_compile.py (bd-rjc2m.G1).

Fixtures use the exact cargo `--keep-going` output format observed in the Round-0 census.
Run: python3 scripts/test_check_verification_targets_compile.py
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_verification_targets_compile import (  # noqa: E402
    _CONF_CMD,
    _FUZZ_CMD,
    parse_broken_targets,
    records_from_output,
    main,
)

CONF_FIXTURE = r"""
   Compiling frankenengine-node v0.1.0 (/data/projects/franken_node/crates/franken-node)
warning: unused import: `Foo`
error[E0599]: no method named `check` found for struct `CapabilityGate` in the current scope
error: could not compile `frankenengine-node` (test "bd_1nfu_remote_capability_gate_conformance") due to 45 previous errors; 3 warnings emitted
warning: `frankenengine-node` (test "migrate_cli_e2e") generated 6 warnings
error: could not compile `frankenengine-node` (test "rollback_bundle_conformance") due to 1 previous error
error[E0716]: temporary value dropped while borrowed
error: could not compile `frankenengine-node` (test "rollback_bundle_conformance") due to 36 previous errors
"""

FUZZ_FIXTURE = "\x1b[0m\x1b[1m\x1b[91merror\x1b[0m: could not compile `franken-node-fuzz` (bin \"fuzz_capability_token_parser\") due to 2 previous errors\n" \
    'error: could not compile `franken-node-fuzz` (bin "fuzz_ssrf_policy") due to 13 previous errors; 1 warning emitted\n'

CLEAN_FIXTURE = """
   Compiling frankenengine-node v0.1.0
    Finished `test` profile [unoptimized + debuginfo] target(s) in 10m 02s
warning: `frankenengine-node` (test "fleet_cli_e2e") generated 2 warnings
"""


class TestParser(unittest.TestCase):
    def test_parses_conformance_targets_and_dedups_max_count(self):
        got = parse_broken_targets(CONF_FIXTURE)
        names = {n: c for (n, k, c) in got}
        self.assertIn("bd_1nfu_remote_capability_gate_conformance", names)
        self.assertEqual(names["bd_1nfu_remote_capability_gate_conformance"], 45)
        # rollback_bundle appears twice (1 then 36) -> keep the max
        self.assertEqual(names["rollback_bundle_conformance"], 36)
        # a target that only 'generated warnings' is NOT broken
        self.assertNotIn("migrate_cli_e2e", names)

    def test_parses_fuzz_bins_through_ansi(self):
        got = parse_broken_targets(FUZZ_FIXTURE)
        d = {n: (k, c) for (n, k, c) in got}
        self.assertEqual(d["fuzz_capability_token_parser"], ("bin", 2))
        self.assertEqual(d["fuzz_ssrf_policy"], ("bin", 13))

    def test_clean_output_has_no_broken(self):
        self.assertEqual(parse_broken_targets(CLEAN_FIXTURE), [])

    def test_layer_mapping(self):
        recs = records_from_output(CONF_FIXTURE + FUZZ_FIXTURE, "2026-05-30T00:00:00Z")
        layers = {r.target: r.layer for r in recs}
        self.assertEqual(layers["bd_1nfu_remote_capability_gate_conformance"], "conformance")
        self.assertEqual(layers["fuzz_capability_token_parser"], "fuzz")
        # all census records are compile-failures => not green
        self.assertTrue(all((not r.compiles and not r.is_green()) for r in recs))

    def test_cargo_census_commands_are_locked(self):
        self.assertIn("--locked", _CONF_CMD)
        self.assertIn("--locked", _FUZZ_CMD)


class TestGateExitCode(unittest.TestCase):
    def _write(self, d, name, content):
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        return p

    def test_gate_fails_when_broken(self):
        with tempfile.TemporaryDirectory() as d:
            conf = self._write(d, "conf.txt", CONF_FIXTURE)
            fuzz = self._write(d, "fuzz.txt", FUZZ_FIXTURE)
            rc = main(["--from-log", f"conf={conf},fuzz={fuzz}", "--out", os.path.join(d, "out"), "--ts", "2026-05-30T00:00:00Z"])
            self.assertEqual(rc, 1)

    def test_gate_passes_when_clean(self):
        with tempfile.TemporaryDirectory() as d:
            clean = self._write(d, "clean.txt", CLEAN_FIXTURE)
            rc = main(["--from-log", f"conf={clean}", "--out", os.path.join(d, "out"), "--ts", "2026-05-30T00:00:00Z"])
            self.assertEqual(rc, 0)

    def test_warn_only_never_fails(self):
        with tempfile.TemporaryDirectory() as d:
            conf = self._write(d, "conf.txt", CONF_FIXTURE)
            rc = main(["--from-log", f"conf={conf}", "--warn-only", "--out", os.path.join(d, "out"), "--ts", "2026-05-30T00:00:00Z"])
            self.assertEqual(rc, 0)  # warn-only annotates but does not block


class TestRunCommandExitCode(unittest.TestCase):
    def _run_censuses(self, results, *, warn_only=False):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            args = ["--run", "--out", directory, "--ts", "2026-05-30T00:00:00Z"]
            if warn_only:
                args.append("--warn-only")
            with patch("check_verification_targets_compile.subprocess.run", side_effect=results) as run:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = main(args)
            self.assertEqual(
                [invocation.args[0] for invocation in run.call_args_list],
                [_CONF_CMD, _FUZZ_CMD],
                "both censuses must run even when the first command fails",
            )
            report_path = os.path.join(directory, "compile_census_20260530T000000Z.jsonl")
            with open(report_path, encoding="utf-8") as report:
                records = [json.loads(line) for line in report if line.strip()]
        return rc, stdout.getvalue(), stderr.getvalue(), records

    def test_run_passes_only_when_commands_succeed_and_no_targets_fail(self):
        rc, stdout, stderr, records = self._run_censuses([
            subprocess.CompletedProcess(_CONF_CMD, 0, stdout=CLEAN_FIXTURE, stderr=""),
            subprocess.CompletedProcess(_FUZZ_CMD, 0, stdout=CLEAN_FIXTURE, stderr=""),
        ])
        self.assertEqual(rc, 0)
        self.assertIn("ALL verification targets compile", stdout)
        self.assertIn("failed commands: 0", stdout)
        self.assertEqual(stderr, "")
        self.assertEqual(records, [])

    def test_run_fails_on_library_error_and_preserves_both_output_streams(self):
        diagnostic = "error: could not compile `frankenengine-node` (lib) due to 1 previous error\n"
        rc, stdout, stderr, records = self._run_censuses([
            subprocess.CompletedProcess(_CONF_CMD, 101, stdout="upstream compiler output\n", stderr=diagnostic),
            subprocess.CompletedProcess(_FUZZ_CMD, 0, stdout=CLEAN_FIXTURE, stderr=""),
        ])
        self.assertEqual(rc, 1)
        self.assertNotIn("ALL verification targets compile", stdout)
        self.assertIn("failed commands: 1", stdout)
        self.assertIn("conformance census command exited 101", stderr)
        self.assertIn("upstream compiler output", stderr)
        self.assertIn(diagnostic, stderr)
        self.assertEqual(records, [], "a library error must not fabricate named-target records")

    def test_run_fails_on_fuzz_dependency_error_without_named_targets(self):
        diagnostic = "error: failed to get dependency for package franken-node-fuzz\n"
        rc, stdout, stderr, records = self._run_censuses([
            subprocess.CompletedProcess(_CONF_CMD, 0, stdout=CLEAN_FIXTURE, stderr=""),
            subprocess.CompletedProcess(_FUZZ_CMD, 101, stdout="", stderr=diagnostic),
        ])
        self.assertEqual(rc, 1)
        self.assertNotIn("ALL verification targets compile", stdout)
        self.assertIn("fuzz census command exited 101", stderr)
        self.assertIn(diagnostic, stderr)
        self.assertEqual(records, [])

    def test_run_fails_on_empty_output_and_signal_termination(self):
        for status in (101, -9):
            with self.subTest(status=status):
                rc, stdout, stderr, records = self._run_censuses([
                    subprocess.CompletedProcess(_CONF_CMD, status, stdout="", stderr=""),
                    subprocess.CompletedProcess(_FUZZ_CMD, 0, stdout=CLEAN_FIXTURE, stderr=""),
                ])
                self.assertEqual(rc, 1)
                self.assertNotIn("ALL verification targets compile", stdout)
                self.assertIn(f"conformance census command exited {status}", stderr)
                self.assertEqual(records, [])

    def test_run_retains_named_target_census_alongside_command_failures(self):
        rc, stdout, stderr, records = self._run_censuses([
            subprocess.CompletedProcess(_CONF_CMD, 101, stdout="", stderr=CONF_FIXTURE),
            subprocess.CompletedProcess(_FUZZ_CMD, 101, stdout="", stderr="dependency unavailable"),
        ])
        self.assertEqual(rc, 1)
        self.assertIn("failed commands: 2", stdout)
        self.assertIn("conformance census command exited 101", stderr)
        self.assertIn("fuzz census command exited 101", stderr)
        by_target = {record["target"]: record for record in records}
        self.assertEqual(len(by_target), 2)
        self.assertEqual(by_target["rollback_bundle_conformance"]["errors_before"], 36)
        self.assertTrue(all(not record["compiles"] for record in records))

    def test_run_named_target_failures_still_fail_when_runner_returns_zero(self):
        rc, stdout, stderr, records = self._run_censuses([
            subprocess.CompletedProcess(_CONF_CMD, 0, stdout=CONF_FIXTURE, stderr=""),
            subprocess.CompletedProcess(_FUZZ_CMD, 0, stdout=CLEAN_FIXTURE, stderr=""),
        ])
        self.assertEqual(rc, 1)
        self.assertNotIn("ALL verification targets compile", stdout)
        self.assertIn("failed commands: 0", stdout)
        self.assertEqual(stderr, "")
        self.assertEqual(len(records), 2)

    def test_run_warn_only_reports_command_failure_without_claiming_success(self):
        rc, stdout, stderr, records = self._run_censuses([
            subprocess.CompletedProcess(_CONF_CMD, 101, stdout="", stderr="compiler unavailable"),
            subprocess.CompletedProcess(_FUZZ_CMD, 0, stdout=CLEAN_FIXTURE, stderr=""),
        ], warn_only=True)
        self.assertEqual(rc, 0)
        self.assertNotIn("ALL verification targets compile", stdout)
        self.assertIn("::warning::conformance census command exited 101", stderr)
        self.assertNotIn("::error::", stderr)
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
