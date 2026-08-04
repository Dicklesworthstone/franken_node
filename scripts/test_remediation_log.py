#!/usr/bin/env python3
"""Unit tests for scripts/remediation_log.py (bd-rjc2m.A).

Run: python3 scripts/test_remediation_log.py   (no pytest dependency required)
Covers: validation rules, is_green, JSONL round-trip, summary rendering, CLI exit code.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remediation_log import (  # noqa: E402
    CommandReceipt,
    RemediationRecord,
    parsed_status_for_records,
    read_command_receipts,
    read_jsonl,
    render_command_summary,
    render_summary,
    write_command_receipts,
    write_jsonl,
    all_green,
    COMMAND_RECEIPT_SCHEMA_VERSION,
    SCHEMA_VERSION,
)


def green_rec(target="t", layer="conformance"):
    return RemediationRecord(
        target=target, layer=layer, ts_rfc3339="2026-05-30T00:00:00Z",
        compiles=True, ran=True, errors_before=10, errors_after=0,
        tests_run=5, tests_passed=5, assertions_preserved=True, duration_ms=100,
    )


def command_receipt(step="full_conformance", status="passed", exit_code=0):
    return CommandReceipt(
        step_id=step,
        label="Full conformance",
        command="rch exec -- cargo test -p frankenengine-node",
        command_digest="sha256:" + ("a" * 64),
        exit_code=exit_code,
        duration_ms=123,
        log_path="artifacts/verification/full_test.log",
        parsed_status=status,
        ts_rfc3339="2026-05-30T00:00:00Z",
    )


class TestValidation(unittest.TestCase):
    def test_valid_record_has_no_errors(self):
        self.assertEqual(green_rec().validate(), [])

    def test_bad_layer_rejected(self):
        r = green_rec()
        r.layer = "bogus"
        self.assertTrue(any("layer" in e for e in r.validate()))

    def test_empty_target_rejected(self):
        r = green_rec()
        r.target = ""
        self.assertTrue(any("target" in e for e in r.validate()))

    def test_passed_gt_run_rejected(self):
        r = green_rec()
        r.tests_passed = 6
        r.tests_run = 5
        self.assertTrue(any("exceed" in e for e in r.validate()))

    def test_ran_requires_compiles(self):
        r = green_rec()
        r.compiles = False
        r.ran = True
        self.assertTrue(any("compiles=True" in e for e in r.validate()))

    def test_ran_requires_zero_residual_errors(self):
        r = green_rec()
        r.errors_after = 3
        self.assertTrue(any("errors_after==0" in e for e in r.validate()))

    def test_negative_counts_rejected(self):
        r = green_rec()
        r.errors_after = -1
        self.assertTrue(any("non-negative" in e for e in r.validate()))


class TestIsGreen(unittest.TestCase):
    def test_green_record_is_green(self):
        self.assertTrue(green_rec().is_green())

    def test_crash_is_not_green(self):
        r = green_rec()
        r.crashed = True
        self.assertFalse(r.is_green())

    def test_dropped_assertion_is_not_green(self):
        r = green_rec()
        r.assertions_preserved = False
        self.assertFalse(r.is_green())

    def test_partial_pass_is_not_green(self):
        r = green_rec()
        r.tests_passed = 4
        r.tests_run = 5
        self.assertFalse(r.is_green())

    def test_compile_only_not_green(self):
        r = green_rec()
        r.ran = False
        self.assertFalse(r.is_green())


class TestRoundTrip(unittest.TestCase):
    def test_jsonl_round_trip(self):
        recs = [green_rec("a", "conformance"), green_rec("b", "fuzz"), green_rec("c", "sdk")]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.jsonl")
            n = write_jsonl(recs, p)
            self.assertEqual(n, 3)
            back = read_jsonl(p)
            self.assertEqual([r.target for r in back], ["a", "b", "c"])
            self.assertEqual([r.layer for r in back], ["conformance", "fuzz", "sdk"])
            self.assertTrue(all(r.is_green() for r in back))

    def test_write_rejects_invalid(self):
        bad = green_rec()
        bad.layer = "nope"
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                write_jsonl([bad], os.path.join(d, "r.jsonl"))

    def test_to_json_has_schema_version(self):
        d = json.loads(green_rec().to_json())
        self.assertEqual(d["schema_version"], SCHEMA_VERSION)

    def test_command_receipt_round_trip(self):
        receipts = [
            command_receipt("full_conformance", "passed", 0),
            command_receipt("summary", "parsed_failure", 1),
        ]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "commands.jsonl")
            n = write_command_receipts(receipts, p)
            self.assertEqual(n, 2)
            back = read_command_receipts(p)
            self.assertEqual([r.step_id for r in back], ["full_conformance", "summary"])
            self.assertEqual([r.parsed_status for r in back], ["passed", "parsed_failure"])

    def test_command_receipt_json_has_schema_version(self):
        d = json.loads(command_receipt().to_json())
        self.assertEqual(d["schema_version"], COMMAND_RECEIPT_SCHEMA_VERSION)

    def test_command_receipt_rejects_bad_status(self):
        bad = command_receipt()
        bad.parsed_status = "surprise"
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                write_command_receipts([bad], os.path.join(d, "commands.jsonl"))


class TestSummary(unittest.TestCase):
    def test_summary_counts_green(self):
        red = green_rec("bad")
        red.errors_after = 0
        red.ran = False  # compile-only => RED
        recs = [green_rec("ok1"), green_rec("ok2"), red]
        out = render_summary(recs)
        self.assertIn("GREEN: 2/3", out)
        self.assertIn("## RED targets", out)
        self.assertIn("bad", out)

    def test_all_green_predicate(self):
        self.assertTrue(all_green([green_rec("a"), green_rec("b")]))
        self.assertFalse(all_green([]))  # empty is not "all green"
        r = green_rec()
        r.crashed = True
        self.assertFalse(all_green([green_rec("a"), r]))

    def test_command_summary_distinguishes_process_and_parsed_failures(self):
        receipts = [
            command_receipt("passing_command", "passed", 0),
            command_receipt("failing_command", "command_failed", 2),
            command_receipt("parsed_test_failure", "parsed_failure", 101),
            command_receipt("cargo_abort", "cargo_abort", 101),
        ]
        out = render_command_summary(receipts)
        self.assertIn("EXIT-0: 1/4 commands", out)
        self.assertIn("### Command failures", out)
        self.assertIn("failing_command", out)
        self.assertIn("### Parsed verification failures", out)
        self.assertIn("parsed_test_failure", out)
        self.assertIn("### Cargo aborts", out)
        self.assertIn("cargo_abort", out)


class TestParsedStatusForRecords(unittest.TestCase):
    def test_passing_records_report_passed(self):
        self.assertEqual(parsed_status_for_records([green_rec("ok")], exit_code=0), "passed")

    def test_red_records_report_parsed_failure(self):
        red = green_rec("bad")
        red.tests_passed = 4
        self.assertEqual(parsed_status_for_records([red], exit_code=101), "parsed_failure")

    def test_cargo_abort_record_reports_cargo_abort(self):
        abort = RemediationRecord(
            target="conformance_cargo_test_abort",
            layer="conformance",
            ts_rfc3339="2026-05-30T00:00:00Z",
            compiles=False,
            ran=False,
            errors_after=1,
            notes="cargo test aborted before per-target result",
        )
        self.assertEqual(parsed_status_for_records([abort], exit_code=101), "cargo_abort")

    def test_failed_command_without_records_reports_command_failed(self):
        self.assertEqual(parsed_status_for_records([], exit_code=2), "command_failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
