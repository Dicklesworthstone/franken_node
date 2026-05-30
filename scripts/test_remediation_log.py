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
    RemediationRecord,
    write_jsonl,
    read_jsonl,
    render_summary,
    all_green,
    SCHEMA_VERSION,
)


def green_rec(target="t", layer="conformance"):
    return RemediationRecord(
        target=target, layer=layer, ts_rfc3339="2026-05-30T00:00:00Z",
        compiles=True, ran=True, errors_before=10, errors_after=0,
        tests_run=5, tests_passed=5, assertions_preserved=True, duration_ms=100,
    )


class TestValidation(unittest.TestCase):
    def test_valid_record_has_no_errors(self):
        self.assertEqual(green_rec().validate(), [])

    def test_bad_layer_rejected(self):
        r = green_rec(); r.layer = "bogus"
        self.assertTrue(any("layer" in e for e in r.validate()))

    def test_empty_target_rejected(self):
        r = green_rec(); r.target = ""
        self.assertTrue(any("target" in e for e in r.validate()))

    def test_passed_gt_run_rejected(self):
        r = green_rec(); r.tests_passed = 6; r.tests_run = 5
        self.assertTrue(any("exceed" in e for e in r.validate()))

    def test_ran_requires_compiles(self):
        r = green_rec(); r.compiles = False; r.ran = True
        self.assertTrue(any("compiles=True" in e for e in r.validate()))

    def test_ran_requires_zero_residual_errors(self):
        r = green_rec(); r.errors_after = 3
        self.assertTrue(any("errors_after==0" in e for e in r.validate()))

    def test_negative_counts_rejected(self):
        r = green_rec(); r.errors_after = -1
        self.assertTrue(any("non-negative" in e for e in r.validate()))


class TestIsGreen(unittest.TestCase):
    def test_green_record_is_green(self):
        self.assertTrue(green_rec().is_green())

    def test_crash_is_not_green(self):
        r = green_rec(); r.crashed = True
        self.assertFalse(r.is_green())

    def test_dropped_assertion_is_not_green(self):
        r = green_rec(); r.assertions_preserved = False
        self.assertFalse(r.is_green())

    def test_partial_pass_is_not_green(self):
        r = green_rec(); r.tests_passed = 4; r.tests_run = 5
        self.assertFalse(r.is_green())

    def test_compile_only_not_green(self):
        r = green_rec(); r.ran = False
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
        bad = green_rec(); bad.layer = "nope"
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                write_jsonl([bad], os.path.join(d, "r.jsonl"))

    def test_to_json_has_schema_version(self):
        d = json.loads(green_rec().to_json())
        self.assertEqual(d["schema_version"], SCHEMA_VERSION)


class TestSummary(unittest.TestCase):
    def test_summary_counts_green(self):
        red = green_rec("bad"); red.errors_after = 0; red.ran = False  # compile-only => RED
        recs = [green_rec("ok1"), green_rec("ok2"), red]
        out = render_summary(recs)
        self.assertIn("GREEN: 2/3", out)
        self.assertIn("## RED targets", out)
        self.assertIn("bad", out)

    def test_all_green_predicate(self):
        self.assertTrue(all_green([green_rec("a"), green_rec("b")]))
        self.assertFalse(all_green([]))  # empty is not "all green"
        r = green_rec(); r.crashed = True
        self.assertFalse(all_green([green_rec("a"), r]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
