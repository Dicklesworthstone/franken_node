#!/usr/bin/env python3
"""Unit tests for scripts/parse_cargo_test_results.py (bd-rjc2m.E2E1).
Run: python3 scripts/test_parse_cargo_test_results.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_cargo_test_results import parse_cargo_test_output, parse_fuzz_smoke  # noqa: E402

TS = "2026-05-30T00:00:00Z"

# Realistic cargo test output (two targets: one green, one with a failure + ignored).
TEST_LOG = r"""
     Running tests/conformance/audience_token_security.rs (target/debug/deps/audience_token_security-1a2b3c4d5e6f)
running 5 tests
test tests::a ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

     Running tests/conformance/bd_3h7k_anti_entropy_reconciliation_conformance.rs (target/debug/deps/bd_3h7k_anti_entropy_reconciliation_conformance-99aa88bb77cc)
running 3 tests
test tests::run_conformance_suite ... FAILED
test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 470.77s

     Running tests/conformance/control_lane_policy_metamorphic.rs (target/debug/deps/control_lane_policy_metamorphic-deadbeef1234)
running 4 tests
test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""

FUZZ_CLEAN = "#479941\tREDUCE cov: 1675 ft: 4115 corp: 785\n#488638\tDONE   cov: 1675\nDone 488638 runs in 241 second(s)\n"
FUZZ_CRASH = "==1234== ERROR: libFuzzer: deadly signal\nSUMMARY: AddressSanitizer: ...\n"
FUZZ_BUILD_FAIL = "error[E0599]: no method named `issue`\nerror: could not compile `franken-node-fuzz` (bin \"x\") due to 2 previous errors\n"


class TestCargoTestParse(unittest.TestCase):
    def test_maps_targets_to_results(self):
        recs = {r.target: r for r in parse_cargo_test_output(TEST_LOG, TS)}
        self.assertEqual(set(recs), {
            "audience_token_security",
            "bd_3h7k_anti_entropy_reconciliation_conformance",
            "control_lane_policy_metamorphic",
        })

    def test_green_target(self):
        recs = {r.target: r for r in parse_cargo_test_output(TEST_LOG, TS)}
        g = recs["audience_token_security"]
        self.assertTrue(g.is_green())
        self.assertEqual((g.tests_run, g.tests_passed), (5, 5))

    def test_failed_target_not_green(self):
        recs = {r.target: r for r in parse_cargo_test_output(TEST_LOG, TS)}
        f = recs["bd_3h7k_anti_entropy_reconciliation_conformance"]
        self.assertFalse(f.is_green())
        self.assertEqual((f.tests_run, f.tests_passed), (3, 2))  # 2 passed + 1 failed
        self.assertIn("FAILED", f.notes)

    def test_ignored_excluded_from_run_count(self):
        recs = {r.target: r for r in parse_cargo_test_output(TEST_LOG, TS)}
        ig = recs["control_lane_policy_metamorphic"]
        # 3 passed + 0 failed (1 ignored not counted) -> green
        self.assertTrue(ig.is_green())
        self.assertEqual((ig.tests_run, ig.tests_passed), (3, 3))


class TestFuzzSmoke(unittest.TestCase):
    def test_clean_smoke_is_green(self):
        r = parse_fuzz_smoke("fuzz_canonical_serializer_roundtrip", FUZZ_CLEAN, TS)
        self.assertTrue(r.is_green())
        self.assertFalse(r.crashed)

    def test_crash_is_not_green(self):
        r = parse_fuzz_smoke("fuzz_x", FUZZ_CRASH, TS)
        self.assertTrue(r.crashed)
        self.assertFalse(r.is_green())

    def test_build_fail_is_not_green(self):
        r = parse_fuzz_smoke("fuzz_x", FUZZ_BUILD_FAIL, TS)
        self.assertFalse(r.compiles)
        self.assertFalse(r.is_green())


if __name__ == "__main__":
    unittest.main(verbosity=2)
