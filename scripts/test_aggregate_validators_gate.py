#!/usr/bin/env python3
"""Unit tests for scripts/aggregate_validators_gate.py (bd-rjc2m.VALWIRE).
Run: python3 scripts/test_aggregate_validators_gate.py
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aggregate_validators_gate as G  # noqa: E402


class FakeProc:
    def __init__(self, rc):
        self.returncode = rc
        self.stdout = ""
        self.stderr = ""


def fake_runner(argv, capture_output=True, text=True):
    """rc based on the check script name: check_pass_* -> 0, check_fail_* -> 1."""
    name = os.path.basename(argv[1])
    return FakeProc(0 if name.startswith("check_pass") else 1)


def make_checks_dir(names):
    d = tempfile.mkdtemp()
    for n in names:
        with open(os.path.join(d, n), "w") as fh:
            fh.write("# fixture check\n")
    return d


class TestDiscoveryClassify(unittest.TestCase):
    def test_discover_only_check_prefixed(self):
        d = make_checks_dir(["check_a.py", "check_b.py", "helper.py", "run_all_checks.py"])
        self.assertEqual(G.discover_checks(d), ["check_a.py", "check_b.py"])

    def test_classify_untriaged_default(self):
        c = G.classify(["check_a.py", "check_b.py"], {"check_a.py": {"mode": "wired", "args": ["--json"]}})
        self.assertEqual(c["check_a.py"]["mode"], "wired")
        self.assertEqual(c["check_a.py"]["args"], ["--json"])
        self.assertEqual(c["check_b.py"]["mode"], "untriaged")


class TestEvaluate(unittest.TestCase):
    def test_failed_wired_sets_nonzero_exit(self):
        d = make_checks_dir(["check_pass_a.py", "check_fail_b.py"])
        manifest = {"check_pass_a.py": {"mode": "wired"}, "check_fail_b.py": {"mode": "wired"}}
        classified = G.classify(G.discover_checks(d), manifest)
        results, rc, stats = G.evaluate(classified, d, strict=False, runner=fake_runner)
        self.assertEqual(rc, 1)
        self.assertEqual(stats["failed_wired"], 1)

    def test_all_wired_pass_exit_zero(self):
        d = make_checks_dir(["check_pass_a.py", "check_pass_b.py"])
        manifest = {"check_pass_a.py": {"mode": "wired"}, "check_pass_b.py": {"mode": "wired"}}
        classified = G.classify(G.discover_checks(d), manifest)
        _, rc, stats = G.evaluate(classified, d, strict=False, runner=fake_runner)
        self.assertEqual(rc, 0)
        self.assertEqual(stats["failed_wired"], 0)

    def test_excluded_is_skipped_not_run(self):
        d = make_checks_dir(["check_fail_x.py"])
        manifest = {"check_fail_x.py": {"mode": "excluded", "rationale": "superseded"}}
        classified = G.classify(G.discover_checks(d), manifest)
        results, rc, stats = G.evaluate(classified, d, strict=False, runner=fake_runner)
        self.assertEqual(rc, 0)  # excluded check does NOT fail the gate
        self.assertEqual(results[0].mode, "excluded")
        self.assertEqual(results[0].rationale, "superseded")

    def test_untriaged_counted_and_strict_fails(self):
        d = make_checks_dir(["check_pass_a.py", "check_unknown_b.py"])
        manifest = {"check_pass_a.py": {"mode": "wired"}}
        classified = G.classify(G.discover_checks(d), manifest)
        _, rc_lax, stats = G.evaluate(classified, d, strict=False, runner=fake_runner)
        self.assertEqual(rc_lax, 0)  # lax: untriaged does not fail
        self.assertEqual(stats["untriaged"], 1)
        _, rc_strict, _ = G.evaluate(classified, d, strict=True, runner=fake_runner)
        self.assertEqual(rc_strict, 1)  # strict: untriaged fails


class TestRender(unittest.TestCase):
    def test_render_lists_failures_and_untriaged(self):
        d = make_checks_dir(["check_pass_a.py", "check_fail_b.py", "check_unknown_c.py"])
        manifest = {"check_pass_a.py": {"mode": "wired"}, "check_fail_b.py": {"mode": "wired"}}
        classified = G.classify(G.discover_checks(d), manifest)
        results, _, stats = G.evaluate(classified, d, strict=False, runner=fake_runner)
        out = G.render(results, stats)
        self.assertIn("FAILED wired checks", out)
        self.assertIn("check_fail_b.py", out)
        self.assertIn("UNTRIAGED", out)
        self.assertIn("check_unknown_c.py", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
