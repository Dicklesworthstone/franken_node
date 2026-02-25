"""Unit tests for scripts/check_fuzz_testing.py (bd-1ul)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_fuzz_testing",
    ROOT / "scripts" / "check_fuzz_testing.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


# ── Path and helper tests ────────────────────────────────────────────

class TestSafeRel(TestCase):
    def test_inside_root(self) -> None:
        p = mod.ROOT / "fuzz" / "corpus"
        self.assertEqual(mod._safe_rel(p), "fuzz/corpus")

    def test_outside_root(self) -> None:
        p = Path("/tmp/outside")
        self.assertEqual(mod._safe_rel(p), "/tmp/outside")

    def test_root_itself(self) -> None:
        self.assertEqual(mod._safe_rel(mod.ROOT), ".")


class TestCheckHelper(TestCase):
    def test_pass_appends(self) -> None:
        mod.RESULTS.clear()
        entry = mod._check("test_pass", True, "ok")
        self.assertTrue(entry["pass"])
        self.assertEqual(entry["detail"], "ok")
        self.assertEqual(len(mod.RESULTS), 1)

    def test_fail_appends(self) -> None:
        mod.RESULTS.clear()
        entry = mod._check("test_fail", False)
        self.assertFalse(entry["pass"])
        self.assertEqual(entry["detail"], "NOT FOUND")

    def test_default_detail_on_pass(self) -> None:
        mod.RESULTS.clear()
        entry = mod._check("test_default", True)
        self.assertEqual(entry["detail"], "found")


class TestCountFiles(TestCase):
    def test_corpus_migration_count(self) -> None:
        count = mod._count_files(mod.CORPUS_MIGRATION)
        self.assertGreaterEqual(count, 50)

    def test_corpus_shim_count(self) -> None:
        count = mod._count_files(mod.CORPUS_SHIM)
        self.assertGreaterEqual(count, 50)

    def test_nonexistent_dir(self) -> None:
        count = mod._count_files(Path("/nonexistent/dir"))
        self.assertEqual(count, 0)


# ── File existence tests ─────────────────────────────────────────────

class TestFileExists(TestCase):
    def test_spec_exists(self) -> None:
        mod.RESULTS.clear()
        mod._file_exists(mod.SPEC, "spec")
        self.assertTrue(mod.RESULTS[-1]["pass"])

    def test_policy_exists(self) -> None:
        mod.RESULTS.clear()
        mod._file_exists(mod.POLICY, "policy")
        self.assertTrue(mod.RESULTS[-1]["pass"])

    def test_budget_config_exists(self) -> None:
        mod.RESULTS.clear()
        mod._file_exists(mod.BUDGET_CONFIG, "budget")
        self.assertTrue(mod.RESULTS[-1]["pass"])

    def test_missing_file(self) -> None:
        mod.RESULTS.clear()
        mod._file_exists(Path("/nonexistent/file.txt"), "missing")
        self.assertFalse(mod.RESULTS[-1]["pass"])
        self.assertIn("missing", mod.RESULTS[-1]["detail"])


class TestDirExists(TestCase):
    def test_corpus_migration_dir(self) -> None:
        mod.RESULTS.clear()
        mod._dir_exists(mod.CORPUS_MIGRATION, "migration corpus")
        self.assertTrue(mod.RESULTS[-1]["pass"])

    def test_missing_dir(self) -> None:
        mod.RESULTS.clear()
        mod._dir_exists(Path("/nonexistent/dir"), "missing")
        self.assertFalse(mod.RESULTS[-1]["pass"])


# ── Content check tests ─────────────────────────────────────────────

class TestContains(TestCase):
    def test_spec_contains_event_code(self) -> None:
        mod.RESULTS.clear()
        result = mod._contains(mod.SPEC, "FZT-001", "spec")
        self.assertTrue(result["pass"])

    def test_spec_missing_pattern(self) -> None:
        mod.RESULTS.clear()
        result = mod._contains(mod.SPEC, "NONEXISTENT_XYZ_123", "spec")
        self.assertFalse(result["pass"])

    def test_missing_file_returns_fail(self) -> None:
        mod.RESULTS.clear()
        result = mod._contains(Path("/nonexistent"), "pattern", "test")
        self.assertFalse(result["pass"])
        self.assertEqual(result["detail"], "file missing")


# ── Check function tests ────────────────────────────────────────────

class TestCheckBudgetConfig(TestCase):
    def test_budget_config_checks(self) -> None:
        mod.RESULTS.clear()
        mod.check_budget_config()
        checks = list(mod.RESULTS)
        self.assertTrue(all(c["pass"] for c in checks))
        names = [c["check"] for c in checks]
        self.assertTrue(any("migration section" in n for n in names))
        self.assertTrue(any("shim section" in n for n in names))


class TestCheckCorpus(TestCase):
    def test_migration_corpus_passes(self) -> None:
        mod.RESULTS.clear()
        mod.check_corpus_migration()
        self.assertTrue(all(c["pass"] for c in mod.RESULTS))

    def test_shim_corpus_passes(self) -> None:
        mod.RESULTS.clear()
        mod.check_corpus_shim()
        self.assertTrue(all(c["pass"] for c in mod.RESULTS))


class TestCheckRegression(TestCase):
    def test_migration_regression_passes(self) -> None:
        mod.RESULTS.clear()
        mod.check_regression_migration()
        self.assertTrue(all(c["pass"] for c in mod.RESULTS))

    def test_shim_regression_passes(self) -> None:
        mod.RESULTS.clear()
        mod.check_regression_shim()
        self.assertTrue(all(c["pass"] for c in mod.RESULTS))


class TestCheckFuzzTargets(TestCase):
    def test_all_targets_exist(self) -> None:
        mod.RESULTS.clear()
        mod.check_fuzz_targets()
        target_checks = [c for c in mod.RESULTS if "target:" in c["check"]]
        self.assertEqual(len(target_checks), 5)
        self.assertTrue(all(c["pass"] for c in target_checks))

    def test_target_test_coverage(self) -> None:
        mod.RESULTS.clear()
        mod.check_target_test_coverage()
        self.assertTrue(all(c["pass"] for c in mod.RESULTS))


class TestCheckCoverageReports(TestCase):
    def test_coverage_reports_pass(self) -> None:
        mod.RESULTS.clear()
        mod.check_coverage_reports()
        self.assertTrue(all(c["pass"] for c in mod.RESULTS))


class TestCheckSpecContent(TestCase):
    def test_all_spec_content_found(self) -> None:
        mod.RESULTS.clear()
        mod.check_spec_content()
        self.assertTrue(all(c["pass"] for c in mod.RESULTS))

    def test_event_codes_in_spec(self) -> None:
        text = mod.SPEC.read_text(encoding="utf-8")
        for code in mod.EVENT_CODES:
            self.assertIn(code, text)

    def test_invariants_in_spec(self) -> None:
        text = mod.SPEC.read_text(encoding="utf-8")
        for inv in mod.INVARIANTS:
            self.assertIn(inv, text)


class TestCheckPolicyContent(TestCase):
    def test_all_policy_content_found(self) -> None:
        mod.RESULTS.clear()
        mod.check_policy_content()
        self.assertTrue(all(c["pass"] for c in mod.RESULTS))


# ── Full run tests ───────────────────────────────────────────────────

class TestRunAll(TestCase):
    def test_full_run_passes(self) -> None:
        report = mod.run_all()
        self.assertEqual(report["bead_id"], "bd-1ul")
        self.assertEqual(report["section"], "10.7")
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(report["overall_pass"])

    def test_check_count(self) -> None:
        report = mod.run_all()
        self.assertGreaterEqual(report["summary"]["total"], 15)

    def test_no_failures(self) -> None:
        report = mod.run_all()
        failing = [c for c in report["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}",
        )


class TestSelfTest(TestCase):
    def test_self_test_passes(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self) -> None:
        ok, checks = mod.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


# ── CLI tests ────────────────────────────────────────────────────────

class TestCli(TestCase):
    def test_json_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_fuzz_testing.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["bead_id"], "bd-1ul")

    def test_human_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_fuzz_testing.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)

    def test_self_test_flag(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_fuzz_testing.py"), "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("self_test", proc.stdout)

    def test_self_test_json(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_fuzz_testing.py"),
             "--self-test", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])


# ── Constant validation tests ────────────────────────────────────────

class TestConstants(TestCase):
    def test_event_codes_count(self) -> None:
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariants_count(self) -> None:
        self.assertEqual(len(mod.INVARIANTS), 5)

    def test_migration_targets_count(self) -> None:
        self.assertEqual(len(mod.MIGRATION_TARGETS), 3)

    def test_shim_targets_count(self) -> None:
        self.assertEqual(len(mod.SHIM_TARGETS), 2)

    def test_spec_required_content_count(self) -> None:
        self.assertGreaterEqual(len(mod.SPEC_REQUIRED_CONTENT), 14)

    def test_policy_required_content_count(self) -> None:
        self.assertGreaterEqual(len(mod.POLICY_REQUIRED_CONTENT), 5)


# ── JSON serialization test ──────────────────────────────────────────

class TestJsonSerialization(TestCase):
    def test_report_is_json_serializable(self) -> None:
        report = mod.run_all()
        json_str = json.dumps(report)
        self.assertIsInstance(json_str, str)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["bead_id"], "bd-1ul")


if __name__ == "__main__":
    main()
