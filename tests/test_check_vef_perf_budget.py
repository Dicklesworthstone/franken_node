"""Unit tests for scripts/check_vef_perf_budget.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_vef_perf_budget as mod  # noqa: E402


def _write_comment_only_fixture(root: Path) -> None:
    connector = root / "crates" / "franken-node" / "src" / "connector"
    connector.mkdir(parents=True)
    docs = root / "docs" / "specs" / "section_10_18"
    docs.mkdir(parents=True)

    (connector / "mod.rs").write_text("// pub mod vef_perf_budget;\n", encoding="utf-8")

    comment_markers = [
        "pub struct VefOverheadGate",
        "fn evaluate",
        "fn to_csv",
        "max_cv_pct",
        "noise_multiplier",
        "warmup_iterations",
        *[f'"{path_name}"' for path_name in mod.VEF_HOT_PATHS],
        *[f'"{mode}"' for mode in mod.VEF_MODES],
        *[f'"{code}"' for code in mod.REQUIRED_EVENT_CODES],
        *[f'"{inv}"' for inv in mod.REQUIRED_INVARIANTS],
        *[str(value) for values in mod.NORMAL_BUDGETS.values() for value in values],
        *[str(multiplier) for multiplier in mod.MODE_MULTIPLIERS.values()],
        *["#[test]" for _ in range(12)],
    ]
    (connector / "vef_perf_budget.rs").write_text(
        "\n".join(
            [
                "// " + " ".join(comment_markers[:20]),
                "/*",
                *comment_markers[20:],
                "*/",
            ]
        ),
        encoding="utf-8",
    )

    spec_lines = [
        "# bd-ufk5 contract",
        "Normal Mode",
        "Restricted Mode",
        "Quarantine Mode",
        *mod.REQUIRED_EVENT_CODES,
    ]
    (docs / "bd-ufk5_contract.md").write_text("\n".join(spec_lines), encoding="utf-8")


class TestConstants(unittest.TestCase):
    def test_hot_path_count(self):
        self.assertEqual(len(mod.VEF_HOT_PATHS), 5)

    def test_mode_count(self):
        self.assertEqual(len(mod.VEF_MODES), 3)

    def test_event_code_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_EVENT_CODES), 8)

    def test_invariant_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_INVARIANTS), 6)

    def test_normal_budgets_cover_all_paths(self):
        for path in mod.VEF_HOT_PATHS:
            self.assertIn(path, mod.NORMAL_BUDGETS)

    def test_mode_multipliers(self):
        self.assertAlmostEqual(mod.MODE_MULTIPLIERS["normal"], 1.0)
        self.assertAlmostEqual(mod.MODE_MULTIPLIERS["restricted"], 1.5)
        self.assertAlmostEqual(mod.MODE_MULTIPLIERS["quarantine"], 2.0)


class TestRunAllChecks(unittest.TestCase):
    def test_returns_list(self):
        checks = mod.run_all_checks()
        self.assertIsInstance(checks, list)

    def test_has_many_checks(self):
        checks = mod.run_all_checks()
        self.assertGreaterEqual(len(checks), 30)

    def test_required_keys(self):
        checks = mod.run_all_checks()
        for entry in checks:
            self.assertIn("check", entry)
            self.assertIn("pass", entry)
            self.assertIn("detail", entry)

    def test_all_checks_pass(self):
        checks = mod.run_all_checks()
        failing = [c for c in checks if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failing),
        )

    def test_preserves_string_literals_while_stripping_comments(self):
        source = (
            'const KEEP: &str = "VEF-PERF-001 // literal"; // "VEF-PERF-002"\n'
            'const RAW: &str = r#"INV-VEF-PBG-GATE /* literal */"#; /* "VEF-PERF-003" */\n'
        )

        stripped = mod._strip_rust_comments(source)

        self.assertIn('"VEF-PERF-001 // literal"', stripped)
        self.assertIn('r#"INV-VEF-PBG-GATE /* literal */"#', stripped)
        self.assertNotIn('"VEF-PERF-002"', stripped)
        self.assertNotIn('"VEF-PERF-003"', stripped)

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            _write_comment_only_fixture(fixture_root)

            with patch.object(mod, "ROOT", fixture_root):
                checks = {entry["check"]: entry for entry in mod.run_all_checks()}

        self.assertTrue(checks["rust_module_exists"]["pass"])
        self.assertTrue(checks["spec_contract"]["pass"])
        self.assertTrue(checks["spec_table_normal"]["pass"])
        self.assertTrue(checks["spec_table_restricted"]["pass"])
        self.assertTrue(checks["spec_table_quarantine"]["pass"])
        for code in mod.REQUIRED_EVENT_CODES:
            self.assertTrue(checks[f"spec_event_{code}"]["pass"])

        expected_failures = [
            "mod_registration",
            "gate_struct",
            "evaluate_method",
            "csv_output",
            "inline_tests",
            "noise_tolerance",
            "warmup_iterations",
        ]
        expected_failures.extend(f"hot_path_{path_name}" for path_name in mod.VEF_HOT_PATHS)
        expected_failures.extend(f"mode_{mode}" for mode in mod.VEF_MODES)
        expected_failures.extend(f"event_code_{code}" for code in mod.REQUIRED_EVENT_CODES)
        expected_failures.extend(f"invariant_{inv}" for inv in mod.REQUIRED_INVARIANTS)
        expected_failures.extend(f"budget_{path_name}" for path_name in mod.NORMAL_BUDGETS)
        expected_failures.extend(f"multiplier_{mode}" for mode in mod.MODE_MULTIPLIERS)

        for key in expected_failures:
            self.assertIn(key, checks)
            self.assertFalse(checks[key]["pass"], key)


class TestRunAll(unittest.TestCase):
    def test_structure(self):
        result = mod.run_all()
        for key in [
            "bead_id", "title", "section", "gate", "verdict",
            "overall_pass", "total", "passed", "failed",
            "hot_paths", "modes", "checks",
        ]:
            self.assertIn(key, result)

    def test_identity(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-ufk5")
        self.assertEqual(result["section"], "10.18")
        self.assertFalse(result["gate"])

    def test_pass_verdict(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failure_summary(result))
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["failed"], 0, self._failure_summary(result))

    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.JSONDecoder().decode(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-ufk5")

    def _failure_summary(self, result):
        failures = [c for c in result.get("checks", []) if not c.get("pass")]
        return "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failures)


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        self.assertTrue(mod.self_test())


class TestKeyChecks(unittest.TestCase):
    def test_rust_module_check(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertIn("rust_module_exists", checks)
        self.assertTrue(checks["rust_module_exists"]["pass"])

    def test_mod_registration_check(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertIn("mod_registration", checks)
        self.assertTrue(checks["mod_registration"]["pass"])

    def test_hot_path_checks_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for path in mod.VEF_HOT_PATHS:
            key = f"hot_path_{path}"
            self.assertIn(key, checks, f"check {key} missing")
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_mode_checks_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for mode in mod.VEF_MODES:
            key = f"mode_{mode}"
            self.assertIn(key, checks, f"check {key} missing")
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_event_code_checks_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for code in mod.REQUIRED_EVENT_CODES:
            key = f"event_code_{code}"
            self.assertIn(key, checks, f"check {key} missing")
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_spec_contract_check(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertIn("spec_contract", checks)
        self.assertTrue(checks["spec_contract"]["pass"])

    def test_gate_struct_check(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertIn("gate_struct", checks)
        self.assertTrue(checks["gate_struct"]["pass"])


if __name__ == "__main__":
    unittest.main()
