"""Unit tests for scripts/check_trajectory_gaming_camouflage.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_trajectory_gaming_camouflage as mod  # noqa: E402


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-35m7")
        self.assertEqual(mod.SECTION, "12")

    def test_required_event_codes(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 5)

    def test_required_contract_terms(self):
        self.assertGreaterEqual(len(mod.REQUIRED_CONTRACT_TERMS), 10)

    def test_runtime_export_forbidden_tokens_configured(self):
        self.assertIn("tgc-runtime-placeholder", mod.RUNTIME_EXPORT_FORBIDDEN_TOKENS)
        self.assertIn("export_for_verifier", mod.RUNTIME_EXPORT_FORBIDDEN_TOKENS)


class TestFileChecks(unittest.TestCase):
    def test_contract_exists(self):
        result = mod.check_file(mod.CONTRACT, "contract")
        self.assertTrue(result["pass"])

    def test_report_exists(self):
        result = mod.check_file(mod.REPORT, "report")
        self.assertTrue(result["pass"])


class TestContractChecks(unittest.TestCase):
    def test_contract_passes(self):
        checks = mod.check_contract()
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")


class TestRustIntegrationChecks(unittest.TestCase):
    def test_rust_integration_paths_and_symbols_pass(self):
        checks = mod.check_rust_integration()
        self.assertGreaterEqual(len(checks), 10)
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")

    def test_trust_card_camouflage_mark_is_checked(self):
        checks = mod.check_rust_integration()
        names = {check["check"] for check in checks}
        self.assertIn(
            "rust: trust-card camouflage mark symbol mark_camouflage_suspected",
            names,
        )
        self.assertIn(
            "rust: trust-card camouflage mark symbol TRUST_CARD_CAMOUFLAGE_SUSPECTED",
            names,
        )

    def test_runtime_export_truthfulness_checks_pass(self):
        checks = mod.check_runtime_export_truthfulness()
        self.assertGreaterEqual(len(checks), len(mod.RUNTIME_EXPORT_FORBIDDEN_TOKENS))
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")

    def test_rust_integration_symbols_ignore_comment_only_markers(self):
        original_symbols = mod.RUST_INTEGRATION_SYMBOLS
        with tempfile.TemporaryDirectory() as tmpdir:
            rust_path = Path(tmpdir) / "trajectory_gaming.rs"
            rust_path.write_text(
                "\n".join(
                    [
                        "// CamouflageHint",
                        "// ingest_verifier_hints",
                        "/* export_runtime_trajectory */",
                    ]
                ),
                encoding="utf-8",
            )

            try:
                mod.RUST_INTEGRATION_SYMBOLS = [
                    (
                        "comment-only trajectory runtime contract",
                        rust_path,
                        [
                            "CamouflageHint",
                            "ingest_verifier_hints",
                            "export_runtime_trajectory",
                        ],
                    )
                ]
                checks = mod.check_rust_integration()
            finally:
                mod.RUST_INTEGRATION_SYMBOLS = original_symbols

        self.assertTrue(checks[0]["pass"])
        for check in checks[1:]:
            self.assertFalse(check["pass"], check["check"])

    def test_runtime_export_truthfulness_requires_non_comment_status_markers(self):
        original_path = mod.RUNTIME_EXPORT_PATH
        with tempfile.TemporaryDirectory() as tmpdir:
            rust_path = Path(tmpdir) / "trajectory_gaming.rs"
            rust_path.write_text(
                "\n".join(
                    [
                        "// analysis_ready",
                        "/* TGC_RUNTIME_TRAJECTORY_ONLY */",
                        "pub fn export_runtime_trajectory() {}",
                    ]
                ),
                encoding="utf-8",
            )

            try:
                mod.RUNTIME_EXPORT_PATH = rust_path
                checks = mod.check_runtime_export_truthfulness()
            finally:
                mod.RUNTIME_EXPORT_PATH = original_path

        status_check = next(
            check
            for check in checks
            if check["check"] == "rust: trajectory runtime export declares non-analysis status"
        )
        self.assertFalse(status_check["pass"])


class TestReportLoad(unittest.TestCase):
    def test_load_report_success(self):
        data, checks = mod.load_report()
        self.assertIsInstance(data, dict)
        self.assertTrue(all(c["pass"] for c in checks))

    def test_malformed_report_fails_closed(self):
        original_report = mod.REPORT
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                mod.REPORT = Path(tmpdir) / "trajectory_gaming_camouflage_report.json"
                mod.REPORT.write_text("{bad-json", encoding="utf-8")

                data, checks = mod.load_report()

            self.assertIsNone(data)
            self.assertFalse(checks[-1]["pass"])
            self.assertEqual(checks[-1]["check"], "report: valid json")
        finally:
            mod.REPORT = original_report

    def test_non_object_report_fails_closed(self):
        original_report = mod.REPORT
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                mod.REPORT = Path(tmpdir) / "trajectory_gaming_camouflage_report.json"
                mod.REPORT.write_text("[]", encoding="utf-8")

                data, checks = mod.load_report()

            self.assertIsNone(data)
            self.assertFalse(checks[-1]["pass"])
            self.assertEqual(checks[-1]["detail"], "not an object")
        finally:
            mod.REPORT = original_report


class TestHelpers(unittest.TestCase):
    def test_motif_subset_hashes(self):
        data, _ = mod.load_report()
        hashes = mod.motif_subset_hashes(data)
        self.assertEqual(len(hashes), 2)
        self.assertEqual(len(set(hashes)), 2)

    def test_fusion_flags_non_behavioral_failures(self):
        data, _ = mod.load_report()
        self.assertTrue(mod.fusion_flags_non_behavioral_failures(data))

    def test_evaluate_policy_shape(self):
        data, _ = mod.load_report()
        out = mod.evaluate_policy(data)
        for key in [
            "pattern_count",
            "quarterly_update_ok",
            "known_recall_pct",
            "known_threshold_pct",
            "adaptive_rounds",
            "adaptive_min_recall_pct",
            "adaptive_threshold_pct",
            "motif_unique_subsets",
            "fusion_flags_non_behavioral_failures",
        ]:
            self.assertIn(key, out)

    def test_evaluate_policy_values(self):
        data, _ = mod.load_report()
        out = mod.evaluate_policy(data)
        self.assertGreaterEqual(out["pattern_count"], 100)
        self.assertTrue(out["quarterly_update_ok"])
        self.assertGreaterEqual(out["known_recall_pct"], 90.0)
        self.assertEqual(out["adaptive_rounds"], 10)
        self.assertGreaterEqual(out["adaptive_min_recall_pct"], 80.0)
        self.assertTrue(out["motif_unique_subsets"])
        self.assertTrue(out["fusion_flags_non_behavioral_failures"])


class TestReportChecks(unittest.TestCase):
    def test_report_checks_pass(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")

    def test_scenario_a_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "scenario A: known mimicry flagged >=90% confidence")
        self.assertTrue(item["pass"])

    def test_scenario_e_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "scenario E: adaptive adversary 10-round recall >=80%")
        self.assertTrue(item["pass"])

    def test_adversarial_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "adversarial: motif-subset reuse is detected")
        self.assertTrue(item["pass"])


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertGreater(result["summary"]["passing"], 0)

    def test_result_shape(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)


class TestJsonRoundTrip(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        blob = json.dumps(result, indent=2)
        parsed = json.JSONDecoder().decode(blob)
        self.assertEqual(parsed["bead_id"], "bd-35m7")


if __name__ == "__main__":
    unittest.main()
