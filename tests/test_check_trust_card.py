"""Unit tests for scripts/check_trust_card.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_trust_card",
    ROOT / "scripts" / "check_trust_card.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixturePaths(TestCase):
    def test_impl_paths_exist(self) -> None:
        self.assertTrue(mod.TRUST_CARD_IMPL.is_file())
        self.assertTrue(mod.API_IMPL.is_file())
        self.assertTrue(mod.CLI_IMPL.is_file())
        self.assertTrue(mod.MAIN_IMPL.is_file())

    def test_contract_exists(self) -> None:
        self.assertTrue(mod.SPEC.parent.is_dir())


class TestEvidenceAnalysis(TestCase):
    def test_evidence_artifact_passes(self) -> None:
        result = mod.analyze_trust_card_evidence()
        self.assertTrue(result["valid_evidence"])
        self.assertTrue(result["bead_id_ok"])
        self.assertTrue(result["status_ok"])
        self.assertTrue(result["commands_ok"])
        self.assertTrue(result["required_files_cited"])

    def test_deterministic_hash_and_signatures_are_source_backed(self) -> None:
        result = mod.analyze_trust_card_evidence()
        self.assertTrue(result["deterministic_card_hash_source"])
        self.assertTrue(result["signature_verification_source"])

    def test_hash_chain_and_diff_are_source_backed(self) -> None:
        result = mod.analyze_trust_card_evidence()
        self.assertTrue(result["hash_chain_source"])
        self.assertTrue(result["diff_source"])
        self.assertTrue(result["e2e_lifecycle_source"])

    def test_missing_evidence_fails_closed(self) -> None:
        result = mod.analyze_trust_card_evidence(ROOT / "no" / "bd-2yh-evidence.json")
        self.assertFalse(result["valid_evidence"])
        self.assertFalse(result["status_ok"])
        self.assertFalse(result["commands_ok"])

    def test_invalid_evidence_fails_closed(self) -> None:
        with patch.object(
            mod,
            "_read_json_object",
            return_value=(None, "invalid JSON: broken"),
        ):
            result = mod.analyze_trust_card_evidence()
        self.assertFalse(result["valid_evidence"])
        self.assertIn("invalid JSON", result["detail"])


class TestChecks(TestCase):
    def test_run_checks_passes(self) -> None:
        report = mod.run_checks()
        self.assertEqual(report["bead_id"], "bd-2yh")
        self.assertEqual(report["verdict"], "PASS")

    def test_self_test_passes(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 10)

    def test_missing_file_is_detected(self) -> None:
        with patch.object(mod, "CLI_IMPL", ROOT / "does" / "not" / "exist.rs"):
            report = mod.run_checks()
        failed = [check for check in report["checks"] if not check["pass"]]
        self.assertTrue(any("file: cli surface" in check["check"] for check in failed))

    def test_required_cli_patterns_include_trust_card_surface(self) -> None:
        self.assertIn("name = \"trust-card\"", mod.REQUIRED_CLI_PATTERNS)
        self.assertIn("pub enum TrustCardCommand", mod.REQUIRED_CLI_PATTERNS)


class TestEvidenceBindingChecks(TestCase):
    def test_required_evidence_binding_patterns_found(self) -> None:
        report = mod.run_checks()
        failed = [
            check
            for check in report["checks"]
            if not check["pass"] and "evidence binding" in check["check"]
        ]
        self.assertEqual([], failed)

    def test_completion_debt_evidence_passes(self) -> None:
        results = mod.check_completion_debt_evidence()
        for result in results:
            self.assertTrue(result["pass"], f"{result['check']}: {result['detail']}")

    def test_completion_debt_records_all_audit_items(self) -> None:
        results = mod.check_completion_debt_evidence()
        coverage = next(
            result
            for result in results
            if result["check"] == "completion debt evidence: all audit items covered"
        )
        self.assertTrue(coverage["pass"])
        for item in mod.COMPLETION_DEBT_ITEMS:
            self.assertIn(item, coverage["detail"])

    def test_completion_debt_evidence_missing_fails_closed(self) -> None:
        with patch.object(mod, "REPLACEMENT_EVIDENCE", Path("/no/bd-1oju-evidence.json")):
            results = mod.check_completion_debt_evidence()
        self.assertFalse(results[0]["pass"])
        self.assertIn("missing", results[0]["detail"])


if __name__ == "__main__":
    main()
