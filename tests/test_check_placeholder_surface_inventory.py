"""Unit tests for scripts/check_placeholder_surface_inventory.py."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_placeholder_surface_inventory as mod


def _write_inventory(root: Path, text: str) -> None:
    target = root / mod.INVENTORY_DOC_REL
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _copy_real_inventory(root: Path) -> None:
    _write_inventory(root, (ROOT / mod.INVENTORY_DOC_REL).read_text(encoding="utf-8"))


def _rule(rule_id: str) -> mod.RuleSpec:
    return next(rule for rule in mod.RULES if rule.rule_id == rule_id)


class InventoryParsingTests(unittest.TestCase):
    def test_inventory_tables_include_expected_rows(self) -> None:
        tables = mod.load_inventory_tables()
        inventory_ids = {row["ID"] for row in tables["inventory"]}
        allowed_surfaces = {row["Surface"] for row in tables["allowed_simulations"]}

        self.assertIn("`PSI-003`", inventory_ids)
        self.assertIn("`PSI-010`", inventory_ids)
        self.assertTrue(any("fixture_registry(...)" in surface for surface in allowed_surfaces))


class EvaluateRuleTests(unittest.TestCase):
    def test_allowlist_escape_in_production_context_fails(self) -> None:
        rule = _rule("fixture_registry_boundary")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _copy_real_inventory(root)
            target = root / "crates/franken-node/src/main.rs"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                "fn live() {\n    let _ = supply_chain::trust_card::fixture_registry(1);\n}\n",
                encoding="utf-8",
            )

            result = mod.evaluate_rule(rule, root=root)

        self.assertFalse(result["pass"])
        self.assertEqual(result["reason_code"], mod.ALLOWLIST_ESCAPE)
        self.assertEqual(result["allowlist_escape_count"], 1)

    def test_documented_live_occurrence_is_recorded_without_failure(self) -> None:
        rule = _rule("incident_sample_event_boundary")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _copy_real_inventory(root)
            main_rs = root / "crates/franken-node/src/main.rs"
            main_rs.parent.mkdir(parents=True, exist_ok=True)
            main_rs.write_text(
                "fn live() {\n    let _ = sample_incident_events(\"INC-1\");\n}\n",
                encoding="utf-8",
            )
            replay_bundle = root / "crates/franken-node/src/tools/replay_bundle.rs"
            replay_bundle.parent.mkdir(parents=True, exist_ok=True)
            replay_bundle.write_text(
                "pub fn sample_incident_events(id: &str) -> Vec<()> { let _ = id; Vec::new() }\n",
                encoding="utf-8",
            )

            result = mod.evaluate_rule(rule, root=root)

        self.assertTrue(result["pass"])
        self.assertEqual(result["documented_occurrence_count"], 1)
        self.assertEqual(result["allowlisted_occurrence_count"], 1)
        self.assertEqual(result["reason_code"], mod.STATIC_PASS)

    def test_inventory_drift_fails_when_required_row_missing(self) -> None:
        rule = _rule("decision_receipt_demo_key_boundary")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_inventory(
                root,
                """# Placeholder Surface Inventory

## Inventory

| ID | Classification | Surface | Entry points / files | Reachability | Current behavior | Remediation owner |
|---|---|---|---|---|---|---|

## Allowed Simulations

| Surface | Why it is allowed |
|---|---|
""",
            )
            result = mod.evaluate_rule(rule, root=root)

        self.assertFalse(result["pass"])
        self.assertEqual(result["reason_code"], mod.INVENTORY_DRIFT)
        self.assertTrue(result["inventory_alignment_failures"])


class RealRepoTests(unittest.TestCase):
    def test_run_all_passes_on_shared_tree(self) -> None:
        payload = mod.run_all()
        self.assertTrue(payload["overall_pass"], payload["failed_rules"])

    def test_ci_workflow_exists(self) -> None:
        workflow = ROOT / ".github/workflows/placeholder-remediation-gate.yml"
        self.assertTrue(workflow.is_file())

    def test_incident_sample_events_rule_reports_documented_live_debt(self) -> None:
        payload = mod.run_all()
        rule = next(rule for rule in payload["rules"] if rule["rule_id"] == "incident_sample_event_boundary")
        documented_paths = {entry["path"] for entry in rule["documented_occurrences"]}

        self.assertIn("crates/franken-node/src/main.rs", documented_paths)
        self.assertGreaterEqual(rule["documented_occurrence_count"], 1)

    def test_demo_signing_key_rule_confines_occurrences_to_allowlist(self) -> None:
        payload = mod.run_all()
        rule = next(rule for rule in payload["rules"] if rule["rule_id"] == "decision_receipt_demo_key_boundary")

        self.assertEqual(rule["unexpected_occurrence_count"], 0)
        self.assertEqual(rule["allowlist_escape_count"], 0)
        self.assertGreaterEqual(rule["allowlisted_occurrence_count"], 1)


class ArtifactWriteTests(unittest.TestCase):
    def test_write_artifacts_creates_expected_files(self) -> None:
        payload = mod.run_all()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            mod.write_artifacts(payload, root)

            evidence = root / mod.EVIDENCE_PATH_REL
            summary = root / mod.SUMMARY_PATH_REL
            self.assertTrue(evidence.exists())
            self.assertTrue(summary.exists())
            self.assertIn("Placeholder Surface Inventory Gate", summary.read_text(encoding="utf-8"))
            self.assertIn("Documented Open Debt", summary.read_text(encoding="utf-8"))


class SelfTestTests(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    unittest.main()
