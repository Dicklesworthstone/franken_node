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


def _write_file(root: Path, rel_path: str, text: str) -> None:
    target = root / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _rule(rule_id: str) -> mod.RuleSpec:
    return next(rule for rule in mod.RULES if rule.rule_id == rule_id)


def _write_minimal_docs_truth_root(root: Path) -> None:
    _write_file(
        root,
        "crates/franken-node/Cargo.toml",
        """[features]
engine = []
http-client = []
test-support = []
default = ["engine", "http-client"]
""",
    )
    feature_section = """### Feature Flags

- **`engine`** - engine integration (default: enabled)
- **`http-client`** - HTTP client support (default: enabled)
- **`test-support`** - test helpers
"""
    _write_file(
        root,
        "AGENTS.md",
        f"""# Agents

## Toolchain

Rust 2024; this fixture does not pin a rust-toolchain.toml.

{feature_section}
""",
    )
    _write_file(
        root,
        "docs/ARCHITECTURE_OVERVIEW.md",
        """# Architecture

**Language:** Rust 2024 Edition; no rust-toolchain.toml is pinned.

## Feature Flags

- **`engine`** - engine integration (default: enabled)
- **`http-client`** - HTTP client support (default: enabled)
- **`test-support`** - test helpers
""",
    )
    _write_file(root, "README.md", "# Project\n\nRust 2024\n")
    _write_file(
        root,
        "docs/governance/placeholder_surface_inventory.md",
        """# Placeholder Surface Inventory

External reproduction executes mapped procedure references; dry-run mode is planned only.
""",
    )
    _write_file(root, "docs/reproduction_playbook.md", "Executed runs call mapped procedures.\n")
    _write_file(
        root,
        "scripts/reproduce.py",
        """def verify_claim():
    subprocess.run([])
    detail = "procedure executed successfully and met threshold"

REPORT = {"run_mode": "executed"}
""",
    )


class InventoryParsingTests(unittest.TestCase):
    def test_inventory_tables_include_expected_rows(self) -> None:
        tables = mod.load_inventory_tables()
        inventory_ids = {row["ID"] for row in tables["inventory"]}
        allowed_surfaces = {row["Surface"] for row in tables["allowed_simulations"]}

        self.assertIn("`PSI-003`", inventory_ids)
        self.assertIn("`PSI-010`", inventory_ids)
        self.assertTrue(any("fixture_registry(...)" in surface for surface in allowed_surfaces))
        self.assertTrue(any("fixture_incident_events(...)" in surface for surface in allowed_surfaces))


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

    def test_fixture_only_occurrence_is_allowlisted_without_documented_live_debt(self) -> None:
        rule = _rule("incident_fixture_event_boundary")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _copy_real_inventory(root)
            main_rs = root / "crates/franken-node/src/main.rs"
            main_rs.parent.mkdir(parents=True, exist_ok=True)
            main_rs.write_text(
                "#[cfg(test)]\nmod incident_list_tests {\n    #[test]\n    fn fixture_usage() {\n        let _ = fixture_incident_events(\"INC-1\");\n    }\n}\n",
                encoding="utf-8",
            )
            replay_bundle = root / "crates/franken-node/src/tools/replay_bundle.rs"
            replay_bundle.parent.mkdir(parents=True, exist_ok=True)
            replay_bundle.write_text(
                "#[cfg(test)]\npub(crate) fn fixture_incident_events(id: &str) -> Vec<()> { let _ = id; Vec::new() }\n",
                encoding="utf-8",
            )

            result = mod.evaluate_rule(rule, root=root)

        self.assertTrue(result["pass"])
        self.assertEqual(result["documented_occurrence_count"], 0)
        self.assertEqual(result["allowlisted_occurrence_count"], 2)
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


class DocsTruthTests(unittest.TestCase):
    def test_minimal_docs_truth_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_minimal_docs_truth_root(root)

            checks = mod.evaluate_docs_truth(root)

        self.assertTrue(all(check["pass"] for check in checks), checks)

    def test_stale_reproduction_placeholder_text_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_minimal_docs_truth_root(root)
            _write_file(
                root,
                "docs/governance/placeholder_surface_inventory.md",
                "The script currently emits `pass: true` with verification simulated (full execution requires test harness).\n",
            )

            checks = mod.evaluate_docs_truth(root)
            failed = [check for check in checks if not check["pass"]]

        self.assertEqual([check["check_id"] for check in failed], ["reproduction:procedure_execution_status"])
        self.assertIn("stale_markers=", failed[0]["observed_value"])

    def test_missing_feature_flag_doc_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_minimal_docs_truth_root(root)
            agents = (root / "AGENTS.md").read_text(encoding="utf-8").replace(
                "- **`test-support`** - test helpers\n",
                "",
            )
            (root / "AGENTS.md").write_text(agents, encoding="utf-8")

            checks = mod.evaluate_docs_truth(root)
            failed = [check for check in checks if check["check_id"] == "feature_flags:AGENTS.md"]

        self.assertEqual(len(failed), 1)
        self.assertFalse(failed[0]["pass"])
        self.assertIn("missing=test-support", failed[0]["observed_value"])

    def test_extra_feature_flag_doc_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_minimal_docs_truth_root(root)
            arch = (root / "docs/ARCHITECTURE_OVERVIEW.md").read_text(encoding="utf-8")
            arch += "- **`phantom-feature`** - nonexistent feature\n"
            (root / "docs/ARCHITECTURE_OVERVIEW.md").write_text(arch, encoding="utf-8")

            checks = mod.evaluate_docs_truth(root)
            failed = [
                check
                for check in checks
                if check["check_id"] == "feature_flags:docs/ARCHITECTURE_OVERVIEW.md"
            ]

        self.assertEqual(len(failed), 1)
        self.assertFalse(failed[0]["pass"])
        self.assertIn("extra=phantom-feature", failed[0]["observed_value"])

    def test_incorrect_default_feature_doc_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_minimal_docs_truth_root(root)
            agents = (root / "AGENTS.md").read_text(encoding="utf-8").replace(
                "- **`test-support`** - test helpers",
                "- **`test-support`** - test helpers (default: enabled)",
            )
            (root / "AGENTS.md").write_text(agents, encoding="utf-8")

            checks = mod.evaluate_docs_truth(root)
            failed = [check for check in checks if check["check_id"] == "feature_flags:AGENTS.md"]

        self.assertEqual(len(failed), 1)
        self.assertFalse(failed[0]["pass"])
        self.assertIn("extra_defaults=test-support", failed[0]["observed_value"])

    def test_nightly_toolchain_claim_fails_without_toolchain_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_minimal_docs_truth_root(root)
            arch = (root / "docs/ARCHITECTURE_OVERVIEW.md").read_text(encoding="utf-8")
            arch = arch.replace("Rust 2024 Edition", "Rust 2024 Edition (nightly toolchain)")
            (root / "docs/ARCHITECTURE_OVERVIEW.md").write_text(arch, encoding="utf-8")

            checks = mod.evaluate_docs_truth(root)
            failed = [
                check
                for check in checks
                if check["check_id"] == "toolchain:docs/ARCHITECTURE_OVERVIEW.md"
            ]

        self.assertEqual(len(failed), 1)
        self.assertFalse(failed[0]["pass"])
        self.assertIn("nightly toolchain", failed[0]["observed_value"])


class RealRepoTests(unittest.TestCase):
    def test_run_all_passes_on_shared_tree(self) -> None:
        payload = mod.run_all()
        self.assertTrue(
            payload["overall_pass"],
            (payload["failed_rules"], payload["failed_docs_truth_checks"]),
        )

    def test_ci_workflow_exists(self) -> None:
        workflow = ROOT / ".github/workflows/placeholder-remediation-gate.yml"
        self.assertTrue(workflow.is_file())

    def test_fixture_incident_events_rule_confines_occurrences_to_allowlist(self) -> None:
        payload = mod.run_all()
        rule = next(rule for rule in payload["rules"] if rule["rule_id"] == "incident_fixture_event_boundary")

        self.assertEqual(rule["documented_occurrence_count"], 0)
        self.assertEqual(rule["unexpected_occurrence_count"], 0)
        self.assertEqual(rule["allowlist_escape_count"], 0)
        self.assertGreaterEqual(rule["allowlisted_occurrence_count"], 1)

    def test_demo_signing_key_rule_confines_occurrences_to_allowlist(self) -> None:
        payload = mod.run_all()
        rule = next(rule for rule in payload["rules"] if rule["rule_id"] == "decision_receipt_demo_key_boundary")

        self.assertEqual(rule["unexpected_occurrence_count"], 0)
        self.assertEqual(rule["allowlist_escape_count"], 0)
        self.assertGreaterEqual(rule["allowlisted_occurrence_count"], 1)

    def test_time_travel_fixture_identity_rule_allows_crate_metamorphic_test(self) -> None:
        payload = mod.run_all()
        rule = next(
            rule
            for rule in payload["rules"]
            if rule["rule_id"] == "time_travel_fixture_identity_replay_boundary"
        )
        allowlisted_paths = {occurrence["path"] for occurrence in rule["allowlisted_occurrences"]}

        self.assertEqual(rule["unexpected_occurrence_count"], 0)
        self.assertEqual(rule["allowlist_escape_count"], 0)
        self.assertIn(
            "crates/franken-node/tests/time_travel_metamorphic.rs",
            allowlisted_paths,
        )


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
