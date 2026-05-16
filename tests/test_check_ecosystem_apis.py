"""Unit tests for scripts/check_ecosystem_apis.py (bd-2aj)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Add scripts directory to import path.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_ecosystem_apis as checker  # noqa: E402


def _write_comment_only_fixture(root: Path) -> dict[str, Path]:
    connector = root / "crates" / "franken-node" / "src" / "connector"
    connector.mkdir(parents=True)
    docs = root / "docs" / "specs" / "section_10_12"
    docs.mkdir(parents=True)

    paths = {
        "contract": docs / "bd-2aj_contract.md",
        "schema": docs / "bd-2aj_api_schema.md",
        "registry": connector / "ecosystem_registry.rs",
        "reputation": connector / "ecosystem_reputation.rs",
        "compliance": connector / "ecosystem_compliance.rs",
        "mod": connector / "mod.rs",
    }

    paths["contract"].write_text(
        "\n".join(["# bd-2aj contract", *checker.REQUIRED_CONTRACT_INVARIANTS]),
        encoding="utf-8",
    )
    paths["schema"].write_text(
        "\n".join(
            [
                "# bd-2aj API schema",
                *checker.REQUIRED_SCHEMA_ENDPOINTS,
                *checker.REQUIRED_SCHEMA_AUTH_TERMS,
            ]
        ),
        encoding="utf-8",
    )
    paths["mod"].write_text(
        "\n".join(
            [
                "// pub mod ecosystem_registry;",
                "//! pub mod ecosystem_reputation;",
                "/* pub mod ecosystem_compliance; */",
            ]
        ),
        encoding="utf-8",
    )

    paths["registry"].write_text(
        "\n".join(
            [
                "// " + " ".join(checker.REQUIRED_REGISTRY_SYMBOLS),
                "/*",
                "SybilDuplicate",
                "RateLimitExceeded",
                "ENE-001 ENE-002 ENE-011",
                "*/",
            ]
        ),
        encoding="utf-8",
    )
    paths["reputation"].write_text(
        "\n".join(
            [
                "/*",
                *checker.REQUIRED_REPUTATION_SYMBOLS,
                "is_anomalous_delta",
                "file_dispute",
                "resolve_dispute",
                "ENE-003 ENE-004",
                "*/",
            ]
        ),
        encoding="utf-8",
    )
    paths["compliance"].write_text(
        "\n".join(
            [
                "// " + " ".join(checker.REQUIRED_COMPLIANCE_SYMBOLS),
                "// " + " ".join(checker.REQUIRED_CROSS_PROGRAM_TESTS),
                "// ENE-005 ENE-006 ENE-007 ENE-008 ENE-009 ENE-010",
            ]
        ),
        encoding="utf-8",
    )
    return paths


def _patch_paths(root: Path, paths: dict[str, Path]):
    return mock.patch.multiple(
        checker,
        ROOT=root,
        CONTRACT_PATH=paths["contract"],
        API_SCHEMA_PATH=paths["schema"],
        REGISTRY_PATH=paths["registry"],
        REPUTATION_PATH=paths["reputation"],
        COMPLIANCE_PATH=paths["compliance"],
        MOD_PATH=paths["mod"],
    )


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        self.assertTrue(checker.self_test())


class TestFileChecks(unittest.TestCase):
    def test_contract_exists(self) -> None:
        result = checker.check_file_exists(checker.CONTRACT_PATH)
        self.assertTrue(result["exists"])
        self.assertGreater(result["size_bytes"], 0)

    def test_schema_exists(self) -> None:
        result = checker.check_file_exists(checker.API_SCHEMA_PATH)
        self.assertTrue(result["exists"])
        self.assertGreater(result["size_bytes"], 0)

    def test_registry_module_exists(self) -> None:
        result = checker.check_file_exists(checker.REGISTRY_PATH)
        self.assertTrue(result["exists"])

    def test_reputation_module_exists(self) -> None:
        result = checker.check_file_exists(checker.REPUTATION_PATH)
        self.assertTrue(result["exists"])

    def test_compliance_module_exists(self) -> None:
        result = checker.check_file_exists(checker.COMPLIANCE_PATH)
        self.assertTrue(result["exists"])


class TestContractCoverage(unittest.TestCase):
    def test_contract_invariants_present(self) -> None:
        result = checker.check_content(
            checker.CONTRACT_PATH,
            checker.REQUIRED_CONTRACT_INVARIANTS,
            "contract file not found",
        )
        self.assertTrue(result["pass"], f"missing invariants: {result['missing']}")


class TestApiSchemaCoverage(unittest.TestCase):
    def test_schema_endpoints_present(self) -> None:
        result = checker.check_content(
            checker.API_SCHEMA_PATH,
            checker.REQUIRED_SCHEMA_ENDPOINTS,
            "api schema file not found",
        )
        self.assertTrue(result["pass"], f"missing endpoints: {result['missing']}")

    def test_endpoint_coverage_threshold(self) -> None:
        result = checker.check_endpoint_coverage()
        self.assertTrue(result["pass"])
        self.assertGreaterEqual(result["coverage_pct"], 95.0)

    def test_auth_and_pagination_terms_present(self) -> None:
        result = checker.check_content(
            checker.API_SCHEMA_PATH,
            checker.REQUIRED_SCHEMA_AUTH_TERMS,
            "api schema file not found",
        )
        self.assertTrue(result["pass"], f"missing terms: {result['missing']}")


class TestRustSymbolCoverage(unittest.TestCase):
    def test_registry_symbols_present(self) -> None:
        result = checker.check_content(
            checker.REGISTRY_PATH,
            checker.REQUIRED_REGISTRY_SYMBOLS,
            "registry module not found",
        )
        self.assertTrue(result["pass"], f"missing symbols: {result['missing']}")

    def test_reputation_symbols_present(self) -> None:
        result = checker.check_content(
            checker.REPUTATION_PATH,
            checker.REQUIRED_REPUTATION_SYMBOLS,
            "reputation module not found",
        )
        self.assertTrue(result["pass"], f"missing symbols: {result['missing']}")

    def test_compliance_symbols_present(self) -> None:
        result = checker.check_content(
            checker.COMPLIANCE_PATH,
            checker.REQUIRED_COMPLIANCE_SYMBOLS,
            "compliance module not found",
        )
        self.assertTrue(result["pass"], f"missing symbols: {result['missing']}")

    def test_preserves_string_literals_while_stripping_comments(self) -> None:
        source = (
            'pub const KEEP: &str = "ENE-001 // literal"; // "ENE-002"\n'
            'pub const RAW: &str = r#"ENE-003 /* literal */"#; /* "ENE-004" */\n'
        )

        stripped = checker._strip_rust_comments(source)

        self.assertIn('"ENE-001 // literal"', stripped)
        self.assertIn('r#"ENE-003 /* literal */"#', stripped)
        self.assertNotIn('"ENE-002"', stripped)
        self.assertNotIn('"ENE-004"', stripped)

    def test_comment_only_rust_markers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = _write_comment_only_fixture(root)
            with _patch_paths(root, paths):
                evidence = checker.run_all_checks()

        checks = evidence["checks"]
        self.assertTrue(checks["files"]["registry_module"]["exists"])
        self.assertTrue(checks["files"]["reputation_module"]["exists"])
        self.assertTrue(checks["files"]["compliance_module"]["exists"])
        self.assertTrue(checks["files"]["connector_mod"]["exists"])
        self.assertTrue(checks["contract_invariants"]["pass"])
        self.assertTrue(checks["api_schema_contract"]["pass"])
        self.assertTrue(checks["endpoint_coverage"]["pass"])
        self.assertTrue(checks["auth_and_pagination"]["pass"])

        for key in [
            "registry_symbols",
            "reputation_symbols",
            "compliance_symbols",
            "event_codes",
            "anti_gaming",
            "cross_program_evidence",
            "mod_registration",
        ]:
            self.assertFalse(checks[key]["pass"], key)

        self.assertFalse(evidence["overall_pass"])


class TestBehaviorChecks(unittest.TestCase):
    def test_event_codes_present(self) -> None:
        result = checker.check_event_codes()
        self.assertTrue(result["pass"], f"missing event codes: {result['missing']}")

    def test_anti_gaming_markers_present(self) -> None:
        result = checker.check_anti_gaming()
        self.assertTrue(result["pass"], f"missing markers: {result['missing']}")

    def test_cross_program_evidence_tests_present(self) -> None:
        result = checker.check_cross_program_evidence()
        self.assertTrue(result["pass"], f"missing tests: {result['missing']}")

    def test_mod_registration(self) -> None:
        result = checker.check_mod_registration()
        self.assertTrue(result["pass"], f"missing modules: {result['missing']}")


class TestFullEvidence(unittest.TestCase):
    def test_run_all_checks_shape(self) -> None:
        evidence = checker.run_all_checks()
        self.assertEqual(evidence["bead_id"], "bd-2aj")
        self.assertEqual(evidence["section"], "10.12")
        self.assertIn("timestamp", evidence)
        self.assertIn("checks", evidence)
        self.assertIn("summary", evidence)

    def test_overall_pass(self) -> None:
        evidence = checker.run_all_checks()
        self.assertTrue(evidence["overall_pass"])

    def test_summary_counts(self) -> None:
        evidence = checker.run_all_checks()
        self.assertEqual(evidence["summary"]["total_checks"], 12)
        self.assertEqual(evidence["summary"]["passed"], 12)
        self.assertEqual(evidence["summary"]["failed"], 0)

    def test_json_serializable(self) -> None:
        evidence = checker.run_all_checks()
        payload = json.dumps(evidence)
        self.assertGreater(len(payload), 0)
        restored = json.JSONDecoder().decode(payload)
        self.assertEqual(restored["bead_id"], "bd-2aj")
