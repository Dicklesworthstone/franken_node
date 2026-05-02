"""Unit tests for scripts/check_claim_language_policy.py."""

import json
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_claim_language_policy.py"


class ScriptNamespace:
    def __init__(self, script_globals: dict[str, object]) -> None:
        object.__setattr__(self, "_script_globals", script_globals)

    def __getattr__(self, name: str) -> object:
        return self._script_globals[name]


script_globals = runpy.run_path(str(SCRIPT))
mod = ScriptNamespace(script_globals["run_checks"].__globals__)


def load_json(text: str) -> dict[str, object]:
    return json.JSONDecoder().decode(text)


class TestConstants(unittest.TestCase):
    """Verify module-level constants are well-formed."""

    def test_bead_id(self):
        self.assertEqual(mod.BEAD_ID, "bd-33kj")

    def test_section(self):
        self.assertEqual(mod.SECTION, "10.15")

    def test_required_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 4)

    def test_required_event_codes_prefixed(self):
        for code in mod.REQUIRED_EVENT_CODES:
            self.assertTrue(code.startswith("CLM-"), f"{code} missing CLM- prefix")

    def test_required_sections_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_SECTIONS), 5)

    def test_required_rules_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_RULES), 2)

    def test_required_invariants_prefixed(self):
        for inv in mod.REQUIRED_INVARIANTS:
            self.assertTrue(inv.startswith("INV-EP-"), f"{inv} missing INV-EP- prefix")

    def test_required_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 6)

    def test_required_claim_categories_count(self):
        self.assertEqual(len(mod.REQUIRED_CLAIM_CATEGORIES), 5)

    def test_min_claim_mappings(self):
        self.assertGreaterEqual(mod.MIN_CLAIM_MAPPINGS, 5)

    def test_root_path(self):
        self.assertTrue(mod.ROOT.is_dir())

    def test_policy_path_under_root(self):
        self.assertTrue(str(mod.POLICY_PATH).startswith(str(mod.ROOT)))


class TestHelpers(unittest.TestCase):
    """Tests for helper functions."""

    def test_check_pass(self):
        result = mod._check("test", True, "ok")
        self.assertEqual(result["name"], "test")
        self.assertTrue(result["passed"])
        self.assertEqual(result["detail"], "ok")

    def test_check_fail(self):
        result = mod._check("test", False, "not ok")
        self.assertFalse(result["passed"])

    def test_check_passed_is_bool(self):
        result = mod._check("test", 1, "truthy")
        self.assertIsInstance(result["passed"], bool)

    def test_read_existing_file(self):
        text = mod._read(mod.POLICY_PATH)
        self.assertIn("Claim-Language Policy", text)

    def test_read_missing_file(self):
        text = mod._read(Path("/nonexistent/path.md"))
        self.assertEqual(text, "")

    def test_count_claim_mappings_zero(self):
        self.assertEqual(mod._count_claim_mappings("no claims here"), 0)

    def test_count_claim_mappings_positive(self):
        text = "CLM-DR-01 and CLM-TR-01 are mapped"
        self.assertEqual(mod._count_claim_mappings(text), 2)

    def test_count_claim_mappings_no_false_positives(self):
        text = "CLM- is not a valid claim id"
        self.assertEqual(mod._count_claim_mappings(text), 0)


class TestRunChecks(unittest.TestCase):
    """Tests for run_checks() integration."""

    def setUp(self):
        self.result = mod.run_checks()

    def test_overall_pass(self):
        self.assertTrue(self.result["overall_pass"])
        self.assertEqual(self.result["verdict"], "PASS")

    def test_bead_id(self):
        self.assertEqual(self.result["bead_id"], "bd-33kj")

    def test_section(self):
        self.assertEqual(self.result["section"], "10.15")

    def test_title_present(self):
        self.assertIn("claim", self.result["title"].lower())

    def test_checks_list_not_empty(self):
        self.assertGreater(len(self.result["checks"]), 0)

    def test_summary_counts(self):
        s = self.result["summary"]
        self.assertEqual(s["failing"], 0)
        self.assertEqual(s["total"], s["passing"] + s["failing"])
        self.assertGreaterEqual(s["total"], 25)

    def test_each_check_has_required_keys(self):
        for c in self.result["checks"]:
            self.assertIn("name", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)

    def test_no_failing_checks(self):
        failing = [c for c in self.result["checks"] if not c["passed"]]
        self.assertEqual(len(failing), 0, f"Failing checks: {failing}")


class TestFileExistenceChecks(unittest.TestCase):
    """Verify file existence checks pass."""

    def setUp(self):
        self.result = mod.run_checks()
        self.by_name = {c["name"]: c for c in self.result["checks"]}

    def test_policy_doc_exists(self):
        self.assertTrue(self.by_name["policy_doc_exists"]["passed"])

    def test_spec_contract_exists(self):
        self.assertTrue(self.by_name["spec_contract_exists"]["passed"])

    def test_evidence_artifact_exists(self):
        self.assertTrue(self.by_name["evidence_artifact_exists"]["passed"])


class TestSectionChecks(unittest.TestCase):
    """Verify required sections are found."""

    def setUp(self):
        self.result = mod.run_checks()
        self.by_name = {c["name"]: c for c in self.result["checks"]}

    def test_purpose_section(self):
        self.assertTrue(self.by_name["section:Purpose"]["passed"])

    def test_rules_section(self):
        self.assertTrue(self.by_name["section:Rules"]["passed"])

    def test_event_codes_section(self):
        self.assertTrue(self.by_name["section:Event Codes"]["passed"])

    def test_mapping_table_section(self):
        self.assertTrue(self.by_name["section:Claim-Invariant Mapping Table"]["passed"])


class TestEventCodeChecks(unittest.TestCase):
    """Verify event codes are detected in the policy."""

    def setUp(self):
        self.result = mod.run_checks()
        self.by_name = {c["name"]: c for c in self.result["checks"]}

    def test_clm_001(self):
        self.assertTrue(self.by_name["event_code:CLM-001"]["passed"])

    def test_clm_002(self):
        self.assertTrue(self.by_name["event_code:CLM-002"]["passed"])

    def test_clm_003(self):
        self.assertTrue(self.by_name["event_code:CLM-003"]["passed"])

    def test_clm_004(self):
        self.assertTrue(self.by_name["event_code:CLM-004"]["passed"])


class TestInvariantChecks(unittest.TestCase):
    """Verify asupersync-backed invariants are referenced."""

    def setUp(self):
        self.result = mod.run_checks()
        self.by_name = {c["name"]: c for c in self.result["checks"]}

    def test_inv_ep_monotonic(self):
        self.assertTrue(self.by_name["invariant:INV-EP-MONOTONIC"]["passed"])

    def test_inv_ep_drain_barrier(self):
        self.assertTrue(self.by_name["invariant:INV-EP-DRAIN-BARRIER"]["passed"])

    def test_inv_ep_fail_closed(self):
        self.assertTrue(self.by_name["invariant:INV-EP-FAIL-CLOSED"]["passed"])

    def test_inv_ep_split_brain_guard(self):
        self.assertTrue(self.by_name["invariant:INV-EP-SPLIT-BRAIN-GUARD"]["passed"])

    def test_inv_ep_immutable_creation_epoch(self):
        self.assertTrue(self.by_name["invariant:INV-EP-IMMUTABLE-CREATION-EPOCH"]["passed"])

    def test_inv_ep_audit_history(self):
        self.assertTrue(self.by_name["invariant:INV-EP-AUDIT-HISTORY"]["passed"])


class TestClaimMappingChecks(unittest.TestCase):
    """Verify claim-mapping integrity checks."""

    def setUp(self):
        self.result = mod.run_checks()
        self.by_name = {c["name"]: c for c in self.result["checks"]}

    def test_mapping_count(self):
        self.assertTrue(self.by_name["claim_mapping_count"]["passed"])

    def test_no_unbacked_claims(self):
        self.assertTrue(self.by_name["no_unbacked_claims"]["passed"])


class TestSelfTest(unittest.TestCase):
    """Tests for self_test()."""

    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = mod.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)

    def test_self_test_check_structure(self):
        _, checks = mod.self_test()
        for c in checks:
            self.assertIn("name", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)


class TestJsonOutput(unittest.TestCase):
    """Tests for JSON serialization of results."""

    def test_json_serializable(self):
        result = mod.run_checks()
        output = json.dumps(result, indent=2)
        parsed = load_json(output)
        self.assertEqual(parsed["bead_id"], "bd-33kj")

    def test_json_has_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "section", "title", "checks", "summary",
                     "verdict", "overall_pass"]:
            self.assertIn(key, result, f"Missing key: {key}")


class TestPolicyContentChecks(unittest.TestCase):
    """Verify meta-checks about policy content quality."""

    def setUp(self):
        self.result = mod.run_checks()
        self.by_name = {c["name"]: c for c in self.result["checks"]}

    def test_asupersync_referenced(self):
        self.assertTrue(self.by_name["asupersync_referenced"]["passed"])

    def test_staleness_window_defined(self):
        self.assertTrue(self.by_name["staleness_window_defined"]["passed"])

    def test_retirement_protocol_defined(self):
        self.assertTrue(self.by_name["retirement_protocol_defined"]["passed"])

    def test_evidence_verdict_pass(self):
        self.assertTrue(self.by_name["evidence_verdict_pass"]["passed"])


if __name__ == "__main__":
    unittest.main()
