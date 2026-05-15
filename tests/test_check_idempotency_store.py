"""Unit tests for scripts/check_idempotency_store.py (bd-206h)."""
# ruff: noqa: E402

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_idempotency_store as mod


class TestConstants(unittest.TestCase):
    def test_required_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 7)

    def test_required_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 5)

    def test_required_core_types_count(self):
        self.assertEqual(len(mod.REQUIRED_CORE_TYPES), 5)

    def test_required_operations_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_OPERATIONS), 8)


class TestEvidenceAnalysis(unittest.TestCase):
    def test_hash_deterministic(self):
        result = mod.analyze_dedupe_store_evidence()
        self.assertTrue(result["hash_payload_test_present"])

    def test_content_hash_determinism_verified(self):
        result = mod.analyze_dedupe_store_evidence()
        self.assertTrue(result["content_hash_determinism_verified"])

    def test_ttl_expired(self):
        result = mod.analyze_dedupe_store_evidence()
        self.assertTrue(result["ttl_expiration_verified"])

    def test_ttl_boundary_expired(self):
        result = mod.analyze_dedupe_store_evidence()
        self.assertTrue(result["ttl_boundary_test_present"])

    def test_ttl_not_expired(self):
        result = mod.analyze_dedupe_store_evidence()
        self.assertTrue(result["ttl_live_window_test_present"])

    def test_event_code_count(self):
        result = mod.analyze_dedupe_store_evidence()
        self.assertTrue(result["event_codes_match"])

    def test_invariant_count(self):
        result = mod.analyze_dedupe_store_evidence()
        self.assertTrue(result["invariants_covered"])

    def test_core_type_count(self):
        result = mod.analyze_dedupe_store_evidence()
        self.assertTrue(result["core_variants_covered"])

    def test_missing_evidence_fails_closed(self):
        result = mod.analyze_dedupe_store_evidence(ROOT / "no" / "evidence.json")
        self.assertFalse(result["valid_evidence"])
        self.assertFalse(result["verdict_ok"])

    def test_invalid_evidence_fails_closed(self):
        with patch.object(mod, "_read_json", return_value=(None, "invalid JSON: broken")):
            result = mod.analyze_dedupe_store_evidence()
        self.assertFalse(result["valid_evidence"])
        self.assertIn("invalid JSON", result["detail"])


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-206h")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.14")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["total"], 40)

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestRunAll(unittest.TestCase):
    def test_run_all_alias(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-206h")


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok, "self_test failed")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.JSONDecoder().decode(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-206h")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in [
            "bead_id",
            "title",
            "section",
            "verdict",
            "total",
            "passed",
            "failed",
            "checks",
        ]:
            self.assertIn(key, result)


class TestHelpers(unittest.TestCase):
    def test_sha256_deterministic(self):
        h1 = mod._sha256_hex(b"test")
        h2 = mod._sha256_hex(b"test")
        self.assertEqual(h1, h2)

    def test_sha256_distinct(self):
        h1 = mod._sha256_hex(b"a")
        h2 = mod._sha256_hex(b"b")
        self.assertNotEqual(h1, h2)


class TestFileChecks(unittest.TestCase):
    def test_source_exists(self):
        result = mod.run_checks()
        impl_check = next(c for c in result["checks"] if "SOURCE_EXISTS" in c["check"])
        self.assertTrue(impl_check["pass"])

    def test_spec_exists(self):
        result = mod.run_checks()
        spec_check = next(c for c in result["checks"] if "contract spec" in c["check"])
        self.assertTrue(spec_check["pass"])


class TestIndividualCheckGroups(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = mod.run_checks()
        cls.checks_by_name = {c["check"]: c for c in cls.result["checks"]}

    def _assert_pass(self, name):
        self.assertIn(name, self.checks_by_name, f"check '{name}' not found")
        self.assertTrue(self.checks_by_name[name]["pass"],
                        f"check '{name}' failed: {self.checks_by_name[name]['detail']}")

    def test_event_codes_all(self):
        self._assert_pass("EVENT_CODES all 7 present")

    def test_invariants_all(self):
        self._assert_pass("INVARIANTS all 5 present")

    def test_conflict_error(self):
        self._assert_pass("CONFLICT_ERROR code")

    def test_ttl_default(self):
        self._assert_pass("TTL_EXPIRATION: DEFAULT_TTL_SECS defined")

    def test_crash_recovery_recover(self):
        self._assert_pass("CRASH_RECOVERY: recover_inflight")

    def test_audit_trail(self):
        self._assert_pass("AUDIT_TRAIL: export_audit_log_jsonl")

    def test_content_hash_covers_created_at(self):
        self._assert_pass("CONTENT_HASH: created_at_secs participates")

    def test_content_hash_covers_ttl(self):
        self._assert_pass("CONTENT_HASH: ttl_secs participates")

    def test_content_hash_covers_completed_at(self):
        self._assert_pass("CONTENT_HASH: completed_at_secs participates")

    def test_content_hash_covers_result_data(self):
        self._assert_pass("CONTENT_HASH: result_data participates")

    def test_content_hash_encodes_outcome_presence(self):
        self._assert_pass("CONTENT_HASH: outcome presence is encoded")

    def test_schema_version(self):
        self._assert_pass("SCHEMA_VERSION ids-v1.0")

    def test_dedupe_result_inflight(self):
        self._assert_pass("DedupeResult::InFlight variant")

    def test_hash_payload(self):
        self._assert_pass("hash_payload helper")

    def test_serde(self):
        self._assert_pass("Serde Serialize derive")


if __name__ == "__main__":
    unittest.main()
