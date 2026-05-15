"""Unit tests for scripts/check_trust_object_ids.py."""

import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_trust_object_ids as mod  # noqa: E402


def _json_round_trip(value):
    encoded = json.dumps(value)
    try:
        return json.JSONDecoder().decode(encoded)
    except json.JSONDecodeError as exc:
        raise AssertionError("JSON round-trip failed") from exc


class TestConstants(unittest.TestCase):
    def test_required_structs_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_STRUCTS), 7)

    def test_required_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 2)

    def test_required_error_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_ERROR_CODES), 4)

    def test_required_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 4)

    def test_required_functions_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_FUNCTIONS), 12)

    def test_domain_prefixes_count(self):
        self.assertEqual(len(mod.DOMAIN_PREFIXES), 6)

    def test_derivation_modes_count(self):
        self.assertEqual(len(mod.DERIVATION_MODES), 2)

    def test_required_spec_sections_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_SPEC_SECTIONS), 9)


class TestEvidenceAnalysis(unittest.TestCase):
    def _valid_evidence(self):
        data = mod._load_json(mod.EVIDENCE_FILE)
        self.assertIsInstance(data, dict)
        return deepcopy(data)

    def test_valid_evidence_passes(self):
        checks = mod.analyze_trust_object_evidence(self._valid_evidence())
        self.assertTrue(all(c["pass"] for c in checks), self._failing(checks))

    def test_empty_evidence_fails_closed(self):
        checks = mod.analyze_trust_object_evidence({})
        self.assertFalse(all(c["pass"] for c in checks))
        self.assertTrue(any(c["check"] == "evidence verdict PASS" and not c["pass"] for c in checks))

    def test_bad_verdict_fails_closed(self):
        data = self._valid_evidence()
        data["verdict"] = "FAIL"
        checks = mod.analyze_trust_object_evidence(data)
        self.assertFalse(all(c["pass"] for c in checks))
        self.assertTrue(any(c["check"] == "evidence verdict PASS" and not c["pass"] for c in checks))

    def test_missing_acceptance_marker_fails_closed(self):
        data = self._valid_evidence()
        data["acceptance_criteria"]["AC1_domain_prefixes"] = "PASS"
        checks = mod.analyze_trust_object_evidence(data)
        self.assertFalse(all(c["pass"] for c in checks))
        self.assertTrue(any(
            c["check"] == "evidence acceptance AC1_domain_prefixes" and not c["pass"]
            for c in checks
        ))

    def test_underreported_rust_tests_fail_closed(self):
        data = self._valid_evidence()
        data["metrics"]["rust_unit_tests"] = 0
        checks = mod.analyze_trust_object_evidence(data)
        self.assertFalse(all(c["pass"] for c in checks))
        self.assertTrue(any(c["check"] == "evidence Rust unit test count" and not c["pass"] for c in checks))

    def test_malformed_numeric_metric_fails_closed(self):
        data = self._valid_evidence()
        data["metrics"]["functions_verified"] = "many"
        checks = mod.analyze_trust_object_evidence(data)
        self.assertFalse(all(c["pass"] for c in checks))
        self.assertTrue(any(c["check"] == "evidence function coverage" and not c["pass"] for c in checks))

    def _failing(self, checks):
        failures = [c for c in checks if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-1l5")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.10")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["total"], 80)

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestRunAll(unittest.TestCase):
    def test_run_all_alias(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-1l5")
        self.assertIn("verdict", result)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok, f"self_test failed with {sum(1 for c in checks if not c['pass'])} failures")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = _json_round_trip(result)
        self.assertEqual(parsed["bead_id"], "bd-1l5")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result)


class TestHelpers(unittest.TestCase):
    def test_load_json_valid_artifact(self):
        data = mod._load_json(mod.EVIDENCE_FILE)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["bead_id"], "bd-1l5")

    def test_load_json_missing_file(self):
        self.assertIsNone(mod._load_json(Path("/nonexistent/bd-1l5-evidence.json")))

    def test_pass_text_rejects_non_string(self):
        self.assertEqual(mod._pass_text({"not": "text"}), "")

    def test_metric_int_rejects_non_numeric(self):
        self.assertEqual(mod._metric_int({"rust_unit_tests": "many"}, "rust_unit_tests"), 0)


class TestFileChecks(unittest.TestCase):
    def test_impl_exists(self):
        result = mod.run_checks()
        impl_check = next(
            c for c in result["checks"] if "trust_object_id implementation" in c["check"]
        )
        self.assertTrue(impl_check["pass"])

    def test_spec_exists(self):
        result = mod.run_checks()
        spec_check = next(c for c in result["checks"] if "contract spec" in c["check"])
        self.assertTrue(spec_check["pass"])


class TestCommentOnlyRustRegression(unittest.TestCase):
    """Commented Rust markers must not satisfy implementation checks."""

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            impl_file = Path(tmp) / "trust_object_id.rs"
            markers = (
                REQUIRED_RUST_MARKERS
                + [
                    "Sha256",
                    "hex::encode",
                    "64",
                    "hex chars",
                    "Serialize",
                    "Deserialize",
                    "assert_send",
                    "assert_sync",
                    "cross_domain",
                    "deterministic",
                    "sha256",
                    "256",
                ]
            )
            impl_file.write_text(
                "\n".join(f"// {marker}" for marker in markers)
                + "\n/*\n"
                + "\n".join("#[test]" for _ in range(45))
                + "\n*/\n",
                encoding="utf-8",
            )

            original_impl = mod.IMPL_FILE
            mod.IMPL_FILE = impl_file
            try:
                result = mod.run_checks()
            finally:
                mod.IMPL_FILE = original_impl

        by_name = {check["check"]: check for check in result["checks"]}
        self.assertTrue(by_name["trust_object_id implementation exists"]["pass"])

        rust_marker_prefixes = (
            "struct/enum ",
            "event code ",
            "error code ",
            "invariant ",
            "function ",
            "domain ",
            "derivation mode ",
            "serde derives on ",
            "test: ",
            "AC",
        )
        rust_marker_names = [
            check["check"]
            for check in result["checks"]
            if check["check"].startswith(rust_marker_prefixes)
            or check["check"]
            in {
                "6 domain prefixes defined",
                "imports sha2::Sha256",
                "uses hex::encode",
                "SHA-256 digest length check",
                "Rust unit tests present (0)",
                "Send + Sync assertions",
            }
            or check["check"].startswith("domain prefix ")
            or check["check"].startswith("Rust unit tests present")
        ]
        self.assertTrue(rust_marker_names)
        self.assertTrue(all(not by_name[name]["pass"] for name in rust_marker_names))


REQUIRED_RUST_MARKERS = (
    mod.REQUIRED_EVENT_CODES
    + mod.REQUIRED_ERROR_CODES
    + mod.REQUIRED_INVARIANTS
    + mod.REQUIRED_FUNCTIONS
    + [name for name, _prefix in mod.DOMAIN_PREFIXES]
    + [f'"{prefix}"' for _name, prefix in mod.DOMAIN_PREFIXES]
    + mod.DERIVATION_MODES
    + [f"pub struct {name}" for name in mod.REQUIRED_STRUCTS]
    + [f"pub enum {name}" for name in mod.REQUIRED_STRUCTS]
    + [
        "fn split_prefix",
        "DomainPrefix::all()",
        "strip_prefix(domain.prefix())",
        "IdError::InvalidPrefix",
        "hasher.update(b\"trust_object_hash_v1:\")",
        "hasher.update(b\"trust_object_derive_v1:\")",
        "to_le_bytes()",
        "to_be_bytes()",
        "hex::encode(hasher.finalize())",
        "let domain_bytes = domain.prefix().as_bytes();",
        "hasher.update(domain_bytes);",
        "\"{}sha256:{}\"",
        "\"{}{}:{}:{}\"",
        "Sha256::new()",
        "validate_hex_digest",
        "s.len() != 64",
        "is_ascii_digit()",
        "test_all_domains_count",
        "test_parse_round_trip",
        "test_cross_domain_collision",
        "test_derive_content_addressed",
        "test_derive_context_addressed",
        "test_short_form",
        "test_error_codes",
        "test_trust_object_id_serde",
        "test_types_send_sync",
        "test_derive_trust_object_id_events_uses_caller_inputs",
        "test_registry_new",
        "test_content_addressed_deterministic",
    ]
)


if __name__ == "__main__":
    unittest.main()
