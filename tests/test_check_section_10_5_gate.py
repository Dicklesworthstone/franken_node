"""Unit tests for scripts/check_section_10_5_gate.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_section_10_5_gate as mod


class TestConstants(unittest.TestCase):
    def test_section_beads_count(self):
        self.assertEqual(len(mod.SECTION_BEADS), 8)

    def test_cross_bead_patterns_count(self):
        self.assertGreaterEqual(len(mod.CROSS_BEAD_PATTERNS), 6)

    def test_event_code_families_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_EVENT_CODE_FAMILIES), 4)

    def test_all_beads_have_required_keys(self):
        for bead_id, info in mod.SECTION_BEADS.items():
            self.assertIn("title", info, f"{bead_id} missing title")
            self.assertIn("evidence", info, f"{bead_id} missing evidence")
            self.assertIn("impl_files", info, f"{bead_id} missing impl_files")
            self.assertIn("spec", info, f"{bead_id} missing spec")


class TestBeadEvidence(unittest.TestCase):
    def test_existing_bead(self):
        info = mod.SECTION_BEADS["bd-137"]
        results = mod.check_bead_evidence("bd-137", info)
        self.assertTrue(len(results) >= 3)
        self.assertTrue(results[0]["pass"], f"Evidence exists failed: {results[0]}")

    def test_all_beads_have_evidence(self):
        for bead_id, info in mod.SECTION_BEADS.items():
            results = mod.check_bead_evidence(bead_id, info)
            exists_check = results[0]
            self.assertTrue(exists_check["pass"], f"{bead_id} evidence missing: {exists_check}")

    def test_all_beads_pass_verdict(self):
        for bead_id, info in mod.SECTION_BEADS.items():
            results = mod.check_bead_evidence(bead_id, info)
            verdict_check = results[1]
            self.assertTrue(verdict_check["pass"], f"{bead_id} verdict not PASS: {verdict_check}")


class TestEvidencePasses(unittest.TestCase):
    def test_standard_pass(self):
        info = mod.SECTION_BEADS["bd-137"]
        self.assertTrue(mod._evidence_passes(info))

    def test_all_beads_pass(self):
        for bead_id, info in mod.SECTION_BEADS.items():
            self.assertTrue(mod._evidence_passes(info), f"{bead_id} evidence does not pass")

    def test_missing_file(self):
        fake = {"evidence": Path("/nonexistent/file.json")}
        self.assertFalse(mod._evidence_passes(fake))


class TestCrossBeadIntegration(unittest.TestCase):
    def test_all_patterns_found(self):
        results = mod.check_cross_bead_integration()
        for r in results:
            self.assertTrue(r["pass"], f"Cross-bead check failed: {r['check']}: {r['detail']}")

    def test_result_count(self):
        results = mod.check_cross_bead_integration()
        self.assertEqual(len(results), len(mod.CROSS_BEAD_PATTERNS))


class TestAuditEventCoverage(unittest.TestCase):
    def test_all_families_found(self):
        results = mod.check_audit_event_coverage()
        for r in results:
            self.assertTrue(r["pass"], f"Audit coverage failed: {r['check']}: {r['detail']}")

    def test_result_count(self):
        results = mod.check_audit_event_coverage()
        self.assertEqual(len(results), len(mod.REQUIRED_EVENT_CODE_FAMILIES))


class TestSectionModuleCount(unittest.TestCase):
    def test_sufficient_modules(self):
        result = mod.check_section_module_count()
        self.assertTrue(result["pass"], f"Module count check failed: {result['detail']}")


class TestAllBeadsClosed(unittest.TestCase):
    def test_all_closed(self):
        result = mod.check_all_beads_closed()
        self.assertTrue(result["pass"], f"Not all beads closed: {result['detail']}")


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"], self._failing_details(result))

    def test_verdict_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing_details(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-1koz")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.5")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0, self._failing_details(result))

    def test_beads_checked(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["beads_checked"], 8)

    def test_beads_passed(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["beads_passed"], 8)

    def test_has_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 40)

    def _failing_details(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, msg = mod.self_test()
        self.assertTrue(ok, msg)


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-1koz")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
