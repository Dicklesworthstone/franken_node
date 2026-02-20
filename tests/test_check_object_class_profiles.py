"""Unit tests for check_object_class_profiles.py."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_object_class_profiles.py"
SPEC = ROOT / "docs" / "specs" / "object_class_profiles.md"
CONFIG = ROOT / "config" / "object_class_profiles.toml"
REGISTRY = ROOT / "artifacts" / "10.14" / "object_class_registry.json"
FIXTURE = ROOT / "fixtures" / "object_class_profiles" / "cases.json"

sys.path.insert(0, str(ROOT / "scripts"))
import check_object_class_profiles as cocp


class TestObjectClassProfileFiles(unittest.TestCase):
    def test_spec_exists(self):
        self.assertTrue(SPEC.is_file())

    def test_config_exists(self):
        self.assertTrue(CONFIG.is_file())

    def test_registry_exists(self):
        self.assertTrue(REGISTRY.is_file())

    def test_fixture_exists(self):
        self.assertTrue(FIXTURE.is_file())


class TestObjectClassProfileSemantics(unittest.TestCase):
    def test_required_classes_present(self):
        config = cocp.load_config()
        classes = set(config.get("classes", {}).keys())
        for class_name in cocp.REQUIRED_CLASSES:
            self.assertIn(class_name, classes)

    def test_unknown_class_rejected(self):
        config = cocp.load_config()
        ok, err = cocp.validate_class_name("unknown_artifact", config)
        self.assertFalse(ok)
        self.assertEqual(err, "OCP_UNKNOWN_CLASS")

    def test_known_class_allowed(self):
        config = cocp.load_config()
        ok, err = cocp.validate_class_name("trust_receipt", config)
        self.assertTrue(ok)
        self.assertIsNone(err)


class TestVerificationArtifacts(unittest.TestCase):
    def test_registry_has_event_codes(self):
        registry = cocp.load_registry()
        self.assertTrue(set(cocp.EVENT_CODES).issubset(set(registry.get("event_codes", []))))

    def test_registry_has_error_codes(self):
        registry = cocp.load_registry()
        self.assertTrue(set(cocp.ERROR_CODES).issubset(set(registry.get("error_codes", []))))

    def test_fixture_cases_cover_pass_and_fail(self):
        fixture = json.loads(FIXTURE.read_text())
        cases = fixture.get("cases", [])
        self.assertGreaterEqual(len(cases), 3)
        self.assertTrue(any(case.get("expected_valid") is True for case in cases))
        self.assertTrue(any(case.get("expected_valid") is False for case in cases))


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test_passes(self):
        report = cocp.self_test()
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["summary"]["failing_checks"], 0)

    def test_cli_json_output(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(ROOT),
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = json.loads(completed.stdout)
        self.assertEqual(output["verdict"], "PASS")
        check_ids = {check["id"] for check in output["checks"]}
        self.assertIn("OCP-CONFIG", check_ids)
        self.assertIn("OCP-INTEGRATION", check_ids)
        self.assertIn("OCP-LOGS", check_ids)


if __name__ == "__main__":
    unittest.main()
