"""Unit tests for check_sandbox_profiles.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_sandbox_profiles.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-3ua7/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestSandboxFixtures(unittest.TestCase):

    def _load_fixture(self, name):
        path = ROOT / "fixtures/sandbox_profiles" / name
        self.assertTrue(path.is_file(), f"Fixture {name} must exist")
        return decode_json_object(path.read_text(encoding="utf-8"))

    def test_profile_capabilities_exist(self):
        data = self._load_fixture("profile_capabilities.json")
        self.assertIn("profiles", data)

    def test_downgrade_scenarios_exist(self):
        data = self._load_fixture("downgrade_scenarios.json")
        self.assertIn("cases", data)
        self.assertGreater(len(data["cases"]), 0)

    def test_all_four_profiles_in_capabilities(self):
        data = self._load_fixture("profile_capabilities.json")
        for p in ["strict", "strict_plus", "moderate", "permissive"]:
            self.assertIn(p, data["profiles"], f"Missing profile {p}")

    def test_each_profile_has_6_grants(self):
        data = self._load_fixture("profile_capabilities.json")
        for p, info in data["profiles"].items():
            self.assertEqual(len(info["grants"]), 6, f"Profile {p} should have 6 grants")

    def test_strict_all_deny(self):
        data = self._load_fixture("profile_capabilities.json")
        for cap, access in data["profiles"]["strict"]["grants"].items():
            self.assertEqual(access, "deny", f"strict.{cap} should be deny")

    def test_permissive_all_allow(self):
        data = self._load_fixture("profile_capabilities.json")
        for cap, access in data["profiles"]["permissive"]["grants"].items():
            self.assertEqual(access, "allow", f"permissive.{cap} should be allow")

    def test_downgrade_has_blocked_and_ok_cases(self):
        data = self._load_fixture("downgrade_scenarios.json")
        results = [c["expected"] for c in data["cases"]]
        self.assertIn("ok", results)
        self.assertIn("SANDBOX_DOWNGRADE_BLOCKED", results)

    def test_levels_ascending(self):
        data = self._load_fixture("profile_capabilities.json")
        levels = [data["profiles"][p]["level"] for p in ["strict", "strict_plus", "moderate", "permissive"]]
        for i in range(1, len(levels)):
            self.assertGreater(levels[i], levels[i - 1])


class TestSandboxCompilerOutput(unittest.TestCase):

    def test_compiler_output_exists(self):
        path = ROOT / "artifacts/section_10_13/bd-3ua7/sandbox_profile_compiler_output.json"
        self.assertTrue(path.is_file())

    def test_compiler_output_has_4_policies(self):
        path = ROOT / "artifacts/section_10_13/bd-3ua7/sandbox_profile_compiler_output.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["compiled_policies"]), 4)

    def test_each_policy_has_6_grants(self):
        path = ROOT / "artifacts/section_10_13/bd-3ua7/sandbox_profile_compiler_output.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        for p in data["compiled_policies"]:
            self.assertEqual(len(p["grants"]), 6, f"Policy {p['profile']} should have 6 grants")


class TestSandboxImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/security/sandbox_policy_compiler.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_sandbox_profile_enum(self):
        self.assertIn("enum SandboxProfile", self.content)

    def test_has_compile_policy(self):
        self.assertIn("fn compile_policy", self.content)

    def test_has_profile_tracker(self):
        self.assertIn("struct ProfileTracker", self.content)

    def test_has_downgrade_check(self):
        self.assertIn("is_downgrade_to", self.content)

    def test_has_all_error_codes(self):
        for code in ["SANDBOX_DOWNGRADE_BLOCKED", "SANDBOX_PROFILE_UNKNOWN",
                     "SANDBOX_POLICY_CONFLICT", "SANDBOX_COMPILE_ERROR"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_access_levels(self):
        for level in ["Deny", "Scoped", "Filtered", "Allow"]:
            self.assertIn(level, self.content, f"Missing access level {level}")


class TestSandboxSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-3ua7_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-SANDBOX-TIERED", "INV-SANDBOX-NO-DOWNGRADE",
                    "INV-SANDBOX-COMPILED", "INV-SANDBOX-AUDIT"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["SANDBOX_DOWNGRADE_BLOCKED", "SANDBOX_PROFILE_UNKNOWN",
                     "SANDBOX_POLICY_CONFLICT", "SANDBOX_COMPILE_ERROR"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_all_profiles(self):
        for p in ["strict", "strict_plus", "moderate", "permissive"]:
            self.assertIn(p, self.content, f"Missing profile {p}")


class TestSandboxCli(unittest.TestCase):

    def test_json_mode_is_structural_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "sandbox_profile_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["SANDBOX-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-3ua7:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
