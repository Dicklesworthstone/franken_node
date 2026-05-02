"""Tests for scripts/check_adjacent_substrate_policy.py."""

from __future__ import annotations

import copy
import json
import runpy
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_adjacent_substrate_policy.py"


class ScriptNamespace:
    def __init__(self, script_globals: dict[str, object]) -> None:
        object.__setattr__(self, "_script_globals", script_globals)

    def __getattr__(self, name: str) -> object:
        return self._script_globals[name]


script_globals = runpy.run_path(str(SCRIPT))
mod = ScriptNamespace(script_globals["run_all"].__globals__)


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )


def load_json(text: str) -> dict[str, object]:
    return json.JSONDecoder().decode(text)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


class TestCLI(unittest.TestCase):
    def test_json_output(self):
        proc = run_script("--json")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = load_json(proc.stdout)
        self.assertEqual(payload["bead_id"], "bd-2owx")
        self.assertEqual(payload["section"], "10.16")
        self.assertEqual(payload["verdict"], "PASS")

    def test_self_test_cli(self):
        proc = run_script("--self-test")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("self_test passed", proc.stdout)


class TestSchemaAndCoverage(unittest.TestCase):
    def test_unknown_substrate_name_rejected(self):
        manifest = {
            "schema_version": "1.0.0",
            "policy_id": "x",
            "module_root": "crates/franken-node/src",
            "classification_mode": "first_match",
            "substrates": [
                {
                    "name": "unknown_substrate",
                    "version": "^0.1.0",
                    "plane": "model",
                    "mandatory_modules": ["crates/franken-node/src/config.rs"],
                    "should_use_modules": ["crates/franken-node/src/main.rs"],
                    "optional_modules": ["crates/franken-node/src/**"],
                }
            ],
            "exceptions": [],
            "metadata": {
                "schema_version": "1.0.0",
                "created_at": "2026-02-22T00:00:00Z",
                "policy_hash": "sha256:test",
            },
        }
        errors = mod.validate_manifest_schema(manifest)
        self.assertTrue(any("unknown substrate name" in err for err in errors))

    def test_empty_module_inventory_is_detected(self):
        manifest = mod._load_json(mod.MANIFEST_PATH)
        self.assertIsNotNone(manifest)
        assignments, unmapped = mod.classify_modules([], manifest["substrates"])
        self.assertTrue(all(len(v) == 0 for v in assignments.values()))
        self.assertEqual(unmapped, [])

    def test_module_coverage_complete_on_real_manifest(self):
        manifest = mod._load_json(mod.MANIFEST_PATH)
        self.assertIsNotNone(manifest)
        modules = mod.list_source_modules(manifest["module_root"])
        assignments, unmapped = mod.classify_modules(modules, manifest["substrates"])
        self.assertGreater(len(modules), 0)
        self.assertEqual(unmapped, [])
        self.assertEqual(set(assignments.keys()), {
            "frankentui",
            "frankensqlite",
            "sqlmodel_rust",
            "fastapi_rust",
        })


class TestContractConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        payload = mod._load_json(mod.MANIFEST_PATH)
        if payload is None:
            raise AssertionError(f"failed to load manifest: {mod.MANIFEST_PATH}")

        policy_src = mod.POLICY_PATH.read_text(encoding="utf-8")
        contract = mod.parse_policy_contract_block(policy_src)
        if contract is None:
            raise AssertionError(f"failed to parse contract: {mod.POLICY_PATH}")

        cls.manifest = payload
        cls.contract = contract

    def test_contract_matches_manifest(self):
        errors = mod.compare_contract_to_manifest(self.contract, self.manifest)
        self.assertEqual(errors, [])

    def test_contract_mismatch_detected(self):
        tampered = copy.deepcopy(self.contract)
        tampered["manifest_path"] = "artifacts/10.16/WRONG.json"
        errors = mod.compare_contract_to_manifest(tampered, self.manifest)
        self.assertTrue(errors)
        self.assertTrue(any("manifest_path mismatch" in err for err in errors))

    def test_policy_hash_is_stable(self):
        digest_one = mod.compute_policy_hash(self.manifest)
        digest_two = mod.compute_policy_hash(self.manifest)
        self.assertEqual(digest_one, digest_two)


if __name__ == "__main__":
    unittest.main()
