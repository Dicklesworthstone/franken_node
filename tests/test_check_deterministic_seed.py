"""Unit tests for check_deterministic_seed.py (bd-29r6)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_deterministic_seed.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "encoding" / "deterministic_seed.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-29r6_contract.md"
VECTORS = ROOT / "artifacts" / "10.14" / "seed_derivation_vectors.json"

sys.path.insert(0, str(ROOT / "scripts"))
import check_deterministic_seed as cds


class TestFileExistence(unittest.TestCase):
    def test_implementation_exists(self):
        self.assertTrue(IMPL.is_file())

    def test_spec_exists(self):
        self.assertTrue(SPEC.is_file())

    def test_script_exists(self):
        self.assertTrue(SCRIPT.is_file())

    def test_vectors_exist(self):
        self.assertTrue(VECTORS.is_file())


class TestTypePresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_deterministic_seed_deriver(self):
        self.assertIn("pub struct DeterministicSeedDeriver", self.content)

    def test_deterministic_seed(self):
        self.assertIn("pub struct DeterministicSeed", self.content)

    def test_content_hash(self):
        self.assertIn("pub struct ContentHash", self.content)

    def test_schedule_config(self):
        self.assertIn("pub struct ScheduleConfig", self.content)

    def test_domain_tag(self):
        self.assertIn("pub enum DomainTag", self.content)

    def test_version_bump_record(self):
        self.assertIn("pub struct VersionBumpRecord", self.content)


class TestDomainPrefixes(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_all_prefixes(self):
        for prefix in [
            "franken_node.encoding.v1",
            "franken_node.repair.v1",
            "franken_node.scheduling.v1",
            "franken_node.placement.v1",
            "franken_node.verification.v1",
        ]:
            self.assertIn(prefix, self.content, f"Missing prefix: {prefix}")


class TestEventCodes(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_seed_derived(self):
        self.assertIn("SEED_DERIVED", self.content)

    def test_seed_version_bump(self):
        self.assertIn("SEED_VERSION_BUMP", self.content)


class TestGoldenVectors(unittest.TestCase):
    def test_vectors_valid_json(self):
        data = json.loads(VECTORS.read_text())
        self.assertIn("vectors", data)

    def test_vectors_count(self):
        data = json.loads(VECTORS.read_text())
        self.assertGreaterEqual(len(data["vectors"]), 10)

    def test_all_domains_covered(self):
        data = json.loads(VECTORS.read_text())
        domains = {v["domain"] for v in data["vectors"]}
        for d in ["encoding", "repair", "scheduling", "placement", "verification"]:
            self.assertIn(d, domains, f"Missing domain in vectors: {d}")

    def test_vector_cross_validation(self):
        """Verify each vector using Python SHA-256 derivation."""
        checks = cds.validate_vectors()
        failing = [c for c in checks if not c["pass"]]
        self.assertEqual(len(failing), 0, f"Failing vectors: {json.dumps(failing, indent=2)}")


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test(self):
        ok, results = cds.self_test()
        self.assertTrue(ok)

    def test_cli_json(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["bead_id"], "bd-29r6")

    def test_cli_human(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("bd-29r6", completed.stdout)


class TestAllChecksPass(unittest.TestCase):
    def test_no_failures(self):
        result = cds.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0,
                         f"Failing: {json.dumps(failing, indent=2)}")


if __name__ == "__main__":
    unittest.main()
