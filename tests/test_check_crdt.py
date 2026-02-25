"""Unit tests for check_crdt.py verification logic."""

import json
import os
import unittest

# Paths
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCrdtFixtures(unittest.TestCase):
    """Test that fixture files are valid and well-formed."""

    def _load_fixture(self, name):
        path = os.path.join(ROOT, "fixtures/crdt", name)
        self.assertTrue(os.path.isfile(path), f"Fixture {name} must exist")
        with open(path) as f:
            return json.load(f)

    def test_lww_map_fixture_exists(self):
        data = self._load_fixture("lww_map_merge.json")
        self.assertEqual(data["crdt_type"], "lww_map")

    def test_or_set_fixture_exists(self):
        data = self._load_fixture("or_set_merge.json")
        self.assertEqual(data["crdt_type"], "or_set")

    def test_gcounter_fixture_exists(self):
        data = self._load_fixture("gcounter_merge.json")
        self.assertEqual(data["crdt_type"], "gcounter")

    def test_pncounter_fixture_exists(self):
        data = self._load_fixture("pncounter_merge.json")
        self.assertEqual(data["crdt_type"], "pncounter")

    def test_lww_map_has_cases(self):
        data = self._load_fixture("lww_map_merge.json")
        self.assertGreater(len(data["cases"]), 0)
        for case in data["cases"]:
            self.assertIn("name", case)
            self.assertIn("law", case)

    def test_or_set_has_cases(self):
        data = self._load_fixture("or_set_merge.json")
        self.assertGreater(len(data["cases"]), 0)
        for case in data["cases"]:
            self.assertIn("name", case)
            self.assertIn("law", case)

    def test_gcounter_has_cases(self):
        data = self._load_fixture("gcounter_merge.json")
        self.assertGreater(len(data["cases"]), 0)
        for case in data["cases"]:
            self.assertIn("name", case)
            self.assertIn("law", case)

    def test_pncounter_has_cases(self):
        data = self._load_fixture("pncounter_merge.json")
        self.assertGreater(len(data["cases"]), 0)
        for case in data["cases"]:
            self.assertIn("name", case)
            self.assertIn("law", case)

    def test_all_fixtures_cover_commutativity(self):
        for name in ["lww_map_merge.json", "or_set_merge.json",
                     "gcounter_merge.json", "pncounter_merge.json"]:
            data = self._load_fixture(name)
            laws = [c["law"] for c in data["cases"]]
            self.assertIn("commutativity", laws, f"{name} missing commutativity case")

    def test_all_fixtures_cover_idempotency(self):
        for name in ["lww_map_merge.json", "or_set_merge.json",
                     "gcounter_merge.json", "pncounter_merge.json"]:
            data = self._load_fixture(name)
            laws = [c["law"] for c in data["cases"]]
            self.assertIn("idempotency", laws, f"{name} missing idempotency case")

    def test_all_fixtures_cover_associativity(self):
        for name in ["lww_map_merge.json", "or_set_merge.json",
                     "gcounter_merge.json", "pncounter_merge.json"]:
            data = self._load_fixture(name)
            laws = [c["law"] for c in data["cases"]]
            self.assertIn("associativity", laws, f"{name} missing associativity case")


class TestCrdtImplementation(unittest.TestCase):
    """Test that implementation file has expected structure."""

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/crdt.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_lww_map(self):
        self.assertIn("struct LwwMap", self.content)

    def test_has_or_set(self):
        self.assertIn("struct OrSet", self.content)

    def test_has_gcounter(self):
        self.assertIn("struct GCounter", self.content)

    def test_has_pncounter(self):
        self.assertIn("struct PnCounter", self.content)

    def test_has_crdt_type_enum(self):
        self.assertIn("enum CrdtType", self.content)

    def test_has_crdt_error(self):
        self.assertIn("enum CrdtError", self.content)
        self.assertIn("TypeMismatch", self.content)

    def test_has_merge_methods(self):
        self.assertGreaterEqual(self.content.count("fn merge("), 4)

    def test_has_serde_derives(self):
        self.assertIn("Serialize", self.content)
        self.assertIn("Deserialize", self.content)

    def test_has_schema_tags(self):
        self.assertGreaterEqual(self.content.count("pub crdt_type: CrdtType"), 4)


class TestCrdtConformance(unittest.TestCase):
    """Test that conformance test file has expected structure."""

    def setUp(self):
        self.conf_path = os.path.join(ROOT, "tests/conformance/crdt_merge_fixtures.rs")
        self.assertTrue(os.path.isfile(self.conf_path))
        with open(self.conf_path) as f:
            self.content = f.read()

    def test_covers_commutativity(self):
        self.assertIn("commutativity", self.content)

    def test_covers_associativity(self):
        self.assertIn("associativity", self.content)

    def test_covers_idempotency(self):
        self.assertIn("idempotency", self.content)

    def test_covers_type_mismatch(self):
        self.assertIn("type_mismatch", self.content)

    def test_covers_all_four_types(self):
        self.assertIn("LwwMap", self.content)
        self.assertIn("OrSet", self.content)
        self.assertIn("GCounter", self.content)
        self.assertIn("PnCounter", self.content)


class TestCrdtSpec(unittest.TestCase):
    """Test that spec contract exists and is well-formed."""

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-19u_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_all_types(self):
        for t in ["lww_map", "or_set", "gcounter", "pncounter"]:
            self.assertIn(t, self.content, f"Spec missing {t}")

    def test_has_merge_laws(self):
        self.assertIn("Commutativity", self.content)
        self.assertIn("Associativity", self.content)
        self.assertIn("Idempotency", self.content)

    def test_has_error_codes(self):
        self.assertIn("CRDT_TYPE_MISMATCH", self.content)


if __name__ == "__main__":
    unittest.main()
