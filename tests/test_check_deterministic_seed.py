"""Unit tests for check_deterministic_seed.py (bd-29r6)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_deterministic_seed.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "encoding" / "deterministic_seed.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-29r6_contract.md"
VECTORS = ROOT / "artifacts" / "10.14" / "seed_derivation_vectors.json"
JSON_DECODER = json.JSONDecoder()

sys.path.insert(0, str(ROOT / "scripts"))
import check_deterministic_seed as cds  # noqa: E402


def load_vectors() -> dict:
    parsed = JSON_DECODER.decode(VECTORS.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


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
        data = load_vectors()
        self.assertIn("vectors", data)

    def test_vectors_count(self):
        data = load_vectors()
        self.assertGreaterEqual(len(data["vectors"]), 10)

    def test_all_domains_covered(self):
        data = load_vectors()
        domains = {v["domain"] for v in data["vectors"]}
        for d in ["encoding", "repair", "scheduling", "placement", "verification"]:
            self.assertIn(d, domains, f"Missing domain in vectors: {d}")

    def test_vector_cross_validation(self):
        """Verify each vector using Python SHA-256 derivation."""
        checks = cds.validate_vectors()
        failing = [c for c in checks if not c["pass"]]
        self.assertEqual(len(failing), 0, f"Failing vectors: {json.dumps(failing, indent=2)}")


class TestRustCommentStripping(unittest.TestCase):
    def test_preserves_string_literals_while_stripping_comments(self):
        source = "\n".join(
            [
                'const PREFIX: &str = "franken_node.encoding.v1";',
                "// pub struct DeterministicSeedDeriver",
                'const RAW: &str = r#"SEED_DERIVED"#;',
                "/* #[test] */",
            ]
        )
        stripped = cds.strip_rust_comments(source)
        self.assertIn('"franken_node.encoding.v1"', stripped)
        self.assertIn('r#"SEED_DERIVED"#', stripped)
        self.assertNotIn("pub struct DeterministicSeedDeriver", stripped)
        self.assertNotIn("#[test]", stripped)


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
        payload = JSON_DECODER.decode(completed.stdout)
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


class TestCommentOnlyRustRegression(unittest.TestCase):
    """Commented Rust markers must not satisfy implementation checks."""

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            impl = tmp_path / "deterministic_seed.rs"
            mod_rs = tmp_path / "mod.rs"
            impl.write_text(
                "\n".join(f"// {marker}" for marker in COMMENT_ONLY_MARKERS)
                + "\n/*\n"
                + "\n".join("#[derive(Serialize, Deserialize)]" for _ in range(4))
                + "\n"
                + "\n".join("#[test]" for _ in range(25))
                + "\n*/\n",
                encoding="utf-8",
            )
            mod_rs.write_text("// pub mod deterministic_seed;\n", encoding="utf-8")

            with (
                mock.patch.object(cds, "IMPL", impl),
                mock.patch.object(cds, "MOD_RS", mod_rs),
            ):
                result = cds.run_checks()

        by_name = {check["check"]: check for check in result["checks"]}
        self.assertTrue(by_name["file: implementation"]["pass"])

        rust_backed_checks = [
            check["check"]
            for check in result["checks"]
            if check["check"] == "module registered in mod.rs"
            or check["check"].startswith(
                (
                    "type: ",
                    "method: ",
                    "domain_prefix: ",
                    "event_code: ",
                    "invariant: ",
                    "test: ",
                )
            )
            or check["check"] in {
                "compile-time Send + Sync assertion",
                "Serialize+Deserialize derives",
                "unit test count",
            }
        ]
        self.assertTrue(rust_backed_checks)
        passing_markers = [name for name in rust_backed_checks if by_name[name]["pass"]]
        self.assertEqual(passing_markers, [])


COMMENT_ONLY_MARKERS = [
    "pub mod deterministic_seed;",
    "pub struct DeterministicSeedDeriver",
    "pub struct DeterministicSeed",
    "pub struct ContentHash",
    "pub struct ScheduleConfig",
    "pub struct VersionBumpRecord",
    "pub enum DomainTag",
    "pub enum SeedError",
    "fn derive_seed(",
    "fn config_hash(",
    "fn from_hex(",
    "fn to_hex(",
    "fn prefix_hex(",
    "fn bump_records(",
    "fn clear_bump_records(",
    "fn tracked_domains(",
    "fn with_param(",
    "franken_node.encoding.v1",
    "franken_node.repair.v1",
    "franken_node.scheduling.v1",
    "franken_node.placement.v1",
    "franken_node.verification.v1",
    "SEED_DERIVED",
    "SEED_VERSION_BUMP",
    "INV-SEED-DOMAIN-SEP",
    "INV-SEED-STABLE",
    "INV-SEED-BOUNDED",
    "INV-SEED-NO-PLATFORM",
    "pub fn prefix(&self) -> &'static str",
    "hasher.update(domain.prefix().as_bytes())",
    "hasher.update([0x00])",
    "Sha256::new()",
    "hasher.update(content_hash.0)",
    "hasher.update(config.config_hash())",
    "hasher.finalize().into()",
    "pub struct ContentHash(#[serde(with = \"hex_bytes\")] pub [u8; 32])",
    "content_hash: &ContentHash",
    "BTreeMap<String, String>",
    "for (k, v) in &self.parameters",
    "self.version.to_le_bytes()",
    "u64::try_from(k.len()).unwrap_or(u64::MAX).to_le_bytes()",
    "u64::try_from(v.len()).unwrap_or(u64::MAX).to_le_bytes()",
    "assert_send_sync",
    "test_derive_seed_deterministic",
    "test_domain_separation_encoding_vs_repair",
    "test_domain_separation_all_pairs",
    "test_different_content_different_seed",
    "test_different_config_different_seed",
    "test_config_param_order_irrelevant",
    "test_deriver_config_change_triggers_bump",
    "test_no_collisions_100_samples",
    "test_golden_vector_encoding_zero",
    "test_golden_vector_repair_ff",
    "test_golden_vector_encoding_seq_v2",
    "test_golden_vector_scheduling_empty_params",
    "test_golden_vector_verification_singlebit",
    "test_seed_serialization_roundtrip",
    "content_hash_serialization_roundtrip",
    "test_single_bit_content_change",
    "test_empty_content_hash",
    "test_event_codes_defined",
]


if __name__ == "__main__":
    unittest.main()
