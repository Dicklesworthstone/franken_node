"""Unit tests for scripts/check_fork_detection.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_fork_detection as mod  # noqa: E402


class TestConstants(unittest.TestCase):
    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 12)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 15)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 8)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_response_modes_count(self):
        self.assertEqual(len(mod.RESPONSE_MODES), 4)

    def test_gate_states_count(self):
        self.assertEqual(len(mod.GATE_STATES), 5)

    def test_mutation_kinds_count(self):
        self.assertEqual(len(mod.MUTATION_KINDS), 6)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 40)


class TestCheckFiles(unittest.TestCase):
    def test_all_files_exist(self):
        results = mod.check_files()
        for r in results:
            self.assertTrue(r["pass"], f"File missing: {r['check']}")

    def test_file_count(self):
        results = mod.check_files()
        self.assertEqual(len(results), 6)


class TestRustCommentStripping(unittest.TestCase):
    def test_preserves_string_literals_while_stripping_comments(self):
        source = "\n".join(
            [
                'const CODE: &str = "DG-001";',
                "// pub struct ControlPlaneDivergenceGate",
                'const RAW: &str = r#"INV-DG-NO-MUTATION"#;',
                "/* #[test] */",
            ]
        )

        stripped = mod.strip_rust_comments(source)

        self.assertIn('"DG-001"', stripped)
        self.assertIn('r#"INV-DG-NO-MUTATION"#', stripped)
        self.assertNotIn("pub struct ControlPlaneDivergenceGate", stripped)
        self.assertNotIn("#[test]", stripped)


class TestMethodMarkers(unittest.TestCase):
    def test_generic_method_marker_matches_before_paren(self):
        content = "pub fn respond_recover<R: Resolver>(&mut self) {}"

        self.assertTrue(mod.method_marker_present(content, "pub fn respond_recover("))


class TestCheckModule(unittest.TestCase):
    def test_module_registered(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTypes(unittest.TestCase):
    def test_all_types_found(self):
        results = mod.check_types()
        for r in results:
            self.assertTrue(r["pass"], f"Type missing: {r['check']}")


class TestCheckMethods(unittest.TestCase):
    def test_all_methods_found(self):
        results = mod.check_methods()
        for r in results:
            self.assertTrue(r["pass"], f"Method missing: {r['check']}")


class TestCheckEventCodes(unittest.TestCase):
    def test_all_event_codes_found(self):
        results = mod.check_event_codes()
        for r in results:
            self.assertTrue(r["pass"], f"Event code missing: {r['check']}")


class TestCheckInvariants(unittest.TestCase):
    def test_all_invariants_found(self):
        results = mod.check_invariants()
        for r in results:
            self.assertTrue(r["pass"], f"Invariant missing: {r['check']}")


class TestCheckResponseModes(unittest.TestCase):
    def test_all_modes_found(self):
        results = mod.check_response_modes()
        for r in results:
            self.assertTrue(r["pass"], f"Response mode missing: {r['check']}")


class TestCheckGateStates(unittest.TestCase):
    def test_all_states_found(self):
        results = mod.check_gate_states()
        for r in results:
            self.assertTrue(r["pass"], f"Gate state missing: {r['check']}")


class TestCheckMutationKinds(unittest.TestCase):
    def test_all_kinds_found(self):
        results = mod.check_mutation_kinds()
        for r in results:
            self.assertTrue(r["pass"], f"Mutation kind missing: {r['check']}")


class TestCheckTests(unittest.TestCase):
    def test_all_tests_found(self):
        results = mod.check_tests()
        for r in results:
            self.assertTrue(r["pass"], f"Test missing: {r['check']}")


class TestCheckTestCount(unittest.TestCase):
    def test_sufficient_tests(self):
        result = mod.check_test_count()
        self.assertTrue(result["pass"], result["detail"])


class TestCheckUpstream(unittest.TestCase):
    def test_all_upstream_patterns(self):
        results = mod.check_upstream_integration()
        for r in results:
            self.assertTrue(r["pass"], f"Upstream pattern missing: {r['check']}")


class TestCheckSerde(unittest.TestCase):
    def test_serde_derives(self):
        result = mod.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckSha256(unittest.TestCase):
    def test_sha256_usage(self):
        result = mod.check_sha256_usage()
        self.assertTrue(result["pass"])


class TestCheckSpec(unittest.TestCase):
    def test_spec_sections(self):
        results = mod.check_spec_sections()
        for r in results:
            self.assertTrue(r["pass"], f"Spec section missing: {r['check']}")


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"], self._failing(result))

    def test_verdict_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2ms")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.10")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 100)

    def _failing(self, result):
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
        self.assertEqual(parsed["bead_id"], "bd-2ms")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


class TestCommentOnlyRustRegression(unittest.TestCase):
    """Commented Rust markers must not satisfy implementation checks."""

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            impl = tmp_path / "divergence_gate.rs"
            mod_rs = tmp_path / "mod.rs"
            fork = tmp_path / "fork_detection.rs"
            marker = tmp_path / "marker_stream.rs"
            mmr = tmp_path / "mmr_proofs.rs"

            impl.write_text(
                "\n".join(f"// {entry}" for entry in COMMENT_ONLY_MARKERS)
                + "\n/*\n"
                + "\n".join("#[test]" for _ in range(40))
                + "\nSerialize\nDeserialize\nSha256\n"
                + "\n*/\n",
                encoding="utf-8",
            )
            mod_rs.write_text("// pub mod divergence_gate;\n", encoding="utf-8")
            fork.write_text("", encoding="utf-8")
            marker.write_text("", encoding="utf-8")
            mmr.write_text("", encoding="utf-8")

            with (
                mock.patch.object(mod, "IMPL", impl),
                mock.patch.object(mod, "MOD_RS", mod_rs),
                mock.patch.object(mod, "UPSTREAM_FORK", fork),
                mock.patch.object(mod, "UPSTREAM_MARKER", marker),
                mock.patch.object(mod, "UPSTREAM_MMR", mmr),
            ):
                result = mod.run_checks()

        by_name = {check["check"]: check for check in result["checks"]}
        for required_file in [
            "file: implementation",
            "file: control_plane mod.rs",
            "file: upstream fork_detection.rs",
            "file: upstream marker_stream.rs",
            "file: upstream mmr_proofs.rs",
        ]:
            self.assertTrue(by_name[required_file]["pass"])

        rust_backed_checks = [
            check["check"]
            for check in result["checks"]
            if check["check"] == "module registered in mod.rs"
            or check["check"].startswith(
                (
                    "type: ",
                    "method: ",
                    "event_code: ",
                    "invariant: ",
                    "response_mode: ",
                    "gate_state: ",
                    "mutation_kind: ",
                    "test: ",
                    "upstream: ",
                )
            )
            or check["check"]
            in {
                "test count >= 40",
                "Serialize/Deserialize derives",
                "SHA-256 usage",
            }
        ]
        self.assertTrue(rust_backed_checks)
        passing_markers = [name for name in rust_backed_checks if by_name[name]["pass"]]
        self.assertEqual(passing_markers, [])


COMMENT_ONLY_MARKERS = (
    ["pub mod divergence_gate;"]
    + mod.REQUIRED_TYPES
    + mod.REQUIRED_METHODS
    + mod.EVENT_CODES
    + mod.INVARIANTS
    + mod.RESPONSE_MODES
    + mod.GATE_STATES
    + mod.MUTATION_KINDS
    + [f"fn {test_name}" for test_name in mod.REQUIRED_TESTS]
    + mod.UPSTREAM_PATTERNS
)


if __name__ == "__main__":
    unittest.main()
