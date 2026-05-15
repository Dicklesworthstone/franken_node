"""Unit tests for scripts/check_counterfactual.py."""

import importlib.util
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from unittest import mock
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_counterfactual",
    ROOT / "scripts" / "check_counterfactual.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixture(TestCase):
    def test_fixture_exists(self):
        self.assertTrue(mod.FIXTURE.is_file())

    def test_fixture_vectors_non_empty(self):
        vectors = mod.load_fixture_vectors()
        self.assertGreater(len(vectors), 0)


class TestEvidenceAnalysis(TestCase):
    def _valid_evidence(self):
        data = mod.load_evidence()
        self.assertIsInstance(data, dict)
        return deepcopy(data)

    def test_valid_evidence_passes(self):
        checks = mod.check_evidence(self._valid_evidence())
        self.assertTrue(all(check["pass"] for check in checks), self._failing(checks))

    def test_missing_evidence_fails_closed(self):
        checks = mod.check_evidence({})
        self.assertFalse(all(check["pass"] for check in checks))
        self.assertTrue(any(check["check"] == "evidence: bead id" and not check["pass"] for check in checks))

    def test_missing_required_file_fails_closed(self):
        data = self._valid_evidence()
        data["implementation"]["files"] = []
        checks = mod.check_evidence(data)
        self.assertFalse(all(check["pass"] for check in checks))
        self.assertTrue(any(check["check"].startswith("evidence file:") and not check["pass"] for check in checks))

    def test_missing_acceptance_mapping_fails_closed(self):
        data = self._valid_evidence()
        data["acceptance_criteria_mapping"] = []
        checks = mod.check_evidence(data)
        self.assertFalse(all(check["pass"] for check in checks))
        self.assertTrue(any(check["check"].startswith("evidence acceptance:") and not check["pass"] for check in checks))

    def test_missing_rch_command_fails_closed(self):
        data = self._valid_evidence()
        data["verification"]["commands"] = []
        checks = mod.check_evidence(data)
        self.assertFalse(all(check["pass"] for check in checks))
        self.assertTrue(any(check["check"].startswith("evidence command recorded:") and not check["pass"] for check in checks))

    def _failing(self, checks):
        failures = [check for check in checks if not check["pass"]]
        return "\n".join(f"FAIL: {check['check']}: {check['detail']}" for check in failures[:10])


class TestChecks(TestCase):
    def test_run_checks_passes(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2fa")
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)

    def test_check_contains_detects_pattern(self):
        results = mod.check_contains(mod.IMPL, ["pub struct CounterfactualReplayEngine"], "impl")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["pass"])

    def test_rust_test_markers_present(self):
        checks = mod.check_rust_tests()
        self.assertTrue(all(check["pass"] for check in checks))


class TestRustCommentStripping(TestCase):
    def test_preserves_string_literals_while_stripping_comments(self):
        source = "\n".join(
            [
                'const MARKER: &str = "CounterfactualReplayEngine";',
                "// pub struct CounterfactualReplayEngine",
                'const RAW: &str = r#"incident counterfactual"#;',
                "/* CounterfactualSimulationOutput */",
            ]
        )
        stripped = mod.strip_rust_comments(source)
        self.assertIn('"CounterfactualReplayEngine"', stripped)
        self.assertIn('r#"incident counterfactual"#', stripped)
        self.assertNotIn("pub struct CounterfactualReplayEngine", stripped)
        self.assertNotIn("CounterfactualSimulationOutput", stripped)


class TestCommentOnlyRustRegression(TestCase):
    """Commented Rust markers must not satisfy implementation checks."""

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            impl = tmp_path / "counterfactual_replay.rs"
            mod_rs = tmp_path / "mod.rs"
            main_rs = tmp_path / "main.rs"

            impl.write_text(
                "\n".join(f"// {marker}" for marker in mod.REQUIRED_IMPL_PATTERNS)
                + "\n/*\n"
                + "\n".join("#[test]" for _ in range(20))
                + "\n"
                + "\n".join(f"fn {name}() {{}}" for name in mod.REQUIRED_RUST_TESTS)
                + "\n*/\n",
                encoding="utf-8",
            )
            mod_rs.write_text("// pub mod counterfactual_replay;\n", encoding="utf-8")
            main_rs.write_text(
                "/* incident counterfactual\nCounterfactualReplayEngine\ncounterfactual summary:\n*/\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(mod, "IMPL", impl),
                mock.patch.object(mod, "MOD_RS", mod_rs),
                mock.patch.object(mod, "MAIN_RS", main_rs),
            ):
                result = mod.run_checks()

        by_name = {check["check"]: check for check in result["checks"]}
        self.assertTrue(by_name["file: counterfactual replay implementation"]["pass"])

        rust_backed_checks = [
            check["check"]
            for check in result["checks"]
            if check["check"].startswith(("impl: ", "module wiring: ", "cli wiring: ", "rust test: "))
            or check["check"] == "rust tests: counterfactual replay coverage count"
        ]
        self.assertTrue(rust_backed_checks)
        passing_markers = [name for name in rust_backed_checks if by_name[name]["pass"]]
        self.assertEqual(passing_markers, [])


if __name__ == "__main__":
    main()
