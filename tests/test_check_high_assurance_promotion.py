"""Unit tests for check_high_assurance_promotion.py verification script."""

import importlib.util
import json
import os

import pytest

# Load the verification script as a module
SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "check_high_assurance_promotion.py",
)
spec = importlib.util.spec_from_file_location("check_mod", SCRIPT)
check_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_mod)


def _required_test_names() -> list[str]:
    return [
        check["check"].removeprefix("test: ")
        for check in check_mod.run_checks()
        if check["check"].startswith("test: ")
    ]


def _write_comment_only_fixture(root):
    connector_dir = root / "crates/franken-node/src/connector"
    spec_dir = root / "docs/specs/section_10_14"
    artifact_dir = root / "artifacts/10.14"
    connector_dir.mkdir(parents=True)
    spec_dir.mkdir(parents=True)
    artifact_dir.mkdir(parents=True)

    paths = {
        "impl": connector_dir / "high_assurance_promotion.rs",
        "mod": connector_dir / "mod.rs",
        "spec": spec_dir / "bd-3ort_contract.md",
        "matrix": artifact_dir / "high_assurance_promotion_matrix.json",
    }

    paths["mod"].write_text("// pub mod high_assurance_promotion;\n", encoding="utf-8")

    markers = [
        "pub enum AssuranceMode",
        "pub enum ObjectClass",
        "pub enum ProofRequirement",
        "pub struct ProofBundle",
        "pub enum PromotionDenialReason",
        "pub struct PolicyAuthorization",
        "pub struct HighAssuranceGate",
        "pub struct PromotionMatrixEntry",
        "Standard",
        "HighAssurance",
        "CriticalMarker",
        "StateObject",
        "TelemetryArtifact",
        "ConfigObject",
        "FullProofChain",
        "IntegrityProof",
        "IntegrityHash",
        "SchemaProof",
        "ProofBundleMissing",
        "ProofBundleInsufficient",
        "UnauthorizedModeDowngrade",
        "fn evaluate(",
        "fn switch_mode(",
        "fn promotion_matrix(",
        "fn satisfies(",
        "fn empty(",
        "fn full(",
        "fn label(",
        "fn requires_proof(",
        "fn code(",
        "fn to_json(",
        "fn proof_requirement_for(",
        "QUARANTINE_PROMOTION_APPROVED",
        "QUARANTINE_PROMOTION_DENIED",
        "ASSURANCE_MODE_CHANGED",
        "INV-HA-PROOF-REQUIRED",
        "INV-HA-FAIL-CLOSED",
        "INV-HA-MODE-POLICY",
        "PROMOTION_DENIED_PROOF_BUNDLE_MISSING",
        "PROMOTION_DENIED_PROOF_INSUFFICIENT",
        "MODE_DOWNGRADE_UNAUTHORIZED",
        *[f"fn {name}(" for name in _required_test_names()],
        *["#[test]" for _ in range(25)],
    ]
    paths["impl"].write_text(
        "// " + "\n// ".join(markers[:20]) + "\n/*\n    " + "\n    ".join(markers[20:]) + "\n*/\n",
        encoding="utf-8",
    )

    paths["spec"].write_text("# bd-3ort contract\n", encoding="utf-8")
    paths["matrix"].write_text(
        json.dumps(
            [
                {
                    "object_class": object_class,
                    "assurance_mode": "high_assurance",
                    "proof_requirement": "full_proof_chain",
                }
                for object_class in [
                    "critical_marker",
                    "state_object",
                    "telemetry_artifact",
                    "config_object",
                ]
            ]
        ),
        encoding="utf-8",
    )

    return paths


class TestRunChecks:
    """Tests that run_checks() returns expected structure."""

    def test_returns_list(self):
        result = check_mod.run_checks()
        assert isinstance(result, list)

    def test_all_entries_have_required_keys(self):
        for entry in check_mod.run_checks():
            assert "check" in entry
            assert "pass" in entry
            assert "detail" in entry

    def test_pass_values_are_bool(self):
        for entry in check_mod.run_checks():
            assert isinstance(entry["pass"], bool)

    def test_minimum_check_count(self):
        result = check_mod.run_checks()
        assert len(result) >= 60, f"Expected >= 60 checks, got {len(result)}"

    def test_all_checks_pass(self):
        """Verify all checks pass against current codebase."""
        result = check_mod.run_checks()
        failing = [c for c in result if not c["pass"]]
        assert not failing, f"Failing checks: {failing}"


class TestFileChecks:
    """Tests for file existence checks."""

    def test_implementation_file_check(self):
        checks = check_mod.run_checks()
        impl_check = next(c for c in checks if c["check"] == "file: implementation")
        assert impl_check["pass"]

    def test_spec_file_check(self):
        checks = check_mod.run_checks()
        spec_check = next(c for c in checks if c["check"] == "file: spec contract")
        assert spec_check["pass"]

    def test_matrix_file_check(self):
        checks = check_mod.run_checks()
        matrix_check = next(c for c in checks if c["check"] == "file: promotion matrix artifact")
        assert matrix_check["pass"]


class TestTypeChecks:
    """Tests for type definitions in source."""

    TYPES = [
        "pub enum AssuranceMode",
        "pub enum ObjectClass",
        "pub enum ProofRequirement",
        "pub struct ProofBundle",
        "pub enum PromotionDenialReason",
        "pub struct PolicyAuthorization",
        "pub struct HighAssuranceGate",
        "pub struct PromotionMatrixEntry",
    ]

    @pytest.mark.parametrize("ty", TYPES)
    def test_type_found(self, ty):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == f"type: {ty}")
        assert check["pass"], f"Type not found: {ty}"


class TestEventCodes:
    """Tests for event code presence."""

    CODES = [
        "QUARANTINE_PROMOTION_APPROVED",
        "QUARANTINE_PROMOTION_DENIED",
        "ASSURANCE_MODE_CHANGED",
    ]

    @pytest.mark.parametrize("code", CODES)
    def test_event_code_found(self, code):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == f"event_code: {code}")
        assert check["pass"]


class TestInvariants:
    """Tests for invariant presence."""

    INVARIANTS = [
        "INV-HA-PROOF-REQUIRED",
        "INV-HA-FAIL-CLOSED",
        "INV-HA-MODE-POLICY",
    ]

    @pytest.mark.parametrize("inv", INVARIANTS)
    def test_invariant_found(self, inv):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == f"invariant: {inv}")
        assert check["pass"]


class TestUnitTestChecks:
    """Tests that unit test count is verified."""

    def test_unit_test_count_passes(self):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == "unit test count")
        assert check["pass"]
        assert "33" in check["detail"] or int(check["detail"].split()[0]) >= 25


class TestSelfTest:
    """Tests for the self_test() function."""

    def test_self_test_passes(self):
        assert check_mod.self_test()


class TestCheckHelper:
    """Tests for the _check helper."""

    def test_pass_true(self):
        result = check_mod._check("test", True, "ok")
        assert result == {"check": "test", "pass": True, "detail": "ok"}

    def test_pass_false(self):
        result = check_mod._check("test", False, "nope")
        assert result == {"check": "test", "pass": False, "detail": "nope"}

    def test_default_detail_pass(self):
        result = check_mod._check("test", True)
        assert result["detail"] == "found"

    def test_default_detail_fail(self):
        result = check_mod._check("test", False)
        assert result["detail"] == "NOT FOUND"


class TestPromotionMatrix:
    """Tests for promotion matrix artifact validation."""

    def test_matrix_covers_all_classes(self):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == "matrix covers all classes")
        assert check["pass"]

    def test_matrix_has_four_entries(self):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == "matrix has 4 entries")
        assert check["pass"]


class TestCommentOnlyRustRegression:
    """Regression tests for comment-only Rust marker false positives."""

    def test_preserves_string_literals_while_stripping_comments(self):
        source = (
            'pub const KEEP: &str = "INV-HA-FAIL-CLOSED // literal"; // "INV-HA-MODE-POLICY"\n'
            'pub const RAW: &str = r#"PROMOTION_DENIED_PROOF_INSUFFICIENT /* literal */"#; '
            '/* "MODE_DOWNGRADE_UNAUTHORIZED" */\n'
        )

        stripped = check_mod._strip_rust_comments(source)

        assert '"INV-HA-FAIL-CLOSED // literal"' in stripped
        assert 'r#"PROMOTION_DENIED_PROOF_INSUFFICIENT /* literal */"#' in stripped
        removed_comment_literals = ('"INV-HA-MODE-POLICY"', '"MODE_DOWNGRADE_UNAUTHORIZED"')
        assert all(marker not in stripped for marker in removed_comment_literals)

    def test_comment_only_rust_markers_fail_closed(self, tmp_path, monkeypatch):
        paths = _write_comment_only_fixture(tmp_path)
        monkeypatch.setattr(check_mod, "ROOT", str(tmp_path))
        monkeypatch.setattr(check_mod, "IMPL", str(paths["impl"]))
        monkeypatch.setattr(check_mod, "MOD_RS", str(paths["mod"]))
        monkeypatch.setattr(check_mod, "SPEC", str(paths["spec"]))
        monkeypatch.setattr(check_mod, "MATRIX", str(paths["matrix"]))

        checks = check_mod.run_checks()

        by_name = {check["check"]: check for check in checks}
        artifact_checks = {
            "file: implementation",
            "file: spec contract",
            "file: promotion matrix artifact",
            "matrix is list",
            "matrix has 4 entries",
            "matrix covers all classes",
            "HA entries have proof requirements",
        }
        for name in artifact_checks:
            assert by_name[name]["pass"], name

        rust_backed_failures = [check for check in checks if check["check"] not in artifact_checks]
        assert rust_backed_failures
        for check in rust_backed_failures:
            assert not check["pass"], check["check"]
