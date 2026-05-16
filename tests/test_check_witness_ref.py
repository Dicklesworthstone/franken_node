"""Tests for scripts/check_witness_ref.py (bd-1oof)."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_witness_ref.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "observability" / "witness_ref.rs"
spec = importlib.util.spec_from_file_location("check_witness_ref_mod", SCRIPT)
check_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_mod)


def write_comment_only_fixture(root: Path) -> dict[str, Path]:
    observability_dir = root / "crates/franken-node/src/observability"
    spec_dir = root / "docs/specs/section_10_14"
    observability_dir.mkdir(parents=True)
    spec_dir.mkdir(parents=True)

    paths = {
        "impl": observability_dir / "witness_ref.rs",
        "mod": observability_dir / "mod.rs",
        "spec": spec_dir / "bd-1oof_contract.md",
    }

    rust_markers = [
        "DecisionKind",
        "EvidenceEntry",
        *check_mod.REQUIRED_TYPES,
        *check_mod.REQUIRED_METHODS,
        *check_mod.EVENT_CODES,
        *check_mod.INVARIANTS,
        *check_mod.WITNESS_KINDS,
        *check_mod.ERROR_CODES,
        *[f"#[test]\nfn {name}() {{}}" for name in check_mod.REQUIRED_TESTS],
    ]
    paths["impl"].write_text(
        "// " + "\n// ".join(rust_markers[:20]) + "\n/*\n" + "\n".join(rust_markers[20:]) + "\n*/\n",
        encoding="utf-8",
    )
    paths["mod"].write_text("// pub mod witness_ref;\n", encoding="utf-8")
    paths["spec"].write_text("trace witness reference contract\n", encoding="utf-8")
    return paths


class TestFileExistence:
    def test_implementation_exists(self):
        assert IMPL.is_file()

    def test_script_exists(self):
        assert SCRIPT.is_file()

    def test_spec_exists(self):
        spec = ROOT / "docs" / "specs" / "section_10_14" / "bd-1oof_contract.md"
        assert spec.is_file()


class TestTypePresence:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.content = IMPL.read_text()

    def test_witness_id(self):
        assert "pub struct WitnessId" in self.content

    def test_witness_kind(self):
        assert "pub enum WitnessKind" in self.content

    def test_witness_ref(self):
        assert "pub struct WitnessRef" in self.content

    def test_witness_set(self):
        assert "pub struct WitnessSet" in self.content

    def test_witness_validator(self):
        assert "pub struct WitnessValidator" in self.content

    def test_witness_audit(self):
        assert "pub struct WitnessAudit" in self.content

    def test_validation_error(self):
        assert "pub enum WitnessValidationError" in self.content


class TestEventCodes:
    def test_all_event_codes(self):
        content = IMPL.read_text()
        for code in ["EVD-WITNESS-001", "EVD-WITNESS-002", "EVD-WITNESS-003", "EVD-WITNESS-004"]:
            assert code in content, f"missing event code {code}"


class TestInvariants:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.content = IMPL.read_text()

    def test_presence_invariant(self):
        assert "INV-WITNESS-PRESENCE" in self.content

    def test_integrity_invariant(self):
        assert "INV-WITNESS-INTEGRITY" in self.content

    def test_resolvable_invariant(self):
        assert "INV-WITNESS-RESOLVABLE" in self.content


class TestWitnessKinds:
    def test_all_four_kinds(self):
        content = IMPL.read_text()
        for kind in ["Telemetry", "StateSnapshot", "ProofArtifact", "ExternalSignal"]:
            assert kind in content, f"missing WitnessKind variant {kind}"


class TestMethodPresence:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.content = IMPL.read_text()

    def test_is_high_impact(self):
        assert "fn is_high_impact(" in self.content

    def test_validate(self):
        assert "fn validate(" in self.content

    def test_verify_integrity(self):
        assert "fn verify_integrity(" in self.content

    def test_coverage_audit(self):
        assert "fn coverage_audit(" in self.content


class TestSelfTestAndCli:
    def test_self_test(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from check_witness_ref import self_test
        ok, results = self_test()
        assert ok, f"self_test failed: {[r for r in results if not r['pass']]}"

    def test_cli_human(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "Verdict: PASS" in result.stdout

    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS"
        assert data["bead_id"] == "bd-1oof"


class TestAllChecksPass:
    def test_no_failures(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from check_witness_ref import self_test
        ok, results = self_test()
        failures = [r for r in results if not r["pass"]]
        assert not failures, f"failing checks: {failures}"


class TestCommentStripping:
    def test_preserves_string_literals_while_stripping_comments(self):
        source = (
            'pub const KEEP: &str = "EVD-WITNESS-001 // literal"; // "EVD-WITNESS-002"\n'
            'pub const RAW: &str = r#"INV-WITNESS-PRESENCE /* literal */"#; '
            '/* "EVD-WITNESS-003" */\n'
            "pub/* hidden */ struct WitnessRef;\n"
        )

        stripped = check_mod.strip_rust_comments(source)

        assert '"EVD-WITNESS-001 // literal"' in stripped
        assert 'r#"INV-WITNESS-PRESENCE /* literal */"#' in stripped
        assert "pub  struct WitnessRef" in stripped
        assert all(marker not in stripped for marker in ('"EVD-WITNESS-002"', '"EVD-WITNESS-003"'))

    def test_comment_only_rust_markers_fail_closed(self, tmp_path, monkeypatch):
        paths = write_comment_only_fixture(tmp_path)

        monkeypatch.setattr(check_mod, "ROOT", tmp_path)
        monkeypatch.setattr(check_mod, "IMPL", paths["impl"])
        monkeypatch.setattr(check_mod, "MOD_RS", paths["mod"])
        monkeypatch.setattr(check_mod, "SPEC", paths["spec"])

        result = check_mod.run_checks()
        by_name = {check["check"]: check for check in result["checks"]}

        assert result["verdict"] == "FAIL"
        assert result["test_count"] == 0
        assert by_name["file: implementation"]["pass"]
        assert by_name["file: spec contract"]["pass"]
        assert not by_name["module registered in mod.rs"]["pass"]
        assert not by_name["imports DecisionKind + EvidenceEntry"]["pass"]
        assert not by_name["unit test count"]["pass"]
        assert not by_name["type: pub struct WitnessRef"]["pass"]
        assert not by_name["method: fn validate("]["pass"]
        assert not by_name["event_code: EVD-WITNESS-001"]["pass"]
        assert by_name["invariant: INV-WITNESS-PRESENCE"]["pass"]
        assert not by_name["witness_kind: Telemetry"]["pass"]
        assert not by_name["error_code: ERR_MISSING_WITNESSES"]["pass"]
        assert not by_name["test: witness_ref_creation"]["pass"]
