"""Tests for scripts/check_witness_ref.py (bd-1oof)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_witness_ref.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "observability" / "witness_ref.rs"


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
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "Verdict: PASS" in result.stdout

    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True,
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
