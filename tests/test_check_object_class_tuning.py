"""Unit tests for check_object_class_tuning.py verification script (bd-8tvs)."""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

spec = importlib.util.spec_from_file_location(
    "check_object_class_tuning",
    ROOT + "/scripts/check_object_class_tuning.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestRunChecks:
    def test_returns_list(self):
        result = mod.run_checks()
        assert isinstance(result, list)

    def test_all_entries_have_required_keys(self):
        for entry in mod.run_checks():
            assert "check" in entry
            assert "pass" in entry
            assert "detail" in entry

    def test_pass_values_are_bool(self):
        for entry in mod.run_checks():
            assert isinstance(entry["pass"], bool)

    def test_minimum_check_count(self):
        result = mod.run_checks()
        assert len(result) >= 80, f"Expected >= 80 checks, got {len(result)}"

    def test_all_checks_pass(self):
        result = mod.run_checks()
        failing = [c for c in result if not c["pass"]]
        assert not failing, f"Failing checks: {failing}"


class TestFileChecks:
    def test_implementation_file(self):
        checks = mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: implementation")["pass"]

    def test_spec_file(self):
        checks = mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: spec contract")["pass"]

    def test_csv_file(self):
        checks = mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: policy report CSV")["pass"]

    def test_benchmark_directory(self):
        checks = mod.run_checks()
        assert next(c for c in checks if c["check"] == "directory: object_class_tuning benchmarks")["pass"]

    def test_encode_decode_benchmark_file(self):
        checks = mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: encode/decode benchmark")["pass"]

    def test_fetch_latency_benchmark_file(self):
        checks = mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: fetch latency benchmark")["pass"]


class TestTypeChecks:
    TYPES = [
        "pub enum ObjectClass",
        "pub enum FetchPriority",
        "pub enum PrefetchPolicy",
        "pub struct ClassTuning",
        "pub struct BenchmarkMeasurement",
        "pub struct TuningError",
        "pub struct TuningEvent",
        "pub struct ObjectClassTuningEngine",
    ]

    @pytest.mark.parametrize("ty", TYPES)
    def test_type_found(self, ty):
        checks = mod.run_checks()
        check = next(c for c in checks if c["check"] == f"type: {ty}")
        assert check["pass"], f"Type not found: {ty}"


class TestEventCodes:
    CODES = [
        "OC_POLICY_ENGINE_INIT", "OC_POLICY_OVERRIDE_APPLIED",
        "OC_POLICY_OVERRIDE_REJECTED", "OC_BENCHMARK_BASELINE_LOADED",
    ]

    @pytest.mark.parametrize("code", CODES)
    def test_event_code_found(self, code):
        checks = mod.run_checks()
        check = next(c for c in checks if c["check"] == f"event_code: {code}")
        assert check["pass"]


class TestErrorCodes:
    CODES = ["ERR_ZERO_SYMBOL_SIZE", "ERR_INVALID_OVERHEAD_RATIO", "ERR_UNKNOWN_CLASS"]

    @pytest.mark.parametrize("code", CODES)
    def test_error_code_found(self, code):
        checks = mod.run_checks()
        check = next(c for c in checks if c["check"] == f"error_code: {code}")
        assert check["pass"]


class TestInvariants:
    INVARIANTS = [
        "INV-TUNE-CLASS-SPECIFIC",
        "INV-TUNE-OVERRIDE-AUDITED",
        "INV-TUNE-REJECT-INVALID",
        "INV-TUNE-DETERMINISTIC",
    ]

    @pytest.mark.parametrize("inv", INVARIANTS)
    def test_invariant_found(self, inv):
        checks = mod.run_checks()
        check = next(c for c in checks if c["check"] == f"invariant: {inv}")
        assert check["pass"]


class TestUnitTestCount:
    def test_count_passes(self):
        checks = mod.run_checks()
        check = next(c for c in checks if c["check"] == "unit test count")
        assert check["pass"]


class TestBenchmarkArtifacts:
    def test_encode_decode_benchmark_covers_classes(self):
        checks = mod.run_checks()
        for class_id in ["critical_marker", "trust_receipt", "replay_bundle", "telemetry_artifact"]:
            assert next(c for c in checks if c["check"] == f"encode/decode benchmark: {class_id}")["pass"]

    def test_fetch_latency_benchmark_covers_classes(self):
        checks = mod.run_checks()
        for class_id in ["critical_marker", "trust_receipt", "replay_bundle", "telemetry_artifact"]:
            assert next(c for c in checks if c["check"] == f"fetch latency benchmark: {class_id}")["pass"]

    def test_benchmark_artifact_schema_tokens(self):
        checks = mod.run_checks()
        for expected_check in [
            "encode/decode benchmark: EncodeDecodeRow",
            "encode/decode benchmark: ENCODE_DECODE_ROWS",
            "encode/decode benchmark: p50_encode_us",
            "encode/decode benchmark: p99_decode_us",
            "fetch latency benchmark: FetchLatencyRow",
            "fetch latency benchmark: FETCH_LATENCY_ROWS",
            "fetch latency benchmark: fetch_priority",
            "fetch latency benchmark: p99_fetch_us",
        ]:
            matches = [entry for entry in checks if entry["check"] == expected_check]
            if not matches or not matches[0]["pass"]:
                raise AssertionError(f"expected passing check {expected_check}")


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test()


class TestCheckHelper:
    def test_pass_true(self):
        result = mod._check("t", True, "ok")
        assert bool(result["pass"])

    def test_pass_false(self):
        result = mod._check("t", False)
        assert result["detail"] == "NOT FOUND"


class TestJsonOutput:
    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, ROOT + "/scripts/check_object_class_tuning.py", "--json"],
            capture_output=True, text=True,
            timeout=30,
        )
        assert result.returncode == 0
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError(result.stdout) from exc
        assert data["verdict"] == "PASS"
        assert data["summary"]["total"] == 116

    def test_cli_write_evidence_flag_is_available(self):
        result = subprocess.run(
            [sys.executable, ROOT + "/scripts/check_object_class_tuning.py", "--help"],
            capture_output=True, text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "--write-evidence" in result.stdout
