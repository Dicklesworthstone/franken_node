"""Tests for scripts/check_marker_stream.py (bd-126h marker stream verification)."""

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_marker_stream.py"

spec = importlib.util.spec_from_file_location("check_marker_stream", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# self_test
# ---------------------------------------------------------------------------

def test_self_test_passes():
    mod.self_test()  # asserts internally; raises if fails


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_required_event_types_count():
    assert len(mod.REQUIRED_EVENT_TYPES) == 6


def test_required_error_codes_count():
    assert len(mod.REQUIRED_ERROR_CODES) == 7


def test_required_operations_count():
    assert len(mod.REQUIRED_OPERATIONS) == 6


def test_required_structs_count():
    assert len(mod.REQUIRED_STRUCTS) == 4


# ---------------------------------------------------------------------------
# check_file_exists
# ---------------------------------------------------------------------------

class TestCheckFileExists:
    def test_existing_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mod, "ROOT", tmp_path)
        f = tmp_path / "test.rs"
        f.write_text("content")
        ok, detail = mod.check_file_exists(f)
        assert ok is True

    def test_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mod, "ROOT", tmp_path)
        f = tmp_path / "missing.rs"
        ok, detail = mod.check_file_exists(f)
        assert ok is False
        assert "MISSING" in detail


# ---------------------------------------------------------------------------
# check_content_contains
# ---------------------------------------------------------------------------

class TestCheckContentContains:
    def test_all_patterns_found(self, tmp_path):
        f = tmp_path / "test.rs"
        f.write_text("pub struct Marker\npub struct MarkerStream\n")
        results = mod.check_content_contains(f, ["pub struct Marker", "pub struct MarkerStream"], "test")
        assert all(r["pass"] for r in results)

    def test_pattern_not_found(self, tmp_path):
        f = tmp_path / "test.rs"
        f.write_text("pub struct Marker\n")
        results = mod.check_content_contains(f, ["pub struct Missing"], "test")
        assert not results[0]["pass"]
        assert "NOT FOUND" in results[0]["detail"]

    def test_missing_file(self, tmp_path):
        f = tmp_path / "missing.rs"
        results = mod.check_content_contains(f, ["anything"], "test")
        assert not results[0]["pass"]
        assert "file missing" in results[0]["detail"]


# ---------------------------------------------------------------------------
# check_test_coverage
# ---------------------------------------------------------------------------

class TestCheckTestCoverage:
    def test_sufficient_tests(self, tmp_path):
        f = tmp_path / "test.rs"
        # Create content with 20+ #[test] attributes and required test names
        test_content = ""
        for i in range(25):
            test_content += f"#[test]\nfn test_{i}() {{}}\n"
        for name in [
            "append_single_marker",
            "dense_sequence_numbers",
            "hash_chain_links_correctly",
            "time_regression_rejected",
            "empty_payload_hash_rejected",
            "verify_integrity_valid_stream",
            "verify_integrity_detects_hash_chain_break",
            "recover_torn_tail_corrupt_last",
            "recover_torn_tail_healthy_stream",
            "all_event_types_appendable",
            "error_codes_all_present",
            "large_stream_integrity",
        ]:
            test_content += f"#[test]\nfn {name}() {{}}\n"
        f.write_text(test_content)

        results = mod.check_test_coverage(f)
        count_check = next(r for r in results if r["check"] == "unit test count")
        assert count_check["pass"]

    def test_too_few_tests(self, tmp_path):
        f = tmp_path / "test.rs"
        f.write_text("#[test]\nfn test_one() {}\n")
        results = mod.check_test_coverage(f)
        count_check = next(r for r in results if r["check"] == "unit test count")
        assert not count_check["pass"]

    def test_missing_file(self, tmp_path):
        f = tmp_path / "missing.rs"
        results = mod.check_test_coverage(f)
        assert len(results) == 1
        assert not results[0]["pass"]
        assert "file missing" in results[0]["detail"]


# ---------------------------------------------------------------------------
# run_checks (integration-level)
# ---------------------------------------------------------------------------

def test_run_checks_returns_valid_structure():
    result = mod.run_checks()
    assert result["bead"] == "bd-126h"
    assert result["section"] == "10.14"
    assert "passed" in result
    assert "total" in result
    assert isinstance(result["checks"], list)
    assert len(result["checks"]) > 0
    assert "all_pass" in result
    assert result["all_pass"] == (result["passed"] == result["total"])


def test_run_checks_title():
    result = mod.run_checks()
    assert "marker stream" in result["title"].lower()
