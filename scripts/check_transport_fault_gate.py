#!/usr/bin/env python3
"""bd-3u6o: Verification script for transport fault gate (Section 10.15).

Usage:
    python3 scripts/check_transport_fault_gate.py            # human-readable
    python3 scripts/check_transport_fault_gate.py --json      # machine-readable
    python3 scripts/check_transport_fault_gate.py --self-test  # internal consistency
"""

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/connector/transport_fault_gate.rs"
MOD_FILE = ROOT / "crates/franken-node/src/connector/mod.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_15/bd-3u6o_contract.md"
UPSTREAM_FILE = ROOT / "crates/franken-node/src/remote/virtual_transport_faults.rs"
EVIDENCE_FILE = ROOT / "artifacts/section_10_15/bd-3u6o/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_15/bd-3u6o/verification_summary.md"

ALL_CHECKS: list[dict[str, Any]] = []
RESULTS: dict[str, Any] = {}

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_TYPES = [
    "pub enum ControlProtocol",
    "pub enum FaultMode",
    "pub enum ProtocolOutcome",
    "pub enum TransportFaultGateError",
    "pub struct FaultTestResult",
    "pub struct TransportFaultGateConfig",
    "pub struct TransportFaultGate",
    "pub struct GateVerdict",
    "pub struct TfgAuditRecord",
    "pub struct ProtocolSummary",
]

REQUIRED_EVENT_CODES = [
    "TFG-001",
    "TFG-002",
    "TFG-003",
    "TFG-004",
    "TFG-005",
    "TFG-006",
    "TFG-007",
    "TFG-008",
]

REQUIRED_ERROR_CODES = [
    "ERR_TFG_INVALID_CONFIG",
    "ERR_TFG_UNKNOWN_PROTOCOL",
    "ERR_TFG_SEED_UNSTABLE",
    "ERR_TFG_GATE_FAILED",
    "ERR_TFG_PARTITION_ERROR",
    "ERR_TFG_INIT_FAILED",
]

REQUIRED_INVARIANTS = [
    "INV-TFG-DETERMINISTIC",
    "INV-TFG-CORRECT-OR-FAIL",
    "INV-TFG-NO-CUSTOM",
    "INV-TFG-SEED-STABLE",
    "INV-TFG-FULL-COVERAGE",
    "INV-TFG-PARTITION-CLOSED",
]

REQUIRED_PROTOCOLS = [
    "EpochTransition",
    "LeaseRenewal",
    "EvidenceCommit",
    "MarkerAppend",
    "FencingAcquire",
    "HealthCheck",
]

REQUIRED_FAULT_MODES = [
    "Drop",
    "Reorder",
    "Corrupt",
    "Partition",
]

REQUIRED_FUNCTIONS = [
    "fn run_full_gate",
    "fn test_protocol",
    "fn check_seed_stability",
    "fn evaluate_outcome",
    "fn to_config",
    "fn validate",
    "fn export_audit_log_jsonl",
    "fn summarize_by_protocol",
]


# ── Helpers ────────────────────────────────────────────────────────────────


def record(name: str, passed: bool, detail: str = "") -> None:
    ALL_CHECKS.append({"name": name, "passed": passed, "detail": detail})


def safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def file_contains(path: Path, needle: str) -> bool:
    if not path.exists():
        return False
    return needle in path.read_text(encoding="utf-8")


def rust_file_contains(path: Path, needle: str) -> bool:
    if not path.exists():
        return False
    return needle in strip_rust_comments(path.read_text(encoding="utf-8"))


def read_rust_source(path: Path) -> str:
    if not path.exists():
        return ""
    return strip_rust_comments(path.read_text(encoding="utf-8"))


def strip_rust_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        raw_start = rust_raw_string_start(text, i)
        if raw_start is not None:
            body_start, hashes = raw_start
            end = rust_raw_string_end(text, body_start + 1, hashes)
            if end is None:
                out.append(text[i:])
                break
            out.append(text[i:end])
            i = end
            continue

        if ch == '"':
            end = rust_quoted_literal_end(text, i, ch)
            out.append(text[i:end])
            i = end
            continue

        if text.startswith("//", i):
            newline = text.find("\n", i + 2)
            if newline == -1:
                break
            out.append("\n")
            i = newline + 1
            continue

        if text.startswith("/*", i):
            i = rust_block_comment_end(text, i + 2)
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def rust_raw_string_start(text: str, index: int) -> tuple[int, int] | None:
    n = len(text)
    if text.startswith("br", index):
        cursor = index + 2
    elif text.startswith("r", index):
        cursor = index + 1
    else:
        return None

    hashes = 0
    while cursor < n and text[cursor] == "#":
        hashes += 1
        cursor += 1
    if cursor < n and text[cursor] == '"':
        return cursor, hashes
    return None


def rust_raw_string_end(text: str, index: int, hashes: int) -> int | None:
    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, index)
    if end == -1:
        return None
    return end + len(terminator)


def rust_quoted_literal_end(text: str, index: int, quote: str) -> int:
    i = index + 1
    n = len(text)
    escaped = False
    while i < n:
        ch = text[i]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == quote:
            return i + 1
        i += 1
    return n


def rust_block_comment_end(text: str, index: int) -> int:
    depth = 1
    i = index
    n = len(text)
    while i < n and depth:
        if text.startswith("/*", i):
            depth += 1
            i += 2
        elif text.startswith("*/", i):
            depth -= 1
            i += 2
        else:
            i += 1
    return i


# ── Checks ─────────────────────────────────────────────────────────────────


def check_files_exist() -> None:
    for label, path in [
        ("impl_file", IMPL_FILE),
        ("mod_file", MOD_FILE),
        ("spec_file", SPEC_FILE),
        ("upstream_file", UPSTREAM_FILE),
    ]:
        exists = path.exists()
        record(f"file_exists:{label}", exists, safe_rel(path))


def check_module_wired() -> None:
    wired = rust_file_contains(MOD_FILE, "transport_fault_gate")
    record("module_wired", wired, "connector/mod.rs includes transport_fault_gate")


def check_upstream_import() -> None:
    """Verify module imports from the canonical upstream harness (no custom fault injection)."""
    has_import = rust_file_contains(IMPL_FILE, "use crate::remote::virtual_transport_faults")
    record("upstream_import", has_import, "imports crate::remote::virtual_transport_faults")


def check_required_types() -> None:
    for t in REQUIRED_TYPES:
        found = rust_file_contains(IMPL_FILE, t)
        record(f"type:{t}", found, t)


def check_event_codes() -> None:
    for code in REQUIRED_EVENT_CODES:
        found = rust_file_contains(IMPL_FILE, code)
        record(f"event_code:{code}", found, code)


def check_error_codes() -> None:
    for code in REQUIRED_ERROR_CODES:
        found = rust_file_contains(IMPL_FILE, code)
        record(f"error_code:{code}", found, code)


def check_invariants_in_impl() -> None:
    for inv in REQUIRED_INVARIANTS:
        found = rust_file_contains(IMPL_FILE, inv)
        record(f"invariant_impl:{inv}", found, inv)


def check_invariants_in_spec() -> None:
    for inv in REQUIRED_INVARIANTS:
        found = file_contains(SPEC_FILE, inv)
        record(f"invariant_spec:{inv}", found, inv)


def check_protocols() -> None:
    for proto in REQUIRED_PROTOCOLS:
        found = rust_file_contains(IMPL_FILE, proto)
        record(f"protocol:{proto}", found, proto)


def check_fault_modes() -> None:
    for mode in REQUIRED_FAULT_MODES:
        found = rust_file_contains(IMPL_FILE, mode)
        record(f"fault_mode:{mode}", found, mode)


def check_functions() -> None:
    for fn_sig in REQUIRED_FUNCTIONS:
        found = rust_file_contains(IMPL_FILE, fn_sig)
        record(f"function:{fn_sig}", found, fn_sig)


def check_schema_version() -> None:
    found = rust_file_contains(IMPL_FILE, '"tfg-v1.0"')
    record("schema_version", found, 'SCHEMA_VERSION = "tfg-v1.0"')


def check_bead_identity() -> None:
    found_id = rust_file_contains(IMPL_FILE, '"bd-3u6o"')
    found_section = rust_file_contains(IMPL_FILE, '"10.15"')
    record("bead_id", found_id, 'BEAD_ID = "bd-3u6o"')
    record("bead_section", found_section, 'SECTION = "10.15"')


def check_unit_tests() -> None:
    if not IMPL_FILE.exists():
        record("rust_unit_tests", False, "impl file missing")
        return
    impl_text = read_rust_source(IMPL_FILE)
    test_count = impl_text.count("#[test]")
    has_tests = test_count >= 18
    record(
        "rust_unit_tests",
        has_tests,
        f"{test_count} tests found (need >= 18)",
    )
    RESULTS["rust_test_count"] = test_count


def check_serde_derives() -> None:
    if not IMPL_FILE.exists():
        record("serde_derives", False, "impl file missing")
        return
    impl_text = read_rust_source(IMPL_FILE)
    has_serde = "Serialize, Deserialize" in impl_text
    record("serde_derives", has_serde, "key types derive Serialize/Deserialize")


def check_spec_acceptance_criteria() -> None:
    if not SPEC_FILE.exists():
        record("spec_acceptance_criteria", False, "spec file missing")
        return
    spec_text = SPEC_FILE.read_text(encoding="utf-8")
    has_ac = "Acceptance Criteria" in spec_text
    record("spec_acceptance_criteria", has_ac, "acceptance criteria section present")


# ── run_checks (entry point for programmatic use) ─────────────────────────


def run_checks() -> dict[str, Any]:
    """Run all checks and return structured result dict."""
    ALL_CHECKS.clear()
    RESULTS.clear()

    check_files_exist()
    check_module_wired()
    check_upstream_import()
    check_required_types()
    check_event_codes()
    check_error_codes()
    check_invariants_in_impl()
    check_invariants_in_spec()
    check_protocols()
    check_fault_modes()
    check_functions()
    check_schema_version()
    check_bead_identity()
    check_unit_tests()
    check_serde_derives()
    check_spec_acceptance_criteria()

    passed = sum(1 for c in ALL_CHECKS if c["passed"])
    total = len(ALL_CHECKS)
    verdict = "PASS" if passed == total else "FAIL"

    return {
        "bead_id": "bd-3u6o",
        "section": "10.15",
        "title": "Enforce canonical virtual transport fault harness for distributed control protocols",
        "verdict": verdict,
        "passed": passed,
        "total": total,
        "all_passed": passed == total,
        "checks": ALL_CHECKS,
        **RESULTS,
    }


# ── Self-test ──────────────────────────────────────────────────────────────


def self_test() -> dict[str, Any]:
    """Run internal consistency checks against the verification script itself."""
    st_checks: list[dict[str, Any]] = []

    def st_record(name: str, passed: bool, detail: str = "") -> None:
        st_checks.append({"name": name, "passed": passed, "detail": detail})

    # Verify all check lists are non-empty
    st_record("required_types_nonempty", len(REQUIRED_TYPES) > 0, f"{len(REQUIRED_TYPES)} types")
    st_record("required_event_codes_nonempty", len(REQUIRED_EVENT_CODES) > 0, f"{len(REQUIRED_EVENT_CODES)} codes")
    st_record("required_error_codes_nonempty", len(REQUIRED_ERROR_CODES) > 0, f"{len(REQUIRED_ERROR_CODES)} codes")
    st_record("required_invariants_nonempty", len(REQUIRED_INVARIANTS) > 0, f"{len(REQUIRED_INVARIANTS)} invs")
    st_record("required_protocols_nonempty", len(REQUIRED_PROTOCOLS) > 0, f"{len(REQUIRED_PROTOCOLS)} protos")
    st_record("required_functions_nonempty", len(REQUIRED_FUNCTIONS) > 0, f"{len(REQUIRED_FUNCTIONS)} fns")

    # Exact counts
    st_record("types_count", len(REQUIRED_TYPES) == 10, f"{len(REQUIRED_TYPES)} types (need 10)")
    st_record("event_codes_count", len(REQUIRED_EVENT_CODES) == 8, f"{len(REQUIRED_EVENT_CODES)} codes (need 8)")
    st_record("error_codes_count", len(REQUIRED_ERROR_CODES) == 6, f"{len(REQUIRED_ERROR_CODES)} codes (need 6)")
    st_record("invariants_count", len(REQUIRED_INVARIANTS) == 6, f"{len(REQUIRED_INVARIANTS)} invs (need 6)")
    st_record("protocols_count", len(REQUIRED_PROTOCOLS) == 6, f"{len(REQUIRED_PROTOCOLS)} protos (need 6)")
    st_record("fault_modes_count", len(REQUIRED_FAULT_MODES) == 4, f"{len(REQUIRED_FAULT_MODES)} modes (need 4)")
    st_record("functions_count", len(REQUIRED_FUNCTIONS) == 8, f"{len(REQUIRED_FUNCTIONS)} fns (need 8)")

    # Verify ROOT path points to project root
    st_record("root_has_cargo_toml", (ROOT / "Cargo.toml").exists(), str(ROOT / "Cargo.toml"))

    # Verify run_checks is callable
    st_record("run_checks_callable", callable(run_checks), "run_checks() is callable")

    passed = sum(1 for c in st_checks if c["passed"])
    total = len(st_checks)

    return {
        "self_test": True,
        "passed": passed,
        "total": total,
        "all_passed": passed == total,
        "checks": st_checks,
    }


# ── Main ───────────────────────────────────────────────────────────────────


def main() -> None:
    configure_test_logging("check_transport_fault_gate")
    json_mode = "--json" in sys.argv
    self_test_mode = "--self-test" in sys.argv

    if self_test_mode:
        result = self_test()
        if json_mode:
            print(json.dumps(result, indent=2))
        else:
            for c in result["checks"]:
                status = "PASS" if c["passed"] else "FAIL"
                print(f"  [{status}] {c['name']}: {c['detail']}")
            print(f"\nSelf-test: {result['passed']}/{result['total']} passed")
        sys.exit(0 if result["all_passed"] else 1)

    output = run_checks()

    if json_mode:
        print(json.dumps(output, indent=2))
    else:
        for c in output["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['name']}: {c['detail']}")
        print(f"\nResult: {output['passed']}/{output['total']} checks passed")
        if not output["all_passed"]:
            failed = [c for c in output["checks"] if not c["passed"]]
            print(f"\nFailed ({len(failed)}):")
            for c in failed:
                print(f"  - {c['name']}: {c['detail']}")

    sys.exit(0 if output["all_passed"] else 1)


if __name__ == "__main__":
    main()
