#!/usr/bin/env python3
"""Verification script for bd-15j6: mandatory evidence emission for control decisions.

Usage:
    python scripts/check_control_evidence.py          # human-readable
    python scripts/check_control_evidence.py --json    # machine-readable
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "control_evidence.rs"
SPEC = ROOT / "docs" / "integration" / "control_evidence_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
SAMPLES = ROOT / "artifacts" / "10.15" / "control_evidence_samples.jsonl"
CONFORMANCE_TEST = ROOT / "tests" / "conformance" / "control_policy_evidence_required.rs"
POLICY_EVIDENCE_REQUIRED_SENTINEL = "policy_evidence_required"

REQUIRED_TYPES = [
    "pub enum DecisionType",
    "pub enum DecisionKind",
    "pub enum DecisionOutcome",
    "pub struct ControlEvidenceEntry",
    "pub enum ConformanceError",
    "pub struct ControlEvidenceEvent",
    "pub struct ControlEvidenceEmitter",
]

REQUIRED_METHODS = [
    "fn emit_evidence(",
    "fn execute_with_evidence(",
    "fn verify_ordering(",
    "fn uncovered_types(",
    "fn entries(",
    "fn events(",
    "fn take_events(",
    "fn to_jsonl(",
    "fn validate(",
    "fn map_decision_kind(",
    "fn ordering_key(",
    "fn label(",
    "fn all(",
]

EVENT_CODES = [
    "EVD-001",
    "EVD-002",
    "EVD-003",
    "EVD-004",
    "EVD-005",
]

INVARIANTS = [
    "INV-CE-MANDATORY",
    "INV-CE-SCHEMA",
    "INV-CE-DETERMINISTIC",
    "INV-CE-FAIL-CLOSED",
]

DECISION_TYPES = [
    "HealthGateEval",
    "RolloutTransition",
    "QuarantineAction",
    "FencingDecision",
    "MigrationDecision",
]

REQUIRED_TESTS = [
    "test_decision_type_all",
    "test_decision_type_labels",
    "test_decision_type_display",
    "test_decision_kind_labels",
    "test_decision_kind_display",
    "test_map_health_gate_pass",
    "test_map_health_gate_fail",
    "test_map_rollout_go",
    "test_map_rollout_nogo",
    "test_map_quarantine_promote",
    "test_map_quarantine_demote",
    "test_map_fencing_grant",
    "test_map_fencing_deny",
    "test_map_migration_proceed",
    "test_map_migration_abort",
    "test_entry_validate_valid",
    "test_entry_validate_bad_schema_version",
    "test_entry_validate_empty_decision_id",
    "test_entry_validate_empty_trace_id",
    "test_entry_validate_empty_action",
    "test_emit_valid_evidence",
    "test_emit_invalid_evidence_rejected",
    "test_emit_emits_evd001_event",
    "test_emit_emits_evd003_event",
    "test_emit_invalid_emits_evd004_event",
    "test_execute_with_evidence_success",
    "test_execute_without_evidence_fails",
    "test_execute_without_evidence_emits_evd002",
    "test_execute_with_wrong_type_fails",
    "test_ordering_valid",
    "test_ordering_violation_detected",
    "test_ordering_violation_emits_evd005",
    "test_coverage_starts_empty",
    "test_coverage_tracks_emitted_types",
    "test_full_coverage",
    "test_deterministic_entries",
    "test_deterministic_jsonl",
    "test_jsonl_export",
    "test_jsonl_multiple_entries",
    "test_take_events_drains",
    "test_conformance_error_display_missing",
    "test_conformance_error_display_schema",
    "test_conformance_error_display_ordering",
    "test_conformance_error_display_mismatch",
    "test_entry_serde_roundtrip",
    "test_decision_type_serde_roundtrip",
    "test_conformance_error_serde_roundtrip",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_default_emitter",
    "test_all_types_can_emit",
]

REQUIRED_CONFORMANCE_TESTS = [
    POLICY_EVIDENCE_REQUIRED_SENTINEL,
    "policy_evidence_required_for_every_policy_influenced_decision",
    "policy_evidence_required_missing_entry_fails_closed",
    "policy_evidence_required_rejects_malformed_schema",
    "policy_evidence_required_ordering_is_deterministic",
    "policy_evidence_required_detects_ordering_violation",
]


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {safe_rel(path)}" if ok else f"MISSING: {path}",
    }


def safe_rel(path):
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def check_content(path, patterns, category, *, strip_comments=True):
    results = []
    if not path.exists():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    text = read_rust_source(path) if strip_comments else read_text(path)
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def read_text(path):
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def read_rust_source(path):
    return strip_rust_comments(read_text(path))


def strip_rust_comments(text):
    out = []
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


def rust_raw_string_start(text, index):
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


def rust_raw_string_end(text, index, hashes):
    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, index)
    if end == -1:
        return None
    return end + len(terminator)


def rust_quoted_literal_end(text, index, quote):
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


def rust_block_comment_end(text, index):
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


def check_module_registered():
    if not MOD_RS.exists():
        return {"check": "module registered in mod.rs", "pass": False, "detail": "mod.rs missing"}
    text = read_rust_source(MOD_RS)
    found = "pub mod control_evidence;" in text
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_test_count():
    if not IMPL.exists():
        return {"check": "unit test count", "pass": False, "detail": "impl missing"}
    text = read_rust_source(IMPL)
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 40
    return {
        "check": "unit test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 40)",
    }


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = read_rust_source(IMPL)
    has_ser = "Serialize" in text and "Deserialize" in text
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_ser,
        "detail": "found" if has_ser else "NOT FOUND",
    }


def check_samples_jsonl():
    results = []
    if not SAMPLES.exists():
        results.append({"check": "samples JSONL exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "samples JSONL exists", "pass": True, "detail": "found"})
    lines = [line for line in read_text(SAMPLES).strip().split("\n") if line.strip()]
    ok = len(lines) >= 10
    results.append({
        "check": "samples JSONL: entry count",
        "pass": ok,
        "detail": f"{len(lines)} entries (minimum 10)",
    })
    # Check all 5 decision types are represented
    types_found = set()
    for line in lines:
        try:
            entry = json.JSONDecoder().decode(line)
            types_found.add(entry.get("decision_type", ""))
        except json.JSONDecodeError:
            pass
    all_types = len(types_found) >= 5
    results.append({
        "check": "samples JSONL: all decision types",
        "pass": all_types,
        "detail": f"found {len(types_found)} types" if all_types else f"only {len(types_found)} types",
    })
    return results


def check_spec_content():
    results = []
    if not SPEC.exists():
        results.append({"check": "spec: decision types listed", "pass": False, "detail": "spec missing"})
        return results
    text = read_text(SPEC)
    for dt in DECISION_TYPES:
        found = dt in text
        results.append({
            "check": f"spec: {dt} documented",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def run_checks():
    checks = []

    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(SAMPLES, "evidence samples JSONL"))
    checks.append(check_file(CONFORMANCE_TEST, "policy evidence required conformance test"))
    checks.extend(check_samples_jsonl())
    checks.extend(check_spec_content())
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_serde_derives())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))
    checks.extend(check_content(CONFORMANCE_TEST, REQUIRED_CONFORMANCE_TESTS, "conformance_test"))

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-15j6",
        "title": "Mandatory evidence emission for policy-influenced control decisions",
        "section": "10.15",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": check_test_count()["detail"].split()[0] if IMPL.exists() else 0,
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    logger = configure_test_logging("check_control_evidence")
    logger.info("starting %s verification", "check_control_evidence")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-15j6 verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
