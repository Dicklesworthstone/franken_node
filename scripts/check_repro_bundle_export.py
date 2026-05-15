#!/usr/bin/env python3
"""bd-2808: Verify deterministic repro bundle export implementation.

Usage:
  python3 scripts/check_repro_bundle_export.py          # human-readable
  python3 scripts/check_repro_bundle_export.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "testing" / "lab_runtime.rs"
EVIDENCE_REF_HELPER = ROOT / "crates" / "franken-node" / "src" / "tools" / "repro_bundle_export.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-2808_contract.md"
SCHEMA = ROOT / "artifacts" / "10.14" / "repro_bundle_schema_v1.json"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
SUMMARY = ROOT / "artifacts" / "section_10_14" / "bd-2808" / "verification_summary.md"
EVIDENCE = ROOT / "artifacts" / "section_10_14" / "bd-2808" / "verification_evidence.json"

CANONICAL_IMPL_PATH = "crates/franken-node/src/testing/lab_runtime.rs"
EVIDENCE_REF_HELPER_PATH = "crates/franken-node/src/tools/repro_bundle_export.rs"

REQUIRED_TYPES = [
    "pub enum LabError",
    "pub struct LabConfig",
    "pub struct LabEvent",
    "pub struct FaultProfile",
    "pub struct VirtualLink",
    "pub struct ScenarioResult",
    "pub struct ReproBundle",
    "pub struct LabRuntime",
]

REQUIRED_METHODS = [
    "pub fn to_json(",
    "pub fn from_json(",
    "pub fn run_scenario(",
    "pub fn run_scenario_dpor(",
    "pub fn export_repro_bundle(",
    "pub fn replay_bundle(",
    "pub fn events(",
]

EVENT_CODES = [
    "EVT_REPRO_EXPORTED",
    "EVT_SCENARIO_STARTED",
    "EVT_SCENARIO_FAILED",
    "EVT_SCENARIO_COMPLETED",
]

INVARIANTS = [
    "INV-LB-REPLAY",
    "INV-LB-DETERMINISTIC",
    "INV-LB-NO-WALLCLOCK",
]

REQUIRED_TESTS = [
    "test_repro_bundle_export_json_round_trip",
    "test_repro_bundle_to_json_reports_serialization_error",
    "test_repro_bundle_export_is_idempotent_for_same_state",
    "test_repro_bundle_export_respects_max_events_bound",
    "test_repro_bundle_from_json_reports_parse_error",
    "test_repro_bundle_from_json_rejects_unsupported_schema_version",
    "test_repro_bundle_from_json_rejects_seed_mismatch",
    "test_repro_bundle_from_json_rejects_invalid_fault_profile",
    "test_repro_bundle_from_json_rejects_link_capacity_overflow",
    "test_repro_bundle_from_json_rejects_zero_seed_config",
    "test_repro_bundle_from_json_rejects_missing_events_field",
    "test_repro_bundle_from_json_rejects_links_type_confusion",
    "test_repro_bundle_replay_deterministic",
    "test_repro_bundle_replay_divergence_detected",
    "test_repro_bundle_replay_detects_trace_divergence_with_same_outcome",
]

REQUIRED_BUNDLE_FIELDS = [
    "schema_version",
    "seed",
    "config",
    "links",
    "events",
    "passed",
]

REQUIRED_SCHEMA_FIELDS = [
    "schema_version",
    "seed",
    "event_trace",
    "evidence_refs",
]

HELPER_PATTERNS = [
    "pub struct EvidenceRef",
    "pub fn is_portable(",
    "evidence_ref_rejects_nul_byte_relative_path",
    "evidence_ref_accepts_plain_relative_path",
]


def check_file(path, label):
    ok = path.is_file()
    if ok:
        try:
            rel = str(path.relative_to(ROOT))
        except ValueError:
            rel = str(path)
    else:
        rel = str(path)
    return {"check": f"file: {label}", "pass": ok,
            "detail": f"exists: {rel}" if ok else f"MISSING: {rel}"}


def check_content(path, patterns, category, *, strip_comments=True):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    content = read_rust_source(path) if strip_comments else read_text(path)
    for p in patterns:
        found = p in content
        results.append({"check": f"{category}: {p}", "pass": found,
                        "detail": "found" if found else "NOT FOUND"})
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
    if not MOD_RS.is_file():
        return {"check": "module registered in mod.rs", "pass": False, "detail": "mod.rs missing"}
    content = read_rust_source(MOD_RS)
    found = "repro_bundle_export" in content
    return {"check": "EvidenceRef helper registered in tools/mod.rs", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_test_count():
    if not IMPL.is_file():
        return {"check": "unit test count", "pass": False, "detail": "file missing"}
    content = read_rust_source(IMPL)
    count = len(re.findall(r"#\[test\]", content))
    return {"check": "lab runtime unit test count", "pass": count >= 15,
            "detail": f"{count} tests (minimum 15)"}


def check_schema_version():
    if not IMPL.is_file():
        return {"check": "schema version constant", "pass": False, "detail": "file missing"}
    content = read_rust_source(IMPL)
    found = "SCHEMA_VERSION" in content and "schema_version" in content
    return {"check": "schema version constant", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_event_bound():
    if not IMPL.is_file():
        return {"check": "bounded repro events", "pass": False, "detail": "file missing"}
    content = read_rust_source(IMPL)
    found = "MAX_EVENTS" in content and "EVT_REPRO_EXPORTED" in content
    return {"check": "bounded repro events", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_path_truth():
    results = []
    for path, label in [
        (SPEC, "spec contract"),
        (SUMMARY, "verification summary"),
        (EVIDENCE, "verification evidence"),
    ]:
        if not path.is_file():
            results.append({
                "check": f"path truth: {label}",
                "pass": False,
                "detail": f"missing: {path}",
            })
            continue
        text = path.read_text(encoding="utf-8")
        found = CANONICAL_IMPL_PATH in text
        results.append({
            "check": f"path truth: {label} names lab runtime implementation",
            "pass": found,
            "detail": CANONICAL_IMPL_PATH if found else "canonical path missing",
        })
    return results


def self_test():
    result = run_checks()
    all_pass = result["verdict"] == "PASS"
    return all_pass, result["checks"]


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "lab runtime implementation"))
    checks.append(check_file(EVIDENCE_REF_HELPER, "EvidenceRef portability helper"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(SCHEMA, "schema artifact"))
    checks.append(check_file(SUMMARY, "verification summary"))
    checks.append(check_file(EVIDENCE, "verification evidence"))
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_schema_version())
    checks.append(check_event_bound())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))
    checks.extend(check_content(IMPL, REQUIRED_BUNDLE_FIELDS, "bundle_field"))
    checks.extend(check_content(EVIDENCE_REF_HELPER, HELPER_PATTERNS, "evidence_ref_helper"))
    checks.extend(check_content(SCHEMA, REQUIRED_SCHEMA_FIELDS, "schema_field", strip_comments=False))
    checks.extend(check_path_truth())

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    test_count = len(re.findall(r"#\[test\]", read_rust_source(IMPL))) if IMPL.is_file() else 0
    return {
        "bead_id": "bd-2808",
        "title": "Deterministic repro bundle export for control-plane failures",
        "section": "10.14",
        "overall_pass": passed == total,
        "verdict": "PASS" if passed == total else "FAIL",
        "test_count": test_count,
        "summary": {"passing": passed, "failing": total - passed, "total": total},
        "checks": checks,
    }


def main():
    configure_test_logging("check_repro_bundle_export")
    if "--self-test" in sys.argv:
        ok, results = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'}")
        return

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("=== bd-2808: Repro Bundle Export Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing']}/{s['total']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
