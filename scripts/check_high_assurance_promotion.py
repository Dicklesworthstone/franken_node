#!/usr/bin/env python3
"""Verification script for bd-3ort: proof-presence quarantine promotion."""

import json
import os
import re
import sys
from pathlib import Path

ROOT_PATH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_PATH))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

ROOT = str(ROOT_PATH)
IMPL = os.path.join(ROOT, "crates/franken-node/src/connector/high_assurance_promotion.rs")
MOD_RS = os.path.join(ROOT, "crates/franken-node/src/connector/mod.rs")
SPEC = os.path.join(ROOT, "docs/specs/section_10_14/bd-3ort_contract.md")
MATRIX = os.path.join(ROOT, "artifacts/10.14/high_assurance_promotion_matrix.json")


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "pass": passed, "detail": detail or ("found" if passed else "NOT FOUND")}


def _file_exists(path: str, label: str) -> dict:
    exists = os.path.isfile(path)
    return _check(f"file: {label}", exists, f"exists: {os.path.relpath(path, ROOT)}" if exists else f"missing: {os.path.relpath(path, ROOT)}")


def _read_text(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _read_rust_source(path: str) -> str:
    return _strip_rust_comments(_read_text(path))


def _strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            i = _rust_block_comment_end(text, i + 2)
            continue

        raw_end = _rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = _rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def _rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def _rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def _rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor


def _src_contains(pattern: str, label: str) -> dict:
    src = _read_rust_source(IMPL)
    found = bool(re.search(pattern, src))
    return _check(label, found)


def run_checks() -> list[dict]:
    checks = []

    # File existence
    checks.append(_file_exists(IMPL, "implementation"))
    checks.append(_file_exists(SPEC, "spec contract"))
    checks.append(_file_exists(MATRIX, "promotion matrix artifact"))

    # Module registered
    mod_src = _read_rust_source(MOD_RS)
    checks.append(_check("module registered in mod.rs",
                          "pub mod high_assurance_promotion;" in mod_src))

    src = _read_rust_source(IMPL)

    # Types
    for ty in ["pub enum AssuranceMode", "pub enum ObjectClass",
               "pub enum ProofRequirement", "pub struct ProofBundle",
               "pub enum PromotionDenialReason", "pub struct PolicyAuthorization",
               "pub struct HighAssuranceGate", "pub struct PromotionMatrixEntry"]:
        checks.append(_check(f"type: {ty}", ty in src))

    # AssuranceMode variants
    for variant in ["Standard", "HighAssurance"]:
        checks.append(_check(f"assurance_mode: {variant}",
                              bool(re.search(rf"^\s+{variant}\b", src, re.MULTILINE))))

    # ObjectClass variants
    for variant in ["CriticalMarker", "StateObject", "TelemetryArtifact", "ConfigObject"]:
        checks.append(_check(f"object_class: {variant}",
                              bool(re.search(rf"^\s+{variant}\b", src, re.MULTILINE))))

    # ProofRequirement variants
    for variant in ["FullProofChain", "IntegrityProof", "IntegrityHash", "SchemaProof"]:
        checks.append(_check(f"proof_requirement: {variant}",
                              bool(re.search(rf"^\s+{variant}\b", src, re.MULTILINE))))

    # PromotionDenialReason variants
    for variant in ["ProofBundleMissing", "ProofBundleInsufficient", "UnauthorizedModeDowngrade"]:
        checks.append(_check(f"denial_reason: {variant}",
                              variant in src))

    # Methods
    for method in ["fn evaluate(", "fn switch_mode(", "fn promotion_matrix(",
                   "fn satisfies(", "fn empty(", "fn full(",
                   "fn label(", "fn requires_proof(", "fn code(",
                   "fn to_json(", "fn proof_requirement_for("]:
        checks.append(_check(f"method: {method}", method in src))

    # Event codes
    for code in ["QUARANTINE_PROMOTION_APPROVED", "QUARANTINE_PROMOTION_DENIED",
                 "ASSURANCE_MODE_CHANGED"]:
        checks.append(_check(f"event_code: {code}", code in src))

    # Invariants
    for inv in ["INV-HA-PROOF-REQUIRED", "INV-HA-FAIL-CLOSED", "INV-HA-MODE-POLICY"]:
        checks.append(_check(f"invariant: {inv}", inv in src))

    # Denial codes
    for code in ["PROMOTION_DENIED_PROOF_BUNDLE_MISSING",
                 "PROMOTION_DENIED_PROOF_INSUFFICIENT",
                 "MODE_DOWNGRADE_UNAUTHORIZED"]:
        checks.append(_check(f"denial_code: {code}", code in src))

    # Tests
    test_names = [
        "assurance_mode_labels", "assurance_mode_display", "assurance_mode_requires_proof",
        "object_class_labels", "object_class_all_four", "object_class_display",
        "proof_requirement_labels", "proof_requirement_mapping",
        "empty_proof_bundle", "full_proof_bundle", "proof_bundle_satisfies_check",
        "standard_mode_allows_without_proof", "standard_mode_allows_with_proof",
        "high_assurance_rejects_without_proof", "high_assurance_rejects_insufficient_proof",
        "high_assurance_approves_with_full_proof", "high_assurance_per_class_enforcement",
        "high_assurance_each_class_has_requirement",
        "upgrade_to_high_assurance_no_auth_needed", "downgrade_without_auth_rejected",
        "downgrade_with_auth_allowed", "same_mode_switch_is_noop",
        "counters_accumulate",
        "promotion_matrix_standard_mode", "promotion_matrix_high_assurance_mode",
        "promotion_matrix_per_class_requirements", "matrix_entry_to_json",
        "denial_reason_codes", "denial_reason_display",
        "partial_bundle_rejected_for_critical", "mode_downgrade_via_direct_mutation_blocked",
        "gate_defaults", "gate_high_assurance_defaults",
    ]
    for test in test_names:
        checks.append(_check(f"test: {test}", f"fn {test}(" in src))

    # Unit test count
    test_count = len(re.findall(r"#\[test\]", src))
    checks.append(_check("unit test count", test_count >= 25,
                          f"{test_count} tests (minimum 25)"))

    # Promotion matrix artifact validity
    if os.path.isfile(MATRIX):
        with open(MATRIX, encoding="utf-8") as f:
            matrix = json.load(f)
        checks.append(_check("matrix is list", isinstance(matrix, list)))
        checks.append(_check("matrix has 4 entries", len(matrix) == 4))
        class_names = {e["object_class"] for e in matrix}
        checks.append(_check("matrix covers all classes",
                              class_names == {"critical_marker", "state_object",
                                              "telemetry_artifact", "config_object"}))
        ha_entries = [e for e in matrix if e.get("assurance_mode") == "high_assurance"]
        all_have_req = all(e.get("proof_requirement") is not None for e in ha_entries)
        checks.append(_check("HA entries have proof requirements", all_have_req))
    else:
        for label in ["matrix is list", "matrix has 4 entries",
                       "matrix covers all classes", "HA entries have proof requirements"]:
            checks.append(_check(label, False, "matrix file missing"))

    return checks


def self_test():
    """Run internal consistency checks."""
    checks = run_checks()
    strip_check_ok = _strip_rust_comments('"kept // literal"; // removed') == '"kept // literal"; '
    if not strip_check_ok:
        print("self_test: Rust comment stripper corrupted string literals")
        return False
    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing
    print(f"self_test: {passing}/{total} checks pass, {failing} failing")
    if failing:
        for c in checks:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} — {c['detail']}")
    return failing == 0


def main():
    configure_test_logging("check_high_assurance_promotion")
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    checks = run_checks()
    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing
    test_count = len(re.findall(r"#\[test\]", _read_rust_source(IMPL))) if os.path.isfile(IMPL) else 0

    if args.json:
        result = {
            "bead_id": "bd-3ort",
            "title": "Proof-presence requirement for quarantine promotion",
            "section": "10.14",
            "overall_pass": failing == 0,
            "verdict": "PASS" if failing == 0 else "FAIL",
            "test_count": test_count,
            "summary": {"passing": passing, "failing": failing, "total": total},
            "checks": checks,
        }
        print(json.dumps(result, indent=2))
    else:
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{passing}/{total} checks pass")

    sys.exit(0 if failing == 0 else 1)


if __name__ == "__main__":
    main()
