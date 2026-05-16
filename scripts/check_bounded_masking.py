#!/usr/bin/env python3
"""Verification script for bd-24k bounded masking implementation."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "runtime" / "bounded_mask.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_11" / "bd-24k_contract.md"
EVIDENCE = ROOT / "artifacts" / "section_10_11" / "bd-24k" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_11" / "bd-24k" / "verification_summary.md"

REQUIRED_CONSTANTS = [
    "pub const MAX_MASK_DURATION_NS: u64 = 1_000;",
    "pub const DEFAULT_TIMEOUT_NS: u64 = 1_000_000;",
    'pub const MASK_INVOCATION_EVENT: &str = "bounded_mask.invocation";',
    'pub const MASK_ENTER: &str = "MASK_ENTER";',
    'pub const MASK_EXIT: &str = "MASK_EXIT";',
    'pub const MASK_BUDGET_EXCEEDED: &str = "MASK_BUDGET_EXCEEDED";',
    'pub const MASK_NESTING_VIOLATION: &str = "MASK_NESTING_VIOLATION";',
]

REQUIRED_EVENT_CODES = [
    "FN_BM_001_MASK_ENTER",
    "FN_BM_002_MASK_EXIT",
    "FN_BM_003_MASK_BUDGET_EXCEEDED",
    "FN_BM_004_MASK_NESTING_VIOLATION",
    "FN_BM_005_MASK_TIMEOUT_EXCEEDED",
    "FN_BM_006_MASK_CANCEL_DEFERRED",
]

REQUIRED_TYPES = [
    "pub struct CapabilityContext",
    "pub struct CancellationState",
    "pub struct MaskPolicy",
    "pub enum MaskError",
    "pub struct MaskEvent",
    "pub struct MaskInvocationReport",
    "pub struct BoundedMask<T>",
]

REQUIRED_FUNCTIONS = [
    "pub fn bounded_mask<",
    "pub fn bounded_mask_with_report<",
    "pub fn bounded_mask_with_policy<",
    "fn enter_mask_scope",
    "fn emit_event(",
]

REQUIRED_TEST_NAMES = [
    "operation_within_budget_succeeds",
    "timeout_exceeded_returns_error",
    "cancellation_before_entry_aborts_immediately",
    "cancellation_during_mask_is_deferred_then_delivered",
    "nested_mask_panics_with_violation_code",
    "test_mode_emits_budget_warning_without_timeout_when_not_enforced",
    "panic_inside_mask_lifts_scope_and_delivers_deferred_cancel",
    "missing_capability_context_returns_error",
]

REQUIRED_EVIDENCE_FIELDS = [
    "invocations_total",
    "completed_within_bound",
    "mask_timeout_exceeded",
    "deferred_cancels_delivered",
    "avg_mask_duration_us",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read(path))


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


def _record(results: list[dict[str, Any]], name: str, passed: bool, detail: str) -> None:
    results.append({"name": name, "passed": passed, "detail": detail})


def _has_all_tokens(text: str, tokens: list[str]) -> tuple[bool, list[str]]:
    missing = [token for token in tokens if token not in text]
    return (len(missing) == 0, missing)


def _check_impl_signatures(impl_text: str) -> tuple[bool, str]:
    patterns = [
        r"pub fn bounded_mask<[^>]*>\(",
        r"pub fn bounded_mask_with_report<[^>]*>\(",
        r"pub fn bounded_mask_with_policy<[^>]*>\(",
    ]
    for pattern in patterns:
        if re.search(pattern, impl_text) is None:
            return False, f"missing signature matching regex: {pattern}"
    return True, "all expected function signatures present"


def _check_evidence_fields(evidence: dict[str, Any]) -> tuple[bool, list[str]]:
    metrics = evidence.get("verification_metrics")
    if not isinstance(metrics, dict):
        return False, ["verification_metrics missing or not an object"]

    missing = [field for field in REQUIRED_EVIDENCE_FIELDS if field not in metrics]
    return (len(missing) == 0, missing)


def run_checks(project_root: Path = ROOT) -> tuple[bool, dict[str, Any]]:
    impl_path = project_root / IMPL.relative_to(ROOT)
    mod_path = project_root / MOD_RS.relative_to(ROOT)
    spec_path = project_root / SPEC.relative_to(ROOT)
    evidence_path = project_root / EVIDENCE.relative_to(ROOT)
    summary_path = project_root / SUMMARY.relative_to(ROOT)

    results: list[dict[str, Any]] = []

    # Existence checks
    for label, path in [
        ("impl_exists", impl_path),
        ("module_exists", mod_path),
        ("spec_exists", spec_path),
        ("evidence_exists", evidence_path),
        ("summary_exists", summary_path),
    ]:
        _record(results, label, path.is_file(), str(path))

    if not all(entry["passed"] for entry in results):
        payload = {
            "bead_id": "bd-24k",
            "ok": False,
            "results": results,
            "summary": {
                "passed": sum(1 for r in results if r["passed"]),
                "total": len(results),
            },
        }
        return False, payload

    impl_text = _read_rust_source(impl_path)
    mod_text = _read_rust_source(mod_path)
    spec_text = _read(spec_path)
    summary_text = _read(summary_path)
    evidence_json = json.JSONDecoder().decode(_read(evidence_path))

    # Implementation coverage
    ok, missing = _has_all_tokens(impl_text, REQUIRED_CONSTANTS)
    _record(results, "required_constants", ok, "missing: " + ", ".join(missing) if missing else "ok")

    ok, missing = _has_all_tokens(impl_text, REQUIRED_EVENT_CODES)
    _record(results, "required_event_codes", ok, "missing: " + ", ".join(missing) if missing else "ok")

    ok, missing = _has_all_tokens(impl_text, REQUIRED_TYPES)
    _record(results, "required_types", ok, "missing: " + ", ".join(missing) if missing else "ok")

    ok, missing = _has_all_tokens(impl_text, REQUIRED_FUNCTIONS)
    _record(results, "required_functions", ok, "missing: " + ", ".join(missing) if missing else "ok")

    sig_ok, sig_detail = _check_impl_signatures(impl_text)
    _record(results, "signature_patterns", sig_ok, sig_detail)

    tests_ok, missing_tests = _has_all_tokens(impl_text, REQUIRED_TEST_NAMES)
    _record(
        results,
        "unit_test_presence",
        tests_ok,
        "missing: " + ", ".join(missing_tests) if missing_tests else "ok",
    )

    _record(
        results,
        "runtime_mod_wiring",
        "pub mod bounded_mask;" in mod_text,
        "runtime/mod.rs must export bounded_mask module",
    )

    # Spec + summary checks
    _record(
        results,
        "spec_mentions_invariants",
        "## Invariants" in spec_text and "INV-BM-CANCEL-DEFERRED" in spec_text,
        "spec must include invariant table and cancellation deferral invariant",
    )
    _record(
        results,
        "summary_mentions_event_codes",
        "FN-BM-001" in summary_text and "FN-BM-006" in summary_text,
        "summary must mention full event-code span FN-BM-001..FN-BM-006",
    )

    ev_ok, ev_missing = _check_evidence_fields(evidence_json)
    _record(
        results,
        "evidence_metrics_fields",
        ev_ok,
        "missing: " + ", ".join(ev_missing) if ev_missing else "ok",
    )

    passed = all(entry["passed"] for entry in results)
    payload = {
        "bead_id": "bd-24k",
        "ok": passed,
        "results": results,
        "summary": {
            "passed": sum(1 for r in results if r["passed"]),
            "total": len(results),
        },
    }
    return passed, payload


def self_test() -> tuple[bool, dict[str, Any]]:
    sample = "alpha beta gamma"
    ok, missing = _has_all_tokens(sample, ["alpha", "gamma"])
    signature_ok, _ = _check_impl_signatures(
        "pub fn bounded_mask<T, F>() {}\n"
        "pub fn bounded_mask_with_report<T, F>() {}\n"
        "pub fn bounded_mask_with_policy<T, F>() {}\n"
    )
    strip_ok = _strip_rust_comments('"kept // literal"; // removed') == '"kept // literal"; '
    passed = ok and not missing and signature_ok and strip_ok
    return passed, {
        "self_test": "passed" if passed else "failed",
        "token_check_ok": ok,
        "signature_check_ok": signature_ok,
        "strip_check_ok": strip_ok,
    }


def main() -> int:
    configure_test_logging("check_bounded_masking")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="run script self-test")
    args = parser.parse_args()

    if args.self_test:
        ok, payload = self_test()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"self-test: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

    ok, payload = run_checks()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("bd-24k bounded masking verification")
        print(f"status: {'PASS' if ok else 'FAIL'}")
        for row in payload["results"]:
            status = "PASS" if row["passed"] else "FAIL"
            print(f"- {status:4} {row['name']}: {row['detail']}")
        print(f"summary: {payload['summary']['passed']}/{payload['summary']['total']} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
