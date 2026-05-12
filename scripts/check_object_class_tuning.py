#!/usr/bin/env python3
"""Verification script for bd-8tvs: per-class object tuning policy."""

import json
import os
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates/franken-node/src/policy/object_class_tuning.rs")
MOD_RS = os.path.join(ROOT, "crates/franken-node/src/policy/mod.rs")
SPEC = os.path.join(ROOT, "docs/specs/section_10_14/bd-8tvs_contract.md")
CSV_ARTIFACT = os.path.join(ROOT, "artifacts/10.14/object_class_policy_report.csv")
BENCH_DIR = os.path.join(ROOT, "benchmarks/object_class_tuning")
BENCH_ENCODE_DECODE = os.path.join(BENCH_DIR, "bench_encode_decode.rs")
BENCH_FETCH_LATENCY = os.path.join(BENCH_DIR, "bench_fetch_latency.rs")
EVIDENCE_JSON = os.path.join(ROOT, "artifacts/section_10_14/bd-8tvs/verification_evidence.json")
CHECK_REPORT_JSON = os.path.join(ROOT, "artifacts/section_10_14/bd-8tvs/check_report.json")


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "pass": passed, "detail": detail or ("found" if passed else "NOT FOUND")}


def _file_exists(path: str, label: str) -> dict:
    exists = os.path.isfile(path)
    return _check(f"file: {label}", exists,
                  f"exists: {os.path.relpath(path, ROOT)}" if exists else f"missing: {os.path.relpath(path, ROOT)}")


def run_checks() -> list[dict]:
    checks = []

    # File existence
    checks.append(_file_exists(IMPL, "implementation"))
    checks.append(_file_exists(SPEC, "spec contract"))
    checks.append(_file_exists(CSV_ARTIFACT, "policy report CSV"))
    checks.append(_check("directory: object_class_tuning benchmarks", os.path.isdir(BENCH_DIR),
                         f"exists: {os.path.relpath(BENCH_DIR, ROOT)}" if os.path.isdir(BENCH_DIR)
                         else f"missing: {os.path.relpath(BENCH_DIR, ROOT)}"))
    checks.append(_file_exists(BENCH_ENCODE_DECODE, "encode/decode benchmark"))
    checks.append(_file_exists(BENCH_FETCH_LATENCY, "fetch latency benchmark"))

    # Module registered
    with open(MOD_RS) as f:
        mod_src = f.read()
    checks.append(_check("module registered in mod.rs", "pub mod object_class_tuning;" in mod_src))

    with open(IMPL) as f:
        src = f.read()

    # Types
    for ty in ["pub enum ObjectClass", "pub enum FetchPriority", "pub enum PrefetchPolicy",
               "pub struct ClassTuning", "pub struct BenchmarkMeasurement",
               "pub struct TuningError", "pub struct TuningEvent",
               "pub struct ObjectClassTuningEngine"]:
        checks.append(_check(f"type: {ty}", ty in src))

    # ObjectClass variants
    for variant in ["CriticalMarker", "TrustReceipt", "ReplayBundle", "TelemetryArtifact", "Custom("]:
        checks.append(_check(f"variant: {variant}", variant in src))

    # FetchPriority variants
    for variant in ["Critical", "Normal", "Background"]:
        checks.append(_check(f"fetch_priority: {variant}", f"FetchPriority::{variant}" in src
                             or f"    {variant}," in src))

    # PrefetchPolicy variants
    for variant in ["Eager", "Lazy", "None"]:
        checks.append(_check(f"prefetch_policy: {variant}", f"PrefetchPolicy::{variant}" in src
                             or f"    {variant}," in src))

    # ClassTuning fields
    for field in ["symbol_size_bytes", "encoding_overhead_ratio", "fetch_priority", "prefetch_policy"]:
        checks.append(_check(f"field: {field}", f"pub {field}:" in src or f"{field}:" in src))

    # Default tuning values
    checks.append(_check("default: CriticalMarker 256B", "symbol_size_bytes: 256" in src))
    checks.append(_check("default: TrustReceipt 1024B", "symbol_size_bytes: 1024" in src))
    checks.append(_check("default: ReplayBundle 16384B", "symbol_size_bytes: 16384" in src))
    checks.append(_check("default: TelemetryArtifact 4096B", "symbol_size_bytes: 4096" in src))

    # Methods
    for method in ["fn resolve(", "fn apply_override(", "fn remove_override(",
                   "fn has_override(", "fn active_overrides(", "fn events(",
                   "fn load_benchmark_baseline(", "fn to_csv(",
                   "fn validate(", "fn default_tuning(",
                   "fn label(", "fn canonical_classes(",
                   "fn with_init_event(", "fn unknown_class("]:
        checks.append(_check(f"method: {method}", method in src))

    # Event codes
    for code in ["OC_POLICY_ENGINE_INIT", "OC_POLICY_OVERRIDE_APPLIED",
                 "OC_POLICY_OVERRIDE_REJECTED", "OC_BENCHMARK_BASELINE_LOADED"]:
        checks.append(_check(f"event_code: {code}", code in src))

    # Error codes
    for code in ["ERR_ZERO_SYMBOL_SIZE", "ERR_INVALID_OVERHEAD_RATIO", "ERR_UNKNOWN_CLASS"]:
        checks.append(_check(f"error_code: {code}", code in src))

    # Invariants
    for inv in ["INV-TUNE-CLASS-SPECIFIC", "INV-TUNE-OVERRIDE-AUDITED",
                "INV-TUNE-REJECT-INVALID", "INV-TUNE-DETERMINISTIC"]:
        checks.append(_check(f"invariant: {inv}", inv in src))

    # Serde derives
    checks.append(_check("serde derives", "Serialize" in src and "Deserialize" in src))

    # Send + Sync
    checks.append(_check("Send + Sync asserted", "assert_send" in src and "assert_sync" in src))

    # Tests
    test_names = [
        "test_critical_marker_defaults",
        "test_trust_receipt_defaults",
        "test_replay_bundle_defaults",
        "test_telemetry_artifact_defaults",
        "test_custom_class_no_default",
        "test_all_canonical_classes_have_distinct_symbol_sizes",
        "test_validate_valid_tuning",
        "test_validate_zero_symbol_size",
        "test_validate_negative_overhead",
        "test_validate_overhead_above_one",
        "test_engine_resolve_defaults",
        "test_engine_resolve_custom_returns_none",
        "test_engine_apply_valid_override",
        "test_engine_override_emits_event",
        "test_engine_reject_invalid_override",
        "test_engine_reject_emits_event",
        "test_remove_override",
        "test_active_overrides",
        "test_with_init_event",
        "test_load_benchmark_baseline",
        "test_csv_export_header",
        "test_csv_export_has_all_canonical_classes",
        "test_csv_export_row_count",
        "test_object_class_labels",
        "test_fetch_priority_labels",
        "test_prefetch_policy_labels",
        "test_event_codes_defined",
        "test_error_codes_defined",
        "test_class_tuning_serde_roundtrip",
        "test_object_class_serde_roundtrip",
        "test_error_serde_roundtrip",
        "test_deterministic_resolution",
        "test_four_canonical_classes",
    ]
    for test in test_names:
        checks.append(_check(f"test: {test}", f"fn {test}(" in src))

    # Unit test count
    test_count = len(re.findall(r"#\[test\]", src))
    checks.append(_check("unit test count", test_count >= 30,
                          f"{test_count} tests (minimum 30)"))

    # CSV artifact content
    if os.path.isfile(CSV_ARTIFACT):
        with open(CSV_ARTIFACT) as f:
            csv_content = f.read()
        checks.append(_check("CSV has header", "class_id,symbol_size_bytes," in csv_content))
        checks.append(_check("CSV has critical_marker", "critical_marker" in csv_content))
        checks.append(_check("CSV has trust_receipt", "trust_receipt" in csv_content))
        checks.append(_check("CSV has replay_bundle", "replay_bundle" in csv_content))
        checks.append(_check("CSV has telemetry_artifact", "telemetry_artifact" in csv_content))
    else:
        for label in ["CSV has header", "CSV has critical_marker", "CSV has trust_receipt",
                       "CSV has replay_bundle", "CSV has telemetry_artifact"]:
            checks.append(_check(label, False, "file missing"))

    benchmark_expectations = [
        (BENCH_ENCODE_DECODE, "encode/decode benchmark", [
            "EncodeDecodeRow",
            "ENCODE_DECODE_ROWS",
            "p50_encode_us",
            "p99_decode_us",
        ]),
        (BENCH_FETCH_LATENCY, "fetch latency benchmark", [
            "FetchLatencyRow",
            "FETCH_LATENCY_ROWS",
            "fetch_priority",
            "p99_fetch_us",
        ]),
    ]
    for path, label, tokens in benchmark_expectations:
        if os.path.isfile(path):
            with open(path) as f:
                benchmark_src = f.read()
            for token in tokens:
                checks.append(_check(f"{label}: {token}", token in benchmark_src))
            for class_id in ["critical_marker", "trust_receipt", "replay_bundle", "telemetry_artifact"]:
                checks.append(_check(f"{label}: {class_id}", class_id in benchmark_src))
        else:
            for token in tokens + ["critical_marker", "trust_receipt", "replay_bundle", "telemetry_artifact"]:
                checks.append(_check(f"{label}: {token}", False, "file missing"))

    return checks


def self_test():
    checks = run_checks()
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
    logger = configure_test_logging("check_object_class_tuning")
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--write-evidence",
        action="store_true",
        help="write bd-8tvs verification_evidence.json and check_report.json",
    )
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    checks = run_checks()
    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing

    test_count = len(re.findall(r"#\[test\]", Path(IMPL).read_text())) if os.path.isfile(IMPL) else 0

    result = {
        "bead_id": "bd-8tvs",
        "title": "Per-class object tuning policy",
        "section": "10.14",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": test_count,
        "summary": {"passing": passing, "failing": failing, "total": total},
        "checks": checks,
    }

    if args.write_evidence:
        payload = json.dumps(result, indent=2) + "\n"
        Path(EVIDENCE_JSON).write_text(payload, encoding="utf-8")
        Path(CHECK_REPORT_JSON).write_text(payload, encoding="utf-8")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{passing}/{total} checks pass")

    sys.exit(0 if failing == 0 else 1)


if __name__ == "__main__":
    main()
