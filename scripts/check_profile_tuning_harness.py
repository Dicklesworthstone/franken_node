#!/usr/bin/env python3
"""Verification script for bd-27o2: profile tuning harness.

Usage:
    python scripts/check_profile_tuning_harness.py          # human-readable
    python scripts/check_profile_tuning_harness.py --json    # machine-readable
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

IMPL = ROOT / "crates" / "franken-node" / "src" / "tools" / "profile_tuning_harness.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-27o2_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
SIGNED_BUNDLE = ROOT / "artifacts" / "10.14" / "signed_policy_update_bundle.json"
BASELINE_CSV = ROOT / "artifacts" / "10.14" / "object_class_policy_report.csv"

REQUIRED_TYPES = [
    "pub struct BenchmarkResult",
    "pub struct BaselineRow",
    "pub struct CandidateUpdate",
    "pub struct PolicyDelta",
    "pub struct HardwareFingerprint",
    "pub struct SignedPolicyBundle",
    "pub struct RegressionDiagnostic",
    "pub struct HarnessEvent",
    "pub struct HarnessConfig",
    "pub struct ProfileTuningHarness",
    "pub enum HarnessOutcome",
]

REQUIRED_METHODS = [
    "fn run(",
    "fn verify_bundle(",
    "fn sign_bundle(",
    "fn compute_deltas(",
    "fn check_regressions(",
    "fn events(",
    "fn take_events(",
    "fn config(",
    "fn is_regression(",
    "fn signable_payload(",
    "fn bundle_hash(",
    "fn hmac_sign(",
    "fn hmac_verify(",
    "fn parse_baseline_csv(",
    "fn from_info(",
    "fn with_defaults(",
]

EVENT_CODES = [
    "PT_HARNESS_START",
    "PT_BENCHMARK_COMPLETE",
    "PT_CANDIDATE_COMPUTED",
    "PT_REGRESSION_REJECTED",
    "PT_BUNDLE_SIGNED",
    "PT_BUNDLE_VERIFIED",
]

INVARIANTS = [
    "INV-PT-IDEMPOTENT",
    "INV-PT-SIGNED",
    "INV-PT-REGRESSION-SAFE",
    "INV-PT-CHAIN",
]

REQUIRED_TESTS = [
    "test_hmac_sign_deterministic",
    "test_hmac_sign_different_key",
    "test_hmac_sign_different_payload",
    "test_hmac_verify_valid",
    "test_hmac_verify_invalid",
    "test_hmac_verify_wrong_key",
    "test_hardware_fingerprint_deterministic",
    "test_hardware_fingerprint_different_info",
    "test_hardware_fingerprint_display",
    "test_delta_no_regression",
    "test_delta_encode_regression",
    "test_delta_decode_regression",
    "test_delta_at_exact_threshold_not_regression",
    "test_regression_diagnostic_display",
    "test_parse_baseline_csv",
    "test_parse_baseline_csv_empty",
    "test_parse_baseline_csv_skips_short_lines",
    "test_harness_successful_run",
    "test_harness_produces_signed_bundle",
    "test_harness_bundle_has_candidates",
    "test_harness_bundle_has_deltas",
    "test_harness_bundle_has_provenance",
    "test_harness_bundle_signature_verifies",
    "test_harness_idempotent",
    "test_harness_rejects_regression",
    "test_harness_regression_diagnostic_detail",
    "test_harness_regression_emits_event",
    "test_harness_emits_start_event",
    "test_harness_emits_benchmark_complete",
    "test_harness_emits_candidate_computed",
    "test_harness_emits_bundle_signed",
    "test_harness_emits_bundle_verified",
    "test_take_events_drains",
    "test_bundle_chain_first_has_no_previous",
    "test_bundle_chain_second_references_first",
    "test_bundle_hash_deterministic",
    "test_default_config",
    "test_custom_threshold",
    "test_config_access",
    "test_bundle_signable_payload_excludes_signature",
    "test_bundle_serde_roundtrip",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_verify_bundle_wrong_key",
    "test_empty_benchmarks",
    "test_delta_shows_old_and_new_values",
    "test_delta_p99_change_zero_without_previous",
]


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.exists():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered():
    if not MOD_RS.exists():
        return {"check": "module registered in mod.rs", "pass": False, "detail": "mod.rs missing"}
    text = MOD_RS.read_text()
    found = "pub mod profile_tuning_harness;" in text
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_test_count():
    if not IMPL.exists():
        return {"check": "unit test count", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 35
    return {
        "check": "unit test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 35)",
    }


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_ser = "Serialize" in text and "Deserialize" in text
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_ser,
        "detail": "found" if has_ser else "NOT FOUND",
    }


def check_signed_bundle():
    results = []
    if not SIGNED_BUNDLE.exists():
        results.append({"check": "signed bundle exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "signed bundle exists", "pass": True, "detail": "found"})
    data = json.loads(SIGNED_BUNDLE.read_text())

    has_version = "version" in data
    results.append({
        "check": "bundle: version field",
        "pass": has_version,
        "detail": "found" if has_version else "NOT FOUND",
    })

    has_sig = "signature" in data and data["signature"]
    results.append({
        "check": "bundle: signature field",
        "pass": has_sig,
        "detail": "found" if has_sig else "NOT FOUND",
    })

    has_candidates = "candidates" in data and len(data["candidates"]) >= 4
    results.append({
        "check": "bundle: candidates count",
        "pass": has_candidates,
        "detail": f"{len(data.get('candidates', []))} candidates (minimum 4)",
    })

    has_deltas = "deltas" in data and len(data["deltas"]) >= 4
    results.append({
        "check": "bundle: deltas count",
        "pass": has_deltas,
        "detail": f"{len(data.get('deltas', []))} deltas (minimum 4)",
    })

    has_hw = "hardware_fingerprint" in data and data["hardware_fingerprint"]
    results.append({
        "check": "bundle: hardware fingerprint",
        "pass": has_hw,
        "detail": "found" if has_hw else "NOT FOUND",
    })

    has_threshold = "regression_threshold_pct" in data
    results.append({
        "check": "bundle: regression threshold",
        "pass": has_threshold,
        "detail": "found" if has_threshold else "NOT FOUND",
    })

    return results


def check_baseline_csv():
    if not BASELINE_CSV.exists():
        return {"check": "baseline CSV exists", "pass": False, "detail": "MISSING"}
    text = BASELINE_CSV.read_text()
    lines = [l for l in text.strip().split("\n") if l.strip()]
    ok = len(lines) >= 5  # header + 4 classes
    return {
        "check": "baseline CSV exists",
        "pass": ok,
        "detail": f"{len(lines)} lines (minimum 5)",
    }


def run_checks():
    checks = []

    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(SIGNED_BUNDLE, "signed bundle artifact"))
    checks.append(check_baseline_csv())
    checks.extend(check_signed_bundle())
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_serde_derives())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-27o2",
        "title": "Profile tuning harness with signed policy updates",
        "section": "10.14",
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
    logger = configure_test_logging("check_profile_tuning_harness")
    logger.info("starting %s verification", "check_profile_tuning_harness")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-27o2 verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
