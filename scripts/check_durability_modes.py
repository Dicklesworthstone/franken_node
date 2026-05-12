#!/usr/bin/env python3
"""Verification script for bd-18ud: durability=local and durability=quorum(M) modes.

Usage:
    python scripts/check_durability_modes.py          # human-readable
    python scripts/check_durability_modes.py --json    # machine-readable
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

IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "durability.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-18ud_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
CLAIM_MATRIX = ROOT / "artifacts" / "10.14" / "durability_mode_claim_matrix.json"

REQUIRED_TYPES = [
    "pub enum DurabilityMode",
    "pub enum WriteOutcome",
    "pub struct DurabilityClaim",
    "pub struct DurabilityError",
    "pub struct DurabilityEvent",
    "pub struct ModeSwitchPolicy",
    "pub struct ReplicaResponse",
    "pub struct DurabilityController",
]

REQUIRED_METHODS = [
    "fn write_local(",
    "fn write_quorum(",
    "fn switch_mode(",
    "fn claim_matrix(",
    "fn derive(",
    "fn is_authorized(",
    "fn validate(",
    "fn mode(",
    "fn class_id(",
]

EVENT_CODES = [
    "DM_MODE_INITIALIZED",
    "DM_MODE_SWITCH",
    "DM_MODE_SWITCH_DENIED",
    "DM_WRITE_LOCAL_CONFIRMED",
    "DM_WRITE_QUORUM_CONFIRMED",
    "DM_WRITE_QUORUM_FAILED",
    "DM_CLAIM_GENERATED",
]

ERROR_CODES = [
    "ERR_QUORUM_INSUFFICIENT",
    "ERR_MODE_SWITCH_DENIED",
    "ERR_INVALID_QUORUM_SIZE",
]

INVARIANTS = [
    "INV-DUR-ENFORCE",
    "INV-DUR-CLAIM-DETERMINISTIC",
    "INV-DUR-SWITCH-AUDITABLE",
    "INV-DUR-QUORUM-FAIL-CLOSED",
]

REQUIRED_TESTS = [
    "test_mode_local_label",
    "test_mode_quorum_label",
    "test_mode_local_display",
    "test_mode_quorum_display",
    "test_mode_validate_local",
    "test_mode_validate_quorum_valid",
    "test_mode_validate_quorum_zero_rejected",
    "test_mode_serde_roundtrip_local",
    "test_mode_serde_roundtrip_quorum",
    "test_outcome_local_is_success",
    "test_outcome_quorum_acked_is_success",
    "test_outcome_quorum_failed_is_not_success",
    "test_claim_local_fsync",
    "test_claim_quorum_acked",
    "test_claim_quorum_failed",
    "test_claim_determinism",
    "test_claim_serde_roundtrip",
    "test_default_policy_allows_upgrade",
    "test_default_policy_denies_downgrade",
    "test_default_policy_allows_downgrade_with_auth",
    "test_strict_policy_denies_upgrade_without_auth",
    "test_strict_policy_allows_with_auth",
    "test_same_mode_same_params_allowed",
    "test_quorum_size_increase_is_upgrade",
    "test_quorum_size_decrease_is_downgrade",
    "test_controller_local_initialization",
    "test_controller_local_write",
    "test_controller_local_emits_events",
    "test_controller_quorum_initialization",
    "test_controller_quorum_write_success",
    "test_controller_quorum_write_excess_acks",
    "test_controller_quorum_write_fail_closed",
    "test_controller_quorum_write_emits_events",
    "test_controller_quorum_failure_emits_events",
    "test_switch_local_to_quorum_default_policy",
    "test_switch_quorum_to_local_denied_without_auth",
    "test_switch_quorum_to_local_allowed_with_auth",
    "test_switch_emits_mode_switch_event",
    "test_switch_denied_emits_denial_event",
    "test_local_write_in_quorum_mode_fails",
    "test_quorum_write_in_local_mode_fails",
    "test_claim_matrix_has_entries",
    "test_claim_matrix_contains_local",
    "test_claim_matrix_all_deterministic",
    "test_take_events_drains",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_error_serde_roundtrip",
    "test_switch_then_write_quorum",
    "test_switch_then_write_local",
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
    found = "pub mod durability;" in text
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
    ok = count >= 40
    return {
        "check": "unit test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 40)",
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


def check_claim_matrix_artifact():
    results = []
    if not CLAIM_MATRIX.exists():
        results.append({"check": "claim matrix artifact exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "claim matrix artifact exists", "pass": True, "detail": "found"})
    data = json.loads(CLAIM_MATRIX.read_text())
    claims = data.get("claims", [])
    ok = len(claims) >= 5
    results.append({
        "check": "claim matrix: claim count",
        "pass": ok,
        "detail": f"{len(claims)} claims (minimum 5)",
    })
    all_det = all(c.get("deterministic", False) for c in claims)
    results.append({
        "check": "claim matrix: all deterministic",
        "pass": all_det,
        "detail": "all deterministic" if all_det else "some not deterministic",
    })
    return results


def check_two_modes():
    if not IMPL.exists():
        return {"check": "two mode variants", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_local = "Local" in text
    has_quorum = "Quorum" in text and "min_acks" in text
    ok = has_local and has_quorum
    return {
        "check": "two mode variants",
        "pass": ok,
        "detail": "Local and Quorum both present" if ok else "missing mode variants",
    }


def check_fail_closed():
    if not IMPL.exists():
        return {"check": "fail-closed quorum semantics", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_check = "ERR_QUORUM_INSUFFICIENT" in text and "acked >= min_acks" in text
    return {
        "check": "fail-closed quorum semantics",
        "pass": has_check,
        "detail": "found" if has_check else "NOT FOUND",
    }


def check_mode_switch_policy():
    if not IMPL.exists():
        return {"check": "mode switch policy", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_policy = "ModeSwitchPolicy" in text and "is_authorized" in text
    return {
        "check": "mode switch policy",
        "pass": has_policy,
        "detail": "found" if has_policy else "NOT FOUND",
    }


def check_claim_determinism():
    if not IMPL.exists():
        return {"check": "claim determinism implementation", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_derive = "fn derive(" in text and "deterministic: true" in text
    return {
        "check": "claim determinism implementation",
        "pass": has_derive,
        "detail": "found" if has_derive else "NOT FOUND",
    }


def run_checks():
    checks = []

    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(CLAIM_MATRIX, "claim matrix artifact"))
    checks.extend(check_claim_matrix_artifact())
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_serde_derives())
    checks.append(check_two_modes())
    checks.append(check_fail_closed())
    checks.append(check_mode_switch_policy())
    checks.append(check_claim_determinism())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, ERROR_CODES, "error_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-18ud",
        "title": "Durability modes (local and quorum)",
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
    logger = configure_test_logging("check_durability_modes")
    logger.info("starting %s verification", "check_durability_modes")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-18ud verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
