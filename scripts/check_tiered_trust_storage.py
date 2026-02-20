#!/usr/bin/env python3
"""Verification script for bd-okqy: L1/L2/L3 tiered trust artifact storage.

Usage:
    python scripts/check_tiered_trust_storage.py          # human-readable
    python scripts/check_tiered_trust_storage.py --json    # machine-readable
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "tiered_trust_storage.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-okqy_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
AUTH_MAP = ROOT / "artifacts" / "10.14" / "tiered_storage_authority_map.json"

REQUIRED_TYPES = [
    "pub enum ObjectClass",
    "pub enum Tier",
    "pub struct AuthorityLevel",
    "pub struct ArtifactId",
    "pub struct TrustArtifact",
    "pub struct StorageError",
    "pub struct AuthorityMap",
    "pub struct TieredTrustStorage",
    "pub struct StorageEvent",
]

REQUIRED_METHODS = [
    "fn store(",
    "fn retrieve(",
    "fn evict(",
    "fn authority_level(",
    "fn recover_tier(",
    "fn try_update_authority(",
    "fn authority_map(",
    "fn to_json(",
    "fn authoritative_tier(",
    "fn is_authoritative(",
]

EVENT_CODES = [
    "TS_TIER_INITIALIZED",
    "TS_STORE_COMPLETE",
    "TS_RETRIEVE_COMPLETE",
    "TS_EVICT_COMPLETE",
    "TS_RECOVERY_START",
    "TS_RECOVERY_COMPLETE",
    "TS_AUTHORITY_MAP_VIOLATION",
]

ERROR_CODES = [
    "ERR_AUTHORITY_MAP_IMMUTABLE",
    "ERR_ARTIFACT_NOT_FOUND",
    "ERR_RECOVERY_SOURCE_MISSING",
    "ERR_RECOVERY_DIRECTION_INVALID",
    "ERR_EVICT_REQUIRES_RETRIEVABILITY",
]

INVARIANTS = [
    "INV-TIER-AUTHORITY",
    "INV-TIER-IMMUTABLE",
    "INV-TIER-RECOVERY",
    "INV-TIER-ORDERED",
]

REQUIRED_TESTS = [
    "test_authority_levels_are_ordered",
    "test_authority_level_for_tiers",
    "test_authority_map_default_has_all_classes",
    "test_authority_map_default_assignments",
    "test_authority_map_immutable",
    "test_authority_map_is_authoritative",
    "test_authority_map_len",
    "test_authority_map_json_serialization",
    "test_authority_map_custom",
    "test_storage_initialization_events",
    "test_storage_empty_on_creation",
    "test_storage_authority_levels",
    "test_store_and_retrieve_l1",
    "test_store_and_retrieve_l2",
    "test_store_and_retrieve_l3",
    "test_retrieve_missing_returns_error",
    "test_evict_l1_requires_l2_or_l3_copy",
    "test_evict_l1_succeeds_with_l2_copy",
    "test_evict_l1_succeeds_with_l3_copy",
    "test_evict_l2_requires_l3_copy",
    "test_evict_l2_succeeds_with_l3_copy",
    "test_evict_l3_always_allowed",
    "test_evict_missing_artifact_error",
    "test_recover_l1_from_l2",
    "test_recover_l1_from_l3",
    "test_recover_l2_from_l3",
    "test_recover_l3_fails",
    "test_recover_missing_source_fails",
    "test_recover_prefers_l2_over_l3",
    "test_recovery_events_emitted",
    "test_try_update_authority_fails_with_event",
    "test_object_class_all",
    "test_object_class_as_str",
    "test_object_class_display",
    "test_object_class_serde_roundtrip",
    "test_tier_all",
    "test_tier_ordering",
    "test_tier_as_str",
    "test_tier_serde_roundtrip",
    "test_take_events_drains",
    "test_artifact_serde_roundtrip",
    "test_storage_error_serde_roundtrip",
    "test_contains_false_when_empty",
    "test_contains_true_after_store",
    "test_store_emits_event",
    "test_retrieve_emits_event",
    "test_evict_emits_event",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_tier_count_increments",
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
    found = "pub mod tiered_trust_storage;" in text
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


def check_authority_map_artifact():
    results = []
    if not AUTH_MAP.exists():
        results.append({"check": "authority map artifact exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "authority map artifact exists", "pass": True, "detail": "found"})
    data = json.loads(AUTH_MAP.read_text())
    classes = data.get("authority_mapping", {})
    ok = len(classes) >= 4
    results.append({
        "check": "authority map: class count",
        "pass": ok,
        "detail": f"{len(classes)} classes (minimum 4)",
    })
    tiers = data.get("tiers", {})
    ok = len(tiers) >= 3
    results.append({
        "check": "authority map: tier count",
        "pass": ok,
        "detail": f"{len(tiers)} tiers (minimum 3)",
    })
    recovery = data.get("recovery_paths", [])
    ok = len(recovery) >= 3
    results.append({
        "check": "authority map: recovery paths",
        "pass": ok,
        "detail": f"{len(recovery)} paths documented",
    })
    return results


def check_three_tiers():
    if not IMPL.exists():
        return {"check": "three tier variants", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_l1 = "L1Local" in text
    has_l2 = "L2Warm" in text
    has_l3 = "L3Archive" in text
    ok = has_l1 and has_l2 and has_l3
    return {
        "check": "three tier variants",
        "pass": ok,
        "detail": "L1Local, L2Warm, L3Archive all present" if ok else "missing tier variants",
    }


def check_object_classes():
    if not IMPL.exists():
        return {"check": "four object classes", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    classes = ["CriticalMarker", "TrustReceipt", "ReplayBundle", "TelemetryArtifact"]
    found = [c for c in classes if c in text]
    ok = len(found) == 4
    return {
        "check": "four object classes",
        "pass": ok,
        "detail": f"{len(found)}/4 classes found" if ok else f"missing: {set(classes) - set(found)}",
    }


def check_eviction_preconditions():
    if not IMPL.exists():
        return {"check": "eviction precondition enforcement", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_check = "ERR_EVICT_REQUIRES_RETRIEVABILITY" in text and "evict" in text
    return {
        "check": "eviction precondition enforcement",
        "pass": has_check,
        "detail": "found" if has_check else "NOT FOUND",
    }


def check_recovery_path():
    if not IMPL.exists():
        return {"check": "recovery path implementation", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_recover = "fn recover_tier(" in text and "find_recovery_source" in text
    return {
        "check": "recovery path implementation",
        "pass": has_recover,
        "detail": "found" if has_recover else "NOT FOUND",
    }


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(AUTH_MAP, "authority map artifact"))

    # Authority map artifact content
    checks.extend(check_authority_map_artifact())

    # Module registration
    checks.append(check_module_registered())

    # Test count
    checks.append(check_test_count())

    # Serde derives
    checks.append(check_serde_derives())

    # Structural checks
    checks.append(check_three_tiers())
    checks.append(check_object_classes())
    checks.append(check_eviction_preconditions())
    checks.append(check_recovery_path())

    # Required types
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))

    # Required methods
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))

    # Event codes
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))

    # Error codes
    checks.extend(check_content(IMPL, ERROR_CODES, "error_code"))

    # Invariants
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))

    # Required tests
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-okqy",
        "title": "L1/L2/L3 tiered trust artifact storage",
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
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-okqy verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
