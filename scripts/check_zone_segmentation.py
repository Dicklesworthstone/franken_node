#!/usr/bin/env python3
"""Verification script for bd-1vp: Zone/Tenant Trust Segmentation Policies.

Checks that the zone segmentation artefacts are present, complete, and
internally consistent.

Usage:
    python3 scripts/check_zone_segmentation.py              # human-readable
    python3 scripts/check_zone_segmentation.py --json        # machine-readable
    python3 scripts/check_zone_segmentation.py --self-test   # smoke-test
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


SPEC = ROOT / "docs" / "specs" / "section_10_10" / "bd-1vp_contract.md"
POLICY = ROOT / "docs" / "policy" / "zone_trust_segmentation.md"
RUST_MODULE = ROOT / "crates" / "franken-node" / "src" / "security" / "trust_zone.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "security" / "mod.rs"
EVIDENCE = ROOT / "artifacts" / "section_10_10" / "bd-1vp" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_10" / "bd-1vp" / "verification_summary.md"

EVENT_CODES = ["ZTS-001", "ZTS-002", "ZTS-003", "ZTS-004"]

INVARIANTS = [
    "INV-ZTS-ISOLATE",
    "INV-ZTS-CEILING",
    "INV-ZTS-DEPTH",
    "INV-ZTS-BIND",
]

ERROR_CODES = [
    "ERR_ZTS_CROSS_ZONE_VIOLATION",
    "ERR_ZTS_TENANT_NOT_BOUND",
    "ERR_ZTS_ZONE_NOT_FOUND",
    "ERR_ZTS_DELEGATION_EXCEEDED",
    "ERR_ZTS_ISOLATION_VIOLATION",
    "ERR_ZTS_DUPLICATE_ZONE",
    "ERR_ZTS_DUPLICATE_TENANT",
    "ERR_ZTS_BRIDGE_INCOMPLETE",
    "ERR_ZTS_FRESHNESS_STALE",
    "ERR_ZTS_KEY_ZONE_MISMATCH",
]

REQUIRED_STRUCTS = [
    "ZonePolicy",
    "TenantBinding",
    "CrossZoneRequest",
    "ZoneSegmentationEngine",
    "SegmentationError",
    "IsolationLevel",
    "ZoneAuditEvent",
]

REQUIRED_METHODS = [
    "register_zone",
    "bind_tenant",
    "authorize_cross_zone",
    "check_isolation",
    "resolve_zone",
    "delete_zone",
    "check_delegation_depth",
    "check_trust_ceiling",
    "validate_key_zone",
]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append({"name": name, "passed": passed, "detail": detail})


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read_text(path))


def _strip_rust_comments(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    while i < n:
        raw_start = _rust_raw_string_start(text, i)
        if raw_start is not None:
            body_start, hashes = raw_start
            end = _rust_raw_string_end(text, body_start + 1, hashes)
            if end is None:
                out.append(text[i:])
                break
            out.append(text[i:end])
            i = end
            continue

        ch = text[i]
        if ch == '"':
            end = _rust_quoted_literal_end(text, i)
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
            i = _rust_block_comment_end(text, i + 2)
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def _rust_raw_string_start(text: str, index: int) -> tuple[int, int] | None:
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


def _rust_raw_string_end(text: str, index: int, hashes: int) -> int | None:
    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, index)
    if end == -1:
        return None
    return end + len(terminator)


def _rust_quoted_literal_end(text: str, index: int) -> int:
    i = index + 1
    n = len(text)
    escaped = False
    while i < n:
        ch = text[i]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            return i + 1
        i += 1
    return n


def _rust_block_comment_end(text: str, index: int) -> int:
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


# -- Spec checks -------------------------------------------------------------


def check_spec_exists() -> None:
    ok = SPEC.is_file()
    _check("spec_exists", ok,
           f"Spec file {'found' if ok else 'MISSING'}: {_safe_rel(SPEC)}")


def check_spec_event_codes() -> None:
    if not SPEC.is_file():
        _check("spec_event_codes", False, "spec file missing")
        return
    text = SPEC.read_text()
    missing = [c for c in EVENT_CODES if c not in text]
    ok = len(missing) == 0
    _check("spec_event_codes", ok,
           "All event codes in spec" if ok else f"Missing: {missing}")


def check_spec_invariants() -> None:
    if not SPEC.is_file():
        _check("spec_invariants", False, "spec file missing")
        return
    text = SPEC.read_text()
    missing = [i for i in INVARIANTS if i not in text]
    ok = len(missing) == 0
    _check("spec_invariants", ok,
           "All invariants in spec" if ok else f"Missing: {missing}")


def check_spec_error_codes() -> None:
    if not SPEC.is_file():
        _check("spec_error_codes", False, "spec file missing")
        return
    text = SPEC.read_text()
    missing = [c for c in ERROR_CODES if c not in text]
    ok = len(missing) == 0
    _check("spec_error_codes", ok,
           "All error codes in spec" if ok else f"Missing: {missing}")


def check_spec_threshold() -> None:
    if not SPEC.is_file():
        _check("spec_threshold", False, "Spec file missing")
        return
    text = SPEC.read_text().lower()
    ok = "threshold" in text and "0" in text
    _check("spec_threshold", ok,
           "Zero-violation threshold documented" if ok else "Missing threshold")


def check_spec_alert_pipeline() -> None:
    if not SPEC.is_file():
        _check("spec_alert_pipeline", False, "Spec file missing")
        return
    text = SPEC.read_text().lower()
    ok = "alert" in text and ("pipeline" in text or "escalation" in text)
    _check("spec_alert_pipeline", ok,
           "Alert pipeline documented" if ok else "Alert pipeline missing")


# -- Policy checks -----------------------------------------------------------


def check_policy_exists() -> None:
    ok = POLICY.is_file()
    _check("policy_exists", ok,
           f"Policy file {'found' if ok else 'MISSING'}: {_safe_rel(POLICY)}")


def check_policy_risk_documented() -> None:
    if not POLICY.is_file():
        _check("policy_risk_documented", False, "Policy file missing")
        return
    text = POLICY.read_text()
    ok = all(k in text for k in ["Impact", "Likelihood", "Trust-System Boundary"])
    _check("policy_risk_documented", ok,
           "Risk description, impact, and likelihood documented" if ok
           else "Missing risk sections")


def check_policy_countermeasures() -> None:
    if not POLICY.is_file():
        _check("policy_countermeasures", False, "Policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = all(k in text for k in ["isolation", "ceiling", "delegation", "bridge", "dashboard"])
    _check("policy_countermeasures", ok,
           "All countermeasures documented" if ok else "Missing countermeasures")


def check_policy_escalation() -> None:
    if not POLICY.is_file():
        _check("policy_escalation", False, "Policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "escalation" in text
    _check("policy_escalation", ok,
           "Escalation procedures documented" if ok else "Missing escalation")


def check_policy_monitoring() -> None:
    if not POLICY.is_file():
        _check("policy_monitoring", False, "Policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "dashboard" in text and "velocity" in text
    _check("policy_monitoring", ok,
           "Monitoring with dashboards and velocity metrics" if ok else "Incomplete monitoring")


def check_policy_evidence_requirements() -> None:
    if not POLICY.is_file():
        _check("policy_evidence_requirements", False, "Policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "evidence" in text and "review" in text
    _check("policy_evidence_requirements", ok,
           "Evidence requirements documented" if ok else "Missing evidence requirements")


# -- Rust module checks ------------------------------------------------------


def check_rust_module_exists() -> None:
    ok = RUST_MODULE.is_file()
    _check("rust_module_exists", ok,
           f"Rust module {'found' if ok else 'MISSING'}: {_safe_rel(RUST_MODULE)}")


def check_rust_module_registered() -> None:
    if not MOD_RS.is_file():
        _check("rust_module_registered", False, "mod.rs MISSING")
        return
    text = _read_rust_source(MOD_RS)
    ok = "trust_zone" in text
    _check("rust_module_registered", ok,
           "trust_zone in mod.rs" if ok else "trust_zone NOT in mod.rs")


def check_rust_structs() -> None:
    if not RUST_MODULE.is_file():
        _check("rust_structs", False, "Rust module MISSING")
        return
    text = _read_rust_source(RUST_MODULE)
    missing = [s for s in REQUIRED_STRUCTS if s not in text]
    ok = len(missing) == 0
    _check("rust_structs", ok,
           f"All {len(REQUIRED_STRUCTS)} structs/enums found" if ok
           else f"Missing: {missing}")


def check_rust_methods() -> None:
    if not RUST_MODULE.is_file():
        _check("rust_methods", False, "Rust module MISSING")
        return
    text = _read_rust_source(RUST_MODULE)
    missing = [m for m in REQUIRED_METHODS if f"fn {m}" not in text]
    ok = len(missing) == 0
    _check("rust_methods", ok,
           f"All {len(REQUIRED_METHODS)} methods found" if ok
           else f"Missing: {missing}")


def check_rust_event_codes() -> None:
    if not RUST_MODULE.is_file():
        _check("rust_event_codes", False, "Rust module MISSING")
        return
    text = _read_rust_source(RUST_MODULE)
    missing = [c for c in EVENT_CODES if c not in text]
    ok = len(missing) == 0
    _check("rust_event_codes", ok,
           "All event codes in Rust source" if ok else f"Missing: {missing}")


def check_rust_invariants() -> None:
    if not RUST_MODULE.is_file():
        _check("rust_invariants", False, "Rust module MISSING")
        return
    text = _read_rust_source(RUST_MODULE)
    missing = [i for i in INVARIANTS if i not in text]
    ok = len(missing) == 0
    _check("rust_invariants", ok,
           "All invariants in Rust source" if ok else f"Missing: {missing}")


def check_rust_isolation_levels() -> None:
    if not RUST_MODULE.is_file():
        _check("rust_isolation_levels", False, "Rust module MISSING")
        return
    text = _read_rust_source(RUST_MODULE)
    levels = ["Strict", "Permissive", "Custom"]
    missing = [lev for lev in levels if lev not in text]
    ok = len(missing) == 0
    _check("rust_isolation_levels", ok,
           "All isolation levels present" if ok else f"Missing: {missing}")


def check_rust_test_count() -> None:
    if not RUST_MODULE.is_file():
        _check("rust_test_count", False, "Rust module MISSING")
        return
    text = _read_rust_source(RUST_MODULE)
    test_count = text.count("#[test]")
    ok = test_count >= 25
    _check("rust_test_count", ok,
           f"{test_count} #[test] annotations (need >= 25)"
           if ok else f"Only {test_count} tests (need >= 25)")


def check_rust_segmentation_errors() -> None:
    if not RUST_MODULE.is_file():
        _check("rust_segmentation_errors", False, "Rust module MISSING")
        return
    text = _read_rust_source(RUST_MODULE)
    variants = [
        "CrossZoneViolation", "TenantNotBound", "ZoneNotFound",
        "DelegationDepthExceeded", "IsolationViolation", "DuplicateZone",
        "DuplicateTenant", "BridgeAuthIncomplete", "FreshnessStale",
        "KeyZoneMismatch",
    ]
    missing = [v for v in variants if v not in text]
    ok = len(missing) == 0
    _check("rust_segmentation_errors", ok,
           f"All {len(variants)} error variants present" if ok
           else f"Missing: {missing}")


def check_rust_freshness_gate() -> None:
    if not RUST_MODULE.is_file():
        _check("rust_freshness_gate", False, "Rust module MISSING")
        return
    text = _read_rust_source(RUST_MODULE)
    ok = "FreshnessStale" in text and "freshness_valid" in text
    _check("rust_freshness_gate", ok,
           "Freshness gate integration present" if ok else "Missing freshness gate")


def check_rust_key_zone_binding() -> None:
    if not RUST_MODULE.is_file():
        _check("rust_key_zone_binding", False, "Rust module MISSING")
        return
    text = _read_rust_source(RUST_MODULE)
    ok = "KeyZoneMismatch" in text and "key_zone_bindings" in text
    _check("rust_key_zone_binding", ok,
           "Key-zone binding with mismatch detection" if ok
           else "Missing key-zone binding")


# -- Evidence checks ---------------------------------------------------------


def check_verification_evidence() -> None:
    if not EVIDENCE.is_file():
        _check("verification_evidence", False,
               f"Evidence file MISSING: {_safe_rel(EVIDENCE)}")
        return
    try:
        data = json.JSONDecoder().decode(_read_text(EVIDENCE))
        ok = data.get("bead_id") == "bd-1vp" and data.get("status") == "pass"
        _check("verification_evidence", ok,
               "Evidence file valid" if ok
               else "Evidence has incorrect bead_id or status")
    except (json.JSONDecodeError, KeyError) as exc:
        _check("verification_evidence", False, f"Evidence parse error: {exc}")


def check_verification_summary() -> None:
    ok = SUMMARY.is_file()
    _check("verification_summary", ok,
           f"Summary file {'found' if ok else 'MISSING'}: {_safe_rel(SUMMARY)}")


# -- Runner ------------------------------------------------------------------


ALL_CHECKS = [
    check_spec_exists,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_error_codes,
    check_spec_threshold,
    check_spec_alert_pipeline,
    check_policy_exists,
    check_policy_risk_documented,
    check_policy_countermeasures,
    check_policy_escalation,
    check_policy_monitoring,
    check_policy_evidence_requirements,
    check_rust_module_exists,
    check_rust_module_registered,
    check_rust_structs,
    check_rust_methods,
    check_rust_event_codes,
    check_rust_invariants,
    check_rust_isolation_levels,
    check_rust_test_count,
    check_rust_segmentation_errors,
    check_rust_freshness_gate,
    check_rust_key_zone_binding,
    check_verification_evidence,
    check_verification_summary,
]


def run_all() -> dict[str, Any]:
    RESULTS.clear()
    for fn in ALL_CHECKS:
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    total = len(RESULTS)
    failed = total - passed
    return {
        "bead_id": "bd-1vp",
        "section": "10.10",
        "title": "Zone/Tenant Trust Segmentation Policies",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "status": "pass" if failed == 0 else "fail",
        "passed": passed,
        "failed": failed,
        "total": total,
        "all_passed": failed == 0,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    """Smoke-test: run all checks and assert the structure is valid."""
    result = run_all()
    assert isinstance(result, dict)
    assert result["bead_id"] == "bd-1vp"
    assert result["section"] == "10.10"
    assert isinstance(result["checks"], list)
    assert result["total"] == len(ALL_CHECKS)
    assert result["passed"] <= result["total"]
    assert result["failed"] == result["total"] - result["passed"]
    assert result["verdict"] in ("PASS", "FAIL")
    for check in result["checks"]:
        assert "name" in check
        assert "passed" in check
        assert "detail" in check
    print("self_test passed")
    return True


def main() -> None:
    configure_test_logging("check_zone_segmentation")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("bd-1vp: Zone/Tenant Trust Segmentation Policies")
        print("=" * 60)
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")
        print(f"\n  {result['passed']}/{result['total']} checks passed"
              f" (verdict={result['verdict']})")
        if result["verdict"] != "PASS":
            sys.exit(1)


if __name__ == "__main__":
    main()
