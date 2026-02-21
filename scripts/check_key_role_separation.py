#!/usr/bin/env python3
"""bd-364: Verify key-role separation for control-plane signing.

Checks:
  1. key_role_separation.rs exists with required types and operations
  2. KeyRole enum defines four variants with 2-byte tags
  3. KeyRoleBinding struct with required fields
  4. KeyRoleRegistry with bind, lookup, lookup_by_role, revoke, rotate, verify_role
  5. Error codes: KRS_ROLE_SEPARATION_VIOLATION, KRS_KEY_ROLE_MISMATCH,
     KRS_KEY_NOT_FOUND, KRS_ROTATION_FAILED
  6. Event codes: KRS_KEY_ROLE_BOUND, KRS_KEY_ROLE_REVOKED,
     KRS_KEY_ROLE_ROTATED, KRS_ROLE_VIOLATION_ATTEMPT
  7. Invariant markers in code
  8. Unit tests cover binding, exclusivity, lookup, revoke, rotation, verify_role

Usage:
  python3 scripts/check_key_role_separation.py          # human-readable
  python3 scripts/check_key_role_separation.py --json    # machine-readable
  python3 scripts/check_key_role_separation.py --self-test
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "key_role_separation.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_10" / "bd-364_contract.md"
POLICY = ROOT / "docs" / "policy" / "key_role_separation.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mod.rs"


def _safe_rel(path):
    """Return path relative to ROOT, or str(path) if outside ROOT."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


REQUIRED_TYPES = [
    "pub enum KeyRole",
    "pub struct KeyRoleBinding",
    "pub struct KeyRoleRegistry",
    "pub enum KeyRoleSeparationError",
]

REQUIRED_METHODS = [
    "fn bind(",
    "fn lookup(",
    "fn lookup_by_role(",
    "fn revoke(",
    "fn rotate(",
    "fn verify_role(",
    "fn tag(",
    "fn from_tag(",
]

REQUIRED_ERROR_CODES = [
    "KRS_ROLE_SEPARATION_VIOLATION",
    "KRS_KEY_ROLE_MISMATCH",
    "KRS_KEY_NOT_FOUND",
    "KRS_ROTATION_FAILED",
]

REQUIRED_EVENT_CODES = [
    "KRS_KEY_ROLE_BOUND",
    "KRS_KEY_ROLE_REVOKED",
    "KRS_KEY_ROLE_ROTATED",
    "KRS_ROLE_VIOLATION_ATTEMPT",
]

REQUIRED_INVARIANTS = [
    "INV-KRS-ROLE-EXCLUSIVITY",
    "INV-KRS-ONE-ACTIVE",
    "INV-KRS-ROLE-GUARD",
    "INV-KRS-ROTATION-ATOMIC",
]

REQUIRED_ROLES = [
    "Signing",
    "Encryption",
    "Issuance",
    "Attestation",
]

REQUIRED_TESTS = [
    "role_signing_tag",
    "role_encryption_tag",
    "role_issuance_tag",
    "role_attestation_tag",
    "role_from_tag_roundtrip",
    "role_from_tag_invalid",
    "role_all_has_four_variants",
    "bind_signing_key",
    "bind_encryption_key",
    "bind_issuance_key",
    "bind_attestation_key",
    "role_exclusivity_violation",
    "role_exclusivity_violation_all_pairs",
    "lookup_existing_key",
    "lookup_missing_key",
    "lookup_by_role_returns_matching",
    "lookup_by_role_empty_for_unbound_role",
    "revoke_active_key",
    "revoke_nonexistent_key",
    "revoke_and_relookup_returns_none",
    "rotate_key_successfully",
    "rotation_atomicity_old_revoked_new_bound",
    "rotate_nonexistent_old_key_fails",
    "rotate_wrong_role_fails",
    "verify_role_pass",
    "verify_role_mismatch",
    "verify_role_not_found",
    "verify_role_all_roles",
    "verify_role_cross_role_rejected",
    "bind_emits_event",
    "revoke_emits_event",
    "rotate_emits_event",
    "violation_emits_critical_event",
    "events_contain_trace_id",
    "error_codes_all_variants",
    "full_lifecycle_bind_use_rotate_revoke",
]

SPEC_CONTENT = [
    "KeyRole",
    "KeyRoleBinding",
    "KeyRoleRegistry",
    "INV-KRS-ROLE-EXCLUSIVITY",
    "INV-KRS-ROTATION-ATOMIC",
    "verify_role",
    "KRS_KEY_ROLE_BOUND",
    "KRS_KEY_ROLE_MISMATCH",
]

POLICY_CONTENT = [
    "Key-Role Separation Policy",
    "Signing",
    "Encryption",
    "Issuance",
    "Attestation",
    "Role Exclusivity",
    "verify_role",
]


def check_file(path, label):
    ok = path.is_file()
    rel = _safe_rel(path) if ok else _safe_rel(path)
    return {
        "id": f"KRS-FILE-{label.upper().replace(' ', '-')}",
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {rel}" if ok else f"MISSING: {rel}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({
                "id": f"KRS-{category.upper()}-MISSING",
                "check": f"{category}: {p}",
                "pass": False,
                "detail": "file missing",
            })
        return results
    content = path.read_text()
    for p in patterns:
        found = p in content
        short = p[:30].upper().replace(' ', '-').replace('(', '').replace(')', '')
        results.append({
            "id": f"KRS-{category.upper()}-{short}",
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered():
    if not MOD_RS.is_file():
        return {"id": "KRS-MOD-REG", "check": "module registered in mod.rs",
                "pass": False, "detail": "mod.rs missing"}
    content = MOD_RS.read_text()
    found = "key_role_separation" in content
    return {
        "id": "KRS-MOD-REG",
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_role_tags(path):
    """Verify that each role has a fixed 2-byte tag."""
    results = []
    if not path.is_file():
        results.append({"id": "KRS-ROLE-TAGS", "check": "role tags",
                        "pass": False, "detail": "file missing"})
        return results
    content = path.read_text()
    for role, tag in [("Signing", "0x00, 0x01"), ("Encryption", "0x00, 0x02"),
                      ("Issuance", "0x00, 0x03"), ("Attestation", "0x00, 0x04")]:
        found = tag in content
        results.append({
            "id": f"KRS-TAG-{role.upper()}",
            "check": f"role tag: {role} = [{tag}]",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_test_count(path):
    if not path.is_file():
        return {"id": "KRS-TEST-COUNT", "check": "test count",
                "pass": False, "detail": "file missing"}
    content = path.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {
        "id": "KRS-TEST-COUNT",
        "check": "unit test count",
        "pass": count >= 30,
        "detail": f"{count} tests (minimum 30)",
    }


def check_binding_fields(path):
    """Verify KeyRoleBinding has required fields."""
    results = []
    if not path.is_file():
        return results
    content = path.read_text()
    for field in ["key_id", "role", "public_key_bytes", "bound_at", "bound_by",
                  "max_validity_seconds"]:
        found = f"pub {field}" in content
        results.append({
            "id": f"KRS-FIELD-{field.upper().replace('_', '-')}",
            "check": f"binding field: {field}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(POLICY, "policy document"))

    # Module registration
    checks.append(check_module_registered())

    # Types
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))

    # Methods
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))

    # Error codes
    checks.extend(check_content(IMPL, REQUIRED_ERROR_CODES, "error_code"))

    # Event codes
    checks.extend(check_content(IMPL, REQUIRED_EVENT_CODES, "event_code"))

    # Invariants
    checks.extend(check_content(IMPL, REQUIRED_INVARIANTS, "invariant"))

    # Role variants
    checks.extend(check_content(IMPL, REQUIRED_ROLES, "role"))

    # Role tags
    checks.extend(check_role_tags(IMPL))

    # Binding fields
    checks.extend(check_binding_fields(IMPL))

    # Test count
    checks.append(check_test_count(IMPL))

    # Required tests
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    # Spec content
    checks.extend(check_content(SPEC, SPEC_CONTENT, "spec"))

    # Policy content
    checks.extend(check_content(POLICY, POLICY_CONTENT, "policy"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)

    return {
        "bead": "bd-364",
        "title": "Key-role separation for control-plane signing",
        "section": "10.10",
        "verdict": "PASS" if passed == total else "FAIL",
        "summary": {
            "passing_checks": passed,
            "failing_checks": total - passed,
            "total_checks": total,
        },
        "checks": checks,
    }


def self_test():
    result = run_checks()
    assert isinstance(result, dict), "Result must be a dict"
    assert result["bead"] == "bd-364"
    assert "checks" in result
    assert isinstance(result["checks"], list)
    assert len(result["checks"]) > 0
    assert "verdict" in result
    assert "summary" in result
    print(f"self_test passed: {result['summary']['passing_checks']}/{result['summary']['total_checks']} checks")
    return result


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== bd-364: Key-Role Separation Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing_checks']}/{s['total_checks']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
