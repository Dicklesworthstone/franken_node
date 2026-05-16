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
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

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


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _read_rust_source(path: Path) -> str:
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

INVARIANT_IMPLEMENTATION_MARKERS = {
    "INV-KRS-ROLE-EXCLUSIVITY": [
        "self.active.get(key_id)",
        "existing_role != role",
        "KeyRoleEvent::violation(",
        "KeyRoleSeparationError::RoleSeparationViolation",
    ],
    "INV-KRS-ONE-ACTIVE": [
        "pub fn lookup_by_role(",
        "self.active.values().filter",
        "b.role == role",
        "self.active.insert(key_id.to_string(), binding)",
    ],
    "INV-KRS-ROLE-GUARD": [
        "pub fn verify_role(",
        "actual_role != expected_role",
        "KeyRoleEvent::violation(",
        "KeyRoleSeparationError::KeyRoleMismatch",
    ],
    "INV-KRS-ROTATION-ATOMIC": [
        "pub fn rotate(",
        "self.active.remove(old_key_id)",
        "self.active.insert(new_key_id.to_string(), new_binding)",
        "KeyRoleEvent::rotated(",
    ],
}

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
    content = _read_rust_source(path) if path.suffix == ".rs" else _read_text(path)
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


def check_invariants(path):
    results = []
    if not path.is_file():
        for inv in REQUIRED_INVARIANTS:
            results.append({
                "id": f"KRS-INVARIANT-{inv}",
                "check": f"invariant: {inv}",
                "pass": False,
                "detail": "file missing",
            })
        return results
    content = _read_rust_source(path)
    for inv in REQUIRED_INVARIANTS:
        markers = INVARIANT_IMPLEMENTATION_MARKERS[inv]
        missing = [marker for marker in markers if marker not in content]
        results.append({
            "id": f"KRS-INVARIANT-{inv}",
            "check": f"invariant: {inv}",
            "pass": not missing,
            "detail": "implementation markers present" if not missing else f"missing: {missing}",
        })
    return results


def check_module_registered():
    if not MOD_RS.is_file():
        return {"id": "KRS-MOD-REG", "check": "module registered in mod.rs",
                "pass": False, "detail": "mod.rs missing"}
    content = _read_rust_source(MOD_RS)
    found = "pub mod key_role_separation;" in content
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
    content = _read_rust_source(path)
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
    content = _read_rust_source(path)
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
    content = _read_rust_source(path)
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
    checks.extend(check_invariants(IMPL))

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
    _require(isinstance(result, dict), "result must be a dict")
    _require(result["bead"] == "bd-364", "unexpected bead id")
    _require("checks" in result, "checks missing")
    _require(isinstance(result["checks"], list), "checks must be a list")
    _require(len(result["checks"]) > 0, "checks must not be empty")
    _require("verdict" in result, "verdict missing")
    _require("summary" in result, "summary missing")
    print(f"self_test passed: {result['summary']['passing_checks']}/{result['summary']['total_checks']} checks")
    return result


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    configure_test_logging("check_key_role_separation")
    if "--self-test" in sys.argv:
        self_test()
        return 0

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("=== bd-364: Key-Role Separation Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing_checks']}/{s['total_checks']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
