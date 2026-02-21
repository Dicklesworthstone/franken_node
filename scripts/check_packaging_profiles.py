#!/usr/bin/env python3
"""Verification script for bd-3kn: Packaging profiles for local/dev/enterprise.

Usage:
    python3 scripts/check_packaging_profiles.py              # human-readable
    python3 scripts/check_packaging_profiles.py --json        # machine-readable JSON
    python3 scripts/check_packaging_profiles.py --self-test   # self-test mode
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_10_6" / "bd-3kn_contract.md"
POLICY = ROOT / "docs" / "policy" / "packaging_profiles.md"
PROFILES_TOML = ROOT / "packaging" / "profiles.toml"

VALID_PROFILES = ["local", "dev", "enterprise"]

EVENT_CODES = ["PKG-001", "PKG-002", "PKG-003", "PKG-004"]

INVARIANTS = [
    "INV-PKG-PROFILES",
    "INV-PKG-SELECTION",
    "INV-PKG-SIZE",
    "INV-PKG-INTEGRITY",
    "INV-PKG-COMPONENTS",
    "INV-PKG-TELEMETRY",
    "INV-PKG-AUDIT",
    "INV-PKG-ERROR",
]

COMPONENTS = [
    "core_binary",
    "debug_symbols",
    "lockstep_harness",
    "fixture_generators",
    "compliance_evidence",
    "audit_log_infra",
    "signed_binary_verification",
    "telemetry_export",
]

TELEMETRY_LEVELS = {"local": "off", "dev": "debug-local", "enterprise": "structured-export"}

SIZE_BUDGETS = {"local": 25, "dev": 60, "enterprise": 80}

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    """Return a relative path string, guarding against non-ROOT paths."""
    s_path = str(path)
    s_root = str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = _safe_rel(path)
    return _check(
        f"file_exists: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _file_contains(path: Path, keyword: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: '{keyword}'", False, "file missing")
    content = path.read_text(encoding="utf-8")
    found = keyword in content
    return _check(
        f"{label}: '{keyword}'",
        found,
        "found" if found else "not found in file",
    )


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def check_spec_exists() -> dict[str, Any]:
    """C01: Spec contract file exists."""
    return _file_exists(SPEC, "spec contract")


def check_policy_exists() -> dict[str, Any]:
    """C02: Policy document exists."""
    return _file_exists(POLICY, "policy document")


def check_profiles_toml_exists() -> dict[str, Any]:
    """C03: packaging/profiles.toml configuration file exists."""
    return _file_exists(PROFILES_TOML, "profiles.toml")


def check_profiles_toml_defines_three_profiles() -> dict[str, Any]:
    """C04: profiles.toml defines exactly three profiles: local, dev, enterprise."""
    if not PROFILES_TOML.is_file():
        return _check("profiles_toml_three_profiles", False, "profiles.toml missing")
    content = PROFILES_TOML.read_text(encoding="utf-8")
    missing = [p for p in VALID_PROFILES if f"[profiles.{p}]" in content]
    all_found = len(missing) == 3  # all 3 must be present
    detail = "all 3 profiles defined" if all_found else f"only {len(missing)}/3 found"
    return _check("profiles_toml_three_profiles", all_found, detail)


def check_profiles_toml_components() -> dict[str, Any]:
    """C05: profiles.toml defines component sections for each profile."""
    if not PROFILES_TOML.is_file():
        return _check("profiles_toml_components", False, "profiles.toml missing")
    content = PROFILES_TOML.read_text(encoding="utf-8")
    expected = [f"[profiles.{p}.components]" for p in VALID_PROFILES]
    missing = [s for s in expected if s not in content]
    passed = len(missing) == 0
    detail = "all component sections present" if passed else f"missing: {missing}"
    return _check("profiles_toml_components", passed, detail)


def check_profiles_toml_defaults() -> dict[str, Any]:
    """C06: profiles.toml defines default policy sections for each profile."""
    if not PROFILES_TOML.is_file():
        return _check("profiles_toml_defaults", False, "profiles.toml missing")
    content = PROFILES_TOML.read_text(encoding="utf-8")
    expected = [f"[profiles.{p}.defaults]" for p in VALID_PROFILES]
    missing = [s for s in expected if s not in content]
    passed = len(missing) == 0
    detail = "all default sections present" if passed else f"missing: {missing}"
    return _check("profiles_toml_defaults", passed, detail)


def check_profiles_toml_startup() -> dict[str, Any]:
    """C07: profiles.toml defines startup sections for each profile."""
    if not PROFILES_TOML.is_file():
        return _check("profiles_toml_startup", False, "profiles.toml missing")
    content = PROFILES_TOML.read_text(encoding="utf-8")
    expected = [f"[profiles.{p}.startup]" for p in VALID_PROFILES]
    missing = [s for s in expected if s not in content]
    passed = len(missing) == 0
    detail = "all startup sections present" if passed else f"missing: {missing}"
    return _check("profiles_toml_startup", passed, detail)


def check_profiles_toml_size_budget() -> dict[str, Any]:
    """C08: profiles.toml defines size_budget sections for each profile."""
    if not PROFILES_TOML.is_file():
        return _check("profiles_toml_size_budget", False, "profiles.toml missing")
    content = PROFILES_TOML.read_text(encoding="utf-8")
    expected = [f"[profiles.{p}.size_budget]" for p in VALID_PROFILES]
    missing = [s for s in expected if s not in content]
    passed = len(missing) == 0
    detail = "all size_budget sections present" if passed else f"missing: {missing}"
    return _check("profiles_toml_size_budget", passed, detail)


def check_spec_event_codes() -> dict[str, Any]:
    """C09: Spec defines all four event codes PKG-001 through PKG-004."""
    if not SPEC.is_file():
        return _check("spec_event_codes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes present" if passed else f"missing: {missing}"
    return _check("spec_event_codes", passed, detail)


def check_spec_invariants() -> dict[str, Any]:
    """C10: Spec defines all eight INV-PKG invariants."""
    if not SPEC.is_file():
        return _check("spec_invariants", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = f"all {len(INVARIANTS)} invariants present" if passed else f"missing: {missing}"
    return _check("spec_invariants", passed, detail)


def check_policy_event_codes() -> dict[str, Any]:
    """C11: Policy references all four event codes."""
    if not POLICY.is_file():
        return _check("policy_event_codes", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes in policy" if passed else f"missing: {missing}"
    return _check("policy_event_codes", passed, detail)


def check_policy_invariants() -> dict[str, Any]:
    """C12: Policy references all eight invariants."""
    if not POLICY.is_file():
        return _check("policy_invariants", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = f"all {len(INVARIANTS)} invariants in policy" if passed else f"missing: {missing}"
    return _check("policy_invariants", passed, detail)


def check_local_telemetry_off() -> dict[str, Any]:
    """C13: local profile has telemetry = off in profiles.toml."""
    if not PROFILES_TOML.is_file():
        return _check("local_telemetry_off", False, "profiles.toml missing")
    content = PROFILES_TOML.read_text(encoding="utf-8")
    # Check for telemetry = "off" in the local defaults section
    found = 'telemetry = "off"' in content
    return _check("local_telemetry_off", found, "found" if found else "not found")


def check_enterprise_audit_mandatory() -> dict[str, Any]:
    """C14: enterprise profile has audit_logging = true in profiles.toml."""
    if not PROFILES_TOML.is_file():
        return _check("enterprise_audit_mandatory", False, "profiles.toml missing")
    content = PROFILES_TOML.read_text(encoding="utf-8")
    # enterprise defaults section should have audit_logging = true
    # Parse by finding the enterprise.defaults section
    in_enterprise_defaults = False
    for line in content.splitlines():
        if "[profiles.enterprise.defaults]" in line:
            in_enterprise_defaults = True
            continue
        if in_enterprise_defaults and line.startswith("["):
            break
        if in_enterprise_defaults and "audit_logging = true" in line:
            return _check("enterprise_audit_mandatory", True, "audit_logging = true in enterprise defaults")
    return _check("enterprise_audit_mandatory", False, "audit_logging not true in enterprise defaults")


def check_enterprise_integrity_self_check() -> dict[str, Any]:
    """C15: enterprise profile has integrity_self_check = true in startup."""
    if not PROFILES_TOML.is_file():
        return _check("enterprise_integrity_check", False, "profiles.toml missing")
    content = PROFILES_TOML.read_text(encoding="utf-8")
    in_enterprise_startup = False
    for line in content.splitlines():
        if "[profiles.enterprise.startup]" in line:
            in_enterprise_startup = True
            continue
        if in_enterprise_startup and line.startswith("["):
            break
        if in_enterprise_startup and "integrity_self_check = true" in line:
            return _check("enterprise_integrity_check", True, "integrity_self_check = true in enterprise startup")
    return _check("enterprise_integrity_check", False, "integrity_self_check not true in enterprise startup")


def check_spec_size_constraint() -> dict[str, Any]:
    """C16: Spec documents the 30% size reduction constraint for local vs enterprise."""
    return _file_contains(SPEC, "30%", "spec_size_constraint")


def check_spec_cli_flag() -> dict[str, Any]:
    """C17: Spec documents --profile CLI flag."""
    return _file_contains(SPEC, "--profile", "spec_cli_flag")


def check_spec_env_var() -> dict[str, Any]:
    """C18: Spec documents FRANKEN_NODE_PROFILE env var."""
    return _file_contains(SPEC, "FRANKEN_NODE_PROFILE", "spec_env_var")


# ---------------------------------------------------------------------------
# Profile validation helpers (for testing profile objects)
# ---------------------------------------------------------------------------


def validate_profile(name: str, profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate a profile definition object. Returns list of check results."""
    results: list[dict[str, Any]] = []

    # Profile name valid
    ok = name in VALID_PROFILES
    results.append({"name": "profile_name_valid", "passed": ok, "detail": f"name={name}"})

    # Components section present
    components = profile.get("components", {})
    ok = isinstance(components, dict) and len(components) > 0
    results.append({"name": "components_present", "passed": ok, "detail": f"{len(components)} components"})

    # core_binary must be true
    ok = components.get("core_binary") is True
    results.append({"name": "core_binary_true", "passed": ok, "detail": f"core_binary={components.get('core_binary')}"})

    # Defaults section present
    defaults = profile.get("defaults", {})
    ok = isinstance(defaults, dict) and "telemetry" in defaults
    results.append({"name": "defaults_present", "passed": ok, "detail": "defaults with telemetry key"})

    # Telemetry level valid
    telemetry = defaults.get("telemetry")
    expected = TELEMETRY_LEVELS.get(name)
    ok = telemetry == expected
    results.append({"name": "telemetry_level", "passed": ok, "detail": f"telemetry={telemetry} expected={expected}"})

    # Startup section present
    startup = profile.get("startup", {})
    ok = isinstance(startup, dict) and "mode" in startup
    results.append({"name": "startup_present", "passed": ok, "detail": "startup with mode key"})

    # Size budget present
    size_budget = profile.get("size_budget", {})
    ok = isinstance(size_budget, dict) and "max_binary_mb" in size_budget
    results.append({"name": "size_budget_present", "passed": ok, "detail": "size_budget with max_binary_mb"})

    # Size budget within expected range
    max_mb = size_budget.get("max_binary_mb", 0)
    expected_mb = SIZE_BUDGETS.get(name, 0)
    ok = max_mb == expected_mb
    results.append({"name": "size_budget_value", "passed": ok, "detail": f"max={max_mb}MB expected={expected_mb}MB"})

    return results


# ---------------------------------------------------------------------------
# All check functions
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_profiles_toml_exists,
    check_profiles_toml_defines_three_profiles,
    check_profiles_toml_components,
    check_profiles_toml_defaults,
    check_profiles_toml_startup,
    check_profiles_toml_size_budget,
    check_spec_event_codes,
    check_spec_invariants,
    check_policy_event_codes,
    check_policy_invariants,
    check_local_telemetry_off,
    check_enterprise_audit_mandatory,
    check_enterprise_integrity_self_check,
    check_spec_size_constraint,
    check_spec_cli_flag,
    check_spec_env_var,
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all() -> dict[str, Any]:
    """Run all checks and return structured result."""
    global RESULTS
    RESULTS = []

    for fn in ALL_CHECKS:
        fn()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-3kn",
        "title": "Packaging profiles for local/dev/enterprise deployments",
        "section": "10.6",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    """Run self-test: execute all checks and report pass/fail."""
    report = run_all()
    total = report["total"]
    passed = report["passed"]
    failed = report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-3kn: Packaging profiles for local/dev/enterprise"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    report = run_all()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{report['passed']}/{report['total']} checks pass (verdict={report['verdict']})")

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
