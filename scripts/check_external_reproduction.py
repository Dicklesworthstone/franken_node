#!/usr/bin/env python3
"""Verification script for bd-2pu: External-Reproduction Playbook and Automation Scripts.

Checks that the playbook, headline claims registry, automation script,
spec contract, and policy document exist and contain all required content.

Usage:
    python scripts/check_external_reproduction.py           # human-readable
    python scripts/check_external_reproduction.py --json    # machine-readable
    python scripts/check_external_reproduction.py --self-test
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_7" / "bd-2pu_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "external_reproduction.md"
PLAYBOOK_PATH = ROOT / "docs" / "reproduction_playbook.md"
CLAIMS_PATH = ROOT / "docs" / "headline_claims.toml"
SCRIPT_PATH = ROOT / "scripts" / "reproduce.py"

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str = "") -> bool:
    RESULTS.append({"name": name, "pass": passed, "detail": detail})
    return passed


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# File existence checks
# ---------------------------------------------------------------------------

def check_files_exist() -> int:
    ok = 0
    files = [
        ("spec", SPEC_PATH),
        ("policy", POLICY_PATH),
        ("playbook", PLAYBOOK_PATH),
        ("claims_registry", CLAIMS_PATH),
        ("automation_script", SCRIPT_PATH),
    ]
    for label, path in files:
        if _check(f"file_exists:{label}", path.is_file(), f"{label} at {_safe_rel(path)}"):
            ok += 1
    return ok


# ---------------------------------------------------------------------------
# Spec contract checks
# ---------------------------------------------------------------------------

def check_spec_event_codes() -> int:
    if not SPEC_PATH.is_file():
        _check("spec_event_codes:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    codes = ["ERP-001", "ERP-002", "ERP-003", "ERP-004"]
    ok = 0
    for code in codes:
        if _check(f"spec_event_code:{code}", code in text, code):
            ok += 1
    return ok


def check_spec_invariants() -> int:
    if not SPEC_PATH.is_file():
        _check("spec_invariants:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    invs = ["INV-ERP-COMPLETE", "INV-ERP-REPLAY", "INV-ERP-ENVIRONMENT", "INV-ERP-DETERMINISM"]
    ok = 0
    for inv in invs:
        if _check(f"spec_invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_spec_sections() -> int:
    if not SPEC_PATH.is_file():
        _check("spec_sections:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    keywords = [
        "reproduction playbook",
        "automation scripts",
        "headline claims registry",
        "reproduction report",
        "acceptance criteria",
    ]
    ok = 0
    for kw in keywords:
        if _check(f"spec_section:{kw}", kw in text, f"spec section: {kw}"):
            ok += 1
    return ok


def check_spec_error_codes() -> int:
    if not SPEC_PATH.is_file():
        _check("spec_error_codes:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    codes = ["ERR_ERP_PLAYBOOK_MISSING", "ERR_ERP_CLAIMS_MISSING",
             "ERR_ERP_SCRIPT_MISSING", "ERR_ERP_FIXTURE_CHECKSUM"]
    ok = 0
    for code in codes:
        if _check(f"spec_error_code:{code}", code in text, code):
            ok += 1
    return ok


# ---------------------------------------------------------------------------
# Policy document checks
# ---------------------------------------------------------------------------

def check_policy_sections() -> int:
    if not POLICY_PATH.is_file():
        _check("policy_sections:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = [
        "playbook format",
        "automation requirements",
        "environment specification",
        "seed data management",
        "headline claims registry",
        "ci integration",
        "determinism",
        "event codes",
    ]
    ok = 0
    for kw in keywords:
        if _check(f"policy_section:{kw}", kw in text, f"policy section: {kw}"):
            ok += 1
    return ok


def check_policy_event_codes() -> int:
    if not POLICY_PATH.is_file():
        _check("policy_event_codes:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text()
    codes = ["ERP-001", "ERP-002", "ERP-003", "ERP-004"]
    ok = 0
    for code in codes:
        if _check(f"policy_event_code:{code}", code in text, code):
            ok += 1
    return ok


def check_policy_governance() -> int:
    if not POLICY_PATH.is_file():
        _check("policy_governance:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = [
        "sha-256",
        "idempotent",
        "skip-install",
        "dry-run",
        "nightly",
        "release gate",
    ]
    ok = 0
    for kw in keywords:
        if _check(f"policy_governance:{kw}", kw in text, f"policy governance: {kw}"):
            ok += 1
    return ok


# ---------------------------------------------------------------------------
# Playbook completeness checks (INV-ERP-COMPLETE)
# ---------------------------------------------------------------------------

def check_playbook_sections() -> int:
    if not PLAYBOOK_PATH.is_file():
        _check("playbook_sections:present", False, "playbook missing")
        return 0
    text = PLAYBOOK_PATH.read_text().lower()
    sections = [
        "environment setup",
        "fixture download",
        "benchmark execution",
        "result comparison",
        "troubleshooting",
    ]
    ok = 0
    for section in sections:
        if _check(f"playbook_section:{section}", section in text, f"playbook section: {section}"):
            ok += 1
    return ok


def check_playbook_environment() -> int:
    if not PLAYBOOK_PATH.is_file():
        _check("playbook_env:present", False, "playbook missing")
        return 0
    text = PLAYBOOK_PATH.read_text().lower()
    keywords = ["rust", "node", "python", "cpu", "ram", "disk"]
    ok = 0
    for kw in keywords:
        if _check(f"playbook_env:{kw}", kw in text, f"playbook env: {kw}"):
            ok += 1
    return ok


def check_playbook_commands() -> int:
    if not PLAYBOOK_PATH.is_file():
        _check("playbook_commands:present", False, "playbook missing")
        return 0
    text = PLAYBOOK_PATH.read_text()
    commands = ["scripts/reproduce.py", "git clone", "rustup"]
    ok = 0
    for cmd in commands:
        if _check(f"playbook_command:{cmd}", cmd in text, f"playbook command: {cmd}"):
            ok += 1
    return ok


def check_playbook_variance() -> int:
    if not PLAYBOOK_PATH.is_file():
        _check("playbook_variance:present", False, "playbook missing")
        return 0
    text = PLAYBOOK_PATH.read_text().lower()
    keywords = ["variance", "pass/fail", "threshold"]
    ok = 0
    for kw in keywords:
        if _check(f"playbook_variance:{kw}", kw in text, f"playbook variance: {kw}"):
            ok += 1
    return ok


# ---------------------------------------------------------------------------
# Headline claims registry checks
# ---------------------------------------------------------------------------

def check_claims_format() -> int:
    if not CLAIMS_PATH.is_file():
        _check("claims_format:present", False, "claims registry missing")
        return 0
    text = CLAIMS_PATH.read_text()
    required_fields = ["claim_id", "claim_text", "verification_method",
                       "acceptance_threshold", "test_reference"]
    ok = 0
    for field in required_fields:
        if _check(f"claims_field:{field}", field in text, f"claims field: {field}"):
            ok += 1
    return ok


def check_claims_entries() -> int:
    if not CLAIMS_PATH.is_file():
        _check("claims_entries:present", False, "claims registry missing")
        return 0
    text = CLAIMS_PATH.read_text()
    entry_count = text.count("[[claim]]")
    ok = entry_count >= 5
    _check("claims_entries:count", ok, f"{entry_count} claims (minimum 5)")
    return 1 if ok else 0


def check_claims_categories() -> int:
    if not CLAIMS_PATH.is_file():
        _check("claims_categories:present", False, "claims registry missing")
        return 0
    text = CLAIMS_PATH.read_text().lower()
    categories = ["compatibility", "security", "performance", "migration", "trust"]
    ok = 0
    for cat in categories:
        if _check(f"claims_category:{cat}", cat in text, f"claims category: {cat}"):
            ok += 1
    return ok


def check_claims_ids() -> int:
    if not CLAIMS_PATH.is_file():
        _check("claims_ids:present", False, "claims registry missing")
        return 0
    text = CLAIMS_PATH.read_text()
    ids = ["HC-001", "HC-002", "HC-003", "HC-004", "HC-005"]
    ok = 0
    for cid in ids:
        if _check(f"claims_id:{cid}", cid in text, cid):
            ok += 1
    return ok


# ---------------------------------------------------------------------------
# Automation script checks
# ---------------------------------------------------------------------------

def check_script_features() -> int:
    if not SCRIPT_PATH.is_file():
        _check("script_features:present", False, "automation script missing")
        return 0
    text = SCRIPT_PATH.read_text()
    features = [
        "skip-install",
        "dry-run",
        "--json",
        "--yes",
        "--claim",
        "environment_fingerprint",
        "reproduction_report",
        "idempotent",
    ]
    ok = 0
    for feat in features:
        if _check(f"script_feature:{feat}", feat in text, f"script feature: {feat}"):
            ok += 1
    return ok


def check_script_report_fields() -> int:
    if not SCRIPT_PATH.is_file():
        _check("script_report:present", False, "automation script missing")
        return 0
    text = SCRIPT_PATH.read_text()
    fields = ["environment", "claims", "verdict", "timestamp", "duration_seconds"]
    ok = 0
    for field in fields:
        if _check(f"script_report_field:{field}", field in text, f"report field: {field}"):
            ok += 1
    return ok


def check_script_env_fingerprint() -> int:
    if not SCRIPT_PATH.is_file():
        _check("script_fingerprint:present", False, "automation script missing")
        return 0
    text = SCRIPT_PATH.read_text().lower()
    fields = ["os", "cpu", "python_version", "rust_version", "node_version"]
    ok = 0
    for field in fields:
        if _check(f"script_fingerprint:{field}", field in text, f"fingerprint: {field}"):
            ok += 1
    return ok


# ---------------------------------------------------------------------------
# run_all / self_test / main
# ---------------------------------------------------------------------------

def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_spec_event_codes()
    check_spec_invariants()
    check_spec_sections()
    check_spec_error_codes()
    check_policy_sections()
    check_policy_event_codes()
    check_policy_governance()
    check_playbook_sections()
    check_playbook_environment()
    check_playbook_commands()
    check_playbook_variance()
    check_claims_format()
    check_claims_entries()
    check_claims_categories()
    check_claims_ids()
    check_script_features()
    check_script_report_fields()
    check_script_env_fingerprint()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-2pu",
        "title": "External-Reproduction Playbook and Automation Scripts",
        "section": "10.7",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test():
    assert callable(check_files_exist)
    assert callable(check_spec_event_codes)
    assert callable(check_spec_invariants)
    assert callable(check_playbook_sections)
    assert callable(check_claims_format)
    assert callable(check_script_features)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    assert result["bead_id"] == "bd-2pu"
    assert isinstance(result["checks"], list)
    print("self_test: OK")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-2pu External Reproduction Playbook: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
