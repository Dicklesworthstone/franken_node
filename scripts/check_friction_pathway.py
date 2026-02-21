#!/usr/bin/env python3
"""Verification script for bd-34d5: Friction-Minimized Install-to-Production Pathway.

Usage:
    python scripts/check_friction_pathway.py          # human-readable
    python scripts/check_friction_pathway.py --json   # JSON output
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

BEAD_ID = "bd-34d5"
SECTION = "section_13"

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_13" / "bd-34d5_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "friction_minimized_pathway.md"
EVIDENCE_PATH = ROOT / "artifacts" / "section_13" / "bd-34d5" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_13" / "bd-34d5" / "verification_summary.md"

ARCHETYPES = [
    "Express API",
    "React SPA",
    "CLI Tool",
    "Monorepo",
    "Serverless",
]

EVENT_CODES = ["FMP-001", "FMP-002", "FMP-003", "FMP-004"]

INVARIANTS = [
    "INV-FMP-TIME",
    "INV-FMP-ZERO-EDIT",
    "INV-FMP-TELEMETRY",
    "INV-FMP-ARCHETYPES",
]


def check_spec_exists() -> dict:
    """Check that the spec document exists."""
    ok = SPEC_PATH.is_file()
    return {
        "check": "spec_exists",
        "passed": ok,
        "detail": f"Spec file {'found' if ok else 'missing'} at {SPEC_PATH.relative_to(ROOT) if str(SPEC_PATH).startswith(str(ROOT)) else SPEC_PATH}",
    }


def check_policy_exists() -> dict:
    """Check that the policy document exists."""
    ok = POLICY_PATH.is_file()
    return {
        "check": "policy_exists",
        "passed": ok,
        "detail": f"Policy file {'found' if ok else 'missing'} at {POLICY_PATH.relative_to(ROOT) if str(POLICY_PATH).startswith(str(ROOT)) else POLICY_PATH}",
    }


def check_archetypes() -> dict:
    """Check that all 5 archetypes are defined in the spec."""
    if not SPEC_PATH.is_file():
        return {
            "check": "archetypes_defined",
            "passed": False,
            "detail": "Spec file missing; cannot check archetypes",
        }
    content = SPEC_PATH.read_text()
    missing = [a for a in ARCHETYPES if a not in content]
    ok = len(missing) == 0
    detail = "All 5 archetypes present" if ok else f"Missing archetypes: {missing}"
    return {"check": "archetypes_defined", "passed": ok, "detail": detail}


def check_time_budget() -> dict:
    """Check that the spec defines the 300-second time budget."""
    if not SPEC_PATH.is_file():
        return {
            "check": "time_budget",
            "passed": False,
            "detail": "Spec file missing; cannot check time budget",
        }
    content = SPEC_PATH.read_text()
    ok = "300" in content and ("5 min" in content or "5 minutes" in content)
    return {
        "check": "time_budget",
        "passed": ok,
        "detail": "Time budget of 300s / 5 min found" if ok else "Time budget not properly defined",
    }


def check_zero_edit() -> dict:
    """Check that the zero-edit requirement is documented."""
    if not SPEC_PATH.is_file():
        return {
            "check": "zero_edit_requirement",
            "passed": False,
            "detail": "Spec file missing; cannot check zero-edit requirement",
        }
    content = SPEC_PATH.read_text()
    ok = "zero manual file edit" in content.lower() or "zero-edit" in content.lower()
    return {
        "check": "zero_edit_requirement",
        "passed": ok,
        "detail": "Zero-edit requirement documented" if ok else "Zero-edit requirement missing",
    }


def check_event_codes() -> dict:
    """Check that all 4 event codes are defined in the spec."""
    if not SPEC_PATH.is_file():
        return {
            "check": "event_codes",
            "passed": False,
            "detail": "Spec file missing; cannot check event codes",
        }
    content = SPEC_PATH.read_text()
    missing = [code for code in EVENT_CODES if code not in content]
    ok = len(missing) == 0
    detail = "All 4 event codes defined" if ok else f"Missing event codes: {missing}"
    return {"check": "event_codes", "passed": ok, "detail": detail}


def check_invariants() -> dict:
    """Check that all 4 invariants are defined in the spec."""
    if not SPEC_PATH.is_file():
        return {
            "check": "invariants",
            "passed": False,
            "detail": "Spec file missing; cannot check invariants",
        }
    content = SPEC_PATH.read_text()
    missing = [inv for inv in INVARIANTS if inv not in content]
    ok = len(missing) == 0
    detail = "All 4 invariants defined" if ok else f"Missing invariants: {missing}"
    return {"check": "invariants", "passed": ok, "detail": detail}


def check_telemetry_in_policy() -> dict:
    """Check that the policy defines telemetry requirements."""
    if not POLICY_PATH.is_file():
        return {
            "check": "telemetry_policy",
            "passed": False,
            "detail": "Policy file missing; cannot check telemetry",
        }
    content = POLICY_PATH.read_text()
    has_schema = "Event Schema" in content or "event_schema" in content.lower()
    has_codes = all(code in content for code in EVENT_CODES)
    ok = has_schema and has_codes
    return {
        "check": "telemetry_policy",
        "passed": ok,
        "detail": "Telemetry schema and event codes in policy" if ok else "Telemetry requirements incomplete in policy",
    }


def check_error_handling_policy() -> dict:
    """Check that the policy covers error handling requirements."""
    if not POLICY_PATH.is_file():
        return {
            "check": "error_handling_policy",
            "passed": False,
            "detail": "Policy file missing; cannot check error handling",
        }
    content = POLICY_PATH.read_text().lower()
    has_clear = "clear message" in content
    has_recovery = "recovery suggest" in content or "recovery" in content
    has_no_silent = "silent failure" in content or "no silent" in content
    ok = has_clear and has_recovery and has_no_silent
    return {
        "check": "error_handling_policy",
        "passed": ok,
        "detail": "Error handling policy complete" if ok else "Error handling policy incomplete (needs clear messages, recovery suggestions, no-silent-failure rule)",
    }


def check_ci_gate_policy() -> dict:
    """Check that the policy defines CI gate requirements for all archetypes."""
    if not POLICY_PATH.is_file():
        return {
            "check": "ci_gate_policy",
            "passed": False,
            "detail": "Policy file missing; cannot check CI gate",
        }
    content = POLICY_PATH.read_text()
    has_ci = "CI Gate" in content or "ci gate" in content.lower()
    has_archetypes = "INV-FMP-ARCHETYPES" in content
    ok = has_ci and has_archetypes
    return {
        "check": "ci_gate_policy",
        "passed": ok,
        "detail": "CI gate policy defined for all archetypes" if ok else "CI gate policy incomplete",
    }


def check_spec_sections() -> dict:
    """Check that the spec contains all required sections."""
    if not SPEC_PATH.is_file():
        return {
            "check": "spec_sections",
            "passed": False,
            "detail": "Spec file missing; cannot check sections",
        }
    content = SPEC_PATH.read_text()
    required = [
        "Archetypes",
        "Pathway Steps",
        "Time Budget",
        "Event Codes",
        "Invariants",
        "Acceptance Criteria",
        "Error Handling",
    ]
    missing = [s for s in required if s not in content]
    ok = len(missing) == 0
    detail = "All required spec sections present" if ok else f"Missing spec sections: {missing}"
    return {"check": "spec_sections", "passed": ok, "detail": detail}


def check_policy_pathway_steps() -> dict:
    """Check that the policy defines the 4-step pathway."""
    if not POLICY_PATH.is_file():
        return {
            "check": "policy_pathway_steps",
            "passed": False,
            "detail": "Policy file missing; cannot check pathway steps",
        }
    content = POLICY_PATH.read_text().lower()
    steps = ["install", "init", "configure", "run"]
    missing = [s for s in steps if s not in content]
    ok = len(missing) == 0
    return {
        "check": "policy_pathway_steps",
        "passed": ok,
        "detail": "All 4 pathway steps defined in policy" if ok else f"Missing steps: {missing}",
    }


def check_archetype_scores() -> dict:
    """Check that archetype compatibility scores are specified."""
    if not SPEC_PATH.is_file():
        return {
            "check": "archetype_scores",
            "passed": False,
            "detail": "Spec file missing; cannot check scores",
        }
    content = SPEC_PATH.read_text()
    scores = ["0.90", "0.85", "0.92", "0.80", "0.88"]
    found = [s for s in scores if s in content]
    ok = len(found) == len(scores)
    return {
        "check": "archetype_scores",
        "passed": ok,
        "detail": f"Found {len(found)}/5 archetype compatibility scores",
    }


ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_archetypes,
    check_time_budget,
    check_zero_edit,
    check_event_codes,
    check_invariants,
    check_telemetry_in_policy,
    check_error_handling_policy,
    check_ci_gate_policy,
    check_spec_sections,
    check_policy_pathway_steps,
    check_archetype_scores,
]


def run_all_checks() -> list[dict]:
    """Run every check and return list of results."""
    return [fn() for fn in ALL_CHECKS]


def write_evidence(results: list[dict]) -> None:
    """Write verification evidence JSON."""
    EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    evidence = {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_checks": len(results),
        "passed": sum(1 for r in results if r["passed"]),
        "failed": sum(1 for r in results if not r["passed"]),
        "all_passed": all(r["passed"] for r in results),
        "checks": results,
    }
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n")


def write_summary(results: list[dict]) -> None:
    """Write human-readable verification summary."""
    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    lines = [
        f"# bd-34d5 Verification Summary",
        "",
        f"**Bead:** {BEAD_ID}",
        f"**Section:** 13 -- Friction-Minimized Install-to-Production Pathway",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        f"## Results: {passed}/{total} checks passed",
        "",
        "| # | Check | Result | Detail |",
        "|---|-------|--------|--------|",
    ]
    for i, r in enumerate(results, 1):
        status = "PASS" if r["passed"] else "FAIL"
        lines.append(f"| {i} | {r['check']} | {status} | {r['detail']} |")
    lines.append("")
    if failed == 0:
        lines.append("All checks passed. Bead bd-34d5 is ready for closure.")
    else:
        lines.append(f"**{failed} check(s) failed.** Review details above.")
    lines.append("")
    SUMMARY_PATH.write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-34d5: Friction-Minimized Install-to-Production Pathway"
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    results = run_all_checks()
    write_evidence(results)
    write_summary(results)

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    all_ok = all(r["passed"] for r in results)

    if args.json:
        output = {
            "bead_id": BEAD_ID,
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "all_passed": all_ok,
            "checks": results,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"bd-34d5 Verification: {passed}/{total} checks passed\n")
        for r in results:
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"  [{mark}] {r['check']}: {r['detail']}")
        print()
        if all_ok:
            print("All checks passed.")
        else:
            print(f"{total - passed} check(s) failed.")

    sys.exit(0 if all_ok else 1)


def self_test() -> None:
    """Self-test: run all checks and assert they return valid structure."""
    results = run_all_checks()
    assert isinstance(results, list), "results must be a list"
    assert len(results) == len(ALL_CHECKS), f"expected {len(ALL_CHECKS)} results, got {len(results)}"
    for r in results:
        assert "check" in r, "each result must have 'check'"
        assert "passed" in r, "each result must have 'passed'"
        assert "detail" in r, "each result must have 'detail'"
        assert isinstance(r["passed"], bool), "'passed' must be bool"
        assert isinstance(r["check"], str), "'check' must be str"
        assert isinstance(r["detail"], str), "'detail' must be str"

    # Verify evidence and summary were written
    assert EVIDENCE_PATH.parent.exists(), "evidence directory must exist after run"

    # Verify specific check names are present
    check_names = {r["check"] for r in results}
    expected_names = {
        "spec_exists",
        "policy_exists",
        "archetypes_defined",
        "time_budget",
        "zero_edit_requirement",
        "event_codes",
        "invariants",
        "telemetry_policy",
        "error_handling_policy",
        "ci_gate_policy",
        "spec_sections",
        "policy_pathway_steps",
        "archetype_scores",
    }
    assert check_names == expected_names, f"check names mismatch: {check_names ^ expected_names}"

    print("self_test passed: all checks return valid structure")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
    else:
        main()
