#!/usr/bin/env python3
"""Verification script for bd-34d5: Friction-Minimized Install-to-Production Pathway.

Usage:
    python scripts/check_friction_pathway.py          # human-readable
    python scripts/check_friction_pathway.py --json   # JSON output
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BEAD_ID = "bd-34d5"
SECTION = "section_13"


SPEC_PATH = ROOT / "docs" / "specs" / "section_13" / "bd-34d5_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "friction_minimized_pathway.md"
EVIDENCE_PATH = ROOT / "artifacts" / "section_13" / "bd-34d5" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_13" / "bd-34d5" / "verification_summary.md"
PATHWAY_SENTINEL_PATH = ROOT / "tests" / "e2e" / "install_to_production_pathway.sh"
ONBOARDING_TIMING_REPORT_PATH = ROOT / "artifacts" / "13" / "onboarding_timing_report.json"

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

SETUP_IDS = [
    "macos_npm",
    "linux_npm",
    "windows_npm",
    "docker_container",
    "github_actions_ci",
]


def section_slice(content: str, start_heading: str, end_heading: str | None) -> str | None:
    """Return the markdown section between two headings."""
    try:
        start = content.index(start_heading)
    except ValueError:
        return None
    if end_heading is None:
        return content[start:]
    try:
        end = content.index(end_heading, start)
    except ValueError:
        return None
    return content[start:end]


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
        "Current Shipped Surface",
        "Planned Target Pathway",
        "Archetypes",
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
    """Check that the policy documents the shipped install/init/run surface."""
    if not POLICY_PATH.is_file():
        return {
            "check": "policy_pathway_steps",
            "passed": False,
            "detail": "Policy file missing; cannot check pathway steps",
        }
    content = POLICY_PATH.read_text()
    required_fragments = [
        "https://raw.githubusercontent.com/Dicklesworthstone/franken_node/main/install.sh",
        "franken-node init --profile balanced",
        "franken-node run ./my-app --policy balanced",
    ]
    missing = [fragment for fragment in required_fragments if fragment not in content]
    has_stale_configure = "franken-node configure" in content
    ok = len(missing) == 0 and not has_stale_configure
    detail = "Current shipped install/init/run steps are documented with no stale configure command"
    if missing:
        detail = f"Missing pathway fragments: {missing}"
    elif has_stale_configure:
        detail = "Policy still references stale franken-node configure command"
    return {
        "check": "policy_pathway_steps",
        "passed": ok,
        "detail": detail,
    }


def check_current_surface_reality() -> dict:
    """Check that docs explicitly separate current behavior from target behavior."""
    if not SPEC_PATH.is_file() or not POLICY_PATH.is_file():
        return {
            "check": "current_surface_reality",
            "passed": False,
            "detail": "Spec or policy file missing; cannot check current-surface reality notes",
        }
    spec = SPEC_PATH.read_text()
    policy = POLICY_PATH.read_text()
    spec_current = section_slice(spec, "## Current Shipped Surface", "## Planned Target Pathway")
    spec_target = section_slice(spec, "## Planned Target Pathway", "## Time Budget")
    policy_current = section_slice(
        policy, "## 1. Current Shipped Surface", "## 2. Planned Target Pathway"
    )
    policy_target = section_slice(policy, "## 2. Planned Target Pathway", "## 3. Archetypes")
    if None in (spec_current, spec_target, policy_current, policy_target):
        return {
            "check": "current_surface_reality",
            "passed": False,
            "detail": "Could not isolate current vs target sections in spec/policy",
        }
    combined_current = f"{spec_current}\n{policy_current}"
    required_current_groups = [
        ["prints resolved config to stdout by default"],
        ["raw GitHub `install.sh`"],
        [
            "does **not** currently inspect marker files",
            "does **not** auto-detect archetypes during onboarding",
            "does **not** auto-detect archetypes during `init`",
        ],
        [
            "not emitted by the current CLI",
            "does **not** emit FMP-001 through FMP-004 telemetry events",
            "FMP-001 through FMP-004 pathway telemetry events are **not** emitted",
        ],
        ["franken-node run ./my-app --policy balanced"],
    ]
    missing_current = [
        " / ".join(group)
        for group in required_current_groups
        if not any(fragment in combined_current for fragment in group)
    ]
    target_only_ok = (
        "https://get.frankennode.dev" not in spec_current
        and "https://get.frankennode.dev" not in policy_current
        and "https://get.frankennode.dev" in spec_target
        and "https://get.frankennode.dev" in policy_target
    )
    ok = len(missing_current) == 0 and target_only_ok
    detail = "Docs distinguish current shipped surface from future pathway targets"
    if missing_current:
        detail = f"Missing current-surface reality notes: {missing_current}"
    elif not target_only_ok:
        detail = "Installer alias boundary drifted between current and planned pathway sections"
    return {
        "check": "current_surface_reality",
        "passed": ok,
        "detail": detail,
    }


def check_current_reporting_surface() -> dict:
    """Check that current docs mention the shipped JSON/JSONL reporting flags."""
    if not SPEC_PATH.is_file() or not POLICY_PATH.is_file():
        return {
            "check": "current_reporting_surface",
            "passed": False,
            "detail": "Spec or policy file missing; cannot check current reporting surface",
        }
    spec = SPEC_PATH.read_text()
    policy = POLICY_PATH.read_text()
    spec_current = section_slice(spec, "## Current Shipped Surface", "## Planned Target Pathway")
    policy_current = section_slice(
        policy, "## 1. Current Shipped Surface", "## 2. Planned Target Pathway"
    )
    if None in (spec_current, policy_current):
        return {
            "check": "current_reporting_surface",
            "passed": False,
            "detail": "Could not isolate current sections in spec/policy",
        }
    required = [
        "franken-node init --json",
        "franken-node init --structured-logs-jsonl",
        "franken-node run --json",
        "franken-node run --structured-logs-jsonl",
    ]
    missing = [
        fragment
        for fragment in required
        if fragment not in spec_current and fragment not in policy_current
    ]
    ok = len(missing) == 0
    return {
        "check": "current_reporting_surface",
        "passed": ok,
        "detail": (
            "Current docs enumerate the shipped init/run JSON and JSONL surfaces"
            if ok
            else f"Missing current reporting-surface fragments: {missing}"
        ),
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


def check_named_pathway_artifacts() -> dict:
    """Check that bd-34d5's named completion-debt artifacts exist."""
    required = {
        "tests/e2e/install_to_production_pathway.sh": PATHWAY_SENTINEL_PATH,
        "artifacts/13/onboarding_timing_report.json": ONBOARDING_TIMING_REPORT_PATH,
    }
    missing = [path for path, absolute in required.items() if not absolute.is_file()]
    if missing:
        return {
            "check": "named_pathway_artifacts",
            "passed": False,
            "detail": f"Missing named bd-34d5 artifacts: {missing}",
        }
    shell_text = PATHWAY_SENTINEL_PATH.read_text(encoding="utf-8")
    report_text = ONBOARDING_TIMING_REPORT_PATH.read_text(encoding="utf-8")
    shell_markers = [
        "bd-34d5",
        "current-reality boundary",
        "does not prove the future full target pathway",
    ]
    report_markers = ["target_pathway_shipped", "setup_results", "not_measured_target_unshipped"]
    missing_markers = [
        marker for marker in shell_markers if marker not in shell_text
    ] + [
        marker for marker in report_markers if marker not in report_text
    ]
    ok = not missing_markers
    return {
        "check": "named_pathway_artifacts",
        "passed": ok,
        "detail": (
            "Named shell sentinel and onboarding timing report are present with reality-boundary markers"
            if ok
            else f"Named artifacts missing markers: {missing_markers}"
        ),
    }


def check_onboarding_timing_report() -> dict:
    """Check that the timing report covers all required setups without overclaiming."""
    if not ONBOARDING_TIMING_REPORT_PATH.is_file():
        return {
            "check": "onboarding_timing_report",
            "passed": False,
            "detail": "artifacts/13/onboarding_timing_report.json missing",
        }
    try:
        report = json.JSONDecoder().decode(
            ONBOARDING_TIMING_REPORT_PATH.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return {
            "check": "onboarding_timing_report",
            "passed": False,
            "detail": f"Invalid onboarding timing JSON: {exc}",
        }
    setup_results = report.get("setup_results")
    if not isinstance(setup_results, list):
        return {
            "check": "onboarding_timing_report",
            "passed": False,
            "detail": "onboarding timing report lacks setup_results list",
        }
    setup_by_id = {
        item.get("setup_id"): item
        for item in setup_results
        if isinstance(item, dict)
    }
    missing_setups = [setup for setup in SETUP_IDS if setup not in setup_by_id]
    overclaimed = [
        setup_id
        for setup_id, item in setup_by_id.items()
        if item.get("status") != "not_measured_target_unshipped"
        or item.get("target_total_elapsed_seconds") is not None
    ]
    target_pathway_shipped = report.get("target_pathway_shipped")
    claimed_full_e2e_success = report.get("claimed_full_e2e_success")
    ok = (
        report.get("bead_id") == BEAD_ID
        and isinstance(target_pathway_shipped, bool)
        and not target_pathway_shipped
        and isinstance(claimed_full_e2e_success, bool)
        and not claimed_full_e2e_success
        and not missing_setups
        and not overclaimed
    )
    if ok:
        detail = "Onboarding timing report covers all 5 setups as current-reality, non-overclaiming evidence"
    elif missing_setups:
        detail = f"Onboarding timing report missing setups: {missing_setups}"
    elif overclaimed:
        detail = f"Onboarding timing report overclaims measured target success for: {overclaimed}"
    else:
        detail = "Onboarding timing report bead id or reality flags are incorrect"
    return {
        "check": "onboarding_timing_report",
        "passed": ok,
        "detail": detail,
    }


def check_completion_debt_citations() -> dict:
    """Check that docs cite the named artifacts and their non-overclaiming role."""
    if not SPEC_PATH.is_file() or not POLICY_PATH.is_file():
        return {
            "check": "completion_debt_citations",
            "passed": False,
            "detail": "Spec or policy file missing; cannot check completion-debt citations",
        }
    combined = f"{SPEC_PATH.read_text(encoding='utf-8')}\n{POLICY_PATH.read_text(encoding='utf-8')}"
    required = [
        "tests/e2e/install_to_production_pathway.sh",
        "artifacts/13/onboarding_timing_report.json",
        "target_pathway_shipped=false",
        "must not be cited as full end-to-end success",
    ]
    missing = [fragment for fragment in required if fragment not in combined]
    ok = not missing
    return {
        "check": "completion_debt_citations",
        "passed": ok,
        "detail": (
            "Spec and policy cite the named shell/report artifacts with non-overclaiming boundaries"
            if ok
            else f"Missing completion-debt citation fragments: {missing}"
        ),
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
    check_current_surface_reality,
    check_current_reporting_surface,
    check_archetype_scores,
    check_named_pathway_artifacts,
    check_onboarding_timing_report,
    check_completion_debt_citations,
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
        "# bd-34d5 Verification Summary",
        "",
        f"**Bead:** {BEAD_ID}",
        "**Section:** 13 -- Friction-Minimized Install-to-Production Pathway",
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
    from scripts.lib.test_logger import configure_test_logging

    configure_test_logging("check_friction_pathway")
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
    if not isinstance(results, list):
        raise AssertionError("results must be a list")
    if len(results) != len(ALL_CHECKS):
        raise AssertionError(f"expected {len(ALL_CHECKS)} results, got {len(results)}")
    for r in results:
        if "check" not in r:
            raise AssertionError("each result must have 'check'")
        if "passed" not in r:
            raise AssertionError("each result must have 'passed'")
        if "detail" not in r:
            raise AssertionError("each result must have 'detail'")
        if not isinstance(r["passed"], bool):
            raise AssertionError("'passed' must be bool")
        if not isinstance(r["check"], str):
            raise AssertionError("'check' must be str")
        if not isinstance(r["detail"], str):
            raise AssertionError("'detail' must be str")

    # Verify evidence and summary were written
    if not EVIDENCE_PATH.parent.exists():
        raise AssertionError("evidence directory must exist after run")

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
        "current_surface_reality",
        "current_reporting_surface",
        "archetype_scores",
        "named_pathway_artifacts",
        "onboarding_timing_report",
        "completion_debt_citations",
    }
    if check_names != expected_names:
        raise AssertionError(f"check names mismatch: {check_names ^ expected_names}")

    print("self_test passed: all checks return valid structure")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
    else:
        main()
