#!/usr/bin/env python3
"""Verification script for bd-2ymp: rollout wedge contract field.

Usage:
    python3 scripts/check_rollout_wedge.py          # human-readable
    python3 scripts/check_rollout_wedge.py --json    # machine-readable
    python3 scripts/check_rollout_wedge.py --self-test
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "specs" / "section_11" / "bd-2ymp_contract.md"
POLICY = ROOT / "docs" / "policy" / "rollout_wedge.md"

EVENT_CODES = ["RWG-001", "RWG-002", "RWG-003", "RWG-004"]
INVARIANTS = ["INV-RWG-STAGED", "INV-RWG-OBSERVE", "INV-RWG-BLAST", "INV-RWG-ROLLBACK"]
WEDGE_STATES = ["PENDING", "ACTIVE", "PAUSED", "ROLLED_BACK", "COMPLETE"]
INCREMENT_POLICIES = ["linear", "exponential", "manual"]

SPEC_REQUIRED_FIELDS = [
    "wedge_stages",
    "initial_percentage",
    "increment_policy",
    "max_blast_radius",
    "observation_window_hours",
    "wedge_state",
]

STAGE_REQUIRED_FIELDS = [
    "stage_id",
    "target_percentage",
    "duration_hours",
    "success_criteria",
    "rollback_trigger",
]

THRESHOLDS = [
    "<= 10%",
    ">= 2",
    ">= 1 hour",
    "<= 25%",
    "<= 60 seconds",
]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {"check": name, "pass": bool(passed), "detail": detail or ("found" if passed else "NOT FOUND")}
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    s_path, s_root = str(path), str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_spec_exists() -> None:
    ok = SPEC.exists() and SPEC.is_file()
    _check("file: spec contract", ok,
           f"exists: {_safe_rel(SPEC)}" if ok else f"MISSING: {_safe_rel(SPEC)}")


def check_policy_exists() -> None:
    ok = POLICY.exists() and POLICY.is_file()
    _check("file: policy document", ok,
           f"exists: {_safe_rel(POLICY)}" if ok else f"MISSING: {_safe_rel(POLICY)}")


def check_spec_required_fields() -> None:
    if not SPEC.exists():
        for f in SPEC_REQUIRED_FIELDS:
            _check(f"spec field: {f}", False, "spec missing")
        return
    text = SPEC.read_text()
    for f in SPEC_REQUIRED_FIELDS:
        _check(f"spec field: {f}", f"`{f}`" in text or f"| `{f}`" in text)


def check_spec_stage_fields() -> None:
    if not SPEC.exists():
        for f in STAGE_REQUIRED_FIELDS:
            _check(f"stage field: {f}", False, "spec missing")
        return
    text = SPEC.read_text()
    for f in STAGE_REQUIRED_FIELDS:
        _check(f"stage field: {f}", f"`{f}`" in text or f"| `{f}`" in text)


def check_spec_event_codes() -> None:
    if not SPEC.exists():
        for code in EVENT_CODES:
            _check(f"spec event code: {code}", False, "spec missing")
        return
    text = SPEC.read_text()
    for code in EVENT_CODES:
        _check(f"spec event code: {code}", code in text)


def check_spec_invariants() -> None:
    if not SPEC.exists():
        for inv in INVARIANTS:
            _check(f"spec invariant: {inv}", False, "spec missing")
        return
    text = SPEC.read_text()
    for inv in INVARIANTS:
        _check(f"spec invariant: {inv}", inv in text)


def check_spec_wedge_states() -> None:
    if not SPEC.exists():
        for state in WEDGE_STATES:
            _check(f"spec wedge state: {state}", False, "spec missing")
        return
    text = SPEC.read_text()
    for state in WEDGE_STATES:
        _check(f"spec wedge state: {state}", f"`{state}`" in text)


def check_spec_increment_policies() -> None:
    if not SPEC.exists():
        for pol in INCREMENT_POLICIES:
            _check(f"spec increment policy: {pol}", False, "spec missing")
        return
    text = SPEC.read_text()
    for pol in INCREMENT_POLICIES:
        _check(f"spec increment policy: {pol}", f"`{pol}`" in text)


def check_spec_thresholds() -> None:
    if not SPEC.exists():
        for t in THRESHOLDS:
            _check(f"spec threshold: {t}", False, "spec missing")
        return
    text = SPEC.read_text()
    for t in THRESHOLDS:
        _check(f"spec threshold: {t}", t in text)


def check_spec_validation_rules() -> None:
    if not SPEC.exists():
        _check("spec validation rules section", False, "spec missing")
        return
    text = SPEC.read_text()
    _check("spec validation rules section", "## Validation Rules" in text)


def check_spec_helper_functions() -> None:
    if not SPEC.exists():
        _check("spec helper: validate_rollout_wedge", False, "spec missing")
        _check("spec helper: compute_total_rollout_duration", False, "spec missing")
        return
    text = SPEC.read_text()
    _check("spec helper: validate_rollout_wedge", "validate_rollout_wedge" in text)
    _check("spec helper: compute_total_rollout_duration", "compute_total_rollout_duration" in text)


def check_policy_event_codes() -> None:
    if not POLICY.exists():
        for code in EVENT_CODES:
            _check(f"policy event code: {code}", False, "policy missing")
        return
    text = POLICY.read_text()
    for code in EVENT_CODES:
        _check(f"policy event code: {code}", code in text)


def check_policy_invariants() -> None:
    if not POLICY.exists():
        for inv in INVARIANTS:
            _check(f"policy invariant: {inv}", False, "policy missing")
        return
    text = POLICY.read_text()
    for inv in INVARIANTS:
        _check(f"policy invariant: {inv}", inv in text)


def check_policy_wedge_states() -> None:
    if not POLICY.exists():
        for state in WEDGE_STATES:
            _check(f"policy wedge state: {state}", False, "policy missing")
        return
    text = POLICY.read_text()
    for state in WEDGE_STATES:
        _check(f"policy wedge state: {state}", f"`{state}`" in text)


def check_policy_increment_policies() -> None:
    if not POLICY.exists():
        for pol in INCREMENT_POLICIES:
            _check(f"policy increment policy: {pol}", False, "policy missing")
        return
    text = POLICY.read_text()
    for pol in INCREMENT_POLICIES:
        _check(f"policy increment policy: {pol}", f"`{pol}`" in text)


def check_policy_blast_radius() -> None:
    if not POLICY.exists():
        _check("policy blast radius controls", False, "policy missing")
        return
    text = POLICY.read_text()
    _check("policy blast radius controls", "max_blast_radius" in text and "blast radius" in text.lower())


def check_policy_observation_window() -> None:
    if not POLICY.exists():
        _check("policy observation window", False, "policy missing")
        return
    text = POLICY.read_text()
    _check("policy observation window", "observation_window_hours" in text or "observation window" in text.lower())


def check_policy_governance() -> None:
    if not POLICY.exists():
        _check("policy governance section", False, "policy missing")
        return
    text = POLICY.read_text()
    _check("policy governance section", "## Governance" in text)


def check_policy_appeal_process() -> None:
    if not POLICY.exists():
        _check("policy appeal process", False, "policy missing")
        return
    text = POLICY.read_text()
    _check("policy appeal process", "## Appeal Process" in text or "waiver" in text.lower())


ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_spec_required_fields,
    check_spec_stage_fields,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_wedge_states,
    check_spec_increment_policies,
    check_spec_thresholds,
    check_spec_validation_rules,
    check_spec_helper_functions,
    check_policy_event_codes,
    check_policy_invariants,
    check_policy_wedge_states,
    check_policy_increment_policies,
    check_policy_blast_radius,
    check_policy_observation_window,
    check_policy_governance,
    check_policy_appeal_process,
]


# ---------------------------------------------------------------------------
# Helpers: validate_rollout_wedge, compute_total_rollout_duration
# ---------------------------------------------------------------------------

def validate_rollout_wedge(wedge: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate a rollout wedge dict. Returns (valid, errors)."""
    errors: list[str] = []

    # wedge_stages
    stages = wedge.get("wedge_stages")
    if not isinstance(stages, list) or len(stages) < 2:
        errors.append("wedge_stages must be a list with at least 2 entries")
    else:
        prev_pct = -1
        for i, stage in enumerate(stages):
            if not isinstance(stage, dict):
                errors.append(f"stage {i}: must be a dict")
                continue
            for field in STAGE_REQUIRED_FIELDS:
                if field not in stage:
                    errors.append(f"stage {i}: missing required field '{field}'")
            pct = stage.get("target_percentage", 0)
            if not isinstance(pct, (int, float)) or pct < 0 or pct > 100:
                errors.append(f"stage {i}: target_percentage must be 0-100")
            elif pct <= prev_pct:
                errors.append(f"stage {i}: target_percentage must be monotonically increasing")
            prev_pct = pct
            dur = stage.get("duration_hours", 0)
            if not isinstance(dur, (int, float)) or dur <= 0:
                errors.append(f"stage {i}: duration_hours must be > 0")
            criteria = stage.get("success_criteria")
            if not isinstance(criteria, list) or len(criteria) == 0:
                errors.append(f"stage {i}: success_criteria must be a non-empty list")
            trigger = stage.get("rollback_trigger")
            if not isinstance(trigger, str) or not trigger.strip():
                errors.append(f"stage {i}: rollback_trigger must be a non-empty string")

    # initial_percentage
    init_pct = wedge.get("initial_percentage")
    if not isinstance(init_pct, (int, float)) or init_pct <= 0 or init_pct > 100:
        errors.append("initial_percentage must be > 0 and <= 100")

    # increment_policy
    inc_pol = wedge.get("increment_policy")
    if inc_pol not in INCREMENT_POLICIES:
        errors.append(f"increment_policy must be one of {INCREMENT_POLICIES}")

    # max_blast_radius
    mbr = wedge.get("max_blast_radius")
    if not isinstance(mbr, (int, float)) or mbr <= 0 or mbr > 100:
        errors.append("max_blast_radius must be > 0 and <= 100")

    # observation_window_hours
    owh = wedge.get("observation_window_hours")
    if not isinstance(owh, (int, float)) or owh < 1.0:
        errors.append("observation_window_hours must be >= 1.0")

    # wedge_state
    ws = wedge.get("wedge_state")
    if ws not in WEDGE_STATES:
        errors.append(f"wedge_state must be one of {WEDGE_STATES}")

    return (len(errors) == 0, errors)


def compute_total_rollout_duration(wedge: dict[str, Any]) -> float:
    """Compute total rollout duration: sum(stage.duration_hours) + observation_window_hours * len(stages)."""
    stages = wedge.get("wedge_stages", [])
    owh = wedge.get("observation_window_hours", 0)
    stage_hours = sum(s.get("duration_hours", 0) for s in stages if isinstance(s, dict))
    return stage_hours + owh * len(stages)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all() -> dict[str, Any]:
    global RESULTS
    RESULTS = []
    for fn in ALL_CHECKS:
        fn()
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    return {
        "bead_id": "bd-2ymp",
        "title": "rollout wedge contract field",
        "section": "11",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    report = run_all()
    total, passed, failed = report["total"], report["passed"], report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify bd-2ymp: rollout wedge contract field")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
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
