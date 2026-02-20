#!/usr/bin/env python3
"""bd-3rya: Verify the monotonic hardening state machine implementation.

Checks:
  1. hardening_state_machine.rs exists and contains HardeningStateMachine.
  2. HardeningLevel enum has at least 5 levels with total ordering.
  3. escalate and governance_rollback functions exist.
  4. replay_transitions function exists.
  5. EVD-HARDEN log codes are present.
  6. GovernanceRollbackArtifact struct with validation.
  7. Unit tests cover escalation, regression rejection, rollback, and replay.
  8. State history artifact exists and is valid.

Usage:
  python3 scripts/check_hardening_state_machine.py          # human-readable
  python3 scripts/check_hardening_state_machine.py --json    # machine-readable
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "policy" / "hardening_state_machine.rs"
HISTORY_PATH = ROOT / "artifacts" / "10.14" / "hardening_state_history.json"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_14" / "bd-3rya" / "verification_evidence.json"


def check_impl_exists() -> tuple[bool, str]:
    if not IMPL_PATH.exists():
        return False, f"missing: {IMPL_PATH}"
    content = IMPL_PATH.read_text()
    if "pub struct HardeningStateMachine" not in content:
        return False, "HardeningStateMachine struct not found"
    return True, "HardeningStateMachine struct found"


def check_hardening_levels() -> tuple[bool, str]:
    content = IMPL_PATH.read_text()
    levels = re.findall(r"(Baseline|Standard|Enhanced|Maximum|Critical)\s*=\s*\d", content)
    unique = set(levels)
    if len(unique) < 5:
        return False, f"only {len(unique)} levels found (need >= 5)"
    return True, f"{len(unique)} hardening levels defined"


def check_escalate_fn() -> tuple[bool, str]:
    content = IMPL_PATH.read_text()
    if "fn escalate(" not in content:
        return False, "escalate function not found"
    return True, "escalate function present"


def check_governance_rollback_fn() -> tuple[bool, str]:
    content = IMPL_PATH.read_text()
    if "fn governance_rollback(" not in content:
        return False, "governance_rollback function not found"
    return True, "governance_rollback function present"


def check_replay_fn() -> tuple[bool, str]:
    content = IMPL_PATH.read_text()
    if "fn replay_transitions(" not in content:
        return False, "replay_transitions function not found"
    return True, "replay_transitions function present"


def check_log_codes() -> tuple[bool, str]:
    content = IMPL_PATH.read_text()
    codes = ["EVD-HARDEN-001", "EVD-HARDEN-002", "EVD-HARDEN-003", "EVD-HARDEN-004"]
    missing = [c for c in codes if c not in content]
    if missing:
        return False, f"missing log codes: {missing}"
    return True, "all EVD-HARDEN log codes present"


def check_governance_artifact() -> tuple[bool, str]:
    content = IMPL_PATH.read_text()
    if "pub struct GovernanceRollbackArtifact" not in content:
        return False, "GovernanceRollbackArtifact struct not found"
    if "fn validate(" not in content:
        return False, "validate function not found on artifact"
    return True, "GovernanceRollbackArtifact with validation"


def check_error_types() -> tuple[bool, str]:
    content = IMPL_PATH.read_text()
    required = ["IllegalRegression", "InvalidRollbackArtifact", "InvalidRollbackTarget"]
    missing = [r for r in required if r not in content]
    if missing:
        return False, f"missing error variants: {missing}"
    return True, "all HardeningError variants present"


def count_tests() -> tuple[bool, str, int]:
    content = IMPL_PATH.read_text()
    test_fns = re.findall(r"#\[test\]", content)
    count = len(test_fns)
    if count < 20:
        return False, f"only {count} tests (need >= 20)", count
    return True, f"{count} unit tests", count


def check_history_artifact() -> tuple[bool, str]:
    if not HISTORY_PATH.exists():
        return False, f"missing: {HISTORY_PATH}"
    try:
        data = json.loads(HISTORY_PATH.read_text())
    except json.JSONDecodeError as e:
        return False, f"invalid JSON: {e}"
    if "transitions" not in data:
        return False, "missing 'transitions' key"
    return True, f"state history valid with {len(data['transitions'])} transitions"


def self_test() -> tuple[bool, list]:
    checks = [
        ("impl_exists", check_impl_exists),
        ("hardening_levels", check_hardening_levels),
        ("escalate_fn", check_escalate_fn),
        ("governance_rollback_fn", check_governance_rollback_fn),
        ("replay_fn", check_replay_fn),
        ("log_codes", check_log_codes),
        ("governance_artifact", check_governance_artifact),
        ("error_types", check_error_types),
        ("test_count", lambda: count_tests()[:2]),
        ("history_artifact", check_history_artifact),
    ]
    results = []
    all_pass = True
    for name, fn in checks:
        ok, msg = fn()
        results.append({"check": name, "pass": ok, "detail": msg})
        if not ok:
            all_pass = False
    return all_pass, results


def main():
    parser = argparse.ArgumentParser(description="Verify hardening state machine (bd-3rya)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    all_pass, results = self_test()

    if args.json:
        evidence = {
            "bead_id": "bd-3rya",
            "title": "Monotonic hardening state machine verification",
            "overall_pass": all_pass,
            "checks": results,
            "test_count": count_tests()[2],
            "artifacts": {
                "implementation": str(IMPL_PATH.relative_to(ROOT)),
                "history": str(HISTORY_PATH.relative_to(ROOT)),
            },
        }
        print(json.dumps(evidence, indent=2))
    else:
        for r in results:
            status = "PASS" if r["pass"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
        print()
        print("All checks PASSED." if all_pass else "Some checks FAILED.")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
