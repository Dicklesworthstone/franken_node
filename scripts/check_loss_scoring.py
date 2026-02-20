#!/usr/bin/env python3
"""Verification script for bd-33b expected-loss scoring."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS: list[dict[str, str]] = []
EPSILON = 1e-9
DEFAULT_DELTA = 0.05


def check(check_id: str, description: str, passed: bool, details: str | None = None) -> bool:
    entry: dict[str, str] = {
        "id": check_id,
        "description": description,
        "status": "PASS" if passed else "FAIL",
    }
    if details:
        entry["details"] = details
    CHECKS.append(entry)

    status = entry["status"]
    print(f"  [{status}] {check_id}: {description}")
    if details:
        print(f"         {details}")
    return passed


def validate_probabilities(probabilities: list[float], expected_len: int) -> None:
    if len(probabilities) != expected_len:
        raise ValueError("probability length mismatch")
    if any((p < 0.0 or p > 1.0) for p in probabilities):
        raise ValueError("probabilities must be in [0,1]")
    if any(not isinstance(p, (int, float)) for p in probabilities):
        raise ValueError("probabilities must be numeric")
    total = sum(probabilities)
    if abs(total - 1.0) > EPSILON:
        raise ValueError(f"probabilities must sum to 1.0, got {total}")


def score_action(
    action: str,
    actions: list[str],
    outcomes: list[str],
    matrix: list[list[float]],
    probabilities: list[float],
) -> dict[str, Any]:
    validate_probabilities(probabilities, len(outcomes))
    if action not in actions:
        raise ValueError(f"unknown action: {action}")
    row = matrix[actions.index(action)]
    if len(row) != len(outcomes):
        raise ValueError("matrix row width mismatch")

    breakdown: list[dict[str, float | str]] = []
    expected_loss = 0.0
    dominant = ("", float("-inf"))
    for outcome, loss_value, probability in zip(outcomes, row, probabilities):
        contribution = loss_value * probability
        expected_loss += contribution
        breakdown.append({"outcome": outcome, "contribution": contribution})
        if contribution > dominant[1]:
            dominant = (outcome, contribution)

    return {
        "action": action,
        "expected_loss": expected_loss,
        "dominant_outcome": dominant[0],
        "breakdown": breakdown,
    }


def compare_actions(
    action_names: list[str],
    actions: list[str],
    outcomes: list[str],
    matrix: list[list[float]],
    probabilities: list[float],
) -> list[dict[str, Any]]:
    if not action_names:
        raise ValueError("no actions requested")
    scored = [
        score_action(action, actions, outcomes, matrix, probabilities)
        for action in action_names
    ]
    scored.sort(key=lambda item: (item["expected_loss"], item["action"]))
    return scored


def _perturb_probabilities(
    base: list[float], index: int, delta: float
) -> list[float] | None:
    if len(base) <= 1:
        return [1.0] if abs(base[0] + delta - 1.0) <= EPSILON else None

    target = base[index] + delta
    if target < 0.0 or target > 1.0:
        return None

    updated = list(base)
    old_rest = 1.0 - base[index]
    new_rest = 1.0 - target
    updated[index] = target

    if abs(old_rest) <= EPSILON:
        share = new_rest / (len(base) - 1)
        for i in range(len(updated)):
            if i != index:
                updated[i] = share
    else:
        for i in range(len(updated)):
            if i != index:
                updated[i] = (base[i] / old_rest) * new_rest

    if any((p < 0.0 or p > 1.0) for p in updated):
        return None
    total = sum(updated)
    if total <= 0.0:
        return None
    normalized = [p / total for p in updated]
    return normalized


def sensitivity_analysis(
    action_names: list[str],
    actions: list[str],
    outcomes: list[str],
    matrix: list[list[float]],
    probabilities: list[float],
    delta: float = DEFAULT_DELTA,
) -> list[dict[str, Any]]:
    if delta <= 0.0:
        raise ValueError("delta must be > 0")

    baseline = compare_actions(action_names, actions, outcomes, matrix, probabilities)
    baseline_rank = {item["action"]: i + 1 for i, item in enumerate(baseline)}
    records: list[dict[str, Any]] = []

    for idx, outcome in enumerate(outcomes):
        for signed_delta in (delta, -delta):
            perturbed = _perturb_probabilities(probabilities, idx, signed_delta)
            if perturbed is None:
                continue
            ranked = compare_actions(action_names, actions, outcomes, matrix, perturbed)
            perturbed_rank = {item["action"]: i + 1 for i, item in enumerate(ranked)}
            for action in action_names:
                original_rank = baseline_rank[action]
                new_rank = perturbed_rank[action]
                if original_rank != new_rank:
                    records.append(
                        {
                            "action": action,
                            "parameter_name": outcome,
                            "delta": signed_delta,
                            "original_rank": original_rank,
                            "perturbed_rank": new_rank,
                        }
                    )

    records.sort(
        key=lambda row: (
            row["parameter_name"],
            -row["delta"],
            row["action"],
            row["original_rank"],
            row["perturbed_rank"],
        )
    )
    return records


def build_reference_matrix() -> tuple[list[str], list[str], list[list[float]], list[float]]:
    actions = ["do_nothing", "throttle", "quarantine", "rebuild"]
    outcomes = ["benign", "contained", "spread", "catastrophic", "compliance_penalty"]
    matrix = [
        [1.0, 5.0, 40.0, 90.0, 30.0],
        [2.0, 3.0, 20.0, 60.0, 15.0],
        [5.0, 2.0, 8.0, 20.0, 5.0],
        [12.0, 4.0, 6.0, 10.0, 3.0],
    ]
    probabilities = [0.5, 0.2, 0.15, 0.1, 0.05]
    return actions, outcomes, matrix, probabilities


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    actions, outcomes, matrix, probs = build_reference_matrix()
    ranked = compare_actions(actions, actions, outcomes, matrix, probs)
    checks.append(
        {
            "id": "SELF-RANKING",
            "status": "PASS" if ranked[0]["action"] == "quarantine" else "FAIL",
            "details": f"best_action={ranked[0]['action']}",
        }
    )

    deg_actions = ["do_nothing"]
    deg_outcomes = ["single"]
    deg_matrix = [[2.5]]
    deg_probs = [1.0]
    deg_scored = score_action("do_nothing", deg_actions, deg_outcomes, deg_matrix, deg_probs)
    checks.append(
        {
            "id": "SELF-DEGENERATE",
            "status": "PASS"
            if abs(deg_scored["expected_loss"] - 2.5) <= EPSILON
            else "FAIL",
            "details": f"expected_loss={deg_scored['expected_loss']}",
        }
    )

    sensitivity_actions = ["do_nothing", "monitor", "block"]
    sensitivity_outcomes = ["false_alarm", "active_attack"]
    sensitivity_matrix = [[1.0, 100.0], [5.0, 60.0], [20.0, 20.0]]
    sensitivity_probs = [0.8, 0.2]
    records = sensitivity_analysis(
        sensitivity_actions,
        sensitivity_actions,
        sensitivity_outcomes,
        sensitivity_matrix,
        sensitivity_probs,
        delta=0.3,
    )
    checks.append(
        {
            "id": "SELF-SENSITIVITY",
            "status": "PASS" if len(records) > 0 else "FAIL",
            "details": f"records={len(records)}",
        }
    )

    failing = [item for item in checks if item["status"] == "FAIL"]
    return {
        "verdict": "PASS" if not failing else "FAIL",
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable evidence JSON to stdout",
    )
    args = parser.parse_args()

    print("bd-33b: Expected-loss scoring verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/execution_scorer.rs")
    impl_exists = os.path.isfile(impl_path)
    impl_content = open(impl_path).read() if impl_exists else ""
    required_symbols = [
        "struct LossMatrix",
        "struct ExpectedLossScore",
        "struct SensitivityRecord",
        "fn score_action",
        "fn compare_actions",
        "fn sensitivity_analysis",
        "schema_version",
    ]
    all_pass &= check(
        "ELS-IMPL",
        "Rust implementation exposes required expected-loss scoring symbols",
        impl_exists and all(symbol in impl_content for symbol in required_symbols),
    )

    spec_path = os.path.join(ROOT, "docs/specs/section_10_5/bd-33b_contract.md")
    spec_exists = os.path.isfile(spec_path)
    spec_content = open(spec_path).read() if spec_exists else ""
    spec_markers = [
        "INV-ELS-MATRIX-EXPLICIT",
        "INV-ELS-PROBABILITY-VALID",
        "INV-ELS-DETERMINISTIC",
        "INV-ELS-SENSITIVITY",
    ]
    all_pass &= check(
        "ELS-SPEC",
        "Spec contract exists with expected invariants",
        spec_exists and all(marker in spec_content for marker in spec_markers),
    )

    script_tests_path = os.path.join(ROOT, "tests/test_check_loss_scoring.py")
    all_pass &= check(
        "ELS-TESTS",
        "Python verification test file exists",
        os.path.isfile(script_tests_path),
    )

    self_test_result = self_test()
    all_pass &= check(
        "ELS-SELFTEST",
        "Verification self-test scenarios pass",
        self_test_result["verdict"] == "PASS",
        f"{self_test_result['summary']['passing_checks']}/{self_test_result['summary']['total_checks']} checks",
    )

    passing = sum(1 for item in CHECKS if item["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "expected_loss_scoring_verification",
        "bead": "bd-33b",
        "section": "10.5",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "self_test": self_test_result,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": total - passing,
        },
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_5/bd-33b")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as handle:
        json.dump(evidence, handle, indent=2)
        handle.write("\n")

    if args.json:
        print(json.dumps(evidence, indent=2))

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
