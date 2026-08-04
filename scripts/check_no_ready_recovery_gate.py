#!/usr/bin/env python3
"""Gate the no-ready recovery package with checked-in fixtures for bd-z1q8l."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts import check_blocked_bead_freshness as blocker_freshness  # noqa: E402
from scripts import check_tracker_actionability as actionability  # noqa: E402
from scripts import normalize_rch_evidence as rch_evidence  # noqa: E402
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


CHECK_BEAD_ID = "bd-z1q8l"
TITLE = "No-ready recovery fixture gate"
SCHEMA_VERSION = "franken-node/no-ready-recovery-gate/v1"
DEFAULT_FIXTURE = ROOT / "artifacts" / "validation_broker" / CHECK_BEAD_ID / "no_ready_recovery_fixtures.v1.json"
JSON_DECODER = json.JSONDecoder()


def _check(check: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {
        "check": check,
        "passed": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }


def _expect_equal(check: str, actual: Any, expected: Any) -> dict[str, Any]:
    passed = actual == expected
    return _check(check, passed, "" if passed else f"{actual} != {expected}")


def _load_json(path: Path) -> Any:
    return JSON_DECODER.decode(path.read_text(encoding="utf-8"))


def _parse_instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _classification_by_id(actionability_result: dict[str, Any]) -> dict[str, str]:
    return {
        item["id"]: item["classification"]
        for item in actionability_result.get("classifications", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str) and isinstance(item.get("classification"), str)
    }


def _rch_by_id(rch_result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        record["sample_id"]: record
        for record in rch_result.get("records", [])
        if isinstance(record, dict) and isinstance(record.get("sample_id"), str)
    }


def _validate_handoff(handoff: Any, expected_action: str) -> list[dict[str, Any]]:
    if not isinstance(handoff, dict):
        return [_check("runbook-handoff-object", False, "runbook_handoff must be an object")]
    checks = [
        _check("handoff-ready-count", isinstance(handoff.get("ready_count"), int)),
        _check(
            "handoff-active-agents",
            isinstance(handoff.get("active_agents"), list)
            and all(isinstance(agent, str) and agent for agent in handoff.get("active_agents", [])),
        ),
        _check("handoff-exact-blockers", isinstance(handoff.get("exact_blockers"), list)),
        _expect_equal("handoff-next-action", handoff.get("next_action"), expected_action),
    ]
    blockers = handoff.get("exact_blockers")
    if isinstance(blockers, list):
        for index, blocker in enumerate(blockers):
            checks.append(
                _check(
                    f"handoff-blocker:{index}",
                    isinstance(blocker, dict)
                    and all(isinstance(blocker.get(field), str) and blocker.get(field) for field in ("bead_id", "command", "first_blocker")),
                    "" if isinstance(blocker, dict) else "blocker must be an object",
                )
            )
    return checks


def _final_decision(
    actionability_result: dict[str, Any],
    freshness_result: dict[str, Any],
) -> str:
    recommended = actionability_result.get("summary", {}).get("recommended_next_action")
    if recommended == "claim":
        return "claim"
    if freshness_result.get("verdict") != "PASS":
        return "refresh-blocker"
    if recommended == "create-new-bead":
        return "create-new-bead"
    return "coordinate"


def evaluate_scenario(scenario: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    scenario_id = str(scenario.get("id", "unknown"))
    expected = scenario.get("expected") if isinstance(scenario.get("expected"), dict) else {}

    actionability_result = actionability.run_checks(
        scenario.get("ready", []),
        scenario.get("bv_plan", {}),
        scenario.get("issues", []),
        expected_agent="NavyTurtle",
    )
    freshness_result = blocker_freshness.run_checks(
        scenario.get("blocked_items", []),
        now=now,
        max_age_hours=168,
    )
    rch_records = [
        rch_evidence.normalize_text(str(snippet.get("text", "")), sample_id=str(snippet.get("sample_id", "unknown")))
        for snippet in scenario.get("rch_snippets", [])
        if isinstance(snippet, dict)
    ]
    rch_result = rch_evidence.run_checks(rch_records)

    final_decision = _final_decision(actionability_result, freshness_result)
    actionability_classes = _classification_by_id(actionability_result)
    rch_records_by_id = _rch_by_id(rch_result)
    expected_actionability = expected.get("actionability") if isinstance(expected.get("actionability"), dict) else {}
    expected_rch = expected.get("rch") if isinstance(expected.get("rch"), dict) else {}
    expected_final = expected.get("final_decision")

    checks = [
        _expect_equal("actionability-verdict", actionability_result.get("verdict"), "PASS"),
        _expect_equal("blocker-freshness-verdict", freshness_result.get("verdict"), "PASS"),
        _expect_equal("rch-normalizer-verdict", rch_result.get("verdict"), "PASS"),
        _expect_equal("final-decision", final_decision, expected_final),
    ]

    for issue_id, expected_class in expected_actionability.items():
        checks.append(
            _expect_equal(
                f"actionability-class:{issue_id}",
                actionability_classes.get(issue_id),
                expected_class,
            )
        )

    for sample_id, expectation in expected_rch.items():
        record = rch_records_by_id.get(sample_id)
        expected_class = expectation.get("classification") if isinstance(expectation, dict) else None
        expected_blocker = expectation.get("first_blocker") if isinstance(expectation, dict) else None
        checks.append(
            _expect_equal(
                f"rch-class:{sample_id}",
                record.get("classification") if isinstance(record, dict) else None,
                expected_class,
            )
        )
        checks.append(
            _expect_equal(
                f"rch-first-blocker:{sample_id}",
                record.get("first_blocker") if isinstance(record, dict) else None,
                expected_blocker,
            )
        )

    checks.extend(_validate_handoff(scenario.get("runbook_handoff"), str(expected_final)))

    if expected_final != "claim":
        checks.append(_check("no-ready-does-not-claim", final_decision != "claim", final_decision))

    return {
        "scenario_id": scenario_id,
        "verdict": "PASS" if all(check["passed"] for check in checks) else "FAIL",
        "final_decision": final_decision,
        "trace": {
            "ready_count": len(scenario.get("ready", [])) if isinstance(scenario.get("ready"), list) else 0,
            "actionability_recommendation": actionability_result.get("summary", {}).get("recommended_next_action"),
            "actionability_classes": actionability_classes,
            "blocker_freshness_verdict": freshness_result.get("verdict"),
            "rch_classes": {
                sample_id: record.get("classification")
                for sample_id, record in rch_records_by_id.items()
            },
            "runbook_next_action": scenario.get("runbook_handoff", {}).get("next_action")
            if isinstance(scenario.get("runbook_handoff"), dict)
            else None,
        },
        "checks": checks,
    }


def run_gate(fixture_payload: Any) -> dict[str, Any]:
    if not isinstance(fixture_payload, dict):
        return {
            "schema_version": SCHEMA_VERSION,
            "bead_id": CHECK_BEAD_ID,
            "title": TITLE,
            "verdict": "FAIL",
            "summary": {"scenario_count": 0, "passing": 0, "failing": 1},
            "scenarios": [],
            "checks": [_check("fixture-object", False, "fixture root must be an object")],
        }

    now_raw = fixture_payload.get("now")
    now = _parse_instant(now_raw if isinstance(now_raw, str) else "2026-06-18T15:00:00Z")
    scenarios = [
        item
        for item in fixture_payload.get("scenarios", [])
        if isinstance(item, dict)
    ]
    scenario_results = [evaluate_scenario(scenario, now=now) for scenario in scenarios]
    checks = [
        _check("fixture-schema", fixture_payload.get("schema_version") == "franken-node/no-ready-recovery-fixtures/v1"),
        _check("scenarios-present", bool(scenarios), "at least one scenario required"),
    ]
    for scenario in scenario_results:
        for check in scenario["checks"]:
            checks.append(_check(f"{scenario['scenario_id']}:{check['check']}", bool(check["passed"]), str(check["detail"])))

    passing = sum(1 for scenario in scenario_results if scenario["verdict"] == "PASS")
    failing = len(scenario_results) - passing
    return {
        "schema_version": SCHEMA_VERSION,
        "bead_id": CHECK_BEAD_ID,
        "title": TITLE,
        "verdict": "PASS" if all(check["passed"] for check in checks) else "FAIL",
        "summary": {
            "scenario_count": len(scenario_results),
            "passing": passing,
            "failing": failing,
            "final_decisions": {
                scenario["scenario_id"]: scenario["final_decision"]
                for scenario in scenario_results
            },
        },
        "scenarios": scenario_results,
        "checks": checks,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=TITLE)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_test_logging("check_no_ready_recovery_gate")
    result = run_gate(_load_json(args.fixture))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{TITLE}: {result['verdict']}")
        for scenario in result["scenarios"]:
            print(f"- {scenario['scenario_id']}: {scenario['verdict']} -> {scenario['final_decision']}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
