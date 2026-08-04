#!/usr/bin/env python3
"""Classify Beads/BV recommendations by real claimability for bd-bc679."""

from __future__ import annotations

import argparse
import hmac
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


CHECK_BEAD_ID = "bd-bc679"
TITLE = "Tracker actionability claimability checker"
CHECK_SCHEMA_VERSION = "franken-node/tracker-actionability/v1"
BLOCKING_DEP_TYPES = {"blocks", "parent-child"}
EXTERNAL_BLOCKER_HINTS = (
    "rch",
    "remote",
    "sibling",
    "cross-repo",
    "franken_engine",
    "frankensqlite",
    "fastapi_rust",
    "worker",
    "timeout",
    "ssh",
)
JSON_DECODER = json.JSONDecoder()


def _check(check: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {
        "check": check,
        "passed": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }


def _load_json(path: Path) -> Any:
    return JSON_DECODER.decode(path.read_text(encoding="utf-8"))


def _as_issue_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("issues"), list):
        return [item for item in payload["issues"] if isinstance(item, dict)]
    return []


def _bv_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    plan = payload.get("plan")
    if isinstance(plan, dict) and isinstance(plan.get("tracks"), list):
        items: list[dict[str, Any]] = []
        for track in plan["tracks"]:
            if not isinstance(track, dict) or not isinstance(track.get("items"), list):
                continue
            items.extend(item for item in track["items"] if isinstance(item, dict))
        return items
    if isinstance(payload.get("items"), list):
        return [item for item in payload["items"] if isinstance(item, dict)]
    return []


def _issue_id(issue: dict[str, Any]) -> str:
    value = issue.get("id") or issue.get("issue_id")
    return value if isinstance(value, str) else ""


def _text_blob(issue: dict[str, Any]) -> str:
    chunks: list[str] = []
    for key in ("title", "description", "notes", "status", "issue_type", "assignee"):
        value = issue.get(key)
        if isinstance(value, str):
            chunks.append(value)
    for label in issue.get("labels") or []:
        if isinstance(label, str):
            chunks.append(label)
    for comment in issue.get("comments") or []:
        if isinstance(comment, dict) and isinstance(comment.get("text"), str):
            chunks.append(comment["text"])
    return "\n".join(chunks).lower()


def _external_blocker(issue: dict[str, Any]) -> bool:
    blob = _text_blob(issue)
    return any(hint in blob for hint in EXTERNAL_BLOCKER_HINTS)


def _blocking_dependencies(issue: dict[str, Any]) -> list[dict[str, Any]]:
    dependencies = issue.get("dependencies")
    if not isinstance(dependencies, list):
        return []
    blockers: list[dict[str, Any]] = []
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        dep_type = dep.get("dependency_type") or dep.get("type")
        dep_status = dep.get("status")
        if dep_type in BLOCKING_DEP_TYPES and dep_status != "closed" and dep_status != "completed":
            blockers.append(dep)
    return blockers


def classify_item(
    bv_item: dict[str, Any],
    *,
    ready_ids: set[str],
    issues_by_id: dict[str, dict[str, Any]],
    expected_agent: str | None,
) -> dict[str, Any]:
    item_id = _issue_id(bv_item)
    issue = dict(issues_by_id.get(item_id, {}))
    merged = {**bv_item, **issue}
    issue_id = item_id or _issue_id(merged)

    if not issue_id:
        return {
            "id": "",
            "title": merged.get("title", ""),
            "classification": "needs_manual_review",
            "recommended_action": "coordinate",
            "reason": "BV item is missing an issue id",
            "blockers": [],
        }

    title = merged.get("title") if isinstance(merged.get("title"), str) else ""
    status = merged.get("status") if isinstance(merged.get("status"), str) else ""
    issue_type = merged.get("issue_type") if isinstance(merged.get("issue_type"), str) else ""
    assignee = merged.get("assignee") if isinstance(merged.get("assignee"), str) else None
    blockers = _blocking_dependencies(merged)

    if issue_id in ready_ids:
        return {
            "id": issue_id,
            "title": title,
            "classification": "claimable",
            "recommended_action": "claim",
            "reason": "Issue is present in br ready output",
            "blockers": [],
        }

    if status == "blocked":
        classification = "external_blocker" if _external_blocker(merged) else "blocked"
        return {
            "id": issue_id,
            "title": title,
            "classification": classification,
            "recommended_action": "refresh-blocker" if classification == "external_blocker" else "wait",
            "reason": "Issue status is blocked",
            "blockers": [],
        }

    if assignee and expected_agent and not hmac.compare_digest(assignee, expected_agent):
        return {
            "id": issue_id,
            "title": title,
            "classification": "assigned_elsewhere",
            "recommended_action": "coordinate",
            "reason": f"Issue is assigned to {assignee}",
            "blockers": [],
        }

    if issue_type == "epic":
        return {
            "id": issue_id,
            "title": title,
            "classification": "parent_epic",
            "recommended_action": "create-new-bead",
            "reason": "BV surfaced a parent epic rather than a concrete implementation task",
            "blockers": [],
        }

    if blockers:
        return {
            "id": issue_id,
            "title": title,
            "classification": "blocked",
            "recommended_action": "refresh-blocker",
            "reason": "Issue has unresolved blocking dependencies",
            "blockers": [
                {
                    "id": dep.get("id") or dep.get("depends_on_id"),
                    "title": dep.get("title", ""),
                    "status": dep.get("status", ""),
                    "dependency_type": dep.get("dependency_type") or dep.get("type"),
                }
                for dep in blockers
            ],
        }

    return {
        "id": issue_id,
        "title": title,
        "classification": "needs_manual_review",
        "recommended_action": "coordinate",
        "reason": "BV item is not ready, blocked, assigned, or a parent epic from the supplied evidence",
        "blockers": [],
    }


def run_checks(
    ready_payload: Any,
    bv_plan_payload: Any,
    issue_payload: Any,
    *,
    expected_agent: str | None = None,
) -> dict[str, Any]:
    ready_items = _as_issue_list(ready_payload)
    bv_items = _bv_items(bv_plan_payload)
    issue_items = _as_issue_list(issue_payload)

    ready_ids = {_issue_id(issue) for issue in ready_items if _issue_id(issue)}
    issues_by_id = {_issue_id(issue): issue for issue in issue_items if _issue_id(issue)}
    classifications = [
        classify_item(item, ready_ids=ready_ids, issues_by_id=issues_by_id, expected_agent=expected_agent)
        for item in bv_items
    ]

    claimable_count = sum(1 for item in classifications if item["classification"] == "claimable")
    no_ready_recovery = len(ready_ids) == 0 and claimable_count == 0
    checks = [
        _check("ready-input-valid", isinstance(ready_payload, (list, dict)), "ready JSON must be list/object"),
        _check("bv-input-has-items", bool(bv_items), "BV plan must contain at least one item"),
        _check("classifications-produced", len(classifications) == len(bv_items)),
    ]

    recommendation = "claim" if claimable_count else "create-new-bead" if no_ready_recovery else "coordinate"
    result = {
        "schema_version": CHECK_SCHEMA_VERSION,
        "bead_id": CHECK_BEAD_ID,
        "title": TITLE,
        "verdict": "PASS" if all(check["passed"] for check in checks) else "FAIL",
        "summary": {
            "ready_count": len(ready_ids),
            "bv_item_count": len(bv_items),
            "claimable_count": claimable_count,
            "no_ready_recovery": no_ready_recovery,
            "recommended_next_action": recommendation,
        },
        "classifications": classifications,
        "checks": checks,
    }
    return result


def _self_test_payloads() -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    ready: list[dict[str, Any]] = []
    bv_plan = {
        "plan": {
            "tracks": [
                {
                    "track_id": "track-A",
                    "items": [
                        {"id": "bd-f5b04.2", "title": "Phase 1", "status": "open"},
                        {"id": "bd-f5b04.2.6", "title": "Engine-boundary coordination", "status": "blocked"},
                        {"id": "bd-famte", "title": "RCH validation proof", "status": "blocked"},
                        {"id": "bd-other-agent", "title": "Assigned elsewhere", "status": "open"},
                        {"id": "bd-child", "title": "Child blocked by parent", "status": "open"},
                    ],
                }
            ]
        }
    }
    issues = [
        {"id": "bd-f5b04.2", "title": "Phase 1", "status": "open", "issue_type": "epic"},
        {
            "id": "bd-f5b04.2.6",
            "title": "Engine-boundary coordination",
            "status": "blocked",
            "issue_type": "task",
            "notes": "blocked on sibling franken_engine real hostcall producer revision",
        },
        {
            "id": "bd-famte",
            "title": "RCH validation proof",
            "status": "blocked",
            "issue_type": "bug",
            "labels": ["rch", "validation"],
            "notes": "Current first blocker: [RCH-E104] SSH command timed out",
        },
        {
            "id": "bd-other-agent",
            "title": "Assigned elsewhere",
            "status": "open",
            "issue_type": "task",
            "assignee": "OtherAgent",
        },
        {
            "id": "bd-child",
            "title": "Child blocked by parent",
            "status": "open",
            "issue_type": "task",
            "dependencies": [
                {
                    "id": "bd-parent",
                    "title": "Parent",
                    "status": "open",
                    "dependency_type": "parent-child",
                }
            ],
        },
    ]
    return ready, bv_plan, issues


def _write_fixture(root: Path, name: str, payload: Any) -> Path:
    path = root / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=TITLE)
    parser.add_argument("--ready", type=Path, help="JSON file from br ready --json")
    parser.add_argument("--bv-plan", type=Path, help="JSON file from bv --recipe actionable --robot-plan")
    parser.add_argument("--items", type=Path, help="JSON file containing br show/list issue details")
    parser.add_argument("--expected-agent", default=None)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_test_logging("check_tracker_actionability")

    if args.self_test:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ready, bv_plan, issues = _self_test_payloads()
            ready_path = _write_fixture(root, "ready.json", ready)
            bv_path = _write_fixture(root, "bv-plan.json", bv_plan)
            items_path = _write_fixture(root, "items.json", issues)
            result = run_checks(
                _load_json(ready_path),
                _load_json(bv_path),
                _load_json(items_path),
                expected_agent=args.expected_agent or "NavyTurtle",
            )
    else:
        missing = [name for name, path in (("ready", args.ready), ("bv-plan", args.bv_plan), ("items", args.items)) if path is None]
        if missing:
            print(f"missing required inputs: {', '.join(missing)}", file=sys.stderr)
            return 2
        result = run_checks(
            _load_json(args.ready),
            _load_json(args.bv_plan),
            _load_json(args.items),
            expected_agent=args.expected_agent,
        )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{TITLE}: {result['verdict']}")
        print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
