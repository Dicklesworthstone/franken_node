#!/usr/bin/env python3
"""Audit blocked Beads for fresh first-blocker evidence for bd-8igw1."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


CHECK_BEAD_ID = "bd-8igw1"
TITLE = "Blocked-bead first-blocker freshness audit"
CHECK_SCHEMA_VERSION = "franken-node/blocked-bead-freshness/v1"
DEFAULT_MAX_AGE_HOURS = 168

COMMAND_RE = re.compile(
    r"(Exact command:|command remains|deferred command|rch exec --|br update |cargo |python3 |pytest |FullCapsHandler::)"
)
BLOCKER_RE = re.compile(
    r"(first blocker|current blocker|blocked on|remains blocked|failed|timeout|timed out|Validation failed|E[0-9]{3,}|CapabilityDenied|returns false)",
    re.IGNORECASE,
)
EXTERNAL_HINT_RE = re.compile(
    r"(sibling|cross-repo|/data/projects/|/dp/|franken_engine|frankensqlite|fastapi_rust|worker|remote|RCH)",
    re.IGNORECASE,
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


def _parse_instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _as_issue_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("issues"), list):
        return [item for item in payload["issues"] if isinstance(item, dict)]
    return []


def _comment_texts(issue: dict[str, Any]) -> list[tuple[str, datetime | None]]:
    comments = issue.get("comments")
    rows: list[tuple[str, datetime | None]] = []
    if isinstance(comments, list):
        for comment in comments:
            if not isinstance(comment, dict):
                continue
            text = comment.get("text")
            if isinstance(text, str):
                rows.append((text, _parse_instant(comment.get("created_at"))))
    return rows


def _evidence_text(issue: dict[str, Any]) -> str:
    chunks: list[str] = []
    for key in ("notes", "description"):
        value = issue.get(key)
        if isinstance(value, str):
            chunks.append(value)
    chunks.extend(text for text, _timestamp in _comment_texts(issue))
    return "\n".join(chunks)


def _latest_evidence_time(issue: dict[str, Any]) -> datetime | None:
    candidates = [
        _parse_instant(issue.get("updated_at")),
        _parse_instant(issue.get("created_at")),
    ]
    candidates.extend(timestamp for _text, timestamp in _comment_texts(issue))
    present = [timestamp for timestamp in candidates if timestamp is not None]
    return max(present) if present else None


def audit_issue(issue: dict[str, Any], *, now: datetime, max_age_hours: int) -> dict[str, Any]:
    issue_id = issue.get("id") if isinstance(issue.get("id"), str) else ""
    title = issue.get("title") if isinstance(issue.get("title"), str) else ""
    text = _evidence_text(issue)
    latest = _latest_evidence_time(issue)
    missing: list[str] = []

    if not text.strip():
        missing.append("evidence_text")
    if not COMMAND_RE.search(text):
        missing.append("command_or_symbol")
    if not BLOCKER_RE.search(text):
        missing.append("first_blocker")
    if EXTERNAL_HINT_RE.search(text) and not re.search(r"(/data/projects/|/dp/|franken_engine|frankensqlite|fastapi_rust|worker|remote|RCH)", text, re.IGNORECASE):
        missing.append("external_context")

    age_hours: float | None = None
    stale = False
    if latest is None:
        missing.append("timestamp")
    else:
        age_hours = max(0.0, (now - latest).total_seconds() / 3600.0)
        stale = age_hours > max_age_hours

    if not text.strip():
        classification = "missing_evidence"
    elif missing:
        classification = "incomplete_evidence"
    elif stale:
        classification = "stale"
    else:
        classification = "fresh"

    return {
        "id": issue_id,
        "title": title,
        "classification": classification,
        "missing": missing,
        "latest_evidence_at": latest.isoformat() if latest else None,
        "evidence_age_hours": age_hours,
        "recommended_action": "leave-blocked" if classification == "fresh" else "refresh-blocker",
    }


def run_checks(
    issues_payload: Any,
    *,
    now: datetime | None = None,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
) -> dict[str, Any]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issues = _as_issue_list(issues_payload)
    blocked = [issue for issue in issues if issue.get("status") == "blocked"]
    audits = [audit_issue(issue, now=now, max_age_hours=max_age_hours) for issue in blocked]
    failing = [audit for audit in audits if audit["classification"] != "fresh"]
    checks = [
        _check("input-valid", isinstance(issues_payload, (list, dict)), "items JSON must be list/object"),
        _check("blocked-items-inspected", bool(blocked), "input must include at least one blocked bead"),
        _check("blocked-evidence-fresh", not failing, f"{len(failing)} blocked bead(s) need evidence refresh"),
    ]

    counts: dict[str, int] = {}
    for audit in audits:
        classification = str(audit["classification"])
        counts[classification] = counts.get(classification, 0) + 1

    return {
        "schema_version": CHECK_SCHEMA_VERSION,
        "bead_id": CHECK_BEAD_ID,
        "title": TITLE,
        "verdict": "PASS" if all(check["passed"] for check in checks) else "FAIL",
        "summary": {
            "blocked_count": len(blocked),
            "fresh_count": counts.get("fresh", 0),
            "stale_count": counts.get("stale", 0),
            "incomplete_count": counts.get("incomplete_evidence", 0),
            "missing_count": counts.get("missing_evidence", 0),
            "max_age_hours": max_age_hours,
        },
        "audits": audits,
        "checks": checks,
    }


def _self_test_payload() -> list[dict[str, Any]]:
    return [
        {
            "id": "bd-fresh-rch",
            "title": "Fresh RCH blocker",
            "status": "blocked",
            "updated_at": "2026-06-18T12:00:00Z",
            "notes": (
                "Exact command: rch exec -- cargo clippy -p frankenengine-node. "
                "Current first blocker: [RCH-E104] SSH command timed out on remote worker vmi1152480."
            ),
        },
        {
            "id": "bd-fresh-engine",
            "title": "Fresh engine blocker",
            "status": "blocked",
            "updated_at": "2026-06-18T12:30:00Z",
            "comments": [
                {
                    "created_at": "2026-06-18T12:30:00Z",
                    "text": (
                        "Blocked on sibling /data/projects/franken_engine revision. "
                        "FullCapsHandler::dispatches_real_hostcalls() returns false; "
                        "first blocker remains missing real fs/http producer."
                    ),
                }
            ],
        },
    ]


def _write_fixture(root: Path, payload: Any) -> Path:
    path = root / "blocked-items.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=TITLE)
    parser.add_argument("--items", type=Path, help="JSON file containing Beads issue objects")
    parser.add_argument("--max-age-hours", type=int, default=DEFAULT_MAX_AGE_HOURS)
    parser.add_argument("--now", help="Override current UTC time for deterministic tests")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_test_logging("check_blocked_bead_freshness")
    now = _parse_instant(args.now) if args.now else None
    if args.now and now is None:
        print(f"invalid --now timestamp: {args.now}", file=sys.stderr)
        return 2

    if args.self_test:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_fixture(Path(tmp), _self_test_payload())
            result = run_checks(_load_json(path), now=now or _parse_instant("2026-06-18T13:00:00Z"))
    else:
        if args.items is None:
            print("missing required input: --items", file=sys.stderr)
            return 2
        result = run_checks(_load_json(args.items), now=now, max_age_hours=args.max_age_hours)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{TITLE}: {result['verdict']}")
        print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
