#!/usr/bin/env python3
"""Normalize RCH proof evidence snippets for bd-cucoo."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


CHECK_BEAD_ID = "bd-cucoo"
TITLE = "RCH evidence normalizer"
SCHEMA_VERSION = "franken-node/rch-evidence-normalizer/v1"
JSON_DECODER = json.JSONDecoder()

COMMAND_RE = re.compile(r"(?im)^\s*(?:Exact command|Command|Deferred command):\s*(?P<command>.+?)\s*$")
WORKER_RE = re.compile(r"\b(?P<worker>vmi[0-9]+|ts[0-9]+)\b")
JOB_RE = re.compile(r"(?i)\b(?:job|build|build_id|job_id)[ =:#-]*(?P<job>[0-9]{6,})\b")
RCH_E104_RE = re.compile(r"(?im)^\s*(?P<line>\[RCH-E104\].*SSH command timed out.*)$")
STALE_PROGRESS_RE = re.compile(
    r"(?im)^\s*(?P<line>.*(?:fresh heartbeat|heartbeat remains fresh|progress stale|stale progress|no output).*)$"
)
DEPENDENCY_RESOLVER_RE = re.compile(
    r"(?im)^\s*(?P<line>(?:error:\s+failed to select a version|failed to load manifest for dependency|failed to resolve.*dependency|no matching package named ).*)$"
)
PRODUCT_FAILURE_RE = re.compile(
    r"(?im)^\s*(?P<line>(?:error(?:\[[A-Z0-9]+\])?:|error:\s+could not compile|test result:\s+FAILED|clippy.*error|rustfmt.*failed).*)$"
)
SUCCESS_RE = re.compile(r"(?im)(test result:\s+ok\.|Finished\s+`|Finished\s+dev|Finished\s+release)")
CANCEL_RE = re.compile(r"(?i)\b(cancelled|canceled|interrupted|aborted locally|operator cancelled)\b")
PRODUCT_DIAGNOSTIC_RE = re.compile(
    r"(?im)^\s*(?P<line>(?:error(?:\[[A-Z0-9]+\])?:|error:\s+failed to select a version|error:\s+could not compile|test result:\s+FAILED).*)$"
)


@dataclass(frozen=True)
class NormalizationPolicy:
    default_command: str | None = None


def _check(check: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {
        "check": check,
        "passed": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }


def _bounded_line(value: str | None, *, limit: int = 400) -> str | None:
    if value is None:
        return None
    line = " ".join(value.strip().split())
    if not line:
        return None
    return line[:limit]


def _first_match_line(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    if not match:
        return None
    value = match.groupdict().get("line") or match.group(0)
    return _bounded_line(value)


def _command(text: str, policy: NormalizationPolicy) -> str | None:
    match = COMMAND_RE.search(text)
    if match:
        return _bounded_line(match.group("command"), limit=800)
    if policy.default_command:
        return _bounded_line(policy.default_command, limit=800)
    return None


def _worker_id(text: str) -> str | None:
    match = WORKER_RE.search(text)
    return match.group("worker") if match else None


def _job_id(text: str) -> str | None:
    match = JOB_RE.search(text)
    return match.group("job") if match else None


def _classify(text: str) -> tuple[str, str, str | None, bool, bool, str]:
    ssh_line = _first_match_line(RCH_E104_RE, text)
    if ssh_line:
        return (
            "ssh_timeout",
            "RCH_RETRY_SSH_TIMEOUT",
            ssh_line,
            False,
            True,
            "retry_remote_different_worker",
        )

    stale_line = _first_match_line(STALE_PROGRESS_RE, text)
    if stale_line and re.search(r"(?i)(remote_exec_start|heartbeat|progress stale|stale_detector)", text):
        return (
            "stale_progress",
            "RCH_STALE_PROGRESS",
            stale_line,
            False,
            True,
            "retry_remote_different_worker",
        )

    dependency_line = _first_match_line(DEPENDENCY_RESOLVER_RE, text)
    if dependency_line:
        return (
            "dependency_resolver_error",
            "RCH_PRODUCT_DEPENDENCY_RESOLVER",
            dependency_line,
            True,
            False,
            "fix_product_failure",
        )

    product_line = _first_match_line(PRODUCT_FAILURE_RE, text)
    if product_line:
        return (
            "product_failure",
            "RCH_PRODUCT_DIAGNOSTIC",
            product_line,
            True,
            False,
            "fix_product_failure",
        )

    if SUCCESS_RE.search(text):
        return ("success", "RCH_SUCCESS", None, False, False, "use_receipt")

    fallback_line = _first_match_line(re.compile(r"(?im)^\s*(?P<line>.*local fallback.*)$"), text)
    if fallback_line:
        return (
            "local_fallback_refused",
            "RCH_REJECT_LOCAL_FALLBACK",
            fallback_line,
            False,
            True,
            "retry_remote_different_worker",
        )

    unknown = _bounded_line(text.splitlines()[0] if text.splitlines() else "")
    return ("unknown", "RCH_UNKNOWN", unknown, False, False, "record_blocker")


def normalize_text(
    text: str,
    *,
    sample_id: str,
    policy: NormalizationPolicy | None = None,
) -> dict[str, Any]:
    policy = policy or NormalizationPolicy()
    evidence_class, reason_code, first_blocker, product_diagnostics_reached, retry_recommended, action = _classify(text)
    command = _command(text, policy)
    cancellation_observed = bool(CANCEL_RE.search(text))
    worker_id = _worker_id(text)
    job_id = _job_id(text)
    product_line = _first_match_line(PRODUCT_DIAGNOSTIC_RE, text)

    record = {
        "schema_version": SCHEMA_VERSION,
        "sample_id": sample_id,
        "classification": evidence_class,
        "reason_code": reason_code,
        "command": command,
        "worker_id": worker_id,
        "job_id": job_id,
        "first_blocker": first_blocker,
        "product_diagnostics_reached": product_diagnostics_reached,
        "product_diagnostic": product_line,
        "retry_recommended": retry_recommended,
        "cancellation_observed": cancellation_observed,
        "recommended_action": action,
        "beads_comment": _beads_comment(
            command=command,
            worker_id=worker_id,
            job_id=job_id,
            first_blocker=first_blocker,
            classification=evidence_class,
            product_diagnostics_reached=product_diagnostics_reached,
            retry_recommended=retry_recommended,
            cancellation_observed=cancellation_observed,
            recommended_action=action,
        ),
    }
    return record


def _beads_comment(
    *,
    command: str | None,
    worker_id: str | None,
    job_id: str | None,
    first_blocker: str | None,
    classification: str,
    product_diagnostics_reached: bool,
    retry_recommended: bool,
    cancellation_observed: bool,
    recommended_action: str,
) -> str:
    lines = [
        "RCH evidence normalization:",
        f"- classification: {classification}",
        f"- command: {command or 'unknown'}",
        f"- worker_id: {worker_id or 'unknown'}",
        f"- job_id: {job_id or 'unknown'}",
        f"- first_blocker: {first_blocker or 'none'}",
        f"- product_diagnostics_reached: {str(product_diagnostics_reached).lower()}",
        f"- retry_recommended: {str(retry_recommended).lower()}",
        f"- cancellation_observed: {str(cancellation_observed).lower()}",
        f"- recommended_action: {recommended_action}",
    ]
    return "\n".join(lines)


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _records_from_inputs(paths: list[Path], policy: NormalizationPolicy) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        records.append(normalize_text(_load_text(path), sample_id=path.name, policy=policy))
    return records


def run_checks(records: list[dict[str, Any]]) -> dict[str, Any]:
    missing_first_blocker = [
        record["sample_id"]
        for record in records
        if record["classification"] != "success" and not record.get("first_blocker")
    ]
    missing_command = [record["sample_id"] for record in records if not record.get("command")]
    product_hidden_as_retry = [
        record["sample_id"]
        for record in records
        if record.get("product_diagnostics_reached") and record.get("retry_recommended")
    ]
    checks = [
        _check("records-present", bool(records), "at least one evidence record is required"),
        _check("commands-preserved", not missing_command, f"missing command in {missing_command}"),
        _check("first-blockers-preserved", not missing_first_blocker, f"missing first blocker in {missing_first_blocker}"),
        _check(
            "product-failures-not-retryable",
            not product_hidden_as_retry,
            f"product diagnostics marked retryable in {product_hidden_as_retry}",
        ),
    ]

    counts: dict[str, int] = {}
    for record in records:
        classification = str(record["classification"])
        counts[classification] = counts.get(classification, 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "bead_id": CHECK_BEAD_ID,
        "title": TITLE,
        "verdict": "PASS" if all(check["passed"] for check in checks) else "FAIL",
        "summary": {
            "record_count": len(records),
            "class_counts": counts,
            "retry_count": sum(1 for record in records if record.get("retry_recommended")),
            "product_diagnostics_count": sum(1 for record in records if record.get("product_diagnostics_reached")),
            "cancellation_count": sum(1 for record in records if record.get("cancellation_observed")),
        },
        "records": records,
        "checks": checks,
    }


def _self_test_records() -> list[dict[str, Any]]:
    fixtures = {
        "ssh-timeout": (
            "Exact command: rch exec -- cargo clippy --all-targets -- -D warnings\n"
            "build 29750734287276250 selected worker vmi1156319\n"
            "[RCH-E104] SSH command timed out (no local fallback)\n"
            "[RCH] remote vmi1156319 (1800.0s)\n"
        ),
        "fresh-heartbeat-stale-progress": (
            "Exact command: rch exec -- cargo test -p frankenengine-node validation_proof_cache\n"
            "job_id=29750734287276251 worker=vmi1167313 last_phase=remote_exec_start\n"
            "fresh heartbeat but no output for 900s; progress stale before wall timeout\n"
            "cancelled locally after stale detector marked progress stale\n"
        ),
        "dependency-resolver": (
            "Exact command: rch exec -- cargo test -p frankenengine-node\n"
            "error: failed to select a version for `getrandom`.\n"
            "required by package `fsqlite-ext-misc v0.1.0 (/dp/frankensqlite/crates/fsqlite-ext-misc)`\n"
        ),
        "product-compile": (
            "Exact command: rch exec -- cargo check --all-targets\n"
            "error[E0599]: no method named `emit_receipt` found for struct `ValidationBroker`\n"
        ),
        "clean-success": (
            "Exact command: rch exec -- cargo test -p frankenengine-node doctor_policy_activation_e2e\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        ),
    }
    return [normalize_text(text, sample_id=name) for name, text in fixtures.items()]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=TITLE)
    parser.add_argument("--input", type=Path, action="append", default=[], help="RCH log/proof snippet to normalize")
    parser.add_argument("--command", help="Default command when an input snippet does not contain one")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_test_logging("normalize_rch_evidence")
    policy = NormalizationPolicy(default_command=args.command)

    if args.self_test:
        records = _self_test_records()
    else:
        if not args.input:
            print("missing required input: --input or --self-test", file=sys.stderr)
            return 2
        records = _records_from_inputs(args.input, policy)

    result = run_checks(records)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{TITLE}: {result['verdict']}")
        print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
