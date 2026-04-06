#!/usr/bin/env python3
"""External reproduction automation script for franken_node.

Automates the full reproduction playbook: environment check, fixture
acquisition, test execution, and report generation. The script is
idempotent and can be re-run safely.

Usage:
    python3 scripts/reproduce.py                    # full run
    python3 scripts/reproduce.py --skip-install     # skip dependency install
    python3 scripts/reproduce.py --dry-run          # list steps only
    python3 scripts/reproduce.py --verbose          # print detailed claim status
    python3 scripts/reproduce.py --json             # structured JSON output
    python3 scripts/reproduce.py --claim HC-001     # single claim
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CLAIMS_PATH = ROOT / "docs" / "headline_claims.toml"
PLAYBOOK_PATH = ROOT / "docs" / "reproduction_playbook.md"
REPORT_PATH = ROOT / "reproduction_report.json"
SCHEMA_VERSION = "erp-report.v2"
DEFAULT_TIMEOUT_SECONDS = 300
SUPPORTED_HARNESS_KINDS = {"python"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _append_execution_log(
    events: list[dict[str, Any]],
    phase: str,
    event: str,
    detail: str | None = None,
    **fields: Any,
) -> None:
    entry: dict[str, Any] = {
        "timestamp": _utc_now_iso(),
        "phase": phase,
        "event": event,
    }
    if detail:
        entry["detail"] = detail
    for key, value in fields.items():
        if value is not None:
            entry[key] = value
    events.append(entry)


def _parse_claims_toml(path: Path) -> list[dict[str, Any]]:
    """Load [[claim]] entries from TOML with a minimal fallback parser."""
    if not path.is_file():
        return []
    try:
        import tomllib
    except ImportError:
        tomllib = None  # type: ignore[assignment]

    if tomllib is not None:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
        claims = data.get("claim", [])
        if isinstance(claims, list):
            return [claim for claim in claims if isinstance(claim, dict)]

    text = path.read_text(encoding="utf-8")
    claims: list[dict[str, Any]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[claim]]":
            if current:
                claims.append(current)
            current = {}
        elif "=" in stripped and not stripped.startswith("#"):
            key, _, val = stripped.partition("=")
            key = key.strip()
            val = val.strip().strip('"')
            current[key] = val
    if current:
        claims.append(current)
    return claims


def environment_fingerprint() -> dict[str, str]:
    """Capture the environment fingerprint."""
    fp: dict[str, str] = {
        "os": f"{platform.system()} {platform.release()} {platform.machine()}",
        "cpu": platform.processor() or "unknown",
        "python_version": platform.python_version(),
    }
    # Rust version
    try:
        result = subprocess.run(
            ["rustc", "--version"], capture_output=True, text=True, timeout=3600
        )
        fp["rust_version"] = result.stdout.strip() if result.returncode == 0 else "not found"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        fp["rust_version"] = "not found"
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "--version"], capture_output=True, text=True, timeout=3600
        )
        fp["cargo_version"] = result.stdout.strip() if result.returncode == 0 else "not found"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        fp["cargo_version"] = "not found"

    # Node version
    try:
        result = subprocess.run(
            ["node", "--version"], capture_output=True, text=True, timeout=3600
        )
        fp["node_version"] = result.stdout.strip() if result.returncode == 0 else "not found"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        fp["node_version"] = "not found"

    # Memory
    try:
        import psutil
        fp["memory_gb"] = str(round(psutil.virtual_memory().total / (1024**3)))
    except ImportError:
        fp["memory_gb"] = "unknown"

    return fp


def _stringify_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def _resolve_path(ref: str) -> Path:
    path = Path(ref)
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def _base_claim_result(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": claim.get("claim_id", "unknown"),
        "claim_text": claim.get("claim_text", ""),
        "verification_method": claim.get("verification_method", ""),
        "acceptance_threshold": claim.get("acceptance_threshold", ""),
        "test_reference": claim.get("test_reference", ""),
        "category": claim.get("category", ""),
        "procedure_ref": claim.get("procedure_ref", ""),
        "harness_kind": claim.get("harness_kind", ""),
        "measurement_key": claim.get("measurement_key", ""),
    }


def _claim_command(claim: dict[str, Any]) -> tuple[list[str], Path]:
    procedure_ref = str(claim.get("procedure_ref", "")).strip()
    harness_kind = str(claim.get("harness_kind", "")).strip()
    missing = [
        field
        for field in ("procedure_ref", "harness_kind", "measurement_key")
        if not str(claim.get(field, "")).strip()
    ]
    if missing:
        raise ValueError(f"missing mapping fields: {', '.join(missing)}")
    if harness_kind not in SUPPORTED_HARNESS_KINDS:
        raise ValueError(f"unsupported harness kind: {harness_kind}")
    resolved = _resolve_path(procedure_ref)
    if not resolved.is_file():
        raise ValueError(f"procedure not found: {procedure_ref}")
    if harness_kind == "python":
        return [sys.executable, str(resolved), "--json"], resolved
    raise ValueError(f"unsupported harness kind: {harness_kind}")


def _format_command(command: list[str]) -> str:
    return shlex.join(command)


def _extract_measurement(payload: dict[str, Any], measurement_key: str) -> Any:
    value: Any = payload
    for segment in measurement_key.split("."):
        if not isinstance(value, dict) or segment not in value:
            raise ValueError(f"measurement key not found: {measurement_key}")
        value = value[segment]
    return value


def _coerce_threshold_value(raw: str) -> Any:
    token = raw.strip()
    lowered = token.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if re.fullmatch(r"-?\d+(?:\.\d+)?", token):
        return float(token) if "." in token else int(token)
    return token


def _evaluate_threshold(
    measured_value: Any,
    threshold: str,
    measurement_key: str,
) -> bool:
    for operator in ("<=", ">=", "==", "=", "<", ">"):
        if operator in threshold:
            lhs, rhs = threshold.split(operator, 1)
            lhs = lhs.strip()
            rhs_value = _coerce_threshold_value(rhs)
            if lhs and lhs != measurement_key:
                raise ValueError(
                    f"threshold references '{lhs}' but measurement_key is '{measurement_key}'"
                )
            break
    else:
        operator = "=="
        rhs_value = _coerce_threshold_value(threshold)

    if operator == "=":
        operator = "=="

    if operator == "==":
        return measured_value == rhs_value
    if operator == "<=":
        return measured_value <= rhs_value
    if operator == ">=":
        return measured_value >= rhs_value
    if operator == "<":
        return measured_value < rhs_value
    if operator == ">":
        return measured_value > rhs_value
    raise ValueError(f"unsupported threshold operator in '{threshold}'")


def dry_run_steps(claims: list[dict[str, Any]]) -> list[str]:
    """Return the list of steps that would be executed."""
    steps = [
        "1. Environment check: verify OS, toolchain versions, resources",
        "2. Fixture acquisition: download/generate fixtures, verify checksums",
    ]
    for i, claim in enumerate(claims, start=3):
        cid = claim.get("claim_id", "unknown")
        method = claim.get("harness_kind", claim.get("verification_method", "unknown"))
        procedure_ref = claim.get("procedure_ref", "<unmapped>")
        steps.append(
            f"{i}. Verify {cid}: {claim.get('claim_text', '')} [{method}] via {procedure_ref}"
        )
    steps.append(f"{len(claims) + 3}. Generate reproduction report")
    return steps


def _planned_claim(claim: dict[str, Any]) -> dict[str, Any]:
    result = _base_claim_result(claim)
    result["execution_state"] = "planned"
    result["result_kind"] = "not_run"
    try:
        command, resolved = _claim_command(claim)
        result["command"] = _format_command(command)
        result["resolved_procedure_ref"] = _display_path(resolved)
        result["detail"] = "claim mapped successfully; execution not requested"
    except ValueError as exc:
        result["detail"] = f"mapping unresolved: {exc}"
    return result


def verify_claim(
    claim: dict[str, Any],
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Execute the configured verification procedure for a single claim."""
    result = _base_claim_result(claim)
    result["execution_state"] = "error"
    result["result_kind"] = "error"
    events: list[dict[str, Any]] = []
    claim_id = str(result["claim_id"])

    _append_execution_log(
        events,
        "claim",
        "claim_execution_started",
        claim_id=claim_id,
        harness_kind=result["harness_kind"],
        measurement_key=result["measurement_key"],
    )

    try:
        command, resolved = _claim_command(claim)
        result["command"] = _format_command(command)
        result["resolved_procedure_ref"] = _display_path(resolved)
    except ValueError as exc:
        result["detail"] = str(exc)
        _append_execution_log(
            events,
            "claim",
            "claim_execution_finished",
            detail=result["detail"],
            claim_id=claim_id,
            execution_state=result["execution_state"],
            result_kind=result["result_kind"],
        )
        return result, events

    start = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        result["detail"] = f"procedure timed out after {timeout_seconds}s"
        result["duration_seconds"] = round(time.monotonic() - start, 2)
        _append_execution_log(
            events,
            "claim",
            "claim_execution_finished",
            detail=result["detail"],
            claim_id=claim_id,
            command=result.get("command"),
            resolved_procedure_ref=result.get("resolved_procedure_ref"),
            execution_state=result["execution_state"],
            result_kind=result["result_kind"],
            duration_seconds=result["duration_seconds"],
        )
        return result, events
    except OSError as exc:
        result["detail"] = f"procedure launch failed: {exc}"
        result["duration_seconds"] = round(time.monotonic() - start, 2)
        _append_execution_log(
            events,
            "claim",
            "claim_execution_finished",
            detail=result["detail"],
            claim_id=claim_id,
            command=result.get("command"),
            resolved_procedure_ref=result.get("resolved_procedure_ref"),
            execution_state=result["execution_state"],
            result_kind=result["result_kind"],
            duration_seconds=result["duration_seconds"],
        )
        return result, events

    result["duration_seconds"] = round(time.monotonic() - start, 2)
    result["exit_code"] = completed.returncode
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if stderr:
        result["stderr"] = stderr

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        result["detail"] = f"procedure output was not valid JSON: {exc}"
        _append_execution_log(
            events,
            "claim",
            "claim_execution_finished",
            detail=result["detail"],
            claim_id=claim_id,
            command=result.get("command"),
            resolved_procedure_ref=result.get("resolved_procedure_ref"),
            execution_state=result["execution_state"],
            result_kind=result["result_kind"],
            duration_seconds=result["duration_seconds"],
            exit_code=result["exit_code"],
        )
        return result, events

    measurement_key = str(claim.get("measurement_key", "")).strip()
    try:
        measured_value = _extract_measurement(payload, measurement_key)
        result["measured_value"] = measured_value
        passed = _evaluate_threshold(
            measured_value,
            str(claim.get("acceptance_threshold", "")).strip(),
            measurement_key,
        )
    except ValueError as exc:
        result["detail"] = str(exc)
        _append_execution_log(
            events,
            "claim",
            "claim_execution_finished",
            detail=result["detail"],
            claim_id=claim_id,
            command=result.get("command"),
            resolved_procedure_ref=result.get("resolved_procedure_ref"),
            execution_state=result["execution_state"],
            result_kind=result["result_kind"],
            duration_seconds=result["duration_seconds"],
            exit_code=result["exit_code"],
        )
        return result, events

    result["execution_state"] = "executed"
    if completed.returncode == 0 and passed:
        result["result_kind"] = "pass"
        result["detail"] = "procedure executed successfully and met threshold"
    elif not passed:
        result["result_kind"] = "fail"
        result["detail"] = "procedure executed but did not meet threshold"
    else:
        result["detail"] = (
            "procedure exited non-zero despite meeting the declared threshold"
        )
    _append_execution_log(
        events,
        "claim",
        "claim_execution_finished",
        detail=result["detail"],
        claim_id=claim_id,
        command=result.get("command"),
        resolved_procedure_ref=result.get("resolved_procedure_ref"),
        execution_state=result["execution_state"],
        result_kind=result["result_kind"],
        duration_seconds=result["duration_seconds"],
        exit_code=result["exit_code"],
        measured_value=result.get("measured_value"),
    )
    return result, events


def run_reproduction(
    *,
    skip_install: bool = False,
    dry_run: bool = False,
    claim_filter: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Execute the full reproduction flow."""
    start = time.monotonic()
    execution_log: list[dict[str, Any]] = []
    run_mode = "plan" if dry_run else "executed"
    _append_execution_log(
        execution_log,
        "startup",
        "run_started",
        run_mode=run_mode,
        skip_install=skip_install,
        claim_filter=claim_filter,
    )
    claims = _parse_claims_toml(CLAIMS_PATH)
    _append_execution_log(
        execution_log,
        "startup",
        "claims_loaded",
        claim_count=len(claims),
        claims_path=_display_path(CLAIMS_PATH),
    )

    if claim_filter:
        claims = [c for c in claims if c.get("claim_id") == claim_filter]
        if not claims:
            detail = f"unknown claim id: {claim_filter}"
            _append_execution_log(
                execution_log,
                "startup",
                "claim_filter_not_found",
                detail=detail,
                claim_filter=claim_filter,
            )
            return {
                "schema_version": SCHEMA_VERSION,
                "run_mode": run_mode,
                "verdict": "ERROR",
                "claim_count": 0,
                "claims": [],
                "error": detail,
                "timestamp": _utc_now_iso(),
                "duration_seconds": round(time.monotonic() - start, 2),
                "execution_log": execution_log,
            }
        _append_execution_log(
            execution_log,
            "startup",
            "claim_filter_applied",
            claim_count=len(claims),
            claim_filter=claim_filter,
        )

    if dry_run:
        planned_claims = [_planned_claim(claim) for claim in claims]
        steps = dry_run_steps(claims)
        for claim in planned_claims:
            _append_execution_log(
                execution_log,
                "planning",
                "claim_planned",
                detail=claim.get("detail"),
                claim_id=claim["claim_id"],
                execution_state=claim["execution_state"],
                result_kind=claim["result_kind"],
                command=claim.get("command"),
                resolved_procedure_ref=claim.get("resolved_procedure_ref"),
            )
        _append_execution_log(
            execution_log,
            "reporting",
            "plan_completed",
            verdict="PLANNED",
            claim_count=len(claims),
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "run_mode": "plan",
            "verdict": "PLANNED",
            "steps": steps,
            "claims": planned_claims,
            "claim_count": len(claims),
            "timestamp": _utc_now_iso(),
            "skip_install": skip_install,
            "execution_log": execution_log,
        }

    env = environment_fingerprint()
    _append_execution_log(
        execution_log,
        "environment",
        "environment_captured",
        detail="captured environment fingerprint for executed reproduction",
        fingerprint_keys=sorted(env.keys()),
    )
    results = []
    for claim in claims:
        result, claim_events = verify_claim(claim, timeout_seconds=timeout_seconds)
        results.append(result)
        execution_log.extend(claim_events)
    elapsed = time.monotonic() - start
    passed_count = sum(1 for r in results if r["result_kind"] == "pass")
    failed_count = sum(1 for r in results if r["result_kind"] == "fail")
    error_count = sum(1 for r in results if r["result_kind"] == "error")

    if error_count:
        verdict = "ERROR"
    elif failed_count:
        verdict = "FAIL"
    else:
        verdict = "PASS"

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_mode": "executed",
        "environment": env,
        "claims": results,
        "verdict": verdict,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(elapsed, 2),
        "claim_count": len(results),
        "passed_count": passed_count,
        "failed_count": failed_count,
        "error_count": error_count,
        "skip_install": skip_install,
    }

    _append_execution_log(
        execution_log,
        "reporting",
        "report_ready",
        verdict=verdict,
        claim_count=len(results),
        passed_count=passed_count,
        failed_count=failed_count,
        error_count=error_count,
        report_path=_display_path(REPORT_PATH),
    )
    report["execution_log"] = execution_log
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="franken_node external reproduction automation"
    )
    parser.add_argument("--skip-install", action="store_true", help="Skip dependency installation")
    parser.add_argument("--dry-run", action="store_true", help="List steps without executing")
    parser.add_argument("--json", action="store_true", help="Structured JSON output")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed claim command and status information",
    )
    parser.add_argument("--yes", action="store_true", help="Skip confirmation prompts")
    parser.add_argument("--claim", type=str, default=None, help="Verify a single claim by ID")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-claim procedure timeout in seconds",
    )
    args = parser.parse_args()

    report = run_reproduction(
        skip_install=args.skip_install,
        dry_run=args.dry_run,
        claim_filter=args.claim,
        timeout_seconds=args.timeout_seconds,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        if report.get("run_mode") == "plan":
            print("=== DRY RUN ===")
            for step in report["steps"]:
                print(f"  {step}")
            print(f"\n{report['claim_count']} claims would be verified.")
            unresolved = [
                claim for claim in report["claims"]
                if claim.get("detail", "").startswith("mapping unresolved")
            ]
            if unresolved:
                print("\nUnresolved claim mappings:")
                for claim in unresolved:
                    print(f"  [{claim['claim_id']}] {claim['detail']}")
            if args.verbose:
                print("\nPlanned claim details:")
                for claim in report["claims"]:
                    print(f"  [{claim['result_kind'].upper()}] {claim['claim_id']}: {claim['claim_text']}")
                    if command := claim.get("command"):
                        print(f"    command: {command}")
                    if resolved := claim.get("resolved_procedure_ref"):
                        print(f"    resolved_procedure_ref: {resolved}")
                    if detail := claim.get("detail"):
                        print(f"    detail: {detail}")
        else:
            verdict = report["verdict"]
            passed = report["passed_count"]
            total = report["claim_count"]
            errors = report.get("error_count", 0)
            print(
                f"Reproduction verdict: {verdict} "
                f"({passed}/{total} claims passed, {errors} errors)"
            )
            for claim in report["claims"]:
                status = claim["result_kind"].upper()
                print(f"  [{status}] {claim['claim_id']}: {claim['claim_text']}")
                if args.verbose or claim["result_kind"] != "pass":
                    if command := claim.get("command"):
                        print(f"    command: {command}")
                    if resolved := claim.get("resolved_procedure_ref"):
                        print(f"    resolved_procedure_ref: {resolved}")
                    print(f"    execution_state: {claim['execution_state']}")
                    if "measured_value" in claim:
                        print(f"    measured_value: {_stringify_scalar(claim['measured_value'])}")
                    if "exit_code" in claim:
                        print(f"    exit_code: {claim['exit_code']}")
                    if detail := claim.get("detail"):
                        print(f"    detail: {detail}")
                    if stderr := claim.get("stderr"):
                        print(f"    stderr: {stderr}")

    sys.exit(0 if report.get("verdict") in {"PASS", "PLANNED"} else 1)


if __name__ == "__main__":
    main()
