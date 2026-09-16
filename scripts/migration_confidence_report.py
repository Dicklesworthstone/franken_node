#!/usr/bin/env python3
"""Evidence-gated migration confidence; scores are heuristics, not probabilities."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from datetime import datetime, timezone

HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_TESTS = 1024


def checked_number(value, maximum: float, label: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError(f"{label} must be finite and between 0 and {maximum}")
    return value


def compute_confidence(risk_score: float, validation_pass_rate: float,
                       fixture_coverage: float, api_tracked_pct: float) -> dict:
    """Calculate a bounded heuristic. Its interval is NOT a statistical CI."""
    checked_number(risk_score, 100, "risk_score")
    for name, value in (("validation_pass_rate", validation_pass_rate),
                        ("fixture_coverage", fixture_coverage), ("api_tracked_pct", api_tracked_pct)):
        checked_number(value, 1, name)
    components = {"risk_component": (100 - risk_score) * 0.35,
                  "validation_component": validation_pass_rate * 35,
                  "coverage_component": fixture_coverage * 15,
                  "tracking_component": api_tracked_pct * 15}
    score = round(sum(components.values()), 1)
    completeness = (fixture_coverage + api_tracked_pct + validation_pass_rate) / 3
    width = round((1 - completeness) * 30, 1)
    return {"confidence_score": score, "score_kind": "heuristic_not_probability",
            "uncertainty_band": {"lower": round(max(0, score - width), 1),
                                 "upper": round(min(100, score + width), 1), "width": width,
                                 "kind": "heuristic_not_statistical_interval"},
            "components": {key: round(value, 1) for key, value in components.items()}}


def classify_confidence(score: float) -> dict:
    checked_number(score, 100, "confidence_score")
    if score >= 80:
        return {"level": "high", "recommendation": "Evaluate a staged rollout against measured evidence"}
    if score >= 50:
        return {"level": "medium", "recommendation": "Require monitored staged evaluation"}
    if score >= 20:
        return {"level": "low", "recommendation": "Address evidence gaps before proceeding"}
    return {"level": "insufficient", "recommendation": "Migration not recommended"}


def validation_evidence(result: dict | None) -> dict:
    """Reconcile observations, not merely a caller-supplied PASS or pass rate.

    This checks internal consistency, not authenticity. Only the orchestrator's
    own execution establishes that measurements happened; unsigned imported
    reports must not be treated as trusted certificates.
    """
    invalid = {"valid": False, "all_passed": False, "pass_rate": None,
               "total_tests": 0, "reason": "no complete measured validation"}
    try:
        if (not isinstance(result, dict) or result.get("schema_version") != "migration-validation-v1"
                or result.get("phase") != "execution" or result.get("comparison_mode") != "exact-bytes"):
            return invalid
        summary, rows = result["summary"], result["validation_results"]
        if not isinstance(summary, dict) or not isinstance(rows, list):
            return invalid
        counts = [summary[key] for key in ("total_tests", "passed", "failed", "skipped", "errored")]
        if any(type(value) is not int or not 0 <= value <= MAX_TESTS for value in counts):
            return invalid
        total, passed, failed, skipped, errored = counts
        if (not total or total != passed + failed + skipped + errored or skipped or errored
                or len(rows) != total or result.get("errors")):
            return invalid
        expected_verdict = "FAIL" if failed else "PASS"
        if summary.get("verdict") != expected_verdict:
            return invalid
        discovery = result["test_discovery"]
        names = discovery["test_files"]
        if (not isinstance(names, list) or len(names) != total
                or type(discovery.get("test_files_found")) is not int
                or discovery.get("test_files_found") != total
                or discovery.get("missing_baseline") or discovery.get("missing_migration")
                or any(not isinstance(name, str) or not name for name in names)
                or len(set(names)) != total):
            return invalid
        filesystem = result.get("filesystem_comparison")
        if type(filesystem) is not bool:
            return invalid
        expected_scope = "test-process-and-workspace-delta" if filesystem else "test-process-stdout-stderr-exit"
        if result.get("validation_scope") != expected_scope:
            return invalid
        inputs = result["inputs"]
        if (not isinstance(inputs, dict) or set(inputs) != {"baseline_sha256", "migration_sha256"}
                or any(not isinstance(value, str) or HASH_RE.fullmatch(value) is None for value in inputs.values())):
            return invalid
        commands = result["commands"]
        if not isinstance(commands, dict) or set(commands) != {"baseline", "migration"}:
            return invalid
        for command in commands.values():
            if (not isinstance(command, list) or not 2 <= len(command) <= 256
                    or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in command)
                    or command.count("{test}") != 1 or command[0] == "{test}"):
                return invalid
        seen, measured_passed = set(), 0
        for row in rows:
            name = row["test"]
            if name not in names or name in seen or row.get("status") not in {"PASS", "FAIL"}:
                return invalid
            seen.add(name)
            successful = True
            for leg in ("baseline", "migration"):
                observation = row[leg]
                exit_code, termination = observation["exit_code"], observation["termination"]
                if (type(exit_code) is not int or termination not in {"exited", "signal", "timeout", "output_limit"}
                        or (termination == "signal" and exit_code >= 0)
                        or (termination == "exited" and exit_code < 0)):
                    return invalid
                streams = observation["streams"]
                if not isinstance(streams, dict) or set(streams) != {"stdout", "stderr"}:
                    return invalid
                for stream in streams.values():
                    digest, count, retained = stream["sha256"], stream["bytes_observed"], stream["retained_bytes"]
                    if (not isinstance(digest, str) or HASH_RE.fullmatch(digest) is None
                            or type(count) is not int or count < 0 or type(retained) is not int
                            or not 0 <= retained <= count or type(stream["complete"]) is not bool
                            or (count == 0 and digest != EMPTY_SHA256)
                            or (termination == "exited" and (not stream["complete"] or retained != count))):
                        return invalid
                successful &= exit_code == 0 and termination == "exited"
                if filesystem:
                    delta = observation["workspace_delta"]
                    if (not isinstance(delta["sha256"], str) or HASH_RE.fullmatch(delta["sha256"]) is None
                            or type(delta["changed_paths"]) is not int or delta["changed_paths"] < 0):
                        return invalid
            equal = all(row["baseline"]["streams"][channel] == row["migration"]["streams"][channel]
                        for channel in ("stdout", "stderr"))
            if filesystem:
                equal &= all(row["baseline"]["workspace_delta"][key] == row["migration"]["workspace_delta"][key]
                             for key in ("sha256", "changed_paths"))
            measured_pass = successful and equal
            if ((row["status"] == "PASS") != measured_pass
                    or not isinstance(row.get("divergences"), list)
                    or (not row["divergences"]) != measured_pass):
                return invalid
            measured_passed += int(measured_pass)
        if measured_passed != passed or len(seen) != total:
            return invalid
        return {"valid": True, "all_passed": passed == total, "pass_rate": passed / total,
                "total_tests": total, "reason": "complete internally consistent execution evidence"}
    except (KeyError, TypeError, ValueError, AttributeError):
        return invalid


def generate_report(scan_summary: dict | None = None, risk_report: dict | None = None,
                    validation_result: dict | None = None, *, fixture_coverage: float | None = None,
                    api_tracked_pct: float | None = None) -> dict:
    """Missing coverage is unknown, not assumed 50%; risk is not API coverage."""
    risk_score = risk_report.get("risk_score") if risk_report else None
    if risk_score is not None:
        checked_number(risk_score, 100, "risk_score")
    for name, value in (("fixture_coverage", fixture_coverage), ("api_tracked_pct", api_tracked_pct)):
        if value is not None:
            checked_number(value, 1, name)
    evidence = validation_evidence(validation_result)
    confidence = compute_confidence(100 if risk_score is None else risk_score,
                                    evidence["pass_rate"] or 0, fixture_coverage or 0, api_tracked_pct or 0)
    classification = classify_confidence(confidence["confidence_score"])
    blockers = []
    if risk_score is None:
        blockers.append("risk assessment is unavailable")
    if not evidence["valid"]:
        blockers.append(evidence["reason"])
    elif not evidence["all_passed"]:
        blockers.append("at least one measured migration case failed")
    if classification["level"] not in {"high", "medium"}:
        blockers.append("insufficient evidence score")
    distribution = (scan_summary or {}).get("risk_distribution", {})
    if any(distribution.get(level, 0) for level in ("critical", "high")):
        blockers.append("high or critical static findings require review")
    unknown = [name for name, value in (("risk_score", risk_score),
                                        ("fixture_coverage", fixture_coverage),
                                        ("api_tracked_pct", api_tracked_pct),
                                        ("validation_pass_rate", evidence["pass_rate"])) if value is None]
    return {"report_timestamp": datetime.now(timezone.utc).isoformat(), "confidence": confidence,
            "classification": classification,
            "go_decision": {"proceed": not blockers, "scope": "captured-tests-only; not production authorization",
                            "rationale": "; ".join(blockers) if blockers else classification["recommendation"],
                            "blocking_reasons": blockers},
            "validation_evidence": evidence,
            "uncertainty_sources": [{"source": name, "impact": "unknown", "assumed": False} for name in unknown],
            "data_inputs": {"risk_score": risk_score, "validation_pass_rate": evidence["pass_rate"],
                            "fixture_coverage": fixture_coverage, "api_tracked_pct": api_tracked_pct}}


def self_test() -> dict:
    high = compute_confidence(5, 1, .9, .95)
    low = compute_confidence(80, .2, .3, .4)
    checks = [{"id": "CONF-HIGH", "status": "PASS" if high["confidence_score"] >= 70 else "FAIL"},
              {"id": "CONF-LOW", "status": "PASS" if low["confidence_score"] < 50 else "FAIL"},
              {"id": "CONF-BOUNDED", "status": "PASS" if 0 <= high["confidence_score"] <= 100 else "FAIL"},
              {"id": "CONF-UNCERTAINTY", "status": "PASS" if high["uncertainty_band"]["width"] >= 0 else "FAIL"},
              {"id": "CONF-CLASSIFY", "status": "PASS" if classify_confidence(85)["level"] == "high" else "FAIL"},
              {"id": "CONF-REPORT", "status": "PASS" if "go_decision" in generate_report() else "FAIL"},
              {"id": "CONF-MISSING-EVIDENCE", "status": "PASS" if not generate_report()["go_decision"]["proceed"] else "FAIL"}]
    failures = sum(check["status"] != "PASS" for check in checks)
    return {"gate": "confidence_report_verification", "section": "10.3",
            "verdict": "FAIL" if failures else "PASS", "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": checks, "summary": {"total_checks": len(checks), "passing_checks": len(checks) - failures,
                                           "failing_checks": failures}}


def main() -> int:
    result = self_test() if "--self-test" in sys.argv else generate_report()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2, allow_nan=False))
    elif "--self-test" in sys.argv:
        for check in result["checks"]:
            print(f"[{check['status']}] {check['id']}")
        print(f"Verdict: {result['verdict']}")
    else:
        print(f"Confidence: {result['confidence']['confidence_score']}/100 (heuristic)")
        print(f"Go/No-Go: {'GO' if result['go_decision']['proceed'] else 'NO-GO'}")
        print(result["go_decision"]["rationale"])
    return (0 if result["verdict"] == "PASS" else 1) if "--self-test" in sys.argv else 2


if __name__ == "__main__":
    sys.exit(main())
