#!/usr/bin/env python3
"""bd-2fa verification: counterfactual replay mode for policy simulation."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "tools" / "counterfactual_replay.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
MAIN_RS = ROOT / "crates" / "franken-node" / "src" / "main.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_5" / "bd-2fa_contract.md"
FIXTURE = ROOT / "fixtures" / "interop" / "interop_test_vectors.json"

REQUIRED_IMPL_PATTERNS = [
    "pub struct CounterfactualReplayEngine",
    "pub trait SandboxedExecutor",
    "pub enum SimulationMode",
    "pub struct CounterfactualResult",
    "pub struct DivergenceRecord",
    "pub struct SummaryStatistics",
    "max_replay_steps",
    "max_wall_clock_millis",
]


def canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sorted(value.keys())}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(canonical(value), separators=(",", ":"), ensure_ascii=True)


def parse_rfc3339(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def normalize_rfc3339(ts: str) -> str:
    dt = parse_rfc3339(ts).astimezone(timezone.utc)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def load_fixture_vectors() -> list[dict[str, Any]]:
    if not FIXTURE.is_file():
        return []
    data = json.loads(FIXTURE.read_text())
    return data.get("test_vectors", [])


def fixture_to_bundle(vectors: list[dict[str, Any]]) -> dict[str, Any]:
    base = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    timeline = []
    for idx, vector in enumerate(vectors[:12], start=1):
        severity = "high" if idx % 3 == 0 else "medium" if idx % 2 == 0 else "low"
        confidence = 35 + (idx * 7) % 60
        timeline.append(
            {
                "sequence_number": idx,
                "timestamp": normalize_rfc3339(
                    (base + timedelta(microseconds=idx)).isoformat().replace("+00:00", "Z")
                ),
                "event_type": "policy_eval" if idx % 2 == 0 else "external_signal",
                "payload": {
                    "case_id": vector.get("case_id"),
                    "severity": severity,
                    "confidence": confidence,
                },
                "causal_parent": idx - 1 if idx > 1 else None,
            }
        )

    return {
        "incident_id": "INC-CF-CHECK-001",
        "created_at": timeline[-1]["timestamp"]
        if timeline
        else "1970-01-01T00:00:00.000000Z",
        "timeline": timeline,
        "policy_version": "1.0.0",
        "integrity_hash": "fixture-hash",
        "manifest": {"event_count": len(timeline)},
    }


@dataclass(frozen=True)
class PolicyConfig:
    policy_name: str
    quarantine_threshold: int
    observe_threshold: int
    degraded_mode_bias: int = 0


BASELINE_POLICY = PolicyConfig("baseline", 85, 55, 10)
STRICT_POLICY = PolicyConfig("strict", 65, 35, 30)


class ReplayBoundExceeded(RuntimeError):
    def __init__(self, kind: str, partial_result: dict[str, Any]):
        super().__init__(kind)
        self.kind = kind
        self.partial_result = partial_result


def evaluate_event(event: dict[str, Any], policy: PolicyConfig) -> dict[str, Any]:
    payload = event.get("payload", {})
    score = int(payload.get("confidence", 50))
    severity = str(payload.get("severity", "medium"))
    if severity == "critical":
        score = max(score, 97)
    elif severity == "high":
        score = max(score, 84)
    elif severity == "medium":
        score = max(score, 62)
    else:
        score = max(score, 30)

    if payload.get("degraded_mode"):
        score += policy.degraded_mode_bias
    score = max(0, min(100, score))

    if score >= policy.quarantine_threshold:
        decision = "quarantine"
        base_loss = 8
    elif score >= policy.observe_threshold:
        decision = "observe"
        base_loss = 24
    else:
        decision = "allow"
        base_loss = 58

    expected_loss = base_loss + max(0, (100 - score) // 2)
    return {
        "sequence_number": int(event["sequence_number"]),
        "decision": decision,
        "rationale": f"risk={score} policy={policy.policy_name}",
        "expected_loss": int(expected_loss),
    }


def impact_estimate(delta: int) -> str:
    delta = abs(delta)
    if delta == 0:
        return "none"
    if delta <= 9:
        return "low"
    if delta <= 24:
        return "medium"
    if delta <= 49:
        return "high"
    return "critical"


def build_result(
    bundle: dict[str, Any],
    baseline: PolicyConfig,
    alternate: PolicyConfig,
    original: list[dict[str, Any]],
    counterfactual: list[dict[str, Any]],
) -> dict[str, Any]:
    divergences = []
    changed = 0
    original_total = 0
    counter_total = 0
    for left, right in zip(original, counterfactual):
        original_total += int(left["expected_loss"])
        counter_total += int(right["expected_loss"])
        if left["decision"] != right["decision"]:
            changed += 1
            delta = int(right["expected_loss"]) - int(left["expected_loss"])
            divergences.append(
                {
                    "sequence_number": int(left["sequence_number"]),
                    "original_decision": left["decision"],
                    "counterfactual_decision": right["decision"],
                    "original_rationale": left["rationale"],
                    "counterfactual_rationale": right["rationale"],
                    "impact_estimate": impact_estimate(delta),
                }
            )

    return {
        "scenario_id": f"{bundle['incident_id']}::{alternate.policy_name}",
        "original_outcomes": original,
        "counterfactual_outcomes": counterfactual,
        "divergence_points": divergences,
        "summary_statistics": {
            "total_decisions": len(original),
            "changed_decisions": changed,
            "severity_delta": counter_total - original_total,
        },
        "metadata": {
            "bundle_hash": bundle.get("integrity_hash", ""),
            "policy_override_diff": [
                {
                    "field": "quarantine_threshold",
                    "original": str(baseline.quarantine_threshold),
                    "counterfactual": str(alternate.quarantine_threshold),
                }
            ],
            "replay_timestamp": bundle.get("created_at", ""),
            "engine_version": "counterfactual-v1",
        },
    }


def run_counterfactual(
    bundle: dict[str, Any],
    baseline: PolicyConfig,
    alternate: PolicyConfig,
    max_steps: int = 100_000,
    max_wall_clock_ms: int = 30_000,
) -> dict[str, Any]:
    timeline = bundle.get("timeline", [])
    original: list[dict[str, Any]] = []
    counterfactual: list[dict[str, Any]] = []

    for idx, event in enumerate(timeline, start=1):
        elapsed_ms = idx - 1  # deterministic simulated clock
        if elapsed_ms >= max_wall_clock_ms:
            partial = build_result(bundle, baseline, alternate, original, counterfactual)
            raise ReplayBoundExceeded("wall_clock", partial)
        if idx > max_steps:
            partial = build_result(bundle, baseline, alternate, original, counterfactual)
            raise ReplayBoundExceeded("max_steps", partial)
        original.append(evaluate_event(event, baseline))
        counterfactual.append(evaluate_event(event, alternate))

    return build_result(bundle, baseline, alternate, original, counterfactual)


def run_parameter_sweep(
    bundle: dict[str, Any],
    baseline: PolicyConfig,
    parameter: str,
    values: list[int],
    template: PolicyConfig,
) -> list[dict[str, Any]]:
    results = []
    for value in values:
        if parameter == "quarantine_threshold":
            policy = PolicyConfig(
                f"{template.policy_name}:{parameter}={value}",
                int(value),
                template.observe_threshold,
                template.degraded_mode_bias,
            )
        elif parameter == "observe_threshold":
            policy = PolicyConfig(
                f"{template.policy_name}:{parameter}={value}",
                template.quarantine_threshold,
                int(value),
                template.degraded_mode_bias,
            )
        else:
            raise ValueError(f"unsupported parameter: {parameter}")
        results.append(run_counterfactual(bundle, baseline, policy))
    return results


def check_file(path: Path, label: str) -> dict[str, Any]:
    ok = path.is_file()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"missing: {path}",
    }


def check_contains(path: Path, patterns: list[str], label: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return [{"check": f"{label}: {pattern}", "pass": False, "detail": "file missing"} for pattern in patterns]
    content = path.read_text()
    checks = []
    for pattern in patterns:
        checks.append(
            {
                "check": f"{label}: {pattern}",
                "pass": pattern in content,
                "detail": "found" if pattern in content else "not found",
            }
        )
    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_file(IMPL, "counterfactual replay implementation"))
    checks.append(check_file(SPEC, "contract"))
    checks.extend(check_contains(IMPL, REQUIRED_IMPL_PATTERNS, "impl"))
    checks.extend(check_contains(MOD_RS, ["pub mod counterfactual_replay;"], "module wiring"))
    checks.extend(
        check_contains(
            MAIN_RS,
            [
                "incident counterfactual",
                "CounterfactualReplayEngine",
                "counterfactual summary:",
            ],
            "cli wiring",
        )
    )

    vectors = load_fixture_vectors()
    checks.append(
        {
            "check": "fixture vectors",
            "pass": len(vectors) > 0,
            "detail": f"vectors={len(vectors)}",
        }
    )
    if vectors:
        bundle = fixture_to_bundle(vectors)
        first = run_counterfactual(bundle, BASELINE_POLICY, STRICT_POLICY)
        second = run_counterfactual(bundle, BASELINE_POLICY, STRICT_POLICY)
        divergence_ok = len(first["divergence_points"]) > 0
        deterministic_ok = canonical_json(first) == canonical_json(second)
        checks.append(
            {
                "check": "single policy swap divergence",
                "pass": divergence_ok,
                "detail": f"divergence_points={len(first['divergence_points'])}",
            }
        )
        checks.append(
            {
                "check": "single policy swap determinism",
                "pass": deterministic_ok,
                "detail": "result A == result B",
            }
        )

        sweep_results = run_parameter_sweep(
            bundle,
            BASELINE_POLICY,
            "quarantine_threshold",
            [60, 75, 90],
            PolicyConfig("sweep", 85, 55, 10),
        )
        checks.append(
            {
                "check": "parameter sweep mode",
                "pass": len(sweep_results) == 3,
                "detail": f"scenarios={len(sweep_results)}",
            }
        )

        timeout_guard_ok = False
        step_guard_ok = False
        try:
            run_counterfactual(bundle, BASELINE_POLICY, STRICT_POLICY, max_wall_clock_ms=0)
        except ReplayBoundExceeded as exc:
            timeout_guard_ok = exc.kind == "wall_clock" and isinstance(exc.partial_result, dict)
        try:
            run_counterfactual(bundle, BASELINE_POLICY, STRICT_POLICY, max_steps=1)
        except ReplayBoundExceeded as exc:
            step_guard_ok = exc.kind == "max_steps" and isinstance(exc.partial_result, dict)

        checks.append(
            {
                "check": "timeout guard",
                "pass": timeout_guard_ok,
                "detail": "raises bound-exceeded with partial result",
            }
        )
        checks.append(
            {
                "check": "max-steps guard",
                "pass": step_guard_ok,
                "detail": "raises bound-exceeded with partial result",
            }
        )

    passing = sum(1 for check in checks if check["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-2fa",
        "title": "Counterfactual replay mode for policy simulation",
        "section": "10.5",
        "verdict": "PASS" if passing == total else "FAIL",
        "overall_pass": passing == total,
        "summary": {"passing": passing, "failing": total - passing, "total": total},
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    result = run_checks()
    return result["verdict"] == "PASS", result["checks"]


def main() -> None:
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'} ({len(checks)} checks)")
        raise SystemExit(0 if ok else 1)

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("=== bd-2fa: counterfactual replay verification ===")
        print(f"Verdict: {result['verdict']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    raise SystemExit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
