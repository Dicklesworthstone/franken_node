#!/usr/bin/env python3
"""Verification gate for bd-ye4m BPET adversarial evolution suite.

This gate anchors bd-ye4m.1 sub-task 5 to the real adversarial evolution
implementation surface shipped by sub-tasks 1-4:

  * `crates/franken-node/src/security/bpet/adversarial_evolution.rs`
    (ST1, ~1217 LOC, 24 unit tests) — `AdversaryKind`, `RampCurve`,
    `AdversaryScenario`, canonical encoding, baseline phenotype.
  * `crates/franken-node/src/security/bpet/adversarial_harness.rs`
    (ST2, ~1221 LOC, 13 unit tests) — `AdversarialHarness`, `run_scenario`,
    `DetectorThresholds`, `ScenarioVerdict`.
  * `crates/franken-node/src/security/bpet/adversarial_scenarios.rs`
    (ST3, 649 LOC, 11 unit tests) — `AdversarialScenarioFixture`,
    `evaluate_scenario_fixture`, 8 `synthesize_*` helpers, JSON loader.
  * `tests/security/adversarial_scenarios/*.json` (ST3) — 8 on-disk fixtures
    keyed by `AdversaryKind` variant.
  * `tests/security/bpet_adversarial_evolution_suite.rs` (ST4, 491 LOC, 13
    integration tests) registered in `crates/franken-node/Cargo.toml`.
  * `docs/security/bpet_adversarial_playbook.md` (ST5, this gate) —
    operator playbook covering the 8 adversary kinds + 4 ramp curves +
    detector thresholds.

By default the gate runs the Rust integration test through `rch`. Unit tests
may pass `--skip-cargo` to validate the static contract without launching a
build (mirrors `check_dgis_contagion_simulator.py`).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-ye4m"
COMPLETION_DEBT_BEAD_ID = "bd-ye4m.1"
SECTION = "10.21"

EVOLUTION_SRC = ROOT / "crates/franken-node/src/security/bpet/adversarial_evolution.rs"
HARNESS_SRC = ROOT / "crates/franken-node/src/security/bpet/adversarial_harness.rs"
SCENARIOS_SRC = ROOT / "crates/franken-node/src/security/bpet/adversarial_scenarios.rs"
INTEGRATION_TEST = ROOT / "tests/security/bpet_adversarial_evolution_suite.rs"
SCENARIO_DIR = ROOT / "tests/security/adversarial_scenarios"
CARGO_TOML = ROOT / "crates/franken-node/Cargo.toml"
PLAYBOOK = ROOT / "docs/security/bpet_adversarial_playbook.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_21/bd-ye4m/verification_evidence.json"

# AdversaryKind variant -> on-disk fixture stem (snake_case) -> expected ramp
# curve kind (matches the in-code synthesizers in adversarial_scenarios.rs).
REQUIRED_ADVERSARY_KINDS: dict[str, dict[str, str]] = {
    "SlowRollDrift": {"fixture": "slow_roll_drift", "ramp": "linear", "verdict": "caught_late"},
    "CapabilityCreepDisguisedAsFeature": {
        "fixture": "capability_creep_disguised_as_feature",
        "ramp": "sigmoid",
        "verdict": "caught_late",
    },
    "EvictionViaTrustFlooding": {
        "fixture": "eviction_via_trust_flooding",
        "ramp": "stepped",
        "verdict": "caught_early",
    },
    "ManyTinyUpdates": {
        "fixture": "many_tiny_updates",
        "ramp": "linear",
        "verdict": "missed_entirely",
    },
    "MultiPersonaCoordination": {
        "fixture": "multi_persona_coordination",
        "ramp": "exponential",
        "verdict": "caught_early",
    },
    "FalseRecoveryClaim": {
        "fixture": "false_recovery_claim",
        "ramp": "stepped",
        "verdict": "caught_late",
    },
    "IndirectViaDep": {
        "fixture": "indirect_via_dep",
        "ramp": "sigmoid",
        "verdict": "caught_late",
    },
    "SignatureRollover": {
        "fixture": "signature_rollover",
        "ramp": "exponential",
        "verdict": "caught_early",
    },
}

REQUIRED_RAMP_CURVES = ("Linear", "Exponential", "Sigmoid", "Stepped")


@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def check_scenario_fixture_count() -> CheckResult:
    if not SCENARIO_DIR.exists():
        return CheckResult("scenario_fixture_count", False, f"missing {rel(SCENARIO_DIR)}")
    found = sorted(p.name for p in SCENARIO_DIR.glob("*.json"))
    expected = sorted(f"{spec['fixture']}.json" for spec in REQUIRED_ADVERSARY_KINDS.values())
    if found != expected:
        return CheckResult(
            "scenario_fixture_count",
            False,
            f"fixture set drift: expected {expected}, got {found}",
            {"expected": expected, "found": found},
        )
    return CheckResult(
        "scenario_fixture_count",
        True,
        f"exactly 8 JSON scenario fixtures present (one per AdversaryKind)",
        {"fixtures": found},
    )


def check_scenario_schema() -> CheckResult:
    failures: list[str] = []
    summary: dict[str, dict[str, Any]] = {}
    for kind, spec in REQUIRED_ADVERSARY_KINDS.items():
        path = SCENARIO_DIR / f"{spec['fixture']}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{rel(path)}: load failed: {exc}")
            continue

        for top_key in ("name", "description", "scenario", "baseline", "thresholds", "expected_verdict"):
            if top_key not in data:
                failures.append(f"{rel(path)}: missing top-level key `{top_key}`")
        if failures and failures[-1].startswith(f"{rel(path)}:"):
            continue

        if data["name"] != spec["fixture"]:
            failures.append(f"{rel(path)}: name `{data['name']}` != filename stem `{spec['fixture']}`")

        scenario = data["scenario"]
        if scenario.get("kind") != spec["fixture"]:
            failures.append(
                f"{rel(path)}: scenario.kind `{scenario.get('kind')}` != filename stem `{spec['fixture']}`"
            )
        ramp = scenario.get("ramp_curve", {})
        if ramp.get("kind") != spec["ramp"]:
            failures.append(
                f"{rel(path)}: ramp_curve.kind `{ramp.get('kind')}` != expected `{spec['ramp']}`"
            )

        verdict = data["expected_verdict"]
        if verdict.get("kind") != spec["verdict"]:
            failures.append(
                f"{rel(path)}: expected_verdict.kind `{verdict.get('kind')}` != expected `{spec['verdict']}`"
            )
        if verdict["kind"] in ("caught_early", "caught_late"):
            lo, hi = verdict.get("at_step_lower"), verdict.get("at_step_upper")
            if not isinstance(lo, int) or not isinstance(hi, int) or lo > hi:
                failures.append(f"{rel(path)}: at_step bounds invalid: [{lo}, {hi}]")

        thresholds = data["thresholds"]
        for tname in ("drift", "regime_shift", "hazard", "provenance", "combined"):
            val = thresholds.get(tname)
            if not isinstance(val, (int, float)) or not (0.0 <= float(val) <= 1.0):
                failures.append(f"{rel(path)}: threshold `{tname}` out of [0,1]: {val!r}")

        summary[kind] = {
            "fixture": spec["fixture"],
            "n_steps": scenario.get("n_steps"),
            "ramp_kind": ramp.get("kind"),
            "verdict_kind": verdict.get("kind"),
        }

    if failures:
        return CheckResult(
            "scenario_schema",
            False,
            f"scenario schema validation failed ({len(failures)} issues)",
            {"failures": failures, "summary": summary},
        )
    return CheckResult(
        "scenario_schema",
        True,
        "all 8 scenario fixtures parse + match kind/ramp/verdict invariants",
        {"summary": summary},
    )


def check_evolution_source() -> CheckResult:
    if not EVOLUTION_SRC.exists():
        return CheckResult("evolution_source", False, f"missing {rel(EVOLUTION_SRC)}")
    content = EVOLUTION_SRC.read_text(encoding="utf-8")
    loc = content.count("\n") + 1
    if loc <= 1000:
        return CheckResult(
            "evolution_source",
            False,
            f"{rel(EVOLUTION_SRC)} LOC={loc} <= 1000",
            {"loc": loc},
        )
    missing_kinds = [k for k in REQUIRED_ADVERSARY_KINDS if f"AdversaryKind::{k}" not in content]
    if missing_kinds:
        return CheckResult(
            "evolution_source",
            False,
            f"missing AdversaryKind variants: {missing_kinds}",
            {"loc": loc, "missing": missing_kinds},
        )
    missing_ramps = [r for r in REQUIRED_RAMP_CURVES if f"RampCurve::{r}" not in content]
    if missing_ramps:
        return CheckResult(
            "evolution_source",
            False,
            f"missing RampCurve variants: {missing_ramps}",
            {"loc": loc, "missing": missing_ramps},
        )
    return CheckResult(
        "evolution_source",
        True,
        f"adversarial_evolution.rs LOC={loc} has all 8 AdversaryKind + 4 RampCurve variants",
        {"loc": loc},
    )


def check_harness_source() -> CheckResult:
    if not HARNESS_SRC.exists():
        return CheckResult("harness_source", False, f"missing {rel(HARNESS_SRC)}")
    content = HARNESS_SRC.read_text(encoding="utf-8")
    loc = content.count("\n") + 1
    if loc <= 1000:
        return CheckResult("harness_source", False, f"LOC={loc} <= 1000", {"loc": loc})
    required_symbols = [
        "pub fn run_scenario",
        "pub struct AdversarialHarness",
        "pub struct DetectorThresholds",
        "pub enum ScenarioVerdict",
        "pub enum DetectionVerdict",
    ]
    missing = [s for s in required_symbols if s not in content]
    if missing:
        return CheckResult(
            "harness_source",
            False,
            f"missing harness symbols: {missing}",
            {"loc": loc, "missing": missing},
        )
    return CheckResult(
        "harness_source",
        True,
        f"adversarial_harness.rs LOC={loc} exports run_scenario + AdversarialHarness + DetectorThresholds",
        {"loc": loc},
    )


def check_integration_suite() -> CheckResult:
    if not INTEGRATION_TEST.exists():
        return CheckResult("integration_suite", False, f"missing {rel(INTEGRATION_TEST)}")
    content = INTEGRATION_TEST.read_text(encoding="utf-8")
    total_tests = content.count("#[test]")
    if total_tests < 13:
        return CheckResult(
            "integration_suite",
            False,
            f"#[test] count {total_tests} < 13",
            {"total_tests": total_tests},
        )

    cargo = CARGO_TOML.read_text(encoding="utf-8")
    cargo_checks = {
        "test_name": 'name = "bpet_adversarial_evolution_suite"' in cargo,
        "test_path": 'path = "../../tests/security/bpet_adversarial_evolution_suite.rs"' in cargo,
    }
    failed = [k for k, ok in cargo_checks.items() if not ok]
    if failed:
        return CheckResult(
            "integration_suite",
            False,
            f"Cargo.toml registration missing: {failed}",
            {"total_tests": total_tests, "failed_cargo": failed},
        )
    return CheckResult(
        "integration_suite",
        True,
        f"integration suite has {total_tests} #[test]s and is registered in Cargo.toml",
        {"total_tests": total_tests},
    )


def check_playbook() -> CheckResult:
    if not PLAYBOOK.exists():
        return CheckResult("playbook", False, f"missing {rel(PLAYBOOK)}")
    content = PLAYBOOK.read_text(encoding="utf-8")
    loc = content.count("\n") + 1

    missing_kinds = [k for k in REQUIRED_ADVERSARY_KINDS if k not in content]
    if missing_kinds:
        return CheckResult(
            "playbook",
            False,
            f"playbook missing AdversaryKind variants: {missing_kinds}",
            {"loc": loc, "missing_kinds": missing_kinds},
        )
    missing_ramps = [r for r in REQUIRED_RAMP_CURVES if r not in content]
    if missing_ramps:
        return CheckResult(
            "playbook",
            False,
            f"playbook missing RampCurve variants: {missing_ramps}",
            {"loc": loc, "missing_ramps": missing_ramps},
        )
    must_mention = [
        "DetectorThresholds",
        "bpet_adversarial_evolution_suite",
        "ScenarioVerdict",
    ]
    missing_terms = [t for t in must_mention if t not in content]
    if missing_terms:
        return CheckResult(
            "playbook",
            False,
            f"playbook missing required terms: {missing_terms}",
            {"loc": loc, "missing_terms": missing_terms},
        )
    return CheckResult(
        "playbook",
        True,
        f"docs/security/bpet_adversarial_playbook.md LOC={loc} documents all 8 kinds + 4 ramps + thresholds",
        {"loc": loc},
    )


def cargo_command(target_dir: str) -> list[str]:
    return [
        "rch",
        "exec",
        "--",
        "env",
        "CARGO_INCREMENTAL=0",
        "CARGO_BUILD_JOBS=1",
        f"CARGO_TARGET_DIR={target_dir}",
        "cargo",
        "test",
        "-p",
        "frankenengine-node",
        "--test",
        "bpet_adversarial_evolution_suite",
        "--",
        "--nocapture",
    ]


def run_cargo_check(timeout_seconds: int, target_dir: str) -> CheckResult:
    cmd = cargo_command(target_dir)
    env = os.environ.copy()
    try:
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        return CheckResult(
            "cargo_bpet_adversarial_evolution_suite",
            False,
            "rch executable not found",
            {"command": cmd},
        )
    except subprocess.TimeoutExpired as exc:
        return CheckResult(
            "cargo_bpet_adversarial_evolution_suite",
            False,
            f"timed out after {timeout_seconds}s",
            {
                "command": cmd,
                "stdout_tail": (exc.stdout or "")[-4000:],
                "stderr_tail": (exc.stderr or "")[-4000:],
            },
        )

    output = f"{completed.stdout}\n{completed.stderr}"
    passed = completed.returncode == 0
    message = (
        "rch cargo test --test bpet_adversarial_evolution_suite passed"
        if passed
        else "rch cargo test --test bpet_adversarial_evolution_suite failed"
    )
    return CheckResult(
        "cargo_bpet_adversarial_evolution_suite",
        passed,
        message,
        {
            "command": cmd,
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
            "observed_success_markers": [
                m
                for m in ["13 passed", "test result: ok", "bpet_adversarial_evolution_suite"]
                if m in output
            ],
        },
    )


def run_all_checks(run_cargo: bool, timeout_seconds: int, target_dir: str) -> list[CheckResult]:
    checks = [
        check_scenario_fixture_count(),
        check_scenario_schema(),
        check_evolution_source(),
        check_harness_source(),
        check_integration_suite(),
        check_playbook(),
    ]
    if run_cargo:
        checks.append(run_cargo_check(timeout_seconds, target_dir))
    else:
        checks.append(
            CheckResult(
                "cargo_bpet_adversarial_evolution_suite",
                True,
                "skipped by --skip-cargo; full gate must run this through rch before closeout",
                {"command": cargo_command(target_dir), "skipped": True},
            )
        )
    return checks


def output_payload(results: list[CheckResult], cargo_skipped: bool) -> dict[str, Any]:
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    if passed != total:
        verdict = "FAIL"
    elif cargo_skipped:
        verdict = "PASS_STATIC_ONLY"
    else:
        verdict = "PASS"
    return {
        "schema_version": "franken-node/verification-evidence/v1",
        "gate": "bpet_adversarial_evolution",
        "bead_id": BEAD_ID,
        "completion_debt_bead_id": COMPLETION_DEBT_BEAD_ID,
        "section": SECTION,
        "verdict": verdict,
        "passed": passed,
        "total": total,
        "cargo_skipped": cargo_skipped,
        "source_paths": [
            rel(EVOLUTION_SRC),
            rel(HARNESS_SRC),
            rel(SCENARIOS_SRC),
            rel(INTEGRATION_TEST),
            *[rel(SCENARIO_DIR / f"{spec['fixture']}.json") for spec in REQUIRED_ADVERSARY_KINDS.values()],
            rel(CARGO_TOML),
            rel(PLAYBOOK),
        ],
        "checks": [
            {
                "name": r.name,
                "passed": r.passed,
                "message": r.message,
                **({"details": r.details} if r.details else {}),
            }
            for r in results
        ],
    }


def self_test() -> bool:
    results = run_all_checks(
        run_cargo=False,
        timeout_seconds=1,
        target_dir="/tmp/franken-node-bpet-adversarial-selftest",
    )
    assert len(results) == 7
    assert all(isinstance(r.name, str) and r.name for r in results)
    assert all(isinstance(r.passed, bool) for r in results)
    payload = output_payload(results, cargo_skipped=True)
    assert payload["gate"] == "bpet_adversarial_evolution"
    assert payload["verdict"] in {"PASS_STATIC_ONLY", "FAIL"}
    return True


def main() -> int:
    configure_test_logging("check_bpet_adversarial_evolution")
    parser = argparse.ArgumentParser(description="BPET adversarial evolution verification gate")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--skip-cargo",
        action="store_true",
        help="skip the rch cargo test; for checker unit tests only",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run internal checker sanity checks",
    )
    parser.add_argument("--no-write", action="store_true", help="do not update the evidence JSON file")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument(
        "--target-dir",
        default="/data/tmp/franken_node-crimsoncrane-bdye4m-target",
        help="CARGO_TARGET_DIR passed to the rch cargo invocation",
    )
    args = parser.parse_args()

    if args.self_test:
        try:
            self_test()
        except AssertionError as exc:
            print(f"self_test: FAIL - {exc}")
            return 1
        print("self_test: PASS")
        return 0

    results = run_all_checks(
        run_cargo=not args.skip_cargo,
        timeout_seconds=args.timeout_seconds,
        target_dir=args.target_dir,
    )
    payload = output_payload(results, cargo_skipped=args.skip_cargo)

    if not args.no_write:
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            print(f"  [{status}] {r.name}: {r.message}")
        print(f"\n{payload['verdict']}: {payload['passed']}/{payload['total']} checks passed")

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
