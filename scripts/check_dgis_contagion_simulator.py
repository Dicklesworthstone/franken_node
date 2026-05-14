#!/usr/bin/env python3
"""Verification gate for bd-1q38 DGIS adversarial contagion simulator.

This gate anchors bd-1q38.1 sub-task 5 to the real contagion graph,
simulator, profile-loader implementation, the three shipped adversarial
campaign fixtures, and the Cargo-registered integration test. By default it
runs the Rust integration test through rch. Unit tests may pass --skip-cargo
to validate the static contract without launching a build.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-1q38"
COMPLETION_DEBT_BEAD_ID = "bd-1q38.1"
SECTION = "10.20"

CONTAGION_GRAPH_SRC = ROOT / "crates/franken-node/src/dgis/contagion_graph.rs"
CONTAGION_SIMULATOR_SRC = ROOT / "crates/franken-node/src/dgis/contagion_simulator.rs"
CONTAGION_PROFILES_SRC = ROOT / "crates/franken-node/src/dgis/contagion_profiles.rs"
INTEGRATION_TEST = ROOT / "tests/security/dgis_contagion_simulator.rs"
PROFILE_DIR = ROOT / "tests/security/contagion_profiles"
CARGO_TOML = ROOT / "crates/franken-node/Cargo.toml"
EVIDENCE_PATH = ROOT / "artifacts/section_10_20/bd-1q38/verification_evidence.json"

REQUIRED_FIXTURES = [
    "xz_style.json",
    "dependency_confusion.json",
    "typosquat.json",
]

REQUIRED_TESTS = [
    "test_xz_style_profile_evaluates_to_pass",
    "test_dependency_confusion_profile_evaluates_to_pass",
    "test_typosquat_profile_evaluates_to_pass",
    "test_all_profiles_deterministic_across_two_runs",
    "test_profile_with_missing_node_fails_evaluation",
    "test_profile_with_nan_weight_rejected_at_load",
    "test_full_spread_termination_reached",
    "test_no_spread_termination_when_no_edges",
]

REQUIRED_SYMBOLS = [
    "ContagionGraph",
    "ContagionEdge",
    "EdgeKind",
    "InfectionState",
    "SimulatorConfig",
    "SimulationTrace",
    "TerminationReason",
    "ContagionProfile",
    "ProfileGraphSpec",
    "ProfileEdgeSpec",
    "ExpectedOutcome",
    "ProfileVerdict",
    "ProfileError",
    "load_profile_from_json",
    "build_graph_from_spec",
    "evaluate_profile",
    "simulate",
    "detect_termination",
]

EXPECTED_PROFILE_INVARIANTS = {
    "xz_style": {
        "nodes": 20,
        "edges": 18,
        "initial_infected": 1,
        "termination_reason": "Converged",
        "min_infected_count": 18,
        "max_infected_count": 19,
        "terminated_by_step": 50,
    },
    "dependency_confusion": {
        "nodes": 15,
        "edges": 12,
        "initial_infected": 1,
        "termination_reason": "Converged",
        "min_infected_count": 8,
        "max_infected_count": 10,
        "terminated_by_step": 20,
    },
    "typosquat": {
        "nodes": 30,
        "edges": 16,
        "initial_infected": 5,
        "termination_reason": "Converged",
        "min_infected_count": 9,
        "max_infected_count": 11,
        "terminated_by_step": 30,
    },
}


@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def check_paths_exist() -> CheckResult:
    paths = [
        CONTAGION_GRAPH_SRC,
        CONTAGION_SIMULATOR_SRC,
        CONTAGION_PROFILES_SRC,
        INTEGRATION_TEST,
        PROFILE_DIR,
        CARGO_TOML,
        EVIDENCE_PATH,
        *[PROFILE_DIR / fixture for fixture in REQUIRED_FIXTURES],
    ]
    missing = [rel(path) for path in paths if not path.exists()]
    if missing:
        return CheckResult("paths_exist", False, f"missing paths: {missing}", {"missing": missing})
    return CheckResult(
        "paths_exist",
        True,
        "all bd-1q38 implementation, fixture, test, and evidence paths exist",
    )


def check_cargo_registration() -> CheckResult:
    if not CARGO_TOML.exists():
        return CheckResult("cargo_registration", False, "crates/franken-node/Cargo.toml missing")
    content = CARGO_TOML.read_text(encoding="utf-8")
    checks = {
        "test_name": 'name = "dgis_contagion_simulator"' in content,
        "test_path": 'path = "../../tests/security/dgis_contagion_simulator.rs"' in content,
    }
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        return CheckResult("cargo_registration", False, f"missing Cargo test wiring: {failed}", {"failed": failed})
    return CheckResult("cargo_registration", True, "dgis_contagion_simulator integration test is registered in Cargo.toml")


def check_rust_symbols() -> CheckResult:
    sources = [CONTAGION_GRAPH_SRC, CONTAGION_SIMULATOR_SRC, CONTAGION_PROFILES_SRC]
    missing_paths = [rel(path) for path in sources if not path.exists()]
    if missing_paths:
        return CheckResult("rust_symbols", False, f"source paths missing: {missing_paths}", {"missing": missing_paths})

    content = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    missing = [symbol for symbol in REQUIRED_SYMBOLS if symbol not in content]
    if missing:
        return CheckResult("rust_symbols", False, f"missing required contagion symbols: {missing}", {"missing": missing})

    hardening_markers = [
        "BTreeMap",
        "BTreeSet",
        "is_finite()",
        "saturating_add",
        "MAX_PROFILE_NODES",
        "MAX_PROFILE_EDGES",
        "MAX_INITIAL_INFECTED",
        "MAX_SIMULATION_STEPS",
        "InvalidWeight",
        "BoundedGrowthExceeded",
        "UnknownNode",
    ]
    missing_markers = [marker for marker in hardening_markers if marker not in content]
    if missing_markers:
        return CheckResult("rust_symbols", False, f"missing hardening markers: {missing_markers}", {"missing": missing_markers})
    return CheckResult(
        "rust_symbols",
        True,
        f"all {len(REQUIRED_SYMBOLS)} contagion symbols and hardening markers are present",
    )


def check_integration_tests() -> CheckResult:
    if not INTEGRATION_TEST.exists():
        return CheckResult("integration_tests", False, "integration test missing")
    content = INTEGRATION_TEST.read_text(encoding="utf-8")
    missing = [test for test in REQUIRED_TESTS if test not in content]
    total_tests = content.count("#[test]")
    if missing:
        return CheckResult(
            "integration_tests",
            False,
            f"missing required integration tests: {missing}",
            {"missing": missing, "total_tests": total_tests},
        )

    real_path_markers = [
        "ContagionGraph",
        "ContagionEdge",
        "build_graph_from_spec",
        "evaluate_profile",
        "load_profile_from_json",
        "simulate",
        "detect_termination",
        "xz_style",
        "dependency_confusion",
        "typosquat",
    ]
    missing_markers = [marker for marker in real_path_markers if marker not in content]
    if missing_markers:
        return CheckResult("integration_tests", False, f"missing real-path markers: {missing_markers}", {"missing": missing_markers})
    return CheckResult(
        "integration_tests",
        True,
        f"all {len(REQUIRED_TESTS)} required integration tests are present",
        {"total_tests": total_tests},
    )


def load_profile(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        return json.JSONDecoder().decode(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{rel(path)} failed to load JSON: {exc}") from exc


def fixture_invariants(profile: dict[str, Any]) -> dict[str, Any]:
    graph = profile["graph"]
    expected = profile["expected"]
    return {
        "nodes": len(graph["nodes"]),
        "edges": len(graph["edges"]),
        "initial_infected": len(profile["initial_infected"]),
        "termination_reason": expected["termination_reason"],
        "min_infected_count": expected["min_infected_count"],
        "max_infected_count": expected["max_infected_count"],
        "terminated_by_step": expected["terminated_by_step"],
    }


def validate_profile_shape(profile: dict[str, Any], path: Path) -> list[str]:
    failures: list[str] = []
    required_top_level = {"name", "description", "graph", "initial_infected", "config", "expected"}
    missing = sorted(required_top_level.difference(profile.keys()))
    if missing:
        return [f"{rel(path)} missing top-level keys: {missing}"]

    graph = profile["graph"]
    graph_nodes = graph.get("nodes", [])
    graph_edges = graph.get("edges", [])
    node_set = set(graph_nodes)
    if not graph_nodes:
        failures.append(f"{rel(path)} has no graph nodes")
    if len(node_set) != len(graph_nodes):
        failures.append(f"{rel(path)} contains duplicate graph nodes")

    for seed in profile.get("initial_infected", []):
        if seed not in node_set:
            failures.append(f"{rel(path)} initial_infected references unknown node {seed}")

    for idx, edge in enumerate(graph_edges):
        for endpoint in ["from", "to"]:
            if edge.get(endpoint) not in node_set:
                failures.append(f"{rel(path)} edge {idx} unknown {endpoint}={edge.get(endpoint)}")
        weight = edge.get("weight")
        if not isinstance(weight, (int, float)) or not math.isfinite(float(weight)):
            failures.append(f"{rel(path)} edge {idx} has non-finite weight")
        elif float(weight) < 0.0 or float(weight) > 1.0:
            failures.append(f"{rel(path)} edge {idx} weight outside [0,1]: {weight}")

    expected = profile["expected"]
    min_count = expected.get("min_infected_count")
    max_count = expected.get("max_infected_count")
    if not isinstance(min_count, int) or not isinstance(max_count, int) or min_count > max_count:
        failures.append(f"{rel(path)} expected infected count range is invalid")
    elif max_count > len(graph_nodes):
        failures.append(f"{rel(path)} expected max_infected_count exceeds node count")

    config = profile["config"]
    for key in ["infection_threshold", "decay_factor"]:
        value = config.get(key)
        if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            failures.append(f"{rel(path)} config {key} is non-finite")
        elif float(value) < 0.0 or float(value) > 1.0:
            failures.append(f"{rel(path)} config {key} outside [0,1]: {value}")

    return failures


def check_profile_fixtures() -> CheckResult:
    if not PROFILE_DIR.exists():
        return CheckResult("profile_fixtures", False, "contagion profile fixture directory missing")

    loaded: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    edge_kinds: Counter[str] = Counter()
    for fixture_name in REQUIRED_FIXTURES:
        path = PROFILE_DIR / fixture_name
        try:
            profile = load_profile(path)
        except (OSError, ValueError) as exc:
            failures.append(f"{rel(path)} failed to load: {exc}")
            continue

        profile_name = profile.get("name")
        if profile_name not in EXPECTED_PROFILE_INVARIANTS:
            failures.append(f"{rel(path)} has unexpected profile name {profile_name!r}")
            continue
        loaded[profile_name] = profile
        failures.extend(validate_profile_shape(profile, path))
        edge_kinds.update(str(edge.get("edge_kind")) for edge in profile["graph"]["edges"])

    missing_profiles = sorted(set(EXPECTED_PROFILE_INVARIANTS).difference(loaded))
    if missing_profiles:
        failures.append(f"missing expected profiles: {missing_profiles}")

    profiles: dict[str, dict[str, Any]] = {}
    for name, expected in EXPECTED_PROFILE_INVARIANTS.items():
        if name not in loaded:
            continue
        actual = fixture_invariants(loaded[name])
        profiles[name] = actual
        if actual != expected:
            failures.append(f"{name} invariants changed: expected {expected}, got {actual}")

    aggregate = {
        "profile_count": len(loaded),
        "total_nodes": sum(item["nodes"] for item in profiles.values()),
        "total_edges": sum(item["edges"] for item in profiles.values()),
        "total_initial_infected": sum(item["initial_infected"] for item in profiles.values()),
        "total_expected_min_infected": sum(item["min_infected_count"] for item in profiles.values()),
        "total_expected_max_infected": sum(item["max_infected_count"] for item in profiles.values()),
        "edge_kinds": dict(sorted(edge_kinds.items())),
    }
    expected_aggregate = {
        "profile_count": 3,
        "total_nodes": 65,
        "total_edges": 46,
        "total_initial_infected": 7,
        "total_expected_min_infected": 35,
        "total_expected_max_infected": 40,
        "edge_kinds": {
            "DependencyImport": 35,
            "MaintainerOverlap": 2,
            "NamespaceShadow": 9,
        },
    }
    if aggregate != expected_aggregate:
        failures.append(f"aggregate fixture invariants changed: expected {expected_aggregate}, got {aggregate}")

    details = {
        "profiles": profiles,
        "aggregate": aggregate,
        "fixture_paths": [rel(PROFILE_DIR / fixture) for fixture in REQUIRED_FIXTURES],
    }
    if failures:
        return CheckResult("profile_fixtures", False, f"profile fixture validation failed: {failures}", {**details, "failures": failures})
    return CheckResult(
        "profile_fixtures",
        True,
        "three adversarial campaign profile fixtures load and expose exact non-trivial invariants",
        details,
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
        "dgis_contagion_simulator",
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
        return CheckResult("cargo_dgis_contagion_simulator", False, "rch executable not found", {"command": cmd})
    except subprocess.TimeoutExpired as exc:
        return CheckResult(
            "cargo_dgis_contagion_simulator",
            False,
            f"timed out after {timeout_seconds}s",
            {"command": cmd, "stdout_tail": (exc.stdout or "")[-4000:], "stderr_tail": (exc.stderr or "")[-4000:]},
        )

    output = f"{completed.stdout}\n{completed.stderr}"
    passed = completed.returncode == 0
    message = (
        "rch cargo test --test dgis_contagion_simulator passed"
        if passed
        else "rch cargo test --test dgis_contagion_simulator failed"
    )
    return CheckResult(
        "cargo_dgis_contagion_simulator",
        passed,
        message,
        {
            "command": cmd,
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
            "observed_success_markers": [
                marker
                for marker in ["8 passed", "test result: ok", "dgis_contagion_simulator"]
                if marker in output
            ],
        },
    )


def run_all_checks(run_cargo: bool, timeout_seconds: int, target_dir: str) -> list[CheckResult]:
    checks = [
        check_paths_exist(),
        check_cargo_registration(),
        check_rust_symbols(),
        check_integration_tests(),
        check_profile_fixtures(),
    ]
    if run_cargo:
        checks.append(run_cargo_check(timeout_seconds, target_dir))
    else:
        checks.append(
            CheckResult(
                "cargo_dgis_contagion_simulator",
                True,
                "skipped by --skip-cargo; full gate must run this through rch before closeout",
                {"command": cargo_command(target_dir), "skipped": True},
            )
        )
    return checks


def output_payload(results: list[CheckResult], cargo_skipped: bool) -> dict[str, Any]:
    passed = sum(1 for result in results if result.passed)
    total = len(results)
    return {
        "schema_version": "franken-node/verification-evidence/v1",
        "gate": "dgis_contagion_simulator",
        "bead_id": BEAD_ID,
        "completion_debt_bead_id": COMPLETION_DEBT_BEAD_ID,
        "section": SECTION,
        "verdict": "PASS" if passed == total and not cargo_skipped else "PASS_STATIC_ONLY" if passed == total else "FAIL",
        "passed": passed,
        "total": total,
        "cargo_skipped": cargo_skipped,
        "source_paths": [
            rel(CONTAGION_GRAPH_SRC),
            rel(CONTAGION_SIMULATOR_SRC),
            rel(CONTAGION_PROFILES_SRC),
            rel(INTEGRATION_TEST),
            *[rel(PROFILE_DIR / fixture) for fixture in REQUIRED_FIXTURES],
            rel(CARGO_TOML),
        ],
        "checks": [
            {
                "name": result.name,
                "passed": result.passed,
                "message": result.message,
                **({"details": result.details} if result.details else {}),
            }
            for result in results
        ],
    }


def self_test() -> bool:
    results = run_all_checks(
        run_cargo=False,
        timeout_seconds=1,
        target_dir="/tmp/franken-node-dgis-contagion-simulator-selftest",
    )
    assert len(results) == 6
    assert all(isinstance(result.name, str) and result.name for result in results)
    assert all(isinstance(result.passed, bool) for result in results)
    payload = output_payload(results, cargo_skipped=True)
    assert payload["gate"] == "dgis_contagion_simulator"
    assert payload["verdict"] in {"PASS_STATIC_ONLY", "FAIL"}
    return True


def main() -> int:
    configure_test_logging("check_dgis_contagion_simulator")
    parser = argparse.ArgumentParser(description="DGIS contagion simulator verification gate")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--skip-cargo", action="store_true", help="skip the rch cargo test; for checker unit tests only")
    parser.add_argument("--self-test", action="store_true", help="run internal checker sanity checks")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument(
        "--target-dir",
        default="/data/tmp/franken_node-snowybeaver-bd1q38-target",
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

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for result in results:
            status = "PASS" if result.passed else "FAIL"
            print(f"  [{status}] {result.name}: {result.message}")
        print(f"\n{payload['verdict']}: {payload['passed']}/{payload['total']} checks passed")

    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
