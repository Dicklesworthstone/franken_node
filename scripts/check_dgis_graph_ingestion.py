#!/usr/bin/env python3
"""Verification gate for bd-2bj4 DGIS graph ingestion.

This gate anchors bd-2bj4 to the real graph-ingestion implementation,
the realistic npm seed fixture, and the Cargo-registered integration test.
By default it runs the Rust integration test through rch. Unit tests may pass
--skip-cargo to validate the static contract without launching a build.
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

BEAD_ID = "bd-2bj4"
SECTION = "10.20"

GRAPH_INGESTION_SRC = ROOT / "crates/franken-node/src/dgis/graph_ingestion.rs"
GRAPH_SEEDS_SRC = ROOT / "crates/franken-node/src/dgis/graph_seeds.rs"
INTEGRATION_TEST = ROOT / "tests/security/dgis_graph_ingestion.rs"
SEED_FIXTURE = ROOT / "tests/security/graph_seeds/realistic_npm_topology.json"
CARGO_TOML = ROOT / "crates/franken-node/Cargo.toml"
EVIDENCE_PATH = ROOT / "artifacts/section_10_20/bd-2bj4/verification_evidence.json"

REQUIRED_TESTS = [
    "test_realistic_npm_topology_loads_from_json",
    "test_realistic_npm_topology_in_code_matches_json",
    "test_full_pipeline_yields_expected_node_count",
    "test_full_pipeline_yields_expected_edge_count",
    "test_pipeline_dedups_duplicate_observation",
    "test_pipeline_bounded_growth_rejects_overflow",
    "test_time_decay_weights_increase_for_newer_observations",
    "test_pipeline_is_deterministic_across_two_runs",
    "test_maintainer_overlap_produces_shared_maintainer_node",
    "test_dep_chain_of_length_3_present_in_topology",
    "test_pipeline_rejects_nan_weight_observation",
    "test_finalize_window_emits_canonical_btreemap_iteration_order",
]

REQUIRED_SYMBOLS = [
    "ManifestObservation",
    "IngestionPipeline",
    "WindowedGraph",
    "canonical_observation_bytes",
    "observation_hash",
    "finalize_window",
    "build_windowed_graph_from_seed",
    "load_seed_from_json",
    "seed_expected_invariants",
]


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
        GRAPH_INGESTION_SRC,
        GRAPH_SEEDS_SRC,
        INTEGRATION_TEST,
        SEED_FIXTURE,
        CARGO_TOML,
        EVIDENCE_PATH,
    ]
    missing = [rel(path) for path in paths if not path.exists()]
    if missing:
        return CheckResult("paths_exist", False, f"missing paths: {missing}", {"missing": missing})
    return CheckResult("paths_exist", True, "all bd-2bj4 implementation, test, and evidence paths exist")


def check_cargo_registration() -> CheckResult:
    if not CARGO_TOML.exists():
        return CheckResult("cargo_registration", False, "crates/franken-node/Cargo.toml missing")
    content = CARGO_TOML.read_text(encoding="utf-8")
    checks = {
        "test_name": 'name = "dgis_graph_ingestion"' in content,
        "test_path": 'path = "../../tests/security/dgis_graph_ingestion.rs"' in content,
    }
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        return CheckResult("cargo_registration", False, f"missing Cargo test wiring: {failed}", {"failed": failed})
    return CheckResult("cargo_registration", True, "dgis_graph_ingestion integration test is registered in Cargo.toml")


def check_rust_symbols() -> CheckResult:
    if not GRAPH_INGESTION_SRC.exists() or not GRAPH_SEEDS_SRC.exists():
        return CheckResult("rust_symbols", False, "source paths missing")
    content = GRAPH_INGESTION_SRC.read_text(encoding="utf-8") + "\n" + GRAPH_SEEDS_SRC.read_text(encoding="utf-8")
    missing = [symbol for symbol in REQUIRED_SYMBOLS if symbol not in content]
    if missing:
        return CheckResult("rust_symbols", False, f"missing required graph ingestion symbols: {missing}", {"missing": missing})
    hardening_markers = [
        "BTreeMap",
        "BTreeSet",
        "is_finite()",
        "saturating_add",
        "MAX_SEED_OBSERVATIONS",
        "CANONICAL_DOMAIN",
    ]
    missing_markers = [marker for marker in hardening_markers if marker not in content]
    if missing_markers:
        return CheckResult("rust_symbols", False, f"missing hardening markers: {missing_markers}", {"missing": missing_markers})
    return CheckResult(
        "rust_symbols",
        True,
        f"all {len(REQUIRED_SYMBOLS)} graph ingestion symbols and hardening markers are present",
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
        "ManifestObservation",
        "IngestionPipeline",
        "GraphSeed",
        "build_windowed_graph_from_seed",
        "load_seed_from_json",
        "realistic_npm_topology.json",
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


def load_seed() -> dict[str, Any]:
    with SEED_FIXTURE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def graph_invariants(seed: dict[str, Any]) -> dict[str, int]:
    observations = seed.get("observations", [])
    package_versions: set[tuple[str, str]] = set()
    maintainers: set[str] = set()
    dep_targets: set[str] = set()
    edges: set[tuple[str, str, str]] = set()
    observation_keys: set[str] = set()

    for obs in observations:
        package_name = str(obs["package_name"])
        version = str(obs["version"])
        package_versions.add((package_name, version))
        package_id = f"pkg:{package_name}@{version}"
        observation_keys.add(
            json.dumps(obs, sort_keys=True, separators=(",", ":"))
        )
        for maintainer in obs.get("maintainers", []):
            maintainer = str(maintainer)
            maintainers.add(maintainer)
            edges.add((package_id, f"mnt:{maintainer}", "MaintainedBy"))
        for dep_name in obs.get("dependencies", {}).keys():
            dep_name = str(dep_name)
            dep_targets.add(dep_name)
            edges.add((package_id, f"dep:{dep_name}", "Depends"))

    return {
        "total_observations": len(observations),
        "expected_unique_observations": len(observation_keys),
        "expected_unique_package_versions": len(package_versions),
        "expected_unique_maintainers": len(maintainers),
        "expected_unique_dependency_targets": len(dep_targets),
        "min_total_nodes": len(package_versions) + len(maintainers) + len(dep_targets),
        "min_total_edges": len(edges),
    }


def check_seed_fixture() -> CheckResult:
    if not SEED_FIXTURE.exists():
        return CheckResult("seed_fixture", False, "realistic npm seed fixture missing")
    try:
        seed = load_seed()
    except (OSError, json.JSONDecodeError) as exc:
        return CheckResult("seed_fixture", False, f"seed fixture failed to load: {exc}")

    required_top_level = {"name", "description", "window_start_ms", "window_end_ms", "observations"}
    missing = sorted(required_top_level.difference(seed.keys()))
    if missing:
        return CheckResult("seed_fixture", False, f"seed fixture missing keys: {missing}", {"missing": missing})
    if seed["name"] != "realistic_npm_topology":
        return CheckResult("seed_fixture", False, f"unexpected seed name: {seed['name']}")
    if seed["window_end_ms"] < seed["window_start_ms"]:
        return CheckResult("seed_fixture", False, "seed fixture has inverted window")

    invariants = graph_invariants(seed)
    thresholds = {
        "total_observations": 50,
        "expected_unique_package_versions": 10,
        "expected_unique_maintainers": 6,
        "min_total_nodes": 25,
        "min_total_edges": 20,
    }
    failed = [
        f"{name}={invariants[name]} < {minimum}"
        for name, minimum in thresholds.items()
        if invariants[name] < minimum
    ]
    if failed:
        return CheckResult("seed_fixture", False, f"seed fixture invariants too weak: {failed}", {"invariants": invariants})
    return CheckResult(
        "seed_fixture",
        True,
        "realistic npm seed fixture loads and exposes non-trivial WindowedGraph invariants",
        {"invariants": invariants, "path": rel(SEED_FIXTURE)},
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
        "dgis_graph_ingestion",
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
        return CheckResult("cargo_dgis_graph_ingestion", False, "rch executable not found", {"command": cmd})
    except subprocess.TimeoutExpired as exc:
        return CheckResult(
            "cargo_dgis_graph_ingestion",
            False,
            f"timed out after {timeout_seconds}s",
            {"command": cmd, "stdout_tail": (exc.stdout or "")[-4000:], "stderr_tail": (exc.stderr or "")[-4000:]},
        )

    output = f"{completed.stdout}\n{completed.stderr}"
    passed = completed.returncode == 0
    message = "rch cargo test --test dgis_graph_ingestion passed" if passed else "rch cargo test --test dgis_graph_ingestion failed"
    return CheckResult(
        "cargo_dgis_graph_ingestion",
        passed,
        message,
        {
            "command": cmd,
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
            "observed_success_markers": [
                marker
                for marker in ["12 passed", "test result: ok", "dgis_graph_ingestion"]
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
        check_seed_fixture(),
    ]
    if run_cargo:
        checks.append(run_cargo_check(timeout_seconds, target_dir))
    else:
        checks.append(
            CheckResult(
                "cargo_dgis_graph_ingestion",
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
        "gate": "dgis_graph_ingestion",
        "bead_id": BEAD_ID,
        "completion_debt_bead_id": "bd-2bj4.1",
        "section": SECTION,
        "verdict": "PASS" if passed == total and not cargo_skipped else "PASS_STATIC_ONLY" if passed == total else "FAIL",
        "passed": passed,
        "total": total,
        "cargo_skipped": cargo_skipped,
        "source_paths": [
            rel(GRAPH_INGESTION_SRC),
            rel(GRAPH_SEEDS_SRC),
            rel(INTEGRATION_TEST),
            rel(SEED_FIXTURE),
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
    results = run_all_checks(run_cargo=False, timeout_seconds=1, target_dir="/tmp/franken-node-dgis-graph-ingestion-selftest")
    assert len(results) == 6
    assert all(isinstance(result.name, str) and result.name for result in results)
    assert all(isinstance(result.passed, bool) for result in results)
    payload = output_payload(results, cargo_skipped=True)
    assert payload["verdict"] in {"PASS_STATIC_ONLY", "FAIL"}
    return True


def main() -> int:
    configure_test_logging("check_dgis_graph_ingestion")
    parser = argparse.ArgumentParser(description="DGIS graph ingestion verification gate")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--skip-cargo", action="store_true", help="skip the rch cargo test; for checker unit tests only")
    parser.add_argument("--self-test", action="store_true", help="run internal checker sanity checks")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument(
        "--target-dir",
        default="/data/tmp/franken_node-snowybeaver-bd2bj4-target",
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
