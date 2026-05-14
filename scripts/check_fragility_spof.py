#!/usr/bin/env python3
"""Verification gate for bd-2jns DGIS maintainer/publisher fragility + SPOF.

This gate anchors bd-2jns to the real fragility-model implementation, the
real SPOF detector, the 10 fragility fixtures on disk, and the
Cargo-registered integration test that exercises all of them.

By default the gate runs the Rust integration test through rch. Unit tests
and CI smoke checks may pass --skip-cargo to validate the static contract
without launching a build.

Replaces the stale (fabricated) verification_evidence.json originally written
on 2026-02-22 with a real, machine-generated artifact.
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

BEAD_ID = "bd-2jns"
SECTION = "10.20"

FRAGILITY_MODEL_SRC = ROOT / "crates/franken-node/src/dgis/fragility_model.rs"
SPOF_DETECTION_SRC = ROOT / "crates/franken-node/src/dgis/spof_detection.rs"
FRAGILITY_FIXTURES_SRC = ROOT / "crates/franken-node/src/dgis/fragility_fixtures.rs"
INTEGRATION_TEST = ROOT / "tests/security/dgis_fragility_spof.rs"
FIXTURE_DIR = ROOT / "tests/security/fragility_fixtures"
CARGO_TOML = ROOT / "crates/franken-node/Cargo.toml"
EVIDENCE_PATH = ROOT / "artifacts/section_10_20/bd-2jns/verification_evidence.json"

SPOF_FIXTURES = [
    "single_maintainer_dominant",
    "key_person_high_share",
    "dependency_chain_fragile",
    "org_concentrated",
    "orphaned_pkg",
]

ROBUST_FIXTURES = [
    "well_distributed_maintainers",
    "diverse_org_ownership",
    "active_maintainers_recent_commits",
    "independent_packages_no_chains",
    "multi_quorum_publishers",
]

ALL_FIXTURES = SPOF_FIXTURES + ROBUST_FIXTURES

REQUIRED_FIXTURE_FIELDS = {
    "name",
    "description",
    "now_ms",
    "maintainers",
    "publishers",
    "nodes",
    "edges",
    "expected_findings",
}

REQUIRED_INTEGRATION_TESTS = [
    "test_single_maintainer_dominant_fixture_detects_spof",
    "test_key_person_high_share_fixture_detects_spof",
    "test_dependency_chain_fragile_fixture_detects_spof",
    "test_org_concentrated_fixture_detects_spof",
    "test_orphaned_pkg_fixture_detects_spof",
    "test_well_distributed_maintainers_is_robust",
    "test_diverse_org_ownership_is_robust",
    "test_active_maintainers_recent_commits_is_robust",
    "test_independent_packages_no_chains_is_robust",
    "test_multi_quorum_publishers_is_robust",
    "test_in_code_synthesizers_match_json_fixtures",
    "test_detect_spofs_deterministic_across_two_runs",
]


@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def check_fixture_directory() -> CheckResult:
    """Check 1: fixture directory exists and contains exactly 10 JSON files."""
    if not FIXTURE_DIR.exists() or not FIXTURE_DIR.is_dir():
        return CheckResult(
            "fixture_directory",
            False,
            f"fixture directory missing: {rel(FIXTURE_DIR)}",
        )
    json_files = sorted(p.stem for p in FIXTURE_DIR.glob("*.json"))
    expected = sorted(ALL_FIXTURES)
    if json_files != expected:
        return CheckResult(
            "fixture_directory",
            False,
            f"fixture set mismatch: found {len(json_files)}, expected {len(expected)}",
            {"found": json_files, "expected": expected,
             "missing": sorted(set(expected) - set(json_files)),
             "extra": sorted(set(json_files) - set(expected))},
        )
    return CheckResult(
        "fixture_directory",
        True,
        f"all {len(expected)} expected fixtures present "
        f"({len(SPOF_FIXTURES)} SPOF + {len(ROBUST_FIXTURES)} robust)",
        {"fixture_count": len(json_files), "fixtures": json_files},
    )


def check_fixture_schemas() -> CheckResult:
    """Check 2: every fixture parses + has required schema fields."""
    if not FIXTURE_DIR.exists():
        return CheckResult("fixture_schemas", False, "fixture directory missing")
    bad: list[dict[str, Any]] = []
    per_fixture: dict[str, dict[str, Any]] = {}
    for name in ALL_FIXTURES:
        path = FIXTURE_DIR / f"{name}.json"
        if not path.exists():
            bad.append({"fixture": name, "error": "missing on disk"})
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            bad.append({"fixture": name, "error": f"parse: {exc}"})
            continue
        if not isinstance(data, dict):
            bad.append({"fixture": name, "error": "top-level is not an object"})
            continue
        missing = sorted(REQUIRED_FIXTURE_FIELDS - set(data.keys()))
        if missing:
            bad.append({"fixture": name, "error": f"missing fields {missing}"})
            continue
        if data["name"] != name:
            bad.append({
                "fixture": name,
                "error": f"name field {data['name']!r} disagrees with filename",
            })
            continue
        if not isinstance(data["expected_findings"], list):
            bad.append({"fixture": name, "error": "expected_findings is not a list"})
            continue
        per_fixture[name] = {
            "now_ms": data["now_ms"],
            "maintainers": len(data["maintainers"]) if isinstance(data["maintainers"], dict) else 0,
            "publishers": len(data["publishers"]) if isinstance(data["publishers"], dict) else 0,
            "nodes": len(data["nodes"]) if isinstance(data["nodes"], list) else 0,
            "edges": len(data["edges"]) if isinstance(data["edges"], list) else 0,
            "expected_finding_count": len(data["expected_findings"]),
        }
    if bad:
        return CheckResult(
            "fixture_schemas",
            False,
            f"{len(bad)} fixture(s) failed schema validation",
            {"failures": bad, "per_fixture": per_fixture},
        )
    # Cross-class invariants: SPOF fixtures must declare >=1 expected finding,
    # robust fixtures must declare zero.
    invariant_failures: list[str] = []
    for name in SPOF_FIXTURES:
        if per_fixture[name]["expected_finding_count"] < 1:
            invariant_failures.append(f"{name}: SPOF fixture has no expected_findings")
    for name in ROBUST_FIXTURES:
        if per_fixture[name]["expected_finding_count"] != 0:
            invariant_failures.append(
                f"{name}: robust fixture has non-empty expected_findings"
            )
    if invariant_failures:
        return CheckResult(
            "fixture_schemas",
            False,
            "fixture class invariants violated",
            {"failures": invariant_failures, "per_fixture": per_fixture},
        )
    return CheckResult(
        "fixture_schemas",
        True,
        f"all {len(ALL_FIXTURES)} fixtures parse and satisfy class invariants",
        {"per_fixture": per_fixture},
    )


def _count_loc(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for _ in path.read_text(encoding="utf-8").splitlines())


def check_fragility_model() -> CheckResult:
    """Check 3: fragility_model.rs exists with substantive content."""
    if not FRAGILITY_MODEL_SRC.exists():
        return CheckResult(
            "fragility_model_source",
            False,
            f"missing source: {rel(FRAGILITY_MODEL_SRC)}",
        )
    content = FRAGILITY_MODEL_SRC.read_text(encoding="utf-8")
    loc = len(content.splitlines())
    test_blocks = content.count("#[test]")
    has_assess_maintainer = "fn assess_maintainer" in content
    has_assess_publisher = "fn assess_publisher" in content
    min_loc = 500
    min_tests = 5
    failures: list[str] = []
    if loc < min_loc:
        failures.append(f"LOC={loc} < {min_loc}")
    if test_blocks < min_tests:
        failures.append(f"#[test] count={test_blocks} < {min_tests}")
    if not has_assess_maintainer:
        failures.append("missing `fn assess_maintainer`")
    if not has_assess_publisher:
        failures.append("missing `fn assess_publisher`")
    if failures:
        return CheckResult(
            "fragility_model_source",
            False,
            f"fragility_model.rs contract violated: {failures}",
            {
                "loc": loc, "test_blocks": test_blocks,
                "has_assess_maintainer": has_assess_maintainer,
                "has_assess_publisher": has_assess_publisher,
            },
        )
    return CheckResult(
        "fragility_model_source",
        True,
        f"fragility_model.rs OK (LOC={loc}, #[test]={test_blocks})",
        {"loc": loc, "test_blocks": test_blocks, "path": rel(FRAGILITY_MODEL_SRC)},
    )


def check_spof_detection() -> CheckResult:
    """Check 4: spof_detection.rs exists with substantive content."""
    if not SPOF_DETECTION_SRC.exists():
        return CheckResult(
            "spof_detection_source",
            False,
            f"missing source: {rel(SPOF_DETECTION_SRC)}",
        )
    content = SPOF_DETECTION_SRC.read_text(encoding="utf-8")
    loc = len(content.splitlines())
    test_blocks = content.count("#[test]")
    has_detect = "fn detect_spofs" in content
    min_loc = 800
    failures: list[str] = []
    if loc < min_loc:
        failures.append(f"LOC={loc} < {min_loc}")
    if test_blocks < 5:
        failures.append(f"#[test] count={test_blocks} < 5")
    if not has_detect:
        failures.append("missing `fn detect_spofs`")
    if failures:
        return CheckResult(
            "spof_detection_source",
            False,
            f"spof_detection.rs contract violated: {failures}",
            {
                "loc": loc, "test_blocks": test_blocks,
                "has_detect_spofs": has_detect,
            },
        )
    return CheckResult(
        "spof_detection_source",
        True,
        f"spof_detection.rs OK (LOC={loc}, #[test]={test_blocks})",
        {"loc": loc, "test_blocks": test_blocks, "path": rel(SPOF_DETECTION_SRC)},
    )


def check_integration_test_and_cargo() -> CheckResult:
    """Check 5: integration test exists + is registered in Cargo.toml."""
    if not INTEGRATION_TEST.exists():
        return CheckResult(
            "integration_test_and_cargo",
            False,
            f"missing integration test: {rel(INTEGRATION_TEST)}",
        )
    if not CARGO_TOML.exists():
        return CheckResult(
            "integration_test_and_cargo",
            False,
            f"missing Cargo.toml: {rel(CARGO_TOML)}",
        )
    test_content = INTEGRATION_TEST.read_text(encoding="utf-8")
    cargo_content = CARGO_TOML.read_text(encoding="utf-8")
    missing_tests = [t for t in REQUIRED_INTEGRATION_TESTS if t not in test_content]
    test_blocks = test_content.count("#[test]")
    cargo_name = 'name = "dgis_fragility_spof"' in cargo_content
    cargo_path = 'path = "../../tests/security/dgis_fragility_spof.rs"' in cargo_content
    failures: list[str] = []
    if missing_tests:
        failures.append(f"missing test fns: {missing_tests}")
    if not cargo_name:
        failures.append('Cargo.toml missing `name = "dgis_fragility_spof"`')
    if not cargo_path:
        failures.append("Cargo.toml missing the matching `path = ...` line")
    if test_blocks < len(REQUIRED_INTEGRATION_TESTS):
        failures.append(
            f"#[test] count {test_blocks} < required {len(REQUIRED_INTEGRATION_TESTS)}"
        )
    if failures:
        return CheckResult(
            "integration_test_and_cargo",
            False,
            f"integration test or Cargo wiring incomplete: {failures}",
            {
                "missing_tests": missing_tests,
                "test_blocks": test_blocks,
                "cargo_name_present": cargo_name,
                "cargo_path_present": cargo_path,
            },
        )
    return CheckResult(
        "integration_test_and_cargo",
        True,
        f"integration test wired into Cargo.toml ({test_blocks} #[test] blocks, "
        f"all {len(REQUIRED_INTEGRATION_TESTS)} required tests present)",
        {
            "test_blocks": test_blocks,
            "test_path": rel(INTEGRATION_TEST),
        },
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
        "dgis_fragility_spof",
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
            "cargo_dgis_fragility_spof",
            False,
            "rch executable not found",
            {"command": cmd},
        )
    except subprocess.TimeoutExpired as exc:
        return CheckResult(
            "cargo_dgis_fragility_spof",
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
        "rch cargo test --test dgis_fragility_spof passed"
        if passed
        else "rch cargo test --test dgis_fragility_spof failed"
    )
    return CheckResult(
        "cargo_dgis_fragility_spof",
        passed,
        message,
        {
            "command": cmd,
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
            "observed_success_markers": [
                marker
                for marker in ["12 passed", "test result: ok", "dgis_fragility_spof"]
                if marker in output
            ],
        },
    )


def run_all_checks(
    run_cargo: bool,
    timeout_seconds: int,
    target_dir: str,
) -> list[CheckResult]:
    checks = [
        check_fixture_directory(),
        check_fixture_schemas(),
        check_fragility_model(),
        check_spof_detection(),
        check_integration_test_and_cargo(),
    ]
    if run_cargo:
        checks.append(run_cargo_check(timeout_seconds, target_dir))
    else:
        checks.append(
            CheckResult(
                "cargo_dgis_fragility_spof",
                True,
                "skipped by --skip-cargo; full gate must run this through rch "
                "before closeout",
                {"command": cargo_command(target_dir), "skipped": True},
            )
        )
    return checks


def head_sha() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return completed.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"


def output_payload(
    results: list[CheckResult],
    cargo_skipped: bool,
    sha: str,
) -> dict[str, Any]:
    passed = sum(1 for result in results if result.passed)
    total = len(results)
    if passed == total and not cargo_skipped:
        verdict = "PASS"
    elif passed == total:
        verdict = "PASS_STATIC_ONLY"
    else:
        verdict = "FAIL"
    return {
        "schema_version": "franken-node/verification-evidence/v1",
        "gate": "dgis_fragility_spof",
        "bead_id": BEAD_ID,
        "completion_debt_bead_id": "bd-2jns.1",
        "section": SECTION,
        "verdict": verdict,
        "passed": passed,
        "total": total,
        "cargo_skipped": cargo_skipped,
        "sha_at_evaluation": sha,
        "integration_test_name": "dgis_fragility_spof",
        "source_paths": [
            rel(FRAGILITY_MODEL_SRC),
            rel(SPOF_DETECTION_SRC),
            rel(FRAGILITY_FIXTURES_SRC),
            rel(INTEGRATION_TEST),
            rel(CARGO_TOML),
        ] + [
            rel(FIXTURE_DIR / f"{name}.json") for name in ALL_FIXTURES
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
        target_dir="/tmp/franken-node-dgis-fragility-spof-selftest",
    )
    assert len(results) == 6, f"expected 6 checks, got {len(results)}"
    assert all(isinstance(r.name, str) and r.name for r in results)
    assert all(isinstance(r.passed, bool) for r in results)
    payload = output_payload(results, cargo_skipped=True, sha="selftest")
    assert payload["verdict"] in {"PASS_STATIC_ONLY", "FAIL"}, payload["verdict"]
    assert payload["bead_id"] == BEAD_ID
    assert payload["completion_debt_bead_id"] == "bd-2jns.1"
    assert payload["integration_test_name"] == "dgis_fragility_spof"
    assert len(payload["source_paths"]) == 5 + len(ALL_FIXTURES)
    # The 10 fixture paths must each appear in source_paths so reviewers can
    # trace evidence back to ground truth.
    for name in ALL_FIXTURES:
        rel_fixture = rel(FIXTURE_DIR / f"{name}.json")
        assert rel_fixture in payload["source_paths"], f"missing {rel_fixture}"
    return True


def main() -> int:
    logger = configure_test_logging("check_fragility_spof")
    parser = argparse.ArgumentParser(
        description="DGIS maintainer/publisher fragility + SPOF verification gate"
    )
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON",
    )
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
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="do not write the evidence file; print to stdout instead",
    )
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument(
        "--target-dir",
        default="/data/tmp/franken_node-crimsoncrane-bd2jns-target",
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

    try:
        results = run_all_checks(
            run_cargo=not args.skip_cargo,
            timeout_seconds=args.timeout_seconds,
            target_dir=args.target_dir,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("gate execution error", extra={"error": str(exc)})
        print(f"ERROR: gate execution failure: {exc}", file=sys.stderr)
        return 2

    payload = output_payload(
        results,
        cargo_skipped=args.skip_cargo,
        sha=head_sha(),
    )

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for result in results:
            status = "PASS" if result.passed else "FAIL"
            print(f"  [{status}] {result.name}: {result.message}")
        print(
            f"\n{payload['verdict']}: {payload['passed']}/{payload['total']} "
            f"checks passed (sha={payload['sha_at_evaluation'][:12]})"
        )

    if not args.no_write and payload["verdict"] in {"PASS", "PASS_STATIC_ONLY"}:
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )
        logger.info(
            "wrote evidence",
            extra={"path": str(EVIDENCE_PATH), "verdict": payload["verdict"]},
        )

    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
