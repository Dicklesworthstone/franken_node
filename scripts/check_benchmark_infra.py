#!/usr/bin/env python3
"""Verification script for bd-f5d benchmark campaign infrastructure."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any


BEAD_ID = "bd-f5d"
SECTION = "10.9"
TITLE = "Build public Node/Bun/franken_node benchmark campaign infrastructure"

CONTRACT = ROOT / "docs" / "specs" / "section_10_9" / "bd-f5d_contract.md"
METHODOLOGY = ROOT / "docs" / "policy" / "benchmark_campaign_methodology.md"
MANIFEST = ROOT / "fixtures" / "benchmarks" / "campaign_manifest.json"
DATASET_CATALOG = ROOT / "fixtures" / "benchmarks" / "dataset_catalog.json"
BASELINE = ROOT / "fixtures" / "benchmarks" / "campaign_results_baseline.json"
CANDIDATE = ROOT / "fixtures" / "benchmarks" / "campaign_results_candidate.json"
CHART_SPEC = ROOT / "fixtures" / "benchmarks" / "chart_spec.json"
RUNNER = ROOT / "scripts" / "run_benchmark_campaign.sh"

OUT_DIR = ROOT / "artifacts" / "section_10_9" / BEAD_ID
RUN_OUTPUT = OUT_DIR / "campaign_run.json"
DIFF_OUTPUT = OUT_DIR / "diff_report.json"
REPORT_OUTPUT = OUT_DIR / "public_report.md"

REQUIRED_WORKLOADS = {
    "http_server_throughput",
    "module_loading",
    "cold_start",
    "json_processing",
    "file_io",
    "child_process_spawning",
    "stream_throughput",
    "crypto_operations",
    "url_parsing",
    "compatibility_shim_overhead",
}

REQUIRED_DIMENSIONS = {
    "compatibility_correctness",
    "performance",
    "containment_revocation_latency",
    "replay_determinism",
    "adversarial_resilience",
    "migration_speed_failure_rate",
}

REQUIRED_EVENT_CODES = ["BCI-001", "BCI-002", "BCI-003", "BCI-004", "BCI-005"]


def check_file(path: Path, label: str) -> dict[str, Any]:
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def load_json(path: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if not path.exists():
        return None, {"check": f"json: {path.relative_to(ROOT)}", "pass": False, "detail": "MISSING"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, {"check": f"json: {path.relative_to(ROOT)}", "pass": False, "detail": "invalid-json"}
    return payload, {"check": f"json: {path.relative_to(ROOT)}", "pass": True, "detail": "valid"}


def check_contract() -> list[dict[str, Any]]:
    checks = [check_file(CONTRACT, "contract")]
    if not CONTRACT.exists():
        return checks
    text = CONTRACT.read_text(encoding="utf-8")
    for token in ["INV-BCI-WORKLOADS", "INV-BCI-RUNTIMES", "INV-BCI-REPRODUCIBLE", "INV-BCI-METRICS", "INV-BCI-TARGETS", "INV-BCI-RERUN"]:
        checks.append({"check": f"contract: {token}", "pass": token in text, "detail": "present" if token in text else "MISSING"})
    for code in REQUIRED_EVENT_CODES:
        checks.append({"check": f"contract: event code {code}", "pass": code in text, "detail": "present" if code in text else "MISSING"})
    return checks


def metric_shape_ok(runtime_metrics: dict[str, Any]) -> bool:
    latency = runtime_metrics.get("latency_ms", {})
    required = {"mean", "median", "p95", "p99"}
    return required.issubset(latency.keys()) and "throughput_rps" in runtime_metrics


def check_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    workloads = set(manifest.get("workloads", []))
    checks.append({"check": "manifest: >=10 workloads", "pass": len(workloads) >= 10, "detail": f"count={len(workloads)}"})
    checks.append({"check": "manifest: required workloads present", "pass": REQUIRED_WORKLOADS.issubset(workloads), "detail": "all present" if REQUIRED_WORKLOADS.issubset(workloads) else f"missing={sorted(REQUIRED_WORKLOADS - workloads)}"})

    runtimes = set(manifest.get("runtimes", {}).keys())
    checks.append({"check": "manifest: runtimes include node/bun/franken_node", "pass": {"node", "bun", "franken_node"}.issubset(runtimes), "detail": f"runtimes={sorted(runtimes)}"})

    dimensions = set(manifest.get("dimensions", []))
    checks.append({"check": "manifest: required dimensions present", "pass": REQUIRED_DIMENSIONS.issubset(dimensions), "detail": "all present" if REQUIRED_DIMENSIONS.issubset(dimensions) else f"missing={sorted(REQUIRED_DIMENSIONS - dimensions)}"})

    methodology = manifest.get("methodology", {})
    methodology_ok = (
        int(methodology.get("warmup_iterations", 0)) > 0
        and int(methodology.get("measurement_iterations", 0)) > 0
        and str(methodology.get("outlier_policy", "")).strip() != ""
        and str(methodology.get("confidence_interval", "")).strip() != ""
    )
    checks.append({"check": "manifest: methodology populated", "pass": methodology_ok, "detail": "valid" if methodology_ok else "invalid methodology"})

    container = manifest.get("container", {})
    container_ok = "image" in container and "digest" in container and str(container.get("digest", "")).startswith("sha256:")
    checks.append({"check": "manifest: hermetic container provenance", "pass": container_ok, "detail": "valid" if container_ok else "missing image/digest"})

    return checks


def check_campaign_results(result_payload: dict[str, Any], label: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    workloads = result_payload.get("workloads", [])
    checks.append({"check": f"{label}: workload rows >=10", "pass": len(workloads) >= 10, "detail": f"count={len(workloads)}"})

    shape_ok = True
    missing = []
    for row in workloads:
        name = row.get("name")
        metrics = row.get("metrics", {})
        for runtime in ["node", "bun", "franken_node"]:
            if runtime not in metrics or not metric_shape_ok(metrics[runtime]):
                shape_ok = False
                missing.append(f"{name}:{runtime}")
    checks.append({"check": f"{label}: per-runtime metric shape (mean/median/p95/p99/throughput)", "pass": shape_ok, "detail": "valid" if shape_ok else f"missing={missing[:5]}"})

    targets = result_payload.get("targets", {})
    targets_present = {"compatibility_pct", "migration_velocity_x", "compromise_reduction_x"}.issubset(targets.keys())
    checks.append({"check": f"{label}: category target fields present", "pass": targets_present, "detail": f"targets={sorted(targets.keys())}"})

    if label == "candidate":
        checks.append({"check": "candidate: compatibility >=95%", "pass": float(targets.get("compatibility_pct", 0.0)) >= 95.0, "detail": f"value={targets.get('compatibility_pct')}"})
        checks.append({"check": "candidate: migration velocity >=3x", "pass": float(targets.get("migration_velocity_x", 0.0)) >= 3.0, "detail": f"value={targets.get('migration_velocity_x')}"})
        checks.append({"check": "candidate: compromise reduction >=10x", "pass": float(targets.get("compromise_reduction_x", 0.0)) >= 10.0, "detail": f"value={targets.get('compromise_reduction_x')}"})

    return checks


def run_campaign_runner() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = [check_file(RUNNER, "campaign runner")]
    if not RUNNER.exists():
        return checks

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for path in [RUN_OUTPUT, DIFF_OUTPUT, REPORT_OUTPUT]:
        if path.exists():
            path.unlink()

    proc = subprocess.run(
        [
            str(RUNNER),
            "--baseline",
            str(BASELINE.relative_to(ROOT)),
            "--candidate",
            str(CANDIDATE.relative_to(ROOT)),
            "--output",
            str(RUN_OUTPUT.relative_to(ROOT)),
            "--diff-output",
            str(DIFF_OUTPUT.relative_to(ROOT)),
            "--report-output",
            str(REPORT_OUTPUT.relative_to(ROOT)),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=3600,
    )
    checks.append({"check": "runner: execution exit code", "pass": proc.returncode == 0, "detail": f"code={proc.returncode}"})

    for label, path in [("runner output", RUN_OUTPUT), ("runner diff", DIFF_OUTPUT), ("runner report", REPORT_OUTPUT)]:
        checks.append(check_file(path, label))

    if REPORT_OUTPUT.exists():
        text = REPORT_OUTPUT.read_text(encoding="utf-8")
        checks.append({"check": "runner report: contains table", "pass": "| Workload |" in text, "detail": "present" if "| Workload |" in text else "missing"})
        checks.append({"check": "runner report: highlights category targets", "pass": "Category-Defining Targets" in text, "detail": "present" if "Category-Defining Targets" in text else "missing"})

    # Determinism: running twice with identical inputs should keep identical output.
    if RUN_OUTPUT.exists():
        first = RUN_OUTPUT.read_bytes()
        proc2 = subprocess.run(
            [
                str(RUNNER),
                "--baseline",
                str(BASELINE.relative_to(ROOT)),
                "--candidate",
                str(CANDIDATE.relative_to(ROOT)),
                "--output",
                str(RUN_OUTPUT.relative_to(ROOT)),
                "--diff-output",
                str(DIFF_OUTPUT.relative_to(ROOT)),
                "--report-output",
                str(REPORT_OUTPUT.relative_to(ROOT)),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        second = RUN_OUTPUT.read_bytes() if RUN_OUTPUT.exists() else b""
        checks.append({"check": "runner: deterministic campaign output", "pass": proc2.returncode == 0 and first == second, "detail": "stable" if proc2.returncode == 0 and first == second else "unstable"})

    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    checks.extend(check_contract())
    checks.append(check_file(METHODOLOGY, "methodology policy"))

    manifest, manifest_check = load_json(MANIFEST)
    checks.append(manifest_check)
    if manifest:
        checks.extend(check_manifest(manifest))

    catalog, catalog_check = load_json(DATASET_CATALOG)
    checks.append(catalog_check)
    if catalog:
        datasets = catalog.get("datasets", [])
        checks.append({"check": "dataset catalog: datasets >=3", "pass": isinstance(datasets, list) and len(datasets) >= 3, "detail": f"count={len(datasets) if isinstance(datasets, list) else 0}"})
        hashes_ok = isinstance(datasets, list) and all(str(item.get("sha256", "")).strip() for item in datasets)
        checks.append({"check": "dataset catalog: integrity hashes present", "pass": hashes_ok, "detail": "all present" if hashes_ok else "missing hashes"})

    baseline_payload, baseline_check = load_json(BASELINE)
    checks.append(baseline_check)
    if baseline_payload:
        checks.extend(check_campaign_results(baseline_payload, "baseline"))

    candidate_payload, candidate_check = load_json(CANDIDATE)
    checks.append(candidate_check)
    if candidate_payload:
        checks.extend(check_campaign_results(candidate_payload, "candidate"))

    chart_payload, chart_check = load_json(CHART_SPEC)
    checks.append(chart_check)
    if chart_payload:
        chart_ok = isinstance(chart_payload.get("charts"), list) and len(chart_payload["charts"]) >= 3
        checks.append({"check": "chart spec: comparative visualization definitions", "pass": chart_ok, "detail": f"count={len(chart_payload.get('charts', []))}"})

    checks.extend(run_campaign_runner())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "section": SECTION,
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": len(checks),
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    checks = [
        {"check": "self: required workloads count", "pass": len(REQUIRED_WORKLOADS) == 10},
        {"check": "self: required dimensions count", "pass": len(REQUIRED_DIMENSIONS) == 6},
        {"check": "self: event codes count", "pass": len(REQUIRED_EVENT_CODES) == 5},
    ]
    return all(c["pass"] for c in checks), checks


def main() -> int:
    logger = configure_test_logging("check_benchmark_infra")
    as_json = "--json" in sys.argv
    run_self_test = "--self-test" in sys.argv

    if run_self_test:
        ok, checks = self_test()
        payload = {
            "self_test_passed": ok,
            "checks_total": len(checks),
            "checks_passing": sum(1 for c in checks if c["pass"]),
            "checks_failing": sum(1 for c in checks if not c["pass"]),
        }
        if as_json:
            print(json.dumps(payload, indent=2))
        else:
            print("PASS" if ok else "FAIL")
            for check in checks:
                status = "PASS" if check["pass"] else "FAIL"
                print(f"[{status}] {check['check']}")
        return 0 if ok else 1

    result = run_checks()
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        summary = result["summary"]
        print(f"{result['verdict']}: {TITLE} ({summary['passing']}/{summary['total']} checks passed)")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")

    return 0 if result["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
