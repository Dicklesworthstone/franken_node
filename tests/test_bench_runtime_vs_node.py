"""Tests for scripts/bench_runtime_vs_node.py (HC-003 measured benchmark).

These cover the harness's decision logic, order-statistic quantile CIs,
peak RSS capture, Ed25519 receipt signing, cold-start budget evaluation,
and triad interleaving over all 6 workloads.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bench_runtime_vs_node.py"

spec = importlib.util.spec_from_file_location("bench_runtime_vs_node", SCRIPT)
bench = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bench)


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=300,
    )


def test_identical_samples_give_unit_ratio_ci():
    samples = [10.0, 11.0, 12.0, 10.5, 11.5]
    low, high = bench.bootstrap_ratio_ci(samples, samples)
    assert bench.median_ratio(samples, samples) == 1.0
    assert low <= 1.0 <= high


def test_twice_as_slow_is_detected_with_tight_ci():
    node = [30.0, 31.0, 29.5, 30.5, 30.2, 29.8]
    franken = [2 * s for s in node]
    low, high = bench.bootstrap_ratio_ci(franken, node)
    assert 1.8 < low <= 2.0 <= high < 2.2
    assert bench.workload_verdict(high) == "FAIL"


def test_bootstrap_is_deterministic():
    node = [30.0, 35.0, 32.0, 31.0]
    franken = [40.0, 33.0, 38.0, 36.0]
    assert bench.bootstrap_ratio_ci(franken, node) == bench.bootstrap_ratio_ci(franken, node)


def test_ceiling_is_inclusive_at_ten_percent():
    assert bench.workload_verdict(1.10) == "PASS"
    assert bench.workload_verdict(1.1001) == "FAIL"


def test_overall_verdict_requires_every_workload_to_pass():
    assert bench.overall_verdict(["PASS", "PASS"]) == "PASS"
    assert bench.overall_verdict(["PASS", "FAIL"]) == "FAIL"
    assert bench.overall_verdict(["PASS", "INVALID"]) == "FAIL"
    assert bench.overall_verdict([]) == "ERROR"


def test_order_statistic_quantile_ci_exact_binomial_coverage():
    samples = [float(i) for i in range(1, 31)]
    ci50 = bench.order_statistic_quantile_ci(samples, 0.50, confidence=0.95)
    assert ci50["ci_low"] <= ci50["estimate"] <= ci50["ci_high"]
    assert 1 <= ci50["rank_low"] < ci50["rank_high"] <= 30
    assert ci50["actual_coverage"] >= 0.95

    ci95 = bench.order_statistic_quantile_ci(samples, 0.95, confidence=0.95)
    assert ci95["ci_low"] <= ci95["estimate"] <= ci95["ci_high"]
    assert 1 <= ci95["rank_low"] < ci95["rank_high"] <= 30
    assert 0.0 < ci95["actual_coverage"] <= 1.0

    ci99 = bench.order_statistic_quantile_ci(samples, 0.99, confidence=0.95)
    assert ci99["ci_low"] <= ci99["estimate"] <= ci99["ci_high"]
    assert 1 <= ci99["rank_low"] < ci99["rank_high"] <= 30

    single = bench.order_statistic_quantile_ci([42.5], 0.50)
    assert single["rank_low"] == 1
    assert single["rank_high"] == 1
    assert single["actual_coverage"] == 0.0


@pytest.mark.skipif(not hasattr(os, "wait4"), reason="POSIX wait4 required for ru_maxrss")
def test_run_once_with_rusage_reports_positive_rss(tmp_path):
    elapsed_ms, maxrss_kb, completed = bench._run_once_with_rusage(
        [sys.executable, "-c", "buf = bytearray(4 * 1024 * 1024); print(len(buf))"],
        tmp_path,
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == b"4194304"
    assert elapsed_ms > 0.0
    assert maxrss_kb > 1024


def test_ed25519_report_signing_and_tamper_rejection():
    pytest.importorskip("cryptography")
    seed_hex = ("5a" * 32).encode("ascii")
    sample_report = {
        "schema_version": bench.SCHEMA_VERSION,
        "claim_id": "HC-003",
        "verdict": "FAIL",
        "workloads": {"hello": {"franken_median_ms": 88.5}},
    }
    sig = bench.sign_report_ed25519(sample_report, seed_hex)
    assert sig is not None
    signed = dict(sample_report, signature=sig)
    assert bench.verify_report_ed25519(signed) is True

    # Tampered metric must fail verification.
    tampered = json.loads(json.dumps(signed))
    tampered["workloads"]["hello"]["franken_median_ms"] = 12.0
    assert bench.verify_report_ed25519(tampered) is False

    # PEM blobs must be refused fail-closed.
    assert bench.sign_report_ed25519(sample_report, b"-----BEGIN PRIVATE KEY-----\n") is None


def test_cold_start_budget_evaluation_enforces_min_iterations_and_ceiling():
    budgets = bench.load_perf_budgets()
    assert budgets is not None
    fast_workloads = {
        "hello": {
            "verdict": "FAIL",
            "franken_median_ms": 95.0,
            "runtimes": {
                "franken-node": {
                    "cold_start_ms": 110.0,
                    "warm_dispatch": {
                        "p50_ms": 95.0,
                        "p99_ms": 130.0,
                        "p99_ci95": {"ci_low": 120.0, "ci_high": 135.0},
                    },
                }
            },
        }
    }
    # Under-sampled run (runs=10 < min_iterations=30) must not PASS the budget gate.
    undersampled = bench.evaluate_cold_start_budget(
        fast_workloads, budgets, "ci_dev", runs=10, warmup=1
    )
    assert undersampled["within_budget"] is True
    assert undersampled["sufficient_iterations"] is False
    assert undersampled["verdict"] == "FAIL"

    # Full 30-iteration + 5-warmup run within 200ms ci_dev budget PASSes.
    qualified = bench.evaluate_cold_start_budget(
        fast_workloads, budgets, "ci_dev", runs=30, warmup=5
    )
    assert qualified["verdict"] == "PASS"
    assert qualified["cold_start_budget_ms"] == 200.0

    # Exceeding enterprise 100ms ceiling FAILs enterprise while PASSing ci_dev.
    slow_workloads = json.loads(json.dumps(fast_workloads))
    slow_workloads["hello"]["runtimes"]["franken-node"]["warm_dispatch"]["p50_ms"] = 140.0
    enterprise = bench.evaluate_cold_start_budget(
        slow_workloads, budgets, "enterprise", runs=30, warmup=5
    )
    assert enterprise["within_budget"] is False
    assert enterprise["verdict"] == "FAIL"


def test_missing_explicit_binary_is_error_not_fallback(tmp_path):
    result = run_script("--bin", str(tmp_path / "no-such-franken-node"), "--json")
    report = json.loads(result.stdout)
    assert result.returncode == 2
    assert report["verdict"] == "ERROR"
    assert "not found" in report["detail"]


@pytest.mark.skipif(shutil.which("node") is None, reason="reference runtime node not installed")
def test_wrong_output_is_invalid_and_never_timed(tmp_path):
    # Planted negative: a "franken-node" that answers every workload wrongly
    # must be rejected by the correctness guard, not benchmarked.
    fake = tmp_path / "franken-node"
    fake.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  init) exit 0 ;;\n"
        "  --version) echo fake-franken-node ;;\n"
        "  run) echo wrong-answer ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    result = run_script("--bin", str(fake), "--runs", "3", "--json")
    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert report["verdict"] == "FAIL"
    assert set(report["workloads"]) == set(bench.WORKLOADS)
    for entry in report["workloads"].values():
        assert entry["verdict"] == "INVALID"
        assert "franken_samples_ms" not in entry


@pytest.mark.skipif(shutil.which("node") is None, reason="reference runtime node not installed")
def test_triad_interleaved_e2e_all_six_workloads_and_signed_receipt(tmp_path):
    node_bin = shutil.which("node")
    assert node_bin is not None
    shim = tmp_path / "franken-node"
    shim.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  init)\n"
        "    mkdir -p .franken-node/keys\n"
        f"    printf '%s\\n' '{'7b' * 32}' > .franken-node/keys/receipt-signing.key\n"
        "    printf 'allowlist = []\\n' > franken_node.toml\n"
        "    exit 0\n"
        "    ;;\n"
        "  --version)\n"
        "    echo shim-franken-node-0.2.0\n"
        "    ;;\n"
        "  run)\n"
        f'    exec "{node_bin}" "$2"\n'
        "    ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    out_file = tmp_path / "report.json"
    result = run_script(
        "--bin",
        str(shim),
        "--runs",
        "3",
        "--warmup",
        "1",
        "--json",
        "--out",
        str(out_file),
    )
    assert out_file.is_file()
    report = json.loads(result.stdout)
    assert set(report["workloads"]) == {
        "hello",
        "json_roundtrip",
        "compute_loop",
        "fs_read",
        "require_pkg",
        "loopback_http",
    }
    for wname, entry in report["workloads"].items():
        assert entry["verdict"] in ("PASS", "FAIL"), f"{wname} unexpectedly {entry}"
        fn_rt = entry["runtimes"]["franken-node"]
        assert fn_rt["cold_start_ms"] > 0.0
        assert fn_rt["warm_dispatch"]["p50_ms"] > 0.0
        assert fn_rt["warm_dispatch"]["p95_ms"] >= fn_rt["warm_dispatch"]["p50_ms"]
        assert fn_rt["warm_dispatch"]["p99_ms"] >= fn_rt["warm_dispatch"]["p95_ms"]
        assert fn_rt["rss_kb"]["max_kb"] > 0
        if report["host"]["bun_available"]:
            assert "bun" in entry["runtimes"]
            assert "bun_median_ms" in entry
    assert report["workloads"]["loopback_http"]["node_stdout"] == "loopback-bench-ok:42"
    assert report["workloads"]["require_pkg"]["node_stdout"].startswith("fnv1a:")
    if "signature" in report:
        assert bench.verify_report_ed25519(report) is True
