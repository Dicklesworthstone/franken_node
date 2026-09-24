"""Tests for scripts/bench_runtime_vs_node.py (HC-003 measured benchmark).

These cover the harness's own decision logic. They do not prove anything
about franken-node's latency: only a real run of the script does.
"""

from __future__ import annotations

import importlib.util
import json
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
