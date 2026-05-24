#!/usr/bin/env python3
"""
Validation test for bd-98xo5.3.2 production metrics collection.

This test validates that the required production N distribution summary
has been generated with all required statistics.
"""

import json
import os
from pathlib import Path

def test_metrics_collection_output():
    """Test that bd-98xo5.3.2 metrics collection generated valid output."""
    artifacts_dir = Path("tests/artifacts/perf/cuckoo_n_distribution")

    # Find the most recent JSON file
    json_files = list(artifacts_dir.glob("*.json"))
    assert len(json_files) > 0, "No metrics collection output found"

    latest_file = max(json_files, key=lambda p: p.stat().st_mtime)
    print(f"Testing metrics file: {latest_file}")

    with open(latest_file) as f:
        summary = json.load(f)

    # Validate collection_window
    assert "collection_window" in summary
    window = summary["collection_window"]
    assert "start_timestamp_ms" in window
    assert "end_timestamp_ms" in window
    assert "duration_hours" in window
    assert "sample_count" in window

    # Ensure 7-day window requirement met
    assert window["duration_hours"] >= 168.0, f"Window too short: {window['duration_hours']} hours"
    assert window["sample_count"] >= 2, f"Too few samples: {window['sample_count']}"

    # Validate revocation_filter_metrics
    assert "revocation_filter_metrics" in summary
    metrics = summary["revocation_filter_metrics"]

    required_metrics = ["p50", "p95", "p99", "max_observed", "cuckoo_cliff_crossings", "max_growth_rate_per_minute"]
    for metric in required_metrics:
        assert metric in metrics, f"Missing required metric: {metric}"
        assert isinstance(metrics[metric], (int, float)), f"Invalid metric type for {metric}"

    # Validate metric ranges
    assert metrics["p50"] > 0, "p50 should be positive"
    assert metrics["p95"] >= metrics["p50"], "p95 should be >= p50"
    assert metrics["p99"] >= metrics["p95"], "p99 should be >= p95"
    assert metrics["max_observed"] >= metrics["p99"], "max_observed should be >= p99"
    assert metrics["cuckoo_cliff_crossings"] >= 0, "cliff crossings should be non-negative"
    assert metrics["max_growth_rate_per_minute"] >= 0, "growth rate should be non-negative"

    # Validate task reference
    assert "task_reference" in summary
    assert summary["task_reference"] == "bd-98xo5.3.2"

    # Validate timestamp
    assert "generated_timestamp" in summary
    assert isinstance(summary["generated_timestamp"], int)

    print("✅ All bd-98xo5.3.2 requirements validated successfully")
    print(f"📊 Key findings:")
    print(f"  • p50: {metrics['p50']}")
    print(f"  • p95: {metrics['p95']}")
    print(f"  • p99: {metrics['p99']}")
    print(f"  • max_observed: {metrics['max_observed']}")
    print(f"  • cuckoo_cliff_crossings: {metrics['cuckoo_cliff_crossings']}")
    print(f"  • max_growth_rate_per_minute: {metrics['max_growth_rate_per_minute']}")

    return True

if __name__ == "__main__":
    test_metrics_collection_output()
    print("✅ bd-98xo5.3.2 validation test passed")