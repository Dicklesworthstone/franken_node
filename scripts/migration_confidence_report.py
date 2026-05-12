#!/usr/bin/env python3
"""
Migration Confidence Report Generator.

Synthesizes scan, risk, validation, and rollout data into a confidence
assessment with uncertainty bands.

Usage:
    python3 scripts/migration_confidence_report.py --self-test [--json]
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

ROOT = Path(__file__).resolve().parent.parent

CONFIDENCE_LEVELS = [
    (100, "high", "Proceed with standard rollout"),
    (79, "medium", "Proceed with extended monitoring"),
    (49, "low", "Address risks before proceeding"),
    (19, "insufficient", "Migration not recommended"),
]


def compute_confidence(risk_score: float, validation_pass_rate: float,
                       fixture_coverage: float, api_tracked_pct: float) -> dict:
    """Compute confidence score with uncertainty bands.

    Args:
        risk_score: 0-100, lower is better (from risk scorer)
        validation_pass_rate: 0-1, fraction of tests passing
        fixture_coverage: 0-1, fraction of APIs with fixtures
        api_tracked_pct: 0-1, fraction of detected APIs in registry
    """
    # Base confidence: inverse of risk + validation success
    risk_component = max(0, (100 - risk_score)) * 0.35
    validation_component = validation_pass_rate * 100 * 0.35
    coverage_component = fixture_coverage * 100 * 0.15
    tracking_component = api_tracked_pct * 100 * 0.15

    raw_score = risk_component + validation_component + coverage_component + tracking_component
    confidence = round(min(100, max(0, raw_score)), 1)

    # Uncertainty band: wider when data is less complete
    completeness = (fixture_coverage + api_tracked_pct + validation_pass_rate) / 3
    uncertainty_width = round((1 - completeness) * 30, 1)  # Max ±30 points
    lower_bound = round(max(0, confidence - uncertainty_width), 1)
    upper_bound = round(min(100, confidence + uncertainty_width), 1)

    return {
        "confidence_score": confidence,
        "uncertainty_band": {
            "lower": lower_bound,
            "upper": upper_bound,
            "width": uncertainty_width,
        },
        "components": {
            "risk_component": round(risk_component, 1),
            "validation_component": round(validation_component, 1),
            "coverage_component": round(coverage_component, 1),
            "tracking_component": round(tracking_component, 1),
        },
    }


def classify_confidence(score: float) -> dict:
    """Classify confidence level."""
    for threshold, level, recommendation in CONFIDENCE_LEVELS:
        if score >= threshold - 20:  # Adjusted ranges
            pass
    # Use explicit bands
    if score >= 80:
        return {"level": "high", "recommendation": "Proceed with standard rollout"}
    if score >= 50:
        return {"level": "medium", "recommendation": "Proceed with extended monitoring"}
    if score >= 20:
        return {"level": "low", "recommendation": "Address risks before proceeding"}
    return {"level": "insufficient", "recommendation": "Migration not recommended"}


def generate_report(scan_summary: dict = None, risk_report: dict = None,
                    validation_result: dict = None) -> dict:
    """Generate complete confidence report."""
    # Extract metrics (with sensible defaults for missing data)
    risk_score = risk_report.get("risk_score", 50) if risk_report else 50
    validation_pass_rate = 0.0
    if validation_result:
        summary = validation_result.get("summary", {})
        total = summary.get("total_tests", 0)
        passed = summary.get("passed", 0)
        validation_pass_rate = passed / total if total > 0 else 0

    fixture_coverage = 0.5  # Default: assume partial coverage
    api_tracked_pct = 0.8   # Default: assume most APIs tracked

    if scan_summary:
        total_apis = scan_summary.get("total_apis_detected", 0)
        risk_dist = scan_summary.get("risk_distribution", {})
        low_count = risk_dist.get("low", 0)
        api_tracked_pct = low_count / total_apis if total_apis > 0 else 0.5

    confidence = compute_confidence(risk_score, validation_pass_rate, fixture_coverage, api_tracked_pct)
    classification = classify_confidence(confidence["confidence_score"])

    # Go/no-go
    go_decision = classification["level"] in ("high", "medium")

    return {
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "confidence": confidence,
        "classification": classification,
        "go_decision": {
            "proceed": go_decision,
            "rationale": classification["recommendation"],
        },
        "uncertainty_sources": [
            {"source": "fixture_coverage", "impact": "medium" if fixture_coverage < 0.8 else "low"},
            {"source": "validation_completeness", "impact": "high" if validation_pass_rate < 0.5 else "low"},
            {"source": "api_tracking", "impact": "medium" if api_tracked_pct < 0.8 else "low"},
        ],
        "data_inputs": {
            "risk_score": risk_score,
            "validation_pass_rate": validation_pass_rate,
            "fixture_coverage": fixture_coverage,
            "api_tracked_pct": api_tracked_pct,
        },
    }


def self_test() -> dict:
    """Run self-test."""
    checks = []

    # Test 1: High-confidence scenario
    conf = compute_confidence(risk_score=5, validation_pass_rate=1.0, fixture_coverage=0.9, api_tracked_pct=0.95)
    checks.append({"id": "CONF-HIGH", "status": "PASS" if conf["confidence_score"] >= 70 else "FAIL",
                    "details": {"score": conf["confidence_score"]}})

    # Test 2: Low-confidence scenario
    conf2 = compute_confidence(risk_score=80, validation_pass_rate=0.2, fixture_coverage=0.3, api_tracked_pct=0.4)
    checks.append({"id": "CONF-LOW", "status": "PASS" if conf2["confidence_score"] < 50 else "FAIL",
                    "details": {"score": conf2["confidence_score"]}})

    # Test 3: Score bounded
    checks.append({"id": "CONF-BOUNDED", "status": "PASS" if 0 <= conf["confidence_score"] <= 100 and 0 <= conf2["confidence_score"] <= 100 else "FAIL"})

    # Test 4: Uncertainty band
    checks.append({"id": "CONF-UNCERTAINTY", "status": "PASS" if conf["uncertainty_band"]["width"] >= 0 else "FAIL",
                    "details": {"width": conf["uncertainty_band"]["width"]}})

    # Test 5: Classification
    cls_high = classify_confidence(85)
    cls_low = classify_confidence(15)
    checks.append({"id": "CONF-CLASSIFY", "status": "PASS" if cls_high["level"] == "high" and cls_low["level"] == "insufficient" else "FAIL"})

    # Test 6: Report generation
    report = generate_report()
    has_fields = all(k in report for k in ("confidence", "classification", "go_decision"))
    checks.append({"id": "CONF-REPORT", "status": "PASS" if has_fields else "FAIL"})

    failing = [c for c in checks if c["status"] == "FAIL"]
    return {
        "gate": "confidence_report_verification",
        "section": "10.3",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }


def main():
    logger = configure_test_logging("migration_confidence_report")
    logger.info("starting migration confidence report")
    json_output = "--json" in sys.argv
    is_self_test = "--self-test" in sys.argv

    if is_self_test:
        result = self_test()
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            for c in result["checks"]:
                print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
            print(f"\nVerdict: {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    report = generate_report()
    if json_output:
        print(json.dumps(report, indent=2))
    else:
        c = report["confidence"]
        print(f"Confidence: {c['confidence_score']}/100 [{c['uncertainty_band']['lower']}-{c['uncertainty_band']['upper']}]")
        print(f"Level: {report['classification']['level']}")
        print(f"Go/No-Go: {'GO' if report['go_decision']['proceed'] else 'NO-GO'}")


if __name__ == "__main__":
    main()
