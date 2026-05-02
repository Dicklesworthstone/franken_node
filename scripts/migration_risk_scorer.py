#!/usr/bin/env python3
"""
Migration Risk Scoring Model.

Takes a project scan report and produces a weighted, explainable
risk score for migration decision-making.

Usage:
    python3 scripts/migration_risk_scorer.py <scan_report.json> [--json]
    python3 scripts/migration_risk_scorer.py --self-test [--json]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Feature weights
WEIGHTS = {
    "critical_api_count": 10,
    "high_risk_api_count": 5,
    "medium_risk_api_count": 2,
    "native_addon_count": 15,
    "unsafe_api_count": 12,
    "total_dependency_count": 0.5,
    "untracked_api_count": 3,
}

DIFFICULTY_BANDS = [
    (15, "low", "Proceed with standard migration"),
    (40, "medium", "Address high-risk items first"),
    (70, "high", "Significant effort required"),
    (100, "critical", "Migration not recommended without major changes"),
]


def extract_features(report: dict) -> dict:
    """Extract scoring features from a scan report."""
    risk_dist = report.get("summary", {}).get("risk_distribution", {})
    api_usage = report.get("api_usage", [])
    dependencies = report.get("dependencies", [])

    unsafe_count = sum(1 for a in api_usage if a.get("api_family") == "unsafe")
    untracked = sum(1 for a in api_usage if a.get("band") is None and a.get("api_family") != "unsafe")
    native_addons = sum(1 for d in dependencies if d.get("has_native_addon"))

    return {
        "critical_api_count": risk_dist.get("critical", 0),
        "high_risk_api_count": risk_dist.get("high", 0),
        "medium_risk_api_count": risk_dist.get("medium", 0),
        "native_addon_count": native_addons,
        "unsafe_api_count": unsafe_count,
        "total_dependency_count": len(dependencies),
        "untracked_api_count": untracked,
    }


def compute_score(features: dict) -> tuple[float, list[dict]]:
    """Compute weighted risk score with per-feature explanations."""
    explanations = []
    raw_score = 0.0

    for feature_name, weight in WEIGHTS.items():
        value = features.get(feature_name, 0)
        contribution = weight * value
        raw_score += contribution
        if value > 0:
            explanations.append({
                "feature": feature_name,
                "value": value,
                "weight": weight,
                "contribution": contribution,
                "explanation": f"{feature_name}: {value} items × weight {weight} = {contribution}",
            })

    # Normalize to 0-100 (cap at 100)
    score = min(100.0, raw_score)
    return round(score, 1), explanations


def classify_difficulty(score: float) -> dict:
    """Classify migration difficulty from score."""
    for threshold, level, recommendation in DIFFICULTY_BANDS:
        if score <= threshold:
            return {"level": level, "recommendation": recommendation, "threshold": threshold}
    return {"level": "critical", "recommendation": DIFFICULTY_BANDS[-1][2], "threshold": 100}


def score_report(scan_report: dict) -> dict:
    """Produce a complete risk score report."""
    features = extract_features(scan_report)
    score, explanations = compute_score(features)
    difficulty = classify_difficulty(score)

    return {
        "project": scan_report.get("project", "<unknown>"),
        "score_timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": score,
        "difficulty": difficulty,
        "features": features,
        "explanations": explanations,
        "weights_used": WEIGHTS,
    }


def load_scan_report(report_path: Path) -> dict:
    """Load a scan report, failing closed on unreadable or malformed input."""
    try:
        return json.JSONDecoder().decode(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid scan report JSON: {report_path}: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"failed to read scan report: {report_path}: {exc}") from exc


def self_test() -> dict:
    """Run self-test with synthetic scan reports."""
    checks = []

    # Test 1: Clean project
    clean = {
        "project": "clean-project",
        "summary": {"total_apis_detected": 3, "risk_distribution": {"low": 3, "medium": 0, "high": 0, "critical": 0}},
        "api_usage": [
            {"api_family": "path", "api_name": "join", "band": "core", "risk_level": "low"},
            {"api_family": "fs", "api_name": "readFile", "band": "core", "risk_level": "low"},
            {"api_family": "process", "api_name": "env", "band": "core", "risk_level": "low"},
        ],
        "dependencies": [{"name": "express", "has_native_addon": False, "risk_level": "low"}],
    }
    result = score_report(clean)
    checks.append({"id": "RISK-CLEAN", "status": "PASS" if result["risk_score"] <= 15 else "FAIL",
                    "details": {"score": result["risk_score"], "difficulty": result["difficulty"]["level"]}})

    # Test 2: Risky project
    risky = {
        "project": "risky-project",
        "summary": {"total_apis_detected": 5, "risk_distribution": {"low": 1, "medium": 1, "high": 2, "critical": 1}},
        "api_usage": [
            {"api_family": "path", "api_name": "join", "band": "core", "risk_level": "low"},
            {"api_family": "fs", "api_name": "readFile", "band": "core", "risk_level": "medium"},
            {"api_family": "http", "api_name": "createServer", "band": "high-value", "risk_level": "high"},
            {"api_family": "crypto", "api_name": "createHash", "band": "high-value", "risk_level": "high"},
            {"api_family": "unsafe", "api_name": "eval", "band": "unsafe", "risk_level": "critical"},
        ],
        "dependencies": [
            {"name": "express", "has_native_addon": False, "risk_level": "low"},
            {"name": "sharp", "has_native_addon": True, "risk_level": "critical"},
        ],
    }
    result2 = score_report(risky)
    checks.append({"id": "RISK-RISKY", "status": "PASS" if result2["risk_score"] > 15 else "FAIL",
                    "details": {"score": result2["risk_score"], "difficulty": result2["difficulty"]["level"]}})

    # Test 3: Score is bounded
    checks.append({"id": "RISK-BOUNDED", "status": "PASS" if 0 <= result["risk_score"] <= 100 and 0 <= result2["risk_score"] <= 100 else "FAIL"})

    # Test 4: Explanations present
    has_explanations = len(result2["explanations"]) > 0
    checks.append({"id": "RISK-EXPLAINED", "status": "PASS" if has_explanations else "FAIL",
                    "details": {"explanation_count": len(result2["explanations"])}})

    # Test 5: Difficulty classification
    checks.append({"id": "RISK-CLASSIFIED", "status": "PASS" if result2["difficulty"]["level"] in ("medium", "high", "critical") else "FAIL"})

    failing = [c for c in checks if c["status"] == "FAIL"]
    return {
        "gate": "risk_scorer_verification",
        "section": "10.3",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }


def main():
    json_output = "--json" in sys.argv
    is_self_test = "--self-test" in sys.argv

    if is_self_test:
        result = self_test()
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            print("=== Risk Scorer Self-Test ===")
            for c in result["checks"]:
                print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
            print(f"\nVerdict: {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("Usage: python3 scripts/migration_risk_scorer.py <scan_report.json> [--json]", file=sys.stderr)
        sys.exit(2)

    report_path = Path(args[0])
    scan_report = load_scan_report(report_path)
    result = score_report(scan_report)

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"Project: {result['project']}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Difficulty: {result['difficulty']['level']}")
        print(f"Recommendation: {result['difficulty']['recommendation']}")
        if result["explanations"]:
            print("\nContributing factors:")
            for e in result["explanations"]:
                print(f"  - {e['explanation']}")


if __name__ == "__main__":
    main()
