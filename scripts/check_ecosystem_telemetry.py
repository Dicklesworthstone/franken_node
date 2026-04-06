#!/usr/bin/env python3
"""Verification script for bd-phf ecosystem telemetry."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SPEC_PATH = ROOT / "docs/specs/section_10_4/bd-phf_contract.md"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/supply_chain/ecosystem_telemetry.rs"
MOD_PATH = ROOT / "crates/franken-node/src/supply_chain/mod.rs"

EVIDENCE_DIR = ROOT / "artifacts/section_10_4/bd-phf"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_INVARIANTS = [
    "INV-TEL-OPT-IN",
    "INV-TEL-PRIVACY",
    "INV-TEL-RETENTION",
    "INV-TEL-ANOMALY",
    "INV-TEL-BUDGET",
    "INV-TEL-QUERY",
    "INV-TEL-EXPORT",
    "INV-TEL-GOVERNANCE",
    "INV-TEL-EXPORT-PROVENANCE",
    "INV-TEL-EXPORT-NO-PLACEHOLDER",
    "INV-TEL-COMPROMISE",
    "INV-TEL-CERT-DIST",
]

REQUIRED_SPEC_MARKERS = [
    "artifacts/13/compromise_reduction_report.json",
    "baseline_compromised / hardened_compromised",
    "complete_containment",
    "SignedExtensionRegistry.list(Some(ExtensionStatus::Active))",
    "CertificationRegistry",
    "uncertified",
    "trust_card.rs",
]

REQUIRED_VALIDATION_MARKERS = [
    "`bd-2fqyv.9.3` ratchets this surface with a scenario matrix",
    "`partial_active_set_coverage`",
    "`missing_inputs`",
    "`stale_compromise_report`",
    "`stale_certification_inputs`",
    "`complete_containment_or_baseline_absent`",
    "python3 scripts/check_ecosystem_telemetry.py --json",
    "artifacts/section_10_4/bd-phf/verification_evidence.json",
    "artifacts/section_10_4/bd-phf/verification_summary.md",
    "`authoritative_inputs`, `observed_inputs`, `source_timestamp`, and `detail`",
]

REQUIRED_RUST_SYMBOLS = [
    "pub enum TrustMetricKind",
    "pub enum AdoptionMetricKind",
    "pub enum MetricKind",
    "pub struct TelemetryDataPoint",
    "pub enum AggregationLevel",
    "pub struct DataGovernance",
    "pub struct RetentionPolicy",
    "pub enum AnomalyType",
    "pub enum AnomalySeverity",
    "pub struct AnomalyAlert",
    "pub struct AnomalyConfig",
    "pub struct TelemetryQuery",
    "pub struct TelemetryQueryResult",
    "pub enum DerivedMetricAvailability",
    "pub struct DerivedMetricContract",
    "pub struct DerivedMetricMetadata",
    "pub struct CompromiseReductionReport",
    "pub fn load_compromise_reduction_report(",
    "pub fn compromise_reduction_factor_contract()",
    "pub fn certification_distribution_contract()",
    "pub struct EcosystemHealthExport",
    "pub struct ResourceBudget",
    "pub struct TelemetryPipeline",
]

REQUIRED_PROVENANCE_FIELDS = [
    "pub authoritative_inputs: Vec<String>",
    "pub observed_inputs: Vec<String>",
    "pub source_timestamp: Option<String>",
    "pub detail: String",
]

REQUIRED_EVENT_CODES = [
    "TELEMETRY_INGESTED",
    "TELEMETRY_AGGREGATED",
    "TELEMETRY_QUERY_SERVED",
    "TELEMETRY_ANOMALY_DETECTED",
    "TELEMETRY_EXPORT_GENERATED",
    "TELEMETRY_PRIVACY_FILTER_APPLIED",
]

REQUIRED_TRUST_METRICS = [
    "CertificationDistribution",
    "RevocationPropagationLatency",
    "QuarantineResolutionTime",
    "ProvenanceCoverageRate",
    "ReputationDistribution",
]

REQUIRED_ADOPTION_METRICS = [
    "ExtensionsPublished",
    "ProvenanceLevelAdoption",
    "TrustCardQueryVolume",
    "PolicyOverrideFrequency",
    "QuarantineActionsPerPeriod",
]

REQUIRED_ANOMALY_TYPES = [
    "ProvenanceCoverageDrop",
    "QuarantineSpike",
    "ReputationDistributionShift",
    "RevocationPropagationDelay",
    "PublicationVolumeAnomaly",
]

REQUIRED_PIPELINE_METHODS = [
    "pub fn new()",
    "pub fn with_governance",
    "pub fn enable_collection",
    "pub fn ingest(",
    "pub fn detect_anomalies(",
    "pub fn query(",
    "pub fn export_health(",
    "pub fn active_alerts(",
    "pub fn ingested_count(",
    "pub fn stored_count(",
    "pub fn governance(",
    "pub fn resource_budget(",
]

REQUIRED_TESTS = [
    "test_collection_disabled_by_default",
    "test_collection_after_enable",
    "test_query_by_metric",
    "test_query_by_time_range",
    "test_anomaly_detection_provenance_drop",
    "test_anomaly_detection_quarantine_spike",
    "test_anomaly_detection_reputation_shift",
    "test_anomaly_detection_revocation_delay",
    "test_anomaly_detection_publication_volume",
    "test_no_anomaly_within_threshold",
    "test_health_export",
    "test_load_compromise_reduction_report_from_artifact",
    "test_health_export_computes_compromise_reduction_from_authoritative_report",
    "test_health_export_surfaces_complete_containment_instead_of_placeholder_ratio",
    "test_health_export_surfaces_baseline_absent_for_undefined_compromise_ratio",
    "test_health_export_surfaces_stale_compromise_report",
    "test_health_export_counts_active_extensions_using_certification_registry",
    "test_health_export_marks_stale_certification_distribution_inputs",
    "test_resource_budget_eviction",
    "test_governance_default_opt_in",
    "test_compromise_reduction_contract_declares_complete_containment",
    "test_certification_distribution_contract_uses_active_registry_and_uncertified_fallback",
]


def check_file_exists(path: Path) -> dict[str, Any]:
    exists = path.exists()
    return {
        "path": str(path.relative_to(ROOT)),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
    }


def check_content(name: str, path: Path, required: list[str]) -> dict[str, Any]:
    if not path.exists():
        return {"pass": False, "reason": f"{name} file not found", "found": [], "missing": required}
    content = path.read_text()
    found = [item for item in required if item in content]
    missing = [item for item in required if item not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_mod_registration() -> dict[str, Any]:
    if not MOD_PATH.exists():
        return {"pass": False, "reason": "mod.rs not found"}
    content = MOD_PATH.read_text()
    has_module = "pub mod ecosystem_telemetry;" in content
    return {"pass": has_module, "registered": has_module}


def check_privacy_governance() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_governance = "pub struct DataGovernance" in content
    has_opt_in = "collection_enabled: false" in content
    has_k_anon = "min_aggregation_k" in content
    has_retention = "pub struct RetentionPolicy" in content
    return {
        "pass": all([has_governance, has_opt_in, has_k_anon, has_retention]),
        "governance_struct": has_governance,
        "opt_in_default": has_opt_in,
        "k_anonymity": has_k_anon,
        "retention_policy": has_retention,
    }


def check_anomaly_detection() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_config = "pub struct AnomalyConfig" in content
    has_detect = "pub fn detect_anomalies" in content
    has_threshold = "deviation_threshold_pct" in content
    has_min_points = "min_data_points" in content
    return {
        "pass": all([has_config, has_detect, has_threshold, has_min_points]),
        "anomaly_config": has_config,
        "detect_function": has_detect,
        "deviation_threshold": has_threshold,
        "min_data_points": has_min_points,
    }


def check_resource_budget() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_budget = "pub struct ResourceBudget" in content
    has_max_points = "max_in_memory_points" in content
    has_eviction = "retain(" in content
    return {
        "pass": all([has_budget, has_max_points, has_eviction]),
        "budget_struct": has_budget,
        "max_points": has_max_points,
        "eviction_logic": has_eviction,
    }


def run_all_checks() -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = {
        "files": {
            "spec": check_file_exists(SPEC_PATH),
            "rust_impl": check_file_exists(RUST_IMPL_PATH),
            "mod_rs": check_file_exists(MOD_PATH),
        },
        "spec_invariants": check_content("spec", SPEC_PATH, REQUIRED_INVARIANTS),
        "spec_metric_contracts": check_content("spec", SPEC_PATH, REQUIRED_SPEC_MARKERS),
        "validation_matrix": check_content("spec", SPEC_PATH, REQUIRED_VALIDATION_MARKERS),
        "rust_symbols": check_content("rust", RUST_IMPL_PATH, REQUIRED_RUST_SYMBOLS),
        "provenance_metadata_fields": check_content(
            "rust", RUST_IMPL_PATH, REQUIRED_PROVENANCE_FIELDS
        ),
        "event_codes": check_content("rust", RUST_IMPL_PATH, REQUIRED_EVENT_CODES),
        "trust_metrics": check_content("rust", RUST_IMPL_PATH, REQUIRED_TRUST_METRICS),
        "adoption_metrics": check_content("rust", RUST_IMPL_PATH, REQUIRED_ADOPTION_METRICS),
        "anomaly_types": check_content("rust", RUST_IMPL_PATH, REQUIRED_ANOMALY_TYPES),
        "pipeline_methods": check_content("rust", RUST_IMPL_PATH, REQUIRED_PIPELINE_METHODS),
        "tests": check_content("rust", RUST_IMPL_PATH, REQUIRED_TESTS),
        "mod_registration": check_mod_registration(),
        "privacy_governance": check_privacy_governance(),
        "anomaly_detection": check_anomaly_detection(),
        "resource_budget": check_resource_budget(),
    }

    check_results = [
        checks["spec_invariants"],
        checks["spec_metric_contracts"],
        checks["validation_matrix"],
        checks["rust_symbols"],
        checks["provenance_metadata_fields"],
        checks["event_codes"],
        checks["trust_metrics"],
        checks["adoption_metrics"],
        checks["anomaly_types"],
        checks["pipeline_methods"],
        checks["tests"],
        checks["mod_registration"],
        checks["privacy_governance"],
        checks["anomaly_detection"],
        checks["resource_budget"],
    ]

    all_pass = all(c.get("pass", False) for c in check_results)
    file_pass = all(f["exists"] for f in checks["files"].values())
    passed_count = sum(1 for c in check_results if c.get("pass", False)) + (1 if file_pass else 0)

    return {
        "bead_id": "bd-phf",
        "section": "10.4",
        "title": "Ecosystem Telemetry for Trust and Adoption Metrics",
        "timestamp": timestamp,
        "overall_pass": all_pass and file_pass,
        "checks": checks,
        "summary": {
            "total_checks": 16,
            "passed": passed_count,
            "failed": 16 - passed_count,
        },
    }


def write_evidence(evidence: dict[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n")


def write_summary(evidence: dict[str, Any]) -> None:
    s = evidence["summary"]
    lines = [
        f"# Verification Summary: {evidence['title']}",
        "",
        f"**Bead:** {evidence['bead_id']} | **Section:** {evidence['section']}",
        f"**Timestamp:** {evidence['timestamp']}",
        f"**Overall:** {'PASS' if evidence['overall_pass'] else 'FAIL'}",
        f"**Checks:** {s['passed']}/{s['total_checks']} passed",
        "",
        "## Check Results",
        "",
    ]
    for name, result in sorted(evidence["checks"].items()):
        if name == "files":
            for fname, finfo in result.items():
                status = "PASS" if finfo["exists"] else "FAIL"
                lines.append(f"- **File {fname}:** {status} ({finfo['path']}, {finfo['size_bytes']} bytes)")
        else:
            status = "PASS" if result.get("pass", False) else "FAIL"
            lines.append(f"- **{name}:** {status}")
            if "missing" in result and result["missing"]:
                for m in result["missing"]:
                    lines.append(f"  - Missing: `{m}`")

    lines.extend(["", "## Artifacts", ""])
    lines.append(f"- Spec: `{SPEC_PATH.relative_to(ROOT)}`")
    lines.append(f"- Implementation: `{RUST_IMPL_PATH.relative_to(ROOT)}`")
    lines.append(f"- Evidence: `{EVIDENCE_PATH.relative_to(ROOT)}`")
    lines.append("")
    SUMMARY_PATH.write_text("\n".join(lines) + "\n")


def self_test() -> bool:
    evidence = run_all_checks()
    assert isinstance(evidence, dict)
    assert evidence["bead_id"] == "bd-phf"
    assert "checks" in evidence
    assert "summary" in evidence
    expected = [
        "files", "spec_invariants", "spec_metric_contracts", "validation_matrix",
        "rust_symbols", "provenance_metadata_fields", "event_codes", "trust_metrics",
        "adoption_metrics", "anomaly_types", "pipeline_methods", "tests",
        "mod_registration", "privacy_governance", "anomaly_detection", "resource_budget",
    ]
    for cat in expected:
        assert cat in evidence["checks"], f"missing check: {cat}"
    return True


def main() -> None:
    logger = configure_test_logging("check_ecosystem_telemetry")
    parser = argparse.ArgumentParser(description="Verify bd-phf ecosystem telemetry")
    parser.add_argument("--json", action="store_true", help="Output JSON evidence")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    evidence = run_all_checks()

    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        s = evidence["summary"]
        status = "PASS" if evidence["overall_pass"] else "FAIL"
        print(f"bd-phf verification: {status} ({s['passed']}/{s['total_checks']} checks passed)")
        for name, result in sorted(evidence["checks"].items()):
            if name == "files":
                for fname, finfo in result.items():
                    sym = "+" if finfo["exists"] else "-"
                    print(f"  [{sym}] file:{fname} {finfo['path']}")
            else:
                sym = "+" if result.get("pass", False) else "-"
                print(f"  [{sym}] {name}")
                if "missing" in result and result["missing"]:
                    for m in result["missing"]:
                        print(f"       missing: {m}")

    write_evidence(evidence)
    write_summary(evidence)


if __name__ == "__main__":
    main()
