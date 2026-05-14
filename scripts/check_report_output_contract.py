#!/usr/bin/env python3
"""bd-1sgr: Report output contract - verification gate."""
import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "report_output_contract.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_16", "bd-1sgr_contract.md")
REPORT_DIR = os.path.join(ROOT, "artifacts", "section_16", "bd-1sgr", "publishable_reports")
REPORT_REGISTRY = os.path.join(REPORT_DIR, "reproducible_report_registry.json")
BEAD, SECTION = "bd-1sgr", "16"

CODES = [f"ROC-{str(i).zfill(3)}" for i in range(1, 11)] + ["ROC-ERR-001", "ROC-ERR-002"]
INVS = ["INV-ROC-COMPLETE", "INV-ROC-DETERMINISTIC", "INV-ROC-INTEGRITY", "INV-ROC-REPRODUCIBLE", "INV-ROC-VERSIONED", "INV-ROC-AUDITABLE"]
REQUIRED_REPORT_TOPICS = {"compatibility_migration", "trust_security", "benchmark_verification"}
REQUIRED_REPORT_HEADINGS = [
    "## Abstract",
    "## Introduction",
    "## Related Work",
    "## Methodology",
    "## Results",
    "## Discussion",
    "## Conclusion",
    "## References",
]

def _read(p):
    with open(p) as f: return f.read()

def _read_json(p):
    with open(p) as f: return json.load(f)

def _rel_exists(rel_path):
    return os.path.isfile(os.path.join(ROOT, rel_path))

def _registry_reports():
    if not os.path.isfile(REPORT_REGISTRY):
        return []
    try:
        data = _read_json(REPORT_REGISTRY)
    except (OSError, json.JSONDecodeError):
        return []
    reports = data.get("reports", [])
    return reports if isinstance(reports, list) else []

def _report_text_has_required_headings(rel_path):
    try:
        text = _read(os.path.join(ROOT, rel_path))
    except OSError:
        return False
    return all(heading in text for heading in REQUIRED_REPORT_HEADINGS)

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    reports = _registry_reports()
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod report_output_contract;" in _read(MOD_RS))
    ok("report_types", all(t in src for t in ["TechnicalAnalysis", "SecurityAssessment", "PerformanceBenchmark", "ComplianceReport", "IncidentPostmortem"]), "5 types")
    ok("required_artifacts", "REQUIRED_ARTIFACT_TYPES" in src and "report_pdf" in src, "5 required artifact types")
    for st in ["ReportBundle", "ArtifactEntry", "OutputCatalog", "ReportOutputContract"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("integrity_verification", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("completeness_checking", "is_complete" in src and "REQUIRED_ARTIFACT_TYPES" in src, "Completeness validation")
    ok("reproducibility", "reproduction_command" in src, "Reproduction instructions")
    ok("catalog_generation", "generate_catalog" in src and "OutputCatalog" in src, "Catalog with completeness")
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "RocAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("contract_version", "roc-v1.0" in src, "roc-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 20, f"{test_count} tests")
    # 16. Catalog hash covers complete_bundles (bd-3by7l)
    ok("catalog_hash_covers_complete_bundles",
       "catalog_hash_changes_with_complete_bundles" in src,
       "complete_bundles included in content_hash")
    # 17. Length-prefixed catalog hash (bd-3by7l)
    ok("catalog_hash_length_prefixed",
       "to_le_bytes" in src and "report_output_catalog_hash_v1" in src,
       "Length-prefixed hash inputs with domain separator")
    ok("publishable_reports_dir", os.path.isdir(REPORT_DIR), REPORT_DIR)
    ok("reproducible_report_registry", os.path.isfile(REPORT_REGISTRY), REPORT_REGISTRY)
    ok("publishable_report_count", len(reports) >= 3, f"{len(reports)} reports")
    topics = {str(report.get("topic", "")) for report in reports if isinstance(report, dict)}
    ok("publishable_report_topics", REQUIRED_REPORT_TOPICS.issubset(topics), ",".join(sorted(topics)))
    report_artifacts = [
        report.get("report_artifact")
        for report in reports
        if isinstance(report, dict) and isinstance(report.get("report_artifact"), str)
    ]
    ok(
        "publishable_report_artifacts",
        len(report_artifacts) >= 3 and all(_rel_exists(path) and _report_text_has_required_headings(path) for path in report_artifacts),
        f"{len(report_artifacts)} report artifacts",
    )
    reproduction_ready = []
    for report in reports:
        if not isinstance(report, dict):
            reproduction_ready.append(False)
            continue
        data_paths = report.get("data_artifacts", [])
        script_paths = report.get("scripts", [])
        reproduction_ready.append(
            bool(report.get("reproduction_command"))
            and bool(report.get("expected_results"))
            and bool(report.get("tolerance_bounds"))
            and isinstance(data_paths, list)
            and data_paths
            and all(isinstance(path, str) and _rel_exists(path) for path in data_paths)
            and isinstance(script_paths, list)
            and script_paths
            and all(isinstance(path, str) and _rel_exists(path) for path in script_paths)
        )
    ok("publishable_report_reproduction_inputs", bool(reproduction_ready) and all(reproduction_ready), f"{sum(1 for item in reproduction_ready if item)}/{len(reproduction_ready)} ready")
    badges = [report.get("reproducibility_badge") for report in reports if isinstance(report, dict)]
    ok("reproducibility_badges", len(badges) >= 3 and all(badges), f"{len(badges)} badges")
    external_reproductions = [
        report.get("external_reproduction", {})
        for report in reports
        if isinstance(report, dict) and isinstance(report.get("external_reproduction"), dict)
    ]
    within_tolerance_count = sum(
        1 for item in external_reproductions if item.get("within_tolerance") == True
    )
    ok(
        "external_reproduction_within_tolerance",
        within_tolerance_count > 0,
        f"{within_tolerance_count} within tolerance",
    )
    return r

def self_test():
    r = _checks()
    assert len(r) >= 26
    for x in r:
        assert "check" in x and "passed" in x
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True

def main():
    logger = configure_test_logging("check_report_output_contract")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv: self_test(); return
    results = _checks(); p = sum(1 for x in results if x["passed"]); t = len(results); v = "PASS" if p == t else "FAIL"
    if as_json:
        print(json.dumps({"bead_id": BEAD, "section": SECTION, "gate_script": os.path.basename(__file__), "checks_passed": p, "checks_total": t, "verdict": v, "checks": results}, indent=2))
    else:
        for x in results: print(f"  [{'PASS' if x['passed'] else 'FAIL'}] {x['check']}: {x['detail']}")
        print(f"\n{BEAD}: {p}/{t} checks - {v}")
    sys.exit(0 if v == "PASS" else 1)

if __name__ == "__main__": main()
