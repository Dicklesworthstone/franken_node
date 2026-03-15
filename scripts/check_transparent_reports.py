#!/usr/bin/env python3
"""bd-10ee: Transparent technical reports — verification gate."""

import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools",
                     "transparent_reports.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_16", "bd-10ee_contract.md")

BEAD = "bd-10ee"
SECTION = "16"

REQUIRED_CATEGORIES = ["SecurityIncident", "PerformanceRegression", "DataIntegrity",
                        "ServiceOutage", "ComplianceGap"]
REQUIRED_SECTIONS = ["executive_summary", "incident_description", "timeline",
                      "root_cause_analysis", "impact_assessment", "corrective_actions",
                      "lessons_learned"]
REQUIRED_STATUSES = ["Identified", "Planned", "Implemented", "Verified"]
REQUIRED_CODES = [f"TR-{str(i).zfill(3)}" for i in range(1, 11)] + ["TR-ERR-001", "TR-ERR-002"]
REQUIRED_INVARIANTS = [
    "INV-TR-TRANSPARENT", "INV-TR-DETERMINISTIC", "INV-TR-TIMELINE",
    "INV-TR-CORRECTIVE", "INV-TR-VERSIONED", "INV-TR-AUDITABLE",
]


def _read(p):
    with open(p) as f:
        return f.read()


def _checks():
    results = []
    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read(IMPL)
    production_src = src.split("#[cfg(test)]", 1)[0]
    report_hash_region = ""
    if "fn compute_report_content_hash" in production_src and "fn compute_catalog_content_hash" in production_src:
        report_hash_region = production_src.split("fn compute_report_content_hash", 1)[1].split(
            "fn compute_catalog_content_hash", 1
        )[0]
    catalog_hash_region = ""
    if "fn compute_catalog_content_hash" in production_src and "// ---------------------------------------------------------------------------\n// Engine" in production_src:
        catalog_hash_region = production_src.split("fn compute_catalog_content_hash", 1)[1].split(
            "// ---------------------------------------------------------------------------\n// Engine", 1
        )[0]

    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod transparent_reports;" in _read(MOD_RS), "tools/mod.rs")

    found_cats = [c for c in REQUIRED_CATEGORIES if c in src]
    ok("report_categories", len(found_cats) >= 5, f"{len(found_cats)}/5")

    found_secs = [s for s in REQUIRED_SECTIONS if f'"{s}"' in src]
    ok("required_sections", len(found_secs) >= 7, f"{len(found_secs)}/7")

    found_sts = [s for s in REQUIRED_STATUSES if s in src]
    ok("action_statuses", len(found_sts) >= 4, f"{len(found_sts)}/4")

    ok("status_transitions", "valid_transitions" in src, "State machine enforcement")

    for st in ["TransparentReport", "TimelineEntry", "CorrectiveAction",
               "ReportCatalog", "TransparentReports"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    ok("timeline_validation", "TimelineEntry" in src and "timeline" in src, "Timeline structure")
    ok("root_cause_analysis", "root_causes" in src, "Root cause tracking")
    ok("lessons_learned", "lessons_learned" in src, "Lessons learned section")
    report_hash_fields = [
        "report_id", "severity", "timeline", "root_causes",
        "corrective_actions", "lessons_learned", "report_version", "created_at",
    ]
    report_hash_refreshes = production_src.count("compute_report_content_hash(") >= 3
    ok(
        "content_hashing",
        all(field in report_hash_region for field in report_hash_fields) and report_hash_refreshes,
        "report hash covers mutable report content and refreshes on mutations",
    )
    ok(
        "catalog_hashing",
        all(field in catalog_hash_region for field in ["by_category", "by_severity", "open_actions", "report_version"]),
        "catalog hash covers category, severity, and open action state",
    )
    ok("catalog_generation", "generate_catalog" in src and "ReportCatalog" in src, "Catalog with open_actions")

    found_codes = [c for c in REQUIRED_CODES if c in src]
    ok("event_codes", len(found_codes) >= 12, f"{len(found_codes)}/12")

    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants", len(found_invs) >= 6, f"{len(found_invs)}/6")

    ok("audit_log", "TrAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("report_version", "REPORT_VERSION" in src and "tr-v1.0" in src, "tr-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 22, f"{test_count} tests (>=22)")

    return results


def self_test():
    results = _checks()
    assert len(results) >= 15
    for r in results:
        assert "check" in r and "passed" in r
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main():
    logger = configure_test_logging("check_transparent_reports")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test(); return

    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"

    if as_json:
        print(json.dumps({
            "bead_id": BEAD, "section": SECTION,
            "gate_script": os.path.basename(__file__),
            "checks_passed": passed, "checks_total": total,
            "verdict": verdict, "checks": results,
        }, indent=2))
    else:
        for r in results:
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"  [{mark}] {r['check']}: {r['detail']}")
        print(f"\n{BEAD}: {passed}/{total} checks — {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
