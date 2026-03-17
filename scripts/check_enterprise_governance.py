#!/usr/bin/env python3
"""bd-3mj9: Enterprise governance integrations — verification gate."""

import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools",
                     "enterprise_governance.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_15", "bd-3mj9_contract.md")

BEAD = "bd-3mj9"
SECTION = "15"

REQUIRED_CATEGORIES = [
    "AccessControl", "DataRetention", "AuditLogging",
    "ChangeManagement", "IncidentResponse",
]
REQUIRED_ENFORCEMENTS = ["Mandatory", "Recommended", "Advisory"]
REQUIRED_STATUSES = ["Compliant", "NonCompliant", "PartiallyCompliant", "NotAssessed"]
REQUIRED_CODES = [f"EGI-{str(i).zfill(3)}" for i in range(1, 11)] + [
    "EGI-ERR-001", "EGI-ERR-002",
]
REQUIRED_INVARIANTS = [
    "INV-EGI-ENFORCED", "INV-EGI-ASSESSED", "INV-EGI-DETERMINISTIC",
    "INV-EGI-GATED", "INV-EGI-VERSIONED", "INV-EGI-AUDITABLE",
]


def _read(p):
    with open(p) as f:
        return f.read()


def _checks():
    results = []

    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read(IMPL)

    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod enterprise_governance;" in _read(MOD_RS), "tools/mod.rs")

    found_cats = [c for c in REQUIRED_CATEGORIES if c in src]
    ok("rule_categories", len(found_cats) >= 5, f"{len(found_cats)}/5")

    found_enf = [e for e in REQUIRED_ENFORCEMENTS if e in src]
    ok("enforcement_levels", len(found_enf) >= 3, f"{len(found_enf)}/3")

    found_sts = [s for s in REQUIRED_STATUSES if s in src]
    ok("compliance_statuses", len(found_sts) >= 4, f"{len(found_sts)}/4")

    for st in ["GovernanceRule", "ComplianceAssessment", "CategoryCompliance",
               "ComplianceReport", "EnterpriseGovernance"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    ok("gate_actions", all(a in src for a in ["Allow", "Warn", "Block"]),
       "Policy enforcement gating")
    ok("compliance_rate", "compliance_rate" in src, "Per-category compliance rate")
    ok(
        "hash_surface",
        all(token in src for token in [
            "compute_report_content_hash",
            "category.total_rules",
            "category.compliant",
            "category.non_compliant",
            "category.partially_compliant",
            "category.not_assessed",
            "category.compliance_rate",
            "blocked_rules",
        ]),
        "ComplianceReport hash covers category payload",
    )
    ok("evidence_capture", "evidence" in src and "assessor" in src, "Evidence-based assessments")
    ok("blocked_rules", "blocked_rules" in src, "Blocked rules tracking")

    found_codes = [c for c in REQUIRED_CODES if c in src]
    ok("event_codes", len(found_codes) >= 12, f"{len(found_codes)}/12")

    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants", len(found_invs) >= 6, f"{len(found_invs)}/6")

    ok("audit_log", "EgiAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("schema_version", "SCHEMA_VERSION" in src and "egi-v1.0" in src, "egi-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 24, f"{test_count} tests (>=24)")

    return results


def self_test():
    results = _checks()
    assert len(results) >= 15
    for r in results:
        assert "check" in r and "passed" in r
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main():
    logger = configure_test_logging("check_enterprise_governance")
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
