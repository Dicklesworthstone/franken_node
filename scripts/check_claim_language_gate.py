#!/usr/bin/env python3
"""Verification script for bd-2ji2: claim language gate.

Usage:
    python scripts/check_claim_language_gate.py          # human-readable
    python scripts/check_claim_language_gate.py --json    # machine-readable
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

IMPL = ROOT / "tests" / "conformance" / "adjacent_claim_language_gate.rs"
POLICY_DOC = ROOT / "docs" / "policy" / "adjacent_substrate_claim_language.md"
SPEC = ROOT / "docs" / "specs" / "section_10_16" / "bd-2ji2_contract.md"
REPORT = ROOT / "artifacts" / "10.16" / "adjacent_claim_language_gate_report.json"

CLAIM_CATEGORIES = ["Tui", "Api", "Storage", "Model"]

EVENT_CODES = [
    "CLAIM_GATE_SCAN_START",
    "CLAIM_LINKED",
    "CLAIM_UNLINKED",
    "CLAIM_LINK_BROKEN",
    "CLAIM_GATE_PASS",
    "CLAIM_GATE_FAIL",
]

INVARIANTS = [
    "INV-CLG-LINKED",
    "INV-CLG-VERIFIED",
    "INV-CLG-COMPLETE",
    "INV-CLG-BLOCKING",
]

REQUIRED_TYPES = [
    "pub enum ClaimCategory",
    "pub enum ClaimStatus",
    "pub struct Claim",
    "pub struct ClaimGateEvent",
    "pub struct ClaimGateSummary",
    "pub struct ClaimLanguageGate",
]

REQUIRED_METHODS = [
    "fn scan_claim(",
    "fn scan_batch(",
    "fn gate_pass(",
    "fn summary(",
    "fn claims(",
    "fn events(",
    "fn take_events(",
    "fn to_report(",
    "fn label(",
    "fn all(",
    "fn is_pass(",
]

REQUIRED_TESTS = [
    "test_category_all",
    "test_category_labels",
    "test_category_display",
    "test_category_serde_roundtrip",
    "test_status_linked_passes",
    "test_status_unlinked_fails",
    "test_status_broken_link_fails",
    "test_status_display",
    "test_status_serde_roundtrip",
    "test_summary_gate_pass",
    "test_summary_gate_fail_unlinked",
    "test_summary_gate_fail_broken",
    "test_summary_gate_fail_empty",
    "test_summary_display",
    "test_gate_all_linked",
    "test_gate_unlinked_fails",
    "test_gate_broken_link_fails",
    "test_gate_empty_fails",
    "test_gate_batch_scan",
    "test_gate_summary_counts",
    "test_linked_emits_scan_start",
    "test_linked_emits_claim_linked",
    "test_unlinked_emits_claim_unlinked",
    "test_broken_emits_claim_link_broken",
    "test_event_has_claim_hash",
    "test_take_events_drains",
    "test_report_structure",
    "test_report_claims_count",
    "test_report_fail_verdict",
    "test_default_gate",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_claim_serde_roundtrip",
    "test_claim_gate_event_serde",
    "test_determinism_identical_claims",
    "test_tui_claim_linked",
    "test_api_claim_linked",
    "test_storage_claim_linked",
    "test_model_claim_linked",
]


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.exists():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_impl_test_count():
    if not IMPL.exists():
        return {"check": "conformance test count", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 30
    return {
        "check": "conformance test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 30)",
    }


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_ser = "Serialize" in text and "Deserialize" in text
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_ser,
        "detail": "found" if has_ser else "NOT FOUND",
    }


def check_report():
    results = []
    if not REPORT.exists():
        results.append({"check": "report: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "report: exists", "pass": True, "detail": "found"})
    try:
        data = json.loads(REPORT.read_text())
    except json.JSONDecodeError:
        results.append({"check": "report: valid JSON", "pass": False, "detail": "invalid JSON"})
        return results
    results.append({"check": "report: valid JSON", "pass": True, "detail": "valid"})

    # Gate verdict
    verdict = data.get("gate_verdict", "")
    results.append({
        "check": "report: gate verdict PASS",
        "pass": verdict == "PASS",
        "detail": verdict,
    })

    # Claims present
    claims = data.get("claims", [])
    has_claims = len(claims) >= 4
    results.append({
        "check": "report: claims present",
        "pass": has_claims,
        "detail": f"{len(claims)} claims",
    })

    # All categories covered
    categories = {c.get("category", "") for c in claims}
    all_cats = all(cat.lower() in categories for cat in CLAIM_CATEGORIES)
    results.append({
        "check": "report: all categories covered",
        "pass": all_cats,
        "detail": f"categories: {sorted(categories)}" if all_cats else "missing categories",
    })

    # Zero unlinked
    summary = data.get("summary", {})
    zero_unlinked = summary.get("unlinked", -1) == 0
    results.append({
        "check": "report: zero unlinked claims",
        "pass": zero_unlinked,
        "detail": f"unlinked: {summary.get('unlinked', '?')}",
    })

    # Zero broken links
    zero_broken = summary.get("broken_links", -1) == 0
    results.append({
        "check": "report: zero broken links",
        "pass": zero_broken,
        "detail": f"broken_links: {summary.get('broken_links', '?')}",
    })

    return results


def check_policy_doc():
    results = []
    if not POLICY_DOC.exists():
        results.append({"check": "policy doc: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "policy doc: exists", "pass": True, "detail": "found"})
    text = POLICY_DOC.read_text()

    for cat in ["TUI", "API", "Storage", "Model"]:
        found = cat in text
        results.append({
            "check": f"policy doc: category {cat}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    for section in ["Evidence Linking", "Blocking Behavior", "Language Standards"]:
        found = section in text
        results.append({
            "check": f"policy doc: section '{section}'",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "conformance test"))
    checks.append(check_file(POLICY_DOC, "claim language policy"))
    checks.append(check_file(REPORT, "claim gate report"))

    # Test count
    checks.append(check_impl_test_count())

    # Serde derives
    checks.append(check_serde_derives())

    # Implementation content
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    # Report
    checks.extend(check_report())

    # Policy doc
    checks.extend(check_policy_doc())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-2ji2",
        "title": "Claim language gate for substrate-backed evidence",
        "section": "10.16",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": check_impl_test_count()["detail"].split()[0] if IMPL.exists() else 0,
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    logger = configure_test_logging("check_claim_language_gate")
    logger.info("starting %s verification", "check_claim_language_gate")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-2ji2 verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
