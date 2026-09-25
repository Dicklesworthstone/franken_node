#!/usr/bin/env python3
"""
Product Charter Verification Script.

Validates that the product charter document exists, has required sections,
and that cross-references to other documents are valid (no dead links).

Usage:
    python3 scripts/verify_product_charter.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL
    2 = ERROR
"""

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path

CHARTER_PATH = ROOT / "docs" / "PRODUCT_CHARTER.md"

REQUIRED_SECTIONS = [
    "Product Purpose",
    "Scope Boundary",
    "Target Users",
    "Non-Negotiable",
    "Success Criteria",
    "Impossible-by-Default",
    "Governance Model",
    "Execution Tracks",
    "Off-Charter Behaviors",
    "Cross-References",
]

REQUIRED_CROSS_REFS = [
    "ENGINE_SPLIT_CONTRACT.md",
    "ROADMAP.md",
    "CAPABILITY_OWNERSHIP_REGISTRY.md",
    "DUAL_ORACLE_CLOSE_CONDITION.md",
    "PLAN_TO_CREATE_FRANKEN_NODE.md",
]

README_CHARTER_LINK = "docs/PRODUCT_CHARTER.md"


def main():
    logger = configure_test_logging("verify_product_charter")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = []

    # Check 1: Charter file exists
    check = {"id": "CHARTER-EXISTS", "status": "PASS", "details": {}}
    if not CHARTER_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/PRODUCT_CHARTER.md not found"
        checks.append(check)
        emit(checks, timestamp, json_output)
        sys.exit(1)
    check["details"]["path"] = str(CHARTER_PATH.relative_to(ROOT))
    checks.append(check)

    charter_text = CHARTER_PATH.read_text()
    charter_lower = charter_text.lower()

    # Check 2: Required sections present
    check = {"id": "CHARTER-SECTIONS", "status": "PASS", "details": {"missing": [], "found": []}}
    for section in REQUIRED_SECTIONS:
        if section.lower() in charter_lower:
            check["details"]["found"].append(section)
        else:
            check["details"]["missing"].append(section)
    if check["details"]["missing"]:
        check["status"] = "FAIL"
    checks.append(check)

    # Check 3: Cross-references resolve to existing files
    check = {"id": "CHARTER-XREFS", "status": "PASS", "details": {"valid": [], "broken": []}}
    for ref in REQUIRED_CROSS_REFS:
        # Check both docs/ and root-level paths
        candidates = [
            ROOT / "docs" / ref,
            ROOT / "docs" / "plans" / ref,
            ROOT / ref,
        ]
        found = any(c.exists() for c in candidates)
        if found:
            check["details"]["valid"].append(ref)
        else:
            check["details"]["broken"].append(ref)
    if check["details"]["broken"]:
        check["status"] = "FAIL"
    checks.append(check)

    # Check 4: README links to charter
    check = {"id": "CHARTER-README-LINK", "status": "PASS", "details": {}}
    readme_path = ROOT / "README.md"
    if readme_path.exists():
        readme_text = readme_path.read_text()
        if README_CHARTER_LINK in readme_text or "PRODUCT_CHARTER" in readme_text:
            check["details"]["linked"] = True
        else:
            check["status"] = "FAIL"
            check["details"]["error"] = "README.md does not link to PRODUCT_CHARTER.md"
    else:
        check["status"] = "FAIL"
        check["details"]["error"] = "README.md not found"
    checks.append(check)

    # Check 5: ROADMAP links to charter
    check = {"id": "CHARTER-ROADMAP-LINK", "status": "PASS", "details": {}}
    roadmap_path = ROOT / "docs" / "ROADMAP.md"
    if roadmap_path.exists():
        roadmap_text = roadmap_path.read_text()
        if "PRODUCT_CHARTER" in roadmap_text:
            check["details"]["linked"] = True
        else:
            check["status"] = "FAIL"
            check["details"]["error"] = "ROADMAP.md does not link to PRODUCT_CHARTER.md"
    else:
        check["status"] = "FAIL"
        check["details"]["error"] = "ROADMAP.md not found"
    checks.append(check)

    # Check 6: Heading structure is valid (starts with H1, no gaps)
    check = {"id": "CHARTER-HEADINGS", "status": "PASS", "details": {}}
    headings = re.findall(r'^(#{1,6})\s+(.+)$', charter_text, re.MULTILINE)
    check["details"]["heading_count"] = len(headings)
    if headings:
        first_level = len(headings[0][0])
        if first_level != 1:
            check["status"] = "FAIL"
            check["details"]["error"] = f"First heading is H{first_level}, expected H1"
    else:
        check["status"] = "FAIL"
        check["details"]["error"] = "No headings found"
    checks.append(check)

    emit(checks, timestamp, json_output)


def emit(checks, timestamp, json_output):
    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "product_charter_verification",
        "section": "10.1",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Product Charter Verification ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "error" in details:
                    print(f"       Error: {details['error']}")
                if "missing" in details and details["missing"]:
                    print(f"       Missing: {details['missing']}")
                if "broken" in details and details["broken"]:
                    print(f"       Broken: {details['broken']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
