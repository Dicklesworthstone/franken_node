#!/usr/bin/env python3
"""
Claim-Language Policy Enforcer.

Validates that docs/CLAIMS_REGISTRY.md exists, is well-formed,
and that all registered claims reference existing verification artifacts.

Usage:
    python3 scripts/check_claim_language.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL
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

REGISTRY_PATH = ROOT / "docs" / "CLAIMS_REGISTRY.md"
ARTIFACTS_DIR = ROOT / "artifacts"


def parse_claims(text: str) -> list[dict]:
    """Parse claim entries from the registry markdown."""
    # Strip fenced code blocks and HTML comments so templates aren't parsed
    text = re.sub(r'```.*?```', '', text, flags=re.DOTALL)
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)

    claims = []
    # Match ### CLAIM-<id>: <title> blocks
    claim_pattern = re.compile(
        r'^###\s+CLAIM-(\S+):\s+(.+?)$', re.MULTILINE
    )
    matches = list(claim_pattern.finditer(text))

    for i, match in enumerate(matches):
        claim_id = match.group(1)
        title = match.group(2).strip()
        # Get block text until next claim or end
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]

        claim = {
            "id": f"CLAIM-{claim_id}",
            "title": title,
            "category": _extract_field(block, "Category"),
            "claim_text": _extract_field(block, "Claim"),
            "evidence_artifacts": _extract_evidence_field(block),
            "verification_command": _extract_field(block, "Verification command"),
            "last_verified": _extract_field(block, "Last verified"),
            "status": _extract_field(block, "Status"),
        }
        claims.append(claim)

    return claims


def _extract_field(block: str, field_name: str) -> str:
    """Extract a field value from a claim block."""
    pattern = re.compile(
        rf'^\s*-\s+\*\*{re.escape(field_name)}\*\*:\s*(.+?)$',
        re.MULTILINE
    )
    m = pattern.search(block)
    return m.group(1).strip() if m else ""


# The registry's documented format (docs/CLAIMS_REGISTRY.md "Format") spells the
# field in the singular; the plural is the older spelling and still accepted.
EVIDENCE_FIELD_LABELS = ("Evidence artifact", "Evidence artifacts")
_CODE_SPAN = re.compile(r"`([^`]+)`")


def _extract_evidence_field(block: str) -> str:
    """The evidence field value, joined with its indented continuation lines."""
    for label in EVIDENCE_FIELD_LABELS:
        pattern = re.compile(
            rf"^[ \t]*-[ \t]+\*\*{re.escape(label)}\*\*:[ \t]*(.*(?:\n[ \t]+\S.*)*)",
            re.MULTILINE,
        )
        m = pattern.search(block)
        if m:
            return " ".join(line.strip() for line in m.group(1).splitlines()).strip()
    return ""


def artifact_paths(value: str) -> list[str]:
    """Repository paths cited by an evidence field.

    Markdown code spans are the documented form: every whitespace-free span
    containing a `/` is a path (a trailing `::item` or `:line` reference is
    dropped); spans that are commands or runtime templates (`<id>`) are not.
    Without any code span the value is a comma-separated list of paths.
    """
    if "`" in value:
        paths = []
        for span in _CODE_SPAN.findall(value):
            path = re.sub(r":\d[\d-]*$", "", span.split("::")[0])
            if (
                "/" in path
                and not any(ch.isspace() for ch in path)
                and "<" not in path
                and not path.startswith("-")
            ):
                paths.append(path)
        return paths
    return [p.strip() for p in value.split(",") if p.strip()]


def artifact_exists(path: str) -> bool:
    """A cited path exists, or (for a glob) matches at least one file."""
    if any(ch in path for ch in "*?["):
        return any(ROOT.glob(path))
    return (ROOT / path).exists()


def check_registry_exists() -> dict:
    """CLAIM-REGISTRY: Check that CLAIMS_REGISTRY.md exists."""
    check = {"id": "CLAIM-REGISTRY", "status": "PASS", "details": {}}
    if not REGISTRY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/CLAIMS_REGISTRY.md not found"
    else:
        check["details"]["path"] = str(REGISTRY_PATH.relative_to(ROOT))
        check["details"]["size_bytes"] = REGISTRY_PATH.stat().st_size
    return check


def check_registry_format() -> dict:
    """CLAIM-FORMAT: Check that the registry has required structure."""
    check = {"id": "CLAIM-FORMAT", "status": "PASS", "details": {}}
    if not REGISTRY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Registry file missing"
        return check

    text = REGISTRY_PATH.read_text()
    # Must have a top-level heading
    if not re.search(r'^#\s+Claims Registry', text, re.MULTILINE):
        check["status"] = "FAIL"
        check["details"]["error"] = "Missing '# Claims Registry' heading"
        return check

    # Must have the Registered Claims section
    if "## Registered Claims" not in text:
        check["status"] = "FAIL"
        check["details"]["error"] = "Missing '## Registered Claims' section"
        return check

    check["details"]["well_formed"] = True
    return check


def check_claims_have_artifacts() -> dict:
    """CLAIM-ARTIFACTS: Check that registered claims reference existing artifacts."""
    check = {"id": "CLAIM-ARTIFACTS", "status": "PASS", "details": {"claims": []}}
    if not REGISTRY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Registry file missing"
        return check

    text = REGISTRY_PATH.read_text()
    claims = parse_claims(text)
    check["details"]["claim_count"] = len(claims)

    for claim in claims:
        entry = {"id": claim["id"], "title": claim["title"], "status": "PASS"}

        # Must have evidence_artifacts
        if not claim["evidence_artifacts"]:
            entry["status"] = "FAIL"
            entry["error"] = "No evidence artifacts specified"
            check["status"] = "FAIL"
        else:
            # Check each artifact path exists
            paths = artifact_paths(claim["evidence_artifacts"])
            if not paths:
                entry["status"] = "FAIL"
                entry["error"] = "Evidence field cites no repository path"
                check["status"] = "FAIL"
                check["details"]["claims"].append(entry)
                continue
            missing = []
            for p in paths:
                if not artifact_exists(p):
                    missing.append(p)
            if missing:
                entry["status"] = "FAIL"
                entry["error"] = f"Missing artifacts: {', '.join(missing)}"
                check["status"] = "FAIL"
            else:
                entry["artifact_count"] = len(paths)

        check["details"]["claims"].append(entry)

    return check


def check_evidence_verdicts() -> dict:
    """CLAIM-VERDICTS: cited JSON evidence parses, and any verdict it records is
    a non-empty string.

    Raw measurement data (corpus results, signed timing census) carries no
    verdict: each claim's verification command recomputes that live, and a
    committed verdict file only goes stale (bd-3agp's check_report.json said
    PASS for months after the live gate turned FAIL).
    """
    check = {"id": "CLAIM-VERDICTS", "status": "PASS", "details": {"claims": []}}
    if not REGISTRY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Registry file missing"
        return check

    text = REGISTRY_PATH.read_text()
    claims = parse_claims(text)

    for claim in claims:
        if not claim["evidence_artifacts"]:
            continue

        entry = {"id": claim["id"], "status": "PASS"}
        paths = artifact_paths(claim["evidence_artifacts"])

        for p in paths:
            full = ROOT / p
            if not full.exists():
                continue
            if full.suffix != ".json":
                continue
            try:
                data = json.loads(full.read_text())
                verdict = data.get("verdict") if isinstance(data, dict) else None
                if isinstance(data, dict) and "verdict" in data and not (
                    isinstance(verdict, str) and verdict.strip()
                ):
                    entry["status"] = "FAIL"
                    entry["error"] = f"{p}: 'verdict' must be a non-empty string"
                    check["status"] = "FAIL"
            except json.JSONDecodeError:
                entry["status"] = "FAIL"
                entry["error"] = f"{p}: invalid JSON"
                check["status"] = "FAIL"

        check["details"]["claims"].append(entry)

    return check


def check_policy_doc_exists() -> dict:
    """CLAIM-POLICY: Check that the policy spec document exists."""
    check = {"id": "CLAIM-POLICY", "status": "PASS", "details": {}}
    spec = ROOT / "docs" / "specs" / "section_10_1" / "bd-1mj_contract.md"
    if not spec.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Policy spec not found"
    else:
        check["details"]["path"] = str(spec.relative_to(ROOT))
    return check


def main():
    logger = configure_test_logging("check_claim_language")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_registry_exists(),
        check_registry_format(),
        check_claims_have_artifacts(),
        check_evidence_verdicts(),
        check_policy_doc_exists(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "claim_language_policy",
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
        print("=== Claim-Language Policy Enforcer ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL" and "error" in c.get("details", {}):
                print(f"       Error: {c['details']['error']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
