#!/usr/bin/env python3
"""
Cross-Track Canonical-Reference Linter.

Validates that integration/adoption beads properly reference their canonical
owner tracks and artifact contracts, preventing silent semantic drift.

Reads the capability ownership registry and the beads database to find beads
in integration tracks that reference capabilities without citing canonical owners.

Usage:
    python3 scripts/lint_cross_track_references.py [--json]

Exit codes:
    0 = PASS (no lint findings)
    1 = FAIL (findings detected)
    2 = ERROR (registry or beads missing)
"""

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ROOT / "docs" / "capability_ownership_registry.json"

# Regex patterns that indicate cross-track integration/adoption.
# These are matched against the "objective text" (title + task objective +
# in-scope + acceptance criteria), NOT against boilerplate testing sections.
INTEGRATION_PATTERNS = [
    r"\bintegrat(?:e|es|ed|ing)\b(?!\s+tests?\b)(?!\s*/\s*e2e)",
    r"\badopt(?:s|ed|ing|ion)\b",
    r"\bpolicy[\s-]gate\b",
    r"\benforcement\s+gate\b",
    r"\brelease\s+gate\b",
    r"\bconsumed\s+by\b",
    r"\benforced\s+through\b",
    r"\bfrom\s+`?10\.\d+",
    r"\bcross[\s-]track\b",
    r"\bcross[\s-]section\b",
    r"\bcanonical[\s-]owner\b",
]

# Section headers that start boilerplate content (excluded from keyword scan)
BOILERPLATE_HEADERS = [
    "testing & logging requirements",
    "task-specific clarification",
    "expected artifacts",
]


def extract_objective_text(description: str) -> str:
    """Extract objective/scope text, stripping boilerplate testing sections.

    Bead descriptions follow a structured template where the top portion
    (Task Objective, In Scope, Acceptance Criteria) contains the real
    integration semantics, while the bottom sections (Testing & Logging,
    Task-Specific Clarification, Expected Artifacts) contain boilerplate
    that falsely matches integration keywords like 'integration tests'.
    """
    lines = description.split("\n")
    objective_lines = []
    in_boilerplate = False

    for line in lines:
        stripped = line.strip().lower().rstrip(":")
        if any(stripped.startswith(h) for h in BOILERPLATE_HEADERS):
            in_boilerplate = True
        elif stripped and not stripped[0].isspace() and stripped.endswith(":"):
            # A new top-level header that isn't boilerplate restores scanning
            # (handles rare cases of sections after boilerplate)
            pass
        if not in_boilerplate:
            objective_lines.append(line)

    return "\n".join(objective_lines)


def is_integration_bead(title: str, description: str) -> bool:
    """Determine if a bead involves cross-track integration.

    Uses regex patterns matched against objective text only,
    excluding boilerplate testing sections.
    """
    objective = extract_objective_text(description)
    text = f"{title} {objective}".lower()
    return any(re.search(pat, text) for pat in INTEGRATION_PATTERNS)


def load_registry() -> dict:
    """Load the capability ownership registry."""
    if not REGISTRY_PATH.exists():
        print(f"ERROR: Registry not found: {REGISTRY_PATH}", file=sys.stderr)
        sys.exit(2)
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def load_beads() -> list[dict]:
    """Load all beads via br list --json."""
    try:
        result = subprocess.run(
            ["br", "list", "--json"],
            capture_output=True, text=True, timeout=3600,
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(f"ERROR: Failed to load beads: {e}", file=sys.stderr)
        sys.exit(2)


def extract_section(title: str) -> str | None:
    """Extract section number from bead title like '[10.15] ...'."""
    m = re.match(r"\[(\d+\.\d+)\]", title)
    return m.group(1) if m else None


def find_referenced_tracks(text: str) -> list[str]:
    """Find track references like '10.13', '10.14' in text."""
    return re.findall(r"10\.\d+", text)


def lint_bead(bead: dict, registry: dict) -> list[dict]:
    """Lint a single bead for cross-track reference issues."""
    findings = []
    title = bead.get("title", "")
    desc = bead.get("description", "")
    section = extract_section(title)

    if not section:
        return []

    # Only lint beads that exhibit cross-track integration language
    if not is_integration_bead(title, desc):
        return []

    # Use objective text (no boilerplate) for reference and domain matching
    objective = extract_objective_text(desc)
    objective_lower = f"{title} {objective}".lower()

    # Find track references in the objective text
    referenced_tracks = find_referenced_tracks(objective)
    if not referenced_tracks:
        return []

    # Check each capability to see if this bead should cite canonical owners
    for cap in registry.get("capabilities", []):
        cap_owner = cap["canonical_owner"]
        owners = cap_owner.split("+")
        integration_tracks = cap.get("integration_tracks", [])

        # If this bead's section is an integration track for this capability
        if section in integration_tracks:
            # Check if the objective references the canonical owner track
            owner_referenced = any(o in referenced_tracks for o in owners)

            if not owner_referenced:
                # Check if domain keywords appear in the objective text
                domain_kws = [
                    w.lower() for w in re.split(r"[,/+\s]+", cap["domain"])
                    if len(w) > 3
                ]
                domain_match = any(kw in objective_lower for kw in domain_kws)

                if domain_match:
                    findings.append({
                        "finding_id": f"XREF-{cap['id']}-{bead['id']}",
                        "category": "missing_canonical_reference",
                        "bead_id": bead["id"],
                        "bead_title": title[:80],
                        "bead_section": section,
                        "capability": cap["id"],
                        "capability_domain": cap["domain"],
                        "canonical_owner": cap_owner,
                        "remediation": (
                            f"Bead {bead['id']} (section {section}) integrates "
                            f"capability {cap['id']} but does not reference "
                            f"canonical owner track {cap_owner}. Add explicit "
                            f"reference to the canonical implementation."
                        ),
                    })

    return findings


def main():
    json_output = "--json" in sys.argv

    registry = load_registry()
    beads = load_beads()

    all_findings = []
    beads_linted = 0
    integration_beads = 0

    for bead in beads:
        beads_linted += 1
        title = bead.get("title", "")
        desc = bead.get("description", "")

        if is_integration_bead(title, desc):
            integration_beads += 1

        findings = lint_bead(bead, registry)
        all_findings.extend(findings)

    verdict = "PASS" if not all_findings else "FAIL"
    timestamp = datetime.now(timezone.utc).isoformat()

    report = {
        "gate": "cross_track_canonical_reference_lint",
        "verdict": verdict,
        "timestamp": timestamp,
        "beads_scanned": beads_linted,
        "integration_beads_found": integration_beads,
        "findings_count": len(all_findings),
        "findings": all_findings,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Cross-Track Canonical-Reference Lint ===")
        print(f"Beads scanned: {beads_linted}")
        print(f"Integration beads: {integration_beads}")
        print(f"Findings: {len(all_findings)}")
        print(f"Verdict: {verdict}")
        if all_findings:
            print()
            for f in all_findings:
                print(f"  [{f['finding_id']}] {f['bead_id']}: {f['bead_title']}")
                print(f"    Missing ref to {f['canonical_owner']} "
                      f"for {f['capability']} ({f['capability_domain'][:50]})")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
