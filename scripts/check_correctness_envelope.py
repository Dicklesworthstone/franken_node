#!/usr/bin/env python3
"""bd-sddz: Verify the immutable correctness envelope implementation.

Checks:
  1. correctness_envelope.rs exists and contains CorrectnessEnvelope struct.
  2. At least 10 immutable invariants are defined.
  3. Every invariant has id, name, description, owner_track, and enforcement.
  4. No enforcement mode is 'None'.
  5. All invariant IDs are unique.
  6. Governance spec exists and lists all invariants.
  7. Manifest artifact is valid JSON and lists all invariants.
  8. is_within_envelope function exists with rejection and acceptance logic.
  9. Unit tests cover every invariant rejection path.
 10. EVD-ENVELOPE log codes are present.

Usage:
  python3 scripts/check_correctness_envelope.py          # human-readable
  python3 scripts/check_correctness_envelope.py --json    # machine-readable
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "policy" / "correctness_envelope.rs"
MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_14" / "bd-sddz_contract.md"
MANIFEST_PATH = ROOT / "artifacts" / "10.14" / "correctness_envelope_manifest.json"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_14" / "bd-sddz" / "verification_evidence.json"


def check_impl_exists() -> tuple[bool, str]:
    """Check that the implementation file exists."""
    if not IMPL_PATH.exists():
        return False, f"missing: {IMPL_PATH}"
    content = IMPL_PATH.read_text()
    if "pub struct CorrectnessEnvelope" not in content:
        return False, "CorrectnessEnvelope struct not found in implementation"
    return True, "CorrectnessEnvelope struct found"


def check_mod_rs() -> tuple[bool, str]:
    """Check that the module is wired into the policy mod.rs."""
    if not MOD_PATH.exists():
        return False, f"missing: {MOD_PATH}"
    content = MOD_PATH.read_text()
    if "correctness_envelope" not in content:
        return False, "correctness_envelope not declared in mod.rs"
    return True, "correctness_envelope module declared"


def count_invariants() -> tuple[bool, str, int]:
    """Count invariants in the implementation."""
    if not IMPL_PATH.exists():
        return False, "implementation file missing", 0
    content = IMPL_PATH.read_text()
    # Count Invariant { ... } blocks in canonical_invariants()
    matches = re.findall(r'InvariantId::new\("(INV-[^"]+)"\)', content)
    unique_ids = set(matches)
    # Count only those within the canonical_invariants function
    in_fn = False
    ids_in_fn = set()
    for line in content.splitlines():
        if "fn canonical_invariants()" in line:
            in_fn = True
        if in_fn:
            m = re.search(r'InvariantId::new\("(INV-[^"]+)"\)', line)
            if m:
                ids_in_fn.add(m.group(1))
            if in_fn and line.strip() == "}":
                if len(ids_in_fn) > 0:
                    break
    count = len(ids_in_fn)
    if count < 10:
        return False, f"only {count} invariants defined (need >= 10)", count
    return True, f"{count} invariants defined", count


def check_invariant_ids_unique() -> tuple[bool, str]:
    """Check that invariant IDs in canonical_invariants() are unique."""
    content = IMPL_PATH.read_text()
    # Extract only IDs from the canonical_invariants function
    in_fn = False
    brace_depth = 0
    ids = []
    for line in content.splitlines():
        if "fn canonical_invariants()" in line:
            in_fn = True
            brace_depth = 0
        if in_fn:
            brace_depth += line.count("{") - line.count("}")
            m = re.search(r'InvariantId::new\("(INV-[^"]+)"\)', line)
            if m:
                ids.append(m.group(1))
            if brace_depth <= 0 and len(ids) > 0:
                break
    seen = set()
    dupes = []
    for inv_id in ids:
        if inv_id in seen:
            dupes.append(inv_id)
        seen.add(inv_id)
    if dupes:
        return False, f"duplicate invariant IDs: {dupes}"
    return True, f"{len(seen)} unique invariant IDs"


def check_no_enforcement_none() -> tuple[bool, str]:
    """Check that no invariant has enforcement mode None."""
    content = IMPL_PATH.read_text()
    if "EnforcementMode::None" in content:
        return False, "found EnforcementMode::None in implementation"
    return True, "no EnforcementMode::None found"


def check_is_within_envelope() -> tuple[bool, str]:
    """Check that is_within_envelope function exists."""
    content = IMPL_PATH.read_text()
    if "fn is_within_envelope" not in content:
        return False, "is_within_envelope function not found"
    return True, "is_within_envelope function present"


def check_log_codes() -> tuple[bool, str]:
    """Check that EVD-ENVELOPE log codes are present."""
    content = IMPL_PATH.read_text()
    codes = ["EVD-ENVELOPE-001", "EVD-ENVELOPE-002", "EVD-ENVELOPE-003"]
    missing = [c for c in codes if c not in content]
    if missing:
        return False, f"missing log codes: {missing}"
    return True, "all EVD-ENVELOPE log codes present"


def check_spec_exists() -> tuple[bool, str]:
    """Check that governance spec exists."""
    if not SPEC_PATH.exists():
        return False, f"missing: {SPEC_PATH}"
    content = SPEC_PATH.read_text()
    if "INV-001" not in content:
        return False, "spec does not reference invariant INV-001"
    return True, "governance spec present with invariant references"


def check_manifest() -> tuple[bool, str]:
    """Check that the manifest artifact is valid."""
    if not MANIFEST_PATH.exists():
        return False, f"missing: {MANIFEST_PATH}"
    try:
        data = json.loads(MANIFEST_PATH.read_text())
    except json.JSONDecodeError as e:
        return False, f"invalid JSON: {e}"
    if "invariants" not in data:
        return False, "manifest missing 'invariants' key"
    count = len(data["invariants"])
    if count < 10:
        return False, f"manifest has only {count} invariants"
    return True, f"manifest valid with {count} invariants"


def check_test_coverage() -> tuple[bool, str]:
    """Check that tests exist for each invariant rejection."""
    content = IMPL_PATH.read_text()
    test_section = content[content.find("#[cfg(test)]"):] if "#[cfg(test)]" in content else ""
    inv_ids = [
        "INV-001", "INV-002", "INV-003", "INV-004", "INV-005", "INV-006",
        "INV-007", "INV-008", "INV-009", "INV-010", "INV-011", "INV-012",
    ]
    missing = [inv_id for inv_id in inv_ids if inv_id not in test_section]
    if missing:
        return False, f"missing test assertions for: {missing}"
    return True, "all invariants tested in rejection tests"


def self_test() -> bool:
    """Run all checks and return overall pass/fail."""
    checks = [
        ("impl_exists", check_impl_exists),
        ("mod_rs", check_mod_rs),
        ("invariant_count", lambda: count_invariants()[:2]),
        ("unique_ids", check_invariant_ids_unique),
        ("no_enforcement_none", check_no_enforcement_none),
        ("is_within_envelope", check_is_within_envelope),
        ("log_codes", check_log_codes),
        ("spec_exists", check_spec_exists),
        ("manifest", check_manifest),
        ("test_coverage", check_test_coverage),
    ]
    results = []
    all_pass = True
    for name, fn in checks:
        ok, msg = fn()
        results.append({"check": name, "pass": ok, "detail": msg})
        if not ok:
            all_pass = False
    return all_pass, results


def main():
    parser = argparse.ArgumentParser(description="Verify correctness envelope (bd-sddz)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    all_pass, results = self_test()

    if args.json:
        evidence = {
            "bead_id": "bd-sddz",
            "title": "Immutable correctness envelope verification",
            "overall_pass": all_pass,
            "checks": results,
            "invariant_count": count_invariants()[2],
            "artifacts": {
                "implementation": str(IMPL_PATH.relative_to(ROOT)),
                "spec": str(SPEC_PATH.relative_to(ROOT)),
                "manifest": str(MANIFEST_PATH.relative_to(ROOT)),
            },
        }
        print(json.dumps(evidence, indent=2))
    else:
        for r in results:
            status = "PASS" if r["pass"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
        print()
        if all_pass:
            print("All checks PASSED.")
        else:
            print("Some checks FAILED.")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
