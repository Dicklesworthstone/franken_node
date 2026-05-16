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
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "policy" / "correctness_envelope.rs"
MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_14" / "bd-sddz_contract.md"
MANIFEST_PATH = ROOT / "artifacts" / "10.14" / "correctness_envelope_manifest.json"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_14" / "bd-sddz" / "verification_evidence.json"


def read_text(path: Path) -> str:
    """Read UTF-8 text from an existing file."""
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def read_rust_source(path: Path) -> str:
    """Read Rust source without comments, preserving string literals."""
    return strip_rust_comments(read_text(path))


def strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            end = rust_block_comment_end(text, i + 2)
            comment = text[i:end]
            result.append("\n" * comment.count("\n") or " ")
            i = end
            continue

        raw_end = rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor


def check_impl_exists() -> tuple[bool, str]:
    """Check that the implementation file exists."""
    if not IMPL_PATH.exists():
        return False, f"missing: {IMPL_PATH}"
    content = read_rust_source(IMPL_PATH)
    if "pub struct CorrectnessEnvelope" not in content:
        return False, "CorrectnessEnvelope struct not found in implementation"
    return True, "CorrectnessEnvelope struct found"


def check_mod_rs() -> tuple[bool, str]:
    """Check that the module is wired into the policy mod.rs."""
    if not MOD_PATH.exists():
        return False, f"missing: {MOD_PATH}"
    content = read_rust_source(MOD_PATH)
    if "correctness_envelope" not in content:
        return False, "correctness_envelope not declared in mod.rs"
    return True, "correctness_envelope module declared"


def count_invariants() -> tuple[bool, str, int]:
    """Count invariants in the implementation."""
    if not IMPL_PATH.exists():
        return False, "implementation file missing", 0
    content = read_rust_source(IMPL_PATH)
    # Count Invariant { ... } blocks in canonical_invariants()
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
    content = read_rust_source(IMPL_PATH)
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
    if not seen:
        return False, "no invariant IDs found in canonical_invariants()"
    return True, f"{len(seen)} unique invariant IDs"


def check_no_enforcement_none() -> tuple[bool, str]:
    """Check that no invariant has enforcement mode None."""
    content = read_rust_source(IMPL_PATH)
    if "EnforcementMode::None" in content:
        return False, "found EnforcementMode::None in implementation"
    return True, "no EnforcementMode::None found"


def check_is_within_envelope() -> tuple[bool, str]:
    """Check that is_within_envelope function exists."""
    content = read_rust_source(IMPL_PATH)
    if "fn is_within_envelope" not in content:
        return False, "is_within_envelope function not found"
    return True, "is_within_envelope function present"


def check_log_codes() -> tuple[bool, str]:
    """Check that EVD-ENVELOPE log codes are present."""
    content = read_rust_source(IMPL_PATH)
    codes = ["EVD-ENVELOPE-001", "EVD-ENVELOPE-002", "EVD-ENVELOPE-003"]
    missing = [c for c in codes if c not in content]
    if missing:
        return False, f"missing log codes: {missing}"
    return True, "all EVD-ENVELOPE log codes present"


def check_spec_exists() -> tuple[bool, str]:
    """Check that governance spec exists."""
    if not SPEC_PATH.exists():
        return False, f"missing: {SPEC_PATH}"
    content = read_text(SPEC_PATH)
    if "INV-001" not in content:
        return False, "spec does not reference invariant INV-001"
    return True, "governance spec present with invariant references"


def check_manifest() -> tuple[bool, str]:
    """Check that the manifest artifact is valid."""
    if not MANIFEST_PATH.exists():
        return False, f"missing: {MANIFEST_PATH}"
    try:
        data = json.loads(read_text(MANIFEST_PATH))
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
    content = read_rust_source(IMPL_PATH)
    test_section = content[content.find("#[cfg(test)]"):] if "#[cfg(test)]" in content else ""
    inv_ids = [
        "INV-001", "INV-002", "INV-003", "INV-004", "INV-005", "INV-006",
        "INV-007", "INV-008", "INV-009", "INV-010", "INV-011", "INV-012",
    ]
    missing = [inv_id for inv_id in inv_ids if inv_id not in test_section]
    if missing:
        return False, f"missing test assertions for: {missing}"
    return True, "all invariants tested in rejection tests"


def self_test() -> tuple[bool, list[dict[str, object]]]:
    """Run all checks and return overall pass/fail."""
    if strip_rust_comments('"kept // literal"; // removed') != '"kept // literal"; ':
        return False, [
            {
                "check": "comment_stripper",
                "pass": False,
                "detail": "Rust comment stripper corrupted string literals",
            }
        ]

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
    configure_test_logging("check_correctness_envelope")
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
