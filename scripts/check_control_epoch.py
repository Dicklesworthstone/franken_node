#!/usr/bin/env python3
"""bd-3hdv: Verify monotonic control epoch in canonical manifest state.

Checks:
  1. control_epoch.rs exists with required types and operations
  2. ControlEpoch type implements Copy + Ord + Hash traits
  3. EpochStore provides epoch_advance, epoch_read, epoch_set
  4. EpochTransition contains required fields and verify() method
  5. Error codes defined: EPOCH_REGRESSION, EPOCH_OVERFLOW, EPOCH_INVALID_MANIFEST
  6. Invariant markers present in code
  7. Unit tests cover monotonicity, regression, crash recovery, overflow

Usage:
  python3 scripts/check_control_epoch.py          # human-readable
  python3 scripts/check_control_epoch.py --json    # machine-readable
  python3 scripts/check_control_epoch.py --self-test
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "control_epoch.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-3hdv_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mod.rs"

REQUIRED_TYPES = [
    "pub struct ControlEpoch",
    "pub struct EpochTransition",
    "pub struct EpochStore",
    "pub enum EpochError",
]

REQUIRED_METHODS = [
    "fn epoch_advance(",
    "fn epoch_read(",
    "fn epoch_set(",
    "fn recover(",
    "fn committed_epoch(",
    "fn verify(",
    "fn next(",
]

REQUIRED_ERROR_CODES = [
    "EPOCH_REGRESSION",
    "EPOCH_OVERFLOW",
    "EPOCH_INVALID_MANIFEST",
]

REQUIRED_EVENT_CODES = [
    "EPOCH_ADVANCED",
    "EPOCH_REGRESSION_REJECTED",
    "EPOCH_READ",
    "EPOCH_RECOVERED",
]

REQUIRED_INVARIANTS = [
    "INV-EPOCH-MONOTONIC",
    "INV-EPOCH-DURABLE",
    "INV-EPOCH-SIGNED-EVENT",
    "INV-EPOCH-NO-GAP",
]

INVARIANT_IMPLEMENTATION_MARKERS = {
    "INV-EPOCH-MONOTONIC": [
        "if attempted <= self.current",
        "EpochError::EpochRegression",
        "self.current = new_epoch;",
    ],
    "INV-EPOCH-DURABLE": [
        "committed: ControlEpoch",
        "current: ControlEpoch::new(committed_epoch)",
        "self.committed = new_epoch;",
        "pub fn committed_epoch(&self) -> ControlEpoch",
    ],
    "INV-EPOCH-SIGNED-EVENT": [
        "pub struct EpochTransition",
        "fn compute_mac(",
        "let event_mac =",
        "constant_time::ct_eq(&self.event_mac, &expected)",
    ],
    "INV-EPOCH-NO-GAP": [
        "pub fn next(self) -> Option<Self>",
        "self.0.checked_add(1).map(Self)",
        ".next()",
        "EpochError::EpochOverflow",
    ],
}

REQUIRED_TESTS = [
    "epoch_genesis_is_zero",
    "epoch_next",
    "epoch_next_overflow",
    "epoch_ordering",
    "single_advance",
    "sequential_advances",
    "thousand_advances_monotonic",
    "regression_same_value_rejected",
    "regression_lower_value_rejected",
    "transition_event_verifiable",
    "transition_event_tamper_detected",
    "crash_recovery_preserves_committed",
    "advance_after_recovery",
    "empty_manifest_hash_rejected",
    "epoch_at_max_overflows_on_advance",
    "error_display_all_variants",
    "same_inputs_produce_same_mac",
    "different_inputs_produce_different_mac",
]

REQUIRED_TRAITS = [
    "Copy",
    "Ord",
    "Hash",
    "PartialEq",
    "Eq",
]

SPEC_CONTENT = [
    "ControlEpoch",
    "EpochTransition",
    "EpochStore",
    "INV-EPOCH-MONOTONIC",
    "INV-EPOCH-DURABLE",
    "epoch_advance",
    "epoch_read",
    "crash recovery",
]


def check_file(path, label):
    ok = path.is_file()
    rel = display_path(path) if ok else str(path)
    return {
        "id": f"CEP-FILE-{label.upper().replace(' ', '-')}",
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {rel}" if ok else f"MISSING: {rel}",
    }


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def check_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"id": f"CEP-{category.upper()}-MISSING",
                           "check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    content = read_text(path)
    for p in patterns:
        found = p in content
        short = p[:30].upper().replace(' ', '-').replace('(', '').replace(')', '')
        results.append({
            "id": f"CEP-{category.upper()}-{short}",
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def read_rust_source(path: Path) -> str:
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
            i = rust_block_comment_end(text, i + 2)
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


def check_rust_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"id": f"CEP-{category.upper()}-MISSING",
                           "check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    content = read_rust_source(path)
    for p in patterns:
        found = p in content
        short = p[:30].upper().replace(' ', '-').replace('(', '').replace(')', '')
        results.append({
            "id": f"CEP-{category.upper()}-{short}",
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_invariants(path):
    results = []
    if not path.is_file():
        for invariant in REQUIRED_INVARIANTS:
            results.append({"id": "CEP-INVARIANT-MISSING",
                           "check": f"invariant: {invariant}", "pass": False, "detail": "file missing"})
        return results
    content = read_rust_source(path)
    for invariant in REQUIRED_INVARIANTS:
        markers = INVARIANT_IMPLEMENTATION_MARKERS.get(invariant, [])
        missing = [marker for marker in markers if marker not in content]
        short = invariant[:30].upper().replace(' ', '-').replace('(', '').replace(')', '')
        results.append({
            "id": f"CEP-INVARIANT-{short}",
            "check": f"invariant: {invariant}",
            "pass": not missing,
            "detail": "implementation markers present" if not missing else f"missing: {missing}",
        })
    return results


def check_module_registered():
    if not MOD_RS.is_file():
        return {"id": "CEP-MOD-REG", "check": "module registered in mod.rs",
                "pass": False, "detail": "mod.rs missing"}
    content = read_rust_source(MOD_RS)
    found = "control_epoch" in content
    return {
        "id": "CEP-MOD-REG",
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_traits(path):
    results = []
    if not path.is_file():
        return results
    content = read_rust_source(path)
    for trait_name in REQUIRED_TRAITS:
        found = trait_name in content
        results.append({
            "id": f"CEP-TRAIT-{trait_name.upper()}",
            "check": f"trait: {trait_name}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_test_count(path):
    if not path.is_file():
        return {"id": "CEP-TEST-COUNT", "check": "test count",
                "pass": False, "detail": "file missing"}
    content = read_rust_source(path)
    count = len(re.findall(r"#\[test\]", content))
    return {
        "id": "CEP-TEST-COUNT",
        "check": "unit test count",
        "pass": count >= 20,
        "detail": f"{count} tests (minimum 20)",
    }


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))

    # Module registration
    checks.append(check_module_registered())

    # Types
    checks.extend(check_rust_content(IMPL, REQUIRED_TYPES, "type"))

    # Methods
    checks.extend(check_rust_content(IMPL, REQUIRED_METHODS, "method"))

    # Error codes
    checks.extend(check_rust_content(IMPL, REQUIRED_ERROR_CODES, "error_code"))

    # Event codes
    checks.extend(check_rust_content(IMPL, REQUIRED_EVENT_CODES, "event_code"))

    # Invariants
    checks.extend(check_invariants(IMPL))

    # Traits
    checks.extend(check_traits(IMPL))

    # Test count
    checks.append(check_test_count(IMPL))

    # Required tests
    checks.extend(check_rust_content(IMPL, REQUIRED_TESTS, "test"))

    # Spec content
    checks.extend(check_content(SPEC, SPEC_CONTENT, "spec"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)

    return {
        "bead": "bd-3hdv",
        "title": "Monotonic control epoch in canonical manifest state",
        "section": "10.14",
        "verdict": "PASS" if passed == total else "FAIL",
        "summary": {
            "passing_checks": passed,
            "failing_checks": total - passed,
            "total_checks": total,
        },
        "checks": checks,
    }


def self_test():
    result = run_checks()
    _require(isinstance(result, dict), "result must be a dict")
    _require(result["bead"] == "bd-3hdv", "unexpected bead id")
    _require("checks" in result, "checks missing")
    _require(isinstance(result["checks"], list), "checks must be a list")
    _require(len(result["checks"]) > 0, "checks must not be empty")
    _require("verdict" in result, "verdict missing")
    _require("summary" in result, "summary missing")
    print(f"self_test passed: {result['summary']['passing_checks']}/{result['summary']['total_checks']} checks")
    return result


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    configure_test_logging("check_control_epoch")
    if "--self-test" in sys.argv:
        self_test()
        return 0

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("=== bd-3hdv: Control Epoch Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing_checks']}/{s['total_checks']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
