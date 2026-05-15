#!/usr/bin/env python3
"""bd-7om: Canonical cancel -> drain -> finalize protocol contracts -- verification gate.

Usage:
    python scripts/check_cancellable_task_protocol.py            # human-readable
    python scripts/check_cancellable_task_protocol.py --json     # machine-readable JSON
    python scripts/check_cancellable_task_protocol.py --self-test # self-test mode
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


SRC = ROOT / "crates" / "franken-node" / "src" / "runtime" / "cancellable_task.rs"
MOD = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_11" / "bd-7om_contract.md"
TEST_SUITE = ROOT / "tests" / "test_check_cancellable_task_protocol.py"
EVIDENCE = ROOT / "artifacts" / "section_10_11" / "bd-7om" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_11" / "bd-7om" / "verification_summary.md"

BEAD = "bd-7om"
SECTION = "10.11"

EVENT_CODES = [
    "FN-CX-001", "FN-CX-002", "FN-CX-003", "FN-CX-004", "FN-CX-005",
    "FN-CX-006", "FN-CX-007", "FN-CX-008", "FN-CX-009", "FN-CX-010",
]

ERROR_CODES = [
    "ERR_CXT_INVALID_PHASE",
    "ERR_CXT_DRAIN_TIMEOUT",
    "ERR_CXT_CLOSURE_INCOMPLETE",
    "ERR_CXT_TASK_NOT_FOUND",
    "ERR_CXT_ALREADY_FINALIZED",
    "ERR_CXT_DUPLICATE_TASK",
]

INVARIANTS = [
    "INV-CXT-THREE-PHASE",
    "INV-CXT-DRAIN-BOUNDED",
    "INV-CXT-FINALIZE-RECORD",
    "INV-CXT-CLOSURE-COMPLETE",
    "INV-CXT-LANE-RELEASE",
    "INV-CXT-NESTED-PROPAGATION",
]


def _safe_rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "passed": passed, "detail": detail or ("found" if passed else "missing")}


def _read(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text()


def _strip_rust_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        raw_start = _rust_raw_string_start(text, i)
        if raw_start is not None:
            body_start, hashes = raw_start
            end = _rust_raw_string_end(text, body_start + 1, hashes)
            if end is None:
                out.append(text[i:])
                break
            out.append(text[i:end])
            i = end
            continue

        if ch == '"':
            end = _rust_quoted_literal_end(text, i, ch)
            out.append(text[i:end])
            i = end
            continue

        if text.startswith("//", i):
            newline = text.find("\n", i + 2)
            if newline == -1:
                break
            out.append("\n")
            i = newline + 1
            continue

        if text.startswith("/*", i):
            i = _rust_block_comment_end(text, i + 2)
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def _rust_raw_string_start(text: str, index: int) -> tuple[int, int] | None:
    n = len(text)
    if text.startswith("br", index):
        cursor = index + 2
    elif text.startswith("r", index):
        cursor = index + 1
    else:
        return None

    hashes = 0
    while cursor < n and text[cursor] == "#":
        hashes += 1
        cursor += 1
    if cursor < n and text[cursor] == '"':
        return cursor, hashes
    return None


def _rust_raw_string_end(text: str, index: int, hashes: int) -> int | None:
    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, index)
    if end == -1:
        return None
    return end + len(terminator)


def _rust_quoted_literal_end(text: str, index: int, quote: str) -> int:
    i = index + 1
    n = len(text)
    escaped = False
    while i < n:
        ch = text[i]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == quote:
            return i + 1
        i += 1
    return n


def _rust_block_comment_end(text: str, index: int) -> int:
    depth = 1
    i = index
    n = len(text)
    while i < n and depth:
        if text.startswith("/*", i):
            depth += 1
            i += 2
        elif text.startswith("*/", i):
            depth -= 1
            i += 2
        else:
            i += 1
    return i


def _checks() -> list:
    results = []
    src = _strip_rust_comments(_read(SRC))
    mod_src = _strip_rust_comments(_read(MOD))

    # --- File existence ---
    results.append(_check("source file exists", SRC.exists(), _safe_rel(SRC)))
    results.append(_check("module wired in runtime/mod.rs",
                          "pub mod cancellable_task;" in mod_src,
                          "runtime/mod.rs contains pub mod cancellable_task"))
    results.append(_check("spec contract exists", SPEC.exists(), _safe_rel(SPEC)))
    results.append(_check("test suite exists", TEST_SUITE.exists(), _safe_rel(TEST_SUITE)))
    results.append(_check("verification evidence exists", EVIDENCE.exists(), _safe_rel(EVIDENCE)))
    results.append(_check("verification summary exists", SUMMARY.exists(), _safe_rel(SUMMARY)))

    # --- Trait and types ---
    results.append(_check("CancellableTask trait",
                          "trait CancellableTask" in src))
    results.append(_check("CancellationRuntime struct",
                          "struct CancellationRuntime" in src))
    results.append(_check("DrainResult enum",
                          "enum DrainResult" in src))
    results.append(_check("FinalizeRecord struct",
                          "struct FinalizeRecord" in src))
    results.append(_check("ObligationClosureProof struct",
                          "struct ObligationClosureProof" in src))

    # --- Methods ---
    results.append(_check("on_cancel method", "fn on_cancel" in src))
    results.append(_check("on_drain_complete method", "fn on_drain_complete" in src))
    results.append(_check("on_finalize method", "fn on_finalize" in src))
    results.append(_check("register_task function", "fn register_task" in src))
    results.append(_check("cancel_task function", "fn cancel_task" in src))

    # --- Event codes ---
    ec_found = sum(1 for ec in EVENT_CODES if ec in src)
    results.append(_check(
        f"event codes ({ec_found}/{len(EVENT_CODES)})",
        ec_found == len(EVENT_CODES),
        f"{ec_found}/{len(EVENT_CODES)}"))

    # --- Error codes ---
    err_found = sum(1 for ec in ERROR_CODES if ec in src)
    results.append(_check(
        f"error codes ({err_found}/{len(ERROR_CODES)})",
        err_found == len(ERROR_CODES),
        f"{err_found}/{len(ERROR_CODES)}"))

    # --- Invariant constants ---
    inv_found = sum(1 for inv in INVARIANTS if inv in src)
    results.append(_check(
        f"invariant constants ({inv_found}/{len(INVARIANTS)})",
        inv_found == len(INVARIANTS),
        f"{inv_found}/{len(INVARIANTS)}"))

    # --- Schema version ---
    results.append(_check("schema version cxt-v1.0", "cxt-v1.0" in src))

    # --- Serde derives ---
    results.append(_check("Serialize/Deserialize derives",
                          "Serialize" in src and "Deserialize" in src))

    # --- Unit tests ---
    test_count = len(re.findall(r"#\[test\]", src))
    results.append(_check(f"unit tests >= 15 ({test_count})", test_count >= 15, f"{test_count} tests"))

    # --- cfg(test) module ---
    results.append(_check("#[cfg(test)] module", "#[cfg(test)]" in src))

    return results


def self_test():
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    return {
        "name": "cancellable_task_protocol_verification",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": len(checks) - passed,
        "checks": checks,
        "verdict": "PASS" if all(c["passed"] for c in checks) else "FAIL",
    }


def run_checks() -> dict:
    checks = _checks()
    passing = sum(1 for c in checks if c["passed"])
    failing = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "bead_id": BEAD,
        "title": "Canonical cancel -> drain -> finalize protocol contracts",
        "section": SECTION,
        "overall_pass": failing == 0,
        "verdict": verdict,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "checks": checks,
        "events": EVENT_CODES,
    }


def main():
    configure_test_logging("check_cancellable_task_protocol")
    if "--self-test" in sys.argv:
        result = self_test()
        if result["verdict"] == "PASS":
            print("self_test passed")
            sys.exit(0)
        else:
            failures = [c for c in result["checks"] if not c["passed"]]
            detail = "; ".join(f"{c['check']}: {c['detail']}" for c in failures[:5])
            print(f"self_test failed: {detail}")
            sys.exit(1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["overall_pass"] else 1)

    for c in result["checks"]:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"  [{status}] {c['check']}: {c['detail']}")

    passing = result["summary"]["passing"]
    total = result["summary"]["total"]
    print(f"\n{BEAD} verification: {result['verdict']} ({passing}/{total} checks pass)")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
