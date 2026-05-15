#!/usr/bin/env python3
"""bd-383z verification gate for counterfactual incident lab and mitigation synthesis."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


BEAD = "bd-383z"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/counterfactual_incident_lab.md"
IMPL_FILE = ROOT / "crates/franken-node/src/ops/mitigation_synthesis.rs"
MOD_FILE = ROOT / "crates/franken-node/src/ops/mod.rs"
LIB_FILE = ROOT / "crates/franken-node/src/lib.rs"
LAB_TEST = ROOT / "tests/lab/counterfactual_mitigation_eval.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_counterfactual_lab.py"
REPORT_FILE = ROOT / "artifacts/10.17/counterfactual_eval_report.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-383z/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-383z/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "LAB_INCIDENT_LOADED",
    "LAB_MITIGATION_SYNTHESIZED",
    "LAB_REPLAY_COMPARED",
    "LAB_LOSS_DELTA_COMPUTED",
    "LAB_MITIGATION_PROMOTED",
]

REQUIRED_ERROR_CODES = [
    "ERR_LAB_TRACE_CORRUPT",
    "ERR_LAB_REPLAY_DIVERGED",
    "ERR_LAB_MITIGATION_UNSAFE",
    "ERR_LAB_ROLLOUT_UNSIGNED",
    "ERR_LAB_ROLLBACK_MISSING",
    "ERR_LAB_LOSS_DELTA_NEGATIVE",
]

REQUIRED_INVARIANTS = [
    "INV-LAB-REPLAY-FIDELITY",
    "INV-LAB-SIGNED-ROLLOUT",
    "INV-LAB-ROLLBACK-CONTRACT",
    "INV-LAB-LOSS-DELTA-POSITIVE",
]


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read(path))


def _strip_rust_comments(text: str) -> str:
    out = []
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


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _checks() -> list[dict]:
    checks = []
    impl_src = _read_rust_source(IMPL_FILE)
    mod_src = _read_rust_source(MOD_FILE)
    lib_src = _read_rust_source(LIB_FILE)
    spec_src = _read(SPEC_FILE)
    lab_test_src = _read_rust_source(LAB_TEST)

    # File existence checks
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check("Ops mod file exists", MOD_FILE.exists(), str(MOD_FILE)))
    checks.append(_check(
        "Library module wired",
        "pub mod ops;" in lib_src,
        "pub mod ops; in lib.rs",
    ))
    checks.append(_check(
        "Ops mod exports mitigation_synthesis",
        "pub mod mitigation_synthesis;" in mod_src,
        "pub mod mitigation_synthesis; in ops/mod.rs",
    ))

    # Required implementation tokens
    required_impl_tokens = [
        "struct IncidentTrace",
        "struct MitigationCandidate",
        "struct RolloutContract",
        "struct RollbackContract",
        "struct PromotedMitigation",
        "struct IncidentLab",
        "fn load_trace",
        "fn replay_baseline",
        "fn synthesize_mitigation",
        "fn compare_replay",
        "fn promote_mitigation",
        "fn run_full_workflow",
        "struct LabDecision",
        "struct ReplayComparison",
        "struct LabConfig",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    # Event codes
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Error codes
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Invariants
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv}",
            inv in impl_src and inv in spec_src,
            inv,
        ))

    # Rust unit tests
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 8", test_count >= 8, f"found {test_count}"))

    # Lab test file
    checks.append(_check("Lab test exists", LAB_TEST.exists(), str(LAB_TEST)))
    lab_test_count = lab_test_src.count("#[test]")
    checks.append(_check(
        "Lab test has >= 10 tests",
        lab_test_count >= 10,
        f"found {lab_test_count}",
    ))

    # Python checker unit test
    checks.append(_check("Python checker unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "counterfactual-lab-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Counterfactual incident lab and mitigation synthesis workflow",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "lab_contract": {
            "requires_signed_rollout": True,
            "requires_rollback_contract": True,
            "requires_positive_loss_delta": True,
            "requires_trace_integrity": True,
        },
    }


def write_report(result: dict) -> None:
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict:
    checks = []
    checks.append(_check("event code count >= 5", len(REQUIRED_EVENT_CODES) >= 5))
    checks.append(_check("error code count >= 6", len(REQUIRED_ERROR_CODES) >= 6))
    checks.append(_check("invariant count >= 4", len(REQUIRED_INVARIANTS) >= 4))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 10))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_counterfactual_lab",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    configure_test_logging("check_counterfactual_lab")
    parser = argparse.ArgumentParser(description="bd-383z checker")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--build-report", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        st = self_test()
        if args.json:
            print(json.dumps(st, indent=2))
        else:
            print(f"self-test: {st['verdict']} ({st['passed']}/{st['passed'] + st['failed']})")
        sys.exit(0 if st["verdict"] == "PASS" else 1)

    result = run_all()
    if args.build_report:
        write_report(result)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-383z: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
