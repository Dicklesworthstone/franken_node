#!/usr/bin/env python3
"""Verify bd-ufk5: VEF performance budget gates for p95/p99 hot paths.

Checks that the VEF performance budget gate infrastructure is correctly
implemented: Rust module present, budget thresholds defined for all hot
paths and modes, event codes documented, spec contract present, and the
gate evaluation logic is structurally sound.

Usage:
    python scripts/check_vef_perf_budget.py
    python scripts/check_vef_perf_budget.py --json
    python scripts/check_vef_perf_budget.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


CHECKS: list[dict[str, Any]] = []

# VEF hot paths and modes from the spec contract.
VEF_HOT_PATHS = [
    "receipt_emission",
    "chain_append",
    "checkpoint_computation",
    "verification_gate_check",
    "mode_transition",
]

VEF_MODES = ["normal", "restricted", "quarantine"]

REQUIRED_EVENT_CODES = [
    "VEF-PERF-001",
    "VEF-PERF-002",
    "VEF-PERF-003",
    "VEF-PERF-004",
    "VEF-PERF-005",
    "VEF-PERF-006",
    "VEF-PERF-ERR-001",
    "VEF-PERF-ERR-002",
]

REQUIRED_INVARIANTS = [
    "INV-VEF-PBG-BUDGET",
    "INV-VEF-PBG-GATE",
    "INV-VEF-PBG-PROFILING",
    "INV-VEF-PBG-MODE-AWARE",
    "INV-VEF-PBG-BASELINE",
    "INV-VEF-PBG-REPRODUCIBLE",
]

# Normal-mode base budgets from the spec contract.
NORMAL_BUDGETS: dict[str, tuple[float, float, float]] = {
    "receipt_emission": (2.0, 5.0, 15.0),
    "chain_append": (1.0, 3.0, 10.0),
    "checkpoint_computation": (5.0, 12.0, 25.0),
    "verification_gate_check": (1.5, 4.0, 12.0),
    "mode_transition": (3.0, 8.0, 20.0),
}

MODE_MULTIPLIERS: dict[str, float] = {
    "normal": 1.0,
    "restricted": 1.5,
    "quarantine": 2.0,
}


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    CHECKS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read_text(path))


def _strip_rust_comments(text: str) -> str:
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
            i = _rust_block_comment_end(text, i + 2)
            continue

        raw_end = _rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = _rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def _rust_raw_string_end(text: str, start: int) -> int | None:
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


def _rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def _rust_block_comment_end(text: str, start: int) -> int:
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


# ---------------------------------------------------------------------------
# Checks: Rust implementation
# ---------------------------------------------------------------------------

def check_rust_module_exists() -> None:
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs"
    exists = path.is_file()
    _check("rust_module_exists", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_mod_registration() -> None:
    mod_rs = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
    src = _read_rust_source(mod_rs)
    registered = "pub mod vef_perf_budget;" in src
    _check("mod_registration", registered, "vef_perf_budget registered in connector/mod.rs" if registered else "vef_perf_budget NOT in connector/mod.rs")


def check_hot_path_enum() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    for path_name in VEF_HOT_PATHS:
        # Match the enum variant based on the label
        found = f'"{path_name}"' in src
        _check(f"hot_path_{path_name}", found, f"hot path label {path_name} in source")


def check_mode_enum() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    for mode in VEF_MODES:
        found = f'"{mode}"' in src
        _check(f"mode_{mode}", found, f"mode label {mode} in source")


def check_event_codes() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    for code in REQUIRED_EVENT_CODES:
        found = f'"{code}"' in src
        _check(f"event_code_{code}", found, f"event code {code} defined" if found else f"event code {code} missing")


def check_invariant_constants() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    for inv in REQUIRED_INVARIANTS:
        found = f'"{inv}"' in src
        _check(f"invariant_{inv}", found, f"invariant {inv} defined" if found else f"invariant {inv} missing")


def check_budget_thresholds_defined() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    for path_name, (p95, p99, cold) in NORMAL_BUDGETS.items():
        # Check that the numeric values appear in the source
        p95_found = str(p95) in src
        p99_found = str(p99) in src
        cold_found = str(cold) in src
        all_found = p95_found and p99_found and cold_found
        _check(
            f"budget_{path_name}",
            all_found,
            f"{path_name}: p95={p95} p99={p99} cold={cold}" if all_found else f"{path_name}: threshold values not all found",
        )


def check_mode_multiplier_logic() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    for mode, mult in MODE_MULTIPLIERS.items():
        found = str(mult) in src
        _check(f"multiplier_{mode}", found, f"{mode} multiplier {mult}" if found else f"{mode} multiplier {mult} missing")


def check_gate_struct() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    found = "pub struct VefOverheadGate" in src
    _check("gate_struct", found, "VefOverheadGate defined" if found else "VefOverheadGate missing")


def check_evaluate_method() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    found = "fn evaluate" in src
    _check("evaluate_method", found, "evaluate method present" if found else "evaluate method missing")


def check_csv_output() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    found = "fn to_csv" in src
    _check("csv_output", found, "to_csv method present" if found else "to_csv method missing")


def check_inline_tests() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    test_count = len(re.findall(r"#\[test\]", src))
    passed = test_count >= 10
    _check("inline_tests", passed, f"{test_count} inline tests found (need >= 10)")


# ---------------------------------------------------------------------------
# Checks: Spec contract
# ---------------------------------------------------------------------------

def check_spec_contract() -> None:
    path = ROOT / "docs" / "specs" / "section_10_18" / "bd-ufk5_contract.md"
    exists = path.is_file()
    _check("spec_contract", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_spec_budget_tables() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_10_18" / "bd-ufk5_contract.md")
    for mode in ["Normal Mode", "Restricted Mode", "Quarantine Mode"]:
        found = mode in src
        _check(f"spec_table_{mode.split()[0].lower()}", found, f"{mode} budget table in spec" if found else f"{mode} budget table missing")


def check_spec_event_codes() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_10_18" / "bd-ufk5_contract.md")
    for code in REQUIRED_EVENT_CODES:
        found = code in src
        _check(f"spec_event_{code}", found, f"{code} in spec" if found else f"{code} missing from spec")


# ---------------------------------------------------------------------------
# Checks: Noise and reproducibility
# ---------------------------------------------------------------------------

def check_noise_tolerance() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    has_cv = "max_cv_pct" in src
    has_noise = "noise_multiplier" in src
    _check("noise_tolerance", has_cv and has_noise, "cv and noise multiplier defined" if has_cv and has_noise else "missing noise tolerance fields")


def check_warmup_iterations() -> None:
    src = _read_rust_source(ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_perf_budget.rs")
    found = "warmup_iterations" in src
    _check("warmup_iterations", found, "warmup_iterations field present" if found else "warmup_iterations missing")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_checks() -> list[dict[str, Any]]:
    CHECKS.clear()

    # Rust implementation checks
    check_rust_module_exists()
    check_mod_registration()
    check_hot_path_enum()
    check_mode_enum()
    check_event_codes()
    check_invariant_constants()
    check_budget_thresholds_defined()
    check_mode_multiplier_logic()
    check_gate_struct()
    check_evaluate_method()
    check_csv_output()
    check_inline_tests()

    # Spec contract checks
    check_spec_contract()
    check_spec_budget_tables()
    check_spec_event_codes()

    # Noise and reproducibility
    check_noise_tolerance()
    check_warmup_iterations()

    return CHECKS


def run_all() -> dict[str, Any]:
    checks = run_all_checks()
    total = len(checks)
    passed = sum(1 for c in checks if c["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-ufk5",
        "title": "VEF performance budget gates for p95/p99 hot paths",
        "section": "10.18",
        "gate": False,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "overall_pass": failed == 0,
        "total": total,
        "passed": passed,
        "failed": failed,
        "hot_paths": VEF_HOT_PATHS,
        "modes": VEF_MODES,
        "checks": checks,
    }


def self_test() -> bool:
    checks = run_all_checks()
    if not checks:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False

    strip_check_ok = _strip_rust_comments('"kept // literal"; // removed') == '"kept // literal"; '
    if not strip_check_ok:
        print("SELF-TEST FAIL: Rust comment stripper corrupted string literals", file=sys.stderr)
        return False

    required_keys = {"check", "pass", "detail"}
    for entry in checks:
        if not isinstance(entry, dict) or not required_keys.issubset(entry.keys()):
            print(f"SELF-TEST FAIL: malformed check entry: {entry}", file=sys.stderr)
            return False

    print(f"SELF-TEST OK: {len(checks)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    configure_test_logging("check_vef_perf_budget")
    parser = argparse.ArgumentParser(description="bd-ufk5: VEF performance budget gate verification")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    output = run_all()

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(
            f"\n  VEF Performance Budget Gate: {'PASS' if output['overall_pass'] else 'FAIL'} "
            f"({output['passed']}/{output['total']})\n"
        )
        for entry in output["checks"]:
            mark = "+" if entry["pass"] else "x"
            print(f"  [{mark}] {entry['check']}: {entry['detail']}")

    sys.exit(0 if output["overall_pass"] else 1)


if __name__ == "__main__":
    main()
