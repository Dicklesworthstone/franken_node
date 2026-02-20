#!/usr/bin/env python3
"""bd-3a3q: Verify the anytime-valid guardrail monitor set implementation.

Checks:
  1. guardrail_monitor.rs exists with GuardrailMonitor trait.
  2. GuardrailVerdict enum with Allow/Block/Warn.
  3. SystemState struct with required fields.
  4. Four concrete monitors registered.
  5. GuardrailMonitorSet with check_all.
  6. EVD-GUARD event codes (001-004).
  7. Anytime-valid property (is_valid_at_any_stopping_point).
  8. Threshold enforcement (envelope minimums).
  9. Unit test count >= 35.
  10. Spec document exists.
  11. Telemetry CSV exists and is valid.

Usage:
  python3 scripts/check_guardrail_monitor.py          # human-readable
  python3 scripts/check_guardrail_monitor.py --json    # machine-readable
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "policy" / "guardrail_monitor.rs"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_14" / "bd-3a3q_contract.md"
TELEMETRY_PATH = ROOT / "artifacts" / "10.14" / "guardrail_monitor_telemetry.csv"


def _read_impl() -> str:
    return IMPL_PATH.read_text()


def check_impl_exists() -> tuple[bool, str]:
    if not IMPL_PATH.exists():
        return False, f"missing: {IMPL_PATH}"
    content = _read_impl()
    if "trait GuardrailMonitor" not in content:
        return False, "GuardrailMonitor trait not found"
    return True, "GuardrailMonitor trait found"


def check_verdict_enum() -> tuple[bool, str]:
    content = _read_impl()
    if "enum GuardrailVerdict" not in content:
        return False, "GuardrailVerdict enum not found"
    for variant in ["Allow", "Block", "Warn"]:
        if variant not in content:
            return False, f"GuardrailVerdict missing variant: {variant}"
    return True, "GuardrailVerdict with Allow/Block/Warn"


def check_system_state() -> tuple[bool, str]:
    content = _read_impl()
    if "pub struct SystemState" not in content:
        return False, "SystemState struct not found"
    fields = [
        "memory_used_bytes", "memory_budget_bytes", "durability_level",
        "hardening_level", "proposed_hardening_level", "evidence_emission_active",
        "epoch_id",
    ]
    missing = [f for f in fields if f not in content]
    if missing:
        return False, f"SystemState missing fields: {missing}"
    return True, "SystemState with all required fields"


def check_concrete_monitors() -> tuple[bool, str]:
    content = _read_impl()
    monitors = [
        "MemoryBudgetGuardrail",
        "DurabilityLossGuardrail",
        "HardeningRegressionGuardrail",
        "EvidenceEmissionGuardrail",
    ]
    missing = [m for m in monitors if f"pub struct {m}" not in content]
    if missing:
        return False, f"missing concrete monitors: {missing}"
    return True, "4 concrete monitors implemented"


def check_monitor_set() -> tuple[bool, str]:
    content = _read_impl()
    if "pub struct GuardrailMonitorSet" not in content:
        return False, "GuardrailMonitorSet not found"
    if "fn check_all" not in content:
        return False, "check_all method not found"
    if "fn evaluate" not in content:
        return False, "evaluate method not found"
    return True, "GuardrailMonitorSet with check_all and evaluate"


def check_event_codes() -> tuple[bool, str]:
    content = _read_impl()
    codes = ["EVD-GUARD-001", "EVD-GUARD-002", "EVD-GUARD-003", "EVD-GUARD-004"]
    missing = [c for c in codes if c not in content]
    if missing:
        return False, f"missing event codes: {missing}"
    return True, "all EVD-GUARD event codes present"


def check_anytime_valid() -> tuple[bool, str]:
    content = _read_impl()
    if "is_valid_at_any_stopping_point" not in content:
        return False, "anytime-valid method not found"
    if "anytime_valid" not in content.lower():
        return False, "anytime-valid tests not found"
    return True, "anytime-valid property implemented and tested"


def check_threshold_enforcement() -> tuple[bool, str]:
    content = _read_impl()
    if "ENVELOPE_MIN" not in content:
        return False, "envelope minimum constants not found"
    if "respects_envelope_minimum" not in content:
        return False, "envelope minimum enforcement test not found"
    return True, "threshold enforcement with envelope minimums"


def count_tests() -> tuple[bool, str, int]:
    content = _read_impl()
    test_fns = re.findall(r"#\[test\]", content)
    count = len(test_fns)
    if count < 35:
        return False, f"only {count} tests (need >= 35)", count
    return True, f"{count} unit tests", count


def check_spec_exists() -> tuple[bool, str]:
    if not SPEC_PATH.exists():
        return False, f"missing: {SPEC_PATH}"
    content = SPEC_PATH.read_text()
    required = ["GuardrailVerdict", "GuardrailMonitorSet", "anytime"]
    missing = [r for r in required if r.lower() not in content.lower()]
    if missing:
        return False, f"spec missing content: {missing}"
    return True, "spec document with required content"


def check_telemetry_csv() -> tuple[bool, str]:
    if not TELEMETRY_PATH.exists():
        return False, f"missing: {TELEMETRY_PATH}"
    try:
        text = TELEMETRY_PATH.read_text().strip()
        lines = text.split("\n")
        if len(lines) < 2:
            return False, "telemetry CSV has fewer than 2 lines"
        reader = csv.reader(lines)
        header = next(reader)
        required_cols = ["monitor_name", "verdict", "budget_id"]
        missing = [c for c in required_cols if c not in header]
        if missing:
            return False, f"telemetry CSV missing columns: {missing}"
        rows = list(reader)
        if len(rows) < 5:
            return False, f"telemetry CSV has only {len(rows)} data rows (need >= 5)"
        return True, f"telemetry CSV valid with {len(rows)} rows"
    except Exception as e:
        return False, f"telemetry CSV parse error: {e}"


def self_test() -> tuple[bool, list]:
    checks = [
        ("impl_exists", check_impl_exists),
        ("verdict_enum", check_verdict_enum),
        ("system_state", check_system_state),
        ("concrete_monitors", check_concrete_monitors),
        ("monitor_set", check_monitor_set),
        ("event_codes", check_event_codes),
        ("anytime_valid", check_anytime_valid),
        ("threshold_enforcement", check_threshold_enforcement),
        ("test_count", lambda: count_tests()[:2]),
        ("spec_exists", check_spec_exists),
        ("telemetry_csv", check_telemetry_csv),
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
    parser = argparse.ArgumentParser(description="Verify guardrail monitors (bd-3a3q)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    all_pass, results = self_test()
    test_count = count_tests()[2]

    if args.json:
        evidence = {
            "bead_id": "bd-3a3q",
            "title": "Anytime-valid guardrail monitor set",
            "overall_pass": all_pass,
            "checks": results,
            "test_count": test_count,
            "artifacts": {
                "implementation": str(IMPL_PATH.relative_to(ROOT)),
                "spec": str(SPEC_PATH.relative_to(ROOT)),
                "telemetry": str(TELEMETRY_PATH.relative_to(ROOT)),
            },
        }
        print(json.dumps(evidence, indent=2))
    else:
        for r in results:
            status = "PASS" if r["pass"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
        print()
        print("All checks PASSED." if all_pass else "Some checks FAILED.")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
