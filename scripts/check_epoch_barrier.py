#!/usr/bin/env python3
"""bd-2wsm: Epoch transition barrier protocol — verification gate."""
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "epoch_transition_barrier.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-2wsm_contract.md"
BEAD, SECTION = "bd-2wsm", "10.14"

EVENT_CODES = [
    "BARRIER_PROPOSED", "BARRIER_DRAIN_ACK", "BARRIER_COMMITTED",
    "BARRIER_ABORTED", "BARRIER_TIMEOUT", "BARRIER_DRAIN_FAILED",
    "BARRIER_ABORT_SENT", "BARRIER_CONCURRENT_REJECTED",
    "BARRIER_TRANSCRIPT_EXPORTED", "BARRIER_PARTICIPANT_REGISTERED",
]
ERROR_CODES = [
    "ERR_BARRIER_CONCURRENT", "ERR_BARRIER_NO_PARTICIPANTS",
    "ERR_BARRIER_TIMEOUT", "ERR_BARRIER_DRAIN_FAILED",
    "ERR_BARRIER_ALREADY_COMPLETE", "ERR_BARRIER_INVALID_PHASE",
    "ERR_BARRIER_UNKNOWN_PARTICIPANT", "ERR_BARRIER_EPOCH_MISMATCH",
]
INVS = [
    "INV-BARRIER-ALL-ACK", "INV-BARRIER-NO-PARTIAL",
    "INV-BARRIER-ABORT-SAFE", "INV-BARRIER-SERIALIZED",
    "INV-BARRIER-TRANSCRIPT", "INV-BARRIER-TIMEOUT",
]

def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _checks() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    def ok(name: str, passed: bool, detail: str = "") -> None:
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read_text(IMPL) if IMPL.is_file() else ""
    mod_src = _read_text(MOD_RS) if MOD_RS.is_file() else ""
    ok("source_exists", IMPL.is_file(), str(IMPL))
    ok("module_wiring", "pub mod epoch_transition_barrier;" in mod_src)

    # Barrier phases
    phases = ["Proposed", "Draining", "Committed", "Aborted"]
    ok("barrier_phases", all(p in src for p in phases), f"{len(phases)} phases")

    # Key structs/enums
    for st in ["EpochTransitionBarrier", "BarrierInstance", "BarrierPhase",
               "DrainAck", "AbortReason", "BarrierError", "BarrierConfig",
               "BarrierTranscript", "TranscriptEntry", "BarrierAuditRecord"]:
        ok(f"struct_{st}", st in src and ("struct " + st in src or "enum " + st in src or "pub type " + st in src), st)

    # Core operations
    ok("propose", "fn propose" in src, "Barrier proposal")
    ok("record_drain_ack", "fn record_drain_ack" in src, "Drain ACK recording")
    ok("try_commit", "fn try_commit" in src, "Commit attempt")
    ok("abort", "fn abort" in src, "Barrier abort")
    ok("record_drain_failure", "fn record_drain_failure" in src, "Drain failure handling")
    ok("check_participant_timeouts", "fn check_participant_timeouts" in src, "Timeout checking")
    ok("register_participant", "fn register_participant" in src, "Participant registration")
    ok("export_jsonl", "fn export_jsonl" in src, "JSONL export")

    # Invariant enforcement
    ok("all_acked_check", "fn all_acked" in src, "INV-BARRIER-ALL-ACK")
    ok("missing_acks", "fn missing_acks" in src, "Missing ACK tracking")
    ok("is_terminal", "fn is_terminal" in src, "Terminal state check")
    ok("serialized_barrier", "is_barrier_active" in src and "ConcurrentBarrier" in src, "INV-BARRIER-SERIALIZED")
    ok(
        "epoch_mismatch",
        "EpochMismatch" in src
        and "expected_epoch" in src
        and ".checked_add(1)" in src
        and "target_epoch != expected_epoch" in src,
        "Epoch validation",
    )

    # Event and error codes
    ok("event_codes", sum(1 for c in EVENT_CODES if c in src) >= 10, f"{sum(1 for c in EVENT_CODES if c in src)}/10")
    ok("error_codes", sum(1 for c in ERROR_CODES if c in src) >= 8, f"{sum(1 for c in ERROR_CODES if c in src)}/8")
    ok("invariant_markers", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")

    # Schema version and config
    ok("schema_version", "eb-v1.0" in src, "eb-v1.0")
    ok("default_timeout", "DEFAULT_BARRIER_TIMEOUT_MS" in src and "DEFAULT_DRAIN_TIMEOUT_MS" in src, "Timeout defaults")
    ok("config_validate", "fn validate" in src, "Config validation")
    ok("participant_timeout_override", "participant_timeouts" in src and "drain_timeout_for" in src, "Per-participant timeouts")

    # Spec and tests
    ok("spec_alignment", SPEC.is_file(), str(SPEC))
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 30, f"{test_count} tests")

    return results


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def self_test() -> bool:
    results = _checks()
    _require(len(results) >= 25, "too few checks")
    for check in results:
        _require("check" in check and "passed" in check, "malformed check result")
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main() -> int:
    configure_test_logging("check_epoch_barrier")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test()
        return 0
    results = _checks()
    p = sum(1 for x in results if x["passed"])
    t = len(results)
    v = "PASS" if p == t else "FAIL"
    if as_json:
        print(
            json.dumps(
                {
                    "bead_id": BEAD,
                    "section": SECTION,
                    "gate_script": Path(__file__).name,
                    "checks_passed": p,
                    "checks_total": t,
                    "verdict": v,
                    "checks": results,
                },
                indent=2,
            )
        )
    else:
        for x in results:
            print(f"  [{'PASS' if x['passed'] else 'FAIL'}] {x['check']}: {x['detail']}")
        print(f"\n{BEAD}: {p}/{t} checks — {v}")
    return 0 if v == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
