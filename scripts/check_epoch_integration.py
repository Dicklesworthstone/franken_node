#!/usr/bin/env python3
"""Verification script for bd-2gr: epoch integration in runtime services."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


BEAD_ID = "bd-2gr"
SECTION = "10.11"
TITLE = "Epoch Guard + Transition Barrier Integration"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_11" / "bd-2gr_contract.md"
GUARD_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "epoch_guard.rs"
TRANSITION_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "epoch_transition.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"

EVENT_CODES_GUARD = [
    "EPOCH_OPERATION_ACCEPTED",
    "STALE_EPOCH_REJECTED",
    "FUTURE_EPOCH_REJECTED",
    "EPOCH_UNAVAILABLE",
    "EPOCH_SIGNATURE_VERIFIED",
    "EPOCH_SIGNATURE_REJECTED",
]

EVENT_CODES_TRANSITION = [
    "EPOCH_PROPOSED",
    "EPOCH_DRAIN_REQUESTED",
    "EPOCH_DRAIN_CONFIRMED",
    "EPOCH_ADVANCED",
    "EPOCH_TRANSITION_ABORTED",
]

ERROR_CODES = [
    "STALE_EPOCH_REJECTED",
    "FUTURE_EPOCH_REJECTED",
    "EPOCH_UNAVAILABLE",
    "EPOCH_TRANSITION_NO_ACTIVE",
    "ERR_BARRIER_CONCURRENT",
    "EPOCH_TRANSITION_ADVANCE_MISMATCH",
]

INVARIANTS = [
    "INV-EP-MONOTONIC",
    "INV-EP-DRAIN-BARRIER",
    "INV-EP-FAIL-CLOSED",
    "INV-EP-SPLIT-BRAIN-GUARD",
    "INV-EP-IMMUTABLE-CREATION-EPOCH",
    "INV-EP-AUDIT-HISTORY",
]

REQUIRED_GUARD_TYPES = [
    "EpochGuardEvent",
    "EpochGuardError",
    "EpochSource",
    "StaticEpochSource",
    "EpochTaggedArtifact",
    "EpochGuard",
]

REQUIRED_TRANSITION_TYPES = [
    "EpochTransitionLogEvent",
    "EpochTransitionRecord",
    "EpochTransitionProposal",
    "EpochTransitionError",
    "ProductEpochCoordinator",
]

REQUIRED_GUARD_METHODS = [
    "new_signed",
    "artifact_id",
    "creation_epoch",
    "validate_operation_epoch",
    "validate_artifact_epoch",
    "verify_tagged_artifact",
]

REQUIRED_TRANSITION_METHODS = [
    "new",
    "current_epoch",
    "register_service",
    "validate_operation_epoch",
    "validate_replica_lag",
    "propose_transition",
    "ack_drain",
    "commit_transition",
    "abort_transition_timeout",
    "abort_transition_cancellation",
    "events",
    "history",
]

MIN_GUARD_TESTS = 9
MIN_TRANSITION_TESTS = 8


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": bool(passed), "detail": detail}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _has_type(source: str, name: str) -> bool:
    patterns = [
        rf"pub\s+struct\s+{name}\b",
        rf"pub\s+enum\s+{name}\b",
        rf"pub\s+trait\s+{name}\b",
        rf"struct\s+{name}\b",
        rf"enum\s+{name}\b",
        rf"trait\s+{name}\b",
    ]
    return any(re.search(p, source) for p in patterns)


def _has_method(source: str, name: str) -> bool:
    return bool(re.search(rf"fn\s+{name}\b", source))


def run_all() -> dict:
    spec = _read(SPEC_PATH)
    guard = _read(GUARD_RS)
    transition = _read(TRANSITION_RS)
    mod_rs = _read(MOD_RS)

    checks: list[dict] = []

    checks.append(_check("spec_exists", SPEC_PATH.is_file(), str(SPEC_PATH.relative_to(ROOT))))
    checks.append(_check("guard_module_exists", GUARD_RS.is_file(), str(GUARD_RS.relative_to(ROOT))))
    checks.append(
        _check(
            "transition_module_exists",
            TRANSITION_RS.is_file(),
            str(TRANSITION_RS.relative_to(ROOT)),
        )
    )

    checks.append(
        _check(
            "runtime_mod_wiring_guard",
            "pub mod epoch_guard;" in mod_rs,
            "runtime/mod.rs exports epoch_guard",
        )
    )
    checks.append(
        _check(
            "runtime_mod_wiring_transition",
            "pub mod epoch_transition;" in mod_rs,
            "runtime/mod.rs exports epoch_transition",
        )
    )

    for invariant in INVARIANTS:
        checks.append(
            _check(
                f"spec_invariant:{invariant}",
                invariant in spec,
                f"{invariant} present in contract",
            )
        )

    for code in EVENT_CODES_GUARD + EVENT_CODES_TRANSITION:
        checks.append(
            _check(
                f"spec_event:{code}",
                code in spec,
                f"{code} present in contract",
            )
        )

    for code in ERROR_CODES:
        checks.append(
            _check(
                f"spec_error:{code}",
                code in spec,
                f"{code} present in contract",
            )
        )

    for name in REQUIRED_GUARD_TYPES:
        checks.append(
            _check(
                f"guard_type:{name}",
                _has_type(guard, name),
                f"{name} present in epoch_guard.rs",
            )
        )

    for name in REQUIRED_TRANSITION_TYPES:
        checks.append(
            _check(
                f"transition_type:{name}",
                _has_type(transition, name),
                f"{name} present in epoch_transition.rs",
            )
        )

    for name in REQUIRED_GUARD_METHODS:
        checks.append(
            _check(
                f"guard_method:{name}",
                _has_method(guard, name),
                f"fn {name} exists in epoch_guard.rs",
            )
        )

    for name in REQUIRED_TRANSITION_METHODS:
        checks.append(
            _check(
                f"transition_method:{name}",
                _has_method(transition, name),
                f"fn {name} exists in epoch_transition.rs",
            )
        )

    for code in EVENT_CODES_GUARD:
        checks.append(
            _check(
                f"guard_event:{code}",
                code in guard,
                f"{code} declared/used in epoch_guard.rs",
            )
        )

    for code in EVENT_CODES_TRANSITION:
        checks.append(
            _check(
                f"transition_event:{code}",
                code in transition,
                f"{code} declared/used in epoch_transition.rs",
            )
        )

    combined = guard + "\n" + transition
    for code in ERROR_CODES:
        checks.append(
            _check(
                f"error_code:{code}",
                code in combined,
                f"{code} appears in runtime modules",
            )
        )

    checks.append(
        _check(
            "fail_closed_unavailable_path",
            "EpochUnavailable" in guard and "source.current_epoch()?" in guard,
            "unavailable epoch path returns error",
        )
    )
    checks.append(
        _check(
            "fail_closed_latency_test",
            "fail_closed_unavailable_returns_within_100ms" in guard,
            "explicit bounded-latency fail-closed test exists",
        )
    )

    private_creation_epoch = bool(
        re.search(
            r"pub\s+struct\s+EpochTaggedArtifact\s*\{[^}]*\bcreation_epoch:\s*ControlEpoch",
            guard,
            re.DOTALL,
        )
    ) and "pub creation_epoch" not in guard
    checks.append(
        _check(
            "artifact_creation_epoch_private",
            private_creation_epoch,
            "creation_epoch field is private",
        )
    )
    checks.append(
        _check(
            "artifact_creation_epoch_getter",
            "fn creation_epoch(&self)" in guard,
            "creation_epoch getter exists",
        )
    )
    checks.append(
        _check(
            "artifact_creation_epoch_no_setter",
            "fn set_creation_epoch" not in guard,
            "no creation_epoch mutation API",
        )
    )

    checks.append(
        _check(
            "epoch_key_signing_integration",
            "sign_epoch_artifact" in guard and "verify_epoch_signature" in guard,
            "epoch-scoped signature integration present",
        )
    )

    checks.append(
        _check(
            "transition_barrier_integration",
            "EpochTransitionBarrier" in transition
            and "TransitionAbortManager" in transition
            and "epoch_advance" in transition,
            "coordinator integrates barrier + abort + epoch store",
        )
    )

    checks.append(
        _check(
            "split_brain_guard",
            "max_epoch_lag" in transition and "validate_replica_lag" in transition,
            "bounded lag guard implemented",
        )
    )

    checks.append(
        _check(
            "transition_sequence_apis",
            all(name in transition for name in ["propose_transition", "ack_drain", "commit_transition"]),
            "propose/drain/commit APIs present",
        )
    )

    checks.append(
        _check(
            "abort_timeout_api",
            "abort_transition_timeout" in transition,
            "timeout abort API present",
        )
    )

    checks.append(
        _check(
            "transition_history_metadata",
            all(
                field in transition
                for field in [
                    "transition_id",
                    "pre_epoch",
                    "target_epoch",
                    "initiator",
                    "reason",
                    "timestamp_ms",
                    "outcome",
                    "abort_reason",
                ]
            ),
            "history metadata fields encoded",
        )
    )

    checks.append(
        _check(
            "integration_test_five_services",
            "five_service_quiescence_transition_commits" in transition,
            "5-service quiescence test present",
        )
    )

    checks.append(
        _check(
            "integration_test_timeout_abort",
            "timeout_abort_keeps_pre_epoch_and_records_event" in transition,
            "timeout abort integration test present",
        )
    )

    checks.append(
        _check(
            "unit_test_monotonicity",
            "epoch_transitions_are_monotonic_across_commits" in transition,
            "monotonic transition test present",
        )
    )

    guard_tests = len(re.findall(r"#\[test\]", guard))
    transition_tests = len(re.findall(r"#\[test\]", transition))
    checks.append(
        _check(
            "guard_test_count",
            guard_tests >= MIN_GUARD_TESTS,
            f"{guard_tests} tests in epoch_guard.rs (>= {MIN_GUARD_TESTS})",
        )
    )
    checks.append(
        _check(
            "transition_test_count",
            transition_tests >= MIN_TRANSITION_TESTS,
            f"{transition_tests} tests in epoch_transition.rs (>= {MIN_TRANSITION_TESTS})",
        )
    )

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "total": len(checks),
        "status": "pass" if failed == 0 else "fail",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "all_passed": failed == 0,
    }


def self_test() -> bool:
    result = run_all()
    if result["bead_id"] != BEAD_ID:
        raise RuntimeError("unexpected bead_id")
    if result["section"] != SECTION:
        raise RuntimeError("unexpected section")
    if result["total"] < 40:
        raise RuntimeError("expected at least 40 checks")
    for check in result["checks"]:
        if "name" not in check or "passed" not in check or "detail" not in check:
            raise RuntimeError(f"malformed check: {check!r}")
    return True


def main() -> None:
    configure_test_logging("check_epoch_integration")
    as_json = "--json" in sys.argv

    if "--self-test" in sys.argv:
        self_test()
        print("self_test passed")
        return

    result = run_all()

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        for check in result["checks"]:
            marker = "PASS" if check["passed"] else "FAIL"
            print(f"[{marker}] {check['name']}: {check['detail']}")
        print(
            f"\n{BEAD_ID}: {result['passed']}/{result['total']} checks - {result['verdict']}"
        )

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
