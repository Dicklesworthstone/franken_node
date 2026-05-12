#!/usr/bin/env python3
"""bd-oty: Verification script for session-authenticated control channel.

Usage:
    python3 scripts/check_session_auth.py           # human-readable
    python3 scripts/check_session_auth.py --json     # machine-readable
    python3 scripts/check_session_auth.py --self-test # internal consistency
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/api/session_auth.rs"
CARGO_TOML = ROOT / "crates/franken-node/Cargo.toml"
SPEC_FILE = ROOT / "docs/specs/section_10_10/bd-oty_contract.md"
POLICY_FILE = ROOT / "docs/policy/session_authenticated_control.md"
EVIDENCE_FILE = ROOT / "artifacts/section_10_10/bd-oty/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_10/bd-oty/verification_summary.md"

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_STRUCTS = [
    "SessionState",
    "SessionConfig",
    "AuthenticatedSession",
    "SessionManager",
    "AuthenticatedMessage",
    "MessageDirection",
    "SessionEvent",
    "SessionError",
]

REQUIRED_EVENT_CODES = [
    "SCC-001",
    "SCC-002",
    "SCC-003",
    "SCC-004",
]

REQUIRED_ERROR_CODES = [
    "ERR_SCC_NO_SESSION",
    "ERR_SCC_SEQUENCE_VIOLATION",
    "ERR_SCC_SESSION_TERMINATED",
    "ERR_SCC_ROLE_MISMATCH",
    "ERR_SCC_AUTH_FAILED",
    "ERR_SCC_MAX_SESSIONS",
]

REQUIRED_INVARIANTS = [
    "INV-SCC-SESSION-AUTH",
    "INV-SCC-MONOTONIC",
    "INV-SCC-ROLE-KEYS",
    "INV-SCC-TERMINATED",
]

REQUIRED_FUNCTIONS = [
    "establish_session",
    "process_message",
    "terminate_session",
    "validate_key_roles",
    "demo_session_lifecycle",
    "demo_windowed_replay",
    "activate",
    "begin_termination",
    "terminate",
    "next_send_seq",
    "next_recv_seq",
    "active_session_count",
    "get_session",
    "session_ids",
]

REQUIRED_SPEC_SECTIONS = [
    "Overview",
    "Data Model",
    "SessionState",
    "AuthenticatedSession",
    "SessionManager",
    "SessionConfig",
    "AuthenticatedMessage",
    "Invariants",
    "Event Codes",
    "Error Codes",
    "Acceptance Criteria",
]

SESSION_STATES = [
    "Establishing",
    "Active",
    "Terminating",
    "Terminated",
]

KEY_ROLES = [
    "Encryption",
    "Signing",
]

DIRECTIONS = [
    "Send",
    "Receive",
]

REGISTERED_SESSION_AUTH_TEST_TARGETS = {
    "session_auth_real_lifecycle": "tests/session_auth_real_lifecycle.rs",
    "session_auth_key_roles": "tests/session_auth_key_roles.rs",
    "session_auth_real_lifecycle_structured": "tests/session_auth_real_lifecycle_structured.rs",
}

LEGACY_SESSION_AUTH_MARKER = "LEGACY-UNREGISTERED-SESSION-AUTH-COVERAGE"
LEGACY_UNREGISTERED_SESSION_AUTH_TESTS = [
    ROOT / "crates/franken-node/tests/integration_api_session_auth_real_service.rs",
    ROOT / "crates/franken-node/tests/api_session_auth_real_service_integration.rs",
]
LEGACY_ACTIVE_COVERAGE_CLAIMS = [
    "NO MOCKS",
    "No mocked authentication",
]

SESSION_AUTH_GIT_XREF = [
    {
        "bead_id": "bd-390wi",
        "commit": "d790ce19df1a4d0c4a45a66d67b4623ae89ed867",
        "subject": "fix(session-auth): pin send/recv seq at saturation when checked_add overflows",
        "paths": ["crates/franken-node/src/api/session_auth.rs"],
        "evidence": [
            "send_seq is pinned to sequence when checked_add(1) overflows",
            "recv_seq is pinned to sequence when checked_add(1) overflows",
            "send_seq_exhausted and recv_seq_exhausted fail closed future accepted messages",
        ],
    }
]

REQUIRED_POLICY_CONTENT = [
    "Session-Authenticated Control Channel Policy",
    "INV-SCC-SESSION-AUTH",
    "INV-SCC-MONOTONIC",
    "INV-SCC-ROLE-KEYS",
    "INV-SCC-TERMINATED",
    "SCC-001",
    "SCC-004",
    "ERR_SCC_NO_SESSION",
    "Encryption",
    "Signing",
    "replay_window",
    "establish_session",
    "validate_key_roles",
]

REAL_EVIDENCE_REQUIREMENTS = [
    (
        "real evidence: HMAC transcript authentication",
        IMPL_FILE,
        [
            "adversarial_forged_handshake_mac_rejected",
            "adversarial_forged_message_mac_rejected",
            "HANDSHAKE_HMAC_PREFIX",
            "MESSAGE_HMAC_PREFIX",
            "constant_time::ct_eq_bytes",
        ],
    ),
    (
        "real evidence: strict sequence enforcement",
        IMPL_FILE,
        [
            "test_strict_send_sequence",
            "test_strict_recv_sequence",
            "test_independent_send_recv_sequences",
            "test_send_sequence_exhaustion_rejected_before_duplicate_terminal_use",
            "SequenceViolation",
        ],
    ),
    (
        "real evidence: replay-window rejection",
        IMPL_FILE,
        [
            "test_windowed_out_of_order_accepted",
            "test_windowed_replay_rejected",
            "test_windowed_regress_below_floor_rejected",
            "negative_replay_attacks_sequence_manipulation",
            "ReplayDetected",
        ],
    ),
    (
        "real evidence: terminated and expired sessions reject",
        IMPL_FILE,
        [
            "test_terminated_session_rejects_messages",
            "test_expired_session_rejects_messages",
            "terminating_session_rejects_message_without_advancing_sequence",
            "process_message_rejects_expired_session_before_sequence_advance",
            "ensure_active_session",
        ],
    ),
    (
        "real evidence: max-session and duplicate capacity gates",
        IMPL_FILE,
        [
            "test_max_sessions_enforced",
            "zero_max_sessions_rejects_first_valid_handshake",
            "test_duplicate_live_session_id_rejected_without_resetting_counters",
            "test_terminating_session_still_counts_toward_max_sessions",
            "MaxSessionsReached",
        ],
    ),
    (
        "real evidence: key-role validation fail-closed",
        IMPL_FILE,
        [
            "test_validate_key_roles_ok",
            "test_validate_key_roles_wrong_encryption",
            "test_validate_key_roles_wrong_signing",
            "validate_session_key_ids",
            "KeyRole::Encryption",
            "KeyRole::Signing",
        ],
    ),
    (
        "real evidence: audited rejection events",
        IMPL_FILE,
        [
            "test_rejection_event_on_sequence_violation",
            "event_codes::SCC_MESSAGE_REJECTED",
            "SessionEvent",
            "detail:",
            "trace_id",
        ],
    ),
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "pass": ok, "detail": detail or ("ok" if ok else "FAIL")}


# ── Check groups ───────────────────────────────────────────────────────────

def check_file_existence() -> list:
    checks = []
    checks.append(_check(
        "session_auth implementation exists",
        IMPL_FILE.exists(),
        str(IMPL_FILE),
    ))
    checks.append(_check(
        "contract spec exists",
        SPEC_FILE.exists(),
        str(SPEC_FILE),
    ))
    checks.append(_check(
        "evidence artifact exists",
        EVIDENCE_FILE.exists(),
        str(EVIDENCE_FILE),
    ))
    checks.append(_check(
        "summary artifact exists",
        SUMMARY_FILE.exists(),
        str(SUMMARY_FILE),
    ))
    checks.append(_check(
        "policy document exists",
        POLICY_FILE.exists(),
        str(POLICY_FILE),
    ))
    return checks


def check_structs() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for s in REQUIRED_STRUCTS:
        found = f"pub enum {s}" in src or f"pub struct {s}" in src
        checks.append(_check(f"struct/enum {s}", found, "defined in session_auth.rs"))
    return checks


def check_event_codes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for code in REQUIRED_EVENT_CODES:
        found = code in src
        checks.append(_check(f"event code {code}", found))
    return checks


def check_error_codes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for code in REQUIRED_ERROR_CODES:
        found = code in src
        checks.append(_check(f"error code {code}", found))
    return checks


def check_invariants() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for inv in REQUIRED_INVARIANTS:
        found = inv in src
        checks.append(_check(f"invariant {inv}", found))
    return checks


def check_functions() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for fn_name in REQUIRED_FUNCTIONS:
        found = f"fn {fn_name}" in src or f"pub fn {fn_name}" in src
        checks.append(_check(f"function {fn_name}", found))
    return checks


def check_spec_sections() -> list:
    src = _read(SPEC_FILE)
    checks = []
    for section in REQUIRED_SPEC_SECTIONS:
        found = section in src
        checks.append(_check(f"spec section: {section}", found))
    return checks


def check_session_states() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for state in SESSION_STATES:
        found = state in src
        checks.append(_check(f"session state {state}", found, "variant in SessionState"))
    return checks


def check_key_role_integration() -> list:
    src = _read(IMPL_FILE)
    checks = []
    # Must import KeyRole from key_role_separation
    found_import = "key_role_separation::KeyRole" in src or "key_role_separation::{KeyRole" in src
    checks.append(_check("imports KeyRole from key_role_separation", found_import))
    for role in KEY_ROLES:
        found = f"KeyRole::{role}" in src
        checks.append(_check(f"uses KeyRole::{role}", found))
    return checks


def check_direction_integration() -> list:
    src = _read(IMPL_FILE)
    checks = []
    found_import = "control_channel::Direction" in src
    checks.append(_check("imports Direction from control_channel", found_import))
    for d in DIRECTIONS:
        found = f"Direction::{d}" in src
        checks.append(_check(f"uses Direction::{d}", found))
    return checks


def check_serde_derives() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for t in ["SessionState", "SessionConfig", "AuthenticatedSession",
              "AuthenticatedMessage", "MessageDirection", "SessionEvent"]:
        idx = src.find(f"pub enum {t}") if f"pub enum {t}" in src else src.find(f"pub struct {t}")
        if idx >= 0:
            preceding = src[max(0, idx - 200):idx]
            has_serde = "Serialize" in preceding and "Deserialize" in preceding
            checks.append(_check(f"serde derives on {t}", has_serde))
        else:
            checks.append(_check(f"serde derives on {t}", False, "type not found"))
    return checks


def check_tests() -> list:
    src = _read(IMPL_FILE)
    checks = []
    test_count = src.count("#[test]")
    checks.append(_check(
        f"Rust unit tests present ({test_count})",
        test_count >= 40,
        f"{test_count} tests found",
    ))

    # Check for key test categories
    test_categories = [
        ("lifecycle tests", "test_session_lifecycle"),
        ("sequence enforcement tests", "test_strict_send_sequence"),
        ("replay window tests", "test_windowed"),
        ("terminated session tests", "test_terminated_session"),
        ("max sessions test", "test_max_sessions"),
        ("key role validation tests", "test_validate_key_roles"),
        ("serde roundtrip tests", "test_session_state_serde"),
        ("send+sync tests", "test_types_send_sync"),
        ("demo lifecycle test", "test_demo_session_lifecycle"),
        ("demo windowed test", "test_demo_windowed_replay"),
    ]
    for name, pattern in test_categories:
        found = pattern in src
        checks.append(_check(f"test: {name}", found))
    return checks


def check_policy_content() -> list:
    src = _read(POLICY_FILE)
    checks = []
    for item in REQUIRED_POLICY_CONTENT:
        found = item in src
        checks.append(_check(f"policy: {item}", found))
    return checks


def check_send_sync() -> list:
    src = _read(IMPL_FILE)
    checks = []
    found = "assert_send" in src and "assert_sync" in src
    checks.append(_check("Send + Sync assertions", found))
    return checks


def check_acceptance_criteria() -> list:
    """Verify acceptance criteria from the spec."""
    src = _read(IMPL_FILE)
    checks = []

    # AC1: Every control message requires active authenticated session
    ac1 = "NoSession" in src and "SessionTerminated" in src
    checks.append(_check("AC1: session requirement enforced", ac1))

    # AC2: Per-direction sequence monotonicity
    ac2 = "SequenceViolation" in src and "send_seq" in src and "recv_seq" in src
    checks.append(_check("AC2: per-direction sequence monotonicity", ac2))

    # AC3: Replay window configurable
    ac3 = "replay_window" in src and "ReplayDetected" in src
    checks.append(_check("AC3: configurable replay window", ac3))

    # AC4: Role key usage
    ac4 = "encryption_key_id" in src and "signing_key_id" in src and "validate_key_roles" in src
    checks.append(_check("AC4: role key separation", ac4))

    # AC5: Terminated sessions reject
    ac5 = "SessionTerminated" in src and "Terminated" in src
    checks.append(_check("AC5: terminated sessions reject", ac5))

    # AC6: SessionManager tracks concurrent sessions
    ac6 = "max_sessions" in src and "MaxSessionsReached" in src
    checks.append(_check("AC6: concurrent session limit", ac6))

    # AC7: Session events with trace_id
    ac7 = "trace_id" in src and "session_id" in src and "SessionEvent" in src
    checks.append(_check("AC7: traced session events", ac7))

    # AC8: Unit tests cover lifecycle, sequence, replay, role keys
    ac8 = (
        "test_session_lifecycle" in src
        and "test_strict_send_sequence" in src
        and "test_windowed_replay_rejected" in src
        and "test_validate_key_roles" in src
    )
    checks.append(_check("AC8: comprehensive unit test coverage", ac8))

    return checks


def _missing_patterns(path: Path, patterns: list[str]) -> list[str]:
    if not path.is_file():
        return patterns
    content = path.read_text(encoding="utf-8")
    return [pattern for pattern in patterns if pattern not in content]


def _crate_test_path(path: Path) -> str:
    return path.relative_to(ROOT / "crates/franken-node").as_posix()


def check_real_session_auth_evidence() -> list:
    checks = []
    for name, path, patterns in REAL_EVIDENCE_REQUIREMENTS:
        missing = _missing_patterns(path, patterns)
        detail = "ok" if not missing else f"missing in {path.relative_to(ROOT)}: {missing}"
        checks.append(_check(name, not missing, detail))
    return checks


def check_session_auth_test_registration_truth() -> list:
    cargo = _read(CARGO_TOML)
    checks = []

    for target_name, target_path in REGISTERED_SESSION_AUTH_TEST_TARGETS.items():
        target_registered = (
            f'name = "{target_name}"' in cargo
            and f'path = "{target_path}"' in cargo
        )
        checks.append(_check(
            f"registered session-auth target: {target_name}",
            target_registered,
            target_path,
        ))

    for path in LEGACY_UNREGISTERED_SESSION_AUTH_TESTS:
        rel = _crate_test_path(path)
        content = _read(path)
        checks.append(_check(
            f"legacy session-auth file exists: {rel}",
            path.exists(),
            rel,
        ))
        checks.append(_check(
            f"legacy session-auth file not registered: {rel}",
            f'path = "{rel}"' not in cargo,
            "source-only legacy file",
        ))
        checks.append(_check(
            f"legacy session-auth file marked: {rel}",
            LEGACY_SESSION_AUTH_MARKER in content,
            LEGACY_SESSION_AUTH_MARKER,
        ))
        missing_targets = [
            target_name
            for target_name in REGISTERED_SESSION_AUTH_TEST_TARGETS
            if target_name not in content
        ]
        checks.append(_check(
            f"legacy session-auth file points to active targets: {rel}",
            not missing_targets,
            "ok" if not missing_targets else f"missing target names: {missing_targets}",
        ))
        stale_claims = [
            claim
            for claim in LEGACY_ACTIVE_COVERAGE_CLAIMS
            if claim in content
        ]
        checks.append(_check(
            f"legacy session-auth file has no active no-mock claim: {rel}",
            not stale_claims,
            "ok" if not stale_claims else f"stale claims: {stale_claims}",
        ))

    return checks


def check_session_auth_git_xref() -> list:
    src = _read(IMPL_FILE)
    xref = next((entry for entry in SESSION_AUTH_GIT_XREF if entry["bead_id"] == "bd-390wi"), None)
    has_commit = xref is not None and len(xref["commit"]) == 40
    has_sequence_guard = (
        "checked_add(1)" in src
        and "send_seq_exhausted = true" in src
        and "recv_seq_exhausted = true" in src
        and "SessionError::SequenceExhausted" in src
        and "test_send_sequence_exhaustion_rejected_before_duplicate_terminal_use" in src
    )
    return [
        _check(
            "git_xref: bd-390wi session_auth sequence exhaustion",
            bool(has_commit and has_sequence_guard),
            xref["commit"] if xref else "missing bd-390wi git_xref",
        )
    ]


# ── Main check runner ──────────────────────────────────────────────────────

def run_checks() -> dict:
    checks = []
    checks.extend(check_file_existence())
    checks.extend(check_structs())
    checks.extend(check_event_codes())
    checks.extend(check_error_codes())
    checks.extend(check_invariants())
    checks.extend(check_functions())
    checks.extend(check_spec_sections())
    checks.extend(check_session_states())
    checks.extend(check_key_role_integration())
    checks.extend(check_direction_integration())
    checks.extend(check_serde_derives())
    checks.extend(check_tests())
    checks.extend(check_send_sync())
    checks.extend(check_policy_content())
    checks.extend(check_acceptance_criteria())
    checks.extend(check_real_session_auth_evidence())
    checks.extend(check_session_auth_test_registration_truth())
    checks.extend(check_session_auth_git_xref())

    passed = sum(1 for c in checks if c["pass"])
    failed = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-oty",
        "title": "Session-authenticated control channel integration",
        "section": "10.10",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "git_xref": SESSION_AUTH_GIT_XREF,
        "checks": checks,
    }


def run_all() -> dict:
    """Alias for run_checks()."""
    return run_checks()


def self_test() -> tuple:
    """Internal consistency checks."""
    result = run_checks()
    return (result["verdict"] == "PASS", result["checks"])


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    configure_test_logging("check_session_auth")
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        passed = sum(1 for c in checks if c["pass"])
        total = len(checks)
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}")
        print(f"\nself-test: {passed}/{total} {'PASS' if ok else 'FAIL'}")
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
