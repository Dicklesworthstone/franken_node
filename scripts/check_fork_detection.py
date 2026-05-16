#!/usr/bin/env python3
"""Verification script for bd-2ms: Rollback/fork detection in control-plane state propagation.

Usage:
    python3 scripts/check_fork_detection.py          # human output
    python3 scripts/check_fork_detection.py --json    # JSON output
    python3 scripts/check_fork_detection.py --self-test
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


SPEC = ROOT / "docs" / "specs" / "section_10_10" / "bd-2ms_contract.md"
IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "divergence_gate.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mod.rs"
UPSTREAM_FORK = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "fork_detection.rs"
UPSTREAM_MARKER = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "marker_stream.rs"
UPSTREAM_MMR = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mmr_proofs.rs"
POLICY = ROOT / "docs" / "policy" / "rollback_fork_detection.md"

# ---- Required types ----
REQUIRED_TYPES = [
    "pub enum ResponseMode",
    "pub enum GateState",
    "pub enum MutationKind",
    "pub enum DivergenceGateError",
    "pub struct ControlPlaneDivergenceGate",
    "pub struct ActiveDivergence",
    "pub struct OperatorAuthorization",
    "pub struct QuarantinePartition",
    "pub struct OperatorAlert",
    "pub struct GateAuditEntry",
    "pub struct MutationCheckResult",
    "pub struct RecoveryResult",
]

# ---- Required methods ----
REQUIRED_METHODS = [
    "pub fn new(",
    "pub fn state(",
    "pub fn allows_mutation(",
    "pub fn check_propagation(",
    "pub fn check_mutation(",
    "pub fn respond_halt(",
    "pub fn respond_quarantine(",
    "pub fn respond_alert(",
    "pub fn respond_recover(",
    "pub fn verify_marker(",
    "pub fn events(",
    "pub fn take_events(",
    "pub fn audit_log(",
    "pub fn quarantined_partitions(",
    "pub fn alerts(",
    "pub fn blocked_mutations(",
    "pub fn active_divergence(",
    "pub fn verify(",  # OperatorAuthorization
    "pub fn label(",
    "pub fn all(",
]

# ---- Event codes ----
EVENT_CODES = [
    "DG-001", "DG-002", "DG-003", "DG-004",
    "DG-005", "DG-006", "DG-007", "DG-008",
]

# ---- Invariants ----
INVARIANTS = [
    "INV-DG-NO-MUTATION",
    "INV-DG-OPERATOR-RECOVERY",
    "INV-DG-ONE-CYCLE",
    "INV-DG-VALID-TRANSITIONS",
]

# ---- Response modes ----
RESPONSE_MODES = ["Halt", "Quarantine", "Alert", "Recover"]

# ---- Gate states ----
GATE_STATES = ["Normal", "Diverged", "Quarantined", "Alerted", "Recovering"]

# ---- Mutation kinds ----
MUTATION_KINDS = [
    "PolicyUpdate", "TokenIssuance", "ZoneBoundaryChange",
    "RevocationPublish", "EpochTransition", "QuarantinePromotion",
]

# ---- Required tests ----
REQUIRED_TESTS = [
    "test_new_gate_normal",
    "test_converged_stays_normal",
    "test_converged_allows_mutation",
    "test_fork_transitions_to_diverged",
    "test_fork_blocks_mutation",
    "test_fork_emits_divergence_event",
    "test_fork_active_divergence",
    "test_gap_transitions_to_diverged",
    "test_rollback_transitions_to_diverged",
    "test_halt_from_diverged",
    "test_halt_from_normal_fails",
    "test_quarantine_from_diverged",
    "test_quarantine_from_normal_fails",
    "test_quarantine_blocks_mutation",
    "test_alert_from_diverged",
    "test_alert_from_quarantined",
    "test_alert_from_normal_fails",
    "test_recover_from_diverged",
    "test_recover_from_alerted",
    "test_recover_from_normal_fails",
    "test_recover_unauthorized_fails",
    "test_recover_empty_operator_fails",
    "test_operator_authorization_verify",
    "test_operator_authorization_tampered",
    "test_operator_authorization_serde",
    "test_all_mutation_kinds_blocked",
    "test_response_mode_all",
    "test_response_mode_labels",
    "test_response_mode_serde",
    "test_gate_state_allows_mutation",
    "test_gate_state_serde",
    "test_event_codes_defined",
    "test_invariant_constants",
    "test_error_display_divergence_block",
    "test_error_display_invalid_transition",
    "test_error_display_unauthorized",
    "test_error_display_freshness",
    "test_error_serde_roundtrip",
    "test_audit_log_on_fork",
    "test_audit_log_on_recovery",
    "test_full_lifecycle_fork_quarantine_alert_recover",
    "test_convergence_emits_freshness_event",
    "test_quarantine_partition_serde",
    "test_mutation_check_result_serde",
    "test_default_gate",
]

# ---- Upstream integration patterns ----
UPSTREAM_PATTERNS = [
    "DivergenceDetector",
    "MarkerProofVerifier",
    "StateVector",
    "DetectionResult",
    "RollbackProof",
    "DivergenceLogEvent",
    "MarkerStream",
]


def _safe_rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "pass": passed, "detail": detail or ("found" if passed else "missing")}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


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


def method_marker_present(content: str, marker: str) -> bool:
    if not marker.startswith("pub fn ") or not marker.endswith("("):
        return marker in content

    prefix = marker[:-1]
    return f"{prefix}(" in content or f"{prefix}<" in content


def _file_contains(path: Path, pattern: str) -> bool:
    if not path.exists():
        return False
    return pattern in read_rust_source(path)


def check_files() -> list:
    checks = []
    for label, p in [
        ("spec contract", SPEC),
        ("implementation", IMPL),
        ("control_plane mod.rs", MOD_RS),
        ("upstream fork_detection.rs", UPSTREAM_FORK),
        ("upstream marker_stream.rs", UPSTREAM_MARKER),
        ("upstream mmr_proofs.rs", UPSTREAM_MMR),
    ]:
        checks.append(_check(f"file: {label}", p.exists(), _safe_rel(p)))
    return checks


def check_module_registered() -> dict:
    return _check(
        "module registered in mod.rs",
        _file_contains(MOD_RS, "pub mod divergence_gate;"),
    )


def check_types() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"type: {t}", False, "impl file missing") for t in REQUIRED_TYPES]
    content = read_rust_source(IMPL)
    for t in REQUIRED_TYPES:
        checks.append(_check(f"type: {t}", t in content))
    return checks


def check_methods() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"method: {m}", False, "impl file missing") for m in REQUIRED_METHODS]
    content = read_rust_source(IMPL)
    for m in REQUIRED_METHODS:
        checks.append(_check(f"method: {m}", method_marker_present(content, m)))
    return checks


def check_event_codes() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"event_code: {c}", False) for c in EVENT_CODES]
    content = read_rust_source(IMPL)
    for code in EVENT_CODES:
        checks.append(_check(f"event_code: {code}", code in content))
    return checks


def check_invariants() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"invariant: {i}", False) for i in INVARIANTS]
    content = read_rust_source(IMPL)
    for inv in INVARIANTS:
        checks.append(_check(f"invariant: {inv}", inv in content))
    return checks


def check_response_modes() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"response_mode: {m}", False) for m in RESPONSE_MODES]
    content = read_rust_source(IMPL)
    for mode in RESPONSE_MODES:
        checks.append(_check(f"response_mode: {mode}", mode in content))
    return checks


def check_gate_states() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"gate_state: {s}", False) for s in GATE_STATES]
    content = read_rust_source(IMPL)
    for state in GATE_STATES:
        checks.append(_check(f"gate_state: {state}", state in content))
    return checks


def check_mutation_kinds() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"mutation_kind: {k}", False) for k in MUTATION_KINDS]
    content = read_rust_source(IMPL)
    for kind in MUTATION_KINDS:
        checks.append(_check(f"mutation_kind: {kind}", kind in content))
    return checks


def check_tests() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"test: {t}", False) for t in REQUIRED_TESTS]
    content = read_rust_source(IMPL)
    for t in REQUIRED_TESTS:
        checks.append(_check(f"test: {t}", f"fn {t}" in content))
    return checks


def check_test_count() -> dict:
    if not IMPL.exists():
        return _check("test count >= 40", False, "impl file missing")
    content = read_rust_source(IMPL)
    count = content.count("#[test]")
    return _check("test count >= 40", count >= 40, f"{count} tests found")


def check_upstream_integration() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"upstream: {p}", False) for p in UPSTREAM_PATTERNS]
    content = read_rust_source(IMPL)
    for pattern in UPSTREAM_PATTERNS:
        checks.append(_check(f"upstream: {pattern}", pattern in content))
    return checks


def check_serde_derives() -> dict:
    if not IMPL.exists():
        return _check("Serialize/Deserialize derives", False)
    content = read_rust_source(IMPL)
    has_ser = "Serialize" in content and "Deserialize" in content
    return _check("Serialize/Deserialize derives", has_ser)


def check_sha256_usage() -> dict:
    if not IMPL.exists():
        return _check("SHA-256 usage", False)
    content = read_rust_source(IMPL)
    return _check("SHA-256 usage", "Sha256" in content or "sha2" in content)


def check_spec_sections() -> list:
    checks = []
    if not SPEC.exists():
        return [_check("spec: sections", False, "spec missing")]
    content = read_text(SPEC)
    for section in [
        "StateVector", "DivergenceDetector", "RollbackProof",
        "Invariants", "Event Codes", "Error Codes", "Acceptance Criteria",
    ]:
        checks.append(_check(f"spec: {section}", section in content))
    return checks


def run_checks() -> dict:
    checks = []
    checks.extend(check_files())
    checks.append(check_module_registered())
    checks.extend(check_types())
    checks.extend(check_methods())
    checks.extend(check_event_codes())
    checks.extend(check_invariants())
    checks.extend(check_response_modes())
    checks.extend(check_gate_states())
    checks.extend(check_mutation_kinds())
    checks.extend(check_tests())
    checks.append(check_test_count())
    checks.extend(check_upstream_integration())
    checks.append(check_serde_derives())
    checks.append(check_sha256_usage())
    checks.extend(check_spec_sections())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "bead_id": "bd-2ms",
        "title": "Rollback/fork detection in control-plane state propagation",
        "section": "10.10",
        "overall_pass": failing == 0,
        "verdict": verdict,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "checks": checks,
    }


def self_test() -> tuple:
    result = run_checks()
    if not result["overall_pass"]:
        failures = [c for c in result["checks"] if not c["pass"]]
        detail = "; ".join(f"{c['check']}: {c['detail']}" for c in failures[:5])
        return False, f"self_test failed: {detail}"
    return True, "self_test passed"


def main():
    configure_test_logging("check_fork_detection")
    if "--self-test" in sys.argv:
        ok, msg = self_test()
        print(msg)
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["overall_pass"] else 1)

    for c in result["checks"]:
        status = "PASS" if c["pass"] else "FAIL"
        print(f"  [{status}] {c['check']}: {c['detail']}")

    passing = result["summary"]["passing"]
    total = result["summary"]["total"]
    print(f"\nbd-2ms verification: {result['verdict']} ({passing}/{total} checks pass)")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
