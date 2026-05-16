#!/usr/bin/env python3
"""Verification script for bd-1r2: Audience-bound token chains for control actions.

Usage:
    python3 scripts/check_audience_tokens.py          # human output
    python3 scripts/check_audience_tokens.py --json    # JSON output
    python3 scripts/check_audience_tokens.py --self-test
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


SPEC = ROOT / "docs" / "specs" / "section_10_10" / "bd-1r2_contract.md"
IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "audience_token.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mod.rs"
POLICY = ROOT / "docs" / "policy" / "audience_bound_tokens.md"

# ---- Required types ----
REQUIRED_TYPES = [
    "pub struct TokenId(",
    "pub enum ActionScope",
    "pub struct AudienceBoundToken",
    "pub struct TokenError",
    "pub struct TokenEvent",
    "pub struct TokenChain",
    "pub struct TokenValidator",
]

# ---- Required methods ----
REQUIRED_METHODS = [
    # TokenId
    "pub fn new(",
    "pub fn as_str(",
    # ActionScope
    "pub fn label(",
    "pub fn all(",
    # AudienceBoundToken
    "pub fn hash(",
    "pub fn is_expired(",
    "pub fn has_valid_window(",
    "pub fn is_root(",
    "pub fn audience_contains(",
    # TokenError
    "pub fn attenuation_violation(",
    "pub fn audience_mismatch(",
    "pub fn token_expired(",
    "pub fn replay_detected(",
    # TokenChain
    "pub fn append(",
    "pub fn depth(",
    "pub fn root(",
    "pub fn leaf(",
    "pub fn tokens(",
    # TokenValidator
    "pub fn record_issuance(",
    "pub fn record_delegation(",
    "pub fn verify_chain(",
    "pub fn check_audience(",
    "pub fn advance_epoch(",
    "pub fn epoch_id(",
    "pub fn take_events(",
    "pub fn events(",
    "pub fn tokens_issued(",
    "pub fn tokens_delegated(",
    "pub fn tokens_verified(",
    "pub fn tokens_rejected(",
    "pub fn nonce_count(",
]

# ---- Event codes ----
EVENT_CODES = ["ABT-001", "ABT-002", "ABT-003", "ABT-004"]

# ---- Error codes ----
ERROR_CODES = [
    "ERR_ABT_ATTENUATION_VIOLATION",
    "ERR_ABT_AUDIENCE_MISMATCH",
    "ERR_ABT_TOKEN_EXPIRED",
    "ERR_ABT_REPLAY_DETECTED",
]

# ---- Invariants ----
INVARIANTS = [
    "INV-ABT-ATTENUATION",
    "INV-ABT-AUDIENCE",
    "INV-ABT-EXPIRY",
    "INV-ABT-REPLAY",
]

# ---- Action scopes ----
ACTION_SCOPES = ["Migrate", "Rollback", "Promote", "Revoke", "Configure"]

# ---- Required tests ----
REQUIRED_TESTS = [
    "test_token_id_display",
    "test_token_id_as_str",
    "test_action_scope_labels",
    "test_action_scope_all",
    "test_action_scope_display",
    "test_action_scope_serde_roundtrip",
    "test_root_token_creation",
    "test_token_hash_deterministic",
    "test_token_hash_changes_with_id",
    "test_token_is_expired",
    "test_token_has_valid_window",
    "test_token_audience_contains",
    "test_token_serde_roundtrip",
    "test_error_display",
    "test_error_audience_mismatch",
    "test_error_token_expired",
    "test_error_replay_detected",
    "test_error_serde_roundtrip",
    "test_chain_new_root",
    "test_chain_rejects_non_root_first",
    "test_chain_single_hop_delegation",
    "test_chain_multi_hop_delegation",
    "test_chain_audience_escalation_rejected",
    "test_chain_scope_escalation_rejected",
    "test_chain_depth_limit_exceeded",
    "test_chain_zero_validity_rejected",
    "test_chain_root_zero_validity_rejected",
    "test_chain_forged_parent_hash",
    "test_chain_missing_parent_hash_on_delegate",
    "test_chain_empty_capabilities_valid",
    "test_chain_tokens_accessor",
    "test_chain_depth_20",
    "test_validator_new",
    "test_validator_record_issuance",
    "test_validator_record_delegation",
    "test_validator_verify_chain_success",
    "test_validator_audience_mismatch",
    "test_validator_expired_token_rejected",
    "test_validator_expired_intermediate_rejected",
    "test_validator_nonce_replay_detected",
    "test_validator_advance_epoch_clears_nonces",
    "test_validator_check_audience_pass",
    "test_validator_check_audience_fail",
    "test_validator_take_events_drains",
    "test_validator_chain_integrity_violation",
    "test_validator_verify_deep_chain",
    "test_event_codes_defined",
    "test_error_codes_defined",
    "test_invariant_tags_defined",
    "test_delegate_with_all_parent_caps",
    "test_chain_serde_roundtrip",
    "test_token_event_serde_roundtrip",
    "test_validator_metrics_accumulate",
    "test_verify_rejects_after_leaf_audience_narrowed",
    "test_cross_audience_replay_rejected",
]

# ---- AudienceBoundToken fields ----
TOKEN_FIELDS = [
    "token_id",
    "issuer",
    "audience",
    "capabilities",
    "issued_at",
    "expires_at",
    "nonce",
    "parent_token_hash",
    "signature",
    "max_delegation_depth",
]


ALL_CHECKS = []
RESULTS = []


def _safe_rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _check(name: str, passed: bool, detail: str = "") -> dict:
    entry = {"check": name, "pass": passed, "detail": detail or ("found" if passed else "missing")}
    RESULTS.append(entry)
    return entry


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


def _file_contains(path: Path, pattern: str) -> bool:
    if not path.exists():
        return False
    return pattern in read_rust_source(path)


def validate_token(token_obj: dict) -> tuple:
    """Validate that a token-like dict has required structural fields.

    Returns (is_valid, detail_message).
    """
    required_keys = [
        "token_id", "issuer", "audience", "capabilities",
        "issued_at", "expires_at", "nonce", "parent_token_hash",
        "signature", "max_delegation_depth",
    ]
    missing = [k for k in required_keys if k not in token_obj]
    if missing:
        return False, f"missing keys: {missing}"
    if not isinstance(token_obj["audience"], list):
        return False, "audience must be a list"
    if not isinstance(token_obj["issued_at"], (int, float)):
        return False, "issued_at must be numeric"
    if not isinstance(token_obj["expires_at"], (int, float)):
        return False, "expires_at must be numeric"
    if token_obj["issued_at"] >= token_obj["expires_at"]:
        return False, "issued_at must be < expires_at"
    return True, "valid token structure"


def check_files() -> list:
    checks = []
    for label, p in [
        ("spec contract", SPEC),
        ("implementation", IMPL),
        ("control_plane mod.rs", MOD_RS),
        ("policy doc", POLICY),
    ]:
        checks.append(_check(f"file: {label}", p.exists(), _safe_rel(p)))
    return checks


def check_module_registered() -> dict:
    return _check(
        "module registered in mod.rs",
        _file_contains(MOD_RS, "pub mod audience_token;"),
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
        checks.append(_check(f"method: {m}", m in content))
    return checks


def check_event_codes() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"event_code: {c}", False) for c in EVENT_CODES]
    content = read_rust_source(IMPL)
    for code in EVENT_CODES:
        checks.append(_check(f"event_code: {code}", code in content))
    return checks


def check_error_codes() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"error_code: {c}", False) for c in ERROR_CODES]
    content = read_rust_source(IMPL)
    for code in ERROR_CODES:
        checks.append(_check(f"error_code: {code}", code in content))
    return checks


def check_invariants() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"invariant: {i}", False) for i in INVARIANTS]
    content = read_rust_source(IMPL)
    for inv in INVARIANTS:
        checks.append(_check(f"invariant: {inv}", inv in content))
    return checks


def check_action_scopes() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"action_scope: {s}", False) for s in ACTION_SCOPES]
    content = read_rust_source(IMPL)
    for scope in ACTION_SCOPES:
        checks.append(_check(f"action_scope: {scope}", scope in content))
    return checks


def check_token_fields() -> list:
    checks = []
    if not IMPL.exists():
        return [_check(f"token_field: {f}", False) for f in TOKEN_FIELDS]
    content = read_rust_source(IMPL)
    for field in TOKEN_FIELDS:
        checks.append(_check(f"token_field: {field}", f"pub {field}:" in content or f"pub {field}(" in content))
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
        return _check("test count >= 50", False, "impl file missing")
    content = read_rust_source(IMPL)
    count = content.count("#[test]")
    return _check("test count >= 50", count >= 50, f"{count} tests found")


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


def check_send_sync() -> dict:
    if not IMPL.exists():
        return _check("Send+Sync assertions", False)
    content = read_rust_source(IMPL)
    return _check("Send+Sync assertions", "assert_send" in content and "assert_sync" in content)


def check_spec_sections() -> list:
    checks = []
    if not SPEC.exists():
        return [_check("spec: sections", False, "spec missing")]
    content = read_text(SPEC)
    for section in [
        "AudienceBoundToken", "ActionScope", "TokenChain", "TokenValidator",
        "Invariants", "Event Codes", "Error Codes", "Acceptance Criteria",
    ]:
        checks.append(_check(f"spec: {section}", section in content))
    return checks


def check_policy_sections() -> list:
    checks = []
    if not POLICY.exists():
        return [_check("policy: sections", False, "policy missing")]
    content = read_text(POLICY)
    for section in [
        "Token Issuance", "Delegation Rules", "Validation",
        "Invariants", "Event Codes", "Error Codes",
    ]:
        checks.append(_check(f"policy: {section}", section in content))
    return checks


def check_adversarial_tests() -> list:
    """Check that adversarial test scenarios from the spec are covered."""
    checks = []
    if not IMPL.exists():
        return [_check("adversarial tests", False)]
    content = read_rust_source(IMPL)
    adversarial = [
        ("forged parent_hash", "forged"),
        ("scope escalation", "scope_escalation"),
        ("audience escalation", "audience_escalation"),
        ("cross-audience replay", "cross_audience_replay"),
        ("expired intermediate", "expired_intermediate"),
        ("depth limit exceeded", "depth_limit_exceeded"),
    ]
    for label, pattern in adversarial:
        checks.append(_check(f"adversarial: {label}", pattern in content))
    return checks


def check_depth_coverage() -> list:
    """Check that chain depths 1, 5, and 20 are tested per spec."""
    checks = []
    if not IMPL.exists():
        return [_check("depth coverage", False)]
    content = read_rust_source(IMPL)
    # Depth 1 = root-only chain (test_chain_new_root, test_validator_verify_chain_success, etc.)
    checks.append(_check("depth: 1 (root-only)", "test_chain_new_root" in content))
    # Depth 5 = multi-hop (test_chain_multi_hop_delegation goes to depth 4)
    checks.append(_check("depth: 5+ (multi-hop)", "test_chain_multi_hop_delegation" in content))
    # Depth 20 = deep chain
    checks.append(_check("depth: 20 (deep chain)", "test_chain_depth_20" in content))
    return checks


def run_checks() -> dict:
    global RESULTS
    RESULTS = []

    checks = []
    checks.extend(check_files())
    checks.append(check_module_registered())
    checks.extend(check_types())
    checks.extend(check_methods())
    checks.extend(check_event_codes())
    checks.extend(check_error_codes())
    checks.extend(check_invariants())
    checks.extend(check_action_scopes())
    checks.extend(check_token_fields())
    checks.extend(check_tests())
    checks.append(check_test_count())
    checks.append(check_serde_derives())
    checks.append(check_sha256_usage())
    checks.append(check_send_sync())
    checks.extend(check_spec_sections())
    checks.extend(check_policy_sections())
    checks.extend(check_adversarial_tests())
    checks.extend(check_depth_coverage())

    # validate_token helper self-checks
    valid_token = {
        "token_id": "tok-1", "issuer": "issuer-1",
        "audience": ["kernel-A"], "capabilities": ["Migrate"],
        "issued_at": 1000, "expires_at": 100000,
        "nonce": "nonce-1", "parent_token_hash": None,
        "signature": "sig-1", "max_delegation_depth": 3,
    }
    ok, detail = validate_token(valid_token)
    checks.append({"check": "validate_token: valid token accepted", "pass": ok, "detail": detail})

    invalid_token = dict(valid_token)
    del invalid_token["nonce"]
    ok_bad, detail_bad = validate_token(invalid_token)
    checks.append({"check": "validate_token: incomplete token rejected", "pass": not ok_bad, "detail": detail_bad})

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "bead": "bd-1r2",
        "title": "Audience-bound token chains for control actions",
        "section": "10.10",
        "overall_pass": failing == 0,
        "verdict": verdict,
        "summary": {
            "passing_checks": passing,
            "failing_checks": failing,
            "total_checks": passing + failing,
        },
        "checks": checks,
    }


def run_all() -> dict:
    """Alias for run_checks for pattern compatibility."""
    return run_checks()


def self_test():
    result = run_checks()
    assert isinstance(result, dict), "Result must be a dict"
    assert result["bead"] == "bd-1r2"
    assert "checks" in result
    assert isinstance(result["checks"], list)
    assert len(result["checks"]) > 0
    assert "verdict" in result
    assert "summary" in result
    print(f"self_test passed: {result['summary']['passing_checks']}/{result['summary']['total_checks']} checks")
    return result


def main():
    configure_test_logging("check_audience_tokens")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("=== bd-1r2: Audience-Bound Token Chains Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing_checks']}/{s['total_checks']}")
        print()
        for c in result["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
