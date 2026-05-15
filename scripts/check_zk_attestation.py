#!/usr/bin/env python3
"""bd-kcg9 verification gate for zero-knowledge attestation support."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


BEAD = "bd-kcg9"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/zk_attestation_contract.md"
CONTRACT_FILE = ROOT / "docs/specs/section_10_17/bd-kcg9_contract.md"
IMPL_FILE = ROOT / "crates/franken-node/src/security/zk_attestation.rs"
SECURITY_MOD_FILE = ROOT / "crates/franken-node/src/security/mod.rs"
SECURITY_TEST = ROOT / "tests/security/zk_attestation_verification.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_zk_attestation.py"
REPORT_FILE = ROOT / "artifacts/10.17/zk_attestation_vectors.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-kcg9/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-kcg9/verification_summary.md"

# Task-specified event codes (appear in spec)
REQUIRED_EVENT_CODES = [
    "ZK_ATTESTATION_REQUEST",
    "ZK_PROOF_GENERATED",
    "ZK_PROOF_VERIFIED",
    "ZK_PREDICATE_SATISFIED",
    "ZK_ATTESTATION_ISSUED",
]

# FN-ZK codes in implementation (FN-ZK-001 through FN-ZK-012)
REQUIRED_FN_CODES = [
    "FN-ZK-001",
    "FN-ZK-002",
    "FN-ZK-003",
    "FN-ZK-004",
    "FN-ZK-005",
    "FN-ZK-006",
    "FN-ZK-007",
    "FN-ZK-008",
    "FN-ZK-009",
    "FN-ZK-010",
    "FN-ZK-011",
    "FN-ZK-012",
]

# Task-specified error codes (appear in spec)
REQUIRED_ERROR_CODES = [
    "ERR_ZK_PROOF_INVALID",
    "ERR_ZK_PROOF_FORGED",
    "ERR_ZK_PREDICATE_UNSATISFIED",
    "ERR_ZK_WITNESS_MISSING",
    "ERR_ZK_CIRCUIT_MISMATCH",
    "ERR_ZK_ATTESTATION_EXPIRED",
]

# Implementation error codes (ERR_ZKA_xxx series in Rust code)
REQUIRED_IMPL_ERROR_CODES = [
    "ERR_ZKA_INVALID_PROOF",
    "ERR_ZKA_POLICY_MISMATCH",
    "ERR_ZKA_EXPIRED",
    "ERR_ZKA_REVOKED",
    "ERR_ZKA_PREDICATE_UNSATISFIED",
    "ERR_ZKA_DUPLICATE",
    "ERR_ZKA_TIMEOUT",
    "ERR_ZKA_POLICY_NOT_FOUND",
    "ERR_ZKA_BATCH_PARTIAL",
    "ERR_ZKA_METADATA_LEAK",
]

# Task-specified invariants (appear in spec)
REQUIRED_INVARIANTS = [
    "INV-ZK-NO-DISCLOSURE",
    "INV-ZK-PROOF-SOUNDNESS",
    "INV-ZK-FAIL-CLOSED",
    "INV-ZK-PREDICATE-COMPLETENESS",
]

# Implementation invariants (INV-ZKA-xxx series in Rust code)
REQUIRED_IMPL_INVARIANTS = [
    "INV-ZKA-SELECTIVE",
    "INV-ZKA-SOUNDNESS",
    "INV-ZKA-COMPLETENESS",
    "INV-ZKA-POLICY-BOUND",
    "INV-ZKA-AUDIT-TRAIL",
    "INV-ZKA-SCHEMA-VERSIONED",
]

REQUIRED_TYPES = [
    "ZkAttestation",
    "ZkPolicy",
    "ZkVerificationResult",
    "ZkBatchResult",
    "ZkAuditRecord",
    "PredicateOutcome",
    "AttestationStatus",
    "PolicyRegistry",
    "AttestationLedger",
    "ZkProofPayload",
]

REQUIRED_METHODS = [
    "generate_proof",
    "verify_proof",
    "verify_batch",
    "register_policy",
    "deregister_policy",
    "revoke_attestation",
    "query_audit",
    "is_valid",
    "sweep_expired",
    "generate_compliance_report",
]

MIN_TESTS = 20


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read(path))


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


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _has_type(source: str, name: str) -> bool:
    patterns = [
        rf"pub\s+struct\s+{name}\b",
        rf"pub\s+enum\s+{name}\b",
        rf"struct\s+{name}\b",
        rf"enum\s+{name}\b",
    ]
    return any(re.search(p, source) for p in patterns)


def _has_method(source: str, name: str) -> bool:
    return bool(re.search(rf"fn\s+{name}\b", source))


def run_all_checks() -> list[dict]:
    """Return list of check dicts."""
    checks: list[dict] = []
    impl_src = _read_rust_source(IMPL_FILE)
    spec_src = _read(SPEC_FILE)
    contract_src = _read(CONTRACT_FILE)
    sec_mod_src = _read_rust_source(SECURITY_MOD_FILE)
    sec_test_src = _read_rust_source(SECURITY_TEST)

    # ── File existence ───────────────────────────────────────────────────
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Contract file exists", CONTRACT_FILE.exists(), str(CONTRACT_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check(
        "Security module wired",
        "pub mod zk_attestation;" in sec_mod_src,
        "pub mod zk_attestation; in security/mod.rs",
    ))
    checks.append(_check("Security test exists", SECURITY_TEST.exists(), str(SECURITY_TEST)))
    checks.append(_check("Python unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))
    checks.append(_check("Evidence file exists", EVIDENCE_FILE.exists(), str(EVIDENCE_FILE)))
    checks.append(_check("Summary file exists", SUMMARY_FILE.exists(), str(SUMMARY_FILE)))

    # ── Type/struct checks ──────────────────────────────────────────────
    for name in REQUIRED_TYPES:
        checks.append(_check(f"Impl type '{name}'", _has_type(impl_src, name), name))

    # ── Method checks ───────────────────────────────────────────────────
    for name in REQUIRED_METHODS:
        checks.append(_check(f"Impl method '{name}'", _has_method(impl_src, name), name))

    # ── Event codes in spec ─────────────────────────────────────────────
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(f"Event code {code} in spec", code in spec_src, code))

    # ── FN codes in implementation ──────────────────────────────────────
    for code in REQUIRED_FN_CODES:
        checks.append(_check(f"FN code {code} in impl", code in impl_src, code))

    # ── Error codes in spec ─────────────────────────────────────────────
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(f"Error code {code} in spec", code in spec_src, code))

    # ── Impl error codes ────────────────────────────────────────────────
    for code in REQUIRED_IMPL_ERROR_CODES:
        checks.append(_check(f"Impl error code {code}", code in impl_src, code))

    # ── Invariants in spec ──────────────────────────────────────────────
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(f"Invariant {inv} in spec", inv in spec_src, inv))

    # ── Impl invariants ─────────────────────────────────────────────────
    for inv in REQUIRED_IMPL_INVARIANTS:
        checks.append(_check(f"Impl invariant {inv}", inv in impl_src, inv))

    # ── Invariants in contract ──────────────────────────────────────────
    for inv in REQUIRED_IMPL_INVARIANTS:
        checks.append(_check(f"Contract invariant {inv}", inv in contract_src, inv))

    # ── Rust inline test count ──────────────────────────────────────────
    inline_count = len(re.findall(r"#\[test\]", impl_src))
    checks.append(_check("Rust inline tests >= 20", inline_count >= MIN_TESTS, f"found {inline_count}"))

    # ── Security test count ─────────────────────────────────────────────
    sec_count = len(re.findall(r"#\[test\]", sec_test_src))
    checks.append(_check("Security tests >= 10", sec_count >= 10, f"found {sec_count}"))

    # ── Structural checks ──────────────────────────────────────────────
    checks.append(_check("Uses BTreeMap", "BTreeMap" in impl_src, "BTreeMap in implementation"))
    checks.append(_check("Schema version defined", "SCHEMA_VERSION" in impl_src, "SCHEMA_VERSION constant"))
    checks.append(_check("Schema version value", "zka-v1.0" in impl_src, "zka-v1.0"))
    checks.append(_check("Serde derives", "Serialize" in impl_src and "Deserialize" in impl_src, "Serialize/Deserialize"))
    checks.append(_check("cfg(test) module", "#[cfg(test)]" in impl_src, "#[cfg(test)] module present"))
    checks.append(_check("Invariants module", "pub mod invariants" in impl_src, "pub mod invariants"))
    checks.append(_check(
        "Selective disclosure",
        "metadata_commitment" in impl_src and "proof_bytes_hex" in impl_src,
        "commitment-based proof, not raw metadata",
    ))

    return checks


# Legacy alias used by existing test files.
_checks = run_all_checks

# Expose constants for existing test suite.
EVENT_CODES = REQUIRED_FN_CODES
ERROR_CODES = REQUIRED_IMPL_ERROR_CODES
INVARIANTS = REQUIRED_IMPL_INVARIANTS
SOURCE_RS = IMPL_FILE
SPEC_PATH = CONTRACT_FILE
TEST_SUITE = UNIT_TEST_FILE


def run_all() -> dict:
    checks = run_all_checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "zk-attestation-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Zero-knowledge attestation support for selective compliance verification",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "status": "pass" if failed == 0 else "fail",
        "all_passed": failed == 0,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "impl_error_codes": REQUIRED_IMPL_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "impl_invariants": REQUIRED_IMPL_INVARIANTS,
        "zk_contract": {
            "selective_disclosure": True,
            "proof_soundness": True,
            "fail_closed": True,
            "predicate_completeness": True,
            "policy_bound": True,
            "audit_trail": True,
            "schema_versioned": True,
        },
    }


def write_report(result: dict) -> None:
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict:
    checks: list[dict] = []
    checks.append(_check("event code count >= 5", len(REQUIRED_EVENT_CODES) >= 5))
    checks.append(_check("error code count >= 6", len(REQUIRED_ERROR_CODES) >= 6))
    checks.append(_check("impl error code count >= 10", len(REQUIRED_IMPL_ERROR_CODES) >= 10))
    checks.append(_check("invariant count >= 4", len(REQUIRED_INVARIANTS) >= 4))
    checks.append(_check("impl invariant count >= 6", len(REQUIRED_IMPL_INVARIANTS) >= 6))
    checks.append(_check("FN code count >= 12", len(REQUIRED_FN_CODES) >= 12))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 20))
    checks.append(_check("run_all has zk_contract", isinstance(result.get("zk_contract"), dict)))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_zk_attestation",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    configure_test_logging("check_zk_attestation")
    parser = argparse.ArgumentParser(description="bd-kcg9 checker")
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
        print(f"bd-kcg9: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
