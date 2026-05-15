#!/usr/bin/env python3
"""bd-nbwo: Verification script for universal verifier SDK and replay capsule format.

Usage:
    python3 scripts/check_universal_verifier_sdk.py           # human-readable
    python3 scripts/check_universal_verifier_sdk.py --json     # machine-readable
    python3 scripts/check_universal_verifier_sdk.py --self-test # internal consistency
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


# -- File paths ----------------------------------------------------------------

IMPL_FILE = ROOT / "crates/franken-node/src/connector/universal_verifier_sdk.rs"
MOD_FILE = ROOT / "crates/franken-node/src/connector/mod.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_17/bd-nbwo_contract.md"
TEST_FILE = ROOT / "tests/test_check_universal_verifier_sdk.py"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-nbwo/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-nbwo/verification_summary.md"

# -- Required elements ---------------------------------------------------------

REQUIRED_EVENT_CODES = [
    "VSDK_001",
    "VSDK_002",
    "VSDK_003",
    "VSDK_004",
    "VSDK_005",
    "VSDK_006",
    "VSDK_007",
]

REQUIRED_ERROR_CODES = [
    "ERR_VSDK_CAPSULE_INVALID",
    "ERR_VSDK_SIGNATURE_MISMATCH",
    "ERR_VSDK_SCHEMA_UNSUPPORTED",
    "ERR_VSDK_REPLAY_DIVERGED",
    "ERR_VSDK_SESSION_SEALED",
    "ERR_VSDK_MANIFEST_INCOMPLETE",
    "ERR_VSDK_EMPTY_PAYLOAD",
]

REQUIRED_INVARIANTS = [
    "INV-VSDK-CAPSULE-DETERMINISTIC",
    "INV-VSDK-NO-PRIVILEGE",
    "INV-VSDK-SCHEMA-VERSIONED",
    "INV-VSDK-SESSION-MONOTONIC",
    "INV-VSDK-SIGNATURE-BOUND",
]

REQUIRED_TYPES = [
    "CapsuleVerdict",
    "CapsuleManifest",
    "ReplayCapsule",
    "ReplayResult",
    "SessionStep",
    "VerificationSession",
    "VerifierSdk",
    "VsdkEvent",
    "VsdkError",
]

CORE_OPERATIONS = [
    "fn validate_manifest",
    "fn verify_capsule_signature",
    "fn sign_capsule",
    "fn replay_capsule",
    "fn create_session",
    "fn record_session_step",
    "fn seal_session",
    "fn create_verifier_sdk",
]

# -- Helpers -------------------------------------------------------------------


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

        if text[i] in {'"', "'"}:
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
    quote = text[start]
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == quote:
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


# -- Check functions -----------------------------------------------------------


def _checks() -> list:
    """Return list of {check, passed, detail} dicts."""
    checks = []
    src = _read_rust_source(IMPL_FILE)
    mod_src = _read_rust_source(MOD_FILE)

    # 1. Rust module exists
    checks.append(_check(
        "Rust module exists",
        IMPL_FILE.exists(),
        str(IMPL_FILE),
    ))

    # 2. Wired into mod.rs
    checks.append(_check(
        "Wired into connector/mod.rs",
        "pub mod universal_verifier_sdk;" in mod_src,
        "universal_verifier_sdk in mod.rs",
    ))

    # 3. Spec contract exists
    checks.append(_check(
        "Spec contract exists",
        SPEC_FILE.exists(),
        str(SPEC_FILE),
    ))

    # 4. Test file exists
    checks.append(_check(
        "Test file exists",
        TEST_FILE.exists(),
        str(TEST_FILE),
    ))

    # 5. Evidence exists with PASS verdict
    evidence_pass = False
    if EVIDENCE_FILE.exists():
        try:
            ev = json.JSONDecoder().decode(EVIDENCE_FILE.read_text(encoding="utf-8"))
            evidence_pass = ev.get("verdict") == "PASS"
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Evidence exists with PASS verdict",
        evidence_pass,
        str(EVIDENCE_FILE),
    ))

    # 6. Summary file exists
    checks.append(_check(
        "Verification summary exists",
        SUMMARY_FILE.exists(),
        str(SUMMARY_FILE),
    ))

    # 7. Event codes defined
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code} defined",
            code in src,
        ))

    # 8. Error codes defined
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code} defined",
            code in src,
        ))

    # 9. Invariants defined
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv} defined",
            inv in src,
        ))

    # 10. Core operations defined
    for op in CORE_OPERATIONS:
        checks.append(_check(
            f"Core operation '{op}' defined",
            op in src,
        ))

    # 11. Required types defined
    for t in REQUIRED_TYPES:
        found = f"pub struct {t}" in src or f"pub enum {t}" in src
        checks.append(_check(f"Type {t} defined", found))

    # 12. Schema version constant
    checks.append(_check(
        "Schema version vsdk-v1.0",
        'vsdk-v1.0' in src,
    ))

    # 13. BTreeMap usage for determinism
    checks.append(_check(
        "BTreeMap usage for determinism",
        "BTreeMap" in src,
    ))

    # 14. Serde derives
    checks.append(_check(
        "Serialize/Deserialize derives",
        "Serialize" in src and "Deserialize" in src,
    ))

    # 15. Tests present (minimum 20)
    test_count = src.count("#[test]")
    checks.append(_check(
        f"Rust unit tests ({test_count})",
        test_count >= 20,
        f"{test_count} tests found",
    ))

    # 16. ReplayCapsule has signature field
    checks.append(_check(
        "ReplayCapsule has signature field",
        "pub signature:" in src,
    ))

    # 17. CapsuleManifest has schema_version field
    checks.append(_check(
        "CapsuleManifest has schema_version field",
        "pub schema_version:" in src,
    ))

    # 18. VerificationSession has sealed field
    checks.append(_check(
        "VerificationSession has sealed field",
        "pub sealed:" in src,
    ))

    # 19. VerificationSession has final_verdict field
    checks.append(_check(
        "VerificationSession has final_verdict field",
        "pub final_verdict:" in src,
    ))

    # 20. CapsuleManifest has expected_output_hash field
    checks.append(_check(
        "CapsuleManifest has expected_output_hash",
        "pub expected_output_hash:" in src,
    ))

    # 21. No privileged access required (invariant documented)
    checks.append(_check(
        "No-privilege invariant documented",
        "INV-VSDK-NO-PRIVILEGE" in src and "without privileged" in _read(SPEC_FILE),
    ))

    # 22. Reference capsule builder
    checks.append(_check(
        "Reference capsule builder exists",
        "fn build_reference_capsule" in src,
    ))

    # 23. Reference session builder
    checks.append(_check(
        "Reference session builder exists",
        "fn build_reference_session" in src,
    ))

    # 24. Deterministic hash helper
    checks.append(_check(
        "Deterministic hash helper",
        "fn deterministic_hash" in src,
    ))

    # 25. VSDK_SCHEMA_VERSION constant
    checks.append(_check(
        "VSDK_SCHEMA_VERSION constant",
        "VSDK_SCHEMA_VERSION" in src,
    ))

    return checks


def self_test() -> dict:
    """Internal consistency checks for the gate script itself."""
    checks = []

    # Constants
    checks.append(_check("REQUIRED_EVENT_CODES == 7", len(REQUIRED_EVENT_CODES) == 7))
    checks.append(_check("REQUIRED_ERROR_CODES == 7", len(REQUIRED_ERROR_CODES) == 7))
    checks.append(_check("REQUIRED_INVARIANTS == 5", len(REQUIRED_INVARIANTS) == 5))
    checks.append(_check("REQUIRED_TYPES >= 9", len(REQUIRED_TYPES) >= 9))
    checks.append(_check("CORE_OPERATIONS == 8", len(CORE_OPERATIONS) == 8))

    # _checks returns list
    result = _checks()
    checks.append(_check("_checks returns list", isinstance(result, list)))
    checks.append(_check("_checks returns dicts", all(isinstance(c, dict) for c in result)))
    checks.append(_check("_checks >= 25 checks", len(result) >= 25))

    # Check structure
    for c in result[:5]:
        checks.append(_check(
            f"check '{c['check']}' has required keys",
            all(k in c for k in ["check", "passed", "detail"]),
        ))

    # Full run
    full = run_all()
    checks.append(_check("run_all has bead_id", full.get("bead_id") == "bd-nbwo"))
    checks.append(_check("run_all has section", full.get("section") == "10.17"))
    checks.append(_check("run_all has verdict", full.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has events", isinstance(full.get("events"), list)))
    checks.append(_check("run_all has summary", isinstance(full.get("summary"), str)))
    checks.append(_check("run_all has timestamp", isinstance(full.get("timestamp"), str)))

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def run_all() -> dict:
    """Run all checks and return structured result."""
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failed == 0 else "FAIL"

    events = []
    for code in REQUIRED_EVENT_CODES:
        events.append({"code": code, "status": "defined"})

    summary_lines = [
        "bd-nbwo: Universal Verifier SDK and Replay Capsule Format",
        f"Checks: {passed}/{len(checks)} passing",
        f"Verdict: {verdict}",
    ]
    if failed > 0:
        failing = [c for c in checks if not c["passed"]]
        for c in failing[:5]:
            summary_lines.append(f"  FAIL: {c['check']}: {c['detail']}")

    return {
        "bead_id": "bd-nbwo",
        "title": "Universal Verifier SDK and Replay Capsule Format",
        "section": "10.17",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "events": events,
        "summary": "\n".join(summary_lines),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# -- CLI -----------------------------------------------------------------------


def main():
    configure_test_logging("check_universal_verifier_sdk")
    if "--self-test" in sys.argv:
        result = self_test()
        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['check']}")
        print(f"\nself-test: {result['passed']}/{result['total']} {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
