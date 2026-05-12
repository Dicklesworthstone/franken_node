#!/usr/bin/env python3
"""bd-3c2: Verification script for verifier-economy SDK with independent validation workflows.

Usage:
    python3 scripts/check_verifier_sdk.py           # human-readable
    python3 scripts/check_verifier_sdk.py --json     # machine-readable
    python3 scripts/check_verifier_sdk.py --self-test # internal consistency
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path


# -- File paths ----------------------------------------------------------------

IMPL_FILE = ROOT / "crates/franken-node/src/connector/verifier_sdk.rs"
MOD_FILE = ROOT / "crates/franken-node/src/connector/mod.rs"
SCHEMA_FILE = ROOT / "spec/evidence_bundle_schema.json"
SPEC_FILE = ROOT / "docs/specs/section_10_12/bd-3c2_contract.md"
TEST_FILE = ROOT / "tests/test_check_verifier_sdk.py"
EVIDENCE_FILE = ROOT / "artifacts/section_10_12/bd-3c2/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_12/bd-3c2/verification_summary.md"

# -- Required elements ---------------------------------------------------------

REQUIRED_EVENT_CODES = [
    "VER-001",
    "VER-002",
    "VER-003",
    "VER-004",
    "VER-005",
    "VER-006",
    "VER-007",
    "VER-008",
    "VER-009",
    "VER-010",
]

REQUIRED_ERROR_CODES = [
    "ERR_VER_INVALID_CLAIM",
    "ERR_VER_EVIDENCE_MISSING",
    "ERR_VER_SIGNATURE_INVALID",
    "ERR_VER_HASH_MISMATCH",
    "ERR_VER_REPLAY_DIVERGED",
    "ERR_VER_ANCHOR_UNKNOWN",
    "ERR_VER_BUNDLE_INCOMPLETE",
]

REQUIRED_INVARIANTS = [
    "INV-VER-DETERMINISTIC",
    "INV-VER-OFFLINE-CAPABLE",
    "INV-VER-EVIDENCE-BOUND",
    "INV-VER-RESULT-SIGNED",
    "INV-VER-TRANSPARENCY-APPEND",
]

REQUIRED_TYPES = [
    "Claim",
    "Evidence",
    "EvidenceBundle",
    "VerificationResult",
    "ReplayResult",
    "ValidationWorkflow",
    "TransparencyLogEntry",
    "Verdict",
    "AssertionResult",
    "VerifierSdkEvent",
    "VerifierSdkError",
]

CORE_OPERATIONS = [
    "fn verify_claim",
    "fn verify_migration_artifact",
    "fn verify_trust_state",
    "fn replay_capsule",
]

REPLACEMENT_CRITICAL_GUARDS = [
    {
        "name": "migration_signature_path",
        "anchor": "pub fn verify_migration_artifact(",
        "required": [
            "canonical_migration_artifact_payload(artifact)?",
            "verify_ed25519_signature_hex(signer_public_key, &signature_payload, sig).is_ok()",
        ],
        "banned": [
            "let sig_ok = !sig.is_empty()",
            "let sig_ok = !signature.is_empty()",
        ],
        "span": 3200,
    },
    {
        "name": "content_hash_path",
        "anchor": "pub fn verify_migration_artifact(",
        "required": [
            "let ch_ok = is_sha256_hex(ch);",
        ],
        "banned": [
            "let ch_ok = !ch.is_empty()",
            "let ch_ok = ch.is_empty() == false",
        ],
        "span": 3200,
    },
]

# -- Helpers -------------------------------------------------------------------


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _source_window(source: str, anchor: str, span: int) -> str:
    start = source.find(anchor)
    if start == -1:
        return ""
    return source[start : start + span]


def _replacement_critical_guard_checks(source: str) -> list[dict]:
    checks = []
    for guard in REPLACEMENT_CRITICAL_GUARDS:
        window = _source_window(source, guard["anchor"], guard["span"])
        if not window:
            checks.append(_check(
                f"Replacement-critical guard {guard['name']} anchor",
                False,
                f"missing anchor: {guard['anchor']}",
            ))
            continue

        missing = [marker for marker in guard["required"] if marker not in window]
        checks.append(_check(
            f"Replacement-critical guard {guard['name']} required markers",
            len(missing) == 0,
            "all required markers present" if not missing else f"missing: {missing}",
        ))

        present = [marker for marker in guard["banned"] if marker in window]
        checks.append(_check(
            f"Replacement-critical guard {guard['name']} no shortcuts",
            len(present) == 0,
            "no shortcut markers found" if not present else f"banned markers present: {present}",
        ))

    return checks


# -- Check functions -----------------------------------------------------------


def _checks() -> list:
    """Return list of {check, passed, detail} dicts."""
    checks = []
    src = _read(IMPL_FILE)
    mod_src = _read(MOD_FILE)

    # 1. Rust module exists
    checks.append(_check(
        "Rust module exists",
        IMPL_FILE.exists(),
        str(IMPL_FILE),
    ))

    # 2. Wired into mod.rs
    checks.append(_check(
        "Wired into connector/mod.rs",
        "pub mod verifier_sdk;" in mod_src,
        "verifier_sdk in mod.rs",
    ))

    # 3. Spec contract exists
    checks.append(_check(
        "Spec contract exists",
        SPEC_FILE.exists(),
        str(SPEC_FILE),
    ))

    # 4. JSON schema exists
    checks.append(_check(
        "JSON schema exists",
        SCHEMA_FILE.exists(),
        str(SCHEMA_FILE),
    ))

    # 5. Test file exists
    checks.append(_check(
        "Test file exists",
        TEST_FILE.exists(),
        str(TEST_FILE),
    ))

    # 6. Evidence exists with PASS verdict
    evidence_pass = False
    if EVIDENCE_FILE.exists():
        try:
            ev = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
            evidence_pass = ev.get("verdict") == "PASS"
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Evidence exists with PASS verdict",
        evidence_pass,
        str(EVIDENCE_FILE),
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

    # 10. Core operation types defined
    for op in CORE_OPERATIONS:
        checks.append(_check(
            f"Core operation '{op}' defined",
            op in src,
        ))

    # 11. Required types defined
    for t in REQUIRED_TYPES:
        found = f"pub struct {t}" in src or f"pub enum {t}" in src
        checks.append(_check(f"Type {t} defined", found))

    # 12. VerificationResult type
    checks.append(_check(
        "VerificationResult has verdict field",
        "pub verdict:" in src and "Verdict" in src,
    ))

    # 13. EvidenceBundle type
    checks.append(_check(
        "EvidenceBundle has self_contained field",
        "pub self_contained:" in src,
    ))

    # 14. Workflow types
    checks.append(_check(
        "ValidationWorkflow::ReleaseValidation",
        "ReleaseValidation" in src,
    ))
    checks.append(_check(
        "ValidationWorkflow::IncidentValidation",
        "IncidentValidation" in src,
    ))
    checks.append(_check(
        "ValidationWorkflow::ComplianceAudit",
        "ComplianceAudit" in src,
    ))

    # 15. Offline capability
    checks.append(_check(
        "Offline capability documented",
        "INV-VER-OFFLINE-CAPABLE" in src and "OFFLINE" in src,
    ))

    # 16. Transparency log
    checks.append(_check(
        "Transparency log append function",
        "fn append_transparency_log" in src,
    ))
    checks.append(_check(
        "TransparencyLogEntry has merkle_proof",
        "pub merkle_proof:" in src,
    ))

    # 17. Schema version
    checks.append(_check(
        "Schema version ver-v1.0",
        'ver-v1.0' in src,
    ))

    # 18. BTreeMap usage for determinism
    checks.append(_check(
        "BTreeMap usage for determinism",
        "BTreeMap" in src,
    ))

    # 19. Serde derives
    checks.append(_check(
        "Serialize/Deserialize derives",
        "Serialize" in src and "Deserialize" in src,
    ))

    # 20. Tests present
    test_count = src.count("#[test]")
    checks.append(_check(
        f"Rust unit tests ({test_count})",
        test_count >= 25,
        f"{test_count} tests found",
    ))

    checks.extend(_replacement_critical_guard_checks(src))

    # 21. Summary file exists
    checks.append(_check(
        "Verification summary exists",
        SUMMARY_FILE.exists(),
        str(SUMMARY_FILE),
    ))

    # 22. JSON schema parseable and has expected defs
    if SCHEMA_FILE.exists():
        try:
            schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
            defs = schema.get("$defs", {})
            for def_name in ["Claim", "Evidence", "VerificationResult", "ReplayResult", "TransparencyLogEntry"]:
                checks.append(_check(
                    f"Schema $def '{def_name}'",
                    def_name in defs,
                ))
        except (json.JSONDecodeError, OSError):
            checks.append(_check("Schema parseable", False, "JSON parse error"))
    else:
        checks.append(_check("Schema parseable", False, "file not found"))

    return checks


def self_test() -> dict:
    """Internal consistency checks for the gate script itself."""
    checks = []

    # Constants
    checks.append(_check("REQUIRED_EVENT_CODES == 10", len(REQUIRED_EVENT_CODES) == 10))
    checks.append(_check("REQUIRED_ERROR_CODES == 7", len(REQUIRED_ERROR_CODES) == 7))
    checks.append(_check("REQUIRED_INVARIANTS == 5", len(REQUIRED_INVARIANTS) == 5))
    checks.append(_check("REQUIRED_TYPES >= 10", len(REQUIRED_TYPES) >= 10))
    checks.append(_check("CORE_OPERATIONS == 4", len(CORE_OPERATIONS) == 4))

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
    checks.append(_check("run_all has bead_id", full.get("bead_id") == "bd-3c2"))
    checks.append(_check("run_all has section", full.get("section") == "10.12"))
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
        "bd-3c2: Verifier-Economy SDK with Independent Validation Workflows",
        f"Checks: {passed}/{len(checks)} passing",
        f"Verdict: {verdict}",
    ]
    if failed > 0:
        failing = [c for c in checks if not c["passed"]]
        for c in failing[:5]:
            summary_lines.append(f"  FAIL: {c['check']}: {c['detail']}")

    return {
        "bead_id": "bd-3c2",
        "title": "Verifier-Economy SDK with Independent Validation Workflows",
        "section": "10.12",
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
    logger = configure_test_logging("check_verifier_sdk")
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
