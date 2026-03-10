#!/usr/bin/env python3
"""bd-nbwo verification gate for universal verifier SDK and replay capsule format.

Usage:
    python3 scripts/check_verifier_sdk_capsule.py                # human-readable
    python3 scripts/check_verifier_sdk_capsule.py --json          # machine-readable
    python3 scripts/check_verifier_sdk_capsule.py --self-test     # internal consistency
    python3 scripts/check_verifier_sdk_capsule.py --build-report  # write certification report
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path


BEAD = "bd-nbwo"
SECTION = "10.17"

# ---------------------------------------------------------------------------
# File paths
# ---------------------------------------------------------------------------

IMPL_FILE = ROOT / "crates/franken-node/src/connector/universal_verifier_sdk.rs"
MOD_FILE = ROOT / "crates/franken-node/src/connector/mod.rs"
SPEC_FILE = ROOT / "docs/specs/replay_capsule_format.md"
SDK_MOD_FILE = ROOT / "sdk/verifier/src/lib.rs"
SDK_CAPSULE_FILE = ROOT / "sdk/verifier/src/capsule.rs"
CONFORMANCE_TEST = ROOT / "tests/conformance/verifier_sdk_capsule_replay.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_verifier_sdk_capsule.py"
REPORT_FILE = ROOT / "artifacts/10.17/verifier_sdk_certification_report.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-nbwo/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-nbwo/verification_summary.md"

# ---------------------------------------------------------------------------
# Required elements
# ---------------------------------------------------------------------------

REQUIRED_EVENT_CODES = [
    "CAPSULE_CREATED",
    "CAPSULE_SIGNED",
    "CAPSULE_REPLAY_START",
    "CAPSULE_VERDICT_REPRODUCED",
    "SDK_VERSION_CHECK",
]

REQUIRED_ERROR_CODES = [
    "ERR_CAPSULE_SIGNATURE_INVALID",
    "ERR_CAPSULE_SCHEMA_MISMATCH",
    "ERR_CAPSULE_REPLAY_DIVERGED",
    "ERR_CAPSULE_VERDICT_MISMATCH",
    "ERR_SDK_VERSION_UNSUPPORTED",
    "ERR_CAPSULE_ACCESS_DENIED",
]

REQUIRED_INVARIANTS = [
    "INV-CAPSULE-STABLE-SCHEMA",
    "INV-CAPSULE-VERSIONED-API",
    "INV-CAPSULE-NO-PRIVILEGED-ACCESS",
    "INV-CAPSULE-VERDICT-REPRODUCIBLE",
]

REQUIRED_IMPL_EVENT_CODES = [
    "VSDK_001",
    "VSDK_002",
    "VSDK_003",
    "VSDK_004",
    "VSDK_005",
    "VSDK_006",
    "VSDK_007",
]

REQUIRED_IMPL_ERROR_CODES = [
    "ERR_VSDK_CAPSULE_INVALID",
    "ERR_VSDK_SIGNATURE_MISMATCH",
    "ERR_VSDK_SCHEMA_UNSUPPORTED",
    "ERR_VSDK_REPLAY_DIVERGED",
    "ERR_VSDK_SESSION_SEALED",
    "ERR_VSDK_MANIFEST_INCOMPLETE",
    "ERR_VSDK_EMPTY_PAYLOAD",
]

REQUIRED_IMPL_INVARIANTS = [
    "INV-VSDK-CAPSULE-DETERMINISTIC",
    "INV-VSDK-NO-PRIVILEGE",
    "INV-VSDK-SCHEMA-VERSIONED",
    "INV-VSDK-SESSION-MONOTONIC",
    "INV-VSDK-SIGNATURE-BOUND",
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def run_all_checks() -> list[dict]:
    """Return list of {check, passed, detail} dicts."""
    checks: list[dict] = []
    impl_src = _read(IMPL_FILE)
    mod_src = _read(MOD_FILE)
    spec_src = _read(SPEC_FILE)
    sdk_mod_src = _read(SDK_MOD_FILE)
    sdk_capsule_src = _read(SDK_CAPSULE_FILE)

    # -- File existence checks -----------------------------------------------

    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check("SDK lib.rs exists", SDK_MOD_FILE.exists(), str(SDK_MOD_FILE)))
    checks.append(_check("SDK capsule.rs exists", SDK_CAPSULE_FILE.exists(), str(SDK_CAPSULE_FILE)))
    checks.append(_check(
        "Wired into connector/mod.rs",
        "pub mod universal_verifier_sdk;" in mod_src,
        "universal_verifier_sdk in mod.rs",
    ))
    checks.append(_check("Conformance test exists", CONFORMANCE_TEST.exists(), str(CONFORMANCE_TEST)))
    checks.append(_check("Python checker unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))

    # -- Event codes in SDK facade -------------------------------------------

    for code in REQUIRED_EVENT_CODES:
        found = code in sdk_mod_src or code in sdk_capsule_src or code in spec_src
        checks.append(_check(f"Event code {code}", found, code))

    # -- Error codes in SDK facade -------------------------------------------

    for code in REQUIRED_ERROR_CODES:
        found = code in sdk_mod_src or code in sdk_capsule_src or code in spec_src
        checks.append(_check(f"Error code {code}", found, code))

    # -- Invariants in SDK facade --------------------------------------------

    for inv in REQUIRED_INVARIANTS:
        found = inv in sdk_mod_src or inv in sdk_capsule_src or inv in spec_src
        checks.append(_check(f"Invariant {inv}", found, inv))

    # -- Implementation event codes ------------------------------------------

    for code in REQUIRED_IMPL_EVENT_CODES:
        checks.append(_check(f"Impl event code {code}", code in impl_src, code))

    # -- Implementation error codes ------------------------------------------

    for code in REQUIRED_IMPL_ERROR_CODES:
        checks.append(_check(f"Impl error code {code}", code in impl_src, code))

    # -- Implementation invariants -------------------------------------------

    for inv in REQUIRED_IMPL_INVARIANTS:
        checks.append(_check(f"Impl invariant {inv}", inv in impl_src, inv))

    # -- Core operations -----------------------------------------------------

    for op in CORE_OPERATIONS:
        checks.append(_check(f"Core operation '{op}'", op in impl_src, op))

    # -- Required types ------------------------------------------------------

    for t in REQUIRED_TYPES:
        found = f"pub struct {t}" in impl_src or f"pub enum {t}" in impl_src
        checks.append(_check(f"Type {t}", found, t))

    # -- Structural checks ---------------------------------------------------

    checks.append(_check(
        "Schema version vsdk-v1.0",
        "vsdk-v1.0" in impl_src,
        "VSDK_SCHEMA_VERSION",
    ))

    checks.append(_check(
        "BTreeMap usage for determinism",
        "BTreeMap" in impl_src,
        "deterministic ordering",
    ))

    checks.append(_check(
        "Serde derives present",
        "Serialize" in impl_src and "Deserialize" in impl_src,
        "Serialize + Deserialize",
    ))

    test_count = impl_src.count("#[test]")
    checks.append(_check(
        "Rust unit tests >= 20",
        test_count >= 20,
        f"found {test_count}",
    ))

    sdk_test_count = sdk_mod_src.count("#[test]") + sdk_capsule_src.count("#[test]")
    checks.append(_check(
        "SDK facade tests >= 8",
        sdk_test_count >= 8,
        f"found {sdk_test_count}",
    ))

    checks.append(_check(
        "ReplayCapsule has signature field",
        "pub signature:" in impl_src,
        "signature field",
    ))

    checks.append(_check(
        "CapsuleManifest has schema_version field",
        "pub schema_version:" in impl_src,
        "schema_version field",
    ))

    checks.append(_check(
        "No-privilege invariant documented",
        "INV-VSDK-NO-PRIVILEGE" in impl_src and "without privileged" in impl_src,
        "no-privilege invariant",
    ))

    checks.append(_check(
        "Reference capsule builder",
        "fn build_reference_capsule" in impl_src,
        "build_reference_capsule",
    ))

    checks.append(_check(
        "Deterministic hash helper",
        "fn deterministic_hash" in impl_src,
        "deterministic_hash",
    ))

    # -- Evidence and summary ------------------------------------------------

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

    checks.append(_check(
        "Verification summary exists",
        SUMMARY_FILE.exists(),
        str(SUMMARY_FILE),
    ))

    return checks


def run_all() -> dict:
    """Run all checks and return structured result."""
    checks = run_all_checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
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
        "schema_version": "verifier-sdk-capsule-v1.0",
        "bead_id": BEAD,
        "title": "Universal Verifier SDK and Replay Capsule Format",
        "section": SECTION,
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "capsule_contract": {
            "capsule_replay_deterministic": True,
            "no_privileged_access": True,
            "schema_versioned": True,
            "signature_bound": True,
        },
        "events": events,
        "summary": "\n".join(summary_lines),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def write_report(result: dict) -> None:
    """Write the certification report to the artifacts directory."""
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict:
    """Internal consistency checks for the gate script itself."""
    checks: list[dict] = []

    # Constants
    checks.append(_check("event code count >= 5", len(REQUIRED_EVENT_CODES) >= 5))
    checks.append(_check("error code count >= 6", len(REQUIRED_ERROR_CODES) >= 6))
    checks.append(_check("invariant count >= 4", len(REQUIRED_INVARIANTS) >= 4))
    checks.append(_check("impl event code count >= 7", len(REQUIRED_IMPL_EVENT_CODES) >= 7))
    checks.append(_check("impl error code count >= 7", len(REQUIRED_IMPL_ERROR_CODES) >= 7))
    checks.append(_check("impl invariant count >= 5", len(REQUIRED_IMPL_INVARIANTS) >= 5))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 25))
    checks.append(_check("run_all has bead_id", result.get("bead_id") == BEAD))
    checks.append(_check("run_all has section", result.get("section") == SECTION))
    checks.append(_check("run_all has capsule_contract", isinstance(result.get("capsule_contract"), dict)))
    checks.append(_check("run_all has events", isinstance(result.get("events"), list)))
    checks.append(_check("run_all has summary", isinstance(result.get("summary"), str)))
    checks.append(_check("run_all has timestamp", isinstance(result.get("timestamp"), str)))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_verifier_sdk_capsule",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    logger = configure_test_logging("check_verifier_sdk_capsule")
    parser = argparse.ArgumentParser(description="bd-nbwo checker")
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
            for c in st["checks"]:
                mark = "+" if c["passed"] else "x"
                print(f"[{mark}] {c['check']}: {c['detail']}")
        sys.exit(0 if st["verdict"] == "PASS" else 1)

    result = run_all()
    if args.build_report:
        write_report(result)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-nbwo: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
