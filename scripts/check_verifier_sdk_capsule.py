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
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


BEAD = "bd-nbwo"
SECTION = "10.17"

# ---------------------------------------------------------------------------
# File paths
# ---------------------------------------------------------------------------

IMPL_FILE = ROOT / "crates/franken-node/src/connector/universal_verifier_sdk.rs"
MOD_FILE = ROOT / "crates/franken-node/src/connector/mod.rs"
SPEC_FILE = ROOT / "docs/specs/replay_capsule_format.md"
CONTRACT_FILE = ROOT / "docs/specs/section_10_17/bd-nbwo_contract.md"
SDK_CARGO_FILE = ROOT / "sdk/verifier/Cargo.toml"
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

ARTIFACT_CONSISTENCY_CHECK_NAMES = (
    "Verification evidence checker counts match live checker results",
    "Verification evidence unit test counts match live checker results",
    "Verification summary counts match live checker results",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _compact_whitespace(text: str) -> str:
    return " ".join(text.split())


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _required_checks_pass(checks: list[dict], required_names: set[str]) -> bool:
    """Fail closed when any required check is missing or failing."""
    passed_by_name = {
        check.get("check"): bool(check.get("passed"))
        for check in checks
        if isinstance(check.get("check"), str)
    }
    return all(passed_by_name.get(name) is True for name in required_names)


def _parse_json_document(raw: str) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _count_unittest_cases(unit_test_src: str) -> int:
    return sum(1 for line in unit_test_src.splitlines() if line.lstrip().startswith("def test_"))


def _artifact_consistency_checks(
    base_checks: list[dict],
    evidence_doc: dict,
    summary_src: str,
    unit_test_src: str,
) -> list[dict]:
    pending_artifact_checks = len(ARTIFACT_CONSISTENCY_CHECK_NAMES)
    expected_total = len(base_checks) + pending_artifact_checks
    expected_passed = (
        sum(1 for check in base_checks if bool(check.get("passed"))) + pending_artifact_checks
    )
    expected_failed = expected_total - expected_passed

    checker_summary_line = (
        f"- Check script: `scripts/check_verifier_sdk_capsule.py` -- "
        f"{expected_passed}/{expected_total} checks PASS"
    )
    unit_test_count = _count_unittest_cases(unit_test_src)
    unit_test_summary_line = (
        f"- Unit tests: `tests/test_check_verifier_sdk_capsule.py` -- "
        f"{unit_test_count}/{unit_test_count} tests PASS"
    )

    evidence_checker = evidence_doc.get("checker", {}) if isinstance(evidence_doc, dict) else {}
    evidence_unit_tests = (
        evidence_doc.get("unit_tests", {}) if isinstance(evidence_doc, dict) else {}
    )

    return [
        _check(
            ARTIFACT_CONSISTENCY_CHECK_NAMES[0],
            evidence_checker.get("passed_checks") == expected_passed
            and evidence_checker.get("failed_checks") == expected_failed
            and evidence_checker.get("exit_code") == 0,
            (
                "artifacts/section_10_17/bd-nbwo/verification_evidence.json checker counts must "
                "match live checker state: "
                f"expected exit_code=0, passed={expected_passed}, failed={expected_failed}"
            ),
        ),
        _check(
            ARTIFACT_CONSISTENCY_CHECK_NAMES[1],
            evidence_unit_tests.get("passed_tests") == unit_test_count
            and evidence_unit_tests.get("failed_tests") == 0
            and evidence_unit_tests.get("exit_code") == 0,
            (
                "artifacts/section_10_17/bd-nbwo/verification_evidence.json unit test counts "
                "must match live checker state: "
                f"expected exit_code=0, passed={unit_test_count}, failed=0"
            ),
        ),
        _check(
            ARTIFACT_CONSISTENCY_CHECK_NAMES[2],
            checker_summary_line in summary_src and unit_test_summary_line in summary_src,
            (
                "artifacts/section_10_17/bd-nbwo/verification_summary.md must include: "
                f"{checker_summary_line} | {unit_test_summary_line}"
            ),
        ),
    ]


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def run_all_checks() -> list[dict]:
    """Return list of {check, passed, detail} dicts."""
    checks: list[dict] = []
    impl_src = _read(IMPL_FILE)
    mod_src = _read(MOD_FILE)
    spec_src = _read(SPEC_FILE)
    contract_src = _read(CONTRACT_FILE)
    spec_doc = _compact_whitespace(spec_src)
    contract_doc = _compact_whitespace(contract_src)
    sdk_cargo_src = _read(SDK_CARGO_FILE)
    sdk_mod_src = _read(SDK_MOD_FILE)
    sdk_capsule_src = _read(SDK_CAPSULE_FILE)
    sdk_doc_src = "\n".join((spec_src, contract_src))
    unit_test_src = _read(UNIT_TEST_FILE)
    evidence_doc = _parse_json_document(_read(EVIDENCE_FILE))
    summary_src = _read(SUMMARY_FILE)

    workspace_sdk_posture_explicit = (
        'pub const STRUCTURAL_ONLY_SECURITY_POSTURE: &str = "structural_only_not_replacement_critical";'
        in sdk_mod_src
        and 'pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK";'
        in sdk_mod_src
    )
    workspace_capsule_posture_explicit = (
        'pub const STRUCTURAL_ONLY_SECURITY_POSTURE: &str = "structural_only_not_replacement_critical";'
        in sdk_capsule_src
        and 'pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_REPLAY_CAPSULE";'
        in sdk_capsule_src
        and "structural signature digest" in sdk_capsule_src
    )
    workspace_docs_structural_only = all(
        marker in sdk_doc_src
        for marker in (
            "The standalone workspace crate `sdk/verifier` is structural-only.",
            "structural signature digest helpers",
            "not the replacement-critical canonical verifier",
            "does not claim detached cryptographic verification authority",
        )
    )
    connector_docs_detached_signature_authority = all(
        marker in sdk_doc_src
        for marker in (
            "`connector::universal_verifier_sdk`",
            "detached Ed25519 signature",
            "canonical signing payload",
        )
    )
    workspace_docs_expected_hash_shape = (
        "`expected_output_hash` must be a 64-character hex sha256 digest." in spec_doc
        and "`expected_output_hash` must be a 64-character hex sha256 digest." in contract_doc
        and "required fields, and `expected_output_hash` shape" in spec_doc
    )
    workspace_docs_input_ref_binding = (
        "Declared `input_refs` must be unique and exactly match the replayed `inputs`"
        in spec_doc
        and "Declared `input_refs` must be unique and exactly match the replayed `inputs`"
        in contract_doc
        and "Verify the declared `input_refs` are unique and exactly match the replayed `inputs` set."
        in spec_doc
    )
    workspace_metadata_structural_only = (
        'description = "Structural-only verifier SDK for replaying structurally bound capsules and reproducing claim verdicts"'
        in sdk_cargo_src
    )
    workspace_metadata_avoid_overclaim = all(
        marker not in sdk_cargo_src
        for marker in (
            "signed capsules",
            "cryptographic authority",
        )
    )

    # -- File existence checks -----------------------------------------------

    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Contract file exists", CONTRACT_FILE.exists(), str(CONTRACT_FILE)))
    checks.append(_check("SDK Cargo.toml exists", SDK_CARGO_FILE.exists(), str(SDK_CARGO_FILE)))
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
        found = code in sdk_mod_src or code in sdk_capsule_src or code in sdk_doc_src
        checks.append(_check(f"Event code {code}", found, code))

    # -- Error codes in SDK facade -------------------------------------------

    for code in REQUIRED_ERROR_CODES:
        found = code in sdk_mod_src or code in sdk_capsule_src or code in sdk_doc_src
        checks.append(_check(f"Error code {code}", found, code))

    # -- Invariants in SDK facade --------------------------------------------

    for inv in REQUIRED_INVARIANTS:
        found = inv in sdk_mod_src or inv in sdk_capsule_src or inv in sdk_doc_src
        checks.append(_check(f"Invariant {inv}", found, inv))

    checks.append(_check(
        "Workspace SDK structural-only posture explicit",
        workspace_sdk_posture_explicit,
        "sdk/verifier/src/lib.rs structural-only posture markers",
    ))

    checks.append(_check(
        "Workspace replay capsule structural-only posture explicit",
        workspace_capsule_posture_explicit,
        "sdk/verifier/src/capsule.rs structural-only posture markers",
    ))

    checks.append(_check(
        "Public docs distinguish structural-only workspace SDK",
        workspace_docs_structural_only,
        "replay capsule spec and bd-nbwo contract describe the structural-only workspace companion",
    ))

    checks.append(_check(
        "Public docs describe connector detached Ed25519 signature authority",
        connector_docs_detached_signature_authority,
            "replay capsule spec and bd-nbwo contract describe detached Ed25519 signatures over the canonical signing payload",
    ))

    checks.append(_check(
        "Public docs pin sha256-shaped expected_output_hash",
        workspace_docs_expected_hash_shape,
        "spec + bd-nbwo contract require 64-character hex sha256 expected_output_hash values",
    ))

    checks.append(_check(
        "Public docs pin exact input_refs to inputs binding",
        workspace_docs_input_ref_binding,
        "spec + bd-nbwo contract require unique declared input_refs to exactly match replayed inputs",
    ))

    checks.append(_check(
        "SDK package metadata marks structural-only posture",
        workspace_metadata_structural_only,
        "sdk/verifier/Cargo.toml description aligns with structural-only posture",
    ))

    checks.append(_check(
        "SDK package metadata avoids signed-capsule overclaim",
        workspace_metadata_avoid_overclaim,
        "sdk/verifier/Cargo.toml avoids signed-capsule or authority overclaim wording",
    ))

    checks.append(_check(
        "Workspace replay capsule rejects malformed expected_output_hash",
        all(
            marker in sdk_capsule_src
            for marker in (
                "fn is_sha256_hex",
                "!is_sha256_hex(&manifest.expected_output_hash)",
                "expected_output_hash must be a 64-character hex sha256 digest",
                "test_validate_manifest_malformed_expected_hash",
                "test_replay_rejects_malformed_expected_hash",
            )
        ),
        "sdk/verifier/src/capsule.rs fail-closes on malformed expected_output_hash before replay verdict evaluation",
    ))

    checks.append(_check(
        "Workspace replay capsule uses constant-time expected_output_hash comparison",
        all(
            marker in sdk_capsule_src
            for marker in (
                "fn ct_eq(a: &str, b: &str) -> bool",
                "let verdict = if ct_eq(",
                "&capsule.manifest.expected_output_hash",
            )
        ),
        "sdk/verifier/src/capsule.rs uses ct_eq for replay-hash vs expected_output_hash comparison",
    ))

    checks.append(_check(
        "Workspace replay capsule binds declared input_refs to inputs",
        all(
            marker in sdk_capsule_src
            for marker in (
                "fn validate_declared_input_refs",
                "input_refs contains duplicate entries",
                "input_refs do not match inputs",
                "validate_declared_input_refs(capsule)?",
                "test_replay_rejects_missing_declared_input",
                "test_replay_rejects_extra_undeclared_input",
                "test_replay_rejects_duplicate_declared_input_refs",
            )
        ),
        "sdk/verifier/src/capsule.rs enforces unique input_refs that exactly match replayed inputs",
    ))

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

    checks.extend(
        _artifact_consistency_checks(
            checks,
            evidence_doc,
            summary_src,
            unit_test_src,
        )
    )

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
            "workspace_sdk_structural_only_posture_explicit": _required_checks_pass(
                checks,
                {
                    "Workspace SDK structural-only posture explicit",
                    "Workspace replay capsule structural-only posture explicit",
                    "Public docs distinguish structural-only workspace SDK",
                    "SDK package metadata marks structural-only posture",
                    "SDK package metadata avoids signed-capsule overclaim",
                },
            ),
            "connector_signature_authority_explicit": _required_checks_pass(
                checks,
                {"Public docs describe connector detached Ed25519 signature authority"},
            ),
            "workspace_manifest_binding_explicit": _required_checks_pass(
                checks,
                {
                    "Public docs pin sha256-shaped expected_output_hash",
                    "Public docs pin exact input_refs to inputs binding",
                    "Workspace replay capsule rejects malformed expected_output_hash",
                    "Workspace replay capsule uses constant-time expected_output_hash comparison",
                    "Workspace replay capsule binds declared input_refs to inputs",
                },
            ),
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
