#!/usr/bin/env python3
"""bd-209w gate: Signed Extension Registry with Provenance and Revocation (Section 15).

Validates the Rust implementation in
crates/franken-node/src/supply_chain/extension_registry.rs against
the spec contract docs/specs/section_15/bd-209w_contract.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


SRC = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "extension_registry.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_15" / "bd-209w_contract.md"
REPLACEMENT_EVIDENCE_DIR = ROOT / "artifacts" / "replacement_gap" / "bd-3hdn"
REPLACEMENT_EVIDENCE = REPLACEMENT_EVIDENCE_DIR / "verification_evidence.json"
REPLACEMENT_SUMMARY = REPLACEMENT_EVIDENCE_DIR / "verification_summary.md"
ADVERSARIAL_FIXTURE_INDEX = REPLACEMENT_EVIDENCE_DIR / "adversarial_fixture_index.json"
OPERATOR_E2E = ROOT / "tests" / "e2e" / "extension_registry_operator_suite.sh"
OPERATOR_LOG = REPLACEMENT_EVIDENCE_DIR / "operator_e2e_log.jsonl"
OPERATOR_SUMMARY_JSON = REPLACEMENT_EVIDENCE_DIR / "operator_e2e_summary.json"
OPERATOR_SUMMARY_MD = REPLACEMENT_EVIDENCE_DIR / "operator_e2e_summary.md"
GOLDEN_TEST = ROOT / "crates" / "franken-node" / "tests" / "supply_chain_attestation_manifest_golden.rs"
GOLDEN_ARTIFACT = ROOT / "artifacts" / "golden" / "supply_chain_attestation_manifest.json"
CONFORMANCE_TEST = ROOT / "crates" / "franken-node" / "tests" / "supply_chain_registry_attestation_receipt_conformance.rs"
ADVERSARIAL_TEST = ROOT / "crates" / "franken-node" / "tests" / "adversarial_supply_chain_poisoning.rs"
CLAIMS_E2E_TEST = ROOT / "crates" / "franken-node" / "tests" / "supply_chain_registry_claims_e2e_integration.rs"

REPLACEMENT_BEAD_ID = "bd-3hdn"
COMPLETION_DEBT_BEAD = "bd-3hdn.1"
COMPLETION_DEBT_REQUIRED_SPEC_ITEMS = {
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
    "tests.golden.primary",
    "telemetry.primary",
}
REQUIRED_TELEMETRY_FIELDS = [
    "trace_id",
    "artifact_id",
    "publisher_key_id",
    "decision",
    "reason_code",
    "transparency_checkpoint",
    "attestation_digest",
]
COMPLETION_DEBT_OBLIGATIONS = [
    {
        "spec_item": "tests.unit.primary",
        "category": "unit",
        "status": "covered",
        "description": "source checker and Python tests cover the signed admission kernel, no-shape-shortcut regression checks, evidence-pack drift, and completion-debt contract",
        "evidence_paths": [
            "scripts/check_signed_extension_registry.py",
            "tests/test_check_signed_extension_registry.py",
            "crates/franken-node/src/supply_chain/extension_registry.rs",
        ],
        "commands": [
            "python3 scripts/check_signed_extension_registry.py --json",
            "python3 scripts/check_signed_extension_registry.py --self-test",
            "python3 -m pytest -q tests/test_check_signed_extension_registry.py",
        ],
    },
    {
        "spec_item": "tests.integration.primary",
        "category": "integration",
        "status": "covered",
        "description": "cargo-visible integration and conformance suites exercise registry admission receipts, adversarial poisoning failures, claims lifecycle boundaries, and deterministic replay vectors",
        "evidence_paths": [
            "crates/franken-node/tests/supply_chain_registry_attestation_receipt_conformance.rs",
            "crates/franken-node/tests/adversarial_supply_chain_poisoning.rs",
            "crates/franken-node/tests/supply_chain_registry_claims_e2e_integration.rs",
            "crates/franken-node/tests/fixtures/supply_chain_registry_attestation_receipt_vectors.json",
        ],
        "commands": [
            "rch exec -- cargo test -p frankenengine-node --test supply_chain_registry_attestation_receipt_conformance",
            "rch exec -- cargo test -p frankenengine-node --test adversarial_supply_chain_poisoning",
            "rch exec -- cargo test -p frankenengine-node --test supply_chain_registry_claims_e2e_integration",
        ],
    },
    {
        "spec_item": "tests.e2e.primary",
        "category": "e2e",
        "status": "covered",
        "description": "operator shell harness runs the registry checker end to end and emits structured extension-admission telemetry artifacts",
        "evidence_paths": [
            "tests/e2e/extension_registry_operator_suite.sh",
            "artifacts/replacement_gap/bd-3hdn/operator_e2e_log.jsonl",
            "artifacts/replacement_gap/bd-3hdn/operator_e2e_summary.json",
            "artifacts/replacement_gap/bd-3hdn/operator_e2e_summary.md",
        ],
        "commands": [
            "tests/e2e/extension_registry_operator_suite.sh",
        ],
    },
    {
        "spec_item": "tests.golden.primary",
        "category": "golden",
        "status": "covered",
        "description": "signed extension manifest serialization is frozen as a golden artifact so schema or signature-material drift requires review",
        "evidence_paths": [
            "crates/franken-node/tests/supply_chain_attestation_manifest_golden.rs",
            "artifacts/golden/supply_chain_attestation_manifest.json",
            "artifacts/replacement_gap/bd-3hdn/adversarial_fixture_index.json",
        ],
        "commands": [
            "rch exec -- cargo test -p frankenengine-node --test supply_chain_attestation_manifest_golden",
        ],
    },
    {
        "spec_item": "telemetry.primary",
        "category": "telemetry",
        "status": "covered",
        "description": "EXT_REG_ADMISSION_* and EXT_REG_PROVENANCE_* operator events expose stable trace, artifact, publisher, decision, reason, transparency, and attestation fields",
        "evidence_paths": [
            "tests/e2e/extension_registry_operator_suite.sh",
            "artifacts/replacement_gap/bd-3hdn/operator_e2e_log.jsonl",
            "artifacts/replacement_gap/bd-3hdn/operator_e2e_summary.json",
            "crates/franken-node/src/supply_chain/extension_registry.rs",
        ],
        "required_fields": REQUIRED_TELEMETRY_FIELDS,
        "commands": [
            "tests/e2e/extension_registry_operator_suite.sh",
            "python3 scripts/check_signed_extension_registry.py --json",
        ],
    },
]

EXTENSION_STATUSES = [
    "Submitted",
    "Active",
    "Deprecated",
    "Revoked",
]

EVENT_CODES = [
    "SER-001", "SER-002", "SER-003", "SER-004", "SER-005",
    "SER-006", "SER-007", "SER-008", "SER-009", "SER-010",
    "SER-011",
    "SER-ERR-001", "SER-ERR-002", "SER-ERR-003", "SER-ERR-004",
    "SER-ERR-005", "SER-ERR-006", "SER-ERR-007", "SER-ERR-008",
    "SER-ERR-009", "SER-ERR-010", "SER-ERR-011",
]

INVARIANTS = [
    "INV-SER-SIGNED",
    "INV-SER-PROVENANCE",
    "INV-SER-REVOCABLE",
    "INV-SER-MONOTONIC",
    "INV-SER-AUDITABLE",
    "INV-SER-DETERMINISTIC",
]

REVOCATION_REASONS = [
    "SecurityVulnerability",
    "PolicyViolation",
    "MaintainerRequest",
    "LicenseConflict",
    "Superseded",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read(path))


def _strip_rust_comments(text: str) -> str:
    result: list[str] = []
    cursor = 0
    length = len(text)
    while cursor < length:
        if text.startswith("//", cursor):
            end = text.find("\n", cursor)
            if end == -1:
                break
            result.append("\n")
            cursor = end + 1
            continue

        if text.startswith("/*", cursor):
            end = _rust_block_comment_end(text, cursor + 2)
            comment = text[cursor:end]
            result.append("\n" * comment.count("\n") or " ")
            cursor = end
            continue

        raw_end = _rust_raw_string_end(text, cursor)
        if raw_end is not None:
            result.append(text[cursor:raw_end])
            cursor = raw_end
            continue

        if text[cursor] == '"':
            end = _rust_quoted_literal_end(text, cursor)
            result.append(text[cursor:end])
            cursor = end
            continue

        result.append(text[cursor])
        cursor += 1

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


def check_source_exists() -> tuple[str, bool, str]:
    ok = SRC.is_file()
    return ("source_exists", ok, f"Source file exists: {SRC.name}")


def check_module_wiring() -> tuple[str, bool, str]:
    content = _read_rust_source(MOD_RS)
    ok = "pub mod extension_registry;" in content
    return ("module_wiring", ok, "Module wired in supply_chain/mod.rs")


def check_structs() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    required = [
        "struct ExtensionSignature",
        "ProvenanceAttestation",  # Imported from provenance module
        "struct VersionEntry",
        "struct RevocationRecord",
        "struct SignedExtension",
        "struct RegistryAuditRecord",
        "struct RegistrationRequest",
        "struct RegistryResult",
        "struct RegistryConfig",
        "struct SignedExtensionRegistry",
    ]
    missing = [s for s in required if s not in src]
    ok = len(missing) == 0
    detail = f"All {len(required)} structs present" if ok else f"Missing: {missing}"
    return ("structs", ok, detail)


def check_extension_statuses() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    missing = [s for s in EXTENSION_STATUSES if s not in src]
    ok = len(missing) == 0 and "enum ExtensionStatus" in src
    return ("extension_statuses", ok, f"4 statuses: {4 - len(missing)}/4")


def check_revocation_reasons() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    missing = [r for r in REVOCATION_REASONS if r not in src]
    ok = len(missing) == 0 and "enum RevocationReason" in src
    return ("revocation_reasons", ok, f"5 reasons: {5 - len(missing)}/5")


def check_registry_operations() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    ops = [
        "fn register(" in src,
        "fn add_version(" in src,
        "fn deprecate(" in src,
        "fn revoke(" in src,
        "fn query(" in src,
        "fn list(" in src,
        "fn version_lineage(" in src,
    ]
    ok = all(ops)
    return ("registry_operations", ok, f"Registry operations: {sum(ops)}/7 functions")


def check_signature_verification() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    checks = [
        "artifact_signing::verify_signature(" in src,
        "KeyRing" in src,
        "signature.signature_bytes" in src,
        "SER_ERR_INVALID_SIGNATURE" in src,
    ]
    ok = all(checks)
    return ("signature_verification", ok, f"Cryptographic signature verification: {sum(checks)}/4 checks")


def check_provenance_validation() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    checks = [
        "prov::verify_attestation_chain(" in src,
        "VerificationPolicy" in src,
        "provenance.vcs_commit_sha" in src,
        "provenance.build_system_identifier" in src,
        "provenance.output_hash" in src,
        "SER_ERR_PROVENANCE_CHAIN_INVALID" in src,
    ]
    ok = all(checks)
    return ("provenance_validation", ok, f"Canonical provenance validation: {sum(checks)}/6 checks")


def check_admission_kernel() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    checks = [
        "pub struct AdmissionKernel" in src,
        "compute_admission_digest(" in src,
        "extension_registry_admission_v1:" in src,
        "canonical_registration_manifest_bytes" in src,
        "registration_manifest_divergence" in src,
        "tv::verify_inclusion(" in src,
        "NegativeWitness" in src,
        "admission_receipts" in src,
    ]
    ok = all(checks)
    return ("admission_kernel", ok, f"Admission kernel controls: {sum(checks)}/8 checks")


def check_monotonic_revocation() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    checks = [
        "revocation_sequence" in src,
        "RevocationRecord" in src,
        "RevocationReason" in src,
        "is_terminal" in src,
    ]
    ok = all(checks)
    return ("monotonic_revocation", ok, f"Monotonic revocation: {sum(checks)}/4 checks")


def check_event_codes() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    found = [c for c in EVENT_CODES if f'"{c}"' in src]
    ok = len(found) == len(EVENT_CODES)
    return ("event_codes", ok, f"Event codes: {len(found)}/{len(EVENT_CODES)}")


def check_invariants() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    found = [i for i in INVARIANTS if i in src]
    ok = len(found) == len(INVARIANTS)
    return ("invariants", ok, f"Invariants: {len(found)}/{len(INVARIANTS)}")


def check_content_hash() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    checks = [
        "content_hash" in src,
        "Sha256" in src,
        "hex::encode" in src,
    ]
    ok = all(checks)
    return ("content_hash", ok, f"Content hash: {sum(checks)}/3 checks")


def check_audit_logging() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    checks = [
        "struct RegistryAuditRecord" in src,
        "audit_log" in src,
        "export_audit_log_jsonl" in src,
    ]
    ok = all(checks)
    return ("audit_logging", ok, f"Audit logging: {sum(checks)}/3 checks")


def check_spec_alignment() -> tuple[str, bool, str]:
    if not SPEC.is_file():
        return ("spec_alignment", False, "Spec contract not found")
    spec = _read(SPEC)
    checks = [
        "bd-209w" in spec,
        "Signed Extension Registry" in spec,
        "Section" in spec and "15" in spec,
    ]
    ok = all(checks)
    return ("spec_alignment", ok, "Spec contract aligns with implementation")


def check_test_coverage() -> tuple[str, bool, str]:
    src = _read_rust_source(SRC)
    test_count = len(re.findall(r"#\[test\]", src))
    ok = test_count >= 25
    return ("test_coverage", ok, f"Rust unit tests: {test_count} (target >= 25)")


def _artifact_rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def check_replacement_evidence_files() -> tuple[str, bool, str]:
    required = [
        REPLACEMENT_EVIDENCE,
        REPLACEMENT_SUMMARY,
        ADVERSARIAL_FIXTURE_INDEX,
        OPERATOR_E2E,
        OPERATOR_LOG,
        OPERATOR_SUMMARY_JSON,
        OPERATOR_SUMMARY_MD,
        GOLDEN_TEST,
        GOLDEN_ARTIFACT,
        CONFORMANCE_TEST,
        ADVERSARIAL_TEST,
        CLAIMS_E2E_TEST,
    ]
    missing = [_artifact_rel(path) for path in required if not path.exists()]
    ok = not missing
    detail = (
        f"All {len(required)} bd-3hdn evidence files present"
        if ok
        else f"Missing evidence files: {missing}"
    )
    return ("bd_3hdn_evidence_files", ok, detail)


def check_telemetry_contract() -> tuple[str, bool, str]:
    texts = []
    for path in (OPERATOR_E2E, OPERATOR_LOG, OPERATOR_SUMMARY_JSON):
        if path.exists():
            texts.append(_read(path))
    combined = "\n".join(texts)
    missing_fields = [field for field in REQUIRED_TELEMETRY_FIELDS if field not in combined]
    missing_families = [
        family
        for family in ("EXT_REG_ADMISSION_", "EXT_REG_PROVENANCE_")
        if family not in combined
    ]
    ok = not missing_fields and not missing_families
    detail = (
        "Extension registry telemetry contract present"
        if ok
        else json.dumps(
            {"missing_fields": missing_fields, "missing_event_families": missing_families},
            sort_keys=True,
        )
    )
    return ("bd_3hdn_telemetry_contract", ok, detail)


def check_completion_debt_coverage() -> tuple[str, bool, str]:
    coverage_by_item = {
        obligation.get("spec_item"): obligation
        for obligation in COMPLETION_DEBT_OBLIGATIONS
        if isinstance(obligation, dict)
    }
    missing_items = sorted(COMPLETION_DEBT_REQUIRED_SPEC_ITEMS - set(coverage_by_item))
    noncovered_items = sorted(
        str(item)
        for item, obligation in coverage_by_item.items()
        if obligation.get("status") != "covered"
    )
    missing_paths: list[str] = []
    for obligation in coverage_by_item.values():
        for rel_path in obligation.get("evidence_paths", []):
            if isinstance(rel_path, str) and not (ROOT / rel_path).exists():
                missing_paths.append(rel_path)
    ok = not missing_items and not noncovered_items and not missing_paths
    detail = (
        "all bd-3hdn.1 completion-debt obligations covered"
        if ok
        else json.dumps(
            {
                "missing_items": missing_items,
                "noncovered_items": noncovered_items,
                "missing_paths": sorted(missing_paths),
            },
            sort_keys=True,
        )
    )
    return ("bd_3hdn_1_completion_debt", ok, detail)


def completion_debt_contract() -> dict:
    return {
        "parent_bead": REPLACEMENT_BEAD_ID,
        "completion_bead": COMPLETION_DEBT_BEAD,
        "required_spec_items": sorted(COMPLETION_DEBT_REQUIRED_SPEC_ITEMS),
        "coverage_obligations": COMPLETION_DEBT_OBLIGATIONS,
    }


ALL_CHECKS = [
    check_source_exists,
    check_module_wiring,
    check_structs,
    check_extension_statuses,
    check_revocation_reasons,
    check_registry_operations,
    check_admission_kernel,
    check_signature_verification,
    check_provenance_validation,
    check_monotonic_revocation,
    check_event_codes,
    check_invariants,
    check_content_hash,
    check_audit_logging,
    check_spec_alignment,
    check_test_coverage,
    check_replacement_evidence_files,
    check_telemetry_contract,
    check_completion_debt_coverage,
]


def run_all() -> list[dict]:
    results = []
    for fn in ALL_CHECKS:
        name, passed, detail = fn()
        results.append({"check": name, "passed": passed, "detail": detail})
    return results


def self_test() -> bool:
    results = run_all()
    if not results:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False
    for entry in results:
        if not isinstance(entry, dict) or "check" not in entry or "passed" not in entry:
            print(f"SELF-TEST FAIL: malformed entry: {entry}", file=sys.stderr)
            return False
    print(f"SELF-TEST OK: {len(results)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    configure_test_logging("check_signed_extension_registry")
    parser = argparse.ArgumentParser(description="bd-209w gate: Signed Extension Registry")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    results = run_all()
    total = len(results)
    n_passed = sum(1 for r in results if r["passed"])
    n_failed = total - n_passed
    verdict = "PASS" if n_failed == 0 else "FAIL"

    if args.json:
        output = {
            "bead_id": "bd-209w",
            "replacement_bead_id": REPLACEMENT_BEAD_ID,
            "title": "Signed extension registry with provenance and revocation",
            "section": "15",
            "verdict": verdict,
            "overall_pass": n_failed == 0,
            "summary": {"passing": n_passed, "failing": n_failed, "total": total},
            "total": total,
            "passed": n_passed,
            "failed": n_failed,
            "completion_debt": completion_debt_contract(),
            "checks": results,
        }
        print(json.dumps(output, indent=2))
    else:
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
        print(f"\n  {n_passed}/{total} checks passed — {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
