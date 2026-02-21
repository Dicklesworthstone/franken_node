#!/usr/bin/env python3
"""Verification script for bd-2pw artifact signing and checksum verification."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_6" / "bd-2pw_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "artifact_signing_verification.md"
RUST_IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "artifact_signing.rs"
MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "mod.rs"
CLI_PATH = ROOT / "crates" / "franken-node" / "src" / "cli.rs"
MAIN_PATH = ROOT / "crates" / "franken-node" / "src" / "main.rs"

EVIDENCE_DIR = ROOT / "artifacts" / "section_10_6" / "bd-2pw"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_INVARIANTS = [
    "INV-ASV-SIG",
    "INV-ASV-MANIFEST",
    "INV-ASV-MSIG",
    "INV-ASV-KEYID",
    "INV-ASV-ROTATE",
    "INV-ASV-THRESH",
    "INV-ASV-TAMPER",
    "INV-ASV-AUDIT",
]

REQUIRED_EVENT_CODES = [
    "ASV-001",
    "ASV-002",
    "ASV-003",
    "ASV-004",
]

REQUIRED_RUST_SYMBOLS = [
    "pub struct ManifestEntry",
    "pub struct ChecksumManifest",
    "pub struct ArtifactVerificationResult",
    "pub struct VerificationReport",
    "pub struct KeyTransitionRecord",
    "pub struct PartialSignature",
    "pub struct KeyRing",
    "pub struct KeyId",
    "pub struct AuditLogEntry",
    "pub enum ArtifactSigningError",
    "pub fn sha256_hex(",
    "pub fn sign_bytes(",
    "pub fn verify_signature(",
    "pub fn build_and_sign_manifest(",
    "pub fn sign_artifact(",
    "pub fn verify_release(",
    "pub fn create_key_transition(",
    "pub fn verify_key_transition(",
    "pub fn collect_threshold_signatures(",
    "pub fn verify_threshold(",
    "pub fn demo_signing_key(",
    "pub fn demo_signing_key_2(",
    "pub fn demo_signing_key_3(",
]

REQUIRED_ERROR_VARIANTS = [
    "ManifestSignatureInvalid",
    "ChecksumMismatch",
    "SignatureInvalid",
    "ArtifactMissing",
    "UnlistedArtifact",
    "KeyNotFound",
    "ThresholdNotMet",
    "TransitionRecordInvalid",
    "IoError",
]

REQUIRED_TESTS = [
    "test_sha256_hex_deterministic",
    "test_sha256_hex_changes_on_different_input",
    "test_sign_and_verify_roundtrip",
    "test_verify_fails_on_tampered_data",
    "test_build_and_sign_manifest",
    "test_manifest_canonical_bytes_deterministic",
    "test_manifest_parse_canonical",
    "test_verify_release_success",
    "test_verify_release_tampered_content",
    "test_verify_release_missing_artifact",
    "test_verify_release_manifest_not_updated",
    "test_key_rotation_roundtrip",
    "test_key_rotation_invalid_transition",
    "test_old_key_verifies_old_artifact_after_rotation",
    "test_new_key_signs_new_artifact_after_rotation",
    "test_threshold_signing_2_of_3",
    "test_threshold_signing_insufficient",
    "test_threshold_rejects_duplicate_signer",
    "test_key_id_derivation_deterministic",
    "test_key_id_different_for_different_keys",
    "test_audit_log_entry",
    "test_error_display",
    "test_verify_release_invalid_detached_sig",
    "test_key_ring_empty",
    "test_sign_artifact_produces_64_bytes",
]

REQUIRED_CLI_PATTERNS = [
    "VerifyReleaseArgs",
    "Release(VerifyReleaseArgs)",
    "release_path",
    "key_dir",
]

REQUIRED_MAIN_PATTERNS = [
    "VerifyCommand::Release(args)",
    "handle_verify_release",
    "ASV_002_VERIFICATION_OK",
    "ASV_003_VERIFICATION_FAILED",
]


def _safe_rel(path: Path) -> str:
    """Return path relative to ROOT, falling back to str(path)."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def check_file_exists(path: Path) -> dict[str, Any]:
    exists = path.is_file()
    return {
        "path": _safe_rel(path),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
    }


def check_content(name: str, path: Path, required: list[str]) -> dict[str, Any]:
    if not path.is_file():
        return {"pass": False, "reason": f"{name} file not found", "found": [], "missing": required}
    content = path.read_text(encoding="utf-8")
    found = [item for item in required if item in content]
    missing = [item for item in required if item not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_mod_registration() -> dict[str, Any]:
    if not MOD_PATH.is_file():
        return {"pass": False, "reason": "mod.rs not found"}
    content = MOD_PATH.read_text(encoding="utf-8")
    has_module = "pub mod artifact_signing;" in content
    return {"pass": has_module, "registered": has_module}


def check_test_count() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return {"pass": False, "reason": "rust impl not found", "count": 0}
    content = RUST_IMPL_PATH.read_text(encoding="utf-8")
    count = len(re.findall(r"#\[test\]", content))
    return {"pass": count >= 20, "count": count}


def check_signing_scheme() -> dict[str, Any]:
    """Verify Ed25519 + SHA-256 scheme is used."""
    if not RUST_IMPL_PATH.is_file():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text(encoding="utf-8")
    has_ed25519 = "ed25519_dalek" in content
    has_sha256 = "Sha256" in content
    has_signer = "Signer" in content
    has_verifier = "Verifier" in content
    return {
        "pass": all([has_ed25519, has_sha256, has_signer, has_verifier]),
        "ed25519": has_ed25519,
        "sha256": has_sha256,
        "signer_trait": has_signer,
        "verifier_trait": has_verifier,
    }


def check_threshold_logic() -> dict[str, Any]:
    """Verify threshold signing logic is implemented."""
    if not RUST_IMPL_PATH.is_file():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text(encoding="utf-8")
    has_partial = "PartialSignature" in content
    has_collect = "collect_threshold_signatures" in content
    has_dedup = "seen_keys" in content or "HashSet" in content
    has_threshold = "ThresholdNotMet" in content
    return {
        "pass": all([has_partial, has_collect, has_dedup, has_threshold]),
        "partial_signatures": has_partial,
        "collect_function": has_collect,
        "deduplication": has_dedup,
        "threshold_error": has_threshold,
    }


def check_key_rotation_logic() -> dict[str, Any]:
    """Verify key rotation via transition records."""
    if not RUST_IMPL_PATH.is_file():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text(encoding="utf-8")
    has_transition = "KeyTransitionRecord" in content
    has_create = "create_key_transition" in content
    has_verify = "verify_key_transition" in content
    has_old_endorses_new = "old_key_id" in content and "new_key_id" in content
    return {
        "pass": all([has_transition, has_create, has_verify, has_old_endorses_new]),
        "transition_record": has_transition,
        "create_fn": has_create,
        "verify_fn": has_verify,
        "endorsement_flow": has_old_endorses_new,
    }


def check_manifest_format() -> dict[str, Any]:
    """Verify canonical manifest format."""
    if not RUST_IMPL_PATH.is_file():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text(encoding="utf-8")
    has_canonical = "canonical_bytes" in content
    has_btree = "BTreeMap" in content  # ordered entries
    has_format = "sha256" in content.lower() and "name" in content and "size_bytes" in content
    return {
        "pass": all([has_canonical, has_btree, has_format]),
        "canonical_serialization": has_canonical,
        "ordered_entries": has_btree,
        "format_fields": has_format,
    }


def run_all_checks() -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()

    checks: dict[str, Any] = {
        "files": {
            "spec": check_file_exists(SPEC_PATH),
            "policy": check_file_exists(POLICY_PATH),
            "rust_impl": check_file_exists(RUST_IMPL_PATH),
            "mod_rs": check_file_exists(MOD_PATH),
            "cli": check_file_exists(CLI_PATH),
            "main": check_file_exists(MAIN_PATH),
        },
        "spec_invariants": check_content("spec", SPEC_PATH, REQUIRED_INVARIANTS),
        "spec_event_codes": check_content("spec", SPEC_PATH, REQUIRED_EVENT_CODES),
        "rust_symbols": check_content("rust", RUST_IMPL_PATH, REQUIRED_RUST_SYMBOLS),
        "error_variants": check_content("rust", RUST_IMPL_PATH, REQUIRED_ERROR_VARIANTS),
        "rust_event_codes": check_content("rust", RUST_IMPL_PATH, REQUIRED_EVENT_CODES),
        "rust_tests": check_content("rust", RUST_IMPL_PATH, REQUIRED_TESTS),
        "cli_patterns": check_content("cli", CLI_PATH, REQUIRED_CLI_PATTERNS),
        "main_patterns": check_content("main", MAIN_PATH, REQUIRED_MAIN_PATTERNS),
        "mod_registration": check_mod_registration(),
        "test_count": check_test_count(),
        "signing_scheme": check_signing_scheme(),
        "threshold_logic": check_threshold_logic(),
        "key_rotation_logic": check_key_rotation_logic(),
        "manifest_format": check_manifest_format(),
    }

    check_results = [
        checks["spec_invariants"],
        checks["spec_event_codes"],
        checks["rust_symbols"],
        checks["error_variants"],
        checks["rust_event_codes"],
        checks["rust_tests"],
        checks["cli_patterns"],
        checks["main_patterns"],
        checks["mod_registration"],
        checks["test_count"],
        checks["signing_scheme"],
        checks["threshold_logic"],
        checks["key_rotation_logic"],
        checks["manifest_format"],
    ]

    all_pass = all(c.get("pass", False) for c in check_results)
    file_pass = all(f["exists"] for f in checks["files"].values())
    passed_count = sum(1 for c in check_results if c.get("pass", False)) + (1 if file_pass else 0)
    total_checks = len(check_results) + 1  # +1 for files

    return {
        "bead_id": "bd-2pw",
        "section": "10.6",
        "title": "Artifact Signing and Checksum Verification for Releases",
        "timestamp": timestamp,
        "overall_pass": all_pass and file_pass,
        "checks": checks,
        "summary": {
            "total_checks": total_checks,
            "passed": passed_count,
            "failed": total_checks - passed_count,
        },
    }


def write_evidence(evidence: dict[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n")


def write_summary(evidence: dict[str, Any]) -> None:
    s = evidence["summary"]
    lines = [
        f"# Verification Summary: {evidence['title']}",
        "",
        f"**Bead:** {evidence['bead_id']} | **Section:** {evidence['section']}",
        f"**Timestamp:** {evidence['timestamp']}",
        f"**Overall:** {'PASS' if evidence['overall_pass'] else 'FAIL'}",
        f"**Checks:** {s['passed']}/{s['total_checks']} passed",
        "",
        "## Check Results",
        "",
    ]
    for name, result in sorted(evidence["checks"].items()):
        if name == "files":
            for fname, finfo in result.items():
                status = "PASS" if finfo["exists"] else "FAIL"
                lines.append(f"- **File {fname}:** {status} ({finfo['path']}, {finfo['size_bytes']} bytes)")
        else:
            status = "PASS" if result.get("pass", False) else "FAIL"
            lines.append(f"- **{name}:** {status}")
            if "missing" in result and result["missing"]:
                for m in result["missing"]:
                    lines.append(f"  - Missing: `{m}`")

    lines.extend(["", "## Artifacts", ""])
    lines.append(f"- Spec: `{_safe_rel(SPEC_PATH)}`")
    lines.append(f"- Policy: `{_safe_rel(POLICY_PATH)}`")
    lines.append(f"- Implementation: `{_safe_rel(RUST_IMPL_PATH)}`")
    lines.append(f"- Evidence: `{_safe_rel(EVIDENCE_PATH)}`")
    lines.append("")
    SUMMARY_PATH.write_text("\n".join(lines) + "\n")


def self_test() -> bool:
    evidence = run_all_checks()
    assert isinstance(evidence, dict)
    assert evidence["bead_id"] == "bd-2pw"
    assert "checks" in evidence
    assert "summary" in evidence
    expected = [
        "files", "spec_invariants", "spec_event_codes", "rust_symbols",
        "error_variants", "rust_event_codes", "rust_tests", "cli_patterns",
        "main_patterns", "mod_registration", "test_count", "signing_scheme",
        "threshold_logic", "key_rotation_logic", "manifest_format",
    ]
    for cat in expected:
        assert cat in evidence["checks"], f"missing check: {cat}"
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify bd-2pw artifact signing implementation")
    parser.add_argument("--json", action="store_true", help="Output JSON evidence")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    evidence = run_all_checks()

    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        s = evidence["summary"]
        status = "PASS" if evidence["overall_pass"] else "FAIL"
        print(f"bd-2pw verification: {status} ({s['passed']}/{s['total_checks']} checks passed)")
        for name, result in sorted(evidence["checks"].items()):
            if name == "files":
                for fname, finfo in result.items():
                    sym = "+" if finfo["exists"] else "-"
                    print(f"  [{sym}] file:{fname} {finfo['path']}")
            else:
                sym = "+" if result.get("pass", False) else "-"
                print(f"  [{sym}] {name}")
                if "missing" in result and result["missing"]:
                    for m in result["missing"]:
                        print(f"       missing: {m}")

    write_evidence(evidence)
    write_summary(evidence)

    sys.exit(0 if evidence["overall_pass"] else 1)


if __name__ == "__main__":
    main()
