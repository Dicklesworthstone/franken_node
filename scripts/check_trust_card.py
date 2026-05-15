#!/usr/bin/env python3
"""Verification script for bd-2yh trust-card API/CLI surfaces."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


TRUST_CARD_IMPL = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "trust_card.rs"
CERTIFICATION_IMPL = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "certification.rs"
SUPPLY_CHAIN_MOD = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "mod.rs"
API_IMPL = ROOT / "crates" / "franken-node" / "src" / "api" / "trust_card_routes.rs"
API_MOD = ROOT / "crates" / "franken-node" / "src" / "api" / "mod.rs"
CLI_IMPL = ROOT / "crates" / "franken-node" / "src" / "cli.rs"
MAIN_IMPL = ROOT / "crates" / "franken-node" / "src" / "main.rs"
LIB_IMPL = ROOT / "crates" / "franken-node" / "src" / "lib.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_4" / "bd-2yh_contract.md"
TRUST_CARD_INTEGRATION = (
    ROOT / "tests" / "conformance" / "capability_artifact_trust_card_integration_conformance.rs"
)
TRUST_CARD_API_CONFORMANCE = ROOT / "tests" / "conformance" / "trust_card_api_surface_conformance.rs"
TRUST_CARD_E2E = ROOT / "crates" / "franken-node" / "tests" / "e2e_trust_card_lifecycle.rs"
TRUST_CARD_EVIDENCE_DIR = ROOT / "artifacts" / "section_10_4" / "bd-2yh"
TRUST_CARD_EVIDENCE = TRUST_CARD_EVIDENCE_DIR / "verification_evidence.json"
TRUST_CARD_SUMMARY = TRUST_CARD_EVIDENCE_DIR / "verification_summary.md"
TRUST_CARD_REPORT = TRUST_CARD_EVIDENCE_DIR / "trust_card_report.json"
TRUST_CARD_SELF_TEST = TRUST_CARD_EVIDENCE_DIR / "trust_card_self_test.json"
TRUST_CARD_BEAD_ID = "bd-2yh"
REPLACEMENT_EVIDENCE_DIR = ROOT / "artifacts" / "replacement_gap" / "bd-1oju"
REPLACEMENT_EVIDENCE = REPLACEMENT_EVIDENCE_DIR / "verification_evidence.json"
REPLACEMENT_SUMMARY = REPLACEMENT_EVIDENCE_DIR / "verification_summary.md"
REPLACEMENT_BEAD_ID = "bd-1oju"
COMPLETION_DEBT_BEAD = "bd-1oju.1"
COMPLETION_DEBT_ITEMS = [
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
]

REQUIRED_TRUST_CARD_PATTERNS = [
    "pub struct TrustCard",
    "pub struct TrustCardInput",
    "pub struct TrustCardMutation",
    "pub struct TrustCardRegistry",
    "pub fn create(",
    "pub fn update(",
    "pub fn read(",
    "pub fn list(",
    "pub fn list_by_publisher(",
    "pub fn search(",
    "pub fn compare(",
    "pub fn compare_versions(",
    "pub fn read_version(",
    "pub fn verify_card_signature(",
    "pub fn render_trust_card_human(",
    "pub fn render_comparison_human(",
    "TRUST_CARD_CREATED",
    "TRUST_CARD_UPDATED",
    "TRUST_CARD_REVOKED",
    "TRUST_CARD_QUERIED",
    "TRUST_CARD_CACHE_HIT",
    "TRUST_CARD_CACHE_MISS",
    "TRUST_CARD_STALE_REFRESH",
    "TRUST_CARD_DIFF_COMPUTED",
]

REQUIRED_API_PATTERNS = [
    "pub fn create_trust_card(",
    "pub fn update_trust_card(",
    "pub fn get_trust_card(",
    "pub fn list_trust_cards(",
    "pub fn get_trust_cards_by_publisher(",
    "pub fn search_trust_cards(",
    "pub fn compare_trust_cards(",
    "pub fn compare_trust_card_versions(",
    "pub struct Pagination",
    "pub struct ApiResponse",
]

REQUIRED_CLI_PATTERNS = [
    "name = \"trust-card\"",
    "TrustCard(TrustCardCommand)",
    "pub enum TrustCardCommand",
    "Show(TrustCardShowArgs)",
    "Export(TrustCardExportArgs)",
    "List(TrustCardListArgs)",
    "Compare(TrustCardCompareArgs)",
    "Diff(TrustCardDiffArgs)",
    "pub struct TrustCardShowArgs",
    "pub struct TrustCardExportArgs",
    "pub struct TrustCardListArgs",
    "pub struct TrustCardCompareArgs",
    "pub struct TrustCardDiffArgs",
    "pub json: bool",
]

REQUIRED_LIB_PATTERNS = [
    "pub mod api;",
]

REQUIRED_MAIN_PATTERNS = [
    "Command::TrustCard(sub)",
    "fn handle_trust_card_command(",
    "TrustCardCommand::Show",
    "TrustCardCommand::Export",
    "TrustCardCommand::List",
    "TrustCardCommand::Compare",
    "TrustCardCommand::Diff",
    "get_trust_card(",
    "get_trust_cards_by_publisher(",
    "search_trust_cards(",
    "compare_trust_cards(",
    "compare_trust_card_versions(",
    "list_trust_cards(",
]

REQUIRED_TRUST_CARD_EVIDENCE_PATTERNS = [
    "ensure_evidence_refs_present",
    "compute_trust_card_derivation_hash",
    "pub derivation_evidence: Option<DerivationMetadata>",
    "pub evidence_refs: Vec<VerifiedEvidenceRef>",
    "pub evidence_refs: Option<Vec<VerifiedEvidenceRef>>",
    "TrustCardError::EvidenceMissing",
    "TrustCardError::EvidenceRequiredForUpgrade",
    "derivation_evidence: Some(derivation)",
]

REQUIRED_CERTIFICATION_EVIDENCE_PATTERNS = [
    "pub evidence_refs: Vec<VerifiedEvidenceRef>",
    "pub struct VerifiedEvidenceRef",
    "pub struct DerivationMetadata",
    "pub(crate) fn compute_derivation_hash",
    "pub derivation: Option<DerivationMetadata>",
    "evidence_binding_present",
]

REQUIRED_TRUST_CARD_EVIDENCE_TESTS = [
    "create_rejects_empty_evidence",
    "create_includes_derivation_evidence",
    "update_upgrade_without_evidence_rejected",
    "update_upgrade_with_empty_evidence_rejected",
    "update_with_evidence_replaces_derivation",
]

REQUIRED_CERTIFICATION_EVIDENCE_TESTS = [
    "test_no_evidence_returns_uncertified",
    "test_derivation_metadata_present_with_evidence",
    "test_derivation_hash_deterministic",
]

REQUIRED_EVIDENCE_UNIT_TESTS = [
    *REQUIRED_TRUST_CARD_EVIDENCE_TESTS,
    *REQUIRED_CERTIFICATION_EVIDENCE_TESTS,
]

REQUIRED_EVIDENCE_INTEGRATION_MARKERS = [
    "capability_artifact_trust_card_integration_full_conformance_suite",
    "VerifiedEvidenceRef",
    "trust_input.evidence_refs.clear()",
    "TrustCardError::EvidenceMissing",
    "Trust card with missing evidence was incorrectly created",
]

REQUIRED_EVIDENCE_E2E_MARKERS = [
    "e2e_trust_card_lifecycle_create_upgrade_revoke_snapshot",
    "e2e_trust_card_evidence_required_at_creation",
    "VerifiedEvidenceRef",
    "evidence_refs: Some(upgrade_evidence.clone())",
    "TrustCardError::EvidenceRequiredForUpgrade",
    "creating a card with no evidence is rejected",
]

REQUIRED_TRUST_CARD_EVIDENCE_FILES = [
    "crates/franken-node/src/supply_chain/trust_card.rs",
    "crates/franken-node/src/api/trust_card_routes.rs",
    "crates/franken-node/src/cli.rs",
    "crates/franken-node/src/main.rs",
    "docs/specs/section_10_4/bd-2yh_contract.md",
    "scripts/check_trust_card.py",
    "tests/test_check_trust_card.py",
    "artifacts/section_10_4/bd-2yh/trust_card_report.json",
    "artifacts/section_10_4/bd-2yh/trust_card_self_test.json",
]

REQUIRED_TRUST_CARD_EVIDENCE_COMMANDS = [
    "python3 scripts/check_trust_card.py --json",
    "python3 scripts/check_trust_card.py --self-test --json",
    "python3 -m unittest tests/test_check_trust_card.py",
]

COMPLETION_DEBT_REQUIRED_PATHS = {
    "tests.unit.primary": [
        "crates/franken-node/src/supply_chain/trust_card.rs",
        "crates/franken-node/src/supply_chain/certification.rs",
    ],
    "tests.integration.primary": [
        "tests/conformance/capability_artifact_trust_card_integration_conformance.rs",
        "tests/conformance/trust_card_api_surface_conformance.rs",
        "tests/conformance/trust_card_manifest_reference_conformance.rs",
    ],
    "tests.e2e.primary": [
        "crates/franken-node/tests/e2e_trust_card_lifecycle.rs",
        "scripts/check_trust_card.py",
        "tests/test_check_trust_card.py",
    ],
}

COMPLETION_DEBT_REQUIRED_TEST_NAMES = {
    "tests.unit.primary": REQUIRED_EVIDENCE_UNIT_TESTS,
    "tests.integration.primary": [
        "capability_artifact_trust_card_integration_full_conformance_suite",
        "test_valid_trust_card_references",
        "test_get_trust_card_success",
    ],
    "tests.e2e.primary": [
        "e2e_trust_card_lifecycle_create_upgrade_revoke_snapshot",
        "e2e_trust_card_evidence_required_at_creation",
        "test_completion_debt_evidence_passes",
    ],
}


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = _safe_rel(path)
    return _check(
        f"file: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _contains(path: Path, pattern: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: {pattern}", False, "file missing")
    content = path.read_text(encoding="utf-8")
    return _check(
        f"{label}: {pattern}",
        pattern in content,
        "found" if pattern in content else "not found",
    )


def _read(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _read_json_object(path: Path) -> tuple[dict[str, Any] | None, str]:
    try:
        data = json.JSONDecoder().decode(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, f"missing: {_safe_rel(path)}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"

    if not isinstance(data, dict):
        return None, "top-level JSON must be an object"
    return data, "valid JSON object"


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _canonical(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    return value


def _canonical_text(value: Any) -> str:
    return json.dumps(_canonical(value), separators=(",", ":"), ensure_ascii=True)


def _missing_trust_card_evidence(detail: str) -> dict[str, Any]:
    return {
        "valid_evidence": False,
        "detail": detail,
        "bead_id_ok": False,
        "status_ok": False,
        "status_detail": detail,
        "commands_ok": False,
        "commands_detail": detail,
        "required_files_cited": False,
        "files_detail": detail,
        "deterministic_card_hash_source": False,
        "signature_verification_source": False,
        "hash_chain_source": False,
        "diff_source": False,
        "e2e_lifecycle_source": False,
    }


def analyze_trust_card_evidence(evidence_path: Path = TRUST_CARD_EVIDENCE) -> dict[str, Any]:
    evidence, detail = _read_json_object(evidence_path)
    if evidence is None:
        return _missing_trust_card_evidence(detail)

    src = _read(TRUST_CARD_IMPL)
    e2e = _read(TRUST_CARD_E2E)
    api_conformance = _read(TRUST_CARD_API_CONFORMANCE)
    artifact_text = _canonical_text(evidence)

    verification = evidence.get("verification", {})
    command_results = {
        item.get("command"): item.get("result")
        for item in verification.get("commands", [])
        if isinstance(item, dict)
    }
    missing_commands = [
        command
        for command in REQUIRED_TRUST_CARD_EVIDENCE_COMMANDS
        if command_results.get(command) != "pass"
    ]

    cited_files = set(evidence.get("implementation", {}).get("files", []))
    missing_files = [
        path
        for path in REQUIRED_TRUST_CARD_EVIDENCE_FILES
        if path not in cited_files or not (ROOT / path).exists()
    ]
    status = str(evidence.get("status", ""))

    deterministic_markers = [
        "pub fn compute_card_hash(" in src,
        "canonical_card_without_hash_and_signature(card)" in src,
        "hasher.update(b\"trust_card_hash_v1:\")" in src,
        "card_hash field must match compute_card_hash output" in e2e,
        "INV-TC-DETERMINISTIC" in api_conformance,
        "deterministic hash" in artifact_text,
    ]
    signature_markers = [
        "pub fn verify_card_signature(" in src,
        "mac.update(b\"trust_card_registry_sig_v1:\")" in src,
        "constant_time::ct_eq(&card.registry_signature" in src,
        "signature_verification_rejects_tampered_card" in src,
        "verify_card_signature(&v1, REGISTRY_KEY).expect(\"v1 signature verifies\")" in e2e,
        "verify_card_signature(&v2, REGISTRY_KEY).expect(\"v2 signature verifies\")" in e2e,
        "verify_card_signature(&v3, REGISTRY_KEY).expect(\"v3 signature verifies\")" in e2e,
        "cryptographically signed" in artifact_text,
    ]
    hash_chain_markers = [
        "next.previous_version_hash = Some(latest.card_hash.clone())" in src,
        "validate_snapshot_history(" in src,
        "broke previous_version_hash linkage" in src,
        "Some(v1.card_hash.as_str())" in e2e,
        "hash-linked" in artifact_text,
    ]
    diff_markers = [
        "pub fn compare(" in src,
        "pub fn compare_versions(" in src,
        "field: \"certification_level\".to_string()" in src,
        "field: \"reputation_score_basis_points\".to_string()" in src,
        "field: \"revocation_status\".to_string()" in src,
        "field: \"active_quarantine\".to_string()" in src,
        "fn compare_shows_changes()" in src,
        "fn compare_versions_for_same_extension()" in src,
    ]
    e2e_markers = [
        "e2e_trust_card_lifecycle_create_upgrade_revoke_snapshot" in e2e,
        "assert_eq!(v1.trust_card_version, 1)" in e2e,
        "assert_eq!(v2.trust_card_version, 2)" in e2e,
        "v3_revoked" in e2e,
        "snapshot_roundtrip_preserves_revocation" in e2e,
    ]

    return {
        "valid_evidence": True,
        "detail": detail,
        "bead_id_ok": evidence.get("bead_id") == TRUST_CARD_BEAD_ID,
        "status_ok": status in {"PASS", "completed_with_known_repo_gate_failures"},
        "status_detail": status,
        "commands_ok": not missing_commands,
        "commands_detail": (
            "all required commands passed"
            if not missing_commands
            else "missing passing commands: " + ", ".join(missing_commands)
        ),
        "required_files_cited": not missing_files,
        "files_detail": (
            "all required files cited and present"
            if not missing_files
            else "missing files: " + ", ".join(missing_files)
        ),
        "deterministic_card_hash_source": all(deterministic_markers),
        "signature_verification_source": all(signature_markers),
        "hash_chain_source": all(hash_chain_markers),
        "diff_source": all(diff_markers),
        "e2e_lifecycle_source": all(e2e_markers),
    }


def check_completion_debt_evidence() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if not REPLACEMENT_EVIDENCE.is_file():
        return [
            _check(
                "completion debt evidence exists",
                False,
                f"missing: {_safe_rel(REPLACEMENT_EVIDENCE)}",
            )
        ]

    try:
        data, detail = _read_json_object(REPLACEMENT_EVIDENCE)
    except OSError as exc:
        return [_check("completion debt evidence JSON parses", False, str(exc))]
    if data is None:
        return [_check("completion debt evidence JSON parses", False, detail)]

    checks.append(
        _check(
            "completion debt evidence: replacement bead id",
            data.get("bead_id") == REPLACEMENT_BEAD_ID,
            str(data.get("bead_id")),
        )
    )
    checks.append(
        _check(
            "completion debt evidence: debt bead id",
            data.get("completion_debt_bead_id") == COMPLETION_DEBT_BEAD,
            str(data.get("completion_debt_bead_id")),
        )
    )
    checks.append(
        _check(
            "completion debt evidence: pass verdict",
            data.get("verdict") == "PASS",
            str(data.get("verdict")),
        )
    )

    completion_debt = data.get("completion_debt", {})
    covered = set(completion_debt.get("covered_spec_items", []))
    checks.append(
        _check(
            "completion debt evidence: all audit items covered",
            set(COMPLETION_DEBT_ITEMS).issubset(covered),
            ", ".join(sorted(covered)) if covered else "none",
        )
    )

    obligations = {
        obligation.get("spec_item"): obligation
        for obligation in completion_debt.get("obligations", [])
    }
    for spec_item in COMPLETION_DEBT_ITEMS:
        obligation = obligations.get(spec_item)
        checks.append(
            _check(
                f"completion debt evidence: {spec_item} obligation",
                obligation is not None,
                "present" if obligation else "missing",
            )
        )
        if not obligation:
            continue

        evidence_paths = set(obligation.get("evidence_paths", []))
        required_paths = set(COMPLETION_DEBT_REQUIRED_PATHS[spec_item])
        checks.append(
            _check(
                f"completion debt evidence: {spec_item} paths cited",
                required_paths.issubset(evidence_paths),
                ", ".join(sorted(evidence_paths)) if evidence_paths else "none",
            )
        )

        missing_paths = [
            path for path in evidence_paths if not (ROOT / path).exists()
        ]
        checks.append(
            _check(
                f"completion debt evidence: {spec_item} paths exist",
                not missing_paths,
                ", ".join(missing_paths) if missing_paths else "all paths exist",
            )
        )

        test_names = set(obligation.get("test_names", []))
        required_tests = set(COMPLETION_DEBT_REQUIRED_TEST_NAMES[spec_item])
        checks.append(
            _check(
                f"completion debt evidence: {spec_item} tests cited",
                required_tests.issubset(test_names),
                ", ".join(sorted(test_names)) if test_names else "none",
            )
        )

    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    checks.extend(
        [
            _file_exists(TRUST_CARD_IMPL, "trust card implementation"),
            _file_exists(SUPPLY_CHAIN_MOD, "supply chain module"),
            _file_exists(CERTIFICATION_IMPL, "certification implementation"),
            _file_exists(API_IMPL, "trust card api routes"),
            _file_exists(API_MOD, "api module"),
            _file_exists(CLI_IMPL, "cli surface"),
            _file_exists(MAIN_IMPL, "main command wiring"),
            _file_exists(SPEC, "bd-2yh contract"),
            _file_exists(TRUST_CARD_INTEGRATION, "trust-card integration conformance"),
            _file_exists(TRUST_CARD_API_CONFORMANCE, "trust-card api conformance"),
            _file_exists(TRUST_CARD_E2E, "trust-card e2e lifecycle"),
            _file_exists(TRUST_CARD_EVIDENCE, "bd-2yh verification evidence"),
            _file_exists(TRUST_CARD_SUMMARY, "bd-2yh verification summary"),
            _file_exists(TRUST_CARD_REPORT, "bd-2yh trust-card report"),
            _file_exists(TRUST_CARD_SELF_TEST, "bd-2yh trust-card self-test"),
            _file_exists(REPLACEMENT_EVIDENCE, "bd-1oju completion-debt evidence"),
            _file_exists(REPLACEMENT_SUMMARY, "bd-1oju completion-debt summary"),
        ]
    )

    checks.extend(_contains(TRUST_CARD_IMPL, p, "trust_card.rs") for p in REQUIRED_TRUST_CARD_PATTERNS)
    checks.extend(
        _contains(TRUST_CARD_IMPL, p, "trust_card.rs evidence binding")
        for p in REQUIRED_TRUST_CARD_EVIDENCE_PATTERNS
    )
    checks.extend(
        _contains(CERTIFICATION_IMPL, p, "certification.rs evidence binding")
        for p in REQUIRED_CERTIFICATION_EVIDENCE_PATTERNS
    )
    checks.extend(
        _contains(TRUST_CARD_IMPL, p, "trust_card.rs evidence tests")
        for p in REQUIRED_TRUST_CARD_EVIDENCE_TESTS
    )
    checks.extend(
        _contains(CERTIFICATION_IMPL, p, "certification.rs evidence tests")
        for p in REQUIRED_CERTIFICATION_EVIDENCE_TESTS
    )
    checks.extend(
        _contains(TRUST_CARD_INTEGRATION, p, "trust-card integration evidence binding")
        for p in REQUIRED_EVIDENCE_INTEGRATION_MARKERS
    )
    checks.extend(
        _contains(TRUST_CARD_E2E, p, "trust-card e2e evidence binding")
        for p in REQUIRED_EVIDENCE_E2E_MARKERS
    )
    checks.extend(_contains(API_IMPL, p, "trust_card_routes.rs") for p in REQUIRED_API_PATTERNS)
    checks.extend(_contains(CLI_IMPL, p, "cli.rs") for p in REQUIRED_CLI_PATTERNS)
    checks.extend(_contains(MAIN_IMPL, p, "main.rs") for p in REQUIRED_MAIN_PATTERNS)
    checks.extend(_contains(LIB_IMPL, p, "lib.rs") for p in REQUIRED_LIB_PATTERNS)

    if SUPPLY_CHAIN_MOD.is_file():
        content = SUPPLY_CHAIN_MOD.read_text(encoding="utf-8")
        checks.append(_check("mod export: trust_card", "pub mod trust_card;" in content))
    else:
        checks.append(_check("mod export: trust_card", False, "mod file missing"))

    if API_MOD.is_file():
        content = API_MOD.read_text(encoding="utf-8")
        checks.append(_check("mod export: trust_card_routes", "pub mod trust_card_routes;" in content))
    else:
        checks.append(_check("mod export: trust_card_routes", False, "mod file missing"))

    evidence = analyze_trust_card_evidence()
    checks.append(
        _check("trust-card evidence artifact loads", evidence["valid_evidence"], evidence["detail"])
    )
    checks.append(_check("trust-card evidence bead id", evidence["bead_id_ok"], TRUST_CARD_BEAD_ID))
    checks.append(
        _check(
            "trust-card evidence status recognized",
            evidence["status_ok"],
            evidence["status_detail"],
        )
    )
    checks.append(
        _check(
            "trust-card evidence commands pass",
            evidence["commands_ok"],
            evidence["commands_detail"],
        )
    )
    checks.append(
        _check(
            "trust-card evidence files cited",
            evidence["required_files_cited"],
            evidence["files_detail"],
        )
    )
    checks.append(
        _check(
            "deterministic card hash",
            evidence["deterministic_card_hash_source"],
            "Rust compute_card_hash + e2e/API conformance markers",
        )
    )
    checks.append(
        _check(
            "signature verification",
            evidence["signature_verification_source"],
            "Rust verify_card_signature + lifecycle markers",
        )
    )
    checks.append(
        _check(
            "hash chain linkage",
            evidence["hash_chain_source"],
            "Rust previous_version_hash + snapshot validation markers",
        )
    )
    checks.append(
        _check(
            "diff identifies trust posture changes",
            evidence["diff_source"],
            "Rust compare/compare_versions field diff markers",
        )
    )
    checks.append(
        _check(
            "e2e lifecycle evidence covers signed versions",
            evidence["e2e_lifecycle_source"],
            "create, upgrade, revoke, snapshot round-trip markers",
        )
    )

    if TRUST_CARD_IMPL.is_file():
        src = TRUST_CARD_IMPL.read_text(encoding="utf-8")
        test_count = len(re.findall(r"#\[test\]", src))
        checks.append(_check("unit test count in trust_card.rs", test_count >= 9, f"{test_count} tests"))
    else:
        checks.append(_check("unit test count in trust_card.rs", False, "impl file missing"))

    checks.extend(check_completion_debt_evidence())

    total = len(checks)
    passing = sum(1 for check in checks if check["pass"])
    failing = total - passing

    return {
        "bead_id": "bd-2yh",
        "title": "Trust-card API and CLI surfaces",
        "section": "10.4",
        "verdict": "PASS" if failing == 0 else "FAIL",
        "overall_pass": failing == 0,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": total,
        },
        "checks": checks,
        "evidence_analysis": {
            "commands": evidence["commands_detail"],
            "files": evidence["files_detail"],
        },
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    report = run_checks()
    checks = report["checks"]
    ok = all(check["pass"] for check in checks)
    return ok, checks


def main() -> None:
    configure_test_logging("check_trust_card")
    parser = argparse.ArgumentParser(description="Verify bd-2yh trust-card implementation")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok, checks = self_test()
        if args.json:
            print(
                json.dumps(
                    {
                        "ok": ok,
                        "checks": checks,
                    },
                    indent=2,
                )
            )
        else:
            passing = sum(1 for check in checks if check["pass"])
            print(f"self_test: {passing}/{len(checks)} checks pass")
            if not ok:
                for check in checks:
                    if not check["pass"]:
                        print(f"FAIL: {check['check']} :: {check['detail']}")
        sys.exit(0 if ok else 1)

    report = run_checks()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for check in report["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
        print(
            f"\n{report['summary']['passing']}/{report['summary']['total']} checks pass "
            f"(verdict={report['verdict']})"
        )

    sys.exit(0 if report["overall_pass"] else 1)


if __name__ == "__main__":
    main()
