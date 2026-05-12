#!/usr/bin/env python3
"""Verification script for bd-2yh trust-card API/CLI surfaces."""

from __future__ import annotations

import argparse
import hashlib
import hmac
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
TRUST_CARD_E2E = ROOT / "crates" / "franken-node" / "tests" / "e2e_trust_card_lifecycle.rs"
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


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _canonical(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    return value


def _canonical_text(value: Any) -> str:
    return json.dumps(_canonical(value), separators=(",", ":"), ensure_ascii=True)


def _values_differ(left: Any, right: Any) -> bool:
    left_text = _canonical_text(left)
    right_text = _canonical_text(right)
    return not hmac.compare_digest(left_text, right_text)


def _compute_card_hash(card: dict[str, Any]) -> str:
    canon = dict(card)
    canon["card_hash"] = ""
    canon["registry_signature"] = ""
    payload = _canonical_text(canon)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _sign_card(card: dict[str, Any], key: bytes) -> dict[str, Any]:
    card = dict(card)
    card["card_hash"] = _compute_card_hash(card)
    card["registry_signature"] = hmac.new(
        key,
        card["card_hash"].encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return card


def _verify_card(card: dict[str, Any], key: bytes) -> bool:
    expected_hash = _compute_card_hash(card)
    if card.get("card_hash") != expected_hash:
        return False
    expected_sig = hmac.new(
        key,
        expected_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    signature = card.get("registry_signature", "")
    return isinstance(signature, str) and hmac.compare_digest(signature, expected_sig)


def _build_base_card(extension_id: str, version: str, trust_version: int, previous_hash: str | None) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "trust_card_version": trust_version,
        "previous_version_hash": previous_hash,
        "extension": {"extension_id": extension_id, "version": version},
        "publisher": {"publisher_id": "pub-acme", "display_name": "Acme Security"},
        "certification_level": "gold" if trust_version == 1 else "bronze",
        "capability_declarations": [
            {"name": "auth.validate-token", "risk": "medium"},
            {"name": "auth.revoke-session", "risk": "high"},
        ],
        "behavioral_profile": {
            "network_access": True,
            "filesystem_access": False,
            "subprocess_access": False,
        },
        "revocation_status": (
            {"status": "active"}
            if trust_version == 1
            else {
                "status": "revoked",
                "reason": "publisher key compromised",
                "revoked_at": "2026-02-20T12:01:00Z",
            }
        ),
        "provenance_summary": {
            "attestation_level": "slsa-l3",
            "source_uri": "https://registry.example/acme/auth-guard",
            "verified_at": "2026-02-20T12:00:00Z",
        },
        "reputation_score_basis_points": 920 if trust_version == 1 else 410,
        "reputation_trend": "improving" if trust_version == 1 else "declining",
        "active_quarantine": trust_version != 1,
        "dependency_trust_summary": [{"dependency_id": "npm:jsonwebtoken@9", "trust_level": "verified"}],
        "last_verified_timestamp": "2026-02-20T12:00:00Z" if trust_version == 1 else "2026-02-20T12:01:00Z",
        "user_facing_risk_assessment": {
            "level": "low" if trust_version == 1 else "critical",
            "summary": "safe" if trust_version == 1 else "do not deploy",
        },
        "audit_history": [
            {
                "timestamp": "2026-02-20T12:00:00Z",
                "event_code": "TRUST_CARD_CREATED",
                "detail": "trust card created",
                "trace_id": "trace-check",
            }
        ],
        "card_hash": "",
        "registry_signature": "",
    }


def simulate_trust_card_flow() -> dict[str, Any]:
    key = b"franken-node-trust-card-registry-key-v1"

    v1 = _sign_card(_build_base_card("npm:@acme/auth-guard", "1.4.2", 1, None), key)
    v1_repeat = _sign_card(_build_base_card("npm:@acme/auth-guard", "1.4.2", 1, None), key)

    v2 = _build_base_card("npm:@acme/auth-guard", "1.4.3", 2, v1["card_hash"])
    v2 = _sign_card(v2, key)

    changed_fields = []
    for field in [
        "certification_level",
        "reputation_score_basis_points",
        "revocation_status",
        "active_quarantine",
        "extension",
    ]:
        if _values_differ(v1[field], v2[field]):
            changed_fields.append(field)

    return {
        "deterministic": hmac.compare_digest(v1["card_hash"], v1_repeat["card_hash"]),
        "v1_verified": _verify_card(v1, key),
        "v2_verified": _verify_card(v2, key),
        "hash_chain_linked": hmac.compare_digest(v2["previous_version_hash"], v1["card_hash"]),
        "changed_fields": changed_fields,
        "v1": v1,
        "v2": v2,
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
        with REPLACEMENT_EVIDENCE.open(encoding="utf-8") as evidence_file:
            data = json.load(evidence_file)
    except json.JSONDecodeError as exc:
        return [_check("completion debt evidence JSON parses", False, str(exc))]

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
            _file_exists(TRUST_CARD_E2E, "trust-card e2e lifecycle"),
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

    simulation = simulate_trust_card_flow()
    checks.append(_check("deterministic card hash", simulation["deterministic"], "same input -> same hash"))
    checks.append(_check("v1 signature verifies", simulation["v1_verified"]))
    checks.append(_check("v2 signature verifies", simulation["v2_verified"]))
    checks.append(_check("hash chain linkage", simulation["hash_chain_linked"], "v2.previous_version_hash == v1.card_hash"))
    checks.append(
        _check(
            "diff identifies trust posture changes",
            len(simulation["changed_fields"]) >= 4,
            f"changed={simulation['changed_fields']}",
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
        "simulation": {
            "changed_fields": simulation["changed_fields"],
            "v1_card_hash": simulation["v1"]["card_hash"],
            "v2_card_hash": simulation["v2"]["card_hash"],
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
