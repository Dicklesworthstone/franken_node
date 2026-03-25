#!/usr/bin/env python3
"""
Duplicate-implementation and semantic-boundary anti-drift CI gate for franken_node.

Reads the canonical capability ownership registry, verifies that the semantic
boundary contract stays aligned with the implementation-level checker, and
scans Rust source files for:

- prohibited duplicate implementations of canonically owned capabilities,
- undocumented semantic-family expansion outside the sanctioned path set, and
- forbidden cross-kernel imports into `*_internal` / `::internal::` modules.

Usage:
    python3 scripts/check_ownership_violations.py [--json] [--waiver FILE]

Exit codes:
    0 = PASS (no violations)
    1 = FAIL (violations detected)
    2 = ERROR (registry missing, parse error, or policy contract missing)
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging

REGISTRY_PATH = ROOT / "docs" / "capability_ownership_registry.json"
CONTRACT_PATH = ROOT / "docs" / "architecture" / "tri_kernel_ownership_contract.md"
CONTRACT_REL_PATH = "docs/architecture/tri_kernel_ownership_contract.md"
POLICY_MATRIX_HEADING = "## Semantic Twin Inventory And Classification Matrix"
RULE_CATALOG_HEADING = "### Anti-Drift Rule Catalog"

RULE_CATALOG = [
    {
        "rule_id": "OWN-SEMB-001",
        "reason_code": "SEMANTIC_BOUNDARY_CONTRACT_DRIFT",
        "summary": "semantic-boundary contract and checker drifted out of alignment",
    },
    {
        "rule_id": "OWN-SEMB-002",
        "reason_code": "UNDOCUMENTED_SEMANTIC_FAMILY",
        "summary": "a protected semantic-family filename appeared outside the sanctioned path set",
    },
    {
        "rule_id": "OWN-SEMB-003",
        "reason_code": "FORBIDDEN_INTERNAL_BOUNDARY_CROSSING",
        "summary": "franken_node imported another kernel's internal module directly",
    },
]

SEMANTIC_BOUNDARY_FAMILIES = [
    {
        "family_id": "region-lifecycle",
        "policy_outcome": "Keep local model",
        "protected_filenames": ["region_ownership.rs", "region_tree.rs"],
        "allowed_paths": [
            "crates/franken-node/src/connector/region_ownership.rs",
            "crates/franken-node/src/runtime/region_tree.rs",
        ],
    },
    {
        "family_id": "supervision",
        "policy_outcome": "Keep local model",
        "protected_filenames": ["supervision.rs"],
        "allowed_paths": [
            "crates/franken-node/src/connector/supervision.rs",
        ],
    },
    {
        "family_id": "perf-budget-guards",
        "policy_outcome": "Keep local model",
        "protected_filenames": ["perf_budget_guard.rs"],
        "allowed_paths": [
            "crates/franken-node/src/connector/perf_budget_guard.rs",
            "crates/franken-node/src/policy/perf_budget_guard.rs",
        ],
    },
    {
        "family_id": "cancellation-protocol",
        "policy_outcome": "Wrap canonical ownership",
        "protected_filenames": ["cancellation_protocol.rs"],
        "allowed_paths": [
            "crates/franken-node/src/connector/cancellation_protocol.rs",
            "crates/franken-node/src/control_plane/cancellation_protocol.rs",
        ],
    },
    {
        "family_id": "obligation-lifecycle",
        "policy_outcome": "Wrap canonical ownership",
        "protected_filenames": ["obligation_tracker.rs", "obligation_channel.rs"],
        "allowed_paths": [
            "crates/franken-node/src/connector/obligation_tracker.rs",
            "crates/franken-node/src/runtime/obligation_channel.rs",
        ],
    },
    {
        "family_id": "epoch-boundaries",
        "policy_outcome": "Wrap canonical ownership",
        "protected_filenames": [
            "control_epoch.rs",
            "epoch_transition_barrier.rs",
            "epoch_transition.rs",
            "epoch_guard.rs",
        ],
        "allowed_paths": [
            "crates/franken-node/src/control_plane/control_epoch.rs",
            "crates/franken-node/src/control_plane/epoch_transition_barrier.rs",
            "crates/franken-node/src/runtime/epoch_transition.rs",
            "crates/franken-node/src/runtime/epoch_guard.rs",
        ],
    },
    {
        "family_id": "evidence-publication",
        "policy_outcome": "Keep local model",
        "protected_filenames": ["evidence_ledger.rs", "evidence_emission.rs"],
        "allowed_paths": [
            "crates/franken-node/src/observability/evidence_ledger.rs",
            "crates/franken-node/src/policy/evidence_emission.rs",
        ],
    },
    {
        "family_id": "remote-computation-registry",
        "policy_outcome": "Wrap canonical ownership",
        "protected_filenames": ["computation_registry.rs"],
        "allowed_paths": [
            "crates/franken-node/src/remote/computation_registry.rs",
        ],
    },
    {
        "family_id": "lane-semantics",
        "policy_outcome": "Wrap canonical ownership",
        "protected_filenames": [
            "control_lane_mapping.rs",
            "control_lane_policy.rs",
            "lane_scheduler.rs",
            "lane_router.rs",
        ],
        "allowed_paths": [
            "crates/franken-node/src/control_plane/control_lane_mapping.rs",
            "crates/franken-node/src/control_plane/control_lane_policy.rs",
            "crates/franken-node/src/runtime/lane_scheduler.rs",
            "crates/franken-node/src/runtime/lane_router.rs",
        ],
    },
    {
        "family_id": "service-boundary-skeleton",
        "policy_outcome": "Defer until trigger",
        "protected_filenames": ["service.rs"],
        "allowed_paths": [
            "crates/franken-node/src/api/service.rs",
        ],
    },
]

FORBIDDEN_INTERNAL_IMPORT_PATTERNS = [
    re.compile(r"^\s*use\s+franken_engine::[A-Za-z0-9_:]*_internal(?:::|;)", re.MULTILINE),
    re.compile(r"^\s*use\s+franken_engine::[A-Za-z0-9_:]*::internal(?:::|;)", re.MULTILINE),
    re.compile(r"^\s*use\s+asupersync::[A-Za-z0-9_:]*_internal(?:::|;)", re.MULTILINE),
    re.compile(r"^\s*use\s+asupersync::[A-Za-z0-9_:]*::internal(?:::|;)", re.MULTILINE),
]

# Track-to-directory mapping: which directories belong to which section.
# As the codebase grows, this mapping will expand.
# For now, map known ownership domains to file path patterns.
TRACK_PATH_PATTERNS = {
    "10.13": [
        "crates/*/src/fcp_*",
        "crates/*/src/revocation*",
        "crates/*/src/control_channel*",
        "crates/*/src/error_taxonomy*",
        "crates/*/src/auth_channel*",
    ],
    "10.14": [
        "crates/*/src/evidence_*",
        "crates/*/src/epoch_*",
        "crates/*/src/remote_registry*",
        "crates/*/src/idempotency*",
        "crates/*/src/saga_*",
        "crates/*/src/fault_harness*",
        "crates/*/src/dpor*",
        "crates/*/src/marker_stream*",
    ],
    "10.15": [
        "crates/*/src/asupersync_*",
        "crates/*/src/control_plane*",
    ],
    "10.17": [
        "crates/*/src/verifier_*",
        "crates/*/src/replay_capsule*",
        "crates/*/src/claim_compiler*",
        "crates/*/src/trust_scoreboard*",
        "crates/*/src/oracle_l2*",
    ],
    "10.18": [
        "crates/*/src/vef_*",
        "crates/*/src/policy_constraint_compiler*",
        "crates/*/src/receipt_commitment*",
        "crates/*/src/proof_gen*",
    ],
    "10.19": [
        "crates/*/src/atc_*",
        "crates/*/src/federated_signal*",
        "crates/*/src/global_prior*",
    ],
    "10.20": [
        "crates/*/src/dgis_*",
        "crates/*/src/topo_risk*",
        "crates/*/src/contagion_sim*",
    ],
    "10.21": [
        "crates/*/src/bpet_*",
        "crates/*/src/phenotype_*",
        "crates/*/src/drift_detect*",
        "crates/*/src/hazard_score*",
    ],
    "10.2": [
        "crates/*/src/compat_*",
        "crates/*/src/divergence_*",
        "crates/*/src/oracle_l1*",
        "crates/*/src/fixture_oracle*",
    ],
}

# Semantic keyword patterns that indicate implementation (not just integration/reference)
IMPLEMENTATION_INDICATORS = [
    r"^pub\s+(struct|enum|trait|fn|impl)\s+",
    r"^pub\s+async\s+fn\s+",
    r"^pub\s+mod\s+",
    r"^impl\s+",
]


def _relative_to_root(filepath: Path, project_root: Path = ROOT) -> str:
    """Return a stable project-relative path when possible."""
    try:
        return str(filepath.resolve().relative_to(project_root.resolve()))
    except ValueError:
        if filepath.is_absolute():
            return str(filepath)
        return str(filepath)


def load_registry() -> dict[str, Any]:
    """Load and validate the capability ownership registry."""
    if not REGISTRY_PATH.exists():
        print(f"ERROR: Registry not found: {REGISTRY_PATH}", file=sys.stderr)
        sys.exit(2)
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def load_policy_contract_text(contract_path: Path = CONTRACT_PATH) -> str:
    """Load the tri-kernel ownership contract text."""
    if not contract_path.exists():
        print(f"ERROR: Policy contract not found: {contract_path}", file=sys.stderr)
        sys.exit(2)
    return contract_path.read_text()


def load_waivers(waiver_path: str | None) -> list[dict[str, Any]]:
    """Load waiver file if provided."""
    if not waiver_path:
        return []
    path = Path(waiver_path)
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    return data.get("waivers", [])


def _make_violation(
    *,
    rule_id: str,
    reason_code: str,
    file: str,
    detail: str,
    remediation: str,
    severity: str = "error",
    **extra: Any,
) -> dict[str, Any]:
    violation = {
        "rule_id": rule_id,
        "reason_code": reason_code,
        "file": file,
        "severity": severity,
        "detail": detail,
        "remediation": remediation,
    }
    violation.update(extra)
    return violation


def check_contract_alignment(contract_text: str) -> list[dict[str, Any]]:
    """Ensure the semantic-boundary contract stays aligned with the checker."""
    violations = []

    if POLICY_MATRIX_HEADING not in contract_text:
        violations.append(
            _make_violation(
                rule_id="OWN-SEMB-001",
                reason_code="SEMANTIC_BOUNDARY_CONTRACT_DRIFT",
                file=CONTRACT_REL_PATH,
                detail=f"missing contract heading: {POLICY_MATRIX_HEADING}",
                remediation=(
                    "Restore the semantic-twin matrix heading in the tri-kernel "
                    "ownership contract."
                ),
            )
        )

    if RULE_CATALOG_HEADING not in contract_text:
        violations.append(
            _make_violation(
                rule_id="OWN-SEMB-001",
                reason_code="SEMANTIC_BOUNDARY_CONTRACT_DRIFT",
                file=CONTRACT_REL_PATH,
                detail=f"missing contract heading: {RULE_CATALOG_HEADING}",
                remediation=(
                    "Restore the anti-drift rule catalog heading in the tri-kernel "
                    "ownership contract."
                ),
            )
        )

    for rule in RULE_CATALOG:
        if rule["rule_id"] not in contract_text or rule["reason_code"] not in contract_text:
            violations.append(
                _make_violation(
                    rule_id="OWN-SEMB-001",
                    reason_code="SEMANTIC_BOUNDARY_CONTRACT_DRIFT",
                    file=CONTRACT_REL_PATH,
                    detail=(
                        "contract missing anti-drift rule catalog entry "
                        f"{rule['rule_id']} / {rule['reason_code']}"
                    ),
                    remediation=(
                        "Add the missing anti-drift rule catalog entry to the "
                        "tri-kernel ownership contract."
                    ),
                )
            )

    for family in SEMANTIC_BOUNDARY_FAMILIES:
        for allowed_path in family["allowed_paths"]:
            if allowed_path not in contract_text:
                violations.append(
                    _make_violation(
                        rule_id="OWN-SEMB-001",
                        reason_code="SEMANTIC_BOUNDARY_CONTRACT_DRIFT",
                        file=CONTRACT_REL_PATH,
                        detail=(
                            "contract missing sanctioned semantic-boundary path "
                            f"{allowed_path} for family {family['family_id']}"
                        ),
                        remediation=(
                            "Document the sanctioned path in the semantic-twin matrix "
                            "before extending the checker family."
                        ),
                        family_id=family["family_id"],
                        sanctioned_path=allowed_path,
                    )
                )

    return violations


def check_file_ownership(filepath: Path, registry: dict[str, Any]) -> list[dict[str, Any]]:
    """Check a single file for cross-track ownership violations."""
    violations = []
    relpath = _relative_to_root(filepath)

    # Determine which track this file belongs to based on path patterns.
    file_track = None
    for track, patterns in TRACK_PATH_PATTERNS.items():
        for pattern in patterns:
            pattern_re = pattern.replace("*", "[^/]+")
            if re.match(pattern_re, relpath):
                file_track = track
                break
        if file_track:
            break

    if not file_track:
        return []

    # Check if this file implements capabilities owned by another track.
    for cap in registry.get("capabilities", []):
        cap_owner = cap["canonical_owner"]
        owners = cap_owner.split("+")

        if file_track in owners:
            continue
        if file_track in cap.get("integration_tracks", []):
            continue

        domain = cap["domain"].lower()
        domain_keywords = [
            word
            for word in re.split(r"[,/+\s]+", domain)
            if len(word) > 3 and word not in ("and", "the", "with", "for")
        ]

        file_stem = filepath.stem.lower()
        matching_keywords = [kw for kw in domain_keywords if kw in file_stem]

        if matching_keywords:
            violations.append(
                {
                    "rule_id": f"OWNERSHIP-{cap['id']}",
                    "reason_code": "CROSS_TRACK_CAPABILITY_REDEFINITION",
                    "file": relpath,
                    "file_track": file_track,
                    "capability": cap["id"],
                    "capability_domain": cap["domain"],
                    "canonical_owner": cap_owner,
                    "matching_keywords": matching_keywords,
                    "severity": "error",
                    "detail": (
                        f"{relpath} appears to implement capability {cap['id']} "
                        f"from canonical track {cap_owner}"
                    ),
                    "remediation": (
                        f"Move implementation to the canonical track {cap_owner} or "
                        "refactor this file into an integration/adoption role."
                    ),
                }
            )

    return violations


def check_semantic_boundary_drift(
    filepath: Path,
    project_root: Path = ROOT,
) -> list[dict[str, Any]]:
    """Check whether a protected semantic family expanded beyond sanctioned paths."""
    violations = []
    relpath = _relative_to_root(filepath, project_root)
    filename = filepath.name

    for family in SEMANTIC_BOUNDARY_FAMILIES:
        if filename not in family["protected_filenames"]:
            continue
        if relpath in family["allowed_paths"]:
            continue
        violations.append(
            _make_violation(
                rule_id="OWN-SEMB-002",
                reason_code="UNDOCUMENTED_SEMANTIC_FAMILY",
                file=relpath,
                detail=(
                    f"{filename} belongs to protected semantic family "
                    f"{family['family_id']} but {relpath} is not in the sanctioned path set"
                ),
                remediation=(
                    "Reuse an existing sanctioned surface or update the semantic-twin "
                    "matrix and anti-drift checker in the same change."
                ),
                family_id=family["family_id"],
                policy_outcome=family["policy_outcome"],
                documented_paths=family["allowed_paths"],
            )
        )

    return violations


def check_forbidden_internal_imports(
    filepath: Path,
    project_root: Path = ROOT,
) -> list[dict[str, Any]]:
    """Reject direct imports into another kernel's internal modules."""
    text = filepath.read_text(errors="ignore")
    relpath = _relative_to_root(filepath, project_root)
    violations = []

    for pattern in FORBIDDEN_INTERNAL_IMPORT_PATTERNS:
        for match in pattern.finditer(text):
            snippet = match.group(0).strip()
            violations.append(
                _make_violation(
                    rule_id="OWN-SEMB-003",
                    reason_code="FORBIDDEN_INTERNAL_BOUNDARY_CROSSING",
                    file=relpath,
                    detail=f"forbidden internal import detected: {snippet}",
                    remediation=(
                        "Import the public adapter/facade surface instead of reaching "
                        "into another kernel's internal modules."
                    ),
                    import_snippet=snippet,
                )
            )

    return violations


def _waive(violations: list[dict[str, Any]], waiver_rules: set[tuple[str, str]]) -> list[dict[str, Any]]:
    for violation in violations:
        violation["waived"] = (violation["file"], violation["rule_id"]) in waiver_rules
    return violations


def main() -> None:
    logger = configure_test_logging("check_ownership_violations")
    json_output = "--json" in sys.argv
    waiver_path = None
    for i, arg in enumerate(sys.argv):
        if arg == "--waiver" and i + 1 < len(sys.argv):
            waiver_path = sys.argv[i + 1]

    registry = load_registry()
    contract_text = load_policy_contract_text()
    waivers = load_waivers(waiver_path)
    waiver_rules = {(w["file"], w["rule_id"]) for w in waivers}

    crates_dir = ROOT / "crates"
    rust_files = sorted(crates_dir.rglob("*/src/**/*.rs")) if crates_dir.exists() else []

    contract_violations = _waive(check_contract_alignment(contract_text), waiver_rules)
    registry_violations: list[dict[str, Any]] = []
    semantic_violations: list[dict[str, Any]] = []
    boundary_violations: list[dict[str, Any]] = []

    for rs_file in rust_files:
        registry_violations.extend(
            _waive(check_file_ownership(rs_file, registry), waiver_rules)
        )
        semantic_violations.extend(
            _waive(check_semantic_boundary_drift(rs_file), waiver_rules)
        )
        boundary_violations.extend(
            _waive(check_forbidden_internal_imports(rs_file), waiver_rules)
        )

    all_violations = contract_violations + registry_violations + semantic_violations + boundary_violations
    active_violations = [v for v in all_violations if not v["waived"]]
    waived_violations = [v for v in all_violations if v["waived"]]

    verdict = "PASS" if not active_violations else "FAIL"

    report = {
        "schema_version": "ownership-check/v2",
        "verdict": verdict,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "policy_contract": {
            "path": CONTRACT_REL_PATH,
            "policy_matrix_heading": POLICY_MATRIX_HEADING,
            "rule_catalog_heading": RULE_CATALOG_HEADING,
        },
        "rule_catalog": RULE_CATALOG,
        "registry_capabilities": len(registry.get("capabilities", [])),
        "files_scanned": len(rust_files),
        "category_counts": {
            "contract_alignment": len([v for v in contract_violations if not v["waived"]]),
            "cross_track_redefinition": len([v for v in registry_violations if not v["waived"]]),
            "semantic_family_drift": len([v for v in semantic_violations if not v["waived"]]),
            "internal_boundary_crossing": len([v for v in boundary_violations if not v["waived"]]),
        },
        "active_violations": len(active_violations),
        "waived_violations": len(waived_violations),
        "violations": active_violations,
        "waived": waived_violations,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Semantic Boundary + Ownership CI Gate ===")
        print(f"Registry capabilities: {report['registry_capabilities']}")
        print(f"Files scanned: {report['files_scanned']}")
        print("Active violations by category:")
        for name, count in report["category_counts"].items():
            print(f"  - {name}: {count}")
        print(f"Waived violations: {len(waived_violations)}")
        print(f"Verdict: {verdict}")
        if active_violations:
            print()
            for violation in active_violations:
                print(f"  [{violation['rule_id']}] {violation['file']}")
                print(f"    Reason: {violation['reason_code']}")
                print(f"    Detail: {violation['detail']}")
                print(f"    Remediation: {violation['remediation']}")

    if not json_output:
        logger.info(
            "ownership gate complete",
            extra={
                "verdict": verdict,
                "active_violations": len(active_violations),
                "waived_violations": len(waived_violations),
            },
        )
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
