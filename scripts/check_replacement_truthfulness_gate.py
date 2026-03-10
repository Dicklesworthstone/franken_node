#!/usr/bin/env python3
"""Static replacement-gap truthfulness gate seed for bd-3tw7.

This checker is intentionally narrow: it covers the currently open,
non-reserved replacement-critical surfaces that already have concrete source
anchors proving fail-closed behavior. It does not claim the full parent
bd-3tw7 gate is complete; it provides the deterministic static scanner and
witness-matrix seed that the broader gate can consume later.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

PARENT_BEAD = "bd-3tw7"
SUPPORT_BEAD = "bd-3tw7.1"
ARTIFACT_SUPPORT_BEADS = ("bd-3tw7.5",)
ARTIFACT_DIR = ROOT / "artifacts" / "replacement_gap" / PARENT_BEAD
WITNESS_MATRIX_PATH = ARTIFACT_DIR / "witness_matrix.json"
EVIDENCE_PATH = ARTIFACT_DIR / "verification_evidence.json"
SUMMARY_PATH = ARTIFACT_DIR / "verification_summary.md"

SURROGATE_REINTRODUCED = "TRUTHFULNESS_GATE_SURROGATE_REINTRODUCED"
MISSING_ANCHOR = "TRUTHFULNESS_GATE_MISSING_ANCHOR"
SOURCE_MISSING = "TRUTHFULNESS_GATE_SOURCE_MISSING"
STATIC_PASS = "TRUTHFULNESS_GATE_STATIC_PASS"


@dataclass(frozen=True)
class WitnessSpec:
    witness_id: str
    surface: str
    witness_family: str
    source_paths: tuple[str, ...]
    required_markers: tuple[str, ...]
    banned_markers: tuple[str, ...] = ()
    related_checkers: tuple[str, ...] = ()
    remediation_bead: str = PARENT_BEAD
    support_bead: str = SUPPORT_BEAD


EXCLUDED_SURFACES = [
    {
        "path": "crates/franken-node/src/verifier_economy/mod.rs",
        "owner": "RoseRidge",
        "reason": "Reserved under bd-1z5a.8",
    },
    {
        "path": "crates/franken-node/src/connector/verifier_sdk.rs",
        "owner": "RoseRidge",
        "reason": "Reserved under bd-1z5a.8",
    },
    {
        "path": "crates/franken-node/src/sdk/verifier_sdk.rs",
        "owner": "RoseRidge",
        "reason": "Reserved under bd-1z5a.8",
    },
    {
        "path": "crates/franken-node/src/sdk/replay_capsule.rs",
        "owner": "RoseRidge",
        "reason": "Reserved under bd-1z5a.8",
    },
]


WITNESS_SPECS = (
    WitnessSpec(
        witness_id="migration_placeholder_prefix_shortcuts",
        surface="migration",
        witness_family="forged migration inputs whose names previously spoofed heuristics",
        source_paths=("crates/franken-node/src/connector/migration_pipeline.rs",),
        required_markers=("fn test_placeholder_prefix_shortcuts_absent_from_source()",),
        banned_markers=("blocked_", "fail_verify_"),
        related_checkers=("scripts/check_migration_pipeline.py",),
    ),
    WitnessSpec(
        witness_id="compatibility_placeholder_signature_shortcuts",
        surface="policy",
        witness_family="forged compatibility receipts and placeholder signature shortcuts",
        source_paths=(
            "crates/franken-node/src/policy/compat_gates.rs",
            "crates/franken-node/src/policy/compatibility_gate.rs",
        ),
        required_markers=(
            "fn compatibility_sources_do_not_reintroduce_placeholder_signature_shortcuts()",
        ),
        banned_markers=(
            "placeholder signature",
            "Simplified HMAC for demonstration",
            "compat_gate_sign_v1:",
        ),
        related_checkers=("scripts/check_compat_gates.py",),
    ),
    WitnessSpec(
        witness_id="safe_mode_stale_frontier_fail_closed",
        surface="runtime_safe_mode",
        witness_family="stale safe-mode frontier and trust-digest drift fail closed",
        source_paths=("crates/franken-node/src/runtime/safe_mode.rs",),
        required_markers=(
            "SMO_006_TRUST_REVERIFICATION",
            "fn test_verify_trust_state_stale_frontier_at_exact_boundary()",
            "fn compute_evidence_digest(",
            "safe_mode_evidence_digest_v1:",
            "safe_mode_trust_proof_v1:",
        ),
        related_checkers=("scripts/check_safe_mode.py",),
    ),
    WitnessSpec(
        witness_id="anti_entropy_canonical_proof_verification",
        surface="runtime_anti_entropy",
        witness_family="zero-filled or decorative anti-entropy proofs must not pass",
        source_paths=("crates/franken-node/src/runtime/anti_entropy.rs",),
        required_markers=(
            "fn regression_non_empty_check_no_longer_sufficient()",
            "fn verify_mmr_proof(",
            "mmr_proofs::verify_inclusion",
            "INV-AE-PROOF",
        ),
        related_checkers=("scripts/check_anti_entropy_reconciliation.py",),
    ),
    WitnessSpec(
        witness_id="extension_registry_shape_only_signature_shortcuts",
        surface="supply_chain_extension_registry",
        witness_family="forged extension manifests with valid-looking but invalid signatures",
        source_paths=("crates/franken-node/src/supply_chain/extension_registry.rs",),
        required_markers=(
            "fn static_check_no_shape_shortcuts()",
            "artifact_signing::verify_signature",
            "shape-only check would have accepted this",
        ),
        related_checkers=("scripts/check_signed_extension_registry.py",),
    ),
    WitnessSpec(
        witness_id="control_channel_non_empty_token_shortcut",
        surface="control_channel",
        witness_family="guessed control tokens and non-empty credential shortcuts",
        source_paths=("crates/franken-node/src/connector/control_channel.rs",),
        required_markers=(
            "fn regression_non_empty_string_is_not_sufficient()",
            "transcript_mac_mismatch",
            "ACC_AUTH_FAILED",
        ),
        banned_markers=("!token.is_empty()",),
        related_checkers=("scripts/check_control_channel.py",),
    ),
    WitnessSpec(
        witness_id="session_auth_opaque_signature_regression",
        surface="api_session_auth",
        witness_family="decorative session signatures and forged transcript MACs",
        source_paths=("crates/franken-node/src/api/session_auth.rs",),
        required_markers=(
            "INV-SCC-HANDSHAKE-BIND",
            "INV-SCC-MSG-VERIFY",
            "fn adversarial_forged_handshake_mac_rejected()",
            "fn regression_opaque_signature_no_longer_accepted()",
            "ERR_SCC_AUTH_FAILED",
        ),
        related_checkers=("scripts/check_session_auth.py",),
    ),
    WitnessSpec(
        witness_id="trust_card_evidence_binding",
        surface="supply_chain_trust_card",
        witness_family="caller-injected trust-card inputs without verified evidence",
        source_paths=("crates/franken-node/src/supply_chain/trust_card.rs",),
        required_markers=(
            "fn create_rejects_empty_evidence()",
            "fn update_upgrade_without_evidence_rejected()",
            "EvidenceMissing",
            "EvidenceRequiredForUpgrade",
            "derivation_evidence",
        ),
        related_checkers=("scripts/check_trust_card.py",),
    ),
    WitnessSpec(
        witness_id="certification_evidence_binding",
        surface="supply_chain_certification",
        witness_family="caller-supplied certification assertions without verified evidence",
        source_paths=("crates/franken-node/src/supply_chain/certification.rs",),
        required_markers=(
            "fn test_no_evidence_returns_uncertified()",
            "fn test_derivation_metadata_present_with_evidence()",
            "caller-supplied assertions",
            "evidence_binding_present",
            "compute_derivation_hash",
        ),
        related_checkers=("scripts/check_certification_levels.py",),
    ),
    WitnessSpec(
        witness_id="workspace_verifier_sdk_structural_only_posture",
        surface="workspace_verifier_sdk",
        witness_family="public verifier sdk surface must remain explicitly structural-only",
        source_paths=(
            "sdk/verifier/src/lib.rs",
            "sdk/verifier/src/capsule.rs",
            "docs/specs/replay_capsule_format.md",
            "docs/specs/section_10_17/bd-nbwo_contract.md",
        ),
        required_markers=(
            'pub const STRUCTURAL_ONLY_SECURITY_POSTURE: &str = "structural_only_not_replacement_critical";',
            'pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK";',
            'pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_REPLAY_CAPSULE";',
            "structural signature digest",
            "structural-only",
        ),
        banned_markers=(
            "cryptographic signature",
            "signature integrity",
            "signed capsules",
            "self-contained, signed unit",
        ),
        related_checkers=("scripts/check_verifier_sdk_capsule.py",),
        support_bead="bd-3tw7.2",
    ),
    WitnessSpec(
        witness_id="workspace_verifier_sdk_package_metadata_truthfulness",
        surface="workspace_verifier_sdk_metadata",
        witness_family="public verifier sdk package metadata must remain structural-only",
        source_paths=("sdk/verifier/Cargo.toml",),
        required_markers=(
            'description = "Structural-only verifier SDK for replaying structurally bound capsules and reproducing claim verdicts"',
        ),
        banned_markers=(
            "signed capsules",
            "cryptographic authority",
        ),
        related_checkers=("scripts/check_verifier_sdk_capsule.py",),
        support_bead="bd-3tw7.4",
    ),
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*", "", text)
    return text


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def evaluate_witness(spec: WitnessSpec, root: Path = ROOT) -> dict[str, Any]:
    resolved_paths = [root / rel for rel in spec.source_paths]
    missing_paths = [rel for rel, path in zip(spec.source_paths, resolved_paths) if not path.exists()]
    if missing_paths:
        return {
            "witness_id": spec.witness_id,
            "surface": spec.surface,
            "witness_family": spec.witness_family,
            "source_paths": list(spec.source_paths),
            "related_checkers": list(spec.related_checkers),
            "remediation_bead": spec.remediation_bead,
            "support_bead": spec.support_bead,
            "pass": False,
            "reason_code": SOURCE_MISSING,
            "offending_path": missing_paths[0],
            "missing_required_markers": [],
            "present_banned_markers": [],
            "detail": f"missing source path: {missing_paths[0]}",
        }

    contents = {rel: _read(root / rel) for rel in spec.source_paths}
    combined_raw = "\n".join(contents.values())
    missing_required = [marker for marker in spec.required_markers if marker not in combined_raw]

    present_banned: list[dict[str, str]] = []
    for rel, text in contents.items():
        stripped = _strip_comments(text)
        for marker in spec.banned_markers:
            if marker in stripped:
                present_banned.append({"path": rel, "marker": marker})

    if missing_required:
        return {
            "witness_id": spec.witness_id,
            "surface": spec.surface,
            "witness_family": spec.witness_family,
            "source_paths": list(spec.source_paths),
            "related_checkers": list(spec.related_checkers),
            "remediation_bead": spec.remediation_bead,
            "support_bead": spec.support_bead,
            "pass": False,
            "reason_code": MISSING_ANCHOR,
            "offending_path": spec.source_paths[0],
            "missing_required_markers": missing_required,
            "present_banned_markers": [],
            "detail": f"missing required marker(s): {', '.join(missing_required)}",
        }

    if present_banned:
        first_hit = present_banned[0]
        return {
            "witness_id": spec.witness_id,
            "surface": spec.surface,
            "witness_family": spec.witness_family,
            "source_paths": list(spec.source_paths),
            "related_checkers": list(spec.related_checkers),
            "remediation_bead": spec.remediation_bead,
            "support_bead": spec.support_bead,
            "pass": False,
            "reason_code": SURROGATE_REINTRODUCED,
            "offending_path": first_hit["path"],
            "missing_required_markers": [],
            "present_banned_markers": present_banned,
            "detail": f"banned surrogate marker present: {first_hit['marker']}",
        }

    return {
        "witness_id": spec.witness_id,
        "surface": spec.surface,
        "witness_family": spec.witness_family,
        "source_paths": list(spec.source_paths),
        "related_checkers": list(spec.related_checkers),
        "remediation_bead": spec.remediation_bead,
        "support_bead": spec.support_bead,
        "pass": True,
        "reason_code": STATIC_PASS,
        "offending_path": spec.source_paths[0],
        "missing_required_markers": [],
        "present_banned_markers": [],
        "detail": f"all {len(spec.required_markers)} required anchor(s) present",
    }


def run_all(root: Path = ROOT) -> dict[str, Any]:
    witness_matrix = [evaluate_witness(spec, root) for spec in WITNESS_SPECS]
    support_bead_ids = sorted({spec.support_bead for spec in WITNESS_SPECS} | set(ARTIFACT_SUPPORT_BEADS))
    passed = sum(1 for item in witness_matrix if item["pass"])
    failed = len(witness_matrix) - passed
    overall_pass = failed == 0
    return {
        "schema_version": "replacement-truthfulness-gate-v1.0",
        "bead_id": PARENT_BEAD,
        "support_bead_ids": support_bead_ids,
        "title": "Replacement-critical truthfulness gate static seed",
        "verdict": "PASS" if overall_pass else "FAIL",
        "overall_pass": overall_pass,
        "artifact_scope": "Static cross-surface surrogate scanner and witness-matrix seed for currently unreserved replacement-critical surfaces.",
        "generated_at": _now(),
        "verification_method": "python3 scripts/check_replacement_truthfulness_gate.py --json",
        "artifacts": {
            "verification_evidence": "artifacts/replacement_gap/bd-3tw7/verification_evidence.json",
            "verification_summary": "artifacts/replacement_gap/bd-3tw7/verification_summary.md",
            "witness_matrix": "artifacts/replacement_gap/bd-3tw7/witness_matrix.json",
            "checker": "scripts/check_replacement_truthfulness_gate.py",
            "checker_tests": "tests/test_check_replacement_truthfulness_gate.py",
            "evidence_pack_checker": "scripts/check_bd_3tw7_evidence_pack.py",
            "evidence_pack_checker_tests": "tests/test_check_bd_3tw7_evidence_pack.py",
        },
        "excluded_surfaces": EXCLUDED_SURFACES,
        "witness_matrix": witness_matrix,
        "total_witnesses": len(witness_matrix),
        "passed_witnesses": passed,
        "failed_witnesses": failed,
        "notes": [
            "This support shard intentionally excludes the verifier/capsule Rust files currently reserved under bd-1z5a.8.",
            "bd-3tw7.2 extends the static seed to the standalone sdk/verifier workspace crate and its public verifier contract docs.",
            "The witness matrix is a static seed for bd-3tw7, not a claim that the full parent dynamic/e2e truthfulness gate is complete.",
            "bd-3tw7.5 adds deterministic evidence-pack coherence coverage so artifact drift fails closed.",
            "Each witness links to concrete source anchors already present in the shared tree so regressions fail on exact guarded paths, not vague heuristics.",
        ],
    }


def write_artifacts(payload: dict[str, Any], root: Path = ROOT) -> None:
    artifact_dir = root / "artifacts" / "replacement_gap" / PARENT_BEAD
    artifact_dir.mkdir(parents=True, exist_ok=True)

    witness_matrix_path = artifact_dir / "witness_matrix.json"
    witness_matrix_path.write_text(
        json.dumps(payload["witness_matrix"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    evidence_path = artifact_dir / "verification_evidence.json"
    evidence_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary_lines = [
        "# bd-3tw7 Static Truthfulness Gate Seed",
        "",
        f"- Parent bead: `{PARENT_BEAD}`",
        f"- Support beads: `{', '.join(payload['support_bead_ids'])}`",
        f"- Verdict: `{payload['verdict']}`",
        f"- Scope: {payload['artifact_scope']}",
        "- Static-seed disclaimer: this pack does not claim the full parent dynamic/e2e truthfulness gate is complete.",
        "",
        "## Guarded Witnesses",
        "",
    ]
    for entry in payload["witness_matrix"]:
        status = "PASS" if entry["pass"] else "FAIL"
        summary_lines.append(
            f"- `{entry['witness_id']}` ({entry['surface']}): `{status}` via `{entry['reason_code']}`"
        )

    summary_lines.extend(
        [
            "",
            "## Excluded Reserved Surfaces",
            "",
        ]
    )
    for entry in payload["excluded_surfaces"]:
        summary_lines.append(
            f"- `{entry['path']}` excluded because {entry['reason']} (`{entry['owner']}`)."
        )

    summary_lines.extend(
        [
            "",
            "## Guard Checkers",
            "",
            f"- Primary seed checker: `{payload['artifacts']['checker']}`",
            f"- Primary seed tests: `{payload['artifacts']['checker_tests']}`",
            f"- Evidence-pack coherence checker: `{payload['artifacts']['evidence_pack_checker']}`",
            f"- Evidence-pack coherence tests: `{payload['artifacts']['evidence_pack_checker_tests']}`",
            "",
            "## Artifact Paths",
            "",
            "- `artifacts/replacement_gap/bd-3tw7/verification_evidence.json`",
            "- `artifacts/replacement_gap/bd-3tw7/verification_summary.md`",
            "- `artifacts/replacement_gap/bd-3tw7/witness_matrix.json`",
        ]
    )

    summary_path = artifact_dir / "verification_summary.md"
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")


def self_test() -> bool:
    spec = WitnessSpec(
        witness_id="toy_witness",
        surface="toy",
        witness_family="toy family",
        source_paths=("src/toy.rs",),
        required_markers=("fn anchor()",),
        banned_markers=("!token.is_empty()",),
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        toy = root / "src" / "toy.rs"
        toy.parent.mkdir(parents=True, exist_ok=True)

        toy.write_text("fn anchor() {}\n// !token.is_empty()\n", encoding="utf-8")
        comment_only = evaluate_witness(spec, root)
        if not comment_only["pass"]:
            return False

        toy.write_text("fn anchor() { let ok = !token.is_empty(); }\n", encoding="utf-8")
        banned = evaluate_witness(spec, root)
        if banned["reason_code"] != SURROGATE_REINTRODUCED:
            return False

        toy.write_text("fn other() {}\n", encoding="utf-8")
        missing = evaluate_witness(spec, root)
        if missing["reason_code"] != MISSING_ANCHOR:
            return False

    return True


def _print_human(payload: dict[str, Any]) -> None:
    print(
        f"{PARENT_BEAD} static truthfulness gate seed: {payload['verdict']} "
        f"({payload['passed_witnesses']}/{payload['total_witnesses']} witnesses PASS)"
    )
    for entry in payload["witness_matrix"]:
        status = "PASS" if entry["pass"] else "FAIL"
        print(f"- [{status}] {entry['witness_id']}: {entry['detail']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="run internal consistency checks")
    args = parser.parse_args(argv)

    logger = configure_test_logging("check_replacement_truthfulness_gate", json_mode=args.json)

    if args.self_test:
        ok = self_test()
        logger.info("self-test complete", extra={"passed": ok})
        if args.json:
            print(json.dumps({"self_test": ok}))
        else:
            print("self_test PASSED" if ok else "self_test FAILED")
        return 0 if ok else 1

    payload = run_all()
    write_artifacts(payload)
    logger.info(
        "static truthfulness scan complete",
        extra={
            "verdict": payload["verdict"],
            "passed_witnesses": payload["passed_witnesses"],
            "failed_witnesses": payload["failed_witnesses"],
        },
    )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human(payload)
    return 0 if payload["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
