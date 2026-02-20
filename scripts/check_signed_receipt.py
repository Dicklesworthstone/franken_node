#!/usr/bin/env python3
"""Verification script for bd-21z signed decision receipts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys

from nacl.signing import SigningKey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS: list[dict[str, str]] = []


def check(check_id: str, description: str, passed: bool, details: str | None = None) -> bool:
    entry: dict[str, str] = {
        "id": check_id,
        "description": description,
        "status": "PASS" if passed else "FAIL",
    }
    if details:
        entry["details"] = details
    CHECKS.append(entry)

    status = entry["status"]
    print(f"  [{status}] {check_id}: {description}")
    if details:
        print(f"         {details}")
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="also print machine-readable verification evidence to stdout",
    )
    args = parser.parse_args()

    print("bd-21z: Signed decision receipt verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/security/decision_receipt.rs")
    impl_exists = os.path.isfile(impl_path)
    impl_content = open(impl_path).read() if impl_exists else ""
    required_symbols = [
        "struct Receipt",
        "struct SignedReceipt",
        "fn sign_receipt",
        "fn verify_receipt",
        "fn verify_hash_chain",
        "fn export_receipts_cbor",
    ]
    all_pass &= check(
        "SR-IMPL",
        "Receipt implementation exists with required API symbols",
        impl_exists and all(symbol in impl_content for symbol in required_symbols),
    )

    error_markers = [
        "MissingHighImpactReceipt",
        "HashChainMismatch",
        "SignatureDecode",
        "TimestampParse",
    ]
    all_pass &= check(
        "SR-ERRORS",
        "Receipt error coverage present",
        impl_exists and all(marker in impl_content for marker in error_markers),
    )

    cli_path = os.path.join(ROOT, "crates/franken-node/src/cli.rs")
    main_path = os.path.join(ROOT, "crates/franken-node/src/main.rs")
    cli_ok = False
    if os.path.isfile(cli_path) and os.path.isfile(main_path):
        cli_content = open(cli_path).read()
        main_content = open(main_path).read()
        cli_ok = (
            "receipt_out" in cli_content
            and "receipt_summary_out" in cli_content
            and "TrustRevokeArgs" in cli_content
            and "TrustQuarantineArgs" in cli_content
            and "IncidentBundleArgs" in cli_content
            and "maybe_export_demo_receipts" in main_content
        )
    all_pass &= check(
        "SR-CLI",
        "CLI receipt export wiring exists for trust/incident paths",
        cli_ok,
    )

    fixture_path = os.path.join(ROOT, "fixtures/security/decision_receipt_samples.json")
    fixture_ok = False
    if os.path.isfile(fixture_path):
        try:
            fixture = json.load(open(fixture_path))
            fixture_ok = "cases" in fixture and len(fixture["cases"]) >= 4
        except json.JSONDecodeError:
            fixture_ok = False
    all_pass &= check("SR-FIXTURE", "Receipt sample fixture present with >=4 cases", fixture_ok)

    artifact_path = os.path.join(
        ROOT, "artifacts/section_10_5/bd-21z/decision_receipt_chain.json"
    )
    artifact_ok = False
    if os.path.isfile(artifact_path):
        try:
            artifact = json.load(open(artifact_path))
            chain = artifact.get("chain", [])
            artifact_ok = (
                isinstance(chain, list)
                and len(chain) >= 2
                and all("chain_hash" in r and "signature" in r for r in chain)
            )
        except json.JSONDecodeError:
            artifact_ok = False
    all_pass &= check("SR-ARTIFACT", "Receipt chain artifact is structurally valid", artifact_ok)

    spec_path = os.path.join(ROOT, "docs/specs/section_10_5/bd-21z_contract.md")
    spec_ok = False
    if os.path.isfile(spec_path):
        spec_content = open(spec_path).read()
        spec_ok = all(
            inv in spec_content
            for inv in [
                "INV-RECEIPT-CANONICAL",
                "INV-RECEIPT-SIGNATURE",
                "INV-RECEIPT-CHAIN",
                "INV-RECEIPT-HIGH-IMPACT",
                "INV-RECEIPT-EXPORT",
            ]
        )
    all_pass &= check("SR-SPEC", "Spec contract defines receipt invariants", spec_ok)

    # Signature correctness proof against deterministic demo signing key.
    signature_ok = False
    signature_details = None
    try:
        chain = json.load(open(artifact_path)).get("chain", [])
        verify_key = SigningKey(bytes([42] * 32)).verify_key
        previous = None
        for receipt in chain:
            payload_fields = {
                "receipt_id": receipt["receipt_id"],
                "action_name": receipt["action_name"],
                "actor_identity": receipt["actor_identity"],
                "timestamp": receipt["timestamp"],
                "input_hash": receipt["input_hash"],
                "output_hash": receipt["output_hash"],
                "decision": receipt["decision"],
                "rationale": receipt["rationale"],
                "evidence_refs": receipt["evidence_refs"],
                "policy_rule_chain": receipt["policy_rule_chain"],
                "confidence": receipt["confidence"],
                "rollback_command": receipt["rollback_command"],
                "previous_receipt_hash": previous,
            }

            payload = json.dumps(payload_fields, separators=(",", ":"), sort_keys=True).encode()
            expected_chain_hash = hashlib.sha256(
                ((previous or "GENESIS") + ":" + payload.decode()).encode()
            ).hexdigest()
            if expected_chain_hash != receipt["chain_hash"]:
                raise ValueError(
                    f"chain hash mismatch for {receipt['receipt_id']}: "
                    f"expected={expected_chain_hash} actual={receipt['chain_hash']}"
                )

            signature_bytes = base64.b64decode(receipt["signature"])
            verify_key.verify(payload, signature_bytes)
            previous = expected_chain_hash

        signature_ok = len(chain) > 0
        signature_details = f"verified {len(chain)} signed receipt(s)"
    except Exception as exc:  # pylint: disable=broad-except
        signature_details = str(exc)

    all_pass &= check(
        "SR-SIGNATURE",
        "Signature correctness validated on sample receipt chain",
        signature_ok,
        signature_details,
    )

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "signed_receipt_verification",
        "bead": "bd-21z",
        "section": "10.5",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": total - passing,
        },
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_5/bd-21z")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as handle:
        json.dump(evidence, handle, indent=2)
        handle.write("\n")

    if args.json:
        print(json.dumps(evidence, indent=2))

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
