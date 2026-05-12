# Threshold Signatures

This is the stable public entry point for the threshold-signature publication
contract.

The authoritative section-owned contract is
`docs/specs/section_10_13/bd-35q1_contract.md`. That contract defines the
quorum, partial-rejection, duplicate-signer, stable-failure-reason, and
connector-publication artifact requirements for bd-35q1.

The executable surfaces for this contract are:

- `crates/franken-node/src/security/threshold_sig.rs`
- `tests/security/threshold_signature_verification.rs`
- `fixtures/threshold_sig/verification_scenarios.json`
- `artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json`
- `scripts/check_threshold_sig.py`

This file exists to preserve the artifact path named by the original plan while
keeping `docs/specs/section_10_13/bd-35q1_contract.md` as the source of truth.
