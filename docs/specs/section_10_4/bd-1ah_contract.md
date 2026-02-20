# bd-1ah: Provenance Attestation Requirements and Verification Chain

## Bead: bd-1ah | Section: 10.4

## Purpose

Defines the canonical provenance attestation contract for extension admission.
The attestation proves where an artifact came from, who built it, and whether
its transitive trust chain is still valid/fresh under policy.

## Invariants

| ID | Statement |
|----|-----------|
| INV-PAT-REQUIRED-FIELDS | Every attestation includes non-empty `source_repository_url`, `build_system_identifier`, `builder_identity`, `builder_version`, `vcs_commit_sha`, `build_timestamp_epoch`, `reproducibility_hash`, `input_hash`, `output_hash`, and `slsa_level_claim`. |
| INV-PAT-CHAIN-ORDER | Transitive links are ordered `publisher -> build_system -> source_vcs` and carry signatures over canonical signable payloads. |
| INV-PAT-FAIL-CLOSED | Missing/invalid/revoked/stale links are rejected by default with a structured error containing broken link identity and remediation text. |
| INV-PAT-FORMAT-CANONICAL | Attestation envelopes support `in_toto` and `franken_node_envelope_v1`; signature verification uses deterministic canonical JSON serialization. |
| INV-PAT-PROFILE-DEPTH | Chain depth and self-signing behavior are profile-driven (`development_profile` can accept depth=1 self-signed publisher links; `production_default` requires depth=3). |
| INV-PAT-FRESHNESS | Attestation and link freshness are enforced via max-age windows; stale chains trigger `CHAIN_STALE` and are only tolerated under explicit cached-trust policy windows. |
| INV-PAT-DOWNSTREAM-GATES | Successful provenance verification projects into 10.13 downstream gates (`threshold_signature_required`, `transparency_log_required`) deterministically from provenance level. |
| INV-PAT-STRUCTURED-EVENTS | Verification emits structured event codes including `ATTESTATION_VERIFIED`, `ATTESTATION_REJECTED`, `PROVENANCE_LEVEL_ASSIGNED`, `CHAIN_INCOMPLETE`, `CHAIN_STALE`, `PROVENANCE_CHAIN_BROKEN`, `PROVENANCE_DEGRADED_MODE_ENTERED`. |

## Canonical Data Model

- Rust module: `crates/franken-node/src/supply_chain/provenance.rs`
- JSON schema: `schemas/provenance_attestation.schema.json`

Primary structures:

1. `ProvenanceAttestation`
2. `AttestationLink`
3. `VerificationPolicy`
4. `ChainValidityReport`
5. `VerificationFailure`
6. `DownstreamGateRequirements`

## Verification Algorithm

1. Validate required fields (`INV-PAT-REQUIRED-FIELDS`).
2. Validate chain depth and canonical ordering (`INV-PAT-CHAIN-ORDER`).
3. Validate attestation freshness and per-link freshness (`INV-PAT-FRESHNESS`).
4. Validate each link:
   - not revoked
   - signed payload hash binds to attested output hash
   - deterministic canonical signature matches expected signature
   - self-signed policy rules
5. Derive provenance level:
   - `Level0Unsigned`
   - `Level1PublisherSigned`
   - `Level2SignedReproducible`
   - `Level3IndependentReproduced`
6. Enforce policy minimum level and mode (`FailClosed` vs `CachedTrustWindow`).
7. Emit structured events and project downstream 10.13 gate requirements.

## Policy Profiles

| Profile | Min Level | Depth | Self-Signed | Mode |
|---------|-----------|-------|-------------|------|
| `production_default` | `Level2SignedReproducible` | 3 | No | `fail_closed` |
| `development_profile` | `Level1PublisherSigned` | 1 | Yes | `cached_trust_window` |

## Error Codes

| Code | Meaning |
|------|---------|
| `ATTESTATION_MISSING_FIELD` | Required attestation field missing or empty |
| `CHAIN_INCOMPLETE` | Required chain depth/coverage missing |
| `CHAIN_LINK_ORDER_INVALID` | Link order violates canonical transitive role order |
| `INVALID_SIGNATURE` | Signature missing/mismatched or payload-hash mismatch |
| `CHAIN_LINK_REVOKED` | Signing identity in chain is revoked |
| `CHAIN_STALE` | Link or attestation freshness exceeds policy window |
| `LEVEL_INSUFFICIENT` | Derived provenance level below policy minimum |
| `CANONICALIZATION_FAILED` | Canonical payload could not be serialized deterministically |

## Integration Contracts

### With bd-1gx (Manifest Schema)

- Manifest provenance envelope references this attestation bundle by digest/URI.
- Admission combines `SignedExtensionManifest` validation with provenance-chain validation.

### With 10.13 FCP Trust Gates

`verify_and_project_gates(...)` maps provenance level to mandatory downstream checks:

- `Level0`: no downstream gates (deny by policy in production)
- `Level1`: require threshold-signature verification
- `Level2/Level3`: require threshold-signature and transparency-log verification

## Artifacts

- Spec: `docs/specs/section_10_4/bd-1ah_contract.md`
- Schema: `schemas/provenance_attestation.schema.json`
- Implementation: `crates/franken-node/src/supply_chain/provenance.rs`
- Integration tests: `tests/integration/provenance_verification_chain.rs`
- Verification script: `scripts/check_provenance_attestation.py`
- Verification evidence: `artifacts/section_10_4/bd-1ah/verification_evidence.json`
- Verification summary: `artifacts/section_10_4/bd-1ah/verification_summary.md`
