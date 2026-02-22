# VEF Proof Service Contract (bd-1u8m)

## Purpose
`vef::proof_service` defines the backend-agnostic proof-generation interface used by the
Verifiable Execution Fabric (VEF) pipeline. It converts scheduler-selected receipt windows and
policy predicates into deterministic proof envelopes that can be independently verified.

## Schema Versions
- Input/output envelope schema: `vef-proof-service-v1`
- Default backend IDs:
  - `hash_attestation_v1`
  - `double_hash_attestation_v1`

## Deterministic Input Envelope
`ProofInputEnvelope` is self-contained and includes:
- scheduler job and window identifiers
- workload tier and trace ID
- receipt range bounds and receipt hash sequence
- chain head hash and optional checkpoint commitment hash
- policy hash and canonical policy predicates
- extensible metadata map

Determinism rules:
1. `policy_predicates` are canonicalized (sorted + deduped) before commitment hashing.
2. `receipt_hashes` preserve receipt-order semantics (index order) and are never reordered.
3. `metadata` uses key-sorted map semantics (`BTreeMap`).

## Output Envelope
`ProofOutputEnvelope` includes:
- backend identifier and backend version
- input commitment hash
- backend proof material
- verification metadata
- trace ID and generation timestamp

Fail-closed validation requires:
- schema/version match
- `sha256:<64hex>` format for commitment/proof material
- output/input commitment equality
- trace correlation equality

## Backend Interface
`ProofBackend` contract:
- `generate(input, generated_at, parameters) -> ProofOutputEnvelope`
- `verify(input, proof, parameters) -> Result<(), ProofServiceError>`

Backend swap invariant:
- Different backends may emit different `proof_material` bytes.
- Verification semantics must remain stable for the same input envelope.

## Failure Classification
Structured event codes:
- `VEF-PROOF-001` request received
- `VEF-PROOF-002` backend selected
- `VEF-PROOF-003` proof generated
- `VEF-PROOF-ERR-001` timeout
- `VEF-PROOF-ERR-002` backend crash
- `VEF-PROOF-ERR-003` malformed output
- `VEF-PROOF-ERR-004` verification/unavailable/input failure

Stable error codes:
- `ERR-VEF-PROOF-TIMEOUT`
- `ERR-VEF-PROOF-BACKEND-CRASH`
- `ERR-VEF-PROOF-MALFORMED-OUTPUT`
- `ERR-VEF-PROOF-BACKEND-UNAVAILABLE`
- `ERR-VEF-PROOF-INPUT`
- `ERR-VEF-PROOF-VERIFY`

## Fail-Closed Semantics
Any of the following yields denial-class error (no degraded-pass):
- malformed envelope fields
- backend not enabled
- backend-reported crash/timeout
- output commitment mismatch
- output verification mismatch

## Traceability
Every proof request propagates `trace_id` from scheduler job/window to output envelope and
structured service events, enabling deterministic replay and cross-component audit stitching.
