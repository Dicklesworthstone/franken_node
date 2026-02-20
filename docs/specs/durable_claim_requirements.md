# Durable Claim Gate Requirements (bd-1l62)

## Objective

No durable claim may be emitted unless required markers and proofs are present,
valid, fresh, and verification-complete.

## Fail-Closed Contract

The gate must reject any claim when:
- required marker is unavailable
- required proof is missing
- proof validation fails
- proof is stale/expired
- verification is incomplete or timed out

No bypass path is allowed.

## Stable Denial Codes

`ClaimDenialReason` provides these stable codes:

- `CLAIM_PROOF_MISSING`
- `CLAIM_PROOF_INVALID`
- `CLAIM_PROOF_EXPIRED`
- `CLAIM_PROOF_VERIFICATION_TIMEOUT`
- `CLAIM_MARKER_UNAVAILABLE`

## Supported Proof Classes

- `merkle_inclusion`
- `marker_mmr`
- `epoch_boundary`
- custom proof classes (`custom:<name>`)

## Determinism

For identical `(claim, markers, proofs, epoch)` inputs, decisions must be identical:

- same `accepted` value
- same denial code (if denied)
- same evidence witness hash (if accepted)

## Freshness Policy

Gate config:
- `verification_timeout_ms` (default `1000`)
- `freshness_window_epochs` (default `1`)

Proofs are rejected as expired when:
- `current_epoch > expires_at_epoch`, or
- `current_epoch - issued_at_epoch > freshness_window_epochs`

## Evidence Integration

On acceptance, emit an `EvidenceEntry` carrying:
- `claim_id`
- `epoch`
- `proof_artifact_hash` (deterministic digest over sorted proof hashes)
- `trace_id`

## Structured Events

The gate emits:
- `CLAIM_SUBMITTED`
- `CLAIM_ACCEPTED`
- `CLAIM_REJECTED`
- `PROOF_VERIFIED`
- `PROOF_INVALID`

Each event includes `claim_id`, marker/proof counts, `trace_id`, and `epoch`.

## Security Validation Requirements

- dedicated test for each denial variant
- forged proof payload rejection
- wrong-epoch proof rejection
- wrong-claim proof rejection
- malformed/partial proof fuzz-style denial loop
