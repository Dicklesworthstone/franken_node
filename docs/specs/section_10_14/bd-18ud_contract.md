# bd-18ud: Durability Modes for Control/Trust Artifacts

## Scope

Explicit `durability=local` and `durability=quorum(M)` semantics for control
and trust artifacts. Mode enforcement is end-to-end, switching is
policy-gated, and claim language is deterministic.

## Modes

| Mode | Semantics | Use Case |
|------|-----------|----------|
| `Local` | Single-node fsync confirmation | Re-derivable artifacts |
| `Quorum(M)` | M replica acks required before durable | Critical control artifacts |

## Claim Language

Deterministic mapping: identical (mode, outcome) inputs always produce
identical claim strings.

| Mode | Outcome | Claim String |
|------|---------|-------------|
| Local | Fsync confirmed | `local-fsync-confirmed` |
| Quorum(M) | N/T acked | `quorum-N-of-T-acked(min=M)` |
| Quorum(M) | N/T failed | `quorum-failed-N-of-T-acked(required=M,min=M)` |

## Mode Switch Policy

- **Upgrades** (Local to Quorum, or higher M): Allowed without operator auth by default
- **Downgrades** (Quorum to Local, or lower M): Requires explicit operator authorization
- **Strict mode**: All transitions require operator auth
- All switches emit `DM_MODE_SWITCH` event; denied switches emit `DM_MODE_SWITCH_DENIED`

## Quorum Semantics

- Fail-closed: writes rejected when fewer than M replicas acknowledge
- Ack counting is deterministic
- Partial quorum produces a failure claim (still logged)

## Invariants

| ID | Statement |
|----|-----------|
| INV-DUR-ENFORCE | Write path enforces configured durability mode end-to-end |
| INV-DUR-CLAIM-DETERMINISTIC | Claim language is deterministic for (mode, outcome) pairs |
| INV-DUR-SWITCH-AUDITABLE | Mode switches are policy-gated and logged |
| INV-DUR-QUORUM-FAIL-CLOSED | Quorum mode rejects writes when M not reached |

## Event Codes

| Code | Trigger |
|------|---------|
| DM_MODE_INITIALIZED | Mode set at startup |
| DM_MODE_SWITCH | Mode transition |
| DM_MODE_SWITCH_DENIED | Unauthorized switch |
| DM_WRITE_LOCAL_CONFIRMED | Local fsync done |
| DM_WRITE_QUORUM_CONFIRMED | Quorum acks received |
| DM_WRITE_QUORUM_FAILED | Insufficient acks |
| DM_CLAIM_GENERATED | Claim language produced |

## Error Codes

| Code | Condition |
|------|-----------|
| ERR_QUORUM_INSUFFICIENT | Quorum write failed: insufficient acks |
| ERR_MODE_SWITCH_DENIED | Unauthorized mode transition |
| ERR_INVALID_QUORUM_SIZE | Quorum min_acks = 0 |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/connector/durability.rs` |
| Spec contract | `docs/specs/section_10_14/bd-18ud_contract.md` |
| Claim matrix | `artifacts/10.14/durability_mode_claim_matrix.json` |
| Verification script | `scripts/check_durability_modes.py` |
| Python unit tests | `tests/test_check_durability_modes.py` |
| Verification evidence | `artifacts/section_10_14/bd-18ud/verification_evidence.json` |
| Verification summary | `artifacts/section_10_14/bd-18ud/verification_summary.md` |
