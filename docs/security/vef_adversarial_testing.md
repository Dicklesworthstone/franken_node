# VEF Adversarial Testing Methodology

Bead: `bd-3ptu`  
Section: `10.18` (Verifiable Execution Fabric)

## Attack Classes

The adversarial suite covers four fail-closed attack classes:

1. `receipt_tampering`
- Mutates receipt content inside the proof window.
- Also covers truncation/injection shape drift.
- Error code: `VEF-ADVERSARIAL-ERR-TAMPER`
- Remediation: rebuild chain from trusted source and regenerate proof.

2. `proof_replay`
- Reuses a valid proof envelope under a different binding (window, chain, or policy context).
- Error code: `VEF-ADVERSARIAL-ERR-REPLAY`
- Remediation: require fresh proof bound to current chain/window/policy.

3. `stale_policy`
- Presents proof generated against an outdated or unrelated policy snapshot hash.
- Error code: `VEF-ADVERSARIAL-ERR-STALE-POLICY`
- Remediation: regenerate proof against active policy snapshot.

4. `commitment_mismatch`
- Substitutes checkpoint commitment material from adjacent window, foreign chain, or null value.
- Error code: `VEF-ADVERSARIAL-ERR-COMMITMENT`
- Remediation: recompute commitment from canonical receipts and reject mismatch.

## Structured Logging Contract

All detected attacks emit deterministic structured events:

- `VEF-ADVERSARIAL-001` — attack detected
- `VEF-ADVERSARIAL-002` — attack class identified
- `VEF-ADVERSARIAL-ERR-*` — stable mismatch/error class in verdict payload

Each event carries a trace correlation ID for replay triage.

## Determinism Contract

For each attack class, the suite runs repeated checks and asserts a stable signature:

- stable error code
- stable remediation hint
- stable event code set

This prevents nondeterministic diagnostics that would undermine forensic repeatability.

## False Positive Guard

Legitimate proof envelopes (proper chain/window/policy/commitment bindings) are asserted to pass,
preventing overblocking regressions.
