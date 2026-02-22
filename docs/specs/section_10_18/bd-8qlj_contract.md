# bd-8qlj: VEF Verification State in High-Risk Control Transitions

**Section:** 10.18 -- Verifiable Execution Fabric (VEF)
**Track:** C/E -- Trust-Native + Frontier Industrialization
**Status:** Active

## Purpose

Integrate VEF verification state into high-risk control transitions and action
authorization.  Every capability grant, trust-level change, artifact promotion,
and policy override must present valid VEF evidence before the transition is
authorized.  Unauthorized transitions without valid VEF evidence are blocked
with structured denial containing a stable reason code.

## Scope

### In scope

- `ControlTransitionGate` enforcing evidence requirements for all high-risk transitions.
- `TransitionType` enum: `CapabilityGrant`, `TrustLevelChange`, `ArtifactPromotion`, `PolicyOverride`.
- `AuthorizationDecision` enum: `Authorized`, `Denied(DenialReason)`, `PendingVerification`.
- `VefEvidenceRef` with scope, state, hash, and expiration metadata.
- `TransitionRequest` binding actor, target, transition type, and evidence references.
- `GatePolicy` with per-transition-type overrides (min evidence count, max age, trust level).
- `GateMetrics` tracking authorized/denied/pending counts per transition type.
- Structured `GateEvent` emission with stable event codes CTL-001 through CTL-008.
- Serde round-trip serialization for all public types.

### Out of scope

- Cryptographic verification of evidence payloads (handled by receipt chain / proof scheduler).
- Distributed quorum or consensus for multi-party authorization.
- Persistent storage of gate decisions (future bead).

## Transition Types

1. `capability_grant` -- Granting a capability to an actor or connector.
2. `trust_level_change` -- Changing the trust level of an entity.
3. `artifact_promotion` -- Promoting an artifact through a trust gate.
4. `policy_override` -- Overriding an existing policy constraint.

## Event Codes

| Code    | Meaning                                   |
|---------|-------------------------------------------|
| CTL-001 | Transition request received               |
| CTL-002 | Transition authorized                     |
| CTL-003 | Denied: missing evidence                  |
| CTL-004 | Denied: expired evidence                  |
| CTL-005 | Denied: evidence scope mismatch           |
| CTL-006 | Pending verification                      |
| CTL-007 | Denied: invalid evidence hash             |
| CTL-008 | Denied: insufficient trust level          |

## Error Codes

| Code                         | Meaning                          |
|------------------------------|----------------------------------|
| ERR-CTL-MISSING-EVIDENCE     | No evidence provided             |
| ERR-CTL-EXPIRED-EVIDENCE     | All evidence has expired         |
| ERR-CTL-SCOPE-MISMATCH      | Evidence does not cover scope    |
| ERR-CTL-INVALID-HASH         | Evidence hash invalid            |
| ERR-CTL-INSUFFICIENT-TRUST   | Actor trust below minimum        |
| ERR-CTL-INTERNAL             | Internal gate error              |

## Invariants

- `INV-CTL-EVIDENCE-REQUIRED`: Every high-risk transition must reference at
  least one valid VEF evidence entry; transitions with no evidence are denied
  unconditionally.
- `INV-CTL-DENY-LOGGED`: Every denial produces a structured event with a
  stable event code and human-readable reason.
- `INV-CTL-NO-BYPASS`: There is no code path that skips evidence validation
  for high-risk transition types.

## Acceptance Criteria

1. All four transition types require VEF evidence (INV-CTL-NO-BYPASS).
2. Missing evidence produces a Denied decision with ERR-CTL-MISSING-EVIDENCE.
3. Expired evidence produces a Denied decision with ERR-CTL-EXPIRED-EVIDENCE.
4. Scope-mismatched evidence produces a Denied decision with ERR-CTL-SCOPE-MISMATCH.
5. Invalid evidence state produces a Denied decision with ERR-CTL-INVALID-HASH.
6. Unverified evidence produces a PendingVerification decision.
7. Valid evidence with correct scope produces an Authorized decision.
8. Every denial emits a structured GateEvent (INV-CTL-DENY-LOGGED).
9. Per-transition-type policy overrides are respected.
10. Trust level enforcement blocks low-trust actors.
11. Serde round-trip for TransitionRequest and AuthorizationDecision.
12. At least 25 unit tests covering all paths.
13. Checker script and test suite pass with machine-readable evidence.

## Verification Artifacts

- `crates/franken-node/src/vef/control_integration.rs`
- `crates/franken-node/src/vef/mod.rs`
- `scripts/check_vef_control_integration.py`
- `tests/test_check_vef_control_integration.py`
- `artifacts/section_10_18/bd-8qlj/verification_evidence.json`
- `artifacts/section_10_18/bd-8qlj/verification_summary.md`
