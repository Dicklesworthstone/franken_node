# bd-3ku8: Capability-Carrying Extension Artifact Format

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-3ku8 |
| Section | 10.17 |
| Title | Define and enforce capability-carrying extension artifact format |
| Type | task |

## Purpose

Extensions in the franken_node radical expansion track must carry explicit
capability contracts within their artifact bundles. This bead defines the
canonical artifact format for capability-carrying extensions, implements
admission control that fails closed on missing or invalid capability contracts,
and enforces that runtime behaviour matches the admitted capability envelope
without drift.

The artifact format enables:
- Machine-readable declaration of capabilities an extension requires.
- Cryptographic binding of the capability envelope to the artifact identity.
- Admission-time validation that rejects artifacts with missing, malformed,
  or over-scoped capability contracts.
- Runtime envelope enforcement that detects and blocks capability drift.

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_17/bd-3ku8_contract.md` |
| Rust module | `crates/franken-node/src/connector/capability_artifact.rs` |
| Check script | `scripts/check_capability_artifact_format.py` |
| Test suite | `tests/test_check_capability_artifact_format.py` |
| Evidence | `artifacts/section_10_17/bd-3ku8/verification_evidence.json` |
| Summary | `artifacts/section_10_17/bd-3ku8/verification_summary.md` |

## Invariants

- **INV-CART-FAIL-CLOSED**: Artifact admission rejects any artifact with a
  missing, invalid, or malformed capability contract. No artifact is admitted
  without a valid envelope.
- **INV-CART-ENVELOPE-MATCH**: At runtime, the enforced capability set must
  exactly match the admitted envelope. Any drift (capability used but not
  declared, or declared but revoked) triggers an enforcement error.
- **INV-CART-SCHEMA-VERSIONED**: Every capability artifact carries a schema
  version. Format changes are backward-detectable.
- **INV-CART-DIGEST-BOUND**: The capability envelope is cryptographically
  bound to the artifact identity via a SHA-256 digest.
- **INV-CART-DETERMINISTIC**: All serialized outputs use BTreeMap/BTreeSet
  for deterministic ordering across platforms.
- **INV-CART-AUDIT-COMPLETE**: Every admission and enforcement decision is
  recorded in a structured audit log with stable event codes.

## Event Codes

| Code | Meaning |
|------|---------|
| CART-001 | Artifact submitted for admission |
| CART-002 | Artifact admission succeeded |
| CART-003 | Artifact admission rejected (fail-closed) |
| CART-004 | Capability envelope validated |
| CART-005 | Capability envelope validation failed |
| CART-006 | Runtime enforcement check passed |
| CART-007 | Runtime enforcement drift detected |
| CART-008 | Artifact digest verified |
| CART-009 | Artifact digest mismatch |
| CART-010 | Schema version validated |

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_CART_MISSING_ENVELOPE | Artifact has no capability envelope |
| ERR_CART_INVALID_ENVELOPE | Capability envelope fails schema validation |
| ERR_CART_DIGEST_MISMATCH | Envelope digest does not match artifact identity |
| ERR_CART_OVER_SCOPED | Envelope requests capabilities beyond maximum scope |
| ERR_CART_DRIFT_DETECTED | Runtime capability usage does not match envelope |
| ERR_CART_SCHEMA_UNKNOWN | Artifact carries an unrecognised schema version |
| ERR_CART_EMPTY_CAPABILITIES | Envelope declares zero capabilities |
| ERR_CART_DUPLICATE_ARTIFACT | Artifact ID already admitted |

## Acceptance Criteria

1. Artifact admission fails closed on missing or invalid capability contracts.
2. Runtime enforcement matches the admitted capability envelope without drift.
3. Schema version is validated; unknown versions are rejected.
4. Capability envelope is digest-bound to the artifact identity.
5. All admission and enforcement decisions produce structured audit entries.
6. BTreeMap/BTreeSet used throughout for deterministic output.
7. Minimum 20 inline unit tests covering all error paths and invariants.
8. Check script produces machine-readable JSON evidence.

## Testing Requirements

- Unit tests for every error variant and every invariant.
- Integration-level admission/rejection scenarios.
- Deterministic replay: given the same inputs, identical output.
- Structured log entries with stable event codes for triage.
