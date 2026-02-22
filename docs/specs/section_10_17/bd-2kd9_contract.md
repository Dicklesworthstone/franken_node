# bd-2kd9: Claim Compiler and Public Trust Scoreboard Pipeline

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-2kd9 |
| Section | 10.17 |
| Title | Implement claim compiler and public trust scoreboard pipeline |
| Type | task |

## Purpose

External claims entering the franken_node radical expansion track must compile
to executable evidence contracts before they influence trust decisions. The claim
compiler validates, normalises, and compiles raw claim text into structured
`CompiledClaim` objects that carry evidence links and provenance metadata.
Unverifiable or malformed claim text is rejected at compile time (fail-closed).

The public trust scoreboard aggregates compiled claims into a deterministic,
signed scoreboard snapshot. Each score entry publishes evidence links so that
any observer can independently verify trust scores. The scoreboard updates are
atomic: partial updates never become visible.

The pipeline enables:
- Machine-readable compilation of external claims to evidence contracts.
- Fail-closed rejection of unverifiable or malformed claim text.
- Deterministic trust score aggregation with BTreeMap ordering.
- Signed evidence links on every scoreboard publication.
- Schema-versioned output for backward-compatible evolution.
- Complete audit trail with stable event and error codes.

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_17/bd-2kd9_contract.md` |
| Rust module | `crates/franken-node/src/connector/claim_compiler.rs` |
| Check script | `scripts/check_claim_compiler.py` |
| Test suite | `tests/test_check_claim_compiler.py` |
| Evidence | `artifacts/section_10_17/bd-2kd9/verification_evidence.json` |
| Summary | `artifacts/section_10_17/bd-2kd9/verification_summary.md` |

## Invariants

- **INV-CLMC-FAIL-CLOSED**: The claim compiler rejects any claim with missing,
  empty, or malformed fields. No unverifiable claim compiles to an evidence
  contract. This is enforced at the `compile_claim` entry point.
- **INV-CLMC-EVIDENCE-LINKED**: Every compiled claim carries at least one
  evidence link. Compilation without evidence links is an error.
- **INV-CLMC-SCOREBOARD-ATOMIC**: Scoreboard updates are atomic; partial updates
  are never visible. The scoreboard either reflects all compiled claims in a
  batch or none of them.
- **INV-CLMC-DETERMINISTIC**: All serialized outputs use BTreeMap/BTreeSet for
  deterministic ordering across platforms. Two identical input batches produce
  byte-identical scoreboard snapshots.
- **INV-CLMC-SIGNED-EVIDENCE**: Every scoreboard publication carries a SHA-256
  digest binding the evidence links to the scoreboard state.
- **INV-CLMC-SCHEMA-VERSIONED**: Every compiled claim and scoreboard snapshot
  carries a schema version string. Format changes are backward-detectable.
- **INV-CLMC-AUDIT-COMPLETE**: Every compilation and scoreboard update decision
  is recorded in a structured audit log with stable event codes.

## Event Codes

| Code | Meaning |
|------|---------|
| CLMC_001 | Claim submitted for compilation |
| CLMC_002 | Claim compilation succeeded |
| CLMC_003 | Claim compilation rejected (fail-closed) |
| CLMC_004 | Scoreboard update started |
| CLMC_005 | Scoreboard update committed |
| CLMC_006 | Scoreboard update rolled back |
| CLMC_007 | Evidence link validated |
| CLMC_008 | Evidence link validation failed |
| CLMC_009 | Scoreboard snapshot signed |
| CLMC_010 | Scoreboard snapshot digest verified |

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_CLMC_EMPTY_CLAIM_TEXT | Claim text is empty or whitespace-only |
| ERR_CLMC_MISSING_SOURCE | Claim source metadata is missing |
| ERR_CLMC_NO_EVIDENCE_LINKS | Claim has zero evidence links |
| ERR_CLMC_INVALID_EVIDENCE_LINK | An evidence link fails URI validation |
| ERR_CLMC_DUPLICATE_CLAIM_ID | Claim ID already exists in the scoreboard |
| ERR_CLMC_SCOREBOARD_FULL | Scoreboard has reached maximum capacity |
| ERR_CLMC_DIGEST_MISMATCH | Computed digest does not match expected |
| ERR_CLMC_SCHEMA_UNKNOWN | Unrecognised schema version in input |

## Acceptance Criteria

1. External claims compile to executable evidence contracts; unverifiable claim
   text is blocked at compile time.
2. Scoreboard updates publish signed evidence links on every commit.
3. BTreeMap/BTreeSet used throughout for deterministic output.
4. Schema version is carried on every compiled claim and scoreboard snapshot.
5. All compilation and scoreboard decisions produce structured audit entries
   with stable event codes.
6. Minimum 20 inline Rust unit tests covering all error paths and invariants.
7. Check script produces machine-readable JSON evidence.
8. Scoreboard capacity is bounded with a configurable maximum (default 10000).

## Testing Requirements

- Unit tests for every error variant and every invariant.
- Deterministic replay: given the same inputs, identical output.
- Structured log entries with stable event codes for triage.
- Python checker verifies Rust source for required tokens, codes, and invariants.
