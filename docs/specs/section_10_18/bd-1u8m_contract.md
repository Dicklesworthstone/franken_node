# bd-1u8m Contract: Proof-Generation Service Interface (Backend-Agnostic)

**Bead:** bd-1u8m
**Section:** 10.18 (Verifiable Execution Fabric)
**Status:** Active

## Purpose

Implement a backend-agnostic proof generation service interface that creates
versioned, self-describing compliance proofs for receipt windows. The design
supports pluggable backends (mock/hash-based, future ZK, external proving
services) without requiring changes to the orchestration layer.

## Configuration

| Field                      | Type   | Default  | Description                                  |
|----------------------------|--------|----------|----------------------------------------------|
| `default_timeout_millis`   | u64    | 60000    | Default timeout for proof generation (ms)    |
| `max_entries_per_request`  | usize  | 256      | Max receipt entries per proof request         |
| `max_pending_requests`     | usize  | 64       | Max concurrent tracked proof requests        |

## Event Codes

| Code    | Severity | Description                           |
|---------|----------|---------------------------------------|
| PGN-001 | INFO     | Proof generation request received     |
| PGN-002 | INFO     | Proof generation started by backend   |
| PGN-003 | INFO     | Proof generation completed            |
| PGN-004 | ERROR    | Proof generation failed               |
| PGN-005 | INFO     | Backend registered or swapped         |
| PGN-006 | INFO     | Proof verification performed          |

## Error Codes

| Code                      | Description                                    |
|---------------------------|------------------------------------------------|
| ERR-PGN-BACKEND-UNAVAILABLE | Backend not available or not registered      |
| ERR-PGN-WINDOW-EMPTY      | Receipt window is empty                        |
| ERR-PGN-TIMEOUT            | Proof generation exceeded timeout              |
| ERR-PGN-INTERNAL           | Internal pipeline error                        |

## Invariants

- **INV-PGN-BACKEND-AGNOSTIC** -- The `ProofBackend` trait fully decouples proof
  generation from any specific proving system. Backends are interchangeable
  without modifying the orchestrator.
- **INV-PGN-VERSIONED-FORMAT** -- Every `ComplianceProof` carries an explicit
  `format_version` and `backend_name`, making proofs self-describing and
  forward-compatible.
- **INV-PGN-DETERMINISTIC** -- Given identical inputs and backend state, proof
  generation produces identical outputs (subject to backend determinism
  guarantees).

## Types

### ProofBackend (trait)

| Method         | Signature                                                      | Description                      |
|----------------|----------------------------------------------------------------|----------------------------------|
| `backend_name` | `fn backend_name(&self) -> &str`                               | Human-readable backend name      |
| `generate`     | `fn generate(&self, request: &ProofRequest) -> Result<..>`     | Generate compliance proof        |
| `verify`       | `fn verify(&self, proof: &ComplianceProof, entries: &[..]) -> Result<bool, ..>` | Verify proof against entries |

### MockProofBackend

Hash-based mock implementation of `ProofBackend`. Produces SHA-256 hash-chain
proofs deterministically. Suitable for testing and development.

### ComplianceProof

| Field               | Type               | Description                              |
|---------------------|--------------------|------------------------------------------|
| `proof_id`          | String             | Unique proof identifier                  |
| `format_version`    | String             | Proof format version                     |
| `receipt_window_ref`| String             | Reference to the proved receipt window   |
| `proof_data`        | Vec<u8>            | Opaque proof bytes from backend          |
| `proof_data_hash`   | String             | SHA-256 hash of proof data               |
| `generated_at_millis`| u64               | Generation timestamp                     |
| `backend_name`      | String             | Backend that produced the proof          |
| `metadata`          | BTreeMap           | Backend metadata (deterministic)         |
| `trace_id`          | String             | Trace correlation ID                     |

### ProofRequest

| Field              | Type               | Description                              |
|--------------------|--------------------|------------------------------------------|
| `request_id`       | String             | Unique request identifier                |
| `window`           | ProofWindow        | Target proof window                      |
| `entries`          | Vec                | Receipt chain entries                    |
| `timeout_millis`   | u64                | Timeout budget                           |
| `trace_id`         | String             | Trace correlation ID                     |
| `created_at_millis`| u64                | Request creation timestamp               |

### ProofStatus

| Variant      | Description                          |
|--------------|--------------------------------------|
| `Pending`    | Request received, not yet started    |
| `Generating` | Backend actively generating          |
| `Complete`   | Generation succeeded                 |
| `Failed`     | Generation failed                    |

### ProofGenerator

Orchestrator that manages proof requests and delegates to a pluggable backend.

| Method            | Description                                          |
|-------------------|------------------------------------------------------|
| `new`             | Create with backend and config                       |
| `submit_request`  | Submit proof generation request                      |
| `generate_proof`  | Execute proof generation for a pending request       |
| `verify_proof`    | Verify a compliance proof                            |
| `enforce_timeouts`| Mark timed-out requests as failed                    |
| `status_counts`   | Get request status counts                            |
| `swap_backend`    | Hot-swap to a new backend                            |

## Acceptance Criteria

1. `ProofBackend` trait is backend-agnostic (mock, hash-based, future ZK).
2. `MockProofBackend` implements hash-based proof generation.
3. `ComplianceProof` format is versioned (`format_version`) and self-describing
   (`backend_name`).
4. `ProofGenerator` orchestrates proof creation from receipt windows.
5. Event codes PGN-001 through PGN-006 are emitted at appropriate points.
6. Error codes ERR-PGN-BACKEND-UNAVAILABLE, ERR-PGN-WINDOW-EMPTY,
   ERR-PGN-TIMEOUT are used for classified failures.
7. Proof generation is deterministic for identical inputs (INV-PGN-DETERMINISTIC).
8. >= 25 unit tests covering all invariants and error paths.
9. Verification script `scripts/check_proof_generator.py` passes.
10. Evidence artifacts in `artifacts/section_10_18/bd-1u8m/`.

## Dependencies

- bd-3g4k: Receipt chain (provides `ReceiptChainEntry`)
- bd-28u0: Proof scheduler (provides `ProofWindow`)

## Validation Gates

- Checker: `python3 scripts/check_proof_generator.py --json`
- Checker self-test: `python3 scripts/check_proof_generator.py --self-test`
- Unit tests: `python3 -m pytest -q tests/test_check_proof_generator.py`

## File Layout

```
docs/specs/section_10_18/bd-1u8m_contract.md     (this file)
crates/franken-node/src/vef/proof_generator.rs
scripts/check_proof_generator.py
tests/test_check_proof_generator.py
artifacts/section_10_18/bd-1u8m/verification_evidence.json
artifacts/section_10_18/bd-1u8m/verification_summary.md
```
