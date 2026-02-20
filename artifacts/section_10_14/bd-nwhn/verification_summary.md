# bd-nwhn Verification Summary

## Root Pointer Atomic Publication Protocol

- **Section:** 10.14
- **Status:** PASS
- **Implementation:** `crates/franken-node/src/control_plane/root_pointer.rs`
- **Integration Test:** `tests/integration/root_pointer_crash_safety.rs`
- **Spec:** `docs/specs/root_publication_protocol.md`

## Verified Properties

- Canonical publication order is enforced: `write_temp -> fsync_temp -> rename -> fsync_dir`.
- Crash injection at each protocol boundary yields canonical root state of either old or new value.
- Epoch regression (`attempted <= current`) is blocked with stable error code `EPOCH_REGRESSION_BLOCKED`.
- Root publication emits signed control event payloads with verifiable signatures.
- Concurrent publish calls are serialized by process-level lock.

## Artifacts

- Crash matrix: `artifacts/10.14/root_publication_crash_matrix.csv`
- Machine evidence: `artifacts/section_10_14/bd-nwhn/verification_evidence.json`
