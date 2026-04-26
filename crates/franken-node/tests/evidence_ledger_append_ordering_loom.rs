#![cfg(loom)]

//! Loom model for SharedEvidenceLedger concurrent append operations.
//!
//! Run with:
//! `RUSTFLAGS="--cfg loom" cargo test --release --test evidence_ledger_append_ordering_loom`

#[test]
fn shared_evidence_ledger_concurrent_append_is_deterministic() {
    frankenengine_node::observability::evidence_ledger::shared_evidence_ledger_concurrent_append_loom_model();
}