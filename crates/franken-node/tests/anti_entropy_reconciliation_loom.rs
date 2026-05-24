#![cfg(loom)]

//! Loom model for AntiEntropyReconciler concurrent reconciliation operations.
//!
//! Run with:
//! `RUSTFLAGS="--cfg loom" rch exec -- cargo test --release --test anti_entropy_reconciliation_loom`

#[test]
fn anti_entropy_concurrent_reconciliation_is_deterministic() {
    frankenengine_node::runtime::anti_entropy::anti_entropy_concurrent_reconciliation_loom_model();
}