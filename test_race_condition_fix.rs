//! Historical non-authoritative artifact for bd-wvxof.
//!
//! This root-level file is intentionally not a registered Cargo test. It does
//! not exercise `ValidationProofCoalescerStore::steal_stale_lease`, advisory
//! file locks, or the production lease store, and it must not be cited as
//! implementation evidence.
//!
//! Authoritative coverage lives in:
//! `crates/franken-node/tests/validation_proof_coalescer.rs`.

fn main() {
    eprintln!(
        "test_race_condition_fix.rs is historical and non-authoritative; \
         run the registered validation_proof_coalescer tests for proof."
    );
    eprintln!(
        "authoritative command: rch exec -- cargo test -p frankenengine-node \
         --test validation_proof_coalescer steal_stale_lease -- --nocapture"
    );
    std::process::exit(2);
}
