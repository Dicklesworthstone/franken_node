#![cfg(loom)]

//! Run with:
//! `rch exec -- env RUSTFLAGS="--cfg loom" cargo test --release --features loom-models --test remote_cap_replay_token_set_loom`

#[test]
fn replay_token_set_duplicate_insert_is_atomic() {
    frankenengine_node::security::remote_cap::replay_token_set_duplicate_insert_is_atomic_loom_model();
}
