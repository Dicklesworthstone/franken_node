#![cfg(loom)]

//! Run with:
//! `RUSTFLAGS="--cfg loom" rch exec -- cargo test --release --test remote_cap_replay_token_set_loom`

#[test]
fn replay_token_set_duplicate_insert_is_atomic() {
    frankenengine_node::security::remote_cap::replay_token_set_duplicate_insert_is_atomic_loom_model();
}
