#![cfg(loom)]

//! Run with:
//! `RUSTFLAGS="--cfg loom" cargo test --release replay_token_set_duplicate_insert_is_atomic -- --exact`
//!
//! The loom model lives in `security::remote_cap` so it can reuse private
//! replay-token internals while keeping `loom` as a dev-dependency only.
