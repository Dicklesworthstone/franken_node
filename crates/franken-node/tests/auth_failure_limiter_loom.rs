#![cfg(loom)]

//! Run with:
//! `RUSTFLAGS="--cfg loom" cargo test --release --test auth_failure_limiter_loom`

#[test]
fn auth_failure_limiter_cardinality_is_bounded() {
    frankenengine_node::api::middleware::auth_failure_limiter_cardinality_loom_model();
}