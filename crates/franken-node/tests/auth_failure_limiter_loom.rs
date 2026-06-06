#![cfg(loom)]

//! Run with:
//! `rch exec -- env RUSTFLAGS="--cfg loom" cargo test --release --features control-plane,loom-models --test auth_failure_limiter_loom`

#[test]
fn auth_failure_limiter_cardinality_is_bounded() {
    frankenengine_node::api::middleware::auth_failure_limiter_cardinality_loom_model();
}
