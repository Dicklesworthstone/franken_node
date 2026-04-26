#![cfg(loom)]

//! Run with:
//! `RUSTFLAGS="--cfg loom" cargo test --release --test operator_process_start_initialization_loom`

#[test]
fn process_start_initialization_has_one_winner_under_all_interleavings() {
    frankenengine_node::api::operator_routes::process_start_initialization_loom_model();
}

#[test]
fn operator_config_initialization_has_one_winner_under_all_interleavings() {
    frankenengine_node::api::operator_routes::operator_config_initialization_loom_model();
}
