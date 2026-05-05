use frankenengine_node::ops::telemetry_bridge::{
    assert_persistence_loop_batches_ready_envelopes_for_tests,
    assert_slowloris_partial_fragments_exceed_cap_after_timeout_shed_for_tests,
    assert_socket_lock_blocks_stale_cleanup_for_tests,
};

/// Integration test for telemetry_bridge slowloris regression
///
/// This test was previously in telemetry_bridge.rs #[cfg(test)] but those
/// tests were dead code because the lib target has `test = false` in Cargo.toml.
///
/// Referenced in bd-28p1b: ensure slowloris protection regression tests are executable.
#[test]
fn slowloris_partial_fragments_exceed_cap_after_timeout_shed() {
    assert_slowloris_partial_fragments_exceed_cap_after_timeout_shed_for_tests();
}

/// Integration test for socket lock cross-process serialization
///
/// This test ensures that socket cleanup operations are properly serialized
/// across processes to prevent race conditions that could orphan telemetry routing.
#[test]
fn socket_lock_blocks_stale_cleanup() {
    assert_socket_lock_blocks_stale_cleanup_for_tests();
}

/// Integration test for batched telemetry persistence.
///
/// Keeps the persistence batching regression executable from the registered
/// integration target because the module's inline tests are not compiled.
#[test]
fn persistence_loop_batches_ready_envelopes() {
    assert_persistence_loop_batches_ready_envelopes_for_tests();
}
