use frankenengine_node::connector::cancellation_protocol::assert_cancellation_protocol_conformance_for_tests;

#[test]
fn cancellation_protocol_transition_conformance_matrix() {
    assert_cancellation_protocol_conformance_for_tests();
}
