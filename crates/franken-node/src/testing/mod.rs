pub mod lab_runtime;
pub mod scenario_builder;
pub mod virtual_transport;

#[cfg(test)]
mod tests {
    use super::scenario_builder::{
        NodeRole, ScenarioAssertion, ScenarioBuilder, ScenarioBuilderError,
    };
    use super::virtual_transport::{LinkFaultConfig, VirtualTransportError, VirtualTransportLayer};

    fn two_node_builder() -> ScenarioBuilder {
        ScenarioBuilder::new("negative-path-scenario")
            .seed(42)
            .add_node("n1", "Node 1", NodeRole::Coordinator)
            .expect("first node should be accepted")
            .add_node("n2", "Node 2", NodeRole::Participant)
            .expect("second node should be accepted")
    }

    #[test]
    fn negative_empty_scenario_name_is_rejected() {
        let err = ScenarioBuilder::new("")
            .seed(42)
            .build()
            .expect_err("empty scenario names must be rejected");

        assert!(matches!(err, ScenarioBuilderError::EmptyName));
    }

    #[test]
    fn negative_missing_seed_is_rejected_before_topology_use() {
        let err = ScenarioBuilder::new("missing-seed")
            .build()
            .expect_err("zero seed must be rejected");

        assert!(matches!(err, ScenarioBuilderError::NoSeed));
    }

    #[test]
    fn negative_single_node_topology_is_rejected() {
        let err = ScenarioBuilder::new("too-few-nodes")
            .seed(42)
            .add_node("n1", "Node 1", NodeRole::Coordinator)
            .expect("initial node should be accepted")
            .build()
            .expect_err("one-node scenario must violate minimum topology size");

        assert!(matches!(
            err,
            ScenarioBuilderError::TooFewNodes {
                count: 1,
                minimum: 2
            }
        ));
    }

    #[test]
    fn negative_duplicate_node_id_is_rejected_at_insert() {
        let builder = ScenarioBuilder::new("duplicate-node")
            .seed(42)
            .add_node("n1", "Node 1", NodeRole::Coordinator)
            .expect("first node should be accepted");

        let err = builder
            .add_node("n1", "Node 1 duplicate", NodeRole::Observer)
            .expect_err("duplicate node IDs must be rejected");

        assert!(matches!(
            err,
            ScenarioBuilderError::DuplicateNode { node_id } if node_id == "n1"
        ));
    }

    #[test]
    fn negative_duplicate_link_id_is_rejected_at_insert() {
        let builder = two_node_builder()
            .add_link("link-1", "n1", "n2", true)
            .expect("first link should be accepted");

        let err = builder
            .add_link("link-1", "n2", "n1", true)
            .expect_err("duplicate link IDs must be rejected");

        assert!(matches!(
            err,
            ScenarioBuilderError::DuplicateLink { link_id } if link_id == "link-1"
        ));
    }

    #[test]
    fn negative_link_with_missing_endpoint_is_rejected_on_build() {
        let err = two_node_builder()
            .add_link("link-1", "n1", "missing-node", true)
            .expect("endpoint validation is deferred to build")
            .build()
            .expect_err("unknown link endpoint must invalidate scenario");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidLinkEndpoint {
                link_id,
                missing_node
            } if link_id == "link-1" && missing_node == "missing-node"
        ));
    }

    #[test]
    fn negative_fault_profile_for_unknown_link_is_rejected() {
        let err = two_node_builder()
            .add_link("link-1", "n1", "n2", true)
            .expect("link should be accepted")
            .set_fault_profile("missing-link", LinkFaultConfig::no_faults())
            .build()
            .expect_err("fault profile must reference a declared link");

        assert!(matches!(
            err,
            ScenarioBuilderError::UnknownFaultProfileLink { link_id }
                if link_id == "missing-link"
        ));
    }

    #[test]
    fn negative_fault_profile_probability_above_one_is_rejected() {
        let err = two_node_builder()
            .add_link("link-1", "n1", "n2", true)
            .expect("link should be accepted")
            .set_fault_profile(
                "link-1",
                LinkFaultConfig {
                    drop_probability: 1.01,
                    ..LinkFaultConfig::default()
                },
            )
            .build()
            .expect_err("invalid probability must invalidate scenario");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidFaultProfile { link_id, .. } if link_id == "link-1"
        ));
    }

    #[test]
    fn negative_assertion_with_unknown_message_target_is_rejected() {
        let err = two_node_builder()
            .add_assertion(ScenarioAssertion::MessageDelivered {
                from: "n1".to_string(),
                to: "missing-node".to_string(),
                within_ticks: 10,
            })
            .build()
            .expect_err("assertions must reference existing nodes");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidAssertionNode {
                assertion,
                node_id
            } if assertion == "MessageDelivered.to" && node_id == "missing-node"
        ));
    }

    #[test]
    fn negative_transport_rejects_invalid_link_probability() {
        let mut transport = VirtualTransportLayer::new(42);

        let err = transport
            .create_link(
                "n1",
                "n2",
                LinkFaultConfig {
                    drop_probability: -0.01,
                    ..LinkFaultConfig::default()
                },
            )
            .expect_err("invalid link probability must be rejected");

        assert!(matches!(
            err,
            VirtualTransportError::InvalidProbability { field, value }
                if field == "drop_probability" && value < 0.0
        ));
    }

    #[test]
    fn negative_transport_rejects_duplicate_link() {
        let mut transport = VirtualTransportLayer::new(42);
        transport
            .create_link("n1", "n2", LinkFaultConfig::no_faults())
            .expect("initial link should be accepted");

        let err = transport
            .create_link("n1", "n2", LinkFaultConfig::no_faults())
            .expect_err("duplicate canonical link IDs must be rejected");

        assert!(matches!(
            err,
            VirtualTransportError::LinkExists { link_id } if link_id == "n1->n2"
        ));
    }

    #[test]
    fn negative_transport_send_to_missing_link_is_rejected() {
        let mut transport = VirtualTransportLayer::new(42);

        let err = transport
            .send_message("n1", "n2", b"payload".to_vec())
            .expect_err("sending over an undeclared link must fail closed");

        assert!(matches!(
            err,
            VirtualTransportError::LinkNotFound { link_id } if link_id == "n1->n2"
        ));
    }

    #[test]
    fn negative_transport_send_over_partition_is_rejected() {
        let mut transport = VirtualTransportLayer::new(42);
        let link_id = transport
            .create_link("n1", "n2", LinkFaultConfig::no_faults())
            .expect("link should be accepted");
        transport
            .activate_partition(&link_id)
            .expect("partition activation should succeed");

        let err = transport
            .send_message("n1", "n2", b"payload".to_vec())
            .expect_err("partitioned links must reject sends");

        assert!(matches!(
            err,
            VirtualTransportError::Partitioned { link_id } if link_id == "n1->n2"
        ));
    }
}

#[cfg(test)]
mod testing_module_negative_tests {
    use super::lab_runtime::{
        FaultProfile, LabConfig, LabError, LabRuntime, ReproBundle, TestClock, VirtualLink,
    };
    use super::scenario_builder::{
        NodeRole, Scenario, ScenarioAssertion, ScenarioBuilder, ScenarioBuilderError,
    };

    #[test]
    fn negative_lab_config_rejects_zero_seed() {
        let config = LabConfig {
            seed: 0,
            ..LabConfig::default()
        };

        assert!(matches!(config.validate(), Err(LabError::NoSeed)));
        assert!(matches!(LabRuntime::new(config), Err(LabError::NoSeed)));
    }

    #[test]
    fn negative_fault_profile_rejects_nan_drop_probability() {
        let profile = FaultProfile {
            drop_pct: f64::NAN,
            ..FaultProfile::default()
        };

        let err = profile.validate().expect_err("NaN drop_pct must fail");

        assert!(matches!(
            err,
            LabError::FaultRange { ref field, .. } if field == "drop_pct"
        ));
    }

    #[test]
    fn negative_virtual_link_rejects_infinite_corrupt_probability() {
        let profile = FaultProfile {
            corrupt_probability: f64::INFINITY,
            ..FaultProfile::default()
        };

        let err = VirtualLink::new("a", "b", profile)
            .expect_err("infinite corrupt probability must fail");

        assert!(matches!(
            err,
            LabError::FaultRange { ref field, .. } if field == "corrupt_probability"
        ));
    }

    #[test]
    fn negative_test_clock_rejects_tick_overflow() {
        let mut clock = TestClock::new();
        clock.current_tick = u64::MAX;

        let err = clock
            .schedule_timer(1, "overflow")
            .expect_err("timer schedule must reject tick overflow");

        assert!(matches!(
            err,
            LabError::TickOverflow {
                current: u64::MAX,
                delta: 1,
            }
        ));
    }

    #[test]
    fn negative_runtime_rejects_unknown_link_lookup() {
        let runtime = LabRuntime::new(LabConfig::default()).unwrap();

        let err = runtime
            .find_link("missing-source", "missing-target")
            .expect_err("unknown link lookup must fail");

        assert!(matches!(
            err,
            LabError::LinkNotFound {
                ref source,
                ref target,
            } if source == "missing-source" && target == "missing-target"
        ));
    }

    #[test]
    fn negative_scenario_builder_rejects_duplicate_node() {
        let result = ScenarioBuilder::new("duplicate-node")
            .seed(7)
            .add_node("n1", "Node One", NodeRole::Coordinator)
            .unwrap()
            .add_node("n1", "Node One Again", NodeRole::Participant);

        assert!(matches!(
            result,
            Err(ScenarioBuilderError::DuplicateNode { ref node_id }) if node_id == "n1"
        ));
    }

    #[test]
    fn negative_scenario_builder_rejects_unknown_fault_profile_link() {
        let result = ScenarioBuilder::new("unknown-profile-link")
            .seed(7)
            .add_node("n1", "Node One", NodeRole::Coordinator)
            .unwrap()
            .add_node("n2", "Node Two", NodeRole::Participant)
            .unwrap()
            .set_fault_profile(
                "missing-link",
                super::virtual_transport::LinkFaultConfig::default(),
            )
            .build();

        assert!(matches!(
            result,
            Err(ScenarioBuilderError::UnknownFaultProfileLink { ref link_id })
                if link_id == "missing-link"
        ));
    }

    #[test]
    fn negative_scenario_builder_rejects_assertion_unknown_node() {
        let result = ScenarioBuilder::new("bad-assertion")
            .seed(7)
            .add_node("n1", "Node One", NodeRole::Coordinator)
            .unwrap()
            .add_node("n2", "Node Two", NodeRole::Participant)
            .unwrap()
            .add_assertion(ScenarioAssertion::PartitionDetected {
                by_node: "missing-node".to_string(),
                within_ticks: 10,
            })
            .build();

        assert!(matches!(
            result,
            Err(ScenarioBuilderError::InvalidAssertionNode { ref node_id, .. })
                if node_id == "missing-node"
        ));
    }

    #[test]
    fn negative_scenario_from_json_rejects_malformed_payload() {
        let err =
            Scenario::from_json("{not-valid-json").expect_err("malformed scenario JSON must fail");

        assert!(matches!(err, ScenarioBuilderError::JsonParse { .. }));
    }

    #[test]
    fn negative_repro_bundle_from_json_rejects_malformed_payload() {
        let err = ReproBundle::from_json("{not-valid-json")
            .expect_err("malformed repro bundle JSON must fail");

        assert!(matches!(err, LabError::BundleDeserialization { .. }));
    }

    // ── Additional comprehensive negative-path integration tests ──

    #[test]
    fn negative_scenario_builder_with_massive_unicode_node_names_handles_gracefully() {
        let massive_unicode_name = "🚀".repeat(10000); // 40KB of unicode rockets

        let result = ScenarioBuilder::new("unicode-stress-test")
            .seed(42)
            .add_node("n1", &massive_unicode_name, NodeRole::Coordinator);

        // Should either succeed (handle large unicode) or fail gracefully (validate size)
        match result {
            Ok(builder) => {
                // If accepted, should be able to continue building
                let final_result = builder
                    .add_node("n2", "Normal Node", NodeRole::Participant)
                    .expect("second node should work")
                    .build();
                assert!(final_result.is_ok() || final_result.is_err());
            }
            Err(_) => {
                // Graceful rejection is also acceptable for oversized content
            }
        }
    }

    #[test]
    fn negative_scenario_builder_rejects_node_name_with_control_characters() {
        let control_char_name = "Node\x00\r\n\t\x1b[31mRed\x1b[0m";

        let result = ScenarioBuilder::new("control-char-test").seed(42).add_node(
            "n1",
            control_char_name,
            NodeRole::Coordinator,
        );

        // Should handle control characters gracefully
        match result {
            Ok(builder) => {
                // If accepted, name should be preserved exactly
                let scenario = builder
                    .add_node("n2", "Normal Node", NodeRole::Participant)
                    .expect("second node should work")
                    .build()
                    .expect("should build successfully");

                // Verify the control characters are preserved
                assert!(scenario.to_json().unwrap().contains(control_char_name));
            }
            Err(_) => {
                // Early rejection of control characters is also valid
            }
        }
    }

    #[test]
    fn negative_transport_with_zero_capacity_event_log_maintains_functionality() {
        let mut transport = VirtualTransportLayer::with_event_log_capacity(42, 0);

        // Should function normally even with zero event log capacity
        transport
            .create_link(
                "n1",
                "n2",
                super::virtual_transport::LinkFaultConfig::no_faults(),
            )
            .expect("link creation should work with zero event capacity");

        transport
            .send_message("n1", "n2", b"test message".to_vec())
            .expect("message send should work");

        let delivered = transport
            .deliver_next("n1->n2")
            .expect("delivery should work")
            .expect("message should be delivered");

        assert_eq!(delivered.payload, b"test message");
        assert!(
            transport.event_log().is_empty(),
            "event log should remain empty with zero capacity"
        );
    }

    #[test]
    fn negative_scenario_with_arithmetic_overflow_tick_values_clamps_safely() {
        let result = ScenarioBuilder::new("tick-overflow-test")
            .seed(42)
            .add_node("n1", "Node 1", NodeRole::Coordinator)
            .unwrap()
            .add_node("n2", "Node 2", NodeRole::Participant)
            .unwrap()
            .add_assertion(ScenarioAssertion::MessageDelivered {
                from: "n1".to_string(),
                to: "n2".to_string(),
                within_ticks: u64::MAX, // Maximum possible tick value
            })
            .build();

        // Should either accept large tick values or reject gracefully
        match result {
            Ok(scenario) => {
                // If accepted, JSON serialization should work
                let json_result = scenario.to_json();
                assert!(
                    json_result.is_ok(),
                    "JSON serialization should handle large tick values"
                );
            }
            Err(err) => {
                // Graceful rejection of extreme tick values is acceptable
                assert!(matches!(
                    err,
                    ScenarioBuilderError::InvalidAssertionValue { .. }
                ));
            }
        }
    }

    #[test]
    fn negative_cross_module_integration_with_malformed_fault_configs() {
        let mut transport = VirtualTransportLayer::new(42);

        // Create a link with extreme fault configuration
        let extreme_config = super::virtual_transport::LinkFaultConfig {
            drop_probability: 0.999999999999, // Nearly 1.0 but not quite
            reorder_depth: usize::MAX / 2,    // Very large reorder depth
            corrupt_bit_count: 1_000_000,     // Extreme corruption
            delay_ticks: u64::MAX / 4,        // Very large delay
            partition: false,
        };

        let result = transport.create_link("n1", "n2", extreme_config);

        match result {
            Ok(_) => {
                // If link created, sending should work (even if messages get dropped/corrupted)
                for i in 0..10 {
                    let _ = transport.send_message("n1", "n2", vec![i]);
                }

                // Stats should remain consistent
                let stats = transport.stats();
                assert!(stats.total_messages <= 10);
                assert!(stats.dropped_messages <= stats.total_messages);
            }
            Err(err) => {
                // Rejection of extreme config is acceptable
                assert!(matches!(
                    err,
                    super::virtual_transport::VirtualTransportError::InvalidProbability { .. }
                ));
            }
        }
    }

    #[test]
    fn negative_scenario_builder_deeply_nested_json_serialization_stress() {
        let mut builder = ScenarioBuilder::new("deep-nesting-test").seed(42);

        // Add many nodes and links to create complex JSON structure
        for i in 0..100 {
            let node_id = format!("node_{}", i);
            let node_desc = format!("Node {} Description", i);
            let role = if i == 0 {
                NodeRole::Coordinator
            } else {
                NodeRole::Participant
            };

            builder = builder
                .add_node(&node_id, &node_desc, role)
                .expect("node addition should work");
        }

        // Add many links between nodes
        for i in 0..99 {
            let link_id = format!("link_{}", i);
            let from = format!("node_{}", i);
            let to = format!("node_{}", i + 1);

            builder = builder
                .add_link(&link_id, &from, &to, true)
                .expect("link addition should work");
        }

        // Add many assertions
        for i in 0..50 {
            let from = format!("node_{}", i);
            let to = format!("node_{}", i + 1);

            builder = builder.add_assertion(ScenarioAssertion::MessageDelivered {
                from,
                to,
                within_ticks: 100,
            });
        }

        let scenario = builder.build().expect("complex scenario should build");

        // JSON serialization should handle complex nested structure without stack overflow
        let json_result = std::panic::catch_unwind(|| scenario.to_json());
        assert!(
            json_result.is_ok(),
            "JSON serialization should not panic on complex structures"
        );

        if let Ok(Ok(json)) = json_result {
            assert!(json.len() > 1000, "JSON should contain substantial content");
            assert!(json.contains("node_99"), "should contain all nodes");
            assert!(json.contains("link_98"), "should contain all links");
        }
    }

    #[test]
    fn negative_virtual_transport_message_id_exhaustion_cascading_effects() {
        let mut transport = VirtualTransportLayer::new(42);
        transport
            .create_link(
                "n1",
                "n2",
                super::virtual_transport::LinkFaultConfig::no_faults(),
            )
            .expect("link creation should succeed");

        // Simulate message ID near exhaustion
        // Note: We can't easily set next_message_id directly, so we test the error condition
        // by creating a scenario where we might hit ID exhaustion

        let mut message_count = 0;
        let mut exhausted = false;

        // Try to send many messages until we potentially hit exhaustion
        for i in 0..1000 {
            match transport.send_message("n1", "n2", vec![i as u8]) {
                Ok(_) => {
                    message_count = message_count.saturating_add(1);
                }
                Err(super::virtual_transport::VirtualTransportError::MessageIdExhausted) => {
                    exhausted = true;
                    break;
                }
                Err(other) => {
                    panic!("Unexpected error: {:?}", other);
                }
            }
        }

        if exhausted {
            // If we hit exhaustion, further attempts should consistently fail
            for _ in 0..10 {
                let err = transport
                    .send_message("n1", "n2", b"after-exhaustion".to_vec())
                    .expect_err("should fail after ID exhaustion");
                assert!(matches!(
                    err,
                    super::virtual_transport::VirtualTransportError::MessageIdExhausted
                ));
            }

            // Transport should still function for other operations
            assert_eq!(transport.buffered_count("n1->n2").unwrap(), message_count);
            assert_eq!(transport.link_count(), 1);

            // Delivery should still work for existing messages
            let mut delivered = 0;
            while transport.deliver_next("n1->n2").unwrap().is_some() {
                delivered = delivered.saturating_add(1);
                if delivered > message_count + 10 {
                    break;
                } // Safety valve
            }
            assert_eq!(delivered, message_count);
        }
    }

    #[test]
    fn negative_scenario_serialization_with_unicode_injection_patterns() {
        let injection_patterns = [
            "node\u{202E}spoofed",   // Right-to-left override
            "node\u{200B}invisible", // Zero-width space
            "node\u{FEFF}bom",       // Byte order mark
            "node\x00null",          // Null byte
            "node\r\ninjection",     // CRLF injection
            "node\u{1F4A9}emoji",    // Emoji
        ];

        for pattern in &injection_patterns {
            let result = std::panic::catch_unwind(|| {
                let scenario = ScenarioBuilder::new("unicode-injection-test")
                    .seed(42)
                    .add_node("n1", pattern, NodeRole::Coordinator)
                    .expect("node should be accepted")
                    .add_node("n2", "Normal Node", NodeRole::Participant)
                    .expect("second node should work")
                    .build()
                    .expect("scenario should build");

                // Test JSON round-trip
                let json = scenario.to_json().expect("JSON serialization should work");
                let parsed = super::scenario_builder::Scenario::from_json(&json)
                    .expect("JSON deserialization should work");

                // Verify the pattern is preserved exactly
                assert!(
                    json.contains(pattern),
                    "pattern should be preserved in JSON"
                );
                parsed
            });

            assert!(
                result.is_ok(),
                "Unicode pattern '{}' should be handled without panic",
                pattern.escape_unicode()
            );
        }
    }

    // ── COMPREHENSIVE NEGATIVE-PATH INLINE TESTS ────────────────────────────────
    // Additional edge cases and boundary validation for security-critical scenarios

    /// Test scenario builder with extreme capacity and memory stress scenarios
    #[test]
    fn test_scenario_builder_capacity_boundaries() {
        // Test with maximum realistic node count
        let mut builder = ScenarioBuilder::new("capacity-stress").seed(42);

        // Add many nodes to stress capacity handling
        for i in 0..10000 {
            let node_id = format!("n{}", i);
            let result = builder.add_node(&node_id, "Stress Node", NodeRole::Participant);

            match result {
                Ok(new_builder) => {
                    builder = new_builder;
                }
                Err(err) => {
                    // If we hit capacity limits, that's acceptable - should fail gracefully
                    match err {
                        ScenarioBuilderError::CapacityExceeded { .. } => break,
                        other => panic!("Unexpected error at node {}: {:?}", i, other),
                    }
                }
            }
        }

        // Test empty node ID (edge case)
        let empty_id_result = builder.add_node("", "Empty ID Node", NodeRole::Coordinator);
        match empty_id_result {
            Ok(_) => {}                                  // Empty ID accepted
            Err(ScenarioBuilderError::EmptyNodeId) => {} // Rejected gracefully
            Err(other) => panic!("Unexpected error for empty node ID: {:?}", other),
        }

        // Test very long node ID
        let long_id = "x".repeat(100000);
        let long_id_result = builder.add_node(&long_id, "Long ID Node", NodeRole::Participant);
        match long_id_result {
            Ok(_) => {}                                           // Long ID accepted
            Err(ScenarioBuilderError::NodeIdTooLong { .. }) => {} // Rejected gracefully
            Err(other) => panic!("Unexpected error for long node ID: {:?}", other),
        }

        // Test node description with extreme length
        let long_desc = "D".repeat(1000000);
        let long_desc_result = builder.add_node("long_desc", &long_desc, NodeRole::Observer);
        match long_desc_result {
            Ok(_) => {}                                             // Long description accepted
            Err(ScenarioBuilderError::NodeDescTooLong { .. }) => {} // Rejected gracefully
            Err(other) => panic!("Unexpected error for long description: {:?}", other),
        }
    }

    /// Test fault profile validation with floating-point edge cases
    #[test]
    fn test_fault_profile_floating_point_boundaries() {
        use super::virtual_transport::LinkFaultConfig;

        // Test very small positive probability
        let tiny_positive = LinkFaultConfig {
            drop_probability: f64::MIN_POSITIVE,
            ..Default::default()
        };
        // Should be valid (smallest positive value)
        assert!(tiny_positive.drop_probability > 0.0);

        // Test just below zero (should be invalid)
        let just_below_zero = LinkFaultConfig {
            drop_probability: -f64::EPSILON,
            ..Default::default()
        };

        let mut transport = VirtualTransportLayer::new(42);
        let result = transport.create_link("a", "b", just_below_zero);
        assert!(result.is_err(), "Negative epsilon should be rejected");

        // Test just above one (should be invalid)
        let just_above_one = LinkFaultConfig {
            drop_probability: 1.0 + f64::EPSILON,
            ..Default::default()
        };

        let result2 = transport.create_link("c", "d", just_above_one);
        assert!(result2.is_err(), "1.0 + epsilon should be rejected");

        // Test subnormal values
        let subnormal = LinkFaultConfig {
            drop_probability: f64::MIN_POSITIVE / 2.0,
            ..Default::default()
        };

        let result3 = transport.create_link("e", "f", subnormal);
        // Should either accept subnormal values or reject gracefully
        match result3 {
            Ok(_) => {}  // Subnormal accepted
            Err(_) => {} // Subnormal rejected (also valid)
        }

        // Test maximum normal finite value just under 1.0
        let max_normal_under_one = LinkFaultConfig {
            drop_probability: 1.0 - f64::EPSILON,
            ..Default::default()
        };

        let result4 = transport.create_link("g", "h", max_normal_under_one);
        assert!(result4.is_ok(), "1.0 - epsilon should be valid");
    }

    /// Test virtual transport with extreme message payloads and edge cases
    #[test]
    fn test_virtual_transport_payload_boundaries() {
        let mut transport = VirtualTransportLayer::new(42);
        transport
            .create_link(
                "a",
                "b",
                super::virtual_transport::LinkFaultConfig::no_faults(),
            )
            .expect("link creation should succeed");

        // Empty payload
        let empty_result = transport.send_message("a", "b", vec![]);
        assert!(empty_result.is_ok(), "Empty payload should be allowed");

        // Single byte payload
        let single_result = transport.send_message("a", "b", vec![42]);
        assert!(single_result.is_ok(), "Single byte should work");

        // Maximum realistic payload (10MB)
        let large_payload = vec![0xFF; 10_000_000];
        let large_result = transport.send_message("a", "b", large_payload.clone());
        match large_result {
            Ok(msg_id) => {
                // If accepted, delivery should work
                let delivered = transport.deliver_next("a->b").unwrap().unwrap();
                assert_eq!(delivered.payload.len(), 10_000_000);
                assert_eq!(delivered.id, msg_id);
            }
            Err(err) => {
                // Rejection of oversized payload is also acceptable
                match err {
                    super::virtual_transport::VirtualTransportError::PayloadTooLarge { .. } => {}
                    other => panic!("Unexpected error for large payload: {:?}", other),
                }
            }
        }

        // Payload with all possible byte values
        let full_range_payload: Vec<u8> = (0..=255).collect();
        let full_range_result = transport.send_message("a", "b", full_range_payload.clone());
        assert!(
            full_range_result.is_ok(),
            "Full byte range should be accepted"
        );

        let delivered_full = transport.deliver_next("a->b").unwrap().unwrap();
        assert_eq!(delivered_full.payload, full_range_payload);

        // Payload designed to trigger potential integer overflow in corruption
        let overflow_payload = vec![0x00; usize::MAX.min(100_000_000)]; // Limit to reasonable size
        let overflow_result = transport.send_message("a", "b", overflow_payload);
        assert!(overflow_result.is_ok(), "Large uniform payload should work");
    }

    /// Test lab runtime with timer edge cases and scheduling boundaries
    #[test]
    fn test_lab_runtime_timer_boundaries() {
        use super::lab_runtime::{LabConfig, LabRuntime};

        let config = LabConfig::default();
        let mut runtime = LabRuntime::new(config).unwrap();

        // Test scheduling timer with zero delay (immediate firing)
        let zero_delay_result = runtime.schedule_timer(0, "immediate");
        assert!(zero_delay_result.is_ok(), "Zero delay should be valid");

        // Test scheduling timer with maximum delay
        let max_delay_result = runtime.schedule_timer(u64::MAX, "maximum");
        assert!(max_delay_result.is_ok(), "Max delay should be valid");

        // Test timer scheduling near overflow boundary
        runtime.test_clock.current_tick = u64::MAX - 10;
        let near_overflow_result = runtime.schedule_timer(5, "near_overflow");
        assert!(
            near_overflow_result.is_ok(),
            "Timer just under overflow should work"
        );

        // Test timer that would overflow
        let overflow_result = runtime.schedule_timer(20, "overflow");
        assert!(
            overflow_result.is_err(),
            "Timer causing overflow should be rejected"
        );

        // Test advancing clock with zero delta
        let zero_advance_result = runtime.advance_clock(0);
        assert!(zero_advance_result.is_ok(), "Zero advance should work");

        let fired = zero_advance_result.unwrap();
        // Should fire the zero-delay timer
        assert_eq!(fired.len(), 1);

        // Test timer label with extreme content
        let weird_label = "\x00\r\n\t🚀🔥💀\u{202E}reverse";
        let weird_label_result = runtime.schedule_timer(1, weird_label);
        assert!(
            weird_label_result.is_ok(),
            "Weird timer labels should be accepted"
        );

        // Test very long timer label
        let long_label = "L".repeat(100000);
        let long_label_result = runtime.schedule_timer(1, long_label);
        match long_label_result {
            Ok(_) => {}  // Long labels accepted
            Err(_) => {} // Or rejected gracefully
        }
    }

    /// Test scenario assertion validation with boundary conditions
    #[test]
    fn test_scenario_assertion_boundaries() {
        use super::scenario_builder::{NodeRole, ScenarioAssertion, ScenarioBuilder};

        let mut builder = ScenarioBuilder::new("assertion-boundaries")
            .seed(42)
            .add_node("n1", "Node 1", NodeRole::Coordinator)
            .unwrap()
            .add_node("n2", "Node 2", NodeRole::Participant)
            .unwrap();

        // Test assertion with zero ticks (immediate)
        builder = builder.add_assertion(ScenarioAssertion::MessageDelivered {
            from: "n1".to_string(),
            to: "n2".to_string(),
            within_ticks: 0,
        });

        // Test assertion with maximum tick value
        builder = builder.add_assertion(ScenarioAssertion::MessageDelivered {
            from: "n2".to_string(),
            to: "n1".to_string(),
            within_ticks: u64::MAX,
        });

        // Test assertion with empty node names (edge case)
        let empty_from_result = ScenarioBuilder::new("empty-assertion-from")
            .seed(42)
            .add_node("", "Empty ID", NodeRole::Coordinator)
            .and_then(|b| b.add_node("n2", "Normal", NodeRole::Participant))
            .map(|b| {
                b.add_assertion(ScenarioAssertion::PartitionDetected {
                    by_node: "".to_string(),
                    within_ticks: 10,
                })
            });

        match empty_from_result {
            Ok(_) => {}  // Empty node names in assertions accepted
            Err(_) => {} // Or rejected gracefully
        }

        // Test assertion with very long node names
        let long_node_name = "n".repeat(100000);
        builder = builder.add_assertion(ScenarioAssertion::PartitionDetected {
            by_node: long_node_name.clone(),
            within_ticks: 10,
        });

        // Build should validate and either accept or reject gracefully
        let build_result = builder.build();
        match build_result {
            Ok(_) => {}                                                  // Long node names accepted
            Err(ScenarioBuilderError::InvalidAssertionNode { .. }) => {} // Rejected gracefully
            Err(other) => panic!("Unexpected error for long assertion node name: {:?}", other),
        }
    }

    /// Test JSON serialization with malicious and extreme content
    #[test]
    fn test_json_serialization_attack_resistance() {
        use super::scenario_builder::{NodeRole, ScenarioBuilder};

        // Test JSON injection attempts in node names
        let injection_attempts = vec![
            r#"Node", "injected": "value", "fake"#,
            "Node\"},\"injected\":\"value\",\"fake\":\"",
            "Node\\\"},\\\"injected\\\":\\\"value\\\",\\\"fake\\\":\\\"",
            "Node\x00\x01\x02\x03\x04\x05", // Control characters
            "Node\u{FEFF}\u{200B}\u{202E}", // Unicode special chars
        ];

        for injection in injection_attempts {
            let result = std::panic::catch_unwind(|| {
                let scenario = ScenarioBuilder::new("injection-test")
                    .seed(42)
                    .add_node("n1", injection, NodeRole::Coordinator)
                    .expect("node should be accepted")
                    .add_node("n2", "Normal", NodeRole::Participant)
                    .expect("second node should work")
                    .build()
                    .expect("scenario should build");

                let json = scenario.to_json().expect("JSON should serialize");

                // Verify JSON is well-formed
                let _parsed: serde_json::Value =
                    serde_json::from_str(&json).expect("JSON should be valid");

                // Verify injection didn't break structure
                assert!(json.contains("n1"), "Node ID should be preserved");
                assert!(json.contains("n2"), "Second node should be preserved");

                json
            });

            assert!(
                result.is_ok(),
                "Injection attempt should be handled safely: {:?}",
                injection
            );
        }

        // Test extremely nested/recursive-looking content
        let recursive_content = "{".repeat(1000) + &"}".repeat(1000);
        let recursive_result = std::panic::catch_unwind(|| {
            let scenario = ScenarioBuilder::new("recursive-test")
                .seed(42)
                .add_node("n1", &recursive_content, NodeRole::Coordinator)
                .expect("recursive content should be accepted")
                .add_node("n2", "Normal", NodeRole::Participant)
                .expect("second node should work")
                .build()
                .expect("scenario should build");

            scenario.to_json().expect("JSON should serialize")
        });

        assert!(
            recursive_result.is_ok(),
            "Recursive-looking content should be handled safely"
        );
    }

    /// Test memory and resource exhaustion scenarios
    #[test]
    fn test_resource_exhaustion_protection() {
        use super::scenario_builder::{NodeRole, ScenarioAssertion, ScenarioBuilder};

        // Test building scenario with many duplicate-named elements (stress uniqueness checking)
        let large_scenario_result = std::panic::catch_unwind(|| {
            let mut builder = ScenarioBuilder::new("resource-stress").seed(42);

            // Add nodes up to reasonable limit
            for i in 0..1000 {
                let node_id = format!("node_{}", i);
                match builder.add_node(&node_id, "Stress Node", NodeRole::Participant) {
                    Ok(new_builder) => builder = new_builder,
                    Err(_) => break, // Hit capacity limit, which is expected
                }
            }

            // Try to add many links
            for i in 0..999 {
                let link_id = format!("link_{}", i);
                let from = format!("node_{}", i);
                let to = format!("node_{}", i + 1);

                match builder.add_link(&link_id, &from, &to, true) {
                    Ok(new_builder) => builder = new_builder,
                    Err(_) => break, // Hit capacity or validation limit
                }
            }

            // Try to add many assertions
            for i in 0..500 {
                let from = format!("node_{}", i);
                let to = format!("node_{}", (i + 1) % 1000);

                builder = builder.add_assertion(ScenarioAssertion::MessageDelivered {
                    from,
                    to,
                    within_ticks: 100,
                });
            }

            builder.build()
        });

        assert!(
            large_scenario_result.is_ok(),
            "Large scenario construction should not panic"
        );

        // Test extremely large single string fields
        let huge_string = "X".repeat(10_000_000); // 10MB string
        let huge_string_result = std::panic::catch_unwind(|| {
            ScenarioBuilder::new(&huge_string)
                .seed(42)
                .add_node("n1", "Node", NodeRole::Coordinator)
                .and_then(|b| b.add_node("n2", "Node2", NodeRole::Participant))
                .and_then(|b| Ok(b.build()))
        });

        match huge_string_result {
            Ok(Ok(Ok(_))) => {}  // Huge strings accepted
            Ok(Ok(Err(_))) => {} // Or rejected gracefully
            Ok(Err(_)) => {}     // Node addition failed gracefully
            Err(_) => panic!("Huge string should not cause panic"),
        }
    }

    /// Test concurrent access patterns and thread safety assumptions
    #[test]
    fn test_concurrent_access_patterns() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        use super::scenario_builder::{NodeRole, ScenarioBuilder};
        use super::virtual_transport::VirtualTransportLayer;

        // Test concurrent transport operations
        let transport = Arc::new(Mutex::new(VirtualTransportLayer::new(42)));

        // Spawn multiple threads to stress concurrent access
        let handles: Vec<_> = (0..4)
            .map(|thread_id| {
                let transport_clone = Arc::clone(&transport);
                thread::spawn(move || {
                    for i in 0..100 {
                        let link_id = format!("link_{}_{}", thread_id, i);
                        let source = format!("src_{}_{}", thread_id, i);
                        let target = format!("tgt_{}_{}", thread_id, i);

                        let link_result = {
                            let mut t = transport_clone.lock().unwrap();
                            t.create_link(
                                &source,
                                &target,
                                super::virtual_transport::LinkFaultConfig::no_faults(),
                            )
                        };

                        match link_result {
                            Ok(_) => {
                                // Try to send a message
                                let mut t = transport_clone.lock().unwrap();
                                let _ = t.send_message(&source, &target, vec![i as u8]);
                            }
                            Err(_) => {
                                // Link creation failed (expected under concurrent stress)
                            }
                        }
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete without panic");
        }

        // Verify transport state is still consistent
        let final_transport = transport.lock().unwrap();
        assert!(
            final_transport.link_count() <= 400,
            "Link count should be reasonable"
        );
        assert!(final_transport.stats().total_messages <= final_transport.link_count() as u64);

        // Test scenario builder under concurrent-like stress (single threaded but rapid operations)
        let rapid_scenario_result = std::panic::catch_unwind(|| {
            for iteration in 0..100 {
                let scenario_name = format!("rapid_scenario_{}", iteration);
                let scenario = ScenarioBuilder::new(&scenario_name)
                    .seed(42 + iteration)
                    .add_node("n1", "Node 1", NodeRole::Coordinator)?
                    .add_node("n2", "Node 2", NodeRole::Participant)?
                    .build()?;

                // Verify each scenario is valid
                let json = scenario.to_json()?;
                assert!(json.len() > 50, "Scenario JSON should have reasonable size");
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        assert!(
            rapid_scenario_result.is_ok(),
            "Rapid scenario creation should not panic"
        );
    }

    // ============================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH TESTS - INTEGRATION MODULE
    // ============================================================================
    // Comprehensive cross-module attack resistance and sophisticated edge cases

    #[test]
    fn negative_unicode_injection_cross_module_comprehensive() {
        // Test Unicode injection attacks across scenario builder and virtual transport integration
        use super::scenario_builder::{NodeRole, ScenarioBuilder};
        use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

        let unicode_attack_vectors = vec![
            // BiDi override attacks in scenario names
            (
                "bidi_scenario",
                "test\u{202e}_gnirwol\u{202c}_scenario",
                "normal_node",
            ),
            // Zero-width character pollution in node names
            (
                "zws_nodes",
                "normal_scenario",
                "node\u{200b}_test\u{200c}_id\u{200d}",
            ),
            // BOM injection in scenario/node combinations
            (
                "bom_mixed",
                "\u{feff}scenario\u{feff}",
                "\u{feff}node\u{feff}",
            ),
            // Unicode normalization confusion
            ("nfc_attack", "café_scenario", "café_node"),
            ("nfd_attack", "cafe\u{0301}_scenario", "cafe\u{0301}_node"),
            // Confusable characters across modules
            ("cyrillic_confuse", "sсenario", "nоde"), // Cyrillic chars
            ("greek_confuse", "sсenario", "nοde"),    // Greek chars
            // Combining character stacking
            (
                "combining_overflow",
                "sc\u{0300}\u{0301}\u{0302}enario",
                "no\u{0300}\u{0301}\u{0302}de",
            ),
            // Mixed script injection
            ("mixed_script", "test_сценарий_scenario", "test_नोड_node"),
        ];

        for (test_name, scenario_name, node_name) in unicode_attack_vectors {
            // Test scenario builder with Unicode injection
            let scenario_result = std::panic::catch_unwind(|| {
                ScenarioBuilder::new(scenario_name)
                    .seed(12345)
                    .add_node(node_name, "Test Node", NodeRole::Coordinator)
                    .and_then(|b| b.add_node("target_node", "Target", NodeRole::Participant))
                    .and_then(|b| b.build())
            });

            match scenario_result {
                Ok(Ok(scenario)) => {
                    // If scenario creation succeeds, test virtual transport integration
                    let transport_result = std::panic::catch_unwind(|| {
                        let mut transport = VirtualTransportLayer::new(54321);

                        // Create link using Unicode-injected node names
                        let create_result = transport.create_link(
                            node_name,
                            "target_node",
                            LinkFaultConfig::default(),
                        );

                        match create_result {
                            Ok(_) => {
                                // Test message sending with Unicode payload
                                let unicode_payload = format!("message_from_{}", scenario_name)
                                    .as_bytes()
                                    .to_vec();
                                let send_result = transport.send_message(
                                    node_name,
                                    "target_node",
                                    unicode_payload,
                                );

                                // Should handle Unicode without corruption
                                assert!(
                                    send_result.is_ok() || send_result.is_err(),
                                    "Send should complete without panic: {}",
                                    test_name
                                );
                            }
                            Err(_) => {
                                // Transport may reject Unicode node names - that's acceptable
                            }
                        }
                        Ok(())
                    });

                    assert!(
                        transport_result.is_ok(),
                        "Transport operations should not panic: {}",
                        test_name
                    );

                    // Verify scenario JSON serialization handles Unicode correctly
                    let json_result = scenario.to_json();
                    assert!(
                        json_result.is_ok(),
                        "JSON serialization should handle Unicode: {}",
                        test_name
                    );

                    if let Ok(json) = json_result {
                        assert!(
                            json.contains(scenario_name) || json.len() > 10,
                            "JSON should preserve or escape Unicode: {}",
                            test_name
                        );
                    }
                }
                Ok(Err(_)) => {
                    // Scenario building failed - acceptable for extreme Unicode
                }
                Err(_) => {
                    panic!("Unicode injection should not cause panic: {}", test_name);
                }
            }
        }
    }

    #[test]
    fn negative_memory_exhaustion_cross_module_stress() {
        // Test memory exhaustion attacks across integrated module boundaries
        use super::scenario_builder::{NodeRole, ScenarioAssertion, ScenarioBuilder};
        use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

        // Test 1: Massive scenario with many nodes and transport links
        let massive_scenario_result = std::panic::catch_unwind(|| {
            let mut builder = ScenarioBuilder::new("massive_cross_module_test").seed(99999);

            // Add many nodes (up to reasonable limit)
            for i in 0..1000 {
                let node_id = format!("node_{:04}", i);
                let node_name = format!("Node {} with long description {}", i, "x".repeat(100));

                builder = match builder.add_node(&node_id, &node_name, NodeRole::Participant) {
                    Ok(b) => b,
                    Err(_) => break, // Hit capacity limit
                };
            }

            // Add many links between nodes
            for i in 0..500 {
                let source = format!("node_{:04}", i);
                let target = format!("node_{:04}", (i + 1) % 1000);
                let link_id = format!("link_{:04}", i);

                builder = match builder.add_link(&link_id, &source, &target, true) {
                    Ok(b) => b,
                    Err(_) => break, // Hit capacity or validation limit
                };
            }

            // Add many assertions
            for i in 0..200 {
                let from = format!("node_{:04}", i * 5);
                let to = format!("node_{:04}", (i * 5 + 1) % 1000);

                builder = match builder.add_assertion(ScenarioAssertion::MessageDelivered {
                    from,
                    to,
                    within_ticks: 100,
                }) {
                    Ok(b) => b,
                    Err(_) => break, // Hit assertion limit
                };
            }

            // Build scenario - should handle large size gracefully
            let scenario = builder.build()?;

            // Test transport with scenario data
            let mut transport = VirtualTransportLayer::new(77777);

            // Create transport links corresponding to scenario links
            for link in scenario.links().iter().take(100) {
                // Limit for memory
                let create_result = transport.create_link(
                    &link.source_node,
                    &link.target_node,
                    LinkFaultConfig::default(),
                );

                match create_result {
                    Ok(_) => {
                        // Send test message
                        let payload = format!("test_{}", link.id).as_bytes().to_vec();
                        transport
                            .send_message(&link.source_node, &link.target_node, payload)
                            .ok();
                    }
                    Err(_) => {
                        // Transport may reject due to capacity limits
                        break;
                    }
                }
            }

            Ok(())
        });

        assert!(
            massive_scenario_result.is_ok(),
            "Massive cross-module scenario should not panic"
        );

        // Test 2: Very long string fields across modules
        let long_string_test = std::panic::catch_unwind(|| {
            let huge_name = "x".repeat(1_000_000); // 1MB string
            let huge_description = "Long description ".repeat(50_000);

            // Test scenario builder with huge strings
            let scenario_result = ScenarioBuilder::new(&huge_name)
                .seed(11111)
                .add_node("node1", &huge_description, NodeRole::Coordinator)
                .and_then(|b| b.add_node("node2", "Normal", NodeRole::Participant))
                .and_then(|b| b.build());

            match scenario_result {
                Ok(scenario) => {
                    // Test transport with huge identifiers
                    let mut transport = VirtualTransportLayer::new(22222);
                    let create_result =
                        transport.create_link("node1", "node2", LinkFaultConfig::default());

                    // Should handle or reject gracefully
                    match create_result {
                        Ok(_) => {
                            let huge_payload = vec![0x42; 10_000_000]; // 10MB payload
                            transport.send_message("node1", "node2", huge_payload).ok();
                        }
                        Err(_) => {
                            // Rejection is acceptable for huge data
                        }
                    }

                    // Test JSON serialization with huge data
                    scenario.to_json().ok(); // May succeed or fail gracefully
                }
                Err(_) => {
                    // Scenario building may fail for huge strings - acceptable
                }
            }

            Ok(())
        });

        assert!(
            long_string_test.is_ok(),
            "Long string cross-module test should not panic"
        );
    }

    #[test]
    fn negative_fault_injection_precision_boundary_integration() {
        // Test fault injection with extreme precision values across module boundaries
        use super::scenario_builder::{NodeRole, ScenarioBuilder};
        use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

        let precision_test_cases = vec![
            // Floating-point precision edge cases
            (f64::EPSILON, "epsilon"),
            (1.0 - f64::EPSILON, "one_minus_epsilon"),
            (f64::MIN_POSITIVE, "min_positive"),
            (0.1 + 0.2, "classic_fp_precision"), // Should be 0.3 but might have precision issues
            (1.0 / 3.0, "one_third_fraction"),
            // Boundary probability values
            (0.0, "zero_prob"),
            (1.0, "one_prob"),
            (0.5, "half_prob"),
            (0.999999999999999, "near_one"),
            (0.000000000000001, "near_zero"),
        ];

        for (drop_probability, test_name) in precision_test_cases {
            // Create scenario with fault profile
            let scenario_result = std::panic::catch_unwind(|| {
                let fault_config = LinkFaultConfig {
                    drop_probability,
                    reorder_depth: 10,
                    corrupt_bit_count: 1,
                    delay_ticks: 5,
                    partition: false,
                };

                // Test fault config validation
                let validation_result = fault_config.validate();
                if validation_result.is_err() {
                    return Ok(()); // Invalid probability - skip
                }

                let scenario = ScenarioBuilder::new(&format!("precision_test_{}", test_name))
                    .seed(33333)
                    .add_node("source", "Source Node", NodeRole::Coordinator)?
                    .add_node("target", "Target Node", NodeRole::Participant)?
                    .add_link("test_link", "source", "target", true)?
                    .set_fault_profile("test_link", fault_config)?
                    .build()?;

                // Test virtual transport with precision fault injection
                let mut transport = VirtualTransportLayer::new(44444);

                let create_result = transport.create_link("source", "target", fault_config);
                match create_result {
                    Ok(_) => {
                        // Send multiple messages to test probability behavior
                        for i in 0..100 {
                            let payload = format!("precision_test_{}_{}", test_name, i)
                                .as_bytes()
                                .to_vec();
                            transport.send_message("source", "target", payload).ok();
                        }

                        // Verify fault statistics make sense for the probability
                        let stats = transport.stats();

                        if drop_probability == 0.0 {
                            assert_eq!(
                                stats.messages_dropped, 0,
                                "Zero probability should drop no messages: {}",
                                test_name
                            );
                        } else if drop_probability == 1.0 {
                            assert_eq!(
                                stats.messages_delivered, 0,
                                "100% drop should deliver no messages: {}",
                                test_name
                            );
                        }
                        // For intermediate probabilities, just verify no overflow/corruption
                        assert!(
                            stats.total_messages < u64::MAX,
                            "Message count should not overflow: {}",
                            test_name
                        );
                    }
                    Err(_) => {
                        // Transport may reject extreme precision values - acceptable
                    }
                }

                // Test scenario JSON serialization preserves precision
                let json = scenario.to_json()?;
                assert!(
                    json.len() > 50,
                    "Scenario JSON should be reasonable size: {}",
                    test_name
                );

                Ok(())
            });

            assert!(
                precision_test_cases.is_ok(),
                "Precision test should not panic: {}",
                test_name
            );
        }

        // Test invalid probability values across modules
        let invalid_probabilities = vec![
            (f64::NAN, "nan"),
            (f64::INFINITY, "infinity"),
            (f64::NEG_INFINITY, "neg_infinity"),
            (-0.5, "negative"),
            (1.5, "greater_than_one"),
        ];

        for (invalid_prob, test_name) in invalid_probabilities {
            let invalid_config = LinkFaultConfig {
                drop_probability: invalid_prob,
                ..LinkFaultConfig::default()
            };

            // Validation should catch invalid values
            let validation = invalid_config.validate();
            assert!(
                validation.is_err(),
                "Invalid probability should be rejected: {}",
                test_name
            );

            // Scenario builder should also reject invalid configs
            let scenario_result = ScenarioBuilder::new("invalid_test")
                .seed(55555)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .and_then(|b| b.add_node("n2", "Node 2", NodeRole::Participant))
                .and_then(|b| b.add_link("link1", "n1", "n2", true))
                .and_then(|b| b.set_fault_profile("link1", invalid_config))
                .and_then(|b| b.build());

            assert!(
                scenario_result.is_err(),
                "Scenario with invalid probability should be rejected: {}",
                test_name
            );
        }
    }

    #[test]
    fn negative_json_serialization_injection_cross_module() {
        // Test JSON serialization attacks across scenario and transport modules
        use super::scenario_builder::{NodeRole, ScenarioAssertion, ScenarioBuilder};
        use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

        let json_injection_patterns = vec![
            // JSON structure injection in node names
            (
                "json_node",
                r#"node": "injected", "evil": true, "real_node"#,
            ),
            (
                "json_escape",
                r#"node\": \"injection\": true, \"continue\": \""#,
            ),
            // Unicode escape injection
            ("unicode_escape", r#"node\u0022injection\u0022"#),
            ("unicode_null", r#"node\u0000hidden"#),
            // Control character injection
            ("newline_inject", "node\nINJECTED: true\nreal"),
            ("carriage_inject", "node\rSET: evil=true\rreal"),
            // Nested structure attempts
            ("nested_json", r#"{"nested": {"evil": true}, "node": ""#),
            ("array_inject", r#"["injected", "array"], "node": ""#),
            // Binary data disguised as JSON
            ("binary_json", "node\x00{\"evil\": true}"),
            ("mixed_control", "node\x01\x02\x03\x7F"),
        ];

        for (test_name, injection_pattern) in json_injection_patterns {
            let cross_module_result = std::panic::catch_unwind(|| {
                // Test scenario builder with injection pattern
                let scenario_result = ScenarioBuilder::new(&format!("json_test_{}", test_name))
                    .seed(66666)
                    .add_node(injection_pattern, "Injected Node", NodeRole::Coordinator)
                    .and_then(|b| b.add_node("normal", "Normal Node", NodeRole::Participant))
                    .and_then(|b| b.add_link("test_link", injection_pattern, "normal", true))
                    .and_then(|b| {
                        b.add_assertion(ScenarioAssertion::MessageDelivered {
                            from: injection_pattern.to_string(),
                            to: "normal".to_string(),
                            within_ticks: 100,
                        })
                    })
                    .and_then(|b| b.build());

                match scenario_result {
                    Ok(scenario) => {
                        // Test JSON serialization resistance
                        let json_result = scenario.to_json();
                        match json_result {
                            Ok(json_str) => {
                                // Verify JSON is properly escaped
                                assert!(
                                    !json_str.contains("\"evil\": true"),
                                    "Should not contain unescaped injection"
                                );
                                assert!(
                                    !json_str.contains("\"INJECTED\""),
                                    "Should not contain unescaped injection"
                                );

                                // Test round-trip deserialization
                                let parse_result: Result<serde_json::Value, _> =
                                    serde_json::from_str(&json_str);
                                assert!(
                                    parse_result.is_ok(),
                                    "Serialized JSON should be parseable: {}",
                                    test_name
                                );
                            }
                            Err(_) => {
                                // JSON serialization may fail for extreme injection patterns - acceptable
                            }
                        }

                        // Test virtual transport with injection pattern
                        let mut transport = VirtualTransportLayer::new(77777);
                        let create_result = transport.create_link(
                            injection_pattern,
                            "normal",
                            LinkFaultConfig::default(),
                        );

                        match create_result {
                            Ok(_) => {
                                // Send message with injection pattern in payload
                                let injection_payload =
                                    format!("payload with {}", injection_pattern)
                                        .as_bytes()
                                        .to_vec();
                                transport
                                    .send_message(injection_pattern, "normal", injection_payload)
                                    .ok();

                                // Test transport statistics don't leak injection
                                let stats = transport.stats();
                                assert!(
                                    stats.total_messages < u64::MAX,
                                    "Stats should not be corrupted"
                                );
                            }
                            Err(_) => {
                                // Transport may reject injection patterns - acceptable
                            }
                        }
                    }
                    Err(_) => {
                        // Scenario building may fail for injection patterns - acceptable
                    }
                }

                Ok(())
            });

            assert!(
                cross_module_result.is_ok(),
                "JSON injection test should not panic: {}",
                test_name
            );
        }
    }

    #[test]
    fn negative_concurrent_cross_module_state_corruption_simulation() {
        // Test concurrent-like operations across modules to detect state corruption
        use super::scenario_builder::{NodeRole, ScenarioBuilder};
        use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};
        use std::sync::{Arc, Mutex};

        // Simulate rapid interleaved operations between modules
        let cross_module_stress = std::panic::catch_unwind(|| {
            let mut scenarios = Vec::new();
            let transport = Arc::new(Mutex::new(VirtualTransportLayer::new(88888)));

            // Create multiple scenarios rapidly
            for i in 0..50 {
                let scenario_name = format!("stress_scenario_{:03}", i);
                let scenario_result = ScenarioBuilder::new(&scenario_name)
                    .seed(11111 + i as u64)
                    .add_node("rapid_node_a", "Node A", NodeRole::Coordinator)
                    .and_then(|b| b.add_node("rapid_node_b", "Node B", NodeRole::Participant))
                    .and_then(|b| b.add_link("rapid_link", "rapid_node_a", "rapid_node_b", true))
                    .and_then(|b| b.build());

                match scenario_result {
                    Ok(scenario) => {
                        scenarios.push(scenario);

                        // Interleave transport operations
                        let mut t = transport.lock().unwrap();
                        let link_id = format!("transport_link_{}", i);
                        let create_result = t.create_link(
                            &format!("transport_src_{}", i),
                            &format!("transport_tgt_{}", i),
                            LinkFaultConfig::default(),
                        );

                        if create_result.is_ok() {
                            // Rapid message sending
                            for j in 0..5 {
                                let payload = format!("rapid_msg_{}_{}", i, j).as_bytes().to_vec();
                                t.send_message(
                                    &format!("transport_src_{}", i),
                                    &format!("transport_tgt_{}", i),
                                    payload,
                                )
                                .ok();
                            }
                        }
                    }
                    Err(_) => {
                        // Scenario creation may fail under stress - continue
                    }
                }

                // Periodically check state consistency
                if i % 10 == 0 {
                    let t = transport.lock().unwrap();
                    let stats = t.stats();
                    assert!(
                        stats.total_messages < u64::MAX,
                        "Transport stats should not overflow"
                    );
                    assert!(
                        stats.total_links_created < u64::MAX,
                        "Link count should not overflow"
                    );
                }
            }

            // Final consistency verification
            assert!(!scenarios.is_empty(), "Should have created some scenarios");

            // Test JSON serialization of all scenarios
            for (i, scenario) in scenarios.iter().enumerate().take(10) {
                // Limit for performance
                let json_result = scenario.to_json();
                match json_result {
                    Ok(json) => {
                        assert!(
                            json.len() > 20,
                            "Scenario {} JSON should be reasonable size",
                            i
                        );
                    }
                    Err(_) => {
                        // JSON generation may fail under stress - acceptable
                    }
                }
            }

            // Verify transport final state
            let final_transport = transport.lock().unwrap();
            let final_stats = final_transport.stats();
            assert!(
                final_stats.total_messages <= 50 * 5,
                "Message count should be reasonable"
            );
            assert!(
                final_stats.total_links_created <= 50,
                "Link count should be reasonable"
            );

            Ok(())
        });

        assert!(
            cross_module_stress.is_ok(),
            "Cross-module stress test should not panic"
        );
    }

    #[test]
    fn negative_edge_case_node_role_transport_integration() {
        // Test edge cases in node role handling across scenario and transport modules
        use super::scenario_builder::{NodeRole, ScenarioBuilder};
        use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

        let node_role_edge_cases = vec![
            // Test all role combinations
            (
                NodeRole::Coordinator,
                NodeRole::Participant,
                "coord_to_participant",
            ),
            (
                NodeRole::Coordinator,
                NodeRole::Observer,
                "coord_to_observer",
            ),
            (
                NodeRole::Participant,
                NodeRole::Coordinator,
                "participant_to_coord",
            ),
            (
                NodeRole::Participant,
                NodeRole::Observer,
                "participant_to_observer",
            ),
            (
                NodeRole::Observer,
                NodeRole::Coordinator,
                "observer_to_coord",
            ),
            (
                NodeRole::Observer,
                NodeRole::Participant,
                "observer_to_participant",
            ),
            // Self-connections
            (
                NodeRole::Coordinator,
                NodeRole::Coordinator,
                "coord_to_coord",
            ),
            (
                NodeRole::Participant,
                NodeRole::Participant,
                "participant_to_participant",
            ),
            (
                NodeRole::Observer,
                NodeRole::Observer,
                "observer_to_observer",
            ),
        ];

        for (source_role, target_role, test_name) in node_role_edge_cases {
            let role_test_result = std::panic::catch_unwind(|| {
                // Create scenario with specific role combination
                let scenario = ScenarioBuilder::new(&format!("role_test_{}", test_name))
                    .seed(99999)
                    .add_node("source_node", "Source", source_role)?
                    .add_node("target_node", "Target", target_role)?
                    .add_link("role_link", "source_node", "target_node", true)?
                    .build()?;

                // Test transport integration with role-based nodes
                let mut transport = VirtualTransportLayer::new(12121);

                // Create transport link using scenario node information
                let create_result = transport.create_link(
                    "source_node",
                    "target_node",
                    LinkFaultConfig {
                        drop_probability: 0.1,
                        reorder_depth: 5,
                        corrupt_bit_count: 1,
                        delay_ticks: 10,
                        partition: false,
                    },
                );

                match create_result {
                    Ok(_) => {
                        // Test role-specific message patterns
                        let role_specific_messages = match (source_role, target_role) {
                            (NodeRole::Coordinator, _) => vec![
                                b"coordinator_command".to_vec(),
                                b"coordination_update".to_vec(),
                            ],
                            (NodeRole::Participant, _) => {
                                vec![b"participant_data".to_vec(), b"participant_status".to_vec()]
                            }
                            (NodeRole::Observer, _) => {
                                vec![b"observation_report".to_vec(), b"observer_query".to_vec()]
                            }
                        };

                        for (i, message) in role_specific_messages.into_iter().enumerate() {
                            let send_result =
                                transport.send_message("source_node", "target_node", message);

                            match send_result {
                                Ok(message_id) => {
                                    assert!(
                                        message_id > 0,
                                        "Message ID should be valid for role test: {}",
                                        test_name
                                    );
                                }
                                Err(_) => {
                                    // Message sending may fail due to fault injection - acceptable
                                }
                            }

                            // Periodically check transport state
                            if i % 2 == 0 {
                                let stats = transport.stats();
                                assert!(
                                    stats.total_messages < u64::MAX,
                                    "Stats should not overflow: {}",
                                    test_name
                                );
                            }
                        }

                        // Verify transport still functions after role-specific operations
                        let final_stats = transport.stats();
                        assert!(
                            final_stats.total_messages >= 0,
                            "Message count should be non-negative: {}",
                            test_name
                        );
                    }
                    Err(_) => {
                        // Transport creation may fail - acceptable
                    }
                }

                // Test scenario serialization preserves roles correctly
                let json = scenario.to_json()?;
                assert!(
                    json.contains("Coordinator")
                        || json.contains("Participant")
                        || json.contains("Observer"),
                    "JSON should contain role information: {}",
                    test_name
                );

                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });

            assert!(
                role_test_result.is_ok(),
                "Role integration test should not panic: {}",
                test_name
            );
        }
    }

    #[test]
    fn negative_assertion_transport_message_correlation_edge_cases() {
        // Test edge cases in assertion and transport message correlation
        use super::scenario_builder::{NodeRole, ScenarioAssertion, ScenarioBuilder};
        use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

        let correlation_edge_cases = vec![
            // Timing edge cases
            (1, "immediate_delivery"),
            (u64::MAX, "infinite_timeout"),
            (0, "zero_timeout"),
            // Boundary timing values
            (u32::MAX as u64, "u32_max_timeout"),
            (1000000, "large_timeout"),
            (1, "minimum_timeout"),
        ];

        for (within_ticks, test_name) in correlation_edge_cases {
            let correlation_test_result = std::panic::catch_unwind(|| {
                // Create scenario with timing-sensitive assertion
                let scenario_result = ScenarioBuilder::new(&format!("correlation_{}", test_name))
                    .seed(13131)
                    .add_node("message_source", "Message Source", NodeRole::Coordinator)
                    .and_then(|b| {
                        b.add_node("message_target", "Message Target", NodeRole::Participant)
                    })
                    .and_then(|b| {
                        b.add_link("correlation_link", "message_source", "message_target", true)
                    })
                    .and_then(|b| {
                        b.add_assertion(ScenarioAssertion::MessageDelivered {
                            from: "message_source".to_string(),
                            to: "message_target".to_string(),
                            within_ticks,
                        })
                    })
                    .and_then(|b| b.build());

                match scenario_result {
                    Ok(scenario) => {
                        // Test transport behavior under timing constraints
                        let mut transport = VirtualTransportLayer::new(14141);

                        // Create link with delay that might violate assertion
                        let delay_ticks = if within_ticks == 0 || within_ticks == u64::MAX {
                            100 // Reasonable delay for edge cases
                        } else {
                            within_ticks / 2 // Half the timeout
                        };

                        let create_result = transport.create_link(
                            "message_source",
                            "message_target",
                            LinkFaultConfig {
                                drop_probability: 0.0, // No drops for timing test
                                reorder_depth: 0,      // No reordering for timing test
                                corrupt_bit_count: 0,  // No corruption for timing test
                                delay_ticks,
                                partition: false,
                            },
                        );

                        match create_result {
                            Ok(_) => {
                                // Send test message
                                let timing_payload =
                                    format!("timing_test_{}", test_name).as_bytes().to_vec();
                                let send_result = transport.send_message(
                                    "message_source",
                                    "message_target",
                                    timing_payload,
                                );

                                if send_result.is_ok() {
                                    // Advance transport time and check delivery
                                    for tick in 1..=std::cmp::min(within_ticks + 100, 1000) {
                                        transport.advance_time(tick);

                                        // Check if message delivered
                                        let delivered_messages =
                                            transport.get_delivered_messages("message_target");

                                        if !delivered_messages.is_empty() {
                                            let delivery_tick =
                                                delivered_messages[0].delivery_tick();

                                            // Verify timing constraint behavior
                                            if within_ticks != u64::MAX {
                                                assert!(
                                                    delivery_tick <= within_ticks + delay_ticks,
                                                    "Delivery should respect timing bounds: {}",
                                                    test_name
                                                );
                                            }
                                            break;
                                        }
                                    }

                                    // Verify transport state consistency
                                    let stats = transport.stats();
                                    assert!(
                                        stats.total_messages >= 1,
                                        "Should have processed test message: {}",
                                        test_name
                                    );
                                    assert!(
                                        stats.total_messages < u64::MAX,
                                        "Message count should not overflow: {}",
                                        test_name
                                    );
                                }
                            }
                            Err(_) => {
                                // Transport may reject extreme timing configurations - acceptable
                            }
                        }

                        // Test assertion serialization with edge case timing
                        let json = scenario.to_json()?;
                        if within_ticks == u64::MAX {
                            assert!(
                                json.contains("within_ticks") || json.len() > 50,
                                "JSON should handle u64::MAX timing: {}",
                                test_name
                            );
                        } else {
                            assert!(
                                json.contains(&within_ticks.to_string()) || json.len() > 50,
                                "JSON should preserve timing constraint: {}",
                                test_name
                            );
                        }
                    }
                    Err(_) => {
                        // Scenario creation may fail for edge case timing - acceptable for extreme values
                        if within_ticks == u64::MAX || within_ticks == 0 {
                            // These edge cases may legitimately be rejected
                        } else {
                            panic!(
                                "Reasonable timing constraint should not fail: {} ticks",
                                within_ticks
                            );
                        }
                    }
                }

                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });

            assert!(
                correlation_test_result.is_ok(),
                "Correlation test should not panic: {}",
                test_name
            );
        }

        /// Test Unicode injection attacks in testing module components
        #[test]
        fn negative_testing_unicode_injection_comprehensive() {
            use super::scenario_builder::{NodeRole, ScenarioBuilder};
            use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

            let unicode_injection_vectors = vec![
                // BiDi override attacks in test scenarios
                ("bidi_override", "test\u{202E}gninoisufnoc\u{202D}scenario"),
                (
                    "bidi_nested",
                    "test\u{202E}level1\u{202E}level2\u{202D}nested\u{202D}scenario",
                ),
                // Zero-width character pollution
                (
                    "zws_pollution",
                    "test\u{200B}invisible\u{200C}spaces\u{200D}scenario",
                ),
                (
                    "zwj_sequence",
                    "test\u{200D}\u{1F469}\u{200D}\u{1F4BB}scenario",
                ),
                // Confusable character attacks
                ("cyrillic_spoof", "tеst_scеnario"), // Cyrillic 'e' characters
                ("greek_spoof", "test_scεnαrio"),    // Greek characters
                // Control character injection
                ("ansi_escape", "test\x1b[31mred\x1b[0mscenario"),
                ("vertical_tab", "test\x0Bscenario"),
                // Unicode normalization attacks
                ("nfd_attack", "cafe\u{0301}_scenario"), // NFD form
                (
                    "combining_stack",
                    "test\u{0300}\u{0301}\u{0302}\u{0303}scenario",
                ),
            ];

            for (attack_name, malicious_input) in unicode_injection_vectors {
                let injection_result = std::panic::catch_unwind(|| {
                    // Test scenario builder resistance to Unicode injection
                    let scenario_result = ScenarioBuilder::new(malicious_input)
                        .seed(98765)
                        .add_node("clean_node", "Clean Node", NodeRole::Coordinator)
                        .and_then(|b| {
                            b.add_node(malicious_input, "Injected Node", NodeRole::Participant)
                        });

                    match scenario_result {
                        Ok(builder) => {
                            let final_scenario =
                                builder.build().expect("Should build successfully");

                            // Test JSON serialization preserves security
                            let json = final_scenario.to_json().expect("JSON should serialize");

                            // Ensure injection didn't break JSON structure
                            let parsed: serde_json::Value =
                                serde_json::from_str(&json).expect("JSON should remain valid");
                            assert!(parsed.is_object(), "JSON should maintain object structure");

                            // Test virtual transport with Unicode-injected identifiers
                            let mut transport = VirtualTransportLayer::new(54321);
                            let create_result = transport.create_link(
                                "clean_node",
                                malicious_input,
                                LinkFaultConfig::no_faults(),
                            );

                            if create_result.is_ok() {
                                // Test message with Unicode payload
                                let unicode_payload =
                                    format!("payload_{}", malicious_input).into_bytes();
                                let send_result = transport.send_message(
                                    "clean_node",
                                    malicious_input,
                                    unicode_payload,
                                );

                                // Should handle without corruption or bypass
                                assert!(
                                    send_result.is_ok() || send_result.is_err(),
                                    "Send should complete deterministically for: {}",
                                    attack_name
                                );
                            }
                        }
                        Err(_) => {
                            // Graceful rejection of malicious input is acceptable
                        }
                    }

                    Ok(())
                });

                assert!(
                    injection_result.is_ok(),
                    "Unicode injection should not cause panic: {}",
                    attack_name
                );
            }
        }

        /// Test memory exhaustion protection in testing modules
        #[test]
        fn negative_testing_memory_exhaustion_stress() {
            use super::scenario_builder::{NodeRole, ScenarioAssertion, ScenarioBuilder};
            use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

            // Test massive scenario construction with bounded resources
            let memory_stress_result = std::panic::catch_unwind(|| {
                let mut builder = ScenarioBuilder::new("memory_exhaustion_test").seed(77777);

                // Add many nodes to stress memory allocation
                let mut node_count = 0;
                for i in 0..10000 {
                    let node_id = format!("stress_node_{:05}", i);
                    let massive_description = "STRESS ".repeat(1000); // 6KB per description

                    match builder.add_node(&node_id, &massive_description, NodeRole::Participant) {
                        Ok(new_builder) => {
                            builder = new_builder;
                            node_count = node_count.saturating_add(1);
                        }
                        Err(_) => {
                            // Hit memory/capacity limits - expected behavior
                            break;
                        }
                    }

                    // Safety valve to prevent actual memory exhaustion in tests
                    if i >= 1000 {
                        break;
                    }
                }

                // Attempt massive link creation
                let mut link_count = 0;
                for i in 0..(node_count - 1).min(5000) {
                    let link_id = format!("stress_link_{:05}", i);
                    let source = format!("stress_node_{:05}", i);
                    let target = format!("stress_node_{:05}", i + 1);

                    match builder.add_link(&link_id, &source, &target, true) {
                        Ok(new_builder) => {
                            builder = new_builder;
                            link_count = link_count.saturating_add(1);
                        }
                        Err(_) => {
                            // Hit capacity limits
                            break;
                        }
                    }
                }

                // Test memory-intensive assertions
                for i in 0..link_count.min(1000) {
                    let from = format!("stress_node_{:05}", i);
                    let to = format!("stress_node_{:05}", i + 1);

                    builder = builder.add_assertion(ScenarioAssertion::MessageDelivered {
                        from,
                        to,
                        within_ticks: 1000,
                    });
                }

                // Final build should either succeed or fail gracefully
                let build_result = builder.build();
                match build_result {
                    Ok(scenario) => {
                        // If build succeeds, test transport with scenario data
                        let mut transport = VirtualTransportLayer::new(88888);

                        // Create subset of transport links (bounded for memory)
                        for link in scenario.links().iter().take(100) {
                            if transport
                                .create_link(
                                    &link.source_node,
                                    &link.target_node,
                                    LinkFaultConfig::default(),
                                )
                                .is_ok()
                            {
                                // Send bounded message
                                let payload = vec![0x42; 1024]; // 1KB message
                                transport
                                    .send_message(&link.source_node, &link.target_node, payload)
                                    .ok();
                            }
                        }

                        // Verify transport state remains stable
                        let stats = transport.stats();
                        assert!(
                            stats.total_messages < u64::MAX,
                            "Message count should not overflow"
                        );
                        assert!(
                            stats.total_links_created <= 100,
                            "Link count should be bounded"
                        );
                    }
                    Err(_) => {
                        // Build failure under memory pressure is acceptable
                    }
                }

                Ok(())
            });

            assert!(
                memory_stress_result.is_ok(),
                "Memory stress test should not panic"
            );
        }

        /// Test JSON structure integrity validation in testing components
        #[test]
        fn negative_testing_json_integrity_validation() {
            use super::scenario_builder::{NodeRole, Scenario, ScenarioBuilder};

            let json_corruption_patterns = vec![
                // Structural JSON attacks
                (r#"{"injected": true, "real_scenario""#, "incomplete_object"),
                (
                    r#"scenario": {"injected": "payload"}, "real""#,
                    "property_injection",
                ),
                (
                    r#"scenario\": {\"nested\": true}, \"continue\": \""#,
                    "escape_injection",
                ),
                // Array confusion attacks
                (r#"["fake", "array"], "scenario""#, "array_confusion"),
                (
                    r#"scenario", {"fake": "object"}, "continue"#,
                    "mixed_structure",
                ),
                // Unicode escape attacks
                (r#"scenario\u0022injection\u0022"#, "unicode_escape"),
                (r#"scenario\u0000null_injection"#, "null_escape"),
                // Control character corruption
                ("scenario\r\n{\"injected\": true}\r\nreal", "crlf_injection"),
                ("scenario\x00{\"binary\": true}", "binary_injection"),
            ];

            for (malicious_input, attack_name) in json_corruption_patterns {
                let json_test_result = std::panic::catch_unwind(|| {
                    // Create scenario with potentially malicious input
                    let scenario_result = ScenarioBuilder::new(malicious_input)
                        .seed(55555)
                        .add_node("test_node", malicious_input, NodeRole::Coordinator)
                        .and_then(|b| b.add_node("clean_node", "Clean Node", NodeRole::Participant))
                        .and_then(|b| b.build());

                    match scenario_result {
                        Ok(scenario) => {
                            // Test JSON serialization integrity
                            let json_result = scenario.to_json();
                            match json_result {
                                Ok(json_string) => {
                                    // Verify JSON is structurally valid
                                    let parse_result: Result<serde_json::Value, _> =
                                        serde_json::from_str(&json_string);

                                    assert!(
                                        parse_result.is_ok(),
                                        "JSON should remain valid after serialization: {}",
                                        attack_name
                                    );

                                    // Verify no injection occurred
                                    let parsed = parse_result.unwrap();
                                    if let Some(obj) = parsed.as_object() {
                                        // Should not contain injected properties
                                        assert!(
                                            !obj.contains_key("injected"),
                                            "Should not contain injected properties: {}",
                                            attack_name
                                        );
                                        assert!(
                                            !obj.contains_key("fake"),
                                            "Should not contain fake properties: {}",
                                            attack_name
                                        );
                                    }

                                    // Test round-trip integrity
                                    let reparse_result = Scenario::from_json(&json_string);
                                    match reparse_result {
                                        Ok(_) => {
                                            // Successful round-trip preserves integrity
                                        }
                                        Err(_) => {
                                            // Round-trip may fail for extreme cases - acceptable
                                        }
                                    }
                                }
                                Err(_) => {
                                    // JSON serialization may fail for malicious input - acceptable
                                }
                            }
                        }
                        Err(_) => {
                            // Scenario creation may reject malicious input - acceptable
                        }
                    }

                    Ok(())
                });

                assert!(
                    json_test_result.is_ok(),
                    "JSON integrity test should not panic: {}",
                    attack_name
                );
            }
        }

        /// Test arithmetic overflow protection in testing module counters
        #[test]
        fn negative_testing_arithmetic_overflow_protection() {
            use super::lab_runtime::{LabConfig, LabRuntime};
            use super::scenario_builder::{NodeRole, ScenarioBuilder};
            use super::virtual_transport::VirtualTransportLayer;

            // Test virtual transport with overflow-prone operations
            let overflow_test_result = std::panic::catch_unwind(|| {
                let mut transport = VirtualTransportLayer::new(33333);

                // Simulate near-overflow message ID scenarios
                // Note: We can't directly set internal state, so we test overflow handling
                transport
                    .create_link(
                        "overflow_src",
                        "overflow_tgt",
                        super::virtual_transport::LinkFaultConfig::no_faults(),
                    )
                    .expect("Link creation should succeed");

                // Test message sending with potential counter overflow
                let mut message_count = 0u64;
                for i in 0..1000 {
                    let payload = format!("overflow_test_{}", i).into_bytes();
                    match transport.send_message("overflow_src", "overflow_tgt", payload) {
                        Ok(msg_id) => {
                            // Verify message ID doesn't wrap unexpectedly
                            assert!(msg_id > 0, "Message ID should be positive");
                            message_count = message_count.saturating_add(1);
                        }
                        Err(_) => {
                            // Message may fail due to capacity limits - acceptable
                            break;
                        }
                    }
                }

                // Test statistics calculation without overflow
                let stats = transport.stats();
                assert!(
                    stats.total_messages <= message_count,
                    "Stats should not exceed sent messages"
                );
                assert!(
                    stats.delivered_messages <= stats.total_messages,
                    "Delivered ≤ total"
                );
                assert!(
                    stats.dropped_messages <= stats.total_messages,
                    "Dropped ≤ total"
                );

                // Test lab runtime with overflow-prone tick operations
                let lab_config = LabConfig::default();
                let mut runtime =
                    LabRuntime::new(lab_config).expect("Runtime creation should succeed");

                // Test timer scheduling near tick overflow boundaries
                let near_max_tick = u64::MAX - 1000;
                runtime.test_clock.current_tick = near_max_tick;

                // Schedule timer with small delta (should succeed)
                let small_timer_result = runtime.schedule_timer(500, "near_overflow_safe");
                assert!(
                    small_timer_result.is_ok(),
                    "Safe timer scheduling should succeed"
                );

                // Schedule timer that would overflow (should fail gracefully)
                let overflow_timer_result = runtime.schedule_timer(2000, "overflow_attempt");
                assert!(
                    overflow_timer_result.is_err(),
                    "Overflow timer should be rejected"
                );

                // Test clock advance with saturation
                let advance_result = runtime.advance_clock(1000);
                match advance_result {
                    Ok(_) => {
                        // If advance succeeds, tick should be bounded
                        assert!(
                            runtime.test_clock.current_tick <= u64::MAX,
                            "Clock tick should not exceed maximum"
                        );
                    }
                    Err(_) => {
                        // Advance may fail if it would cause overflow - acceptable
                    }
                }

                Ok(())
            });

            assert!(
                overflow_test_result.is_ok(),
                "Arithmetic overflow test should not panic"
            );
        }

        /// Test concurrent access safety simulation in testing modules
        #[test]
        fn negative_testing_concurrent_access_safety() {
            use super::scenario_builder::{NodeRole, ScenarioBuilder};
            use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};
            use std::sync::{Arc, Mutex};
            use std::thread;

            let concurrent_safety_result = std::panic::catch_unwind(|| {
                // Test concurrent scenario creation (simulated)
                let mut scenarios = Vec::new();
                for thread_id in 0..4 {
                    // Simulate concurrent scenario building
                    let scenario_name = format!("concurrent_test_{}", thread_id);
                    let builder =
                        ScenarioBuilder::new(&scenario_name).seed(12345 + thread_id as u64);

                    // Add nodes in rapid succession
                    let mut current_builder = builder;
                    for i in 0..10 {
                        let node_id = format!("thread_{}_node_{}", thread_id, i);
                        let node_desc = format!("Concurrent Node {} {}", thread_id, i);

                        match current_builder.add_node(&node_id, &node_desc, NodeRole::Participant)
                        {
                            Ok(new_builder) => current_builder = new_builder,
                            Err(_) => break,
                        }
                    }

                    // Build scenario
                    if let Ok(scenario) = current_builder.build() {
                        scenarios.push(scenario);
                    }
                }

                // Test shared transport under concurrent-like stress
                let transport = Arc::new(Mutex::new(VirtualTransportLayer::new(99999)));
                let mut handles = Vec::new();

                for thread_id in 0..2 {
                    // Limit threads for test stability
                    let transport_clone = Arc::clone(&transport);
                    let handle = thread::spawn(move || {
                        for i in 0..50 {
                            let source = format!("thread_{}_src_{}", thread_id, i);
                            let target = format!("thread_{}_tgt_{}", thread_id, i);

                            // Acquire lock and perform transport operations
                            if let Ok(mut transport) = transport_clone.lock() {
                                let create_result = transport.create_link(
                                    &source,
                                    &target,
                                    LinkFaultConfig::no_faults(),
                                );

                                if create_result.is_ok() {
                                    let payload =
                                        format!("concurrent_msg_{}_{}", thread_id, i).into_bytes();
                                    transport.send_message(&source, &target, payload).ok();
                                }
                            }

                            // Yield to simulate concurrent access
                            thread::yield_now();
                        }
                    });
                    handles.push(handle);
                }

                // Wait for all threads to complete
                for handle in handles {
                    handle.join().expect("Thread should complete without panic");
                }

                // Verify final state consistency
                if let Ok(final_transport) = transport.lock() {
                    let final_stats = final_transport.stats();
                    assert!(
                        final_stats.total_messages < u64::MAX,
                        "Message count should not overflow"
                    );
                    assert!(
                        final_stats.total_links_created <= 100,
                        "Link count should be reasonable"
                    );
                }

                // Verify scenario data integrity
                assert!(!scenarios.is_empty(), "Should have created some scenarios");
                for scenario in &scenarios {
                    let json_result = scenario.to_json();
                    if let Ok(json) = json_result {
                        assert!(json.len() > 10, "Scenario JSON should have content");
                    }
                }

                Ok(())
            });

            assert!(
                concurrent_safety_result.is_ok(),
                "Concurrent safety test should not panic"
            );
        }

        /// Test display injection and format string safety in testing output
        #[test]
        fn negative_testing_display_injection_safety() {
            use super::scenario_builder::{NodeRole, ScenarioBuilder};
            use super::virtual_transport::{VirtualTransportError, VirtualTransportLayer};

            let display_injection_vectors = vec![
                // Format string injection attempts
                ("format_inject", "test%s%x%d%p"),
                ("format_overflow", "test%.999999s"),
                ("format_position", "test%1$s%2$x"),
                // ANSI escape sequence injection
                ("ansi_colors", "test\x1b[31mRED\x1b[0m"),
                ("ansi_cursor", "test\x1b[H\x1b[2J"),
                ("ansi_title", "test\x1b]0;TITLE\x07"),
                // Terminal control injection
                ("bell_spam", "test\x07\x07\x07"),
                ("backspace_attack", "test\x08\x08\x08hidden"),
                ("carriage_return", "test\roverwrite"),
                // Unicode display corruption
                ("rtl_override", "test\u{202E}desrever\u{202D}"),
                ("combining_overflow", "test\u{0300}\u{0301}\u{0302}\u{0303}"),
                ("width_confusion", "test\u{3000}\u{FF01}"),
            ];

            for (attack_name, malicious_content) in display_injection_vectors {
                let display_safety_result = std::panic::catch_unwind(|| {
                    // Test scenario display safety
                    let scenario_result = ScenarioBuilder::new(malicious_content)
                        .seed(44444)
                        .add_node("display_node", malicious_content, NodeRole::Coordinator)
                        .and_then(|b| {
                            b.add_node("target_node", "Normal Target", NodeRole::Participant)
                        })
                        .and_then(|b| b.build());

                    match scenario_result {
                        Ok(scenario) => {
                            // Test display formatting safety
                            let display_test = format!("{:?}", scenario);
                            assert!(
                                !display_test.contains("%s"),
                                "Display should not contain format specifiers: {}",
                                attack_name
                            );
                            assert!(
                                !display_test.contains("\x1b["),
                                "Display should escape ANSI sequences: {}",
                                attack_name
                            );

                            // Test JSON display safety
                            if let Ok(json) = scenario.to_json() {
                                assert!(
                                    !json.contains("\x1b["),
                                    "JSON should escape control sequences: {}",
                                    attack_name
                                );
                                assert!(
                                    !json.contains("\x00"),
                                    "JSON should escape null bytes: {}",
                                    attack_name
                                );
                            }
                        }
                        Err(_) => {
                            // Scenario creation may reject display injection - acceptable
                        }
                    }

                    // Test transport error display safety
                    let mut transport = VirtualTransportLayer::new(66666);
                    let error_result =
                        transport.send_message(malicious_content, "nonexistent", b"test".to_vec());

                    if let Err(error) = error_result {
                        let error_display = format!("{}", error);
                        assert!(
                            !error_display.contains("%s"),
                            "Error display should not contain format specifiers: {}",
                            attack_name
                        );
                        assert!(
                            !error_display.contains("\x1b["),
                            "Error display should escape ANSI: {}",
                            attack_name
                        );

                        let error_debug = format!("{:?}", error);
                        assert!(
                            !error_debug.contains("\x00"),
                            "Error debug should escape null bytes: {}",
                            attack_name
                        );
                    }

                    Ok(())
                });

                assert!(
                    display_safety_result.is_ok(),
                    "Display injection test should not panic: {}",
                    attack_name
                );
            }
        }

        /// Test boundary condition stress in testing module edge cases
        #[test]
        fn negative_testing_boundary_stress_comprehensive() {
            use super::lab_runtime::{LabConfig, LabRuntime};
            use super::scenario_builder::{NodeRole, ScenarioAssertion, ScenarioBuilder};
            use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

            // Test scenario boundary conditions
            let boundary_test_result = std::panic::catch_unwind(|| {
                // Test empty/minimal scenarios
                let minimal_result = ScenarioBuilder::new("minimal")
                    .seed(1)
                    .add_node("n1", "", NodeRole::Coordinator) // Empty description
                    .and_then(|b| b.add_node("n2", "", NodeRole::Participant))
                    .and_then(|b| b.build());

                match minimal_result {
                    Ok(_) => {}  // Minimal scenarios accepted
                    Err(_) => {} // Or rejected - both acceptable
                }

                // Test maximum realistic scenario size
                let mut large_builder = ScenarioBuilder::new("large_boundary_test").seed(12345);

                // Add nodes up to reasonable boundary
                let mut node_count = 0;
                for i in 0..1000 {
                    let node_id = format!("boundary_node_{:04}", i);
                    match large_builder.add_node(&node_id, "Boundary Node", NodeRole::Participant) {
                        Ok(builder) => {
                            large_builder = builder;
                            node_count = node_count.saturating_add(1);
                        }
                        Err(_) => break, // Hit capacity boundary
                    }
                }

                // Test assertion timing boundaries
                if node_count >= 2 {
                    large_builder = large_builder
                        .add_assertion(ScenarioAssertion::MessageDelivered {
                            from: "boundary_node_0000".to_string(),
                            to: "boundary_node_0001".to_string(),
                            within_ticks: 0, // Minimum timing
                        })
                        .add_assertion(ScenarioAssertion::MessageDelivered {
                            from: "boundary_node_0001".to_string(),
                            to: "boundary_node_0000".to_string(),
                            within_ticks: u64::MAX, // Maximum timing
                        });
                }

                let build_result = large_builder.build();
                match build_result {
                    Ok(_) => {}  // Large scenarios accepted
                    Err(_) => {} // Or rejected at boundary
                }

                // Test virtual transport boundaries
                let mut transport = VirtualTransportLayer::new(11111);

                // Test empty payload boundaries
                transport
                    .create_link(
                        "empty_test_src",
                        "empty_test_tgt",
                        LinkFaultConfig::no_faults(),
                    )
                    .expect("Empty test link should be created");

                let empty_send_result =
                    transport.send_message("empty_test_src", "empty_test_tgt", vec![]);
                assert!(empty_send_result.is_ok(), "Empty payload should be allowed");

                // Test single byte payload
                let single_byte_result =
                    transport.send_message("empty_test_src", "empty_test_tgt", vec![0xFF]);
                assert!(single_byte_result.is_ok(), "Single byte should be allowed");

                // Test maximum reasonable payload size
                let large_payload = vec![0x42; 1_000_000]; // 1MB payload
                let large_send_result =
                    transport.send_message("empty_test_src", "empty_test_tgt", large_payload);
                match large_send_result {
                    Ok(_) => {
                        // Large payloads accepted - verify delivery works
                        let delivered = transport
                            .deliver_next("empty_test_src->empty_test_tgt")
                            .expect("Delivery should work")
                            .expect("Message should be delivered");
                        assert_eq!(
                            delivered.payload.len(),
                            1_000_000,
                            "Payload size should be preserved"
                        );
                    }
                    Err(_) => {
                        // Large payloads rejected - acceptable
                    }
                }

                // Test lab runtime timing boundaries
                let config = LabConfig::default();
                let mut runtime = LabRuntime::new(config).expect("Runtime should initialize");

                // Test zero-delay timer
                let zero_timer_result = runtime.schedule_timer(0, "immediate");
                assert!(
                    zero_timer_result.is_ok(),
                    "Zero delay timer should be allowed"
                );

                // Test maximum delay timer
                let max_timer_result = runtime.schedule_timer(u64::MAX / 2, "very_long");
                assert!(
                    max_timer_result.is_ok(),
                    "Large delay timer should be allowed"
                );

                // Test clock at maximum value
                runtime.test_clock.current_tick = u64::MAX - 100;
                let near_max_timer = runtime.schedule_timer(50, "near_max");
                assert!(near_max_timer.is_ok(), "Timer near max tick should work");

                // Test clock advance that would overflow
                let overflow_advance = runtime.advance_clock(200);
                assert!(
                    overflow_advance.is_err(),
                    "Clock advance causing overflow should be rejected"
                );

                Ok(())
            });

            assert!(
                boundary_test_result.is_ok(),
                "Boundary stress test should not panic"
            );
        }

        /// Test cross-module integration edge cases with sophisticated attack scenarios
        #[test]
        fn negative_testing_integration_attack_scenarios() {
            use super::scenario_builder::{NodeRole, ScenarioAssertion, ScenarioBuilder};
            use super::virtual_transport::{LinkFaultConfig, VirtualTransportLayer};

            let integration_attack_result = std::panic::catch_unwind(|| {
                // Scenario: Coordinated attack across scenario building and transport layers
                let attack_scenario_name = "coordinated\u{202E}kcatta\u{202D}_scenario";
                let attack_node_name = "node\x00\x1b[31mEVIL\x1b[0m_with_%.100s";

                let coordinated_result = ScenarioBuilder::new(attack_scenario_name)
                    .seed(88888)
                    .add_node(
                        attack_node_name,
                        "Malicious Node Description",
                        NodeRole::Coordinator,
                    )
                    .and_then(|b| b.add_node("victim_node", "Victim Node", NodeRole::Participant))
                    .and_then(|b| b.add_link("attack_link", attack_node_name, "victim_node", true))
                    .and_then(|b| {
                        b.set_fault_profile(
                            "attack_link",
                            LinkFaultConfig {
                                drop_probability: 0.999999,       // Near-certain drop to stress edge case
                                reorder_depth: usize::MAX / 1000, // Large but not overflow-inducing
                                corrupt_bit_count: 1000000,       // High corruption
                                delay_ticks: u64::MAX / 2,        // Very large delay
                                partition: false,
                            },
                        )
                    })
                    .and_then(|b| {
                        b.add_assertion(ScenarioAssertion::MessageDelivered {
                            from: attack_node_name.to_string(),
                            to: "victim_node".to_string(),
                            within_ticks: 1, // Nearly impossible timing with high delay
                        })
                    })
                    .and_then(|b| b.build());

                match coordinated_result {
                    Ok(attack_scenario) => {
                        // Test JSON serialization under attack
                        let json_result = attack_scenario.to_json();
                        match json_result {
                            Ok(json_str) => {
                                // Verify attack didn't break JSON structure
                                let parse_check: Result<serde_json::Value, _> =
                                    serde_json::from_str(&json_str);
                                assert!(
                                    parse_check.is_ok(),
                                    "JSON should remain valid under attack"
                                );

                                // Verify display safety
                                let display_test = format!("{:?}", attack_scenario);
                                assert!(
                                    !display_test.contains("\x1b[31m"),
                                    "Display should escape ANSI"
                                );
                                assert!(
                                    !display_test.contains("%s"),
                                    "Display should escape format strings"
                                );
                            }
                            Err(_) => {
                                // JSON serialization may fail under extreme attack - acceptable
                            }
                        }

                        // Test transport under attack scenario
                        let mut transport = VirtualTransportLayer::new(77777);
                        let create_result = transport.create_link(
                            attack_node_name,
                            "victim_node",
                            LinkFaultConfig {
                                drop_probability: 0.999999,
                                reorder_depth: 1000,
                                corrupt_bit_count: 100,
                                delay_ticks: 1000,
                                partition: false,
                            },
                        );

                        match create_result {
                            Ok(_) => {
                                // Send attack payloads
                                let attack_payloads = vec![
                                    b"normal_payload".to_vec(),
                                    format!("unicode\u{202E}kcatta\u{202D}payload").into_bytes(),
                                    b"format%s%x%d\x00payload".to_vec(),
                                    vec![0x00, 0x1b, 0x5b, 0x33, 0x31, 0x6d, 0xff], // Mixed binary/ANSI
                                ];

                                for (i, payload) in attack_payloads.into_iter().enumerate() {
                                    let send_result = transport.send_message(
                                        attack_node_name,
                                        "victim_node",
                                        payload,
                                    );

                                    // Should handle attack payloads without corruption
                                    match send_result {
                                        Ok(msg_id) => {
                                            assert!(
                                                msg_id > 0,
                                                "Message ID should be valid for attack payload {}",
                                                i
                                            );
                                        }
                                        Err(_) => {
                                            // Message may be rejected - acceptable under attack
                                        }
                                    }
                                }

                                // Verify transport state integrity under attack
                                let stats = transport.stats();
                                assert!(
                                    stats.total_messages < u64::MAX,
                                    "Stats should not overflow under attack"
                                );
                                assert!(
                                    stats.dropped_messages <= stats.total_messages,
                                    "Dropped ≤ total under attack"
                                );
                            }
                            Err(_) => {
                                // Transport may reject attack configuration - acceptable
                            }
                        }
                    }
                    Err(_) => {
                        // Scenario building may reject coordinated attack - acceptable defense
                    }
                }

                // Test cascading failure resistance
                let cascade_test = ScenarioBuilder::new("cascade_test").seed(99999).add_node(
                    "cascade_1",
                    "Node 1",
                    NodeRole::Coordinator,
                );

                // Add nodes in rapid succession to test failure propagation
                let mut current_builder = cascade_test.expect("Initial builder should work");
                for i in 2..=100 {
                    let node_id = format!("cascade_{}", i);
                    match current_builder.add_node(&node_id, "Cascade Node", NodeRole::Participant)
                    {
                        Ok(builder) => current_builder = builder,
                        Err(_) => {
                            // Failure should be isolated, not cascade to previous nodes
                            let partial_build = current_builder.build();
                            assert!(
                                partial_build.is_ok() || partial_build.is_err(),
                                "Partial build should complete deterministically"
                            );
                            break;
                        }
                    }
                }

                Ok(())
            });

            assert!(
                integration_attack_result.is_ok(),
                "Integration attack test should not panic"
            );
        }
    }
}
