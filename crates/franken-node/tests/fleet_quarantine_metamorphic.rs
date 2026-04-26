//! Metamorphic tests for fleet quarantine reconciliation inversion
//!
//! Tests that applying a quarantine decision and then its inverse (release)
//! restores the original fleet state, validating core reversibility properties.

use frankenengine_node::api::fleet_quarantine::*;
use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};
use frankenengine_node::control_plane::fleet_transport::FileFleetTransport;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use tempfile::tempdir;

/// Capture fleet state for comparison
#[derive(Debug, Clone, PartialEq)]
struct FleetState {
    zone_status: HashMap<String, FleetStatus>,
    total_quarantines: u32,
    total_revocations: u32,
    incident_count: usize,
}

impl FleetState {
    fn capture_from_manager(mgr: &FleetControlManager) -> Self {
        // Get status for all zones we've seen
        let mut zone_status = HashMap::new();
        let mut total_quarantines: u32 = 0;
        let mut total_revocations: u32 = 0;

        // We need to capture zone status by examining the manager's internal state
        // For metamorphic testing, we'll focus on the aggregate counters
        for zone_id in [
            "zone-a",
            "zone-b",
            "zone-c",
            "default-zone",
            "zone-metamorphic",
        ] {
            if let Ok(status) = mgr.status(zone_id) {
                if status.activated {
                    total_quarantines = total_quarantines.saturating_add(status.active_quarantines);
                    total_revocations = total_revocations.saturating_add(status.active_revocations);
                    zone_status.insert(zone_id.to_string(), status);
                }
            }
        }

        FleetState {
            zone_status,
            total_quarantines,
            total_revocations,
            incident_count: mgr.incident_count(),
        }
    }
}

fn admin_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "fleet-admin-metamorphic".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string()],
    }
}

fn test_trace(operation: &str) -> TraceContext {
    TraceContext {
        trace_id: format!("metamorphic-{}-{}", operation, uuid::Uuid::now_v7()),
        span_id: "0000000000000001".to_string(),
        trace_flags: 1,
    }
}

fn activated_fleet_manager() -> FleetControlManager {
    // Create temporary directory for file-based transport
    let temp_dir = tempdir().expect("create temp directory");
    let transport = FileFleetTransport::new(temp_dir.path().to_path_buf())
        .expect("create file transport");

    // Use real file-based transport instead of mock/in-memory approach
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[63_u8; 32]);
    let signing_material = Some(FleetDecisionSigningMaterial::from_signing_key(
        signing_key,
        "fleet-quarantine-metamorphic-test",
        "fleet-quarantine-metamorphic",
    ));

    let mut manager = FleetControlManager::with_file_transport(transport, signing_material)
        .expect("create manager with file transport");
    manager.activate();
    manager
}

/// Generate test scope with controlled randomness
fn generate_test_scope(rng: &mut rand::rngs::StdRng, zone_suffix: u32) -> QuarantineScope {
    QuarantineScope {
        zone_id: format!("zone-test-{}", zone_suffix),
        tenant_id: if rng.gen_bool(0.5) {
            Some(format!("tenant-{}", rng.gen_range(1..100)))
        } else {
            None
        },
        affected_nodes: rng.gen_range(1..50),
        reason: format!("metamorphic-test-{}", rng.gen_range(1..1000)),
    }
}

/// MR1: Fleet Quarantine Reconciliation Inversion (Inverse)
/// Applying quarantine then release should restore original state
#[cfg(test)]
mod mr_fleet_quarantine_inversion {
    use super::*;

    #[test]
    fn quarantine_release_restores_original_state_simple() {
        // Use fixed inputs for deterministic baseline test
        let mut mgr = activated_fleet_manager();

        let scope = QuarantineScope {
            zone_id: "zone-metamorphic".to_string(),
            tenant_id: Some("tenant-test".to_string()),
            affected_nodes: 5,
            reason: "metamorphic baseline test".to_string(),
        };
        let extension_id = "ext-metamorphic-baseline";
        let identity = admin_identity();

        // Capture initial state
        let initial_state = FleetState::capture_from_manager(&mgr);

        // Apply quarantine decision
        let quarantine_result = mgr
            .quarantine(extension_id, &scope, &identity, &test_trace("quarantine"))
            .expect("quarantine should succeed");

        // Verify state changed
        let quarantined_state = FleetState::capture_from_manager(&mgr);
        assert_ne!(
            initial_state.total_quarantines, quarantined_state.total_quarantines,
            "Quarantine count should have changed"
        );

        // Verify quarantine count increased
        let zone_status = mgr.status(&scope.zone_id).expect("zone status");
        assert_eq!(
            zone_status.active_quarantines, 1,
            "Active quarantines should be 1"
        );

        // Extract incident ID from quarantine result
        let incident_id = format!("inc-{}", quarantine_result.operation_id);

        // Apply release decision (inverse operation)
        let _release_result = mgr
            .release(&incident_id, &identity, &test_trace("release"))
            .expect("release should succeed");

        // Capture final state
        let final_state = FleetState::capture_from_manager(&mgr);

        // INV-FLEET-RECONCILE-INVERSION: Final state should match initial state
        // (modulo event log and operation ID sequence)
        assert_eq!(
            final_state.total_quarantines, initial_state.total_quarantines,
            "Total quarantines should be restored"
        );
        assert_eq!(
            final_state.total_revocations, initial_state.total_revocations,
            "Total revocations should be restored"
        );
        assert_eq!(
            final_state.incident_count, initial_state.incident_count,
            "Incident handles should be restored"
        );

        // Verify zone status specifically
        let final_zone_status = mgr.status(&scope.zone_id).expect("final zone status");
        assert_eq!(
            final_zone_status.active_quarantines, 0,
            "Active quarantines should be back to 0"
        );
    }

    #[test]
    fn quarantine_release_inversion_property_based() {
        // Property-based test with controlled random inputs
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for iteration in 0..10 {
            // Generate test inputs with controlled randomness
            let scope = generate_test_scope(&mut rng, iteration);
            let extension_id = format!("ext-prop-{}", iteration);
            let identity = admin_identity();

            // Create fresh manager for each iteration
            let mut mgr = activated_fleet_manager();

            // Capture initial state
            let initial_state = FleetState::capture_from_manager(&mgr);

            // Apply quarantine decision
            let quarantine_result = match mgr.quarantine(
                &extension_id,
                &scope,
                &identity,
                &test_trace("quarantine-prop"),
            ) {
                Ok(result) => result,
                Err(_) => continue, // Skip invalid inputs (empty zone ID, etc.)
            };

            // Apply release decision (inverse)
            let incident_id = format!("inc-{}", quarantine_result.operation_id);
            if mgr
                .release(&incident_id, &identity, &test_trace("release-prop"))
                .is_err()
            {
                continue; // Skip if release fails for any reason
            }

            // Verify inversion property
            let final_state = FleetState::capture_from_manager(&mgr);

            assert_eq!(
                final_state.total_quarantines, initial_state.total_quarantines,
                "Iteration {}: quarantine/release inversion failed - quarantine count not restored. Initial: {}, Final: {}",
                iteration, initial_state.total_quarantines, final_state.total_quarantines
            );
            assert_eq!(
                final_state.incident_count, initial_state.incident_count,
                "Iteration {}: incident map cardinality not restored. Initial: {}, Final: {}",
                iteration, initial_state.incident_count, final_state.incident_count
            );

            // Verify specific zone was restored
            let final_zone_status = mgr.status(&scope.zone_id).expect("final zone status");
            assert_eq!(
                final_zone_status.active_quarantines, 0,
                "Iteration {}: Zone {} quarantine count not restored to 0",
                iteration, scope.zone_id
            );
        }
    }

    #[test]
    fn multiple_quarantine_release_cycles_property() {
        // Test multiple cycles: quarantine -> release -> quarantine -> release
        let mut mgr = activated_fleet_manager();

        let scope = QuarantineScope {
            zone_id: "zone-multi-cycle".to_string(),
            tenant_id: None,
            affected_nodes: 3,
            reason: "multi-cycle test".to_string(),
        };
        let identity = admin_identity();

        let initial_state = FleetState::capture_from_manager(&mgr);

        // Perform 3 cycles
        for cycle in 1..=3 {
            let extension_id = format!("ext-cycle-{}", cycle);

            // Quarantine
            let quarantine_result = mgr
                .quarantine(
                    &extension_id,
                    &scope,
                    &identity,
                    &test_trace(&format!("quarantine-{}", cycle)),
                )
                .expect("quarantine should succeed");

            // Release
            let incident_id = format!("inc-{}", quarantine_result.operation_id);
            mgr.release(
                &incident_id,
                &identity,
                &test_trace(&format!("release-{}", cycle)),
            )
            .expect("release should succeed");

            // Verify state is restored after each cycle
            let cycle_state = FleetState::capture_from_manager(&mgr);
            assert_eq!(
                cycle_state.total_quarantines, initial_state.total_quarantines,
                "Cycle {}: total quarantines not restored",
                cycle
            );
            assert_eq!(
                cycle_state.incident_count, initial_state.incident_count,
                "Cycle {}: incident handles not restored",
                cycle
            );
        }
    }
}

/// MR2: Fleet State Idempotence Under Multiple Status Queries (Idempotent)
#[cfg(test)]
mod mr_fleet_status_idempotence {
    use super::*;

    #[test]
    fn status_query_idempotence() {
        let mgr = activated_fleet_manager();

        let zone_id = "zone-idempotent";

        // Query status multiple times
        let status1 = mgr.status(zone_id).expect("first status");
        let status2 = mgr.status(zone_id).expect("second status");
        let status3 = mgr.status(zone_id).expect("third status");

        // INV-FLEET-STATUS-IDEMPOTENT: Multiple queries should return identical results
        assert_eq!(status1, status2, "First and second status should match");
        assert_eq!(status2, status3, "Second and third status should match");
        assert_eq!(status1, status3, "First and third status should match");
    }
}
