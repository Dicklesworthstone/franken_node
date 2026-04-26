use frankenengine_node::api::fleet_quarantine::{
    ConvergencePhase, ConvergenceState, DecisionReceipt, FleetAction, FleetStatus, QuarantineScope,
    RevocationScope, RevocationSeverity,
};
use frankenengine_node::test_strategies;
use proptest::prelude::*;

fn bounded_string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 0..64)
        .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn optional_bounded_string() -> impl Strategy<Value = Option<String>> {
    prop::option::of(bounded_string())
}

fn revocation_severity() -> impl Strategy<Value = RevocationSeverity> {
    prop_oneof![
        Just(RevocationSeverity::Advisory),
        Just(RevocationSeverity::Mandatory),
        Just(RevocationSeverity::Emergency),
    ]
}

fn convergence_phase() -> impl Strategy<Value = ConvergencePhase> {
    prop_oneof![
        Just(ConvergencePhase::Pending),
        Just(ConvergencePhase::Propagating),
        Just(ConvergencePhase::Converged),
        Just(ConvergencePhase::TimedOut),
    ]
}

fn quarantine_scope() -> impl Strategy<Value = QuarantineScope> {
    (
        bounded_string(),
        optional_bounded_string(),
        any::<u32>(),
        bounded_string(),
    )
        .prop_map(
            |(zone_id, tenant_id, affected_nodes, reason)| QuarantineScope {
                zone_id,
                tenant_id,
                affected_nodes,
                reason,
            },
        )
}

fn revocation_scope() -> impl Strategy<Value = RevocationScope> {
    (
        bounded_string(),
        optional_bounded_string(),
        revocation_severity(),
        bounded_string(),
    )
        .prop_map(|(zone_id, tenant_id, severity, reason)| RevocationScope {
            zone_id,
            tenant_id,
            severity,
            reason,
        })
}

fn convergence_state() -> impl Strategy<Value = ConvergenceState> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<u8>(),
        prop::option::of(any::<u32>()),
        convergence_phase(),
    )
        .prop_map(
            |(converged_nodes, total_nodes, progress_pct, eta_seconds, phase)| ConvergenceState {
                converged_nodes,
                total_nodes,
                progress_pct,
                eta_seconds,
                phase,
            },
        )
}

fn fleet_action() -> impl Strategy<Value = FleetAction> {
    prop_oneof![
        (bounded_string(), quarantine_scope()).prop_map(|(extension_id, scope)| {
            FleetAction::Quarantine {
                extension_id,
                scope,
            }
        }),
        (bounded_string(), revocation_scope()).prop_map(|(extension_id, scope)| {
            FleetAction::Revoke {
                extension_id,
                scope,
            }
        }),
        bounded_string().prop_map(|incident_id| FleetAction::Release { incident_id }),
        (bounded_string(), bounded_string()).prop_map(|(policy_version, summary)| {
            FleetAction::PolicyUpdate {
                policy_version,
                summary,
            }
        }),
        bounded_string().prop_map(|zone_id| FleetAction::Status { zone_id }),
        Just(FleetAction::Reconcile),
    ]
}

fn fleet_status() -> impl Strategy<Value = FleetStatus> {
    (
        bounded_string(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<bool>(),
        prop::collection::vec(convergence_state(), 0..16),
    )
        .prop_map(
            |(
                zone_id,
                active_quarantines,
                active_revocations,
                healthy_nodes,
                total_nodes,
                activated,
                pending_convergences,
            )| FleetStatus {
                zone_id,
                active_quarantines,
                active_revocations,
                healthy_nodes,
                total_nodes,
                activated,
                pending_convergences,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn fleet_action_serde_roundtrip(action in fleet_action()) {
        let json = serde_json::to_string(&action)?;
        let decoded: FleetAction = serde_json::from_str(&json)?;
        prop_assert_eq!(decoded, action);
    }

    #[test]
    fn decision_receipt_serde_roundtrip(receipt in test_strategies::decision_receipts()) {
        let json = serde_json::to_string(&receipt)?;
        let decoded: DecisionReceipt = serde_json::from_str(&json)?;
        prop_assert_eq!(decoded, receipt);
    }

    #[test]
    fn fleet_status_serde_roundtrip(status in fleet_status()) {
        let json = serde_json::to_string(&status)?;
        let decoded: FleetStatus = serde_json::from_str(&json)?;
        prop_assert_eq!(decoded, status);
    }
}
