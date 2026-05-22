use frankenengine_node::connector::cancellation_protocol::assert_cancellation_protocol_conformance_for_tests;

#[test]
fn cancellation_protocol_transition_conformance_matrix() {
    assert_cancellation_protocol_conformance_for_tests();
}

#[cfg(feature = "control-plane")]
mod control_plane {
    use frankenengine_node::control_plane::cancellation_protocol as cp;
    use std::fmt::Debug;

    fn ensure(condition: bool, label: &str) -> Result<(), String> {
        if condition {
            Ok(())
        } else {
            Err(label.to_string())
        }
    }

    fn ensure_eq<T>(actual: T, expected: T, label: &str) -> Result<(), String>
    where
        T: PartialEq + Debug,
    {
        if actual == expected {
            Ok(())
        } else {
            Err(format!("{label}: expected {expected:?}, got {actual:?}"))
        }
    }

    fn cancel_error_code<T>(
        result: Result<T, cp::CancelProtocolError>,
        label: &str,
    ) -> Result<&'static str, String> {
        result
            .map(|_| Err(format!("{label}: operation unexpectedly succeeded")))
            .unwrap_or_else(|err| Ok(err.code()))
    }

    fn audit_codes(protocol: &cp::CancellationProtocol) -> Vec<&str> {
        protocol
            .audit_log()
            .iter()
            .map(|event| event.event_code.as_str())
            .collect()
    }

    fn audit_last_code(protocol: &cp::CancellationProtocol) -> Result<&str, String> {
        protocol
            .audit_log()
            .last()
            .map(|event| event.event_code.as_str())
            .ok_or_else(|| "audit log should include at least one event".to_string())
    }

    #[test]
    fn control_plane_cancellation_three_phase_must_clause_matrix() -> Result<(), String> {
        let mut protocol = cp::CancellationProtocol::new(cp::DrainConfig::new(1_000, true));

        let requested = protocol
            .request_cancel("wf-must", 3, 1_000, "trace-must")
            .map_err(|err| err.to_string())?;
        ensure_eq(
            requested.current_phase,
            cp::CancelPhase::CancelRequested,
            "CAN-001 moves idle workflow into request phase",
        )?;
        ensure_eq(
            requested.in_flight_count,
            3,
            "CAN-001 records the in-flight count",
        )?;

        let duplicate = protocol
            .request_cancel("wf-must", 99, 1_001, "trace-must")
            .map_err(|err| err.to_string())?;
        ensure_eq(
            duplicate.current_phase,
            cp::CancelPhase::CancelRequested,
            "INV-CANP-IDEMPOTENT absorbs duplicate cancel requests",
        )?;
        ensure_eq(
            duplicate.in_flight_count,
            3,
            "INV-CANP-IDEMPOTENT leaves the original in-flight count intact",
        )?;

        let draining = protocol
            .start_drain("wf-must", 1_100, "trace-must")
            .map_err(|err| err.to_string())?;
        ensure_eq(
            draining.current_phase,
            cp::CancelPhase::Draining,
            "CAN-002 starts the bounded drain phase",
        )?;

        let drained = protocol
            .complete_drain("wf-must", 1_600, "trace-must")
            .map_err(|err| err.to_string())?;
        ensure_eq(
            drained.current_phase,
            cp::CancelPhase::DrainComplete,
            "CAN-003 marks drain completion",
        )?;
        ensure_eq(
            drained.in_flight_count,
            0,
            "INV-CANP-NO-NEW-WORK drains in-flight operations to zero",
        )?;
        ensure_eq(
            drained.drain_duration_ms(),
            Some(500),
            "INV-CANP-DRAIN-BOUNDED records saturated drain duration",
        )?;

        let finalized = protocol
            .finalize(
                "wf-must",
                &cp::ResourceTracker::empty(),
                1_700,
                "trace-must",
            )
            .map_err(|err| err.to_string())?;
        ensure_eq(
            finalized.current_phase,
            cp::CancelPhase::Finalized,
            "CAN-005 finalizes clean cancellation",
        )?;
        ensure_eq(
            protocol.active_count(),
            0,
            "finalized workflows are not active cancellations",
        )?;
        ensure_eq(
            protocol.finalized_count(),
            1,
            "finalized workflow count increments",
        )?;
        ensure_eq(
            audit_codes(&protocol),
            vec![
                cp::event_codes::CAN_001,
                cp::event_codes::CAN_002,
                cp::event_codes::CAN_003,
                cp::event_codes::CAN_005,
            ],
            "INV-CANP-AUDIT-COMPLETE records every successful phase transition",
        )?;

        for event in protocol.audit_log() {
            ensure_eq(
                event.schema_version.as_str(),
                cp::SCHEMA_VERSION,
                "audit events use the control-plane cancellation schema",
            )?;
            ensure_eq(
                event.workflow_id.as_str(),
                "wf-must",
                "audit events bind to the workflow id",
            )?;
            ensure_eq(
                event.trace_id.as_str(),
                "trace-must",
                "audit events bind to the trace id",
            )?;
        }

        Ok(())
    }

    #[test]
    fn control_plane_cancellation_fail_closed_must_clause_matrix() -> Result<(), String> {
        let mut missing = cp::CancellationProtocol::default();
        let missing_code = cancel_error_code(
            missing.start_drain("wf-missing", 1_000, "trace"),
            "missing drain",
        )?;
        ensure_eq(
            missing_code,
            cp::error_codes::ERR_CANCEL_NOT_FOUND,
            "unknown workflows fail closed before drain",
        )?;
        ensure(
            missing.audit_log().is_empty(),
            "unknown workflow rejection must not emit misleading audit events",
        )?;

        let mut invalid = cp::CancellationProtocol::default();
        invalid
            .request_cancel("wf-invalid", 0, 1_000, "trace-invalid")
            .map_err(|err| err.to_string())?;
        let invalid_code = cancel_error_code(
            invalid.finalize(
                "wf-invalid",
                &cp::ResourceTracker::empty(),
                1_100,
                "trace-invalid",
            ),
            "finalize before drain",
        )?;
        ensure_eq(
            invalid_code,
            cp::error_codes::ERR_CANCEL_INVALID_PHASE,
            "finalize before drain fails closed",
        )?;
        ensure_eq(
            invalid.current_phase("wf-invalid"),
            Some(cp::CancelPhase::CancelRequested),
            "invalid finalization leaves phase unchanged",
        )?;

        let mut exact_timeout = cp::CancellationProtocol::new(cp::DrainConfig::new(1_000, false));
        exact_timeout
            .request_cancel("wf-timeout", 1, 1_000, "trace-timeout")
            .map_err(|err| err.to_string())?;
        exact_timeout
            .start_drain("wf-timeout", 1_100, "trace-timeout")
            .map_err(|err| err.to_string())?;
        let timeout_code = cancel_error_code(
            exact_timeout.complete_drain("wf-timeout", 2_100, "trace-timeout"),
            "exact timeout",
        )?;
        ensure_eq(
            timeout_code,
            cp::error_codes::ERR_CANCEL_DRAIN_TIMEOUT,
            "elapsed time equal to timeout fails closed",
        )?;
        ensure_eq(
            exact_timeout.current_phase("wf-timeout"),
            Some(cp::CancelPhase::Draining),
            "non-forced timeout remains in draining state",
        )?;
        let timeout_record = exact_timeout
            .get_record("wf-timeout")
            .ok_or_else(|| "timeout record should exist".to_string())?;
        ensure(
            timeout_record.drain_timed_out,
            "non-forced timeout records timed-out state",
        )?;
        ensure_eq(
            timeout_record.drain_complete_ms,
            None,
            "non-forced timeout does not mark drain completion",
        )?;
        ensure_eq(
            audit_last_code(&exact_timeout)?,
            cp::event_codes::CAN_004,
            "non-forced timeout emits CAN-004",
        )?;

        let mut clock_regression =
            cp::CancellationProtocol::new(cp::DrainConfig::new(1_000, false));
        clock_regression
            .request_cancel("wf-clock", 1, 1_000, "trace-clock")
            .map_err(|err| err.to_string())?;
        clock_regression
            .start_drain("wf-clock", 2_000, "trace-clock")
            .map_err(|err| err.to_string())?;
        let clock_record = clock_regression
            .complete_drain("wf-clock", 1_500, "trace-clock")
            .map_err(|err| err.to_string())?;
        ensure_eq(
            clock_record.drain_duration_ms(),
            Some(0),
            "clock regression uses saturating drain duration arithmetic",
        )?;
        ensure(
            !clock_record.drain_timed_out,
            "clock regression does not underflow into timeout",
        )?;

        let mut leak = cp::CancellationProtocol::default();
        leak.request_cancel("wf-leak", 0, 1_000, "trace-leak")
            .map_err(|err| err.to_string())?;
        leak.start_drain("wf-leak", 1_100, "trace-leak")
            .map_err(|err| err.to_string())?;
        leak.complete_drain("wf-leak", 1_200, "trace-leak")
            .map_err(|err| err.to_string())?;
        let resources = cp::ResourceTracker {
            open_handles: vec!["fd-1".to_string()],
            pending_writes: 2,
            held_locks: vec!["mutex-a".to_string()],
        };
        let leak_code = cancel_error_code(
            leak.finalize("wf-leak", &resources, 1_300, "trace-leak"),
            "resource leak",
        )?;
        ensure_eq(
            leak_code,
            cp::error_codes::ERR_CANCEL_LEAK,
            "resource leaks fail finalization closed",
        )?;
        let leak_record = leak
            .get_record("wf-leak")
            .ok_or_else(|| "leak record should exist".to_string())?;
        ensure_eq(
            leak_record.current_phase,
            cp::CancelPhase::Finalizing,
            "resource leak keeps workflow in finalizing state",
        )?;
        ensure_eq(
            leak_record.finalize_ms,
            None,
            "resource leak does not record clean finalize timestamp",
        )?;
        ensure_eq(
            leak_record.resource_leaks.as_slice(),
            &[
                "handle:fd-1".to_string(),
                "pending_writes:2".to_string(),
                "lock:mutex-a".to_string(),
            ],
            "resource leak report preserves all leak classes",
        )?;
        ensure_eq(
            audit_last_code(&leak)?,
            cp::event_codes::CAN_006,
            "resource leak emits CAN-006",
        )?;

        Ok(())
    }
}
