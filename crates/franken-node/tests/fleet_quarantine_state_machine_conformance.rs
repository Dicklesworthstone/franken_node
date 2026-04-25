use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use frankenengine_node::api::fleet_quarantine::{
    ConvergencePhase, DecisionReceipt, DecisionReceiptPayload, FleetActionResult,
    FleetControlError, FleetControlManager, QuarantineScope, RevocationScope, RevocationSeverity,
    canonical_decision_receipt_payload_hash, sign_decision_receipt,
};
use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("fixtures/fleet_quarantine_state_machine_vectors.json");
const VECTOR_SCHEMA_VERSION: &str = "franken-node/fleet-quarantine-state-machine-conformance/v1";
const SIGNING_KEY_BYTES: [u8; 32] = [73_u8; 32];
const SIGNING_KEY_SOURCE: &str = "fleet-quarantine-state-machine-conformance";
const SIGNING_IDENTITY: &str = "fleet-quarantine-state-machine";
const ADMIN_PRINCIPAL: &str = "fleet-state-machine-admin";
const QUARANTINE_ZONE_ID: &str = "zone-conformance-quarantine";
const REVOCATION_ZONE_ID: &str = "zone-conformance-revocation";

type TestResult = Result<(), String>;

#[derive(Debug, Deserialize)]
struct FleetStateMachineVectors {
    schema_version: String,
    coverage: Vec<CoverageRow>,
    vectors: Vec<TransitionVector>,
}

#[derive(Debug, Deserialize)]
struct CoverageRow {
    spec_section: String,
    level: String,
    tested: bool,
}

#[derive(Debug, Deserialize)]
struct TransitionVector {
    name: String,
    current_state: FleetStateName,
    event: FleetEventName,
    expected_next_state: FleetStateName,
    expected_side_effects: ExpectedSideEffects,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FleetStateName {
    Healthy,
    QuarantinedPropagating,
    QuarantinedConverged,
    EscalatedRevocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FleetEventName {
    Quarantine,
    Reconcile,
    ReleaseWithValidRollback,
    ReleaseWithExpiredRollback,
    EmergencyRevoke,
}

#[derive(Debug, Deserialize)]
struct ExpectedSideEffects {
    success: bool,
    event_code: Option<String>,
    error_code: Option<String>,
    action_type: Option<String>,
    receipt_action_type: Option<String>,
    convergence_phase: Option<String>,
    incident_count_delta: i64,
    active_incidents_delta: i64,
    active_quarantines_delta: i64,
    active_revocations_delta: i64,
    pending_convergences_delta: i64,
    event_count_delta: i64,
}

#[derive(Debug, Clone)]
struct ScenarioContext {
    zone_id: &'static str,
    incident_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct StateSnapshot {
    incident_count: i64,
    active_incidents: i64,
    active_quarantines: i64,
    active_revocations: i64,
    pending_convergences: i64,
    event_count: i64,
}

enum TransitionOutcome {
    Success(FleetActionResult),
    Failure(FleetControlError),
}

fn load_vectors() -> Result<FleetStateMachineVectors, String> {
    serde_json::from_str(VECTORS_JSON)
        .map_err(|err| format!("fleet quarantine state-machine vectors must parse: {err}"))
}

fn admin_identity() -> AuthIdentity {
    AuthIdentity {
        principal: ADMIN_PRINCIPAL.to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string()],
    }
}

fn trace_context(label: &str) -> TraceContext {
    TraceContext {
        trace_id: format!("fleet-state-machine-{label}"),
        span_id: "0000000000000001".to_string(),
        trace_flags: 1,
    }
}

fn activated_manager() -> FleetControlManager {
    let mut manager = FleetControlManager::with_decision_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&SIGNING_KEY_BYTES),
        SIGNING_KEY_SOURCE,
        SIGNING_IDENTITY,
    );
    manager.activate();
    manager
}

fn quarantine_scope() -> QuarantineScope {
    QuarantineScope {
        zone_id: QUARANTINE_ZONE_ID.to_string(),
        tenant_id: Some("tenant-conformance".to_string()),
        affected_nodes: 3,
        reason: "state machine conformance quarantine".to_string(),
    }
}

fn emergency_revocation_scope() -> RevocationScope {
    RevocationScope {
        zone_id: REVOCATION_ZONE_ID.to_string(),
        tenant_id: Some("tenant-conformance".to_string()),
        severity: RevocationSeverity::Emergency,
        reason: "state machine conformance escalation".to_string(),
    }
}

fn rollback_receipt(
    incident_id: &str,
    zone_id: &str,
    issued_at: chrono::DateTime<Utc>,
) -> DecisionReceipt {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&SIGNING_KEY_BYTES);
    let operation_id = format!("rollback-{incident_id}");
    let issued_at = issued_at.to_rfc3339();
    let decision_payload =
        DecisionReceiptPayload::rollback(incident_id, zone_id, "state-machine rollback receipt");
    let payload_hash = canonical_decision_receipt_payload_hash(
        &operation_id,
        ADMIN_PRINCIPAL,
        zone_id,
        &issued_at,
        &decision_payload,
    );
    let mut receipt = DecisionReceipt {
        operation_id: operation_id.clone(),
        receipt_id: format!("rcpt-{operation_id}"),
        issuer: ADMIN_PRINCIPAL.to_string(),
        issued_at,
        zone_id: zone_id.to_string(),
        payload_hash,
        decision_payload,
        signature: None,
    };
    receipt.signature = Some(sign_decision_receipt(
        &receipt,
        &signing_key,
        SIGNING_KEY_SOURCE,
        SIGNING_IDENTITY,
    ));
    receipt
}

fn phase_tag(phase: ConvergencePhase) -> &'static str {
    match phase {
        ConvergencePhase::Pending => "pending",
        ConvergencePhase::Propagating => "propagating",
        ConvergencePhase::Converged => "converged",
        ConvergencePhase::TimedOut => "timed_out",
    }
}

fn zone_for_transition(current_state: FleetStateName, event: FleetEventName) -> &'static str {
    if current_state == FleetStateName::EscalatedRevocation
        || event == FleetEventName::EmergencyRevoke
    {
        REVOCATION_ZONE_ID
    } else {
        QUARANTINE_ZONE_ID
    }
}

fn snapshot(manager: &FleetControlManager, zone_id: &str) -> Result<StateSnapshot, String> {
    let status = manager
        .status(zone_id)
        .map_err(|err| format!("failed to read fleet status for `{zone_id}`: {err:?}"))?;
    Ok(StateSnapshot {
        incident_count: i64::try_from(manager.incident_count())
            .map_err(|_| "incident_count overflowed i64".to_string())?,
        active_incidents: i64::try_from(manager.active_incidents().len())
            .map_err(|_| "active_incidents overflowed i64".to_string())?,
        active_quarantines: i64::from(status.active_quarantines),
        active_revocations: i64::from(status.active_revocations),
        pending_convergences: i64::try_from(status.pending_convergences.len())
            .map_err(|_| "pending_convergences overflowed i64".to_string())?,
        event_count: i64::try_from(manager.events().len())
            .map_err(|_| "event_count overflowed i64".to_string())?,
    })
}

fn assert_state_matches(
    manager: &FleetControlManager,
    zone_id: &str,
    expected: FleetStateName,
    vector_name: &str,
    context: &str,
) -> TestResult {
    let status = manager
        .status(zone_id)
        .map_err(|err| format!("{vector_name}: {context} status lookup failed: {err:?}"))?;
    match expected {
        FleetStateName::Healthy => {
            if manager.incident_count() != 0
                || !manager.active_incidents().is_empty()
                || status.active_quarantines != 0
                || status.active_revocations != 0
                || !status.pending_convergences.is_empty()
            {
                return Err(format!(
                    "{vector_name}: {context} expected healthy state, got incidents={} active_incidents={} active_quarantines={} active_revocations={} pending_convergences={}",
                    manager.incident_count(),
                    manager.active_incidents().len(),
                    status.active_quarantines,
                    status.active_revocations,
                    status.pending_convergences.len(),
                ));
            }
        }
        FleetStateName::QuarantinedPropagating => {
            let pending_phase = status.pending_convergences.first().map(|state| state.phase);
            if manager.incident_count() != 1
                || manager.active_incidents().len() != 1
                || status.active_quarantines != 1
                || status.active_revocations != 0
                || status.pending_convergences.len() != 1
                || pending_phase != Some(ConvergencePhase::Propagating)
            {
                return Err(format!(
                    "{vector_name}: {context} expected propagating quarantine, got incidents={} active_incidents={} active_quarantines={} active_revocations={} pending_convergences={} pending_phase={:?}",
                    manager.incident_count(),
                    manager.active_incidents().len(),
                    status.active_quarantines,
                    status.active_revocations,
                    status.pending_convergences.len(),
                    pending_phase,
                ));
            }
        }
        FleetStateName::QuarantinedConverged => {
            if manager.incident_count() != 1
                || manager.active_incidents().len() != 1
                || status.active_quarantines != 1
                || status.active_revocations != 0
                || !status.pending_convergences.is_empty()
            {
                return Err(format!(
                    "{vector_name}: {context} expected converged quarantine, got incidents={} active_incidents={} active_quarantines={} active_revocations={} pending_convergences={}",
                    manager.incident_count(),
                    manager.active_incidents().len(),
                    status.active_quarantines,
                    status.active_revocations,
                    status.pending_convergences.len(),
                ));
            }
        }
        FleetStateName::EscalatedRevocation => {
            if manager.incident_count() != 1
                || manager.active_incidents().len() != 1
                || status.active_quarantines != 0
                || status.active_revocations != 1
                || !status.pending_convergences.is_empty()
            {
                return Err(format!(
                    "{vector_name}: {context} expected escalated revocation, got incidents={} active_incidents={} active_quarantines={} active_revocations={} pending_convergences={}",
                    manager.incident_count(),
                    manager.active_incidents().len(),
                    status.active_quarantines,
                    status.active_revocations,
                    status.pending_convergences.len(),
                ));
            }
        }
    }
    Ok(())
}

fn setup_state(
    manager: &mut FleetControlManager,
    current_state: FleetStateName,
    zone_id: &'static str,
) -> Result<ScenarioContext, String> {
    match current_state {
        FleetStateName::Healthy => Ok(ScenarioContext {
            zone_id,
            incident_id: None,
        }),
        FleetStateName::QuarantinedPropagating => {
            let result = manager
                .quarantine(
                    "ext-conformance-quarantine",
                    &quarantine_scope(),
                    &admin_identity(),
                    &trace_context("setup-quarantine"),
                )
                .map_err(|err| format!("failed to set up propagating quarantine: {err:?}"))?;
            Ok(ScenarioContext {
                zone_id,
                incident_id: Some(format!("inc-{}", result.operation_id)),
            })
        }
        FleetStateName::QuarantinedConverged => {
            let result = manager
                .quarantine(
                    "ext-conformance-quarantine",
                    &quarantine_scope(),
                    &admin_identity(),
                    &trace_context("setup-quarantine"),
                )
                .map_err(|err| format!("failed to set up converged quarantine: {err:?}"))?;
            manager
                .reconcile(&admin_identity(), &trace_context("setup-reconcile"))
                .map_err(|err| format!("failed to reconcile setup quarantine: {err:?}"))?;
            Ok(ScenarioContext {
                zone_id,
                incident_id: Some(format!("inc-{}", result.operation_id)),
            })
        }
        FleetStateName::EscalatedRevocation => {
            let result = manager
                .revoke(
                    "ext-conformance-revocation",
                    &emergency_revocation_scope(),
                    &admin_identity(),
                    &trace_context("setup-emergency-revoke"),
                )
                .map_err(|err| format!("failed to set up escalated revocation: {err:?}"))?;
            Ok(ScenarioContext {
                zone_id,
                incident_id: Some(format!("inc-{}", result.operation_id)),
            })
        }
    }
}

fn apply_event(
    manager: &mut FleetControlManager,
    vector: &TransitionVector,
    context: &ScenarioContext,
) -> Result<TransitionOutcome, String> {
    let label = vector.name.replace('_', "-");
    let outcome = match vector.event {
        FleetEventName::Quarantine => manager.quarantine(
            "ext-conformance-quarantine",
            &quarantine_scope(),
            &admin_identity(),
            &trace_context(&label),
        ),
        FleetEventName::Reconcile => manager.reconcile(&admin_identity(), &trace_context(&label)),
        FleetEventName::ReleaseWithValidRollback => {
            let incident_id = context
                .incident_id
                .as_deref()
                .ok_or_else(|| format!("{}: release event requires an incident id", vector.name))?;
            manager.register_rollback_receipt(
                incident_id,
                rollback_receipt(incident_id, context.zone_id, Utc::now()),
            );
            manager.release(incident_id, &admin_identity(), &trace_context(&label))
        }
        FleetEventName::ReleaseWithExpiredRollback => {
            let incident_id = context
                .incident_id
                .as_deref()
                .ok_or_else(|| format!("{}: release event requires an incident id", vector.name))?;
            manager.register_rollback_receipt(
                incident_id,
                rollback_receipt(
                    incident_id,
                    context.zone_id,
                    Utc::now() - Duration::hours(48),
                ),
            );
            manager.release(incident_id, &admin_identity(), &trace_context(&label))
        }
        FleetEventName::EmergencyRevoke => manager.revoke(
            "ext-conformance-revocation",
            &emergency_revocation_scope(),
            &admin_identity(),
            &trace_context(&label),
        ),
    };

    Ok(match outcome {
        Ok(result) => TransitionOutcome::Success(result),
        Err(err) => TransitionOutcome::Failure(err),
    })
}

fn assert_delta(vector_name: &str, label: &str, actual: i64, expected: i64) -> TestResult {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{vector_name}: {label} delta mismatch: expected {expected}, got {actual}"
        ))
    }
}

fn assert_side_effects(
    vector: &TransitionVector,
    before: StateSnapshot,
    after: StateSnapshot,
    outcome: &TransitionOutcome,
) -> TestResult {
    assert_delta(
        &vector.name,
        "incident_count",
        after.incident_count - before.incident_count,
        vector.expected_side_effects.incident_count_delta,
    )?;
    assert_delta(
        &vector.name,
        "active_incidents",
        after.active_incidents - before.active_incidents,
        vector.expected_side_effects.active_incidents_delta,
    )?;
    assert_delta(
        &vector.name,
        "active_quarantines",
        after.active_quarantines - before.active_quarantines,
        vector.expected_side_effects.active_quarantines_delta,
    )?;
    assert_delta(
        &vector.name,
        "active_revocations",
        after.active_revocations - before.active_revocations,
        vector.expected_side_effects.active_revocations_delta,
    )?;
    assert_delta(
        &vector.name,
        "pending_convergences",
        after.pending_convergences - before.pending_convergences,
        vector.expected_side_effects.pending_convergences_delta,
    )?;
    assert_delta(
        &vector.name,
        "event_count",
        after.event_count - before.event_count,
        vector.expected_side_effects.event_count_delta,
    )?;

    match outcome {
        TransitionOutcome::Success(result) => {
            if !vector.expected_side_effects.success {
                return Err(format!(
                    "{}: expected failure, got success action_type={}",
                    vector.name, result.action_type
                ));
            }
            if let Some(expected) = &vector.expected_side_effects.event_code
                && &result.event_code != expected
            {
                return Err(format!(
                    "{}: event_code mismatch: expected {}, got {}",
                    vector.name, expected, result.event_code
                ));
            }
            if let Some(expected) = &vector.expected_side_effects.action_type
                && &result.action_type != expected
            {
                return Err(format!(
                    "{}: action_type mismatch: expected {}, got {}",
                    vector.name, expected, result.action_type
                ));
            }
            if let Some(expected) = &vector.expected_side_effects.receipt_action_type
                && &result.receipt.decision_payload.action_type != expected
            {
                return Err(format!(
                    "{}: receipt action mismatch: expected {}, got {}",
                    vector.name, expected, result.receipt.decision_payload.action_type
                ));
            }
            let actual_phase = result
                .convergence
                .as_ref()
                .map(|state| phase_tag(state.phase));
            let expected_phase = vector.expected_side_effects.convergence_phase.as_deref();
            if actual_phase != expected_phase {
                return Err(format!(
                    "{}: convergence phase mismatch: expected {:?}, got {:?}",
                    vector.name, expected_phase, actual_phase
                ));
            }
        }
        TransitionOutcome::Failure(err) => {
            if vector.expected_side_effects.success {
                return Err(format!(
                    "{}: expected success, got error {:?}",
                    vector.name, err
                ));
            }
            if let Some(expected) = &vector.expected_side_effects.error_code
                && err.error_code() != expected
            {
                return Err(format!(
                    "{}: error_code mismatch: expected {}, got {}",
                    vector.name,
                    expected,
                    err.error_code()
                ));
            }
        }
    }

    Ok(())
}

fn run_vector(vector: &TransitionVector) -> TestResult {
    let mut manager = activated_manager();
    let zone_id = zone_for_transition(vector.current_state, vector.event);
    let context = setup_state(&mut manager, vector.current_state, zone_id)?;

    assert_state_matches(
        &manager,
        zone_id,
        vector.current_state,
        &vector.name,
        "setup",
    )?;

    let before = snapshot(&manager, zone_id)?;
    let outcome = apply_event(&mut manager, vector, &context)?;
    let after = snapshot(&manager, zone_id)?;

    assert_side_effects(vector, before, after, &outcome)?;
    assert_state_matches(
        &manager,
        zone_id,
        vector.expected_next_state,
        &vector.name,
        "post-transition",
    )?;

    Ok(())
}

#[test]
fn fleet_quarantine_state_machine_vectors_cover_required_contract() -> TestResult {
    let vectors = load_vectors()?;
    if vectors.schema_version != VECTOR_SCHEMA_VERSION {
        return Err(format!(
            "schema version mismatch: expected `{VECTOR_SCHEMA_VERSION}`, got `{}`",
            vectors.schema_version
        ));
    }
    if vectors.vectors.len() < 5 {
        return Err(
            "fleet quarantine conformance matrix must contain at least five vectors".into(),
        );
    }
    let unique_names = vectors
        .vectors
        .iter()
        .map(|vector| vector.name.as_str())
        .collect::<BTreeSet<_>>();
    if unique_names.len() != vectors.vectors.len() {
        return Err("fleet quarantine conformance vector names must be unique".into());
    }

    for required_section in [
        "quarantine_transition",
        "reconcile_transition",
        "release_transition",
        "expired_rollback_receipt_boundary",
        "emergency_revocation_escalation",
        "escalated_release_transition",
    ] {
        let covered = vectors
            .coverage
            .iter()
            .any(|row| row.spec_section == required_section && row.level == "must" && row.tested);
        if !covered {
            return Err(format!(
                "{required_section} must be marked tested in the conformance coverage matrix"
            ));
        }
    }

    Ok(())
}

#[test]
fn fleet_quarantine_state_machine_vectors_match_authoritative_manager() -> TestResult {
    let vectors = load_vectors()?;
    for vector in &vectors.vectors {
        run_vector(vector)?;
    }
    Ok(())
}
