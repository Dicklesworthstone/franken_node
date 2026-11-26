//! One bounded, resumable maintenance-owned fleet policy rollout.
//!
//! A stable operation ID binds all three immutable actions. Every observation
//! retains the full action prefix and participant union. Only the coordinator's
//! guarded transaction may turn an acknowledged policy snapshot into a resume.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fleet_transport::{
    FleetAction, FleetActionRecord, FleetGuardedPolicyReceipt, FleetGuardedResumeReceipt,
    FleetNativeSessionHoldEvidence, FleetNativeSessionHoldTarget, FleetPolicyArtifact,
    FleetPolicyMaintenanceGuard, FleetSharedState, FleetTransport, FleetTransportError,
    GuardedFleetNativeSessionResume, GuardedFleetPolicyPublication, MAX_GUARDED_POLICY_STALE_AFTER,
    fleet_action_log_checkpoint, fleet_native_session_hold_evidence, fleet_native_session_holds,
    validate_action_id, validate_action_record, validate_fleet_policy_publication,
    validate_zone_id,
};

pub const FLEET_POLICY_ROLLOUT_SCHEMA: &str = "franken-node/fleet-policy-rollout/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetPolicyRolloutPhase {
    Holding,
    Publishing,
    Applying,
    Resuming,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPolicyRolloutReport {
    pub schema_version: String,
    pub rollout_id: String,
    pub zone_id: String,
    pub policy: FleetPolicyArtifact,
    pub hold_action_id: String,
    pub policy_action_id: String,
    pub resume_action_id: String,
    pub phase: FleetPolicyRolloutPhase,
    pub completed: bool,
    pub timed_out: bool,
    pub elapsed_millis: u64,
    pub error: Option<String>,
    pub evidence: Option<FleetNativeSessionHoldEvidence>,
    pub guarded_publication: Option<FleetGuardedPolicyReceipt>,
    pub guarded_resume: Option<FleetGuardedResumeReceipt>,
    pub fleet_quiescence_certified: bool,
}

/// Create before connecting so initialization, network requests, waits and
/// mutations all consume the same monotonic budget. Wall time bounds the
/// coordinator's final release authorization independently of the caller.
pub struct FleetPolicyRollout {
    rollout_id: String,
    zone_id: String,
    artifact: FleetPolicyArtifact,
    started: Instant,
    deadline: Instant,
    expires_at: DateTime<Utc>,
    poll_interval: Duration,
    stale_after: Duration,
    hold_id: String,
    policy_id: String,
    resume_id: String,
}

impl FleetPolicyRollout {
    pub fn new(
        rollout_id: &str,
        zone_id: &str,
        artifact: FleetPolicyArtifact,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self, FleetTransportError> {
        validate_action_id(rollout_id)?;
        validate_zone_id(zone_id)?;
        artifact.validate()?;
        if timeout.is_zero()
            || timeout > Duration::from_secs(86_400)
            || poll_interval < Duration::from_millis(10)
            || poll_interval > Duration::from_secs(5)
            || poll_interval > timeout
        {
            return Err(FleetTransportError::serialization(
                "rollout timeout must be 1ns..=24h and polling 10ms..=5s within that budget",
            ));
        }
        let started = Instant::now();
        let deadline = started.checked_add(timeout).ok_or_else(|| {
            FleetTransportError::serialization("rollout monotonic deadline overflow")
        })?;
        let expires_at = Utc::now()
            .checked_add_signed(
                chrono::TimeDelta::from_std(timeout)
                    .map_err(|error| FleetTransportError::serialization(error.to_string()))?,
            )
            .ok_or_else(|| {
                FleetTransportError::serialization("rollout wall-clock deadline overflow")
            })?;
        let identity = hex::encode(Sha256::digest(rollout_id.as_bytes()));
        Ok(Self {
            rollout_id: rollout_id.to_owned(),
            zone_id: zone_id.to_owned(),
            artifact,
            started,
            deadline,
            expires_at,
            poll_interval,
            stale_after: timeout.min(MAX_GUARDED_POLICY_STALE_AFTER),
            hold_id: format!("fleet-rollout-{identity}-hold"),
            policy_id: format!("fleet-rollout-{identity}-policy"),
            resume_id: format!("fleet-rollout-{identity}-resume"),
        })
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn run(&self, transport: &mut impl FleetTransport) -> FleetPolicyRolloutReport {
        let mut report = FleetPolicyRolloutReport {
            schema_version: FLEET_POLICY_ROLLOUT_SCHEMA.to_owned(),
            rollout_id: self.rollout_id.clone(),
            zone_id: self.zone_id.clone(),
            policy: self.artifact.clone(),
            hold_action_id: self.hold_id.clone(),
            policy_action_id: self.policy_id.clone(),
            resume_action_id: self.resume_id.clone(),
            phase: FleetPolicyRolloutPhase::Holding,
            completed: false,
            timed_out: false,
            elapsed_millis: 0,
            error: None,
            evidence: None,
            guarded_publication: None,
            guarded_resume: None,
            fleet_quiescence_certified: false,
        };
        if let Err(error) = self.run_inner(transport, &mut report) {
            report.error = Some(error.to_string());
        }
        report.timed_out = !report.completed && Instant::now() >= self.deadline;
        report.elapsed_millis =
            u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // The transport belongs to this operation; clearing the budget permits
        // callers to inspect its durable state after a timeout.
        if let Err(error) = transport.set_operation_deadline(None)
            && report.error.is_none()
        {
            report.error = Some(error.to_string());
        }
        report
    }

    fn check_deadline(&self) -> Result<(), FleetTransportError> {
        if Instant::now() >= self.deadline {
            return Err(FleetTransportError::stale_state(
                "fleet policy rollout deadline elapsed; retry the same ID, zone and policy to recover its durable stage",
            ));
        }
        Ok(())
    }

    fn pause(&self) -> Result<(), FleetTransportError> {
        self.check_deadline()?;
        std::thread::sleep(
            self.poll_interval
                .min(self.deadline.saturating_duration_since(Instant::now())),
        );
        self.check_deadline()
    }

    fn guard(
        &self,
        state: &FleetSharedState,
        required: &BTreeSet<(String, String)>,
    ) -> Result<FleetPolicyMaintenanceGuard, FleetTransportError> {
        Ok(FleetPolicyMaintenanceGuard {
            hold_action_id: self.hold_id.clone(),
            expected_action_log: fleet_action_log_checkpoint(&state.actions)?,
            required_nodes: required.clone(),
            stale_after: self.stale_after,
        })
    }

    fn observe(
        &self,
        transport: &impl FleetTransport,
        retained: &mut Vec<FleetActionRecord>,
        required: &mut BTreeSet<(String, String)>,
    ) -> Result<FleetSharedState, FleetTransportError> {
        self.check_deadline()?;
        let state = transport.read_shared_state()?;
        self.check_deadline()?;
        if !state.actions.starts_with(retained) {
            return Err(FleetTransportError::stale_state(
                "rollout lost or rewrote a retained action; refusing further transitions, retry the same rollout ID to inspect durable state",
            ));
        }
        fleet_action_log_checkpoint(&state.actions)?;
        required.extend(
            state
                .nodes
                .iter()
                .filter(|node| self.zone_id == "all" || node.zone_id == self.zone_id)
                .map(|node| (node.zone_id.clone(), node.node_id.clone())),
        );
        *retained = state.actions.clone();
        Ok(state)
    }

    fn immutable_action(
        &self,
        state: &FleetSharedState,
        id: &str,
        action: FleetAction,
    ) -> Result<FleetActionRecord, FleetTransportError> {
        if let Some(retained) = state.actions.iter().find(|record| record.action_id == id) {
            if retained.action != action {
                return Err(FleetTransportError::action_conflict(
                    "rollout ID already binds a different policy, revision, zone or action",
                ));
            }
            return Ok(retained.clone());
        }
        let record = FleetActionRecord {
            action_id: id.to_owned(),
            emitted_at: Utc::now(),
            action,
        };
        validate_action_record(&record)?;
        Ok(record)
    }

    fn run_inner(
        &self,
        transport: &mut impl FleetTransport,
        report: &mut FleetPolicyRolloutReport,
    ) -> Result<(), FleetTransportError> {
        transport.set_operation_deadline(Some(self.deadline))?;
        let mut retained = Vec::new();
        let mut required = BTreeSet::new();
        let mut state = self.observe(transport, &mut retained, &mut required)?;
        let hold = self.immutable_action(
            &state,
            &self.hold_id,
            FleetAction::NativeSessionHold {
                zone_id: self.zone_id.clone(),
                reason: format!(
                    "guarded policy rollout {}: sha256={}",
                    self.rollout_id, self.artifact.content_sha256
                ),
            },
        )?;
        let fields = serde_json::to_value(&self.artifact.policy)
            .map_err(|error| FleetTransportError::serialization(error.to_string()))?
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .filter(|(_, value)| value.as_bool() != Some(false))
                    .map(|(name, _)| name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let policy = self.immutable_action(
            &state,
            &self.policy_id,
            FleetAction::PolicyUpdate {
                zone_id: self.zone_id.clone(),
                policy_version: format!("revision-{}", self.artifact.revision),
                changed_fields: fields,
                artifact: Some(self.artifact.clone()),
            },
        )?;
        let resume = self.immutable_action(
            &state,
            &self.resume_id,
            FleetAction::NativeSessionResume {
                zone_id: self.zone_id.clone(),
                hold_action_id: self.hold_id.clone(),
                reason: Some(format!(
                    "guarded policy rollout {} completed",
                    self.rollout_id
                )),
            },
        )?;
        let had_hold = state.actions.contains(&hold);
        let had_policy = state.actions.contains(&policy);
        let had_resume = state.actions.contains(&resume);
        if (had_policy && !had_hold) || (had_resume && !had_policy) {
            return Err(FleetTransportError::stale_state(
                "rollout action history is incomplete",
            ));
        }
        if had_hold
            && !had_resume
            && !fleet_native_session_holds(&state.actions, &self.zone_id)?.contains(&self.hold_id)
        {
            return Err(FleetTransportError::stale_state(
                "rollout owner was released outside this guarded operation; refusing to republish or resume",
            ));
        }
        if !had_policy {
            // Refuse invalid or weakening policy intent before adding a hold.
            validate_fleet_policy_publication(&policy, &state.actions)?;
        }
        if !had_hold {
            self.check_deadline()?;
            transport.publish_action(&hold)?;
            // Ordinary hold admission may follow another writer's append.
            // Retain the previous prefix and require our exact immutable
            // record, without assuming its position in the new suffix.
            state = self.observe(transport, &mut retained, &mut required)?;
            if !state.actions.contains(&hold) {
                return Err(FleetTransportError::stale_state(
                    "published rollout hold is missing from the authoritative action log",
                ));
            }
        }

        // A restart after publication recovers its original atomic receipt.
        // The durable node inventory never evicts participants; the receipt
        // additionally retains every node admitted at the publication boundary.
        if had_policy {
            report.phase = FleetPolicyRolloutPhase::Applying;
            self.check_deadline()?;
            let receipt = transport.publish_policy_with_maintenance_guard(
                &GuardedFleetPolicyPublication {
                    action: policy.clone(),
                    guard: self.guard(&state, &required)?,
                },
            )?;
            required.extend(
                receipt
                    .evidence
                    .nodes
                    .iter()
                    .map(|node| (node.zone_id.clone(), node.node_id.clone())),
            );
            report.guarded_publication = Some(receipt);
        }
        while report.guarded_publication.is_none() {
            let evidence = fleet_native_session_hold_evidence(
                &state,
                &self.hold_id,
                FleetNativeSessionHoldTarget::Held,
                &required,
                Utc::now(),
                self.stale_after,
            )?;
            let ready = evidence.complete;
            report.evidence = Some(evidence);
            if ready {
                report.phase = FleetPolicyRolloutPhase::Publishing;
                self.check_deadline()?;
                let receipt = transport.publish_policy_with_maintenance_guard(
                    &GuardedFleetPolicyPublication {
                        action: policy.clone(),
                        guard: self.guard(&state, &required)?,
                    },
                )?;
                required.extend(
                    receipt
                        .evidence
                        .nodes
                        .iter()
                        .map(|node| (node.zone_id.clone(), node.node_id.clone())),
                );
                report.guarded_publication = Some(receipt);
                retained.push(policy.clone());
                report.phase = FleetPolicyRolloutPhase::Applying;
            } else {
                self.pause()?;
            }
            state = self.observe(transport, &mut retained, &mut required)?;
        }

        if had_resume {
            report.phase = FleetPolicyRolloutPhase::Resuming;
            self.check_deadline()?;
            let receipt = transport.resume_native_sessions_with_maintenance_guard(
                &GuardedFleetNativeSessionResume {
                    action: resume.clone(),
                    policy_action: policy.clone(),
                    guard: self.guard(&state, &required)?,
                    expires_at: self.expires_at,
                },
            )?;
            required.extend(
                receipt
                    .evidence
                    .nodes
                    .iter()
                    .map(|node| (node.zone_id.clone(), node.node_id.clone())),
            );
            report.guarded_resume = Some(receipt);
        }
        while report.guarded_resume.is_none() {
            let evidence = fleet_native_session_hold_evidence(
                &state,
                &self.hold_id,
                FleetNativeSessionHoldTarget::Held,
                &required,
                Utc::now(),
                self.stale_after,
            )?;
            let ready = evidence.complete;
            report.evidence = Some(evidence);
            if ready {
                report.phase = FleetPolicyRolloutPhase::Resuming;
                self.check_deadline()?;
                let receipt = transport.resume_native_sessions_with_maintenance_guard(
                    &GuardedFleetNativeSessionResume {
                        action: resume.clone(),
                        policy_action: policy.clone(),
                        guard: self.guard(&state, &required)?,
                        expires_at: self.expires_at,
                    },
                )?;
                required.extend(
                    receipt
                        .evidence
                        .nodes
                        .iter()
                        .map(|node| (node.zone_id.clone(), node.node_id.clone())),
                );
                report.guarded_resume = Some(receipt);
                retained.push(resume.clone());
                report.phase = FleetPolicyRolloutPhase::Resuming;
            } else {
                self.pause()?;
            }
            state = self.observe(transport, &mut retained, &mut required)?;
        }
        loop {
            let evidence = fleet_native_session_hold_evidence(
                &state,
                &self.hold_id,
                FleetNativeSessionHoldTarget::Resumed,
                &required,
                Utc::now(),
                self.stale_after,
            )?;
            let complete = evidence.complete;
            report.evidence = Some(evidence);
            self.check_deadline()?;
            if complete {
                report.phase = FleetPolicyRolloutPhase::Complete;
                report.completed = true;
                return Ok(());
            }
            self.pause()?;
            state = self.observe(transport, &mut retained, &mut required)?;
        }
    }
}
