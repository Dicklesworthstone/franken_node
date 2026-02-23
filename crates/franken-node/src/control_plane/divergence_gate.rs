//! Product-level divergence gate for control-plane state propagation.
//!
//! Wraps the low-level fork-detection primitives (bd-xwk5, bd-126h, bd-1dar)
//! with a product-level gate that blocks control-plane mutations when divergence
//! is detected. Implements four response modes: HALT, QUARANTINE, ALERT, RECOVER.
//!
//! **Bead:** bd-2ms — Section 10.10 (FCP-Inspired Hardening)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use super::fork_detection::{
    DetectionResult, DivergenceDetector, DivergenceLogEvent, MarkerProofVerifier, RollbackProof,
    StateVector,
};
use super::marker_stream::MarkerStream;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Divergence detected at the product level — mutations blocked.
    pub const DG_001_DIVERGENCE_DETECTED: &str = "DG-001";
    /// Control-plane mutation blocked due to active divergence.
    pub const DG_002_MUTATION_BLOCKED: &str = "DG-002";
    /// Divergence response mode activated (HALT/QUARANTINE/ALERT).
    pub const DG_003_RESPONSE_ACTIVATED: &str = "DG-003";
    /// Recovery completed with operator authorization.
    pub const DG_004_RECOVERY_COMPLETED: &str = "DG-004";
    /// Freshness proof validated for propagation.
    pub const DG_005_FRESHNESS_VERIFIED: &str = "DG-005";
    /// Quarantine partition created or updated.
    pub const DG_006_PARTITION_QUARANTINED: &str = "DG-006";
    /// Operator alert dispatched with divergence evidence.
    pub const DG_007_OPERATOR_ALERTED: &str = "DG-007";
    /// Marker proof verified against local checkpoint.
    pub const DG_008_MARKER_PROOF_VERIFIED: &str = "DG-008";
}

// ---------------------------------------------------------------------------
// Invariant identifiers
// ---------------------------------------------------------------------------

pub mod invariants {
    /// No control-plane mutation may proceed during active divergence.
    pub const INV_DG_NO_MUTATION: &str = "INV-DG-NO-MUTATION";
    /// Recovery requires explicit operator authorization (signed).
    pub const INV_DG_OPERATOR_RECOVERY: &str = "INV-DG-OPERATOR-RECOVERY";
    /// Divergence detected within one propagation cycle.
    pub const INV_DG_ONE_CYCLE: &str = "INV-DG-ONE-CYCLE";
    /// All response transitions follow valid state machine paths.
    pub const INV_DG_VALID_TRANSITIONS: &str = "INV-DG-VALID-TRANSITIONS";
}

// ---------------------------------------------------------------------------
// Response mode
// ---------------------------------------------------------------------------

/// Product-level response to a detected divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseMode {
    /// Stop all control-plane mutations immediately.
    Halt,
    /// Isolate the divergent state partition from the rest of the system.
    Quarantine,
    /// Emit structured alert with divergence evidence for operator review.
    Alert,
    /// Re-sync from authoritative checkpoint (requires operator approval).
    Recover,
}

impl ResponseMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Halt => "HALT",
            Self::Quarantine => "QUARANTINE",
            Self::Alert => "ALERT",
            Self::Recover => "RECOVER",
        }
    }

    pub fn all() -> &'static [ResponseMode] {
        &[Self::Halt, Self::Quarantine, Self::Alert, Self::Recover]
    }
}

impl fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Gate state machine
// ---------------------------------------------------------------------------

/// State of the divergence gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateState {
    /// Normal operation — no divergence detected.
    Normal,
    /// Divergence detected — mutations blocked, awaiting response.
    Diverged,
    /// Divergent partition quarantined.
    Quarantined,
    /// Operator alerted, awaiting manual review.
    Alerted,
    /// Recovery in progress (operator authorized).
    Recovering,
}

impl GateState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Diverged => "diverged",
            Self::Quarantined => "quarantined",
            Self::Alerted => "alerted",
            Self::Recovering => "recovering",
        }
    }

    /// Can a control-plane mutation proceed in this state?
    pub fn allows_mutation(&self) -> bool {
        matches!(self, Self::Normal)
    }
}

impl fmt::Display for GateState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Mutation kind (what is being gated)
// ---------------------------------------------------------------------------

/// Kinds of control-plane mutations that require freshness verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    PolicyUpdate,
    TokenIssuance,
    ZoneBoundaryChange,
    RevocationPublish,
    EpochTransition,
    QuarantinePromotion,
}

impl MutationKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::PolicyUpdate => "policy_update",
            Self::TokenIssuance => "token_issuance",
            Self::ZoneBoundaryChange => "zone_boundary_change",
            Self::RevocationPublish => "revocation_publish",
            Self::EpochTransition => "epoch_transition",
            Self::QuarantinePromotion => "quarantine_promotion",
        }
    }
}

impl fmt::Display for MutationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the divergence gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceGateError {
    /// Mutation blocked because a divergence is active.
    #[serde(rename = "DIVERGENCE_BLOCK")]
    DivergenceBlock {
        mutation_kind: String,
        gate_state: String,
        detail: String,
    },
    /// Invalid state transition attempted.
    #[serde(rename = "INVALID_TRANSITION")]
    InvalidTransition {
        from: String,
        to: String,
        reason: String,
    },
    /// Recovery attempted without operator authorization.
    #[serde(rename = "UNAUTHORIZED_RECOVERY")]
    UnauthorizedRecovery { reason: String },
    /// Freshness proof failed.
    #[serde(rename = "FRESHNESS_FAILED")]
    FreshnessFailed { detail: String },
}

impl fmt::Display for DivergenceGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DivergenceBlock {
                mutation_kind,
                gate_state,
                detail,
            } => write!(
                f,
                "DIVERGENCE_BLOCK: {mutation_kind} blocked in state {gate_state}: {detail}"
            ),
            Self::InvalidTransition { from, to, reason } => {
                write!(f, "INVALID_TRANSITION: {from} -> {to}: {reason}")
            }
            Self::UnauthorizedRecovery { reason } => {
                write!(f, "UNAUTHORIZED_RECOVERY: {reason}")
            }
            Self::FreshnessFailed { detail } => {
                write!(f, "FRESHNESS_FAILED: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Operator authorization
// ---------------------------------------------------------------------------

/// Signed authorization from an operator for recovery operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAuthorization {
    pub operator_id: String,
    pub authorization_hash: String,
    pub resync_checkpoint_epoch: u64,
    pub timestamp: u64,
    pub reason: String,
}

impl OperatorAuthorization {
    /// Create a new authorization with a computed hash.
    pub fn new(
        operator_id: impl Into<String>,
        resync_checkpoint_epoch: u64,
        timestamp: u64,
        reason: impl Into<String>,
    ) -> Self {
        let operator_id = operator_id.into();
        let reason = reason.into();
        let mut hasher = Sha256::new();
        let canonical = format!(
            "{}|{}|{}|{}",
            operator_id, resync_checkpoint_epoch, timestamp, reason
        );
        hasher.update(canonical.as_bytes());
        let authorization_hash = format!("{:x}", hasher.finalize());
        Self {
            operator_id,
            authorization_hash,
            resync_checkpoint_epoch,
            timestamp,
            reason,
        }
    }

    /// Verify the authorization hash is consistent.
    pub fn verify(&self) -> bool {
        let mut hasher = Sha256::new();
        let canonical = format!(
            "{}|{}|{}|{}",
            self.operator_id, self.resync_checkpoint_epoch, self.timestamp, self.reason
        );
        hasher.update(canonical.as_bytes());
        let expected = format!("{:x}", hasher.finalize());
        self.authorization_hash == expected
    }
}

// ---------------------------------------------------------------------------
// Quarantine partition
// ---------------------------------------------------------------------------

/// A quarantined state partition isolated due to divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinePartition {
    pub partition_id: String,
    pub node_id: String,
    pub divergence_epoch: u64,
    pub quarantined_at: u64,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Alert record
// ---------------------------------------------------------------------------

/// Structured alert dispatched to operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorAlert {
    pub alert_id: String,
    pub severity: String,
    pub divergence_epoch: u64,
    pub local_hash: String,
    pub remote_hash: String,
    pub detection_result: String,
    pub recommended_action: String,
    pub timestamp: u64,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Gate audit log
// ---------------------------------------------------------------------------

/// Audit entry for divergence gate operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateAuditEntry {
    pub timestamp: u64,
    pub event_code: String,
    pub gate_state: String,
    pub detail: String,
    pub trace_id: String,
    pub node_id: String,
    pub epoch_id: u64,
}

// ---------------------------------------------------------------------------
// Mutation check result
// ---------------------------------------------------------------------------

/// Result of checking whether a mutation is allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationCheckResult {
    pub allowed: bool,
    pub mutation_kind: String,
    pub gate_state: String,
    pub detail: String,
    pub event_code: String,
}

// ---------------------------------------------------------------------------
// Recovery result
// ---------------------------------------------------------------------------

/// Result of a recovery operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResult {
    pub success: bool,
    pub authorizing_operator: String,
    pub resync_checkpoint: u64,
    pub markers_replayed: u64,
    pub new_gate_state: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// ControlPlaneDivergenceGate
// ---------------------------------------------------------------------------

/// Product-level gate that blocks control-plane mutations when divergence is detected.
///
/// Wraps `DivergenceDetector` and `MarkerProofVerifier` from the low-level
/// fork-detection layer with a state machine governing response modes.
pub struct ControlPlaneDivergenceGate {
    state: GateState,
    detector: DivergenceDetector,
    events: Vec<String>,
    audit_log: Vec<GateAuditEntry>,
    quarantined_partitions: Vec<QuarantinePartition>,
    alerts: Vec<OperatorAlert>,
    blocked_mutations: Vec<MutationCheckResult>,
    active_divergence: Option<ActiveDivergence>,
    node_id: String,
    alert_counter: u64,
}

/// Tracks an active divergence episode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveDivergence {
    pub detection_result: String,
    pub fork_epoch: u64,
    pub local_hash: String,
    pub remote_hash: String,
    pub detected_at: u64,
    pub proof: Option<RollbackProof>,
    pub response_mode: Option<String>,
}

impl ControlPlaneDivergenceGate {
    /// Create a new gate in Normal state.
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            state: GateState::Normal,
            detector: DivergenceDetector::new(),
            events: Vec::new(),
            audit_log: Vec::new(),
            quarantined_partitions: Vec::new(),
            alerts: Vec::new(),
            blocked_mutations: Vec::new(),
            active_divergence: None,
            node_id: node_id.into(),
            alert_counter: 0,
        }
    }

    /// Current gate state.
    pub fn state(&self) -> GateState {
        self.state
    }

    /// Whether mutations are currently allowed.
    pub fn allows_mutation(&self) -> bool {
        self.state.allows_mutation()
    }

    /// Read-only reference to emitted events.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Drain emitted events.
    pub fn take_events(&mut self) -> Vec<String> {
        std::mem::take(&mut self.events)
    }

    /// Read-only reference to audit log.
    pub fn audit_log(&self) -> &[GateAuditEntry] {
        &self.audit_log
    }

    /// Read-only reference to quarantined partitions.
    pub fn quarantined_partitions(&self) -> &[QuarantinePartition] {
        &self.quarantined_partitions
    }

    /// Read-only reference to dispatched alerts.
    pub fn alerts(&self) -> &[OperatorAlert] {
        &self.alerts
    }

    /// Read-only reference to blocked mutations.
    pub fn blocked_mutations(&self) -> &[MutationCheckResult] {
        &self.blocked_mutations
    }

    /// Active divergence info.
    pub fn active_divergence(&self) -> Option<&ActiveDivergence> {
        self.active_divergence.as_ref()
    }

    // -----------------------------------------------------------------------
    // Core: check propagation
    // -----------------------------------------------------------------------

    /// Check two state vectors for divergence. If divergence is detected,
    /// transition the gate to Diverged and emit structured events.
    pub fn check_propagation(
        &mut self,
        local: &StateVector,
        remote: &StateVector,
        timestamp: u64,
        trace_id: &str,
    ) -> (DetectionResult, Option<RollbackProof>, DivergenceLogEvent) {
        let (result, proof, log_event) = self.detector.compare_and_log(local, remote);

        match result {
            DetectionResult::Converged => {
                self.events
                    .push(event_codes::DG_005_FRESHNESS_VERIFIED.to_string());
                self.emit_audit(
                    timestamp,
                    event_codes::DG_005_FRESHNESS_VERIFIED,
                    "propagation converged",
                    trace_id,
                    local.epoch,
                );
            }
            DetectionResult::Forked | DetectionResult::RollbackDetected => {
                self.transition_to_diverged(
                    &result,
                    local,
                    remote,
                    proof.clone(),
                    timestamp,
                    trace_id,
                );
            }
            DetectionResult::GapDetected => {
                self.transition_to_diverged(
                    &result,
                    local,
                    remote,
                    proof.clone(),
                    timestamp,
                    trace_id,
                );
            }
        }

        (result, proof, log_event)
    }

    fn transition_to_diverged(
        &mut self,
        result: &DetectionResult,
        local: &StateVector,
        remote: &StateVector,
        proof: Option<RollbackProof>,
        timestamp: u64,
        trace_id: &str,
    ) {
        self.state = GateState::Diverged;
        self.active_divergence = Some(ActiveDivergence {
            detection_result: result.label().to_string(),
            fork_epoch: local.epoch,
            local_hash: local.state_hash.clone(),
            remote_hash: remote.state_hash.clone(),
            detected_at: timestamp,
            proof,
            response_mode: None,
        });

        self.events
            .push(event_codes::DG_001_DIVERGENCE_DETECTED.to_string());
        self.emit_audit(
            timestamp,
            event_codes::DG_001_DIVERGENCE_DETECTED,
            &format!(
                "divergence detected: {} at epoch {}",
                result.label(),
                local.epoch
            ),
            trace_id,
            local.epoch,
        );
    }

    // -----------------------------------------------------------------------
    // Gate: mutation check
    // -----------------------------------------------------------------------

    /// Check if a mutation is allowed. If not, record the blocked mutation.
    pub fn check_mutation(
        &mut self,
        kind: &MutationKind,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<MutationCheckResult, DivergenceGateError> {
        if self.state.allows_mutation() {
            let result = MutationCheckResult {
                allowed: true,
                mutation_kind: kind.label().to_string(),
                gate_state: self.state.label().to_string(),
                detail: "gate is normal — mutation allowed".to_string(),
                event_code: event_codes::DG_005_FRESHNESS_VERIFIED.to_string(),
            };
            self.events
                .push(event_codes::DG_005_FRESHNESS_VERIFIED.to_string());
            return Ok(result);
        }

        let result = MutationCheckResult {
            allowed: false,
            mutation_kind: kind.label().to_string(),
            gate_state: self.state.label().to_string(),
            detail: format!(
                "mutation {} blocked: gate in {} state",
                kind.label(),
                self.state.label()
            ),
            event_code: event_codes::DG_002_MUTATION_BLOCKED.to_string(),
        };
        self.blocked_mutations.push(result.clone());
        self.events
            .push(event_codes::DG_002_MUTATION_BLOCKED.to_string());
        self.emit_audit(
            timestamp,
            event_codes::DG_002_MUTATION_BLOCKED,
            &result.detail,
            trace_id,
            0,
        );

        Err(DivergenceGateError::DivergenceBlock {
            mutation_kind: kind.label().to_string(),
            gate_state: self.state.label().to_string(),
            detail: result.detail.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // Response: HALT
    // -----------------------------------------------------------------------

    /// Activate HALT response: stay in Diverged, all mutations blocked.
    /// This is the default response.
    pub fn respond_halt(
        &mut self,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<(), DivergenceGateError> {
        if self.state != GateState::Diverged {
            return Err(DivergenceGateError::InvalidTransition {
                from: self.state.label().to_string(),
                to: "diverged (halt)".to_string(),
                reason: "HALT only valid from Diverged state".to_string(),
            });
        }
        if let Some(ref mut ad) = self.active_divergence {
            ad.response_mode = Some(ResponseMode::Halt.label().to_string());
        }
        self.events
            .push(event_codes::DG_003_RESPONSE_ACTIVATED.to_string());
        self.emit_audit(
            timestamp,
            event_codes::DG_003_RESPONSE_ACTIVATED,
            "HALT response activated — all mutations blocked",
            trace_id,
            self.active_divergence.as_ref().map_or(0, |a| a.fork_epoch),
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Response: QUARANTINE
    // -----------------------------------------------------------------------

    /// Activate QUARANTINE response: isolate the divergent partition.
    pub fn respond_quarantine(
        &mut self,
        partition_id: impl Into<String>,
        node_id: impl Into<String>,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<QuarantinePartition, DivergenceGateError> {
        if self.state != GateState::Diverged {
            return Err(DivergenceGateError::InvalidTransition {
                from: self.state.label().to_string(),
                to: "quarantined".to_string(),
                reason: "QUARANTINE only valid from Diverged state".to_string(),
            });
        }

        let epoch = self.active_divergence.as_ref().map_or(0, |a| a.fork_epoch);

        let partition = QuarantinePartition {
            partition_id: partition_id.into(),
            node_id: node_id.into(),
            divergence_epoch: epoch,
            quarantined_at: timestamp,
            reason: format!("divergence at epoch {epoch}"),
        };

        self.quarantined_partitions.push(partition.clone());
        self.state = GateState::Quarantined;
        if let Some(ref mut ad) = self.active_divergence {
            ad.response_mode = Some(ResponseMode::Quarantine.label().to_string());
        }

        self.events
            .push(event_codes::DG_006_PARTITION_QUARANTINED.to_string());
        self.events
            .push(event_codes::DG_003_RESPONSE_ACTIVATED.to_string());
        self.emit_audit(
            timestamp,
            event_codes::DG_006_PARTITION_QUARANTINED,
            &format!("partition quarantined: {}", partition.partition_id),
            trace_id,
            epoch,
        );

        Ok(partition)
    }

    // -----------------------------------------------------------------------
    // Response: ALERT
    // -----------------------------------------------------------------------

    /// Activate ALERT response: dispatch structured alert to operator.
    pub fn respond_alert(
        &mut self,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<OperatorAlert, DivergenceGateError> {
        if !matches!(self.state, GateState::Diverged | GateState::Quarantined) {
            return Err(DivergenceGateError::InvalidTransition {
                from: self.state.label().to_string(),
                to: "alerted".to_string(),
                reason: "ALERT only valid from Diverged or Quarantined state".to_string(),
            });
        }

        let ad = self
            .active_divergence
            .as_ref()
            .cloned()
            .unwrap_or(ActiveDivergence {
                detection_result: "unknown".to_string(),
                fork_epoch: 0,
                local_hash: String::new(),
                remote_hash: String::new(),
                detected_at: timestamp,
                proof: None,
                response_mode: None,
            });

        self.alert_counter += 1;
        let alert = OperatorAlert {
            alert_id: format!("ALERT-{:04}", self.alert_counter),
            severity: "CRITICAL".to_string(),
            divergence_epoch: ad.fork_epoch,
            local_hash: ad.local_hash.clone(),
            remote_hash: ad.remote_hash.clone(),
            detection_result: ad.detection_result.clone(),
            recommended_action: "Investigate divergence and authorize recovery".to_string(),
            timestamp,
            trace_id: trace_id.to_string(),
        };

        self.alerts.push(alert.clone());
        self.state = GateState::Alerted;
        if let Some(ref mut ad) = self.active_divergence {
            ad.response_mode = Some(ResponseMode::Alert.label().to_string());
        }

        self.events
            .push(event_codes::DG_007_OPERATOR_ALERTED.to_string());
        self.events
            .push(event_codes::DG_003_RESPONSE_ACTIVATED.to_string());
        self.emit_audit(
            timestamp,
            event_codes::DG_007_OPERATOR_ALERTED,
            &format!(
                "operator alerted: {} at epoch {}",
                ad.detection_result, ad.fork_epoch
            ),
            trace_id,
            ad.fork_epoch,
        );

        Ok(alert)
    }

    // -----------------------------------------------------------------------
    // Response: RECOVER
    // -----------------------------------------------------------------------

    /// Activate RECOVER response: re-sync from authoritative checkpoint.
    ///
    /// **Requires operator authorization** — no automatic recovery allowed.
    pub fn respond_recover(
        &mut self,
        authorization: &OperatorAuthorization,
        markers_replayed: u64,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<RecoveryResult, DivergenceGateError> {
        if !matches!(
            self.state,
            GateState::Diverged | GateState::Quarantined | GateState::Alerted
        ) {
            return Err(DivergenceGateError::InvalidTransition {
                from: self.state.label().to_string(),
                to: "normal (recover)".to_string(),
                reason: "RECOVER only valid from Diverged, Quarantined, or Alerted state"
                    .to_string(),
            });
        }

        // Verify authorization
        if !authorization.verify() {
            return Err(DivergenceGateError::UnauthorizedRecovery {
                reason: "authorization hash verification failed".to_string(),
            });
        }

        if authorization.operator_id.is_empty() {
            return Err(DivergenceGateError::UnauthorizedRecovery {
                reason: "operator_id must not be empty".to_string(),
            });
        }

        // Transition to Recovering, then Normal
        self.state = GateState::Recovering;
        self.detector.operator_reset();
        self.state = GateState::Normal;
        let epoch = self.active_divergence.as_ref().map_or(0, |a| a.fork_epoch);
        self.active_divergence = None;

        let result = RecoveryResult {
            success: true,
            authorizing_operator: authorization.operator_id.clone(),
            resync_checkpoint: authorization.resync_checkpoint_epoch,
            markers_replayed,
            new_gate_state: self.state.label().to_string(),
            detail: format!(
                "recovered from epoch {} with operator {} authorization",
                epoch, authorization.operator_id
            ),
        };

        self.events
            .push(event_codes::DG_004_RECOVERY_COMPLETED.to_string());
        self.emit_audit(
            timestamp,
            event_codes::DG_004_RECOVERY_COMPLETED,
            &result.detail,
            trace_id,
            authorization.resync_checkpoint_epoch,
        );

        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Marker proof verification
    // -----------------------------------------------------------------------

    /// Verify a marker proof against a marker stream.
    pub fn verify_marker(
        &mut self,
        stream: &MarkerStream,
        marker_id: &str,
        claimed_epoch: u64,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<(), DivergenceGateError> {
        match MarkerProofVerifier::verify(stream, marker_id, claimed_epoch) {
            Ok(()) => {
                self.events
                    .push(event_codes::DG_008_MARKER_PROOF_VERIFIED.to_string());
                self.emit_audit(
                    timestamp,
                    event_codes::DG_008_MARKER_PROOF_VERIFIED,
                    &format!("marker proof verified: {marker_id} at epoch {claimed_epoch}"),
                    trace_id,
                    claimed_epoch,
                );
                Ok(())
            }
            Err(e) => Err(DivergenceGateError::FreshnessFailed {
                detail: e.to_string(),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn emit_audit(
        &mut self,
        timestamp: u64,
        event_code: &str,
        detail: &str,
        trace_id: &str,
        epoch_id: u64,
    ) {
        self.audit_log.push(GateAuditEntry {
            timestamp,
            event_code: event_code.to_string(),
            gate_state: self.state.label().to_string(),
            detail: detail.to_string(),
            trace_id: trace_id.to_string(),
            node_id: self.node_id.clone(),
            epoch_id,
        });
    }
}

impl Default for ControlPlaneDivergenceGate {
    fn default() -> Self {
        Self::new("default-node")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sv(epoch: u64, state: &str, parent: &str, node: &str) -> StateVector {
        StateVector {
            epoch,
            marker_id: format!("marker-{epoch}"),
            state_hash: StateVector::compute_state_hash(state),
            parent_state_hash: parent.to_string(),
            timestamp: 1000 + epoch * 100,
            node_id: node.to_string(),
        }
    }

    fn converged_pair() -> (StateVector, StateVector) {
        let parent = StateVector::compute_state_hash("parent");
        let local = make_sv(10, "state-10", &parent, "node-A");
        let remote = StateVector {
            node_id: "node-B".to_string(),
            ..local.clone()
        };
        (local, remote)
    }

    fn forked_pair() -> (StateVector, StateVector) {
        let parent = StateVector::compute_state_hash("parent");
        let local = make_sv(10, "state-A", &parent, "node-A");
        let remote = make_sv(10, "state-B", &parent, "node-B");
        (local, remote)
    }

    fn gapped_pair() -> (StateVector, StateVector) {
        let parent = StateVector::compute_state_hash("parent");
        let local = make_sv(10, "state-10", &parent, "node-A");
        let remote = make_sv(15, "state-15", &parent, "node-B");
        (local, remote)
    }

    fn rollback_pair() -> (StateVector, StateVector) {
        let parent = StateVector::compute_state_hash("parent");
        let local = make_sv(10, "state-10", &parent, "node-A");
        let remote = StateVector {
            epoch: 10,
            marker_id: "marker-10".to_string(),
            state_hash: local.state_hash.clone(),
            parent_state_hash: "tampered-parent".to_string(),
            timestamp: local.timestamp,
            node_id: "node-B".to_string(),
        };
        (local, remote)
    }

    // --- Construction ---

    #[test]
    fn test_new_gate_normal() {
        let gate = ControlPlaneDivergenceGate::new("test-node");
        assert_eq!(gate.state(), GateState::Normal);
        assert!(gate.allows_mutation());
    }

    #[test]
    fn test_default_gate() {
        let gate = ControlPlaneDivergenceGate::default();
        assert_eq!(gate.state(), GateState::Normal);
    }

    // --- Converged ---

    #[test]
    fn test_converged_stays_normal() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = converged_pair();
        let (result, proof, _) = gate.check_propagation(&local, &remote, 2000, "trace-1");
        assert_eq!(result, DetectionResult::Converged);
        assert!(proof.is_none());
        assert_eq!(gate.state(), GateState::Normal);
    }

    #[test]
    fn test_converged_allows_mutation() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = converged_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let result = gate.check_mutation(&MutationKind::PolicyUpdate, 2001, "trace-2");
        assert!(result.is_ok());
        assert!(result.unwrap().allowed);
    }

    // --- Fork detection ---

    #[test]
    fn test_fork_transitions_to_diverged() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        let (result, _, _) = gate.check_propagation(&local, &remote, 2000, "trace-1");
        assert_eq!(result, DetectionResult::Forked);
        assert_eq!(gate.state(), GateState::Diverged);
        assert!(!gate.allows_mutation());
    }

    #[test]
    fn test_fork_blocks_mutation() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let result = gate.check_mutation(&MutationKind::TokenIssuance, 2001, "trace-2");
        assert!(result.is_err());
        match result.unwrap_err() {
            DivergenceGateError::DivergenceBlock { mutation_kind, .. } => {
                assert_eq!(mutation_kind, "token_issuance")
            }
            _ => panic!("expected DivergenceBlock"),
        }
    }

    #[test]
    fn test_fork_emits_divergence_event() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        assert!(
            gate.events()
                .contains(&event_codes::DG_001_DIVERGENCE_DETECTED.to_string())
        );
    }

    #[test]
    fn test_fork_active_divergence() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let ad = gate.active_divergence().unwrap();
        assert_eq!(ad.detection_result, "FORKED");
        assert_eq!(ad.fork_epoch, 10);
    }

    // --- Gap detection ---

    #[test]
    fn test_gap_transitions_to_diverged() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = gapped_pair();
        let (result, _, _) = gate.check_propagation(&local, &remote, 2000, "trace-1");
        assert_eq!(result, DetectionResult::GapDetected);
        assert_eq!(gate.state(), GateState::Diverged);
    }

    // --- Rollback detection ---

    #[test]
    fn test_rollback_transitions_to_diverged() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = rollback_pair();
        let (result, proof, _) = gate.check_propagation(&local, &remote, 2000, "trace-1");
        assert_eq!(result, DetectionResult::RollbackDetected);
        assert!(proof.is_some());
        assert_eq!(gate.state(), GateState::Diverged);
    }

    // --- HALT response ---

    #[test]
    fn test_halt_from_diverged() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let result = gate.respond_halt(2001, "trace-2");
        assert!(result.is_ok());
        assert_eq!(gate.state(), GateState::Diverged);
        assert!(
            gate.events()
                .contains(&event_codes::DG_003_RESPONSE_ACTIVATED.to_string())
        );
    }

    #[test]
    fn test_halt_from_normal_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let result = gate.respond_halt(2000, "trace-1");
        assert!(result.is_err());
    }

    // --- QUARANTINE response ---

    #[test]
    fn test_quarantine_from_diverged() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let result = gate.respond_quarantine("part-1", "node-B", 2001, "trace-2");
        assert!(result.is_ok());
        let partition = result.unwrap();
        assert_eq!(partition.partition_id, "part-1");
        assert_eq!(gate.state(), GateState::Quarantined);
        assert_eq!(gate.quarantined_partitions().len(), 1);
    }

    #[test]
    fn test_quarantine_from_normal_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let result = gate.respond_quarantine("part-1", "node-B", 2000, "trace-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_quarantine_blocks_mutation() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        gate.respond_quarantine("part-1", "node-B", 2001, "trace-2")
            .unwrap();
        let result = gate.check_mutation(&MutationKind::ZoneBoundaryChange, 2002, "trace-3");
        assert!(result.is_err());
    }

    // --- ALERT response ---

    #[test]
    fn test_alert_from_diverged() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let result = gate.respond_alert(2001, "trace-2");
        assert!(result.is_ok());
        let alert = result.unwrap();
        assert_eq!(alert.severity, "CRITICAL");
        assert_eq!(gate.state(), GateState::Alerted);
        assert_eq!(gate.alerts().len(), 1);
    }

    #[test]
    fn test_alert_from_quarantined() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        gate.respond_quarantine("part-1", "node-B", 2001, "trace-2")
            .unwrap();
        let result = gate.respond_alert(2002, "trace-3");
        assert!(result.is_ok());
        assert_eq!(gate.state(), GateState::Alerted);
    }

    #[test]
    fn test_alert_from_normal_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let result = gate.respond_alert(2000, "trace-1");
        assert!(result.is_err());
    }

    // --- RECOVER response ---

    #[test]
    fn test_recover_from_diverged() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let auth = OperatorAuthorization::new("operator-1", 9, 2001, "fix fork");
        let result = gate.respond_recover(&auth, 10, 2001, "trace-2");
        assert!(result.is_ok());
        let recovery = result.unwrap();
        assert!(recovery.success);
        assert_eq!(recovery.authorizing_operator, "operator-1");
        assert_eq!(gate.state(), GateState::Normal);
        assert!(gate.allows_mutation());
    }

    #[test]
    fn test_recover_from_alerted() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        gate.respond_alert(2001, "trace-2").unwrap();
        let auth = OperatorAuthorization::new("operator-1", 9, 2002, "fix fork");
        let result = gate.respond_recover(&auth, 10, 2002, "trace-3");
        assert!(result.is_ok());
        assert_eq!(gate.state(), GateState::Normal);
    }

    #[test]
    fn test_recover_from_normal_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let auth = OperatorAuthorization::new("operator-1", 9, 2000, "fix");
        let result = gate.respond_recover(&auth, 10, 2000, "trace-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_recover_unauthorized_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let mut auth = OperatorAuthorization::new("operator-1", 9, 2001, "fix");
        auth.authorization_hash = "tampered".to_string();
        let result = gate.respond_recover(&auth, 10, 2001, "trace-2");
        assert!(result.is_err());
        match result.unwrap_err() {
            DivergenceGateError::UnauthorizedRecovery { .. } => {}
            _ => panic!("expected UnauthorizedRecovery"),
        }
    }

    #[test]
    fn test_recover_empty_operator_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let auth = OperatorAuthorization::new("", 9, 2001, "fix");
        let result = gate.respond_recover(&auth, 10, 2001, "trace-2");
        assert!(result.is_err());
    }

    // --- OperatorAuthorization ---

    #[test]
    fn test_operator_authorization_verify() {
        let auth = OperatorAuthorization::new("op-1", 50, 3000, "reason");
        assert!(auth.verify());
    }

    #[test]
    fn test_operator_authorization_tampered() {
        let mut auth = OperatorAuthorization::new("op-1", 50, 3000, "reason");
        auth.authorization_hash = "bad".to_string();
        assert!(!auth.verify());
    }

    #[test]
    fn test_operator_authorization_serde() {
        let auth = OperatorAuthorization::new("op-1", 50, 3000, "reason");
        let json = serde_json::to_string(&auth).unwrap();
        let decoded: OperatorAuthorization = serde_json::from_str(&json).unwrap();
        assert_eq!(auth, decoded);
    }

    // --- Mutation kinds ---

    #[test]
    fn test_all_mutation_kinds_blocked() {
        let kinds = [
            MutationKind::PolicyUpdate,
            MutationKind::TokenIssuance,
            MutationKind::ZoneBoundaryChange,
            MutationKind::RevocationPublish,
            MutationKind::EpochTransition,
            MutationKind::QuarantinePromotion,
        ];
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        for kind in &kinds {
            let result = gate.check_mutation(kind, 2001, "trace-2");
            assert!(result.is_err(), "expected {} to be blocked", kind.label());
        }
        assert_eq!(gate.blocked_mutations().len(), 6);
    }

    // --- ResponseMode ---

    #[test]
    fn test_response_mode_all() {
        assert_eq!(ResponseMode::all().len(), 4);
    }

    #[test]
    fn test_response_mode_labels() {
        assert_eq!(ResponseMode::Halt.label(), "HALT");
        assert_eq!(ResponseMode::Quarantine.label(), "QUARANTINE");
        assert_eq!(ResponseMode::Alert.label(), "ALERT");
        assert_eq!(ResponseMode::Recover.label(), "RECOVER");
    }

    #[test]
    fn test_response_mode_serde() {
        let mode = ResponseMode::Quarantine;
        let json = serde_json::to_string(&mode).unwrap();
        let decoded: ResponseMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, decoded);
    }

    // --- GateState ---

    #[test]
    fn test_gate_state_allows_mutation() {
        assert!(GateState::Normal.allows_mutation());
        assert!(!GateState::Diverged.allows_mutation());
        assert!(!GateState::Quarantined.allows_mutation());
        assert!(!GateState::Alerted.allows_mutation());
        assert!(!GateState::Recovering.allows_mutation());
    }

    #[test]
    fn test_gate_state_serde() {
        let state = GateState::Quarantined;
        let json = serde_json::to_string(&state).unwrap();
        let decoded: GateState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
    }

    // --- Event codes ---

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::DG_001_DIVERGENCE_DETECTED, "DG-001");
        assert_eq!(event_codes::DG_002_MUTATION_BLOCKED, "DG-002");
        assert_eq!(event_codes::DG_003_RESPONSE_ACTIVATED, "DG-003");
        assert_eq!(event_codes::DG_004_RECOVERY_COMPLETED, "DG-004");
        assert_eq!(event_codes::DG_005_FRESHNESS_VERIFIED, "DG-005");
        assert_eq!(event_codes::DG_006_PARTITION_QUARANTINED, "DG-006");
        assert_eq!(event_codes::DG_007_OPERATOR_ALERTED, "DG-007");
        assert_eq!(event_codes::DG_008_MARKER_PROOF_VERIFIED, "DG-008");
    }

    // --- Invariant constants ---

    #[test]
    fn test_invariant_constants() {
        assert_eq!(invariants::INV_DG_NO_MUTATION, "INV-DG-NO-MUTATION");
        assert_eq!(
            invariants::INV_DG_OPERATOR_RECOVERY,
            "INV-DG-OPERATOR-RECOVERY"
        );
        assert_eq!(invariants::INV_DG_ONE_CYCLE, "INV-DG-ONE-CYCLE");
        assert_eq!(
            invariants::INV_DG_VALID_TRANSITIONS,
            "INV-DG-VALID-TRANSITIONS"
        );
    }

    // --- Error display ---

    #[test]
    fn test_error_display_divergence_block() {
        let e = DivergenceGateError::DivergenceBlock {
            mutation_kind: "policy_update".to_string(),
            gate_state: "diverged".to_string(),
            detail: "blocked".to_string(),
        };
        assert!(e.to_string().contains("DIVERGENCE_BLOCK"));
    }

    #[test]
    fn test_error_display_invalid_transition() {
        let e = DivergenceGateError::InvalidTransition {
            from: "normal".to_string(),
            to: "diverged".to_string(),
            reason: "test".to_string(),
        };
        assert!(e.to_string().contains("INVALID_TRANSITION"));
    }

    #[test]
    fn test_error_display_unauthorized() {
        let e = DivergenceGateError::UnauthorizedRecovery {
            reason: "test".to_string(),
        };
        assert!(e.to_string().contains("UNAUTHORIZED_RECOVERY"));
    }

    #[test]
    fn test_error_display_freshness() {
        let e = DivergenceGateError::FreshnessFailed {
            detail: "test".to_string(),
        };
        assert!(e.to_string().contains("FRESHNESS_FAILED"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let e = DivergenceGateError::DivergenceBlock {
            mutation_kind: "token_issuance".to_string(),
            gate_state: "diverged".to_string(),
            detail: "test".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let decoded: DivergenceGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, decoded);
    }

    // --- Audit log ---

    #[test]
    fn test_audit_log_on_fork() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        assert!(!gate.audit_log().is_empty());
        let entry = &gate.audit_log()[0];
        assert_eq!(entry.event_code, event_codes::DG_001_DIVERGENCE_DETECTED);
        assert_eq!(entry.trace_id, "trace-1");
    }

    #[test]
    fn test_audit_log_on_recovery() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let auth = OperatorAuthorization::new("op-1", 9, 2001, "fix");
        gate.respond_recover(&auth, 10, 2001, "trace-2").unwrap();
        let last = gate.audit_log().last().unwrap();
        assert_eq!(last.event_code, event_codes::DG_004_RECOVERY_COMPLETED);
    }

    // --- Full lifecycle ---

    #[test]
    fn test_full_lifecycle_fork_quarantine_alert_recover() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();

        // Detect fork
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        assert_eq!(gate.state(), GateState::Diverged);

        // Quarantine
        gate.respond_quarantine("part-1", "node-B", 2001, "trace-2")
            .unwrap();
        assert_eq!(gate.state(), GateState::Quarantined);

        // Alert
        gate.respond_alert(2002, "trace-3").unwrap();
        assert_eq!(gate.state(), GateState::Alerted);

        // Blocked mutation
        let blocked = gate.check_mutation(&MutationKind::PolicyUpdate, 2003, "trace-4");
        assert!(blocked.is_err());

        // Recover
        let auth = OperatorAuthorization::new("admin", 9, 2004, "approved fix");
        gate.respond_recover(&auth, 10, 2004, "trace-5").unwrap();
        assert_eq!(gate.state(), GateState::Normal);

        // Now mutations work
        let ok = gate.check_mutation(&MutationKind::PolicyUpdate, 2005, "trace-6");
        assert!(ok.is_ok());
        assert!(ok.unwrap().allowed);
    }

    #[test]
    fn test_convergence_emits_freshness_event() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = converged_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        assert!(
            gate.events()
                .contains(&event_codes::DG_005_FRESHNESS_VERIFIED.to_string())
        );
    }

    // --- QuarantinePartition serde ---

    #[test]
    fn test_quarantine_partition_serde() {
        let p = QuarantinePartition {
            partition_id: "p1".to_string(),
            node_id: "n1".to_string(),
            divergence_epoch: 10,
            quarantined_at: 2000,
            reason: "fork".to_string(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let decoded: QuarantinePartition = serde_json::from_str(&json).unwrap();
        assert_eq!(p, decoded);
    }

    // --- MutationCheckResult serde ---

    #[test]
    fn test_mutation_check_result_serde() {
        let r = MutationCheckResult {
            allowed: false,
            mutation_kind: "policy_update".to_string(),
            gate_state: "diverged".to_string(),
            detail: "blocked".to_string(),
            event_code: "DG-002".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("policy_update"));
    }
}
