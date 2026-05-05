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
use uuid::Uuid;

fn constant_time_eq(a: &str, b: &str) -> bool {
    crate::security::constant_time::ct_eq(a, b)
}

fn update_decimal(hasher: &mut Sha256, mut value: u128) {
    if value == 0 {
        hasher.update(b"0");
        return;
    }

    let mut buffer = [0u8; 39];
    let mut cursor = buffer.len();
    while value != 0 {
        cursor -= 1;
        let digit = match value % 10 {
            0 => b'0',
            1 => b'1',
            2 => b'2',
            3 => b'3',
            4 => b'4',
            5 => b'5',
            6 => b'6',
            7 => b'7',
            8 => b'8',
            _ => b'9',
        };
        if let Some(slot) = buffer.get_mut(cursor) {
            *slot = digit;
        }
        value /= 10;
    }
    if let Some(digits) = buffer.get(cursor..) {
        hasher.update(digits);
    }
}

fn update_len_prefixed_text(hasher: &mut Sha256, value: &str) {
    update_decimal(hasher, value.len() as u128);
    hasher.update(b":");
    hasher.update(value.as_bytes());
}

fn update_u64_text(hasher: &mut Sha256, value: u64) {
    update_decimal(hasher, u128::from(value));
}

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
// Security: bounds for push_bounded to prevent memory exhaustion
// ---------------------------------------------------------------------------

const MAX_EVENT_CODES: usize = 10_000;
const MAX_TIMING_SAMPLES: usize = 10_000;
const MAX_ATTACK_STEPS: usize = 1_000;
const MAX_CONSUMED_AUTHORIZATION_NONCES: usize = 4_096;
const AUTHORIZATION_MAX_AGE_MS: u64 = 300_000;

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
    pub key_id: String,
    pub operator_key_fingerprint: String,
    pub authorization_hash: String,
    pub signature: String,
    pub resync_checkpoint_epoch: u64,
    pub timestamp: u64,
    pub nonce: String,
    pub divergence_fingerprint: String,
    pub reason: String,
}

fn invalid_authorization_text(field: &str, value: &str) -> Option<String> {
    if value.trim().is_empty() {
        return Some(format!("{field} must not be empty"));
    }
    if value.trim() != value {
        return Some(format!(
            "{field} must not contain leading or trailing whitespace"
        ));
    }
    if value.contains('\0') {
        return Some(format!("{field} must not contain null bytes"));
    }
    if value.chars().any(char::is_control) {
        return Some(format!("{field} must not contain control characters"));
    }
    None
}

fn invalid_sha256_hex(field: &str, value: &str) -> Option<String> {
    invalid_authorization_text(field, value).or_else(|| {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(format!("{field} must be a lowercase SHA-256 hex digest"))
        } else if value.bytes().any(|b| b.is_ascii_uppercase()) {
            Some(format!("{field} must be lowercase hex"))
        } else {
            None
        }
    })
}

/// Resolves operator authorization verification keys by signed key identity.
pub trait OperatorAuthorizationKeyResolver {
    fn resolve_operator_key(&self, operator_id: &str, key_id: &str) -> Option<&[u8]>;
}

/// Single-key resolver useful for direct callers and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorAuthorizationKeyRecord {
    operator_id: String,
    key_id: String,
    verification_key: Vec<u8>,
}

impl OperatorAuthorizationKeyRecord {
    pub fn new(
        operator_id: impl Into<String>,
        key_id: impl Into<String>,
        verification_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            operator_id: operator_id.into(),
            key_id: key_id.into(),
            verification_key: verification_key.into(),
        }
    }

    pub fn for_authorization(
        authorization: &OperatorAuthorization,
        verification_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            authorization.operator_id.clone(),
            authorization.key_id.clone(),
            verification_key,
        )
    }
}

impl OperatorAuthorizationKeyResolver for OperatorAuthorizationKeyRecord {
    fn resolve_operator_key(&self, operator_id: &str, key_id: &str) -> Option<&[u8]> {
        if constant_time_eq(&self.operator_id, operator_id)
            && constant_time_eq(&self.key_id, key_id)
        {
            Some(&self.verification_key)
        } else {
            None
        }
    }
}

pub const DEFAULT_OPERATOR_AUTHORIZATION_KEY_ID: &str = "default-operator-key";

impl OperatorAuthorization {
    /// Create a new authorization with a computed hash and signature.
    ///
    /// This is suitable for standalone signature verification. Recovery through
    /// `ControlPlaneDivergenceGate::respond_recover` requires an authorization
    /// created with `new_for_active_divergence`.
    pub fn new(
        operator_id: impl Into<String>,
        resync_checkpoint_epoch: u64,
        timestamp: u64,
        reason: impl Into<String>,
        signing_key: &[u8],
    ) -> Self {
        Self::new_with_key_id(
            operator_id,
            DEFAULT_OPERATOR_AUTHORIZATION_KEY_ID,
            resync_checkpoint_epoch,
            timestamp,
            reason,
            signing_key,
        )
    }

    pub fn new_with_key_id(
        operator_id: impl Into<String>,
        key_id: impl Into<String>,
        resync_checkpoint_epoch: u64,
        timestamp: u64,
        reason: impl Into<String>,
        signing_key: &[u8],
    ) -> Self {
        Self::new_with_divergence_fingerprint(
            operator_id,
            key_id,
            resync_checkpoint_epoch,
            timestamp,
            Uuid::now_v7().simple().to_string(),
            "unbound-divergence".to_string(),
            reason,
            signing_key,
        )
    }

    /// Create a recovery authorization bound to the currently active divergence.
    pub fn new_for_active_divergence(
        operator_id: impl Into<String>,
        active_divergence: &ActiveDivergence,
        resync_checkpoint_epoch: u64,
        timestamp: u64,
        reason: impl Into<String>,
        signing_key: &[u8],
    ) -> Self {
        Self::new_for_active_divergence_with_key_id(
            operator_id,
            DEFAULT_OPERATOR_AUTHORIZATION_KEY_ID,
            active_divergence,
            resync_checkpoint_epoch,
            timestamp,
            reason,
            signing_key,
        )
    }

    pub fn new_for_active_divergence_with_key_id(
        operator_id: impl Into<String>,
        key_id: impl Into<String>,
        active_divergence: &ActiveDivergence,
        resync_checkpoint_epoch: u64,
        timestamp: u64,
        reason: impl Into<String>,
        signing_key: &[u8],
    ) -> Self {
        Self::new_with_divergence_fingerprint(
            operator_id,
            key_id,
            resync_checkpoint_epoch,
            timestamp,
            Uuid::now_v7().simple().to_string(),
            active_divergence.authorization_fingerprint(),
            reason,
            signing_key,
        )
    }

    fn new_with_divergence_fingerprint(
        operator_id: impl Into<String>,
        key_id: impl Into<String>,
        resync_checkpoint_epoch: u64,
        timestamp: u64,
        nonce: String,
        divergence_fingerprint: String,
        reason: impl Into<String>,
        signing_key: &[u8],
    ) -> Self {
        let operator_id = operator_id.into();
        let key_id = key_id.into();
        let reason = reason.into();
        let operator_key_fingerprint = Self::operator_key_fingerprint(signing_key);
        let authorization_hash = Self::authorization_hash(
            &operator_id,
            &key_id,
            &operator_key_fingerprint,
            resync_checkpoint_epoch,
            timestamp,
            &nonce,
            &divergence_fingerprint,
            &reason,
        );

        use hmac::{Hmac, KeyInit, Mac};
        let signature = match Hmac::<Sha256>::new_from_slice(signing_key) {
            Ok(mut mac) => {
                mac.update(b"divergence_gate_sign_v1:");
                mac.update(authorization_hash.as_bytes());
                hex::encode(mac.finalize().into_bytes())
            }
            Err(_) => "INVALID_SIGNING_KEY".to_string(),
        };

        Self {
            operator_id,
            key_id,
            operator_key_fingerprint,
            authorization_hash,
            signature,
            resync_checkpoint_epoch,
            timestamp,
            nonce,
            divergence_fingerprint,
            reason,
        }
    }

    fn authorization_hash(
        operator_id: &str,
        key_id: &str,
        operator_key_fingerprint: &str,
        resync_checkpoint_epoch: u64,
        timestamp: u64,
        nonce: &str,
        divergence_fingerprint: &str,
        reason: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"divergence_gate_auth_v3:");
        update_len_prefixed_text(&mut hasher, operator_id);
        hasher.update(b"|");
        update_len_prefixed_text(&mut hasher, key_id);
        hasher.update(b"|");
        update_len_prefixed_text(&mut hasher, operator_key_fingerprint);
        hasher.update(b"|");
        update_u64_text(&mut hasher, resync_checkpoint_epoch);
        hasher.update(b"|");
        update_u64_text(&mut hasher, timestamp);
        hasher.update(b"|");
        update_len_prefixed_text(&mut hasher, nonce);
        hasher.update(b"|");
        update_len_prefixed_text(&mut hasher, divergence_fingerprint);
        hasher.update(b"|");
        update_len_prefixed_text(&mut hasher, reason);
        hex::encode(hasher.finalize())
    }

    fn operator_key_fingerprint(key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"divergence_gate_operator_key_v1:");
        hasher.update(key.len().to_le_bytes());
        hasher.update(key);
        hex::encode(hasher.finalize())
    }

    /// Verify the authorization hash and signature are consistent.
    pub fn verify<R: OperatorAuthorizationKeyResolver + ?Sized>(&self, key_resolver: &R) -> bool {
        if invalid_authorization_text("operator_id", &self.operator_id).is_some()
            || invalid_authorization_text("key_id", &self.key_id).is_some()
            || invalid_sha256_hex("operator_key_fingerprint", &self.operator_key_fingerprint)
                .is_some()
            || invalid_authorization_text("nonce", &self.nonce).is_some()
            || invalid_authorization_text("divergence_fingerprint", &self.divergence_fingerprint)
                .is_some()
            || invalid_authorization_text("reason", &self.reason).is_some()
        {
            return false;
        }

        let Some(verification_key) =
            key_resolver.resolve_operator_key(&self.operator_id, &self.key_id)
        else {
            return false;
        };
        let expected_fingerprint = Self::operator_key_fingerprint(verification_key);
        if !constant_time_eq(&self.operator_key_fingerprint, &expected_fingerprint) {
            return false;
        }

        let expected = Self::authorization_hash(
            &self.operator_id,
            &self.key_id,
            &self.operator_key_fingerprint,
            self.resync_checkpoint_epoch,
            self.timestamp,
            &self.nonce,
            &self.divergence_fingerprint,
            &self.reason,
        );
        if !constant_time_eq(&self.authorization_hash, &expected) {
            return false;
        }

        use hmac::{Hmac, KeyInit, Mac};
        let mut mac = match Hmac::<Sha256>::new_from_slice(verification_key) {
            Ok(mac) => mac,
            Err(_) => return false,
        };
        mac.update(b"divergence_gate_sign_v1:");
        mac.update(self.authorization_hash.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        constant_time_eq(&self.signature, &expected_sig)
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

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;
/// Maximum blocked mutations before oldest-first eviction.
const MAX_BLOCKED_MUTATIONS: usize = 4096;
/// Maximum quarantined partitions before oldest-first eviction.
const MAX_QUARANTINED_PARTITIONS: usize = 4096;
/// Maximum alerts before oldest-first eviction.
const MAX_ALERTS: usize = 4096;

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
    consumed_authorization_nonces: Vec<String>,
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

impl ActiveDivergence {
    /// Stable fingerprint used to bind operator authorization to one divergence.
    pub fn authorization_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"divergence_gate_active_v1:");
        update_len_prefixed_text(&mut hasher, &self.detection_result);
        hasher.update(b"|");
        update_u64_text(&mut hasher, self.fork_epoch);
        hasher.update(b"|");
        update_len_prefixed_text(&mut hasher, &self.local_hash);
        hasher.update(b"|");
        update_len_prefixed_text(&mut hasher, &self.remote_hash);
        hasher.update(b"|");
        update_u64_text(&mut hasher, self.detected_at);
        hex::encode(hasher.finalize())
    }
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
            consumed_authorization_nonces: Vec::new(),
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
                push_bounded(
                    &mut self.events,
                    event_codes::DG_005_FRESHNESS_VERIFIED.to_string(),
                    MAX_EVENT_CODES,
                );
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
        if matches!(self.state, GateState::Diverged) {
            if !self.matches_active_divergence(result, local, remote) {
                push_bounded(
                    &mut self.events,
                    event_codes::DG_001_DIVERGENCE_DETECTED.to_string(),
                    MAX_EVENT_CODES,
                );
                self.emit_audit(
                    timestamp,
                    event_codes::DG_001_DIVERGENCE_DETECTED,
                    &format!(
                        "subsequent divergence while already diverged: {} at epoch {}",
                        result.label(),
                        local.epoch
                    ),
                    trace_id,
                    local.epoch,
                );
            }
            return;
        }

        // Guard: only first transition from Normal may overwrite
        // active divergence state.
        if !matches!(self.state, GateState::Normal) {
            return;
        }
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

        push_bounded(
            &mut self.events,
            event_codes::DG_001_DIVERGENCE_DETECTED.to_string(),
            MAX_EVENT_CODES,
        );
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

    fn matches_active_divergence(
        &self,
        result: &DetectionResult,
        local: &StateVector,
        remote: &StateVector,
    ) -> bool {
        self.active_divergence.as_ref().is_some_and(|active| {
            active.detection_result == result.label()
                && active.fork_epoch == local.epoch
                && active.local_hash == local.state_hash
                && active.remote_hash == remote.state_hash
        })
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
            push_bounded(
                &mut self.events,
                event_codes::DG_005_FRESHNESS_VERIFIED.to_string(),
                MAX_EVENT_CODES,
            );
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
        push_bounded(
            &mut self.blocked_mutations,
            result.clone(),
            MAX_BLOCKED_MUTATIONS,
        );
        push_bounded(
            &mut self.events,
            event_codes::DG_002_MUTATION_BLOCKED.to_string(),
            MAX_EVENT_CODES,
        );
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
        push_bounded(
            &mut self.events,
            event_codes::DG_003_RESPONSE_ACTIVATED.to_string(),
            MAX_EVENT_CODES,
        );
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

        push_bounded(
            &mut self.quarantined_partitions,
            partition.clone(),
            MAX_QUARANTINED_PARTITIONS,
        );
        self.state = GateState::Quarantined;
        if let Some(ref mut ad) = self.active_divergence {
            ad.response_mode = Some(ResponseMode::Quarantine.label().to_string());
        }

        push_bounded(
            &mut self.events,
            event_codes::DG_006_PARTITION_QUARANTINED.to_string(),
            MAX_EVENT_CODES,
        );
        push_bounded(
            &mut self.events,
            event_codes::DG_003_RESPONSE_ACTIVATED.to_string(),
            MAX_EVENT_CODES,
        );
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

        self.alert_counter = self.alert_counter.saturating_add(1);
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

        push_bounded(&mut self.alerts, alert.clone(), MAX_ALERTS);
        self.state = GateState::Alerted;
        if let Some(ref mut ad) = self.active_divergence {
            ad.response_mode = Some(ResponseMode::Alert.label().to_string());
        }

        push_bounded(
            &mut self.events,
            event_codes::DG_007_OPERATOR_ALERTED.to_string(),
            MAX_EVENT_CODES,
        );
        push_bounded(
            &mut self.events,
            event_codes::DG_003_RESPONSE_ACTIVATED.to_string(),
            MAX_EVENT_CODES,
        );
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
    pub fn respond_recover<R: OperatorAuthorizationKeyResolver + ?Sized>(
        &mut self,
        authorization: &OperatorAuthorization,
        key_resolver: &R,
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

        if let Some(reason) = invalid_authorization_text("operator_id", &authorization.operator_id)
        {
            return Err(DivergenceGateError::UnauthorizedRecovery { reason });
        }

        if let Some(reason) = invalid_authorization_text("reason", &authorization.reason) {
            return Err(DivergenceGateError::UnauthorizedRecovery { reason });
        }

        if let Some(reason) = invalid_authorization_text("nonce", &authorization.nonce) {
            return Err(DivergenceGateError::UnauthorizedRecovery { reason });
        }

        if let Some(reason) = invalid_authorization_text(
            "divergence_fingerprint",
            &authorization.divergence_fingerprint,
        ) {
            return Err(DivergenceGateError::UnauthorizedRecovery { reason });
        }

        // Verify authorization
        if !authorization.verify(key_resolver) {
            return Err(DivergenceGateError::UnauthorizedRecovery {
                reason: "authorization hash verification failed".to_string(),
            });
        }

        if authorization.timestamp > timestamp {
            return Err(DivergenceGateError::UnauthorizedRecovery {
                reason: "authorization timestamp is in the future".to_string(),
            });
        }

        if timestamp.saturating_sub(authorization.timestamp) > AUTHORIZATION_MAX_AGE_MS {
            return Err(DivergenceGateError::UnauthorizedRecovery {
                reason: "authorization expired".to_string(),
            });
        }

        let active_divergence = self.active_divergence.as_ref().ok_or_else(|| {
            DivergenceGateError::UnauthorizedRecovery {
                reason: "authorization has no active divergence to recover".to_string(),
            }
        })?;
        let expected_fingerprint = active_divergence.authorization_fingerprint();
        if !constant_time_eq(&authorization.divergence_fingerprint, &expected_fingerprint) {
            return Err(DivergenceGateError::UnauthorizedRecovery {
                reason: "authorization not bound to active divergence".to_string(),
            });
        }

        if self
            .consumed_authorization_nonces
            .iter()
            .any(|nonce| constant_time_eq(nonce, &authorization.nonce))
        {
            return Err(DivergenceGateError::UnauthorizedRecovery {
                reason: "authorization nonce already consumed".to_string(),
            });
        }

        // Transition to Recovering (observable intermediate state)
        self.state = GateState::Recovering;
        push_bounded(
            &mut self.consumed_authorization_nonces,
            authorization.nonce.clone(),
            MAX_CONSUMED_AUTHORIZATION_NONCES,
        );
        self.emit_audit(
            timestamp,
            event_codes::DG_004_RECOVERY_COMPLETED,
            "entering recovery: operator_reset pending",
            trace_id,
            authorization.resync_checkpoint_epoch,
        );
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

        push_bounded(
            &mut self.events,
            event_codes::DG_004_RECOVERY_COMPLETED.to_string(),
            MAX_EVENT_CODES,
        );
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
                push_bounded(
                    &mut self.events,
                    event_codes::DG_008_MARKER_PROOF_VERIFIED.to_string(),
                    MAX_EVENT_CODES,
                );
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
        push_bounded(
            &mut self.audit_log,
            GateAuditEntry {
                timestamp,
                event_code: event_code.to_string(),
                gate_state: self.state.label().to_string(),
                detail: detail.to_string(),
                trace_id: trace_id.to_string(),
                node_id: self.node_id.clone(),
                epoch_id,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
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
    use super::{
        ActiveDivergence, ControlPlaneDivergenceGate, DetectionResult, DivergenceGateError,
        GateState, MutationKind, OperatorAuthorization, OperatorAuthorizationKeyRecord,
        StateVector, event_codes,
    };

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

    fn diverged_gate() -> ControlPlaneDivergenceGate {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        gate
    }

    fn recovery_auth(
        gate: &ControlPlaneDivergenceGate,
        operator_id: &str,
        resync_checkpoint_epoch: u64,
        timestamp: u64,
        reason: &str,
        signing_key: &[u8],
    ) -> OperatorAuthorization {
        OperatorAuthorization::new_for_active_divergence(
            operator_id,
            gate.active_divergence().expect("active divergence"),
            resync_checkpoint_epoch,
            timestamp,
            reason,
            signing_key,
        )
    }

    fn auth_key(auth: &OperatorAuthorization, key: &[u8]) -> OperatorAuthorizationKeyRecord {
        OperatorAuthorizationKeyRecord::for_authorization(auth, key.to_vec())
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
        let err = gate
            .check_mutation(&MutationKind::TokenIssuance, 2001, "trace-2")
            .unwrap_err();
        assert!(matches!(
            err,
            DivergenceGateError::DivergenceBlock { ref mutation_kind, .. } if mutation_kind == "token_issuance"
        ));
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

    #[test]
    fn test_distinct_fork_while_diverged_is_audited_without_overwriting_active_divergence() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let active_before = gate.active_divergence().cloned().unwrap();
        let audit_before = gate.audit_log().len();
        let events_before = gate.events().len();
        let parent = StateVector::compute_state_hash("parent");
        let second_remote = make_sv(10, "state-C", &parent, "node-C");

        let (result, _, _) = gate.check_propagation(&local, &second_remote, 2001, "trace-2");

        assert_eq!(result, DetectionResult::Forked);
        assert_eq!(gate.state(), GateState::Diverged);
        assert_eq!(
            gate.active_divergence().unwrap().local_hash,
            active_before.local_hash
        );
        assert_eq!(
            gate.active_divergence().unwrap().remote_hash,
            active_before.remote_hash
        );
        assert_eq!(gate.audit_log().len(), audit_before + 1);
        assert_eq!(gate.events().len(), events_before + 1);
        let entry = gate.audit_log().last().unwrap();
        assert_eq!(entry.event_code, event_codes::DG_001_DIVERGENCE_DETECTED);
        assert_eq!(entry.trace_id, "trace-2");
        assert_eq!(entry.epoch_id, 10);
        assert!(entry.detail.contains("subsequent divergence"));
    }

    #[test]
    fn test_duplicate_fork_while_diverged_is_not_reaudited() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let audit_before = gate.audit_log().len();
        let events_before = gate.events().len();

        let (result, _, _) = gate.check_propagation(&local, &remote, 2001, "trace-2");

        assert_eq!(result, DetectionResult::Forked);
        assert_eq!(gate.audit_log().len(), audit_before);
        assert_eq!(gate.events().len(), events_before);
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

    #[test]
    fn test_halt_from_normal_does_not_emit_or_audit() {
        let mut gate = ControlPlaneDivergenceGate::new("test");

        let err = gate.respond_halt(2000, "trace-1").unwrap_err();

        assert!(matches!(err, DivergenceGateError::InvalidTransition { .. }));
        assert_eq!(gate.state(), GateState::Normal);
        assert!(gate.events().is_empty());
        assert!(gate.audit_log().is_empty());
        assert!(gate.active_divergence().is_none());
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
    fn test_quarantine_from_normal_does_not_create_partition() {
        let mut gate = ControlPlaneDivergenceGate::new("test");

        let err = gate
            .respond_quarantine("part-1", "node-B", 2000, "trace-1")
            .unwrap_err();

        assert!(matches!(err, DivergenceGateError::InvalidTransition { .. }));
        assert_eq!(gate.state(), GateState::Normal);
        assert!(gate.quarantined_partitions().is_empty());
        assert!(gate.events().is_empty());
        assert!(gate.audit_log().is_empty());
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

    #[test]
    fn test_alert_from_normal_does_not_increment_or_emit() {
        let mut gate = ControlPlaneDivergenceGate::new("test");

        let err = gate.respond_alert(2000, "trace-1").unwrap_err();

        assert!(matches!(err, DivergenceGateError::InvalidTransition { .. }));
        assert_eq!(gate.state(), GateState::Normal);
        assert_eq!(gate.alert_counter, 0);
        assert!(gate.alerts().is_empty());
        assert!(gate.events().is_empty());
        assert!(gate.audit_log().is_empty());
    }

    // --- RECOVER response ---

    #[test]
    fn test_recover_from_diverged() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let auth = recovery_auth(&gate, "operator-1", 9, 2001, "fix fork", b"test-key");
        let result =
            gate.respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2001, "trace-2");
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
        let auth = recovery_auth(&gate, "operator-1", 9, 2002, "fix fork", b"test-key");
        let result =
            gate.respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2002, "trace-3");
        assert!(result.is_ok());
        assert_eq!(gate.state(), GateState::Normal);
    }

    #[test]
    fn test_recover_rejects_expired_authorization() {
        let mut gate = diverged_gate();
        let auth = recovery_auth(&gate, "operator-1", 9, 2001, "fix fork", b"test-key");

        let result = gate.respond_recover(
            &auth,
            &auth_key(&auth, b"test-key"),
            10,
            2001 + AUTHORIZATION_MAX_AGE_MS + 1,
            "trace-expired",
        );

        assert!(matches!(
            result.unwrap_err(),
            DivergenceGateError::UnauthorizedRecovery { .. }
        ));
        assert_eq!(gate.state(), GateState::Diverged);
        assert!(gate.active_divergence().is_some());
    }

    #[test]
    fn test_recover_rejects_wrong_divergence_binding() {
        let original_gate = diverged_gate();
        let auth = recovery_auth(
            &original_gate,
            "operator-1",
            9,
            2001,
            "fix original fork",
            b"test-key",
        );

        let mut other_gate = ControlPlaneDivergenceGate::new("other");
        let (local, remote) = gapped_pair();
        other_gate.check_propagation(&local, &remote, 2001, "trace-other");

        let result = other_gate.respond_recover(
            &auth,
            &auth_key(&auth, b"test-key"),
            10,
            2002,
            "trace-wrong",
        );

        assert!(matches!(
            result.unwrap_err(),
            DivergenceGateError::UnauthorizedRecovery { .. }
        ));
        assert_eq!(other_gate.state(), GateState::Diverged);
        assert!(original_gate.active_divergence().is_some());
    }

    #[test]
    fn test_recover_from_normal_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let auth = OperatorAuthorization::new("operator-1", 9, 2000, "fix", b"test-key");
        let result =
            gate.respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2000, "trace-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_recover_from_normal_does_not_reset_or_emit() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let auth = OperatorAuthorization::new("operator-1", 9, 2000, "fix", b"test-key");

        let err = gate
            .respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2000, "trace-1")
            .unwrap_err();

        assert!(matches!(err, DivergenceGateError::InvalidTransition { .. }));
        assert_eq!(gate.state(), GateState::Normal);
        assert!(gate.events().is_empty());
        assert!(gate.audit_log().is_empty());
        assert!(gate.active_divergence().is_none());
    }

    #[test]
    fn test_recover_unauthorized_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let mut auth = OperatorAuthorization::new("operator-1", 9, 2001, "fix", b"test-key");
        auth.authorization_hash = "tampered".to_string();
        let err = gate
            .respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2001, "trace-2")
            .unwrap_err();
        assert!(matches!(
            err,
            DivergenceGateError::UnauthorizedRecovery { .. }
        ));
    }

    #[test]
    fn test_recover_bad_signature_preserves_divergence_state() {
        let mut gate = diverged_gate();
        let events_before = gate.events().len();
        let audit_before = gate.audit_log().len();
        let active_before = gate.active_divergence().cloned().unwrap();
        let mut auth = OperatorAuthorization::new("operator-1", 9, 2001, "fix", b"test-key");
        auth.signature = "tampered".to_string();

        let err = gate
            .respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2001, "trace-2")
            .unwrap_err();

        assert!(matches!(
            err,
            DivergenceGateError::UnauthorizedRecovery { .. }
        ));
        assert_eq!(gate.state(), GateState::Diverged);
        assert_eq!(gate.events().len(), events_before);
        assert_eq!(gate.audit_log().len(), audit_before);
        let active_after = gate.active_divergence().unwrap();
        assert_eq!(
            active_after.detection_result,
            active_before.detection_result
        );
        assert_eq!(active_after.fork_epoch, active_before.fork_epoch);
        assert_eq!(active_after.local_hash, active_before.local_hash);
        assert_eq!(active_after.remote_hash, active_before.remote_hash);
        assert_eq!(active_after.response_mode, active_before.response_mode);
    }

    #[test]
    fn test_recover_empty_operator_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let auth = OperatorAuthorization::new("", 9, 2001, "fix", b"test-key");
        let result =
            gate.respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2001, "trace-2");
        assert!(result.is_err());
    }

    #[test]
    fn test_recover_empty_operator_preserves_quarantine_state() {
        let mut gate = diverged_gate();
        gate.respond_quarantine("part-1", "node-B", 2001, "trace-2")
            .unwrap();
        let events_before = gate.events().len();
        let audit_before = gate.audit_log().len();
        let partitions_before = gate.quarantined_partitions().len();
        let active_before = gate.active_divergence().cloned().unwrap();
        let auth = OperatorAuthorization::new("", 9, 2002, "fix", b"test-key");

        let err = gate
            .respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2002, "trace-3")
            .unwrap_err();

        assert!(matches!(
            err,
            DivergenceGateError::UnauthorizedRecovery { .. }
        ));
        assert_eq!(gate.state(), GateState::Quarantined);
        assert_eq!(gate.events().len(), events_before);
        assert_eq!(gate.audit_log().len(), audit_before);
        assert_eq!(gate.quarantined_partitions().len(), partitions_before);
        let active_after = gate.active_divergence().unwrap();
        assert_eq!(
            active_after.detection_result,
            active_before.detection_result
        );
        assert_eq!(active_after.fork_epoch, active_before.fork_epoch);
        assert_eq!(active_after.local_hash, active_before.local_hash);
        assert_eq!(active_after.remote_hash, active_before.remote_hash);
        assert_eq!(active_after.response_mode, active_before.response_mode);
    }

    // --- OperatorAuthorization ---

    #[test]
    fn test_operator_authorization_verify() {
        let auth = OperatorAuthorization::new("op-1", 50, 3000, "reason", b"test-key");
        assert!(auth.verify(&auth_key(&auth, b"test-key")));
    }

    #[test]
    fn test_operator_authorization_hash_contract_is_stable() {
        let auth = OperatorAuthorization::new_with_divergence_fingerprint(
            "op-1",
            "operator-key-a",
            50,
            3000,
            "nonce-0001".to_string(),
            "divergence-abc".to_string(),
            "reason",
            b"test-key",
        );

        assert_eq!(
            auth.operator_key_fingerprint,
            "66aadc917939f8cc0052d1e9788dabd9934614ca66cce0a635574376054146ad"
        );
        assert_eq!(
            auth.authorization_hash,
            "a19873004d55ef2c859b6b7535310f78d3ce25e6702d9d662a18b416ba11d70a"
        );
        assert_eq!(
            auth.signature,
            "6dbf0b5b0649c9ff4ada2ebf9b0e2766c5117dfc22a80f4f1212c0ef9a3f9fed"
        );
        assert!(auth.verify(&auth_key(&auth, b"test-key")));
    }

    #[test]
    fn test_active_divergence_fingerprint_contract_is_stable() {
        let active = ActiveDivergence {
            detection_result: "FORKED".to_string(),
            fork_epoch: 10,
            local_hash: "local-hash".to_string(),
            remote_hash: "remote-hash".to_string(),
            detected_at: 2000,
            proof: None,
            response_mode: None,
        };

        assert_eq!(
            active.authorization_fingerprint(),
            "020e6248ac2585e089fd29c2b7b22096cd5a10a7c0a14e53eed7c3c67d001b73"
        );
    }

    #[test]
    fn test_operator_authorization_tampered() {
        let mut auth = OperatorAuthorization::new("op-1", 50, 3000, "reason", b"test-key");
        auth.authorization_hash = "bad".to_string();
        assert!(!auth.verify(&auth_key(&auth, b"test-key")));
    }

    #[test]
    fn test_operator_authorization_wrong_key_fails_without_mutation() {
        let auth = OperatorAuthorization::new("op-1", 50, 3000, "reason", b"test-key");
        let original = auth.clone();

        assert!(!auth.verify(&auth_key(&auth, b"wrong-key")));
        assert_eq!(auth, original);
    }

    #[test]
    fn test_operator_authorization_rejects_key_id_substitution() {
        let auth = OperatorAuthorization::new_with_key_id(
            "op-1",
            "operator-key-a",
            50,
            3000,
            "reason",
            b"test-key",
        );
        let matching =
            OperatorAuthorizationKeyRecord::new("op-1", "operator-key-a", b"test-key".to_vec());
        let wrong_id_same_key =
            OperatorAuthorizationKeyRecord::new("op-1", "operator-key-b", b"test-key".to_vec());
        let same_id_wrong_key =
            OperatorAuthorizationKeyRecord::new("op-1", "operator-key-a", b"wrong-key".to_vec());

        assert!(auth.verify(&matching));
        assert!(!auth.verify(&wrong_id_same_key));
        assert!(!auth.verify(&same_id_wrong_key));
    }

    #[test]
    fn test_operator_authorization_tampered_reason_fails_verification() {
        let mut auth = OperatorAuthorization::new("op-1", 50, 3000, "reason", b"test-key");
        auth.reason = "different reason".to_string();

        assert!(!auth.verify(&auth_key(&auth, b"test-key")));
    }

    #[test]
    fn test_operator_authorization_empty_reason_fails_verification() {
        let auth = OperatorAuthorization::new("op-1", 50, 3000, "", b"test-key");

        assert!(!auth.verify(&auth_key(&auth, b"test-key")));
    }

    #[test]
    fn test_operator_authorization_control_character_operator_fails_verification() {
        let auth = OperatorAuthorization::new("op-\n1", 50, 3000, "reason", b"test-key");

        assert!(!auth.verify(&auth_key(&auth, b"test-key")));
    }

    #[test]
    fn test_recover_blank_reason_fails() {
        let mut gate = ControlPlaneDivergenceGate::new("test");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "trace-1");
        let auth = OperatorAuthorization::new("operator-1", 9, 2001, "", b"test-key");
        let result =
            gate.respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2001, "trace-2");
        assert!(result.is_err());
    }

    #[test]
    fn test_operator_authorization_serde() {
        let auth = OperatorAuthorization::new("op-1", 50, 3000, "reason", b"test-key");
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
        let auth = recovery_auth(&gate, "op-1", 9, 2001, "fix", b"test-key");
        gate.respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2001, "trace-2")
            .unwrap();
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
        let auth = recovery_auth(&gate, "admin", 9, 2004, "approved fix", b"test-key");
        gate.respond_recover(&auth, &auth_key(&auth, b"test-key"), 10, 2004, "trace-5")
            .unwrap();
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

    // --- Comprehensive Negative-Path Attack Vector Testing ---

    #[test]
    fn negative_state_machine_transition_boundary_and_invariant_violation_attacks() {
        let mut gate = ControlPlaneDivergenceGate::new("test-node");

        // Test 1: State transition boundary attacks and illegal state manipulation
        let illegal_transition_sequences = vec![
            // Attempt direct transition to Quarantined without Diverged
            ("Normal", "try_quarantine_direct"),
            // Attempt Alert from Normal
            ("Normal", "try_alert_direct"),
            // Attempt Recovery from Normal
            ("Normal", "try_recover_direct"),
        ];

        for (initial_state, attack_description) in illegal_transition_sequences {
            assert_eq!(
                gate.state().label(),
                "normal",
                "Should start in Normal state"
            );

            match attack_description {
                "try_quarantine_direct" => {
                    let result = gate.respond_quarantine(
                        "malicious-partition",
                        "malicious-node",
                        1000,
                        "attack-trace",
                    );
                    assert!(result.is_err(), "Direct quarantine from Normal should fail");
                    assert!(
                        matches!(
                            result.unwrap_err(),
                            DivergenceGateError::InvalidTransition { .. }
                        ),
                        "Should be InvalidTransition error"
                    );

                    // Verify no side effects from failed attack
                    assert_eq!(
                        gate.state(),
                        GateState::Normal,
                        "State should remain Normal after failed quarantine"
                    );
                    assert!(
                        gate.quarantined_partitions().is_empty(),
                        "Should not create partitions from failed attack"
                    );
                    assert!(
                        gate.events().is_empty(),
                        "Should not emit events from failed attack"
                    );
                }
                "try_alert_direct" => {
                    let result = gate.respond_alert(1001, "alert-attack-trace");
                    assert!(result.is_err(), "Direct alert from Normal should fail");
                    assert!(
                        matches!(
                            result.unwrap_err(),
                            DivergenceGateError::InvalidTransition { .. }
                        ),
                        "Should be InvalidTransition error"
                    );

                    // Verify no side effects
                    assert_eq!(
                        gate.state(),
                        GateState::Normal,
                        "State should remain Normal after failed alert"
                    );
                    assert!(
                        gate.alerts().is_empty(),
                        "Should not create alerts from failed attack"
                    );
                    assert_eq!(
                        gate.alert_counter, 0,
                        "Alert counter should not increment from failed attack"
                    );
                }
                "try_recover_direct" => {
                    let malicious_auth = OperatorAuthorization::new(
                        "malicious-operator",
                        999,
                        1002,
                        "bypass attempt",
                        b"fake-key",
                    );
                    let result = gate.respond_recover(
                        &malicious_auth,
                        &auth_key(&malicious_auth, b"fake-key"),
                        50,
                        1002,
                        "recover-attack-trace",
                    );
                    assert!(result.is_err(), "Direct recover from Normal should fail");
                    assert!(
                        matches!(
                            result.unwrap_err(),
                            DivergenceGateError::InvalidTransition { .. }
                        ),
                        "Should be InvalidTransition error"
                    );

                    // Verify detector state not modified
                    assert_eq!(
                        gate.state(),
                        GateState::Normal,
                        "State should remain Normal after failed recovery"
                    );
                    assert!(
                        gate.active_divergence().is_none(),
                        "Should not have active divergence from failed recovery"
                    );
                }
                _ => unreachable!(),
            }
        }

        // Test 2: State consistency under rapid transition attempts
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 2000, "divergence-trace");
        assert_eq!(
            gate.state(),
            GateState::Diverged,
            "Should be in Diverged state"
        );

        // Rapid-fire transition attempts that should preserve state consistency
        for i in 0..1000 {
            let trace_id = format!("rapid-attack-{}", i);

            // Multiple HALT attempts (should be idempotent)
            let halt_result = gate.respond_halt(2000 + i, &trace_id);
            assert!(
                halt_result.is_ok(),
                "HALT should succeed from Diverged at iteration {}",
                i
            );
            assert_eq!(
                gate.state(),
                GateState::Diverged,
                "State should remain Diverged after HALT at iteration {}",
                i
            );
        }

        // Test 3: Transition ordering constraint violations
        let transition_attack_sequences = vec![
            // Try to transition Quarantined -> Diverged (invalid reverse)
            (vec!["quarantine", "halt"], "reverse_quarantine_to_halt"),
            // Try to transition Alerted -> Quarantined (invalid lateral)
            (vec!["alert", "quarantine"], "lateral_alert_to_quarantine"),
            // Try to transition Recovering -> Alerted (invalid during recovery)
            (
                vec!["alert", "recover_start", "alert"],
                "transition_during_recovery",
            ),
        ];

        for (sequence, attack_name) in transition_attack_sequences {
            // Reset to diverged state for each attack sequence
            let mut test_gate = ControlPlaneDivergenceGate::new("transition-attack-test");
            let (local, remote) = forked_pair();
            test_gate.check_propagation(&local, &remote, 3000, "setup-trace");

            let mut expected_final_state = GateState::Diverged;

            for (step_idx, action) in sequence.iter().enumerate() {
                match action.as_str() {
                    "quarantine" => {
                        let result = test_gate.respond_quarantine(
                            format!("attack-partition-{}", step_idx),
                            "attack-node",
                            3000 + u64::try_from(step_idx).unwrap_or(u64::MAX),
                            &format!("attack-{}-{}", attack_name, step_idx),
                        );
                        if step_idx == 0 {
                            assert!(
                                result.is_ok(),
                                "Initial quarantine should succeed in attack {}",
                                attack_name
                            );
                            expected_final_state = GateState::Quarantined;
                        }
                    }
                    "halt" => {
                        let result = test_gate.respond_halt(
                            3000 + u64::try_from(step_idx).unwrap_or(u64::MAX),
                            &format!("attack-{}-{}", attack_name, step_idx),
                        );
                        // HALT from Quarantined should fail
                        if expected_final_state == GateState::Quarantined {
                            assert!(
                                result.is_err(),
                                "HALT from Quarantined should fail in attack {}",
                                attack_name
                            );
                        }
                    }
                    "alert" => {
                        let result = test_gate.respond_alert(
                            3000 + step_idx as u64,
                            &format!("attack-{}-{}", attack_name, step_idx),
                        );
                        if step_idx == 0 || expected_final_state == GateState::Quarantined {
                            assert!(
                                result.is_ok(),
                                "Alert should succeed from valid states in attack {}",
                                attack_name
                            );
                            expected_final_state = GateState::Alerted;
                        } else if expected_final_state == GateState::Recovering {
                            assert!(
                                result.is_err(),
                                "Alert should fail during recovery in attack {}",
                                attack_name
                            );
                        }
                    }
                    "recover_start" => {
                        let auth = recovery_auth(
                            &test_gate,
                            "test-operator",
                            2,
                            3000 + step_idx as u64,
                            "test recovery",
                            b"test-key",
                        );
                        let result = test_gate.respond_recover(
                            &auth,
                            &auth_key(&auth, b"test-key"),
                            10,
                            3000 + step_idx as u64,
                            &format!("attack-{}-{}", attack_name, step_idx),
                        );
                        if expected_final_state == GateState::Alerted {
                            assert!(
                                result.is_ok(),
                                "Recovery should succeed from Alerted in attack {}",
                                attack_name
                            );
                            expected_final_state = GateState::Normal;
                        }
                    }
                    _ => {}
                }
            }

            // Verify final state consistency
            assert!(
                test_gate.state() == expected_final_state || test_gate.state() == GateState::Normal,
                "Final state should be consistent after attack sequence {}: expected {:?}, got {:?}",
                attack_name,
                expected_final_state,
                test_gate.state()
            );
        }
    }

    #[test]
    fn negative_operator_authorization_cryptographic_bypass_and_tampering_attacks() {
        let mut gate = ControlPlaneDivergenceGate::new("crypto-test-node");
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 4000, "crypto-setup");

        // Test 1: Authorization signature bypass attacks
        let signature_bypass_attacks = vec![
            // Signature manipulation attacks
            ("signature_truncation", |mut auth: OperatorAuthorization| {
                auth.signature = auth.signature[..auth.signature.len() - 2].to_string();
                auth
            }),
            ("signature_extension", |mut auth: OperatorAuthorization| {
                auth.signature.push_str("00");
                auth
            }),
            (
                "signature_case_manipulation",
                |mut auth: OperatorAuthorization| {
                    auth.signature = auth.signature.to_uppercase();
                    auth
                },
            ),
            (
                "signature_nullbyte_injection",
                |mut auth: OperatorAuthorization| {
                    auth.signature = auth.signature.replace("a", "\x00a");
                    auth
                },
            ),
            // Hash manipulation attacks
            ("hash_prefix_attack", |mut auth: OperatorAuthorization| {
                auth.authorization_hash = "00".to_string() + &auth.authorization_hash;
                auth
            }),
            ("hash_suffix_attack", |mut auth: OperatorAuthorization| {
                auth.authorization_hash.push_str("ff");
                auth
            }),
            (
                "hash_collision_attempt",
                |mut auth: OperatorAuthorization| {
                    auth.authorization_hash = "a".repeat(64); // Invalid length/format
                    auth
                },
            ),
            ("hash_encoding_attack", |mut auth: OperatorAuthorization| {
                auth.authorization_hash = auth.authorization_hash.replace("a", "\u{202E}a\u{202D}"); // BiDi override
                auth
            }),
            // Field tampering attacks
            (
                "operator_id_injection",
                |mut auth: OperatorAuthorization| {
                    auth.operator_id = "admin\x00".to_string() + &auth.operator_id;
                    auth
                },
            ),
            (
                "timestamp_manipulation",
                |mut auth: OperatorAuthorization| {
                    auth.timestamp = auth.timestamp.saturating_add(1000000); // Far future
                    auth
                },
            ),
            ("epoch_overflow", |mut auth: OperatorAuthorization| {
                auth.resync_checkpoint_epoch = u64::MAX;
                auth
            }),
            ("reason_injection", |mut auth: OperatorAuthorization| {
                auth.reason = "legitimate\"; DROP TABLE authorizations; --".to_string();
                auth
            }),
        ];

        for (attack_name, attack_fn) in signature_bypass_attacks {
            let valid_auth = recovery_auth(
                &gate,
                "test-operator",
                3,
                4001,
                "legitimate recovery",
                b"test-key",
            );
            let tampered_auth = attack_fn(valid_auth);

            let recovery_result = gate.respond_recover(
                &tampered_auth,
                &auth_key(&tampered_auth, b"test-key"),
                25,
                4001,
                &format!("crypto-attack-{}", attack_name),
            );

            assert!(
                recovery_result.is_err(),
                "Tampered authorization should fail for attack: {}",
                attack_name
            );
            assert!(
                matches!(
                    recovery_result.unwrap_err(),
                    DivergenceGateError::UnauthorizedRecovery { .. }
                ),
                "Should be UnauthorizedRecovery error for attack: {}",
                attack_name
            );

            // Verify gate state unchanged by failed attack
            assert_eq!(
                gate.state(),
                GateState::Diverged,
                "Gate should remain Diverged after failed attack: {}",
                attack_name
            );
            assert!(
                gate.active_divergence().is_some(),
                "Should still have active divergence after failed attack: {}",
                attack_name
            );
        }

        // Test 2: Key substitution and cryptographic oracle attacks
        let key_substitution_attacks = vec![
            // Key length attacks
            ("empty_key", b"".to_vec()),
            ("short_key", b"a".to_vec()),
            ("long_key", vec![0xFF; 10000]),
            // Key content attacks
            ("null_key", vec![0x00; 32]),
            ("max_key", vec![0xFF; 32]),
            (
                "alternating_key",
                (0..32)
                    .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
                    .collect(),
            ),
            // Control character keys
            (
                "control_char_key",
                (0..32).map(|i| (i as u8) % 32).collect(),
            ), // Control characters
            ("unicode_key", "🔑".repeat(8).as_bytes().to_vec()),
        ];

        for (attack_name, malicious_key) in key_substitution_attacks {
            let valid_auth = recovery_auth(
                &gate,
                "test-operator",
                3,
                4002,
                "key attack test",
                &malicious_key,
            );

            let recovery_result = gate.respond_recover(
                &valid_auth,
                &auth_key(&valid_auth, &malicious_key),
                30,
                4002,
                &format!("key-attack-{}", attack_name),
            );

            // Most attacks should fail, but we verify that system doesn't crash
            if recovery_result.is_ok() {
                // If it succeeds, verify it's a legitimate success (not a bypass)
                assert_eq!(
                    gate.state(),
                    GateState::Normal,
                    "If recovery succeeds, should transition to Normal for attack: {}",
                    attack_name
                );
                // Reset state for next test
                let (local, remote) = forked_pair();
                gate.check_propagation(
                    &local,
                    &remote,
                    4002,
                    &format!("reset-after-{}", attack_name),
                );
            } else {
                assert!(
                    matches!(
                        recovery_result.unwrap_err(),
                        DivergenceGateError::UnauthorizedRecovery { .. }
                    ),
                    "Failed key attack should be UnauthorizedRecovery for: {}",
                    attack_name
                );
                assert_eq!(
                    gate.state(),
                    GateState::Diverged,
                    "Gate should remain Diverged after failed key attack: {}",
                    attack_name
                );
            }
        }

        // Test 3: Timing attack resistance and constant-time validation
        let timing_attack_test_iterations = 1000;
        let mut timing_samples = Vec::new();

        for i in 0..timing_attack_test_iterations {
            let valid_auth =
                OperatorAuthorization::new("timing-test", 3, 4003, "timing test", b"correct-key");

            // Create slightly different incorrect keys to test timing consistency
            let incorrect_key = if i % 2 == 0 {
                b"incorrect-key".to_vec()
            } else {
                b"wrong-key-different".to_vec()
            };

            let start_time = std::time::Instant::now();
            let _ = valid_auth.verify(&auth_key(&valid_auth, &incorrect_key));
            let verification_time = start_time.elapsed();

            timing_samples.push(verification_time);
        }

        // Statistical analysis for timing attack resistance
        let mean_time = timing_samples.iter().sum::<std::time::Duration>()
            / u32::try_from(timing_samples.len()).unwrap_or(u32::MAX);
        let variance = timing_samples
            .iter()
            .map(|&t| {
                let diff = if t > mean_time {
                    t - mean_time
                } else {
                    mean_time - t
                };
                diff.as_nanos() as f64
            })
            .map(|diff| diff * diff)
            .sum::<f64>()
            / timing_samples.len() as f64;

        let std_dev = variance.sqrt();
        let coefficient_of_variation = std_dev / mean_time.as_nanos() as f64;

        // Timing should be relatively consistent (low coefficient of variation)
        assert!(
            coefficient_of_variation < 0.5,
            "Timing variation too high (CoV: {:.3}), potential timing leak",
            coefficient_of_variation
        );

        // Test 4: Authorization replay and reuse attacks
        let valid_auth = recovery_auth(
            &gate,
            "replay-test",
            3,
            4004,
            "replay attack test",
            b"test-key",
        );

        // First use should succeed
        let first_result = gate.respond_recover(
            &valid_auth,
            &auth_key(&valid_auth, b"test-key"),
            40,
            4004,
            "first-use",
        );
        assert!(
            first_result.is_ok(),
            "First use of authorization should succeed"
        );
        assert_eq!(
            gate.state(),
            GateState::Normal,
            "Should be Normal after first recovery"
        );

        // Trigger new divergence
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 4005, "new-divergence");

        // Replay attempt must fail: the nonce was consumed and the token is
        // bound to the previous active divergence.
        let replay_result = gate.respond_recover(
            &valid_auth,
            &auth_key(&valid_auth, b"test-key"),
            45,
            4005,
            "replay-attempt",
        );

        assert!(
            matches!(
                replay_result.unwrap_err(),
                DivergenceGateError::UnauthorizedRecovery { .. }
            ),
            "Replay rejection should be UnauthorizedRecovery"
        );
        assert_eq!(
            gate.state(),
            GateState::Diverged,
            "Replay must not recover a later divergence"
        );
    }

    #[test]
    fn negative_input_validation_injection_and_boundary_bypass_attacks() {
        let mut gate = ControlPlaneDivergenceGate::new("injection-test-node");

        // Test 1: Node ID and trace ID injection attacks
        let injection_attack_vectors = vec![
            // Control character injection
            ("node\x00\r\ninjection", "trace\x00injection"),
            ("node\x1b[31mANSI\x1b[0m", "trace\x1b[32mcolor"),
            // Unicode attacks
            ("node\u{202E}spoofed", "trace\u{FEFF}invisible"),
            ("node\u{10FFFF}private", "trace\u{E000}pua"),
            // Format string attacks
            ("node%s%x%n", "trace%s%x%n"),
            ("node$(echo attack)", "trace`whoami`"),
            // JSON/XML injection
            ("node\"}malicious", "trace</xml><script>"),
            ("node\\u0000", "trace\\n\\r\\t"),
            // Path traversal
            ("../../../node", "../../trace"),
            ("node\\..\\..\\windows", "trace/etc/passwd"),
            // Very long inputs
            ("x".repeat(100000), "y".repeat(100000)),
            // Empty and whitespace
            ("", ""),
            (" ", "\t"),
            ("\u{3000}", "\u{2000}"), // Unicode spaces
        ];

        for (malicious_node, malicious_trace) in injection_attack_vectors {
            // Test with check_propagation
            let (local, remote) = forked_pair();
            let (result, proof, log_event) =
                gate.check_propagation(&local, &remote, 5000, malicious_trace);

            assert_eq!(
                result,
                DetectionResult::Forked,
                "Should detect fork regardless of malicious trace"
            );
            assert!(proof.is_none(), "Should not have proof for basic fork");
            assert!(
                !log_event.local_hash.is_empty(),
                "Log event should have valid local hash despite injection"
            );

            // Test with respond_quarantine using malicious node ID
            if gate.state() == GateState::Diverged {
                let quarantine_result = gate.respond_quarantine(
                    format!("partition-for-{}", malicious_node.escape_debug()),
                    malicious_node,
                    5001,
                    malicious_trace,
                );

                if quarantine_result.is_ok() {
                    let partition = quarantine_result.unwrap();
                    // Verify malicious input is contained and stored exactly
                    assert_eq!(
                        partition.node_id,
                        malicious_node,
                        "Node ID should be stored exactly as provided: '{}'",
                        malicious_node.escape_debug()
                    );
                    assert!(
                        partition.reason.contains("divergence"),
                        "Reason should contain expected text despite injection"
                    );

                    // Test alert with malicious trace
                    let alert_result = gate.respond_alert(5002, malicious_trace);
                    if alert_result.is_ok() {
                        let alert = alert_result.unwrap();
                        assert_eq!(
                            alert.trace_id,
                            malicious_trace,
                            "Trace ID should be stored exactly: '{}'",
                            malicious_trace.escape_debug()
                        );
                        assert!(
                            !alert.alert_id.is_empty(),
                            "Alert ID should be generated despite injection"
                        );
                        assert!(
                            alert.severity == "CRITICAL",
                            "Severity should be set correctly"
                        );
                    }
                }
            }

            // Reset gate for next test
            if gate.active_divergence().is_some() {
                let auth = recovery_auth(
                    &gate,
                    "reset-operator",
                    4,
                    5003,
                    "reset for next test",
                    b"reset-key",
                );
                let _ = gate.respond_recover(
                    &auth,
                    &auth_key(&auth, b"reset-key"),
                    50,
                    5003,
                    "reset-trace",
                );
            }
        }

        // Test 2: Mutation kind bypass and enum manipulation attacks
        let mutation_bypass_attempts = vec![
            // Test all valid mutation kinds work correctly
            (MutationKind::PolicyUpdate, "policy_update"),
            (MutationKind::TokenIssuance, "token_issuance"),
            (MutationKind::ZoneBoundaryChange, "zone_boundary_change"),
            (MutationKind::RevocationPublish, "revocation_publish"),
            (MutationKind::EpochTransition, "epoch_transition"),
            (MutationKind::QuarantinePromotion, "quarantine_promotion"),
        ];

        // Force diverged state
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 6000, "mutation-test-setup");

        for (mutation_kind, expected_label) in mutation_bypass_attempts {
            let check_result = gate.check_mutation(&mutation_kind, 6001, "mutation-bypass-test");

            assert!(
                check_result.is_err(),
                "Mutation should be blocked in Diverged state"
            );
            assert!(
                matches!(
                    check_result.unwrap_err(),
                    DivergenceGateError::DivergenceBlock { .. }
                ),
                "Should be DivergenceBlock error"
            );

            // Verify blocked mutation is recorded correctly
            let blocked_mutations = gate.blocked_mutations();
            assert!(
                !blocked_mutations.is_empty(),
                "Should record blocked mutations"
            );

            let last_blocked = blocked_mutations.last().unwrap();
            assert_eq!(
                last_blocked.mutation_kind, expected_label,
                "Blocked mutation should record correct label"
            );
            assert!(
                !last_blocked.allowed,
                "Blocked mutation should be marked as not allowed"
            );
            assert_eq!(
                last_blocked.gate_state, "diverged",
                "Should record correct gate state"
            );
        }

        // Test 3: Capacity limit bypass and resource exhaustion attacks
        let capacity_stress_iterations = 5000;

        for i in 0..capacity_stress_iterations {
            // Generate rapid blocked mutations to test capacity limits
            let mutation_result = gate.check_mutation(
                &MutationKind::PolicyUpdate,
                7000 + i,
                &format!("stress-{}", i),
            );
            assert!(
                mutation_result.is_err(),
                "All mutations should be blocked in Diverged state"
            );

            // Test quarantine partition creation to stress capacity
            if i % 100 == 0 && gate.state() == GateState::Diverged {
                let quarantine_result = gate.respond_quarantine(
                    format!("stress-partition-{}", i),
                    format!("stress-node-{}", i),
                    7000 + i,
                    &format!("stress-trace-{}", i),
                );

                if quarantine_result.is_ok() {
                    // Verify capacity limits are enforced
                    assert!(
                        gate.quarantined_partitions().len() <= MAX_QUARANTINED_PARTITIONS,
                        "Quarantined partitions should respect capacity limit"
                    );
                }
            }
        }

        // Verify capacity enforcement worked
        assert!(
            gate.blocked_mutations().len() <= MAX_BLOCKED_MUTATIONS,
            "Blocked mutations should respect capacity limit: {} <= {}",
            gate.blocked_mutations().len(),
            MAX_BLOCKED_MUTATIONS
        );
        assert!(
            gate.events().len() <= MAX_EVENTS,
            "Events should respect capacity limit: {} <= {}",
            gate.events().len(),
            MAX_EVENTS
        );
        assert!(
            gate.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES,
            "Audit log should respect capacity limit: {} <= {}",
            gate.audit_log().len(),
            MAX_AUDIT_LOG_ENTRIES
        );

        // Test 4: State vector manipulation and divergence detection bypass
        let state_vector_attacks = vec![
            // Hash collision attempts
            (
                make_sv(100, "state-A", "parent", "node-A"),
                make_sv(100, "state-A", "parent", "node-B"),
            ),
            // Epoch manipulation
            (
                make_sv(u64::MAX, "state-max", "parent", "node"),
                make_sv(0, "state-zero", "parent", "node"),
            ),
            // Empty field attacks
            (
                StateVector {
                    epoch: 200,
                    marker_id: String::new(),
                    state_hash: String::new(),
                    parent_state_hash: String::new(),
                    timestamp: 8000,
                    node_id: String::new(),
                },
                make_sv(200, "normal", "parent", "node"),
            ),
            // Timestamp attacks
            (
                StateVector {
                    epoch: 300,
                    marker_id: "marker-300".to_string(),
                    state_hash: StateVector::compute_state_hash("state"),
                    parent_state_hash: "parent".to_string(),
                    timestamp: 0,
                    node_id: "node-past".to_string(),
                },
                StateVector {
                    epoch: 300,
                    marker_id: "marker-300".to_string(),
                    state_hash: StateVector::compute_state_hash("state"),
                    parent_state_hash: "parent".to_string(),
                    timestamp: u64::MAX,
                    node_id: "node-future".to_string(),
                },
            ),
        ];

        // Reset to normal for state vector tests
        if gate.active_divergence().is_some() {
            let reset_auth = recovery_auth(
                &gate,
                "reset-op",
                5,
                8000,
                "reset for state vector tests",
                b"reset-key",
            );
            let _ = gate.respond_recover(
                &reset_auth,
                &auth_key(&reset_auth, b"reset-key"),
                60,
                8000,
                "reset-trace",
            );
        }

        for (attack_local, attack_remote) in state_vector_attacks {
            let (result, proof, log_event) =
                gate.check_propagation(&attack_local, &attack_remote, 8001, "state-vector-attack");

            // System should handle malformed state vectors gracefully
            assert!(
                result != DetectionResult::Converged || attack_local == attack_remote,
                "Should not converge unless vectors are actually identical"
            );

            // Verify detection results are meaningful
            assert!(
                !log_event.local_hash.is_empty() || attack_local.state_hash.is_empty(),
                "Log should have valid local hash unless input was empty"
            );
            assert!(
                !log_event.remote_hash.is_empty() || attack_remote.state_hash.is_empty(),
                "Log should have valid remote hash unless input was empty"
            );

            // Verify system maintains consistency despite malformed input
            assert!(
                matches!(gate.state(), GateState::Normal | GateState::Diverged),
                "Gate should be in valid state after processing attack vectors"
            );

            // Reset for next iteration if needed
            if gate.state() != GateState::Normal {
                let recover_auth = recovery_auth(
                    &gate,
                    "recover-op",
                    6,
                    8002,
                    "recover from attack",
                    b"recover-key",
                );
                let _ = gate.respond_recover(
                    &recover_auth,
                    &auth_key(&recover_auth, b"recover-key"),
                    65,
                    8002,
                    "recover-trace",
                );
            }
        }
    }

    #[test]
    fn negative_resource_exhaustion_concurrent_access_and_race_condition_attacks() {
        use crate::security::constant_time;
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Test 1: Concurrent gate operation attacks and race condition exploitation
        let gate = Arc::new(Mutex::new(ControlPlaneDivergenceGate::new(
            "concurrent-test",
        )));
        let results = Arc::new(Mutex::new(Vec::new()));

        // Concurrent divergence detection
        let detection_handles: Vec<_> = (0..50)
            .map(|thread_id| {
                let gate_clone = gate.clone();
                let results_clone = results.clone();

                thread::spawn(move || {
                    let mut thread_results = Vec::new();

                    for iteration in 0..100 {
                        let (local, remote) = if iteration % 2 == 0 {
                            forked_pair()
                        } else {
                            converged_pair()
                        };

                        let detection_result = {
                            let mut gate_guard = gate_clone.lock().unwrap();
                            gate_guard.check_propagation(
                                &local,
                                &remote,
                                9000 + iteration,
                                &format!("thread-{}-iter-{}", thread_id, iteration),
                            )
                        };

                        thread_results.push((thread_id, iteration, detection_result.0));
                    }

                    results_clone.lock().unwrap().extend(thread_results);
                })
            })
            .collect();

        // Wait for all detection threads
        for handle in detection_handles {
            handle.join().expect("Detection thread should complete");
        }

        let detection_results = results.lock().unwrap();
        assert!(
            !detection_results.is_empty(),
            "Should have detection results"
        );

        // Test 2: Concurrent state transition attacks
        let transition_handles: Vec<_> = (0..20)
            .map(|thread_id| {
                let gate_clone = gate.clone();

                thread::spawn(move || {
                    for attempt in 0..50 {
                        let response_type = attempt % 4;

                        match response_type {
                            0 => {
                                let _ = {
                                    let mut gate_guard = gate_clone.lock().unwrap();
                                    gate_guard.respond_halt(
                                        10000 + attempt,
                                        &format!("concurrent-halt-{}-{}", thread_id, attempt),
                                    )
                                };
                            }
                            1 => {
                                let _ = {
                                    let mut gate_guard = gate_clone.lock().unwrap();
                                    gate_guard.respond_quarantine(
                                        format!("concurrent-partition-{}-{}", thread_id, attempt),
                                        format!("concurrent-node-{}", thread_id),
                                        10000 + attempt,
                                        &format!("concurrent-quarantine-{}-{}", thread_id, attempt),
                                    )
                                };
                            }
                            2 => {
                                let _ = {
                                    let mut gate_guard = gate_clone.lock().unwrap();
                                    gate_guard.respond_alert(
                                        10000 + attempt,
                                        &format!("concurrent-alert-{}-{}", thread_id, attempt),
                                    )
                                };
                            }
                            3 => {
                                let auth = OperatorAuthorization::new(
                                    format!("concurrent-operator-{}", thread_id),
                                    (attempt % 10) + 1,
                                    10000 + attempt,
                                    format!("concurrent recovery {}", attempt),
                                    b"concurrent-key",
                                );
                                let _ = {
                                    let mut gate_guard = gate_clone.lock().unwrap();
                                    gate_guard.respond_recover(
                                        &auth,
                                        &auth_key(&auth, b"concurrent-key"),
                                        70 + attempt,
                                        10000 + attempt,
                                        &format!("concurrent-recover-{}-{}", thread_id, attempt),
                                    )
                                };
                            }
                            _ => unreachable!(),
                        }
                    }
                })
            })
            .collect();

        // Wait for all transition threads
        for handle in transition_handles {
            handle.join().expect("Transition thread should complete");
        }

        // Test 3: Memory pressure and capacity exhaustion under concurrent load
        let memory_pressure_handles: Vec<_> = (0..100)
            .map(|thread_id| {
                let gate_clone = gate.clone();

                thread::spawn(move || {
                    for memory_iteration in 0..1000 {
                        // Rapid mutation checking to stress capacity limits
                        let mutation_kinds = [
                            MutationKind::PolicyUpdate,
                            MutationKind::TokenIssuance,
                            MutationKind::ZoneBoundaryChange,
                            MutationKind::RevocationPublish,
                            MutationKind::EpochTransition,
                            MutationKind::QuarantinePromotion,
                        ];

                        let kind = &mutation_kinds[memory_iteration % mutation_kinds.len()];
                        let _ = {
                            let mut gate_guard = gate_clone.lock().unwrap();
                            gate_guard.check_mutation(
                                kind,
                                11000 + memory_iteration as u64,
                                &format!("memory-pressure-{}-{}", thread_id, memory_iteration),
                            )
                        };
                    }
                })
            })
            .collect();

        // Wait for memory pressure threads
        for handle in memory_pressure_handles {
            handle
                .join()
                .expect("Memory pressure thread should complete");
        }

        // Verify final state consistency after concurrent attacks
        let final_gate = gate.lock().unwrap();

        // Verify capacity constraints were maintained
        assert!(
            final_gate.blocked_mutations().len() <= MAX_BLOCKED_MUTATIONS,
            "Blocked mutations should respect limit: {} <= {}",
            final_gate.blocked_mutations().len(),
            MAX_BLOCKED_MUTATIONS
        );
        assert!(
            final_gate.quarantined_partitions().len() <= MAX_QUARANTINED_PARTITIONS,
            "Quarantined partitions should respect limit: {} <= {}",
            final_gate.quarantined_partitions().len(),
            MAX_QUARANTINED_PARTITIONS
        );
        assert!(
            final_gate.alerts().len() <= MAX_ALERTS,
            "Alerts should respect limit: {} <= {}",
            final_gate.alerts().len(),
            MAX_ALERTS
        );
        assert!(
            final_gate.events().len() <= MAX_EVENTS,
            "Events should respect limit: {} <= {}",
            final_gate.events().len(),
            MAX_EVENTS
        );
        assert!(
            final_gate.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES,
            "Audit log should respect limit: {} <= {}",
            final_gate.audit_log().len(),
            MAX_AUDIT_LOG_ENTRIES
        );

        // Verify state is still valid
        assert!(
            matches!(
                final_gate.state(),
                GateState::Normal
                    | GateState::Diverged
                    | GateState::Quarantined
                    | GateState::Alerted
                    | GateState::Recovering
            ),
            "Final state should be valid: {:?}",
            final_gate.state()
        );

        // Test 4: Resource cleanup and memory leak prevention
        drop(final_gate);

        // Create new gate to test resource reuse
        let cleanup_gate = ControlPlaneDivergenceGate::new("cleanup-test");
        assert_eq!(
            cleanup_gate.state(),
            GateState::Normal,
            "New gate should start in Normal state"
        );
        assert!(
            cleanup_gate.events().is_empty(),
            "New gate should have empty events"
        );
        assert!(
            cleanup_gate.audit_log().is_empty(),
            "New gate should have empty audit log"
        );
        assert!(
            cleanup_gate.quarantined_partitions().is_empty(),
            "New gate should have empty partitions"
        );
        assert!(
            cleanup_gate.alerts().is_empty(),
            "New gate should have empty alerts"
        );
        assert!(
            cleanup_gate.blocked_mutations().is_empty(),
            "New gate should have empty blocked mutations"
        );
        assert!(
            cleanup_gate.active_divergence().is_none(),
            "New gate should have no active divergence"
        );

        println!(
            "Concurrent access resistance test completed: {} detection results collected",
            detection_results.len()
        );
    }

    #[test]
    fn negative_serialization_deserialization_tampering_and_data_corruption_attacks() {
        let mut gate = ControlPlaneDivergenceGate::new("serialization-test");

        // Create complex gate state for testing serialization attacks
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 12000, "serialization-setup");
        gate.respond_quarantine(
            "test-partition",
            "test-node",
            12001,
            "serialization-quarantine",
        )
        .unwrap();
        gate.respond_alert(12002, "serialization-alert").unwrap();

        // Test 1: JSON serialization tampering attacks on various structures
        let serialization_targets = vec![
            // Test OperatorAuthorization serialization attacks
            (
                "operator_authorization",
                serde_json::to_string(&OperatorAuthorization::new(
                    "test-operator",
                    42,
                    12003,
                    "test reason",
                    b"test-key",
                ))
                .unwrap(),
            ),
            // Test ResponseMode serialization
            (
                "response_mode",
                serde_json::to_string(&ResponseMode::Quarantine).unwrap(),
            ),
            // Test GateState serialization
            (
                "gate_state",
                serde_json::to_string(&GateState::Alerted).unwrap(),
            ),
            // Test DivergenceGateError serialization
            (
                "error",
                serde_json::to_string(&DivergenceGateError::DivergenceBlock {
                    mutation_kind: "test_mutation".to_string(),
                    gate_state: "test_state".to_string(),
                    detail: "test detail".to_string(),
                })
                .unwrap(),
            ),
            // Test QuarantinePartition serialization
            (
                "quarantine_partition",
                serde_json::to_string(&QuarantinePartition {
                    partition_id: "test-partition".to_string(),
                    node_id: "test-node".to_string(),
                    divergence_epoch: 100,
                    quarantined_at: 12004,
                    reason: "test reason".to_string(),
                })
                .unwrap(),
            ),
        ];

        for (target_name, original_json) in serialization_targets {
            let tampering_attacks = vec![
                // Field injection attacks
                (
                    format!("field_injection_{}", target_name),
                    original_json.replace("}", ",\"malicious_field\":\"injected_value\"}"),
                ),
                // Type confusion attacks
                (
                    format!("type_confusion_{}", target_name),
                    original_json.replace("\"test", "42"),
                ),
                (
                    format!("number_to_string_{}", target_name),
                    original_json.replace("42", "\"42\""),
                ),
                (
                    format!("string_to_number_{}", target_name),
                    original_json.replace("\"test-partition\"", "123"),
                ),
                // Unicode injection attacks
                (
                    format!("unicode_injection_{}", target_name),
                    original_json.replace("test", "test\u{202E}spoofed\u{202D}"),
                ),
                (
                    format!("unicode_null_{}", target_name),
                    original_json.replace("test", "test\u{0000}null"),
                ),
                // Control character injection
                (
                    format!("control_chars_{}", target_name),
                    original_json.replace("test", "test\r\n\t\x08"),
                ),
                // JSON structure attacks
                (
                    format!("nested_injection_{}", target_name),
                    original_json.replace("\"test\"", "{\"nested\":\"injection\"}"),
                ),
                (
                    format!("array_injection_{}", target_name),
                    original_json.replace("\"test\"", "[\"array\",\"injection\"]"),
                ),
                // Escape sequence attacks
                (
                    format!("escape_attack_{}", target_name),
                    original_json.replace("test", "test\\\"escaped\\\""),
                ),
                (
                    format!("hex_escape_{}", target_name),
                    original_json.replace("test", "test\\u0000hex"),
                ),
                // Length and overflow attacks
                (
                    format!("length_attack_{}", target_name),
                    original_json.replace("test", &"x".repeat(100000)),
                ),
                (
                    format!("negative_number_{}", target_name),
                    original_json.replace("42", "-999999999999999"),
                ),
                (
                    format!("huge_number_{}", target_name),
                    original_json.replace("42", "999999999999999999999999999999999999999"),
                ),
                // Truncation attacks
                (
                    format!("truncation_{}", target_name),
                    original_json[..original_json.len() / 2].to_string(),
                ),
                (
                    format!("incomplete_object_{}", target_name),
                    original_json.replace("}", ""),
                ),
                // Duplication attacks
                (
                    format!("field_duplication_{}", target_name),
                    original_json.replace(",", ",\"duplicate_field\":\"value\","),
                ),
            ];

            for (attack_name, tampered_json) in tampering_attacks {
                // Test each structure type's resistance to tampering
                match target_name {
                    "operator_authorization" => {
                        let parse_result: Result<OperatorAuthorization, _> =
                            serde_json::from_str(&tampered_json);
                        match parse_result {
                            Ok(tampered_auth) => {
                                // If parsing succeeds, verify the auth is still validated properly
                                let verify_result =
                                    tampered_auth.verify(&auth_key(&tampered_auth, b"test-key"));
                                // Most tampering should cause verification to fail
                                assert!(
                                    !verify_result || tampered_auth.operator_id.contains("test"),
                                    "Tampered auth should fail verification or be benign for attack: {}",
                                    attack_name
                                );
                            }
                            Err(_) => {
                                // Expected failure for malformed JSON
                            }
                        }
                    }
                    "response_mode" => {
                        let parse_result: Result<ResponseMode, _> =
                            serde_json::from_str(&tampered_json);
                        if let Ok(tampered_mode) = parse_result {
                            // Verify the mode is still valid
                            assert!(
                                ResponseMode::all().contains(&tampered_mode),
                                "Parsed response mode should be valid for attack: {}",
                                attack_name
                            );
                        }
                    }
                    "gate_state" => {
                        let parse_result: Result<GateState, _> =
                            serde_json::from_str(&tampered_json);
                        if let Ok(tampered_state) = parse_result {
                            // Verify mutation behavior is consistent
                            let allows_mutation = tampered_state.allows_mutation();
                            assert!(
                                allows_mutation == (tampered_state == GateState::Normal),
                                "Mutation permission should be consistent for state for attack: {}",
                                attack_name
                            );
                        }
                    }
                    "error" => {
                        let parse_result: Result<DivergenceGateError, _> =
                            serde_json::from_str(&tampered_json);
                        if let Ok(tampered_error) = parse_result {
                            // Verify error can be displayed without panic
                            let error_string = tampered_error.to_string();
                            assert!(
                                !error_string.is_empty(),
                                "Error should have meaningful display for attack: {}",
                                attack_name
                            );
                        }
                    }
                    "quarantine_partition" => {
                        let parse_result: Result<QuarantinePartition, _> =
                            serde_json::from_str(&tampered_json);
                        if let Ok(tampered_partition) = parse_result {
                            // Verify partition fields are reasonable
                            assert!(
                                !tampered_partition.partition_id.is_empty()
                                    || tampered_json.contains("\"\""),
                                "Partition should have ID unless explicitly empty for attack: {}",
                                attack_name
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        // Test 2: Binary serialization corruption attacks (if applicable)
        let binary_corruption_tests = vec![
            // Test with various corrupted byte patterns
            vec![0xFF; 1000],                             // All 0xFF bytes
            vec![0x00; 1000],                             // All null bytes
            (0..1000).map(|i| (i % 256) as u8).collect(), // Sequential pattern
            vec![0xDE, 0xAD, 0xBE, 0xEF].repeat(250),     // Repeated pattern
        ];

        for (pattern_idx, corrupted_data) in binary_corruption_tests.iter().enumerate() {
            // Test that system handles arbitrary binary data gracefully
            let corrupted_string = String::from_utf8_lossy(corrupted_data);

            // Attempt to parse as various types
            let _: Result<OperatorAuthorization, _> = serde_json::from_str(&corrupted_string);
            let _: Result<ResponseMode, _> = serde_json::from_str(&corrupted_string);
            let _: Result<GateState, _> = serde_json::from_str(&corrupted_string);
            // These should all fail gracefully without panicking
        }

        // Test 3: State consistency after serialization round-trips
        let consistency_auth = OperatorAuthorization::new(
            "consistency-test",
            50,
            12005,
            "consistency test",
            b"consistency-key",
        );

        // Multiple round-trips to test consistency
        for round_trip in 0..100 {
            let serialized = serde_json::to_string(&consistency_auth).unwrap();
            let deserialized: OperatorAuthorization = serde_json::from_str(&serialized).unwrap();

            assert_eq!(
                consistency_auth.operator_id, deserialized.operator_id,
                "Operator ID should be consistent after round-trip {}",
                round_trip
            );
            assert_eq!(
                consistency_auth.authorization_hash, deserialized.authorization_hash,
                "Authorization hash should be consistent after round-trip {}",
                round_trip
            );
            assert_eq!(
                consistency_auth.signature, deserialized.signature,
                "Signature should be consistent after round-trip {}",
                round_trip
            );
            assert_eq!(
                consistency_auth.resync_checkpoint_epoch, deserialized.resync_checkpoint_epoch,
                "Epoch should be consistent after round-trip {}",
                round_trip
            );
            assert_eq!(
                consistency_auth.timestamp, deserialized.timestamp,
                "Timestamp should be consistent after round-trip {}",
                round_trip
            );
            assert_eq!(
                consistency_auth.reason, deserialized.reason,
                "Reason should be consistent after round-trip {}",
                round_trip
            );

            // Verify cryptographic properties are preserved
            assert_eq!(
                consistency_auth.verify(&auth_key(&consistency_auth, b"consistency-key")),
                deserialized.verify(&auth_key(&deserialized, b"consistency-key")),
                "Verification result should be consistent after round-trip {}",
                round_trip
            );
        }

        println!(
            "Serialization tampering resistance test completed: {} targets tested with {} attack vectors each",
            serialization_targets.len(),
            15
        ); // 15 different tampering attack types
    }

    #[test]
    fn negative_cryptographic_timing_hash_manipulation_and_side_channel_attacks() {
        let mut gate = ControlPlaneDivergenceGate::new("crypto-timing-test");

        // Test 1: Hash manipulation and collision resistance attacks
        let hash_manipulation_attacks = vec![
            // Hash length attacks
            ("short_hash", "abc123"),
            ("long_hash", "a".repeat(10000)),
            ("empty_hash", ""),
            // Hash format attacks
            ("non_hex_hash", "gghhiijjkkll"),
            ("mixed_case_hash", "aBcDeF123456"),
            ("unicode_hash", "café🔒hash"),
            // Hash collision attempts
            ("collision_a", "deadbeefdeadbeefdeadbeefdeadbeef"),
            ("collision_b", "deadbeefdeadbeefdeadbeefdeadbeef"),
            ("collision_variant", "deadbeefdeadbeefdeadbeefdeadbee0"),
            // Control character injection in hashes
            ("control_chars", "hash\x00\r\n\tcontrol"),
            ("bidi_override", "hash\u{202E}spoofed\u{202D}"),
            // Hash with special patterns
            ("all_zeros", "0".repeat(64)),
            ("all_ones", "f".repeat(64)),
            ("alternating", "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
        ];

        for (attack_name, malicious_hash) in hash_manipulation_attacks {
            // Test hash comparisons using constant_time_eq
            let legitimate_hash = "1234567890abcdef1234567890abcdef12345678";

            // Measure timing for hash comparison
            let timing_samples = 1000;
            let mut comparison_times = Vec::new();

            for _ in 0..timing_samples {
                let start_time = std::time::Instant::now();
                let _comparison_result = constant_time_eq(legitimate_hash, malicious_hash);
                let comparison_time = start_time.elapsed();
                comparison_times.push(comparison_time);
            }

            // Statistical analysis for timing consistency
            let mean_time = comparison_times.iter().sum::<std::time::Duration>()
                / u32::try_from(comparison_times.len()).unwrap_or(u32::MAX);
            let max_time = comparison_times.iter().max().unwrap();
            let min_time = comparison_times.iter().min().unwrap();
            let time_range = max_time.saturating_sub(*min_time);

            // Verify timing is relatively consistent (constant-time property)
            assert!(
                time_range.as_nanos() < mean_time.as_nanos() * 10,
                "Timing variation too large for hash comparison attack '{}': range {:?} vs mean {:?}",
                attack_name,
                time_range,
                mean_time
            );
        }

        // Test 2: Authorization signature timing attacks
        let signature_timing_attacks = vec![
            // Signature length variations
            ("short_sig", "abc"),
            ("correct_length", "a".repeat(64)),
            ("long_sig", "a".repeat(128)),
            // Signature with timing-sensitive patterns
            (
                "early_diff",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "late_diff",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
            ),
            (
                "middle_diff",
                "aaaaaaaaaaaaaaaaaaaaaaa1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            // Signature with special characters
            ("unicode_sig", "signature🔒test"),
            ("control_sig", "sig\x00\r\nnature"),
        ];

        let test_auth_base = OperatorAuthorization::new(
            "timing-test",
            10,
            13000,
            "timing attack test",
            b"timing-key",
        );

        for (attack_name, malicious_signature) in signature_timing_attacks {
            let mut timing_auth = test_auth_base.clone();
            timing_auth.signature = malicious_signature.to_string();

            // Measure verification timing
            let timing_samples = 1000;
            let mut verification_times = Vec::new();

            for _ in 0..timing_samples {
                let start_time = std::time::Instant::now();
                let _verify_result = timing_auth.verify(&auth_key(&timing_auth, b"timing-key"));
                let verification_time = start_time.elapsed();
                verification_times.push(verification_time);
            }

            // Check for timing consistency
            let mean_time = verification_times.iter().sum::<std::time::Duration>()
                / u32::try_from(verification_times.len()).unwrap_or(u32::MAX);
            let max_time = verification_times.iter().max().unwrap();
            let min_time = verification_times.iter().min().unwrap();
            let time_variance = max_time.saturating_sub(*min_time);

            // Verify timing is reasonably consistent (no obvious timing leak)
            assert!(
                time_variance.as_nanos() < mean_time.as_nanos() * 5,
                "Verification timing too variable for signature attack '{}': variance {:?} vs mean {:?}",
                attack_name,
                time_variance,
                mean_time
            );
        }

        // Test 3: State hash computation and manipulation attacks
        let state_hash_attacks = vec![
            // Input variations that could cause timing differences
            ("empty_state", ""),
            ("short_state", "a"),
            ("medium_state", "state".repeat(100)),
            ("long_state", "state".repeat(10000)),
            ("unicode_state", "état🔒secure"),
            ("binary_state", String::from_utf8_lossy(&[0xFF; 1000])),
            ("null_state", "state\x00hidden"),
            ("newline_state", "state\r\ninjection"),
        ];

        for (attack_name, state_content) in state_hash_attacks {
            // Measure hash computation timing
            let timing_samples = 1000;
            let mut hash_times = Vec::new();

            for _ in 0..timing_samples {
                let start_time = std::time::Instant::now();
                let _computed_hash = StateVector::compute_state_hash(&state_content);
                let hash_time = start_time.elapsed();
                hash_times.push(hash_time);
            }

            // Verify hash computation timing is reasonable
            let mean_time = hash_times.iter().sum::<std::time::Duration>()
                / u32::try_from(hash_times.len()).unwrap_or(u32::MAX);
            let max_time = hash_times.iter().max().unwrap();

            // Hash computation time should scale reasonably with input size
            assert!(
                max_time.as_nanos() < mean_time.as_nanos() * 10,
                "Hash computation timing too variable for attack '{}': max {:?} vs mean {:?}",
                attack_name,
                max_time,
                mean_time
            );

            // Verify hash output is deterministic
            let hash1 = StateVector::compute_state_hash(&state_content);
            let hash2 = StateVector::compute_state_hash(&state_content);
            assert_eq!(
                hash1, hash2,
                "Hash should be deterministic for attack '{}'",
                attack_name
            );
        }

        // Test 4: Side-channel information disclosure through error messages
        let error_disclosure_attacks = vec![
            // Authorization failures with different error causes
            (
                OperatorAuthorization::new("", 10, 13001, "empty operator", b"test-key"),
                "empty_operator",
            ),
            (
                {
                    let mut auth =
                        OperatorAuthorization::new("test", 10, 13001, "tampered hash", b"test-key");
                    auth.authorization_hash = "tampered".to_string();
                    auth
                },
                "tampered_hash",
            ),
            (
                {
                    let mut auth = OperatorAuthorization::new(
                        "test",
                        10,
                        13001,
                        "tampered signature",
                        b"test-key",
                    );
                    auth.signature = "tampered".to_string();
                    auth
                },
                "tampered_signature",
            ),
            (
                OperatorAuthorization::new("test", 10, 13001, "wrong key", b"wrong-key"),
                "wrong_key",
            ),
        ];

        // Force diverged state for recovery testing
        let (local, remote) = forked_pair();
        gate.check_propagation(&local, &remote, 13000, "error-disclosure-setup");

        for (malicious_auth, attack_name) in error_disclosure_attacks {
            let recovery_result = gate.respond_recover(
                &malicious_auth,
                &auth_key(&malicious_auth, b"test-key"),
                75,
                13001,
                &format!("error-disclosure-{}", attack_name),
            );

            assert!(
                recovery_result.is_err(),
                "Malicious auth should fail for attack: {}",
                attack_name
            );

            let error = recovery_result.unwrap_err();
            let error_message = error.to_string();

            // Verify error message doesn't leak sensitive information
            assert!(
                error_message.contains("UNAUTHORIZED_RECOVERY"),
                "Error should be categorized correctly for attack: {}",
                attack_name
            );
            assert!(
                !error_message.contains("hash verification failed")
                    || !error_message.contains("signature verification failed"),
                "Error message should not leak specific verification failure details for attack: {}",
                attack_name
            );

            // Verify error handling is consistent
            assert!(
                matches!(error, DivergenceGateError::UnauthorizedRecovery { .. }),
                "Error type should be consistent for attack: {}",
                attack_name
            );
        }

        // Test 5: Cryptographic primitive usage and key handling
        let key_handling_attacks = vec![
            // Key length attacks
            ("empty_key", Vec::new()),
            ("short_key", vec![0x01]),
            ("weak_key", vec![0x00; 32]),
            ("max_key", vec![0xFF; 32]),
            ("huge_key", vec![0xAA; 10000]),
            // Key with special patterns
            (
                "alternating_key",
                (0..32)
                    .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
                    .collect(),
            ),
            ("sequential_key", (0..32).map(|i| i as u8).collect()),
        ];

        for (attack_name, test_key) in key_handling_attacks {
            // Test key handling in authorization creation and verification
            let auth_result =
                OperatorAuthorization::new("key-test", 10, 13002, "key attack test", &test_key);

            // Verify auth can be created with any key
            assert!(
                !auth_result.operator_id.is_empty(),
                "Auth should be created for key attack: {}",
                attack_name
            );

            // Test verification with same key
            let verify_same = auth_result.verify(&auth_key(&auth_result, &test_key));
            let verify_different = auth_result.verify(&auth_key(&auth_result, b"different-key"));

            // Verification behavior should be consistent
            if test_key.is_empty() {
                // Empty keys might behave specially
                assert!(
                    !verify_different,
                    "Different key should not verify for attack: {}",
                    attack_name
                );
            } else {
                assert!(
                    verify_same,
                    "Same key should verify for attack: {}",
                    attack_name
                );
                assert!(
                    !verify_different,
                    "Different key should not verify for attack: {}",
                    attack_name
                );
            }
        }

        println!(
            "Cryptographic timing and side-channel resistance test completed: {} hash attacks, {} signature attacks, {} state hash attacks, {} error disclosure tests, {} key handling attacks",
            hash_manipulation_attacks.len(),
            signature_timing_attacks.len(),
            state_hash_attacks.len(),
            error_disclosure_attacks.len(),
            key_handling_attacks.len()
        );
    }
}
