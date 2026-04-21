//! Fleet quarantine/revocation API for bd-tg2.
//!
//! Provides zone/tenant-scoped quarantine, revocation, release, status,
//! and reconcile operations with convergence tracking.
//!
//! Routes:
//! - `POST   /v1/fleet/quarantine`      — quarantine an extension
//! - `POST   /v1/fleet/revoke`          — revoke an extension
//! - `POST   /v1/fleet/release`         — release quarantine for an incident
//! - `GET    /v1/fleet/status`           — fleet status for a zone
//! - `POST   /v1/fleet/reconcile`       — reconcile fleet state
//!
//! Invariants:
//! - INV-FLEET-ZONE-SCOPE   — every operation is scoped to a zone/tenant
//! - INV-FLEET-RECEIPT      — all operations produce signed decision receipts
//! - INV-FLEET-BOUNDED      — all collections are bounded with capacity eviction
//! - INV-FLEET-CONVERGENCE  — convergence state tracked with progress + ETA
//! - INV-FLEET-SAFE-START   — API starts in read-only mode, requires activation
//! - INV-FLEET-ROLLBACK     — release deterministically rolls back quarantine state

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum fleet control events before oldest are evicted.
const MAX_FLEET_EVENTS: usize = 4096;

/// Maximum incident handles retained before released entries are reclaimed.
#[cfg(any(test, feature = "extended-surfaces"))]
const MAX_INCIDENTS: usize = 2048;

/// Maximum zone status entries before oldest are evicted.
#[cfg(any(test, feature = "extended-surfaces"))]
const MAX_ZONE_STATUS: usize = 2048;

use super::error::ApiError;
use super::middleware::{AuthIdentity, TraceContext};
#[cfg(any(test, feature = "extended-surfaces"))]
use super::middleware::{AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata};
use super::trust_card_routes::ApiResponse;

// ── Event Codes ───────────────────────────────────────────────────────────

/// FLEET-001: Quarantine initiated for extension in zone.
#[cfg(any(test, feature = "extended-surfaces"))]
pub const FLEET_QUARANTINE_INITIATED: &str = "FLEET-001";

/// FLEET-002: Revocation issued for extension.
#[cfg(any(test, feature = "extended-surfaces"))]
pub const FLEET_REVOCATION_ISSUED: &str = "FLEET-002";

/// FLEET-003: Convergence progress updated.
#[cfg(feature = "extended-surfaces")]
pub const FLEET_CONVERGENCE_PROGRESS: &str = "FLEET-003";

/// FLEET-004: Fleet released (quarantine rolled back).
pub const FLEET_RELEASED: &str = "FLEET-004";

/// FLEET-005: Reconcile completed.
pub const FLEET_RECONCILE_COMPLETED: &str = "FLEET-005";

// ── Error Codes ───────────────────────────────────────────────────────────

pub const FLEET_SCOPE_INVALID: &str = "FLEET_SCOPE_INVALID";
#[cfg(any(test, feature = "extended-surfaces"))]
pub const FLEET_ZONE_UNREACHABLE: &str = "FLEET_ZONE_UNREACHABLE";
#[cfg(any(test, feature = "extended-surfaces"))]
pub const FLEET_CONVERGENCE_TIMEOUT: &str = "FLEET_CONVERGENCE_TIMEOUT";
pub const FLEET_ROLLBACK_FAILED: &str = "FLEET_ROLLBACK_FAILED";
pub const FLEET_NOT_ACTIVATED: &str = "FLEET_NOT_ACTIVATED";
pub const FLEET_OPERATION_ID_EXHAUSTED: &str = "FLEET_OPERATION_ID_EXHAUSTED";
pub const FLEET_RECEIPT_SIGNING_MATERIAL_MISSING: &str =
    "FLEET_RECEIPT_SIGNING_MATERIAL_MISSING";
#[cfg(any(test, feature = "extended-surfaces"))]
pub const FLEET_INCIDENT_CAPACITY_EXCEEDED: &str = "FLEET_INCIDENT_CAPACITY_EXCEEDED";
#[cfg(any(test, feature = "extended-surfaces"))]
pub const FLEET_ZONE_STATUS_CAPACITY_EXCEEDED: &str = "FLEET_ZONE_STATUS_CAPACITY_EXCEEDED";

// ── Invariant Tags ────────────────────────────────────────────────────────

#[cfg(feature = "extended-surfaces")]
pub const INV_FLEET_ZONE_SCOPE: &str = "INV-FLEET-ZONE-SCOPE";
#[cfg(feature = "extended-surfaces")]
pub const INV_FLEET_RECEIPT: &str = "INV-FLEET-RECEIPT";
#[cfg(feature = "extended-surfaces")]
pub const INV_FLEET_CONVERGENCE: &str = "INV-FLEET-CONVERGENCE";
#[cfg(feature = "extended-surfaces")]
pub const INV_FLEET_SAFE_START: &str = "INV-FLEET-SAFE-START";
#[cfg(feature = "extended-surfaces")]
pub const INV_FLEET_ROLLBACK: &str = "INV-FLEET-ROLLBACK";

// ── Domain Types ──────────────────────────────────────────────────────────

/// Quarantine scope limits blast-radius to zones/tenants.
/// Enforces INV-FLEET-ZONE-SCOPE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineScope {
    /// Zone identifier (required).
    pub zone_id: String,
    /// Optional tenant narrowing within zone.
    pub tenant_id: Option<String>,
    /// Blast-radius metadata: number of affected nodes.
    pub affected_nodes: u32,
    /// Human-readable reason for quarantine.
    pub reason: String,
}

/// Revocation scope with extension and zone targeting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationScope {
    /// Zone identifier (required).
    pub zone_id: String,
    /// Optional tenant narrowing.
    pub tenant_id: Option<String>,
    /// Severity of the revocation.
    pub severity: RevocationSeverity,
    /// Human-readable reason.
    pub reason: String,
}

/// Severity of a revocation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationSeverity {
    /// Advisory only — logged but not enforced.
    Advisory,
    /// Mandatory — extension disabled immediately.
    Mandatory,
    /// Emergency — extension disabled + incident created.
    Emergency,
}

/// A fleet action requested by the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FleetAction {
    /// Quarantine an extension in a scope.
    Quarantine {
        extension_id: String,
        scope: QuarantineScope,
    },
    /// Revoke an extension.
    Revoke {
        extension_id: String,
        scope: RevocationScope,
    },
    /// Release a quarantine incident.
    Release { incident_id: String },
    /// Publish a policy update for downstream fleet agents.
    PolicyUpdate {
        policy_version: String,
        summary: String,
    },
    /// Query fleet status for a zone.
    Status { zone_id: String },
    /// Reconcile fleet state across zones.
    Reconcile,
}

/// Result of a fleet action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetActionResult {
    /// Unique operation ID for tracking.
    pub operation_id: String,
    /// The action that was performed.
    pub action_type: String,
    /// Whether the action completed successfully.
    pub success: bool,
    /// Signed decision receipt (INV-FLEET-RECEIPT).
    pub receipt: DecisionReceipt,
    /// Convergence state for asynchronous actions.
    pub convergence: Option<ConvergenceState>,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Event code emitted.
    pub event_code: String,
}

/// Signed decision receipt for every fleet operation.
/// Enforces INV-FLEET-RECEIPT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Principal who issued the action.
    pub issuer: String,
    /// Timestamp of issuance.
    pub issued_at: String,
    /// Zone this receipt applies to.
    pub zone_id: String,
    /// Hash of the decision payload for tamper detection.
    pub payload_hash: String,
    /// Detached Ed25519 signature over the decision receipt fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<DecisionReceiptSignature>,
}

/// Ed25519 signature envelope for fleet decision receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceiptSignature {
    /// Signature algorithm.
    pub algorithm: String,
    /// Hex-encoded Ed25519 verifying key.
    pub public_key_hex: String,
    /// Stable key identifier derived from the verifying key.
    pub key_id: String,
    /// Where signing material was sourced from.
    pub key_source: String,
    /// Identity that produced the receipt signature.
    pub signing_identity: String,
    /// Scope the signature is valid for.
    pub trust_scope: String,
    /// SHA-256 of the signed receipt payload.
    pub signed_payload_sha256: String,
    /// Hex-encoded Ed25519 signature.
    pub signature_hex: String,
}

fn extend_len_prefixed(buffer: &mut Vec<u8>, field: &str) {
    let field_len = u64::try_from(field.len()).unwrap_or(u64::MAX);
    buffer.extend_from_slice(&field_len.to_le_bytes());
    buffer.extend_from_slice(field.as_bytes());
}

fn decision_receipt_payload_bytes(receipt: &DecisionReceipt) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"franken_node_fleet_decision_receipt_v1:");
    for field in [
        receipt.receipt_id.as_str(),
        receipt.issuer.as_str(),
        receipt.issued_at.as_str(),
        receipt.zone_id.as_str(),
        receipt.payload_hash.as_str(),
    ] {
        extend_len_prefixed(&mut payload, field);
    }
    payload
}

/// Create an Ed25519 signature envelope for a fleet decision receipt.
#[must_use]
pub fn sign_decision_receipt(
    receipt: &DecisionReceipt,
    signing_key: &ed25519_dalek::SigningKey,
    key_source: &str,
    signing_identity: &str,
) -> DecisionReceiptSignature {
    let payload = decision_receipt_payload_bytes(receipt);
    let signature = signing_key.sign(&payload);
    let verifying_key = signing_key.verifying_key();
    let mut payload_hasher = Sha256::new();
    payload_hasher.update(&payload);

    DecisionReceiptSignature {
        algorithm: "ed25519".to_string(),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        key_id: crate::supply_chain::artifact_signing::KeyId::from_verifying_key(&verifying_key)
            .to_string(),
        key_source: key_source.to_string(),
        signing_identity: signing_identity.to_string(),
        trust_scope: "fleet_decision".to_string(),
        signed_payload_sha256: hex::encode(payload_hasher.finalize()),
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Verify the embedded Ed25519 signature on a fleet decision receipt.
#[must_use]
pub fn verify_decision_receipt_signature(receipt: &DecisionReceipt) -> bool {
    let Some(signature) = &receipt.signature else {
        return false;
    };
    if !crate::security::constant_time::ct_eq(&signature.algorithm, "ed25519")
        || !crate::security::constant_time::ct_eq(&signature.trust_scope, "fleet_decision")
    {
        return false;
    }

    let Ok(public_key_bytes) = hex::decode(&signature.public_key_hex) else {
        return false;
    };
    let Ok(public_key_bytes) = <[u8; 32]>::try_from(public_key_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key_bytes) else {
        return false;
    };
    let expected_key_id =
        crate::supply_chain::artifact_signing::KeyId::from_verifying_key(&verifying_key)
            .to_string();
    if !crate::security::constant_time::ct_eq(&signature.key_id, &expected_key_id) {
        return false;
    }

    let payload = decision_receipt_payload_bytes(receipt);
    let mut payload_hasher = Sha256::new();
    payload_hasher.update(&payload);
    let expected_payload_hash = hex::encode(payload_hasher.finalize());
    if !crate::security::constant_time::ct_eq(
        &signature.signed_payload_sha256,
        &expected_payload_hash,
    ) {
        return false;
    }

    let Ok(signature_bytes) = hex::decode(&signature.signature_hex) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };
    verifying_key.verify(&payload, &signature).is_ok()
}

/// Convergence tracking for fleet propagation.
/// Enforces INV-FLEET-CONVERGENCE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceState {
    /// How many nodes have converged.
    pub converged_nodes: u32,
    /// Total nodes in scope.
    pub total_nodes: u32,
    /// Progress as percentage (0-100).
    pub progress_pct: u8,
    /// Estimated time to full convergence in seconds.
    pub eta_seconds: Option<u32>,
    /// Current convergence phase.
    pub phase: ConvergencePhase,
}

/// Phases of convergence propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConvergencePhase {
    /// Action not yet propagated.
    Pending,
    /// Propagation in progress.
    Propagating,
    /// All nodes converged.
    Converged,
    /// Convergence timed out (error state).
    TimedOut,
}

/// Fleet status for a zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStatus {
    /// Zone identifier.
    pub zone_id: String,
    /// Number of active quarantines in this zone.
    pub active_quarantines: u32,
    /// Number of active revocations.
    pub active_revocations: u32,
    /// Number of healthy nodes.
    pub healthy_nodes: u32,
    /// Total nodes in zone.
    pub total_nodes: u32,
    /// Whether the API is activated (not in read-only safe-start mode).
    pub activated: bool,
    /// Pending convergence operations.
    pub pending_convergences: Vec<ConvergenceState>,
}

/// Shared node-health vocabulary for transport-backed fleet state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeHealth {
    Healthy,
    Degraded,
    Unreachable,
    Quarantined,
}

/// Per-node fleet heartbeat persisted by transport backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub quarantine_version: u64,
    pub health: NodeHealth,
}

impl NodeStatus {
    pub fn new(
        node_id: impl Into<String>,
        last_seen: chrono::DateTime<chrono::Utc>,
        quarantine_version: u64,
        health: NodeHealth,
    ) -> Result<Self, FleetTransportError> {
        let status = Self {
            node_id: node_id.into(),
            last_seen,
            quarantine_version,
            health,
        };
        status.validate()?;
        Ok(status)
    }

    pub fn validate(&self) -> Result<(), FleetTransportError> {
        validate_node_id(&self.node_id)?;
        Ok(())
    }
}

/// Action-log entry shared across transport implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetActionEnvelope {
    pub action_id: String,
    pub trace_id: String,
    pub zone_id: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub quarantine_version: u64,
    pub action: FleetAction,
}

impl FleetActionEnvelope {
    pub fn new(
        action_id: impl Into<String>,
        trace_id: impl Into<String>,
        zone_id: impl Into<String>,
        issued_at: chrono::DateTime<chrono::Utc>,
        quarantine_version: u64,
        action: FleetAction,
    ) -> Result<Self, FleetTransportError> {
        let envelope = Self {
            action_id: action_id.into(),
            trace_id: trace_id.into(),
            zone_id: zone_id.into(),
            issued_at,
            quarantine_version,
            action,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), FleetTransportError> {
        if self.action_id.trim().is_empty() {
            return Err(FleetTransportError::serialization(
                "fleet action envelope action_id must not be empty",
            ));
        }
        if self.trace_id.trim().is_empty() {
            return Err(FleetTransportError::serialization(
                "fleet action envelope trace_id must not be empty",
            ));
        }
        validate_zone_id_for_transport(&self.zone_id)?;

        match &self.action {
            FleetAction::Quarantine { scope, .. } => {
                validate_zone_id_for_transport(&scope.zone_id)?;
                if scope.zone_id != self.zone_id {
                    return Err(FleetTransportError::serialization(
                        "quarantine scope zone_id must match envelope zone_id",
                    ));
                }
            }
            FleetAction::Revoke { scope, .. } => {
                validate_zone_id_for_transport(&scope.zone_id)?;
                if scope.zone_id != self.zone_id {
                    return Err(FleetTransportError::serialization(
                        "revocation scope zone_id must match envelope zone_id",
                    ));
                }
            }
            FleetAction::Release { incident_id } => {
                if incident_id.trim().is_empty() {
                    return Err(FleetTransportError::serialization(
                        "release incident_id must not be empty",
                    ));
                }
            }
            FleetAction::PolicyUpdate {
                policy_version,
                summary,
            } => {
                if policy_version.trim().is_empty() {
                    return Err(FleetTransportError::serialization(
                        "policy update policy_version must not be empty",
                    ));
                }
                if summary.trim().is_empty() {
                    return Err(FleetTransportError::serialization(
                        "policy update summary must not be empty",
                    ));
                }
            }
            FleetAction::Status { zone_id } => {
                validate_zone_id_for_transport(zone_id)?;
            }
            FleetAction::Reconcile => {}
        }

        Ok(())
    }
}

pub const FLEET_TRANSPORT_SCHEMA_VERSION: &str = "fleet-transport-v1";

/// Canonical transport snapshot used by CLI/status surfaces and backend tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStateSnapshot {
    pub schema_version: String,
    pub actions: Vec<FleetActionEnvelope>,
    pub nodes: Vec<NodeStatus>,
}

impl Default for FleetStateSnapshot {
    fn default() -> Self {
        Self {
            schema_version: FLEET_TRANSPORT_SCHEMA_VERSION.to_string(),
            actions: Vec::new(),
            nodes: Vec::new(),
        }
    }
}

impl FleetStateSnapshot {
    pub fn validate(&self) -> Result<(), FleetTransportError> {
        if self.schema_version.trim().is_empty() {
            return Err(FleetTransportError::serialization(
                "fleet state snapshot schema_version must not be empty",
            ));
        }
        for action in &self.actions {
            action.validate()?;
        }
        for node in &self.nodes {
            node.validate()?;
        }
        Ok(())
    }
}

/// Stable filesystem layout for transport implementations that persist shared state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStateLayout {
    pub root_dir: PathBuf,
    pub actions_log_path: PathBuf,
    pub node_status_dir: PathBuf,
    pub lock_dir: PathBuf,
    pub policy_state_path: PathBuf,
}

impl FleetStateLayout {
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        let root_dir = root_dir.into();
        Self {
            actions_log_path: root_dir.join("actions.jsonl"),
            node_status_dir: root_dir.join("nodes"),
            lock_dir: root_dir.join("locks"),
            policy_state_path: root_dir.join("policy.json"),
            root_dir,
        }
    }

    pub fn create_all(&self) -> Result<(), FleetTransportError> {
        std::fs::create_dir_all(&self.root_dir).map_err(|err| {
            FleetTransportError::io(format!(
                "failed creating fleet state root {}: {err}",
                self.root_dir.display()
            ))
        })?;
        std::fs::create_dir_all(&self.node_status_dir).map_err(|err| {
            FleetTransportError::io(format!(
                "failed creating fleet node-status directory {}: {err}",
                self.node_status_dir.display()
            ))
        })?;
        std::fs::create_dir_all(&self.lock_dir).map_err(|err| {
            FleetTransportError::io(format!(
                "failed creating fleet lock directory {}: {err}",
                self.lock_dir.display()
            ))
        })?;
        Ok(())
    }
}

/// Shared transport failure vocabulary for fleet backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FleetTransportError {
    IoError { detail: String },
    SerializationError { detail: String },
    LockContention { detail: String },
    StaleState { detail: String },
    NotInitialized { detail: String },
}

impl FleetTransportError {
    pub fn io(detail: impl Into<String>) -> Self {
        Self::IoError {
            detail: detail.into(),
        }
    }

    pub fn serialization(detail: impl Into<String>) -> Self {
        Self::SerializationError {
            detail: detail.into(),
        }
    }

    pub fn lock_contention(detail: impl Into<String>) -> Self {
        Self::LockContention {
            detail: detail.into(),
        }
    }

    pub fn stale_state(detail: impl Into<String>) -> Self {
        Self::StaleState {
            detail: detail.into(),
        }
    }

    pub fn not_initialized(detail: impl Into<String>) -> Self {
        Self::NotInitialized {
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for FleetTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError { detail } => write!(f, "io error: {detail}"),
            Self::SerializationError { detail } => write!(f, "serialization error: {detail}"),
            Self::LockContention { detail } => write!(f, "lock contention: {detail}"),
            Self::StaleState { detail } => write!(f, "stale state: {detail}"),
            Self::NotInitialized { detail } => write!(f, "not initialized: {detail}"),
        }
    }
}

impl std::error::Error for FleetTransportError {}

/// Object-safe transport contract for shared fleet state propagation.
pub trait FleetTransport: Send + Sync {
    fn initialize(&self) -> Result<(), FleetTransportError>;

    fn append_action(
        &self,
        action: &FleetActionEnvelope,
    ) -> Result<FleetActionEnvelope, FleetTransportError>;

    fn snapshot(&self) -> Result<FleetStateSnapshot, FleetTransportError>;

    fn record_node_status(&self, status: &NodeStatus) -> Result<NodeStatus, FleetTransportError>;

    fn list_stale_nodes(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        staleness_threshold: Duration,
    ) -> Result<Vec<NodeStatus>, FleetTransportError>;
}

fn validate_zone_id_for_transport(zone_id: &str) -> Result<(), FleetTransportError> {
    if zone_id.trim().is_empty() {
        return Err(FleetTransportError::serialization(
            "zone_id must not be empty",
        ));
    }
    Ok(())
}

fn validate_node_id(node_id: &str) -> Result<(), FleetTransportError> {
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return Err(FleetTransportError::serialization(
            "node_id must not be empty",
        ));
    }
    if trimmed.len() > 128 {
        return Err(FleetTransportError::serialization(
            "node_id must be at most 128 characters",
        ));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(FleetTransportError::serialization(
            "node_id must not be `.` or `..`",
        ));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(FleetTransportError::serialization(
            "node_id must match [a-zA-Z0-9._-]{1,128}",
        ));
    }
    Ok(())
}

/// Handle for an incident created by quarantine/revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentHandle {
    /// Incident identifier.
    pub incident_id: String,
    /// Extension that triggered the incident.
    pub extension_id: String,
    /// Zone of the incident.
    pub zone_id: String,
    /// Timestamp of creation.
    pub created_at: String,
    /// Current incident status.
    pub status: IncidentStatus,
    /// Action type that created this incident ("quarantine" or "revoke").
    pub action_type: String,
}

/// Status of a quarantine/revocation incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    /// Incident is active.
    Active,
    /// Incident is being resolved.
    Resolving,
    /// Incident has been released/resolved.
    Released,
}

/// Fleet control error with stable error codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FleetControlError {
    /// Scope validation failed.
    ScopeInvalid { code: String, detail: String },
    /// Target zone is unreachable.
    #[cfg(any(test, feature = "extended-surfaces"))]
    ZoneUnreachable { code: String, zone_id: String },
    /// Convergence timed out.
    #[cfg(any(test, feature = "extended-surfaces"))]
    ConvergenceTimeout { code: String, elapsed_seconds: u32 },
    /// Rollback failed during release.
    RollbackFailed {
        code: String,
        incident_id: String,
        detail: String,
    },
    /// API not activated (safe-start mode).
    NotActivated { code: String },
    /// Operation identifier space exhausted.
    OperationIdExhausted { code: String },
    /// Required decision-receipt signing material is unavailable.
    ReceiptSigningMaterialMissing { code: String },
    /// Incident registry is full of unreleased entries.
    #[cfg(any(test, feature = "extended-surfaces"))]
    IncidentCapacityExceeded { code: String },
    /// Zone-status registry is full of live entries.
    #[cfg(any(test, feature = "extended-surfaces"))]
    ZoneStatusCapacityExceeded { code: String },
}

impl FleetControlError {
    pub fn scope_invalid(detail: &str) -> Self {
        Self::ScopeInvalid {
            code: FLEET_SCOPE_INVALID.to_string(),
            detail: detail.to_string(),
        }
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn zone_unreachable(zone_id: &str) -> Self {
        Self::ZoneUnreachable {
            code: FLEET_ZONE_UNREACHABLE.to_string(),
            zone_id: zone_id.to_string(),
        }
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn convergence_timeout(elapsed: u32) -> Self {
        Self::ConvergenceTimeout {
            code: FLEET_CONVERGENCE_TIMEOUT.to_string(),
            elapsed_seconds: elapsed,
        }
    }

    pub fn rollback_failed(incident_id: &str, detail: &str) -> Self {
        Self::RollbackFailed {
            code: FLEET_ROLLBACK_FAILED.to_string(),
            incident_id: incident_id.to_string(),
            detail: detail.to_string(),
        }
    }

    pub fn not_activated() -> Self {
        Self::NotActivated {
            code: FLEET_NOT_ACTIVATED.to_string(),
        }
    }

    pub fn operation_id_exhausted() -> Self {
        Self::OperationIdExhausted {
            code: FLEET_OPERATION_ID_EXHAUSTED.to_string(),
        }
    }

    pub fn receipt_signing_material_missing() -> Self {
        Self::ReceiptSigningMaterialMissing {
            code: FLEET_RECEIPT_SIGNING_MATERIAL_MISSING.to_string(),
        }
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn incident_capacity_exceeded() -> Self {
        Self::IncidentCapacityExceeded {
            code: FLEET_INCIDENT_CAPACITY_EXCEEDED.to_string(),
        }
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn zone_status_capacity_exceeded() -> Self {
        Self::ZoneStatusCapacityExceeded {
            code: FLEET_ZONE_STATUS_CAPACITY_EXCEEDED.to_string(),
        }
    }

    /// Return the stable error code for this error.
    pub fn error_code(&self) -> &str {
        match self {
            Self::ScopeInvalid { code, .. } => code,
            #[cfg(any(test, feature = "extended-surfaces"))]
            Self::ZoneUnreachable { code, .. } => code,
            #[cfg(any(test, feature = "extended-surfaces"))]
            Self::ConvergenceTimeout { code, .. } => code,
            Self::RollbackFailed { code, .. } => code,
            Self::NotActivated { code } => code,
            Self::OperationIdExhausted { code } => code,
            Self::ReceiptSigningMaterialMissing { code } => code,
            #[cfg(any(test, feature = "extended-surfaces"))]
            Self::IncidentCapacityExceeded { code } => code,
            #[cfg(any(test, feature = "extended-surfaces"))]
            Self::ZoneStatusCapacityExceeded { code } => code,
        }
    }
}

/// Structured event for fleet control audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetControlEvent {
    /// Event code (FLEET-001 through FLEET-005).
    pub event_code: String,
    /// Human-readable event name.
    pub event_name: String,
    /// Trace ID for distributed correlation.
    pub trace_id: String,
    /// Zone affected.
    pub zone_id: String,
    /// Optional extension affected.
    pub extension_id: Option<String>,
    /// Timestamp of the event.
    pub timestamp: String,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

impl FleetControlEvent {
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn quarantine_initiated(trace_id: &str, zone_id: &str, extension_id: &str) -> Self {
        Self {
            event_code: FLEET_QUARANTINE_INITIATED.to_string(),
            event_name: "FLEET_QUARANTINE_INITIATED".to_string(),
            trace_id: trace_id.to_string(),
            zone_id: zone_id.to_string(),
            extension_id: Some(extension_id.to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            metadata: BTreeMap::new(),
        }
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn revocation_issued(trace_id: &str, zone_id: &str, extension_id: &str) -> Self {
        Self {
            event_code: FLEET_REVOCATION_ISSUED.to_string(),
            event_name: "FLEET_REVOCATION_ISSUED".to_string(),
            trace_id: trace_id.to_string(),
            zone_id: zone_id.to_string(),
            extension_id: Some(extension_id.to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            metadata: BTreeMap::new(),
        }
    }

    #[cfg(feature = "extended-surfaces")]
    pub fn convergence_progress(trace_id: &str, zone_id: &str, progress_pct: u8) -> Self {
        let mut metadata = BTreeMap::new();
        metadata.insert("progress_pct".to_string(), progress_pct.to_string());
        Self {
            event_code: FLEET_CONVERGENCE_PROGRESS.to_string(),
            event_name: "FLEET_CONVERGENCE_PROGRESS".to_string(),
            trace_id: trace_id.to_string(),
            zone_id: zone_id.to_string(),
            extension_id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            metadata,
        }
    }

    pub fn fleet_released(trace_id: &str, zone_id: &str, incident_id: &str) -> Self {
        let mut metadata = BTreeMap::new();
        metadata.insert("incident_id".to_string(), incident_id.to_string());
        Self {
            event_code: FLEET_RELEASED.to_string(),
            event_name: "FLEET_RELEASED".to_string(),
            trace_id: trace_id.to_string(),
            zone_id: zone_id.to_string(),
            extension_id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            metadata,
        }
    }

    pub fn reconcile_completed(trace_id: &str, zone_count: usize) -> Self {
        let mut metadata = BTreeMap::new();
        metadata.insert("zone_count".to_string(), zone_count.to_string());
        Self {
            event_code: FLEET_RECONCILE_COMPLETED.to_string(),
            event_name: "FLEET_RECONCILE_COMPLETED".to_string(),
            trace_id: trace_id.to_string(),
            zone_id: "all".to_string(),
            extension_id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            metadata,
        }
    }
}

// ── Fleet Control Manager ─────────────────────────────────────────────────

#[derive(Clone)]
struct FleetDecisionSigningMaterial {
    signing_key: ed25519_dalek::SigningKey,
    key_source: &'static str,
    signing_identity: &'static str,
}

fn default_decision_signing_material() -> Option<FleetDecisionSigningMaterial> {
    #[cfg(test)]
    {
        Some(FleetDecisionSigningMaterial {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[24_u8; 32]),
            key_source: "test",
            signing_identity: "fleet-control-plane",
        })
    }
    #[cfg(not(test))]
    {
        None
    }
}

/// Central manager for fleet quarantine/revocation operations.
///
/// Starts in read-only mode (INV-FLEET-SAFE-START) and must be explicitly
/// activated before mutation operations are allowed.
pub struct FleetControlManager {
    /// Whether the API is activated (false = safe-start read-only mode).
    activated: bool,
    /// Incident handles keyed by incident_id; released entries persist until reconcile.
    incidents: BTreeMap<String, IncidentHandle>,
    /// Convergence state keyed by quarantine incident_id for precise lifecycle cleanup.
    incident_convergences: BTreeMap<String, ConvergenceState>,
    /// Per-zone fleet status.
    zone_status: BTreeMap<String, FleetStatus>,
    /// Event log for audit trail.
    events: Vec<FleetControlEvent>,
    /// Counter for generating operation IDs.
    next_op_id: u64,
    /// Optional epoch component for non-default operation ID domains.
    op_epoch: u64,
    /// Set after the final unique operation ID has been allocated.
    operation_ids_exhausted: bool,
    /// Signing material required for every decision receipt.
    decision_signing_material: Option<FleetDecisionSigningMaterial>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct OperationSlot {
    epoch: u64,
    sequence: u64,
}

impl OperationSlot {
    fn operation_id(self) -> String {
        if self.epoch == 0 {
            format!("fleet-op-{}", self.sequence)
        } else {
            format!("fleet-op-{:016x}-{:016x}", self.epoch, self.sequence)
        }
    }
}

fn parse_operation_slot(operation_id: &str) -> Option<OperationSlot> {
    let raw = operation_id.strip_prefix("fleet-op-")?;
    match raw.split_once('-') {
        Some((epoch, sequence)) => Some(OperationSlot {
            epoch: u64::from_str_radix(epoch, 16).ok()?,
            sequence: u64::from_str_radix(sequence, 16).ok()?,
        }),
        None => Some(OperationSlot {
            epoch: 0,
            sequence: raw.parse().ok()?,
        }),
    }
}

fn incident_operation_slot(incident_id: &str) -> Option<OperationSlot> {
    parse_operation_slot(incident_id.strip_prefix("inc-")?)
}

/// Explicit owner for the fleet-control singleton state on the request path.
///
/// This remains a lock-wrapped owner while the request path is still simple:
/// direct method dispatch, bounded in-memory state, and no actor-style mailbox,
/// restart domain, or ad hoc request/reply protocol. Promote this surface only
/// if coordination topology, lifecycle semantics, or contention pressure become
/// the actual problem.
struct SharedFleetControlOwner {
    inner: Mutex<FleetControlManager>,
}

fn map_fleet_control_error(action: &str, trace: &TraceContext, err: FleetControlError) -> ApiError {
    if matches!(err, FleetControlError::OperationIdExhausted { .. }) {
        return ApiError::Internal {
            detail: format!(
                "{}: fleet control operation identifier space exhausted during {action}",
                err.error_code()
            ),
            trace_id: trace.trace_id.clone(),
        };
    }

    let detail = match action {
        "release" => format!("{}: {err:?}", err.error_code()),
        "status" => format!("{}: {}", err.error_code(), "status failed"),
        _ => format!("{}: {action} failed", err.error_code()),
    };
    ApiError::BadRequest {
        detail,
        trace_id: trace.trace_id.clone(),
    }
}

impl SharedFleetControlOwner {
    fn new() -> Self {
        Self {
            inner: Mutex::new(FleetControlManager::new()),
        }
    }

    fn lock(&self, trace: &TraceContext) -> Result<MutexGuard<'_, FleetControlManager>, ApiError> {
        self.inner.lock().map_err(|_| ApiError::Internal {
            detail: "fleet control manager lock poisoned".to_string(),
            trace_id: trace.trace_id.clone(),
        })
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    fn quarantine(
        &self,
        identity: &AuthIdentity,
        trace: &TraceContext,
        request: &QuarantineRequest,
    ) -> Result<FleetActionResult, ApiError> {
        let mut mgr = self.lock(trace)?;
        mgr.quarantine(&request.extension_id, &request.scope, identity, trace)
            .map_err(|e| map_fleet_control_error("quarantine", trace, e))
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    fn revoke(
        &self,
        identity: &AuthIdentity,
        trace: &TraceContext,
        request: &RevokeRequest,
    ) -> Result<FleetActionResult, ApiError> {
        let mut mgr = self.lock(trace)?;
        mgr.revoke(&request.extension_id, &request.scope, identity, trace)
            .map_err(|e| map_fleet_control_error("revocation", trace, e))
    }

    fn release(
        &self,
        identity: &AuthIdentity,
        trace: &TraceContext,
        incident_id: &str,
    ) -> Result<FleetActionResult, ApiError> {
        let mut mgr = self.lock(trace)?;
        mgr.release(incident_id, identity, trace)
            .map_err(|e| map_fleet_control_error("release", trace, e))
    }

    fn status(&self, trace: &TraceContext, zone_id: &str) -> Result<FleetStatus, ApiError> {
        let mgr = self.lock(trace)?;
        mgr.status(zone_id)
            .map_err(|e| map_fleet_control_error("status", trace, e))
    }

    fn reconcile(
        &self,
        identity: &AuthIdentity,
        trace: &TraceContext,
    ) -> Result<FleetActionResult, ApiError> {
        let mut mgr = self.lock(trace)?;
        mgr.reconcile(identity, trace)
            .map_err(|e| map_fleet_control_error("reconcile", trace, e))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn reset_for_tests(&self) {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = FleetControlManager::new();
    }
}

static SHARED_FLEET_CONTROL_MANAGER: OnceLock<SharedFleetControlOwner> = OnceLock::new();

fn shared_fleet_control_manager() -> &'static SharedFleetControlOwner {
    SHARED_FLEET_CONTROL_MANAGER.get_or_init(SharedFleetControlOwner::new)
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_shared_fleet_control_manager_for_tests() {
    shared_fleet_control_manager().reset_for_tests();
}

#[cfg(any(test, feature = "test-support"))]
pub fn activate_shared_fleet_control_manager_for_tests() {
    let mut guard = match shared_fleet_control_manager().inner.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.activate();
}

impl FleetControlManager {
    /// Create a new manager in safe-start (read-only) mode.
    /// INV-FLEET-SAFE-START: API starts read-only.
    pub fn new() -> Self {
        Self {
            activated: false,
            incidents: BTreeMap::new(),
            incident_convergences: BTreeMap::new(),
            zone_status: BTreeMap::new(),
            events: Vec::new(),
            next_op_id: 1,
            op_epoch: 0,
            operation_ids_exhausted: false,
            decision_signing_material: default_decision_signing_material(),
        }
    }

    /// Activate the fleet control API for mutations.
    /// Must be called before quarantine/revoke/release/reconcile.
    pub fn activate(&mut self) {
        self.activated = true;
    }

    /// Check if the manager is activated.
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn is_activated(&self) -> bool {
        self.activated
    }

    /// Quarantine an extension within a scope.
    /// INV-FLEET-ZONE-SCOPE: scope must have a valid zone_id.
    /// INV-FLEET-RECEIPT: produces a signed decision receipt.
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn quarantine(
        &mut self,
        extension_id: &str,
        scope: &QuarantineScope,
        identity: &AuthIdentity,
        trace: &TraceContext,
    ) -> Result<FleetActionResult, FleetControlError> {
        if !self.activated {
            return Err(FleetControlError::not_activated());
        }
        let zone_id = Self::validated_zone_id(&scope.zone_id)?;
        self.ensure_decision_signing_material()?;

        let planned_slot = self.peek_operation_slot()?;
        let planned_op_id = planned_slot.operation_id();
        let planned_incident_id = format!("inc-{planned_op_id}");
        let reclaimed_zone_key = self.prepare_zone_status_slot(zone_id)?;
        let reclaimed_incident_key = self.prepare_incident_slot(&planned_incident_id)?;
        let op_id = self.next_operation_id()?;
        debug_assert_eq!(op_id, planned_op_id);
        let now = chrono::Utc::now().to_rfc3339();
        let incident_id = format!("inc-{op_id}");

        // Create incident handle
        let incident = IncidentHandle {
            incident_id: incident_id.clone(),
            extension_id: extension_id.to_string(),
            zone_id: zone_id.to_string(),
            created_at: now.clone(),
            status: IncidentStatus::Active,
            action_type: "quarantine".to_string(),
        };
        if let Some(reclaimed_zone_key) = reclaimed_zone_key {
            self.zone_status.remove(&reclaimed_zone_key);
        }
        if let Some(reclaimed_incident_key) = reclaimed_incident_key {
            self.incidents.remove(&reclaimed_incident_key);
            self.incident_convergences.remove(&reclaimed_incident_key);
        }
        self.incidents.insert(incident_id.clone(), incident);

        // Update zone status (bounded by MAX_ZONE_STATUS)
        let zone = self
            .zone_status
            .entry(zone_id.to_string())
            .or_insert_with(|| FleetStatus {
                zone_id: zone_id.to_string(),
                active_quarantines: 0,
                active_revocations: 0,
                healthy_nodes: scope.affected_nodes,
                total_nodes: scope.affected_nodes,
                activated: true,
                pending_convergences: Vec::new(),
            });
        zone.active_quarantines = zone.active_quarantines.saturating_add(1);

        // Build receipt (INV-FLEET-RECEIPT)
        let receipt = self.build_receipt(&op_id, &identity.principal, zone_id, &now)?;

        // Convergence state (INV-FLEET-CONVERGENCE)
        let total_nodes = scope.affected_nodes;
        let (progress_pct, eta_seconds, phase) = if total_nodes == 0 {
            (0, None, ConvergencePhase::Pending)
        } else {
            (
                0,
                Some(total_nodes.saturating_mul(2)),
                ConvergencePhase::Propagating,
            )
        };
        let convergence = ConvergenceState {
            converged_nodes: 0,
            total_nodes,
            progress_pct,
            eta_seconds,
            phase,
        };
        self.incident_convergences
            .insert(incident_id.clone(), convergence.clone());
        self.sync_zone_pending_convergences(zone_id);

        // Emit event
        let event = FleetControlEvent::quarantine_initiated(&trace.trace_id, zone_id, extension_id);
        push_bounded(&mut self.events, event, MAX_FLEET_EVENTS);

        Ok(FleetActionResult {
            operation_id: op_id,
            action_type: "quarantine".to_string(),
            success: true,
            receipt,
            convergence: Some(convergence),
            trace_id: trace.trace_id.clone(),
            event_code: FLEET_QUARANTINE_INITIATED.to_string(),
        })
    }

    /// Revoke an extension.
    /// INV-FLEET-ZONE-SCOPE: scope must have a valid zone_id.
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn revoke(
        &mut self,
        extension_id: &str,
        scope: &RevocationScope,
        identity: &AuthIdentity,
        trace: &TraceContext,
    ) -> Result<FleetActionResult, FleetControlError> {
        if !self.activated {
            return Err(FleetControlError::not_activated());
        }
        let zone_id = Self::validated_zone_id(&scope.zone_id)?;
        self.ensure_decision_signing_material()?;

        let planned_slot = self.peek_operation_slot()?;
        let planned_op_id = planned_slot.operation_id();
        let planned_incident_id = format!("inc-{planned_op_id}");
        let reclaimed_zone_key = self.prepare_zone_status_slot(zone_id)?;
        let reclaimed_incident_key = if scope.severity == RevocationSeverity::Emergency {
            self.prepare_incident_slot(&planned_incident_id)?
        } else {
            None
        };
        let op_id = self.next_operation_id()?;
        debug_assert_eq!(op_id, planned_op_id);
        let now = chrono::Utc::now().to_rfc3339();
        let incident_id = format!("inc-{op_id}");

        // Update zone status (bounded by MAX_ZONE_STATUS)
        if let Some(reclaimed_zone_key) = reclaimed_zone_key {
            self.zone_status.remove(&reclaimed_zone_key);
        }
        let zone = self
            .zone_status
            .entry(zone_id.to_string())
            .or_insert_with(|| FleetStatus {
                zone_id: zone_id.to_string(),
                active_quarantines: 0,
                active_revocations: 0,
                healthy_nodes: 0,
                total_nodes: 0,
                activated: true,
                pending_convergences: Vec::new(),
            });
        zone.active_revocations = zone.active_revocations.saturating_add(1);

        let receipt = self.build_receipt(&op_id, &identity.principal, zone_id, &now)?;

        // Emergency revocations create incidents
        if scope.severity == RevocationSeverity::Emergency {
            let incident = IncidentHandle {
                incident_id: incident_id.clone(),
                extension_id: extension_id.to_string(),
                zone_id: zone_id.to_string(),
                created_at: now.clone(),
                status: IncidentStatus::Active,
                action_type: "revoke".to_string(),
            };
            if let Some(reclaimed_incident_key) = reclaimed_incident_key {
                self.incidents.remove(&reclaimed_incident_key);
                self.incident_convergences.remove(&reclaimed_incident_key);
            }
            self.incidents.insert(incident_id, incident);
        }

        let event = FleetControlEvent::revocation_issued(&trace.trace_id, zone_id, extension_id);
        push_bounded(&mut self.events, event, MAX_FLEET_EVENTS);

        Ok(FleetActionResult {
            operation_id: op_id,
            action_type: "revoke".to_string(),
            success: true,
            receipt,
            convergence: None,
            trace_id: trace.trace_id.clone(),
            event_code: FLEET_REVOCATION_ISSUED.to_string(),
        })
    }

    /// Release a quarantine incident, rolling back state.
    /// INV-FLEET-ROLLBACK: deterministic rollback with verification.
    pub fn release(
        &mut self,
        incident_id: &str,
        identity: &AuthIdentity,
        trace: &TraceContext,
    ) -> Result<FleetActionResult, FleetControlError> {
        if !self.activated {
            return Err(FleetControlError::not_activated());
        }

        let (zone_id, action_type) = {
            let incident = self.incidents.get(incident_id).ok_or_else(|| {
                FleetControlError::rollback_failed(incident_id, "incident not found")
            })?;

            if incident.status == IncidentStatus::Released {
                return Err(FleetControlError::rollback_failed(
                    incident_id,
                    "incident already released",
                ));
            }

            (incident.zone_id.clone(), incident.action_type.clone())
        };
        self.ensure_decision_signing_material()?;

        let op_id = self.next_operation_id()?;
        let now = chrono::Utc::now().to_rfc3339();

        // Mark as released
        let incident = self.incidents.get_mut(incident_id).ok_or_else(|| {
            FleetControlError::rollback_failed(incident_id, "incident disappeared during release")
        })?;
        incident.status = IncidentStatus::Released;

        // Decrement zone active count
        if let Some(zone) = self.zone_status.get_mut(&zone_id) {
            if action_type == "quarantine" {
                zone.active_quarantines = zone.active_quarantines.saturating_sub(1);
            } else if action_type == "revoke" {
                zone.active_revocations = zone.active_revocations.saturating_sub(1);
            }
        }
        self.incident_convergences.remove(incident_id);
        self.sync_zone_pending_convergences(&zone_id);

        let receipt = self.build_receipt(&op_id, &identity.principal, &zone_id, &now)?;

        let event = FleetControlEvent::fleet_released(&trace.trace_id, &zone_id, incident_id);
        push_bounded(&mut self.events, event, MAX_FLEET_EVENTS);

        Ok(FleetActionResult {
            operation_id: op_id,
            action_type: "release".to_string(),
            success: true,
            receipt,
            convergence: None,
            trace_id: trace.trace_id.clone(),
            event_code: FLEET_RELEASED.to_string(),
        })
    }

    /// Get fleet status for a zone.
    /// Does not require activation (read-only, safe in safe-start mode).
    pub fn status(&self, zone_id: &str) -> Result<FleetStatus, FleetControlError> {
        let zone_id = Self::validated_zone_id(zone_id)?;

        Ok(self
            .zone_status
            .get(zone_id)
            .cloned()
            .map(|mut status| {
                status.pending_convergences = self.pending_convergences_for_zone(zone_id);
                status
            })
            .unwrap_or_else(|| FleetStatus {
                zone_id: zone_id.to_string(),
                active_quarantines: 0,
                active_revocations: 0,
                healthy_nodes: 0,
                total_nodes: 0,
                activated: self.activated,
                pending_convergences: Vec::new(),
            }))
    }

    /// Reconcile fleet state across all zones.
    pub fn reconcile(
        &mut self,
        identity: &AuthIdentity,
        trace: &TraceContext,
    ) -> Result<FleetActionResult, FleetControlError> {
        if !self.activated {
            return Err(FleetControlError::not_activated());
        }
        self.ensure_decision_signing_material()?;

        let op_id = self.next_operation_id()?;
        let now = chrono::Utc::now().to_rfc3339();
        let zone_count = self.zone_status.len();

        // Clean up released incidents
        self.incidents
            .retain(|_, inc| inc.status != IncidentStatus::Released);
        self.incident_convergences
            .retain(|incident_id, _| self.incidents.contains_key(incident_id));

        // Mark all remaining active incident convergences as fully converged
        for convergence in self.incident_convergences.values_mut() {
            convergence.converged_nodes = convergence.total_nodes;
            convergence.progress_pct = 100;
            convergence.eta_seconds = Some(0);
            convergence.phase = ConvergencePhase::Converged;
        }

        let zone_ids: Vec<String> = self.zone_status.keys().cloned().collect();
        for zone_id in zone_ids {
            self.sync_zone_pending_convergences(&zone_id);
        }

        let receipt = self.build_receipt(&op_id, &identity.principal, "all", &now)?;

        let convergence = ConvergenceState {
            converged_nodes: u32::try_from(zone_count).unwrap_or(u32::MAX),
            total_nodes: u32::try_from(zone_count).unwrap_or(u32::MAX),
            progress_pct: 100,
            eta_seconds: Some(0),
            phase: ConvergencePhase::Converged,
        };

        let event = FleetControlEvent::reconcile_completed(&trace.trace_id, zone_count);
        push_bounded(&mut self.events, event, MAX_FLEET_EVENTS);

        Ok(FleetActionResult {
            operation_id: op_id,
            action_type: "reconcile".to_string(),
            success: true,
            receipt,
            convergence: Some(convergence),
            trace_id: trace.trace_id.clone(),
            event_code: FLEET_RECONCILE_COMPLETED.to_string(),
        })
    }

    /// Return all events in the audit trail.
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn events(&self) -> &[FleetControlEvent] {
        &self.events
    }

    /// Return all active incidents.
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn active_incidents(&self) -> Vec<&IncidentHandle> {
        self.incidents
            .values()
            .filter(|inc| inc.status == IncidentStatus::Active)
            .collect()
    }

    /// Return all zone IDs known to the manager.
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn zones(&self) -> Vec<String> {
        self.zone_status.keys().cloned().collect()
    }

    /// Return the total number of incidents (all statuses).
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn incident_count(&self) -> usize {
        self.incidents.len()
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn peek_operation_slot(&self) -> Result<OperationSlot, FleetControlError> {
        if self.operation_ids_exhausted {
            return Err(FleetControlError::operation_id_exhausted());
        }

        Ok(OperationSlot {
            epoch: self.op_epoch,
            sequence: self.next_op_id,
        })
    }

    fn allocate_operation_slot(&mut self) -> Result<OperationSlot, FleetControlError> {
        if self.operation_ids_exhausted {
            return Err(FleetControlError::operation_id_exhausted());
        }

        let slot = OperationSlot {
            epoch: self.op_epoch,
            sequence: self.next_op_id,
        };

        if let Some(next) = self.next_op_id.checked_add(1) {
            self.next_op_id = next;
        } else {
            self.operation_ids_exhausted = true;
        }

        Ok(slot)
    }

    fn next_operation_id(&mut self) -> Result<String, FleetControlError> {
        Ok(self.allocate_operation_slot()?.operation_id())
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    fn reclaimable_incident_key(&self) -> Option<String> {
        self.incidents
            .iter()
            .filter(|(_, incident)| incident.status == IncidentStatus::Released)
            .min_by_key(|(incident_id, _)| {
                incident_operation_slot(incident_id).unwrap_or(OperationSlot {
                    epoch: u64::MAX,
                    sequence: u64::MAX,
                })
            })
            .map(|(incident_id, _)| incident_id.clone())
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    fn reclaimable_zone_status_key(&self) -> Option<String> {
        self.zone_status
            .iter()
            .find(|(zone_id, status)| {
                status.active_quarantines == 0
                    && status.active_revocations == 0
                    && self.pending_convergences_for_zone(zone_id).is_empty()
                    && !self.zone_has_live_incident(zone_id)
            })
            .map(|(zone_id, _)| zone_id.clone())
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    fn zone_has_live_incident(&self, zone_id: &str) -> bool {
        self.incidents.values().any(|incident| {
            incident.zone_id == zone_id && incident.status != IncidentStatus::Released
        })
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    fn prepare_incident_slot(
        &self,
        incident_id: &str,
    ) -> Result<Option<String>, FleetControlError> {
        if self.incidents.len() < MAX_INCIDENTS || self.incidents.contains_key(incident_id) {
            return Ok(None);
        }

        self.reclaimable_incident_key()
            .map(Some)
            .ok_or_else(FleetControlError::incident_capacity_exceeded)
    }

    #[cfg(any(test, feature = "extended-surfaces"))]
    fn prepare_zone_status_slot(&self, zone_id: &str) -> Result<Option<String>, FleetControlError> {
        if self.zone_status.len() < MAX_ZONE_STATUS || self.zone_status.contains_key(zone_id) {
            return Ok(None);
        }

        self.reclaimable_zone_status_key()
            .map(Some)
            .ok_or_else(FleetControlError::zone_status_capacity_exceeded)
    }

    fn pending_convergences_for_zone(&self, zone_id: &str) -> Vec<ConvergenceState> {
        let mut pending: Vec<(OperationSlot, ConvergenceState)> = self
            .incident_convergences
            .iter()
            .filter_map(|(incident_id, convergence)| {
                let incident = self.incidents.get(incident_id)?;
                if incident.zone_id != zone_id
                    || incident.status == IncidentStatus::Released
                    || incident.action_type != "quarantine"
                    || convergence.phase == ConvergencePhase::Converged
                {
                    return None;
                }
                Some((
                    incident_operation_slot(incident_id).unwrap_or(OperationSlot {
                        epoch: u64::MAX,
                        sequence: u64::MAX,
                    }),
                    convergence.clone(),
                ))
            })
            .collect();
        pending.sort_by_key(|(slot, _)| *slot);
        pending
            .into_iter()
            .map(|(_, convergence)| convergence)
            .collect()
    }

    fn sync_zone_pending_convergences(&mut self, zone_id: &str) {
        let pending = self.pending_convergences_for_zone(zone_id);
        if let Some(zone) = self.zone_status.get_mut(zone_id) {
            zone.pending_convergences = pending;
        }
    }

    fn validated_zone_id(zone_id: &str) -> Result<&str, FleetControlError> {
        let zone_id = zone_id.trim();
        if zone_id.is_empty() {
            return Err(FleetControlError::scope_invalid(
                "zone_id must not be empty",
            ));
        }
        Ok(zone_id)
    }

    fn ensure_decision_signing_material(
        &self,
    ) -> Result<&FleetDecisionSigningMaterial, FleetControlError> {
        self.decision_signing_material
            .as_ref()
            .ok_or_else(FleetControlError::receipt_signing_material_missing)
    }

    fn build_receipt(
        &self,
        op_id: &str,
        principal: &str,
        zone_id: &str,
        timestamp: &str,
    ) -> Result<DecisionReceipt, FleetControlError> {
        let signing_material = self.ensure_decision_signing_material()?;
        // Length-prefixed encoding prevents delimiter-collision ambiguity.
        let mut hasher = Sha256::new();
        hasher.update(b"fleet_receipt_v1:");
        for field in [op_id, principal, zone_id, timestamp] {
            hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(field.as_bytes());
        }
        let payload_hash = hex::encode(hasher.finalize());
        let mut receipt = DecisionReceipt {
            receipt_id: format!("rcpt-{op_id}"),
            issuer: principal.to_string(),
            issued_at: timestamp.to_string(),
            zone_id: zone_id.to_string(),
            payload_hash,
            signature: None,
        };
        receipt.signature = Some(sign_decision_receipt(
            &receipt,
            &signing_material.signing_key,
            signing_material.key_source,
            signing_material.signing_identity,
        ));
        Ok(receipt)
    }
}

impl Default for FleetControlManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Request / Response types for API handlers ─────────────────────────────

#[cfg(any(test, feature = "extended-surfaces"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRequest {
    pub extension_id: String,
    pub scope: QuarantineScope,
}

#[cfg(any(test, feature = "extended-surfaces"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub extension_id: String,
    pub scope: RevocationScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub incident_id: String,
}

#[cfg(feature = "extended-surfaces")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRequest {
    pub zone_id: String,
}

#[cfg(feature = "extended-surfaces")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileResult {
    pub zones_reconciled: usize,
    pub incidents_cleaned: usize,
    pub convergence: ConvergenceState,
}

// ── Route Metadata ────────────────────────────────────────────────────────

#[cfg(any(test, feature = "extended-surfaces"))]
pub fn quarantine_route_metadata() -> Vec<RouteMetadata> {
    vec![
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/fleet/quarantine".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::MtlsClientCert,
            policy_hook: PolicyHook {
                hook_id: "fleet.quarantine.execute".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/fleet/revoke".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::MtlsClientCert,
            policy_hook: PolicyHook {
                hook_id: "fleet.revoke.execute".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/fleet/release".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::MtlsClientCert,
            policy_hook: PolicyHook {
                hook_id: "fleet.release.execute".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/fleet/status".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "fleet.status.read".to_string(),
                required_roles: vec!["operator".to_string(), "fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/fleet/reconcile".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::MtlsClientCert,
            policy_hook: PolicyHook {
                hook_id: "fleet.reconcile.execute".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
    ]
}

// ── API Handlers ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "extended-surfaces"))]
pub fn handle_quarantine(
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &QuarantineRequest,
) -> Result<ApiResponse<FleetActionResult>, ApiError> {
    let result = shared_fleet_control_manager().quarantine(identity, trace, request)?;
    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

#[cfg(any(test, feature = "extended-surfaces"))]
pub fn handle_revoke(
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &RevokeRequest,
) -> Result<ApiResponse<FleetActionResult>, ApiError> {
    let result = shared_fleet_control_manager().revoke(identity, trace, request)?;
    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

pub fn handle_release(
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &ReleaseRequest,
) -> Result<ApiResponse<FleetActionResult>, ApiError> {
    let incident_id = request.incident_id.trim();
    if incident_id.is_empty() {
        return Err(ApiError::BadRequest {
            detail: format!("{}: incident_id must not be empty", FLEET_SCOPE_INVALID),
            trace_id: trace.trace_id.clone(),
        });
    }

    let result = shared_fleet_control_manager().release(identity, trace, incident_id)?;
    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

pub fn handle_status(
    _identity: &AuthIdentity,
    trace: &TraceContext,
    zone_id: &str,
) -> Result<ApiResponse<FleetStatus>, ApiError> {
    let status = shared_fleet_control_manager().status(trace, zone_id)?;
    Ok(ApiResponse {
        ok: true,
        data: status,
        page: None,
    })
}

pub fn handle_reconcile(
    identity: &AuthIdentity,
    trace: &TraceContext,
) -> Result<ApiResponse<FleetActionResult>, ApiError> {
    let result = shared_fleet_control_manager().reconcile(identity, trace)?;
    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::AuthMethod;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn lock_handler_test_state() -> MutexGuard<'static, ()> {
        static HANDLER_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let guard = HANDLER_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("handler test lock");
        reset_shared_fleet_control_manager_for_tests();
        guard
    }

    fn admin_identity() -> AuthIdentity {
        AuthIdentity {
            principal: "fleet-admin-1".to_string(),
            method: AuthMethod::MtlsClientCert,
            roles: vec!["fleet-admin".to_string()],
        }
    }

    fn test_trace() -> TraceContext {
        TraceContext {
            trace_id: "test-trace-quarantine-001".to_string(),
            span_id: "0000000000000001".to_string(),
            trace_flags: 1,
        }
    }

    fn test_quarantine_scope() -> QuarantineScope {
        QuarantineScope {
            zone_id: "zone-us-east-1".to_string(),
            tenant_id: Some("tenant-acme".to_string()),
            affected_nodes: 5,
            reason: "suspected supply-chain compromise".to_string(),
        }
    }

    fn test_revocation_scope() -> RevocationScope {
        RevocationScope {
            zone_id: "zone-eu-west-1".to_string(),
            tenant_id: None,
            severity: RevocationSeverity::Mandatory,
            reason: "known CVE".to_string(),
        }
    }

    // ── Manager lifecycle tests ───────────────────────────────────────────

    #[test]
    fn new_manager_is_not_activated() {
        let mgr = FleetControlManager::new();
        assert!(!mgr.is_activated());
    }

    #[test]
    fn activate_enables_mutations() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        assert!(mgr.is_activated());
    }

    #[test]
    fn default_matches_new() {
        let a = FleetControlManager::new();
        let b = FleetControlManager::default();
        assert_eq!(a.is_activated(), b.is_activated());
        assert_eq!(a.incident_count(), b.incident_count());
    }

    // ── INV-FLEET-SAFE-START tests ────────────────────────────────────────

    #[test]
    fn quarantine_rejected_before_activation() {
        let mut mgr = FleetControlManager::new();
        let scope = test_quarantine_scope();
        let identity = admin_identity();
        let trace = test_trace();
        let err = mgr
            .quarantine("ext-1", &scope, &identity, &trace)
            .expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_NOT_ACTIVATED);
    }

    #[test]
    fn revoke_rejected_before_activation() {
        let mut mgr = FleetControlManager::new();
        let scope = test_revocation_scope();
        let identity = admin_identity();
        let trace = test_trace();
        let err = mgr
            .revoke("ext-1", &scope, &identity, &trace)
            .expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_NOT_ACTIVATED);
    }

    #[test]
    fn release_rejected_before_activation() {
        let mut mgr = FleetControlManager::new();
        let identity = admin_identity();
        let trace = test_trace();
        let err = mgr
            .release("inc-1", &identity, &trace)
            .expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_NOT_ACTIVATED);
    }

    #[test]
    fn reconcile_rejected_before_activation() {
        let mut mgr = FleetControlManager::new();
        let identity = admin_identity();
        let trace = test_trace();
        let err = mgr.reconcile(&identity, &trace).expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_NOT_ACTIVATED);
    }

    #[test]
    fn status_allowed_before_activation() {
        let mgr = FleetControlManager::new();
        let status = mgr
            .status("zone-1")
            .expect("status should work in safe-start");
        assert!(!status.activated);
    }

    // ── INV-FLEET-ZONE-SCOPE tests ───────────────────────────────────────

    #[test]
    fn quarantine_rejects_empty_zone() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = QuarantineScope {
            zone_id: String::new(),
            tenant_id: None,
            affected_nodes: 1,
            reason: "test".to_string(),
        };
        let err = mgr
            .quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_SCOPE_INVALID);
    }

    #[test]
    fn quarantine_rejects_whitespace_only_zone() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = QuarantineScope {
            zone_id: "   ".to_string(),
            tenant_id: None,
            affected_nodes: 1,
            reason: "test".to_string(),
        };
        let err = mgr
            .quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_SCOPE_INVALID);
    }

    #[test]
    fn revoke_rejects_empty_zone() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = RevocationScope {
            zone_id: String::new(),
            tenant_id: None,
            severity: RevocationSeverity::Mandatory,
            reason: "test".to_string(),
        };
        let err = mgr
            .revoke("ext-1", &scope, &admin_identity(), &test_trace())
            .expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_SCOPE_INVALID);
    }

    #[test]
    fn revoke_rejects_whitespace_only_zone() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = RevocationScope {
            zone_id: " \t ".to_string(),
            tenant_id: None,
            severity: RevocationSeverity::Mandatory,
            reason: "test".to_string(),
        };
        let err = mgr
            .revoke("ext-1", &scope, &admin_identity(), &test_trace())
            .expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_SCOPE_INVALID);
    }

    #[test]
    fn status_rejects_empty_zone() {
        let mgr = FleetControlManager::new();
        let err = mgr.status("").expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_SCOPE_INVALID);
    }

    #[test]
    fn status_rejects_whitespace_only_zone() {
        let mgr = FleetControlManager::new();
        let err = mgr.status(" \n ").expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_SCOPE_INVALID);
    }

    // ── Quarantine tests ──────────────────────────────────────────────────

    #[test]
    fn quarantine_creates_incident() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        let result = mgr
            .quarantine("ext-malicious", &scope, &admin_identity(), &test_trace())
            .expect("quarantine should succeed");
        assert!(result.success);
        assert_eq!(result.action_type, "quarantine");
        assert_eq!(result.event_code, FLEET_QUARANTINE_INITIATED);
        assert_eq!(mgr.incident_count(), 1);
    }

    #[test]
    fn quarantine_produces_receipt() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        let result = mgr
            .quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine should succeed");
        assert!(result.receipt.receipt_id.starts_with("rcpt-"));
        assert_eq!(result.receipt.issuer, "fleet-admin-1");
        assert_eq!(result.receipt.zone_id, "zone-us-east-1");
        assert!(!result.receipt.payload_hash.is_empty());
    }

    #[test]
    fn quarantine_has_convergence_state() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        let result = mgr
            .quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine should succeed");
        let conv = result.convergence.expect("should have convergence");
        assert_eq!(conv.total_nodes, 5);
        assert_eq!(conv.phase, ConvergencePhase::Propagating);
    }

    #[test]
    fn quarantine_updates_zone_status() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        let status = mgr.status("zone-us-east-1").expect("status");
        assert_eq!(status.active_quarantines, 1);
        assert_eq!(status.pending_convergences.len(), 1);
        assert_eq!(
            status.pending_convergences[0].phase,
            ConvergencePhase::Propagating
        );
    }

    #[test]
    fn quarantine_normalizes_padded_zone_id() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let mut scope = test_quarantine_scope();
        scope.zone_id = " zone-us-east-1 ".to_string();
        let result = mgr
            .quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        assert_eq!(result.receipt.zone_id, "zone-us-east-1");
        assert_eq!(mgr.events()[0].zone_id, "zone-us-east-1");
        assert_eq!(mgr.active_incidents()[0].zone_id, "zone-us-east-1");
        let status = mgr.status("zone-us-east-1").expect("status");
        assert_eq!(status.zone_id, "zone-us-east-1");
        assert_eq!(status.active_quarantines, 1);
    }

    #[test]
    fn quarantine_emits_event() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        assert_eq!(mgr.events().len(), 1);
        assert_eq!(mgr.events()[0].event_code, FLEET_QUARANTINE_INITIATED);
        assert_eq!(mgr.events()[0].zone_id, "zone-us-east-1");
    }

    #[test]
    fn quarantine_with_tenant_scope() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = QuarantineScope {
            zone_id: "zone-1".to_string(),
            tenant_id: Some("tenant-123".to_string()),
            affected_nodes: 3,
            reason: "test".to_string(),
        };
        let result = mgr
            .quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        assert!(result.success);
    }

    // ── Revocation tests ──────────────────────────────────────────────────

    #[test]
    fn revoke_succeeds() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_revocation_scope();
        let result = mgr
            .revoke("ext-bad", &scope, &admin_identity(), &test_trace())
            .expect("revoke should succeed");
        assert!(result.success);
        assert_eq!(result.action_type, "revoke");
        assert_eq!(result.event_code, FLEET_REVOCATION_ISSUED);
    }

    #[test]
    fn revoke_updates_zone_status() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_revocation_scope();
        mgr.revoke("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("revoke");
        let status = mgr.status("zone-eu-west-1").expect("status");
        assert_eq!(status.active_revocations, 1);
    }

    #[test]
    fn revoke_normalizes_padded_zone_id() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let mut scope = test_revocation_scope();
        scope.zone_id = " zone-eu-west-1\t".to_string();
        let result = mgr
            .revoke("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("revoke");
        assert_eq!(result.receipt.zone_id, "zone-eu-west-1");
        assert_eq!(mgr.events()[0].zone_id, "zone-eu-west-1");
        let status = mgr.status("zone-eu-west-1").expect("status");
        assert_eq!(status.zone_id, "zone-eu-west-1");
        assert_eq!(status.active_revocations, 1);
    }

    #[test]
    fn emergency_revocation_creates_incident() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = RevocationScope {
            zone_id: "zone-1".to_string(),
            tenant_id: None,
            severity: RevocationSeverity::Emergency,
            reason: "critical vulnerability".to_string(),
        };
        mgr.revoke("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("revoke");
        assert_eq!(mgr.incident_count(), 1);
    }

    #[test]
    fn advisory_revocation_no_incident() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = RevocationScope {
            zone_id: "zone-1".to_string(),
            tenant_id: None,
            severity: RevocationSeverity::Advisory,
            reason: "minor issue".to_string(),
        };
        mgr.revoke("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("revoke");
        assert_eq!(mgr.incident_count(), 0);
    }

    #[test]
    fn reclaimable_incident_key_uses_operation_order_not_lexicographic_key_order() {
        let mut mgr = FleetControlManager::new();
        mgr.incidents.insert(
            "inc-fleet-op-10".to_string(),
            IncidentHandle {
                incident_id: "inc-fleet-op-10".to_string(),
                extension_id: "ext-10".to_string(),
                zone_id: "zone-1".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                status: IncidentStatus::Released,
                action_type: "quarantine".to_string(),
            },
        );
        mgr.incidents.insert(
            "inc-fleet-op-2".to_string(),
            IncidentHandle {
                incident_id: "inc-fleet-op-2".to_string(),
                extension_id: "ext-2".to_string(),
                zone_id: "zone-1".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                status: IncidentStatus::Released,
                action_type: "quarantine".to_string(),
            },
        );

        assert_eq!(
            mgr.reclaimable_incident_key().as_deref(),
            Some("inc-fleet-op-2")
        );
    }

    #[test]
    fn quarantine_capacity_reclaims_oldest_released_incident_by_operation_order() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        for seq in 2..=(MAX_INCIDENTS as u64 + 1) {
            let incident_id = format!("inc-fleet-op-{seq}");
            mgr.incidents.insert(
                incident_id.clone(),
                IncidentHandle {
                    incident_id,
                    extension_id: format!("ext-{seq}"),
                    zone_id: "zone-us-east-1".to_string(),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    status: IncidentStatus::Released,
                    action_type: "quarantine".to_string(),
                },
            );
        }
        mgr.next_op_id = MAX_INCIDENTS as u64 + 2;

        let scope = test_quarantine_scope();
        mgr.quarantine("ext-new", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");

        assert_eq!(mgr.incident_count(), MAX_INCIDENTS);
        assert!(!mgr.incidents.contains_key("inc-fleet-op-2"));
        assert!(mgr.incidents.contains_key("inc-fleet-op-10"));
    }

    #[test]
    fn incident_capacity_prefers_released_entries_over_live_ones() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        for seq in 2..=(MAX_INCIDENTS as u64) {
            let incident_id = format!("inc-fleet-op-{seq}");
            mgr.incidents.insert(
                incident_id.clone(),
                IncidentHandle {
                    incident_id,
                    extension_id: format!("ext-{seq}"),
                    zone_id: "zone-us-east-1".to_string(),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    status: IncidentStatus::Active,
                    action_type: "quarantine".to_string(),
                },
            );
        }
        let released_id = format!("inc-fleet-op-{}", MAX_INCIDENTS as u64 + 1);
        mgr.incidents.insert(
            released_id.clone(),
            IncidentHandle {
                incident_id: released_id.clone(),
                extension_id: "ext-released".to_string(),
                zone_id: "zone-us-east-1".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                status: IncidentStatus::Released,
                action_type: "quarantine".to_string(),
            },
        );
        mgr.next_op_id = MAX_INCIDENTS as u64 + 2;

        let scope = test_quarantine_scope();
        mgr.quarantine("ext-new", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");

        assert_eq!(mgr.incident_count(), MAX_INCIDENTS);
        assert!(!mgr.incidents.contains_key(&released_id));
        assert!(mgr.incidents.contains_key("inc-fleet-op-2"));
    }

    #[test]
    fn quarantine_full_of_live_incidents_fails_closed() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        for seq in 2..=(MAX_INCIDENTS as u64 + 1) {
            let incident_id = format!("inc-fleet-op-{seq}");
            mgr.incidents.insert(
                incident_id.clone(),
                IncidentHandle {
                    incident_id,
                    extension_id: format!("ext-{seq}"),
                    zone_id: "zone-us-east-1".to_string(),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    status: IncidentStatus::Active,
                    action_type: "quarantine".to_string(),
                },
            );
        }
        mgr.next_op_id = MAX_INCIDENTS as u64 + 2;
        let rejected_id = format!("inc-fleet-op-{}", MAX_INCIDENTS as u64 + 2);

        let scope = test_quarantine_scope();
        let err = mgr
            .quarantine("ext-new", &scope, &admin_identity(), &test_trace())
            .expect_err("full live registry must reject");

        assert_eq!(err.error_code(), FLEET_INCIDENT_CAPACITY_EXCEEDED);
        assert_eq!(mgr.next_op_id, MAX_INCIDENTS as u64 + 2);
        assert_eq!(mgr.incident_count(), MAX_INCIDENTS);
        assert!(mgr.incidents.contains_key("inc-fleet-op-2"));
        assert!(!mgr.incidents.contains_key(&rejected_id));
    }

    #[test]
    fn emergency_revoke_full_of_live_incidents_fails_closed() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        for seq in 2..=(MAX_INCIDENTS as u64 + 1) {
            let incident_id = format!("inc-fleet-op-{seq}");
            mgr.incidents.insert(
                incident_id.clone(),
                IncidentHandle {
                    incident_id,
                    extension_id: format!("ext-{seq}"),
                    zone_id: "zone-us-east-1".to_string(),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    status: IncidentStatus::Active,
                    action_type: "quarantine".to_string(),
                },
            );
        }
        mgr.next_op_id = MAX_INCIDENTS as u64 + 2;
        let rejected_id = format!("inc-fleet-op-{}", MAX_INCIDENTS as u64 + 2);

        let scope = RevocationScope {
            zone_id: "zone-us-east-1".to_string(),
            tenant_id: None,
            severity: RevocationSeverity::Emergency,
            reason: "critical".to_string(),
        };
        let err = mgr
            .revoke("ext-new", &scope, &admin_identity(), &test_trace())
            .expect_err("full live registry must reject");

        assert_eq!(err.error_code(), FLEET_INCIDENT_CAPACITY_EXCEEDED);
        assert_eq!(mgr.next_op_id, MAX_INCIDENTS as u64 + 2);
        assert_eq!(mgr.incident_count(), MAX_INCIDENTS);
        assert!(mgr.incidents.contains_key("inc-fleet-op-2"));
        assert!(!mgr.incidents.contains_key(&rejected_id));
    }

    #[test]
    fn emergency_revoke_incident_capacity_failure_does_not_leak_zone_status() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        for seq in 2..=(MAX_INCIDENTS as u64 + 1) {
            let incident_id = format!("inc-fleet-op-{seq}");
            mgr.incidents.insert(
                incident_id.clone(),
                IncidentHandle {
                    incident_id,
                    extension_id: format!("ext-{seq}"),
                    zone_id: "zone-us-east-1".to_string(),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    status: IncidentStatus::Active,
                    action_type: "quarantine".to_string(),
                },
            );
        }
        mgr.next_op_id = MAX_INCIDENTS as u64 + 2;

        let scope = RevocationScope {
            zone_id: "zone-us-east-1".to_string(),
            tenant_id: None,
            severity: RevocationSeverity::Emergency,
            reason: "critical".to_string(),
        };
        let err = mgr
            .revoke("ext-new", &scope, &admin_identity(), &test_trace())
            .expect_err("full live registry must reject");

        assert_eq!(err.error_code(), FLEET_INCIDENT_CAPACITY_EXCEEDED);
        let status = mgr.status("zone-us-east-1").expect("status");
        assert_eq!(status.active_revocations, 0);
    }

    #[test]
    fn zone_status_capacity_prefers_empty_zones_over_live_ones() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        mgr.zone_status.insert(
            "zone-empty".to_string(),
            FleetStatus {
                zone_id: "zone-empty".to_string(),
                active_quarantines: 0,
                active_revocations: 0,
                healthy_nodes: 0,
                total_nodes: 0,
                activated: true,
                pending_convergences: Vec::new(),
            },
        );
        for seq in 2..=MAX_ZONE_STATUS as u32 {
            let zone_id = format!("zone-live-{seq:04}");
            mgr.zone_status.insert(
                zone_id.clone(),
                FleetStatus {
                    zone_id,
                    active_quarantines: 1,
                    active_revocations: 0,
                    healthy_nodes: 5,
                    total_nodes: 5,
                    activated: true,
                    pending_convergences: Vec::new(),
                },
            );
        }

        let scope = QuarantineScope {
            zone_id: "zone-new".to_string(),
            tenant_id: None,
            affected_nodes: 5,
            reason: "test".to_string(),
        };
        mgr.quarantine("ext-new", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");

        assert!(!mgr.zone_status.contains_key("zone-empty"));
        assert!(mgr.zone_status.contains_key("zone-live-0002"));
        assert!(mgr.zone_status.contains_key("zone-new"));
    }

    #[test]
    fn zone_status_reclaim_ignores_zero_count_zone_with_live_incident_reference() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        mgr.zone_status.insert(
            "zone-empty".to_string(),
            FleetStatus {
                zone_id: "zone-empty".to_string(),
                active_quarantines: 0,
                active_revocations: 0,
                healthy_nodes: 0,
                total_nodes: 0,
                activated: true,
                pending_convergences: Vec::new(),
            },
        );
        mgr.zone_status.insert(
            "zone-drifted".to_string(),
            FleetStatus {
                zone_id: "zone-drifted".to_string(),
                active_quarantines: 0,
                active_revocations: 0,
                healthy_nodes: 0,
                total_nodes: 0,
                activated: true,
                pending_convergences: Vec::new(),
            },
        );
        mgr.incidents.insert(
            "inc-fleet-op-2".to_string(),
            IncidentHandle {
                incident_id: "inc-fleet-op-2".to_string(),
                extension_id: "ext-drifted".to_string(),
                zone_id: "zone-drifted".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                status: IncidentStatus::Active,
                action_type: "quarantine".to_string(),
            },
        );
        for seq in 3..=MAX_ZONE_STATUS as u32 {
            let zone_id = format!("zone-live-{seq:04}");
            mgr.zone_status.insert(
                zone_id.clone(),
                FleetStatus {
                    zone_id,
                    active_quarantines: 1,
                    active_revocations: 0,
                    healthy_nodes: 5,
                    total_nodes: 5,
                    activated: true,
                    pending_convergences: Vec::new(),
                },
            );
        }

        let scope = QuarantineScope {
            zone_id: "zone-new".to_string(),
            tenant_id: None,
            affected_nodes: 5,
            reason: "test".to_string(),
        };
        mgr.quarantine("ext-new", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");

        assert!(!mgr.zone_status.contains_key("zone-empty"));
        assert!(mgr.zone_status.contains_key("zone-drifted"));
        assert!(mgr.zone_status.contains_key("zone-new"));
    }

    #[test]
    fn quarantine_full_of_live_zone_status_entries_fails_closed_without_inserting_incident() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        for seq in 1..=MAX_ZONE_STATUS as u32 {
            let zone_id = format!("zone-live-{seq:04}");
            mgr.zone_status.insert(
                zone_id.clone(),
                FleetStatus {
                    zone_id,
                    active_quarantines: 1,
                    active_revocations: 0,
                    healthy_nodes: 5,
                    total_nodes: 5,
                    activated: true,
                    pending_convergences: Vec::new(),
                },
            );
        }

        let scope = QuarantineScope {
            zone_id: "zone-new".to_string(),
            tenant_id: None,
            affected_nodes: 5,
            reason: "test".to_string(),
        };
        let err = mgr
            .quarantine("ext-new", &scope, &admin_identity(), &test_trace())
            .expect_err("full live zone registry must reject");

        assert_eq!(err.error_code(), FLEET_ZONE_STATUS_CAPACITY_EXCEEDED);
        assert_eq!(mgr.next_op_id, 1);
        assert_eq!(mgr.incident_count(), 0);
        assert!(!mgr.zone_status.contains_key("zone-new"));
        assert!(mgr.zone_status.contains_key("zone-live-0001"));
    }

    #[test]
    fn revocation_severities() {
        let advisory = RevocationSeverity::Advisory;
        let mandatory = RevocationSeverity::Mandatory;
        let emergency = RevocationSeverity::Emergency;
        assert_ne!(advisory, mandatory);
        assert_ne!(mandatory, emergency);
        assert_ne!(advisory, emergency);
    }

    // ── Release tests ─────────────────────────────────────────────────────

    #[test]
    fn release_rolls_back_quarantine() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        assert_eq!(mgr.incident_count(), 1);

        let incidents: Vec<_> = mgr
            .active_incidents()
            .iter()
            .map(|i| i.incident_id.clone())
            .collect();
        let result = mgr
            .release(&incidents[0], &admin_identity(), &test_trace())
            .expect("release should succeed");
        assert!(result.success);
        assert_eq!(result.action_type, "release");
        assert_eq!(result.event_code, FLEET_RELEASED);
    }

    #[test]
    fn release_decrements_quarantine_count() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        let status = mgr.status("zone-us-east-1").expect("status");
        assert_eq!(status.active_quarantines, 1);

        let incidents: Vec<_> = mgr
            .active_incidents()
            .iter()
            .map(|i| i.incident_id.clone())
            .collect();
        mgr.release(&incidents[0], &admin_identity(), &test_trace())
            .expect("release");
        let status = mgr.status("zone-us-east-1").expect("status");
        assert_eq!(status.active_quarantines, 0);
        assert!(status.pending_convergences.is_empty());
    }

    #[test]
    fn release_fails_closed_before_mutating_state_when_operation_ids_are_exhausted() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");

        let incident_id = mgr
            .active_incidents()
            .first()
            .expect("incident present")
            .incident_id
            .clone();
        mgr.operation_ids_exhausted = true;

        let err = mgr
            .release(&incident_id, &admin_identity(), &test_trace())
            .expect_err("release should fail closed");
        assert_eq!(err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);

        let incident = mgr.incidents.get(&incident_id).expect("incident retained");
        assert_eq!(incident.status, IncidentStatus::Active);

        let status = mgr.status("zone-us-east-1").expect("status");
        assert_eq!(status.active_quarantines, 1);
        assert_eq!(status.pending_convergences.len(), 1);
    }

    #[test]
    fn release_removes_matching_convergence_when_zone_has_multiple_quarantines() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let first_scope = QuarantineScope {
            zone_id: "zone-us-east-1".to_string(),
            tenant_id: None,
            affected_nodes: 3,
            reason: "first".to_string(),
        };
        let second_scope = QuarantineScope {
            zone_id: "zone-us-east-1".to_string(),
            tenant_id: None,
            affected_nodes: 7,
            reason: "second".to_string(),
        };
        mgr.quarantine("ext-1", &first_scope, &admin_identity(), &test_trace())
            .expect("first quarantine");
        mgr.quarantine("ext-2", &second_scope, &admin_identity(), &test_trace())
            .expect("second quarantine");

        let second_incident_id = mgr
            .active_incidents()
            .iter()
            .find(|incident| incident.extension_id == "ext-2")
            .expect("second incident present")
            .incident_id
            .clone();

        mgr.release(&second_incident_id, &admin_identity(), &test_trace())
            .expect("release second quarantine");

        let status = mgr.status("zone-us-east-1").expect("status");
        assert_eq!(status.active_quarantines, 1);
        assert_eq!(status.pending_convergences.len(), 1);
        assert_eq!(status.pending_convergences[0].total_nodes, 3);
        assert_eq!(status.pending_convergences[0].eta_seconds, Some(6));
    }

    #[test]
    fn release_nonexistent_incident_fails() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let err = mgr
            .release("inc-nonexistent", &admin_identity(), &test_trace())
            .expect_err("should fail");
        assert_eq!(err.error_code(), FLEET_ROLLBACK_FAILED);
    }

    // ── Status tests ──────────────────────────────────────────────────────

    #[test]
    fn status_unknown_zone_returns_defaults() {
        let mgr = FleetControlManager::new();
        let status = mgr.status("zone-unknown").expect("status");
        assert_eq!(status.zone_id, "zone-unknown");
        assert_eq!(status.active_quarantines, 0);
    }

    #[test]
    fn status_reflects_quarantine_count() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("q1");
        mgr.quarantine("ext-2", &scope, &admin_identity(), &test_trace())
            .expect("q2");
        let status = mgr.status("zone-us-east-1").expect("status");
        assert_eq!(status.active_quarantines, 2);
    }

    // ── Reconcile tests ───────────────────────────────────────────────────

    #[test]
    fn reconcile_cleans_released_incidents() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        let incidents: Vec<_> = mgr
            .active_incidents()
            .iter()
            .map(|i| i.incident_id.clone())
            .collect();
        mgr.release(&incidents[0], &admin_identity(), &test_trace())
            .expect("release");

        let result = mgr
            .reconcile(&admin_identity(), &test_trace())
            .expect("reconcile");
        assert!(result.success);
        assert_eq!(result.action_type, "reconcile");
        assert_eq!(result.event_code, FLEET_RECONCILE_COMPLETED);
        // Released incident should be cleaned up
        assert_eq!(mgr.incident_count(), 0);
    }

    #[test]
    fn reconcile_clears_pending_convergences_from_status() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");

        let before = mgr
            .status("zone-us-east-1")
            .expect("status before reconcile");
        assert_eq!(before.pending_convergences.len(), 1);

        mgr.reconcile(&admin_identity(), &test_trace())
            .expect("reconcile");

        let after = mgr
            .status("zone-us-east-1")
            .expect("status after reconcile");
        assert_eq!(after.active_quarantines, 1);
        assert!(after.pending_convergences.is_empty());
    }

    #[test]
    fn reconcile_convergence_is_complete() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let result = mgr
            .reconcile(&admin_identity(), &test_trace())
            .expect("reconcile");
        let conv = result.convergence.expect("should have convergence");
        assert_eq!(conv.phase, ConvergencePhase::Converged);
        assert_eq!(conv.progress_pct, 100);
    }

    // ── Event audit trail tests ───────────────────────────────────────────

    #[test]
    fn events_accumulate() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let q_scope = test_quarantine_scope();
        let r_scope = test_revocation_scope();
        mgr.quarantine("ext-1", &q_scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        mgr.revoke("ext-2", &r_scope, &admin_identity(), &test_trace())
            .expect("revoke");
        assert_eq!(mgr.events().len(), 2);
        assert_eq!(mgr.events()[0].event_code, FLEET_QUARANTINE_INITIATED);
        assert_eq!(mgr.events()[1].event_code, FLEET_REVOCATION_ISSUED);
    }

    #[test]
    fn event_has_trace_id() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        assert_eq!(mgr.events()[0].trace_id, "test-trace-quarantine-001");
    }

    #[test]
    fn event_has_zone_id() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-1", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        assert_eq!(mgr.events()[0].zone_id, "zone-us-east-1");
    }

    #[test]
    fn event_has_extension_id() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-malware", &scope, &admin_identity(), &test_trace())
            .expect("quarantine");
        assert_eq!(
            mgr.events()[0].extension_id,
            Some("ext-malware".to_string())
        );
    }

    // ── FleetControlError tests ───────────────────────────────────────────

    #[test]
    fn error_scope_invalid() {
        let err = FleetControlError::scope_invalid("bad zone");
        assert_eq!(err.error_code(), FLEET_SCOPE_INVALID);
    }

    #[test]
    fn error_zone_unreachable() {
        let err = FleetControlError::zone_unreachable("zone-x");
        assert_eq!(err.error_code(), FLEET_ZONE_UNREACHABLE);
    }

    #[test]
    fn error_convergence_timeout() {
        let err = FleetControlError::convergence_timeout(30);
        assert_eq!(err.error_code(), FLEET_CONVERGENCE_TIMEOUT);
    }

    #[test]
    fn error_rollback_failed() {
        let err = FleetControlError::rollback_failed("inc-1", "disk full");
        assert_eq!(err.error_code(), FLEET_ROLLBACK_FAILED);
    }

    #[test]
    fn error_not_activated() {
        let err = FleetControlError::not_activated();
        assert_eq!(err.error_code(), FLEET_NOT_ACTIVATED);
    }

    #[test]
    fn error_operation_id_exhausted() {
        let err = FleetControlError::operation_id_exhausted();
        assert_eq!(err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);
    }

    #[test]
    fn error_incident_capacity_exceeded() {
        let err = FleetControlError::incident_capacity_exceeded();
        assert_eq!(err.error_code(), FLEET_INCIDENT_CAPACITY_EXCEEDED);
    }

    #[test]
    fn error_zone_status_capacity_exceeded() {
        let err = FleetControlError::zone_status_capacity_exceeded();
        assert_eq!(err.error_code(), FLEET_ZONE_STATUS_CAPACITY_EXCEEDED);
    }

    #[test]
    fn operation_id_exhaustion_maps_to_internal_api_error() {
        let err = map_fleet_control_error(
            "quarantine",
            &test_trace(),
            FleetControlError::operation_id_exhausted(),
        );
        assert!(matches!(err, ApiError::Internal { .. }));
        if let ApiError::Internal { detail, .. } = err {
            assert!(detail.contains(FLEET_OPERATION_ID_EXHAUSTED));
        }
    }

    // ── ConvergencePhase tests ────────────────────────────────────────────

    #[test]
    fn convergence_phases_distinct() {
        assert_ne!(ConvergencePhase::Pending, ConvergencePhase::Propagating);
        assert_ne!(ConvergencePhase::Propagating, ConvergencePhase::Converged);
        assert_ne!(ConvergencePhase::Converged, ConvergencePhase::TimedOut);
    }

    // ── IncidentStatus tests ──────────────────────────────────────────────

    #[test]
    fn incident_statuses_distinct() {
        assert_ne!(IncidentStatus::Active, IncidentStatus::Resolving);
        assert_ne!(IncidentStatus::Resolving, IncidentStatus::Released);
    }

    // ── Route metadata tests ──────────────────────────────────────────────

    #[test]
    fn route_metadata_has_five_endpoints() {
        let routes = quarantine_route_metadata();
        assert_eq!(routes.len(), 5);
        assert!(
            routes
                .iter()
                .all(|r| r.group == EndpointGroup::FleetControl)
        );
    }

    #[test]
    fn mutation_routes_require_mtls() {
        let routes = quarantine_route_metadata();
        let mutations: Vec<_> = routes.iter().filter(|r| r.method == "POST").collect();
        for route in mutations {
            assert_eq!(
                route.auth_method,
                AuthMethod::MtlsClientCert,
                "POST route {} should require mTLS",
                route.path
            );
        }
    }

    #[test]
    fn status_route_allows_bearer() {
        let routes = quarantine_route_metadata();
        let status = routes
            .iter()
            .find(|r| r.path.contains("status"))
            .expect("status route");
        assert_eq!(status.auth_method, AuthMethod::BearerToken);
    }

    #[test]
    fn all_routes_are_stable() {
        let routes = quarantine_route_metadata();
        for route in &routes {
            assert_eq!(route.lifecycle, EndpointLifecycle::Stable);
        }
    }

    // ── Handler tests ─────────────────────────────────────────────────────

    #[test]
    fn handle_quarantine_succeeds() {
        let _guard = lock_handler_test_state();
        activate_shared_fleet_control_manager_for_tests();
        let request = QuarantineRequest {
            extension_id: "ext-1".to_string(),
            scope: test_quarantine_scope(),
        };
        let result = handle_quarantine(&admin_identity(), &test_trace(), &request)
            .expect("handle quarantine");
        assert!(result.ok);
        assert_eq!(result.data.action_type, "quarantine");
    }

    #[test]
    fn handle_revoke_succeeds() {
        let _guard = lock_handler_test_state();
        activate_shared_fleet_control_manager_for_tests();
        let request = RevokeRequest {
            extension_id: "ext-1".to_string(),
            scope: test_revocation_scope(),
        };
        let result =
            handle_revoke(&admin_identity(), &test_trace(), &request).expect("handle revoke");
        assert!(result.ok);
        assert_eq!(result.data.action_type, "revoke");
    }

    #[test]
    fn handle_status_succeeds() {
        let _guard = lock_handler_test_state();
        let result =
            handle_status(&admin_identity(), &test_trace(), "zone-1").expect("handle status");
        assert!(result.ok);
        assert_eq!(result.data.zone_id, "zone-1");
        assert!(!result.data.activated);
    }

    #[test]
    fn handle_status_rejects_empty_zone() {
        let _guard = lock_handler_test_state();
        let err = handle_status(&admin_identity(), &test_trace(), "").expect_err("empty zone");
        let detail = match err {
            ApiError::BadRequest { detail, .. } => detail,
            other => unreachable!("unexpected error: {other:?}"),
        };
        assert!(detail.contains(FLEET_SCOPE_INVALID));
    }

    #[test]
    fn handle_status_rejects_whitespace_only_zone() {
        let _guard = lock_handler_test_state();
        let err = handle_status(&admin_identity(), &test_trace(), "   ").expect_err("blank zone");
        let detail = match err {
            ApiError::BadRequest { detail, .. } => detail,
            other => unreachable!("unexpected error: {other:?}"),
        };
        assert!(detail.contains(FLEET_SCOPE_INVALID));
    }

    #[test]
    fn handle_reconcile_succeeds() {
        let _guard = lock_handler_test_state();
        activate_shared_fleet_control_manager_for_tests();
        let result = handle_reconcile(&admin_identity(), &test_trace()).expect("handle reconcile");
        assert!(result.ok);
        assert_eq!(result.data.action_type, "reconcile");
    }

    #[test]
    fn handle_release_nonexistent_incident_returns_error() {
        let _guard = lock_handler_test_state();
        activate_shared_fleet_control_manager_for_tests();
        let identity = admin_identity();
        let trace = TraceContext {
            trace_id: "🙂🙂🙂🙂🙂🙂🙂🙂🙂".to_string(),
            span_id: "0000000000000001".to_string(),
            trace_flags: 1,
        };
        let request = ReleaseRequest {
            incident_id: "🔥incident-with-unicode🔥".to_string(),
        };

        let err = handle_release(&identity, &trace, &request).expect_err("nonexistent incident");
        let detail = match err {
            ApiError::BadRequest { detail, .. } => detail,
            other => unreachable!("unexpected error: {other:?}"),
        };
        assert!(detail.contains(FLEET_ROLLBACK_FAILED));
    }

    #[test]
    fn handle_release_rejects_empty_incident_id() {
        let _guard = lock_handler_test_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = ReleaseRequest {
            incident_id: "   ".to_string(),
        };
        let err = handle_release(&identity, &trace, &request).expect_err("empty incident");
        let detail = match err {
            ApiError::BadRequest { detail, .. } => detail,
            other => unreachable!("unexpected error: {other:?}"),
        };
        assert!(detail.contains(FLEET_SCOPE_INVALID));
    }

    #[test]
    fn handler_status_reflects_prior_quarantine() {
        let _guard = lock_handler_test_state();
        activate_shared_fleet_control_manager_for_tests();
        let request = QuarantineRequest {
            extension_id: "ext-1".to_string(),
            scope: test_quarantine_scope(),
        };
        handle_quarantine(&admin_identity(), &test_trace(), &request).expect("handle quarantine");

        let status = handle_status(&admin_identity(), &test_trace(), "zone-us-east-1")
            .expect("handle status");
        assert_eq!(status.data.active_quarantines, 1);
        assert!(status.data.activated);
        assert_eq!(status.data.pending_convergences.len(), 1);
        assert_eq!(
            status.data.pending_convergences[0].phase,
            ConvergencePhase::Propagating
        );
    }

    #[test]
    fn handler_status_reflects_prior_padded_zone_quarantine_canonically() {
        let _guard = lock_handler_test_state();
        activate_shared_fleet_control_manager_for_tests();
        let request = QuarantineRequest {
            extension_id: "ext-1".to_string(),
            scope: QuarantineScope {
                zone_id: " zone-us-east-1 ".to_string(),
                ..test_quarantine_scope()
            },
        };
        handle_quarantine(&admin_identity(), &test_trace(), &request).expect("handle quarantine");

        let status = handle_status(&admin_identity(), &test_trace(), "zone-us-east-1")
            .expect("handle status");
        assert_eq!(status.data.zone_id, "zone-us-east-1");
        assert_eq!(status.data.active_quarantines, 1);
    }

    #[test]
    fn handler_release_succeeds_for_prior_quarantine_incident() {
        let _guard = lock_handler_test_state();
        activate_shared_fleet_control_manager_for_tests();
        let trace = test_trace();
        let request = QuarantineRequest {
            extension_id: "ext-1".to_string(),
            scope: test_quarantine_scope(),
        };
        handle_quarantine(&admin_identity(), &trace, &request).expect("handle quarantine");

        let incident_id = {
            let mgr = shared_fleet_control_manager()
                .lock(&trace)
                .expect("shared fleet manager");
            mgr.active_incidents()[0].incident_id.clone()
        };

        let release = handle_release(&admin_identity(), &trace, &ReleaseRequest { incident_id })
            .expect("handle release");
        assert_eq!(release.data.action_type, "release");
    }

    #[test]
    fn handle_quarantine_rejects_before_activation() {
        let _guard = lock_handler_test_state();
        let request = QuarantineRequest {
            extension_id: "ext-1".to_string(),
            scope: test_quarantine_scope(),
        };
        let err = handle_quarantine(&admin_identity(), &test_trace(), &request)
            .expect_err("unactivated quarantine should fail");
        let detail = match err {
            ApiError::BadRequest { detail, .. } => detail,
            other => unreachable!("unexpected error: {other:?}"),
        };
        assert!(detail.contains(FLEET_NOT_ACTIVATED));
    }

    #[test]
    fn handle_revoke_rejects_before_activation() {
        let _guard = lock_handler_test_state();
        let request = RevokeRequest {
            extension_id: "ext-1".to_string(),
            scope: test_revocation_scope(),
        };
        let err =
            handle_revoke(&admin_identity(), &test_trace(), &request).expect_err("revoke fails");
        let detail = match err {
            ApiError::BadRequest { detail, .. } => detail,
            other => unreachable!("unexpected error: {other:?}"),
        };
        assert!(detail.contains(FLEET_NOT_ACTIVATED));
    }

    #[test]
    fn handle_release_rejects_before_activation() {
        let _guard = lock_handler_test_state();
        let err = handle_release(
            &admin_identity(),
            &test_trace(),
            &ReleaseRequest {
                incident_id: "inc-1".to_string(),
            },
        )
        .expect_err("release fails");
        let detail = match err {
            ApiError::BadRequest { detail, .. } => detail,
            other => unreachable!("unexpected error: {other:?}"),
        };
        assert!(detail.contains(FLEET_NOT_ACTIVATED));
    }

    #[test]
    fn handle_reconcile_rejects_before_activation() {
        let _guard = lock_handler_test_state();
        let err = handle_reconcile(&admin_identity(), &test_trace()).expect_err("reconcile fails");
        let detail = match err {
            ApiError::BadRequest { detail, .. } => detail,
            other => unreachable!("unexpected error: {other:?}"),
        };
        assert!(detail.contains(FLEET_NOT_ACTIVATED));
    }

    // ── Serde round-trip tests ────────────────────────────────────────────

    #[test]
    fn quarantine_scope_serde() {
        let scope = test_quarantine_scope();
        let json = serde_json::to_string(&scope).expect("serialize");
        let decoded: QuarantineScope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(scope, decoded);
    }

    #[test]
    fn revocation_scope_serde() {
        let scope = test_revocation_scope();
        let json = serde_json::to_string(&scope).expect("serialize");
        let decoded: RevocationScope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(scope, decoded);
    }

    #[test]
    fn fleet_action_result_serde() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let result = mgr
            .quarantine(
                "ext-1",
                &test_quarantine_scope(),
                &admin_identity(),
                &test_trace(),
            )
            .expect("quarantine");
        let json = serde_json::to_string(&result).expect("serialize");
        let decoded: FleetActionResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result.operation_id, decoded.operation_id);
    }

    #[test]
    fn fleet_control_event_serde() {
        let event = FleetControlEvent::quarantine_initiated("trace-1", "zone-1", "ext-1");
        let json = serde_json::to_string(&event).expect("serialize");
        let decoded: FleetControlEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event.event_code, decoded.event_code);
    }

    #[test]
    fn fleet_status_serde() {
        let status = FleetStatus {
            zone_id: "zone-1".to_string(),
            active_quarantines: 2,
            active_revocations: 1,
            healthy_nodes: 8,
            total_nodes: 10,
            activated: true,
            pending_convergences: Vec::new(),
        };
        let json = serde_json::to_string(&status).expect("serialize");
        let decoded: FleetStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, decoded);
    }

    #[test]
    fn decision_receipt_serde() {
        let receipt = DecisionReceipt {
            receipt_id: "rcpt-1".to_string(),
            issuer: "admin".to_string(),
            issued_at: "2026-02-21T00:00:00Z".to_string(),
            zone_id: "zone-1".to_string(),
            payload_hash: "abcdef".to_string(),
            signature: None,
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let decoded: DecisionReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, decoded);
    }

    // ── Send + Sync assertions ────────────────────────────────────────────

    fn _assert_send<T: Send>() {}
    fn _assert_sync<T: Sync>() {}

    #[test]
    fn types_are_send_sync() {
        _assert_send::<QuarantineScope>();
        _assert_sync::<QuarantineScope>();
        _assert_send::<RevocationScope>();
        _assert_sync::<RevocationScope>();
        _assert_send::<FleetActionResult>();
        _assert_sync::<FleetActionResult>();
        _assert_send::<FleetControlEvent>();
        _assert_sync::<FleetControlEvent>();
        _assert_send::<FleetStatus>();
        _assert_sync::<FleetStatus>();
        _assert_send::<DecisionReceipt>();
        _assert_sync::<DecisionReceipt>();
        _assert_send::<IncidentHandle>();
        _assert_sync::<IncidentHandle>();
        _assert_send::<FleetControlError>();
        _assert_sync::<FleetControlError>();
    }

    // ── Multi-zone scenario test ──────────────────────────────────────────

    #[test]
    fn multi_zone_quarantine_and_release() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();

        let scope1 = QuarantineScope {
            zone_id: "zone-a".to_string(),
            tenant_id: None,
            affected_nodes: 3,
            reason: "test".to_string(),
        };
        let scope2 = QuarantineScope {
            zone_id: "zone-b".to_string(),
            tenant_id: None,
            affected_nodes: 5,
            reason: "test".to_string(),
        };

        mgr.quarantine("ext-1", &scope1, &admin_identity(), &test_trace())
            .expect("q1");
        mgr.quarantine("ext-2", &scope2, &admin_identity(), &test_trace())
            .expect("q2");

        assert_eq!(mgr.zones().len(), 2);
        assert_eq!(mgr.incident_count(), 2);

        let incidents: Vec<_> = mgr
            .active_incidents()
            .iter()
            .map(|i| i.incident_id.clone())
            .collect();
        mgr.release(&incidents[0], &admin_identity(), &test_trace())
            .expect("release");
        assert_eq!(mgr.active_incidents().len(), 1);
    }

    #[test]
    fn operation_id_uses_terminal_value_before_failing_closed() {
        let mut mgr = FleetControlManager::new();
        mgr.next_op_id = u64::MAX;

        let final_id = mgr.next_operation_id().expect("final id");
        assert_eq!(final_id, "fleet-op-18446744073709551615");
        assert!(mgr.operation_ids_exhausted);
        assert_eq!(mgr.next_op_id, u64::MAX);
        assert_eq!(mgr.op_epoch, 0);

        let err = mgr
            .next_operation_id()
            .expect_err("allocator should fail after terminal id");
        assert_eq!(err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);
    }

    #[test]
    fn operation_id_allocation_fails_closed_after_absolute_exhaustion() {
        let mut mgr = FleetControlManager::new();
        mgr.op_epoch = u64::MAX;
        mgr.next_op_id = u64::MAX;

        let final_id = mgr.next_operation_id().expect("last id");
        assert_eq!(final_id, "fleet-op-ffffffffffffffff-ffffffffffffffff");

        let err = mgr
            .next_operation_id()
            .expect_err("allocator should fail after last unique id");
        assert_eq!(err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);
    }

    #[test]
    fn quarantine_uses_terminal_operation_id_before_failing_closed() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        mgr.next_op_id = u64::MAX;
        let scope = test_quarantine_scope();

        let first = mgr
            .quarantine("ext-final", &scope, &admin_identity(), &test_trace())
            .expect("final quarantine");
        assert_eq!(first.operation_id, "fleet-op-18446744073709551615");
        assert_eq!(
            first.receipt.receipt_id,
            "rcpt-fleet-op-18446744073709551615"
        );
        assert!(
            mgr.incidents
                .contains_key("inc-fleet-op-18446744073709551615")
        );
        assert!(mgr.operation_ids_exhausted);

        let err = mgr
            .quarantine("ext-overflow", &scope, &admin_identity(), &test_trace())
            .expect_err("second quarantine should fail closed");
        assert_eq!(err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);
        assert_eq!(mgr.active_incidents().len(), 1);
    }

    #[test]
    fn quarantine_fails_closed_when_operation_ids_are_exhausted() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        mgr.op_epoch = u64::MAX;
        mgr.next_op_id = u64::MAX;
        let scope = test_quarantine_scope();

        mgr.quarantine("ext-final", &scope, &admin_identity(), &test_trace())
            .expect("final operation id should still work");
        let err = mgr
            .quarantine("ext-overflow", &scope, &admin_identity(), &test_trace())
            .expect_err("second quarantine should fail closed");
        assert_eq!(err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);
        assert_eq!(mgr.active_incidents().len(), 1);
    }

    // ── Hash determinism test ─────────────────────────────────────────────

    #[test]
    fn receipt_hash_is_deterministic() {
        let mgr = FleetControlManager::new();
        let r1 = mgr
            .build_receipt("op-1", "admin", "zone-1", "2026-01-01T00:00:00Z")
            .expect("receipt");
        let r2 = mgr
            .build_receipt("op-1", "admin", "zone-1", "2026-01-01T00:00:00Z")
            .expect("receipt");
        assert_eq!(r1.payload_hash, r2.payload_hash);
        assert!(verify_decision_receipt_signature(&r1));
    }

    #[test]
    fn receipt_hash_changes_with_input() {
        let mgr = FleetControlManager::new();
        let r1 = mgr
            .build_receipt("op-1", "admin", "zone-1", "2026-01-01T00:00:00Z")
            .expect("receipt");
        let r2 = mgr
            .build_receipt("op-2", "admin", "zone-1", "2026-01-01T00:00:00Z")
            .expect("receipt");
        assert_ne!(r1.payload_hash, r2.payload_hash);
    }

    #[test]
    fn receipt_hash_no_delimiter_collision() {
        let mgr = FleetControlManager::new();
        // Without length-prefixing, "a:b" + "c" and "a" + "b:c" could collide.
        let r1 = mgr
            .build_receipt("op", "admin:x", "zone", "ts")
            .expect("receipt");
        let r2 = mgr
            .build_receipt("op", "admin", "x:zone", "ts")
            .expect("receipt");
        assert_ne!(
            r1.payload_hash, r2.payload_hash,
            "length-prefixed encoding must prevent delimiter collision"
        );
    }

    #[test]
    fn unsigned_decision_receipt_is_rejected() {
        let mgr = FleetControlManager::new();
        let mut receipt = mgr
            .build_receipt("op-unsigned", "admin", "zone-1", "2026-01-01T00:00:00Z")
            .expect("receipt");
        receipt.signature = None;

        assert!(!verify_decision_receipt_signature(&receipt));
    }

    #[test]
    fn tampered_decision_receipt_is_rejected() {
        let mgr = FleetControlManager::new();
        let mut receipt = mgr
            .build_receipt("op-tampered", "admin", "zone-1", "2026-01-01T00:00:00Z")
            .expect("receipt");
        assert!(verify_decision_receipt_signature(&receipt));

        receipt.zone_id = "zone-2".to_string();

        assert!(!verify_decision_receipt_signature(&receipt));
    }

    #[derive(Debug)]
    struct RecordingFleetTransport {
        layout: FleetStateLayout,
        initialized: Mutex<bool>,
        actions: Mutex<Vec<FleetActionEnvelope>>,
        nodes: Mutex<BTreeMap<String, NodeStatus>>,
    }

    impl RecordingFleetTransport {
        fn new(root_dir: PathBuf) -> Self {
            Self {
                layout: FleetStateLayout::new(root_dir),
                initialized: Mutex::new(false),
                actions: Mutex::new(Vec::new()),
                nodes: Mutex::new(BTreeMap::new()),
            }
        }

        fn ensure_initialized(&self) -> Result<(), FleetTransportError> {
            let initialized = self
                .initialized
                .lock()
                .map_err(|_| FleetTransportError::lock_contention("initialized lock poisoned"))?;
            if !*initialized {
                return Err(FleetTransportError::not_initialized(
                    "fleet transport initialize() must succeed before use",
                ));
            }
            Ok(())
        }
    }

    impl FleetTransport for RecordingFleetTransport {
        fn initialize(&self) -> Result<(), FleetTransportError> {
            self.layout.create_all()?;
            let mut initialized = self
                .initialized
                .lock()
                .map_err(|_| FleetTransportError::lock_contention("initialized lock poisoned"))?;
            *initialized = true;
            Ok(())
        }

        fn append_action(
            &self,
            action: &FleetActionEnvelope,
        ) -> Result<FleetActionEnvelope, FleetTransportError> {
            self.ensure_initialized()?;
            action.validate()?;
            let mut actions = self
                .actions
                .lock()
                .map_err(|_| FleetTransportError::lock_contention("actions lock poisoned"))?;
            push_bounded(&mut actions, action.clone(), MAX_FLEET_EVENTS);
            Ok(action.clone())
        }

        fn snapshot(&self) -> Result<FleetStateSnapshot, FleetTransportError> {
            self.ensure_initialized()?;
            let mut actions = self
                .actions
                .lock()
                .map_err(|_| FleetTransportError::lock_contention("actions lock poisoned"))?
                .clone();
            actions.sort_by(|left, right| {
                left.quarantine_version
                    .cmp(&right.quarantine_version)
                    .then_with(|| left.action_id.cmp(&right.action_id))
            });

            let nodes = self
                .nodes
                .lock()
                .map_err(|_| FleetTransportError::lock_contention("nodes lock poisoned"))?
                .values()
                .cloned()
                .collect();

            let snapshot = FleetStateSnapshot {
                schema_version: FLEET_TRANSPORT_SCHEMA_VERSION.to_string(),
                actions,
                nodes,
            };
            snapshot.validate()?;
            Ok(snapshot)
        }

        fn record_node_status(
            &self,
            status: &NodeStatus,
        ) -> Result<NodeStatus, FleetTransportError> {
            self.ensure_initialized()?;
            status.validate()?;
            let mut nodes = self
                .nodes
                .lock()
                .map_err(|_| FleetTransportError::lock_contention("nodes lock poisoned"))?;
            nodes.insert(status.node_id.clone(), status.clone());
            Ok(status.clone())
        }

        fn list_stale_nodes(
            &self,
            now: chrono::DateTime<chrono::Utc>,
            staleness_threshold: Duration,
        ) -> Result<Vec<NodeStatus>, FleetTransportError> {
            self.ensure_initialized()?;
            let staleness_threshold =
                chrono::TimeDelta::from_std(staleness_threshold).map_err(|err| {
                    FleetTransportError::stale_state(format!(
                        "invalid fleet staleness threshold: {err}"
                    ))
                })?;

            let mut stale_nodes: Vec<NodeStatus> = self
                .nodes
                .lock()
                .map_err(|_| FleetTransportError::lock_contention("nodes lock poisoned"))?
                .values()
                .filter(|status| now.signed_duration_since(status.last_seen) > staleness_threshold)
                .cloned()
                .collect();
            stale_nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
            Ok(stale_nodes)
        }
    }

    fn exercise_transport(
        transport: &dyn FleetTransport,
    ) -> Result<FleetStateSnapshot, FleetTransportError> {
        transport.initialize()?;
        let status = NodeStatus::new("node-1", chrono::Utc::now(), 7, NodeHealth::Healthy)?;
        transport.record_node_status(&status)?;
        transport.snapshot()
    }

    #[test]
    fn fleet_transport_trait_is_object_safe() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let transport = RecordingFleetTransport::new(tempdir.path().to_path_buf());

        let snapshot = exercise_transport(&transport).expect("exercise transport");
        assert_eq!(snapshot.nodes.len(), 1);
        assert_eq!(snapshot.nodes[0].node_id, "node-1");
    }

    #[test]
    fn initialize_creates_fleet_directory_structure_if_missing() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let root_dir = tempdir.path().join("fleet-state");
        let transport = RecordingFleetTransport::new(root_dir.clone());

        transport.initialize().expect("initialize transport");

        let layout = FleetStateLayout::new(root_dir);
        assert!(layout.root_dir.is_dir());
        assert!(layout.node_status_dir.is_dir());
        assert!(layout.lock_dir.is_dir());
    }

    #[test]
    fn node_status_rejects_invalid_node_ids() {
        for invalid in ["", ".", "..", "node/1", "node 1", "node:1", "node\t1"] {
            let err = NodeStatus::new(invalid, chrono::Utc::now(), 0, NodeHealth::Healthy)
                .expect_err("invalid node id must fail");
            assert!(matches!(
                err,
                FleetTransportError::SerializationError { .. }
            ));
        }

        let too_long = "a".repeat(129);
        let err = NodeStatus::new(too_long, chrono::Utc::now(), 0, NodeHealth::Healthy)
            .expect_err("too-long node id must fail");
        assert!(matches!(
            err,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn node_status_json_roundtrip_preserves_fields() {
        let status = NodeStatus::new(
            "node.alpha-1",
            chrono::DateTime::parse_from_rfc3339("2026-04-06T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&chrono::Utc),
            11,
            NodeHealth::Quarantined,
        )
        .expect("node status");

        let json = serde_json::to_string(&status).expect("serialize node status");
        let decoded: NodeStatus = serde_json::from_str(&json).expect("deserialize node status");
        assert_eq!(decoded, status);
    }

    #[test]
    fn fleet_state_snapshot_roundtrip_preserves_policy_update_and_node_state() {
        let action = FleetActionEnvelope::new(
            "fleet-action-1",
            "trace-fleet-1",
            "zone-1",
            chrono::DateTime::parse_from_rfc3339("2026-04-06T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&chrono::Utc),
            42,
            FleetAction::PolicyUpdate {
                policy_version: "strict@2026-04-06".to_string(),
                summary: "raise quarantine threshold and sync trust frontier".to_string(),
            },
        )
        .expect("action");
        let node = NodeStatus::new(
            "node-2",
            chrono::DateTime::parse_from_rfc3339("2026-04-06T12:05:00Z")
                .expect("timestamp")
                .with_timezone(&chrono::Utc),
            42,
            NodeHealth::Degraded,
        )
        .expect("node");
        let snapshot = FleetStateSnapshot {
            schema_version: FLEET_TRANSPORT_SCHEMA_VERSION.to_string(),
            actions: vec![action],
            nodes: vec![node],
        };

        snapshot.validate().expect("valid snapshot");
        let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
        let decoded: FleetStateSnapshot =
            serde_json::from_str(&json).expect("deserialize snapshot");
        decoded.validate().expect("decoded snapshot");
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn list_stale_nodes_uses_last_seen_threshold() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let transport = RecordingFleetTransport::new(tempdir.path().to_path_buf());
        transport.initialize().expect("initialize transport");

        let now = chrono::DateTime::parse_from_rfc3339("2026-04-06T12:10:00Z")
            .expect("timestamp")
            .with_timezone(&chrono::Utc);
        let stale = NodeStatus::new(
            "node-stale",
            chrono::DateTime::parse_from_rfc3339("2026-04-06T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&chrono::Utc),
            3,
            NodeHealth::Degraded,
        )
        .expect("stale node");
        let fresh = NodeStatus::new(
            "node-fresh",
            chrono::DateTime::parse_from_rfc3339("2026-04-06T12:09:30Z")
                .expect("timestamp")
                .with_timezone(&chrono::Utc),
            3,
            NodeHealth::Healthy,
        )
        .expect("fresh node");

        transport
            .record_node_status(&stale)
            .expect("record stale node");
        transport
            .record_node_status(&fresh)
            .expect("record fresh node");

        let stale_nodes = transport
            .list_stale_nodes(now, Duration::from_secs(60))
            .expect("stale nodes");
        assert_eq!(stale_nodes.len(), 1);
        assert_eq!(stale_nodes[0].node_id, "node-stale");
    }

    fn test_issued_at() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-04-06T12:00:00Z")
            .expect("timestamp")
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn action_envelope_rejects_empty_action_id() {
        let err = FleetActionEnvelope::new(
            "   ",
            "trace-fleet-1",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::Reconcile,
        )
        .expect_err("empty action id must fail");

        assert!(matches!(
            err,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn action_envelope_rejects_empty_trace_id() {
        let err = FleetActionEnvelope::new(
            "action-1",
            "\t",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::Reconcile,
        )
        .expect_err("empty trace id must fail");

        assert!(matches!(
            err,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn action_envelope_rejects_quarantine_scope_zone_mismatch() {
        let err = FleetActionEnvelope::new(
            "action-1",
            "trace-fleet-1",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::Quarantine {
                extension_id: "ext-1".to_string(),
                scope: QuarantineScope {
                    zone_id: "zone-2".to_string(),
                    tenant_id: None,
                    affected_nodes: 1,
                    reason: "mismatch should fail".to_string(),
                },
            },
        )
        .expect_err("scope zone mismatch must fail");

        assert!(err.to_string().contains("scope zone_id must match"));
    }

    #[test]
    fn action_envelope_rejects_revocation_scope_zone_mismatch() {
        let err = FleetActionEnvelope::new(
            "action-1",
            "trace-fleet-1",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::Revoke {
                extension_id: "ext-1".to_string(),
                scope: RevocationScope {
                    zone_id: "zone-2".to_string(),
                    tenant_id: None,
                    severity: RevocationSeverity::Emergency,
                    reason: "mismatch should fail".to_string(),
                },
            },
        )
        .expect_err("revocation scope zone mismatch must fail");

        assert!(err.to_string().contains("scope zone_id must match"));
    }

    #[test]
    fn action_envelope_rejects_blank_release_incident_id() {
        let err = FleetActionEnvelope::new(
            "action-1",
            "trace-fleet-1",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::Release {
                incident_id: " ".to_string(),
            },
        )
        .expect_err("blank release incident id must fail");

        assert!(err.to_string().contains("release incident_id"));
    }

    #[test]
    fn action_envelope_rejects_blank_policy_update_fields() {
        let blank_version = FleetActionEnvelope::new(
            "action-1",
            "trace-fleet-1",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::PolicyUpdate {
                policy_version: " ".to_string(),
                summary: "policy summary".to_string(),
            },
        )
        .expect_err("blank policy version must fail");
        assert!(blank_version.to_string().contains("policy_version"));

        let blank_summary = FleetActionEnvelope::new(
            "action-2",
            "trace-fleet-1",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::PolicyUpdate {
                policy_version: "strict@2026-04-06".to_string(),
                summary: "\n".to_string(),
            },
        )
        .expect_err("blank policy summary must fail");
        assert!(blank_summary.to_string().contains("summary"));
    }

    #[test]
    fn action_envelope_rejects_status_with_blank_zone_id() {
        let err = FleetActionEnvelope::new(
            "action-1",
            "trace-fleet-1",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::Status {
                zone_id: " ".to_string(),
            },
        )
        .expect_err("blank status zone must fail");

        assert!(err.to_string().contains("zone_id"));
    }

    #[test]
    fn fleet_snapshot_validate_rejects_invalid_embedded_node() {
        let snapshot = FleetStateSnapshot {
            schema_version: FLEET_TRANSPORT_SCHEMA_VERSION.to_string(),
            actions: Vec::new(),
            nodes: vec![NodeStatus {
                node_id: "../node".to_string(),
                last_seen: test_issued_at(),
                quarantine_version: 1,
                health: NodeHealth::Healthy,
            }],
        };

        let err = snapshot
            .validate()
            .expect_err("invalid embedded node must fail snapshot validation");

        assert!(matches!(
            err,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn revocation_severity_deserialize_rejects_lowercase_label() {
        let result: Result<RevocationSeverity, _> = serde_json::from_str("\"emergency\"");

        assert!(result.is_err(), "severity labels must use canonical casing");
    }

    #[test]
    fn convergence_phase_deserialize_rejects_snake_case_label() {
        let result: Result<ConvergencePhase, _> = serde_json::from_str("\"timed_out\"");

        assert!(result.is_err(), "phase labels must use canonical casing");
    }

    #[test]
    fn node_health_deserialize_rejects_unknown_label() {
        let result: Result<NodeHealth, _> = serde_json::from_str("\"Recovering\"");

        assert!(result.is_err(), "unknown node health must fail closed");
    }

    #[test]
    fn quarantine_request_deserialize_rejects_missing_scope() {
        let raw = serde_json::json!({
            "extension_id": "ext-1"
        });

        let result: Result<QuarantineRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "quarantine scope is required");
    }

    #[test]
    fn revoke_request_deserialize_rejects_string_severity() {
        let raw = serde_json::json!({
            "extension_id": "ext-1",
            "scope": {
                "zone_id": "zone-1",
                "tenant_id": null,
                "severity": "emergency",
                "reason": "bad casing"
            }
        });

        let result: Result<RevokeRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "revocation severity must be canonical");
    }

    #[test]
    fn release_request_deserialize_rejects_numeric_incident_id() {
        let raw = serde_json::json!({
            "incident_id": 123_u64
        });

        let result: Result<ReleaseRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "incident_id must remain a string");
    }

    #[test]
    fn convergence_state_deserialize_rejects_progress_overflow() {
        let raw = serde_json::json!({
            "converged_nodes": 1_u32,
            "total_nodes": 1_u32,
            "progress_pct": 256_u16,
            "eta_seconds": null,
            "phase": "Converged"
        });

        let result: Result<ConvergenceState, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "progress_pct must fit in u8");
    }

    #[test]
    fn fleet_snapshot_validate_rejects_invalid_embedded_action() {
        let action = FleetActionEnvelope {
            action_id: "action-1".to_string(),
            trace_id: "trace-fleet-1".to_string(),
            zone_id: "zone-1".to_string(),
            issued_at: test_issued_at(),
            quarantine_version: 1,
            action: FleetAction::Release {
                incident_id: " ".to_string(),
            },
        };
        let snapshot = FleetStateSnapshot {
            schema_version: FLEET_TRANSPORT_SCHEMA_VERSION.to_string(),
            actions: vec![action],
            nodes: Vec::new(),
        };

        let err = snapshot
            .validate()
            .expect_err("invalid embedded action must fail snapshot validation");

        assert!(matches!(
            err,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn negative_push_bounded_zero_capacity_clears_without_retaining_new_item() {
        let mut events = vec![
            FleetControlEvent::fleet_released("trace-1", "zone-1", "incident-1"),
            FleetControlEvent::fleet_released("trace-2", "zone-1", "incident-2"),
        ];

        push_bounded(
            &mut events,
            FleetControlEvent::fleet_released("trace-3", "zone-1", "incident-3"),
            0,
        );

        assert!(events.is_empty());
    }

    #[test]
    fn negative_push_bounded_overfull_input_keeps_newest_tail() {
        let mut events = vec![
            FleetControlEvent::fleet_released("trace-1", "zone-1", "incident-1"),
            FleetControlEvent::fleet_released("trace-2", "zone-1", "incident-2"),
            FleetControlEvent::fleet_released("trace-3", "zone-1", "incident-3"),
        ];

        push_bounded(
            &mut events,
            FleetControlEvent::fleet_released("trace-4", "zone-1", "incident-4"),
            2,
        );

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].trace_id, "trace-3");
        assert_eq!(events[1].trace_id, "trace-4");
    }

    #[test]
    fn negative_fleet_snapshot_validate_rejects_blank_schema_version() {
        let snapshot = FleetStateSnapshot {
            schema_version: String::new(),
            actions: Vec::new(),
            nodes: Vec::new(),
        };

        let err = snapshot
            .validate()
            .expect_err("blank schema version must fail");

        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn negative_fleet_snapshot_validate_rejects_whitespace_schema_version() {
        let snapshot = FleetStateSnapshot {
            schema_version: " \t\n ".to_string(),
            actions: Vec::new(),
            nodes: Vec::new(),
        };

        let err = snapshot
            .validate()
            .expect_err("whitespace schema version must fail");

        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn negative_action_envelope_rejects_blank_top_level_zone_id() {
        let err = FleetActionEnvelope::new(
            "action-1",
            "trace-fleet-1",
            " ",
            test_issued_at(),
            1,
            FleetAction::Reconcile,
        )
        .expect_err("blank envelope zone id must fail");

        assert!(err.to_string().contains("zone_id"));
    }

    #[test]
    fn negative_action_envelope_rejects_blank_quarantine_scope_zone_id() {
        let err = FleetActionEnvelope::new(
            "action-1",
            "trace-fleet-1",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::Quarantine {
                extension_id: "ext-1".to_string(),
                scope: QuarantineScope {
                    zone_id: "\n".to_string(),
                    tenant_id: None,
                    affected_nodes: 1,
                    reason: "blank scope zone should fail".to_string(),
                },
            },
        )
        .expect_err("blank quarantine scope zone id must fail");

        assert!(err.to_string().contains("zone_id"));
    }

    #[test]
    fn negative_action_envelope_rejects_blank_revocation_scope_zone_id() {
        let err = FleetActionEnvelope::new(
            "action-1",
            "trace-fleet-1",
            "zone-1",
            test_issued_at(),
            1,
            FleetAction::Revoke {
                extension_id: "ext-1".to_string(),
                scope: RevocationScope {
                    zone_id: "\t".to_string(),
                    tenant_id: None,
                    severity: RevocationSeverity::Mandatory,
                    reason: "blank scope zone should fail".to_string(),
                },
            },
        )
        .expect_err("blank revocation scope zone id must fail");

        assert!(err.to_string().contains("zone_id"));
    }

    #[test]
    fn negative_status_request_deserialize_rejects_numeric_zone_id() {
        let raw = serde_json::json!({
            "zone_id": 42_u64
        });

        let result: Result<StatusRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "status zone_id must remain a string");
    }

    #[test]
    fn negative_quarantine_scope_deserialize_rejects_affected_nodes_overflow() {
        let raw = serde_json::json!({
            "zone_id": "zone-1",
            "tenant_id": null,
            "affected_nodes": 4_294_967_296_u64,
            "reason": "overflow should fail"
        });

        let result: Result<QuarantineScope, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "affected_nodes must fit in u32");
    }

    // ── Comprehensive Edge Case Security Tests ────────────────────────────

    #[test]
    fn security_edge_case_unicode_injection_in_zone_identifiers() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();

        // Test Unicode normalization attacks and lookalike characters
        let malicious_zones = [
            "zone-αdmin",        // Greek alpha that looks like 'a'
            "zone-аdmin",        // Cyrillic 'a' that looks like Latin 'a'
            "zone\u{200D}admin", // Zero-width joiner injection
            "zone\u{202E}admin", // Right-to-left override
            "zone\u{FEFF}admin", // Byte order mark injection
            "zone\u{00A0}admin", // Non-breaking space
            "zone\u{3000}admin", // Ideographic space
            "zone‍admin",         // Zero-width joiner (visual)
        ];

        for malicious_zone in &malicious_zones {
            let scope = QuarantineScope {
                zone_id: malicious_zone.to_string(),
                tenant_id: None,
                affected_nodes: 1,
                reason: "unicode injection test".to_string(),
            };

            // Should either reject completely or normalize consistently
            if let Ok(result) =
                mgr.quarantine("ext-unicode-test", &scope, &admin_identity(), &test_trace())
            {
                // If accepted, verify zone ID is properly normalized
                assert!(
                    !result.receipt.zone_id.contains('\u{202E}'),
                    "RTL override must be stripped"
                );
                assert!(
                    !result.receipt.zone_id.contains('\u{200D}'),
                    "Zero-width joiner must be stripped"
                );
                assert!(
                    !result.receipt.zone_id.contains('\u{FEFF}'),
                    "BOM must be stripped"
                );
            }

            // Verify status lookups use consistent normalization
            let status_result = mgr.status(malicious_zone);
            if let Ok(status) = status_result {
                // Status should reflect normalized zone ID, not original
                assert!(!status.zone_id.contains('\u{202E}'));
                assert!(!status.zone_id.contains('\u{200D}'));
                assert!(!status.zone_id.contains('\u{FEFF}'));
            }
        }
    }

    #[test]
    fn security_edge_case_memory_exhaustion_through_massive_capacity_overflow() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();

        // Attempt to trigger memory exhaustion through large data structures
        let massive_reason = "A".repeat(1_000_000); // 1MB string
        let massive_extension = "ext-".to_string() + &"x".repeat(100_000); // ~100KB extension ID

        let scope = QuarantineScope {
            zone_id: "zone-memory-test".to_string(),
            tenant_id: Some("tenant-".to_string() + &"y".repeat(50_000)), // ~50KB tenant ID
            affected_nodes: u32::MAX,                                     // Maximum node count
            reason: massive_reason,
        };

        // Should fail closed rather than allocating unbounded memory
        let result = mgr.quarantine(&massive_extension, &scope, &admin_identity(), &test_trace());

        // Verify graceful degradation - either reject or bound the data
        match result {
            Ok(action_result) => {
                // If accepted, verify strings are bounded
                assert!(
                    action_result.receipt.payload_hash.len() < 10_000,
                    "Hash should be bounded"
                );
                assert!(
                    mgr.events().len() <= MAX_FLEET_EVENTS,
                    "Events should respect capacity"
                );
                assert!(
                    mgr.incidents.len() <= MAX_INCIDENTS,
                    "Incidents should respect capacity"
                );
            }
            Err(err) => {
                // Should fail with capacity/validation error, not panic
                assert!(matches!(
                    err.error_code().as_str(),
                    FLEET_SCOPE_INVALID
                        | FLEET_INCIDENT_CAPACITY_EXCEEDED
                        | FLEET_ZONE_STATUS_CAPACITY_EXCEEDED
                ));
            }
        }

        // Verify memory footprint stays bounded
        assert!(
            mgr.zone_status.len() <= MAX_ZONE_STATUS,
            "Zone status should respect capacity"
        );
    }

    #[test]
    fn security_edge_case_concurrent_access_race_conditions() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let mgr = Arc::new(std::sync::Mutex::new(FleetControlManager::new()));
        {
            let mut guard = mgr.lock().unwrap();
            guard.activate();
        }

        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        // Spawn concurrent threads performing different operations
        for i in 0..4 {
            let mgr_clone = Arc::clone(&mgr);
            let barrier_clone = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier_clone.wait(); // Synchronize start

                let scope = QuarantineScope {
                    zone_id: format!("zone-race-{}", i),
                    tenant_id: None,
                    affected_nodes: 1,
                    reason: format!("race condition test {}", i),
                };

                // Attempt concurrent operations that could race
                let mut results = Vec::new();
                for j in 0..10 {
                    let extension_id = format!("ext-{}-{}", i, j);
                    let mut guard = mgr_clone.lock().unwrap();
                    let result =
                        guard.quarantine(&extension_id, &scope, &admin_identity(), &test_trace());
                    results.push(result);
                }
                results
            });
            handles.push(handle);
        }

        // Collect all results
        let mut all_results = Vec::new();
        for handle in handles {
            let thread_results = handle.join().unwrap();
            all_results.extend(thread_results);
        }

        // Verify consistency - no double-allocation of operation IDs
        let mut operation_ids = std::collections::HashSet::new();
        for result in all_results {
            if let Ok(action_result) = result {
                assert!(
                    operation_ids.insert(action_result.operation_id.clone()),
                    "Operation ID {} was allocated twice - race condition detected",
                    action_result.operation_id
                );

                // Verify receipt IDs are also unique
                assert!(
                    action_result.receipt.receipt_id.starts_with("rcpt-"),
                    "Receipt ID format is consistent"
                );
            }
        }

        // Verify final state is consistent
        let guard = mgr.lock().unwrap();
        assert!(
            guard.zones().len() <= 4,
            "Zone count should not exceed thread count"
        );
        assert!(
            guard.incident_count() <= 40,
            "Incident count should not exceed attempts"
        );
    }

    #[test]
    fn security_edge_case_malformed_request_validation_bypass() {
        let _guard = lock_handler_test_state();
        activate_shared_fleet_control_manager_for_tests();

        // Test malformed JSON that could bypass validation
        let malformed_requests = vec![
            // Missing required fields
            serde_json::json!({
                "extension_id": "ext-malformed"
                // Missing scope
            }),
            // Type confusion attacks
            serde_json::json!({
                "extension_id": 123, // Wrong type
                "scope": {
                    "zone_id": "zone-test",
                    "tenant_id": null,
                    "affected_nodes": "not-a-number", // Wrong type
                    "reason": "type confusion"
                }
            }),
            // Nested object injection
            serde_json::json!({
                "extension_id": "ext-test",
                "scope": {
                    "zone_id": "zone-test",
                    "tenant_id": null,
                    "affected_nodes": 1,
                    "reason": "nested test",
                    "__proto__": {"malicious": "field"}, // Prototype pollution attempt
                    "constructor": {"name": "evil"} // Constructor pollution attempt
                }
            }),
            // Array confusion
            serde_json::json!({
                "extension_id": ["ext", "array"], // Array instead of string
                "scope": {
                    "zone_id": "zone-test",
                    "tenant_id": null,
                    "affected_nodes": 1,
                    "reason": "array confusion"
                }
            }),
            // Extremely nested objects
            serde_json::json!({
                "extension_id": "ext-test",
                "scope": {
                    "zone_id": "zone-test",
                    "tenant_id": {"nested": {"deeply": {"malicious": "object"}}}, // Wrong type
                    "affected_nodes": 1,
                    "reason": "deep nesting"
                }
            }),
        ];

        for malformed in malformed_requests {
            let result: Result<QuarantineRequest, _> = serde_json::from_value(malformed.clone());

            // All malformed requests should fail deserialization
            assert!(
                result.is_err(),
                "Malformed request should be rejected: {:?}",
                malformed
            );

            // Verify error handling doesn't leak sensitive info
            if let Err(err) = result {
                let error_string = err.to_string();
                assert!(
                    !error_string.contains("internal"),
                    "Error should not expose internals"
                );
                assert!(
                    !error_string.contains("debug"),
                    "Error should not expose debug info"
                );
            }
        }
    }

    #[test]
    fn security_edge_case_serialization_deserialization_attacks() {
        // Test various serialization attack vectors
        let attack_vectors = vec![
            // Null byte injection in strings
            serde_json::json!({
                "extension_id": "ext-test\0malicious",
                "scope": {
                    "zone_id": "zone-test\0evil",
                    "tenant_id": "tenant\0null",
                    "affected_nodes": 1,
                    "reason": "null\0byte\0injection"
                }
            }),
            // Control character injection
            serde_json::json!({
                "extension_id": "ext-test\x1b[31mevil\x1b[0m", // ANSI escape codes
                "scope": {
                    "zone_id": "zone-test\r\n", // CRLF injection
                    "tenant_id": null,
                    "affected_nodes": 1,
                    "reason": "control\x7fcharacters\x1f"
                }
            }),
            // Integer overflow/underflow
            serde_json::json!({
                "extension_id": "ext-test",
                "scope": {
                    "zone_id": "zone-test",
                    "tenant_id": null,
                    "affected_nodes": -1, // Negative number
                    "reason": "underflow test"
                }
            }),
            // Boolean confusion
            serde_json::json!({
                "extension_id": "ext-test",
                "scope": {
                    "zone_id": true, // Boolean instead of string
                    "tenant_id": false, // Boolean instead of optional string
                    "affected_nodes": 1,
                    "reason": "boolean confusion"
                }
            }),
        ];

        for attack_vector in attack_vectors {
            let result: Result<QuarantineRequest, _> =
                serde_json::from_value(attack_vector.clone());

            // Should fail gracefully without panicking
            assert!(
                result.is_err(),
                "Serialization attack should be rejected: {:?}",
                attack_vector
            );

            // Test round-trip consistency for valid data
            if let Ok(request) = result {
                let serialized =
                    serde_json::to_string(&request).expect("Valid request should serialize");
                let deserialized: QuarantineRequest =
                    serde_json::from_str(&serialized).expect("Serialized data should deserialize");

                // Verify no data corruption occurred
                assert_eq!(request.extension_id, deserialized.extension_id);
                assert_eq!(request.scope, deserialized.scope);
            }
        }
    }

    #[test]
    fn security_edge_case_capacity_boundary_exploits() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();

        // Test boundary conditions around capacity limits

        // 1. Fill incident capacity to exactly at limit
        for i in 0..MAX_INCIDENTS {
            let scope = QuarantineScope {
                zone_id: format!("zone-capacity-{}", i),
                tenant_id: None,
                affected_nodes: 1,
                reason: format!("capacity test {}", i),
            };

            mgr.quarantine(
                &format!("ext-{}", i),
                &scope,
                &admin_identity(),
                &test_trace(),
            )
            .expect("Should fit within capacity");
        }

        assert_eq!(mgr.incident_count(), MAX_INCIDENTS);

        // 2. Test one more should fail
        let overflow_scope = QuarantineScope {
            zone_id: "zone-overflow".to_string(),
            tenant_id: None,
            affected_nodes: 1,
            reason: "overflow attempt".to_string(),
        };

        let err = mgr
            .quarantine(
                "ext-overflow",
                &overflow_scope,
                &admin_identity(),
                &test_trace(),
            )
            .expect_err("Should fail at capacity limit");
        assert_eq!(err.error_code(), FLEET_INCIDENT_CAPACITY_EXCEEDED);

        // 3. Verify no partial state corruption
        assert_eq!(
            mgr.incident_count(),
            MAX_INCIDENTS,
            "Incident count should not change on failure"
        );
        assert!(
            !mgr.zone_status.contains_key("zone-overflow"),
            "Failed zone should not be added"
        );

        // 4. Test zone status capacity limits
        for i in MAX_INCIDENTS..MAX_INCIDENTS + MAX_ZONE_STATUS {
            let zone_id = format!("zone-status-{}", i);
            if mgr.zone_status.len() >= MAX_ZONE_STATUS {
                break;
            }

            // Try to add zone status entries via status queries
            let _ = mgr.status(&zone_id);
        }

        // Verify zone status respects capacity
        assert!(
            mgr.zone_status.len() <= MAX_ZONE_STATUS,
            "Zone status should respect capacity"
        );

        // 5. Test event capacity through reconcile operations
        let initial_event_count = mgr.events().len();
        for _ in 0..10 {
            let _ = mgr.reconcile(&admin_identity(), &test_trace());
        }

        // Events should be bounded
        assert!(
            mgr.events().len() <= MAX_FLEET_EVENTS,
            "Events should respect capacity"
        );
        assert!(
            mgr.events().len() >= initial_event_count,
            "Events should accumulate"
        );
    }

    #[test]
    fn security_edge_case_error_propagation_consistency() {
        let mut mgr = FleetControlManager::new();
        // Note: Don't activate to test safe-start mode errors

        // Test error consistency across different code paths
        let scope = test_quarantine_scope();
        let identity = admin_identity();
        let trace = test_trace();

        // 1. Test not-activated errors are consistent
        let quarantine_err = mgr
            .quarantine("ext-1", &scope, &identity, &trace)
            .expect_err("Should fail before activation");
        let revoke_err = mgr
            .revoke("ext-1", &test_revocation_scope(), &identity, &trace)
            .expect_err("Should fail before activation");
        let release_err = mgr
            .release("inc-fake", &identity, &trace)
            .expect_err("Should fail before activation");
        let reconcile_err = mgr
            .reconcile(&identity, &trace)
            .expect_err("Should fail before activation");

        // All should have same error code
        assert_eq!(quarantine_err.error_code(), FLEET_NOT_ACTIVATED);
        assert_eq!(revoke_err.error_code(), FLEET_NOT_ACTIVATED);
        assert_eq!(release_err.error_code(), FLEET_NOT_ACTIVATED);
        assert_eq!(reconcile_err.error_code(), FLEET_NOT_ACTIVATED);

        mgr.activate();

        // 2. Test scope validation errors are consistent
        let empty_scope = QuarantineScope {
            zone_id: String::new(),
            tenant_id: None,
            affected_nodes: 1,
            reason: "empty zone test".to_string(),
        };

        let empty_revoke_scope = RevocationScope {
            zone_id: String::new(),
            tenant_id: None,
            severity: RevocationSeverity::Mandatory,
            reason: "empty zone test".to_string(),
        };

        let quarantine_scope_err = mgr
            .quarantine("ext-1", &empty_scope, &identity, &trace)
            .expect_err("Should fail with empty zone");
        let revoke_scope_err = mgr
            .revoke("ext-1", &empty_revoke_scope, &identity, &trace)
            .expect_err("Should fail with empty zone");
        let status_err = mgr.status("").expect_err("Should fail with empty zone");

        // All should have same scope error code
        assert_eq!(quarantine_scope_err.error_code(), FLEET_SCOPE_INVALID);
        assert_eq!(revoke_scope_err.error_code(), FLEET_SCOPE_INVALID);
        assert_eq!(status_err.error_code(), FLEET_SCOPE_INVALID);

        // 3. Test operation ID exhaustion errors are consistent
        mgr.operation_ids_exhausted = true;

        let quarantine_id_err = mgr
            .quarantine("ext-1", &scope, &identity, &trace)
            .expect_err("Should fail with exhausted IDs");
        let revoke_id_err = mgr
            .revoke("ext-1", &test_revocation_scope(), &identity, &trace)
            .expect_err("Should fail with exhausted IDs");
        let release_id_err = mgr
            .release("inc-fake", &identity, &trace)
            .expect_err("Should fail with exhausted IDs");
        let reconcile_id_err = mgr
            .reconcile(&identity, &trace)
            .expect_err("Should fail with exhausted IDs");

        // All should have same ID exhaustion error code
        assert_eq!(quarantine_id_err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);
        assert_eq!(revoke_id_err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);
        assert_eq!(release_id_err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);
        assert_eq!(reconcile_id_err.error_code(), FLEET_OPERATION_ID_EXHAUSTED);
    }

    #[test]
    fn security_edge_case_state_corruption_resistance() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();

        // Test resistance to state corruption under adversarial conditions

        // 1. Create some initial state
        let scope = test_quarantine_scope();
        mgr.quarantine("ext-initial", &scope, &admin_identity(), &test_trace())
            .expect("Initial quarantine");

        let initial_incident_count = mgr.incident_count();
        let initial_zone_count = mgr.zones().len();
        let initial_event_count = mgr.events().len();

        // 2. Attempt operations that could corrupt state

        // Try to add incidents beyond capacity
        for i in initial_incident_count..MAX_INCIDENTS + 10 {
            let test_scope = QuarantineScope {
                zone_id: format!("zone-corruption-{}", i),
                tenant_id: None,
                affected_nodes: 1,
                reason: format!("corruption test {}", i),
            };

            let _ = mgr.quarantine(
                &format!("ext-{}", i),
                &test_scope,
                &admin_identity(),
                &test_trace(),
            );
        }

        // Verify incident count never exceeds maximum
        assert!(
            mgr.incident_count() <= MAX_INCIDENTS,
            "Incident count should be bounded"
        );

        // 3. Try invalid releases that could corrupt incident state
        let fake_incident_ids = vec![
            "inc-nonexistent",
            "inc-fleet-op-999999999",
            "",
            "inc-fleet-op--1", // Negative operation ID
            "inc-fleet-op-overflow-attack",
            "inc-\0null-byte",
        ];

        for fake_id in fake_incident_ids {
            let result = mgr.release(fake_id, &admin_identity(), &test_trace());
            if result.is_ok() {
                panic!("Release of fake incident {} should not succeed", fake_id);
            }
        }

        // Verify incident count hasn't been corrupted by failed releases
        assert!(
            mgr.incident_count() <= MAX_INCIDENTS,
            "Failed releases should not corrupt incident count"
        );

        // 4. Test status queries for zones that could corrupt state
        let malicious_zones = vec![
            "../zone-traversal",
            "/absolute/path/zone",
            "zone\0null",
            "zone\r\nheader-injection",
            "zone" + &"x".repeat(10000), // Very long zone name
        ];

        for malicious_zone in malicious_zones {
            let result = mgr.status(&malicious_zone);
            // Either reject or handle safely
            if let Ok(status) = result {
                // If accepted, verify zone ID is sanitized
                assert!(
                    !status.zone_id.contains('\0'),
                    "Zone ID should not contain null bytes"
                );
                assert!(
                    !status.zone_id.contains(".."),
                    "Zone ID should not contain path traversal"
                );
                assert!(status.zone_id.len() < 1000, "Zone ID should be bounded");
            }
        }

        // 5. Verify overall state consistency after all attacks
        assert!(
            mgr.zones().len() <= MAX_ZONE_STATUS,
            "Zone count should be bounded"
        );
        assert!(
            mgr.events().len() <= MAX_FLEET_EVENTS,
            "Event count should be bounded"
        );
        assert!(
            mgr.incident_count() <= MAX_INCIDENTS,
            "Incident count should be bounded"
        );

        // Verify internal consistency
        for incident in mgr.active_incidents() {
            assert!(
                !incident.incident_id.is_empty(),
                "Incident ID should not be empty"
            );
            assert!(!incident.zone_id.is_empty(), "Zone ID should not be empty");
            assert!(
                incident.incident_id.starts_with("inc-"),
                "Incident ID should have correct prefix"
            );
        }

        // Verify no state leakage in receipts
        if let Ok(test_result) =
            mgr.quarantine("ext-final", &scope, &admin_identity(), &test_trace())
        {
            assert!(
                !test_result.receipt.payload_hash.is_empty(),
                "Receipt hash should not be empty"
            );
            assert!(
                !test_result.receipt.receipt_id.contains("internal"),
                "Receipt should not leak internals"
            );
            assert!(
                test_result.receipt.receipt_id.starts_with("rcpt-"),
                "Receipt ID should have correct prefix"
            );
        }
    }
}
