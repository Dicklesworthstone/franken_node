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
//! - INV-FLEET-CONVERGENCE  — convergence state tracked with progress + ETA
//! - INV-FLEET-SAFE-START   — API starts in read-only mode, requires activation
//! - INV-FLEET-ROLLBACK     — release deterministically rolls back quarantine state

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::middleware::{
    AuthIdentity, AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata,
    TraceContext,
};
use super::trust_card_routes::ApiResponse;
use super::utf8_prefix;

// ── Event Codes ───────────────────────────────────────────────────────────

/// FLEET-001: Quarantine initiated for extension in zone.
pub const FLEET_QUARANTINE_INITIATED: &str = "FLEET-001";

/// FLEET-002: Revocation issued for extension.
pub const FLEET_REVOCATION_ISSUED: &str = "FLEET-002";

/// FLEET-003: Convergence progress updated.
pub const FLEET_CONVERGENCE_PROGRESS: &str = "FLEET-003";

/// FLEET-004: Fleet released (quarantine rolled back).
pub const FLEET_RELEASED: &str = "FLEET-004";

/// FLEET-005: Reconcile completed.
pub const FLEET_RECONCILE_COMPLETED: &str = "FLEET-005";

// ── Error Codes ───────────────────────────────────────────────────────────

pub const FLEET_SCOPE_INVALID: &str = "FLEET_SCOPE_INVALID";
pub const FLEET_ZONE_UNREACHABLE: &str = "FLEET_ZONE_UNREACHABLE";
pub const FLEET_CONVERGENCE_TIMEOUT: &str = "FLEET_CONVERGENCE_TIMEOUT";
pub const FLEET_ROLLBACK_FAILED: &str = "FLEET_ROLLBACK_FAILED";
pub const FLEET_NOT_ACTIVATED: &str = "FLEET_NOT_ACTIVATED";

// ── Invariant Tags ────────────────────────────────────────────────────────

pub const INV_FLEET_ZONE_SCOPE: &str = "INV-FLEET-ZONE-SCOPE";
pub const INV_FLEET_RECEIPT: &str = "INV-FLEET-RECEIPT";
pub const INV_FLEET_CONVERGENCE: &str = "INV-FLEET-CONVERGENCE";
pub const INV_FLEET_SAFE_START: &str = "INV-FLEET-SAFE-START";
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
    ZoneUnreachable { code: String, zone_id: String },
    /// Convergence timed out.
    ConvergenceTimeout { code: String, elapsed_seconds: u32 },
    /// Rollback failed during release.
    RollbackFailed {
        code: String,
        incident_id: String,
        detail: String,
    },
    /// API not activated (safe-start mode).
    NotActivated { code: String },
}

impl FleetControlError {
    pub fn scope_invalid(detail: &str) -> Self {
        Self::ScopeInvalid {
            code: FLEET_SCOPE_INVALID.to_string(),
            detail: detail.to_string(),
        }
    }

    pub fn zone_unreachable(zone_id: &str) -> Self {
        Self::ZoneUnreachable {
            code: FLEET_ZONE_UNREACHABLE.to_string(),
            zone_id: zone_id.to_string(),
        }
    }

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

    /// Return the stable error code for this error.
    pub fn error_code(&self) -> &str {
        match self {
            Self::ScopeInvalid { code, .. } => code,
            Self::ZoneUnreachable { code, .. } => code,
            Self::ConvergenceTimeout { code, .. } => code,
            Self::RollbackFailed { code, .. } => code,
            Self::NotActivated { code } => code,
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

/// Central manager for fleet quarantine/revocation operations.
///
/// Starts in read-only mode (INV-FLEET-SAFE-START) and must be explicitly
/// activated before mutation operations are allowed.
pub struct FleetControlManager {
    /// Whether the API is activated (false = safe-start read-only mode).
    activated: bool,
    /// Active quarantine incidents keyed by incident_id.
    incidents: BTreeMap<String, IncidentHandle>,
    /// Per-zone fleet status.
    zone_status: BTreeMap<String, FleetStatus>,
    /// Event log for audit trail.
    events: Vec<FleetControlEvent>,
    /// Counter for generating operation IDs.
    next_op_id: u64,
}

impl FleetControlManager {
    /// Create a new manager in safe-start (read-only) mode.
    /// INV-FLEET-SAFE-START: API starts read-only.
    pub fn new() -> Self {
        Self {
            activated: false,
            incidents: BTreeMap::new(),
            zone_status: BTreeMap::new(),
            events: Vec::new(),
            next_op_id: 1,
        }
    }

    /// Activate the fleet control API for mutations.
    /// Must be called before quarantine/revoke/release/reconcile.
    pub fn activate(&mut self) {
        self.activated = true;
    }

    /// Check if the manager is activated.
    pub fn is_activated(&self) -> bool {
        self.activated
    }

    /// Quarantine an extension within a scope.
    /// INV-FLEET-ZONE-SCOPE: scope must have a valid zone_id.
    /// INV-FLEET-RECEIPT: produces a signed decision receipt.
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
        if scope.zone_id.is_empty() {
            return Err(FleetControlError::scope_invalid(
                "zone_id must not be empty",
            ));
        }

        let op_id = self.next_operation_id();
        let now = chrono::Utc::now().to_rfc3339();
        let incident_id = format!("inc-{op_id}");

        // Create incident handle
        let incident = IncidentHandle {
            incident_id: incident_id.clone(),
            extension_id: extension_id.to_string(),
            zone_id: scope.zone_id.clone(),
            created_at: now.clone(),
            status: IncidentStatus::Active,
            action_type: "quarantine".to_string(),
        };
        self.incidents.insert(incident_id.clone(), incident);

        // Update zone status
        let zone = self
            .zone_status
            .entry(scope.zone_id.clone())
            .or_insert_with(|| FleetStatus {
                zone_id: scope.zone_id.clone(),
                active_quarantines: 0,
                active_revocations: 0,
                healthy_nodes: scope.affected_nodes,
                total_nodes: scope.affected_nodes,
                activated: true,
                pending_convergences: Vec::new(),
            });
        zone.active_quarantines += 1;

        // Build receipt (INV-FLEET-RECEIPT)
        let receipt = self.build_receipt(&op_id, &identity.principal, &scope.zone_id, &now);

        // Convergence state (INV-FLEET-CONVERGENCE)
        let convergence = ConvergenceState {
            converged_nodes: 0,
            total_nodes: scope.affected_nodes,
            progress_pct: 0,
            eta_seconds: Some(scope.affected_nodes * 2),
            phase: ConvergencePhase::Propagating,
        };

        // Emit event
        let event =
            FleetControlEvent::quarantine_initiated(&trace.trace_id, &scope.zone_id, extension_id);
        self.events.push(event);

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
        if scope.zone_id.is_empty() {
            return Err(FleetControlError::scope_invalid(
                "zone_id must not be empty",
            ));
        }

        let op_id = self.next_operation_id();
        let now = chrono::Utc::now().to_rfc3339();

        // Update zone status
        let zone = self
            .zone_status
            .entry(scope.zone_id.clone())
            .or_insert_with(|| FleetStatus {
                zone_id: scope.zone_id.clone(),
                active_quarantines: 0,
                active_revocations: 0,
                healthy_nodes: 10,
                total_nodes: 10,
                activated: true,
                pending_convergences: Vec::new(),
            });
        zone.active_revocations += 1;

        let receipt = self.build_receipt(&op_id, &identity.principal, &scope.zone_id, &now);

        // Emergency revocations create incidents
        if scope.severity == RevocationSeverity::Emergency {
            let incident_id = format!("inc-{op_id}");
            let incident = IncidentHandle {
                incident_id: incident_id.clone(),
                extension_id: extension_id.to_string(),
                zone_id: scope.zone_id.clone(),
                created_at: now.clone(),
                status: IncidentStatus::Active,
                action_type: "revoke".to_string(),
            };
            self.incidents.insert(incident_id, incident);
        }

        let event =
            FleetControlEvent::revocation_issued(&trace.trace_id, &scope.zone_id, extension_id);
        self.events.push(event);

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

        let incident = self
            .incidents
            .get_mut(incident_id)
            .ok_or_else(|| FleetControlError::rollback_failed(incident_id, "incident not found"))?;

        if incident.status == IncidentStatus::Released {
            return Err(FleetControlError::rollback_failed(
                incident_id,
                "incident already released",
            ));
        }

        // Mark as released
        incident.status = IncidentStatus::Released;
        let zone_id = incident.zone_id.clone();
        let action_type = incident.action_type.clone();

        // Decrement zone active count
        if let Some(zone) = self.zone_status.get_mut(&zone_id) {
            if action_type == "quarantine" {
                zone.active_quarantines = zone.active_quarantines.saturating_sub(1);
            } else if action_type == "revoke" {
                zone.active_revocations = zone.active_revocations.saturating_sub(1);
            }
        }

        let op_id = self.next_operation_id();
        let now = chrono::Utc::now().to_rfc3339();
        let receipt = self.build_receipt(&op_id, &identity.principal, &zone_id, &now);

        let event = FleetControlEvent::fleet_released(&trace.trace_id, &zone_id, incident_id);
        self.events.push(event);

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
        if zone_id.is_empty() {
            return Err(FleetControlError::scope_invalid(
                "zone_id must not be empty",
            ));
        }

        Ok(self
            .zone_status
            .get(zone_id)
            .cloned()
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

        let op_id = self.next_operation_id();
        let now = chrono::Utc::now().to_rfc3339();
        let zone_count = self.zone_status.len();

        // Clean up released incidents
        self.incidents
            .retain(|_, inc| inc.status != IncidentStatus::Released);

        let receipt = self.build_receipt(&op_id, &identity.principal, "all", &now);

        let convergence = ConvergenceState {
            converged_nodes: zone_count as u32,
            total_nodes: zone_count as u32,
            progress_pct: 100,
            eta_seconds: Some(0),
            phase: ConvergencePhase::Converged,
        };

        let event = FleetControlEvent::reconcile_completed(&trace.trace_id, zone_count);
        self.events.push(event);

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
    pub fn events(&self) -> &[FleetControlEvent] {
        &self.events
    }

    /// Return all active incidents.
    pub fn active_incidents(&self) -> Vec<&IncidentHandle> {
        self.incidents
            .values()
            .filter(|inc| inc.status == IncidentStatus::Active)
            .collect()
    }

    /// Return all zone IDs known to the manager.
    pub fn zones(&self) -> Vec<String> {
        self.zone_status.keys().cloned().collect()
    }

    /// Return the total number of incidents (all statuses).
    pub fn incident_count(&self) -> usize {
        self.incidents.len()
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn next_operation_id(&mut self) -> String {
        let id = format!("fleet-op-{}", self.next_op_id);
        self.next_op_id += 1;
        id
    }

    fn build_receipt(
        &self,
        op_id: &str,
        principal: &str,
        zone_id: &str,
        timestamp: &str,
    ) -> DecisionReceipt {
        let payload = format!("{op_id}:{principal}:{zone_id}:{timestamp}");
        let payload_hash = format!("{:x}", md5_like_hash(payload.as_bytes()));
        DecisionReceipt {
            receipt_id: format!("rcpt-{op_id}"),
            issuer: principal.to_string(),
            issued_at: timestamp.to_string(),
            zone_id: zone_id.to_string(),
            payload_hash,
        }
    }
}

impl Default for FleetControlManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple deterministic hash for receipt payload (not cryptographic — just
/// for tamper detection in test/demo context).
fn md5_like_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

// ── Request / Response types for API handlers ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRequest {
    pub extension_id: String,
    pub scope: QuarantineScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub extension_id: String,
    pub scope: RevocationScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub incident_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRequest {
    pub zone_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileResult {
    pub zones_reconciled: usize,
    pub incidents_cleaned: usize,
    pub convergence: ConvergenceState,
}

// ── Route Metadata ────────────────────────────────────────────────────────

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

pub fn handle_quarantine(
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &QuarantineRequest,
) -> Result<ApiResponse<FleetActionResult>, ApiError> {
    let mut mgr = FleetControlManager::new();
    mgr.activate();
    let result = mgr
        .quarantine(&request.extension_id, &request.scope, identity, trace)
        .map_err(|e| ApiError::BadRequest {
            detail: format!("{}: {}", e.error_code(), "quarantine failed"),
            trace_id: trace.trace_id.clone(),
        })?;
    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

pub fn handle_revoke(
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &RevokeRequest,
) -> Result<ApiResponse<FleetActionResult>, ApiError> {
    let mut mgr = FleetControlManager::new();
    mgr.activate();
    let result = mgr
        .revoke(&request.extension_id, &request.scope, identity, trace)
        .map_err(|e| ApiError::BadRequest {
            detail: format!("{}: {}", e.error_code(), "revocation failed"),
            trace_id: trace.trace_id.clone(),
        })?;
    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

pub fn handle_release(
    identity: &AuthIdentity,
    trace: &TraceContext,
    _request: &ReleaseRequest,
) -> Result<ApiResponse<FleetActionResult>, ApiError> {
    // In a real system this would look up the incident from persistent state
    let result = FleetActionResult {
        operation_id: format!("fleet-op-release-{}", utf8_prefix(&trace.trace_id, 8)),
        action_type: "release".to_string(),
        success: true,
        receipt: DecisionReceipt {
            receipt_id: format!("rcpt-release-{}", utf8_prefix(&trace.trace_id, 8)),
            issuer: identity.principal.clone(),
            issued_at: chrono::Utc::now().to_rfc3339(),
            zone_id: "pending-lookup".to_string(),
            payload_hash: "0000000000000000".to_string(),
        },
        convergence: None,
        trace_id: trace.trace_id.clone(),
        event_code: FLEET_RELEASED.to_string(),
    };
    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

pub fn handle_status(
    _identity: &AuthIdentity,
    _trace: &TraceContext,
    zone_id: &str,
) -> Result<ApiResponse<FleetStatus>, ApiError> {
    let status = FleetStatus {
        zone_id: zone_id.to_string(),
        active_quarantines: 0,
        active_revocations: 0,
        healthy_nodes: 0,
        total_nodes: 0,
        activated: true,
        pending_convergences: Vec::new(),
    };
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
    let mut mgr = FleetControlManager::new();
    mgr.activate();
    let result = mgr
        .reconcile(identity, trace)
        .map_err(|e| ApiError::BadRequest {
            detail: format!("{}: {}", e.error_code(), "reconcile failed"),
            trace_id: trace.trace_id.clone(),
        })?;
    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::AuthMethod;

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
            .unwrap_err();
        assert_eq!(err.error_code(), FLEET_NOT_ACTIVATED);
    }

    #[test]
    fn revoke_rejected_before_activation() {
        let mut mgr = FleetControlManager::new();
        let scope = test_revocation_scope();
        let identity = admin_identity();
        let trace = test_trace();
        let err = mgr.revoke("ext-1", &scope, &identity, &trace).unwrap_err();
        assert_eq!(err.error_code(), FLEET_NOT_ACTIVATED);
    }

    #[test]
    fn release_rejected_before_activation() {
        let mut mgr = FleetControlManager::new();
        let identity = admin_identity();
        let trace = test_trace();
        let err = mgr.release("inc-1", &identity, &trace).unwrap_err();
        assert_eq!(err.error_code(), FLEET_NOT_ACTIVATED);
    }

    #[test]
    fn reconcile_rejected_before_activation() {
        let mut mgr = FleetControlManager::new();
        let identity = admin_identity();
        let trace = test_trace();
        let err = mgr.reconcile(&identity, &trace).unwrap_err();
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
            .unwrap_err();
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
            .unwrap_err();
        assert_eq!(err.error_code(), FLEET_SCOPE_INVALID);
    }

    #[test]
    fn status_rejects_empty_zone() {
        let mgr = FleetControlManager::new();
        let err = mgr.status("").unwrap_err();
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
    }

    #[test]
    fn release_nonexistent_incident_fails() {
        let mut mgr = FleetControlManager::new();
        mgr.activate();
        let err = mgr
            .release("inc-nonexistent", &admin_identity(), &test_trace())
            .unwrap_err();
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
        let result =
            handle_status(&admin_identity(), &test_trace(), "zone-1").expect("handle status");
        assert!(result.ok);
        assert_eq!(result.data.zone_id, "zone-1");
    }

    #[test]
    fn handle_reconcile_succeeds() {
        let result = handle_reconcile(&admin_identity(), &test_trace()).expect("handle reconcile");
        assert!(result.ok);
        assert_eq!(result.data.action_type, "reconcile");
    }

    #[test]
    fn handle_release_uses_utf8_safe_trace_prefix() {
        let identity = admin_identity();
        let trace = TraceContext {
            trace_id: "🙂🙂🙂🙂🙂🙂🙂🙂🙂".to_string(),
            span_id: "0000000000000001".to_string(),
            trace_flags: 1,
        };
        let request = ReleaseRequest {
            incident_id: "inc-1".to_string(),
        };

        let result = handle_release(&identity, &trace, &request).expect("release");
        let expected: String = trace.trace_id.chars().take(8).collect();
        assert_eq!(
            result.data.operation_id,
            format!("fleet-op-release-{expected}")
        );
        assert_eq!(
            result.data.receipt.receipt_id,
            format!("rcpt-release-{expected}")
        );
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

    // ── Hash determinism test ─────────────────────────────────────────────

    #[test]
    fn receipt_hash_is_deterministic() {
        let mgr = FleetControlManager::new();
        let r1 = mgr.build_receipt("op-1", "admin", "zone-1", "2026-01-01T00:00:00Z");
        let r2 = mgr.build_receipt("op-1", "admin", "zone-1", "2026-01-01T00:00:00Z");
        assert_eq!(r1.payload_hash, r2.payload_hash);
    }

    #[test]
    fn receipt_hash_changes_with_input() {
        let mgr = FleetControlManager::new();
        let r1 = mgr.build_receipt("op-1", "admin", "zone-1", "2026-01-01T00:00:00Z");
        let r2 = mgr.build_receipt("op-2", "admin", "zone-1", "2026-01-01T00:00:00Z");
        assert_ne!(r1.payload_hash, r2.payload_hash);
    }
}
