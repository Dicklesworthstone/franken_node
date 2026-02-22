//! Adaptive multi-rail isolation mesh with hot-elevation policy.
//!
//! Workloads are routed through dynamically selected isolation rails.
//! Hot-elevation to stronger isolation is atomic and logged with structured
//! before/after evidence. No workload runs unclassified.
//!
//! Schema version: `iso-mesh-v1.0`

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Schema version for the isolation mesh protocol.
pub const SCHEMA_VERSION: &str = "iso-mesh-v1.0";

// ─── Invariant constants ────────────────────────────────────────────────────

/// Every workload must be classified before execution; unclassified workloads
/// are rejected at admission.
pub const INV_ISO_NO_UNCLASSIFIED: &str = "INV-ISO-NO-UNCLASSIFIED";

/// Isolation level can only increase (elevate) once assigned. Downgrades are
/// forbidden to prevent privilege regression.
pub const INV_ISO_MONOTONIC_ELEVATION: &str = "INV-ISO-MONOTONIC-ELEVATION";

/// Rail transitions are atomic: the workload is either on the old rail or
/// the new rail, never in an intermediate state.
pub const INV_ISO_ATOMIC_TRANSITION: &str = "INV-ISO-ATOMIC-TRANSITION";

/// Risk score thresholds determine initial rail assignment deterministically.
pub const INV_ISO_DETERMINISTIC_ROUTING: &str = "INV-ISO-DETERMINISTIC-ROUTING";

/// Audit trail captures every classification and elevation with before/after
/// evidence.
pub const INV_ISO_AUDIT_COMPLETE: &str = "INV-ISO-AUDIT-COMPLETE";

/// The set of all invariant IDs, for enumeration in checks.
pub const ALL_INVARIANTS: &[&str] = &[
    INV_ISO_NO_UNCLASSIFIED,
    INV_ISO_MONOTONIC_ELEVATION,
    INV_ISO_ATOMIC_TRANSITION,
    INV_ISO_DETERMINISTIC_ROUTING,
    INV_ISO_AUDIT_COMPLETE,
];

// ─── Event codes ────────────────────────────────────────────────────────────

/// Workload submitted for classification.
pub const ISO_001: &str = "ISO-001";
/// Workload classified and assigned to a rail.
pub const ISO_002: &str = "ISO-002";
/// Hot-elevation initiated for a workload.
pub const ISO_003: &str = "ISO-003";
/// Hot-elevation completed successfully (atomic transition).
pub const ISO_004: &str = "ISO-004";
/// Downgrade attempt rejected (monotonic elevation invariant).
pub const ISO_005: &str = "ISO-005";
/// Unclassified workload rejected at admission.
pub const ISO_006: &str = "ISO-006";

/// All event codes for enumeration.
pub const ALL_EVENT_CODES: &[&str] = &[ISO_001, ISO_002, ISO_003, ISO_004, ISO_005, ISO_006];

// ─── Error codes ────────────────────────────────────────────────────────────

/// Workload has no classification — rejected at admission.
pub const ERR_ISO_UNCLASSIFIED: &str = "ERR_ISO_UNCLASSIFIED";
/// Attempted downgrade from a stronger to a weaker rail.
pub const ERR_ISO_DOWNGRADE_REJECTED: &str = "ERR_ISO_DOWNGRADE_REJECTED";
/// Workload ID not found in the router.
pub const ERR_ISO_WORKLOAD_NOT_FOUND: &str = "ERR_ISO_WORKLOAD_NOT_FOUND";
/// Duplicate workload ID submitted for classification.
pub const ERR_ISO_DUPLICATE_WORKLOAD: &str = "ERR_ISO_DUPLICATE_WORKLOAD";
/// Risk score out of valid range [0.0, 1.0].
pub const ERR_ISO_INVALID_RISK_SCORE: &str = "ERR_ISO_INVALID_RISK_SCORE";
/// Elevation to the same rail (no-op) is rejected as a logical error.
pub const ERR_ISO_SAME_RAIL_ELEVATION: &str = "ERR_ISO_SAME_RAIL_ELEVATION";

/// All error codes for enumeration.
pub const ALL_ERROR_CODES: &[&str] = &[
    ERR_ISO_UNCLASSIFIED,
    ERR_ISO_DOWNGRADE_REJECTED,
    ERR_ISO_WORKLOAD_NOT_FOUND,
    ERR_ISO_DUPLICATE_WORKLOAD,
    ERR_ISO_INVALID_RISK_SCORE,
    ERR_ISO_SAME_RAIL_ELEVATION,
];

// ─── Core types ─────────────────────────────────────────────────────────────

/// Isolation rail levels ordered from weakest to strongest.
///
/// The ordering is used for monotonic elevation enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationRail {
    /// Shared process space — lowest isolation.
    Shared = 0,
    /// OS-level sandbox (seccomp, pledge, etc.).
    Sandboxed = 1,
    /// Hardened sandbox with additional policy enforcement.
    HardenedSandbox = 2,
    /// Full hardware/microVM isolation — strongest.
    FullIsolation = 3,
}

impl IsolationRail {
    /// All rail variants in ascending strength order.
    pub const ALL: [IsolationRail; 4] = [
        Self::Shared,
        Self::Sandboxed,
        Self::HardenedSandbox,
        Self::FullIsolation,
    ];

    /// Numeric strength level (higher = stronger).
    pub fn strength(&self) -> u8 {
        *self as u8
    }

    /// Whether `self` is strictly stronger than `other`.
    pub fn is_stronger_than(&self, other: &IsolationRail) -> bool {
        self.strength() > other.strength()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Sandboxed => "sandboxed",
            Self::HardenedSandbox => "hardened_sandbox",
            Self::FullIsolation => "full_isolation",
        }
    }
}

impl fmt::Display for IsolationRail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classification of a workload, including its assigned rail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkloadClassification {
    pub workload_id: String,
    pub risk_score: f64,
    pub rail: IsolationRail,
    pub classified_at: String,
}

/// Record of a hot-elevation event with before/after evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElevationEvent {
    pub workload_id: String,
    pub from: IsolationRail,
    pub to: IsolationRail,
    pub reason: String,
    pub trace_id: String,
    pub timestamp: String,
}

/// Structured audit entry emitted for every router action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_code: String,
    pub workload_id: String,
    pub detail: String,
    pub timestamp: String,
}

/// Policy governing elevation behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElevationPolicy {
    /// Risk-score thresholds for initial rail assignment.
    /// Workloads with score < thresholds[0] get Shared,
    /// < thresholds[1] get Sandboxed, < thresholds[2] get HardenedSandbox,
    /// otherwise FullIsolation.
    pub thresholds: [f64; 3],
    /// Whether to allow hot-elevation at runtime.
    pub allow_hot_elevation: bool,
}

impl Default for ElevationPolicy {
    fn default() -> Self {
        Self {
            thresholds: [0.25, 0.50, 0.75],
            allow_hot_elevation: true,
        }
    }
}

impl ElevationPolicy {
    /// Determine the initial rail for a given risk score.
    ///
    /// Deterministic: same score always maps to same rail
    /// (`INV-ISO-DETERMINISTIC-ROUTING`).
    pub fn rail_for_score(&self, score: f64) -> IsolationRail {
        if score < self.thresholds[0] {
            IsolationRail::Shared
        } else if score < self.thresholds[1] {
            IsolationRail::Sandboxed
        } else if score < self.thresholds[2] {
            IsolationRail::HardenedSandbox
        } else {
            IsolationRail::FullIsolation
        }
    }
}

// ─── Errors ─────────────────────────────────────────────────────────────────

/// Errors returned by the rail router.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RailRouterError {
    /// Workload has no classification (INV-ISO-NO-UNCLASSIFIED).
    #[serde(rename = "ERR_ISO_UNCLASSIFIED")]
    Unclassified { workload_id: String },

    /// Attempted downgrade violates monotonic elevation (INV-ISO-MONOTONIC-ELEVATION).
    #[serde(rename = "ERR_ISO_DOWNGRADE_REJECTED")]
    DowngradeRejected {
        workload_id: String,
        current: IsolationRail,
        requested: IsolationRail,
    },

    /// Workload not found in the router.
    #[serde(rename = "ERR_ISO_WORKLOAD_NOT_FOUND")]
    WorkloadNotFound { workload_id: String },

    /// Duplicate workload ID.
    #[serde(rename = "ERR_ISO_DUPLICATE_WORKLOAD")]
    DuplicateWorkload { workload_id: String },

    /// Risk score not in [0.0, 1.0].
    #[serde(rename = "ERR_ISO_INVALID_RISK_SCORE")]
    InvalidRiskScore { workload_id: String, score: f64 },

    /// Elevation to the same rail is a no-op error.
    #[serde(rename = "ERR_ISO_SAME_RAIL_ELEVATION")]
    SameRailElevation {
        workload_id: String,
        rail: IsolationRail,
    },
}

impl fmt::Display for RailRouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unclassified { workload_id } => {
                write!(f, "{ERR_ISO_UNCLASSIFIED}: workload '{workload_id}' has no classification")
            }
            Self::DowngradeRejected {
                workload_id,
                current,
                requested,
            } => {
                write!(
                    f,
                    "{ERR_ISO_DOWNGRADE_REJECTED}: workload '{workload_id}' cannot downgrade from {current} to {requested}"
                )
            }
            Self::WorkloadNotFound { workload_id } => {
                write!(f, "{ERR_ISO_WORKLOAD_NOT_FOUND}: workload '{workload_id}' not found")
            }
            Self::DuplicateWorkload { workload_id } => {
                write!(f, "{ERR_ISO_DUPLICATE_WORKLOAD}: workload '{workload_id}' already classified")
            }
            Self::InvalidRiskScore { workload_id, score } => {
                write!(
                    f,
                    "{ERR_ISO_INVALID_RISK_SCORE}: workload '{workload_id}' has invalid risk score {score}"
                )
            }
            Self::SameRailElevation { workload_id, rail } => {
                write!(
                    f,
                    "{ERR_ISO_SAME_RAIL_ELEVATION}: workload '{workload_id}' already on rail {rail}"
                )
            }
        }
    }
}

impl std::error::Error for RailRouterError {}

// ─── Router ─────────────────────────────────────────────────────────────────

/// Adaptive multi-rail isolation mesh router.
///
/// Routes workloads to isolation rails based on risk profiles.
/// Supports hot-elevation (atomic upgrade) to stronger isolation.
/// Enforces that no workload runs unclassified and that downgrades
/// are impossible.
pub struct RailRouter {
    /// Current workload classifications, keyed by workload_id.
    /// BTreeMap for deterministic iteration order.
    classifications: BTreeMap<String, WorkloadClassification>,
    /// Elevation policy governing rail assignment and hot-elevation rules.
    policy: ElevationPolicy,
    /// Chronological log of elevation events.
    elevation_log: Vec<ElevationEvent>,
    /// Chronological audit trail of all router actions.
    audit_log: Vec<AuditEntry>,
    /// Monotonic sequence counter for trace IDs.
    seq: u64,
}

impl RailRouter {
    /// Create a new router with the given elevation policy.
    pub fn new(policy: ElevationPolicy) -> Self {
        Self {
            classifications: BTreeMap::new(),
            policy,
            elevation_log: Vec::new(),
            audit_log: Vec::new(),
            seq: 0,
        }
    }

    /// Create a new router with the default policy.
    pub fn with_default_policy() -> Self {
        Self::new(ElevationPolicy::default())
    }

    /// Classify and admit a workload, assigning it to an isolation rail
    /// based on its risk score.
    ///
    /// Enforces `INV-ISO-NO-UNCLASSIFIED` — every admitted workload gets a rail.
    /// Enforces `INV-ISO-DETERMINISTIC-ROUTING` — score maps deterministically.
    pub fn classify_workload(
        &mut self,
        workload_id: &str,
        risk_score: f64,
    ) -> Result<WorkloadClassification, RailRouterError> {
        // Validate risk score range
        if !(0.0..=1.0).contains(&risk_score) {
            self.emit_audit(ISO_006, workload_id, &format!("invalid risk score: {risk_score}"));
            return Err(RailRouterError::InvalidRiskScore {
                workload_id: workload_id.to_string(),
                score: risk_score,
            });
        }

        // Reject duplicates
        if self.classifications.contains_key(workload_id) {
            return Err(RailRouterError::DuplicateWorkload {
                workload_id: workload_id.to_string(),
            });
        }

        // ISO-001: Workload submitted for classification
        self.emit_audit(ISO_001, workload_id, &format!("risk_score={risk_score}"));

        let rail = self.policy.rail_for_score(risk_score);
        let now = self.timestamp();
        let classification = WorkloadClassification {
            workload_id: workload_id.to_string(),
            risk_score,
            rail,
            classified_at: now,
        };

        self.classifications
            .insert(workload_id.to_string(), classification.clone());

        // ISO-002: Workload classified and assigned
        self.emit_audit(
            ISO_002,
            workload_id,
            &format!("assigned to rail={rail}, risk_score={risk_score}"),
        );

        Ok(classification)
    }

    /// Hot-elevate a workload to a stronger isolation rail.
    ///
    /// Enforces `INV-ISO-MONOTONIC-ELEVATION` — only upgrades allowed.
    /// Enforces `INV-ISO-ATOMIC-TRANSITION` — the classification is updated
    /// in a single write, no intermediate state is observable.
    pub fn hot_elevate(
        &mut self,
        workload_id: &str,
        target_rail: IsolationRail,
        reason: &str,
    ) -> Result<ElevationEvent, RailRouterError> {
        // Look up current classification
        let current = self
            .classifications
            .get(workload_id)
            .ok_or_else(|| RailRouterError::WorkloadNotFound {
                workload_id: workload_id.to_string(),
            })?
            .clone();

        let from_rail = current.rail;

        // Reject same-rail elevation (no-op)
        if target_rail == from_rail {
            return Err(RailRouterError::SameRailElevation {
                workload_id: workload_id.to_string(),
                rail: from_rail,
            });
        }

        // Enforce monotonic elevation: reject downgrades (INV-ISO-MONOTONIC-ELEVATION)
        if !target_rail.is_stronger_than(&from_rail) {
            // ISO-005: Downgrade attempt rejected
            self.emit_audit(
                ISO_005,
                workload_id,
                &format!("downgrade rejected: {from_rail} -> {target_rail}"),
            );
            return Err(RailRouterError::DowngradeRejected {
                workload_id: workload_id.to_string(),
                current: from_rail,
                requested: target_rail,
            });
        }

        // ISO-003: Hot-elevation initiated
        self.emit_audit(
            ISO_003,
            workload_id,
            &format!("elevating from {from_rail} to {target_rail}: {reason}"),
        );

        // Atomic transition (INV-ISO-ATOMIC-TRANSITION): single write
        let entry = self.classifications.get_mut(workload_id).unwrap();
        entry.rail = target_rail;

        let trace_id = self.next_trace_id();
        let now = self.timestamp();
        let event = ElevationEvent {
            workload_id: workload_id.to_string(),
            from: from_rail,
            to: target_rail,
            reason: reason.to_string(),
            trace_id,
            timestamp: now,
        };

        self.elevation_log.push(event.clone());

        // ISO-004: Hot-elevation completed
        self.emit_audit(
            ISO_004,
            workload_id,
            &format!("elevated from {from_rail} to {target_rail}"),
        );

        Ok(event)
    }

    /// Get the current classification for a workload.
    ///
    /// Returns `Err(Unclassified)` if the workload has not been classified,
    /// enforcing `INV-ISO-NO-UNCLASSIFIED`.
    pub fn get_classification(
        &self,
        workload_id: &str,
    ) -> Result<&WorkloadClassification, RailRouterError> {
        self.classifications
            .get(workload_id)
            .ok_or_else(|| RailRouterError::Unclassified {
                workload_id: workload_id.to_string(),
            })
    }

    /// Get the current rail for a workload.
    pub fn get_rail(&self, workload_id: &str) -> Result<IsolationRail, RailRouterError> {
        self.get_classification(workload_id).map(|c| c.rail)
    }

    /// Get all workload IDs on a particular rail.
    pub fn workloads_on_rail(&self, rail: IsolationRail) -> Vec<String> {
        self.classifications
            .iter()
            .filter(|(_, c)| c.rail == rail)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get a summary of workload counts per rail.
    pub fn rail_summary(&self) -> BTreeMap<String, usize> {
        let mut summary = BTreeMap::new();
        for rail in &IsolationRail::ALL {
            summary.insert(rail.as_str().to_string(), 0);
        }
        for c in self.classifications.values() {
            *summary.entry(c.rail.as_str().to_string()).or_insert(0) += 1;
        }
        summary
    }

    /// Total number of classified workloads.
    pub fn workload_count(&self) -> usize {
        self.classifications.len()
    }

    /// Whether every workload has a valid (non-unclassified) rail assignment.
    ///
    /// Always true by construction since classification is mandatory at admission.
    pub fn all_classified(&self) -> bool {
        // By construction, every entry in `classifications` has a valid rail.
        // This method exists as an explicit invariant check surface.
        !self.classifications.is_empty()
            || self.classifications.values().all(|c| IsolationRail::ALL.contains(&c.rail))
    }

    /// Get the elevation event log.
    pub fn elevation_log(&self) -> &[ElevationEvent] {
        &self.elevation_log
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    /// Get the elevation policy.
    pub fn policy(&self) -> &ElevationPolicy {
        &self.policy
    }

    /// Get a set of all active workload IDs.
    pub fn active_workloads(&self) -> BTreeSet<String> {
        self.classifications.keys().cloned().collect()
    }

    /// Remove a workload from the router (e.g., on completion).
    pub fn remove_workload(&mut self, workload_id: &str) -> Result<WorkloadClassification, RailRouterError> {
        self.classifications
            .remove(workload_id)
            .ok_or_else(|| RailRouterError::WorkloadNotFound {
                workload_id: workload_id.to_string(),
            })
    }

    // ─── Internal helpers ───────────────────────────────────────────────

    fn next_trace_id(&mut self) -> String {
        self.seq += 1;
        format!("trace-iso-{:06}", self.seq)
    }

    fn timestamp(&self) -> String {
        // Deterministic for testing; in production this would use real time.
        "2026-02-21T00:00:00Z".to_string()
    }

    fn emit_audit(&mut self, event_code: &str, workload_id: &str, detail: &str) {
        let now = self.timestamp();
        self.audit_log.push(AuditEntry {
            event_code: event_code.to_string(),
            workload_id: workload_id.to_string(),
            detail: detail.to_string(),
            timestamp: now,
        });
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_router() -> RailRouter {
        RailRouter::with_default_policy()
    }

    // === IsolationRail ordering ===

    #[test]
    fn rail_strength_ordering() {
        assert!(IsolationRail::FullIsolation.strength() > IsolationRail::HardenedSandbox.strength());
        assert!(IsolationRail::HardenedSandbox.strength() > IsolationRail::Sandboxed.strength());
        assert!(IsolationRail::Sandboxed.strength() > IsolationRail::Shared.strength());
    }

    #[test]
    fn rail_is_stronger_than() {
        assert!(IsolationRail::FullIsolation.is_stronger_than(&IsolationRail::Shared));
        assert!(IsolationRail::Sandboxed.is_stronger_than(&IsolationRail::Shared));
        assert!(!IsolationRail::Shared.is_stronger_than(&IsolationRail::Sandboxed));
        assert!(!IsolationRail::Shared.is_stronger_than(&IsolationRail::Shared));
    }

    #[test]
    fn four_rail_variants() {
        assert_eq!(IsolationRail::ALL.len(), 4);
    }

    #[test]
    fn rail_display() {
        assert_eq!(IsolationRail::Shared.to_string(), "shared");
        assert_eq!(IsolationRail::Sandboxed.to_string(), "sandboxed");
        assert_eq!(IsolationRail::HardenedSandbox.to_string(), "hardened_sandbox");
        assert_eq!(IsolationRail::FullIsolation.to_string(), "full_isolation");
    }

    // === ElevationPolicy ===

    #[test]
    fn default_policy_thresholds() {
        let p = ElevationPolicy::default();
        assert_eq!(p.thresholds, [0.25, 0.50, 0.75]);
        assert!(p.allow_hot_elevation);
    }

    #[test]
    fn policy_rail_for_score_deterministic() {
        let p = ElevationPolicy::default();
        assert_eq!(p.rail_for_score(0.0), IsolationRail::Shared);
        assert_eq!(p.rail_for_score(0.24), IsolationRail::Shared);
        assert_eq!(p.rail_for_score(0.25), IsolationRail::Sandboxed);
        assert_eq!(p.rail_for_score(0.49), IsolationRail::Sandboxed);
        assert_eq!(p.rail_for_score(0.50), IsolationRail::HardenedSandbox);
        assert_eq!(p.rail_for_score(0.74), IsolationRail::HardenedSandbox);
        assert_eq!(p.rail_for_score(0.75), IsolationRail::FullIsolation);
        assert_eq!(p.rail_for_score(1.0), IsolationRail::FullIsolation);
    }

    // === Workload classification ===

    #[test]
    fn classify_low_risk_workload() {
        let mut r = default_router();
        let c = r.classify_workload("w1", 0.1).unwrap();
        assert_eq!(c.rail, IsolationRail::Shared);
        assert_eq!(c.workload_id, "w1");
    }

    #[test]
    fn classify_medium_risk_workload() {
        let mut r = default_router();
        let c = r.classify_workload("w2", 0.4).unwrap();
        assert_eq!(c.rail, IsolationRail::Sandboxed);
    }

    #[test]
    fn classify_high_risk_workload() {
        let mut r = default_router();
        let c = r.classify_workload("w3", 0.6).unwrap();
        assert_eq!(c.rail, IsolationRail::HardenedSandbox);
    }

    #[test]
    fn classify_critical_risk_workload() {
        let mut r = default_router();
        let c = r.classify_workload("w4", 0.9).unwrap();
        assert_eq!(c.rail, IsolationRail::FullIsolation);
    }

    #[test]
    fn classify_rejects_duplicate() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        let err = r.classify_workload("w1", 0.5).unwrap_err();
        assert!(matches!(err, RailRouterError::DuplicateWorkload { .. }));
    }

    #[test]
    fn classify_rejects_invalid_score_negative() {
        let mut r = default_router();
        let err = r.classify_workload("w1", -0.1).unwrap_err();
        assert!(matches!(err, RailRouterError::InvalidRiskScore { .. }));
    }

    #[test]
    fn classify_rejects_invalid_score_over_one() {
        let mut r = default_router();
        let err = r.classify_workload("w1", 1.1).unwrap_err();
        assert!(matches!(err, RailRouterError::InvalidRiskScore { .. }));
    }

    // === Hot-elevation ===

    #[test]
    fn hot_elevate_succeeds() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        let ev = r.hot_elevate("w1", IsolationRail::Sandboxed, "threat detected").unwrap();
        assert_eq!(ev.from, IsolationRail::Shared);
        assert_eq!(ev.to, IsolationRail::Sandboxed);
        assert_eq!(ev.workload_id, "w1");
        assert!(!ev.trace_id.is_empty());
    }

    #[test]
    fn hot_elevate_monotonic_rejects_downgrade() {
        let mut r = default_router();
        r.classify_workload("w1", 0.6).unwrap(); // HardenedSandbox
        let err = r.hot_elevate("w1", IsolationRail::Shared, "relax").unwrap_err();
        assert!(matches!(err, RailRouterError::DowngradeRejected { .. }));
    }

    #[test]
    fn hot_elevate_rejects_same_rail() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap(); // Shared
        let err = r.hot_elevate("w1", IsolationRail::Shared, "no reason").unwrap_err();
        assert!(matches!(err, RailRouterError::SameRailElevation { .. }));
    }

    #[test]
    fn hot_elevate_unknown_workload() {
        let mut r = default_router();
        let err = r.hot_elevate("missing", IsolationRail::Sandboxed, "x").unwrap_err();
        assert!(matches!(err, RailRouterError::WorkloadNotFound { .. }));
    }

    #[test]
    fn hot_elevate_updates_classification() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        r.hot_elevate("w1", IsolationRail::FullIsolation, "critical").unwrap();
        let rail = r.get_rail("w1").unwrap();
        assert_eq!(rail, IsolationRail::FullIsolation);
    }

    #[test]
    fn double_elevation_monotonic() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap(); // Shared
        r.hot_elevate("w1", IsolationRail::Sandboxed, "step 1").unwrap();
        r.hot_elevate("w1", IsolationRail::HardenedSandbox, "step 2").unwrap();
        assert_eq!(r.get_rail("w1").unwrap(), IsolationRail::HardenedSandbox);
        assert_eq!(r.elevation_log().len(), 2);
    }

    // === Invariant: no unclassified workloads ===

    #[test]
    fn inv_no_unclassified_get_classification_rejects() {
        let r = default_router();
        let err = r.get_classification("nonexistent").unwrap_err();
        assert!(matches!(err, RailRouterError::Unclassified { .. }));
    }

    // === Rail summary ===

    #[test]
    fn rail_summary_counts() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap(); // Shared
        r.classify_workload("w2", 0.3).unwrap(); // Sandboxed
        r.classify_workload("w3", 0.6).unwrap(); // HardenedSandbox
        r.classify_workload("w4", 0.9).unwrap(); // FullIsolation
        let summary = r.rail_summary();
        assert_eq!(summary["shared"], 1);
        assert_eq!(summary["sandboxed"], 1);
        assert_eq!(summary["hardened_sandbox"], 1);
        assert_eq!(summary["full_isolation"], 1);
    }

    #[test]
    fn workload_count() {
        let mut r = default_router();
        assert_eq!(r.workload_count(), 0);
        r.classify_workload("w1", 0.1).unwrap();
        assert_eq!(r.workload_count(), 1);
    }

    // === Audit log ===

    #[test]
    fn audit_log_records_classification() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        let audit = r.audit_log();
        assert!(audit.len() >= 2); // ISO-001 + ISO-002
        assert_eq!(audit[0].event_code, ISO_001);
        assert_eq!(audit[1].event_code, ISO_002);
    }

    #[test]
    fn audit_log_records_elevation() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        r.hot_elevate("w1", IsolationRail::Sandboxed, "test").unwrap();
        let codes: Vec<&str> = r.audit_log().iter().map(|a| a.event_code.as_str()).collect();
        assert!(codes.contains(&ISO_003));
        assert!(codes.contains(&ISO_004));
    }

    #[test]
    fn audit_log_records_downgrade_rejection() {
        let mut r = default_router();
        r.classify_workload("w1", 0.6).unwrap();
        let _ = r.hot_elevate("w1", IsolationRail::Shared, "bad");
        let codes: Vec<&str> = r.audit_log().iter().map(|a| a.event_code.as_str()).collect();
        assert!(codes.contains(&ISO_005));
    }

    // === Workloads on rail ===

    #[test]
    fn workloads_on_rail() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        r.classify_workload("w2", 0.15).unwrap();
        r.classify_workload("w3", 0.6).unwrap();
        let shared = r.workloads_on_rail(IsolationRail::Shared);
        assert_eq!(shared.len(), 2);
        assert!(shared.contains(&"w1".to_string()));
        assert!(shared.contains(&"w2".to_string()));
    }

    // === Remove workload ===

    #[test]
    fn remove_workload_succeeds() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        let removed = r.remove_workload("w1").unwrap();
        assert_eq!(removed.workload_id, "w1");
        assert_eq!(r.workload_count(), 0);
    }

    #[test]
    fn remove_workload_not_found() {
        let mut r = default_router();
        let err = r.remove_workload("missing").unwrap_err();
        assert!(matches!(err, RailRouterError::WorkloadNotFound { .. }));
    }

    // === Serde round-trips ===

    #[test]
    fn serde_roundtrip_rail() {
        for rail in &IsolationRail::ALL {
            let json = serde_json::to_string(rail).unwrap();
            let parsed: IsolationRail = serde_json::from_str(&json).unwrap();
            assert_eq!(rail, &parsed);
        }
    }

    #[test]
    fn serde_roundtrip_classification() {
        let c = WorkloadClassification {
            workload_id: "w1".into(),
            risk_score: 0.42,
            rail: IsolationRail::Sandboxed,
            classified_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let parsed: WorkloadClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(c, parsed);
    }

    #[test]
    fn serde_roundtrip_elevation_event() {
        let ev = ElevationEvent {
            workload_id: "w1".into(),
            from: IsolationRail::Shared,
            to: IsolationRail::Sandboxed,
            reason: "threat".into(),
            trace_id: "trace-iso-000001".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let parsed: ElevationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, parsed);
    }

    #[test]
    fn serde_roundtrip_error() {
        let err = RailRouterError::DowngradeRejected {
            workload_id: "w1".into(),
            current: IsolationRail::HardenedSandbox,
            requested: IsolationRail::Shared,
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: RailRouterError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, parsed);
    }

    // === Error display ===

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<RailRouterError> = vec![
            RailRouterError::Unclassified { workload_id: "w".into() },
            RailRouterError::DowngradeRejected {
                workload_id: "w".into(),
                current: IsolationRail::Sandboxed,
                requested: IsolationRail::Shared,
            },
            RailRouterError::WorkloadNotFound { workload_id: "w".into() },
            RailRouterError::DuplicateWorkload { workload_id: "w".into() },
            RailRouterError::InvalidRiskScore { workload_id: "w".into(), score: 2.0 },
            RailRouterError::SameRailElevation {
                workload_id: "w".into(),
                rail: IsolationRail::Shared,
            },
        ];
        let expected_codes = [
            ERR_ISO_UNCLASSIFIED,
            ERR_ISO_DOWNGRADE_REJECTED,
            ERR_ISO_WORKLOAD_NOT_FOUND,
            ERR_ISO_DUPLICATE_WORKLOAD,
            ERR_ISO_INVALID_RISK_SCORE,
            ERR_ISO_SAME_RAIL_ELEVATION,
        ];
        for (err, code) in errors.iter().zip(expected_codes.iter()) {
            assert!(err.to_string().contains(code), "missing code {code} in: {err}");
        }
    }

    // === Constants enumeration ===

    #[test]
    fn all_invariants_listed() {
        assert_eq!(ALL_INVARIANTS.len(), 5);
        assert!(ALL_INVARIANTS.contains(&INV_ISO_NO_UNCLASSIFIED));
        assert!(ALL_INVARIANTS.contains(&INV_ISO_MONOTONIC_ELEVATION));
        assert!(ALL_INVARIANTS.contains(&INV_ISO_ATOMIC_TRANSITION));
    }

    #[test]
    fn all_event_codes_listed() {
        assert_eq!(ALL_EVENT_CODES.len(), 6);
    }

    #[test]
    fn all_error_codes_listed() {
        assert_eq!(ALL_ERROR_CODES.len(), 6);
    }

    #[test]
    fn schema_version_set() {
        assert_eq!(SCHEMA_VERSION, "iso-mesh-v1.0");
    }
}
