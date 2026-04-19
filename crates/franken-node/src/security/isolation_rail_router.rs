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

// ─── Capacity constants ─────────────────────────────────────────────────────

/// Maximum elevation events to retain in memory (prevents unbounded growth).
const MAX_ELEVATION_LOG_ENTRIES: usize = 1000;

/// Maximum audit events to retain in memory (prevents unbounded growth).
const MAX_AUDIT_LOG_ENTRIES: usize = 2000;

/// Push item to vector with bounded capacity to prevent memory exhaustion.
/// When capacity is exceeded, removes oldest entries to maintain the limit.
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
/// Hot-elevation is disabled by policy for this router.
pub const ERR_ISO_HOT_ELEVATION_DISABLED: &str = "ERR_ISO_HOT_ELEVATION_DISABLED";

/// All error codes for enumeration.
pub const ALL_ERROR_CODES: &[&str] = &[
    ERR_ISO_UNCLASSIFIED,
    ERR_ISO_DOWNGRADE_REJECTED,
    ERR_ISO_WORKLOAD_NOT_FOUND,
    ERR_ISO_DUPLICATE_WORKLOAD,
    ERR_ISO_INVALID_RISK_SCORE,
    ERR_ISO_SAME_RAIL_ELEVATION,
    ERR_ISO_HOT_ELEVATION_DISABLED,
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
    /// Hot-elevation was requested but policy forbids runtime elevation.
    #[serde(rename = "ERR_ISO_HOT_ELEVATION_DISABLED")]
    HotElevationDisabled {
        workload_id: String,
        current: IsolationRail,
        requested: IsolationRail,
    },
}

impl fmt::Display for RailRouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unclassified { workload_id } => {
                write!(
                    f,
                    "{ERR_ISO_UNCLASSIFIED}: workload '{workload_id}' has no classification"
                )
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
                write!(
                    f,
                    "{ERR_ISO_WORKLOAD_NOT_FOUND}: workload '{workload_id}' not found"
                )
            }
            Self::DuplicateWorkload { workload_id } => {
                write!(
                    f,
                    "{ERR_ISO_DUPLICATE_WORKLOAD}: workload '{workload_id}' already classified"
                )
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
            Self::HotElevationDisabled {
                workload_id,
                current,
                requested,
            } => {
                write!(
                    f,
                    "{ERR_ISO_HOT_ELEVATION_DISABLED}: workload '{workload_id}' cannot hot-elevate from {current} to {requested} because policy disables hot elevation"
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
        if workload_id.trim().is_empty() {
            self.emit_audit(ISO_006, workload_id, "blank workload_id");
            return Err(RailRouterError::Unclassified {
                workload_id: workload_id.to_string(),
            });
        }

        // Validate risk score is finite (reject NaN/infinity)
        if !risk_score.is_finite() {
            self.emit_audit(
                ISO_006,
                workload_id,
                &format!("non-finite risk score: {risk_score}"),
            );
            return Err(RailRouterError::InvalidRiskScore {
                workload_id: workload_id.to_string(),
                score: risk_score,
            });
        }

        // Validate risk score range
        if !(0.0..=1.0).contains(&risk_score) {
            self.emit_audit(
                ISO_006,
                workload_id,
                &format!("invalid risk score: {risk_score}"),
            );
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

        if !self.policy.allow_hot_elevation {
            return Err(RailRouterError::HotElevationDisabled {
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
        let entry = self.classifications.get_mut(workload_id).ok_or_else(|| {
            RailRouterError::WorkloadNotFound {
                workload_id: workload_id.to_string(),
            }
        })?;
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

        push_bounded(&mut self.elevation_log, event.clone(), MAX_ELEVATION_LOG_ENTRIES);

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
            summary.insert(rail.as_str().to_string(), 0usize);
        }
        for c in self.classifications.values() {
            let count = summary.entry(c.rail.as_str().to_string()).or_insert(0usize);
            *count = (*count).saturating_add(1usize);
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
            || self
                .classifications
                .values()
                .all(|c| IsolationRail::ALL.contains(&c.rail))
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
    pub fn remove_workload(
        &mut self,
        workload_id: &str,
    ) -> Result<WorkloadClassification, RailRouterError> {
        self.classifications
            .remove(workload_id)
            .ok_or_else(|| RailRouterError::WorkloadNotFound {
                workload_id: workload_id.to_string(),
            })
    }

    // ─── Internal helpers ───────────────────────────────────────────────

    fn next_trace_id(&mut self) -> String {
        self.seq = self.seq.saturating_add(1);
        format!("trace-iso-{:06}", self.seq)
    }

    fn timestamp(&self) -> String {
        // Deterministic for testing; in production this would use real time.
        "2026-02-21T00:00:00Z".to_string()
    }

    fn emit_audit(&mut self, event_code: &str, workload_id: &str, detail: &str) {
        let now = self.timestamp();
        push_bounded(&mut self.audit_log, AuditEntry {
            event_code: event_code.to_string(),
            workload_id: workload_id.to_string(),
            detail: detail.to_string(),
            timestamp: now,
        }, MAX_AUDIT_LOG_ENTRIES);
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
        assert!(
            IsolationRail::FullIsolation.strength() > IsolationRail::HardenedSandbox.strength()
        );
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
        assert_eq!(
            IsolationRail::HardenedSandbox.to_string(),
            "hardened_sandbox"
        );
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

    #[test]
    fn classify_duplicate_preserves_original_classification_and_audit() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        let audit_before = r.audit_log().len();

        let err = r.classify_workload("w1", 0.9).unwrap_err();

        assert!(matches!(err, RailRouterError::DuplicateWorkload { .. }));
        assert_eq!(r.workload_count(), 1);
        assert_eq!(r.get_rail("w1").unwrap(), IsolationRail::Shared);
        assert_eq!(r.audit_log().len(), audit_before);
    }

    #[test]
    fn classify_nan_score_is_rejected_without_admission() {
        let mut r = default_router();

        let err = r.classify_workload("nan-workload", f64::NAN).unwrap_err();

        assert!(matches!(err, RailRouterError::InvalidRiskScore { .. }));
        assert_eq!(r.workload_count(), 0);
        assert!(matches!(
            r.get_classification("nan-workload").unwrap_err(),
            RailRouterError::Unclassified { .. }
        ));
        assert_eq!(r.audit_log().len(), 1);
        assert_eq!(r.audit_log()[0].event_code, ISO_006);
    }

    #[test]
    fn classify_invalid_score_does_not_replace_existing_workload() {
        let mut r = default_router();
        r.classify_workload("w1", 0.4).unwrap();
        let audit_before = r.audit_log().len();

        let err = r.classify_workload("w1", -0.25).unwrap_err();

        assert!(matches!(err, RailRouterError::InvalidRiskScore { .. }));
        assert_eq!(r.workload_count(), 1);
        assert_eq!(r.get_rail("w1").unwrap(), IsolationRail::Sandboxed);
        assert_eq!(r.audit_log().len(), audit_before + 1);
        assert_eq!(r.audit_log().last().unwrap().event_code, ISO_006);
    }

    #[test]
    fn classify_rejects_empty_workload_id_without_admission() {
        let mut r = default_router();

        let err = r.classify_workload("", 0.25).unwrap_err();

        assert!(matches!(
            err,
            RailRouterError::Unclassified { workload_id } if workload_id.is_empty()
        ));
        assert_eq!(r.workload_count(), 0);
        assert!(r.active_workloads().is_empty());
    }

    // ── COMPREHENSIVE NEGATIVE-PATH INLINE TESTS ────────────────────────────────
    // Extended edge cases and boundary validation for security-critical isolation routing

    /// Test IsolationRail enum with extreme ordinal value manipulation
    #[test]
    fn test_isolation_rail_strength_boundaries() {
        // Test all rail strength comparisons exhaustively
        let rails = IsolationRail::ALL;

        for (i, rail1) in rails.iter().enumerate() {
            for (j, rail2) in rails.iter().enumerate() {
                let strength1 = rail1.strength();
                let strength2 = rail2.strength();

                // Verify strength ordering consistency
                assert_eq!(strength1 > strength2, i > j);
                assert_eq!(rail1.is_stronger_than(rail2), i > j);

                // Verify reflexivity (no rail is stronger than itself)
                assert!(!rail1.is_stronger_than(rail1));

                // Verify antisymmetry
                if rail1.is_stronger_than(rail2) {
                    assert!(!rail2.is_stronger_than(rail1));
                }
            }
        }

        // Test strength value boundaries
        assert_eq!(IsolationRail::Shared.strength(), 0);
        assert_eq!(IsolationRail::FullIsolation.strength(), 3);

        // Verify ordering matches enum discriminants
        assert!(IsolationRail::Shared < IsolationRail::Sandboxed);
        assert!(IsolationRail::Sandboxed < IsolationRail::HardenedSandbox);
        assert!(IsolationRail::HardenedSandbox < IsolationRail::FullIsolation);

        // Test string representation consistency
        for rail in &rails {
            let str_repr = rail.as_str();
            assert!(!str_repr.is_empty());
            assert_eq!(rail.to_string(), str_repr);
            assert!(!str_repr.contains(' ')); // Should be snake_case
        }

        // Test ALL constant completeness
        assert_eq!(IsolationRail::ALL.len(), 4);
        assert!(IsolationRail::ALL.contains(&IsolationRail::Shared));
        assert!(IsolationRail::ALL.contains(&IsolationRail::Sandboxed));
        assert!(IsolationRail::ALL.contains(&IsolationRail::HardenedSandbox));
        assert!(IsolationRail::ALL.contains(&IsolationRail::FullIsolation));
    }

    /// Test ElevationPolicy with extreme and malformed threshold configurations
    #[test]
    fn test_elevation_policy_extreme_thresholds() {
        // Test default policy boundary conditions
        let default_policy = ElevationPolicy::default();

        // Edge values around thresholds
        let edge_scores = [
            0.0,
            f64::EPSILON,
            0.25 - f64::EPSILON,
            0.25,
            0.25 + f64::EPSILON,
            0.50 - f64::EPSILON,
            0.50,
            0.50 + f64::EPSILON,
            0.75 - f64::EPSILON,
            0.75,
            0.75 + f64::EPSILON,
            1.0 - f64::EPSILON,
            1.0,
        ];

        for &score in &edge_scores {
            let rail = default_policy.rail_for_score(score);
            assert!(IsolationRail::ALL.contains(&rail));

            // Verify deterministic mapping
            assert_eq!(rail, default_policy.rail_for_score(score));
        }

        // Test extreme threshold configurations
        let extreme_policies = [
            // All thresholds at zero (everything goes to FullIsolation except score 0.0)
            ElevationPolicy {
                thresholds: [0.0, 0.0, 0.0],
                allow_hot_elevation: true,
            },
            // All thresholds at one (everything goes to Shared except score 1.0)
            ElevationPolicy {
                thresholds: [1.0, 1.0, 1.0],
                allow_hot_elevation: true,
            },
            // Inverted thresholds (should still work but be unusual)
            ElevationPolicy {
                thresholds: [0.75, 0.50, 0.25],
                allow_hot_elevation: false,
            },
            // Very close thresholds
            ElevationPolicy {
                thresholds: [0.333, 0.334, 0.335],
                allow_hot_elevation: true,
            },
            // Maximum spread thresholds
            ElevationPolicy {
                thresholds: [f64::EPSILON, 0.5, 1.0 - f64::EPSILON],
                allow_hot_elevation: true,
            },
        ];

        for (i, policy) in extreme_policies.iter().enumerate() {
            // Test boundary scores
            for &score in &[0.0, 0.25, 0.50, 0.75, 1.0] {
                let rail = policy.rail_for_score(score);
                assert!(IsolationRail::ALL.contains(&rail),
                       "Policy {} should assign valid rail for score {}", i, score);
            }

            // Test policy serialization
            let json_result = serde_json::to_string(policy);
            assert!(json_result.is_ok(), "Extreme policy {} should serialize", i);

            if let Ok(json) = json_result {
                let parsed_result: Result<ElevationPolicy, _> = serde_json::from_str(&json);
                assert!(parsed_result.is_ok(), "Extreme policy {} should deserialize", i);
            }
        }
    }

    /// Test workload classification with malicious and edge case workload IDs
    #[test]
    fn test_classify_workload_malicious_ids() {
        let malicious_ids = [
            "",                                    // Empty ID (should fail)
            " ",                                   // Whitespace only
            "\n\r\t",                             // Control characters
            "\x00",                               // Null byte
            "id\x00injection",                    // Null byte injection
            "id\r\nCRLF\r\ninjection",           // CRLF injection
            "../../../etc/passwd",               // Path traversal
            "CON",                                // Windows reserved name
            "aux.txt",                            // Windows reserved with extension
            "\u{202E}spoofed",                    // Unicode right-to-left override
            "\u{FEFF}BOM",                        // Byte order mark
            "\u{200B}invisible",                  // Zero-width space
            "id\u{1F4A9}emoji",                  // Unicode emoji
            "x".repeat(100000),                   // Very long ID
            "<script>alert('xss')</script>",      // XSS attempt
            "'; DROP TABLE workloads; --",       // SQL injection attempt
            "id\x1b[31mred\x1b[0m",             // ANSI escape sequences
            "normal-id",                          // Valid reference for comparison
        ];

        for (i, &workload_id) in malicious_ids.iter().enumerate() {
            let mut router = default_router();
            let risk_score = 0.5; // Valid score

            let result = router.classify_workload(workload_id, risk_score);

            match result {
                Ok(classification) => {
                    // If accepted, workload ID should be preserved exactly
                    assert_eq!(classification.workload_id, workload_id);
                    assert_eq!(classification.risk_score, risk_score);
                    assert!(IsolationRail::ALL.contains(&classification.rail));

                    // Should be retrievable with same ID
                    let retrieved = router.get_classification(workload_id);
                    assert!(retrieved.is_ok(), "Should retrieve classified workload {}", i);

                    // Audit log should contain the workload ID
                    assert!(!router.audit_log().is_empty());
                }
                Err(RailRouterError::Unclassified { .. }) => {
                    // Expected for empty/invalid IDs
                    assert!(workload_id.trim().is_empty(), "Only empty IDs should be rejected as unclassified");
                    assert_eq!(router.workload_count(), 0);
                }
                Err(other) => {
                    panic!("Unexpected error for workload ID '{}': {:?}", workload_id, other);
                }
            }
        }

        // Test that malicious IDs don't interfere with normal operation
        let mut router = default_router();

        // Add a normal workload first
        router.classify_workload("normal", 0.3).expect("Normal workload should succeed");

        // Try to add malicious workloads
        for &malicious_id in &malicious_ids[..5] {
            if !malicious_id.trim().is_empty() {
                let _ = router.classify_workload(malicious_id, 0.7);
            }
        }

        // Normal workload should still be accessible
        let normal_classification = router.get_classification("normal");
        assert!(normal_classification.is_ok(), "Normal workload should remain accessible after malicious attempts");
    }

    /// Test hot elevation with extreme scenarios and attack patterns
    #[test]
    fn test_hot_elevate_extreme_scenarios() {
        let mut router = default_router();

        // Set up workloads on different rails
        router.classify_workload("shared", 0.1).unwrap();      // Shared rail
        router.classify_workload("sandboxed", 0.3).unwrap();   // Sandboxed rail
        router.classify_workload("hardened", 0.6).unwrap();    // HardenedSandbox rail
        router.classify_workload("full", 0.9).unwrap();        // FullIsolation rail

        // Test elevation with malicious reasons
        let malicious_reasons = [
            "",                                          // Empty reason
            "x".repeat(100000),                          // Very long reason
            "reason\x00null\r\ninjection",              // Null/CRLF injection
            "\u{202E}spoofed reason",                    // Unicode direction override
            "<script>alert('xss')</script>",             // XSS attempt
            "'; DROP TABLE elevations; --",             // SQL injection
            "reason\x1b[31mwith\x1b[0mANSI",           // ANSI escape sequences
            "\u{1F4A9}\u{1F525}\u{1F4A5}",              // Unicode emoji
            "legitimate security elevation",             // Normal reason for comparison
        ];

        for (i, &reason) in malicious_reasons.iter().enumerate() {
            // Test elevation from shared to sandboxed
            let elevation_result = router.hot_elevate("shared", IsolationRail::Sandboxed, reason);

            match elevation_result {
                Ok(event) => {
                    // Reason should be preserved exactly
                    assert_eq!(event.reason, reason);
                    assert_eq!(event.from, IsolationRail::Shared);
                    assert_eq!(event.to, IsolationRail::Sandboxed);
                    assert!(!event.trace_id.is_empty());

                    // Verify workload was actually elevated
                    let current_rail = router.get_rail("shared").unwrap();
                    assert_eq!(current_rail, IsolationRail::Sandboxed);

                    // Reset for next test
                    router.classifications.get_mut("shared").unwrap().rail = IsolationRail::Shared;
                }
                Err(err) => {
                    panic!("Hot elevation failed for reason {}: {:?}", i, err);
                }
            }
        }

        // Test elevation attempt with non-existent workload
        for &reason in &malicious_reasons[..3] {
            let nonexistent_result = router.hot_elevate("nonexistent", IsolationRail::FullIsolation, reason);
            assert!(matches!(nonexistent_result, Err(RailRouterError::WorkloadNotFound { .. })));
        }

        // Test all possible elevation paths for monotonicity
        let test_workloads = [
            ("w1", IsolationRail::Shared),
            ("w2", IsolationRail::Sandboxed),
            ("w3", IsolationRail::HardenedSandbox),
            ("w4", IsolationRail::FullIsolation),
        ];

        // Clear router and set up test workloads
        let mut router = default_router();
        for (id, rail) in &test_workloads {
            router.classify_workload(id, 0.5).unwrap();
            // Manually set to desired rail for testing
            router.classifications.get_mut(*id).unwrap().rail = *rail;
        }

        // Test every possible elevation attempt
        for (from_id, from_rail) in &test_workloads {
            for target_rail in &IsolationRail::ALL {
                let elevation_result = router.hot_elevate(from_id, *target_rail, "test elevation");

                if target_rail.is_stronger_than(from_rail) {
                    // Should succeed (upgrade)
                    assert!(elevation_result.is_ok(),
                           "Upgrade from {} to {} should succeed", from_rail, target_rail);
                } else if target_rail == from_rail {
                    // Should fail (same rail)
                    assert!(matches!(elevation_result, Err(RailRouterError::SameRailElevation { .. })),
                           "Same rail elevation from {} to {} should fail", from_rail, target_rail);
                } else {
                    // Should fail (downgrade)
                    assert!(matches!(elevation_result, Err(RailRouterError::DowngradeRejected { .. })),
                           "Downgrade from {} to {} should fail", from_rail, target_rail);
                }

                // Reset workload rail for next test
                router.classifications.get_mut(from_id).unwrap().rail = *from_rail;
            }
        }
    }

    /// Test router state consistency under concurrent-style operations
    #[test]
    fn test_router_state_consistency_stress() {
        let mut router = default_router();

        // Rapid workload classification and elevation
        for i in 0..1000 {
            let workload_id = format!("workload-{:04}", i);
            let risk_score = (i as f64) / 1000.0; // Scores from 0.0 to 0.999

            let classification_result = router.classify_workload(&workload_id, risk_score);
            assert!(classification_result.is_ok(), "Classification should succeed for workload {}", i);

            // Verify state consistency after each classification
            assert_eq!(router.workload_count(), i + 1);
            assert!(router.active_workloads().contains(&workload_id));

            let rail = router.get_rail(&workload_id).unwrap();
            let expected_rail = router.policy().rail_for_score(risk_score);
            assert_eq!(rail, expected_rail, "Rail assignment should be deterministic for score {}", risk_score);
        }

        // Test rail summary consistency
        let summary = router.rail_summary();
        let total_in_summary: usize = summary.values().sum();
        assert_eq!(total_in_summary, 1000, "Rail summary should account for all workloads");

        // Verify every rail type is represented in summary
        for rail in &IsolationRail::ALL {
            assert!(summary.contains_key(rail.as_str()), "Summary should contain {}", rail.as_str());
        }

        // Test elevation stress
        let workloads_to_elevate: Vec<_> = (0..100)
            .map(|i| format!("workload-{:04}", i))
            .collect();

        for workload_id in &workloads_to_elevate {
            let current_rail = router.get_rail(workload_id).unwrap();

            // Try to elevate to next stronger rail if possible
            if current_rail != IsolationRail::FullIsolation {
                let stronger_rails: Vec<_> = IsolationRail::ALL
                    .iter()
                    .filter(|&r| r.is_stronger_than(&current_rail))
                    .collect();

                if let Some(&target_rail) = stronger_rails.first() {
                    let elevation_result = router.hot_elevate(
                        workload_id,
                        *target_rail,
                        &format!("stress test elevation for {}", workload_id),
                    );
                    assert!(elevation_result.is_ok(), "Stress test elevation should succeed");

                    // Verify elevation took effect
                    let new_rail = router.get_rail(workload_id).unwrap();
                    assert_eq!(new_rail, *target_rail, "Elevation should update workload rail");
                }
            }
        }

        // Verify all workloads are still accessible after stress operations
        for i in 0..1000 {
            let workload_id = format!("workload-{:04}", i);
            let classification = router.get_classification(&workload_id);
            assert!(classification.is_ok(), "Workload {} should remain accessible after stress", i);
        }

        // Test audit log integrity
        let audit_log = router.audit_log();
        assert!(audit_log.len() >= 1000 * 2, "Should have at least classification + assignment events");

        // Verify audit events are chronologically consistent
        for window in audit_log.windows(2) {
            assert_eq!(window[0].timestamp, window[1].timestamp, "All timestamps should be equal in test environment");
        }
    }

    /// Test serialization and deserialization with malformed data
    #[test]
    fn test_serialization_attack_resistance() {
        // Test IsolationRail serialization edge cases
        let rail_json_tests = [
            ("\"shared\"", true),
            ("\"sandboxed\"", true),
            ("\"hardened_sandbox\"", true),
            ("\"full_isolation\"", true),
            ("\"Shared\"", false),        // Wrong case
            ("\"SHARED\"", false),        // Wrong case
            ("\"unknown_rail\"", false),  // Invalid variant
            ("0", false),                 // Numeric value
            ("null", false),              // Null value
            ("true", false),              // Boolean value
            ("\"\"", false),              // Empty string
        ];

        for (json, should_succeed) in &rail_json_tests {
            let result: Result<IsolationRail, _> = serde_json::from_str(json);
            assert_eq!(result.is_ok(), *should_succeed,
                      "IsolationRail deserialization should {} for: {}",
                      if *should_succeed { "succeed" } else { "fail" }, json);
        }

        // Test round-trip serialization of all rail types
        for rail in &IsolationRail::ALL {
            let json = serde_json::to_string(rail).expect("Rail should serialize");
            let deserialized: IsolationRail = serde_json::from_str(&json).expect("Rail should deserialize");
            assert_eq!(*rail, deserialized, "Round-trip should preserve rail type");
        }

        // Test WorkloadClassification with extreme data
        let classification = WorkloadClassification {
            workload_id: "test\x00\r\nid".to_string(),
            risk_score: f64::NAN,
            rail: IsolationRail::FullIsolation,
            classified_at: "2026-02-21T00:00:00Z".to_string(),
        };

        let json_result = serde_json::to_string(&classification);
        match json_result {
            Ok(json) => {
                // JSON should escape control characters
                assert!(json.contains("\\u0000") || json.contains("\\r") || json.contains("\\n"),
                       "JSON should escape control characters");

                // NaN should be serialized as null or special value
                let parsed_result: Result<WorkloadClassification, _> = serde_json::from_str(&json);
                // NaN deserialization behavior is implementation-specific, but should not crash
            }
            Err(_) => {
                // Rejection of NaN values during serialization is acceptable
            }
        }

        // Test ElevationEvent with extreme fields
        let extreme_event = ElevationEvent {
            workload_id: "x".repeat(100000),
            from: IsolationRail::Shared,
            to: IsolationRail::FullIsolation,
            reason: "\u{202E}spoofed\u{200B}reason".to_string(),
            trace_id: format!("trace-{}", "y".repeat(50000)),
            timestamp: "invalid-timestamp-format".to_string(),
        };

        let event_json_result = serde_json::to_string(&extreme_event);
        assert!(event_json_result.is_ok(), "Extreme elevation event should serialize");

        if let Ok(json) = event_json_result {
            let parsed_result: Result<ElevationEvent, _> = serde_json::from_str(&json);
            assert!(parsed_result.is_ok(), "Extreme elevation event should deserialize");

            if let Ok(parsed_event) = parsed_result {
                assert_eq!(parsed_event.workload_id.len(), 100000);
                assert!(parsed_event.reason.contains("spoofed"));
            }
        }
    }

    /// Test error handling and display formatting with extreme conditions
    #[test]
    fn test_error_handling_comprehensive() {
        let mut router = default_router();

        // Test all error variants with extreme data
        let error_test_cases = [
            RailRouterError::Unclassified {
                workload_id: "\x00\r\n\t".to_string(),
            },
            RailRouterError::DowngradeRejected {
                workload_id: "x".repeat(100000),
                current: IsolationRail::FullIsolation,
                requested: IsolationRail::Shared,
            },
            RailRouterError::WorkloadNotFound {
                workload_id: "\u{202E}spoofed\u{200B}id".to_string(),
            },
            RailRouterError::DuplicateWorkload {
                workload_id: "<script>alert('xss')</script>".to_string(),
            },
            RailRouterError::InvalidRiskScore {
                workload_id: "normal-id".to_string(),
                score: f64::NAN,
            },
            RailRouterError::SameRailElevation {
                workload_id: "test-id".to_string(),
                rail: IsolationRail::HardenedSandbox,
            },
            RailRouterError::HotElevationDisabled {
                workload_id: "disabled-test".to_string(),
                current: IsolationRail::Shared,
                requested: IsolationRail::FullIsolation,
            },
        ];

        for (i, error) in error_test_cases.iter().enumerate() {
            // Test error display formatting
            let error_string = format!("{}", error);
            assert!(!error_string.is_empty(), "Error {} should have non-empty display", i);

            // Error should contain workload ID (even if malformed)
            match error {
                RailRouterError::Unclassified { workload_id } |
                RailRouterError::WorkloadNotFound { workload_id } |
                RailRouterError::DuplicateWorkload { workload_id } |
                RailRouterError::SameRailElevation { workload_id, .. } |
                RailRouterError::InvalidRiskScore { workload_id, .. } |
                RailRouterError::HotElevationDisabled { workload_id, .. } => {
                    if !workload_id.is_empty() && workload_id.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                        assert!(error_string.contains(workload_id), "Error should contain workload ID");
                    }
                }
                RailRouterError::DowngradeRejected { workload_id, current, requested } => {
                    if workload_id.len() < 1000 { // Don't check very long IDs
                        assert!(error_string.contains(workload_id), "Error should contain workload ID");
                    }
                    assert!(error_string.contains(&current.to_string()), "Error should contain current rail");
                    assert!(error_string.contains(&requested.to_string()), "Error should contain requested rail");
                }
            }

            // Test error serialization
            let json_result = serde_json::to_string(error);
            assert!(json_result.is_ok(), "Error {} should serialize to JSON", i);

            if let Ok(json) = json_result {
                let parsed_result: Result<RailRouterError, _> = serde_json::from_str(&json);
                assert!(parsed_result.is_ok(), "Error {} should deserialize from JSON", i);

                // Verify round-trip preservation
                if let Ok(parsed_error) = parsed_result {
                    match (error, &parsed_error) {
                        (RailRouterError::InvalidRiskScore { score: s1, .. },
                         RailRouterError::InvalidRiskScore { score: s2, .. }) => {
                            // Special handling for NaN values
                            assert_eq!(s1.is_nan(), s2.is_nan(), "NaN values should round-trip consistently");
                        }
                        _ => {
                            // For other errors, exact equality should hold
                            assert_eq!(*error, parsed_error, "Error should round-trip exactly");
                        }
                    }
                }
            }
        }

        // Test error chaining and source information
        for error in &error_test_cases {
            let std_error: &dyn std::error::Error = error;
            let _source = std_error.source(); // Should not panic
            let _debug_format = format!("{:?}", error); // Should not panic
        }

        // Test that router remains functional after error conditions
        router.classify_workload("recovery-test", 0.5).expect("Router should remain functional");
        assert_eq!(router.workload_count(), 1);
    }

    /// Test audit log integrity and tamper resistance
    #[test]
    fn test_audit_log_integrity() {
        let mut router = default_router();

        // Perform various operations that should generate audit entries
        router.classify_workload("w1", 0.1).unwrap();
        router.classify_workload("w2", 0.3).unwrap();
        router.classify_workload("w3", 0.6).unwrap();

        let _ = router.classify_workload("", 0.5); // Should fail and generate audit
        let _ = router.classify_workload("w1", 0.7); // Duplicate, should fail
        let _ = router.classify_workload("w4", -0.1); // Invalid score, should fail

        router.hot_elevate("w1", IsolationRail::Sandboxed, "test elevation").unwrap();
        let _ = router.hot_elevate("w2", IsolationRail::Shared, "invalid downgrade"); // Should fail
        let _ = router.hot_elevate("nonexistent", IsolationRail::FullIsolation, "missing workload"); // Should fail

        let audit_log = router.audit_log();

        // Verify audit log has entries
        assert!(!audit_log.is_empty(), "Audit log should contain entries");

        // Check that all successful operations have corresponding audit entries
        let successful_classifications = audit_log.iter()
            .filter(|entry| entry.event_code == ISO_002)
            .count();
        assert_eq!(successful_classifications, 3, "Should have 3 successful classification events");

        let elevation_starts = audit_log.iter()
            .filter(|entry| entry.event_code == ISO_003)
            .count();
        let elevation_completions = audit_log.iter()
            .filter(|entry| entry.event_code == ISO_004)
            .count();
        assert_eq!(elevation_starts, elevation_completions, "Each elevation start should have completion");

        // Test audit entry integrity
        for (i, entry) in audit_log.iter().enumerate() {
            // Event code should be valid
            assert!(ALL_EVENT_CODES.contains(&&*entry.event_code),
                   "Entry {} should have valid event code: {}", i, entry.event_code);

            // Workload ID should not be empty (except for certain edge cases)
            if entry.event_code != ISO_006 { // ISO_006 can have empty/invalid workload IDs
                assert!(!entry.workload_id.is_empty(), "Entry {} should have non-empty workload ID", i);
            }

            // Timestamp should be consistent
            assert_eq!(entry.timestamp, "2026-02-21T00:00:00Z", "Entry {} should have consistent timestamp", i);

            // Detail should provide meaningful information
            assert!(!entry.detail.is_empty(), "Entry {} should have non-empty detail", i);
        }

        // Test that audit entries are immutable (log is append-only)
        let initial_log_len = audit_log.len();
        router.classify_workload("w5", 0.8).unwrap();
        let new_log_len = router.audit_log().len();
        assert!(new_log_len > initial_log_len, "Audit log should grow with new operations");

        // Verify previous entries remain unchanged
        for (i, entry) in router.audit_log().iter().take(initial_log_len).enumerate() {
            assert_eq!(entry, &audit_log[i], "Previous audit entry {} should remain unchanged", i);
        }

        // Test audit log with extreme workload IDs
        let extreme_ids = [
            "unicode-\u{1F4A9}-test",
            "\x00null\r\ninjection",
            "x".repeat(10000),
        ];

        for &extreme_id in &extreme_ids {
            if !extreme_id.trim().is_empty() {
                let _ = router.classify_workload(extreme_id, 0.5);
            }
        }

        // Audit log should handle extreme data without corruption
        let final_audit_log = router.audit_log();
        for entry in final_audit_log {
            let json_result = serde_json::to_string(entry);
            assert!(json_result.is_ok(), "Audit entry should serialize despite extreme workload IDs");
        }
    }

    /// Test router removal and cleanup operations with edge cases
    #[test]
    fn test_workload_removal_edge_cases() {
        let mut router = default_router();

        // Set up various workloads
        router.classify_workload("normal", 0.3).unwrap();
        router.classify_workload("elevated", 0.1).unwrap();
        router.hot_elevate("elevated", IsolationRail::HardenedSandbox, "test").unwrap();

        // Test normal removal
        let removed = router.remove_workload("normal").unwrap();
        assert_eq!(removed.workload_id, "normal");
        assert_eq!(removed.rail, IsolationRail::Sandboxed);
        assert_eq!(router.workload_count(), 1);

        // Test removal of non-existent workload
        let not_found = router.remove_workload("nonexistent");
        assert!(matches!(not_found, Err(RailRouterError::WorkloadNotFound { .. })));

        // Test removal of already removed workload
        let already_removed = router.remove_workload("normal");
        assert!(matches!(already_removed, Err(RailRouterError::WorkloadNotFound { .. })));

        // Test removal preserves elevation history
        let elevation_log_before = router.elevation_log().len();
        router.remove_workload("elevated").unwrap();
        assert_eq!(router.elevation_log().len(), elevation_log_before,
                  "Elevation history should be preserved after workload removal");

        // Test removal with extreme workload IDs
        let extreme_ids = [
            "\x00null",
            "\u{202E}spoofed",
            "x".repeat(100000),
        ];

        for &extreme_id in &extreme_ids {
            if !extreme_id.trim().is_empty() {
                // Add workload with extreme ID
                let classify_result = router.classify_workload(extreme_id, 0.5);
                if classify_result.is_ok() {
                    // Remove it
                    let remove_result = router.remove_workload(extreme_id);
                    assert!(remove_result.is_ok(), "Should be able to remove workload with extreme ID");
                }
            }
        }

        // Test that router remains functional after removals
        assert_eq!(router.workload_count(), 0);
        router.classify_workload("after-removal", 0.7).unwrap();
        assert_eq!(router.workload_count(), 1);

        // Test rail summary after removals
        let summary = router.rail_summary();
        let total_in_summary: usize = summary.values().sum();
        assert_eq!(total_in_summary, router.workload_count());
    }

    #[test]
    fn classify_rejects_whitespace_workload_id_without_admission() {
        let mut r = default_router();

        let err = r.classify_workload(" \t\n", 0.75).unwrap_err();

        assert!(matches!(
            err,
            RailRouterError::Unclassified { workload_id } if workload_id.trim().is_empty()
        ));
        assert_eq!(r.workload_count(), 0);
        assert!(!r.active_workloads().contains(" \t\n"));
    }

    #[test]
    fn classify_blank_workload_id_emits_iso_006_audit() {
        let mut r = default_router();

        let _ = r.classify_workload("  ", 0.50).unwrap_err();

        assert_eq!(r.audit_log().len(), 1);
        assert_eq!(r.audit_log()[0].event_code, ISO_006);
        assert_eq!(r.audit_log()[0].workload_id, "  ");
        assert!(r.audit_log()[0].detail.contains("blank workload_id"));
    }

    #[test]
    fn blank_workload_rejection_preserves_rail_summary() {
        let mut r = default_router();
        r.classify_workload("valid", 0.6).unwrap();
        let summary_before = r.rail_summary();

        let err = r.classify_workload(" ", 0.1).unwrap_err();

        assert!(matches!(err, RailRouterError::Unclassified { .. }));
        assert_eq!(r.rail_summary(), summary_before);
        assert_eq!(r.get_rail("valid").unwrap(), IsolationRail::HardenedSandbox);
    }

    #[test]
    fn rejected_blank_workload_does_not_block_later_valid_admission() {
        let mut r = default_router();
        let _ = r.classify_workload("\n", 0.9).unwrap_err();

        let admitted = r.classify_workload("valid-after-blank", 0.9).unwrap();

        assert_eq!(admitted.rail, IsolationRail::FullIsolation);
        assert_eq!(r.workload_count(), 1);
        assert!(r.active_workloads().contains("valid-after-blank"));
    }

    #[test]
    fn hot_elevate_empty_workload_id_rejects_without_state_change() {
        let mut r = default_router();
        r.classify_workload("valid", 0.1).unwrap();
        let audit_before = r.audit_log().len();

        let err = r
            .hot_elevate("", IsolationRail::FullIsolation, "empty id")
            .unwrap_err();

        assert!(matches!(err, RailRouterError::WorkloadNotFound { .. }));
        assert_eq!(r.get_rail("valid").unwrap(), IsolationRail::Shared);
        assert!(r.elevation_log().is_empty());
        assert_eq!(r.audit_log().len(), audit_before);
        assert_eq!(r.seq, 0);
    }

    #[test]
    fn remove_blank_workload_id_rejects_without_state_change() {
        let mut r = default_router();
        r.classify_workload("valid", 0.9).unwrap();
        let active_before = r.active_workloads();
        let audit_before = r.audit_log().len();

        let err = r.remove_workload(" ").unwrap_err();

        assert!(matches!(err, RailRouterError::WorkloadNotFound { .. }));
        assert_eq!(r.active_workloads(), active_before);
        assert_eq!(r.workload_count(), 1);
        assert_eq!(r.audit_log().len(), audit_before);
    }

    // === Hot-elevation ===

    #[test]
    fn hot_elevate_succeeds() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        let ev = r
            .hot_elevate("w1", IsolationRail::Sandboxed, "threat detected")
            .unwrap();
        assert_eq!(ev.from, IsolationRail::Shared);
        assert_eq!(ev.to, IsolationRail::Sandboxed);
        assert_eq!(ev.workload_id, "w1");
        assert!(!ev.trace_id.is_empty());
    }

    #[test]
    fn hot_elevate_monotonic_rejects_downgrade() {
        let mut r = default_router();
        r.classify_workload("w1", 0.6).unwrap(); // HardenedSandbox
        let err = r
            .hot_elevate("w1", IsolationRail::Shared, "relax")
            .unwrap_err();
        assert!(matches!(err, RailRouterError::DowngradeRejected { .. }));
    }

    #[test]
    fn hot_elevate_rejects_same_rail() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap(); // Shared
        let err = r
            .hot_elevate("w1", IsolationRail::Shared, "no reason")
            .unwrap_err();
        assert!(matches!(err, RailRouterError::SameRailElevation { .. }));
    }

    #[test]
    fn hot_elevate_unknown_workload() {
        let mut r = default_router();
        let err = r
            .hot_elevate("missing", IsolationRail::Sandboxed, "x")
            .unwrap_err();
        assert!(matches!(err, RailRouterError::WorkloadNotFound { .. }));
    }

    #[test]
    fn hot_elevate_respects_disabled_policy() {
        let mut r = RailRouter::new(ElevationPolicy {
            allow_hot_elevation: false,
            ..ElevationPolicy::default()
        });
        r.classify_workload("w1", 0.1).unwrap();

        let err = r
            .hot_elevate("w1", IsolationRail::Sandboxed, "policy-off")
            .unwrap_err();
        assert!(matches!(
            err,
            RailRouterError::HotElevationDisabled {
                current: IsolationRail::Shared,
                requested: IsolationRail::Sandboxed,
                ..
            }
        ));
        assert_eq!(r.get_rail("w1").unwrap(), IsolationRail::Shared);
    }

    #[test]
    fn hot_elevate_same_rail_does_not_log_or_advance_trace() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        let audit_before = r.audit_log().len();

        let err = r
            .hot_elevate("w1", IsolationRail::Shared, "same rail")
            .unwrap_err();

        assert!(matches!(err, RailRouterError::SameRailElevation { .. }));
        assert_eq!(r.get_rail("w1").unwrap(), IsolationRail::Shared);
        assert!(r.elevation_log().is_empty());
        assert_eq!(r.audit_log().len(), audit_before);
        assert_eq!(r.seq, 0);
    }

    #[test]
    fn hot_elevate_unknown_workload_preserves_existing_state() {
        let mut r = default_router();
        r.classify_workload("w1", 0.6).unwrap();
        let audit_before = r.audit_log().len();
        let active_before = r.active_workloads();

        let err = r
            .hot_elevate("missing", IsolationRail::FullIsolation, "unknown")
            .unwrap_err();

        assert!(matches!(err, RailRouterError::WorkloadNotFound { .. }));
        assert_eq!(r.active_workloads(), active_before);
        assert_eq!(r.get_rail("w1").unwrap(), IsolationRail::HardenedSandbox);
        assert!(r.elevation_log().is_empty());
        assert_eq!(r.audit_log().len(), audit_before);
        assert_eq!(r.seq, 0);
    }

    #[test]
    fn hot_elevate_disabled_policy_does_not_log_or_advance_trace() {
        let mut r = RailRouter::new(ElevationPolicy {
            allow_hot_elevation: false,
            ..ElevationPolicy::default()
        });
        r.classify_workload("w1", 0.1).unwrap();
        let audit_before = r.audit_log().len();

        let err = r
            .hot_elevate("w1", IsolationRail::Sandboxed, "disabled")
            .unwrap_err();

        assert!(matches!(err, RailRouterError::HotElevationDisabled { .. }));
        assert_eq!(r.get_rail("w1").unwrap(), IsolationRail::Shared);
        assert!(r.elevation_log().is_empty());
        assert_eq!(r.audit_log().len(), audit_before);
        assert_eq!(r.seq, 0);
    }

    #[test]
    fn hot_elevate_downgrade_rejection_preserves_rail_and_trace() {
        let mut r = default_router();
        r.classify_workload("w1", 0.6).unwrap();
        let audit_before = r.audit_log().len();

        let err = r
            .hot_elevate("w1", IsolationRail::Shared, "downgrade")
            .unwrap_err();

        assert!(matches!(err, RailRouterError::DowngradeRejected { .. }));
        assert_eq!(r.get_rail("w1").unwrap(), IsolationRail::HardenedSandbox);
        assert!(r.elevation_log().is_empty());
        assert_eq!(r.audit_log().len(), audit_before + 1);
        assert_eq!(r.audit_log().last().unwrap().event_code, ISO_005);
        assert_eq!(r.seq, 0);
    }

    #[test]
    fn hot_elevate_updates_classification() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        r.hot_elevate("w1", IsolationRail::FullIsolation, "critical")
            .unwrap();
        let rail = r.get_rail("w1").unwrap();
        assert_eq!(rail, IsolationRail::FullIsolation);
    }

    #[test]
    fn double_elevation_monotonic() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap(); // Shared
        r.hot_elevate("w1", IsolationRail::Sandboxed, "step 1")
            .unwrap();
        r.hot_elevate("w1", IsolationRail::HardenedSandbox, "step 2")
            .unwrap();
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
        r.hot_elevate("w1", IsolationRail::Sandboxed, "test")
            .unwrap();
        let codes: Vec<&str> = r
            .audit_log()
            .iter()
            .map(|a| a.event_code.as_str())
            .collect();
        assert!(codes.contains(&ISO_003));
        assert!(codes.contains(&ISO_004));
    }

    #[test]
    fn audit_log_records_downgrade_rejection() {
        let mut r = default_router();
        r.classify_workload("w1", 0.6).unwrap();
        let _ = r.hot_elevate("w1", IsolationRail::Shared, "bad");
        let codes: Vec<&str> = r
            .audit_log()
            .iter()
            .map(|a| a.event_code.as_str())
            .collect();
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

    #[test]
    fn remove_missing_workload_preserves_active_workloads() {
        let mut r = default_router();
        r.classify_workload("w1", 0.1).unwrap();
        r.classify_workload("w2", 0.9).unwrap();
        let active_before = r.active_workloads();
        let audit_before = r.audit_log().len();

        let err = r.remove_workload("missing").unwrap_err();

        assert!(matches!(err, RailRouterError::WorkloadNotFound { .. }));
        assert_eq!(r.active_workloads(), active_before);
        assert_eq!(r.workload_count(), 2);
        assert_eq!(r.audit_log().len(), audit_before);
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
            RailRouterError::Unclassified {
                workload_id: "w".into(),
            },
            RailRouterError::DowngradeRejected {
                workload_id: "w".into(),
                current: IsolationRail::Sandboxed,
                requested: IsolationRail::Shared,
            },
            RailRouterError::WorkloadNotFound {
                workload_id: "w".into(),
            },
            RailRouterError::DuplicateWorkload {
                workload_id: "w".into(),
            },
            RailRouterError::InvalidRiskScore {
                workload_id: "w".into(),
                score: 2.0,
            },
            RailRouterError::SameRailElevation {
                workload_id: "w".into(),
                rail: IsolationRail::Shared,
            },
            RailRouterError::HotElevationDisabled {
                workload_id: "w".into(),
                current: IsolationRail::Shared,
                requested: IsolationRail::Sandboxed,
            },
        ];
        let expected_codes = [
            ERR_ISO_UNCLASSIFIED,
            ERR_ISO_DOWNGRADE_REJECTED,
            ERR_ISO_WORKLOAD_NOT_FOUND,
            ERR_ISO_DUPLICATE_WORKLOAD,
            ERR_ISO_INVALID_RISK_SCORE,
            ERR_ISO_SAME_RAIL_ELEVATION,
            ERR_ISO_HOT_ELEVATION_DISABLED,
        ];
        for (err, code) in errors.iter().zip(expected_codes.iter()) {
            assert!(
                err.to_string().contains(code),
                "missing code {code} in: {err}"
            );
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
        assert_eq!(ALL_ERROR_CODES.len(), 7);
    }

    #[test]
    fn schema_version_set() {
        assert_eq!(SCHEMA_VERSION, "iso-mesh-v1.0");
    }
}
