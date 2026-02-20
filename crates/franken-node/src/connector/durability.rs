//! Durability mode enforcement for trust and control artifacts.
//!
//! Bead: bd-18ud (Section 10.14)
//!
//! Two modes:
//! - **Local** – single-node fsync confirmation. Suitable for re-derivable artifacts.
//! - **Quorum(M)** – M replica acknowledgements required before write is durable.
//!   Suitable for critical control artifacts (epoch markers, trust receipts).
//!
//! Mode switches are policy-gated and auditable. Claim language is deterministic:
//! identical (mode, outcome) inputs always produce identical claim strings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const DM_MODE_INITIALIZED: &str = "DM_MODE_INITIALIZED";
pub const DM_MODE_SWITCH: &str = "DM_MODE_SWITCH";
pub const DM_MODE_SWITCH_DENIED: &str = "DM_MODE_SWITCH_DENIED";
pub const DM_WRITE_LOCAL_CONFIRMED: &str = "DM_WRITE_LOCAL_CONFIRMED";
pub const DM_WRITE_QUORUM_CONFIRMED: &str = "DM_WRITE_QUORUM_CONFIRMED";
pub const DM_WRITE_QUORUM_FAILED: &str = "DM_WRITE_QUORUM_FAILED";
pub const DM_CLAIM_GENERATED: &str = "DM_CLAIM_GENERATED";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_QUORUM_INSUFFICIENT: &str = "ERR_QUORUM_INSUFFICIENT";
pub const ERR_MODE_SWITCH_DENIED: &str = "ERR_MODE_SWITCH_DENIED";
pub const ERR_INVALID_QUORUM_SIZE: &str = "ERR_INVALID_QUORUM_SIZE";

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

/// INV-DUR-ENFORCE: Write path enforces configured durability mode end-to-end.
pub const INV_DUR_ENFORCE: &str = "INV-DUR-ENFORCE";
/// INV-DUR-CLAIM-DETERMINISTIC: Claim language is deterministic for (mode, outcome) pairs.
pub const INV_DUR_CLAIM_DETERMINISTIC: &str = "INV-DUR-CLAIM-DETERMINISTIC";
/// INV-DUR-SWITCH-AUDITABLE: Mode switches are policy-gated and logged.
pub const INV_DUR_SWITCH_AUDITABLE: &str = "INV-DUR-SWITCH-AUDITABLE";
/// INV-DUR-QUORUM-FAIL-CLOSED: Quorum mode rejects writes when M not reached.
pub const INV_DUR_QUORUM_FAIL_CLOSED: &str = "INV-DUR-QUORUM-FAIL-CLOSED";

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Durability mode for an artifact class.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DurabilityMode {
    /// Single-node fsync confirmation.
    Local,
    /// Quorum persistence: `min_acks` replicas must acknowledge.
    Quorum { min_acks: u32 },
}

impl DurabilityMode {
    /// Human-readable label for this mode.
    pub fn label(&self) -> String {
        match self {
            DurabilityMode::Local => "local".to_string(),
            DurabilityMode::Quorum { min_acks } => format!("quorum({})", min_acks),
        }
    }

    /// Validate mode parameters.
    pub fn validate(&self) -> Result<(), DurabilityError> {
        match self {
            DurabilityMode::Local => Ok(()),
            DurabilityMode::Quorum { min_acks } => {
                if *min_acks == 0 {
                    Err(DurabilityError::new(
                        ERR_INVALID_QUORUM_SIZE,
                        "Quorum min_acks must be >= 1",
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl fmt::Display for DurabilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Outcome of a write operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WriteOutcome {
    /// Local fsync completed successfully.
    LocalFsyncConfirmed,
    /// Quorum acknowledged by M of N replicas.
    QuorumAcked { acked: u32, total: u32 },
    /// Quorum failed: insufficient acks.
    QuorumFailed { acked: u32, required: u32, total: u32 },
}

impl WriteOutcome {
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            WriteOutcome::LocalFsyncConfirmed | WriteOutcome::QuorumAcked { .. }
        )
    }
}

/// Structured claim about what durability guarantees were achieved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurabilityClaim {
    pub mode: DurabilityMode,
    pub outcome: WriteOutcome,
    pub claim_string: String,
    pub deterministic: bool,
}

impl DurabilityClaim {
    /// Derive a deterministic claim from (mode, outcome).
    pub fn derive(mode: &DurabilityMode, outcome: &WriteOutcome) -> Self {
        let claim_string = match (mode, outcome) {
            (DurabilityMode::Local, WriteOutcome::LocalFsyncConfirmed) => {
                "local-fsync-confirmed".to_string()
            }
            (DurabilityMode::Quorum { min_acks }, WriteOutcome::QuorumAcked { acked, total }) => {
                format!("quorum-{}-of-{}-acked(min={})", acked, total, min_acks)
            }
            (DurabilityMode::Quorum { min_acks }, WriteOutcome::QuorumFailed { acked, required, total }) => {
                format!(
                    "quorum-failed-{}-of-{}-acked(required={},min={})",
                    acked, total, required, min_acks
                )
            }
            (DurabilityMode::Local, WriteOutcome::QuorumAcked { .. })
            | (DurabilityMode::Local, WriteOutcome::QuorumFailed { .. }) => {
                "local-mode-unexpected-quorum-outcome".to_string()
            }
            (DurabilityMode::Quorum { .. }, WriteOutcome::LocalFsyncConfirmed) => {
                "quorum-mode-unexpected-local-outcome".to_string()
            }
        };

        DurabilityClaim {
            mode: mode.clone(),
            outcome: outcome.clone(),
            claim_string,
            deterministic: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurabilityError {
    pub code: String,
    pub message: String,
}

impl DurabilityError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        DurabilityError {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn quorum_insufficient(acked: u32, required: u32) -> Self {
        Self::new(
            ERR_QUORUM_INSUFFICIENT,
            format!(
                "Quorum write failed: {} acks received, {} required",
                acked, required
            ),
        )
    }

    pub fn mode_switch_denied(from: &DurabilityMode, to: &DurabilityMode) -> Self {
        Self::new(
            ERR_MODE_SWITCH_DENIED,
            format!(
                "Mode switch from {} to {} denied: operator authorization required",
                from, to
            ),
        )
    }
}

impl fmt::Display for DurabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurabilityEvent {
    pub code: String,
    pub mode: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Mode policy (controls authorized transitions)
// ---------------------------------------------------------------------------

/// Policy for mode switching authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeSwitchPolicy {
    /// Whether mode upgrades (local → quorum) are allowed without operator auth.
    pub allow_upgrade_without_auth: bool,
    /// Whether mode downgrades (quorum → local) are allowed without operator auth.
    pub allow_downgrade_without_auth: bool,
}

impl Default for ModeSwitchPolicy {
    fn default() -> Self {
        ModeSwitchPolicy {
            // Upgrades to higher durability are safe by default.
            allow_upgrade_without_auth: true,
            // Downgrades require explicit authorization.
            allow_downgrade_without_auth: false,
        }
    }
}

impl ModeSwitchPolicy {
    /// Create a strict policy requiring auth for all transitions.
    pub fn strict() -> Self {
        ModeSwitchPolicy {
            allow_upgrade_without_auth: false,
            allow_downgrade_without_auth: false,
        }
    }

    /// Check whether a mode transition is authorized.
    pub fn is_authorized(
        &self,
        from: &DurabilityMode,
        to: &DurabilityMode,
        operator_authorized: bool,
    ) -> bool {
        if operator_authorized {
            return true;
        }
        match (from, to) {
            (DurabilityMode::Local, DurabilityMode::Quorum { .. }) => {
                self.allow_upgrade_without_auth
            }
            (DurabilityMode::Quorum { .. }, DurabilityMode::Local) => {
                self.allow_downgrade_without_auth
            }
            // Same mode type: allow quorum size changes only with auth.
            (DurabilityMode::Quorum { min_acks: a }, DurabilityMode::Quorum { min_acks: b }) => {
                if b > a {
                    self.allow_upgrade_without_auth
                } else if b < a {
                    self.allow_downgrade_without_auth
                } else {
                    true // No change
                }
            }
            (DurabilityMode::Local, DurabilityMode::Local) => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Replica simulator (for quorum ack counting)
// ---------------------------------------------------------------------------

/// Simulated replica response for quorum mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaResponse {
    pub replica_id: String,
    pub acked: bool,
}

// ---------------------------------------------------------------------------
// DurabilityController
// ---------------------------------------------------------------------------

/// Per-class durability mode controller.
///
/// Manages the durability mode for an artifact class, enforces write
/// semantics, and produces deterministic claims.
#[derive(Debug)]
pub struct DurabilityController {
    class_id: String,
    mode: DurabilityMode,
    policy: ModeSwitchPolicy,
    events: Vec<DurabilityEvent>,
}

impl DurabilityController {
    /// Create a controller for an artifact class with the given mode.
    pub fn new(class_id: impl Into<String>, mode: DurabilityMode, policy: ModeSwitchPolicy) -> Self {
        let class_id = class_id.into();
        let mut ctrl = DurabilityController {
            class_id: class_id.clone(),
            mode: mode.clone(),
            policy,
            events: Vec::new(),
        };
        ctrl.emit(
            DM_MODE_INITIALIZED,
            &mode,
            format!("Durability mode {} initialized for class {}", mode, class_id),
        );
        ctrl
    }

    /// Create with Local mode and default policy.
    pub fn local(class_id: impl Into<String>) -> Self {
        Self::new(class_id, DurabilityMode::Local, ModeSwitchPolicy::default())
    }

    /// Create with Quorum mode and default policy.
    pub fn quorum(class_id: impl Into<String>, min_acks: u32) -> Self {
        Self::new(
            class_id,
            DurabilityMode::Quorum { min_acks },
            ModeSwitchPolicy::default(),
        )
    }

    /// Current durability mode.
    pub fn mode(&self) -> &DurabilityMode {
        &self.mode
    }

    /// Class ID this controller manages.
    pub fn class_id(&self) -> &str {
        &self.class_id
    }

    /// Switch durability mode (policy-gated).
    pub fn switch_mode(
        &mut self,
        new_mode: DurabilityMode,
        operator_authorized: bool,
    ) -> Result<(), DurabilityError> {
        let current_mode = self.mode.clone();
        if !self
            .policy
            .is_authorized(&current_mode, &new_mode, operator_authorized)
        {
            self.emit(
                DM_MODE_SWITCH_DENIED,
                &current_mode,
                format!(
                    "Mode switch from {} to {} denied for class {}",
                    current_mode, new_mode, self.class_id
                ),
            );
            return Err(DurabilityError::mode_switch_denied(&current_mode, &new_mode));
        }

        self.mode = new_mode.clone();
        self.emit(
            DM_MODE_SWITCH,
            &new_mode,
            format!(
                "Mode switched from {} to {} for class {}",
                current_mode, new_mode, self.class_id
            ),
        );
        Ok(())
    }

    /// Execute a local write. Returns a claim on success.
    pub fn write_local(&mut self) -> Result<DurabilityClaim, DurabilityError> {
        let mode = self.mode.clone();
        match &mode {
            DurabilityMode::Local => {
                let outcome = WriteOutcome::LocalFsyncConfirmed;
                let claim = DurabilityClaim::derive(&mode, &outcome);
                self.emit(
                    DM_WRITE_LOCAL_CONFIRMED,
                    &mode,
                    format!("Local fsync confirmed for class {}", self.class_id),
                );
                self.emit(
                    DM_CLAIM_GENERATED,
                    &mode,
                    format!("Claim: {}", claim.claim_string),
                );
                Ok(claim)
            }
            DurabilityMode::Quorum { .. } => {
                // Cannot satisfy quorum mode with local write alone.
                Err(DurabilityError::new(
                    ERR_QUORUM_INSUFFICIENT,
                    "Cannot use write_local in quorum mode",
                ))
            }
        }
    }

    /// Execute a quorum write with the given replica responses.
    /// Fail-closed: if fewer than min_acks replicas acknowledge, the write
    /// is rejected.
    pub fn write_quorum(
        &mut self,
        responses: &[ReplicaResponse],
    ) -> Result<DurabilityClaim, DurabilityError> {
        let mode = self.mode.clone();
        match &mode {
            DurabilityMode::Quorum { min_acks } => {
                let acked = responses.iter().filter(|r| r.acked).count() as u32;
                let total = responses.len() as u32;
                let min_acks = *min_acks;

                if acked >= min_acks {
                    let outcome = WriteOutcome::QuorumAcked { acked, total };
                    let claim = DurabilityClaim::derive(&mode, &outcome);
                    self.emit(
                        DM_WRITE_QUORUM_CONFIRMED,
                        &mode,
                        format!(
                            "Quorum write confirmed: {}/{} acks for class {}",
                            acked, total, self.class_id
                        ),
                    );
                    self.emit(
                        DM_CLAIM_GENERATED,
                        &mode,
                        format!("Claim: {}", claim.claim_string),
                    );
                    Ok(claim)
                } else {
                    let outcome = WriteOutcome::QuorumFailed {
                        acked,
                        required: min_acks,
                        total,
                    };
                    let claim = DurabilityClaim::derive(&mode, &outcome);
                    self.emit(
                        DM_WRITE_QUORUM_FAILED,
                        &mode,
                        format!(
                            "Quorum write FAILED: {}/{} acks (required {}) for class {}",
                            acked, total, min_acks, self.class_id
                        ),
                    );
                    self.emit(
                        DM_CLAIM_GENERATED,
                        &mode,
                        format!("Claim: {}", claim.claim_string),
                    );
                    Err(DurabilityError::quorum_insufficient(acked, min_acks))
                }
            }
            DurabilityMode::Local => Err(DurabilityError::new(
                ERR_QUORUM_INSUFFICIENT,
                "Cannot use write_quorum in local mode",
            )),
        }
    }

    /// Generate the claim matrix for all valid (mode, outcome) pairs.
    pub fn claim_matrix() -> HashMap<String, DurabilityClaim> {
        let mut matrix = HashMap::new();

        // Local mode
        let local = DurabilityMode::Local;
        let local_fsync = WriteOutcome::LocalFsyncConfirmed;
        let claim = DurabilityClaim::derive(&local, &local_fsync);
        matrix.insert("local+fsync_confirmed".to_string(), claim);

        // Quorum mode — representative cases
        for min_acks in [1, 3, 5] {
            let mode = DurabilityMode::Quorum { min_acks };

            // Quorum success
            let outcome = WriteOutcome::QuorumAcked {
                acked: min_acks,
                total: min_acks + 2,
            };
            let claim = DurabilityClaim::derive(&mode, &outcome);
            matrix.insert(
                format!("quorum({})+acked({}/{})", min_acks, min_acks, min_acks + 2),
                claim,
            );

            // Quorum failure
            let outcome = WriteOutcome::QuorumFailed {
                acked: min_acks.saturating_sub(1),
                required: min_acks,
                total: min_acks + 2,
            };
            let claim = DurabilityClaim::derive(&mode, &outcome);
            matrix.insert(
                format!(
                    "quorum({})+failed({}/{})",
                    min_acks,
                    min_acks.saturating_sub(1),
                    min_acks + 2
                ),
                claim,
            );
        }

        matrix
    }

    // -- Events --------------------------------------------------------------

    fn emit(&mut self, code: &str, mode: &DurabilityMode, detail: String) {
        self.events.push(DurabilityEvent {
            code: code.to_string(),
            mode: mode.label(),
            detail,
        });
    }

    /// All events emitted by this controller.
    pub fn events(&self) -> &[DurabilityEvent] {
        &self.events
    }

    /// Drain and return all events.
    pub fn take_events(&mut self) -> Vec<DurabilityEvent> {
        std::mem::take(&mut self.events)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_responses(acked: u32, nacked: u32) -> Vec<ReplicaResponse> {
        let mut responses = Vec::new();
        for i in 0..acked {
            responses.push(ReplicaResponse {
                replica_id: format!("r{}", i),
                acked: true,
            });
        }
        for i in 0..nacked {
            responses.push(ReplicaResponse {
                replica_id: format!("r{}", acked + i),
                acked: false,
            });
        }
        responses
    }

    // -- DurabilityMode ---------------------------------------------------

    #[test]
    fn test_mode_local_label() {
        assert_eq!(DurabilityMode::Local.label(), "local");
    }

    #[test]
    fn test_mode_quorum_label() {
        let mode = DurabilityMode::Quorum { min_acks: 3 };
        assert_eq!(mode.label(), "quorum(3)");
    }

    #[test]
    fn test_mode_local_display() {
        assert_eq!(format!("{}", DurabilityMode::Local), "local");
    }

    #[test]
    fn test_mode_quorum_display() {
        let mode = DurabilityMode::Quorum { min_acks: 5 };
        assert_eq!(format!("{}", mode), "quorum(5)");
    }

    #[test]
    fn test_mode_validate_local() {
        assert!(DurabilityMode::Local.validate().is_ok());
    }

    #[test]
    fn test_mode_validate_quorum_valid() {
        let mode = DurabilityMode::Quorum { min_acks: 3 };
        assert!(mode.validate().is_ok());
    }

    #[test]
    fn test_mode_validate_quorum_zero_rejected() {
        let mode = DurabilityMode::Quorum { min_acks: 0 };
        let err = mode.validate().unwrap_err();
        assert_eq!(err.code, ERR_INVALID_QUORUM_SIZE);
    }

    #[test]
    fn test_mode_serde_roundtrip_local() {
        let mode = DurabilityMode::Local;
        let json = serde_json::to_string(&mode).unwrap();
        let parsed: DurabilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, mode);
    }

    #[test]
    fn test_mode_serde_roundtrip_quorum() {
        let mode = DurabilityMode::Quorum { min_acks: 3 };
        let json = serde_json::to_string(&mode).unwrap();
        let parsed: DurabilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, mode);
    }

    // -- WriteOutcome -----------------------------------------------------

    #[test]
    fn test_outcome_local_is_success() {
        assert!(WriteOutcome::LocalFsyncConfirmed.is_success());
    }

    #[test]
    fn test_outcome_quorum_acked_is_success() {
        let outcome = WriteOutcome::QuorumAcked {
            acked: 3,
            total: 5,
        };
        assert!(outcome.is_success());
    }

    #[test]
    fn test_outcome_quorum_failed_is_not_success() {
        let outcome = WriteOutcome::QuorumFailed {
            acked: 1,
            required: 3,
            total: 5,
        };
        assert!(!outcome.is_success());
    }

    // -- DurabilityClaim --------------------------------------------------

    #[test]
    fn test_claim_local_fsync() {
        let claim = DurabilityClaim::derive(
            &DurabilityMode::Local,
            &WriteOutcome::LocalFsyncConfirmed,
        );
        assert_eq!(claim.claim_string, "local-fsync-confirmed");
        assert!(claim.deterministic);
    }

    #[test]
    fn test_claim_quorum_acked() {
        let claim = DurabilityClaim::derive(
            &DurabilityMode::Quorum { min_acks: 3 },
            &WriteOutcome::QuorumAcked {
                acked: 3,
                total: 5,
            },
        );
        assert_eq!(claim.claim_string, "quorum-3-of-5-acked(min=3)");
    }

    #[test]
    fn test_claim_quorum_failed() {
        let claim = DurabilityClaim::derive(
            &DurabilityMode::Quorum { min_acks: 3 },
            &WriteOutcome::QuorumFailed {
                acked: 2,
                required: 3,
                total: 5,
            },
        );
        assert_eq!(
            claim.claim_string,
            "quorum-failed-2-of-5-acked(required=3,min=3)"
        );
    }

    #[test]
    fn test_claim_determinism() {
        // INV-DUR-CLAIM-DETERMINISTIC: same inputs → same claim.
        let mode = DurabilityMode::Quorum { min_acks: 3 };
        let outcome = WriteOutcome::QuorumAcked {
            acked: 3,
            total: 5,
        };
        let c1 = DurabilityClaim::derive(&mode, &outcome);
        let c2 = DurabilityClaim::derive(&mode, &outcome);
        assert_eq!(c1.claim_string, c2.claim_string);
    }

    #[test]
    fn test_claim_serde_roundtrip() {
        let claim = DurabilityClaim::derive(
            &DurabilityMode::Local,
            &WriteOutcome::LocalFsyncConfirmed,
        );
        let json = serde_json::to_string(&claim).unwrap();
        let parsed: DurabilityClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, claim);
    }

    // -- ModeSwitchPolicy -------------------------------------------------

    #[test]
    fn test_default_policy_allows_upgrade() {
        let policy = ModeSwitchPolicy::default();
        assert!(policy.is_authorized(
            &DurabilityMode::Local,
            &DurabilityMode::Quorum { min_acks: 3 },
            false,
        ));
    }

    #[test]
    fn test_default_policy_denies_downgrade() {
        let policy = ModeSwitchPolicy::default();
        assert!(!policy.is_authorized(
            &DurabilityMode::Quorum { min_acks: 3 },
            &DurabilityMode::Local,
            false,
        ));
    }

    #[test]
    fn test_default_policy_allows_downgrade_with_auth() {
        let policy = ModeSwitchPolicy::default();
        assert!(policy.is_authorized(
            &DurabilityMode::Quorum { min_acks: 3 },
            &DurabilityMode::Local,
            true,
        ));
    }

    #[test]
    fn test_strict_policy_denies_upgrade_without_auth() {
        let policy = ModeSwitchPolicy::strict();
        assert!(!policy.is_authorized(
            &DurabilityMode::Local,
            &DurabilityMode::Quorum { min_acks: 3 },
            false,
        ));
    }

    #[test]
    fn test_strict_policy_allows_with_auth() {
        let policy = ModeSwitchPolicy::strict();
        assert!(policy.is_authorized(
            &DurabilityMode::Local,
            &DurabilityMode::Quorum { min_acks: 3 },
            true,
        ));
    }

    #[test]
    fn test_same_mode_same_params_allowed() {
        let policy = ModeSwitchPolicy::strict();
        let mode = DurabilityMode::Quorum { min_acks: 3 };
        assert!(policy.is_authorized(&mode, &mode, false));
    }

    #[test]
    fn test_quorum_size_increase_is_upgrade() {
        let policy = ModeSwitchPolicy::default();
        assert!(policy.is_authorized(
            &DurabilityMode::Quorum { min_acks: 3 },
            &DurabilityMode::Quorum { min_acks: 5 },
            false,
        ));
    }

    #[test]
    fn test_quorum_size_decrease_is_downgrade() {
        let policy = ModeSwitchPolicy::default();
        assert!(!policy.is_authorized(
            &DurabilityMode::Quorum { min_acks: 5 },
            &DurabilityMode::Quorum { min_acks: 3 },
            false,
        ));
    }

    // -- DurabilityController: local mode ---------------------------------

    #[test]
    fn test_controller_local_initialization() {
        let ctrl = DurabilityController::local("critical_marker");
        assert_eq!(ctrl.mode(), &DurabilityMode::Local);
        assert_eq!(ctrl.class_id(), "critical_marker");
    }

    #[test]
    fn test_controller_local_write() {
        let mut ctrl = DurabilityController::local("critical_marker");
        let claim = ctrl.write_local().unwrap();
        assert_eq!(claim.claim_string, "local-fsync-confirmed");
        assert!(claim.outcome.is_success());
    }

    #[test]
    fn test_controller_local_emits_events() {
        let mut ctrl = DurabilityController::local("test");
        ctrl.write_local().unwrap();
        let codes: Vec<_> = ctrl.events().iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&DM_MODE_INITIALIZED));
        assert!(codes.contains(&DM_WRITE_LOCAL_CONFIRMED));
        assert!(codes.contains(&DM_CLAIM_GENERATED));
    }

    // -- DurabilityController: quorum mode --------------------------------

    #[test]
    fn test_controller_quorum_initialization() {
        let ctrl = DurabilityController::quorum("trust_receipt", 3);
        assert_eq!(ctrl.mode(), &DurabilityMode::Quorum { min_acks: 3 });
    }

    #[test]
    fn test_controller_quorum_write_success() {
        let mut ctrl = DurabilityController::quorum("trust_receipt", 3);
        let responses = make_responses(3, 2); // 3 ack, 2 nack
        let claim = ctrl.write_quorum(&responses).unwrap();
        assert_eq!(claim.claim_string, "quorum-3-of-5-acked(min=3)");
    }

    #[test]
    fn test_controller_quorum_write_excess_acks() {
        let mut ctrl = DurabilityController::quorum("trust_receipt", 3);
        let responses = make_responses(5, 0); // all 5 ack
        let claim = ctrl.write_quorum(&responses).unwrap();
        assert_eq!(claim.claim_string, "quorum-5-of-5-acked(min=3)");
    }

    #[test]
    fn test_controller_quorum_write_fail_closed() {
        // INV-DUR-QUORUM-FAIL-CLOSED
        let mut ctrl = DurabilityController::quorum("trust_receipt", 3);
        let responses = make_responses(2, 3); // only 2 ack
        let err = ctrl.write_quorum(&responses).unwrap_err();
        assert_eq!(err.code, ERR_QUORUM_INSUFFICIENT);
    }

    #[test]
    fn test_controller_quorum_write_emits_events() {
        let mut ctrl = DurabilityController::quorum("test", 2);
        let responses = make_responses(3, 1);
        ctrl.write_quorum(&responses).unwrap();
        let codes: Vec<_> = ctrl.events().iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&DM_WRITE_QUORUM_CONFIRMED));
        assert!(codes.contains(&DM_CLAIM_GENERATED));
    }

    #[test]
    fn test_controller_quorum_failure_emits_events() {
        let mut ctrl = DurabilityController::quorum("test", 3);
        let responses = make_responses(1, 4);
        let _ = ctrl.write_quorum(&responses);
        let codes: Vec<_> = ctrl.events().iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&DM_WRITE_QUORUM_FAILED));
    }

    // -- DurabilityController: mode switch --------------------------------

    #[test]
    fn test_switch_local_to_quorum_default_policy() {
        let mut ctrl = DurabilityController::local("test");
        ctrl.switch_mode(DurabilityMode::Quorum { min_acks: 3 }, false)
            .unwrap();
        assert_eq!(ctrl.mode(), &DurabilityMode::Quorum { min_acks: 3 });
    }

    #[test]
    fn test_switch_quorum_to_local_denied_without_auth() {
        let mut ctrl = DurabilityController::quorum("test", 3);
        let err = ctrl
            .switch_mode(DurabilityMode::Local, false)
            .unwrap_err();
        assert_eq!(err.code, ERR_MODE_SWITCH_DENIED);
    }

    #[test]
    fn test_switch_quorum_to_local_allowed_with_auth() {
        let mut ctrl = DurabilityController::quorum("test", 3);
        ctrl.switch_mode(DurabilityMode::Local, true).unwrap();
        assert_eq!(ctrl.mode(), &DurabilityMode::Local);
    }

    #[test]
    fn test_switch_emits_mode_switch_event() {
        let mut ctrl = DurabilityController::local("test");
        ctrl.switch_mode(DurabilityMode::Quorum { min_acks: 2 }, false)
            .unwrap();
        let switch_events: Vec<_> = ctrl
            .events()
            .iter()
            .filter(|e| e.code == DM_MODE_SWITCH)
            .collect();
        assert_eq!(switch_events.len(), 1);
    }

    #[test]
    fn test_switch_denied_emits_denial_event() {
        let mut ctrl = DurabilityController::quorum("test", 3);
        let _ = ctrl.switch_mode(DurabilityMode::Local, false);
        let denied_events: Vec<_> = ctrl
            .events()
            .iter()
            .filter(|e| e.code == DM_MODE_SWITCH_DENIED)
            .collect();
        assert_eq!(denied_events.len(), 1);
    }

    // -- Cross-mode errors ------------------------------------------------

    #[test]
    fn test_local_write_in_quorum_mode_fails() {
        let mut ctrl = DurabilityController::quorum("test", 3);
        let err = ctrl.write_local().unwrap_err();
        assert_eq!(err.code, ERR_QUORUM_INSUFFICIENT);
    }

    #[test]
    fn test_quorum_write_in_local_mode_fails() {
        let mut ctrl = DurabilityController::local("test");
        let responses = make_responses(3, 0);
        let err = ctrl.write_quorum(&responses).unwrap_err();
        assert_eq!(err.code, ERR_QUORUM_INSUFFICIENT);
    }

    // -- Claim matrix -----------------------------------------------------

    #[test]
    fn test_claim_matrix_has_entries() {
        let matrix = DurabilityController::claim_matrix();
        assert!(matrix.len() >= 7); // 1 local + 3 success + 3 failure
    }

    #[test]
    fn test_claim_matrix_contains_local() {
        let matrix = DurabilityController::claim_matrix();
        assert!(matrix.contains_key("local+fsync_confirmed"));
    }

    #[test]
    fn test_claim_matrix_all_deterministic() {
        let matrix = DurabilityController::claim_matrix();
        for (_, claim) in &matrix {
            assert!(claim.deterministic);
        }
    }

    // -- Event log management ---------------------------------------------

    #[test]
    fn test_take_events_drains() {
        let mut ctrl = DurabilityController::local("test");
        assert!(!ctrl.events().is_empty());
        let events = ctrl.take_events();
        assert!(!events.is_empty());
        assert!(ctrl.events().is_empty());
    }

    // -- Event codes defined ----------------------------------------------

    #[test]
    fn test_event_codes_defined() {
        assert!(!DM_MODE_INITIALIZED.is_empty());
        assert!(!DM_MODE_SWITCH.is_empty());
        assert!(!DM_MODE_SWITCH_DENIED.is_empty());
        assert!(!DM_WRITE_LOCAL_CONFIRMED.is_empty());
        assert!(!DM_WRITE_QUORUM_CONFIRMED.is_empty());
        assert!(!DM_WRITE_QUORUM_FAILED.is_empty());
        assert!(!DM_CLAIM_GENERATED.is_empty());
    }

    // -- Invariant constants defined --------------------------------------

    #[test]
    fn test_invariant_constants_defined() {
        assert!(!INV_DUR_ENFORCE.is_empty());
        assert!(!INV_DUR_CLAIM_DETERMINISTIC.is_empty());
        assert!(!INV_DUR_SWITCH_AUDITABLE.is_empty());
        assert!(!INV_DUR_QUORUM_FAIL_CLOSED.is_empty());
    }

    // -- Error serde roundtrip --------------------------------------------

    #[test]
    fn test_error_serde_roundtrip() {
        let err = DurabilityError::quorum_insufficient(2, 3);
        let json = serde_json::to_string(&err).unwrap();
        let parsed: DurabilityError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    // -- Mixed mode scenario (switch then write) --------------------------

    #[test]
    fn test_switch_then_write_quorum() {
        let mut ctrl = DurabilityController::local("test");
        ctrl.switch_mode(DurabilityMode::Quorum { min_acks: 2 }, false)
            .unwrap();
        let responses = make_responses(3, 1);
        let claim = ctrl.write_quorum(&responses).unwrap();
        assert!(claim.claim_string.contains("quorum"));
    }

    #[test]
    fn test_switch_then_write_local() {
        let mut ctrl = DurabilityController::quorum("test", 3);
        ctrl.switch_mode(DurabilityMode::Local, true).unwrap();
        let claim = ctrl.write_local().unwrap();
        assert_eq!(claim.claim_string, "local-fsync-confirmed");
    }
}
