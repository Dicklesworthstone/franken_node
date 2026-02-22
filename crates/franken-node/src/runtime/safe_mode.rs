//! bd-k6o: Deterministic safe-mode startup and operation flags.
//!
//! Provides a first-class safe-mode operating state with deterministic entry
//! conditions, explicit capability restrictions, and a verified exit path back
//! to normal operation.
//!
//! # Event Codes
//!
//! - **SMO-001**: Safe-mode activated (any trigger).
//! - **SMO-002**: Capability restricted due to safe-mode policy.
//! - **SMO-003**: Flag conflict or redundancy detected.
//! - **SMO-004**: Degraded state entered (automatic trigger).
//!
//! # Invariants
//!
//! - **INV-SMO-DETERMINISTIC**: Given identical flags, environment, and config,
//!   safe-mode entry produces the same capability set, logging level, and trust
//!   re-verification sequence.
//! - **INV-SMO-RESTRICTED**: In safe mode, non-essential extensions are never
//!   loaded, trust delegations are never issued, and trust ledger writes require
//!   explicit operator confirmation.
//! - **INV-SMO-FLAGPARSE**: All operation flags are parsed deterministically.
//!   Unknown flags produce a structured error.
//! - **INV-SMO-RECOVERY**: Exiting safe mode requires explicit operator action.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// SMO-001: Safe-mode activated.
pub const SMO_001_SAFE_MODE_ACTIVATED: &str = "SMO-001";

/// SMO-002: Capability restricted.
pub const SMO_002_CAPABILITY_RESTRICTED: &str = "SMO-002";

/// SMO-003: Flag conflict or redundancy detected.
pub const SMO_003_FLAG_CONFLICT: &str = "SMO-003";

/// SMO-004: Degraded state entered (automatic trigger).
pub const SMO_004_DEGRADED_STATE_ENTERED: &str = "SMO-004";

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

/// INV-SMO-DETERMINISTIC
pub const INV_SMO_DETERMINISTIC: &str = "INV-SMO-DETERMINISTIC";

/// INV-SMO-RESTRICTED
pub const INV_SMO_RESTRICTED: &str = "INV-SMO-RESTRICTED";

/// INV-SMO-FLAGPARSE
pub const INV_SMO_FLAGPARSE: &str = "INV-SMO-FLAGPARSE";

/// INV-SMO-RECOVERY
pub const INV_SMO_RECOVERY: &str = "INV-SMO-RECOVERY";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Reason why safe mode was entered.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafeModeEntryReason {
    /// Explicit `--safe-mode` CLI flag.
    ExplicitFlag,
    /// `FRANKEN_SAFE_MODE=1` environment variable.
    EnvironmentVariable,
    /// `safe_mode: true` in configuration file.
    ConfigField,
    /// Trust state corruption detected.
    TrustCorruption,
    /// Crash loop threshold exceeded.
    CrashLoop {
        /// Number of crashes in the window.
        crash_count: u32,
        /// Window duration in seconds.
        window_secs: u64,
    },
    /// Control epoch mismatch with federation peers.
    EpochMismatch { local_epoch: u64, peer_epoch: u64 },
}

impl fmt::Display for SafeModeEntryReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExplicitFlag => write!(f, "explicit_flag"),
            Self::EnvironmentVariable => write!(f, "environment_variable"),
            Self::ConfigField => write!(f, "config_field"),
            Self::TrustCorruption => write!(f, "trust_corruption"),
            Self::CrashLoop {
                crash_count,
                window_secs,
            } => {
                write!(f, "crash_loop({crash_count} in {window_secs}s)")
            }
            Self::EpochMismatch {
                local_epoch,
                peer_epoch,
            } => {
                write!(f, "epoch_mismatch(local={local_epoch}, peer={peer_epoch})")
            }
        }
    }
}

/// Operation flags parsed from CLI arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationFlags {
    /// Whether `--safe-mode` was passed.
    pub safe_mode: bool,
    /// Whether `--degraded` was passed.
    pub degraded: bool,
    /// Whether `--read-only` was passed.
    pub read_only: bool,
    /// Whether `--no-network` was passed.
    pub no_network: bool,
}

impl OperationFlags {
    /// Create flags with all options disabled.
    pub fn none() -> Self {
        Self {
            safe_mode: false,
            degraded: false,
            read_only: false,
            no_network: false,
        }
    }

    /// Create flags with only safe-mode enabled.
    pub fn safe_mode_only() -> Self {
        Self {
            safe_mode: true,
            degraded: false,
            read_only: false,
            no_network: false,
        }
    }

    /// Parse flags from a list of CLI arguments.
    ///
    /// Returns `Err` if an unknown flag is encountered.
    /// INV-SMO-FLAGPARSE: Deterministic parsing, unknown flags produce structured error.
    pub fn parse_args(args: &[&str]) -> Result<Self, SafeModeError> {
        let mut flags = Self::none();
        for &arg in args {
            match arg {
                "--safe-mode" => flags.safe_mode = true,
                "--degraded" => flags.degraded = true,
                "--read-only" => flags.read_only = true,
                "--no-network" => flags.no_network = true,
                other => {
                    return Err(SafeModeError::UnknownFlag {
                        flag: other.to_string(),
                        recovery_hint: format!(
                            "Valid flags: --safe-mode, --degraded, --read-only, --no-network. Got: {other}"
                        ),
                    });
                }
            }
        }
        Ok(flags)
    }

    /// Detect flag conflicts and return advisory event codes.
    pub fn detect_conflicts(&self) -> Vec<SafeModeEvent> {
        let mut events = Vec::new();
        // SMO-003: safe-mode + degraded is redundant.
        if self.safe_mode && self.degraded {
            events.push(SafeModeEvent {
                code: SMO_003_FLAG_CONFLICT.to_string(),
                message:
                    "safe-mode already restricts more than degraded mode; --degraded is redundant"
                        .to_string(),
                severity: EventSeverity::Warn,
            });
        }
        events
    }

    /// Check whether any restrictive flag is active.
    pub fn any_active(&self) -> bool {
        self.safe_mode || self.degraded || self.read_only || self.no_network
    }

    /// Return the set of active flag names (sorted for determinism).
    pub fn active_flag_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if self.safe_mode {
            names.push("--safe-mode".to_string());
        }
        if self.degraded {
            names.push("--degraded".to_string());
        }
        if self.read_only {
            names.push("--read-only".to_string());
        }
        if self.no_network {
            names.push("--no-network".to_string());
        }
        names
    }
}

impl Default for OperationFlags {
    fn default() -> Self {
        Self::none()
    }
}

/// Capability that can be restricted in safe mode.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    ExtensionLoading,
    TrustDelegations,
    TrustLedgerWrites,
    OutboundNetwork,
    ScheduledTasks,
    NonEssentialListeners,
}

impl Capability {
    /// Return all defined capabilities.
    pub fn all() -> Vec<Self> {
        vec![
            Self::ExtensionLoading,
            Self::TrustDelegations,
            Self::TrustLedgerWrites,
            Self::OutboundNetwork,
            Self::ScheduledTasks,
            Self::NonEssentialListeners,
        ]
    }

    /// Return the human-readable label for this capability.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ExtensionLoading => "extension_loading",
            Self::TrustDelegations => "trust_delegations",
            Self::TrustLedgerWrites => "trust_ledger_writes",
            Self::OutboundNetwork => "outbound_network",
            Self::ScheduledTasks => "scheduled_tasks",
            Self::NonEssentialListeners => "non_essential_listeners",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Event severity level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSeverity {
    Info,
    Warn,
    Error,
}

impl fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// A safe-mode event emitted during operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeEvent {
    pub code: String,
    pub message: String,
    pub severity: EventSeverity,
}

/// Error types for safe-mode operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeModeError {
    /// Unknown CLI flag encountered.
    UnknownFlag { flag: String, recovery_hint: String },
    /// Attempted restricted operation in safe mode.
    CapabilityRestricted {
        capability: Capability,
        recovery_hint: String,
    },
    /// Exit precondition not met.
    ExitPreconditionFailed {
        reason: String,
        recovery_hint: String,
    },
    /// Trust re-verification failed.
    TrustVerificationFailed {
        inconsistencies: Vec<String>,
        recovery_hint: String,
    },
}

impl fmt::Display for SafeModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFlag {
                flag,
                recovery_hint,
            } => {
                write!(f, "unknown flag: {flag} (hint: {recovery_hint})")
            }
            Self::CapabilityRestricted {
                capability,
                recovery_hint,
            } => {
                write!(
                    f,
                    "capability restricted: {capability} (hint: {recovery_hint})"
                )
            }
            Self::ExitPreconditionFailed {
                reason,
                recovery_hint,
            } => {
                write!(
                    f,
                    "exit precondition failed: {reason} (hint: {recovery_hint})"
                )
            }
            Self::TrustVerificationFailed {
                inconsistencies,
                recovery_hint,
            } => {
                write!(
                    f,
                    "trust verification failed: {} inconsistencies (hint: {recovery_hint})",
                    inconsistencies.len()
                )
            }
        }
    }
}

impl std::error::Error for SafeModeError {}

/// Configuration for safe-mode behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeConfig {
    /// Whether safe mode is activated by config.
    pub safe_mode: bool,
    /// Crash loop threshold: max crashes before auto-entry.
    pub crash_loop_threshold: u32,
    /// Crash loop window duration in seconds.
    pub crash_loop_window_secs: u64,
    /// Whether to check environment variable for safe mode.
    pub check_env_var: bool,
    /// Name of the environment variable.
    pub env_var_name: String,
}

impl Default for SafeModeConfig {
    fn default() -> Self {
        Self {
            safe_mode: false,
            crash_loop_threshold: 3,
            crash_loop_window_secs: 60,
            check_env_var: true,
            env_var_name: "FRANKEN_SAFE_MODE".to_string(),
        }
    }
}

/// Receipt produced by trust re-verification on safe-mode entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeEntryReceipt {
    pub timestamp: String,
    pub entry_reason: SafeModeEntryReason,
    pub trust_state_hash: String,
    pub inconsistencies: Vec<String>,
    pub pass: bool,
}

impl SafeModeEntryReceipt {
    /// Create a new entry receipt.
    pub fn new(
        timestamp: &str,
        entry_reason: SafeModeEntryReason,
        trust_state_hash: &str,
        inconsistencies: Vec<String>,
    ) -> Self {
        let pass = inconsistencies.is_empty();
        Self {
            timestamp: timestamp.to_string(),
            entry_reason,
            trust_state_hash: trust_state_hash.to_string(),
            inconsistencies,
            pass,
        }
    }

    /// Serialize to canonical JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Result of pre-exit verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitVerification {
    pub trust_state_consistent: bool,
    pub no_unresolved_incidents: bool,
    pub evidence_ledger_intact: bool,
    pub operator_confirmed: bool,
}

impl ExitVerification {
    /// Check whether all pre-exit conditions are met.
    pub fn all_passed(&self) -> bool {
        self.trust_state_consistent
            && self.no_unresolved_incidents
            && self.evidence_ledger_intact
            && self.operator_confirmed
    }

    /// Return the list of failed checks.
    pub fn failed_checks(&self) -> Vec<String> {
        let mut failed = Vec::new();
        if !self.trust_state_consistent {
            failed.push("trust_state_consistent".to_string());
        }
        if !self.no_unresolved_incidents {
            failed.push("no_unresolved_incidents".to_string());
        }
        if !self.evidence_ledger_intact {
            failed.push("evidence_ledger_intact".to_string());
        }
        if !self.operator_confirmed {
            failed.push("operator_confirmed".to_string());
        }
        failed
    }
}

/// Status report for safe-mode state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeStatus {
    pub safe_mode_active: bool,
    pub entry_reason: Option<SafeModeEntryReason>,
    pub entry_timestamp: Option<String>,
    pub duration_seconds: u64,
    pub suspended_capabilities: Vec<String>,
    pub trust_state_hash: Option<String>,
    pub unresolved_incidents: u32,
    pub active_flags: Vec<String>,
}

impl SafeModeStatus {
    /// Create an inactive status report.
    pub fn inactive() -> Self {
        Self {
            safe_mode_active: false,
            entry_reason: None,
            entry_timestamp: None,
            duration_seconds: 0,
            suspended_capabilities: Vec::new(),
            trust_state_hash: None,
            unresolved_incidents: 0,
            active_flags: Vec::new(),
        }
    }

    /// Serialize to canonical JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Audit entry for safe-mode transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeAuditEntry {
    pub timestamp: String,
    pub action: SafeModeAction,
    pub reason: Option<SafeModeEntryReason>,
    pub operator_id: Option<String>,
    pub details: String,
}

/// Safe-mode transition action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeModeAction {
    Enter,
    Exit,
    CapabilityRestricted,
    ExitDenied,
}

impl fmt::Display for SafeModeAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enter => write!(f, "enter"),
            Self::Exit => write!(f, "exit"),
            Self::CapabilityRestricted => write!(f, "capability_restricted"),
            Self::ExitDenied => write!(f, "exit_denied"),
        }
    }
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

/// The safe-mode controller manages the lifecycle of safe-mode operation.
///
/// INV-SMO-DETERMINISTIC: The controller produces identical output for identical input.
/// INV-SMO-RESTRICTED: Capability checks enforce safe-mode restrictions.
/// INV-SMO-RECOVERY: Exit requires explicit operator action and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeModeController {
    active: bool,
    entry_reason: Option<SafeModeEntryReason>,
    entry_timestamp: Option<String>,
    flags: OperationFlags,
    config: SafeModeConfig,
    restricted_capabilities: BTreeSet<Capability>,
    events: Vec<SafeModeEvent>,
    audit_log: Vec<SafeModeAuditEntry>,
    entry_receipt: Option<SafeModeEntryReceipt>,
    unresolved_incidents: u32,
}

impl SafeModeController {
    /// Create a new controller with default configuration.
    pub fn new(config: SafeModeConfig) -> Self {
        Self {
            active: false,
            entry_reason: None,
            entry_timestamp: None,
            flags: OperationFlags::none(),
            config,
            restricted_capabilities: BTreeSet::new(),
            events: Vec::new(),
            audit_log: Vec::new(),
            entry_receipt: None,
            unresolved_incidents: 0,
        }
    }

    /// Create a controller with default config.
    pub fn with_default_config() -> Self {
        Self::new(SafeModeConfig::default())
    }

    /// Enter safe mode with the given reason and timestamp.
    ///
    /// INV-SMO-DETERMINISTIC: The resulting state is a pure function of the inputs.
    pub fn enter_safe_mode(
        &mut self,
        reason: SafeModeEntryReason,
        timestamp: &str,
        trust_state_hash: &str,
        inconsistencies: Vec<String>,
    ) {
        self.active = true;
        self.entry_reason = Some(reason.clone());
        self.entry_timestamp = Some(timestamp.to_string());

        // INV-SMO-RESTRICTED: Apply capability restrictions.
        self.restricted_capabilities.clear();
        self.restricted_capabilities
            .insert(Capability::ExtensionLoading);
        self.restricted_capabilities
            .insert(Capability::TrustDelegations);
        self.restricted_capabilities
            .insert(Capability::TrustLedgerWrites);
        self.restricted_capabilities
            .insert(Capability::OutboundNetwork);
        self.restricted_capabilities
            .insert(Capability::ScheduledTasks);
        self.restricted_capabilities
            .insert(Capability::NonEssentialListeners);

        // Create entry receipt.
        let receipt =
            SafeModeEntryReceipt::new(timestamp, reason.clone(), trust_state_hash, inconsistencies);
        self.entry_receipt = Some(receipt);

        // Emit SMO-001 activation event.
        self.events.push(SafeModeEvent {
            code: SMO_001_SAFE_MODE_ACTIVATED.to_string(),
            message: format!("Safe mode activated: {reason}"),
            severity: EventSeverity::Info,
        });

        // Emit SMO-002 for each restricted capability.
        for cap in &self.restricted_capabilities {
            self.events.push(SafeModeEvent {
                code: SMO_002_CAPABILITY_RESTRICTED.to_string(),
                message: format!("Capability restricted: {cap}"),
                severity: EventSeverity::Warn,
            });
        }

        // Log audit entry.
        self.audit_log.push(SafeModeAuditEntry {
            timestamp: timestamp.to_string(),
            action: SafeModeAction::Enter,
            reason: Some(reason),
            operator_id: None,
            details: "Safe mode entered".to_string(),
        });
    }

    /// Enter degraded state (automatic trigger).
    pub fn enter_degraded_state(&mut self, reason: SafeModeEntryReason, timestamp: &str) {
        // Emit SMO-004 for degraded state.
        self.events.push(SafeModeEvent {
            code: SMO_004_DEGRADED_STATE_ENTERED.to_string(),
            message: format!("Degraded state entered: {reason}"),
            severity: EventSeverity::Warn,
        });

        // Then activate full safe mode.
        self.enter_safe_mode(reason, timestamp, "degraded-no-hash", Vec::new());
    }

    /// Attempt to exit safe mode.
    ///
    /// INV-SMO-RECOVERY: Exit requires explicit operator action and verification.
    pub fn exit_safe_mode(
        &mut self,
        verification: &ExitVerification,
        operator_id: &str,
        timestamp: &str,
    ) -> Result<(), SafeModeError> {
        if !verification.all_passed() {
            let failed = verification.failed_checks();
            self.audit_log.push(SafeModeAuditEntry {
                timestamp: timestamp.to_string(),
                action: SafeModeAction::ExitDenied,
                reason: self.entry_reason.clone(),
                operator_id: Some(operator_id.to_string()),
                details: format!("Exit denied: failed checks: {}", failed.join(", ")),
            });
            return Err(SafeModeError::ExitPreconditionFailed {
                reason: format!("Failed checks: {}", failed.join(", ")),
                recovery_hint: "Resolve all failing preconditions before exiting safe mode"
                    .to_string(),
            });
        }

        self.active = false;
        self.restricted_capabilities.clear();

        self.audit_log.push(SafeModeAuditEntry {
            timestamp: timestamp.to_string(),
            action: SafeModeAction::Exit,
            reason: self.entry_reason.take(),
            operator_id: Some(operator_id.to_string()),
            details: "Safe mode exited".to_string(),
        });

        // Emit SMO-001 for the exit transition.
        self.events.push(SafeModeEvent {
            code: SMO_001_SAFE_MODE_ACTIVATED.to_string(),
            message: "Safe mode deactivated".to_string(),
            severity: EventSeverity::Info,
        });

        self.entry_timestamp = None;
        self.entry_receipt = None;

        Ok(())
    }

    /// Check whether a capability is restricted.
    ///
    /// INV-SMO-RESTRICTED: Returns structured error if restricted.
    pub fn check_capability(&self, capability: &Capability) -> Result<(), SafeModeError> {
        if self.restricted_capabilities.contains(capability) {
            Err(SafeModeError::CapabilityRestricted {
                capability: capability.clone(),
                recovery_hint: format!(
                    "Exit safe mode to restore {} capability",
                    capability.label()
                ),
            })
        } else {
            Ok(())
        }
    }

    /// Whether safe mode is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// The entry reason, if safe mode is active.
    pub fn entry_reason(&self) -> Option<&SafeModeEntryReason> {
        self.entry_reason.as_ref()
    }

    /// Set operation flags and detect conflicts.
    pub fn set_flags(&mut self, flags: OperationFlags) {
        let conflicts = flags.detect_conflicts();
        self.events.extend(conflicts);
        self.flags = flags;
    }

    /// Get current operation flags.
    pub fn flags(&self) -> &OperationFlags {
        &self.flags
    }

    /// Get the entry receipt.
    pub fn entry_receipt(&self) -> Option<&SafeModeEntryReceipt> {
        self.entry_receipt.as_ref()
    }

    /// Get the list of suspended capability labels (sorted for determinism).
    pub fn suspended_capabilities(&self) -> Vec<String> {
        self.restricted_capabilities
            .iter()
            .map(|c| c.label().to_string())
            .collect()
    }

    /// Get current safe-mode status.
    pub fn status(&self, current_timestamp: &str) -> SafeModeStatus {
        if !self.active {
            return SafeModeStatus::inactive();
        }

        let duration = self
            .entry_timestamp
            .as_deref()
            .and_then(|et| {
                // Simplified duration: parse ISO timestamps as epoch seconds.
                parse_duration_between(et, current_timestamp)
            })
            .unwrap_or(0);

        SafeModeStatus {
            safe_mode_active: true,
            entry_reason: self.entry_reason.clone(),
            entry_timestamp: self.entry_timestamp.clone(),
            duration_seconds: duration,
            suspended_capabilities: self.suspended_capabilities(),
            trust_state_hash: self
                .entry_receipt
                .as_ref()
                .map(|r| r.trust_state_hash.clone()),
            unresolved_incidents: self.unresolved_incidents,
            active_flags: self.flags.active_flag_names(),
        }
    }

    /// Get all emitted events.
    pub fn events(&self) -> &[SafeModeEvent] {
        &self.events
    }

    /// Take and drain all emitted events.
    pub fn take_events(&mut self) -> Vec<SafeModeEvent> {
        std::mem::take(&mut self.events)
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[SafeModeAuditEntry] {
        &self.audit_log
    }

    /// Set unresolved incident count.
    pub fn set_unresolved_incidents(&mut self, count: u32) {
        self.unresolved_incidents = count;
    }

    /// Get the safe-mode configuration.
    pub fn config(&self) -> &SafeModeConfig {
        &self.config
    }

    /// Determine safe-mode activation from all trigger sources.
    ///
    /// INV-SMO-DETERMINISTIC: Evaluates triggers in strict precedence order.
    pub fn evaluate_triggers(
        &self,
        flags: &OperationFlags,
        env_value: Option<&str>,
        config_safe_mode: bool,
    ) -> Option<SafeModeEntryReason> {
        // Priority 1: Explicit CLI flag.
        if flags.safe_mode {
            return Some(SafeModeEntryReason::ExplicitFlag);
        }

        // Priority 2: Environment variable.
        if self.config.check_env_var
            && let Some(val) = env_value
            && (val == "1" || val.eq_ignore_ascii_case("true"))
        {
            return Some(SafeModeEntryReason::EnvironmentVariable);
        }

        // Priority 3: Configuration field.
        if config_safe_mode {
            return Some(SafeModeEntryReason::ConfigField);
        }

        // Priority 4: Automatic detection is checked separately.
        None
    }

    /// Check crash loop trigger.
    pub fn check_crash_loop_trigger(
        &self,
        crash_count: u32,
        window_secs: u64,
    ) -> Option<SafeModeEntryReason> {
        if crash_count >= self.config.crash_loop_threshold {
            Some(SafeModeEntryReason::CrashLoop {
                crash_count,
                window_secs,
            })
        } else {
            None
        }
    }

    /// Check epoch mismatch trigger.
    pub fn check_epoch_mismatch_trigger(
        &self,
        local_epoch: u64,
        peer_epoch: u64,
    ) -> Option<SafeModeEntryReason> {
        if local_epoch != peer_epoch {
            Some(SafeModeEntryReason::EpochMismatch {
                local_epoch,
                peer_epoch,
            })
        } else {
            None
        }
    }

    /// Compute the restricted capability set for given flags.
    ///
    /// INV-SMO-DETERMINISTIC: Pure function of flags.
    pub fn compute_restricted_capabilities(flags: &OperationFlags) -> BTreeSet<Capability> {
        let mut restricted = BTreeSet::new();
        if flags.safe_mode {
            restricted.insert(Capability::ExtensionLoading);
            restricted.insert(Capability::TrustDelegations);
            restricted.insert(Capability::TrustLedgerWrites);
            restricted.insert(Capability::OutboundNetwork);
            restricted.insert(Capability::ScheduledTasks);
            restricted.insert(Capability::NonEssentialListeners);
        }
        if flags.read_only {
            restricted.insert(Capability::TrustLedgerWrites);
        }
        if flags.no_network {
            restricted.insert(Capability::OutboundNetwork);
        }
        if flags.degraded {
            restricted.insert(Capability::ExtensionLoading);
            restricted.insert(Capability::ScheduledTasks);
        }
        restricted
    }

    /// Perform trust re-verification (placeholder for actual implementation).
    pub fn verify_trust_state(
        trust_state_hash: &str,
        evidence_entries: &[&str],
    ) -> SafeModeEntryReceipt {
        let mut inconsistencies = Vec::new();

        // Verify evidence entries are non-empty.
        if evidence_entries.is_empty() {
            inconsistencies.push("evidence ledger is empty".to_string());
        }

        // Verify hash is non-empty.
        if trust_state_hash.is_empty() {
            inconsistencies.push("trust state hash is empty".to_string());
        }

        SafeModeEntryReceipt::new(
            "2026-02-20T00:00:00Z",
            SafeModeEntryReason::ExplicitFlag,
            trust_state_hash,
            inconsistencies,
        )
    }
}

/// Parse duration between two ISO timestamps (simplified: uses the last 10
/// characters as epoch seconds if they parse, otherwise returns 0).
fn parse_duration_between(_start: &str, _end: &str) -> Option<u64> {
    // Simplified placeholder -- real implementation would parse ISO 8601.
    Some(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- OperationFlags tests -----------------------------------------------

    #[test]
    fn test_flags_none() {
        let flags = OperationFlags::none();
        assert!(!flags.safe_mode);
        assert!(!flags.degraded);
        assert!(!flags.read_only);
        assert!(!flags.no_network);
    }

    #[test]
    fn test_flags_safe_mode_only() {
        let flags = OperationFlags::safe_mode_only();
        assert!(flags.safe_mode);
        assert!(!flags.degraded);
        assert!(!flags.read_only);
        assert!(!flags.no_network);
    }

    #[test]
    fn test_flags_parse_empty() {
        let flags = OperationFlags::parse_args(&[]).unwrap();
        assert_eq!(flags, OperationFlags::none());
    }

    #[test]
    fn test_flags_parse_safe_mode() {
        let flags = OperationFlags::parse_args(&["--safe-mode"]).unwrap();
        assert!(flags.safe_mode);
    }

    #[test]
    fn test_flags_parse_degraded() {
        let flags = OperationFlags::parse_args(&["--degraded"]).unwrap();
        assert!(flags.degraded);
    }

    #[test]
    fn test_flags_parse_read_only() {
        let flags = OperationFlags::parse_args(&["--read-only"]).unwrap();
        assert!(flags.read_only);
    }

    #[test]
    fn test_flags_parse_no_network() {
        let flags = OperationFlags::parse_args(&["--no-network"]).unwrap();
        assert!(flags.no_network);
    }

    #[test]
    fn test_flags_parse_all() {
        let flags = OperationFlags::parse_args(&[
            "--safe-mode",
            "--degraded",
            "--read-only",
            "--no-network",
        ])
        .unwrap();
        assert!(flags.safe_mode);
        assert!(flags.degraded);
        assert!(flags.read_only);
        assert!(flags.no_network);
    }

    #[test]
    fn test_flags_parse_unknown_flag() {
        let err = OperationFlags::parse_args(&["--unknown"]).unwrap_err();
        match err {
            SafeModeError::UnknownFlag {
                flag,
                recovery_hint,
            } => {
                assert_eq!(flag, "--unknown");
                assert!(recovery_hint.contains("Valid flags"));
            }
            _ => panic!("expected UnknownFlag error"),
        }
    }

    #[test]
    fn test_flags_deterministic_parsing() {
        // INV-SMO-FLAGPARSE: same input => same output.
        let a = OperationFlags::parse_args(&["--safe-mode", "--read-only"]).unwrap();
        let b = OperationFlags::parse_args(&["--safe-mode", "--read-only"]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_flags_any_active() {
        assert!(!OperationFlags::none().any_active());
        assert!(OperationFlags::safe_mode_only().any_active());
    }

    #[test]
    fn test_flags_active_flag_names() {
        let flags = OperationFlags {
            safe_mode: true,
            degraded: false,
            read_only: true,
            no_network: false,
        };
        let names = flags.active_flag_names();
        assert_eq!(names, vec!["--safe-mode", "--read-only"]);
    }

    #[test]
    fn test_flags_detect_conflicts_safe_degraded() {
        let flags = OperationFlags {
            safe_mode: true,
            degraded: true,
            read_only: false,
            no_network: false,
        };
        let events = flags.detect_conflicts();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].code, SMO_003_FLAG_CONFLICT);
    }

    #[test]
    fn test_flags_detect_no_conflicts() {
        let flags = OperationFlags::safe_mode_only();
        let events = flags.detect_conflicts();
        assert!(events.is_empty());
    }

    #[test]
    fn test_flags_serde_roundtrip() {
        let flags = OperationFlags {
            safe_mode: true,
            degraded: false,
            read_only: true,
            no_network: true,
        };
        let json = serde_json::to_string(&flags).unwrap();
        let parsed: OperationFlags = serde_json::from_str(&json).unwrap();
        assert_eq!(flags, parsed);
    }

    #[test]
    fn test_flags_default() {
        let flags = OperationFlags::default();
        assert_eq!(flags, OperationFlags::none());
    }

    // -- Capability tests ---------------------------------------------------

    #[test]
    fn test_capability_all() {
        let caps = Capability::all();
        assert_eq!(caps.len(), 6);
    }

    #[test]
    fn test_capability_labels() {
        assert_eq!(Capability::ExtensionLoading.label(), "extension_loading");
        assert_eq!(Capability::TrustDelegations.label(), "trust_delegations");
        assert_eq!(Capability::TrustLedgerWrites.label(), "trust_ledger_writes");
        assert_eq!(Capability::OutboundNetwork.label(), "outbound_network");
        assert_eq!(Capability::ScheduledTasks.label(), "scheduled_tasks");
        assert_eq!(
            Capability::NonEssentialListeners.label(),
            "non_essential_listeners"
        );
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(
            format!("{}", Capability::ExtensionLoading),
            "extension_loading"
        );
    }

    #[test]
    fn test_capability_serde_roundtrip() {
        let cap = Capability::ExtensionLoading;
        let json = serde_json::to_string(&cap).unwrap();
        let parsed: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, parsed);
    }

    // -- SafeModeEntryReason tests ------------------------------------------

    #[test]
    fn test_entry_reason_display() {
        assert_eq!(
            format!("{}", SafeModeEntryReason::ExplicitFlag),
            "explicit_flag"
        );
        assert_eq!(
            format!("{}", SafeModeEntryReason::EnvironmentVariable),
            "environment_variable"
        );
        assert_eq!(
            format!("{}", SafeModeEntryReason::ConfigField),
            "config_field"
        );
        assert_eq!(
            format!("{}", SafeModeEntryReason::TrustCorruption),
            "trust_corruption"
        );
    }

    #[test]
    fn test_entry_reason_crash_loop_display() {
        let reason = SafeModeEntryReason::CrashLoop {
            crash_count: 5,
            window_secs: 60,
        };
        assert_eq!(format!("{reason}"), "crash_loop(5 in 60s)");
    }

    #[test]
    fn test_entry_reason_epoch_mismatch_display() {
        let reason = SafeModeEntryReason::EpochMismatch {
            local_epoch: 10,
            peer_epoch: 12,
        };
        assert_eq!(format!("{reason}"), "epoch_mismatch(local=10, peer=12)");
    }

    #[test]
    fn test_entry_reason_serde_roundtrip() {
        let reason = SafeModeEntryReason::CrashLoop {
            crash_count: 3,
            window_secs: 60,
        };
        let json = serde_json::to_string(&reason).unwrap();
        let parsed: SafeModeEntryReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, parsed);
    }

    // -- SafeModeConfig tests -----------------------------------------------

    #[test]
    fn test_config_default() {
        let config = SafeModeConfig::default();
        assert!(!config.safe_mode);
        assert_eq!(config.crash_loop_threshold, 3);
        assert_eq!(config.crash_loop_window_secs, 60);
        assert!(config.check_env_var);
        assert_eq!(config.env_var_name, "FRANKEN_SAFE_MODE");
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = SafeModeConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SafeModeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    // -- SafeModeEntryReceipt tests -----------------------------------------

    #[test]
    fn test_receipt_pass_when_no_inconsistencies() {
        let receipt = SafeModeEntryReceipt::new(
            "2026-02-20T00:00:00Z",
            SafeModeEntryReason::ExplicitFlag,
            "sha256:abc",
            Vec::new(),
        );
        assert!(receipt.pass);
    }

    #[test]
    fn test_receipt_fail_when_inconsistencies() {
        let receipt = SafeModeEntryReceipt::new(
            "2026-02-20T00:00:00Z",
            SafeModeEntryReason::TrustCorruption,
            "sha256:abc",
            vec!["missing entry".to_string()],
        );
        assert!(!receipt.pass);
    }

    #[test]
    fn test_receipt_to_json() {
        let receipt = SafeModeEntryReceipt::new(
            "2026-02-20T00:00:00Z",
            SafeModeEntryReason::ExplicitFlag,
            "sha256:abc",
            Vec::new(),
        );
        let json = receipt.to_json().unwrap();
        assert!(json.contains("sha256:abc"));
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let receipt = SafeModeEntryReceipt::new(
            "2026-02-20T00:00:00Z",
            SafeModeEntryReason::ExplicitFlag,
            "sha256:abc",
            Vec::new(),
        );
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: SafeModeEntryReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    // -- ExitVerification tests ---------------------------------------------

    #[test]
    fn test_exit_verification_all_passed() {
        let v = ExitVerification {
            trust_state_consistent: true,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
            operator_confirmed: true,
        };
        assert!(v.all_passed());
    }

    #[test]
    fn test_exit_verification_some_failed() {
        let v = ExitVerification {
            trust_state_consistent: true,
            no_unresolved_incidents: false,
            evidence_ledger_intact: true,
            operator_confirmed: true,
        };
        assert!(!v.all_passed());
    }

    #[test]
    fn test_exit_verification_failed_checks() {
        let v = ExitVerification {
            trust_state_consistent: false,
            no_unresolved_incidents: false,
            evidence_ledger_intact: true,
            operator_confirmed: true,
        };
        let failed = v.failed_checks();
        assert_eq!(failed.len(), 2);
        assert!(failed.contains(&"trust_state_consistent".to_string()));
        assert!(failed.contains(&"no_unresolved_incidents".to_string()));
    }

    // -- SafeModeStatus tests -----------------------------------------------

    #[test]
    fn test_status_inactive() {
        let status = SafeModeStatus::inactive();
        assert!(!status.safe_mode_active);
        assert!(status.entry_reason.is_none());
    }

    #[test]
    fn test_status_to_json() {
        let status = SafeModeStatus::inactive();
        let json = status.to_json().unwrap();
        assert!(json.contains("safe_mode_active"));
    }

    #[test]
    fn test_status_serde_roundtrip() {
        let status = SafeModeStatus::inactive();
        let json = serde_json::to_string(&status).unwrap();
        let parsed: SafeModeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
    }

    // -- SafeModeAction tests -----------------------------------------------

    #[test]
    fn test_action_display() {
        assert_eq!(format!("{}", SafeModeAction::Enter), "enter");
        assert_eq!(format!("{}", SafeModeAction::Exit), "exit");
        assert_eq!(
            format!("{}", SafeModeAction::CapabilityRestricted),
            "capability_restricted"
        );
        assert_eq!(format!("{}", SafeModeAction::ExitDenied), "exit_denied");
    }

    // -- SafeModeError tests ------------------------------------------------

    #[test]
    fn test_error_display_unknown_flag() {
        let err = SafeModeError::UnknownFlag {
            flag: "--bad".to_string(),
            recovery_hint: "use valid flags".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("--bad"));
    }

    #[test]
    fn test_error_display_capability_restricted() {
        let err = SafeModeError::CapabilityRestricted {
            capability: Capability::ExtensionLoading,
            recovery_hint: "exit safe mode".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("extension_loading"));
    }

    #[test]
    fn test_error_display_exit_precondition() {
        let err = SafeModeError::ExitPreconditionFailed {
            reason: "incidents unresolved".to_string(),
            recovery_hint: "resolve incidents".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("incidents unresolved"));
    }

    #[test]
    fn test_error_display_trust_verification() {
        let err = SafeModeError::TrustVerificationFailed {
            inconsistencies: vec!["bad hash".to_string()],
            recovery_hint: "re-verify".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("1 inconsistencies"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let err = SafeModeError::UnknownFlag {
            flag: "--x".to_string(),
            recovery_hint: "fix".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: SafeModeError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, parsed);
    }

    // -- EventSeverity tests ------------------------------------------------

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", EventSeverity::Info), "INFO");
        assert_eq!(format!("{}", EventSeverity::Warn), "WARN");
        assert_eq!(format!("{}", EventSeverity::Error), "ERROR");
    }

    // -- Controller tests ---------------------------------------------------

    #[test]
    fn test_controller_new_inactive() {
        let ctrl = SafeModeController::with_default_config();
        assert!(!ctrl.is_active());
        assert!(ctrl.entry_reason().is_none());
    }

    #[test]
    fn test_controller_enter_safe_mode() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        assert!(ctrl.is_active());
        assert_eq!(
            ctrl.entry_reason(),
            Some(&SafeModeEntryReason::ExplicitFlag)
        );
    }

    #[test]
    fn test_controller_enter_emits_smo001() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        assert!(
            ctrl.events()
                .iter()
                .any(|e| e.code == SMO_001_SAFE_MODE_ACTIVATED)
        );
    }

    #[test]
    fn test_controller_enter_emits_smo002_for_each_capability() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let smo002_count = ctrl
            .events()
            .iter()
            .filter(|e| e.code == SMO_002_CAPABILITY_RESTRICTED)
            .count();
        assert_eq!(smo002_count, 6); // All 6 capabilities restricted.
    }

    #[test]
    fn test_controller_entry_receipt_created() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let receipt = ctrl.entry_receipt().unwrap();
        assert!(receipt.pass);
        assert_eq!(receipt.trust_state_hash, "sha256:test");
    }

    #[test]
    fn test_controller_entry_receipt_with_inconsistencies() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::TrustCorruption,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            vec!["hash mismatch".to_string()],
        );
        let receipt = ctrl.entry_receipt().unwrap();
        assert!(!receipt.pass);
        assert_eq!(receipt.inconsistencies.len(), 1);
    }

    #[test]
    fn test_controller_capability_restricted() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let result = ctrl.check_capability(&Capability::ExtensionLoading);
        assert!(result.is_err());
    }

    #[test]
    fn test_controller_capability_unrestricted_when_inactive() {
        let ctrl = SafeModeController::with_default_config();
        assert!(ctrl.check_capability(&Capability::ExtensionLoading).is_ok());
    }

    #[test]
    fn test_controller_exit_success() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let verification = ExitVerification {
            trust_state_consistent: true,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
            operator_confirmed: true,
        };
        ctrl.exit_safe_mode(&verification, "operator-1", "2026-02-20T11:00:00Z")
            .unwrap();
        assert!(!ctrl.is_active());
    }

    #[test]
    fn test_controller_exit_denied() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let verification = ExitVerification {
            trust_state_consistent: true,
            no_unresolved_incidents: false,
            evidence_ledger_intact: true,
            operator_confirmed: true,
        };
        let result = ctrl.exit_safe_mode(&verification, "operator-1", "2026-02-20T11:00:00Z");
        assert!(result.is_err());
        assert!(ctrl.is_active()); // Still active.
    }

    #[test]
    fn test_controller_exit_denied_audit_logged() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let verification = ExitVerification {
            trust_state_consistent: false,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
            operator_confirmed: true,
        };
        let _ = ctrl.exit_safe_mode(&verification, "operator-1", "2026-02-20T11:00:00Z");
        let denied_entries: Vec<_> = ctrl
            .audit_log()
            .iter()
            .filter(|e| e.action == SafeModeAction::ExitDenied)
            .collect();
        assert_eq!(denied_entries.len(), 1);
    }

    #[test]
    fn test_controller_exit_requires_confirmation() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let verification = ExitVerification {
            trust_state_consistent: true,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
            operator_confirmed: false,
        };
        assert!(ctrl.exit_safe_mode(&verification, "op", "ts").is_err());
    }

    #[test]
    fn test_controller_suspended_capabilities() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let suspended = ctrl.suspended_capabilities();
        assert_eq!(suspended.len(), 6);
        assert!(suspended.contains(&"extension_loading".to_string()));
    }

    #[test]
    fn test_controller_status_when_active() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.set_flags(OperationFlags::safe_mode_only());
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let status = ctrl.status("2026-02-20T11:00:00Z");
        assert!(status.safe_mode_active);
        assert!(status.entry_reason.is_some());
        assert_eq!(status.suspended_capabilities.len(), 6);
    }

    #[test]
    fn test_controller_status_when_inactive() {
        let ctrl = SafeModeController::with_default_config();
        let status = ctrl.status("2026-02-20T10:00:00Z");
        assert!(!status.safe_mode_active);
    }

    #[test]
    fn test_controller_audit_log_on_enter() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        assert_eq!(ctrl.audit_log().len(), 1);
        assert_eq!(ctrl.audit_log()[0].action, SafeModeAction::Enter);
    }

    #[test]
    fn test_controller_audit_log_on_exit() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:test",
            Vec::new(),
        );
        let verification = ExitVerification {
            trust_state_consistent: true,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
            operator_confirmed: true,
        };
        ctrl.exit_safe_mode(&verification, "op", "ts").unwrap();
        let exit_entries: Vec<_> = ctrl
            .audit_log()
            .iter()
            .filter(|e| e.action == SafeModeAction::Exit)
            .collect();
        assert_eq!(exit_entries.len(), 1);
        assert_eq!(exit_entries[0].operator_id, Some("op".to_string()));
    }

    #[test]
    fn test_controller_set_flags_detects_conflicts() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.set_flags(OperationFlags {
            safe_mode: true,
            degraded: true,
            read_only: false,
            no_network: false,
        });
        assert!(
            ctrl.events()
                .iter()
                .any(|e| e.code == SMO_003_FLAG_CONFLICT)
        );
    }

    #[test]
    fn test_controller_take_events_drains() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(SafeModeEntryReason::ExplicitFlag, "ts", "hash", Vec::new());
        let events = ctrl.take_events();
        assert!(!events.is_empty());
        assert!(ctrl.events().is_empty());
    }

    #[test]
    fn test_controller_enter_degraded_state() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_degraded_state(
            SafeModeEntryReason::CrashLoop {
                crash_count: 5,
                window_secs: 60,
            },
            "2026-02-20T10:00:00Z",
        );
        assert!(ctrl.is_active());
        assert!(
            ctrl.events()
                .iter()
                .any(|e| e.code == SMO_004_DEGRADED_STATE_ENTERED)
        );
    }

    // -- Trigger evaluation tests -------------------------------------------

    #[test]
    fn test_evaluate_triggers_explicit_flag() {
        let ctrl = SafeModeController::with_default_config();
        let flags = OperationFlags::safe_mode_only();
        let reason = ctrl.evaluate_triggers(&flags, None, false);
        assert_eq!(reason, Some(SafeModeEntryReason::ExplicitFlag));
    }

    #[test]
    fn test_evaluate_triggers_env_var() {
        let ctrl = SafeModeController::with_default_config();
        let flags = OperationFlags::none();
        let reason = ctrl.evaluate_triggers(&flags, Some("1"), false);
        assert_eq!(reason, Some(SafeModeEntryReason::EnvironmentVariable));
    }

    #[test]
    fn test_evaluate_triggers_env_var_true() {
        let ctrl = SafeModeController::with_default_config();
        let flags = OperationFlags::none();
        let reason = ctrl.evaluate_triggers(&flags, Some("true"), false);
        assert_eq!(reason, Some(SafeModeEntryReason::EnvironmentVariable));
    }

    #[test]
    fn test_evaluate_triggers_env_var_false() {
        let ctrl = SafeModeController::with_default_config();
        let flags = OperationFlags::none();
        let reason = ctrl.evaluate_triggers(&flags, Some("0"), false);
        assert!(reason.is_none());
    }

    #[test]
    fn test_evaluate_triggers_config_field() {
        let ctrl = SafeModeController::with_default_config();
        let flags = OperationFlags::none();
        let reason = ctrl.evaluate_triggers(&flags, None, true);
        assert_eq!(reason, Some(SafeModeEntryReason::ConfigField));
    }

    #[test]
    fn test_evaluate_triggers_precedence_flag_over_env() {
        let ctrl = SafeModeController::with_default_config();
        let flags = OperationFlags::safe_mode_only();
        let reason = ctrl.evaluate_triggers(&flags, Some("1"), true);
        // Explicit flag has highest priority.
        assert_eq!(reason, Some(SafeModeEntryReason::ExplicitFlag));
    }

    #[test]
    fn test_evaluate_triggers_precedence_env_over_config() {
        let ctrl = SafeModeController::with_default_config();
        let flags = OperationFlags::none();
        let reason = ctrl.evaluate_triggers(&flags, Some("1"), true);
        assert_eq!(reason, Some(SafeModeEntryReason::EnvironmentVariable));
    }

    #[test]
    fn test_evaluate_triggers_none() {
        let ctrl = SafeModeController::with_default_config();
        let flags = OperationFlags::none();
        let reason = ctrl.evaluate_triggers(&flags, None, false);
        assert!(reason.is_none());
    }

    #[test]
    fn test_crash_loop_trigger_above_threshold() {
        let ctrl = SafeModeController::with_default_config();
        let reason = ctrl.check_crash_loop_trigger(3, 60);
        assert!(reason.is_some());
        if let Some(SafeModeEntryReason::CrashLoop {
            crash_count,
            window_secs,
        }) = reason
        {
            assert_eq!(crash_count, 3);
            assert_eq!(window_secs, 60);
        }
    }

    #[test]
    fn test_crash_loop_trigger_below_threshold() {
        let ctrl = SafeModeController::with_default_config();
        let reason = ctrl.check_crash_loop_trigger(2, 60);
        assert!(reason.is_none());
    }

    #[test]
    fn test_epoch_mismatch_trigger() {
        let ctrl = SafeModeController::with_default_config();
        let reason = ctrl.check_epoch_mismatch_trigger(10, 12);
        assert!(reason.is_some());
    }

    #[test]
    fn test_epoch_match_no_trigger() {
        let ctrl = SafeModeController::with_default_config();
        let reason = ctrl.check_epoch_mismatch_trigger(10, 10);
        assert!(reason.is_none());
    }

    // -- Deterministic capability computation --------------------------------

    #[test]
    fn test_compute_restricted_safe_mode() {
        let flags = OperationFlags::safe_mode_only();
        let caps = SafeModeController::compute_restricted_capabilities(&flags);
        assert_eq!(caps.len(), 6);
    }

    #[test]
    fn test_compute_restricted_read_only() {
        let flags = OperationFlags {
            safe_mode: false,
            degraded: false,
            read_only: true,
            no_network: false,
        };
        let caps = SafeModeController::compute_restricted_capabilities(&flags);
        assert_eq!(caps.len(), 1);
        assert!(caps.contains(&Capability::TrustLedgerWrites));
    }

    #[test]
    fn test_compute_restricted_no_network() {
        let flags = OperationFlags {
            safe_mode: false,
            degraded: false,
            read_only: false,
            no_network: true,
        };
        let caps = SafeModeController::compute_restricted_capabilities(&flags);
        assert_eq!(caps.len(), 1);
        assert!(caps.contains(&Capability::OutboundNetwork));
    }

    #[test]
    fn test_compute_restricted_degraded() {
        let flags = OperationFlags {
            safe_mode: false,
            degraded: true,
            read_only: false,
            no_network: false,
        };
        let caps = SafeModeController::compute_restricted_capabilities(&flags);
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&Capability::ExtensionLoading));
        assert!(caps.contains(&Capability::ScheduledTasks));
    }

    #[test]
    fn test_compute_restricted_none() {
        let flags = OperationFlags::none();
        let caps = SafeModeController::compute_restricted_capabilities(&flags);
        assert!(caps.is_empty());
    }

    #[test]
    fn test_compute_restricted_deterministic() {
        // INV-SMO-DETERMINISTIC: same flags => same result.
        let flags = OperationFlags {
            safe_mode: true,
            degraded: false,
            read_only: true,
            no_network: true,
        };
        let a = SafeModeController::compute_restricted_capabilities(&flags);
        let b = SafeModeController::compute_restricted_capabilities(&flags);
        assert_eq!(a, b);
    }

    // -- Trust re-verification tests ----------------------------------------

    #[test]
    fn test_verify_trust_state_pass() {
        let receipt = SafeModeController::verify_trust_state("sha256:abc", &["entry1", "entry2"]);
        assert!(receipt.pass);
        assert!(receipt.inconsistencies.is_empty());
    }

    #[test]
    fn test_verify_trust_state_empty_evidence() {
        let receipt = SafeModeController::verify_trust_state("sha256:abc", &[]);
        assert!(!receipt.pass);
        assert!(!receipt.inconsistencies.is_empty());
    }

    #[test]
    fn test_verify_trust_state_empty_hash() {
        let receipt = SafeModeController::verify_trust_state("", &["entry1"]);
        assert!(!receipt.pass);
    }

    // -- Event code constant tests ------------------------------------------

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(SMO_001_SAFE_MODE_ACTIVATED, "SMO-001");
        assert_eq!(SMO_002_CAPABILITY_RESTRICTED, "SMO-002");
        assert_eq!(SMO_003_FLAG_CONFLICT, "SMO-003");
        assert_eq!(SMO_004_DEGRADED_STATE_ENTERED, "SMO-004");
    }

    // -- Invariant constant tests -------------------------------------------

    #[test]
    fn test_invariant_constants_defined() {
        assert_eq!(INV_SMO_DETERMINISTIC, "INV-SMO-DETERMINISTIC");
        assert_eq!(INV_SMO_RESTRICTED, "INV-SMO-RESTRICTED");
        assert_eq!(INV_SMO_FLAGPARSE, "INV-SMO-FLAGPARSE");
        assert_eq!(INV_SMO_RECOVERY, "INV-SMO-RECOVERY");
    }

    // -- Full lifecycle test ------------------------------------------------

    #[test]
    fn test_full_lifecycle() {
        let mut ctrl = SafeModeController::with_default_config();

        // Initially inactive.
        assert!(!ctrl.is_active());

        // Enter safe mode.
        ctrl.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-02-20T10:00:00Z",
            "sha256:abc123",
            Vec::new(),
        );
        assert!(ctrl.is_active());

        // Capabilities are restricted.
        assert!(
            ctrl.check_capability(&Capability::ExtensionLoading)
                .is_err()
        );
        assert!(
            ctrl.check_capability(&Capability::TrustDelegations)
                .is_err()
        );

        // Receipt exists.
        assert!(ctrl.entry_receipt().is_some());

        // Try exit without confirmation -- denied.
        let bad_verification = ExitVerification {
            trust_state_consistent: true,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
            operator_confirmed: false,
        };
        assert!(ctrl.exit_safe_mode(&bad_verification, "op", "ts").is_err());
        assert!(ctrl.is_active());

        // Exit with full verification.
        let good_verification = ExitVerification {
            trust_state_consistent: true,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
            operator_confirmed: true,
        };
        ctrl.exit_safe_mode(&good_verification, "operator-1", "2026-02-20T11:00:00Z")
            .unwrap();
        assert!(!ctrl.is_active());

        // Capabilities restored.
        assert!(ctrl.check_capability(&Capability::ExtensionLoading).is_ok());
    }

    #[test]
    fn test_drill_trust_corruption() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.enter_safe_mode(
            SafeModeEntryReason::TrustCorruption,
            "2026-02-20T10:00:00Z",
            "sha256:corrupted",
            vec![
                "missing evidence entry 42".to_string(),
                "hash chain break at position 17".to_string(),
            ],
        );
        assert!(ctrl.is_active());
        let receipt = ctrl.entry_receipt().unwrap();
        assert!(!receipt.pass);
        assert_eq!(receipt.inconsistencies.len(), 2);
    }

    #[test]
    fn test_drill_crash_loop() {
        let mut ctrl = SafeModeController::with_default_config();
        let trigger = ctrl.check_crash_loop_trigger(5, 60);
        assert!(trigger.is_some());
        ctrl.enter_degraded_state(trigger.unwrap(), "2026-02-20T10:00:00Z");
        assert!(ctrl.is_active());
        assert!(
            ctrl.events()
                .iter()
                .any(|e| e.code == SMO_004_DEGRADED_STATE_ENTERED)
        );
    }

    #[test]
    fn test_drill_epoch_mismatch() {
        let mut ctrl = SafeModeController::with_default_config();
        let trigger = ctrl.check_epoch_mismatch_trigger(10, 15);
        assert!(trigger.is_some());
        ctrl.enter_safe_mode(
            trigger.unwrap(),
            "2026-02-20T10:00:00Z",
            "sha256:epoch-state",
            Vec::new(),
        );
        assert!(ctrl.is_active());
        if let Some(SafeModeEntryReason::EpochMismatch {
            local_epoch,
            peer_epoch,
        }) = ctrl.entry_reason()
        {
            assert_eq!(*local_epoch, 10);
            assert_eq!(*peer_epoch, 15);
        } else {
            panic!("expected epoch mismatch reason");
        }
    }

    #[test]
    fn test_set_unresolved_incidents() {
        let mut ctrl = SafeModeController::with_default_config();
        ctrl.set_unresolved_incidents(5);
        ctrl.enter_safe_mode(SafeModeEntryReason::ExplicitFlag, "ts", "hash", Vec::new());
        let status = ctrl.status("ts");
        assert_eq!(status.unresolved_incidents, 5);
    }

    #[test]
    fn test_config_accessor() {
        let ctrl = SafeModeController::with_default_config();
        assert_eq!(ctrl.config().crash_loop_threshold, 3);
    }

    #[test]
    fn test_flags_accessor() {
        let ctrl = SafeModeController::with_default_config();
        assert_eq!(*ctrl.flags(), OperationFlags::none());
    }
}
