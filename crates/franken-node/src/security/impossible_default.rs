//! bd-1xao: Impossible-by-default adoption enforcement.
//!
//! Operations that are dangerous or unsafe are blocked at the architecture level
//! unless explicitly enabled with a signed capability token that carries an expiry.
//! Five impossible-by-default capabilities are enforced:
//!
//! - **FsAccess**: Arbitrary file system access outside project root.
//! - **OutboundNetwork**: Outbound network to non-allowlisted hosts.
//! - **ChildProcessSpawn**: Spawning child processes without sandbox.
//! - **UnsignedExtension**: Loading unsigned extensions.
//! - **DisableHardening**: Disabling hardening profiles.
//!
//! Each capability requires an explicit opt-in via a signed capability token with
//! expiry. Attempting a blocked operation produces a clear, actionable error
//! message with the specific capability name, remediation steps, and the error
//! code for structured log consumption.
//!
//! # Event Codes
//!
//! - **IBD-001**: Capability blocked by default (initial gate enforcement).
//! - **IBD-002**: Opt-in granted via signed token.
//! - **IBD-003**: Opt-in expired (token TTL exceeded).
//! - **IBD-004**: Silent disable detected (attempt to disable without audit).
//!
//! # Invariants
//!
//! - **INV-IBD-ENFORCE**: All five capabilities are blocked by default.
//! - **INV-IBD-TOKEN**: Opt-in requires a valid, non-expired signed token.
//! - **INV-IBD-AUDIT**: All enforcement actions (block, grant, expire, silent-disable)
//!   are logged to the audit trail.
//! - **INV-IBD-ADOPTION**: >= 90% of deployments run with all capabilities enforced.
//!
//! # Error Codes
//!
//! - **ERR_IBD_BLOCKED**: Operation blocked because capability is not enabled.
//! - **ERR_IBD_TOKEN_EXPIRED**: The capability token has expired.
//! - **ERR_IBD_INVALID_SIGNATURE**: The capability token signature is invalid.
//! - **ERR_IBD_SILENT_DISABLE**: Attempt to silently disable a capability detected.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// IBD-001: Capability blocked by default.
pub const IBD_001_CAPABILITY_BLOCKED: &str = "IBD-001";
/// IBD-002: Opt-in granted via signed token.
pub const IBD_002_OPT_IN_GRANTED: &str = "IBD-002";
/// IBD-003: Opt-in expired (token TTL exceeded).
pub const IBD_003_OPT_IN_EXPIRED: &str = "IBD-003";
/// IBD-004: Silent disable detected.
pub const IBD_004_SILENT_DISABLE_DETECTED: &str = "IBD-004";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_IBD_BLOCKED: &str = "ERR_IBD_BLOCKED";
pub const ERR_IBD_TOKEN_EXPIRED: &str = "ERR_IBD_TOKEN_EXPIRED";
pub const ERR_IBD_INVALID_SIGNATURE: &str = "ERR_IBD_INVALID_SIGNATURE";
pub const ERR_IBD_SILENT_DISABLE: &str = "ERR_IBD_SILENT_DISABLE";

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

/// INV-IBD-ENFORCE: All five capabilities are blocked by default.
pub const INV_IBD_ENFORCE: &str = "INV-IBD-ENFORCE";
/// INV-IBD-TOKEN: Opt-in requires a valid, non-expired signed token.
pub const INV_IBD_TOKEN: &str = "INV-IBD-TOKEN";
/// INV-IBD-AUDIT: All enforcement actions are logged.
pub const INV_IBD_AUDIT: &str = "INV-IBD-AUDIT";
/// INV-IBD-ADOPTION: >= 90% of deployments run with all capabilities enforced.
pub const INV_IBD_ADOPTION: &str = "INV-IBD-ADOPTION";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The five impossible-by-default capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImpossibleCapability {
    /// Arbitrary file system access outside project root.
    FsAccess,
    /// Outbound network to non-allowlisted hosts.
    OutboundNetwork,
    /// Spawning child processes without sandbox.
    ChildProcessSpawn,
    /// Loading unsigned extensions.
    UnsignedExtension,
    /// Disabling hardening profiles.
    DisableHardening,
}

impl ImpossibleCapability {
    /// All defined capabilities.
    pub const ALL: &'static [ImpossibleCapability] = &[
        ImpossibleCapability::FsAccess,
        ImpossibleCapability::OutboundNetwork,
        ImpossibleCapability::ChildProcessSpawn,
        ImpossibleCapability::UnsignedExtension,
        ImpossibleCapability::DisableHardening,
    ];

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::FsAccess => "fs_access",
            Self::OutboundNetwork => "outbound_network",
            Self::ChildProcessSpawn => "child_process_spawn",
            Self::UnsignedExtension => "unsigned_extension",
            Self::DisableHardening => "disable_hardening",
        }
    }

    /// Actionable description used in error messages.
    pub fn description(&self) -> &'static str {
        match self {
            Self::FsAccess => {
                "Arbitrary file system access outside project root is blocked. \
                               Obtain a signed CapabilityToken with FsAccess scope to proceed."
            }
            Self::OutboundNetwork => {
                "Outbound network to non-allowlisted hosts is blocked. \
                                      Obtain a signed CapabilityToken with OutboundNetwork scope to proceed."
            }
            Self::ChildProcessSpawn => {
                "Spawning child processes without sandbox is blocked. \
                                        Obtain a signed CapabilityToken with ChildProcessSpawn scope to proceed."
            }
            Self::UnsignedExtension => {
                "Loading unsigned extensions is blocked. \
                                        Obtain a signed CapabilityToken with UnsignedExtension scope to proceed."
            }
            Self::DisableHardening => {
                "Disabling hardening profiles is blocked. \
                                       Obtain a signed CapabilityToken with DisableHardening scope to proceed."
            }
        }
    }
}

impl std::fmt::Display for ImpossibleCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A signed capability token granting temporary access to an impossible-by-default
/// capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Unique token identifier.
    pub token_id: String,
    /// The capability this token grants.
    pub capability: ImpossibleCapability,
    /// Identity of the entity that issued the token.
    pub issuer: String,
    /// Identity of the entity the token is granted to.
    pub subject: String,
    /// When the token was issued (milliseconds since epoch).
    pub issued_at_ms: u64,
    /// When the token expires (milliseconds since epoch).
    pub expires_at_ms: u64,
    /// Hex-encoded signature over the token fields.
    pub signature: String,
    /// Justification for the opt-in.
    pub justification: String,
}

impl CapabilityToken {
    /// Check whether the token has expired at the given timestamp.
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        current_time_ms >= self.expires_at_ms
    }

    /// Compute a content hash of the token fields (excluding signature) for
    /// verification purposes.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.token_id.as_bytes());
        hasher.update(self.capability.label().as_bytes());
        hasher.update(self.issuer.as_bytes());
        hasher.update(self.subject.as_bytes());
        hasher.update(self.issued_at_ms.to_le_bytes());
        hasher.update(self.expires_at_ms.to_le_bytes());
        hasher.update(self.justification.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Enforcement status for a single capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementStatus {
    /// Capability is blocked (no valid token).
    Blocked,
    /// Capability is enabled via a valid token.
    Enabled {
        token_id: String,
        expires_at_ms: u64,
    },
}

impl EnforcementStatus {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked)
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }
}

/// Error type for impossible-by-default enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementError {
    /// Error code (ERR_IBD_*).
    pub code: String,
    /// Human-readable, actionable error message.
    pub message: String,
    /// The capability that was affected.
    pub capability: ImpossibleCapability,
}

impl EnforcementError {
    pub fn blocked(capability: ImpossibleCapability) -> Self {
        Self {
            code: ERR_IBD_BLOCKED.to_string(),
            message: format!(
                "[{}] {} To enable, present a signed CapabilityToken for '{}'.",
                ERR_IBD_BLOCKED,
                capability.description(),
                capability.label()
            ),
            capability,
        }
    }

    pub fn token_expired(capability: ImpossibleCapability, token_id: &str) -> Self {
        Self {
            code: ERR_IBD_TOKEN_EXPIRED.to_string(),
            message: format!(
                "[{}] CapabilityToken '{}' for '{}' has expired. Request a new token to continue.",
                ERR_IBD_TOKEN_EXPIRED,
                token_id,
                capability.label()
            ),
            capability,
        }
    }

    pub fn invalid_signature(capability: ImpossibleCapability, token_id: &str) -> Self {
        Self {
            code: ERR_IBD_INVALID_SIGNATURE.to_string(),
            message: format!(
                "[{}] CapabilityToken '{}' for '{}' has an invalid signature. The token cannot be trusted.",
                ERR_IBD_INVALID_SIGNATURE,
                token_id,
                capability.label()
            ),
            capability,
        }
    }

    pub fn silent_disable(capability: ImpossibleCapability) -> Self {
        Self {
            code: ERR_IBD_SILENT_DISABLE.to_string(),
            message: format!(
                "[{}] Attempt to silently disable enforcement for '{}' was detected and blocked. \
                 All disabling actions must be audited.",
                ERR_IBD_SILENT_DISABLE,
                capability.label()
            ),
            capability,
        }
    }
}

impl std::fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Audit log entry for enforcement actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementAuditEntry {
    /// Event code (IBD-001 through IBD-004).
    pub event_code: String,
    /// The capability involved.
    pub capability: ImpossibleCapability,
    /// Actor identity.
    pub actor: String,
    /// Timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
    /// Detail message.
    pub detail: String,
    /// Token ID (if applicable).
    pub token_id: Option<String>,
    /// Hash of the previous audit entry for tamper evidence.
    pub prev_hash: String,
}

impl EnforcementAuditEntry {
    /// Compute the hash of this entry for chain integrity.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.event_code.as_bytes());
        hasher.update(self.capability.label().as_bytes());
        hasher.update(self.actor.as_bytes());
        hasher.update(self.timestamp_ms.to_le_bytes());
        hasher.update(self.detail.as_bytes());
        if let Some(tid) = &self.token_id {
            hasher.update(tid.as_bytes());
        }
        hasher.update(self.prev_hash.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Metrics for enforcement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementMetrics {
    pub blocked_total: u64,
    pub opt_in_granted_total: u64,
    pub opt_in_expired_total: u64,
    pub silent_disable_detected_total: u64,
    /// Number of deployments with all capabilities enforced (for adoption metric).
    pub deployments_enforced: u64,
    /// Total number of deployments observed.
    pub deployments_total: u64,
}

impl EnforcementMetrics {
    /// Compute adoption rate as a percentage.
    pub fn adoption_rate_pct(&self) -> f64 {
        if self.deployments_total == 0 {
            return 100.0;
        }
        (self.deployments_enforced as f64 / self.deployments_total as f64) * 100.0
    }
}

/// A single capability's enforcement report entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReportEntry {
    pub capability: ImpossibleCapability,
    pub enforcement_status: String,
    pub opt_in_rate_pct: f64,
    pub blocked_count: u64,
    pub opted_in_count: u64,
}

/// The enforcement report for evidence output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementReport {
    pub bead_id: String,
    pub section: String,
    pub timestamp: String,
    pub capabilities: Vec<CapabilityReportEntry>,
    pub overall_adoption_rate_pct: f64,
    pub meets_threshold: bool,
    pub threshold_pct: f64,
    pub metrics: EnforcementMetrics,
}

// ---------------------------------------------------------------------------
// Signature verification (pluggable)
// ---------------------------------------------------------------------------

/// Trait for verifying capability token signatures.
pub trait SignatureVerifier: Send + Sync {
    /// Verify the signature on a capability token.
    fn verify(&self, token: &CapabilityToken) -> bool;
}

/// Default verifier that checks the signature matches the SHA-256 content hash.
/// In production, this would use ed25519 or similar.
#[derive(Debug, Clone)]
pub struct HashSignatureVerifier;

impl SignatureVerifier for HashSignatureVerifier {
    fn verify(&self, token: &CapabilityToken) -> bool {
        token.signature == token.content_hash()
    }
}

// ---------------------------------------------------------------------------
// CapabilityEnforcer
// ---------------------------------------------------------------------------

/// The core enforcer that manages impossible-by-default capabilities.
///
/// All five capabilities are blocked by default (INV-IBD-ENFORCE). Opt-in
/// requires presenting a valid, non-expired, properly signed CapabilityToken
/// (INV-IBD-TOKEN). Every action is logged to the audit trail (INV-IBD-AUDIT).
pub struct CapabilityEnforcer {
    /// Current enforcement state per capability.
    state: HashMap<ImpossibleCapability, EnforcementStatus>,
    /// Active tokens indexed by capability.
    tokens: HashMap<ImpossibleCapability, CapabilityToken>,
    /// Audit log.
    audit_log: Vec<EnforcementAuditEntry>,
    /// Metrics.
    metrics: EnforcementMetrics,
    /// Per-capability blocked/opted-in counters for reporting.
    blocked_counts: HashMap<ImpossibleCapability, u64>,
    opted_in_counts: HashMap<ImpossibleCapability, u64>,
    /// Signature verifier.
    verifier: Box<dyn SignatureVerifier>,
}

impl CapabilityEnforcer {
    /// Create a new enforcer with the given signature verifier.
    /// All capabilities start in Blocked state (INV-IBD-ENFORCE).
    pub fn new(verifier: Box<dyn SignatureVerifier>) -> Self {
        let mut state = HashMap::new();
        let mut blocked_counts = HashMap::new();
        let opted_in_counts = HashMap::new();
        for &cap in ImpossibleCapability::ALL {
            state.insert(cap, EnforcementStatus::Blocked);
            blocked_counts.insert(cap, 0);
        }
        Self {
            state,
            tokens: HashMap::new(),
            audit_log: Vec::new(),
            metrics: EnforcementMetrics::default(),
            blocked_counts,
            opted_in_counts,
            verifier,
        }
    }

    /// Create a new enforcer using the default hash-based signature verifier.
    pub fn with_default_verifier() -> Self {
        Self::new(Box::new(HashSignatureVerifier))
    }

    /// Enforce: check whether a capability is allowed at the given time.
    ///
    /// Returns `Ok(())` if the capability is enabled with a valid token.
    /// Returns `Err(EnforcementError)` with an actionable message if blocked.
    ///
    /// Emits IBD-001 (blocked) or IBD-003 (token expired).
    pub fn enforce(
        &mut self,
        capability: ImpossibleCapability,
        actor: &str,
        current_time_ms: u64,
    ) -> Result<(), EnforcementError> {
        // Check for expired tokens first.
        if let Some(token) = self.tokens.get(&capability) {
            if token.is_expired(current_time_ms) {
                let token_id = token.token_id.clone();
                // Expire the token.
                self.state.insert(capability, EnforcementStatus::Blocked);
                self.tokens.remove(&capability);
                self.metrics.opt_in_expired_total += 1;

                self.log_event(
                    IBD_003_OPT_IN_EXPIRED,
                    capability,
                    actor,
                    current_time_ms,
                    &format!(
                        "Token '{}' for '{}' has expired",
                        token_id,
                        capability.label()
                    ),
                    Some(&token_id),
                );

                *self.blocked_counts.entry(capability).or_insert(0) += 1;
                return Err(EnforcementError::token_expired(capability, &token_id));
            }
        }

        match self.state.get(&capability) {
            Some(EnforcementStatus::Enabled { .. }) => Ok(()),
            _ => {
                self.metrics.blocked_total += 1;
                *self.blocked_counts.entry(capability).or_insert(0) += 1;

                self.log_event(
                    IBD_001_CAPABILITY_BLOCKED,
                    capability,
                    actor,
                    current_time_ms,
                    &format!(
                        "Capability '{}' is blocked by default. {}",
                        capability.label(),
                        capability.description()
                    ),
                    None,
                );

                Err(EnforcementError::blocked(capability))
            }
        }
    }

    /// Opt-in: present a signed capability token to enable a capability.
    ///
    /// Validates signature and expiry. Emits IBD-002 on success.
    pub fn opt_in(
        &mut self,
        token: CapabilityToken,
        actor: &str,
        current_time_ms: u64,
    ) -> Result<(), EnforcementError> {
        let capability = token.capability;

        // Verify signature (INV-IBD-TOKEN).
        if !self.verifier.verify(&token) {
            self.log_event(
                IBD_001_CAPABILITY_BLOCKED,
                capability,
                actor,
                current_time_ms,
                &format!(
                    "Invalid signature on token '{}' for '{}'",
                    token.token_id,
                    capability.label()
                ),
                Some(&token.token_id),
            );
            return Err(EnforcementError::invalid_signature(
                capability,
                &token.token_id,
            ));
        }

        // Check expiry.
        if token.is_expired(current_time_ms) {
            self.metrics.opt_in_expired_total += 1;
            self.log_event(
                IBD_003_OPT_IN_EXPIRED,
                capability,
                actor,
                current_time_ms,
                &format!(
                    "Token '{}' for '{}' is already expired at presentation",
                    token.token_id,
                    capability.label()
                ),
                Some(&token.token_id),
            );
            return Err(EnforcementError::token_expired(capability, &token.token_id));
        }

        // Grant opt-in.
        let token_id = token.token_id.clone();
        let expires_at_ms = token.expires_at_ms;
        self.state.insert(
            capability,
            EnforcementStatus::Enabled {
                token_id: token_id.clone(),
                expires_at_ms,
            },
        );
        self.tokens.insert(capability, token);
        self.metrics.opt_in_granted_total += 1;
        *self.opted_in_counts.entry(capability).or_insert(0) += 1;

        self.log_event(
            IBD_002_OPT_IN_GRANTED,
            capability,
            actor,
            current_time_ms,
            &format!(
                "Opt-in granted for '{}' via token '{}', expires at {}ms",
                capability.label(),
                token_id,
                expires_at_ms
            ),
            Some(&token_id),
        );

        Ok(())
    }

    /// Check whether a capability is currently enabled (without enforcing).
    pub fn is_enabled(&self, capability: ImpossibleCapability) -> bool {
        matches!(
            self.state.get(&capability),
            Some(EnforcementStatus::Enabled { .. })
        )
    }

    /// Attempt to silently disable a capability. This is always blocked and
    /// generates an IBD-004 alert (INV-IBD-AUDIT).
    ///
    /// No capability can be silently disabled. Any disabling attempt is logged
    /// and alerted.
    pub fn attempt_silent_disable(
        &mut self,
        capability: ImpossibleCapability,
        actor: &str,
        current_time_ms: u64,
    ) -> Result<(), EnforcementError> {
        self.metrics.silent_disable_detected_total += 1;

        self.log_event(
            IBD_004_SILENT_DISABLE_DETECTED,
            capability,
            actor,
            current_time_ms,
            &format!(
                "ALERT: Attempt to silently disable enforcement for '{}' by '{}'. This action is blocked and has been reported.",
                capability.label(),
                actor
            ),
            None,
        );

        Err(EnforcementError::silent_disable(capability))
    }

    /// Expire all tokens that have passed their expiry time.
    pub fn expire_tokens(&mut self, current_time_ms: u64) -> Vec<ImpossibleCapability> {
        let mut expired = Vec::new();
        let expired_caps: Vec<(ImpossibleCapability, String)> = self
            .tokens
            .iter()
            .filter(|(_, token)| token.is_expired(current_time_ms))
            .map(|(&cap, token)| (cap, token.token_id.clone()))
            .collect();

        for (cap, token_id) in expired_caps {
            self.state.insert(cap, EnforcementStatus::Blocked);
            self.tokens.remove(&cap);
            self.metrics.opt_in_expired_total += 1;

            self.log_event(
                IBD_003_OPT_IN_EXPIRED,
                cap,
                "system",
                current_time_ms,
                &format!("Token '{}' for '{}' expired", token_id, cap.label()),
                Some(&token_id),
            );

            expired.push(cap);
        }

        expired
    }

    /// Record a deployment observation for adoption tracking.
    pub fn record_deployment(&mut self, all_enforced: bool) {
        self.metrics.deployments_total += 1;
        if all_enforced {
            self.metrics.deployments_enforced += 1;
        }
    }

    /// Get current enforcement status for a capability.
    pub fn status(&self, capability: ImpossibleCapability) -> &EnforcementStatus {
        self.state
            .get(&capability)
            .unwrap_or(&EnforcementStatus::Blocked)
    }

    /// Current metrics snapshot.
    pub fn metrics(&self) -> &EnforcementMetrics {
        &self.metrics
    }

    /// Full audit log.
    pub fn audit_log(&self) -> &[EnforcementAuditEntry] {
        &self.audit_log
    }

    /// Generate the enforcement report for evidence output.
    pub fn generate_report(&self, timestamp: &str) -> EnforcementReport {
        let threshold_pct = 90.0;
        let adoption_rate = self.metrics.adoption_rate_pct();

        let capabilities: Vec<CapabilityReportEntry> = ImpossibleCapability::ALL
            .iter()
            .map(|&cap| {
                let blocked = self.blocked_counts.get(&cap).copied().unwrap_or(0);
                let opted_in = self.opted_in_counts.get(&cap).copied().unwrap_or(0);
                let total = blocked + opted_in;
                let opt_in_rate = if total == 0 {
                    0.0
                } else {
                    (opted_in as f64 / total as f64) * 100.0
                };

                CapabilityReportEntry {
                    capability: cap,
                    enforcement_status: if self.is_enabled(cap) {
                        "enabled".to_string()
                    } else {
                        "blocked".to_string()
                    },
                    opt_in_rate_pct: opt_in_rate,
                    blocked_count: blocked,
                    opted_in_count: opted_in,
                }
            })
            .collect();

        EnforcementReport {
            bead_id: "bd-1xao".to_string(),
            section: "13".to_string(),
            timestamp: timestamp.to_string(),
            capabilities,
            overall_adoption_rate_pct: adoption_rate,
            meets_threshold: adoption_rate >= threshold_pct,
            threshold_pct,
            metrics: self.metrics.clone(),
        }
    }

    // -- Internal -----------------------------------------------------------

    fn log_event(
        &mut self,
        event_code: &str,
        capability: ImpossibleCapability,
        actor: &str,
        timestamp_ms: u64,
        detail: &str,
        token_id: Option<&str>,
    ) {
        let prev_hash = self
            .audit_log
            .last()
            .map(|e| e.hash())
            .unwrap_or_else(|| "0".repeat(64));

        let entry = EnforcementAuditEntry {
            event_code: event_code.to_string(),
            capability,
            actor: actor.to_string(),
            timestamp_ms,
            detail: detail.to_string(),
            token_id: token_id.map(|s| s.to_string()),
            prev_hash,
        };

        self.audit_log.push(entry);
    }
}

// ---------------------------------------------------------------------------
// Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<CapabilityEnforcer>();
    assert_sync::<CapabilityEnforcer>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --

    fn make_enforcer() -> CapabilityEnforcer {
        CapabilityEnforcer::with_default_verifier()
    }

    fn make_token(cap: ImpossibleCapability, expires_at_ms: u64) -> CapabilityToken {
        let mut token = CapabilityToken {
            token_id: format!("tok-{}", cap.label()),
            capability: cap,
            issuer: "test-issuer".to_string(),
            subject: "test-subject".to_string(),
            issued_at_ms: 1000,
            expires_at_ms,
            signature: String::new(),
            justification: "test justification".to_string(),
        };
        // Sign with the content hash (matches HashSignatureVerifier).
        token.signature = token.content_hash();
        token
    }

    fn make_bad_sig_token(cap: ImpossibleCapability) -> CapabilityToken {
        CapabilityToken {
            token_id: format!("tok-bad-{}", cap.label()),
            capability: cap,
            issuer: "test-issuer".to_string(),
            subject: "test-subject".to_string(),
            issued_at_ms: 1000,
            expires_at_ms: 999_999,
            signature: "invalid_signature_value".to_string(),
            justification: "test".to_string(),
        }
    }

    // -- AC1: Impossible-by-default capabilities are defined --

    #[test]
    fn test_five_capabilities_defined() {
        assert_eq!(ImpossibleCapability::ALL.len(), 5);
    }

    #[test]
    fn test_capability_variants() {
        let caps = ImpossibleCapability::ALL;
        assert!(caps.contains(&ImpossibleCapability::FsAccess));
        assert!(caps.contains(&ImpossibleCapability::OutboundNetwork));
        assert!(caps.contains(&ImpossibleCapability::ChildProcessSpawn));
        assert!(caps.contains(&ImpossibleCapability::UnsignedExtension));
        assert!(caps.contains(&ImpossibleCapability::DisableHardening));
    }

    #[test]
    fn test_capability_labels() {
        assert_eq!(ImpossibleCapability::FsAccess.label(), "fs_access");
        assert_eq!(
            ImpossibleCapability::OutboundNetwork.label(),
            "outbound_network"
        );
        assert_eq!(
            ImpossibleCapability::ChildProcessSpawn.label(),
            "child_process_spawn"
        );
        assert_eq!(
            ImpossibleCapability::UnsignedExtension.label(),
            "unsigned_extension"
        );
        assert_eq!(
            ImpossibleCapability::DisableHardening.label(),
            "disable_hardening"
        );
    }

    #[test]
    fn test_capability_descriptions_actionable() {
        for &cap in ImpossibleCapability::ALL {
            let desc = cap.description();
            assert!(
                desc.contains("blocked"),
                "desc for {} should mention 'blocked'",
                cap
            );
            assert!(
                desc.contains("CapabilityToken"),
                "desc for {} should mention CapabilityToken",
                cap
            );
        }
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(format!("{}", ImpossibleCapability::FsAccess), "fs_access");
    }

    // -- AC2: All five capabilities blocked by default --

    #[test]
    fn test_all_blocked_by_default() {
        let enforcer = make_enforcer();
        for &cap in ImpossibleCapability::ALL {
            assert!(
                enforcer.status(cap).is_blocked(),
                "Capability {} should be blocked by default",
                cap
            );
        }
    }

    #[test]
    fn test_enforce_blocked_returns_error() {
        let mut enforcer = make_enforcer();
        for &cap in ImpossibleCapability::ALL {
            let err = enforcer.enforce(cap, "user", 1000).unwrap_err();
            assert_eq!(err.code, ERR_IBD_BLOCKED);
            assert_eq!(err.capability, cap);
        }
    }

    #[test]
    fn test_blocked_error_is_actionable() {
        let mut enforcer = make_enforcer();
        let err = enforcer
            .enforce(ImpossibleCapability::FsAccess, "user", 1000)
            .unwrap_err();
        assert!(err.message.contains("blocked"));
        assert!(err.message.contains("CapabilityToken"));
        assert!(err.message.contains("fs_access"));
    }

    // -- AC3: Opt-in via signed token with expiry --

    #[test]
    fn test_opt_in_with_valid_token() {
        let mut enforcer = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 10_000);
        enforcer.opt_in(token, "admin", 2000).unwrap();
        assert!(enforcer.is_enabled(ImpossibleCapability::FsAccess));
    }

    #[test]
    fn test_enforce_after_opt_in_succeeds() {
        let mut enforcer = make_enforcer();
        let token = make_token(ImpossibleCapability::OutboundNetwork, 10_000);
        enforcer.opt_in(token, "admin", 2000).unwrap();
        assert!(
            enforcer
                .enforce(ImpossibleCapability::OutboundNetwork, "user", 3000)
                .is_ok()
        );
    }

    #[test]
    fn test_opt_in_with_invalid_signature_rejected() {
        let mut enforcer = make_enforcer();
        let token = make_bad_sig_token(ImpossibleCapability::FsAccess);
        let err = enforcer.opt_in(token, "admin", 2000).unwrap_err();
        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
    }

    #[test]
    fn test_opt_in_with_expired_token_rejected() {
        let mut enforcer = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 1500);
        let err = enforcer.opt_in(token, "admin", 2000).unwrap_err();
        assert_eq!(err.code, ERR_IBD_TOKEN_EXPIRED);
    }

    #[test]
    fn test_token_expiry_blocks_enforce() {
        let mut enforcer = make_enforcer();
        let token = make_token(ImpossibleCapability::ChildProcessSpawn, 5000);
        enforcer.opt_in(token, "admin", 2000).unwrap();
        // Before expiry: ok.
        assert!(
            enforcer
                .enforce(ImpossibleCapability::ChildProcessSpawn, "user", 4000)
                .is_ok()
        );
        // After expiry: blocked.
        let err = enforcer
            .enforce(ImpossibleCapability::ChildProcessSpawn, "user", 6000)
            .unwrap_err();
        assert_eq!(err.code, ERR_IBD_TOKEN_EXPIRED);
    }

    // -- AC4: Clear, actionable error messages --

    #[test]
    fn test_blocked_error_contains_capability_name() {
        let err = EnforcementError::blocked(ImpossibleCapability::UnsignedExtension);
        assert!(err.message.contains("unsigned_extension"));
        assert!(err.message.contains(ERR_IBD_BLOCKED));
    }

    #[test]
    fn test_expired_error_contains_token_id() {
        let err = EnforcementError::token_expired(ImpossibleCapability::FsAccess, "tok-123");
        assert!(err.message.contains("tok-123"));
        assert!(err.message.contains(ERR_IBD_TOKEN_EXPIRED));
    }

    #[test]
    fn test_invalid_sig_error_actionable() {
        let err = EnforcementError::invalid_signature(ImpossibleCapability::FsAccess, "tok-456");
        assert!(err.message.contains("tok-456"));
        assert!(err.message.contains("invalid signature"));
    }

    #[test]
    fn test_silent_disable_error_actionable() {
        let err = EnforcementError::silent_disable(ImpossibleCapability::DisableHardening);
        assert!(err.message.contains("disable_hardening"));
        assert!(err.message.contains("audited"));
    }

    #[test]
    fn test_error_display() {
        let err = EnforcementError::blocked(ImpossibleCapability::FsAccess);
        let display = format!("{}", err);
        assert!(display.contains(ERR_IBD_BLOCKED));
    }

    // -- AC5: Adoption metric --

    #[test]
    fn test_adoption_rate_100_pct() {
        let mut metrics = EnforcementMetrics::default();
        metrics.deployments_total = 100;
        metrics.deployments_enforced = 100;
        assert!((metrics.adoption_rate_pct() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_adoption_rate_90_pct() {
        let mut metrics = EnforcementMetrics::default();
        metrics.deployments_total = 100;
        metrics.deployments_enforced = 90;
        assert!((metrics.adoption_rate_pct() - 90.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_adoption_rate_zero_deployments() {
        let metrics = EnforcementMetrics::default();
        // No deployments -> 100% by convention (no violations possible).
        assert!((metrics.adoption_rate_pct() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_deployment_enforced() {
        let mut enforcer = make_enforcer();
        enforcer.record_deployment(true);
        enforcer.record_deployment(true);
        enforcer.record_deployment(false);
        assert_eq!(enforcer.metrics().deployments_total, 3);
        assert_eq!(enforcer.metrics().deployments_enforced, 2);
    }

    // -- AC6: Silent disable blocked and logged --

    #[test]
    fn test_silent_disable_blocked() {
        let mut enforcer = make_enforcer();
        let err = enforcer
            .attempt_silent_disable(ImpossibleCapability::DisableHardening, "rogue", 5000)
            .unwrap_err();
        assert_eq!(err.code, ERR_IBD_SILENT_DISABLE);
    }

    #[test]
    fn test_silent_disable_logged() {
        let mut enforcer = make_enforcer();
        let _ = enforcer.attempt_silent_disable(ImpossibleCapability::FsAccess, "rogue", 5000);
        let log = enforcer.audit_log();
        assert!(!log.is_empty());
        let last = log.last().unwrap();
        assert_eq!(last.event_code, IBD_004_SILENT_DISABLE_DETECTED);
    }

    #[test]
    fn test_silent_disable_increments_metric() {
        let mut enforcer = make_enforcer();
        let _ = enforcer.attempt_silent_disable(ImpossibleCapability::FsAccess, "rogue", 5000);
        assert_eq!(enforcer.metrics().silent_disable_detected_total, 1);
    }

    // -- AC7: Enforcement report --

    #[test]
    fn test_generate_report_structure() {
        let enforcer = make_enforcer();
        let report = enforcer.generate_report("2026-02-20T00:00:00Z");
        assert_eq!(report.bead_id, "bd-1xao");
        assert_eq!(report.section, "13");
        assert_eq!(report.capabilities.len(), 5);
        assert_eq!(report.threshold_pct, 90.0);
    }

    #[test]
    fn test_report_all_blocked_by_default() {
        let enforcer = make_enforcer();
        let report = enforcer.generate_report("2026-02-20T00:00:00Z");
        for entry in &report.capabilities {
            assert_eq!(entry.enforcement_status, "blocked");
        }
    }

    #[test]
    fn test_report_after_opt_in() {
        let mut enforcer = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 99_999);
        enforcer.opt_in(token, "admin", 1000).unwrap();
        let report = enforcer.generate_report("2026-02-20T00:00:00Z");
        let fs_entry = report
            .capabilities
            .iter()
            .find(|e| e.capability == ImpossibleCapability::FsAccess)
            .unwrap();
        assert_eq!(fs_entry.enforcement_status, "enabled");
    }

    // -- Audit log --

    #[test]
    fn test_enforce_blocked_creates_audit_entry() {
        let mut enforcer = make_enforcer();
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "user", 1000);
        assert_eq!(enforcer.audit_log().len(), 1);
        assert_eq!(
            enforcer.audit_log()[0].event_code,
            IBD_001_CAPABILITY_BLOCKED
        );
    }

    #[test]
    fn test_opt_in_creates_audit_entry() {
        let mut enforcer = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 99_999);
        enforcer.opt_in(token, "admin", 1000).unwrap();
        let entry = enforcer.audit_log().last().unwrap();
        assert_eq!(entry.event_code, IBD_002_OPT_IN_GRANTED);
    }

    #[test]
    fn test_audit_hash_chain() {
        let mut enforcer = make_enforcer();
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "u", 1000);
        let _ = enforcer.enforce(ImpossibleCapability::OutboundNetwork, "u", 2000);
        let log = enforcer.audit_log();
        assert_eq!(log[1].prev_hash, log[0].hash());
    }

    #[test]
    fn test_audit_first_entry_has_zero_prev_hash() {
        let mut enforcer = make_enforcer();
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "u", 1000);
        assert_eq!(enforcer.audit_log()[0].prev_hash, "0".repeat(64));
    }

    // -- Token --

    #[test]
    fn test_token_is_expired() {
        let token = make_token(ImpossibleCapability::FsAccess, 5000);
        assert!(!token.is_expired(4000));
        assert!(token.is_expired(5000));
        assert!(token.is_expired(6000));
    }

    #[test]
    fn test_token_content_hash_deterministic() {
        let t1 = make_token(ImpossibleCapability::FsAccess, 5000);
        let t2 = make_token(ImpossibleCapability::FsAccess, 5000);
        assert_eq!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn test_token_content_hash_differs_for_different_caps() {
        let t1 = make_token(ImpossibleCapability::FsAccess, 5000);
        let t2 = make_token(ImpossibleCapability::OutboundNetwork, 5000);
        assert_ne!(t1.content_hash(), t2.content_hash());
    }

    // -- Expire tokens --

    #[test]
    fn test_expire_tokens_batch() {
        let mut enforcer = make_enforcer();
        let t1 = make_token(ImpossibleCapability::FsAccess, 5000);
        let t2 = make_token(ImpossibleCapability::OutboundNetwork, 5000);
        enforcer.opt_in(t1, "admin", 1000).unwrap();
        enforcer.opt_in(t2, "admin", 1000).unwrap();
        let expired = enforcer.expire_tokens(6000);
        assert_eq!(expired.len(), 2);
        assert!(!enforcer.is_enabled(ImpossibleCapability::FsAccess));
        assert!(!enforcer.is_enabled(ImpossibleCapability::OutboundNetwork));
    }

    #[test]
    fn test_expire_tokens_partial() {
        let mut enforcer = make_enforcer();
        let t1 = make_token(ImpossibleCapability::FsAccess, 5000);
        let t2 = make_token(ImpossibleCapability::OutboundNetwork, 10_000);
        enforcer.opt_in(t1, "admin", 1000).unwrap();
        enforcer.opt_in(t2, "admin", 1000).unwrap();
        let expired = enforcer.expire_tokens(6000);
        assert_eq!(expired.len(), 1);
        assert!(!enforcer.is_enabled(ImpossibleCapability::FsAccess));
        assert!(enforcer.is_enabled(ImpossibleCapability::OutboundNetwork));
    }

    // -- Metrics --

    #[test]
    fn test_metrics_blocked_total() {
        let mut enforcer = make_enforcer();
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "u", 1000);
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "u", 2000);
        assert_eq!(enforcer.metrics().blocked_total, 2);
    }

    #[test]
    fn test_metrics_opt_in_total() {
        let mut enforcer = make_enforcer();
        let t = make_token(ImpossibleCapability::FsAccess, 99_999);
        enforcer.opt_in(t, "admin", 1000).unwrap();
        assert_eq!(enforcer.metrics().opt_in_granted_total, 1);
    }

    // -- Event codes --

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(IBD_001_CAPABILITY_BLOCKED, "IBD-001");
        assert_eq!(IBD_002_OPT_IN_GRANTED, "IBD-002");
        assert_eq!(IBD_003_OPT_IN_EXPIRED, "IBD-003");
        assert_eq!(IBD_004_SILENT_DISABLE_DETECTED, "IBD-004");
    }

    // -- Error codes --

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(ERR_IBD_BLOCKED, "ERR_IBD_BLOCKED");
        assert_eq!(ERR_IBD_TOKEN_EXPIRED, "ERR_IBD_TOKEN_EXPIRED");
        assert_eq!(ERR_IBD_INVALID_SIGNATURE, "ERR_IBD_INVALID_SIGNATURE");
        assert_eq!(ERR_IBD_SILENT_DISABLE, "ERR_IBD_SILENT_DISABLE");
    }

    // -- Invariant tags --

    #[test]
    fn test_invariant_tags_defined() {
        assert_eq!(INV_IBD_ENFORCE, "INV-IBD-ENFORCE");
        assert_eq!(INV_IBD_TOKEN, "INV-IBD-TOKEN");
        assert_eq!(INV_IBD_AUDIT, "INV-IBD-AUDIT");
        assert_eq!(INV_IBD_ADOPTION, "INV-IBD-ADOPTION");
    }

    // -- EnforcementStatus --

    #[test]
    fn test_enforcement_status_blocked() {
        let status = EnforcementStatus::Blocked;
        assert!(status.is_blocked());
        assert!(!status.is_enabled());
    }

    #[test]
    fn test_enforcement_status_enabled() {
        let status = EnforcementStatus::Enabled {
            token_id: "tok-1".to_string(),
            expires_at_ms: 9999,
        };
        assert!(!status.is_blocked());
        assert!(status.is_enabled());
    }

    // -- Serde --

    #[test]
    fn test_capability_serde_roundtrip() {
        let cap = ImpossibleCapability::FsAccess;
        let json = serde_json::to_string(&cap).unwrap();
        let parsed: ImpossibleCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cap);
    }

    #[test]
    fn test_token_serde_roundtrip() {
        let token = make_token(ImpossibleCapability::FsAccess, 5000);
        let json = serde_json::to_string(&token).unwrap();
        let parsed: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, token);
    }

    #[test]
    fn test_enforcement_error_serde_roundtrip() {
        let err = EnforcementError::blocked(ImpossibleCapability::FsAccess);
        let json = serde_json::to_string(&err).unwrap();
        let parsed: EnforcementError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    #[test]
    fn test_enforcement_report_serde() {
        let enforcer = make_enforcer();
        let report = enforcer.generate_report("2026-02-20T00:00:00Z");
        let json = serde_json::to_string(&report).unwrap();
        let parsed: EnforcementReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.bead_id, "bd-1xao");
    }

    #[test]
    fn test_metrics_serde_roundtrip() {
        let m = EnforcementMetrics {
            blocked_total: 5,
            opt_in_granted_total: 2,
            opt_in_expired_total: 1,
            silent_disable_detected_total: 0,
            deployments_enforced: 90,
            deployments_total: 100,
        };
        let json = serde_json::to_string(&m).unwrap();
        let parsed: EnforcementMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.blocked_total, 5);
    }

    // -- Integration: full lifecycle --

    #[test]
    fn test_full_lifecycle() {
        let mut enforcer = make_enforcer();

        // 1. All blocked by default.
        for &cap in ImpossibleCapability::ALL {
            assert!(enforcer.enforce(cap, "user", 1000).is_err());
        }

        // 2. Opt-in for FsAccess.
        let token = make_token(ImpossibleCapability::FsAccess, 10_000);
        enforcer.opt_in(token, "admin", 2000).unwrap();
        assert!(
            enforcer
                .enforce(ImpossibleCapability::FsAccess, "user", 3000)
                .is_ok()
        );

        // 3. Other capabilities still blocked.
        assert!(
            enforcer
                .enforce(ImpossibleCapability::OutboundNetwork, "user", 3000)
                .is_err()
        );

        // 4. Token expires.
        let expired = enforcer.expire_tokens(11_000);
        assert_eq!(expired.len(), 1);
        assert!(
            enforcer
                .enforce(ImpossibleCapability::FsAccess, "user", 12_000)
                .is_err()
        );

        // 5. Silent disable attempt.
        assert!(
            enforcer
                .attempt_silent_disable(ImpossibleCapability::FsAccess, "rogue", 13_000)
                .is_err()
        );

        // 6. Verify audit completeness.
        let log = enforcer.audit_log();
        assert!(log.len() >= 5); // Multiple events logged.

        // Verify hash chain integrity.
        for i in 1..log.len() {
            assert_eq!(log[i].prev_hash, log[i - 1].hash());
        }
    }
}
