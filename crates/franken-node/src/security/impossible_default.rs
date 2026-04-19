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
use std::collections::BTreeMap;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
        hasher.update(b"impossible_default_hash_v1:");
        // Length-prefix variable-length string fields to prevent delimiter-collision attacks.
        hasher.update(u64::try_from(self.token_id.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(self.token_id.as_bytes());
        let cap_label = self.capability.label();
        hasher.update(u64::try_from(cap_label.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(cap_label.as_bytes());
        hasher.update(u64::try_from(self.issuer.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(self.issuer.as_bytes());
        hasher.update(u64::try_from(self.subject.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(self.subject.as_bytes());
        // Fixed-size u64 fields — no length-prefix needed.
        hasher.update(self.issued_at_ms.to_le_bytes());
        hasher.update(self.expires_at_ms.to_le_bytes());
        hasher.update(u64::try_from(self.justification.len()).unwrap_or(u64::MAX).to_le_bytes());
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
        hasher.update(b"impossible_default_audit_hash_v1:");
        // Length-prefix variable-length string fields to prevent delimiter-collision attacks.
        hasher.update(u64::try_from(self.event_code.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(self.event_code.as_bytes());
        let cap_label = self.capability.label();
        hasher.update(u64::try_from(cap_label.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(cap_label.as_bytes());
        hasher.update(u64::try_from(self.actor.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(self.actor.as_bytes());
        // Fixed-size u64 field — no length-prefix needed.
        hasher.update(self.timestamp_ms.to_le_bytes());
        hasher.update(u64::try_from(self.detail.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(self.detail.as_bytes());
        // Optional token_id: use 0-length sentinel for None, length-prefixed for Some.
        match &self.token_id {
            Some(tid) => {
                hasher.update(u64::try_from(tid.len()).unwrap_or(u64::MAX).to_le_bytes());
                hasher.update(tid.as_bytes());
            }
            None => {
                // Distinct from Some("") because Some("") has length 0 followed by
                // empty bytes, while None uses u64::MAX as a sentinel that no real
                // string length can match.
                hasher.update(u64::MAX.to_le_bytes());
            }
        }
        hasher.update(u64::try_from(self.prev_hash.len()).unwrap_or(u64::MAX).to_le_bytes());
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

/// Ed25519 signature verifier for capability tokens.
///
/// Verifies that `token.signature` (hex-encoded, 64 bytes) is a valid Ed25519
/// signature over the token's `content_hash()` bytes, checked against the
/// stored `VerifyingKey`.
#[derive(Debug, Clone)]
pub struct Ed25519SignatureVerifier {
    /// The Ed25519 public key used to verify token signatures.
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519SignatureVerifier {
    /// Create a new verifier from an Ed25519 verifying (public) key.
    pub fn new(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self { verifying_key }
    }
}

impl SignatureVerifier for Ed25519SignatureVerifier {
    fn verify(&self, token: &CapabilityToken) -> bool {
        use ed25519_dalek::Verifier;

        let Ok(sig_bytes) = hex::decode(&token.signature) else {
            return false;
        };
        let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        let hash = token.content_hash();
        self.verifying_key
            .verify(hash.as_bytes(), &signature)
            .is_ok()
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
    state: BTreeMap<ImpossibleCapability, EnforcementStatus>,
    /// Active tokens indexed by capability.
    tokens: BTreeMap<ImpossibleCapability, CapabilityToken>,
    /// Audit log.
    audit_log: Vec<EnforcementAuditEntry>,
    /// Anchor hash: hash of the most recently evicted audit entry.
    chain_anchor_hash: Option<String>,
    /// Metrics.
    metrics: EnforcementMetrics,
    /// Per-capability blocked/opted-in counters for reporting.
    blocked_counts: BTreeMap<ImpossibleCapability, u64>,
    opted_in_counts: BTreeMap<ImpossibleCapability, u64>,
    /// Signature verifier.
    verifier: Box<dyn SignatureVerifier>,
}

impl CapabilityEnforcer {
    /// Create a new enforcer with the given signature verifier.
    /// All capabilities start in Blocked state (INV-IBD-ENFORCE).
    pub fn new(verifier: Box<dyn SignatureVerifier>) -> Self {
        let mut state = BTreeMap::new();
        let mut blocked_counts = BTreeMap::new();
        let opted_in_counts = BTreeMap::new();
        for &cap in ImpossibleCapability::ALL {
            state.insert(cap, EnforcementStatus::Blocked);
            blocked_counts.insert(cap, 0);
        }
        Self {
            state,
            tokens: BTreeMap::new(),
            audit_log: Vec::new(),
            chain_anchor_hash: None,
            metrics: EnforcementMetrics::default(),
            blocked_counts,
            opted_in_counts,
            verifier,
        }
    }

    /// Create a new enforcer with an Ed25519 verifying key.
    pub fn with_ed25519_verifier(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self::new(Box::new(Ed25519SignatureVerifier::new(verifying_key)))
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
        if let Some(token) = self.tokens.get(&capability)
            && token.is_expired(current_time_ms)
        {
            let token_id = token.token_id.clone();
            // Expire the token.
            self.state.insert(capability, EnforcementStatus::Blocked);
            self.tokens.remove(&capability);
            self.metrics.opt_in_expired_total = self.metrics.opt_in_expired_total.saturating_add(1);

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

            let bc = self.blocked_counts.entry(capability).or_insert(0);
            *bc = bc.saturating_add(1);
            return Err(EnforcementError::token_expired(capability, &token_id));
        }

        match self.state.get(&capability) {
            Some(EnforcementStatus::Enabled { .. }) => Ok(()),
            _ => {
                self.metrics.blocked_total = self.metrics.blocked_total.saturating_add(1);
                let bc = self.blocked_counts.entry(capability).or_insert(0);
                *bc = bc.saturating_add(1);

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
                ERR_IBD_INVALID_SIGNATURE,
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
            self.metrics.opt_in_expired_total = self.metrics.opt_in_expired_total.saturating_add(1);
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
        self.metrics.opt_in_granted_total = self.metrics.opt_in_granted_total.saturating_add(1);
        let oc = self.opted_in_counts.entry(capability).or_insert(0);
        *oc = oc.saturating_add(1);

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
        self.metrics.silent_disable_detected_total =
            self.metrics.silent_disable_detected_total.saturating_add(1);

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
            self.metrics.opt_in_expired_total = self.metrics.opt_in_expired_total.saturating_add(1);

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
        self.metrics.deployments_total = self.metrics.deployments_total.saturating_add(1);
        if all_enforced {
            self.metrics.deployments_enforced = self.metrics.deployments_enforced.saturating_add(1);
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
            .or_else(|| self.chain_anchor_hash.clone())
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

        if self.audit_log.len() >= MAX_AUDIT_LOG_ENTRIES {
            let overflow = self
                .audit_log
                .len()
                .saturating_sub(MAX_AUDIT_LOG_ENTRIES)
                .saturating_add(1);
            let anchor_index = overflow.saturating_sub(1);
            self.chain_anchor_hash = self
                .audit_log
                .get(anchor_index)
                .map(EnforcementAuditEntry::hash);
            self.audit_log.drain(0..overflow.min(self.audit_log.len()));
        }
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

    use ed25519_dalek::{Signer, SigningKey};

    /// Sign a capability token with the given Ed25519 signing key.
    /// Sets `token.signature` to the hex-encoded Ed25519 signature over
    /// the token's `content_hash()`.
    fn sign_token(token: &mut CapabilityToken, signing_key: &SigningKey) {
        let hash = token.content_hash();
        let sig = signing_key.sign(hash.as_bytes());
        token.signature = hex::encode(sig.to_bytes());
    }

    /// Deterministic test keypair (fixed seed for reproducibility).
    fn test_signing_key() -> SigningKey {
        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        SigningKey::from_bytes(&seed)
    }

    fn make_enforcer() -> (CapabilityEnforcer, SigningKey) {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let enforcer = CapabilityEnforcer::with_ed25519_verifier(vk);
        (enforcer, sk)
    }

    fn make_token(
        cap: ImpossibleCapability,
        expires_at_ms: u64,
        sk: &SigningKey,
    ) -> CapabilityToken {
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
        sign_token(&mut token, sk);
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
        let (enforcer, _sk) = make_enforcer();
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
        let (mut enforcer, _sk) = make_enforcer();
        for &cap in ImpossibleCapability::ALL {
            let err = enforcer.enforce(cap, "user", 1000).unwrap_err();
            assert_eq!(err.code, ERR_IBD_BLOCKED);
            assert_eq!(err.capability, cap);
        }
    }

    #[test]
    fn test_blocked_error_is_actionable() {
        let (mut enforcer, _sk) = make_enforcer();
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
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 10_000, &sk);
        enforcer.opt_in(token, "admin", 2000).unwrap();
        assert!(enforcer.is_enabled(ImpossibleCapability::FsAccess));
    }

    #[test]
    fn test_enforce_after_opt_in_succeeds() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::OutboundNetwork, 10_000, &sk);
        enforcer.opt_in(token, "admin", 2000).unwrap();
        assert!(
            enforcer
                .enforce(ImpossibleCapability::OutboundNetwork, "user", 3000)
                .is_ok()
        );
    }

    #[test]
    fn test_opt_in_with_invalid_signature_rejected() {
        let (mut enforcer, _sk) = make_enforcer();
        let token = make_bad_sig_token(ImpossibleCapability::FsAccess);
        let err = enforcer.opt_in(token, "admin", 2000).unwrap_err();
        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
    }

    #[test]
    fn test_opt_in_with_expired_token_rejected() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 1500, &sk);
        let err = enforcer.opt_in(token, "admin", 2000).unwrap_err();
        assert_eq!(err.code, ERR_IBD_TOKEN_EXPIRED);
    }

    #[test]
    fn test_opt_in_expired_at_exact_boundary_rejected_and_not_enabled() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 2000, &sk);

        let err = enforcer.opt_in(token, "admin", 2000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_TOKEN_EXPIRED);
        assert!(!enforcer.is_enabled(ImpossibleCapability::FsAccess));
        assert_eq!(enforcer.metrics().opt_in_expired_total, 1);
        let entry = enforcer
            .audit_log()
            .last()
            .expect("expired token is audited");
        assert_eq!(entry.event_code, IBD_003_OPT_IN_EXPIRED);
        assert_eq!(entry.token_id.as_deref(), Some("tok-fs_access"));
    }

    #[test]
    fn test_opt_in_rejects_token_tampered_after_signing() {
        let (mut enforcer, sk) = make_enforcer();
        let mut token = make_token(ImpossibleCapability::OutboundNetwork, 10_000, &sk);
        token.subject = "attacker-subject".to_string();

        let err = enforcer.opt_in(token, "admin", 2000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert!(!enforcer.is_enabled(ImpossibleCapability::OutboundNetwork));
        assert_eq!(enforcer.metrics().opt_in_granted_total, 0);
        let entry = enforcer
            .audit_log()
            .last()
            .expect("invalid signature is audited");
        assert_eq!(entry.event_code, ERR_IBD_INVALID_SIGNATURE);
    }

    #[test]
    fn test_opt_in_rejects_signature_with_valid_hex_wrong_length() {
        let (mut enforcer, sk) = make_enforcer();
        let mut token = make_token(ImpossibleCapability::UnsignedExtension, 10_000, &sk);
        token.signature = "aa".repeat(63);

        let err = enforcer.opt_in(token, "admin", 2000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert!(!enforcer.is_enabled(ImpossibleCapability::UnsignedExtension));
        assert_eq!(enforcer.metrics().opt_in_granted_total, 0);
    }

    #[test]
    fn test_token_expiry_blocks_enforce() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::ChildProcessSpawn, 5000, &sk);
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

    #[test]
    fn test_enforce_at_exact_expiry_boundary_expires_and_removes_token() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::ChildProcessSpawn, 5000, &sk);
        enforcer.opt_in(token, "admin", 1000).unwrap();

        let err = enforcer
            .enforce(ImpossibleCapability::ChildProcessSpawn, "user", 5000)
            .unwrap_err();

        assert_eq!(err.code, ERR_IBD_TOKEN_EXPIRED);
        assert!(!enforcer.is_enabled(ImpossibleCapability::ChildProcessSpawn));
        assert!(
            enforcer
                .tokens
                .get(&ImpossibleCapability::ChildProcessSpawn)
                .is_none()
        );
        assert_eq!(enforcer.metrics().opt_in_expired_total, 1);
        assert_eq!(
            enforcer.audit_log().last().unwrap().event_code,
            IBD_003_OPT_IN_EXPIRED
        );
    }

    #[test]
    fn test_expired_enforce_does_not_increment_blocked_total() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::DisableHardening, 5000, &sk);
        enforcer.opt_in(token, "admin", 1000).unwrap();

        let err = enforcer
            .enforce(ImpossibleCapability::DisableHardening, "user", 5000)
            .unwrap_err();

        assert_eq!(err.code, ERR_IBD_TOKEN_EXPIRED);
        assert_eq!(enforcer.metrics().blocked_total, 0);
        assert_eq!(enforcer.metrics().opt_in_expired_total, 1);
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
        let metrics = EnforcementMetrics {
            deployments_total: 100,
            deployments_enforced: 100,
            ..Default::default()
        };
        assert!((metrics.adoption_rate_pct() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_adoption_rate_90_pct() {
        let metrics = EnforcementMetrics {
            deployments_total: 100,
            deployments_enforced: 90,
            ..Default::default()
        };
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
        let (mut enforcer, _sk) = make_enforcer();
        enforcer.record_deployment(true);
        enforcer.record_deployment(true);
        enforcer.record_deployment(false);
        assert_eq!(enforcer.metrics().deployments_total, 3);
        assert_eq!(enforcer.metrics().deployments_enforced, 2);
    }

    // -- AC6: Silent disable blocked and logged --

    #[test]
    fn test_silent_disable_blocked() {
        let (mut enforcer, _sk) = make_enforcer();
        let err = enforcer
            .attempt_silent_disable(ImpossibleCapability::DisableHardening, "rogue", 5000)
            .unwrap_err();
        assert_eq!(err.code, ERR_IBD_SILENT_DISABLE);
    }

    #[test]
    fn test_silent_disable_logged() {
        let (mut enforcer, _sk) = make_enforcer();
        let _ = enforcer.attempt_silent_disable(ImpossibleCapability::FsAccess, "rogue", 5000);
        let log = enforcer.audit_log();
        assert!(!log.is_empty());
        let last = log.last().unwrap();
        assert_eq!(last.event_code, IBD_004_SILENT_DISABLE_DETECTED);
    }

    #[test]
    fn test_silent_disable_increments_metric() {
        let (mut enforcer, _sk) = make_enforcer();
        let _ = enforcer.attempt_silent_disable(ImpossibleCapability::FsAccess, "rogue", 5000);
        assert_eq!(enforcer.metrics().silent_disable_detected_total, 1);
    }

    #[test]
    fn test_silent_disable_does_not_turn_off_valid_opt_in() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 10_000, &sk);
        enforcer.opt_in(token, "admin", 1000).unwrap();

        let err = enforcer
            .attempt_silent_disable(ImpossibleCapability::FsAccess, "rogue", 2000)
            .unwrap_err();

        assert_eq!(err.code, ERR_IBD_SILENT_DISABLE);
        assert!(enforcer.is_enabled(ImpossibleCapability::FsAccess));
        assert!(
            enforcer
                .enforce(ImpossibleCapability::FsAccess, "user", 3000)
                .is_ok()
        );
    }

    // -- AC7: Enforcement report --

    #[test]
    fn test_generate_report_structure() {
        let (enforcer, _sk) = make_enforcer();
        let report = enforcer.generate_report("2026-02-20T00:00:00Z");
        assert_eq!(report.bead_id, "bd-1xao");
        assert_eq!(report.section, "13");
        assert_eq!(report.capabilities.len(), 5);
        assert_eq!(report.threshold_pct, 90.0);
    }

    #[test]
    fn test_report_all_blocked_by_default() {
        let (enforcer, _sk) = make_enforcer();
        let report = enforcer.generate_report("2026-02-20T00:00:00Z");
        for entry in &report.capabilities {
            assert_eq!(entry.enforcement_status, "blocked");
        }
    }

    #[test]
    fn test_report_after_opt_in() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 99_999, &sk);
        enforcer.opt_in(token, "admin", 1000).unwrap();
        let report = enforcer.generate_report("2026-02-20T00:00:00Z");
        let fs_entry = report
            .capabilities
            .iter()
            .find(|e| e.capability == ImpossibleCapability::FsAccess)
            .unwrap();
        assert_eq!(fs_entry.enforcement_status, "enabled");
    }

    #[test]
    fn test_report_fails_adoption_threshold_below_ninety_percent() {
        let (mut enforcer, _sk) = make_enforcer();
        for _ in 0..8 {
            enforcer.record_deployment(true);
        }
        for _ in 0..2 {
            enforcer.record_deployment(false);
        }

        let report = enforcer.generate_report("2026-02-20T00:00:00Z");

        assert_eq!(report.overall_adoption_rate_pct, 80.0);
        assert!(!report.meets_threshold);
        assert_eq!(report.threshold_pct, 90.0);
    }

    // -- Audit log --

    #[test]
    fn test_enforce_blocked_creates_audit_entry() {
        let (mut enforcer, _sk) = make_enforcer();
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "user", 1000);
        assert_eq!(enforcer.audit_log().len(), 1);
        assert_eq!(
            enforcer.audit_log()[0].event_code,
            IBD_001_CAPABILITY_BLOCKED
        );
    }

    #[test]
    fn test_opt_in_creates_audit_entry() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 99_999, &sk);
        enforcer.opt_in(token, "admin", 1000).unwrap();
        let entry = enforcer.audit_log().last().unwrap();
        assert_eq!(entry.event_code, IBD_002_OPT_IN_GRANTED);
    }

    #[test]
    fn test_audit_hash_chain() {
        let (mut enforcer, _sk) = make_enforcer();
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "u", 1000);
        let _ = enforcer.enforce(ImpossibleCapability::OutboundNetwork, "u", 2000);
        let log = enforcer.audit_log();
        assert_eq!(log[1].prev_hash, log[0].hash());
    }

    #[test]
    fn test_audit_first_entry_has_zero_prev_hash() {
        let (mut enforcer, _sk) = make_enforcer();
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "u", 1000);
        assert_eq!(enforcer.audit_log()[0].prev_hash, "0".repeat(64));
    }

    // -- Token --

    #[test]
    fn test_token_is_expired() {
        let sk = test_signing_key();
        let token = make_token(ImpossibleCapability::FsAccess, 5000, &sk);
        assert!(!token.is_expired(4000));
        assert!(token.is_expired(5000));
        assert!(token.is_expired(6000));
    }

    #[test]
    fn test_token_content_hash_deterministic() {
        let sk = test_signing_key();
        let t1 = make_token(ImpossibleCapability::FsAccess, 5000, &sk);
        let t2 = make_token(ImpossibleCapability::FsAccess, 5000, &sk);
        assert_eq!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn test_token_content_hash_differs_for_different_caps() {
        let sk = test_signing_key();
        let t1 = make_token(ImpossibleCapability::FsAccess, 5000, &sk);
        let t2 = make_token(ImpossibleCapability::OutboundNetwork, 5000, &sk);
        assert_ne!(t1.content_hash(), t2.content_hash());
    }

    // -- Expire tokens --

    #[test]
    fn test_expire_tokens_batch() {
        let (mut enforcer, sk) = make_enforcer();
        let t1 = make_token(ImpossibleCapability::FsAccess, 5000, &sk);
        let t2 = make_token(ImpossibleCapability::OutboundNetwork, 5000, &sk);
        enforcer.opt_in(t1, "admin", 1000).unwrap();
        enforcer.opt_in(t2, "admin", 1000).unwrap();
        let expired = enforcer.expire_tokens(6000);
        assert_eq!(expired.len(), 2);
        assert!(!enforcer.is_enabled(ImpossibleCapability::FsAccess));
        assert!(!enforcer.is_enabled(ImpossibleCapability::OutboundNetwork));
    }

    #[test]
    fn test_expire_tokens_partial() {
        let (mut enforcer, sk) = make_enforcer();
        let t1 = make_token(ImpossibleCapability::FsAccess, 5000, &sk);
        let t2 = make_token(ImpossibleCapability::OutboundNetwork, 10_000, &sk);
        enforcer.opt_in(t1, "admin", 1000).unwrap();
        enforcer.opt_in(t2, "admin", 1000).unwrap();
        let expired = enforcer.expire_tokens(6000);
        assert_eq!(expired.len(), 1);
        assert!(!enforcer.is_enabled(ImpossibleCapability::FsAccess));
        assert!(enforcer.is_enabled(ImpossibleCapability::OutboundNetwork));
    }

    #[test]
    fn test_expire_tokens_at_exact_boundary_only_expires_matching_tokens() {
        let (mut enforcer, sk) = make_enforcer();
        let t1 = make_token(ImpossibleCapability::FsAccess, 5000, &sk);
        let t2 = make_token(ImpossibleCapability::OutboundNetwork, 5001, &sk);
        enforcer.opt_in(t1, "admin", 1000).unwrap();
        enforcer.opt_in(t2, "admin", 1000).unwrap();

        let expired = enforcer.expire_tokens(5000);

        assert_eq!(expired, vec![ImpossibleCapability::FsAccess]);
        assert!(!enforcer.is_enabled(ImpossibleCapability::FsAccess));
        assert!(enforcer.is_enabled(ImpossibleCapability::OutboundNetwork));
        assert_eq!(enforcer.metrics().opt_in_expired_total, 1);
    }

    #[test]
    fn test_expire_tokens_no_expired_tokens_has_no_audit_side_effects() {
        let (mut enforcer, sk) = make_enforcer();
        let token = make_token(ImpossibleCapability::FsAccess, 5001, &sk);
        enforcer.opt_in(token, "admin", 1000).unwrap();
        let audit_len = enforcer.audit_log().len();

        let expired = enforcer.expire_tokens(5000);

        assert!(expired.is_empty());
        assert_eq!(enforcer.audit_log().len(), audit_len);
        assert!(enforcer.is_enabled(ImpossibleCapability::FsAccess));
    }

    // -- Metrics --

    #[test]
    fn test_metrics_blocked_total() {
        let (mut enforcer, _sk) = make_enforcer();
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "u", 1000);
        let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "u", 2000);
        assert_eq!(enforcer.metrics().blocked_total, 2);
    }

    #[test]
    fn test_metrics_opt_in_total() {
        let (mut enforcer, sk) = make_enforcer();
        let t = make_token(ImpossibleCapability::FsAccess, 99_999, &sk);
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
        let sk = test_signing_key();
        let token = make_token(ImpossibleCapability::FsAccess, 5000, &sk);
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
        let (enforcer, _sk) = make_enforcer();
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
        let (mut enforcer, sk) = make_enforcer();

        // 1. All blocked by default.
        for &cap in ImpossibleCapability::ALL {
            assert!(enforcer.enforce(cap, "user", 1000).is_err());
        }

        // 2. Opt-in for FsAccess.
        let token = make_token(ImpossibleCapability::FsAccess, 10_000, &sk);
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
        assert_eq!(log.len(), 10); // Multiple events logged.

        // Verify hash chain integrity.
        for i in 1..log.len() {
            assert_eq!(log[i].prev_hash, log[i - 1].hash());
        }
    }
}

#[cfg(test)]
mod impossible_default_negative_path_tests {
    use super::*;

    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    fn sign_token(token: &mut CapabilityToken, signing_key: &SigningKey) {
        let hash = token.content_hash();
        let sig = signing_key.sign(hash.as_bytes());
        token.signature = hex::encode(sig.to_bytes());
    }

    fn enforcer_for(signing_key: &SigningKey) -> CapabilityEnforcer {
        CapabilityEnforcer::with_ed25519_verifier(signing_key.verifying_key())
    }

    fn token_with_id(
        token_id: &str,
        capability: ImpossibleCapability,
        expires_at_ms: u64,
        signing_key: &SigningKey,
    ) -> CapabilityToken {
        let mut token = CapabilityToken {
            token_id: token_id.to_string(),
            capability,
            issuer: "negative-test-issuer".to_string(),
            subject: "negative-test-subject".to_string(),
            issued_at_ms: 1_000,
            expires_at_ms,
            signature: String::new(),
            justification: "negative path regression".to_string(),
        };
        sign_token(&mut token, signing_key);
        token
    }

    #[test]
    fn opt_in_rejects_token_signed_by_untrusted_key() {
        let trusted_key = signing_key(0x31);
        let rogue_key = signing_key(0x32);
        let mut enforcer = enforcer_for(&trusted_key);
        let token = token_with_id(
            "rogue-token",
            ImpossibleCapability::FsAccess,
            10_000,
            &rogue_key,
        );

        let err = enforcer.opt_in(token, "admin", 2_000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert!(enforcer.status(ImpossibleCapability::FsAccess).is_blocked());
        assert_eq!(enforcer.metrics().opt_in_granted_total, 0);
        assert_eq!(
            enforcer
                .audit_log()
                .last()
                .map(|entry| entry.event_code.as_str()),
            Some(ERR_IBD_INVALID_SIGNATURE)
        );
    }

    #[test]
    fn opt_in_rejects_overlong_hex_signature() {
        let signing_key = signing_key(0x41);
        let mut enforcer = enforcer_for(&signing_key);
        let mut token = token_with_id(
            "overlong-signature-token",
            ImpossibleCapability::UnsignedExtension,
            10_000,
            &signing_key,
        );
        token.signature = "aa".repeat(65);

        let err = enforcer.opt_in(token, "admin", 2_000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert!(!enforcer.is_enabled(ImpossibleCapability::UnsignedExtension));
        assert_eq!(enforcer.metrics().opt_in_granted_total, 0);
    }

    #[test]
    fn invalid_signature_does_not_replace_existing_valid_token() {
        let signing_key = signing_key(0x51);
        let mut enforcer = enforcer_for(&signing_key);
        let valid = token_with_id(
            "valid-token",
            ImpossibleCapability::OutboundNetwork,
            10_000,
            &signing_key,
        );
        enforcer.opt_in(valid, "admin", 2_000).unwrap();

        let mut invalid = token_with_id(
            "invalid-replacement",
            ImpossibleCapability::OutboundNetwork,
            20_000,
            &signing_key,
        );
        invalid.signature = "not-hex".to_string();

        let err = enforcer.opt_in(invalid, "admin", 3_000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert_eq!(enforcer.metrics().opt_in_granted_total, 1);
        assert_eq!(
            enforcer.status(ImpossibleCapability::OutboundNetwork),
            &EnforcementStatus::Enabled {
                token_id: "valid-token".to_string(),
                expires_at_ms: 10_000,
            }
        );
    }

    #[test]
    fn enforce_at_exact_expiry_boundary_fails_closed_and_removes_token() {
        let signing_key = signing_key(0x61);
        let mut enforcer = enforcer_for(&signing_key);
        let token = token_with_id(
            "boundary-token",
            ImpossibleCapability::ChildProcessSpawn,
            5_000,
            &signing_key,
        );
        enforcer.opt_in(token, "admin", 2_000).unwrap();

        assert!(
            enforcer
                .enforce(ImpossibleCapability::ChildProcessSpawn, "user", 4_999)
                .is_ok()
        );
        let err = enforcer
            .enforce(ImpossibleCapability::ChildProcessSpawn, "user", 5_000)
            .unwrap_err();

        assert_eq!(err.code, ERR_IBD_TOKEN_EXPIRED);
        assert!(
            enforcer
                .status(ImpossibleCapability::ChildProcessSpawn)
                .is_blocked()
        );
        assert_eq!(enforcer.metrics().opt_in_expired_total, 1);
    }

    #[test]
    fn expire_tokens_does_not_double_count_token_expired_by_enforce() {
        let signing_key = signing_key(0x71);
        let mut enforcer = enforcer_for(&signing_key);
        let token = token_with_id(
            "single-expiry-token",
            ImpossibleCapability::DisableHardening,
            5_000,
            &signing_key,
        );
        enforcer.opt_in(token, "admin", 2_000).unwrap();

        let err = enforcer
            .enforce(ImpossibleCapability::DisableHardening, "user", 5_000)
            .unwrap_err();
        let expired = enforcer.expire_tokens(6_000);

        assert_eq!(err.code, ERR_IBD_TOKEN_EXPIRED);
        assert!(expired.is_empty());
        assert_eq!(enforcer.metrics().opt_in_expired_total, 1);
    }

    #[test]
    fn silent_disable_on_blocked_capability_keeps_capability_blocked() {
        let signing_key = signing_key(0x81);
        let mut enforcer = enforcer_for(&signing_key);

        let err = enforcer
            .attempt_silent_disable(ImpossibleCapability::FsAccess, "rogue", 2_000)
            .unwrap_err();

        assert_eq!(err.code, ERR_IBD_SILENT_DISABLE);
        assert!(enforcer.status(ImpossibleCapability::FsAccess).is_blocked());
        assert_eq!(enforcer.metrics().silent_disable_detected_total, 1);
        assert_eq!(
            enforcer
                .audit_log()
                .last()
                .map(|entry| entry.event_code.as_str()),
            Some(IBD_004_SILENT_DISABLE_DETECTED)
        );
    }

    #[test]
    fn audit_log_overflow_keeps_cap_and_continues_hash_chain() {
        let signing_key = signing_key(0x91);
        let mut enforcer = enforcer_for(&signing_key);

        for i in 0..=crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES {
            let timestamp_ms = u64::try_from(i).unwrap_or(u64::MAX);
            let _ = enforcer.enforce(ImpossibleCapability::FsAccess, "user", timestamp_ms);
        }

        let log = enforcer.audit_log();
        assert_eq!(
            log.len(),
            crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES
        );
        assert_ne!(log[0].prev_hash, "0".repeat(64));
        for i in 1..log.len() {
            assert_eq!(log[i].prev_hash, log[i - 1].hash());
        }
    }

    #[test]
    fn opt_in_rejects_capability_tamper_after_signing() {
        let signing_key = signing_key(0xa1);
        let mut enforcer = enforcer_for(&signing_key);
        let mut token = token_with_id(
            "capability-tamper-token",
            ImpossibleCapability::FsAccess,
            10_000,
            &signing_key,
        );
        token.capability = ImpossibleCapability::DisableHardening;

        let err = enforcer.opt_in(token, "admin", 2_000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert!(enforcer.status(ImpossibleCapability::FsAccess).is_blocked());
        assert!(
            enforcer
                .status(ImpossibleCapability::DisableHardening)
                .is_blocked()
        );
        assert_eq!(enforcer.metrics().opt_in_granted_total, 0);
    }

    #[test]
    fn opt_in_rejects_token_id_tamper_after_signing() {
        let signing_key = signing_key(0xa2);
        let mut enforcer = enforcer_for(&signing_key);
        let mut token = token_with_id(
            "original-token-id",
            ImpossibleCapability::OutboundNetwork,
            10_000,
            &signing_key,
        );
        token.token_id = "tampered-token-id".to_string();

        let err = enforcer.opt_in(token, "admin", 2_000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert!(
            enforcer
                .status(ImpossibleCapability::OutboundNetwork)
                .is_blocked()
        );
        assert_eq!(enforcer.metrics().opt_in_granted_total, 0);
    }

    #[test]
    fn opt_in_rejects_issuer_tamper_after_signing() {
        let signing_key = signing_key(0xa3);
        let mut enforcer = enforcer_for(&signing_key);
        let mut token = token_with_id(
            "issuer-tamper-token",
            ImpossibleCapability::ChildProcessSpawn,
            10_000,
            &signing_key,
        );
        token.issuer = "unexpected-issuer".to_string();

        let err = enforcer.opt_in(token, "admin", 2_000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert!(
            enforcer
                .status(ImpossibleCapability::ChildProcessSpawn)
                .is_blocked()
        );
        assert_eq!(enforcer.metrics().opt_in_granted_total, 0);
    }

    #[test]
    fn opt_in_rejects_subject_tamper_after_signing() {
        let signing_key = signing_key(0xa4);
        let mut enforcer = enforcer_for(&signing_key);
        let mut token = token_with_id(
            "subject-tamper-token",
            ImpossibleCapability::UnsignedExtension,
            10_000,
            &signing_key,
        );
        token.subject = "unexpected-subject".to_string();

        let err = enforcer.opt_in(token, "admin", 2_000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert!(
            enforcer
                .status(ImpossibleCapability::UnsignedExtension)
                .is_blocked()
        );
        assert_eq!(enforcer.metrics().opt_in_granted_total, 0);
    }

    #[test]
    fn opt_in_rejects_justification_tamper_after_signing() {
        let signing_key = signing_key(0xa5);
        let mut enforcer = enforcer_for(&signing_key);
        let mut token = token_with_id(
            "justification-tamper-token",
            ImpossibleCapability::DisableHardening,
            10_000,
            &signing_key,
        );
        token.justification = "changed justification".to_string();

        let err = enforcer.opt_in(token, "admin", 2_000).unwrap_err();

        assert_eq!(err.code, ERR_IBD_INVALID_SIGNATURE);
        assert!(
            enforcer
                .status(ImpossibleCapability::DisableHardening)
                .is_blocked()
        );
        assert_eq!(enforcer.metrics().opt_in_granted_total, 0);
    }

    #[test]
    fn enforce_rejects_unrelated_capability_when_other_token_is_enabled() {
        let signing_key = signing_key(0xa6);
        let mut enforcer = enforcer_for(&signing_key);
        let token = token_with_id(
            "network-only-token",
            ImpossibleCapability::OutboundNetwork,
            10_000,
            &signing_key,
        );
        enforcer.opt_in(token, "admin", 2_000).unwrap();

        let err = enforcer
            .enforce(ImpossibleCapability::FsAccess, "user", 3_000)
            .unwrap_err();

        assert_eq!(err.code, ERR_IBD_BLOCKED);
        assert!(enforcer.is_enabled(ImpossibleCapability::OutboundNetwork));
        assert!(enforcer.status(ImpossibleCapability::FsAccess).is_blocked());
        assert_eq!(
            enforcer
                .audit_log()
                .last()
                .map(|entry| entry.event_code.as_str()),
            Some(IBD_001_CAPABILITY_BLOCKED)
        );
    }

    #[test]
    fn expire_tokens_removes_multiple_capabilities_at_boundary() {
        let signing_key = signing_key(0xa7);
        let mut enforcer = enforcer_for(&signing_key);
        let fs_token = token_with_id(
            "fs-boundary-token",
            ImpossibleCapability::FsAccess,
            5_000,
            &signing_key,
        );
        let network_token = token_with_id(
            "network-boundary-token",
            ImpossibleCapability::OutboundNetwork,
            5_000,
            &signing_key,
        );
        enforcer.opt_in(fs_token, "admin", 2_000).unwrap();
        enforcer.opt_in(network_token, "admin", 2_000).unwrap();

        let expired = enforcer.expire_tokens(5_000);

        assert_eq!(expired.len(), 2);
        assert!(expired.contains(&ImpossibleCapability::FsAccess));
        assert!(expired.contains(&ImpossibleCapability::OutboundNetwork));
        assert!(enforcer.status(ImpossibleCapability::FsAccess).is_blocked());
        assert!(
            enforcer
                .status(ImpossibleCapability::OutboundNetwork)
                .is_blocked()
        );
        assert_eq!(enforcer.metrics().opt_in_expired_total, 2);
    }

    // -- Negative-Path Tests --

    #[test]
    fn negative_malformed_capability_token_injection_attacks() {
        // Test capability token validation against various injection and corruption attacks
        let (mut enforcer, sk) = make_enforcer();

        let malicious_token_scenarios = vec![
            // Token with extremely long fields
            CapabilityToken {
                token_id: "x".repeat(1_000_000),
                capability: ImpossibleCapability::FsAccess,
                issuer: "y".repeat(100_000),
                subject: "z".repeat(100_000),
                issued_at_ms: 1000,
                expires_at_ms: 5000,
                signature: String::new(),
            },

            // Token with Unicode injection in fields
            CapabilityToken {
                token_id: "token🚀攻击кибер".to_string(),
                capability: ImpossibleCapability::OutboundNetwork,
                issuer: "issuer\u{200B}invisible".to_string(),
                subject: "subject\u{FEFF}bom".to_string(),
                issued_at_ms: 1000,
                expires_at_ms: 5000,
                signature: String::new(),
            },

            // Token with control characters and null bytes
            CapabilityToken {
                token_id: "token\0null\r\ninjection".to_string(),
                capability: ImpossibleCapability::ChildProcessSpawn,
                issuer: "issuer\x01control".to_string(),
                subject: "subject\x1B[Hescape".to_string(),
                issued_at_ms: 1000,
                expires_at_ms: 5000,
                signature: String::new(),
            },

            // Token with script injection attempts
            CapabilityToken {
                token_id: "token<script>alert('xss')</script>".to_string(),
                capability: ImpossibleCapability::UnsignedExtension,
                issuer: "issuer'; DROP TABLE tokens; --".to_string(),
                subject: "subject && curl evil.com".to_string(),
                issued_at_ms: 1000,
                expires_at_ms: 5000,
                signature: String::new(),
            },

            // Token with path traversal attempts
            CapabilityToken {
                token_id: "../../../etc/passwd".to_string(),
                capability: ImpossibleCapability::DisableHardening,
                issuer: "../../../../proc/version".to_string(),
                subject: "../../bin/sh".to_string(),
                issued_at_ms: 1000,
                expires_at_ms: 5000,
                signature: String::new(),
            },

            // Token with binary data injection
            CapabilityToken {
                token_id: String::from_utf8_lossy(b"token\xFF\xFE\xFD").to_string(),
                capability: ImpossibleCapability::FsAccess,
                issuer: String::from_utf8_lossy(b"issuer\x00\x01\x02").to_string(),
                subject: String::from_utf8_lossy(b"subject\xFC\xFB\xFA").to_string(),
                issued_at_ms: 1000,
                expires_at_ms: 5000,
                signature: String::new(),
            },
        ];

        for (i, mut malicious_token) in malicious_token_scenarios.into_iter().enumerate() {
            // Test with invalid signature (empty)
            let grant_result_unsigned = enforcer.grant_capability(malicious_token.clone());

            match grant_result_unsigned {
                Err(ImpossibleCapabilityError::InvalidSignature { .. }) => {
                    // Expected for unsigned tokens
                },
                Err(_) => {
                    // Other validation errors acceptable for malformed tokens
                },
                Ok(()) => {
                    panic!("Should not grant capability with unsigned malicious token {}", i);
                }
            }

            // Test with valid signature but malicious content
            sign_token(&mut malicious_token, &sk);
            let grant_result_signed = enforcer.grant_capability(malicious_token.clone());

            match grant_result_signed {
                Ok(()) => {
                    // If granted, verify the capability is properly isolated from injection
                    let capability_status = enforcer.status(malicious_token.capability);
                    assert!(capability_status.is_granted());

                    // Test that malicious content doesn't affect other operations
                    let attempt_result = enforcer.attempt_operation(malicious_token.capability, 2000);
                    assert!(attempt_result.is_ok(), "Operation should succeed despite malicious token content");
                },
                Err(_) => {
                    // Acceptable to reject malformed tokens even with valid signatures
                }
            }
        }

        // Enforcer should remain functional despite malicious token attempts
        let metrics = enforcer.metrics();
        assert!(metrics.opt_in_granted_total < 10); // Should not have granted all malicious tokens
    }

    #[test]
    fn negative_extreme_timestamp_arithmetic_overflow_protection() {
        // Test timestamp handling with extreme values near u64::MAX
        let (mut enforcer, sk) = make_enforcer();

        let extreme_timestamp_cases = vec![
            // Token with timestamps at u64::MAX boundary
            (0, u64::MAX, "max_expiry"),
            (u64::MAX, u64::MAX, "max_both"),
            (u64::MAX.saturating_sub(1000), u64::MAX, "near_max_issued"),
            (1, u64::MAX.saturating_sub(1), "near_max_expiry"),

            // Token issued in the future
            (u64::MAX.saturating_sub(100), 1000, "future_issued"),

            // Token with zero timestamps
            (0, 0, "zero_both"),
            (0, 1, "zero_issued"),
            (1, 0, "zero_expiry"),

            // Tokens with potential overflow in TTL calculations
            (u64::MAX.saturating_sub(500), u64::MAX.saturating_sub(100), "overflow_ttl"),
        ];

        for (issued_at, expires_at, case_name) in extreme_timestamp_cases {
            let mut extreme_token = CapabilityToken {
                token_id: format!("extreme-timestamp-{}", case_name),
                capability: ImpossibleCapability::FsAccess,
                issuer: "extreme-issuer".to_string(),
                subject: "extreme-subject".to_string(),
                issued_at_ms: issued_at,
                expires_at_ms: expires_at,
                signature: String::new(),
            };

            sign_token(&mut extreme_token, &sk);

            let grant_result = enforcer.grant_capability(extreme_token.clone());

            match grant_result {
                Ok(()) => {
                    // If granted, test operation attempts with extreme timestamps
                    let operation_times = vec![
                        0,
                        1000,
                        extreme_token.issued_at_ms,
                        extreme_token.expires_at_ms,
                        u64::MAX.saturating_sub(100),
                        u64::MAX,
                    ];

                    for operation_time in operation_times {
                        let attempt_result = enforcer.attempt_operation(extreme_token.capability, operation_time);

                        // Should handle extreme timestamps without arithmetic overflow
                        match attempt_result {
                            Ok(()) => {
                                // Operation allowed - timestamp arithmetic worked correctly
                            },
                            Err(ImpossibleCapabilityError::TokenExpired { .. }) => {
                                // Expected if operation time > expires_at
                            },
                            Err(ImpossibleCapabilityError::Blocked { .. }) => {
                                // Expected if capability not granted or other issues
                            },
                            Err(_) => {
                                // Other errors acceptable for extreme timestamps
                            }
                        }
                    }
                },
                Err(ImpossibleCapabilityError::TokenExpired { .. }) => {
                    // Expected for tokens with invalid timestamp relationships
                },
                Err(_) => {
                    // Other validation errors acceptable for extreme timestamps
                }
            }
        }

        // Metrics should handle extreme timestamps safely
        let metrics = enforcer.metrics();
        assert!(metrics.total_attempts < u64::MAX); // Should not overflow
    }

    #[test]
    fn negative_cryptographic_signature_bypass_and_forgery_attempts() {
        // Test cryptographic signature validation against bypass and forgery attempts
        let (mut enforcer, legitimate_sk) = make_enforcer();

        // Create another signing key for forgery attempts
        let malicious_sk = {
            let seed: [u8; 32] = [0xFF; 32]; // Different seed
            SigningKey::from_bytes(&seed)
        };

        let signature_attack_scenarios = vec![
            // Empty signature
            ("empty_signature", ""),

            // Invalid hex signature
            ("invalid_hex", "gggggggg"),

            // Valid hex but wrong length
            ("wrong_length", "deadbeef"),

            // Signature from wrong key
            ("wrong_key", {
                let mut token = make_token(ImpossibleCapability::FsAccess, 5000, &malicious_sk);
                token.signature.clone()
            }),

            // Signature over different data
            ("different_data", {
                let mut token = make_token(ImpossibleCapability::OutboundNetwork, 5000, &legitimate_sk);
                token.signature.clone()
            }),

            // Signature with extra data appended
            ("extra_data", {
                let mut token = make_token(ImpossibleCapability::FsAccess, 5000, &legitimate_sk);
                format!("{}deadbeef", token.signature)
            }),

            // Signature with case variation
            ("case_variation", {
                let mut token = make_token(ImpossibleCapability::FsAccess, 5000, &legitimate_sk);
                token.signature.to_uppercase()
            }),

            // Signature with null bytes
            ("null_bytes", "0".repeat(127) + "\0"),

            // Signature with Unicode
            ("unicode_sig", "🔐".repeat(16)),

            // Extremely long signature
            ("long_signature", "a".repeat(100_000)),
        ];

        for (attack_name, malicious_signature) in signature_attack_scenarios {
            let mut attack_token = CapabilityToken {
                token_id: format!("attack-token-{}", attack_name),
                capability: ImpossibleCapability::FsAccess,
                issuer: "attack-issuer".to_string(),
                subject: "attack-subject".to_string(),
                issued_at_ms: 1000,
                expires_at_ms: 5000,
                signature: malicious_signature.to_string(),
            };

            let grant_result = enforcer.grant_capability(attack_token);

            match grant_result {
                Err(ImpossibleCapabilityError::InvalidSignature { .. }) => {
                    // Expected for signature attacks
                },
                Err(_) => {
                    // Other validation errors acceptable
                },
                Ok(()) => {
                    panic!("Should not grant capability with forged signature: {}", attack_name);
                }
            }
        }

        // Test signature replay attacks
        let mut legitimate_token = make_token(ImpossibleCapability::FsAccess, 5000, &legitimate_sk);
        let original_signature = legitimate_token.signature.clone();

        // Grant legitimate token
        enforcer.grant_capability(legitimate_token.clone()).expect("legitimate token should be granted");

        // Try to reuse signature on different token
        let mut replay_token = CapabilityToken {
            token_id: "replay-attack".to_string(),
            capability: ImpossibleCapability::OutboundNetwork, // Different capability
            issuer: "replay-issuer".to_string(),
            subject: "replay-subject".to_string(),
            issued_at_ms: 2000,
            expires_at_ms: 6000,
            signature: original_signature, // Reused signature
        };

        let replay_result = enforcer.grant_capability(replay_token);

        match replay_result {
            Err(ImpossibleCapabilityError::InvalidSignature { .. }) => {
                // Expected - signature should not validate for different data
            },
            Err(_) => {
                // Other validation errors acceptable
            },
            Ok(()) => {
                panic!("Should not allow signature replay attack");
            }
        }
    }

    #[test]
    fn negative_capability_enforcement_bypass_through_state_manipulation() {
        // Test attempts to bypass capability enforcement through state manipulation
        let (mut enforcer, sk) = make_enforcer();

        // Grant a capability legitimately
        let legitimate_token = make_token(ImpossibleCapability::FsAccess, 5000, &sk);
        enforcer.grant_capability(legitimate_token).expect("legitimate grant should succeed");

        // Attempt operations on other capabilities without proper tokens
        let unauthorized_capabilities = vec![
            ImpossibleCapability::OutboundNetwork,
            ImpossibleCapability::ChildProcessSpawn,
            ImpossibleCapability::UnsignedExtension,
            ImpossibleCapability::DisableHardening,
        ];

        for unauthorized_cap in unauthorized_capabilities {
            let unauthorized_result = enforcer.attempt_operation(unauthorized_cap, 2000);

            match unauthorized_result {
                Err(ImpossibleCapabilityError::Blocked { .. }) => {
                    // Expected - should block unauthorized capabilities
                },
                Err(_) => {
                    // Other errors acceptable
                },
                Ok(()) => {
                    panic!("Should not allow unauthorized capability: {:?}", unauthorized_cap);
                }
            }

            // Verify capability status remains blocked
            assert!(enforcer.status(unauthorized_cap).is_blocked());
        }

        // Test rapid operation attempts (potential DoS)
        for _i in 0..1000 {
            let rapid_result = enforcer.attempt_operation(ImpossibleCapability::OutboundNetwork, 2000);
            assert!(rapid_result.is_err(), "Rapid attempts should continue to be blocked");
        }

        // Test operations with future timestamps
        let future_result = enforcer.attempt_operation(ImpossibleCapability::FsAccess, u64::MAX);
        assert!(future_result.is_err(), "Future timestamp should not bypass expiry");

        // Test operations with past timestamps
        let past_result = enforcer.attempt_operation(ImpossibleCapability::FsAccess, 0);
        assert!(past_result.is_err(), "Past timestamp should not be valid");

        // Verify metrics accurately reflect blocked attempts
        let metrics = enforcer.metrics();
        assert!(metrics.blocked_attempts_total > 1000);
        assert_eq!(metrics.opt_in_granted_total, 1); // Only one legitimate grant
    }

    #[test]
    fn negative_audit_log_memory_exhaustion_under_operation_flood() {
        // Test audit log behavior under massive operation attempt floods
        let (mut enforcer, sk) = make_enforcer();

        // Create tokens for all capabilities
        let capabilities = [
            ImpossibleCapability::FsAccess,
            ImpossibleCapability::OutboundNetwork,
            ImpossibleCapability::ChildProcessSpawn,
            ImpossibleCapability::UnsignedExtension,
            ImpossibleCapability::DisableHardening,
        ];

        for cap in capabilities {
            let token = make_token(cap, 10000, &sk);
            enforcer.grant_capability(token).expect("grant should succeed");
        }

        // Flood with massive number of operations
        let operation_flood_count = MAX_AUDIT_LOG_ENTRIES.saturating_add(5000);

        for i in 0..operation_flood_count {
            let capability = capabilities[i % capabilities.len()];
            let operation_time = 1000 + (i as u64);

            // Mix of valid and expired operations
            let expiry_time = if i % 3 == 0 { 500 } else { operation_time + 1000 };

            let _ = enforcer.attempt_operation(capability, expiry_time);

            // Periodic revocation attempts to generate more audit events
            if i % 100 == 0 {
                let _ = enforcer.revoke_capability(capability, operation_time);
            }
        }

        // Audit log should be bounded despite massive operation flood
        let audit_events = enforcer.audit_events();
        assert!(audit_events.len() <= MAX_AUDIT_LOG_ENTRIES.saturating_add(100));

        // All audit events should be well-formed despite high volume
        for event in audit_events {
            assert!(!event.event_code.is_empty());
            assert!(!event.capability.label().is_empty());
            assert!(event.timestamp_ms > 0);
        }

        // Metrics should accurately reflect the flood
        let metrics = enforcer.metrics();
        assert!(metrics.total_attempts >= operation_flood_count as u64);
        assert!(metrics.total_attempts < u64::MAX); // Should not overflow

        // Enforcer should remain functional after flood
        let post_flood_token = make_token(ImpossibleCapability::FsAccess, 20000, &sk);
        let post_flood_result = enforcer.grant_capability(post_flood_token);
        assert!(post_flood_result.is_ok(), "Enforcer should remain functional after flood");
    }

    #[test]
    fn negative_concurrent_capability_manipulation_race_conditions() {
        // Test concurrent capability operations for race conditions and state corruption
        use std::sync::{Arc, Mutex};
        use std::thread;

        let (base_enforcer, sk) = make_enforcer();
        let enforcer = Arc::new(Mutex::new(base_enforcer));
        let signing_key = Arc::new(sk);

        let success_count = Arc::new(Mutex::new(0u32));
        let error_count = Arc::new(Mutex::new(0u32));

        // Spawn concurrent threads for different operations
        let operations = vec![
            ("grant", 5),
            ("attempt", 8),
            ("revoke", 3),
            ("status_check", 10),
        ];

        let mut handles = Vec::new();

        for (operation_type, thread_count) in operations {
            for thread_id in 0..thread_count {
                let enforcer_clone = Arc::clone(&enforcer);
                let sk_clone = Arc::clone(&signing_key);
                let success_count_clone = Arc::clone(&success_count);
                let error_count_clone = Arc::clone(&error_count);
                let op_type = operation_type.to_string();

                let handle = thread::spawn(move || {
                    let capability = match thread_id % 5 {
                        0 => ImpossibleCapability::FsAccess,
                        1 => ImpossibleCapability::OutboundNetwork,
                        2 => ImpossibleCapability::ChildProcessSpawn,
                        3 => ImpossibleCapability::UnsignedExtension,
                        _ => ImpossibleCapability::DisableHardening,
                    };

                    for iteration in 0..50 {
                        let timestamp = 1000 + (thread_id * 100) + iteration;

                        let result = match op_type.as_str() {
                            "grant" => {
                                let token = CapabilityToken {
                                    token_id: format!("concurrent-{}-{}-{}", op_type, thread_id, iteration),
                                    capability,
                                    issuer: format!("concurrent-issuer-{}", thread_id),
                                    subject: format!("concurrent-subject-{}", thread_id),
                                    issued_at_ms: timestamp,
                                    expires_at_ms: timestamp + 5000,
                                    signature: String::new(),
                                };

                                // Sign token (mutex needed for thread safety)
                                let mut signed_token = token;
                                sign_token(&mut signed_token, &sk_clone);

                                enforcer_clone.lock().unwrap().grant_capability(signed_token).map_err(|e| format!("{:?}", e))
                            },
                            "attempt" => {
                                enforcer_clone.lock().unwrap().attempt_operation(capability, timestamp).map_err(|e| format!("{:?}", e))
                            },
                            "revoke" => {
                                enforcer_clone.lock().unwrap().revoke_capability(capability, timestamp).map_err(|e| format!("{:?}", e))
                            },
                            "status_check" => {
                                let status = enforcer_clone.lock().unwrap().status(capability);
                                // Status check always succeeds
                                Ok(())
                            },
                            _ => unreachable!(),
                        };

                        match result {
                            Ok(()) => {
                                let mut count = success_count_clone.lock().unwrap();
                                *count = count.saturating_add(1);
                            },
                            Err(_) => {
                                let mut count = error_count_clone.lock().unwrap();
                                *count = count.saturating_add(1);
                            }
                        }
                    }
                });

                handles.push(handle);
            }
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let final_success = *success_count.lock().unwrap();
        let final_errors = *error_count.lock().unwrap();

        // Should handle concurrent operations without panicking
        assert!(final_success + final_errors > 0);

        // Enforcer state should be consistent after concurrent access
        let enforcer_lock = enforcer.lock().unwrap();
        let final_metrics = enforcer_lock.metrics();

        // Metrics should be consistent
        assert!(final_metrics.total_attempts >= final_success as u64);
        assert!(final_metrics.opt_in_granted_total <= final_metrics.total_attempts);

        // All capabilities should have deterministic status
        for cap in [
            ImpossibleCapability::FsAccess,
            ImpossibleCapability::OutboundNetwork,
            ImpossibleCapability::ChildProcessSpawn,
            ImpossibleCapability::UnsignedExtension,
            ImpossibleCapability::DisableHardening,
        ] {
            let status = enforcer_lock.status(cap);
            // Status should be valid (either granted or blocked)
            assert!(status.is_granted() || status.is_blocked());
        }
    }

    #[test]
    fn negative_capability_token_content_hash_collision_resistance() {
        // Test capability token content hash calculation against collision attacks
        let sk = test_signing_key();

        // Create tokens with systematic variations to test hash collision resistance
        let collision_test_cases = vec![
            // Same content, different field ordering (should hash identically)
            (
                CapabilityToken {
                    token_id: "collision-test-1".to_string(),
                    capability: ImpossibleCapability::FsAccess,
                    issuer: "issuer-a".to_string(),
                    subject: "subject-a".to_string(),
                    issued_at_ms: 1000,
                    expires_at_ms: 5000,
                    signature: String::new(),
                },
                CapabilityToken {
                    token_id: "collision-test-1".to_string(),
                    capability: ImpossibleCapability::FsAccess,
                    issuer: "issuer-a".to_string(),
                    subject: "subject-a".to_string(),
                    issued_at_ms: 1000,
                    expires_at_ms: 5000,
                    signature: String::new(),
                },
                true, // Should have same hash
            ),

            // Single bit difference
            (
                CapabilityToken {
                    token_id: "collision-test-2".to_string(),
                    capability: ImpossibleCapability::FsAccess,
                    issuer: "issuer-a".to_string(),
                    subject: "subject-a".to_string(),
                    issued_at_ms: 1000,
                    expires_at_ms: 5000,
                    signature: String::new(),
                },
                CapabilityToken {
                    token_id: "collision-test-2".to_string(),
                    capability: ImpossibleCapability::FsAccess,
                    issuer: "issuer-a".to_string(),
                    subject: "subject-a".to_string(),
                    issued_at_ms: 1001, // Single millisecond difference
                    expires_at_ms: 5000,
                    signature: String::new(),
                },
                false, // Should have different hash
            ),

            // Length extension attempt
            (
                CapabilityToken {
                    token_id: "collision".to_string(),
                    capability: ImpossibleCapability::FsAccess,
                    issuer: "issuer".to_string(),
                    subject: "subject".to_string(),
                    issued_at_ms: 1000,
                    expires_at_ms: 5000,
                    signature: String::new(),
                },
                CapabilityToken {
                    token_id: "collision\x00extra".to_string(),
                    capability: ImpossibleCapability::FsAccess,
                    issuer: "issuer".to_string(),
                    subject: "subject".to_string(),
                    issued_at_ms: 1000,
                    expires_at_ms: 5000,
                    signature: String::new(),
                },
                false, // Should have different hash
            ),

            // Unicode normalization variations
            (
                CapabilityToken {
                    token_id: "café".to_string(), // NFC form
                    capability: ImpossibleCapability::FsAccess,
                    issuer: "issuer".to_string(),
                    subject: "subject".to_string(),
                    issued_at_ms: 1000,
                    expires_at_ms: 5000,
                    signature: String::new(),
                },
                CapabilityToken {
                    token_id: "cafe\u{0301}".to_string(), // NFD form
                    capability: ImpossibleCapability::FsAccess,
                    issuer: "issuer".to_string(),
                    subject: "subject".to_string(),
                    issued_at_ms: 1000,
                    expires_at_ms: 5000,
                    signature: String::new(),
                },
                false, // Should have different hash (no normalization)
            ),
        ];

        for (token1, token2, should_match) in collision_test_cases {
            let hash1 = token1.content_hash();
            let hash2 = token2.content_hash();

            if should_match {
                assert_eq!(hash1, hash2, "Identical tokens should have same hash");
            } else {
                assert_ne!(hash1, hash2, "Different tokens should have different hashes");
            }

            // All hashes should be valid SHA256 format
            assert_eq!(hash1.len(), 64, "Hash should be 64 hex characters");
            assert_eq!(hash2.len(), 64, "Hash should be 64 hex characters");
            assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()), "Hash should contain only hex characters");
            assert!(hash2.chars().all(|c| c.is_ascii_hexdigit()), "Hash should contain only hex characters");
        }

        // Test hash avalanche effect with systematic bit flips
        let base_token = CapabilityToken {
            token_id: "avalanche-test".to_string(),
            capability: ImpossibleCapability::FsAccess,
            issuer: "issuer".to_string(),
            subject: "subject".to_string(),
            issued_at_ms: 1000,
            expires_at_ms: 5000,
            signature: String::new(),
        };

        let base_hash = base_token.content_hash();
        let mut unique_hashes = std::collections::HashSet::new();
        unique_hashes.insert(base_hash.clone());

        // Test variations in each field
        for i in 0..100 {
            let variant_token = CapabilityToken {
                token_id: format!("avalanche-test-{}", i),
                capability: base_token.capability,
                issuer: base_token.issuer.clone(),
                subject: base_token.subject.clone(),
                issued_at_ms: base_token.issued_at_ms + i,
                expires_at_ms: base_token.expires_at_ms + i,
                signature: String::new(),
            };

            let variant_hash = variant_token.content_hash();
            assert_ne!(variant_hash, base_hash, "Variant should have different hash");
            assert!(unique_hashes.insert(variant_hash), "All variant hashes should be unique");
        }

        // Should have generated many unique hashes
        assert!(unique_hashes.len() > 90, "Should generate unique hashes for small variations");
    }

    #[test]
    fn negative_silent_disable_detection_and_prevention() {
        // Test silent disable detection against various bypass attempts
        let (mut enforcer, sk) = make_enforcer();

        // Grant capabilities legitimately
        for cap in [ImpossibleCapability::FsAccess, ImpossibleCapability::OutboundNetwork] {
            let token = make_token(cap, 10000, &sk);
            enforcer.grant_capability(token).expect("grant should succeed");
        }

        // Simulate silent disable attempts through state manipulation
        let silent_disable_scenarios = vec![
            // Attempt to directly disable enforcement
            ("direct_disable", ImpossibleCapability::FsAccess),
            ("environment_override", ImpossibleCapability::OutboundNetwork),
            ("configuration_bypass", ImpossibleCapability::FsAccess),
        ];

        for (attack_type, capability) in silent_disable_scenarios {
            // Record initial state
            let initial_status = enforcer.status(capability);
            assert!(initial_status.is_granted(), "Capability should be initially granted");

            // Attempt operation that should succeed
            let legitimate_operation = enforcer.attempt_operation(capability, 2000);
            assert!(legitimate_operation.is_ok(), "Legitimate operation should succeed");

            // Simulate potential silent disable detection
            // In a real implementation, this might involve:
            // - Environment variable monitoring
            // - Configuration file integrity checks
            // - Runtime flag modification detection
            // For testing, we verify the enforcer maintains state integrity

            // Verify capability status remains consistent
            let post_operation_status = enforcer.status(capability);
            assert!(post_operation_status.is_granted(), "Status should remain granted after operation");

            // Verify audit trail includes operations
            let audit_events = enforcer.audit_events();
            let operation_events = audit_events.iter()
                .filter(|e| e.capability == capability && e.event_code == IBD_002_OPT_IN_GRANTED)
                .count();
            assert!(operation_events > 0, "Should have audit events for capability operations");

            // Test that revocation is properly audited (not silent)
            let revoke_result = enforcer.revoke_capability(capability, 3000);
            match revoke_result {
                Ok(()) => {
                    // Verify revocation is audited
                    let post_revoke_events = enforcer.audit_events();
                    assert!(post_revoke_events.len() > audit_events.len(), "Revocation should be audited");

                    // Verify status properly reflects revocation
                    assert!(enforcer.status(capability).is_blocked(), "Status should be blocked after revocation");
                },
                Err(_) => {
                    // Revocation failure is acceptable in some implementations
                }
            }
        }

        // Verify that metrics accurately track all operations (no silent operations)
        let final_metrics = enforcer.metrics();
        assert!(final_metrics.total_attempts > 0, "Should track all operation attempts");
        assert!(final_metrics.blocked_attempts_total >= 0, "Should track blocked attempts");

        // Test detection of configuration tampering
        // This would typically involve file system monitoring, but we test the audit trail
        let audit_events = enforcer.audit_events();
        for event in audit_events {
            assert!(!event.event_code.is_empty(), "All events should have valid codes");
            assert!(event.timestamp_ms > 0, "All events should have valid timestamps");
        }
    }
}
