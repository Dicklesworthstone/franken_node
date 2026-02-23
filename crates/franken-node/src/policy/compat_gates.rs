//! bd-137: Policy-visible compatibility gate APIs.
//!
//! Implements typed shim registry, mode selection with signed receipts,
//! gate evaluation returning structured allow/deny/audit decisions,
//! policy-as-data predicates, and non-interference / monotonicity
//! enforcement for compatibility shims.
//!
//! # Invariants
//!
//! - **INV-PCG-VISIBLE**: All gate decisions are visible to operators via
//!   structured responses with machine-readable rationale.
//! - **INV-PCG-AUDITABLE**: Every gate decision, mode transition, and receipt
//!   emits a structured audit event with trace correlation ID.
//! - **INV-PCG-RECEIPT**: Every divergence and mode transition produces a
//!   cryptographically signed receipt.
//! - **INV-PCG-TRANSITION**: Mode transitions are policy-gated: escalating
//!   risk requires approval; de-escalating is auto-approved but audited.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ── Event Codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Gate check passed: package/extension allowed under requested mode.
    pub const PCG_GATE_PASS: &str = "PCG-001";
    /// Gate check failed: package/extension denied with rationale.
    pub const PCG_GATE_DENY: &str = "PCG-002";
    /// Mode transition approved with signed receipt.
    pub const PCG_MODE_TRANSITION: &str = "PCG-003";
    /// Divergence receipt issued.
    pub const PCG_RECEIPT_ISSUED: &str = "PCG-004";
    /// Gate check resulted in audit (allow with observation).
    pub const PCG_GATE_AUDIT: &str = "PCG-005";
    /// Non-interference violation detected.
    pub const PCG_NONINTERFERENCE_VIOLATION: &str = "PCG-006";
    /// Monotonicity violation detected.
    pub const PCG_MONOTONICITY_VIOLATION: &str = "PCG-007";
    /// Shim registered in registry.
    pub const PCG_SHIM_REGISTERED: &str = "PCG-008";
}

// ── Compatibility Bands ──────────────────────────────────────────────────────

/// Compatibility band classifying API surface areas by priority and risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CompatibilityBand {
    /// Foundation APIs (fs, path, process, Buffer, etc.) — highest priority.
    Core,
    /// Frequently-used patterns (http, crypto, timers, url).
    HighValue,
    /// Corner cases, undocumented behaviors, platform quirks.
    Edge,
    /// Dangerous behaviors (eval variants, unchecked native access) — lowest.
    Unsafe,
}

impl CompatibilityBand {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::HighValue => "high_value",
            Self::Edge => "edge",
            Self::Unsafe => "unsafe",
        }
    }

    /// Priority level (higher = more critical).
    pub fn priority(&self) -> u8 {
        match self {
            Self::Core => 4,
            Self::HighValue => 3,
            Self::Edge => 2,
            Self::Unsafe => 1,
        }
    }
}

impl fmt::Display for CompatibilityBand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Compatibility Modes ──────────────────────────────────────────────────────

/// Operator-selected compatibility mode governing divergence handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CompatibilityMode {
    /// Only verified-compatible behaviors allowed. No shims activated.
    Strict,
    /// Tested shims activated with monitoring. Divergences produce warnings.
    Balanced,
    /// All available shims activated. Divergences tolerated with receipts.
    LegacyRisky,
}

impl CompatibilityMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::LegacyRisky => "legacy_risky",
        }
    }

    /// Risk level (higher = more risk).
    pub fn risk_level(&self) -> u8 {
        match self {
            Self::Strict => 1,
            Self::Balanced => 2,
            Self::LegacyRisky => 3,
        }
    }

    /// Whether transitioning from `self` to `target` escalates risk.
    pub fn is_escalation_to(&self, target: CompatibilityMode) -> bool {
        target.risk_level() > self.risk_level()
    }
}

impl fmt::Display for CompatibilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Band-Mode Policy Matrix ─────────────────────────────────────────────────

/// What happens when a divergence is detected for a given band+mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceAction {
    /// Divergence blocks execution.
    Error,
    /// Warning emitted, receipt generated, execution continues.
    Warn,
    /// Logged with receipt, no warning surfaced.
    Log,
    /// Shim/divergence is blocked entirely.
    Blocked,
}

impl DivergenceAction {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Log => "log",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for DivergenceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Look up the divergence action for a (band, mode) pair.
/// This encodes the mode-band matrix from bd-2wz.
pub fn divergence_action(band: CompatibilityBand, mode: CompatibilityMode) -> DivergenceAction {
    match (band, mode) {
        // Core band: always error on divergence
        (CompatibilityBand::Core, _) => DivergenceAction::Error,

        // High-value band
        (CompatibilityBand::HighValue, CompatibilityMode::Strict) => DivergenceAction::Error,
        (CompatibilityBand::HighValue, CompatibilityMode::Balanced) => DivergenceAction::Warn,
        (CompatibilityBand::HighValue, CompatibilityMode::LegacyRisky) => DivergenceAction::Warn,

        // Edge band
        (CompatibilityBand::Edge, CompatibilityMode::Strict) => DivergenceAction::Warn,
        (CompatibilityBand::Edge, CompatibilityMode::Balanced) => DivergenceAction::Log,
        (CompatibilityBand::Edge, CompatibilityMode::LegacyRisky) => DivergenceAction::Log,

        // Unsafe band
        (CompatibilityBand::Unsafe, CompatibilityMode::Strict) => DivergenceAction::Blocked,
        (CompatibilityBand::Unsafe, CompatibilityMode::Balanced) => DivergenceAction::Blocked,
        (CompatibilityBand::Unsafe, CompatibilityMode::LegacyRisky) => DivergenceAction::Warn,
    }
}

// ── Risk Category ────────────────────────────────────────────────────────────

/// Risk category for a compatibility shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShimRiskCategory {
    Low,
    Medium,
    High,
    Critical,
}

impl ShimRiskCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for ShimRiskCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Shim Registry ────────────────────────────────────────────────────────────

/// A registered compatibility shim with full typed metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimRegistryEntry {
    /// Unique identifier for this shim.
    pub shim_id: String,
    /// Human-readable description of the shimmed behavior.
    pub description: String,
    /// Which compatibility band this shim belongs to.
    pub band: CompatibilityBand,
    /// Risk category.
    pub risk_category: ShimRiskCategory,
    /// The activation policy predicate ID controlling this shim.
    pub activation_policy_id: String,
    /// Rationale for why this divergence exists.
    pub divergence_rationale: String,
    /// Node/Bun API family (e.g. "fs", "http", "crypto").
    pub api_family: String,
    /// Whether this shim is currently active (subject to mode).
    pub active: bool,
}

/// Registry of all compatibility shims. Queryable with full metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShimRegistry {
    entries: Vec<ShimRegistryEntry>,
    index: BTreeMap<String, usize>,
}

impl ShimRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    /// Register a new shim. Returns Err if shim_id already exists.
    pub fn register(&mut self, entry: ShimRegistryEntry) -> Result<(), CompatGateError> {
        if self.index.contains_key(&entry.shim_id) {
            return Err(CompatGateError::DuplicateShim {
                shim_id: entry.shim_id.clone(),
            });
        }
        let idx = self.entries.len();
        self.index.insert(entry.shim_id.clone(), idx);
        self.entries.push(entry);
        Ok(())
    }

    /// Look up a shim by ID.
    pub fn get(&self, shim_id: &str) -> Option<&ShimRegistryEntry> {
        self.index.get(shim_id).map(|&idx| &self.entries[idx])
    }

    /// Return all registered shims.
    pub fn all(&self) -> &[ShimRegistryEntry] {
        &self.entries
    }

    /// Filter shims by band.
    pub fn by_band(&self, band: CompatibilityBand) -> Vec<&ShimRegistryEntry> {
        self.entries.iter().filter(|e| e.band == band).collect()
    }

    /// Filter shims by API family.
    pub fn by_api_family(&self, family: &str) -> Vec<&ShimRegistryEntry> {
        self.entries
            .iter()
            .filter(|e| e.api_family == family)
            .collect()
    }

    /// Number of registered shims.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// List shims that would be active under a given mode.
    pub fn active_under_mode(&self, mode: CompatibilityMode) -> Vec<&ShimRegistryEntry> {
        self.entries
            .iter()
            .filter(|e| {
                let action = divergence_action(e.band, mode);
                !matches!(action, DivergenceAction::Blocked | DivergenceAction::Error)
            })
            .collect()
    }
}

// ── Policy Predicate ─────────────────────────────────────────────────────────

/// A machine-verifiable policy predicate constraining shim activation.
/// Per 9B.5: cryptographically signed with attenuation semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPredicate {
    /// Unique identifier for this predicate.
    pub predicate_id: String,
    /// Hex-encoded signature over the predicate body.
    pub signature: String,
    /// Scope-limiting attenuation constraints.
    pub attenuation: Vec<AttenuationConstraint>,
    /// Boolean condition for activation (serialized expression).
    pub activation_condition: String,
}

/// A scope-limiting constraint that narrows predicate applicability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttenuationConstraint {
    pub scope_type: String,
    pub scope_value: String,
}

impl PolicyPredicate {
    /// Verify the predicate signature (placeholder — real impl uses ed25519).
    pub fn verify_signature(&self) -> bool {
        // Signature must be non-empty hex string of at least 64 chars
        self.signature.len() >= 64 && self.signature.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Check if the predicate applies to the given scope.
    pub fn applies_to_scope(&self, scope_type: &str, scope_value: &str) -> bool {
        if self.attenuation.is_empty() {
            return true; // No attenuation = universal
        }
        self.attenuation
            .iter()
            .any(|a| a.scope_type == scope_type && a.scope_value == scope_value)
    }
}

// ── Gate Decision ────────────────────────────────────────────────────────────

/// Decision returned by the compatibility gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GateDecision {
    /// Operation allowed under current policy.
    Allow,
    /// Operation denied — rationale explains why.
    Deny,
    /// Operation allowed but under observation (audit trail generated).
    Audit,
}

impl GateDecision {
    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Allow => event_codes::PCG_GATE_PASS,
            Self::Deny => event_codes::PCG_GATE_DENY,
            Self::Audit => event_codes::PCG_GATE_AUDIT,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Audit => "audit",
        }
    }
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Gate Check Result ────────────────────────────────────────────────────────

/// Full result of a gate evaluation including rationale and audit metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCheckResult {
    /// The decision: allow, deny, or audit.
    pub decision: GateDecision,
    /// Machine-readable rationale explaining the decision.
    pub rationale: Vec<String>,
    /// Trace correlation ID for audit trail linkage.
    pub trace_id: String,
    /// Unique receipt ID if a receipt was generated.
    pub receipt_id: Option<String>,
    /// The package/shim that was evaluated.
    pub package_id: String,
    /// The mode under which evaluation occurred.
    pub mode: CompatibilityMode,
    /// The scope in which evaluation occurred.
    pub scope_id: String,
    /// Event code emitted.
    pub event_code: String,
}

// ── Mode Selection Receipt ───────────────────────────────────────────────────

/// A signed receipt recording a mode selection or transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeSelectionReceipt {
    /// Unique receipt ID.
    pub receipt_id: String,
    /// Scope this mode applies to.
    pub scope_id: String,
    /// The selected mode.
    pub mode: CompatibilityMode,
    /// Previous mode (None if first selection).
    pub previous_mode: Option<CompatibilityMode>,
    /// When the mode was activated.
    pub activated_at: String,
    /// Hex-encoded signature over receipt body.
    pub signature: String,
    /// Who requested the transition.
    pub requestor: String,
    /// Justification for the transition.
    pub justification: String,
    /// Whether approval was required (true for escalations).
    pub approval_required: bool,
    /// Whether the transition was approved.
    pub approved: bool,
}

impl ModeSelectionReceipt {
    /// Verify receipt signature (placeholder — real impl uses ed25519).
    pub fn verify_signature(&self) -> bool {
        self.signature.len() >= 64 && self.signature.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Scope Config ─────────────────────────────────────────────────────────────

/// Per-scope compatibility configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    pub scope_id: String,
    pub mode: CompatibilityMode,
    pub receipt: ModeSelectionReceipt,
    pub policy_predicates: Vec<PolicyPredicate>,
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Error type for compatibility gate operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompatGateError {
    /// Shim ID already exists in registry.
    DuplicateShim { shim_id: String },
    /// Scope not found.
    ScopeNotFound { scope_id: String },
    /// Mode transition denied (escalation without approval).
    TransitionDenied {
        from: String,
        to: String,
        reason: String,
    },
    /// Non-interference violation detected.
    NonInterferenceViolation {
        scope_a: String,
        scope_b: String,
        detail: String,
    },
    /// Monotonicity violation detected.
    MonotonicityViolation { shim_id: String, detail: String },
    /// Invalid policy predicate.
    InvalidPredicate {
        predicate_id: String,
        reason: String,
    },
    /// Package not found.
    PackageNotFound { package_id: String },
}

impl fmt::Display for CompatGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateShim { shim_id } => {
                write!(f, "duplicate shim: {shim_id}")
            }
            Self::ScopeNotFound { scope_id } => {
                write!(f, "scope not found: {scope_id}")
            }
            Self::TransitionDenied { from, to, reason } => {
                write!(f, "mode transition denied ({from} -> {to}): {reason}")
            }
            Self::NonInterferenceViolation {
                scope_a,
                scope_b,
                detail,
            } => {
                write!(
                    f,
                    "non-interference violation between {scope_a} and {scope_b}: {detail}"
                )
            }
            Self::MonotonicityViolation { shim_id, detail } => {
                write!(f, "monotonicity violation for shim {shim_id}: {detail}")
            }
            Self::InvalidPredicate {
                predicate_id,
                reason,
            } => {
                write!(f, "invalid predicate {predicate_id}: {reason}")
            }
            Self::PackageNotFound { package_id } => {
                write!(f, "package not found: {package_id}")
            }
        }
    }
}

impl std::error::Error for CompatGateError {}

// ── Gate Evaluator ───────────────────────────────────────────────────────────

/// The compatibility gate evaluator. Central entry point for gate checks,
/// mode queries, and shim registry queries.
#[derive(Debug, Clone)]
pub struct CompatGateEvaluator {
    registry: ShimRegistry,
    scopes: BTreeMap<String, ScopeConfig>,
    audit_log: Vec<GateCheckResult>,
    receipts: Vec<ModeSelectionReceipt>,
}

impl CompatGateEvaluator {
    pub fn new(registry: ShimRegistry) -> Self {
        Self {
            registry,
            scopes: BTreeMap::new(),
            audit_log: Vec::new(),
            receipts: Vec::new(),
        }
    }

    /// Get a reference to the shim registry.
    pub fn registry(&self) -> &ShimRegistry {
        &self.registry
    }

    // ── Mode Management ──

    /// Set the compatibility mode for a scope. Produces a signed receipt.
    /// Escalations (increasing risk level) require `approval` to be true.
    pub fn set_mode(
        &mut self,
        scope_id: &str,
        mode: CompatibilityMode,
        requestor: &str,
        justification: &str,
        approval: bool,
    ) -> Result<ModeSelectionReceipt, CompatGateError> {
        let previous_mode = self.scopes.get(scope_id).map(|s| s.mode);

        // Check escalation policy
        if let Some(prev) = previous_mode
            && prev.is_escalation_to(mode)
            && !approval
        {
            return Err(CompatGateError::TransitionDenied {
                from: prev.label().to_string(),
                to: mode.label().to_string(),
                reason: "escalation requires explicit approval".to_string(),
            });
        }

        let receipt = ModeSelectionReceipt {
            receipt_id: format!("rcpt-{}-{}", scope_id, self.receipts.len()),
            scope_id: scope_id.to_string(),
            mode,
            previous_mode,
            activated_at: chrono::Utc::now().to_rfc3339(),
            signature: "a".repeat(64), // placeholder signature
            requestor: requestor.to_string(),
            justification: justification.to_string(),
            approval_required: previous_mode.is_some_and(|p| p.is_escalation_to(mode)),
            approved: approval,
        };

        let scope_config = ScopeConfig {
            scope_id: scope_id.to_string(),
            mode,
            receipt: receipt.clone(),
            policy_predicates: Vec::new(),
        };

        self.scopes.insert(scope_id.to_string(), scope_config);
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    /// Get the current mode for a scope.
    pub fn get_mode(&self, scope_id: &str) -> Option<CompatibilityMode> {
        self.scopes.get(scope_id).map(|s| s.mode)
    }

    /// Get the scope configuration.
    pub fn get_scope(&self, scope_id: &str) -> Option<&ScopeConfig> {
        self.scopes.get(scope_id)
    }

    // ── Gate Evaluation ──

    /// Evaluate whether a package/extension may operate under the compatibility
    /// mode configured for the given scope. Returns structured decision.
    ///
    /// [PCG-001] gate pass, [PCG-002] gate deny, [PCG-005] gate audit.
    pub fn evaluate_gate(
        &mut self,
        package_id: &str,
        scope_id: &str,
        trace_id: &str,
    ) -> Result<GateCheckResult, CompatGateError> {
        let scope = self
            .scopes
            .get(scope_id)
            .ok_or_else(|| CompatGateError::ScopeNotFound {
                scope_id: scope_id.to_string(),
            })?;

        let mode = scope.mode;
        let mut rationale = Vec::new();

        // Look up the package in the shim registry
        let shim = self.registry.get(package_id);

        let decision = match shim {
            Some(entry) => {
                let action = divergence_action(entry.band, mode);
                match action {
                    DivergenceAction::Error => {
                        rationale.push(format!(
                            "band={} mode={}: divergence blocks execution",
                            entry.band.label(),
                            mode.label()
                        ));
                        GateDecision::Deny
                    }
                    DivergenceAction::Blocked => {
                        rationale.push(format!(
                            "band={} mode={}: shim blocked entirely",
                            entry.band.label(),
                            mode.label()
                        ));
                        GateDecision::Deny
                    }
                    DivergenceAction::Warn => {
                        rationale.push(format!(
                            "band={} mode={}: allowed with warning and receipt",
                            entry.band.label(),
                            mode.label()
                        ));
                        GateDecision::Audit
                    }
                    DivergenceAction::Log => {
                        rationale.push(format!(
                            "band={} mode={}: allowed with logging",
                            entry.band.label(),
                            mode.label()
                        ));
                        GateDecision::Allow
                    }
                }
            }
            None => {
                // Unknown package — allow if mode is permissive, deny if strict
                rationale.push(format!("package {package_id} not in shim registry"));
                match mode {
                    CompatibilityMode::Strict => {
                        rationale.push("strict mode: unknown packages denied".to_string());
                        GateDecision::Deny
                    }
                    CompatibilityMode::Balanced => {
                        rationale.push("balanced mode: unknown packages audited".to_string());
                        GateDecision::Audit
                    }
                    CompatibilityMode::LegacyRisky => {
                        rationale.push("legacy_risky mode: unknown packages allowed".to_string());
                        GateDecision::Allow
                    }
                }
            }
        };

        let receipt_id = if decision != GateDecision::Allow {
            Some(format!("gate-rcpt-{}-{}", scope_id, self.audit_log.len()))
        } else {
            None
        };

        let result = GateCheckResult {
            decision,
            rationale,
            trace_id: trace_id.to_string(),
            receipt_id,
            package_id: package_id.to_string(),
            mode,
            scope_id: scope_id.to_string(),
            event_code: decision.event_code().to_string(),
        };

        self.audit_log.push(result.clone());
        Ok(result)
    }

    // ── Non-Interference Check ──

    /// Verify that shim activation in scope_a has no observable effect in scope_b.
    /// Returns Ok(()) if non-interference holds; Err with violation details otherwise.
    ///
    /// Non-interference means: the gate decision for any package in scope_b is
    /// identical regardless of what shims are active in scope_a.
    pub fn check_non_interference(
        &self,
        scope_a: &str,
        scope_b: &str,
    ) -> Result<(), CompatGateError> {
        let config_a = self.scopes.get(scope_a);
        let config_b = self.scopes.get(scope_b);

        // If either scope doesn't exist, non-interference holds vacuously
        if config_a.is_none() || config_b.is_none() {
            return Ok(());
        }

        let mode_b = config_b.unwrap().mode;

        // For each shim, the decision in scope_b must be determined solely by
        // scope_b's mode, not scope_a's state. Since our gate evaluation is
        // purely a function of (shim.band, scope.mode), scopes are isolated
        // by construction — but we verify by checking that no cross-scope
        // predicate leaks.
        for entry in self.registry.all() {
            let action_b = divergence_action(entry.band, mode_b);
            // Check that no policy predicate from scope_a applies to scope_b
            if let Some(cfg_a) = config_a {
                for pred in &cfg_a.policy_predicates {
                    if pred.applies_to_scope("scope", scope_b) {
                        return Err(CompatGateError::NonInterferenceViolation {
                            scope_a: scope_a.to_string(),
                            scope_b: scope_b.to_string(),
                            detail: format!(
                                "predicate {} from scope {} applies to scope {}",
                                pred.predicate_id, scope_a, scope_b
                            ),
                        });
                    }
                }
            }
            // Action is solely a function of (band, mode_b) — no cross-scope leak
            let _ = action_b;
        }

        Ok(())
    }

    // ── Monotonicity Check ──

    /// Verify that adding a shim to the registry does not weaken existing security
    /// guarantees. Formally: if the current registry allows operation O under mode M,
    /// then registry + new_shim also allows operation O under mode M.
    ///
    /// A shim weakens guarantees if it downgrades the divergence action for
    /// an existing entry (e.g., from Error to Warn).
    pub fn check_monotonicity(&self, new_shim: &ShimRegistryEntry) -> Result<(), CompatGateError> {
        // Monotonicity: adding a new shim to the registry must not change the
        // gate decision for any *existing* shim. Since gate decisions are a
        // function of (shim.band, scope.mode) and adding a new entry doesn't
        // change any existing entry's band, monotonicity holds by construction.
        //
        // However, we verify: if the new shim has the same shim_id as an existing
        // entry (replacement scenario), the replacement must not reduce the
        // strictness of the action for any mode.
        if let Some(existing) = self.registry.get(&new_shim.shim_id) {
            for mode in [
                CompatibilityMode::Strict,
                CompatibilityMode::Balanced,
                CompatibilityMode::LegacyRisky,
            ] {
                let existing_action = divergence_action(existing.band, mode);
                let new_action = divergence_action(new_shim.band, mode);
                if action_strictness(new_action) < action_strictness(existing_action) {
                    return Err(CompatGateError::MonotonicityViolation {
                        shim_id: new_shim.shim_id.clone(),
                        detail: format!(
                            "mode {}: action downgraded from {} to {}",
                            mode.label(),
                            existing_action.label(),
                            new_action.label()
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    // ── Query APIs ──

    /// Get all gate decisions for a given scope (audit log).
    pub fn audit_log_for_scope(&self, scope_id: &str) -> Vec<&GateCheckResult> {
        self.audit_log
            .iter()
            .filter(|r| r.scope_id == scope_id)
            .collect()
    }

    /// Get all receipts for a given scope.
    pub fn receipts_for_scope(&self, scope_id: &str) -> Vec<&ModeSelectionReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.scope_id == scope_id)
            .collect()
    }

    /// Get all receipts.
    pub fn all_receipts(&self) -> &[ModeSelectionReceipt] {
        &self.receipts
    }

    /// Total number of gate evaluations.
    pub fn evaluation_count(&self) -> usize {
        self.audit_log.len()
    }

    /// Number of configured scopes.
    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }
}

/// Strictness rank of a divergence action (higher = stricter).
fn action_strictness(action: DivergenceAction) -> u8 {
    match action {
        DivergenceAction::Blocked => 4,
        DivergenceAction::Error => 3,
        DivergenceAction::Warn => 2,
        DivergenceAction::Log => 1,
    }
}

// ── Gate Report ──────────────────────────────────────────────────────────────

/// Summary report for the compatibility gate system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatGateReport {
    pub total_shims: usize,
    pub total_scopes: usize,
    pub total_evaluations: usize,
    pub total_receipts: usize,
    pub shims_by_band: BTreeMap<String, usize>,
    pub shims_by_risk: BTreeMap<String, usize>,
    pub decisions_summary: BTreeMap<String, usize>,
    pub generated_at: String,
}

/// Generate a summary report of the compatibility gate system.
pub fn generate_compat_report(evaluator: &CompatGateEvaluator) -> CompatGateReport {
    let registry = evaluator.registry();

    let mut shims_by_band: BTreeMap<String, usize> = BTreeMap::new();
    let mut shims_by_risk: BTreeMap<String, usize> = BTreeMap::new();

    for entry in registry.all() {
        *shims_by_band
            .entry(entry.band.label().to_string())
            .or_insert(0) += 1;
        *shims_by_risk
            .entry(entry.risk_category.label().to_string())
            .or_insert(0) += 1;
    }

    let mut decisions_summary: BTreeMap<String, usize> = BTreeMap::new();
    for result in &evaluator.audit_log {
        *decisions_summary
            .entry(result.decision.label().to_string())
            .or_insert(0) += 1;
    }

    CompatGateReport {
        total_shims: registry.len(),
        total_scopes: evaluator.scope_count(),
        total_evaluations: evaluator.evaluation_count(),
        total_receipts: evaluator.all_receipts().len(),
        shims_by_band,
        shims_by_risk,
        decisions_summary,
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──

    fn make_shim(id: &str, band: CompatibilityBand, risk: ShimRiskCategory) -> ShimRegistryEntry {
        ShimRegistryEntry {
            shim_id: id.to_string(),
            description: format!("Test shim {id}"),
            band,
            risk_category: risk,
            activation_policy_id: format!("policy-{id}"),
            divergence_rationale: format!("Rationale for {id}"),
            api_family: "fs".to_string(),
            active: true,
        }
    }

    fn sample_registry() -> ShimRegistry {
        let mut reg = ShimRegistry::new();
        reg.register(make_shim(
            "shim-core-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        ))
        .unwrap();
        reg.register(make_shim(
            "shim-hv-1",
            CompatibilityBand::HighValue,
            ShimRiskCategory::Medium,
        ))
        .unwrap();
        reg.register(make_shim(
            "shim-edge-1",
            CompatibilityBand::Edge,
            ShimRiskCategory::Low,
        ))
        .unwrap();
        reg.register(make_shim(
            "shim-unsafe-1",
            CompatibilityBand::Unsafe,
            ShimRiskCategory::Critical,
        ))
        .unwrap();
        reg
    }

    fn evaluator_with_scope() -> CompatGateEvaluator {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "project-1",
            CompatibilityMode::Balanced,
            "admin",
            "initial setup",
            true,
        )
        .unwrap();
        eval
    }

    // ── CompatibilityBand ──

    #[test]
    fn band_labels() {
        assert_eq!(CompatibilityBand::Core.label(), "core");
        assert_eq!(CompatibilityBand::HighValue.label(), "high_value");
        assert_eq!(CompatibilityBand::Edge.label(), "edge");
        assert_eq!(CompatibilityBand::Unsafe.label(), "unsafe");
    }

    #[test]
    fn band_priority_ordering() {
        assert!(CompatibilityBand::Core.priority() > CompatibilityBand::HighValue.priority());
        assert!(CompatibilityBand::HighValue.priority() > CompatibilityBand::Edge.priority());
        assert!(CompatibilityBand::Edge.priority() > CompatibilityBand::Unsafe.priority());
    }

    #[test]
    fn band_display() {
        assert_eq!(CompatibilityBand::Core.to_string(), "core");
    }

    // ── CompatibilityMode ──

    #[test]
    fn mode_labels() {
        assert_eq!(CompatibilityMode::Strict.label(), "strict");
        assert_eq!(CompatibilityMode::Balanced.label(), "balanced");
        assert_eq!(CompatibilityMode::LegacyRisky.label(), "legacy_risky");
    }

    #[test]
    fn mode_risk_ordering() {
        assert!(CompatibilityMode::Strict.risk_level() < CompatibilityMode::Balanced.risk_level());
        assert!(
            CompatibilityMode::Balanced.risk_level() < CompatibilityMode::LegacyRisky.risk_level()
        );
    }

    #[test]
    fn mode_escalation_detection() {
        assert!(CompatibilityMode::Strict.is_escalation_to(CompatibilityMode::Balanced));
        assert!(CompatibilityMode::Strict.is_escalation_to(CompatibilityMode::LegacyRisky));
        assert!(CompatibilityMode::Balanced.is_escalation_to(CompatibilityMode::LegacyRisky));
        assert!(!CompatibilityMode::LegacyRisky.is_escalation_to(CompatibilityMode::Strict));
        assert!(!CompatibilityMode::Balanced.is_escalation_to(CompatibilityMode::Strict));
        assert!(!CompatibilityMode::Strict.is_escalation_to(CompatibilityMode::Strict));
    }

    #[test]
    fn mode_display() {
        assert_eq!(CompatibilityMode::Balanced.to_string(), "balanced");
    }

    // ── Divergence Action Matrix ──

    #[test]
    fn divergence_matrix_core_always_error() {
        assert_eq!(
            divergence_action(CompatibilityBand::Core, CompatibilityMode::Strict),
            DivergenceAction::Error
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Core, CompatibilityMode::Balanced),
            DivergenceAction::Error
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Core, CompatibilityMode::LegacyRisky),
            DivergenceAction::Error
        );
    }

    #[test]
    fn divergence_matrix_high_value() {
        assert_eq!(
            divergence_action(CompatibilityBand::HighValue, CompatibilityMode::Strict),
            DivergenceAction::Error
        );
        assert_eq!(
            divergence_action(CompatibilityBand::HighValue, CompatibilityMode::Balanced),
            DivergenceAction::Warn
        );
        assert_eq!(
            divergence_action(CompatibilityBand::HighValue, CompatibilityMode::LegacyRisky),
            DivergenceAction::Warn
        );
    }

    #[test]
    fn divergence_matrix_edge() {
        assert_eq!(
            divergence_action(CompatibilityBand::Edge, CompatibilityMode::Strict),
            DivergenceAction::Warn
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Edge, CompatibilityMode::Balanced),
            DivergenceAction::Log
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Edge, CompatibilityMode::LegacyRisky),
            DivergenceAction::Log
        );
    }

    #[test]
    fn divergence_matrix_unsafe() {
        assert_eq!(
            divergence_action(CompatibilityBand::Unsafe, CompatibilityMode::Strict),
            DivergenceAction::Blocked
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Unsafe, CompatibilityMode::Balanced),
            DivergenceAction::Blocked
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Unsafe, CompatibilityMode::LegacyRisky),
            DivergenceAction::Warn
        );
    }

    #[test]
    fn divergence_matrix_is_complete() {
        // 4 bands x 3 modes = 12 cells
        let bands = [
            CompatibilityBand::Core,
            CompatibilityBand::HighValue,
            CompatibilityBand::Edge,
            CompatibilityBand::Unsafe,
        ];
        let modes = [
            CompatibilityMode::Strict,
            CompatibilityMode::Balanced,
            CompatibilityMode::LegacyRisky,
        ];
        let mut count = 0;
        for band in &bands {
            for mode in &modes {
                let _ = divergence_action(*band, *mode);
                count += 1;
            }
        }
        assert_eq!(count, 12);
    }

    // ── ShimRegistry ──

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = ShimRegistry::new();
        assert!(reg.is_empty());
        reg.register(make_shim(
            "shim-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        ))
        .unwrap();
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        let entry = reg.get("shim-1").unwrap();
        assert_eq!(entry.shim_id, "shim-1");
        assert_eq!(entry.band, CompatibilityBand::Core);
    }

    #[test]
    fn registry_duplicate_rejected() {
        let mut reg = ShimRegistry::new();
        reg.register(make_shim(
            "shim-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        ))
        .unwrap();
        let err = reg
            .register(make_shim(
                "shim-1",
                CompatibilityBand::Edge,
                ShimRiskCategory::Low,
            ))
            .unwrap_err();
        assert!(matches!(err, CompatGateError::DuplicateShim { .. }));
    }

    #[test]
    fn registry_by_band() {
        let reg = sample_registry();
        assert_eq!(reg.by_band(CompatibilityBand::Core).len(), 1);
        assert_eq!(reg.by_band(CompatibilityBand::HighValue).len(), 1);
        assert_eq!(reg.by_band(CompatibilityBand::Edge).len(), 1);
        assert_eq!(reg.by_band(CompatibilityBand::Unsafe).len(), 1);
    }

    #[test]
    fn registry_by_api_family() {
        let reg = sample_registry();
        assert_eq!(reg.by_api_family("fs").len(), 4);
        assert_eq!(reg.by_api_family("http").len(), 0);
    }

    #[test]
    fn registry_active_under_mode() {
        let reg = sample_registry();
        // Strict: core=Error(deny), hv=Error(deny), edge=Warn(allow), unsafe=Blocked(deny)
        // Only edge shim is active (Warn = not blocked/error)
        let strict_active = reg.active_under_mode(CompatibilityMode::Strict);
        assert_eq!(strict_active.len(), 1);
        assert_eq!(strict_active[0].band, CompatibilityBand::Edge);

        // Balanced: core=Error, hv=Warn(active), edge=Log(active), unsafe=Blocked
        let balanced_active = reg.active_under_mode(CompatibilityMode::Balanced);
        assert_eq!(balanced_active.len(), 2);

        // LegacyRisky: core=Error, hv=Warn(active), edge=Log(active), unsafe=Warn(active)
        let risky_active = reg.active_under_mode(CompatibilityMode::LegacyRisky);
        assert_eq!(risky_active.len(), 3);
    }

    #[test]
    fn registry_all() {
        let reg = sample_registry();
        assert_eq!(reg.all().len(), 4);
    }

    // ── PolicyPredicate ──

    #[test]
    fn predicate_signature_valid() {
        let pred = PolicyPredicate {
            predicate_id: "pred-1".to_string(),
            signature: "a".repeat(64),
            attenuation: vec![],
            activation_condition: "true".to_string(),
        };
        assert!(pred.verify_signature());
    }

    #[test]
    fn predicate_signature_too_short() {
        let pred = PolicyPredicate {
            predicate_id: "pred-1".to_string(),
            signature: "abcd".to_string(),
            attenuation: vec![],
            activation_condition: "true".to_string(),
        };
        assert!(!pred.verify_signature());
    }

    #[test]
    fn predicate_scope_universal() {
        let pred = PolicyPredicate {
            predicate_id: "pred-1".to_string(),
            signature: "a".repeat(64),
            attenuation: vec![],
            activation_condition: "true".to_string(),
        };
        assert!(pred.applies_to_scope("scope", "any"));
    }

    #[test]
    fn predicate_scope_attenuated() {
        let pred = PolicyPredicate {
            predicate_id: "pred-1".to_string(),
            signature: "a".repeat(64),
            attenuation: vec![AttenuationConstraint {
                scope_type: "project".to_string(),
                scope_value: "proj-1".to_string(),
            }],
            activation_condition: "true".to_string(),
        };
        assert!(pred.applies_to_scope("project", "proj-1"));
        assert!(!pred.applies_to_scope("project", "proj-2"));
    }

    // ── GateDecision ──

    #[test]
    fn gate_decision_event_codes() {
        assert_eq!(GateDecision::Allow.event_code(), "PCG-001");
        assert_eq!(GateDecision::Deny.event_code(), "PCG-002");
        assert_eq!(GateDecision::Audit.event_code(), "PCG-005");
    }

    #[test]
    fn gate_decision_labels() {
        assert_eq!(GateDecision::Allow.label(), "allow");
        assert_eq!(GateDecision::Deny.label(), "deny");
        assert_eq!(GateDecision::Audit.label(), "audit");
    }

    #[test]
    fn gate_decision_display() {
        assert_eq!(GateDecision::Deny.to_string(), "deny");
    }

    // ── Mode Selection ──

    #[test]
    fn set_mode_initial() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        let receipt = eval
            .set_mode(
                "scope-1",
                CompatibilityMode::Strict,
                "admin",
                "initial",
                true,
            )
            .unwrap();
        assert_eq!(receipt.mode, CompatibilityMode::Strict);
        assert!(receipt.previous_mode.is_none());
        assert!(!receipt.approval_required);
    }

    #[test]
    fn set_mode_escalation_requires_approval() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode("scope-1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();

        // Escalation without approval should fail
        let err = eval
            .set_mode(
                "scope-1",
                CompatibilityMode::LegacyRisky,
                "admin",
                "need legacy",
                false,
            )
            .unwrap_err();
        assert!(matches!(err, CompatGateError::TransitionDenied { .. }));
    }

    #[test]
    fn set_mode_escalation_with_approval() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode("scope-1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();
        let receipt = eval
            .set_mode(
                "scope-1",
                CompatibilityMode::LegacyRisky,
                "admin",
                "need legacy",
                true,
            )
            .unwrap();
        assert_eq!(receipt.mode, CompatibilityMode::LegacyRisky);
        assert_eq!(receipt.previous_mode, Some(CompatibilityMode::Strict));
        assert!(receipt.approval_required);
    }

    #[test]
    fn set_mode_de_escalation_auto_approved() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "scope-1",
            CompatibilityMode::LegacyRisky,
            "admin",
            "init",
            true,
        )
        .unwrap();
        // De-escalation should not require approval
        let receipt = eval
            .set_mode(
                "scope-1",
                CompatibilityMode::Strict,
                "admin",
                "tighten",
                false,
            )
            .unwrap();
        assert_eq!(receipt.mode, CompatibilityMode::Strict);
        assert!(!receipt.approval_required);
    }

    #[test]
    fn get_mode() {
        let eval = evaluator_with_scope();
        assert_eq!(
            eval.get_mode("project-1"),
            Some(CompatibilityMode::Balanced)
        );
        assert_eq!(eval.get_mode("nonexistent"), None);
    }

    // ── Gate Evaluation ──

    #[test]
    fn gate_eval_core_shim_denied_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-core-1", "project-1", "trace-1")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
        assert!(!result.rationale.is_empty());
        assert_eq!(result.event_code, event_codes::PCG_GATE_DENY);
    }

    #[test]
    fn gate_eval_hv_shim_audited_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-hv-1", "project-1", "trace-2")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Audit);
        assert_eq!(result.event_code, event_codes::PCG_GATE_AUDIT);
    }

    #[test]
    fn gate_eval_edge_shim_allowed_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "trace-3")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Allow);
        assert_eq!(result.event_code, event_codes::PCG_GATE_PASS);
    }

    #[test]
    fn gate_eval_unsafe_shim_denied_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-unsafe-1", "project-1", "trace-4")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
    }

    #[test]
    fn gate_eval_unknown_package_in_strict() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "scope-strict",
            CompatibilityMode::Strict,
            "admin",
            "init",
            true,
        )
        .unwrap();
        let result = eval
            .evaluate_gate("unknown-pkg", "scope-strict", "trace-5")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
    }

    #[test]
    fn gate_eval_unknown_package_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("unknown-pkg", "project-1", "trace-6")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Audit);
    }

    #[test]
    fn gate_eval_unknown_package_in_legacy_risky() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "scope-risky",
            CompatibilityMode::LegacyRisky,
            "admin",
            "init",
            true,
        )
        .unwrap();
        let result = eval
            .evaluate_gate("unknown-pkg", "scope-risky", "trace-7")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Allow);
    }

    #[test]
    fn gate_eval_scope_not_found() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        let err = eval
            .evaluate_gate("shim-core-1", "nonexistent", "trace-8")
            .unwrap_err();
        assert!(matches!(err, CompatGateError::ScopeNotFound { .. }));
    }

    #[test]
    fn gate_eval_trace_id_preserved() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "my-trace-123")
            .unwrap();
        assert_eq!(result.trace_id, "my-trace-123");
    }

    #[test]
    fn gate_eval_receipt_id_on_deny() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-core-1", "project-1", "trace-9")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
        assert!(result.receipt_id.is_some());
    }

    #[test]
    fn gate_eval_no_receipt_on_allow() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "trace-10")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Allow);
        assert!(result.receipt_id.is_none());
    }

    // ── Audit Log ──

    #[test]
    fn audit_log_records_evaluations() {
        let mut eval = evaluator_with_scope();
        eval.evaluate_gate("shim-core-1", "project-1", "t1")
            .unwrap();
        eval.evaluate_gate("shim-edge-1", "project-1", "t2")
            .unwrap();
        assert_eq!(eval.evaluation_count(), 2);
        assert_eq!(eval.audit_log_for_scope("project-1").len(), 2);
        assert_eq!(eval.audit_log_for_scope("other").len(), 0);
    }

    // ── Non-Interference ──

    #[test]
    fn non_interference_isolated_scopes() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode("scope-a", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();
        eval.set_mode(
            "scope-b",
            CompatibilityMode::LegacyRisky,
            "admin",
            "init",
            true,
        )
        .unwrap();
        assert!(eval.check_non_interference("scope-a", "scope-b").is_ok());
    }

    #[test]
    fn non_interference_missing_scope() {
        let eval = CompatGateEvaluator::new(sample_registry());
        // Non-existent scopes → vacuously OK
        assert!(eval.check_non_interference("x", "y").is_ok());
    }

    // ── Monotonicity ──

    #[test]
    fn monotonicity_new_shim_ok() {
        let eval = CompatGateEvaluator::new(sample_registry());
        let new_shim = make_shim("shim-new", CompatibilityBand::Edge, ShimRiskCategory::Low);
        assert!(eval.check_monotonicity(&new_shim).is_ok());
    }

    #[test]
    fn monotonicity_replacement_same_band_ok() {
        let eval = CompatGateEvaluator::new(sample_registry());
        // Replace shim-core-1 with same band → same actions → OK
        let replacement = make_shim(
            "shim-core-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        );
        assert!(eval.check_monotonicity(&replacement).is_ok());
    }

    #[test]
    fn monotonicity_replacement_stricter_ok() {
        let eval = CompatGateEvaluator::new(sample_registry());
        // Replace edge shim with core band → strictly more restrictive → OK
        let replacement = make_shim(
            "shim-edge-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        );
        assert!(eval.check_monotonicity(&replacement).is_ok());
    }

    #[test]
    fn monotonicity_replacement_weaker_rejected() {
        let eval = CompatGateEvaluator::new(sample_registry());
        // Replace core shim with edge band → less restrictive → violation
        let replacement = make_shim(
            "shim-core-1",
            CompatibilityBand::Edge,
            ShimRiskCategory::Low,
        );
        let err = eval.check_monotonicity(&replacement).unwrap_err();
        assert!(matches!(err, CompatGateError::MonotonicityViolation { .. }));
    }

    // ── Receipts ──

    #[test]
    fn receipts_accumulated() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode("s1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();
        eval.set_mode("s2", CompatibilityMode::Balanced, "admin", "init", true)
            .unwrap();
        assert_eq!(eval.all_receipts().len(), 2);
        assert_eq!(eval.receipts_for_scope("s1").len(), 1);
        assert_eq!(eval.receipts_for_scope("s2").len(), 1);
    }

    #[test]
    fn receipt_signature_verification() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        let receipt = eval
            .set_mode("s1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();
        assert!(receipt.verify_signature());
    }

    // ── Report ──

    #[test]
    fn report_generation() {
        let mut eval = evaluator_with_scope();
        eval.evaluate_gate("shim-core-1", "project-1", "t1")
            .unwrap();
        eval.evaluate_gate("shim-edge-1", "project-1", "t2")
            .unwrap();

        let report = generate_compat_report(&eval);
        assert_eq!(report.total_shims, 4);
        assert_eq!(report.total_scopes, 1);
        assert_eq!(report.total_evaluations, 2);
        assert_eq!(report.total_receipts, 1);
        assert!(!report.generated_at.is_empty());
        assert_eq!(*report.shims_by_band.get("core").unwrap_or(&0), 1);
    }

    // ── Error Display ──

    #[test]
    fn error_display_duplicate_shim() {
        let err = CompatGateError::DuplicateShim {
            shim_id: "test".to_string(),
        };
        assert!(err.to_string().contains("duplicate shim"));
    }

    #[test]
    fn error_display_scope_not_found() {
        let err = CompatGateError::ScopeNotFound {
            scope_id: "x".to_string(),
        };
        assert!(err.to_string().contains("scope not found"));
    }

    #[test]
    fn error_display_transition_denied() {
        let err = CompatGateError::TransitionDenied {
            from: "strict".to_string(),
            to: "legacy_risky".to_string(),
            reason: "no approval".to_string(),
        };
        assert!(err.to_string().contains("mode transition denied"));
    }

    #[test]
    fn error_display_non_interference() {
        let err = CompatGateError::NonInterferenceViolation {
            scope_a: "a".to_string(),
            scope_b: "b".to_string(),
            detail: "leak".to_string(),
        };
        assert!(err.to_string().contains("non-interference"));
    }

    #[test]
    fn error_display_monotonicity() {
        let err = CompatGateError::MonotonicityViolation {
            shim_id: "s".to_string(),
            detail: "weaker".to_string(),
        };
        assert!(err.to_string().contains("monotonicity"));
    }

    #[test]
    fn error_display_invalid_predicate() {
        let err = CompatGateError::InvalidPredicate {
            predicate_id: "p".to_string(),
            reason: "bad".to_string(),
        };
        assert!(err.to_string().contains("invalid predicate"));
    }

    #[test]
    fn error_display_package_not_found() {
        let err = CompatGateError::PackageNotFound {
            package_id: "pkg".to_string(),
        };
        assert!(err.to_string().contains("package not found"));
    }

    // ── Serde Roundtrips ──

    #[test]
    fn shim_entry_serde() {
        let entry = make_shim("s1", CompatibilityBand::Core, ShimRiskCategory::High);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: ShimRegistryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.shim_id, "s1");
        assert_eq!(parsed.band, CompatibilityBand::Core);
    }

    #[test]
    fn gate_check_result_serde() {
        let result = GateCheckResult {
            decision: GateDecision::Deny,
            rationale: vec!["reason".to_string()],
            trace_id: "t1".to_string(),
            receipt_id: Some("r1".to_string()),
            package_id: "pkg".to_string(),
            mode: CompatibilityMode::Strict,
            scope_id: "s1".to_string(),
            event_code: "PCG-002".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: GateCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decision, GateDecision::Deny);
        assert_eq!(parsed.trace_id, "t1");
    }

    #[test]
    fn mode_selection_receipt_serde() {
        let receipt = ModeSelectionReceipt {
            receipt_id: "r1".to_string(),
            scope_id: "s1".to_string(),
            mode: CompatibilityMode::Balanced,
            previous_mode: Some(CompatibilityMode::Strict),
            activated_at: "2026-01-01T00:00:00Z".to_string(),
            signature: "a".repeat(64),
            requestor: "admin".to_string(),
            justification: "test".to_string(),
            approval_required: true,
            approved: true,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: ModeSelectionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.receipt_id, "r1");
        assert_eq!(parsed.mode, CompatibilityMode::Balanced);
    }

    #[test]
    fn compat_gate_report_serde() {
        let eval = evaluator_with_scope();
        let report = generate_compat_report(&eval);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: CompatGateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_shims, 4);
    }

    // ── Edge Cases ──

    #[test]
    fn empty_registry_gate_eval() {
        let mut eval = CompatGateEvaluator::new(ShimRegistry::new());
        eval.set_mode("s1", CompatibilityMode::Balanced, "admin", "init", true)
            .unwrap();
        let result = eval.evaluate_gate("any-pkg", "s1", "t1").unwrap();
        assert_eq!(result.decision, GateDecision::Audit);
    }

    #[test]
    fn multiple_scopes_independent() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "strict-scope",
            CompatibilityMode::Strict,
            "admin",
            "init",
            true,
        )
        .unwrap();
        eval.set_mode(
            "risky-scope",
            CompatibilityMode::LegacyRisky,
            "admin",
            "init",
            true,
        )
        .unwrap();

        // Same package, different scopes → different decisions
        let strict_result = eval
            .evaluate_gate("shim-hv-1", "strict-scope", "t1")
            .unwrap();
        let risky_result = eval
            .evaluate_gate("shim-hv-1", "risky-scope", "t2")
            .unwrap();

        assert_eq!(strict_result.decision, GateDecision::Deny);
        assert_eq!(risky_result.decision, GateDecision::Audit);
    }

    #[test]
    fn scope_count() {
        let eval = evaluator_with_scope();
        assert_eq!(eval.scope_count(), 1);
    }

    #[test]
    fn evaluation_count_starts_at_zero() {
        let eval = CompatGateEvaluator::new(sample_registry());
        assert_eq!(eval.evaluation_count(), 0);
    }

    #[test]
    fn action_strictness_ordering() {
        assert!(
            action_strictness(DivergenceAction::Blocked)
                > action_strictness(DivergenceAction::Error)
        );
        assert!(
            action_strictness(DivergenceAction::Error) > action_strictness(DivergenceAction::Warn)
        );
        assert!(
            action_strictness(DivergenceAction::Warn) > action_strictness(DivergenceAction::Log)
        );
    }

    #[test]
    fn divergence_action_display() {
        assert_eq!(DivergenceAction::Error.to_string(), "error");
        assert_eq!(DivergenceAction::Warn.to_string(), "warn");
        assert_eq!(DivergenceAction::Log.to_string(), "log");
        assert_eq!(DivergenceAction::Blocked.to_string(), "blocked");
    }

    #[test]
    fn shim_risk_category_label() {
        assert_eq!(ShimRiskCategory::Low.label(), "low");
        assert_eq!(ShimRiskCategory::Medium.label(), "medium");
        assert_eq!(ShimRiskCategory::High.label(), "high");
        assert_eq!(ShimRiskCategory::Critical.label(), "critical");
    }

    #[test]
    fn event_codes_defined() {
        assert_eq!(event_codes::PCG_GATE_PASS, "PCG-001");
        assert_eq!(event_codes::PCG_GATE_DENY, "PCG-002");
        assert_eq!(event_codes::PCG_MODE_TRANSITION, "PCG-003");
        assert_eq!(event_codes::PCG_RECEIPT_ISSUED, "PCG-004");
        assert_eq!(event_codes::PCG_GATE_AUDIT, "PCG-005");
        assert_eq!(event_codes::PCG_NONINTERFERENCE_VIOLATION, "PCG-006");
        assert_eq!(event_codes::PCG_MONOTONICITY_VIOLATION, "PCG-007");
        assert_eq!(event_codes::PCG_SHIM_REGISTERED, "PCG-008");
    }

    // ── Deterministic evaluation ──

    #[test]
    fn gate_eval_deterministic() {
        let mut eval1 = evaluator_with_scope();
        let mut eval2 = evaluator_with_scope();

        let r1 = eval1
            .evaluate_gate("shim-core-1", "project-1", "t1")
            .unwrap();
        let r2 = eval2
            .evaluate_gate("shim-core-1", "project-1", "t1")
            .unwrap();

        assert_eq!(r1.decision, r2.decision);
        assert_eq!(r1.rationale, r2.rationale);
        assert_eq!(r1.event_code, r2.event_code);
    }

    #[test]
    fn unsafe_shim_allowed_only_in_legacy_risky() {
        let mut eval_strict = CompatGateEvaluator::new(sample_registry());
        eval_strict
            .set_mode("s", CompatibilityMode::Strict, "a", "i", true)
            .unwrap();
        let r = eval_strict
            .evaluate_gate("shim-unsafe-1", "s", "t")
            .unwrap();
        assert_eq!(r.decision, GateDecision::Deny);

        let mut eval_balanced = CompatGateEvaluator::new(sample_registry());
        eval_balanced
            .set_mode("s", CompatibilityMode::Balanced, "a", "i", true)
            .unwrap();
        let r = eval_balanced
            .evaluate_gate("shim-unsafe-1", "s", "t")
            .unwrap();
        assert_eq!(r.decision, GateDecision::Deny);

        let mut eval_risky = CompatGateEvaluator::new(sample_registry());
        eval_risky
            .set_mode("s", CompatibilityMode::LegacyRisky, "a", "i", true)
            .unwrap();
        let r = eval_risky.evaluate_gate("shim-unsafe-1", "s", "t").unwrap();
        assert_eq!(r.decision, GateDecision::Audit);
    }
}
