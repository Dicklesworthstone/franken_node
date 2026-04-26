//! bd-3vm: Ambient-authority audit gate for product security-critical modules.
//! bd-1xbr: Bounded events capacity with oldest-first eviction.
//!
//! Detects and rejects ambient authority usage in security-critical product
//! modules. Enforces Architecture Invariant #10: "no ambient authority."
//!
//! Every security-critical operation must receive its capabilities explicitly
//! through a `CapabilityContext` rather than relying on global state, ambient
//! environment variables, or implicit file-system access.
//!
//! # Invariants
//!
//! - INV-AA-NO-AMBIENT: No security-critical module may use ambient authority;
//!   all capabilities must be explicitly threaded.
//! - INV-AA-GUARD-ENFORCED: The `AuthorityAuditGuard` must be consulted before
//!   any security-critical operation executes.
//! - INV-AA-AUDIT-COMPLETE: Every audit run must produce a complete report
//!   covering all modules in the security-critical inventory.
//! - INV-AA-INVENTORY-CURRENT: The security-critical module inventory must be
//!   kept in sync with the actual codebase.
//! - INV-AA-DETERMINISTIC: Audit results are deterministic for the same input;
//!   BTreeMap is used for ordered output.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::capacity_defaults::aliases::MAX_EVENTS;
const MAX_VIOLATIONS: usize = 4096;

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

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Audit started for a module.
    pub const FN_AA_001: &str = "FN-AA-001";
    /// Module passed ambient authority check.
    pub const FN_AA_002: &str = "FN-AA-002";
    /// Ambient authority violation detected.
    pub const FN_AA_003: &str = "FN-AA-003";
    /// Capability context verified for module.
    pub const FN_AA_004: &str = "FN-AA-004";
    /// Static analysis pattern matched.
    pub const FN_AA_005: &str = "FN-AA-005";
    /// Audit report generated.
    pub const FN_AA_006: &str = "FN-AA-006";
    /// Module inventory loaded.
    pub const FN_AA_007: &str = "FN-AA-007";
    /// Guard enforcement decision made.
    pub const FN_AA_008: &str = "FN-AA-008";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_AA_MISSING_CAPABILITY: &str = "ERR_AA_MISSING_CAPABILITY";
    pub const ERR_AA_AMBIENT_DETECTED: &str = "ERR_AA_AMBIENT_DETECTED";
    pub const ERR_AA_INVENTORY_STALE: &str = "ERR_AA_INVENTORY_STALE";
    pub const ERR_AA_AUDIT_INCOMPLETE: &str = "ERR_AA_AUDIT_INCOMPLETE";
    pub const ERR_AA_GUARD_BYPASSED: &str = "ERR_AA_GUARD_BYPASSED";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_AA_NO_AMBIENT: &str = "INV-AA-NO-AMBIENT";
    pub const INV_AA_GUARD_ENFORCED: &str = "INV-AA-GUARD-ENFORCED";
    pub const INV_AA_AUDIT_COMPLETE: &str = "INV-AA-AUDIT-COMPLETE";
    pub const INV_AA_INVENTORY_CURRENT: &str = "INV-AA-INVENTORY-CURRENT";
    pub const INV_AA_DETERMINISTIC: &str = "INV-AA-DETERMINISTIC";
}

/// Schema version for audit report format.
pub const SCHEMA_VERSION: &str = "aa-v1.0";

// ---------------------------------------------------------------------------
// RiskLevel
// ---------------------------------------------------------------------------

/// Risk level classification for security-critical modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Low risk: auxiliary modules with limited security impact.
    Low,
    /// Medium risk: modules that handle trust-adjacent data.
    Medium,
    /// High risk: modules directly handling keys, signatures, or access control.
    High,
    /// Critical risk: modules whose compromise breaks the entire trust model.
    Critical,
}

impl RiskLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// Capabilities that may be required by security-critical modules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// Access to cryptographic key material.
    KeyAccess,
    /// Ability to sign artifacts.
    ArtifactSigning,
    /// Ability to verify signatures.
    SignatureVerification,
    /// Access to the epoch store.
    EpochStoreAccess,
    /// Ability to modify trust state.
    TrustStateMutation,
    /// Network egress capability.
    NetworkEgress,
    /// File system read access.
    FileSystemRead,
    /// File system write access.
    FileSystemWrite,
    /// Access to policy evaluation engine.
    PolicyEvaluation,
    /// Access to revocation list.
    RevocationAccess,
}

impl Capability {
    pub fn label(&self) -> &'static str {
        match self {
            Self::KeyAccess => "key_access",
            Self::ArtifactSigning => "artifact_signing",
            Self::SignatureVerification => "signature_verification",
            Self::EpochStoreAccess => "epoch_store_access",
            Self::TrustStateMutation => "trust_state_mutation",
            Self::NetworkEgress => "network_egress",
            Self::FileSystemRead => "file_system_read",
            Self::FileSystemWrite => "file_system_write",
            Self::PolicyEvaluation => "policy_evaluation",
            Self::RevocationAccess => "revocation_access",
        }
    }

    /// All defined capabilities.
    pub fn all() -> &'static [Capability] {
        &[
            Self::KeyAccess,
            Self::ArtifactSigning,
            Self::SignatureVerification,
            Self::EpochStoreAccess,
            Self::TrustStateMutation,
            Self::NetworkEgress,
            Self::FileSystemRead,
            Self::FileSystemWrite,
            Self::PolicyEvaluation,
            Self::RevocationAccess,
        ]
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// CapabilityContext
// ---------------------------------------------------------------------------

/// Explicit capability context threaded into security-critical operations.
///
/// # INV-AA-NO-AMBIENT
/// Operations must receive this context rather than reaching for ambient state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityContext {
    /// Capabilities granted to the caller.
    pub granted: BTreeMap<String, bool>,
    /// Trace identifier for audit correlation.
    pub trace_id: String,
    /// Principal that established this context.
    pub principal: String,
}

impl CapabilityContext {
    /// Create a new capability context with the given granted capabilities.
    pub fn new(
        capabilities: &[Capability],
        trace_id: impl Into<String>,
        principal: impl Into<String>,
    ) -> Self {
        let mut granted = BTreeMap::new();
        for cap in capabilities {
            granted.insert(cap.label().to_string(), true);
        }
        Self {
            granted,
            trace_id: trace_id.into(),
            principal: principal.into(),
        }
    }

    /// Check whether a specific capability is granted.
    pub fn has_capability(&self, cap: &Capability) -> bool {
        self.granted.get(cap.label()).copied().unwrap_or(false)
    }

    /// Check whether all required capabilities are present.
    pub fn has_all(&self, required: &[Capability]) -> bool {
        required.iter().all(|c| self.has_capability(c))
    }

    /// Return the list of missing capabilities from a required set.
    pub fn missing_capabilities(&self, required: &[Capability]) -> Vec<Capability> {
        required
            .iter()
            .filter(|c| !self.has_capability(c))
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// SecurityCriticalModule
// ---------------------------------------------------------------------------

/// Inventory entry for a security-critical module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCriticalModule {
    /// Rust module path (e.g., "crate::security::network_guard").
    pub module_path: String,
    /// Capabilities this module requires.
    pub required_capabilities: Vec<String>,
    /// Risk classification.
    pub risk_level: String,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// SecurityCriticalInventory
// ---------------------------------------------------------------------------

/// Complete inventory of security-critical modules.
///
/// # INV-AA-INVENTORY-CURRENT
/// Must be kept in sync with the actual codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCriticalInventory {
    /// Schema version.
    pub version: String,
    /// Modules indexed by path for deterministic ordering.
    pub modules: BTreeMap<String, SecurityCriticalModule>,
}

impl SecurityCriticalInventory {
    /// Create a new empty inventory.
    pub fn new() -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            modules: BTreeMap::new(),
        }
    }

    /// Add a module to the inventory.
    pub fn add_module(&mut self, module: SecurityCriticalModule) {
        self.modules.insert(module.module_path.clone(), module);
    }

    /// Number of registered modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Build the default product inventory.
    pub fn default_inventory() -> Self {
        let mut inv = Self::new();

        inv.add_module(SecurityCriticalModule {
            module_path: "crate::security::network_guard".to_string(),
            required_capabilities: vec![
                "network_egress".to_string(),
                "policy_evaluation".to_string(),
            ],
            risk_level: "critical".to_string(),
            description: "SSRF and network egress policy enforcement".to_string(),
        });

        inv.add_module(SecurityCriticalModule {
            module_path: "crate::security::interface_hash".to_string(),
            required_capabilities: vec!["signature_verification".to_string()],
            risk_level: "high".to_string(),
            description: "Interface integrity hash verification".to_string(),
        });

        inv.add_module(SecurityCriticalModule {
            module_path: "crate::supply_chain::artifact_signing".to_string(),
            required_capabilities: vec!["key_access".to_string(), "artifact_signing".to_string()],
            risk_level: "critical".to_string(),
            description: "Cryptographic artifact signing".to_string(),
        });

        inv.add_module(SecurityCriticalModule {
            module_path: "crate::control_plane::control_epoch".to_string(),
            required_capabilities: vec![
                "epoch_store_access".to_string(),
                "trust_state_mutation".to_string(),
            ],
            risk_level: "critical".to_string(),
            description: "Epoch lifecycle and trust-state transitions".to_string(),
        });

        inv.add_module(SecurityCriticalModule {
            module_path: "crate::control_plane::fork_detection".to_string(),
            required_capabilities: vec![
                "epoch_store_access".to_string(),
                "signature_verification".to_string(),
            ],
            risk_level: "high".to_string(),
            description: "Fork detection and split-brain prevention".to_string(),
        });

        inv.add_module(SecurityCriticalModule {
            module_path: "crate::security::ssrf_policy".to_string(),
            required_capabilities: vec![
                "network_egress".to_string(),
                "policy_evaluation".to_string(),
            ],
            risk_level: "critical".to_string(),
            description: "SSRF policy rule evaluation".to_string(),
        });

        inv.add_module(SecurityCriticalModule {
            module_path: "crate::supply_chain::manifest".to_string(),
            required_capabilities: vec![
                "file_system_read".to_string(),
                "signature_verification".to_string(),
            ],
            risk_level: "high".to_string(),
            description: "Supply-chain manifest verification".to_string(),
        });

        inv.add_module(SecurityCriticalModule {
            module_path: "crate::connector::lease_conflict".to_string(),
            required_capabilities: vec![
                "trust_state_mutation".to_string(),
                "epoch_store_access".to_string(),
            ],
            risk_level: "medium".to_string(),
            description: "Lease conflict resolution with trust implications".to_string(),
        });

        inv
    }
}

impl Default for SecurityCriticalInventory {
    fn default() -> Self {
        Self::default_inventory()
    }
}

// ---------------------------------------------------------------------------
// AmbientAuthorityPattern
// ---------------------------------------------------------------------------

/// Static analysis pattern that indicates potential ambient authority usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientAuthorityPattern {
    /// Pattern identifier.
    pub id: String,
    /// Human-readable description of the anti-pattern.
    pub description: String,
    /// Regex-like pattern to match (for documentation; actual matching is
    /// performed by the static analysis tooling).
    pub pattern: String,
    /// Severity if this pattern is found in a security-critical module.
    pub severity: String,
}

/// Built-in ambient authority detection patterns.
pub fn builtin_patterns() -> Vec<AmbientAuthorityPattern> {
    vec![
        AmbientAuthorityPattern {
            id: "AA-PAT-001".to_string(),
            description: "Direct std::env::var usage (ambient environment)".to_string(),
            pattern: r"std::env::var\b".to_string(),
            severity: "high".to_string(),
        },
        AmbientAuthorityPattern {
            id: "AA-PAT-002".to_string(),
            description: "Direct std::fs:: usage without capability".to_string(),
            pattern: r"std::fs::\b".to_string(),
            severity: "high".to_string(),
        },
        AmbientAuthorityPattern {
            id: "AA-PAT-003".to_string(),
            description: "Direct std::net:: usage without capability".to_string(),
            pattern: r"std::net::\b".to_string(),
            severity: "critical".to_string(),
        },
        AmbientAuthorityPattern {
            id: "AA-PAT-004".to_string(),
            description: "Global mutable static (lazy_static, once_cell without guard)".to_string(),
            pattern: r"(lazy_static!|static\s+mut\b)".to_string(),
            severity: "medium".to_string(),
        },
        AmbientAuthorityPattern {
            id: "AA-PAT-005".to_string(),
            description: "Process-wide signal or exit handler".to_string(),
            pattern: r"(std::process::exit|ctrlc::set_handler)".to_string(),
            severity: "medium".to_string(),
        },
        AmbientAuthorityPattern {
            id: "AA-PAT-006".to_string(),
            description: "Unrestricted DNS resolution".to_string(),
            pattern: r"ToSocketAddrs|lookup_host".to_string(),
            severity: "high".to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// AmbientAuthorityViolation
// ---------------------------------------------------------------------------

/// A detected ambient authority violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientAuthorityViolation {
    /// Module where the violation was detected.
    pub module_path: String,
    /// Pattern that matched.
    pub pattern_id: String,
    /// Description of the violation.
    pub description: String,
    /// Source location (file:line if available).
    pub location: Option<String>,
    /// Error code associated with the violation.
    pub error_code: String,
}

impl AmbientAuthorityViolation {
    pub fn code(&self) -> &str {
        &self.error_code
    }
}

impl fmt::Display for AmbientAuthorityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ambient authority violation in {}: {} (pattern: {})",
            self.module_path, self.description, self.pattern_id,
        )
    }
}

// ---------------------------------------------------------------------------
// AuthorityAuditGuard
// ---------------------------------------------------------------------------

/// Guard that enforces capability-context checking before security-critical
/// operations execute.
///
/// # INV-AA-GUARD-ENFORCED
/// Must be consulted before any security-critical operation.
///
/// # INV-AA-NO-AMBIENT
/// Rejects operations that lack required capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityAuditGuard {
    /// The inventory of security-critical modules.
    pub inventory: SecurityCriticalInventory,
    /// Events emitted during guard checks.
    pub events: Vec<AuditEvent>,
    /// Detected violations.
    pub violations: Vec<AmbientAuthorityViolation>,
    /// Whether enforcement is strict (reject) or advisory (warn).
    pub strict_mode: bool,
}

impl AuthorityAuditGuard {
    /// Create a new guard with the given inventory.
    pub fn new(inventory: SecurityCriticalInventory, strict_mode: bool) -> Self {
        Self {
            inventory,
            events: Vec::new(),
            violations: Vec::new(),
            strict_mode,
        }
    }

    fn emit_event(&mut self, event: AuditEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    /// Create a guard with the default product inventory.
    pub fn with_default_inventory(strict_mode: bool) -> Self {
        Self::new(SecurityCriticalInventory::default_inventory(), strict_mode)
    }

    /// Check whether a capability context satisfies the requirements for a
    /// given module.
    ///
    /// # INV-AA-GUARD-ENFORCED
    /// This is the central enforcement point.
    pub fn check_context(
        &mut self,
        module_path: &str,
        context: &CapabilityContext,
    ) -> Result<(), AmbientAuthorityViolation> {
        self.emit_event(AuditEvent {
            event_code: event_codes::FN_AA_001.to_string(),
            module_path: module_path.to_string(),
            detail: format!("audit started for module {module_path}"),
            trace_id: context.trace_id.clone(),
        });

        let module = match self.inventory.modules.get(module_path) {
            Some(m) => m.clone(),
            None => {
                // Module not in inventory; no restrictions apply.
                self.emit_event(AuditEvent {
                    event_code: event_codes::FN_AA_002.to_string(),
                    module_path: module_path.to_string(),
                    detail: "module not in security-critical inventory; no restrictions"
                        .to_string(),
                    trace_id: context.trace_id.clone(),
                });
                return Ok(());
            }
        };

        let missing: Vec<String> = module
            .required_capabilities
            .iter()
            .filter(|cap| !context.granted.get(*cap).copied().unwrap_or(false))
            .cloned()
            .collect();

        if missing.is_empty() {
            self.emit_event(AuditEvent {
                event_code: event_codes::FN_AA_004.to_string(),
                module_path: module_path.to_string(),
                detail: format!("all required capabilities present for {module_path}"),
                trace_id: context.trace_id.clone(),
            });
            self.emit_event(AuditEvent {
                event_code: event_codes::FN_AA_008.to_string(),
                module_path: module_path.to_string(),
                detail: "guard enforcement: ALLOW".to_string(),
                trace_id: context.trace_id.clone(),
            });
            Ok(())
        } else {
            let violation = AmbientAuthorityViolation {
                module_path: module_path.to_string(),
                pattern_id: "capability_check".to_string(),
                description: format!("missing capabilities: {}", missing.join(", ")),
                location: None,
                error_code: error_codes::ERR_AA_MISSING_CAPABILITY.to_string(),
            };
            self.emit_event(AuditEvent {
                event_code: event_codes::FN_AA_003.to_string(),
                module_path: module_path.to_string(),
                detail: format!(
                    "ambient authority violation: missing {}",
                    missing.join(", ")
                ),
                trace_id: context.trace_id.clone(),
            });
            self.emit_event(AuditEvent {
                event_code: event_codes::FN_AA_008.to_string(),
                module_path: module_path.to_string(),
                detail: if self.strict_mode {
                    "guard enforcement: REJECT"
                } else {
                    "guard enforcement: WARN"
                }
                .to_string(),
                trace_id: context.trace_id.clone(),
            });
            push_bounded(&mut self.violations, violation.clone(), MAX_VIOLATIONS);
            if self.strict_mode {
                Err(violation)
            } else {
                Ok(())
            }
        }
    }

    /// Run a complete audit across all modules in the inventory.
    ///
    /// # INV-AA-AUDIT-COMPLETE
    /// Covers every module in the inventory.
    pub fn audit_all(&mut self, context: &CapabilityContext) -> AuditReport {
        let module_paths: Vec<String> = self.inventory.modules.keys().cloned().collect();

        let mut module_results: BTreeMap<String, ModuleAuditResult> = BTreeMap::new();

        for path in &module_paths {
            let result = self.check_context(path, context);
            module_results.insert(
                path.clone(),
                ModuleAuditResult {
                    module_path: path.clone(),
                    passed: result.is_ok() || !self.strict_mode,
                    violation: result.err(),
                },
            );
        }

        let total = module_results.len();
        let passed = module_results.values().filter(|r| r.passed).count();
        let failed = total - passed;

        self.emit_event(AuditEvent {
            event_code: event_codes::FN_AA_006.to_string(),
            module_path: "".to_string(),
            detail: format!("audit report generated: {passed}/{total} passed"),
            trace_id: context.trace_id.clone(),
        });

        AuditReport {
            schema_version: SCHEMA_VERSION.to_string(),
            total_modules: total,
            passed,
            failed,
            verdict: if failed == 0 { "PASS" } else { "FAIL" }.to_string(),
            module_results,
            events: self.events.clone(),
            violations: self.violations.clone(),
        }
    }

    /// Return a snapshot of events.
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Return a snapshot of violations.
    pub fn violations(&self) -> &[AmbientAuthorityViolation] {
        &self.violations
    }
}

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/// Structured audit event emitted during authority checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_code: String,
    pub module_path: String,
    pub detail: String,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// ModuleAuditResult
// ---------------------------------------------------------------------------

/// Result of auditing a single module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleAuditResult {
    pub module_path: String,
    pub passed: bool,
    pub violation: Option<AmbientAuthorityViolation>,
}

// ---------------------------------------------------------------------------
// AuditReport
// ---------------------------------------------------------------------------

/// Complete audit report.
///
/// # INV-AA-DETERMINISTIC
/// Uses BTreeMap for deterministic key ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub schema_version: String,
    pub total_modules: usize,
    pub passed: usize,
    pub failed: usize,
    pub verdict: String,
    pub module_results: BTreeMap<String, ModuleAuditResult>,
    pub events: Vec<AuditEvent>,
    pub violations: Vec<AmbientAuthorityViolation>,
}

impl AuditReport {
    /// Generate a summary string.
    pub fn summary(&self) -> String {
        format!(
            "AuditReport(v={}, modules={}, passed={}, failed={}, verdict={})",
            self.schema_version, self.total_modules, self.passed, self.failed, self.verdict,
        )
    }
}

// ---------------------------------------------------------------------------
// Convenience: generate_audit_report
// ---------------------------------------------------------------------------

/// Run a full audit with the default inventory and a given capability context.
pub fn generate_audit_report(context: &CapabilityContext, strict_mode: bool) -> AuditReport {
    let mut guard = AuthorityAuditGuard::with_default_inventory(strict_mode);
    guard.audit_all(context)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Event codes ──────────────────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::FN_AA_001, "FN-AA-001");
        assert_eq!(event_codes::FN_AA_002, "FN-AA-002");
        assert_eq!(event_codes::FN_AA_003, "FN-AA-003");
        assert_eq!(event_codes::FN_AA_004, "FN-AA-004");
        assert_eq!(event_codes::FN_AA_005, "FN-AA-005");
        assert_eq!(event_codes::FN_AA_006, "FN-AA-006");
        assert_eq!(event_codes::FN_AA_007, "FN-AA-007");
        assert_eq!(event_codes::FN_AA_008, "FN-AA-008");
    }

    // ── Error codes ──────────────────────────────────────────────────

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(
            error_codes::ERR_AA_MISSING_CAPABILITY,
            "ERR_AA_MISSING_CAPABILITY"
        );
        assert_eq!(
            error_codes::ERR_AA_AMBIENT_DETECTED,
            "ERR_AA_AMBIENT_DETECTED"
        );
        assert_eq!(
            error_codes::ERR_AA_INVENTORY_STALE,
            "ERR_AA_INVENTORY_STALE"
        );
        assert_eq!(
            error_codes::ERR_AA_AUDIT_INCOMPLETE,
            "ERR_AA_AUDIT_INCOMPLETE"
        );
        assert_eq!(error_codes::ERR_AA_GUARD_BYPASSED, "ERR_AA_GUARD_BYPASSED");
    }

    // ── Invariants ───────────────────────────────────────────────────

    #[test]
    fn test_invariants_defined() {
        assert_eq!(invariants::INV_AA_NO_AMBIENT, "INV-AA-NO-AMBIENT");
        assert_eq!(invariants::INV_AA_GUARD_ENFORCED, "INV-AA-GUARD-ENFORCED");
        assert_eq!(invariants::INV_AA_AUDIT_COMPLETE, "INV-AA-AUDIT-COMPLETE");
        assert_eq!(
            invariants::INV_AA_INVENTORY_CURRENT,
            "INV-AA-INVENTORY-CURRENT"
        );
        assert_eq!(invariants::INV_AA_DETERMINISTIC, "INV-AA-DETERMINISTIC");
    }

    // ── Schema version ───────────────────────────────────────────────

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "aa-v1.0");
    }

    // ── RiskLevel ────────────────────────────────────────────────────

    #[test]
    fn test_risk_level_labels() {
        assert_eq!(RiskLevel::Low.label(), "low");
        assert_eq!(RiskLevel::Medium.label(), "medium");
        assert_eq!(RiskLevel::High.label(), "high");
        assert_eq!(RiskLevel::Critical.label(), "critical");
    }

    #[test]
    fn test_risk_level_from_label() {
        assert_eq!(RiskLevel::from_label("low"), Some(RiskLevel::Low));
        assert_eq!(RiskLevel::from_label("critical"), Some(RiskLevel::Critical));
        assert_eq!(RiskLevel::from_label("bogus"), None);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::High), "high");
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_serde() {
        let json = serde_json::to_string(&RiskLevel::Critical).unwrap();
        let parsed: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, RiskLevel::Critical);
    }

    // ── Capability ───────────────────────────────────────────────────

    #[test]
    fn test_capability_all_count() {
        assert_eq!(Capability::all().len(), 10);
    }

    #[test]
    fn test_capability_labels_unique() {
        let labels: Vec<&str> = Capability::all().iter().map(|c| c.label()).collect();
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len());
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(format!("{}", Capability::KeyAccess), "key_access");
        assert_eq!(format!("{}", Capability::NetworkEgress), "network_egress");
    }

    #[test]
    fn test_capability_serde() {
        let json = serde_json::to_string(&Capability::ArtifactSigning).unwrap();
        let parsed: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Capability::ArtifactSigning);
    }

    // ── CapabilityContext ────────────────────────────────────────────

    #[test]
    fn test_capability_context_new() {
        let ctx = CapabilityContext::new(
            &[Capability::KeyAccess, Capability::ArtifactSigning],
            "trace-1",
            "agent-1",
        );
        assert!(ctx.has_capability(&Capability::KeyAccess));
        assert!(ctx.has_capability(&Capability::ArtifactSigning));
        assert!(!ctx.has_capability(&Capability::NetworkEgress));
    }

    #[test]
    fn test_capability_context_has_all() {
        let ctx = CapabilityContext::new(
            &[Capability::KeyAccess, Capability::ArtifactSigning],
            "trace-1",
            "agent-1",
        );
        assert!(ctx.has_all(&[Capability::KeyAccess, Capability::ArtifactSigning]));
        assert!(!ctx.has_all(&[Capability::KeyAccess, Capability::NetworkEgress]));
    }

    #[test]
    fn test_capability_context_missing() {
        let ctx = CapabilityContext::new(&[Capability::KeyAccess], "trace-1", "agent-1");
        let missing = ctx.missing_capabilities(&[
            Capability::KeyAccess,
            Capability::NetworkEgress,
            Capability::FileSystemRead,
        ]);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&Capability::NetworkEgress));
        assert!(missing.contains(&Capability::FileSystemRead));
    }

    #[test]
    fn test_capability_context_serde() {
        let ctx = CapabilityContext::new(&[Capability::KeyAccess], "trace-1", "agent-1");
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: CapabilityContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.trace_id, "trace-1");
        assert_eq!(parsed.principal, "agent-1");
        assert!(parsed.granted.contains_key("key_access"));
    }

    // ── SecurityCriticalInventory ────────────────────────────────────

    #[test]
    fn test_inventory_default() {
        let inv = SecurityCriticalInventory::default_inventory();
        assert_eq!(inv.module_count(), 8);
        assert_eq!(inv.version, SCHEMA_VERSION);
    }

    #[test]
    fn test_inventory_add_module() {
        let mut inv = SecurityCriticalInventory::new();
        assert_eq!(inv.module_count(), 0);
        inv.add_module(SecurityCriticalModule {
            module_path: "test::module".to_string(),
            required_capabilities: vec!["key_access".to_string()],
            risk_level: "high".to_string(),
            description: "test".to_string(),
        });
        assert_eq!(inv.module_count(), 1);
    }

    #[test]
    fn test_inventory_deterministic_ordering() {
        let inv = SecurityCriticalInventory::default_inventory();
        let keys: Vec<String> = inv.modules.keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap keys must be sorted");
    }

    #[test]
    fn test_inventory_serde() {
        let inv = SecurityCriticalInventory::default_inventory();
        let json = serde_json::to_string(&inv).unwrap();
        let parsed: SecurityCriticalInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.module_count(), inv.module_count());
    }

    // ── AmbientAuthorityPattern ──────────────────────────────────────

    #[test]
    fn test_builtin_patterns_count() {
        let patterns = builtin_patterns();
        assert_eq!(patterns.len(), 6);
    }

    #[test]
    fn test_builtin_patterns_unique_ids() {
        let patterns = builtin_patterns();
        let ids: Vec<&str> = patterns.iter().map(|p| p.id.as_str()).collect();
        let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_pattern_serde() {
        let p = &builtin_patterns()[0];
        let json = serde_json::to_string(p).unwrap();
        let parsed: AmbientAuthorityPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, p.id);
    }

    // ── AmbientAuthorityViolation ────────────────────────────────────

    #[test]
    fn test_violation_display() {
        let v = AmbientAuthorityViolation {
            module_path: "crate::test".to_string(),
            pattern_id: "AA-PAT-001".to_string(),
            description: "direct env access".to_string(),
            location: None,
            error_code: error_codes::ERR_AA_AMBIENT_DETECTED.to_string(),
        };
        let s = format!("{v}");
        assert!(s.contains("crate::test"));
        assert!(s.contains("AA-PAT-001"));
    }

    #[test]
    fn test_violation_code() {
        let v = AmbientAuthorityViolation {
            module_path: "test".to_string(),
            pattern_id: "pat".to_string(),
            description: "d".to_string(),
            location: None,
            error_code: error_codes::ERR_AA_MISSING_CAPABILITY.to_string(),
        };
        assert_eq!(v.code(), error_codes::ERR_AA_MISSING_CAPABILITY);
    }

    #[test]
    fn test_violation_serde() {
        let v = AmbientAuthorityViolation {
            module_path: "test".to_string(),
            pattern_id: "pat".to_string(),
            description: "d".to_string(),
            location: Some("file.rs:42".to_string()),
            error_code: error_codes::ERR_AA_AMBIENT_DETECTED.to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: AmbientAuthorityViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.location, Some("file.rs:42".to_string()));
    }

    // ── AuthorityAuditGuard ──────────────────────────────────────────

    #[test]
    fn test_guard_with_default_inventory() {
        let guard = AuthorityAuditGuard::with_default_inventory(true);
        assert_eq!(guard.inventory.module_count(), 8);
        assert!(guard.strict_mode);
        assert!(guard.events.is_empty());
        assert!(guard.violations.is_empty());
    }

    #[test]
    fn test_guard_check_context_pass() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);
        let ctx = CapabilityContext::new(
            &[Capability::NetworkEgress, Capability::PolicyEvaluation],
            "t1",
            "p1",
        );
        let result = guard.check_context("crate::security::network_guard", &ctx);
        assert!(result.is_ok());
        assert!(guard.violations.is_empty());
    }

    #[test]
    fn test_guard_check_context_fail_strict() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);
        let ctx = CapabilityContext::new(&[Capability::NetworkEgress], "t1", "p1");
        let result = guard.check_context("crate::security::network_guard", &ctx);
        assert!(result.is_err());
        assert_eq!(guard.violations.len(), 1);
        assert_eq!(
            guard.violations[0].error_code,
            error_codes::ERR_AA_MISSING_CAPABILITY
        );
    }

    #[test]
    fn test_guard_check_context_fail_advisory() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(false);
        let ctx = CapabilityContext::new(&[Capability::NetworkEgress], "t1", "p1");
        let result = guard.check_context("crate::security::network_guard", &ctx);
        // Advisory mode: returns Ok even on violation.
        assert!(result.is_ok());
        assert_eq!(guard.violations.len(), 1);
    }

    #[test]
    fn test_guard_unknown_module_passes() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);
        let ctx = CapabilityContext::new(&[], "t1", "p1");
        let result = guard.check_context("crate::unknown::module", &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_guard_emits_events() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);
        let ctx = CapabilityContext::new(
            &[Capability::NetworkEgress, Capability::PolicyEvaluation],
            "t1",
            "p1",
        );
        let _ = guard.check_context("crate::security::network_guard", &ctx);
        assert!(!guard.events().is_empty());
        let codes: Vec<&str> = guard
            .events()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::FN_AA_001));
        assert!(codes.contains(&event_codes::FN_AA_004));
        assert!(codes.contains(&event_codes::FN_AA_008));
    }

    #[test]
    fn test_guard_violation_events() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);
        let ctx = CapabilityContext::new(&[], "t1", "p1");
        let _ = guard.check_context("crate::security::network_guard", &ctx);
        let codes: Vec<&str> = guard
            .events()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::FN_AA_003));
    }

    #[test]
    fn strict_guard_reports_each_missing_capability_for_module() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);
        let ctx = CapabilityContext::new(&[], "trace-missing-all", "principal-missing-all");

        let violation = guard
            .check_context("crate::security::network_guard", &ctx)
            .expect_err("strict guard must reject missing capabilities");

        assert_eq!(violation.code(), error_codes::ERR_AA_MISSING_CAPABILITY);
        assert!(violation.description.contains("network_egress"));
        assert!(violation.description.contains("policy_evaluation"));
        assert_eq!(guard.violations().len(), 1);
    }

    #[test]
    fn strict_guard_treats_explicit_false_grant_as_missing() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);
        let mut ctx = CapabilityContext::new(
            &[Capability::NetworkEgress, Capability::PolicyEvaluation],
            "trace-false-grant",
            "principal-false-grant",
        );
        ctx.granted.insert("policy_evaluation".to_string(), false);

        let violation = guard
            .check_context("crate::security::network_guard", &ctx)
            .expect_err("explicit false grant must reject");

        assert!(violation.description.contains("policy_evaluation"));
        assert!(!violation.description.contains("network_egress"));
        assert!(
            guard
                .events()
                .iter()
                .any(|event| event.detail == "guard enforcement: REJECT")
        );
    }

    #[test]
    fn advisory_guard_records_violation_but_emits_warn_decision() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(false);
        let ctx = CapabilityContext::new(&[], "trace-advisory-warn", "principal-advisory-warn");

        let result = guard.check_context("crate::security::network_guard", &ctx);

        assert!(result.is_ok());
        assert_eq!(guard.violations().len(), 1);
        assert!(
            guard
                .events()
                .iter()
                .any(|event| event.detail == "guard enforcement: WARN")
        );
    }

    #[test]
    fn unknown_required_capability_string_is_not_satisfied_by_known_capabilities() {
        let mut inventory = SecurityCriticalInventory::new();
        inventory.add_module(SecurityCriticalModule {
            module_path: "crate::security::custom_unknown".to_string(),
            required_capabilities: vec!["capability_that_does_not_exist".to_string()],
            risk_level: "critical".to_string(),
            description: "custom unknown capability test".to_string(),
        });
        let mut guard = AuthorityAuditGuard::new(inventory, true);
        let ctx = CapabilityContext::new(
            Capability::all(),
            "trace-unknown-capability",
            "principal-unknown-capability",
        );

        let violation = guard
            .check_context("crate::security::custom_unknown", &ctx)
            .expect_err("unknown required capability must fail closed");

        assert!(
            violation
                .description
                .contains("capability_that_does_not_exist")
        );
        assert_eq!(guard.violations().len(), 1);
    }

    #[test]
    fn strict_audit_with_partial_capabilities_fails_specific_modules() {
        let ctx = CapabilityContext::new(
            &[Capability::NetworkEgress, Capability::PolicyEvaluation],
            "trace-partial-strict",
            "principal-partial-strict",
        );

        let report = generate_audit_report(&ctx, true);

        assert_eq!(report.verdict, "FAIL");
        assert!(report.failed > 0);
        let signing = report
            .module_results
            .get("crate::supply_chain::artifact_signing")
            .expect("artifact signing result");
        assert!(!signing.passed);
        assert!(signing.violation.is_some());
    }

    #[test]
    fn strict_audit_with_no_capabilities_fails_every_inventory_module() {
        let ctx = CapabilityContext::new(&[], "trace-none-strict", "principal-none-strict");

        let report = generate_audit_report(&ctx, true);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.failed, report.total_modules);
        assert_eq!(report.violations.len(), report.total_modules);
        assert!(
            report
                .module_results
                .values()
                .all(|result| !result.passed && result.violation.is_some())
        );
    }

    #[test]
    fn advisory_audit_keeps_pass_verdict_while_retaining_violation_log() {
        let ctx = CapabilityContext::new(&[], "trace-none-advisory", "principal-none-advisory");

        let report = generate_audit_report(&ctx, false);

        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.failed, 0);
        assert_eq!(report.violations.len(), report.total_modules);
        assert!(
            report
                .module_results
                .values()
                .all(|result| result.passed && result.violation.is_none())
        );
    }

    #[test]
    fn failed_guard_preserves_trace_id_on_rejection_events() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);
        let ctx = CapabilityContext::new(&[], "trace-reject-events", "principal-reject-events");

        let _ = guard.check_context("crate::security::network_guard", &ctx);

        assert!(
            guard
                .events()
                .iter()
                .filter(|event| event.event_code == event_codes::FN_AA_003)
                .all(|event| event.trace_id == "trace-reject-events")
        );
    }

    // ── AuditReport (audit_all) ──────────────────────────────────────

    #[test]
    fn test_audit_all_with_full_capabilities() {
        let ctx = CapabilityContext::new(Capability::all(), "t1", "p1");
        let report = generate_audit_report(&ctx, true);
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.failed, 0);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.total_modules, 8);
    }

    #[test]
    fn test_audit_all_with_no_capabilities() {
        let ctx = CapabilityContext::new(&[], "t1", "p1");
        let report = generate_audit_report(&ctx, true);
        assert_eq!(report.verdict, "FAIL");
        assert!(report.failed > 0);
    }

    #[test]
    fn test_audit_all_advisory_mode() {
        let ctx = CapabilityContext::new(&[], "t1", "p1");
        let report = generate_audit_report(&ctx, false);
        // Advisory mode: all pass even with violations recorded.
        assert_eq!(report.verdict, "PASS");
        assert!(!report.violations.is_empty());
    }

    #[test]
    fn test_audit_report_deterministic() {
        let ctx = CapabilityContext::new(Capability::all(), "t1", "p1");
        let r1 = generate_audit_report(&ctx, true);
        let r2 = generate_audit_report(&ctx, true);
        let j1 = serde_json::to_string(&r1.module_results).unwrap();
        let j2 = serde_json::to_string(&r2.module_results).unwrap();
        assert_eq!(j1, j2, "audit reports must be deterministic");
    }

    #[test]
    fn test_audit_report_summary() {
        let ctx = CapabilityContext::new(Capability::all(), "t1", "p1");
        let report = generate_audit_report(&ctx, true);
        let summary = report.summary();
        assert!(summary.contains("aa-v1.0"));
        assert!(summary.contains("PASS"));
    }

    #[test]
    fn test_audit_report_covers_all_inventory_modules() {
        let inv = SecurityCriticalInventory::default_inventory();
        let ctx = CapabilityContext::new(Capability::all(), "t1", "p1");
        let report = generate_audit_report(&ctx, true);
        assert_eq!(report.total_modules, inv.module_count());
        for key in inv.modules.keys() {
            assert!(
                report.module_results.contains_key(key),
                "missing module in report: {key}"
            );
        }
    }

    #[test]
    fn test_audit_report_serde() {
        let ctx = CapabilityContext::new(Capability::all(), "t1", "p1");
        let report = generate_audit_report(&ctx, true);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AuditReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verdict, report.verdict);
        assert_eq!(parsed.total_modules, report.total_modules);
    }

    // ── AuditEvent ───────────────────────────────────────────────────

    #[test]
    fn test_audit_event_serde() {
        let e = AuditEvent {
            event_code: "FN-AA-001".to_string(),
            module_path: "test::module".to_string(),
            detail: "test detail".to_string(),
            trace_id: "t-123".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "FN-AA-001");
    }

    #[test]
    fn risk_level_from_label_rejects_case_and_whitespace() {
        assert_eq!(RiskLevel::from_label("High"), None);
        assert_eq!(RiskLevel::from_label(" critical"), None);
        assert_eq!(RiskLevel::from_label("critical "), None);
        assert_eq!(RiskLevel::from_label(""), None);
    }

    #[test]
    fn case_mismatched_grant_does_not_satisfy_capability() {
        let mut ctx = CapabilityContext::new(&[], "trace-case-grant", "principal-case-grant");
        ctx.granted.insert("NetworkEgress".to_string(), true);
        ctx.granted.insert("network_egress".to_string(), false);

        assert!(!ctx.has_capability(&Capability::NetworkEgress));
        assert_eq!(
            ctx.missing_capabilities(&[Capability::NetworkEgress]),
            vec![Capability::NetworkEgress]
        );
    }

    #[test]
    fn duplicate_inventory_module_replaces_stale_requirements() {
        let mut inventory = SecurityCriticalInventory::new();
        inventory.add_module(SecurityCriticalModule {
            module_path: "crate::security::replace_me".to_string(),
            required_capabilities: vec!["key_access".to_string()],
            risk_level: "high".to_string(),
            description: "first definition".to_string(),
        });
        inventory.add_module(SecurityCriticalModule {
            module_path: "crate::security::replace_me".to_string(),
            required_capabilities: vec!["network_egress".to_string()],
            risk_level: "critical".to_string(),
            description: "replacement definition".to_string(),
        });

        let module = inventory
            .modules
            .get("crate::security::replace_me")
            .expect("replacement module");
        assert_eq!(inventory.module_count(), 1);
        assert_eq!(module.required_capabilities, vec!["network_egress"]);
        assert_eq!(module.description, "replacement definition");
    }

    #[test]
    fn blank_required_capability_string_fails_closed() {
        let mut inventory = SecurityCriticalInventory::new();
        inventory.add_module(SecurityCriticalModule {
            module_path: "crate::security::blank_required".to_string(),
            required_capabilities: vec!["".to_string()],
            risk_level: "critical".to_string(),
            description: "malformed blank capability".to_string(),
        });
        let ctx = CapabilityContext::new(
            Capability::all(),
            "trace-blank-required",
            "principal-blank-required",
        );
        let mut guard = AuthorityAuditGuard::new(inventory, true);

        let violation = guard
            .check_context("crate::security::blank_required", &ctx)
            .expect_err("blank required capability must fail closed");

        assert_eq!(violation.error_code, error_codes::ERR_AA_MISSING_CAPABILITY);
        assert_eq!(violation.pattern_id, "capability_check");
        assert_eq!(guard.violations().len(), 1);
    }

    #[test]
    fn strict_rejection_records_violation_before_decision_event() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);
        let ctx = CapabilityContext::new(&[], "trace-event-order", "principal-event-order");

        let _ = guard.check_context("crate::security::network_guard", &ctx);

        let events = guard.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_code, event_codes::FN_AA_001);
        assert_eq!(events[1].event_code, event_codes::FN_AA_003);
        assert_eq!(events[2].event_code, event_codes::FN_AA_008);
        assert_eq!(events[2].detail, "guard enforcement: REJECT");
    }

    #[test]
    fn advisory_report_keeps_result_violations_empty_on_failed_modules() {
        let ctx = CapabilityContext::new(
            &[],
            "trace-advisory-result-shape",
            "principal-advisory-result-shape",
        );

        let report = generate_audit_report(&ctx, false);

        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.failed, 0);
        assert_eq!(report.violations.len(), report.total_modules);
        assert!(
            report
                .module_results
                .values()
                .all(|result| result.passed && result.violation.is_none())
        );
    }

    #[test]
    fn push_bounded_zero_capacity_discards_without_panic() {
        let mut events = vec![AuditEvent {
            event_code: event_codes::FN_AA_001.to_string(),
            module_path: "crate::security::old".to_string(),
            detail: "old event".to_string(),
            trace_id: "trace-old".to_string(),
        }];

        push_bounded(
            &mut events,
            AuditEvent {
                event_code: event_codes::FN_AA_003.to_string(),
                module_path: "crate::security::new".to_string(),
                detail: "new event".to_string(),
                trace_id: "trace-new".to_string(),
            },
            0,
        );

        assert!(events.is_empty());
    }

    #[test]
    fn push_bounded_retains_latest_entries_after_overflow() {
        let mut entries = Vec::new();

        for index in 0..5 {
            push_bounded(&mut entries, format!("entry-{index}"), 2);
        }

        assert_eq!(entries, vec!["entry-3".to_string(), "entry-4".to_string()]);
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<RiskLevel>();
        assert_sync::<RiskLevel>();
        assert_send::<Capability>();
        assert_sync::<Capability>();
        assert_send::<CapabilityContext>();
        assert_sync::<CapabilityContext>();
        assert_send::<SecurityCriticalModule>();
        assert_sync::<SecurityCriticalModule>();
        assert_send::<SecurityCriticalInventory>();
        assert_sync::<SecurityCriticalInventory>();
        assert_send::<AmbientAuthorityPattern>();
        assert_sync::<AmbientAuthorityPattern>();
        assert_send::<AmbientAuthorityViolation>();
        assert_sync::<AmbientAuthorityViolation>();
        assert_send::<AuthorityAuditGuard>();
        assert_sync::<AuthorityAuditGuard>();
        assert_send::<AuditEvent>();
        assert_sync::<AuditEvent>();
        assert_send::<ModuleAuditResult>();
        assert_sync::<ModuleAuditResult>();
        assert_send::<AuditReport>();
        assert_sync::<AuditReport>();
    }
}

#[cfg(test)]
mod authority_audit_comprehensive_negative_tests {
    use super::*;

    #[test]
    fn negative_capability_context_with_unicode_injection_attacks() {
        // Test with malicious Unicode patterns in context fields
        let malicious_contexts = vec![
            (
                "trace\u{202E}spoofed\u{202D}",
                "principal\u{0000}null\r\n\t\x1b[31mred\x1b[0m",
            ),
            (
                "trace\u{FEFF}\u{200B}\u{200C}\u{200D}",
                "principal\u{10FFFF}\u{E000}\u{FDD0}",
            ),
            (
                "trace\"\\escape\r\n",
                "principal<script>alert('xss')</script>",
            ),
            ("trace' OR '1'='1' --", "principal\u{FFFD}\u{FFFD}"),
            (
                "trace\x00\x01\x02\x03\x04",
                "principal\u{202A}bidi\u{202B}isolate\u{202C}",
            ),
        ];

        for (malicious_trace, malicious_principal) in malicious_contexts {
            let ctx = CapabilityContext::new(
                &[Capability::KeyAccess, Capability::ArtifactSigning],
                malicious_trace,
                malicious_principal,
            );

            // Verify malicious content is preserved exactly
            assert_eq!(ctx.trace_id, malicious_trace);
            assert_eq!(ctx.principal, malicious_principal);
            assert!(ctx.has_capability(&Capability::KeyAccess));

            // Test serialization preserves malicious content
            let json = serde_json::to_string(&ctx).unwrap();
            let deserialized: CapabilityContext = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.trace_id, malicious_trace);
            assert_eq!(deserialized.principal, malicious_principal);
        }
    }

    #[test]
    fn negative_security_critical_module_with_malicious_paths_and_descriptions() {
        let mut inventory = SecurityCriticalInventory::new();

        // Test with various malicious module paths and descriptions
        let malicious_modules = vec![
            (
                "crate::security\u{202E}::evil\u{202D}::legitimate",
                "Description with\r\n\tHTTP/1.1 200 OK\r\n\r\n<html>injection",
                vec!["key_access\u{FEFF}".to_string()],
                "critical\u{200B}",
            ),
            (
                "../../../etc/passwd\x00malicious",
                "XSS<script>alert('audit')</script>description",
                vec!["network_egress\x00null".to_string()],
                "high\r\ninjection",
            ),
            (
                "crate::security::unicode\u{10FFFF}\u{E000}",
                "BiDi\u{202A}attack\u{202C}description",
                vec!["file_system_read\"quotes".to_string()],
                "medium' OR '1'='1' --",
            ),
        ];

        for (path, description, capabilities, risk_level) in malicious_modules {
            let malicious_module = SecurityCriticalModule {
                module_path: path.to_string(),
                required_capabilities: capabilities.clone(),
                risk_level: risk_level.to_string(),
                description: description.to_string(),
            };

            inventory.add_module(malicious_module);

            // Verify malicious content preserved in inventory
            let stored_module = inventory.modules.get(path).unwrap();
            assert_eq!(stored_module.module_path, path);
            assert_eq!(stored_module.description, description);
            assert_eq!(stored_module.required_capabilities, capabilities);
            assert_eq!(stored_module.risk_level, risk_level);
        }

        // Test inventory serialization with malicious content
        let json = serde_json::to_string(&inventory).unwrap();
        let deserialized: SecurityCriticalInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.module_count(), inventory.module_count());
    }

    #[test]
    fn negative_authority_audit_guard_with_massive_event_stress_testing() {
        let mut guard = AuthorityAuditGuard::with_default_inventory(true);

        // Generate massive number of events to test bounded storage
        for i in 0..MAX_EVENTS * 2 {
            let massive_ctx = CapabilityContext::new(
                &[], // Missing capabilities to trigger violations
                &format!("trace_massive_{}_{}", i, "x".repeat(1000)),
                &format!("principal_massive_{}_{}", i, "y".repeat(1000)),
            );

            // Each check generates multiple events
            let _ = guard.check_context(&format!("crate::security::stress_{}", i), &massive_ctx);
        }

        // Events should be bounded by MAX_EVENTS
        assert_eq!(guard.events().len(), MAX_EVENTS);

        // Violations should be bounded by MAX_VIOLATIONS
        assert!(guard.violations().len() <= MAX_VIOLATIONS);

        // Verify latest events are preserved
        let latest_events = &guard.events()[MAX_EVENTS - 10..];
        for event in latest_events {
            assert!(event.trace_id.contains("trace_massive_"));
        }
    }

    #[test]
    fn negative_ambient_authority_violation_display_injection_resistance() {
        // Test violation display with malicious content in all fields
        let malicious_violations = vec![
            AmbientAuthorityViolation {
                module_path: "crate::security\r\n\t\x1b[31mREDTEXT\x1b[0m".to_string(),
                pattern_id: "AA-PAT\u{202E}spoofed\u{202D}".to_string(),
                description: "Direct env access\u{0000}null\r\n".to_string(),
                location: Some("file.rs:42\u{FEFF}BOM".to_string()),
                error_code: "ERR_AA_AMBIENT_DETECTED\u{200B}zw".to_string(),
            },
            AmbientAuthorityViolation {
                module_path: "crate::security\"quotes'apostrophe\\backslash".to_string(),
                pattern_id: "AA-PAT<script>alert('xss')</script>".to_string(),
                description: "HTTP/1.1 200 OK\r\n\r\n<html>injection".to_string(),
                location: Some("evil.rs:1337' OR '1'='1' --".to_string()),
                error_code: "ERR_AA\u{10FFFF}\u{E000}UNICODE".to_string(),
            },
            AmbientAuthorityViolation {
                module_path: "crate::security\u{FFFD}\u{FFFD}surrogate".to_string(),
                pattern_id: "AA-PAT\u{202A}bidi\u{202B}isolate\u{202C}".to_string(),
                description: "Unicode\u{FDD0}nonchar\u{FFFE}injection".to_string(),
                location: None,
                error_code: "ERR_AA_\x00\x01\x02\x03CONTROL".to_string(),
            },
        ];

        for violation in malicious_violations {
            // Test display formatting safety
            let display_string = format!("{}", violation);
            assert!(display_string.contains(&violation.module_path));
            assert!(display_string.contains(&violation.pattern_id));
            assert!(display_string.contains(&violation.description));

            // Test code() method
            assert_eq!(violation.code(), violation.error_code);

            // Test serialization safety
            let json = serde_json::to_string(&violation).unwrap();
            let deserialized: AmbientAuthorityViolation = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, violation);
        }
    }

    #[test]
    fn negative_capability_context_manipulation_and_bypass_attempts() {
        // Test various capability manipulation attempts
        let mut ctx = CapabilityContext::new(
            &[Capability::NetworkEgress],
            "trace-manipulation",
            "principal-manipulation",
        );

        // Test case-sensitive capability checking
        ctx.granted.insert("NETWORK_EGRESS".to_string(), true); // Wrong case
        ctx.granted.insert("network_egress".to_string(), false); // Explicit false
        assert!(!ctx.has_capability(&Capability::NetworkEgress));

        // Test capability injection attempts
        ctx.granted.insert("key_access\x00null".to_string(), true); // Null byte injection
        ctx.granted
            .insert("key_access\u{FEFF}bom".to_string(), true); // BOM injection
        ctx.granted.insert("key_access\u{200B}zw".to_string(), true); // Zero-width injection

        // None of these should satisfy the actual capability
        assert!(!ctx.has_capability(&Capability::KeyAccess));

        // Test missing capabilities with injection attempts
        let missing = ctx.missing_capabilities(&[
            Capability::KeyAccess,
            Capability::ArtifactSigning,
            Capability::NetworkEgress,
        ]);
        assert_eq!(missing.len(), 3); // All should be missing

        // Test has_all with malicious granted map
        ctx.granted.clear();
        ctx.granted.insert("key_access".to_string(), true);
        ctx.granted.insert("artifact_signing".to_string(), true);
        ctx.granted.insert("network_egress".to_string(), true);
        ctx.granted
            .insert("evil_capability_\u{202E}spoofed".to_string(), true);

        assert!(ctx.has_all(&[
            Capability::KeyAccess,
            Capability::ArtifactSigning,
            Capability::NetworkEgress,
        ]));
    }

    #[test]
    fn negative_ambient_authority_pattern_with_extreme_regex_and_descriptions() {
        // Test patterns with extreme and malicious content
        let malicious_patterns = vec![
            AmbientAuthorityPattern {
                id: "AA-PAT\u{202E}spoofed\u{202D}".to_string(),
                description: "Pattern with\r\n\tcontrol\x00chars\u{FEFF}".to_string(),
                pattern: r"std::env::var\b\u{200B}hidden".to_string(),
                severity: "critical\u{10FFFF}unicode".to_string(),
            },
            AmbientAuthorityPattern {
                id: "AA-PAT<script>alert('xss')</script>".to_string(),
                description: "XSS injection pattern\"quotes'apostrophe".to_string(),
                pattern: r"(.*){1000000}".to_string(), // Potentially catastrophic regex
                severity: "high\r\nHTTP/1.1 200 OK\r\n\r\n".to_string(),
            },
            AmbientAuthorityPattern {
                id: "AA-PAT\u{FFFD}\u{FFFD}".to_string(),
                description: "Unicode\u{FDD0}nonchar\u{FFFE}pattern".to_string(),
                pattern: r"std::(fs|net)::\b".to_string(),
                severity: "medium' OR '1'='1' --".to_string(),
            },
        ];

        for pattern in malicious_patterns {
            // Test serialization safety
            let json = serde_json::to_string(&pattern).unwrap();
            let deserialized: AmbientAuthorityPattern = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, pattern);

            // Verify malicious content preserved
            assert_eq!(deserialized.id, pattern.id);
            assert_eq!(deserialized.description, pattern.description);
            assert_eq!(deserialized.pattern, pattern.pattern);
            assert_eq!(deserialized.severity, pattern.severity);
        }

        // Test builtin patterns are safe
        let builtin = builtin_patterns();
        assert_eq!(builtin.len(), 6);
        for pattern in builtin {
            assert!(!pattern.id.is_empty());
            assert!(!pattern.description.is_empty());
            assert!(!pattern.pattern.is_empty());
            assert!(!pattern.severity.is_empty());
        }
    }

    #[test]
    fn negative_audit_event_with_massive_field_lengths_and_injection() {
        // Test events with extreme field sizes and injection patterns
        let massive_events = vec![
            AuditEvent {
                event_code: "FN-AA\u{202E}spoofed\u{202D}".repeat(1000),
                module_path: "crate::security::".to_string() + &"x".repeat(100000),
                detail: "Massive detail: ".to_string() + &"y".repeat(1000000), // 1MB detail
                trace_id: "trace\u{FEFF}\u{200B}\u{200C}\u{200D}".repeat(10000),
            },
            AuditEvent {
                event_code: "FN-AA<script>alert('xss')</script>".to_string(),
                module_path: "crate::security\r\nHTTP/1.1 200 OK\r\n\r\n".to_string(),
                detail: "XSS injection\"quotes'apostrophe\\backslash".to_string(),
                trace_id: "trace' OR '1'='1' --".to_string(),
            },
            AuditEvent {
                event_code: "FN-AA\x00\x01\x02\x03\x04".to_string(),
                module_path: "crate::security\u{FFFD}\u{FFFD}".to_string(),
                detail: "Control\u{FDD0}chars\u{FFFE}detail".to_string(),
                trace_id: "trace\u{10FFFF}\u{E000}".to_string(),
            },
        ];

        for event in massive_events {
            // Test serialization with massive content
            let json = serde_json::to_string(&event).unwrap();
            let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, event);

            // Verify field lengths preserved
            if event.detail.len() > 1000000 {
                assert_eq!(deserialized.detail.len(), event.detail.len());
            }
        }

        // Test push_bounded with massive events
        let mut events = Vec::new();
        for i in 0..100 {
            push_bounded(
                &mut events,
                AuditEvent {
                    event_code: format!("MASSIVE-{}", i),
                    module_path: "x".repeat(10000),
                    detail: "y".repeat(100000), // 100KB each
                    trace_id: "z".repeat(1000),
                },
                50,
            );
        }
        assert_eq!(events.len(), 50);
    }

    #[test]
    fn negative_risk_level_and_capability_enum_serialization_tampering() {
        // Test RiskLevel with invalid serialization attempts
        let invalid_risk_levels = [
            "\"Critical\"",   // Wrong case
            "\"CRITICAL\"",   // All caps
            "\"ultra_high\"", // Non-existent level
            "\"\"",           // Empty string
            "null",
            "42",
            "true",
            "{}",
            "[]",
        ];

        for invalid_json in invalid_risk_levels {
            let result: Result<RiskLevel, _> = serde_json::from_str(invalid_json);
            assert!(
                result.is_err(),
                "Should reject invalid RiskLevel: {}",
                invalid_json
            );
        }

        // Test Capability with invalid serialization attempts
        let invalid_capabilities = [
            "\"KeyAccess\"",          // Wrong case
            "\"KEY_ACCESS\"",         // Wrong format
            "\"unknown_capability\"", // Non-existent
            "\"network-egress\"",     // Wrong separator
            "\"\"",
            "null",
            "false",
        ];

        for invalid_json in invalid_capabilities {
            let result: Result<Capability, _> = serde_json::from_str(invalid_json);
            assert!(
                result.is_err(),
                "Should reject invalid Capability: {}",
                invalid_json
            );
        }

        // Test valid round-trips still work
        for risk_level in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let json = serde_json::to_string(&risk_level).unwrap();
            let parsed: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, risk_level);
        }

        for capability in Capability::all() {
            let json = serde_json::to_string(capability).unwrap();
            let parsed: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *capability);
        }
    }

    #[test]
    fn negative_audit_report_with_malicious_content_and_extreme_sizes() {
        // Create audit report with malicious module results
        let mut malicious_module_results = BTreeMap::new();

        // Add results with malicious module paths
        let malicious_paths = vec![
            "crate::security\u{202E}spoofed\u{202D}::module",
            "crate::security\r\nHTTP/1.1 200 OK\r\n\r\n::module",
            "crate::security\x00null\u{FEFF}bom::module",
            "../../../etc/passwd\u{10FFFF}::module",
            "crate::security\"quotes'apostrophe\\backslash::module",
        ];

        for path in malicious_paths {
            malicious_module_results.insert(
                path.to_string(),
                ModuleAuditResult {
                    module_path: path.to_string(),
                    passed: false,
                    violation: Some(AmbientAuthorityViolation {
                        module_path: path.to_string(),
                        pattern_id: "AA-PAT\u{202A}bidi\u{202C}".to_string(),
                        description: "Malicious\u{FDD0}violation".to_string(),
                        location: Some("evil.rs:1337\u{200B}".to_string()),
                        error_code: "ERR_AA_EVIL\u{FFFD}\u{FFFD}".to_string(),
                    }),
                },
            );
        }

        // Create massive events and violations arrays
        let mut massive_events = Vec::new();
        let mut massive_violations = Vec::new();

        for i in 0..1000 {
            massive_events.push(AuditEvent {
                event_code: format!("FN-AA-{:03}", i),
                module_path: format!("crate::security::module_{}", "x".repeat(1000)),
                detail: format!("Detail {}: {}", i, "y".repeat(10000)),
                trace_id: format!("trace_{}_{}", i, "z".repeat(100)),
            });

            massive_violations.push(AmbientAuthorityViolation {
                module_path: format!("crate::security::violation_{}", "a".repeat(1000)),
                pattern_id: format!("AA-PAT-{:03}", i),
                description: format!("Violation {}: {}", i, "b".repeat(5000)),
                location: Some(format!("file_{}.rs:{}", i, "c".repeat(100))),
                error_code: format!("ERR_AA_{}", "d".repeat(500)),
            });
        }

        let malicious_report = AuditReport {
            schema_version: "aa\u{FEFF}bom\u{200B}zw".to_string(),
            total_modules: usize::MAX,
            passed: usize::MAX - 1,
            failed: 1,
            verdict: "FAIL\r\n\tHTTP/1.1 200 OK\r\n\r\n".to_string(),
            module_results: malicious_module_results,
            events: massive_events,
            violations: massive_violations,
        };

        // Test serialization with malicious and massive content
        let json = serde_json::to_string(&malicious_report).unwrap();
        let deserialized: AuditReport = serde_json::from_str(&json).unwrap();

        // Verify malicious content preserved
        assert!(deserialized.schema_version.contains("aa"));
        assert!(deserialized.verdict.contains("FAIL"));
        assert_eq!(deserialized.total_modules, usize::MAX);
        assert_eq!(deserialized.events.len(), 1000);
        assert_eq!(deserialized.violations.len(), 1000);

        // Test summary with malicious content
        let summary = deserialized.summary();
        assert!(summary.contains("AuditReport"));
        assert!(summary.contains(&format!("{}", usize::MAX)));
    }

    #[test]
    fn negative_authority_audit_guard_concurrent_stress_and_race_conditions() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let guard = Arc::new(Mutex::new(AuthorityAuditGuard::with_default_inventory(
            true,
        )));
        let mut handles = vec![];

        // Spawn multiple threads performing concurrent operations
        for thread_id in 0..8 {
            let guard_clone = Arc::clone(&guard);
            let handle = thread::spawn(move || {
                for op_id in 0..100 {
                    let malicious_ctx = CapabilityContext::new(
                        &[], // Missing capabilities
                        &format!("trace_thread_{}_{}_{}", thread_id, op_id, "x".repeat(100)),
                        &format!(
                            "principal_thread_{}_{}_{}",
                            thread_id,
                            op_id,
                            "y".repeat(100)
                        ),
                    );

                    let mut guard = guard_clone.lock().unwrap();
                    let _ = guard.check_context(
                        &format!("crate::security::thread_{}_{}", thread_id, op_id),
                        &malicious_ctx,
                    );

                    // Test inventory manipulation attempts
                    if op_id % 10 == 0 {
                        guard.inventory.add_module(SecurityCriticalModule {
                            module_path: format!(
                                "crate::security::concurrent_{}_{}",
                                thread_id, op_id
                            ),
                            required_capabilities: vec!["key_access".to_string()],
                            risk_level: "critical".to_string(),
                            description: "concurrent test module".to_string(),
                        });
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state consistency
        let guard = guard.lock().unwrap();
        assert_eq!(guard.events().len(), MAX_EVENTS); // Should be bounded
        assert!(guard.violations().len() <= MAX_VIOLATIONS); // Should be bounded
        assert!(guard.inventory.module_count() >= 8); // Original modules + some added
    }

    #[test]
    fn negative_push_bounded_with_extreme_capacity_and_overflow_scenarios() {
        // Test push_bounded with various extreme scenarios
        let mut items = Vec::new();

        // Test with usize::MAX capacity
        push_bounded(&mut items, "test1".to_string(), usize::MAX);
        push_bounded(&mut items, "test2".to_string(), usize::MAX);
        assert_eq!(items.len(), 2);

        // Test overflow calculation with extreme values
        let mut large_items: Vec<String> = (0..1000).map(|i| format!("item_{}", i)).collect();

        // Test with capacity 1 (extreme drain)
        push_bounded(&mut large_items, "final_item".to_string(), 1);
        assert_eq!(large_items, vec!["final_item".to_string()]);

        // Test with massive items to check memory behavior
        let mut massive_items: Vec<Vec<u8>> = Vec::new();
        for i in 0..100 {
            massive_items.push(vec![i as u8; 100000]); // 100KB each
        }

        push_bounded(&mut massive_items, vec![255u8; 100000], 50);
        assert_eq!(massive_items.len(), 50);
        assert_eq!(massive_items[0], vec![51u8; 100000]); // First remaining
        assert_eq!(massive_items[49], vec![255u8; 100000]); // New item

        // Test edge case where items.len() == cap
        let mut exact_items = vec!["a", "b", "c"];
        push_bounded(&mut exact_items, "d", 3);
        assert_eq!(exact_items, vec!["b", "c", "d"]);
    }

    #[test]
    fn negative_generate_audit_report_with_malformed_context_and_extreme_inventory() {
        // Test with malformed context containing extreme values
        let malformed_ctx = CapabilityContext {
            granted: {
                let mut granted = BTreeMap::new();
                // Add 10,000 malformed capability grants
                for i in 0..10000 {
                    granted.insert(
                        format!("malformed_cap_{}_{}", i, "x".repeat(100)),
                        i % 2 == 0,
                    );
                }
                // Add some valid capabilities with malicious keys
                granted.insert("key_access\u{FEFF}bom".to_string(), false);
                granted.insert("network_egress\x00null".to_string(), false);
                granted.insert("file_system_read\u{202E}spoofed".to_string(), false);
                granted
            },
            trace_id: "trace\u{10FFFF}".repeat(10000), // ~40KB trace ID
            principal: "principal\u{FFFD}\u{FFFD}".repeat(5000), // ~20KB principal
        };

        // Generate report in both strict and advisory modes
        let strict_report = generate_audit_report(&malformed_ctx, true);
        let advisory_report = generate_audit_report(&malformed_ctx, false);

        // Verify reports handle malformed context
        assert_eq!(strict_report.verdict, "FAIL");
        assert_eq!(advisory_report.verdict, "PASS");

        // Both should have same total modules (default inventory)
        assert_eq!(strict_report.total_modules, advisory_report.total_modules);
        assert_eq!(strict_report.total_modules, 8); // Default inventory size

        // Events should contain malformed trace IDs
        for event in strict_report.events.iter().take(10) {
            assert!(event.trace_id.contains("trace"));
            assert!(event.trace_id.len() > 10000); // Massive trace ID preserved
        }

        // Test report serialization with malformed content
        let json = serde_json::to_string(&strict_report).unwrap();
        assert!(json.len() > 1000000); // Should be massive due to malformed content

        let deserialized: AuditReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_modules, strict_report.total_modules);
    }
}
