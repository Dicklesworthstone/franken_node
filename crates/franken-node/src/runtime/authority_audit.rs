//! bd-3vm: Ambient-authority audit gate for product security-critical modules.
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
        self.events.push(AuditEvent {
            event_code: event_codes::FN_AA_001.to_string(),
            module_path: module_path.to_string(),
            detail: format!("audit started for module {module_path}"),
            trace_id: context.trace_id.clone(),
        });

        let module = match self.inventory.modules.get(module_path) {
            Some(m) => m.clone(),
            None => {
                // Module not in inventory; no restrictions apply.
                self.events.push(AuditEvent {
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
            self.events.push(AuditEvent {
                event_code: event_codes::FN_AA_004.to_string(),
                module_path: module_path.to_string(),
                detail: format!("all required capabilities present for {module_path}"),
                trace_id: context.trace_id.clone(),
            });
            self.events.push(AuditEvent {
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
            self.events.push(AuditEvent {
                event_code: event_codes::FN_AA_003.to_string(),
                module_path: module_path.to_string(),
                detail: format!(
                    "ambient authority violation: missing {}",
                    missing.join(", ")
                ),
                trace_id: context.trace_id.clone(),
            });
            self.events.push(AuditEvent {
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
            self.violations.push(violation.clone());
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

        self.events.push(AuditEvent {
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
