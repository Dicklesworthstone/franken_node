//! bd-novi: Stable error code namespace with machine-readable recovery contract.
//!
//! Error codes are unique, namespaced by subsystem (`FRANKEN_{SUBSYSTEM}_{CODE}`),
//! and frozen once registered.  Non-fatal errors carry `retryable`, `retry_after_ms`,
//! and `recovery_hint` metadata.

use std::collections::BTreeMap;
use std::fmt;

// ── Severity ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Unrecoverable — process should terminate or escalate.
    Fatal,
    /// Degraded but functional — operator should investigate.
    Degraded,
    /// Temporary condition — automatic retry is appropriate.
    Transient,
}

impl Severity {
    pub fn is_fatal(self) -> bool {
        matches!(self, Severity::Fatal)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Fatal => write!(f, "fatal"),
            Severity::Degraded => write!(f, "degraded"),
            Severity::Transient => write!(f, "transient"),
        }
    }
}

// ── Recovery info ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryInfo {
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub recovery_hint: String,
}

// ── Error code entry ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ErrorCodeEntry {
    pub code: String,
    pub subsystem: String,
    pub severity: Severity,
    pub recovery: RecoveryInfo,
    pub description: String,
    pub version: u32,
    pub frozen: bool,
}

// ── Registration request ────────────────────────────────────────────────────

pub struct ErrorCodeRegistration {
    pub code: String,
    pub severity: Severity,
    pub recovery: RecoveryInfo,
    pub description: String,
    pub version: u32,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// ECR_INVALID_NAMESPACE — code doesn't start with FRANKEN_{SUBSYSTEM}_.
    InvalidNamespace(String),
    /// ECR_DUPLICATE_CODE — code already registered.
    DuplicateCode(String),
    /// ECR_MISSING_RECOVERY — non-fatal error missing recovery fields.
    MissingRecovery(String),
    /// ECR_FROZEN_CONFLICT — re-registration conflicts with frozen entry.
    FrozenConflict(String),
    /// ECR_NOT_FOUND — code not in registry.
    NotFound(String),
}

impl RegistryError {
    pub fn code(&self) -> &'static str {
        match self {
            RegistryError::InvalidNamespace(_) => "ECR_INVALID_NAMESPACE",
            RegistryError::DuplicateCode(_) => "ECR_DUPLICATE_CODE",
            RegistryError::MissingRecovery(_) => "ECR_MISSING_RECOVERY",
            RegistryError::FrozenConflict(_) => "ECR_FROZEN_CONFLICT",
            RegistryError::NotFound(_) => "ECR_NOT_FOUND",
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::InvalidNamespace(c) => write!(f, "ECR_INVALID_NAMESPACE: {c}"),
            RegistryError::DuplicateCode(c) => write!(f, "ECR_DUPLICATE_CODE: {c}"),
            RegistryError::MissingRecovery(c) => write!(f, "ECR_MISSING_RECOVERY: {c}"),
            RegistryError::FrozenConflict(c) => write!(f, "ECR_FROZEN_CONFLICT: {c}"),
            RegistryError::NotFound(c) => write!(f, "ECR_NOT_FOUND: {c}"),
        }
    }
}

// ── Valid subsystems ────────────────────────────────────────────────────────

const VALID_SUBSYSTEMS: &[&str] = &[
    "PROTOCOL",
    "CAPABILITY",
    "EGRESS",
    "SECURITY",
    "CONNECTOR",
    "RUNTIME",
    "SUPPLY_CHAIN",
    "CONFORMANCE",
];

/// Extract the subsystem from a FRANKEN_{SUBSYSTEM}_{REST} code.
fn parse_subsystem(code: &str) -> Option<String> {
    let rest = code.strip_prefix("FRANKEN_")?;
    for &sub in VALID_SUBSYSTEMS {
        if let Some(after) = rest.strip_prefix(sub)
            && is_valid_code_suffix(after)
        {
            return Some(sub.to_string());
        }
    }
    None
}

fn is_valid_code_suffix(suffix_with_separator: &str) -> bool {
    let Some(suffix) = suffix_with_separator.strip_prefix('_') else {
        return false;
    };
    if suffix.is_empty() || suffix.starts_with('_') || suffix.ends_with('_') {
        return false;
    }
    suffix
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

// ── Registry ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ErrorCodeRegistry {
    entries: BTreeMap<String, ErrorCodeEntry>,
}

impl ErrorCodeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new error code.
    ///
    /// Enforces INV-ECR-NAMESPACED, INV-ECR-UNIQUE, INV-ECR-RECOVERY.
    pub fn register(
        &mut self,
        reg: &ErrorCodeRegistration,
    ) -> Result<ErrorCodeEntry, RegistryError> {
        // INV-ECR-NAMESPACED
        let subsystem = parse_subsystem(&reg.code)
            .ok_or_else(|| RegistryError::InvalidNamespace(reg.code.clone()))?;

        // INV-ECR-FROZEN — if already exists and frozen, check for conflict
        if let Some(existing) = self.entries.get(&reg.code) {
            if existing.frozen {
                let same_severity = existing.severity == reg.severity;
                let same_recovery = existing.recovery == reg.recovery;
                if !same_severity || !same_recovery {
                    return Err(RegistryError::FrozenConflict(reg.code.clone()));
                }
                // Same shape — allow version bump only (must be strictly increasing).
                if reg.version <= existing.version {
                    return Err(RegistryError::FrozenConflict(reg.code.clone()));
                }
                let mut updated = existing.clone();
                updated.version = reg.version;
                updated.description = reg.description.clone();
                self.entries.insert(reg.code.clone(), updated.clone());
                return Ok(updated);
            }
            // Not frozen — duplicate.
            return Err(RegistryError::DuplicateCode(reg.code.clone()));
        }

        // INV-ECR-RECOVERY — non-fatal must have recovery fields
        if !reg.severity.is_fatal() && reg.recovery.recovery_hint.trim().is_empty() {
            return Err(RegistryError::MissingRecovery(reg.code.clone()));
        }

        // Fatal errors must not be retryable
        if reg.severity.is_fatal() && reg.recovery.retryable {
            return Err(RegistryError::MissingRecovery(reg.code.clone()));
        }

        let entry = ErrorCodeEntry {
            code: reg.code.clone(),
            subsystem,
            severity: reg.severity,
            recovery: reg.recovery.clone(),
            description: reg.description.clone(),
            version: reg.version,
            frozen: false,
        };
        self.entries.insert(reg.code.clone(), entry.clone());
        Ok(entry)
    }

    /// Freeze an error code so its semantics cannot change.
    pub fn freeze(&mut self, code: &str) -> Result<(), RegistryError> {
        let entry = self
            .entries
            .get_mut(code)
            .ok_or_else(|| RegistryError::NotFound(code.to_string()))?;
        entry.frozen = true;
        Ok(())
    }

    /// Look up an error code entry.
    pub fn get(&self, code: &str) -> Option<&ErrorCodeEntry> {
        self.entries.get(code)
    }

    /// List all entries for a given subsystem.
    pub fn list_by_subsystem(&self, subsystem: &str) -> Vec<&ErrorCodeEntry> {
        let mut out: Vec<_> = self
            .entries
            .values()
            .filter(|e| e.subsystem == subsystem)
            .collect();
        out.sort_by(|a, b| a.code.cmp(&b.code));
        out
    }

    /// Export a catalog of all registered error codes.
    pub fn catalog(&self) -> Vec<ErrorCodeEntry> {
        let mut out: Vec<_> = self.entries.values().cloned().collect();
        out.sort_by(|a, b| a.code.cmp(&b.code));
        out
    }

    /// Total number of registered codes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery(retryable: bool, retry_ms: Option<u64>, hint: &str) -> RecoveryInfo {
        RecoveryInfo {
            retryable,
            retry_after_ms: retry_ms,
            recovery_hint: hint.to_string(),
        }
    }

    fn reg(code: &str, sev: Severity, rec: RecoveryInfo, version: u32) -> ErrorCodeRegistration {
        ErrorCodeRegistration {
            code: code.to_string(),
            severity: sev,
            recovery: rec,
            description: format!("Test: {code}"),
            version,
        }
    }

    #[test]
    fn register_valid_transient() {
        let mut r = ErrorCodeRegistry::new();
        let e = r
            .register(&reg(
                "FRANKEN_PROTOCOL_AUTH_TIMEOUT",
                Severity::Transient,
                recovery(true, Some(1000), "retry with backoff"),
                1,
            ))
            .unwrap();
        assert_eq!(e.subsystem, "PROTOCOL");
        assert!(e.recovery.retryable);
    }

    #[test]
    fn register_valid_fatal() {
        let mut r = ErrorCodeRegistry::new();
        let e = r
            .register(&reg(
                "FRANKEN_SECURITY_KEY_COMPROMISED",
                Severity::Fatal,
                recovery(false, None, ""),
                1,
            ))
            .unwrap();
        assert!(e.severity.is_fatal());
        assert!(!e.recovery.retryable);
    }

    #[test]
    fn reject_invalid_namespace() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "BAD_PREFIX_FOO",
                Severity::Transient,
                recovery(true, None, "hint"),
                1,
            ))
            .unwrap_err();
        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
    }

    #[test]
    fn reject_unknown_subsystem() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_UNKNOWN_FOO",
                Severity::Transient,
                recovery(true, None, "hint"),
                1,
            ))
            .unwrap_err();
        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
    }

    #[test]
    fn reject_missing_subsystem_after_franken_prefix() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.is_empty());
    }

    #[test]
    fn reject_subsystem_without_code_suffix() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_PROTOCOL",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.get("FRANKEN_PROTOCOL").is_none());
    }

    #[test]
    fn reject_subsystem_with_empty_code_suffix() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_PROTOCOL_",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn reject_partial_subsystem_prefix() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_SUPPLY_BAD",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.list_by_subsystem("SUPPLY_CHAIN").is_empty());
    }

    #[test]
    fn reject_duplicate_code() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_PROTOCOL_DUP",
            Severity::Transient,
            recovery(true, None, "retry"),
            1,
        ))
        .unwrap();
        let err = r
            .register(&reg(
                "FRANKEN_PROTOCOL_DUP",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();
        assert_eq!(err.code(), "ECR_DUPLICATE_CODE");
    }

    #[test]
    fn reject_missing_recovery_hint_non_fatal() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_EGRESS_TIMEOUT",
                Severity::Degraded,
                recovery(true, Some(500), ""),
                1,
            ))
            .unwrap_err();
        assert_eq!(err.code(), "ECR_MISSING_RECOVERY");
    }

    #[test]
    fn reject_fatal_marked_retryable() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_SECURITY_FATAL_BAD",
                Severity::Fatal,
                recovery(true, Some(100), "should not retry"),
                1,
            ))
            .unwrap_err();
        assert_eq!(err.code(), "ECR_MISSING_RECOVERY");
    }

    #[test]
    fn freeze_prevents_change() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            Severity::Transient,
            recovery(true, Some(2000), "renegotiate lease"),
            1,
        ))
        .unwrap();
        r.freeze("FRANKEN_CONNECTOR_LEASE_EXPIRED").unwrap();

        // Same shape — OK (version bump)
        let e = r
            .register(&reg(
                "FRANKEN_CONNECTOR_LEASE_EXPIRED",
                Severity::Transient,
                recovery(true, Some(2000), "renegotiate lease"),
                2,
            ))
            .unwrap();
        assert_eq!(e.version, 2);

        // Different severity — rejected
        let err = r
            .register(&reg(
                "FRANKEN_CONNECTOR_LEASE_EXPIRED",
                Severity::Fatal,
                recovery(false, None, ""),
                3,
            ))
            .unwrap_err();
        assert_eq!(err.code(), "ECR_FROZEN_CONFLICT");
    }

    #[test]
    fn frozen_entry_rejects_same_version_reregistration() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_CONNECTOR_STABLE",
            Severity::Transient,
            recovery(true, Some(2000), "renegotiate lease"),
            1,
        ))
        .unwrap();
        r.freeze("FRANKEN_CONNECTOR_STABLE").unwrap();

        let err = r
            .register(&reg(
                "FRANKEN_CONNECTOR_STABLE",
                Severity::Transient,
                recovery(true, Some(2000), "renegotiate lease"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_FROZEN_CONFLICT");
    }

    #[test]
    fn frozen_entry_rejects_lower_version_reregistration() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_RUNTIME_STABLE",
            Severity::Degraded,
            recovery(false, None, "operator investigation required"),
            2,
        ))
        .unwrap();
        r.freeze("FRANKEN_RUNTIME_STABLE").unwrap();

        let err = r
            .register(&reg(
                "FRANKEN_RUNTIME_STABLE",
                Severity::Degraded,
                recovery(false, None, "operator investigation required"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_FROZEN_CONFLICT");
        assert_eq!(r.get("FRANKEN_RUNTIME_STABLE").unwrap().version, 2);
    }

    #[test]
    fn frozen_entry_rejects_recovery_shape_change() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_PROTOCOL_RETRYABLE",
            Severity::Transient,
            recovery(true, Some(1000), "retry with backoff"),
            1,
        ))
        .unwrap();
        r.freeze("FRANKEN_PROTOCOL_RETRYABLE").unwrap();

        let err = r
            .register(&reg(
                "FRANKEN_PROTOCOL_RETRYABLE",
                Severity::Transient,
                recovery(false, None, "manual intervention required"),
                2,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_FROZEN_CONFLICT");
    }

    #[test]
    fn failed_duplicate_registration_does_not_replace_original_entry() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_CONFORMANCE_DUP",
            Severity::Transient,
            recovery(true, None, "retry conformance check"),
            1,
        ))
        .unwrap();

        let err = r
            .register(&reg(
                "FRANKEN_CONFORMANCE_DUP",
                Severity::Fatal,
                recovery(false, None, ""),
                99,
            ))
            .unwrap_err();

        let entry = r.get("FRANKEN_CONFORMANCE_DUP").unwrap();
        assert_eq!(err.code(), "ECR_DUPLICATE_CODE");
        assert_eq!(entry.severity, Severity::Transient);
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn reject_lowercase_franken_prefix_without_inserting_entry() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "franken_PROTOCOL_CASE",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.is_empty());
    }

    #[test]
    fn reject_lowercase_subsystem_without_inserting_entry() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_protocol_CASE",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn reject_valid_subsystem_prefix_without_separator() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_PROTOCOLX_BAD",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.get("FRANKEN_PROTOCOLX_BAD").is_none());
    }

    #[test]
    fn reject_code_suffix_with_trailing_whitespace_without_inserting_entry() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_PROTOCOL_BAD ",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.is_empty());
    }

    #[test]
    fn reject_code_suffix_with_embedded_newline() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_PROTOCOL_BAD\nLINE",
                Severity::Transient,
                recovery(true, None, "retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.get("FRANKEN_PROTOCOL_BAD\nLINE").is_none());
    }

    #[test]
    fn reject_code_suffix_with_lowercase_tail() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_RUNTIME_bad",
                Severity::Degraded,
                recovery(false, None, "operator review"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn reject_code_suffix_with_empty_middle_segment() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_CONNECTOR__BROKEN",
                Severity::Transient,
                recovery(true, None, "retry connector"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.is_empty());
    }

    #[test]
    fn reject_code_suffix_with_trailing_separator() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_SECURITY_BAD_",
                Severity::Fatal,
                recovery(false, None, ""),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.get("FRANKEN_SECURITY_BAD_").is_none());
    }

    #[test]
    fn reject_code_suffix_with_hyphen() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_SUPPLY_CHAIN_BAD-NAME",
                Severity::Transient,
                recovery(true, Some(100), "retry supply chain check"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.list_by_subsystem("SUPPLY_CHAIN").is_empty());
    }

    fn assert_malformed_suffix_is_rejected(code: &str) {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                code,
                Severity::Transient,
                recovery(true, Some(100), "retry after namespace fix"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert!(r.is_empty());
    }

    #[test]
    fn reject_code_suffix_with_dot() {
        assert_malformed_suffix_is_rejected("FRANKEN_PROTOCOL_BAD.NAME");
    }

    #[test]
    fn reject_code_suffix_with_slash() {
        assert_malformed_suffix_is_rejected("FRANKEN_PROTOCOL_BAD/NAME");
    }

    #[test]
    fn reject_code_suffix_with_colon() {
        assert_malformed_suffix_is_rejected("FRANKEN_PROTOCOL_BAD:NAME");
    }

    #[test]
    fn reject_code_suffix_with_nul_byte() {
        assert_malformed_suffix_is_rejected("FRANKEN_PROTOCOL_BAD\0NAME");
    }

    #[test]
    fn reject_code_suffix_with_non_ascii_letter() {
        assert_malformed_suffix_is_rejected("FRANKEN_PROTOCOL_BAD_é");
    }

    #[test]
    fn reject_code_suffix_with_embedded_space() {
        assert_malformed_suffix_is_rejected("FRANKEN_PROTOCOL_BAD NAME");
    }

    #[test]
    fn failed_invalid_namespace_preserves_existing_catalog() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_PROTOCOL_SEEDED",
            Severity::Transient,
            recovery(true, Some(25), "retry seeded protocol"),
            1,
        ))
        .unwrap();

        let err = r
            .register(&reg(
                " FRANKEN_PROTOCOL_BAD",
                Severity::Transient,
                recovery(true, Some(25), "retry after namespace fix"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert_eq!(r.len(), 1);
        assert!(r.get("FRANKEN_PROTOCOL_SEEDED").is_some());
        assert!(r.get(" FRANKEN_PROTOCOL_BAD").is_none());
    }

    #[test]
    fn failed_unknown_subsystem_preserves_existing_entry() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_RUNTIME_SEEDED",
            Severity::Degraded,
            recovery(false, None, "inspect runtime"),
            1,
        ))
        .unwrap();

        let err = r
            .register(&reg(
                "FRANKEN_RUNTIME_CONTROL_BAD",
                Severity::Transient,
                recovery(true, Some(10), "retry valid namespace"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.list_by_subsystem("RUNTIME")
                .first()
                .map(|entry| entry.code.as_str()),
            Some("FRANKEN_RUNTIME_SEEDED")
        );
        assert!(r.list_by_subsystem("RUNTIME_CONTROL").is_empty());
    }

    #[test]
    fn get_rejects_case_mismatch_without_normalization() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_CONNECTOR_CANONICAL",
            Severity::Transient,
            recovery(true, None, "retry connector"),
            1,
        ))
        .unwrap();

        assert!(r.get("franken_CONNECTOR_CANONICAL").is_none());
        assert!(r.get("FRANKEN_connector_CANONICAL").is_none());
        assert!(r.get("FRANKEN_CONNECTOR_canonical").is_none());
        assert!(r.get("FRANKEN_CONNECTOR_CANONICAL").is_some());
    }

    #[test]
    fn freeze_rejects_padded_code_without_matching_canonical_entry() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_SECURITY_CANONICAL",
            Severity::Fatal,
            recovery(false, None, ""),
            1,
        ))
        .unwrap();

        let err = r.freeze("FRANKEN_SECURITY_CANONICAL ").unwrap_err();

        assert_eq!(err.code(), "ECR_NOT_FOUND");
        assert!(r.get("FRANKEN_SECURITY_CANONICAL").is_some());
        assert!(!r.get("FRANKEN_SECURITY_CANONICAL").unwrap().frozen);
    }

    #[test]
    fn list_by_subsystem_rejects_noncanonical_subsystem_names() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_SUPPLY_CHAIN_CANONICAL",
            Severity::Transient,
            recovery(true, Some(100), "retry supply chain"),
            1,
        ))
        .unwrap();

        assert!(r.list_by_subsystem("supply_chain").is_empty());
        assert!(r.list_by_subsystem(" SUPPLY_CHAIN").is_empty());
        assert!(r.list_by_subsystem("SUPPLY_CHAIN ").is_empty());
        assert_eq!(r.list_by_subsystem("SUPPLY_CHAIN").len(), 1);
    }

    #[test]
    fn duplicate_with_higher_version_does_not_mutate_unfrozen_entry() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_EGRESS_DUP_VERSION",
            Severity::Transient,
            recovery(true, Some(100), "retry egress"),
            1,
        ))
        .unwrap();

        let err = r
            .register(&reg(
                "FRANKEN_EGRESS_DUP_VERSION",
                Severity::Transient,
                recovery(true, Some(500), "retry egress later"),
                2,
            ))
            .unwrap_err();

        let entry = r.get("FRANKEN_EGRESS_DUP_VERSION").unwrap();
        assert_eq!(err.code(), "ECR_DUPLICATE_CODE");
        assert_eq!(entry.version, 1);
        assert_eq!(entry.recovery.retry_after_ms, Some(100));
        assert_eq!(entry.recovery.recovery_hint, "retry egress");
    }

    #[test]
    fn reject_non_fatal_whitespace_only_recovery_hint() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_EGRESS_BLANK_HINT",
                Severity::Transient,
                recovery(true, Some(50), " \t\n"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_MISSING_RECOVERY");
        assert!(r.get("FRANKEN_EGRESS_BLANK_HINT").is_none());
    }

    #[test]
    fn reject_fatal_retryable_even_without_retry_after_hint() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_SECURITY_RETRY_FATAL",
                Severity::Fatal,
                recovery(true, None, "do not retry"),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_MISSING_RECOVERY");
        assert!(r.get("FRANKEN_SECURITY_RETRY_FATAL").is_none());
    }

    #[test]
    fn failed_missing_recovery_registration_does_not_insert_entry() {
        let mut r = ErrorCodeRegistry::new();
        let err = r
            .register(&reg(
                "FRANKEN_RUNTIME_MISSING_HINT",
                Severity::Transient,
                recovery(true, Some(10), ""),
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "ECR_MISSING_RECOVERY");
        assert!(r.is_empty());
    }

    #[test]
    fn failed_frozen_recovery_change_preserves_original_entry() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_CONNECTOR_FROZEN_RECOVERY",
            Severity::Transient,
            recovery(true, Some(250), "retry connector"),
            1,
        ))
        .unwrap();
        r.freeze("FRANKEN_CONNECTOR_FROZEN_RECOVERY").unwrap();

        let err = r
            .register(&reg(
                "FRANKEN_CONNECTOR_FROZEN_RECOVERY",
                Severity::Transient,
                recovery(true, Some(500), "retry slower"),
                2,
            ))
            .unwrap_err();

        let entry = r.get("FRANKEN_CONNECTOR_FROZEN_RECOVERY").unwrap();
        assert_eq!(err.code(), "ECR_FROZEN_CONFLICT");
        assert_eq!(entry.recovery.retry_after_ms, Some(250));
        assert_eq!(entry.recovery.recovery_hint, "retry connector");
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn freeze_not_found() {
        let mut r = ErrorCodeRegistry::new();
        let err = r.freeze("FRANKEN_PROTOCOL_NO_SUCH").unwrap_err();
        assert_eq!(err.code(), "ECR_NOT_FOUND");
    }

    #[test]
    fn get_entry() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_CAPABILITY_NOT_FOUND",
            Severity::Degraded,
            recovery(false, None, "check capability id"),
            1,
        ))
        .unwrap();
        let e = r.get("FRANKEN_CAPABILITY_NOT_FOUND").unwrap();
        assert_eq!(e.subsystem, "CAPABILITY");
    }

    #[test]
    fn list_by_subsystem() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_PROTOCOL_A",
            Severity::Transient,
            recovery(true, None, "a"),
            1,
        ))
        .unwrap();
        r.register(&reg(
            "FRANKEN_PROTOCOL_B",
            Severity::Transient,
            recovery(true, None, "b"),
            1,
        ))
        .unwrap();
        r.register(&reg(
            "FRANKEN_SECURITY_C",
            Severity::Fatal,
            recovery(false, None, ""),
            1,
        ))
        .unwrap();
        let protos = r.list_by_subsystem("PROTOCOL");
        assert_eq!(protos.len(), 2);
    }

    #[test]
    fn catalog_sorted() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_SECURITY_Z",
            Severity::Fatal,
            recovery(false, None, ""),
            1,
        ))
        .unwrap();
        r.register(&reg(
            "FRANKEN_PROTOCOL_A",
            Severity::Transient,
            recovery(true, None, "a"),
            1,
        ))
        .unwrap();
        let cat = r.catalog();
        assert_eq!(cat[0].code, "FRANKEN_PROTOCOL_A");
        assert_eq!(cat[1].code, "FRANKEN_SECURITY_Z");
    }

    #[test]
    fn len_and_is_empty() {
        let mut r = ErrorCodeRegistry::new();
        assert!(r.is_empty());
        r.register(&reg(
            "FRANKEN_RUNTIME_INIT",
            Severity::Fatal,
            recovery(false, None, ""),
            1,
        ))
        .unwrap();
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Fatal.to_string(), "fatal");
        assert_eq!(Severity::Degraded.to_string(), "degraded");
        assert_eq!(Severity::Transient.to_string(), "transient");
    }

    #[test]
    fn error_display() {
        let e = RegistryError::InvalidNamespace("bad".into());
        assert!(e.to_string().contains("ECR_INVALID_NAMESPACE"));
    }

    #[test]
    fn all_error_codes_present() {
        let errors = [
            RegistryError::InvalidNamespace("x".into()),
            RegistryError::DuplicateCode("x".into()),
            RegistryError::MissingRecovery("x".into()),
            RegistryError::FrozenConflict("x".into()),
            RegistryError::NotFound("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"ECR_INVALID_NAMESPACE"));
        assert!(codes.contains(&"ECR_DUPLICATE_CODE"));
        assert!(codes.contains(&"ECR_MISSING_RECOVERY"));
        assert!(codes.contains(&"ECR_FROZEN_CONFLICT"));
        assert!(codes.contains(&"ECR_NOT_FOUND"));
    }

    #[test]
    fn subsystem_parsing() {
        assert_eq!(
            parse_subsystem("FRANKEN_PROTOCOL_FOO"),
            Some("PROTOCOL".into())
        );
        assert_eq!(
            parse_subsystem("FRANKEN_CAPABILITY_BAR"),
            Some("CAPABILITY".into())
        );
        assert_eq!(parse_subsystem("FRANKEN_EGRESS_BAZ"), Some("EGRESS".into()));
        assert_eq!(
            parse_subsystem("FRANKEN_SECURITY_QUX"),
            Some("SECURITY".into())
        );
        assert_eq!(
            parse_subsystem("FRANKEN_CONNECTOR_X"),
            Some("CONNECTOR".into())
        );
        assert_eq!(parse_subsystem("FRANKEN_RUNTIME_Y"), Some("RUNTIME".into()));
        assert_eq!(
            parse_subsystem("FRANKEN_SUPPLY_CHAIN_Z"),
            Some("SUPPLY_CHAIN".into())
        );
        assert_eq!(
            parse_subsystem("FRANKEN_CONFORMANCE_W"),
            Some("CONFORMANCE".into())
        );
        assert_eq!(parse_subsystem("FRANKEN_INVALID_X"), None);
        assert_eq!(parse_subsystem("OTHER_PREFIX"), None);
    }
}
