//! bd-novi: Stable error code namespace with machine-readable recovery contract.
//!
//! Error codes are unique, namespaced by subsystem (`FRANKEN_{SUBSYSTEM}_{CODE}`),
//! and frozen once registered.  Non-fatal errors carry `retryable`, `retry_after_ms`,
//! and `recovery_hint` metadata.

use std::collections::HashMap;
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
    "PROTOCOL", "CAPABILITY", "EGRESS", "SECURITY",
    "CONNECTOR", "RUNTIME", "SUPPLY_CHAIN", "CONFORMANCE",
];

/// Extract the subsystem from a FRANKEN_{SUBSYSTEM}_{REST} code.
fn parse_subsystem(code: &str) -> Option<String> {
    let rest = code.strip_prefix("FRANKEN_")?;
    for &sub in VALID_SUBSYSTEMS {
        if let Some(after) = rest.strip_prefix(sub) {
            if after.starts_with('_') && after.len() > 1 {
                return Some(sub.to_string());
            }
        }
    }
    None
}

// ── Registry ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ErrorCodeRegistry {
    entries: HashMap<String, ErrorCodeEntry>,
}

impl ErrorCodeRegistry {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Register a new error code.
    ///
    /// Enforces INV-ECR-NAMESPACED, INV-ECR-UNIQUE, INV-ECR-RECOVERY.
    pub fn register(&mut self, reg: &ErrorCodeRegistration) -> Result<ErrorCodeEntry, RegistryError> {
        // INV-ECR-NAMESPACED
        let subsystem = parse_subsystem(&reg.code).ok_or_else(|| {
            RegistryError::InvalidNamespace(reg.code.clone())
        })?;

        // INV-ECR-FROZEN — if already exists and frozen, check for conflict
        if let Some(existing) = self.entries.get(&reg.code) {
            if existing.frozen {
                let same_severity = existing.severity == reg.severity;
                let same_recovery = existing.recovery == reg.recovery;
                if !same_severity || !same_recovery {
                    return Err(RegistryError::FrozenConflict(reg.code.clone()));
                }
                // Same shape — allow version bump only.
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
        if !reg.severity.is_fatal() {
            if reg.recovery.recovery_hint.is_empty() {
                return Err(RegistryError::MissingRecovery(reg.code.clone()));
            }
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
        let entry = self.entries.get_mut(code).ok_or_else(|| {
            RegistryError::NotFound(code.to_string())
        })?;
        entry.frozen = true;
        Ok(())
    }

    /// Look up an error code entry.
    pub fn get(&self, code: &str) -> Option<&ErrorCodeEntry> {
        self.entries.get(code)
    }

    /// List all entries for a given subsystem.
    pub fn list_by_subsystem(&self, subsystem: &str) -> Vec<&ErrorCodeEntry> {
        let mut out: Vec<_> = self.entries.values().filter(|e| e.subsystem == subsystem).collect();
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
        let e = r.register(&reg(
            "FRANKEN_PROTOCOL_AUTH_TIMEOUT",
            Severity::Transient,
            recovery(true, Some(1000), "retry with backoff"),
            1,
        )).unwrap();
        assert_eq!(e.subsystem, "PROTOCOL");
        assert!(e.recovery.retryable);
    }

    #[test]
    fn register_valid_fatal() {
        let mut r = ErrorCodeRegistry::new();
        let e = r.register(&reg(
            "FRANKEN_SECURITY_KEY_COMPROMISED",
            Severity::Fatal,
            recovery(false, None, ""),
            1,
        )).unwrap();
        assert!(e.severity.is_fatal());
        assert!(!e.recovery.retryable);
    }

    #[test]
    fn reject_invalid_namespace() {
        let mut r = ErrorCodeRegistry::new();
        let err = r.register(&reg(
            "BAD_PREFIX_FOO",
            Severity::Transient,
            recovery(true, None, "hint"),
            1,
        )).unwrap_err();
        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
    }

    #[test]
    fn reject_unknown_subsystem() {
        let mut r = ErrorCodeRegistry::new();
        let err = r.register(&reg(
            "FRANKEN_UNKNOWN_FOO",
            Severity::Transient,
            recovery(true, None, "hint"),
            1,
        )).unwrap_err();
        assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
    }

    #[test]
    fn reject_duplicate_code() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg(
            "FRANKEN_PROTOCOL_DUP",
            Severity::Transient,
            recovery(true, None, "retry"),
            1,
        )).unwrap();
        let err = r.register(&reg(
            "FRANKEN_PROTOCOL_DUP",
            Severity::Transient,
            recovery(true, None, "retry"),
            1,
        )).unwrap_err();
        assert_eq!(err.code(), "ECR_DUPLICATE_CODE");
    }

    #[test]
    fn reject_missing_recovery_hint_non_fatal() {
        let mut r = ErrorCodeRegistry::new();
        let err = r.register(&reg(
            "FRANKEN_EGRESS_TIMEOUT",
            Severity::Degraded,
            recovery(true, Some(500), ""),
            1,
        )).unwrap_err();
        assert_eq!(err.code(), "ECR_MISSING_RECOVERY");
    }

    #[test]
    fn reject_fatal_marked_retryable() {
        let mut r = ErrorCodeRegistry::new();
        let err = r.register(&reg(
            "FRANKEN_SECURITY_FATAL_BAD",
            Severity::Fatal,
            recovery(true, Some(100), "should not retry"),
            1,
        )).unwrap_err();
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
        )).unwrap();
        r.freeze("FRANKEN_CONNECTOR_LEASE_EXPIRED").unwrap();

        // Same shape — OK (version bump)
        let e = r.register(&reg(
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            Severity::Transient,
            recovery(true, Some(2000), "renegotiate lease"),
            2,
        )).unwrap();
        assert_eq!(e.version, 2);

        // Different severity — rejected
        let err = r.register(&reg(
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            Severity::Fatal,
            recovery(false, None, ""),
            3,
        )).unwrap_err();
        assert_eq!(err.code(), "ECR_FROZEN_CONFLICT");
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
        )).unwrap();
        let e = r.get("FRANKEN_CAPABILITY_NOT_FOUND").unwrap();
        assert_eq!(e.subsystem, "CAPABILITY");
    }

    #[test]
    fn list_by_subsystem() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg("FRANKEN_PROTOCOL_A", Severity::Transient, recovery(true, None, "a"), 1)).unwrap();
        r.register(&reg("FRANKEN_PROTOCOL_B", Severity::Transient, recovery(true, None, "b"), 1)).unwrap();
        r.register(&reg("FRANKEN_SECURITY_C", Severity::Fatal, recovery(false, None, ""), 1)).unwrap();
        let protos = r.list_by_subsystem("PROTOCOL");
        assert_eq!(protos.len(), 2);
    }

    #[test]
    fn catalog_sorted() {
        let mut r = ErrorCodeRegistry::new();
        r.register(&reg("FRANKEN_SECURITY_Z", Severity::Fatal, recovery(false, None, ""), 1)).unwrap();
        r.register(&reg("FRANKEN_PROTOCOL_A", Severity::Transient, recovery(true, None, "a"), 1)).unwrap();
        let cat = r.catalog();
        assert_eq!(cat[0].code, "FRANKEN_PROTOCOL_A");
        assert_eq!(cat[1].code, "FRANKEN_SECURITY_Z");
    }

    #[test]
    fn len_and_is_empty() {
        let mut r = ErrorCodeRegistry::new();
        assert!(r.is_empty());
        r.register(&reg("FRANKEN_RUNTIME_INIT", Severity::Fatal, recovery(false, None, ""), 1)).unwrap();
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
        let errors = vec![
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
        assert_eq!(parse_subsystem("FRANKEN_PROTOCOL_FOO"), Some("PROTOCOL".into()));
        assert_eq!(parse_subsystem("FRANKEN_CAPABILITY_BAR"), Some("CAPABILITY".into()));
        assert_eq!(parse_subsystem("FRANKEN_EGRESS_BAZ"), Some("EGRESS".into()));
        assert_eq!(parse_subsystem("FRANKEN_SECURITY_QUX"), Some("SECURITY".into()));
        assert_eq!(parse_subsystem("FRANKEN_CONNECTOR_X"), Some("CONNECTOR".into()));
        assert_eq!(parse_subsystem("FRANKEN_RUNTIME_Y"), Some("RUNTIME".into()));
        assert_eq!(parse_subsystem("FRANKEN_SUPPLY_CHAIN_Z"), Some("SUPPLY_CHAIN".into()));
        assert_eq!(parse_subsystem("FRANKEN_CONFORMANCE_W"), Some("CONFORMANCE".into()));
        assert_eq!(parse_subsystem("FRANKEN_INVALID_X"), None);
        assert_eq!(parse_subsystem("OTHER_PREFIX"), None);
    }
}
