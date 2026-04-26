//! bd-13q: Product-surface error namespace and compatibility policy.
//!
//! This module adopts the canonical 10.13 error registry as source of truth,
//! then projects stable surface-level representations for CLI/API/protocol/log/SDK.
//! It also provides compatibility checks for append-only error evolution.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::connector::error_code_registry::{ErrorCodeEntry, ErrorCodeRegistry, Severity};
use crate::connector::telemetry_namespace::{NamespaceError, SchemaRegistry};

pub const PRODUCT_SURFACE_PREFIXES: [&str; 6] = [
    "FN-CTRL-", "FN-MIG-", "FN-AUTH-", "FN-POL-", "FN-ZON-", "FN-TOK-",
];

pub const ENS_001: &str = "ENS-001";
pub const ENS_002: &str = "ENS-002";
pub const ENS_003: &str = "ENS-003";
pub const ENS_004: &str = "ENS-004";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProductSurface {
    ControlPlane,
    Migration,
    Auth,
    Policy,
    ZoneTenant,
    Token,
}

impl ProductSurface {
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::ControlPlane => "FN-CTRL-",
            Self::Migration => "FN-MIG-",
            Self::Auth => "FN-AUTH-",
            Self::Policy => "FN-POL-",
            Self::ZoneTenant => "FN-ZON-",
            Self::Token => "FN-TOK-",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCategory {
    Transient,
    Permanent,
    Configuration,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient => write!(f, "TRANSIENT"),
            Self::Permanent => write!(f, "PERMANENT"),
            Self::Configuration => write!(f, "CONFIGURATION"),
        }
    }
}

#[must_use]
pub fn category_for_severity(severity: Severity) -> ErrorCategory {
    match severity {
        Severity::Transient => ErrorCategory::Transient,
        Severity::Fatal => ErrorCategory::Permanent,
        Severity::Degraded => ErrorCategory::Configuration,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductError {
    pub canonical_code: String,
    pub surface_code: String,
    pub message: String,
    pub trace_id: String,
    pub category: ErrorCategory,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub recovery_hint: String,
    pub context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolErrorFrame {
    pub code: String,
    pub canonical_code: String,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkErrorPayload {
    pub code: String,
    pub canonical_code: String,
    pub category: String,
    pub retryable: bool,
    pub trace_id: String,
    pub message: String,
    pub context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductErrorBuildError {
    UnregisteredCode(String),
    MissingTraceId,
    MissingMessage,
    UnknownSurfacePrefix(String),
    RecoveryHintTooShort(String),
}

impl ProductErrorBuildError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnregisteredCode(_) => "ERR_PRODUCT_UNREGISTERED_CODE",
            Self::MissingTraceId => "ERR_PRODUCT_TRACE_ID_MISSING",
            Self::MissingMessage => "ERR_PRODUCT_MESSAGE_MISSING",
            Self::UnknownSurfacePrefix(_) => "ERR_PRODUCT_SURFACE_PREFIX_UNKNOWN",
            Self::RecoveryHintTooShort(_) => "ERR_PRODUCT_RECOVERY_HINT_TOO_SHORT",
        }
    }
}

impl fmt::Display for ProductErrorBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredCode(code) => write!(
                f,
                "ERR_PRODUCT_UNREGISTERED_CODE: canonical code not in registry: {code}"
            ),
            Self::MissingTraceId => write!(f, "ERR_PRODUCT_TRACE_ID_MISSING: trace_id is required"),
            Self::MissingMessage => write!(f, "ERR_PRODUCT_MESSAGE_MISSING: message is required"),
            Self::UnknownSurfacePrefix(prefix) => write!(
                f,
                "ERR_PRODUCT_SURFACE_PREFIX_UNKNOWN: unregistered surface prefix: {prefix}"
            ),
            Self::RecoveryHintTooShort(code) => write!(
                f,
                "ERR_PRODUCT_RECOVERY_HINT_TOO_SHORT: recovery hint too short for {code}"
            ),
        }
    }
}

impl ProductError {
    #[must_use]
    pub fn format_cli(&self) -> String {
        format!(
            "[{}] {} (canonical={}, retryable={}, trace={})",
            self.surface_code, self.message, self.canonical_code, self.retryable, self.trace_id
        )
    }

    #[must_use]
    pub fn format_json_api(&self) -> Value {
        serde_json::json!({
            "error_code": self.surface_code,
            "canonical_code": self.canonical_code,
            "message": self.message,
            "retryable": self.retryable,
            "retry_after_ms": self.retry_after_ms,
            "recovery_hint": self.recovery_hint,
            "trace_id": self.trace_id,
            "category": self.category.to_string(),
            "context": self.context,
        })
    }

    #[must_use]
    pub fn format_protocol_frame(&self) -> ProtocolErrorFrame {
        ProtocolErrorFrame {
            code: self.surface_code.clone(),
            canonical_code: self.canonical_code.clone(),
            retryable: self.retryable,
            retry_after_ms: self.retry_after_ms,
            trace_id: self.trace_id.clone(),
        }
    }

    #[must_use]
    pub fn format_log_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert("error.code".to_string(), self.canonical_code.clone());
        fields.insert("error.surface_code".to_string(), self.surface_code.clone());
        fields.insert("error.retryable".to_string(), self.retryable.to_string());
        fields.insert(
            "error.recovery_hint".to_string(),
            self.recovery_hint.clone(),
        );
        fields.insert("trace_id".to_string(), self.trace_id.clone());
        fields
    }

    #[must_use]
    pub fn format_sdk_payload(&self) -> SdkErrorPayload {
        SdkErrorPayload {
            code: self.surface_code.clone(),
            canonical_code: self.canonical_code.clone(),
            category: self.category.to_string(),
            retryable: self.retryable,
            trace_id: self.trace_id.clone(),
            message: self.message.clone(),
            context: self.context.clone(),
        }
    }
}

#[must_use]
pub fn is_registered_product_prefix(prefix: &str) -> bool {
    PRODUCT_SURFACE_PREFIXES.contains(&prefix)
}

fn build_surface_code(surface: ProductSurface, canonical_code: &str) -> String {
    format!("{}{}", surface.prefix(), canonical_code)
}

/// Build a product-surface error from a canonical registry code.
///
/// Invariants:
/// - INV-ENS-REGISTRY-SOURCE: canonical code must exist in registry.
/// - INV-ENS-RECOVERY-HINT: non-fatal codes require recovery_hint length >= 20.
/// - INV-ENS-PREFIX: every rendered surface code starts with registered FN-* prefix.
pub fn product_error(
    registry: &ErrorCodeRegistry,
    surface: ProductSurface,
    canonical_code: &str,
    message: &str,
    trace_id: &str,
    context: BTreeMap<String, String>,
) -> Result<ProductError, ProductErrorBuildError> {
    if trace_id.trim().is_empty() {
        return Err(ProductErrorBuildError::MissingTraceId);
    }
    if message.trim().is_empty() {
        return Err(ProductErrorBuildError::MissingMessage);
    }

    let entry = registry
        .get(canonical_code)
        .ok_or_else(|| ProductErrorBuildError::UnregisteredCode(canonical_code.to_string()))?;

    if entry.severity != Severity::Fatal && entry.recovery.recovery_hint.trim().len() < 20 {
        return Err(ProductErrorBuildError::RecoveryHintTooShort(
            canonical_code.to_string(),
        ));
    }

    let prefix = surface.prefix();
    if !is_registered_product_prefix(prefix) {
        return Err(ProductErrorBuildError::UnknownSurfacePrefix(
            prefix.to_string(),
        ));
    }

    Ok(ProductError {
        canonical_code: canonical_code.to_string(),
        surface_code: build_surface_code(surface, canonical_code),
        message: message.to_string(),
        trace_id: trace_id.to_string(),
        category: category_for_severity(entry.severity),
        retryable: entry.recovery.retryable,
        retry_after_ms: entry.recovery.retry_after_ms,
        recovery_hint: entry.recovery.recovery_hint.clone(),
        context,
    })
}

/// Build telemetry dimensions for an error metric.
///
/// Integration with 10.13 telemetry namespace:
/// - Metric name must validate via `SchemaRegistry::validate_name`.
/// - Error metrics always include the `error.code` dimension.
pub fn telemetry_error_dimensions(
    metric_name: &str,
    error: &ProductError,
) -> Result<BTreeMap<String, String>, NamespaceError> {
    SchemaRegistry::validate_name(metric_name)?;

    let mut labels = BTreeMap::new();
    labels.insert("error.code".to_string(), error.canonical_code.clone());
    labels.insert("error.surface_code".to_string(), error.surface_code.clone());
    labels.insert("error.category".to_string(), error.category.to_string());
    labels.insert("trace_id".to_string(), error.trace_id.clone());
    Ok(labels)
}

#[macro_export]
macro_rules! product_error {
    ($registry:expr, $surface:expr, $code:expr, $message:expr, $trace_id:expr, $context:expr $(,)?) => {
        $crate::connector::error_surface::product_error(
            $registry, $surface, $code, $message, $trace_id, $context,
        )
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorCompatibilityPolicy {
    pub enforce_append_only: bool,
    pub enforce_category_stability: bool,
    pub enforce_retryable_stability: bool,
    pub recovery_hint_min_len: usize,
}

impl Default for ErrorCompatibilityPolicy {
    fn default() -> Self {
        Self {
            enforce_append_only: true,
            enforce_category_stability: true,
            enforce_retryable_stability: true,
            recovery_hint_min_len: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityViolation {
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityReport {
    pub added: Vec<String>,
    pub unchanged: Vec<String>,
    pub violations: Vec<CompatibilityViolation>,
}

impl CompatibilityReport {
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Compare two registry snapshots for compatibility policy conformance.
#[must_use]
pub fn compatibility_report(
    old_entries: &[ErrorCodeEntry],
    new_entries: &[ErrorCodeEntry],
    policy: &ErrorCompatibilityPolicy,
) -> CompatibilityReport {
    let old_map: BTreeMap<&str, &ErrorCodeEntry> =
        old_entries.iter().map(|e| (e.code.as_str(), e)).collect();
    let new_map: BTreeMap<&str, &ErrorCodeEntry> =
        new_entries.iter().map(|e| (e.code.as_str(), e)).collect();

    let old_codes: BTreeSet<&str> = old_map.keys().copied().collect();
    let new_codes: BTreeSet<&str> = new_map.keys().copied().collect();

    let mut added: Vec<String> = new_codes
        .difference(&old_codes)
        .map(|c| (*c).to_string())
        .collect();
    let mut unchanged: Vec<String> = new_codes
        .intersection(&old_codes)
        .map(|c| (*c).to_string())
        .collect();
    let mut violations = Vec::new();

    added.sort();
    unchanged.sort();

    if policy.enforce_append_only {
        for removed in old_codes.difference(&new_codes) {
            violations.push(CompatibilityViolation {
                code: (*removed).to_string(),
                reason: "removed code violates append-only policy".to_string(),
            });
        }
    }

    for code in &unchanged {
        if let (Some(old), Some(new)) = (old_map.get(code.as_str()), new_map.get(code.as_str())) {
            if policy.enforce_category_stability
                && category_for_severity(old.severity) != category_for_severity(new.severity)
            {
                violations.push(CompatibilityViolation {
                    code: code.clone(),
                    reason: "category changed between versions".to_string(),
                });
            }

            if policy.enforce_retryable_stability
                && old.recovery.retryable != new.recovery.retryable
            {
                violations.push(CompatibilityViolation {
                    code: code.clone(),
                    reason: "retryable flag changed between versions".to_string(),
                });
            }
        }
    }

    for code in &added {
        if let Some(entry) = new_map.get(code.as_str()) {
            if entry.description.trim().is_empty() {
                violations.push(CompatibilityViolation {
                    code: code.clone(),
                    reason: "new code missing description".to_string(),
                });
            }

            if entry.severity != Severity::Fatal
                && entry.recovery.recovery_hint.trim().len() < policy.recovery_hint_min_len
            {
                violations.push(CompatibilityViolation {
                    code: code.clone(),
                    reason: "new code has recovery hint below policy minimum".to_string(),
                });
            }
        }
    }

    CompatibilityReport {
        added,
        unchanged,
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::error_code_registry::{ErrorCodeRegistration, RecoveryInfo};

    fn recovery(retryable: bool, retry_after_ms: Option<u64>, hint: &str) -> RecoveryInfo {
        RecoveryInfo {
            retryable,
            retry_after_ms,
            recovery_hint: hint.to_string(),
        }
    }

    fn register_entry(
        registry: &mut ErrorCodeRegistry,
        code: &str,
        severity: Severity,
        retryable: bool,
        retry_after_ms: Option<u64>,
        hint: &str,
        description: &str,
    ) {
        registry
            .register(&ErrorCodeRegistration {
                code: code.to_string(),
                severity,
                recovery: recovery(retryable, retry_after_ms, hint),
                description: description.to_string(),
                version: 1,
            })
            .expect("registration should succeed");
    }

    fn demo_registry() -> ErrorCodeRegistry {
        let mut registry = ErrorCodeRegistry::new();
        register_entry(
            &mut registry,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            Severity::Transient,
            true,
            Some(1000),
            "Re-authenticate with fresh credentials and retry request",
            "auth failed",
        );
        register_entry(
            &mut registry,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            Severity::Transient,
            true,
            Some(3000),
            "Re-negotiate lease with coordinator before issuing writes",
            "lease expired",
        );
        register_entry(
            &mut registry,
            "FRANKEN_CAPABILITY_NOT_AVAILABLE",
            Severity::Degraded,
            false,
            None,
            "Check capability registry, then recover capability provider",
            "capability missing",
        );
        registry
    }

    #[test]
    fn all_product_prefixes_present() {
        assert_eq!(PRODUCT_SURFACE_PREFIXES.len(), 6);
        assert!(is_registered_product_prefix("FN-CTRL-"));
        assert!(is_registered_product_prefix("FN-MIG-"));
        assert!(is_registered_product_prefix("FN-AUTH-"));
        assert!(is_registered_product_prefix("FN-POL-"));
        assert!(is_registered_product_prefix("FN-ZON-"));
        assert!(is_registered_product_prefix("FN-TOK-"));
    }

    #[test]
    fn product_error_builds_for_registered_code() {
        let registry = demo_registry();
        let mut context = BTreeMap::new();
        context.insert("endpoint".to_string(), "/api/sessions".to_string());

        let err = product_error(
            &registry,
            ProductSurface::ControlPlane,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            "session auth failed",
            "trace-1",
            context,
        )
        .expect("build should succeed");

        assert_eq!(err.surface_code, "FN-CTRL-FRANKEN_PROTOCOL_AUTH_FAILED");
        assert!(err.retryable);
        assert_eq!(err.category, ErrorCategory::Transient);
    }

    #[test]
    fn product_error_rejects_unknown_code() {
        let registry = demo_registry();
        let result = product_error(
            &registry,
            ProductSurface::Migration,
            "FRANKEN_UNKNOWN_CODE",
            "bad",
            "trace-2",
            BTreeMap::new(),
        );
        assert!(matches!(
            result,
            Err(ProductErrorBuildError::UnregisteredCode(_))
        ));
    }

    #[test]
    fn product_error_rejects_missing_trace_id() {
        let registry = demo_registry();
        let result = product_error(
            &registry,
            ProductSurface::Migration,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            "lease expired",
            "",
            BTreeMap::new(),
        );
        assert!(matches!(
            result,
            Err(ProductErrorBuildError::MissingTraceId)
        ));
    }

    #[test]
    fn product_error_rejects_whitespace_trace_id() {
        let registry = demo_registry();
        let result = product_error(
            &registry,
            ProductSurface::Migration,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            "lease expired",
            "   ",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::MissingTraceId)
        ));
    }

    #[test]
    fn product_error_rejects_empty_message() {
        let registry = demo_registry();
        let result = product_error(
            &registry,
            ProductSurface::Auth,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            "",
            "trace-empty-message",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::MissingMessage)
        ));
    }

    #[test]
    fn product_error_rejects_whitespace_message() {
        let registry = demo_registry();
        let result = product_error(
            &registry,
            ProductSurface::Auth,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            "\t \n",
            "trace-blank-message",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::MissingMessage)
        ));
    }

    #[test]
    fn product_error_rejects_short_recovery_hint_for_nonfatal_code() {
        let mut registry = ErrorCodeRegistry::new();
        register_entry(
            &mut registry,
            "FRANKEN_EGRESS_SHORT_HINT",
            Severity::Transient,
            true,
            Some(100),
            "retry",
            "short hint",
        );

        let result = product_error(
            &registry,
            ProductSurface::ControlPlane,
            "FRANKEN_EGRESS_SHORT_HINT",
            "egress failed",
            "trace-short-hint",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::RecoveryHintTooShort(code))
                if code == "FRANKEN_EGRESS_SHORT_HINT"
        ));
    }

    #[test]
    fn formatters_keep_retryable_consistent() {
        let registry = demo_registry();
        let err = product_error(
            &registry,
            ProductSurface::Auth,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            "auth failed",
            "trace-3",
            BTreeMap::new(),
        )
        .expect("build should succeed");

        let cli = err.format_cli();
        assert!(cli.contains("retryable=true"));

        let api = err.format_json_api();
        assert_eq!(api["retryable"], Value::Bool(true));

        let frame = err.format_protocol_frame();
        assert!(frame.retryable);

        let log = err.format_log_fields();
        assert_eq!(log.get("error.retryable"), Some(&"true".to_string()));

        let sdk = err.format_sdk_payload();
        assert!(sdk.retryable);
    }

    #[test]
    fn telemetry_dimensions_include_error_code_dimension() {
        let registry = demo_registry();
        let err = product_error(
            &registry,
            ProductSurface::Policy,
            "FRANKEN_CAPABILITY_NOT_AVAILABLE",
            "capability unavailable",
            "trace-4",
            BTreeMap::new(),
        )
        .expect("build should succeed");

        let labels = telemetry_error_dimensions("franken.protocol.error_total", &err)
            .expect("metric name should be valid");
        assert_eq!(
            labels.get("error.code"),
            Some(&"FRANKEN_CAPABILITY_NOT_AVAILABLE".to_string())
        );
    }

    #[test]
    fn telemetry_dimensions_reject_invalid_namespace() {
        let registry = demo_registry();
        let err = product_error(
            &registry,
            ProductSurface::Token,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            "lease expired",
            "trace-5",
            BTreeMap::new(),
        )
        .expect("build should succeed");

        let result = telemetry_error_dimensions("invalid.metric.error_total", &err);
        assert!(result.is_err());
    }

    #[test]
    fn telemetry_dimensions_reject_empty_metric_name() {
        let registry = demo_registry();
        let err = product_error(
            &registry,
            ProductSurface::Token,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            "lease expired",
            "trace-empty-metric",
            BTreeMap::new(),
        )
        .expect("build should succeed");

        let result = telemetry_error_dimensions("", &err);

        assert!(result.is_err());
    }

    #[test]
    fn compatibility_allows_additive_change() {
        let old_registry = demo_registry();
        let mut new_registry = demo_registry();
        register_entry(
            &mut new_registry,
            "FRANKEN_EGRESS_TIMEOUT",
            Severity::Transient,
            true,
            Some(2000),
            "Retry egress call with exponential backoff and jitter",
            "egress timeout",
        );

        let report = compatibility_report(
            &old_registry.catalog(),
            &new_registry.catalog(),
            &ErrorCompatibilityPolicy::default(),
        );
        assert!(report.is_compatible());
        assert_eq!(report.added, vec!["FRANKEN_EGRESS_TIMEOUT".to_string()]);
    }

    #[test]
    fn compatibility_detects_removed_code() {
        let old_registry = demo_registry();
        let mut new_registry = ErrorCodeRegistry::new();
        register_entry(
            &mut new_registry,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            Severity::Transient,
            true,
            Some(1000),
            "Re-authenticate with fresh credentials and retry request",
            "auth failed",
        );

        let report = compatibility_report(
            &old_registry.catalog(),
            &new_registry.catalog(),
            &ErrorCompatibilityPolicy::default(),
        );
        assert!(!report.is_compatible());
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.reason.contains("append-only"))
        );
    }

    #[test]
    fn compatibility_detects_category_change() {
        let old_registry = demo_registry();
        // Recreate with category change by replacing one entry with fatal severity.
        let new_registry = {
            let mut replacement = ErrorCodeRegistry::new();
            register_entry(
                &mut replacement,
                "FRANKEN_PROTOCOL_AUTH_FAILED",
                Severity::Fatal,
                false,
                None,
                "",
                "auth failed",
            );
            register_entry(
                &mut replacement,
                "FRANKEN_CONNECTOR_LEASE_EXPIRED",
                Severity::Transient,
                true,
                Some(3000),
                "Re-negotiate lease with coordinator before issuing writes",
                "lease expired",
            );
            register_entry(
                &mut replacement,
                "FRANKEN_CAPABILITY_NOT_AVAILABLE",
                Severity::Degraded,
                false,
                None,
                "Check capability registry, then recover capability provider",
                "capability missing",
            );
            replacement
        };

        let report = compatibility_report(
            &old_registry.catalog(),
            &new_registry.catalog(),
            &ErrorCompatibilityPolicy::default(),
        );
        assert!(!report.is_compatible());
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.reason.contains("category changed"))
        );
    }

    #[test]
    fn compatibility_detects_retryable_change() {
        let old_registry = demo_registry();
        let mut new_registry = ErrorCodeRegistry::new();
        register_entry(
            &mut new_registry,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            Severity::Transient,
            false,
            Some(1000),
            "Re-authenticate with fresh credentials and retry request",
            "auth failed",
        );
        register_entry(
            &mut new_registry,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            Severity::Transient,
            true,
            Some(3000),
            "Re-negotiate lease with coordinator before issuing writes",
            "lease expired",
        );
        register_entry(
            &mut new_registry,
            "FRANKEN_CAPABILITY_NOT_AVAILABLE",
            Severity::Degraded,
            false,
            None,
            "Check capability registry, then recover capability provider",
            "capability missing",
        );

        let report = compatibility_report(
            &old_registry.catalog(),
            &new_registry.catalog(),
            &ErrorCompatibilityPolicy::default(),
        );
        assert!(!report.is_compatible());
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.reason.contains("retryable"))
        );
    }

    #[test]
    fn compatibility_detects_new_code_missing_description() {
        let old_registry = demo_registry();
        let mut new_registry = demo_registry();
        register_entry(
            &mut new_registry,
            "FRANKEN_EGRESS_UNDESCRIBED",
            Severity::Transient,
            true,
            Some(2000),
            "Retry egress request after refreshing connection state",
            "",
        );

        let report = compatibility_report(
            &old_registry.catalog(),
            &new_registry.catalog(),
            &ErrorCompatibilityPolicy::default(),
        );

        assert!(!report.is_compatible());
        assert!(report.violations.iter().any(|violation| {
            violation.code == "FRANKEN_EGRESS_UNDESCRIBED"
                && violation.reason.contains("missing description")
        }));
    }

    #[test]
    fn compatibility_detects_new_code_short_recovery_hint() {
        let old_registry = demo_registry();
        let mut new_registry = demo_registry();
        register_entry(
            &mut new_registry,
            "FRANKEN_EGRESS_SHORT_RECOVERY",
            Severity::Transient,
            true,
            Some(2000),
            "retry",
            "short recovery hint",
        );

        let report = compatibility_report(
            &old_registry.catalog(),
            &new_registry.catalog(),
            &ErrorCompatibilityPolicy::default(),
        );

        assert!(!report.is_compatible());
        assert!(report.violations.iter().any(|violation| {
            violation.code == "FRANKEN_EGRESS_SHORT_RECOVERY"
                && violation
                    .reason
                    .contains("recovery hint below policy minimum")
        }));
    }

    #[test]
    fn compatibility_keeps_removed_code_violation_when_other_checks_disabled() {
        let old_registry = demo_registry();
        let mut new_registry = ErrorCodeRegistry::new();
        register_entry(
            &mut new_registry,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            Severity::Transient,
            false,
            Some(1000),
            "Re-authenticate with fresh credentials and retry request",
            "auth failed",
        );
        let policy = ErrorCompatibilityPolicy {
            enforce_append_only: true,
            enforce_category_stability: false,
            enforce_retryable_stability: false,
            recovery_hint_min_len: 1,
        };

        let report =
            compatibility_report(&old_registry.catalog(), &new_registry.catalog(), &policy);

        assert!(!report.is_compatible());
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.reason.contains("append-only"))
        );
    }

    #[test]
    fn product_error_rejects_canonical_code_with_leading_space() {
        let registry = demo_registry();

        let result = product_error(
            &registry,
            ProductSurface::ControlPlane,
            " FRANKEN_PROTOCOL_AUTH_FAILED",
            "auth failed",
            "trace-leading-code",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::UnregisteredCode(code))
                if code == " FRANKEN_PROTOCOL_AUTH_FAILED"
        ));
    }

    #[test]
    fn product_error_rejects_canonical_code_with_trailing_space() {
        let registry = demo_registry();

        let result = product_error(
            &registry,
            ProductSurface::ControlPlane,
            "FRANKEN_PROTOCOL_AUTH_FAILED ",
            "auth failed",
            "trace-trailing-code",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::UnregisteredCode(code))
                if code == "FRANKEN_PROTOCOL_AUTH_FAILED "
        ));
    }

    #[test]
    fn product_error_rejects_whitespace_only_recovery_hint() {
        let mut registry = ErrorCodeRegistry::new();
        register_entry(
            &mut registry,
            "FRANKEN_EGRESS_BLANK_HINT",
            Severity::Transient,
            true,
            Some(250),
            "                         ",
            "blank recovery hint",
        );

        let result = product_error(
            &registry,
            ProductSurface::Migration,
            "FRANKEN_EGRESS_BLANK_HINT",
            "egress retry failed",
            "trace-blank-hint",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::RecoveryHintTooShort(code))
                if code == "FRANKEN_EGRESS_BLANK_HINT"
        ));
    }

    #[test]
    fn product_error_validates_message_before_registry_lookup() {
        let registry = demo_registry();

        let result = product_error(
            &registry,
            ProductSurface::Policy,
            "FRANKEN_NOT_REGISTERED",
            " \t ",
            "trace-message-first",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::MissingMessage)
        ));
    }

    #[test]
    fn telemetry_dimensions_rejects_uppercase_metric_segment() {
        let registry = demo_registry();
        let err = product_error(
            &registry,
            ProductSurface::Token,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            "lease expired",
            "trace-uppercase-metric",
            BTreeMap::new(),
        )
        .expect("build should succeed");

        let result = telemetry_error_dimensions("franken.protocol.ErrorTotal", &err);

        assert!(matches!(
            result,
            Err(NamespaceError::InvalidNamespace(metric))
                if metric == "franken.protocol.ErrorTotal"
        ));
    }

    #[test]
    fn telemetry_dimensions_rejects_empty_metric_segment() {
        let registry = demo_registry();
        let err = product_error(
            &registry,
            ProductSurface::Token,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            "lease expired",
            "trace-empty-segment-metric",
            BTreeMap::new(),
        )
        .expect("build should succeed");

        let result = telemetry_error_dimensions("franken.protocol..error_total", &err);

        assert!(matches!(
            result,
            Err(NamespaceError::InvalidNamespace(metric))
                if metric == "franken.protocol..error_total"
        ));
    }

    #[test]
    fn compatibility_reports_multiple_added_code_defects() {
        let old_registry = demo_registry();
        let mut new_registry = demo_registry();
        register_entry(
            &mut new_registry,
            "FRANKEN_EGRESS_MULTI_DEFECT",
            Severity::Transient,
            true,
            Some(1000),
            "retry",
            "",
        );

        let report = compatibility_report(
            &old_registry.catalog(),
            &new_registry.catalog(),
            &ErrorCompatibilityPolicy::default(),
        );
        let defect_count = report
            .violations
            .iter()
            .filter(|violation| violation.code == "FRANKEN_EGRESS_MULTI_DEFECT")
            .count();

        assert!(!report.is_compatible());
        assert_eq!(defect_count, 2);
    }

    #[test]
    fn compatibility_reports_category_and_retryable_drift_together() {
        let old_registry = demo_registry();
        let mut new_registry = ErrorCodeRegistry::new();
        register_entry(
            &mut new_registry,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            Severity::Fatal,
            false,
            None,
            "",
            "auth failed",
        );
        register_entry(
            &mut new_registry,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            Severity::Transient,
            true,
            Some(3000),
            "Re-negotiate lease with coordinator before issuing writes",
            "lease expired",
        );
        register_entry(
            &mut new_registry,
            "FRANKEN_CAPABILITY_NOT_AVAILABLE",
            Severity::Degraded,
            false,
            None,
            "Check capability registry, then recover capability provider",
            "capability missing",
        );

        let report = compatibility_report(
            &old_registry.catalog(),
            &new_registry.catalog(),
            &ErrorCompatibilityPolicy::default(),
        );

        assert!(!report.is_compatible());
        assert!(report.violations.iter().any(|violation| {
            violation.code == "FRANKEN_PROTOCOL_AUTH_FAILED"
                && violation.reason.contains("category changed")
        }));
        assert!(report.violations.iter().any(|violation| {
            violation.code == "FRANKEN_PROTOCOL_AUTH_FAILED"
                && violation.reason.contains("retryable flag changed")
        }));
    }

    #[test]
    fn product_error_macro_builds_error() {
        let registry = demo_registry();
        let result = crate::product_error!(
            &registry,
            ProductSurface::ZoneTenant,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            "lease renew required",
            "trace-6",
            BTreeMap::new()
        );
        assert!(result.is_ok());
    }

    #[test]
    fn product_error_validates_trace_id_before_registry_lookup() {
        let registry = demo_registry();
        let result = product_error(
            &registry,
            ProductSurface::Policy,
            "FRANKEN_NOT_REGISTERED",
            "registered-looking message",
            " \t ",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::MissingTraceId)
        ));
    }

    #[test]
    fn product_error_rejects_lowercase_canonical_code_alias() {
        let registry = demo_registry();
        let result = product_error(
            &registry,
            ProductSurface::Auth,
            "franken_protocol_auth_failed",
            "session auth failed",
            "trace-lowercase-canonical",
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ProductErrorBuildError::UnregisteredCode(code))
                if code == "franken_protocol_auth_failed"
        ));
    }

    #[test]
    fn product_prefix_without_trailing_dash_is_not_registered() {
        assert!(!is_registered_product_prefix("FN-CTRL"));
        assert!(!is_registered_product_prefix("FN-AUTH"));
        assert!(!is_registered_product_prefix("FN-TOK"));
    }

    #[test]
    fn product_prefix_with_extra_segment_is_not_registered() {
        assert!(!is_registered_product_prefix("FN-CTRL-X"));
        assert!(!is_registered_product_prefix("FN-MIG-ROLLBACK-"));
        assert!(!is_registered_product_prefix("FN-ZON-TENANT-"));
    }

    #[test]
    fn telemetry_dimensions_reject_metric_name_with_space() {
        let registry = demo_registry();
        let err = product_error(
            &registry,
            ProductSurface::ControlPlane,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            "session auth failed",
            "trace-space-metric",
            BTreeMap::new(),
        )
        .expect("build should succeed");

        let result = telemetry_error_dimensions("franken.protocol.error total", &err);

        assert!(result.is_err());
    }

    #[test]
    fn telemetry_dimensions_reject_metric_name_with_leading_dot() {
        let registry = demo_registry();
        let err = product_error(
            &registry,
            ProductSurface::ControlPlane,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            "session auth failed",
            "trace-leading-dot-metric",
            BTreeMap::new(),
        )
        .expect("build should succeed");

        let result = telemetry_error_dimensions(".franken.protocol.error_total", &err);

        assert!(result.is_err());
    }

    #[test]
    fn compatibility_category_policy_disabled_keeps_retryable_violation() {
        let old_registry = demo_registry();
        let mut new_registry = ErrorCodeRegistry::new();
        register_entry(
            &mut new_registry,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            Severity::Fatal,
            false,
            None,
            "",
            "auth failed",
        );
        register_entry(
            &mut new_registry,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            Severity::Transient,
            true,
            Some(3000),
            "Re-negotiate lease with coordinator before issuing writes",
            "lease expired",
        );
        register_entry(
            &mut new_registry,
            "FRANKEN_CAPABILITY_NOT_AVAILABLE",
            Severity::Degraded,
            false,
            None,
            "Check capability registry, then recover capability provider",
            "capability missing",
        );
        let policy = ErrorCompatibilityPolicy {
            enforce_category_stability: false,
            ..ErrorCompatibilityPolicy::default()
        };

        let report =
            compatibility_report(&old_registry.catalog(), &new_registry.catalog(), &policy);

        assert!(!report.is_compatible());
        assert!(report.violations.iter().any(|violation| {
            violation.code == "FRANKEN_PROTOCOL_AUTH_FAILED"
                && violation.reason.contains("retryable flag changed")
        }));
        assert!(!report.violations.iter().any(|violation| {
            violation.code == "FRANKEN_PROTOCOL_AUTH_FAILED"
                && violation.reason.contains("category changed")
        }));
    }

    #[test]
    fn compatibility_retryable_policy_disabled_keeps_category_violation() {
        let old_registry = demo_registry();
        let mut new_registry = ErrorCodeRegistry::new();
        register_entry(
            &mut new_registry,
            "FRANKEN_PROTOCOL_AUTH_FAILED",
            Severity::Degraded,
            true,
            Some(1000),
            "Re-authenticate with fresh credentials and retry request",
            "auth failed",
        );
        register_entry(
            &mut new_registry,
            "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            Severity::Transient,
            true,
            Some(3000),
            "Re-negotiate lease with coordinator before issuing writes",
            "lease expired",
        );
        register_entry(
            &mut new_registry,
            "FRANKEN_CAPABILITY_NOT_AVAILABLE",
            Severity::Degraded,
            false,
            None,
            "Check capability registry, then recover capability provider",
            "capability missing",
        );
        let policy = ErrorCompatibilityPolicy {
            enforce_retryable_stability: false,
            ..ErrorCompatibilityPolicy::default()
        };

        let report =
            compatibility_report(&old_registry.catalog(), &new_registry.catalog(), &policy);

        assert!(!report.is_compatible());
        assert!(report.violations.iter().any(|violation| {
            violation.code == "FRANKEN_PROTOCOL_AUTH_FAILED"
                && violation.reason.contains("category changed")
        }));
        assert!(!report.violations.iter().any(|violation| {
            violation.code == "FRANKEN_PROTOCOL_AUTH_FAILED"
                && violation.reason.contains("retryable flag changed")
        }));
    }

    #[test]
    fn compatibility_append_only_disabled_still_checks_added_code_quality() {
        let old_registry = demo_registry();
        let mut new_registry = demo_registry();
        register_entry(
            &mut new_registry,
            "FRANKEN_EGRESS_BAD_ADDITION",
            Severity::Transient,
            true,
            Some(1000),
            "retry",
            "",
        );
        let policy = ErrorCompatibilityPolicy {
            enforce_append_only: false,
            ..ErrorCompatibilityPolicy::default()
        };

        let report =
            compatibility_report(&old_registry.catalog(), &new_registry.catalog(), &policy);

        assert!(!report.is_compatible());
        assert_eq!(report.violations.len(), 2);
        assert!(
            report
                .violations
                .iter()
                .all(|violation| { violation.code == "FRANKEN_EGRESS_BAD_ADDITION" })
        );
    }

    fn valid_protocol_error_frame_value() -> Value {
        serde_json::json!({
            "code": "FN-AUTH-FRANKEN_PROTOCOL_AUTH_FAILED",
            "canonical_code": "FRANKEN_PROTOCOL_AUTH_FAILED",
            "retryable": true,
            "retry_after_ms": 1000,
            "trace_id": "trace-protocol-valid"
        })
    }

    fn assert_protocol_frame_missing_field_is_rejected(field: &str) {
        let mut value = valid_protocol_error_frame_value();
        value
            .as_object_mut()
            .expect("protocol frame test fixture must be a JSON object")
            .remove(field);

        let err = serde_json::from_value::<ProtocolErrorFrame>(value)
            .expect_err("missing protocol frame field must fail deserialization");

        assert!(
            err.to_string().contains(field),
            "error {err} should identify missing field {field}"
        );
    }

    #[test]
    fn negative_protocol_frame_deserialization_rejects_missing_code() {
        assert_protocol_frame_missing_field_is_rejected("code");
    }

    #[test]
    fn negative_protocol_frame_deserialization_rejects_missing_canonical_code() {
        assert_protocol_frame_missing_field_is_rejected("canonical_code");
    }

    #[test]
    fn negative_protocol_frame_deserialization_rejects_missing_retryable() {
        assert_protocol_frame_missing_field_is_rejected("retryable");
    }

    #[test]
    fn negative_protocol_frame_deserialization_rejects_missing_trace_id() {
        assert_protocol_frame_missing_field_is_rejected("trace_id");
    }

    #[test]
    fn negative_protocol_frame_deserialization_rejects_string_retry_after_ms() {
        let mut value = valid_protocol_error_frame_value();
        value["retry_after_ms"] = serde_json::json!("1000");

        let err = serde_json::from_value::<ProtocolErrorFrame>(value)
            .expect_err("string retry_after_ms must fail deserialization");

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_protocol_frame_deserialization_rejects_negative_retry_after_ms() {
        let mut value = valid_protocol_error_frame_value();
        value["retry_after_ms"] = serde_json::json!(-1);

        let err = serde_json::from_value::<ProtocolErrorFrame>(value)
            .expect_err("negative retry_after_ms must fail deserialization");

        let rendered = err.to_string();
        assert!(
            rendered.contains("invalid value") || rendered.contains("u64"),
            "negative retry_after_ms error should mention unsigned coercion: {rendered}"
        );
    }

    #[test]
    fn protocol_frame_deserialization_rejects_non_bool_retryable() {
        let value = serde_json::json!({
            "code": "FN-AUTH-FRANKEN_PROTOCOL_AUTH_FAILED",
            "canonical_code": "FRANKEN_PROTOCOL_AUTH_FAILED",
            "retryable": "true",
            "retry_after_ms": null,
            "trace_id": "trace-protocol-bad-retryable"
        });

        let result = serde_json::from_value::<ProtocolErrorFrame>(value);

        assert!(result.is_err());
    }

    fn valid_sdk_error_payload_value() -> Value {
        serde_json::json!({
            "code": "FN-AUTH-FRANKEN_PROTOCOL_AUTH_FAILED",
            "canonical_code": "FRANKEN_PROTOCOL_AUTH_FAILED",
            "category": "TRANSIENT",
            "retryable": true,
            "trace_id": "trace-sdk-valid",
            "message": "session auth failed",
            "context": {
                "route": "/v1/control/session"
            }
        })
    }

    fn assert_sdk_payload_missing_field_is_rejected(field: &str) {
        let mut value = valid_sdk_error_payload_value();
        value
            .as_object_mut()
            .expect("sdk payload test fixture must be a JSON object")
            .remove(field);

        let err = serde_json::from_value::<SdkErrorPayload>(value)
            .expect_err("missing SDK payload field must fail deserialization");

        assert!(
            err.to_string().contains(field),
            "error {err} should identify missing field {field}"
        );
    }

    #[test]
    fn negative_sdk_payload_deserialization_rejects_missing_code() {
        assert_sdk_payload_missing_field_is_rejected("code");
    }

    #[test]
    fn negative_sdk_payload_deserialization_rejects_missing_canonical_code() {
        assert_sdk_payload_missing_field_is_rejected("canonical_code");
    }

    #[test]
    fn negative_sdk_payload_deserialization_rejects_missing_category() {
        assert_sdk_payload_missing_field_is_rejected("category");
    }

    #[test]
    fn negative_sdk_payload_deserialization_rejects_missing_trace_id() {
        assert_sdk_payload_missing_field_is_rejected("trace_id");
    }

    #[test]
    fn negative_sdk_payload_deserialization_rejects_numeric_message() {
        let mut value = valid_sdk_error_payload_value();
        value["message"] = serde_json::json!(404);

        let err = serde_json::from_value::<SdkErrorPayload>(value)
            .expect_err("numeric SDK payload message must fail deserialization");

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_sdk_payload_deserialization_rejects_non_string_context_value() {
        let mut value = valid_sdk_error_payload_value();
        value["context"]["route"] = serde_json::json!(["/v1/control/session"]);

        let err = serde_json::from_value::<SdkErrorPayload>(value)
            .expect_err("non-string SDK payload context values must fail deserialization");

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn sdk_payload_deserialization_rejects_array_context() {
        let value = serde_json::json!({
            "code": "FN-AUTH-FRANKEN_PROTOCOL_AUTH_FAILED",
            "canonical_code": "FRANKEN_PROTOCOL_AUTH_FAILED",
            "category": "TRANSIENT",
            "retryable": true,
            "trace_id": "trace-sdk-bad-context",
            "message": "session auth failed",
            "context": ["not", "a", "map"]
        });

        let result = serde_json::from_value::<SdkErrorPayload>(value);

        assert!(result.is_err());
    }
}
