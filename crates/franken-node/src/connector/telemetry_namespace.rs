//! bd-1ugy: Stable telemetry namespace for protocol/capability/egress/security planes.
//!
//! Metric names and labels are versioned and frozen by contract.  Deprecations
//! follow a compatibility policy.  A schema validator enforces namespace rules.

use std::collections::BTreeMap;
use std::fmt;

// ── Planes ──────────────────────────────────────────────────────────────────

/// The four instrumentation planes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Plane {
    Protocol,
    Capability,
    Egress,
    Security,
}

impl Plane {
    pub fn prefix(self) -> &'static str {
        match self {
            Plane::Protocol => "franken.protocol.",
            Plane::Capability => "franken.capability.",
            Plane::Egress => "franken.egress.",
            Plane::Security => "franken.security.",
        }
    }

    pub fn from_name(name: &str) -> Option<Plane> {
        if metric_name_matches_plane(name, Plane::Protocol) {
            Some(Plane::Protocol)
        } else if metric_name_matches_plane(name, Plane::Capability) {
            Some(Plane::Capability)
        } else if metric_name_matches_plane(name, Plane::Egress) {
            Some(Plane::Egress)
        } else if metric_name_matches_plane(name, Plane::Security) {
            Some(Plane::Security)
        } else {
            None
        }
    }
}

fn metric_name_matches_plane(name: &str, plane: Plane) -> bool {
    let Some(suffix) = name.strip_prefix(plane.prefix()) else {
        return false;
    };
    metric_suffix_is_valid(suffix)
}

fn metric_suffix_is_valid(suffix: &str) -> bool {
    !suffix.is_empty()
        && suffix.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
}

impl fmt::Display for Plane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Plane::Protocol => write!(f, "protocol"),
            Plane::Capability => write!(f, "capability"),
            Plane::Egress => write!(f, "egress"),
            Plane::Security => write!(f, "security"),
        }
    }
}

// ── Metric type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
}

impl fmt::Display for MetricType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetricType::Counter => write!(f, "counter"),
            MetricType::Gauge => write!(f, "gauge"),
            MetricType::Histogram => write!(f, "histogram"),
        }
    }
}

// ── Schema ──────────────────────────────────────────────────────────────────

/// A registered metric schema.
#[derive(Debug, Clone)]
pub struct MetricSchema {
    pub name: String,
    pub plane: Plane,
    pub metric_type: MetricType,
    pub labels: Vec<String>,
    pub version: u32,
    pub frozen: bool,
    pub deprecated: bool,
    pub deprecation_reason: Option<String>,
    pub deprecated_at_version: Option<u32>,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceError {
    /// TNS_INVALID_NAMESPACE — name does not start with a valid plane prefix.
    InvalidNamespace(String),
    /// TNS_INVALID_LABEL — label names must be non-empty stable identifiers.
    InvalidLabel(String),
    /// TNS_VERSION_MISSING — schema version not provided (0).
    VersionMissing(String),
    /// TNS_FROZEN_CONFLICT — re-registration conflicts with a frozen schema.
    FrozenConflict(String),
    /// TNS_ALREADY_DEPRECATED — metric is already deprecated.
    AlreadyDeprecated(String),
    /// TNS_INVALID_DEPRECATION — deprecation metadata is malformed.
    InvalidDeprecation(String),
    /// TNS_NOT_FOUND — metric not in registry.
    NotFound(String),
}

impl NamespaceError {
    pub fn code(&self) -> &'static str {
        match self {
            NamespaceError::InvalidNamespace(_) => "TNS_INVALID_NAMESPACE",
            NamespaceError::InvalidLabel(_) => "TNS_INVALID_LABEL",
            NamespaceError::VersionMissing(_) => "TNS_VERSION_MISSING",
            NamespaceError::FrozenConflict(_) => "TNS_FROZEN_CONFLICT",
            NamespaceError::AlreadyDeprecated(_) => "TNS_ALREADY_DEPRECATED",
            NamespaceError::InvalidDeprecation(_) => "TNS_INVALID_DEPRECATION",
            NamespaceError::NotFound(_) => "TNS_NOT_FOUND",
        }
    }
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamespaceError::InvalidNamespace(n) => write!(f, "TNS_INVALID_NAMESPACE: {n}"),
            NamespaceError::InvalidLabel(n) => write!(f, "TNS_INVALID_LABEL: {n}"),
            NamespaceError::VersionMissing(n) => write!(f, "TNS_VERSION_MISSING: {n}"),
            NamespaceError::FrozenConflict(n) => write!(f, "TNS_FROZEN_CONFLICT: {n}"),
            NamespaceError::AlreadyDeprecated(n) => write!(f, "TNS_ALREADY_DEPRECATED: {n}"),
            NamespaceError::InvalidDeprecation(n) => write!(f, "TNS_INVALID_DEPRECATION: {n}"),
            NamespaceError::NotFound(n) => write!(f, "TNS_NOT_FOUND: {n}"),
        }
    }
}

// ── Registration request ────────────────────────────────────────────────────

/// Input for registering or updating a metric schema.
pub struct MetricRegistration {
    pub name: String,
    pub metric_type: MetricType,
    pub labels: Vec<String>,
    pub version: u32,
}

// ── Registry ────────────────────────────────────────────────────────────────

/// In-memory schema registry enforcing all four invariants.
#[derive(Debug, Default)]
pub struct SchemaRegistry {
    schemas: BTreeMap<String, MetricSchema>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new metric schema.
    ///
    /// Enforces INV-TNS-NAMESPACE, INV-TNS-VERSIONED, and INV-TNS-FROZEN.
    pub fn register(&mut self, reg: &MetricRegistration) -> Result<MetricSchema, NamespaceError> {
        // INV-TNS-NAMESPACE
        let plane = Plane::from_name(&reg.name)
            .ok_or_else(|| NamespaceError::InvalidNamespace(reg.name.clone()))?;

        // INV-TNS-VERSIONED
        if reg.version == 0 {
            return Err(NamespaceError::VersionMissing(reg.name.clone()));
        }

        if reg.labels.iter().any(|label| !label_is_valid(label)) {
            return Err(NamespaceError::InvalidLabel(reg.name.clone()));
        }

        // INV-TNS-FROZEN
        if let Some(existing) = self.schemas.get(&reg.name)
            && existing.frozen
        {
            let type_match = existing.metric_type == reg.metric_type;
            let labels_match = existing.labels == reg.labels;
            if !type_match || !labels_match {
                return Err(NamespaceError::FrozenConflict(reg.name.clone()));
            }
            // Same shape is fine — update version only.
            let mut updated = existing.clone();
            updated.version = reg.version;
            self.schemas.insert(reg.name.clone(), updated.clone());
            return Ok(updated);
        }

        let schema = MetricSchema {
            name: reg.name.clone(),
            plane,
            metric_type: reg.metric_type,
            labels: reg.labels.clone(),
            version: reg.version,
            frozen: false,
            deprecated: false,
            deprecation_reason: None,
            deprecated_at_version: None,
        };
        self.schemas.insert(reg.name.clone(), schema.clone());
        Ok(schema)
    }

    /// Freeze a metric so its shape cannot change.
    pub fn freeze(&mut self, name: &str) -> Result<(), NamespaceError> {
        let schema = self
            .schemas
            .get_mut(name)
            .ok_or_else(|| NamespaceError::NotFound(name.to_string()))?;
        schema.frozen = true;
        Ok(())
    }

    /// Deprecate a metric with a reason and version stamp.
    ///
    /// Enforces INV-TNS-DEPRECATED — the metric stays in the registry.
    pub fn deprecate(
        &mut self,
        name: &str,
        reason: &str,
        at_version: u32,
    ) -> Result<(), NamespaceError> {
        let schema = self
            .schemas
            .get_mut(name)
            .ok_or_else(|| NamespaceError::NotFound(name.to_string()))?;
        if schema.deprecated {
            return Err(NamespaceError::AlreadyDeprecated(name.to_string()));
        }
        if reason.trim().is_empty() || reason.as_bytes().contains(&0) || at_version == 0 {
            return Err(NamespaceError::InvalidDeprecation(name.to_string()));
        }
        schema.deprecated = true;
        schema.deprecation_reason = Some(reason.to_string());
        schema.deprecated_at_version = Some(at_version);
        Ok(())
    }

    /// Look up a metric schema by name.
    pub fn get(&self, name: &str) -> Option<&MetricSchema> {
        self.schemas.get(name)
    }

    /// List all schemas for a given plane.
    pub fn list_by_plane(&self, plane: Plane) -> Vec<&MetricSchema> {
        let mut out: Vec<_> = self.schemas.values().filter(|s| s.plane == plane).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Export a catalog snapshot of all registered schemas.
    pub fn catalog(&self) -> Vec<MetricSchema> {
        let mut out: Vec<_> = self.schemas.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Validate a metric name against namespace rules (without registering).
    pub fn validate_name(name: &str) -> Result<Plane, NamespaceError> {
        Plane::from_name(name).ok_or_else(|| NamespaceError::InvalidNamespace(name.to_string()))
    }
}

fn label_is_valid(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str, mt: MetricType, labels: &[&str], version: u32) -> MetricRegistration {
        MetricRegistration {
            name: name.to_string(),
            metric_type: mt,
            labels: labels.iter().map(|s| s.to_string()).collect(),
            version,
        }
    }

    #[test]
    fn register_valid_metric() {
        let mut r = SchemaRegistry::new();
        let s = r
            .register(&reg(
                "franken.protocol.msgs_total",
                MetricType::Counter,
                &["peer"],
                1,
            ))
            .expect("should succeed");
        assert_eq!(s.plane, Plane::Protocol);
        assert_eq!(s.version, 1);
        assert!(!s.frozen);
    }

    #[test]
    fn reject_invalid_namespace() {
        let mut r = SchemaRegistry::new();
        let err = r
            .register(&reg("bad.prefix.foo", MetricType::Counter, &[], 1))
            .unwrap_err();
        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
    }

    #[test]
    fn reject_version_zero() {
        let mut r = SchemaRegistry::new();
        let err = r
            .register(&reg("franken.protocol.foo", MetricType::Counter, &[], 0))
            .unwrap_err();
        assert_eq!(err.code(), "TNS_VERSION_MISSING");
    }

    #[test]
    fn freeze_prevents_shape_change() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.security.auth_total",
            MetricType::Counter,
            &["method"],
            1,
        ))
        .expect("should succeed");
        r.freeze("franken.security.auth_total")
            .expect("freeze should succeed");

        // Same shape — OK
        let s = r
            .register(&reg(
                "franken.security.auth_total",
                MetricType::Counter,
                &["method"],
                2,
            ))
            .expect("should succeed");
        assert_eq!(s.version, 2);

        // Different type — rejected
        let err = r
            .register(&reg(
                "franken.security.auth_total",
                MetricType::Gauge,
                &["method"],
                3,
            ))
            .unwrap_err();
        assert_eq!(err.code(), "TNS_FROZEN_CONFLICT");

        // Different labels — rejected
        let err = r
            .register(&reg(
                "franken.security.auth_total",
                MetricType::Counter,
                &["method", "extra"],
                3,
            ))
            .unwrap_err();
        assert_eq!(err.code(), "TNS_FROZEN_CONFLICT");
    }

    #[test]
    fn deprecate_keeps_metric_queryable() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.egress.bytes_total",
            MetricType::Counter,
            &[],
            1,
        ))
        .expect("should succeed");
        r.deprecate("franken.egress.bytes_total", "replaced by v2", 2)
            .expect("should succeed");
        let s = r.get("franken.egress.bytes_total").expect("should exist");
        assert!(s.deprecated);
        assert_eq!(s.deprecation_reason.as_deref(), Some("replaced by v2"));
        assert_eq!(s.deprecated_at_version, Some(2));
    }

    #[test]
    fn double_deprecate_rejected() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.capability.inv_total",
            MetricType::Counter,
            &[],
            1,
        ))
        .expect("should succeed");
        r.deprecate("franken.capability.inv_total", "reason", 2)
            .expect("should succeed");
        let err = r
            .deprecate("franken.capability.inv_total", "again", 3)
            .unwrap_err();
        assert_eq!(err.code(), "TNS_ALREADY_DEPRECATED");
    }

    #[test]
    fn deprecate_not_found() {
        let mut r = SchemaRegistry::new();
        let err = r
            .deprecate("franken.protocol.no_such", "reason", 1)
            .unwrap_err();
        assert_eq!(err.code(), "TNS_NOT_FOUND");
    }

    #[test]
    fn freeze_not_found() {
        let mut r = SchemaRegistry::new();
        let err = r.freeze("franken.protocol.no_such").unwrap_err();
        assert_eq!(err.code(), "TNS_NOT_FOUND");
    }

    #[test]
    fn validate_name_good() {
        assert_eq!(
            SchemaRegistry::validate_name("franken.protocol.x").expect("should pass"),
            Plane::Protocol
        );
        assert_eq!(
            SchemaRegistry::validate_name("franken.capability.x").expect("should pass"),
            Plane::Capability
        );
        assert_eq!(
            SchemaRegistry::validate_name("franken.egress.x").expect("should pass"),
            Plane::Egress
        );
        assert_eq!(
            SchemaRegistry::validate_name("franken.security.x").expect("should pass"),
            Plane::Security
        );
    }

    #[test]
    fn validate_name_bad() {
        assert!(SchemaRegistry::validate_name("other.prefix.x").is_err());
    }

    #[test]
    fn list_by_plane() {
        let mut r = SchemaRegistry::new();
        r.register(&reg("franken.protocol.a", MetricType::Counter, &[], 1))
            .expect("should succeed");
        r.register(&reg("franken.protocol.b", MetricType::Gauge, &[], 1))
            .expect("should succeed");
        r.register(&reg("franken.security.c", MetricType::Counter, &[], 1))
            .expect("should succeed");
        let protos = r.list_by_plane(Plane::Protocol);
        assert_eq!(protos.len(), 2);
        assert_eq!(protos[0].name, "franken.protocol.a");
    }

    #[test]
    fn catalog_returns_sorted() {
        let mut r = SchemaRegistry::new();
        r.register(&reg("franken.security.z", MetricType::Counter, &[], 1))
            .expect("should succeed");
        r.register(&reg("franken.protocol.a", MetricType::Counter, &[], 1))
            .expect("should succeed");
        let cat = r.catalog();
        assert_eq!(cat.len(), 2);
        assert_eq!(cat[0].name, "franken.protocol.a");
        assert_eq!(cat[1].name, "franken.security.z");
    }

    #[test]
    fn re_register_unfrozen_overwrites() {
        let mut r = SchemaRegistry::new();
        r.register(&reg("franken.protocol.x", MetricType::Counter, &["a"], 1))
            .expect("should succeed");
        let s = r
            .register(&reg("franken.protocol.x", MetricType::Gauge, &["b"], 2))
            .expect("should succeed");
        assert_eq!(s.metric_type, MetricType::Gauge);
        assert_eq!(s.labels, vec!["b".to_string()]);
        assert_eq!(s.version, 2);
    }

    #[test]
    fn plane_display() {
        assert_eq!(Plane::Protocol.to_string(), "protocol");
        assert_eq!(Plane::Capability.to_string(), "capability");
        assert_eq!(Plane::Egress.to_string(), "egress");
        assert_eq!(Plane::Security.to_string(), "security");
    }

    #[test]
    fn metric_type_display() {
        assert_eq!(MetricType::Counter.to_string(), "counter");
        assert_eq!(MetricType::Gauge.to_string(), "gauge");
        assert_eq!(MetricType::Histogram.to_string(), "histogram");
    }

    #[test]
    fn error_display() {
        let e = NamespaceError::InvalidNamespace("bad".into());
        assert!(e.to_string().contains("TNS_INVALID_NAMESPACE"));
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn all_error_codes_present() {
        let errors = [
            NamespaceError::InvalidNamespace("x".into()),
            NamespaceError::InvalidLabel("x".into()),
            NamespaceError::VersionMissing("x".into()),
            NamespaceError::FrozenConflict("x".into()),
            NamespaceError::AlreadyDeprecated("x".into()),
            NamespaceError::InvalidDeprecation("x".into()),
            NamespaceError::NotFound("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"TNS_INVALID_NAMESPACE"));
        assert!(codes.contains(&"TNS_INVALID_LABEL"));
        assert!(codes.contains(&"TNS_VERSION_MISSING"));
        assert!(codes.contains(&"TNS_FROZEN_CONFLICT"));
        assert!(codes.contains(&"TNS_ALREADY_DEPRECATED"));
        assert!(codes.contains(&"TNS_INVALID_DEPRECATION"));
        assert!(codes.contains(&"TNS_NOT_FOUND"));
    }

    #[test]
    fn register_empty_name_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg("", MetricType::Counter, &[], 1))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn register_case_mismatched_prefix_is_rejected() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "Franken.protocol.msgs_total",
                MetricType::Counter,
                &[],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.get("Franken.protocol.msgs_total").is_none());
    }

    #[test]
    fn register_partial_plane_prefix_is_rejected() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.proto.msgs_total",
                MetricType::Counter,
                &[],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.list_by_plane(Plane::Protocol).is_empty());
    }

    #[test]
    fn version_zero_does_not_insert_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.protocol.zero_version",
                MetricType::Counter,
                &[],
                0,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_VERSION_MISSING");
        assert!(r.get("franken.protocol.zero_version").is_none());
    }

    #[test]
    fn version_zero_reregister_does_not_replace_existing_schema() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.protocol.stable",
            MetricType::Counter,
            &["peer"],
            2,
        ))
        .expect("initial registration should succeed");

        let err = r
            .register(&reg(
                "franken.protocol.stable",
                MetricType::Gauge,
                &["node"],
                0,
            ))
            .unwrap_err();
        let schema = r
            .get("franken.protocol.stable")
            .expect("schema should remain");

        assert_eq!(err.code(), "TNS_VERSION_MISSING");
        assert_eq!(schema.metric_type, MetricType::Counter);
        assert_eq!(schema.labels, vec!["peer".to_string()]);
        assert_eq!(schema.version, 2);
    }

    #[test]
    fn frozen_label_order_change_is_rejected_and_original_shape_remains() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.security.auth_latency",
            MetricType::Histogram,
            &["method", "result"],
            1,
        ))
        .expect("initial registration should succeed");
        r.freeze("franken.security.auth_latency")
            .expect("freeze should succeed");

        let err = r
            .register(&reg(
                "franken.security.auth_latency",
                MetricType::Histogram,
                &["result", "method"],
                2,
            ))
            .unwrap_err();
        let schema = r
            .get("franken.security.auth_latency")
            .expect("schema should remain");

        assert_eq!(err.code(), "TNS_FROZEN_CONFLICT");
        assert_eq!(
            schema.labels,
            vec!["method".to_string(), "result".to_string()]
        );
        assert_eq!(schema.version, 1);
    }

    #[test]
    fn double_deprecate_preserves_original_reason_and_version() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.egress.deprecated_total",
            MetricType::Counter,
            &[],
            1,
        ))
        .expect("registration should succeed");
        r.deprecate("franken.egress.deprecated_total", "first reason", 2)
            .expect("first deprecation should succeed");

        let err = r
            .deprecate("franken.egress.deprecated_total", "second reason", 3)
            .unwrap_err();
        let schema = r
            .get("franken.egress.deprecated_total")
            .expect("schema should remain");

        assert_eq!(err.code(), "TNS_ALREADY_DEPRECATED");
        assert_eq!(schema.deprecation_reason.as_deref(), Some("first reason"));
        assert_eq!(schema.deprecated_at_version, Some(2));
    }

    #[test]
    fn deprecate_missing_metric_does_not_create_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .deprecate("franken.capability.missing_total", "not present", 7)
            .unwrap_err();

        assert_eq!(err.code(), "TNS_NOT_FOUND");
        assert!(r.get("franken.capability.missing_total").is_none());
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn register_bare_plane_prefix_is_rejected() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg("franken.protocol.", MetricType::Counter, &[], 1))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn register_trailing_dot_metric_name_is_rejected() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.egress.bytes_total.",
                MetricType::Counter,
                &[],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.get("franken.egress.bytes_total.").is_none());
    }

    #[test]
    fn register_double_dot_metric_name_is_rejected() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.security.auth..failures",
                MetricType::Counter,
                &[],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.list_by_plane(Plane::Security).is_empty());
    }

    #[test]
    fn register_metric_name_with_whitespace_is_rejected() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.capability.inv total",
                MetricType::Counter,
                &[],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn register_uppercase_suffix_is_rejected() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.protocol.Msgs_total",
                MetricType::Counter,
                &[],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.get("franken.protocol.Msgs_total").is_none());
    }

    #[test]
    fn validate_name_rejects_non_ascii_suffix() {
        let err =
            SchemaRegistry::validate_name("franken.security.auth_total_\u{00e9}").unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(matches!(err, NamespaceError::InvalidNamespace(_)));
    }

    #[test]
    fn invalid_namespace_reregister_does_not_replace_existing_schema() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.protocol.msgs_total",
            MetricType::Counter,
            &["peer"],
            1,
        ))
        .expect("initial registration should succeed");

        let err = r
            .register(&reg(
                "franken.protocol.msgs total",
                MetricType::Gauge,
                &["node"],
                2,
            ))
            .unwrap_err();
        let schema = r
            .get("franken.protocol.msgs_total")
            .expect("original schema should remain");

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert_eq!(schema.metric_type, MetricType::Counter);
        assert_eq!(schema.labels, vec!["peer".to_string()]);
        assert_eq!(schema.version, 1);
    }

    #[test]
    fn register_empty_label_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.protocol.empty_label",
                MetricType::Counter,
                &[""],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_LABEL");
        assert!(r.get("franken.protocol.empty_label").is_none());
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn register_whitespace_label_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.protocol.whitespace_label",
                MetricType::Counter,
                &[" \t "],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_LABEL");
        assert!(r.get("franken.protocol.whitespace_label").is_none());
    }

    #[test]
    fn register_uppercase_label_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.security.upper_label",
                MetricType::Gauge,
                &["Peer"],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_LABEL");
        assert!(r.get("franken.security.upper_label").is_none());
    }

    #[test]
    fn register_dotted_label_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.egress.dotted_label",
                MetricType::Histogram,
                &["peer.id"],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_LABEL");
        assert!(r.get("franken.egress.dotted_label").is_none());
    }

    #[test]
    fn register_nul_label_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.capability.nul_label",
                MetricType::Counter,
                &["peer\0hidden"],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_LABEL");
        assert!(r.get("franken.capability.nul_label").is_none());
    }

    #[test]
    fn invalid_label_reregister_does_not_replace_existing_schema() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.protocol.label_stable",
            MetricType::Counter,
            &["peer"],
            1,
        ))
        .expect("initial registration should succeed");

        let err = r
            .register(&reg(
                "franken.protocol.label_stable",
                MetricType::Gauge,
                &["bad-label"],
                2,
            ))
            .unwrap_err();
        let schema = r
            .get("franken.protocol.label_stable")
            .expect("original schema should remain");

        assert_eq!(err.code(), "TNS_INVALID_LABEL");
        assert_eq!(schema.metric_type, MetricType::Counter);
        assert_eq!(schema.labels, vec!["peer".to_string()]);
        assert_eq!(schema.version, 1);
    }

    #[test]
    fn deprecate_empty_reason_is_rejected_without_mutating_schema() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.egress.empty_deprecation_reason",
            MetricType::Counter,
            &[],
            1,
        ))
        .expect("registration should succeed");

        let err = r
            .deprecate("franken.egress.empty_deprecation_reason", " \t ", 2)
            .unwrap_err();
        let schema = r
            .get("franken.egress.empty_deprecation_reason")
            .expect("schema should remain");

        assert_eq!(err.code(), "TNS_INVALID_DEPRECATION");
        assert!(!schema.deprecated);
        assert!(schema.deprecation_reason.is_none());
        assert_eq!(schema.deprecated_at_version, None);
    }

    #[test]
    fn deprecate_nul_reason_is_rejected_without_mutating_schema() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.security.nul_deprecation_reason",
            MetricType::Counter,
            &[],
            1,
        ))
        .expect("registration should succeed");

        let err = r
            .deprecate("franken.security.nul_deprecation_reason", "bad\0reason", 2)
            .unwrap_err();
        let schema = r
            .get("franken.security.nul_deprecation_reason")
            .expect("schema should remain");

        assert_eq!(err.code(), "TNS_INVALID_DEPRECATION");
        assert!(!schema.deprecated);
        assert!(schema.deprecation_reason.is_none());
    }

    #[test]
    fn deprecate_zero_version_is_rejected_without_mutating_schema() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.capability.zero_deprecation_version",
            MetricType::Counter,
            &[],
            1,
        ))
        .expect("registration should succeed");

        let err = r
            .deprecate("franken.capability.zero_deprecation_version", "reason", 0)
            .unwrap_err();
        let schema = r
            .get("franken.capability.zero_deprecation_version")
            .expect("schema should remain");

        assert_eq!(err.code(), "TNS_INVALID_DEPRECATION");
        assert!(!schema.deprecated);
        assert_eq!(schema.deprecated_at_version, None);
    }

    #[test]
    fn validate_name_rejects_hyphenated_metric_segment() {
        let err = SchemaRegistry::validate_name("franken.protocol.requests-total").unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
    }

    #[test]
    fn register_metric_name_with_slash_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.egress.bytes/total",
                MetricType::Counter,
                &[],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn register_metric_name_with_colon_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.security.auth:failures",
                MetricType::Counter,
                &[],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.get("franken.security.auth:failures").is_none());
    }

    #[test]
    fn register_hyphenated_label_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.capability.invocations_total",
                MetricType::Counter,
                &["peer-id"],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_LABEL");
        assert!(r.list_by_plane(Plane::Capability).is_empty());
    }

    #[test]
    fn register_non_ascii_label_is_rejected_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.protocol.non_ascii_label",
                MetricType::Counter,
                &["r\u{00f4}le"],
                1,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_LABEL");
        assert!(r.get("franken.protocol.non_ascii_label").is_none());
    }

    #[test]
    fn deprecate_missing_metric_with_invalid_metadata_still_returns_not_found() {
        let mut r = SchemaRegistry::new();

        let err = r
            .deprecate("franken.security.no_such_metric", " \t ", 0)
            .unwrap_err();

        assert_eq!(err.code(), "TNS_NOT_FOUND");
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn invalid_namespace_preempts_zero_version_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg("bad.prefix.zero", MetricType::Counter, &[], 0))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn zero_version_preempts_invalid_label_without_inserting_schema() {
        let mut r = SchemaRegistry::new();

        let err = r
            .register(&reg(
                "franken.protocol.bad_label_and_version",
                MetricType::Counter,
                &["bad-label"],
                0,
            ))
            .unwrap_err();

        assert_eq!(err.code(), "TNS_VERSION_MISSING");
        assert!(r.get("franken.protocol.bad_label_and_version").is_none());
    }

    #[test]
    fn frozen_schema_invalid_label_reregister_reports_label_error_and_preserves_shape() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.security.frozen_label_guard",
            MetricType::Counter,
            &["peer"],
            1,
        ))
        .expect("initial registration should succeed");
        r.freeze("franken.security.frozen_label_guard")
            .expect("freeze should succeed");

        let err = r
            .register(&reg(
                "franken.security.frozen_label_guard",
                MetricType::Gauge,
                &["bad-label"],
                2,
            ))
            .unwrap_err();
        let schema = r
            .get("franken.security.frozen_label_guard")
            .expect("schema should remain");

        assert_eq!(err.code(), "TNS_INVALID_LABEL");
        assert_eq!(schema.metric_type, MetricType::Counter);
        assert_eq!(schema.labels, vec!["peer".to_string()]);
        assert_eq!(schema.version, 1);
        assert!(schema.frozen);
    }

    #[test]
    fn frozen_schema_version_zero_reregister_reports_version_missing_and_preserves_shape() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.egress.frozen_version_guard",
            MetricType::Histogram,
            &["route"],
            3,
        ))
        .expect("initial registration should succeed");
        r.freeze("franken.egress.frozen_version_guard")
            .expect("freeze should succeed");

        let err = r
            .register(&reg(
                "franken.egress.frozen_version_guard",
                MetricType::Counter,
                &["other"],
                0,
            ))
            .unwrap_err();
        let schema = r
            .get("franken.egress.frozen_version_guard")
            .expect("schema should remain");

        assert_eq!(err.code(), "TNS_VERSION_MISSING");
        assert_eq!(schema.metric_type, MetricType::Histogram);
        assert_eq!(schema.labels, vec!["route".to_string()]);
        assert_eq!(schema.version, 3);
    }

    #[test]
    fn already_deprecated_preempts_invalid_deprecation_metadata_and_preserves_original() {
        let mut r = SchemaRegistry::new();
        r.register(&reg(
            "franken.capability.deprecated_guard",
            MetricType::Counter,
            &[],
            1,
        ))
        .expect("registration should succeed");
        r.deprecate("franken.capability.deprecated_guard", "first reason", 2)
            .expect("initial deprecation should succeed");

        let err = r
            .deprecate("franken.capability.deprecated_guard", " \t ", 0)
            .unwrap_err();
        let schema = r
            .get("franken.capability.deprecated_guard")
            .expect("schema should remain");

        assert_eq!(err.code(), "TNS_ALREADY_DEPRECATED");
        assert_eq!(schema.deprecation_reason.as_deref(), Some("first reason"));
        assert_eq!(schema.deprecated_at_version, Some(2));
    }

    #[test]
    fn freeze_missing_empty_name_returns_not_found_without_creating_schema() {
        let mut r = SchemaRegistry::new();

        let err = r.freeze("").unwrap_err();

        assert_eq!(err, NamespaceError::NotFound(String::new()));
        assert!(r.catalog().is_empty());
    }

    #[test]
    fn validate_name_rejects_newline_in_suffix() {
        let err = SchemaRegistry::validate_name("franken.protocol.requests\n_total").unwrap_err();

        assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
    }

    #[test]
    fn metric_suffix_rejects_empty_middle_segment() {
        assert!(!metric_suffix_is_valid("requests..total"));
        assert!(Plane::from_name("franken.protocol.requests..total").is_none());
    }
}
