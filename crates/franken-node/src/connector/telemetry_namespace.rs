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
        if name.starts_with(Plane::Protocol.prefix()) {
            Some(Plane::Protocol)
        } else if name.starts_with(Plane::Capability.prefix()) {
            Some(Plane::Capability)
        } else if name.starts_with(Plane::Egress.prefix()) {
            Some(Plane::Egress)
        } else if name.starts_with(Plane::Security.prefix()) {
            Some(Plane::Security)
        } else {
            None
        }
    }
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
    /// TNS_VERSION_MISSING — schema version not provided (0).
    VersionMissing(String),
    /// TNS_FROZEN_CONFLICT — re-registration conflicts with a frozen schema.
    FrozenConflict(String),
    /// TNS_ALREADY_DEPRECATED — metric is already deprecated.
    AlreadyDeprecated(String),
    /// TNS_NOT_FOUND — metric not in registry.
    NotFound(String),
}

impl NamespaceError {
    pub fn code(&self) -> &'static str {
        match self {
            NamespaceError::InvalidNamespace(_) => "TNS_INVALID_NAMESPACE",
            NamespaceError::VersionMissing(_) => "TNS_VERSION_MISSING",
            NamespaceError::FrozenConflict(_) => "TNS_FROZEN_CONFLICT",
            NamespaceError::AlreadyDeprecated(_) => "TNS_ALREADY_DEPRECATED",
            NamespaceError::NotFound(_) => "TNS_NOT_FOUND",
        }
    }
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamespaceError::InvalidNamespace(n) => write!(f, "TNS_INVALID_NAMESPACE: {n}"),
            NamespaceError::VersionMissing(n) => write!(f, "TNS_VERSION_MISSING: {n}"),
            NamespaceError::FrozenConflict(n) => write!(f, "TNS_FROZEN_CONFLICT: {n}"),
            NamespaceError::AlreadyDeprecated(n) => write!(f, "TNS_ALREADY_DEPRECATED: {n}"),
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
            .unwrap();
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
        .unwrap();
        r.freeze("franken.security.auth_total").unwrap();

        // Same shape — OK
        let s = r
            .register(&reg(
                "franken.security.auth_total",
                MetricType::Counter,
                &["method"],
                2,
            ))
            .unwrap();
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
        .unwrap();
        r.deprecate("franken.egress.bytes_total", "replaced by v2", 2)
            .unwrap();
        let s = r.get("franken.egress.bytes_total").unwrap();
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
        .unwrap();
        r.deprecate("franken.capability.inv_total", "reason", 2)
            .unwrap();
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
            SchemaRegistry::validate_name("franken.protocol.x").unwrap(),
            Plane::Protocol
        );
        assert_eq!(
            SchemaRegistry::validate_name("franken.capability.x").unwrap(),
            Plane::Capability
        );
        assert_eq!(
            SchemaRegistry::validate_name("franken.egress.x").unwrap(),
            Plane::Egress
        );
        assert_eq!(
            SchemaRegistry::validate_name("franken.security.x").unwrap(),
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
            .unwrap();
        r.register(&reg("franken.protocol.b", MetricType::Gauge, &[], 1))
            .unwrap();
        r.register(&reg("franken.security.c", MetricType::Counter, &[], 1))
            .unwrap();
        let protos = r.list_by_plane(Plane::Protocol);
        assert_eq!(protos.len(), 2);
        assert_eq!(protos[0].name, "franken.protocol.a");
    }

    #[test]
    fn catalog_returns_sorted() {
        let mut r = SchemaRegistry::new();
        r.register(&reg("franken.security.z", MetricType::Counter, &[], 1))
            .unwrap();
        r.register(&reg("franken.protocol.a", MetricType::Counter, &[], 1))
            .unwrap();
        let cat = r.catalog();
        assert_eq!(cat.len(), 2);
        assert_eq!(cat[0].name, "franken.protocol.a");
        assert_eq!(cat[1].name, "franken.security.z");
    }

    #[test]
    fn re_register_unfrozen_overwrites() {
        let mut r = SchemaRegistry::new();
        r.register(&reg("franken.protocol.x", MetricType::Counter, &["a"], 1))
            .unwrap();
        let s = r
            .register(&reg("franken.protocol.x", MetricType::Gauge, &["b"], 2))
            .unwrap();
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
            NamespaceError::VersionMissing("x".into()),
            NamespaceError::FrozenConflict("x".into()),
            NamespaceError::AlreadyDeprecated("x".into()),
            NamespaceError::NotFound("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"TNS_INVALID_NAMESPACE"));
        assert!(codes.contains(&"TNS_VERSION_MISSING"));
        assert!(codes.contains(&"TNS_FROZEN_CONFLICT"));
        assert!(codes.contains(&"TNS_ALREADY_DEPRECATED"));
        assert!(codes.contains(&"TNS_NOT_FOUND"));
    }
}
