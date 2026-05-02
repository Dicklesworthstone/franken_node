//! bd-8tvs: Per-class symbol-size / overhead / fetch policy engine.
//!
//! Each object class (critical marker, trust receipt, replay bundle, telemetry
//! artifact) has distinct performance requirements. This module provides
//! benchmark-derived defaults and a policy override path with auditing.
//!
//! # Invariants
//!
//! - **INV-TUNE-CLASS-SPECIFIC**: Every canonical class has distinct tuning defaults.
//! - **INV-TUNE-OVERRIDE-AUDITED**: All policy overrides are logged with before/after values.
//! - **INV-TUNE-REJECT-INVALID**: Nonsensical overrides (zero size, ratio > 1) are rejected.
//! - **INV-TUNE-DETERMINISTIC**: Same class + config always yields same policy.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const OC_POLICY_ENGINE_INIT: &str = "OC_POLICY_ENGINE_INIT";
pub const OC_POLICY_OVERRIDE_APPLIED: &str = "OC_POLICY_OVERRIDE_APPLIED";
pub const OC_POLICY_OVERRIDE_REJECTED: &str = "OC_POLICY_OVERRIDE_REJECTED";
pub const OC_BENCHMARK_BASELINE_LOADED: &str = "OC_BENCHMARK_BASELINE_LOADED";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_ZERO_SYMBOL_SIZE: &str = "ERR_ZERO_SYMBOL_SIZE";
pub const ERR_INVALID_OVERHEAD_RATIO: &str = "ERR_INVALID_OVERHEAD_RATIO";
pub const ERR_UNKNOWN_CLASS: &str = "ERR_UNKNOWN_CLASS";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Canonical object class identifiers from bd-2573 registry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObjectClass {
    CriticalMarker,
    TrustReceipt,
    ReplayBundle,
    TelemetryArtifact,
    Custom(String),
}

impl ObjectClass {
    pub fn label(&self) -> &str {
        match self {
            Self::CriticalMarker => "critical_marker",
            Self::TrustReceipt => "trust_receipt",
            Self::ReplayBundle => "replay_bundle",
            Self::TelemetryArtifact => "telemetry_artifact",
            Self::Custom(class_id) => class_id.as_str(),
        }
    }

    pub fn canonical_classes() -> Vec<ObjectClass> {
        vec![
            Self::CriticalMarker,
            Self::TrustReceipt,
            Self::ReplayBundle,
            Self::TelemetryArtifact,
        ]
    }

    fn event_class_id(&self) -> String {
        match self {
            Self::Custom(class_id) if invalid_custom_class_id_detail(class_id).is_some() => {
                "custom".to_string()
            }
            _ => self.label().to_string(),
        }
    }

    fn validate_for_override(&self) -> Result<(), TuningError> {
        if let Self::Custom(class_id) = self {
            if let Some(detail) = invalid_custom_class_id_detail(class_id) {
                return Err(TuningError::new(
                    ERR_UNKNOWN_CLASS,
                    format!("Unknown object class {class_id:?}: {detail}"),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Display for ObjectClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Fetch priority for an object class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FetchPriority {
    Critical,
    Normal,
    Background,
}

impl FetchPriority {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Normal => "normal",
            Self::Background => "background",
        }
    }
}

impl fmt::Display for FetchPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Prefetch strategy for an object class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrefetchPolicy {
    Eager,
    Lazy,
    None,
}

impl PrefetchPolicy {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Eager => "eager",
            Self::Lazy => "lazy",
            Self::None => "none",
        }
    }
}

impl fmt::Display for PrefetchPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Tuning parameters for an object class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassTuning {
    pub symbol_size_bytes: u32,
    pub encoding_overhead_ratio: f64,
    pub fetch_priority: FetchPriority,
    pub prefetch_policy: PrefetchPolicy,
}

impl ClassTuning {
    /// Validate tuning parameters.
    pub fn validate(&self) -> Result<(), TuningError> {
        if self.symbol_size_bytes == 0 {
            return Err(TuningError::new(
                ERR_ZERO_SYMBOL_SIZE,
                "Symbol size must be > 0",
            ));
        }
        if !self.encoding_overhead_ratio.is_finite()
            || self.encoding_overhead_ratio < 0.0
            || self.encoding_overhead_ratio > 1.0
        {
            return Err(TuningError::new(
                ERR_INVALID_OVERHEAD_RATIO,
                format!(
                    "Overhead ratio must be finite and in [0.0, 1.0], got {}",
                    self.encoding_overhead_ratio
                ),
            ));
        }
        Ok(())
    }
}

/// Benchmark measurement for a class at a specific symbol size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMeasurement {
    pub class_id: String,
    pub symbol_size_bytes: u32,
    pub overhead_ratio: f64,
    pub fetch_priority: String,
    pub p50_encode_us: f64,
    pub p99_encode_us: f64,
    pub p50_decode_us: f64,
    pub p99_decode_us: f64,
}

/// Error type for tuning operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuningError {
    pub code: String,
    pub message: String,
}

impl TuningError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn unknown_class(class_id: &str) -> Self {
        Self::new(
            ERR_UNKNOWN_CLASS,
            format!("Unknown object class: {}", class_id),
        )
    }
}

fn invalid_custom_class_id_detail(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Some("empty custom class id".to_string());
    }
    if trimmed != value {
        return Some("custom class id contains leading or trailing whitespace".to_string());
    }
    if !value.is_ascii() {
        return Some("custom class id contains non-ASCII characters".to_string());
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Some("custom class id contains control characters".to_string());
    }
    if value.starts_with('/') {
        return Some("custom class id starts with '/'".to_string());
    }
    if value.contains('\\') {
        return Some("custom class id contains backslash".to_string());
    }
    if value.split('/').any(|segment| segment == "..") {
        return Some("custom class id contains path traversal segment".to_string());
    }
    None
}

impl fmt::Display for TuningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Audit event for policy override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningEvent {
    pub code: String,
    pub class_id: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Benchmark-derived defaults
// ---------------------------------------------------------------------------

/// Return benchmark-derived default tuning for a canonical class.
pub fn default_tuning(class: &ObjectClass) -> Option<ClassTuning> {
    match class {
        ObjectClass::CriticalMarker => Some(ClassTuning {
            symbol_size_bytes: 256,
            encoding_overhead_ratio: 0.02,
            fetch_priority: FetchPriority::Critical,
            prefetch_policy: PrefetchPolicy::Eager,
        }),
        ObjectClass::TrustReceipt => Some(ClassTuning {
            symbol_size_bytes: 1024,
            encoding_overhead_ratio: 0.05,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        }),
        ObjectClass::ReplayBundle => Some(ClassTuning {
            symbol_size_bytes: 16384,
            encoding_overhead_ratio: 0.08,
            fetch_priority: FetchPriority::Background,
            prefetch_policy: PrefetchPolicy::None,
        }),
        ObjectClass::TelemetryArtifact => Some(ClassTuning {
            symbol_size_bytes: 4096,
            encoding_overhead_ratio: 0.04,
            fetch_priority: FetchPriority::Background,
            prefetch_policy: PrefetchPolicy::None,
        }),
        ObjectClass::Custom(_) => None,
    }
}

// ---------------------------------------------------------------------------
// ObjectClassTuningEngine
// ---------------------------------------------------------------------------

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::push_bounded;

/// Policy engine that resolves per-class tuning with override support.
pub struct ObjectClassTuningEngine {
    overrides: BTreeMap<ObjectClass, ClassTuning>,
    events: Vec<TuningEvent>,
}

impl ObjectClassTuningEngine {
    pub fn new() -> Self {
        Self {
            overrides: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub fn with_init_event() -> Self {
        let mut engine = Self::new();
        push_bounded(
            &mut engine.events,
            TuningEvent {
                code: OC_POLICY_ENGINE_INIT.to_string(),
                class_id: String::new(),
                detail: "Policy engine initialized with benchmark defaults".to_string(),
            },
            MAX_EVENTS,
        );
        engine
    }

    /// Resolve the effective tuning for a class (override > default).
    pub fn resolve(&self, class: &ObjectClass) -> Option<ClassTuning> {
        if let Some(override_tuning) = self.overrides.get(class) {
            return Some(override_tuning.clone());
        }
        default_tuning(class)
    }

    /// Apply a policy override. Validates parameters and logs the change.
    pub fn apply_override(
        &mut self,
        class: ObjectClass,
        tuning: ClassTuning,
    ) -> Result<(), TuningError> {
        let event_class_id = class.event_class_id();
        if let Err(e) = class.validate_for_override() {
            push_bounded(
                &mut self.events,
                TuningEvent {
                    code: OC_POLICY_OVERRIDE_REJECTED.to_string(),
                    class_id: event_class_id,
                    detail: format!("Override rejected: {}", e),
                },
                MAX_EVENTS,
            );
            return Err(e);
        }

        // Validate
        if let Err(e) = tuning.validate() {
            push_bounded(
                &mut self.events,
                TuningEvent {
                    code: OC_POLICY_OVERRIDE_REJECTED.to_string(),
                    class_id: event_class_id,
                    detail: format!("Override rejected: {}", e),
                },
                MAX_EVENTS,
            );
            return Err(e);
        }

        // For custom classes, verify they have defaults or are known
        let before = self.resolve(&class);
        let before_desc = before
            .as_ref()
            .map(|t| {
                format!(
                    "symbol_size={}, overhead={:.3}, priority={}, prefetch={}",
                    t.symbol_size_bytes,
                    t.encoding_overhead_ratio,
                    t.fetch_priority.label(),
                    t.prefetch_policy.label()
                )
            })
            .unwrap_or_else(|| "none".to_string());

        let after_desc = format!(
            "symbol_size={}, overhead={:.3}, priority={}, prefetch={}",
            tuning.symbol_size_bytes,
            tuning.encoding_overhead_ratio,
            tuning.fetch_priority.label(),
            tuning.prefetch_policy.label()
        );

        self.overrides.insert(class.clone(), tuning);

        push_bounded(
            &mut self.events,
            TuningEvent {
                code: OC_POLICY_OVERRIDE_APPLIED.to_string(),
                class_id: event_class_id,
                detail: format!("before=[{}], after=[{}]", before_desc, after_desc),
            },
            MAX_EVENTS,
        );

        Ok(())
    }

    /// Remove a policy override, reverting to benchmark default.
    pub fn remove_override(&mut self, class: &ObjectClass) -> bool {
        self.overrides.remove(class).is_some()
    }

    /// Check whether a class has an active override.
    pub fn has_override(&self, class: &ObjectClass) -> bool {
        self.overrides.contains_key(class)
    }

    /// Return all active overrides.
    pub fn active_overrides(&self) -> &BTreeMap<ObjectClass, ClassTuning> {
        &self.overrides
    }

    /// All emitted events.
    pub fn events(&self) -> &[TuningEvent] {
        &self.events
    }

    /// Load benchmark baseline data (emits event).
    pub fn load_benchmark_baseline(&mut self, measurements: &[BenchmarkMeasurement]) {
        push_bounded(
            &mut self.events,
            TuningEvent {
                code: OC_BENCHMARK_BASELINE_LOADED.to_string(),
                class_id: String::new(),
                detail: format!("Loaded {} benchmark measurements", measurements.len()),
            },
            MAX_EVENTS,
        );
    }

    /// Export policy report as CSV rows.
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "class_id,symbol_size_bytes,overhead_ratio,fetch_priority,prefetch_policy\n",
        );
        for class in ObjectClass::canonical_classes() {
            if let Some(tuning) = self.resolve(&class) {
                out.push_str(&format!(
                    "{},{},{:.4},{},{}\n",
                    class.label(),
                    tuning.symbol_size_bytes,
                    tuning.encoding_overhead_ratio,
                    tuning.fetch_priority.label(),
                    tuning.prefetch_policy.label(),
                ));
            }
        }
        out
    }
}

impl Default for ObjectClassTuningEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<ObjectClassTuningEngine>();
    assert_sync::<ObjectClassTuningEngine>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Default tuning per class --

    #[test]
    fn test_critical_marker_defaults() {
        let tuning = default_tuning(&ObjectClass::CriticalMarker).unwrap();
        assert_eq!(tuning.symbol_size_bytes, 256);
        assert_eq!(tuning.fetch_priority, FetchPriority::Critical);
        assert_eq!(tuning.prefetch_policy, PrefetchPolicy::Eager);
    }

    #[test]
    fn test_trust_receipt_defaults() {
        let tuning = default_tuning(&ObjectClass::TrustReceipt).unwrap();
        assert_eq!(tuning.symbol_size_bytes, 1024);
        assert_eq!(tuning.fetch_priority, FetchPriority::Normal);
        assert_eq!(tuning.prefetch_policy, PrefetchPolicy::Lazy);
    }

    #[test]
    fn test_replay_bundle_defaults() {
        let tuning = default_tuning(&ObjectClass::ReplayBundle).unwrap();
        assert_eq!(tuning.symbol_size_bytes, 16384);
        assert_eq!(tuning.fetch_priority, FetchPriority::Background);
        assert_eq!(tuning.prefetch_policy, PrefetchPolicy::None);
    }

    #[test]
    fn test_telemetry_artifact_defaults() {
        let tuning = default_tuning(&ObjectClass::TelemetryArtifact).unwrap();
        assert_eq!(tuning.symbol_size_bytes, 4096);
        assert_eq!(tuning.fetch_priority, FetchPriority::Background);
    }

    #[test]
    fn test_custom_class_no_default() {
        assert!(default_tuning(&ObjectClass::Custom("unknown".into())).is_none());
    }

    #[test]
    fn test_all_canonical_classes_have_distinct_symbol_sizes() {
        let sizes: Vec<u32> = ObjectClass::canonical_classes()
            .iter()
            .map(|c| default_tuning(c).unwrap().symbol_size_bytes)
            .collect();
        let unique: std::collections::BTreeSet<u32> = sizes.iter().copied().collect();
        assert_eq!(
            sizes.len(),
            unique.len(),
            "All canonical classes should have distinct symbol sizes"
        );
    }

    // -- Validation --

    #[test]
    fn test_validate_valid_tuning() {
        let tuning = ClassTuning {
            symbol_size_bytes: 1024,
            encoding_overhead_ratio: 0.05,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        assert!(tuning.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_symbol_size() {
        let tuning = ClassTuning {
            symbol_size_bytes: 0,
            encoding_overhead_ratio: 0.05,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        let err = tuning.validate().unwrap_err();
        assert_eq!(err.code, ERR_ZERO_SYMBOL_SIZE);
    }

    #[test]
    fn test_validate_negative_overhead() {
        let tuning = ClassTuning {
            symbol_size_bytes: 1024,
            encoding_overhead_ratio: -0.1,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        let err = tuning.validate().unwrap_err();
        assert_eq!(err.code, ERR_INVALID_OVERHEAD_RATIO);
    }

    #[test]
    fn test_validate_overhead_above_one() {
        let tuning = ClassTuning {
            symbol_size_bytes: 1024,
            encoding_overhead_ratio: 1.5,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        let err = tuning.validate().unwrap_err();
        assert_eq!(err.code, ERR_INVALID_OVERHEAD_RATIO);
    }

    #[test]
    fn test_validate_nan_overhead_rejected() {
        let tuning = ClassTuning {
            symbol_size_bytes: 1024,
            encoding_overhead_ratio: f64::NAN,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        let err = tuning.validate().unwrap_err();
        assert_eq!(err.code, ERR_INVALID_OVERHEAD_RATIO);
    }

    #[test]
    fn test_validate_inf_overhead_rejected() {
        let tuning = ClassTuning {
            symbol_size_bytes: 1024,
            encoding_overhead_ratio: f64::INFINITY,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        let err = tuning.validate().unwrap_err();
        assert_eq!(err.code, ERR_INVALID_OVERHEAD_RATIO);
    }

    #[test]
    fn test_validate_negative_inf_overhead_rejected() {
        let tuning = ClassTuning {
            symbol_size_bytes: 1024,
            encoding_overhead_ratio: f64::NEG_INFINITY,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        let err = tuning.validate().unwrap_err();
        assert_eq!(err.code, ERR_INVALID_OVERHEAD_RATIO);
    }

    #[test]
    fn test_zero_symbol_size_error_precedes_bad_overhead() {
        let tuning = ClassTuning {
            symbol_size_bytes: 0,
            encoding_overhead_ratio: f64::NAN,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        let err = tuning.validate().unwrap_err();
        assert_eq!(err.code, ERR_ZERO_SYMBOL_SIZE);
    }

    // -- Engine resolve --

    #[test]
    fn test_engine_resolve_defaults() {
        let engine = ObjectClassTuningEngine::new();
        let tuning = engine.resolve(&ObjectClass::CriticalMarker).unwrap();
        assert_eq!(tuning.symbol_size_bytes, 256);
    }

    #[test]
    fn test_engine_resolve_custom_returns_none() {
        let engine = ObjectClassTuningEngine::new();
        assert!(engine.resolve(&ObjectClass::Custom("x".into())).is_none());
    }

    // -- Override --

    #[test]
    fn test_engine_apply_valid_override() {
        let mut engine = ObjectClassTuningEngine::new();
        let tuning = ClassTuning {
            symbol_size_bytes: 512,
            encoding_overhead_ratio: 0.03,
            fetch_priority: FetchPriority::Critical,
            prefetch_policy: PrefetchPolicy::Eager,
        };
        engine
            .apply_override(ObjectClass::CriticalMarker, tuning.clone())
            .unwrap();
        let resolved = engine.resolve(&ObjectClass::CriticalMarker).unwrap();
        assert_eq!(resolved.symbol_size_bytes, 512);
    }

    #[test]
    fn test_engine_override_emits_event() {
        let mut engine = ObjectClassTuningEngine::new();
        let tuning = ClassTuning {
            symbol_size_bytes: 512,
            encoding_overhead_ratio: 0.03,
            fetch_priority: FetchPriority::Critical,
            prefetch_policy: PrefetchPolicy::Eager,
        };
        engine
            .apply_override(ObjectClass::CriticalMarker, tuning)
            .unwrap();
        let override_events: Vec<_> = engine
            .events()
            .iter()
            .filter(|e| e.code == OC_POLICY_OVERRIDE_APPLIED)
            .collect();
        assert_eq!(override_events.len(), 1);
        assert!(override_events[0].detail.contains("before="));
        assert!(override_events[0].detail.contains("after="));
    }

    #[test]
    fn test_custom_override_event_uses_specific_class_id() {
        let mut engine = ObjectClassTuningEngine::new();
        let class = ObjectClass::Custom("custom_bundle".into());
        let tuning = ClassTuning {
            symbol_size_bytes: 777,
            encoding_overhead_ratio: 0.10,
            fetch_priority: FetchPriority::Background,
            prefetch_policy: PrefetchPolicy::Lazy,
        };

        engine.apply_override(class, tuning).unwrap();

        let event = engine
            .events()
            .iter()
            .find(|event| event.code == OC_POLICY_OVERRIDE_APPLIED)
            .expect("custom override should emit an applied event");
        assert_eq!(event.class_id, "custom_bundle");
    }

    #[test]
    fn test_engine_reject_invalid_override() {
        let mut engine = ObjectClassTuningEngine::new();
        let tuning = ClassTuning {
            symbol_size_bytes: 0,
            encoding_overhead_ratio: 0.05,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        let err = engine
            .apply_override(ObjectClass::TrustReceipt, tuning)
            .unwrap_err();
        assert_eq!(err.code, ERR_ZERO_SYMBOL_SIZE);
    }

    #[test]
    fn test_engine_reject_emits_event() {
        let mut engine = ObjectClassTuningEngine::new();
        let tuning = ClassTuning {
            symbol_size_bytes: 0,
            encoding_overhead_ratio: 0.05,
            fetch_priority: FetchPriority::Normal,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        let _ = engine.apply_override(ObjectClass::TrustReceipt, tuning);
        let reject_events: Vec<_> = engine
            .events()
            .iter()
            .filter(|e| e.code == OC_POLICY_OVERRIDE_REJECTED)
            .collect();
        assert_eq!(reject_events.len(), 1);
    }

    #[test]
    fn test_invalid_override_does_not_replace_default() {
        let mut engine = ObjectClassTuningEngine::new();
        let before = engine.resolve(&ObjectClass::TrustReceipt).unwrap();
        let tuning = ClassTuning {
            symbol_size_bytes: 2048,
            encoding_overhead_ratio: 1.25,
            fetch_priority: FetchPriority::Critical,
            prefetch_policy: PrefetchPolicy::Eager,
        };

        let err = engine
            .apply_override(ObjectClass::TrustReceipt, tuning)
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_OVERHEAD_RATIO);
        assert!(!engine.has_override(&ObjectClass::TrustReceipt));
        assert_eq!(engine.resolve(&ObjectClass::TrustReceipt).unwrap(), before);
    }

    #[test]
    fn test_invalid_custom_override_does_not_create_class() {
        let mut engine = ObjectClassTuningEngine::new();
        let class = ObjectClass::Custom("unregistered".into());
        let tuning = ClassTuning {
            symbol_size_bytes: 0,
            encoding_overhead_ratio: 0.25,
            fetch_priority: FetchPriority::Background,
            prefetch_policy: PrefetchPolicy::None,
        };

        let err = engine.apply_override(class.clone(), tuning).unwrap_err();

        assert_eq!(err.code, ERR_ZERO_SYMBOL_SIZE);
        assert!(!engine.has_override(&class));
        assert!(engine.resolve(&class).is_none());
    }

    #[test]
    fn test_multiple_invalid_overrides_accumulate_rejections_without_overrides() {
        let mut engine = ObjectClassTuningEngine::new();
        for ratio in [-0.1, 1.1, f64::INFINITY] {
            let tuning = ClassTuning {
                symbol_size_bytes: 1024,
                encoding_overhead_ratio: ratio,
                fetch_priority: FetchPriority::Normal,
                prefetch_policy: PrefetchPolicy::Lazy,
            };
            let _ = engine.apply_override(ObjectClass::TelemetryArtifact, tuning);
        }

        let reject_events = engine
            .events()
            .iter()
            .filter(|event| event.code == OC_POLICY_OVERRIDE_REJECTED)
            .count();

        assert_eq!(reject_events, 3);
        assert!(engine.active_overrides().is_empty());
    }

    #[test]
    fn test_invalid_custom_class_ids_fail_closed() {
        let mut engine = ObjectClassTuningEngine::new();
        let tuning = ClassTuning {
            symbol_size_bytes: 1024,
            encoding_overhead_ratio: 0.25,
            fetch_priority: FetchPriority::Background,
            prefetch_policy: PrefetchPolicy::None,
        };

        for class_id in [
            "",
            " custom ",
            "../escape",
            "/absolute",
            "bad\\path",
            "bad\0id",
        ] {
            let class = ObjectClass::Custom(class_id.into());
            let err = engine
                .apply_override(class.clone(), tuning.clone())
                .unwrap_err();
            assert_eq!(err.code, ERR_UNKNOWN_CLASS);
            assert!(!engine.has_override(&class));
            assert!(engine.resolve(&class).is_none());
        }
    }

    // -- Override management --

    #[test]
    fn test_remove_override() {
        let mut engine = ObjectClassTuningEngine::new();
        let tuning = ClassTuning {
            symbol_size_bytes: 512,
            encoding_overhead_ratio: 0.03,
            fetch_priority: FetchPriority::Critical,
            prefetch_policy: PrefetchPolicy::Eager,
        };
        engine
            .apply_override(ObjectClass::CriticalMarker, tuning)
            .unwrap();
        assert!(engine.has_override(&ObjectClass::CriticalMarker));
        assert!(engine.remove_override(&ObjectClass::CriticalMarker));
        assert!(!engine.has_override(&ObjectClass::CriticalMarker));
        // Should revert to default
        let resolved = engine.resolve(&ObjectClass::CriticalMarker).unwrap();
        assert_eq!(resolved.symbol_size_bytes, 256);
    }

    #[test]
    fn test_remove_missing_override_returns_false_without_event() {
        let mut engine = ObjectClassTuningEngine::new();

        let removed = engine.remove_override(&ObjectClass::ReplayBundle);

        assert!(!removed);
        assert!(engine.events().is_empty());
        assert!(engine.active_overrides().is_empty());
    }

    #[test]
    fn test_active_overrides() {
        let mut engine = ObjectClassTuningEngine::new();
        assert!(engine.active_overrides().is_empty());
        let tuning = ClassTuning {
            symbol_size_bytes: 512,
            encoding_overhead_ratio: 0.03,
            fetch_priority: FetchPriority::Critical,
            prefetch_policy: PrefetchPolicy::Eager,
        };
        engine
            .apply_override(ObjectClass::CriticalMarker, tuning)
            .unwrap();
        assert_eq!(engine.active_overrides().len(), 1);
    }

    // -- Init event --

    #[test]
    fn test_with_init_event() {
        let engine = ObjectClassTuningEngine::with_init_event();
        assert_eq!(engine.events().len(), 1);
        assert_eq!(engine.events()[0].code, OC_POLICY_ENGINE_INIT);
    }

    // -- Benchmark baseline --

    #[test]
    fn test_load_benchmark_baseline() {
        let mut engine = ObjectClassTuningEngine::new();
        let measurements = vec![BenchmarkMeasurement {
            class_id: "critical_marker".into(),
            symbol_size_bytes: 256,
            overhead_ratio: 0.02,
            fetch_priority: "critical".into(),
            p50_encode_us: 1.5,
            p99_encode_us: 5.0,
            p50_decode_us: 1.2,
            p99_decode_us: 4.0,
        }];
        engine.load_benchmark_baseline(&measurements);
        let baseline_events: Vec<_> = engine
            .events()
            .iter()
            .filter(|e| e.code == OC_BENCHMARK_BASELINE_LOADED)
            .collect();
        assert_eq!(baseline_events.len(), 1);
    }

    #[test]
    fn test_empty_benchmark_baseline_still_records_zero_count() {
        let mut engine = ObjectClassTuningEngine::new();

        engine.load_benchmark_baseline(&[]);

        assert_eq!(engine.events().len(), 1);
        assert!(
            engine.events()[0]
                .detail
                .contains("Loaded 0 benchmark measurements")
        );
    }

    // -- CSV export --

    #[test]
    fn test_csv_export_header() {
        let engine = ObjectClassTuningEngine::new();
        let csv = engine.to_csv();
        assert!(csv.starts_with("class_id,symbol_size_bytes,"));
    }

    #[test]
    fn test_csv_export_has_all_canonical_classes() {
        let engine = ObjectClassTuningEngine::new();
        let csv = engine.to_csv();
        assert!(csv.contains("critical_marker"));
        assert!(csv.contains("trust_receipt"));
        assert!(csv.contains("replay_bundle"));
        assert!(csv.contains("telemetry_artifact"));
    }

    #[test]
    fn test_csv_export_row_count() {
        let engine = ObjectClassTuningEngine::new();
        let csv = engine.to_csv();
        let lines: Vec<&str> = csv.trim().lines().collect();
        assert_eq!(lines.len(), 5); // header + 4 classes
    }

    #[test]
    fn test_csv_export_excludes_custom_override_rows() {
        let mut engine = ObjectClassTuningEngine::new();
        let class = ObjectClass::Custom("custom_bundle".into());
        let tuning = ClassTuning {
            symbol_size_bytes: 777,
            encoding_overhead_ratio: 0.10,
            fetch_priority: FetchPriority::Background,
            prefetch_policy: PrefetchPolicy::Lazy,
        };
        engine.apply_override(class, tuning).unwrap();

        let csv = engine.to_csv();

        assert!(!csv.contains("custom_bundle"));
        assert!(!csv.contains("777"));
    }

    // -- Labels --

    #[test]
    fn test_object_class_labels() {
        assert_eq!(ObjectClass::CriticalMarker.label(), "critical_marker");
        assert_eq!(ObjectClass::TrustReceipt.label(), "trust_receipt");
        assert_eq!(ObjectClass::ReplayBundle.label(), "replay_bundle");
        assert_eq!(ObjectClass::TelemetryArtifact.label(), "telemetry_artifact");
        assert_eq!(ObjectClass::Custom("x".into()).label(), "x");
    }

    #[test]
    fn test_fetch_priority_labels() {
        assert_eq!(FetchPriority::Critical.label(), "critical");
        assert_eq!(FetchPriority::Normal.label(), "normal");
        assert_eq!(FetchPriority::Background.label(), "background");
    }

    #[test]
    fn test_prefetch_policy_labels() {
        assert_eq!(PrefetchPolicy::Eager.label(), "eager");
        assert_eq!(PrefetchPolicy::Lazy.label(), "lazy");
        assert_eq!(PrefetchPolicy::None.label(), "none");
    }

    // -- Event codes --

    #[test]
    fn test_event_codes_defined() {
        assert!(!OC_POLICY_ENGINE_INIT.is_empty());
        assert!(!OC_POLICY_OVERRIDE_APPLIED.is_empty());
        assert!(!OC_POLICY_OVERRIDE_REJECTED.is_empty());
        assert!(!OC_BENCHMARK_BASELINE_LOADED.is_empty());
    }

    // -- Error codes --

    #[test]
    fn test_error_codes_defined() {
        assert!(!ERR_ZERO_SYMBOL_SIZE.is_empty());
        assert!(!ERR_INVALID_OVERHEAD_RATIO.is_empty());
        assert!(!ERR_UNKNOWN_CLASS.is_empty());
    }

    // -- Serde --

    #[test]
    fn test_class_tuning_serde_roundtrip() {
        let tuning = default_tuning(&ObjectClass::CriticalMarker).unwrap();
        let json = serde_json::to_string(&tuning).unwrap();
        let parsed: ClassTuning = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tuning);
    }

    #[test]
    fn test_object_class_serde_roundtrip() {
        let class = ObjectClass::TrustReceipt;
        let json = serde_json::to_string(&class).unwrap();
        let parsed: ObjectClass = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, class);
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let err = TuningError::unknown_class("bad");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: TuningError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    // -- Determinism --

    #[test]
    fn test_deterministic_resolution() {
        let engine1 = ObjectClassTuningEngine::new();
        let engine2 = ObjectClassTuningEngine::new();
        for class in ObjectClass::canonical_classes() {
            assert_eq!(engine1.resolve(&class), engine2.resolve(&class));
        }
    }

    // -- Canonical class count --

    #[test]
    fn test_four_canonical_classes() {
        assert_eq!(ObjectClass::canonical_classes().len(), 4);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_tuning_event_window() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_preserves_latest_tuning_events() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 3);

        assert_eq!(items, vec![2, 3, 4]);
    }
}
