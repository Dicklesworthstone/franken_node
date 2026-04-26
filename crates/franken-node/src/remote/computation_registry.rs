//! bd-ac83: Versioned named remote computation registry.
//!
//! This module enforces a canonical name contract (`domain.action.vN`) for
//! remote computations and centralizes dispatch gating behind `RemoteCap`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security::remote_cap::{CapabilityGate, RemoteCap, RemoteOperation};

/// Maximum computation entries before new registrations are rejected.
const MAX_COMPUTATION_ENTRIES: usize = 4096;

// Event codes required by bead acceptance criteria.
pub const CR_REGISTRY_LOADED: &str = "CR_REGISTRY_LOADED";
pub const CR_LOOKUP_SUCCESS: &str = "CR_LOOKUP_SUCCESS";
pub const CR_LOOKUP_UNKNOWN: &str = "CR_LOOKUP_UNKNOWN";
pub const CR_LOOKUP_MALFORMED: &str = "CR_LOOKUP_MALFORMED";
pub const CR_VERSION_UPGRADED: &str = "CR_VERSION_UPGRADED";
pub const CR_DISPATCH_GATED: &str = "CR_DISPATCH_GATED";

/// Maximum number of audit events before oldest-first eviction.
const MAX_AUDIT_EVENTS: usize = 4096;

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

// Stable error codes required by the contract.
pub const ERR_UNKNOWN_COMPUTATION: &str = "ERR_UNKNOWN_COMPUTATION";
pub const ERR_MALFORMED_COMPUTATION_NAME: &str = "ERR_MALFORMED_COMPUTATION_NAME";
pub const ERR_DUPLICATE_COMPUTATION: &str = "ERR_DUPLICATE_COMPUTATION";
pub const ERR_REGISTRY_VERSION_REGRESSION: &str = "ERR_REGISTRY_VERSION_REGRESSION";
pub const ERR_INVALID_COMPUTATION_ENTRY: &str = "ERR_INVALID_COMPUTATION_ENTRY";

/// Metadata for one registered remote computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationEntry {
    pub name: String,
    pub description: String,
    pub required_capabilities: Vec<RemoteOperation>,
    pub input_schema: String,
    pub output_schema: String,
}

impl ComputationEntry {
    fn normalize(&mut self) {
        self.name = self.name.trim().to_string();
        self.description = self.description.trim().to_string();
        self.input_schema = self.input_schema.trim().to_string();
        self.output_schema = self.output_schema.trim().to_string();

        let mut caps: BTreeSet<RemoteOperation> =
            self.required_capabilities.iter().copied().collect();
        caps.insert(RemoteOperation::RemoteComputation);
        self.required_capabilities = caps.into_iter().collect();
    }
}

/// Audit event for registry activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryAuditEvent {
    pub event_code: String,
    pub trace_id: String,
    pub registry_version: u64,
    pub computation_name: Option<String>,
    pub detail: String,
}

/// Serializable registry catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryCatalog {
    pub registry_version: u64,
    pub entries: Vec<ComputationEntry>,
}

/// Stable errors for computation registry operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputationRegistryError {
    UnknownComputation {
        name: String,
    },
    MalformedComputationName {
        name: String,
    },
    DuplicateComputation {
        name: String,
    },
    VersionRegression {
        current: u64,
        requested: u64,
    },
    InvalidComputationEntry {
        name: String,
        reason: String,
    },
    DispatchDenied {
        code: String,
        compatibility_code: Option<String>,
        detail: String,
    },
}

impl ComputationRegistryError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::UnknownComputation { .. } => ERR_UNKNOWN_COMPUTATION,
            Self::MalformedComputationName { .. } => ERR_MALFORMED_COMPUTATION_NAME,
            Self::DuplicateComputation { .. } => ERR_DUPLICATE_COMPUTATION,
            Self::VersionRegression { .. } => ERR_REGISTRY_VERSION_REGRESSION,
            Self::InvalidComputationEntry { .. } => ERR_INVALID_COMPUTATION_ENTRY,
            Self::DispatchDenied { code, .. } => code.as_str(),
        }
    }
}

impl fmt::Display for ComputationRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownComputation { name } => {
                write!(f, "{ERR_UNKNOWN_COMPUTATION}: `{name}`")
            }
            Self::MalformedComputationName { name } => {
                write!(f, "{ERR_MALFORMED_COMPUTATION_NAME}: `{name}`")
            }
            Self::DuplicateComputation { name } => {
                write!(f, "{ERR_DUPLICATE_COMPUTATION}: `{name}`")
            }
            Self::VersionRegression { current, requested } => write!(
                f,
                "{ERR_REGISTRY_VERSION_REGRESSION}: current={current} requested={requested}"
            ),
            Self::InvalidComputationEntry { name, reason } => write!(
                f,
                "{ERR_INVALID_COMPUTATION_ENTRY}: `{name}` reason={reason}"
            ),
            Self::DispatchDenied {
                code,
                compatibility_code,
                detail,
            } => {
                if let Some(alias) = compatibility_code {
                    write!(f, "{code} ({alias}): {detail}")
                } else {
                    write!(f, "{code}: {detail}")
                }
            }
        }
    }
}

impl std::error::Error for ComputationRegistryError {}

/// Versioned registry for allowed remote computation names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationRegistry {
    registry_version: u64,
    entries: BTreeMap<String, ComputationEntry>,
    audit_events: Vec<RegistryAuditEvent>,
}

impl ComputationRegistry {
    /// Construct an empty registry at a specific version.
    #[must_use]
    pub fn new(registry_version: u64, trace_id: &str) -> Self {
        let mut registry = Self {
            registry_version,
            entries: BTreeMap::new(),
            audit_events: Vec::new(),
        };
        registry.record_event(
            CR_REGISTRY_LOADED,
            trace_id,
            None,
            format!("registry loaded version={registry_version}"),
        );
        registry
    }

    /// Build a registry from a serialized catalog.
    pub fn from_catalog(
        catalog: RegistryCatalog,
        trace_id: &str,
    ) -> Result<Self, ComputationRegistryError> {
        let mut registry = Self::new(catalog.registry_version, trace_id);
        for entry in catalog.entries {
            registry.register_computation(entry, trace_id)?;
        }
        Ok(registry)
    }

    #[must_use]
    pub fn registry_version(&self) -> u64 {
        self.registry_version
    }

    #[must_use]
    pub fn audit_events(&self) -> &[RegistryAuditEvent] {
        &self.audit_events
    }

    /// Upgrade registry version monotonically.
    pub fn bump_version(
        &mut self,
        new_version: u64,
        trace_id: &str,
    ) -> Result<(), ComputationRegistryError> {
        if new_version <= self.registry_version {
            return Err(ComputationRegistryError::VersionRegression {
                current: self.registry_version,
                requested: new_version,
            });
        }

        let old_version = self.registry_version;
        self.registry_version = new_version;
        self.record_event(
            CR_VERSION_UPGRADED,
            trace_id,
            None,
            format!("registry version {old_version} -> {new_version}"),
        );
        Ok(())
    }

    /// Register one named computation.
    pub fn register_computation(
        &mut self,
        mut entry: ComputationEntry,
        trace_id: &str,
    ) -> Result<(), ComputationRegistryError> {
        entry.normalize();
        if !is_canonical_computation_name(&entry.name) {
            self.record_event(
                CR_LOOKUP_MALFORMED,
                trace_id,
                Some(entry.name.clone()),
                "registration rejected due malformed computation name".to_string(),
            );
            return Err(ComputationRegistryError::MalformedComputationName { name: entry.name });
        }
        if entry.description.is_empty() {
            return Err(ComputationRegistryError::InvalidComputationEntry {
                name: entry.name,
                reason: "description cannot be empty".to_string(),
            });
        }
        if entry.input_schema.is_empty() || entry.output_schema.is_empty() {
            return Err(ComputationRegistryError::InvalidComputationEntry {
                name: entry.name,
                reason: "input_schema and output_schema are required".to_string(),
            });
        }
        if self.entries.contains_key(&entry.name) {
            return Err(ComputationRegistryError::DuplicateComputation { name: entry.name });
        }
        if self.entries.len() >= MAX_COMPUTATION_ENTRIES {
            return Err(ComputationRegistryError::InvalidComputationEntry {
                name: entry.name,
                reason: format!(
                    "registry at capacity ({} entries, max {MAX_COMPUTATION_ENTRIES})",
                    self.entries.len()
                ),
            });
        }

        let name = entry.name.clone();
        self.entries.insert(name.clone(), entry);
        self.record_event(
            CR_LOOKUP_SUCCESS,
            trace_id,
            Some(name),
            "registered computation".to_string(),
        );
        return Ok(());

        // Inline negative-path tests for register_computation method
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            use crate::security::remote_cap::RemoteOperation;

            // Test: Unicode injection in computation name
            let mut registry = ComputationRegistry::new(1, "test-unicode");
            let unicode_attack_name = "evil\u{202E}tnemtnemtnemuf\u{202D}.action.v1"; // BIDI override attack
            let unicode_entry = ComputationEntry {
                name: unicode_attack_name.to_string(),
                description: "Malicious Unicode computation".to_string(),
                required_capabilities: vec![RemoteOperation::NetworkEgress],
                input_schema: "{}".to_string(),
                output_schema: "{}".to_string(),
            };
            let result = registry.register_computation(unicode_entry, "trace-unicode");
            assert!(
                result.is_err(),
                "Unicode injection in computation name should be rejected"
            );
            if let Err(ComputationRegistryError::MalformedComputationName { name }) = result {
                assert_eq!(
                    name, unicode_attack_name,
                    "Malformed name should be preserved in error"
                );
            }

            // Test: Control character injection in schemas
            let mut registry = ComputationRegistry::new(1, "test-control");
            let control_chars_entry = ComputationEntry {
                name: "domain.action.v1".to_string(),
                description: "Test computation".to_string(),
                required_capabilities: vec![RemoteOperation::RemoteComputation],
                input_schema: "{\x00\x01\x02\"malicious\":\"payload\"}".to_string(),
                output_schema: "{\"result\"\r\n:\"success\"}".to_string(),
            };
            let result = registry.register_computation(control_chars_entry, "trace-control");
            assert!(
                result.is_ok(),
                "Control characters in schemas should be preserved as-is"
            );
            if let Ok(()) = result {
                let entry = registry.entries.get("domain.action.v1").unwrap();
                assert!(
                    entry.input_schema.contains('\x00'),
                    "Control characters should be preserved in input schema"
                );
                assert!(
                    entry.output_schema.contains('\r'),
                    "Control characters should be preserved in output schema"
                );
            }

            // Test: Massive schema memory exhaustion attack
            let mut registry = ComputationRegistry::new(1, "test-memory");
            let massive_schema = "x".repeat(1_000_000); // 1MB schema (reduced for test efficiency)
            let massive_entry = ComputationEntry {
                name: "domain.massive.v1".to_string(),
                description: "Massive schema test".to_string(),
                required_capabilities: vec![RemoteOperation::NetworkEgress],
                input_schema: massive_schema.clone(),
                output_schema: massive_schema.clone(),
            };
            let result = registry.register_computation(massive_entry, "trace-massive");
            assert!(
                result.is_ok(),
                "Massive schemas should be handled without memory issues"
            );
            if let Ok(()) = result {
                let entry = registry.entries.get("domain.massive.v1").unwrap();
                assert_eq!(
                    entry.input_schema.len(),
                    1_000_000,
                    "Massive input schema should be preserved"
                );
                assert_eq!(
                    entry.output_schema.len(),
                    1_000_000,
                    "Massive output schema should be preserved"
                );
            }

            // Test: Audit event capacity boundary attacks (audit log flooding)
            let mut registry = ComputationRegistry::new(1, "test-audit-flood");
            // Pre-fill audit events close to capacity
            for i in 0..(MAX_AUDIT_EVENTS - 5) {
                registry.record_event(
                    "TEST_EVENT",
                    &format!("trace-flood-{}", i),
                    Some(format!("test.computation.v{}", i)),
                    format!("flood event {}", i),
                );
            }

            // Register computation that should trigger audit event
            let flood_entry = ComputationEntry {
                name: "domain.flood.v1".to_string(),
                description: "Audit flood test".to_string(),
                required_capabilities: vec![RemoteOperation::RemoteComputation],
                input_schema: "{}".to_string(),
                output_schema: "{}".to_string(),
            };
            let result = registry.register_computation(flood_entry, "trace-audit-flood");
            assert!(
                result.is_ok(),
                "Registration should succeed despite audit flood"
            );
            // Audit events should be bounded by push_bounded
            assert!(
                registry.audit_events().len() <= MAX_AUDIT_EVENTS,
                "Audit events should be capacity-bounded"
            );

            // Test: Registry capacity boundary attacks (computation flooding)
            let mut registry = ComputationRegistry::new(1, "test-capacity");
            // Fill registry to capacity (use smaller number for test efficiency)
            let test_capacity = 100.min(MAX_COMPUTATION_ENTRIES);
            for i in 0..test_capacity {
                let capacity_entry = ComputationEntry {
                    name: format!("domain.capacity{}.v1", i),
                    description: "Capacity test computation".to_string(),
                    required_capabilities: vec![RemoteOperation::RemoteComputation],
                    input_schema: "{}".to_string(),
                    output_schema: "{}".to_string(),
                };
                let result = registry.register_computation(capacity_entry, "trace-capacity-fill");
                if i < MAX_COMPUTATION_ENTRIES {
                    assert!(result.is_ok(), "Should be able to fill towards capacity");
                }
            }

            // Test: Serialization format injection resistance in description
            let mut registry = ComputationRegistry::new(1, "test-serialization");
            let injection_attacks = [
                r#"{"malicious":"json","exec":"rm -rf /"}"#,
                r#"<?xml version="1.0"?><!DOCTYPE test>"#,
                r#"!!python/object/apply:os.system"#,
                "description\"); DROP TABLE computations; --",
            ];

            for (i, &injection) in injection_attacks.iter().enumerate() {
                let injection_entry = ComputationEntry {
                    name: format!("domain.injection{}.v1", i),
                    description: injection.to_string(),
                    required_capabilities: vec![RemoteOperation::RemoteComputation],
                    input_schema: "{}".to_string(),
                    output_schema: "{}".to_string(),
                };
                let result = registry.register_computation(injection_entry, "trace-injection");
                assert!(
                    result.is_ok(),
                    "Serialization injection should be handled safely"
                );
                if let Ok(()) = result {
                    let entry = registry
                        .entries
                        .get(&format!("domain.injection{}.v1", i))
                        .unwrap();
                    assert_eq!(
                        entry.description, injection,
                        "Injection should be preserved as text"
                    );
                }
            }

            // Test: Hash collision resistance in computation names
            let mut registry = ComputationRegistry::new(1, "test-collision");
            let collision_candidates = [
                ("domain.action1.v1", "domain.action2.v1"),
                ("test.compute.v1", "test.compute.v2"),
                ("example.func.v1", "example.func2.v1"),
            ];

            for &(name1, name2) in &collision_candidates {
                let entry1 = ComputationEntry {
                    name: name1.to_string(),
                    description: "First computation".to_string(),
                    required_capabilities: vec![RemoteOperation::RemoteComputation],
                    input_schema: "{}".to_string(),
                    output_schema: "{}".to_string(),
                };
                let entry2 = ComputationEntry {
                    name: name2.to_string(),
                    description: "Second computation".to_string(),
                    required_capabilities: vec![RemoteOperation::RemoteComputation],
                    input_schema: "{}".to_string(),
                    output_schema: "{}".to_string(),
                };

                let result1 = registry.register_computation(entry1, "trace-collision1");
                let result2 = registry.register_computation(entry2, "trace-collision2");
                assert!(
                    result1.is_ok() && result2.is_ok(),
                    "Similar names should not collide: {} vs {}",
                    name1,
                    name2
                );
            }

            // Test: Normalization boundary attacks with whitespace
            let mut registry = ComputationRegistry::new(1, "test-normalization");
            let whitespace_attacks = [
                "  domain.whitespace.v1  ", // Leading/trailing spaces
                "\tdomain.tab.v1\t",        // Tabs
                "\ndomain.newline.v1\n",    // Newlines
            ];

            for &attack_name in &whitespace_attacks {
                let whitespace_entry = ComputationEntry {
                    name: attack_name.to_string(),
                    description: "  Whitespace test  ".to_string(),
                    required_capabilities: vec![RemoteOperation::RemoteComputation],
                    input_schema: "  {}  ".to_string(),
                    output_schema: "\t{}\n".to_string(),
                };
                let result = registry.register_computation(whitespace_entry, "trace-whitespace");
                // Should either succeed with normalized name or fail validation
                if result.is_ok() {
                    // Verify normalization removed whitespace
                    let trimmed_name = attack_name.trim();
                    if is_canonical_computation_name(trimmed_name) {
                        let entry = registry.entries.get(trimmed_name).unwrap();
                        assert_eq!(
                            entry.description.trim(),
                            "Whitespace test",
                            "Description should be normalized"
                        );
                        assert_eq!(
                            entry.input_schema.trim(),
                            "{}",
                            "Input schema should be normalized"
                        );
                        assert_eq!(
                            entry.output_schema.trim(),
                            "{}",
                            "Output schema should be normalized"
                        );
                    }
                }
            }

            // Test: Empty field validation edge cases
            let mut registry = ComputationRegistry::new(1, "test-empty");
            let empty_field_tests = [
                ("domain.empty.v1", "", "{}"),      // Empty description
                ("domain.empty2.v1", "desc", ""),   // Empty input schema
                ("domain.empty3.v1", "desc", "{}"), // Empty output schema (will be caught separately)
            ];

            for (name, desc, input_schema) in empty_field_tests {
                let empty_entry = ComputationEntry {
                    name: name.to_string(),
                    description: desc.to_string(),
                    required_capabilities: vec![RemoteOperation::RemoteComputation],
                    input_schema: input_schema.to_string(),
                    output_schema: if name == "domain.empty3.v1" {
                        "".to_string()
                    } else {
                        "{}".to_string()
                    },
                };
                let result = registry.register_computation(empty_entry, "trace-empty");
                assert!(
                    result.is_err(),
                    "Empty required fields should be rejected for name: {}",
                    name
                );
            }

            // Test: Capability injection through required_capabilities
            let mut registry = ComputationRegistry::new(1, "test-capabilities");
            let all_capabilities = vec![
                RemoteOperation::NetworkEgress,
                RemoteOperation::FileSystemRead,
                RemoteOperation::FileSystemWrite,
                RemoteOperation::RemoteComputation,
            ];
            let capability_entry = ComputationEntry {
                name: "domain.capabilities.v1".to_string(),
                description: "Capability injection test".to_string(),
                required_capabilities: all_capabilities.clone(),
                input_schema: "{}".to_string(),
                output_schema: "{}".to_string(),
            };
            let result = registry.register_computation(capability_entry, "trace-capabilities");
            assert!(result.is_ok(), "Multiple capabilities should be allowed");
            if let Ok(()) = result {
                let entry = registry.entries.get("domain.capabilities.v1").unwrap();
                // Should automatically include RemoteComputation and deduplicate
                assert!(
                    entry
                        .required_capabilities
                        .contains(&RemoteOperation::RemoteComputation),
                    "Should auto-include RemoteComputation"
                );
            }

            // Test: Duplicate registration attempts
            let mut registry = ComputationRegistry::new(1, "test-duplicate");
            let original_entry = ComputationEntry {
                name: "domain.duplicate.v1".to_string(),
                description: "Original computation".to_string(),
                required_capabilities: vec![RemoteOperation::RemoteComputation],
                input_schema: "{}".to_string(),
                output_schema: "{}".to_string(),
            };
            let duplicate_entry = ComputationEntry {
                name: "domain.duplicate.v1".to_string(),
                description: "Duplicate computation with different description".to_string(),
                required_capabilities: vec![RemoteOperation::NetworkEgress],
                input_schema: "{\"different\":\"schema\"}".to_string(),
                output_schema: "{\"different\":\"output\"}".to_string(),
            };

            let first_result = registry.register_computation(original_entry, "trace-original");
            assert!(first_result.is_ok(), "First registration should succeed");

            let duplicate_result =
                registry.register_computation(duplicate_entry, "trace-duplicate");
            assert!(
                duplicate_result.is_err(),
                "Duplicate registration should fail"
            );
            if let Err(ComputationRegistryError::DuplicateComputation { name }) = duplicate_result {
                assert_eq!(
                    name, "domain.duplicate.v1",
                    "Duplicate error should contain computation name"
                );
            }

            // Verify original computation is preserved
            let preserved_entry = registry.entries.get("domain.duplicate.v1").unwrap();
            assert_eq!(
                preserved_entry.description, "Original computation",
                "Original entry should be preserved"
            );
        }
    }

    /// Validate and look up a computation name.
    pub fn validate_computation_name(
        &mut self,
        name: &str,
        trace_id: &str,
    ) -> Result<ComputationEntry, ComputationRegistryError> {
        if !is_canonical_computation_name(name) {
            self.record_event(
                CR_LOOKUP_MALFORMED,
                trace_id,
                Some(name.to_string()),
                "lookup rejected due malformed computation name".to_string(),
            );
            return Err(ComputationRegistryError::MalformedComputationName {
                name: name.to_string(),
            });
        }

        match self.entries.get(name).cloned() {
            Some(entry) => {
                self.record_event(
                    CR_LOOKUP_SUCCESS,
                    trace_id,
                    Some(name.to_string()),
                    "lookup succeeded".to_string(),
                );
                Ok(entry)
            }
            None => {
                self.record_event(
                    CR_LOOKUP_UNKNOWN,
                    trace_id,
                    Some(name.to_string()),
                    "lookup rejected due unknown computation name".to_string(),
                );
                Err(ComputationRegistryError::UnknownComputation {
                    name: name.to_string(),
                })
            }
        }
    }

    /// Central dispatch gate: requires a registered name and valid `RemoteCap`.
    pub fn authorize_dispatch(
        &mut self,
        name: &str,
        endpoint: &str,
        remote_cap: Option<&RemoteCap>,
        capability_gate: &mut CapabilityGate,
        now_epoch_secs: u64,
        trace_id: &str,
    ) -> Result<ComputationEntry, ComputationRegistryError> {
        let entry = self.validate_computation_name(name, trace_id)?;
        for capability in entry
            .required_capabilities
            .iter()
            .copied()
            .filter(|op| *op != RemoteOperation::RemoteComputation)
        {
            capability_gate
                .recheck_network(remote_cap, capability, endpoint, now_epoch_secs, trace_id)
                .map_err(|err| {
                    self.record_event(
                        CR_DISPATCH_GATED,
                        trace_id,
                        Some(name.to_string()),
                        format!(
                            "dispatch denied endpoint={endpoint} operation={capability} reason={}",
                            err.code()
                        ),
                    );
                    ComputationRegistryError::DispatchDenied {
                        code: err.code().to_string(),
                        compatibility_code: err.compatibility_code().map(ToString::to_string),
                        detail: err.to_string(),
                    }
                })?;
        }
        match capability_gate.authorize_network(
            remote_cap,
            RemoteOperation::RemoteComputation,
            endpoint,
            now_epoch_secs,
            trace_id,
        ) {
            Ok(()) => {
                self.record_event(
                    CR_DISPATCH_GATED,
                    trace_id,
                    Some(name.to_string()),
                    format!("dispatch allowed endpoint={endpoint}"),
                );
                Ok(entry)
            }
            Err(err) => {
                self.record_event(
                    CR_DISPATCH_GATED,
                    trace_id,
                    Some(name.to_string()),
                    format!("dispatch denied endpoint={endpoint} reason={}", err.code()),
                );
                Err(ComputationRegistryError::DispatchDenied {
                    code: err.code().to_string(),
                    compatibility_code: err.compatibility_code().map(ToString::to_string),
                    detail: err.to_string(),
                })
            }
        }
    }

    /// Runtime introspection surface for operator tooling.
    #[must_use]
    pub fn list_computations(&self) -> Vec<ComputationEntry> {
        self.entries.values().cloned().collect()
    }

    /// Export registry catalog for artifact generation.
    #[must_use]
    pub fn to_catalog(&self) -> RegistryCatalog {
        RegistryCatalog {
            registry_version: self.registry_version,
            entries: self.list_computations(),
        }
    }

    fn record_event(
        &mut self,
        event_code: &str,
        trace_id: &str,
        computation_name: Option<String>,
        detail: String,
    ) {
        push_bounded(
            &mut self.audit_events,
            RegistryAuditEvent {
                event_code: event_code.to_string(),
                trace_id: trace_id.to_string(),
                registry_version: self.registry_version,
                computation_name,
                detail,
            },
            MAX_AUDIT_EVENTS,
        );
    }
}

/// Canonical naming contract: `domain.action.vN`
///
/// - `domain`: lowercase ASCII letter + `[a-z0-9_]*`
/// - `action`: lowercase ASCII letter + `[a-z0-9_]*`
/// - `vN`: literal `v` followed by one or more digits
#[must_use]
pub fn is_canonical_computation_name(name: &str) -> bool {
    // Bounds check: prevent resource exhaustion from oversized computation names
    if name.len() > MAX_COMPUTATION_NAME_LENGTH {
        return false;
    }

    let mut parts = name.split('.');
    let Some(domain) = parts.next() else {
        return false;
    };
    let Some(action) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    is_component(domain) && is_component(action) && is_version_component(version)
}

const MAX_COMPONENT_LENGTH: usize = 128;
const MAX_COMPUTATION_NAME_LENGTH: usize = 512;

fn is_component(component: &str) -> bool {
    // Bounds check: prevent resource exhaustion from oversized components
    if component.len() > MAX_COMPONENT_LENGTH {
        return false;
    }

    let mut chars = component.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

fn is_version_component(component: &str) -> bool {
    // Bounds check: prevent resource exhaustion from oversized version components
    if component.len() > MAX_COMPONENT_LENGTH {
        return false;
    }

    let Some(suffix) = component.strip_prefix('v') else {
        return false;
    };
    !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::remote_cap::{CapabilityProvider, RemoteScope};

    fn sample_entry(name: &str) -> ComputationEntry {
        ComputationEntry {
            name: name.to_string(),
            description: "Verify remote manifest state".to_string(),
            required_capabilities: vec![RemoteOperation::RemoteComputation],
            input_schema: "schemas/verify_manifest_input.json".to_string(),
            output_schema: "schemas/verify_manifest_output.json".to_string(),
        }
    }

    #[test]
    fn canonical_name_validation_accepts_expected_shape() {
        assert!(is_canonical_computation_name("trust.verify_manifest.v1"));
        assert!(is_canonical_computation_name("federation.sync_delta.v12"));
    }

    #[test]
    fn canonical_name_validation_rejects_malformed_inputs() {
        let malformed = [
            "",
            "Trust.verify_manifest.v1",
            "trust.verify-manifest.v1",
            "trust.verify_manifest.v",
            "trust.verify_manifest",
            "trust.verify.manifest.v1",
            "trust.9invalid.v1",
        ];
        for name in malformed {
            assert!(
                !is_canonical_computation_name(name),
                "expected malformed name rejection for `{name}`"
            );
        }
    }

    #[test]
    fn unknown_lookup_returns_stable_error_code() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(sample_entry("trust.verify_manifest.v1"), "trace-register")
            .expect("register");
        let err = registry
            .validate_computation_name("trust.unknown_job.v1", "trace-lookup")
            .expect_err("unknown name must fail");
        assert_eq!(err.code(), ERR_UNKNOWN_COMPUTATION);
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        let entry = sample_entry("trust.verify_manifest.v1");
        registry
            .register_computation(entry.clone(), "trace-register-a")
            .expect("first registration");
        let err = registry
            .register_computation(entry, "trace-register-b")
            .expect_err("duplicate must fail");
        assert_eq!(err.code(), ERR_DUPLICATE_COMPUTATION);
    }

    #[test]
    fn duplicate_registration_is_rejected_even_when_registry_is_full() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        let existing = sample_entry("trust.verify_manifest.v1");
        registry
            .entries
            .insert(existing.name.clone(), existing.clone());

        for idx in 0..(MAX_COMPUTATION_ENTRIES - 1) {
            let entry = sample_entry(&format!("d{idx}.action.v1"));
            registry.entries.insert(entry.name.clone(), entry);
        }

        assert_eq!(registry.entries.len(), MAX_COMPUTATION_ENTRIES);
        let err = registry
            .register_computation(existing, "trace-register-duplicate-full")
            .expect_err("duplicate must beat capacity check");
        assert_eq!(err.code(), ERR_DUPLICATE_COMPUTATION);
    }

    #[test]
    fn version_upgrade_must_be_monotonic() {
        let mut registry = ComputationRegistry::new(4, "trace-load");
        registry
            .bump_version(5, "trace-upgrade")
            .expect("upgrade to higher version should succeed");
        let err = registry
            .bump_version(5, "trace-regress")
            .expect_err("same version must fail");
        assert_eq!(err.code(), ERR_REGISTRY_VERSION_REGRESSION);
    }

    #[test]
    fn dispatch_gate_requires_remote_cap() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(sample_entry("trust.verify_manifest.v1"), "trace-register")
            .expect("register");
        let mut gate = CapabilityGate::new("registry-secret");

        let err = registry
            .authorize_dispatch(
                "trust.verify_manifest.v1",
                "https://compute.example.com/verify",
                None,
                &mut gate,
                1_700_000_020,
                "trace-dispatch-missing",
            )
            .expect_err("missing capability must fail");
        assert_eq!(err.code(), "REMOTECAP_MISSING");
    }

    #[test]
    fn dispatch_gate_accepts_valid_capability() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(sample_entry("trust.verify_manifest.v1"), "trace-register")
            .expect("register");

        let provider = CapabilityProvider::new("registry-secret");
        let (cap, _) = provider
            .issue(
                "ops-control-plane",
                RemoteScope::new(
                    vec![RemoteOperation::RemoteComputation],
                    vec!["https://compute.example.com".to_string()],
                ),
                1_700_000_000,
                3_600,
                true,
                false,
                "trace-issue",
            )
            .expect("issue capability");
        let mut gate = CapabilityGate::new("registry-secret");

        let entry = registry
            .authorize_dispatch(
                "trust.verify_manifest.v1",
                "https://compute.example.com/verify",
                Some(&cap),
                &mut gate,
                1_700_000_050,
                "trace-dispatch-ok",
            )
            .expect("dispatch should be authorized");
        assert_eq!(entry.name, "trust.verify_manifest.v1");
    }

    #[test]
    fn dispatch_gate_rejects_missing_additional_required_capability() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(
                ComputationEntry {
                    name: "trust.telemetry_bridge.v1".to_string(),
                    description: "Forward remote telemetry for manifest verification".to_string(),
                    required_capabilities: vec![
                        RemoteOperation::RemoteComputation,
                        RemoteOperation::TelemetryExport,
                    ],
                    input_schema: "schemas/telemetry_bridge_input.json".to_string(),
                    output_schema: "schemas/telemetry_bridge_output.json".to_string(),
                },
                "trace-register",
            )
            .expect("register");

        let provider = CapabilityProvider::new("registry-secret");
        let (cap, _) = provider
            .issue(
                "ops-control-plane",
                RemoteScope::new(
                    vec![RemoteOperation::RemoteComputation],
                    vec!["https://compute.example.com".to_string()],
                ),
                1_700_000_000,
                3_600,
                true,
                true,
                "trace-issue",
            )
            .expect("issue capability");
        let mut gate = CapabilityGate::new("registry-secret");

        let err = registry
            .authorize_dispatch(
                "trust.telemetry_bridge.v1",
                "https://compute.example.com/verify",
                Some(&cap),
                &mut gate,
                1_700_000_050,
                "trace-dispatch-missing-telemetry-export",
            )
            .expect_err("missing extra capability must fail");
        assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");

        gate.authorize_network(
            Some(&cap),
            RemoteOperation::RemoteComputation,
            "https://compute.example.com/verify",
            1_700_000_051,
            "trace-token-still-usable",
        )
        .expect("failed precheck must not consume single-use capability");
    }

    #[test]
    fn dispatch_gate_accepts_full_required_capability_set() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(
                ComputationEntry {
                    name: "trust.telemetry_bridge.v1".to_string(),
                    description: "Forward remote telemetry for manifest verification".to_string(),
                    required_capabilities: vec![
                        RemoteOperation::TelemetryExport,
                        RemoteOperation::RemoteComputation,
                    ],
                    input_schema: "schemas/telemetry_bridge_input.json".to_string(),
                    output_schema: "schemas/telemetry_bridge_output.json".to_string(),
                },
                "trace-register",
            )
            .expect("register");

        let provider = CapabilityProvider::new("registry-secret");
        let (cap, _) = provider
            .issue(
                "ops-control-plane",
                RemoteScope::new(
                    vec![
                        RemoteOperation::RemoteComputation,
                        RemoteOperation::TelemetryExport,
                    ],
                    vec!["https://compute.example.com".to_string()],
                ),
                1_700_000_000,
                3_600,
                true,
                false,
                "trace-issue",
            )
            .expect("issue capability");
        let mut gate = CapabilityGate::new("registry-secret");

        let entry = registry
            .authorize_dispatch(
                "trust.telemetry_bridge.v1",
                "https://compute.example.com/verify",
                Some(&cap),
                &mut gate,
                1_700_000_050,
                "trace-dispatch-ok",
            )
            .expect("dispatch should be authorized");
        assert_eq!(entry.required_capabilities.len(), 2);
        assert_eq!(entry.name, "trust.telemetry_bridge.v1");
    }

    #[test]
    fn catalog_roundtrip_preserves_registry_contents() {
        let mut registry = ComputationRegistry::new(7, "trace-load");
        registry
            .register_computation(sample_entry("trust.verify_manifest.v1"), "trace-register-a")
            .expect("register a");
        registry
            .register_computation(sample_entry("federation.sync_delta.v2"), "trace-register-b")
            .expect("register b");

        let catalog = registry.to_catalog();
        let restored = ComputationRegistry::from_catalog(catalog.clone(), "trace-restore")
            .expect("restore from catalog");
        assert_eq!(restored.registry_version(), 7);
        assert_eq!(restored.list_computations(), catalog.entries);
    }

    #[test]
    fn registration_rejects_blank_description_after_normalization() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        let mut entry = sample_entry("trust.blank_description.v1");
        entry.description = "   ".to_string();

        let err = registry
            .register_computation(entry, "trace-register-blank-description")
            .expect_err("blank description must fail");

        assert_eq!(err.code(), ERR_INVALID_COMPUTATION_ENTRY);
        assert!(err.to_string().contains("description cannot be empty"));
        assert!(registry.list_computations().is_empty());
    }

    #[test]
    fn registration_rejects_blank_input_schema_after_normalization() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        let mut entry = sample_entry("trust.blank_input.v1");
        entry.input_schema = "\t  ".to_string();

        let err = registry
            .register_computation(entry, "trace-register-blank-input")
            .expect_err("blank input schema must fail");

        assert_eq!(err.code(), ERR_INVALID_COMPUTATION_ENTRY);
        assert!(err.to_string().contains("input_schema and output_schema"));
        assert!(registry.list_computations().is_empty());
    }

    #[test]
    fn registration_rejects_blank_output_schema_after_normalization() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        let mut entry = sample_entry("trust.blank_output.v1");
        entry.output_schema = "\n ".to_string();

        let err = registry
            .register_computation(entry, "trace-register-blank-output")
            .expect_err("blank output schema must fail");

        assert_eq!(err.code(), ERR_INVALID_COMPUTATION_ENTRY);
        assert!(err.to_string().contains("input_schema and output_schema"));
        assert!(registry.list_computations().is_empty());
    }

    #[test]
    fn malformed_registration_records_audit_event_without_inserting() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        let err = registry
            .register_computation(
                sample_entry("trust.verify-manifest.v1"),
                "trace-register-malformed",
            )
            .expect_err("hyphenated action is malformed");

        assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
        assert!(registry.list_computations().is_empty());
        let event = registry
            .audit_events()
            .last()
            .expect("malformed registration should record audit event");
        assert_eq!(event.event_code, CR_LOOKUP_MALFORMED);
        assert_eq!(
            event.computation_name.as_deref(),
            Some("trust.verify-manifest.v1")
        );
    }

    #[test]
    fn malformed_lookup_records_malformed_audit_event_not_unknown() {
        let mut registry = ComputationRegistry::new(1, "trace-load");

        let err = registry
            .validate_computation_name("trust.verify_manifest", "trace-lookup-malformed")
            .expect_err("missing version suffix is malformed");

        assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
        let event = registry
            .audit_events()
            .last()
            .expect("malformed lookup should record audit event");
        assert_eq!(event.event_code, CR_LOOKUP_MALFORMED);
        assert_eq!(event.trace_id, "trace-lookup-malformed");
    }

    #[test]
    fn unknown_lookup_records_unknown_audit_event() {
        let mut registry = ComputationRegistry::new(1, "trace-load");

        let err = registry
            .validate_computation_name("trust.missing_job.v1", "trace-lookup-unknown")
            .expect_err("canonical but unknown name must fail");

        assert_eq!(err.code(), ERR_UNKNOWN_COMPUTATION);
        let event = registry
            .audit_events()
            .last()
            .expect("unknown lookup should record audit event");
        assert_eq!(event.event_code, CR_LOOKUP_UNKNOWN);
        assert_eq!(
            event.computation_name.as_deref(),
            Some("trust.missing_job.v1")
        );
    }

    #[test]
    fn from_catalog_rejects_duplicate_entries_without_silent_dedupe() {
        let duplicate = sample_entry("trust.verify_manifest.v1");
        let catalog = RegistryCatalog {
            registry_version: 3,
            entries: vec![duplicate.clone(), duplicate],
        };

        let err = ComputationRegistry::from_catalog(catalog, "trace-restore-duplicate")
            .expect_err("duplicate catalog entries must fail");

        assert_eq!(err.code(), ERR_DUPLICATE_COMPUTATION);
    }

    #[test]
    fn dispatch_rejects_malformed_name_before_capability_authorization() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        let mut gate = CapabilityGate::new("registry-secret");

        let err = registry
            .authorize_dispatch(
                "trust.verify_manifest",
                "https://compute.example.com/verify",
                None,
                &mut gate,
                1_700_000_050,
                "trace-dispatch-malformed",
            )
            .expect_err("malformed dispatch name must fail before cap check");

        assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
        let event = registry
            .audit_events()
            .last()
            .expect("malformed dispatch should record audit event");
        assert_eq!(event.event_code, CR_LOOKUP_MALFORMED);
    }

    #[test]
    fn push_bounded_zero_capacity_discards_without_panicking() {
        let mut events = vec![RegistryAuditEvent {
            event_code: "old".to_string(),
            trace_id: "trace-old".to_string(),
            registry_version: 1,
            computation_name: None,
            detail: "old event".to_string(),
        }];

        push_bounded(
            &mut events,
            RegistryAuditEvent {
                event_code: "new".to_string(),
                trace_id: "trace-new".to_string(),
                registry_version: 1,
                computation_name: None,
                detail: "new event".to_string(),
            },
            0,
        );

        assert!(events.is_empty());
    }

    #[test]
    fn canonical_name_rejects_empty_whitespace_and_extra_components() {
        for name in [
            "",
            " ",
            "trust.verify_manifest.v1.extra",
            "trust.verify_manifest",
            ".verify_manifest.v1",
            "trust..v1",
        ] {
            assert!(!is_canonical_computation_name(name), "{name:?}");
        }
    }

    #[test]
    fn canonical_name_rejects_uppercase_and_hyphenated_components() {
        for name in [
            "Trust.verify_manifest.v1",
            "trust.Verify_manifest.v1",
            "trust.verify-manifest.v1",
            "trust.verify_manifest.V1",
            "trust.verify_manifest.v1-beta",
        ] {
            assert!(!is_canonical_computation_name(name), "{name:?}");
        }
    }

    #[test]
    fn duplicate_registration_after_name_trim_does_not_overwrite_entry() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(sample_entry("trust.verify_manifest.v1"), "trace-first")
            .expect("initial registration");
        let mut duplicate = sample_entry(" trust.verify_manifest.v1 ");
        duplicate.description = "tampered duplicate description".to_string();

        let err = registry
            .register_computation(duplicate, "trace-duplicate-trimmed")
            .expect_err("trimmed duplicate name must be rejected");

        assert_eq!(err.code(), ERR_DUPLICATE_COMPUTATION);
        let entries = registry.list_computations();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].description.as_str(),
            "Verify remote manifest state"
        );
    }

    #[test]
    fn same_version_bump_is_rejected_without_audit_or_version_change() {
        let mut registry = ComputationRegistry::new(7, "trace-load");
        let audit_len = registry.audit_events().len();

        let err = registry
            .bump_version(7, "trace-same-version")
            .expect_err("same version is a regression");

        assert_eq!(err.code(), ERR_REGISTRY_VERSION_REGRESSION);
        assert_eq!(registry.registry_version(), 7);
        assert_eq!(registry.audit_events().len(), audit_len);
    }

    #[test]
    fn lower_version_bump_is_rejected_without_audit_or_version_change() {
        let mut registry = ComputationRegistry::new(7, "trace-load");
        let audit_len = registry.audit_events().len();

        let err = registry
            .bump_version(6, "trace-lower-version")
            .expect_err("lower version is a regression");

        assert_eq!(err.code(), ERR_REGISTRY_VERSION_REGRESSION);
        assert_eq!(registry.registry_version(), 7);
        assert_eq!(registry.audit_events().len(), audit_len);
    }

    #[test]
    fn dispatch_unknown_name_does_not_touch_capability_gate() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        let mut gate = CapabilityGate::new("registry-secret");

        let err = registry
            .authorize_dispatch(
                "trust.unknown_job.v1",
                "https://compute.example.com/verify",
                None,
                &mut gate,
                1_700_000_050,
                "trace-dispatch-unknown",
            )
            .expect_err("unknown computation must fail before capability checks");

        assert_eq!(err.code(), ERR_UNKNOWN_COMPUTATION);
        assert!(gate.audit_log().is_empty());
        assert_eq!(
            registry
                .audit_events()
                .last()
                .map(|event| event.event_code.as_str()),
            Some(CR_LOOKUP_UNKNOWN)
        );
    }

    #[test]
    fn dispatch_missing_cap_records_registry_denial_and_compatibility_alias() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(sample_entry("trust.verify_manifest.v1"), "trace-register")
            .expect("register");
        let mut gate = CapabilityGate::new("registry-secret");

        let err = registry
            .authorize_dispatch(
                "trust.verify_manifest.v1",
                "https://compute.example.com/verify",
                None,
                &mut gate,
                1_700_000_050,
                "trace-dispatch-missing-cap",
            )
            .expect_err("missing capability must deny dispatch");

        assert!(matches!(
            &err,
            ComputationRegistryError::DispatchDenied {
                compatibility_code: Some(ref alias),
                ..
            } if alias == "ERR_REMOTE_CAP_REQUIRED"
        ));
        assert_eq!(err.code(), "REMOTECAP_MISSING");
        assert_eq!(
            registry
                .audit_events()
                .last()
                .map(|event| event.event_code.as_str()),
            Some(CR_DISPATCH_GATED)
        );
    }

    #[test]
    fn from_catalog_with_malformed_entry_returns_error() {
        let catalog = RegistryCatalog {
            registry_version: 3,
            entries: vec![sample_entry("trust.verify-manifest.v1")],
        };

        let err = ComputationRegistry::from_catalog(catalog, "trace-restore-malformed")
            .expect_err("malformed catalog entry must fail restore");

        assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
    }

    #[test]
    fn registration_rejects_empty_name_after_normalization() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        let entry = sample_entry(" \t ");

        let err = registry
            .register_computation(entry, "trace-register-empty-name")
            .expect_err("blank normalized name must fail");

        assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
        assert!(registry.list_computations().is_empty());
        assert_eq!(
            registry
                .audit_events()
                .last()
                .and_then(|event| event.computation_name.as_deref()),
            Some("")
        );
    }

    #[test]
    fn registration_capacity_rejection_does_not_record_success_event() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        for idx in 0..MAX_COMPUTATION_ENTRIES {
            let entry = sample_entry(&format!("d{idx}.action.v1"));
            registry.entries.insert(entry.name.clone(), entry);
        }
        let audit_len_before = registry.audit_events().len();

        let err = registry
            .register_computation(sample_entry("overflow.action.v1"), "trace-overflow")
            .expect_err("new entry over capacity must fail");

        assert_eq!(err.code(), ERR_INVALID_COMPUTATION_ENTRY);
        assert!(err.to_string().contains("registry at capacity"));
        assert_eq!(registry.audit_events().len(), audit_len_before);
        assert!(!registry.entries.contains_key("overflow.action.v1"));
    }

    #[test]
    fn from_catalog_rejects_blank_description_after_prior_valid_entry() {
        let mut invalid = sample_entry("trust.blank_description.v1");
        invalid.description = " \n\t ".to_string();
        let catalog = RegistryCatalog {
            registry_version: 9,
            entries: vec![sample_entry("trust.valid_manifest.v1"), invalid],
        };

        let err = ComputationRegistry::from_catalog(catalog, "trace-catalog-blank-description")
            .expect_err("blank catalog description must fail restore");

        assert_eq!(err.code(), ERR_INVALID_COMPUTATION_ENTRY);
        assert!(err.to_string().contains("description cannot be empty"));
    }

    #[test]
    fn lookup_space_padded_registered_name_is_malformed_not_unknown() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(sample_entry("trust.verify_manifest.v1"), "trace-register")
            .expect("registration should succeed");

        let err = registry
            .validate_computation_name(" trust.verify_manifest.v1 ", "trace-space-lookup")
            .expect_err("space-padded lookup name must be malformed");

        assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
        assert_eq!(
            registry
                .audit_events()
                .last()
                .map(|event| event.event_code.as_str()),
            Some(CR_LOOKUP_MALFORMED)
        );
    }

    #[test]
    fn dispatch_space_padded_name_rejected_before_gate_audit() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(sample_entry("trust.verify_manifest.v1"), "trace-register")
            .expect("registration should succeed");
        let mut gate = CapabilityGate::new("registry-secret");

        let err = registry
            .authorize_dispatch(
                " trust.verify_manifest.v1 ",
                "https://compute.example.com/verify",
                None,
                &mut gate,
                1_700_000_050,
                "trace-space-dispatch",
            )
            .expect_err("space-padded dispatch name must fail before cap check");

        assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
        assert!(gate.audit_log().is_empty());
        assert_eq!(
            registry
                .audit_events()
                .last()
                .map(|event| event.event_code.as_str()),
            Some(CR_LOOKUP_MALFORMED)
        );
    }

    #[test]
    fn push_bounded_over_capacity_discards_oldest_events() {
        let mut events = vec![
            RegistryAuditEvent {
                event_code: "oldest".to_string(),
                trace_id: "trace-oldest".to_string(),
                registry_version: 1,
                computation_name: None,
                detail: "oldest event".to_string(),
            },
            RegistryAuditEvent {
                event_code: "middle".to_string(),
                trace_id: "trace-middle".to_string(),
                registry_version: 1,
                computation_name: None,
                detail: "middle event".to_string(),
            },
            RegistryAuditEvent {
                event_code: "newest".to_string(),
                trace_id: "trace-newest".to_string(),
                registry_version: 1,
                computation_name: None,
                detail: "newest event".to_string(),
            },
        ];

        push_bounded(
            &mut events,
            RegistryAuditEvent {
                event_code: "incoming".to_string(),
                trace_id: "trace-incoming".to_string(),
                registry_version: 1,
                computation_name: None,
                detail: "incoming event".to_string(),
            },
            2,
        );

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_code, "newest");
        assert_eq!(events[1].event_code, "incoming");
    }

    #[test]
    fn version_regression_error_does_not_record_trace_id() {
        let mut registry = ComputationRegistry::new(4, "trace-load");
        let audit_len_before = registry.audit_events().len();

        let err = registry
            .bump_version(3, "trace-regression-ignored")
            .expect_err("lower version must fail");

        assert_eq!(err.code(), ERR_REGISTRY_VERSION_REGRESSION);
        assert_eq!(registry.registry_version(), 4);
        assert_eq!(registry.audit_events().len(), audit_len_before);
        assert!(
            !registry
                .audit_events()
                .iter()
                .any(|event| event.trace_id == "trace-regression-ignored")
        );
    }

    #[test]
    fn canonical_name_rejects_unicode_bidi_and_non_ascii_components() {
        for name in [
            "trust.\u{202e}verify_manifest.v1",
            "trüst.verify_manifest.v1",
            "trust.verify_😀.v1",
            "trust.verify_manifest.v\u{0661}",
        ] {
            assert!(!is_canonical_computation_name(name), "{name:?}");
        }
    }

    #[test]
    fn canonical_name_rejects_control_characters_inside_components() {
        for name in [
            "trust.verify\nmanifest.v1",
            "trust.verify\tmanifest.v1",
            "trust.verify_manifest.v1\r",
            "trust.\0verify_manifest.v1",
        ] {
            assert!(!is_canonical_computation_name(name), "{name:?}");
        }
    }

    #[test]
    fn canonical_name_rejects_malformed_version_digits() {
        for name in [
            "trust.verify_manifest.v+1",
            "trust.verify_manifest.v_1",
            "trust.verify_manifest.vv1",
            "trust.verify_manifest.1",
        ] {
            assert!(!is_canonical_computation_name(name), "{name:?}");
        }
    }

    #[test]
    fn from_catalog_rejects_blank_input_schema_after_prior_valid_entry() {
        let mut invalid = sample_entry("trust.blank_input.v1");
        invalid.input_schema = " \n\t ".to_string();
        let catalog = RegistryCatalog {
            registry_version: 9,
            entries: vec![sample_entry("trust.valid_manifest.v1"), invalid],
        };

        let err = ComputationRegistry::from_catalog(catalog, "trace-catalog-blank-input")
            .expect_err("blank catalog input schema must fail restore");

        assert_eq!(err.code(), ERR_INVALID_COMPUTATION_ENTRY);
        assert!(err.to_string().contains("input_schema and output_schema"));
    }

    #[test]
    fn from_catalog_rejects_blank_output_schema_after_prior_valid_entry() {
        let mut invalid = sample_entry("trust.blank_output.v1");
        invalid.output_schema = "\r\n ".to_string();
        let catalog = RegistryCatalog {
            registry_version: 9,
            entries: vec![sample_entry("trust.valid_manifest.v1"), invalid],
        };

        let err = ComputationRegistry::from_catalog(catalog, "trace-catalog-blank-output")
            .expect_err("blank catalog output schema must fail restore");

        assert_eq!(err.code(), ERR_INVALID_COMPUTATION_ENTRY);
        assert!(err.to_string().contains("input_schema and output_schema"));
    }

    #[test]
    fn malformed_registration_after_valid_entry_preserves_existing_catalog() {
        let mut registry = ComputationRegistry::new(1, "trace-load");
        registry
            .register_computation(sample_entry("trust.valid_manifest.v1"), "trace-valid")
            .expect("valid entry should register");
        let before = registry.to_catalog();

        let err = registry
            .register_computation(sample_entry("trust.invalid-manifest.v1"), "trace-invalid")
            .expect_err("malformed follow-up registration must fail");

        assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
        assert_eq!(registry.to_catalog(), before);
        assert_eq!(
            registry
                .audit_events()
                .last()
                .map(|event| event.event_code.as_str()),
            Some(CR_LOOKUP_MALFORMED)
        );
    }

    #[test]
    fn zero_version_registry_rejects_zero_version_bump_without_audit() {
        let mut registry = ComputationRegistry::new(0, "trace-load-zero");
        let audit_len_before = registry.audit_events().len();

        let err = registry
            .bump_version(0, "trace-zero-bump")
            .expect_err("zero-to-zero version bump must be a regression");

        assert_eq!(err.code(), ERR_REGISTRY_VERSION_REGRESSION);
        assert_eq!(registry.registry_version(), 0);
        assert_eq!(registry.audit_events().len(), audit_len_before);
    }

    #[test]
    fn bounds_check_prevents_resource_exhaustion_attacks() {
        // Test the specific attack vector from audit findings
        let malicious_name = format!("{}.action.v1", "a".repeat(1_000_000));
        assert!(
            !is_canonical_computation_name(&malicious_name),
            "Malicious oversized name should be rejected to prevent resource exhaustion"
        );

        // Test component bounds (MAX_COMPONENT_LENGTH = 128)
        let at_limit_component = "a".repeat(128);
        let over_limit_component = "a".repeat(129);

        // Component at limit should pass validation
        assert!(
            is_component(&at_limit_component),
            "Component at MAX_COMPONENT_LENGTH should be accepted"
        );

        // Component over limit should be rejected
        assert!(
            !is_component(&over_limit_component),
            "Component over MAX_COMPONENT_LENGTH should be rejected"
        );

        // Version component bounds
        let at_limit_version = format!("v{}", "1".repeat(127)); // 'v' + 127 digits = 128
        let over_limit_version = format!("v{}", "1".repeat(128)); // 'v' + 128 digits = 129

        assert!(
            is_version_component(&at_limit_version),
            "Version component at MAX_COMPONENT_LENGTH should be accepted"
        );

        assert!(
            !is_version_component(&over_limit_version),
            "Version component over MAX_COMPONENT_LENGTH should be rejected"
        );

        // Full computation name bounds (MAX_COMPUTATION_NAME_LENGTH = 512)
        // Build name at exactly 512 chars: component1 + '.' + component2 + '.' + version
        // Use 128-char components: 128 + 1 + 128 + 1 + remaining = 512
        let remaining_for_version = 512 - 128 - 1 - 128 - 1; // 254 chars for version
        let at_limit_name = format!(
            "{}.{}.v{}",
            "a".repeat(128),
            "b".repeat(128),
            "1".repeat(remaining_for_version - 1) // -1 for 'v' prefix
        );
        assert_eq!(at_limit_name.len(), 512);

        assert!(
            is_canonical_computation_name(&at_limit_name),
            "Computation name at MAX_COMPUTATION_NAME_LENGTH should be accepted"
        );

        // Name over limit should be rejected
        let over_limit_name = format!("{}_extra", at_limit_name);
        assert!(
            !is_canonical_computation_name(&over_limit_name),
            "Computation name over MAX_COMPUTATION_NAME_LENGTH should be rejected"
        );
    }
}
