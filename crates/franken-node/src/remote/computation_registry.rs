//! bd-ac83: Versioned named remote computation registry.
//!
//! This module enforces a canonical name contract (`domain.action.vN`) for
//! remote computations and centralizes dispatch gating behind `RemoteCap`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security::remote_cap::{CapabilityGate, RemoteCap, RemoteOperation};

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
    items.push(item);
    if items.len() > cap {
        let overflow = items.len() - cap;
        items.drain(0..overflow);
    }
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

        let name = entry.name.clone();
        self.entries.insert(name.clone(), entry);
        self.record_event(
            CR_LOOKUP_SUCCESS,
            trace_id,
            Some(name),
            "registered computation".to_string(),
        );
        Ok(())
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
        push_bounded(&mut self.audit_events, RegistryAuditEvent {
            event_code: event_code.to_string(),
            trace_id: trace_id.to_string(),
            registry_version: self.registry_version,
            computation_name,
            detail,
        }, MAX_AUDIT_EVENTS);
    }
}

/// Canonical naming contract: `domain.action.vN`
///
/// - `domain`: lowercase ASCII letter + `[a-z0-9_]*`
/// - `action`: lowercase ASCII letter + `[a-z0-9_]*`
/// - `vN`: literal `v` followed by one or more digits
#[must_use]
pub fn is_canonical_computation_name(name: &str) -> bool {
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

fn is_component(component: &str) -> bool {
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
}
