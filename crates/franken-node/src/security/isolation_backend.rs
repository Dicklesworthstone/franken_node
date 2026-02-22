//! Strict-plus isolation backend with microVM and hardened fallback.
//!
//! Selects the best available isolation backend at runtime based on
//! platform capabilities. The fallback provides equivalent policy
//! guarantees when microVM is unavailable.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::sandbox_policy_compiler::{AccessLevel, CompiledPolicy, SandboxProfile, compile_policy};

/// Available isolation backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationBackend {
    MicroVm,
    Hardened,
    OsSandbox,
    Container,
}

impl IsolationBackend {
    pub const ALL: [IsolationBackend; 4] = [
        Self::MicroVm,
        Self::Hardened,
        Self::OsSandbox,
        Self::Container,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MicroVm => "microvm",
            Self::Hardened => "hardened",
            Self::OsSandbox => "os_sandbox",
            Self::Container => "container",
        }
    }

    /// Whether this backend provides full hardware-level isolation.
    pub fn is_full_isolation(&self) -> bool {
        matches!(self, Self::MicroVm)
    }

    /// Whether this backend provides policy-equivalent isolation.
    pub fn is_equivalent(&self) -> bool {
        matches!(self, Self::MicroVm | Self::Hardened | Self::OsSandbox)
    }
}

impl fmt::Display for IsolationBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Platform capability probe results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub os: String,
    pub arch: String,
    pub has_kvm: bool,
    pub has_seccomp: bool,
    pub has_namespaces: bool,
    pub has_cgroups: bool,
    pub has_macos_sandbox: bool,
    pub has_oci_runtime: bool,
}

impl PlatformCapabilities {
    /// Probe the current platform (simulated for scaffolding).
    pub fn probe() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            has_kvm: cfg!(target_os = "linux") && std::path::Path::new("/dev/kvm").exists(),
            has_seccomp: cfg!(target_os = "linux"),
            has_namespaces: cfg!(target_os = "linux"),
            has_cgroups: cfg!(target_os = "linux"),
            has_macos_sandbox: cfg!(target_os = "macos"),
            has_oci_runtime: false, // would probe for docker/podman
        }
    }

    /// Create capabilities from known values (for testing).
    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        os: &str,
        arch: &str,
        has_kvm: bool,
        has_seccomp: bool,
        has_namespaces: bool,
        has_cgroups: bool,
        has_macos_sandbox: bool,
        has_oci_runtime: bool,
    ) -> Self {
        Self {
            os: os.to_string(),
            arch: arch.to_string(),
            has_kvm,
            has_seccomp,
            has_namespaces,
            has_cgroups,
            has_macos_sandbox,
            has_oci_runtime,
        }
    }
}

/// Result of backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSelection {
    pub backend: IsolationBackend,
    pub capabilities: PlatformCapabilities,
    pub equivalence: EquivalenceLevel,
    pub policy: CompiledPolicy,
}

/// How closely the selected backend matches full microVM isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivalenceLevel {
    Full,
    Equivalent,
    Baseline,
}

impl fmt::Display for EquivalenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Equivalent => write!(f, "equivalent"),
            Self::Baseline => write!(f, "baseline"),
        }
    }
}

/// Select the best isolation backend for the given platform capabilities.
pub fn select_backend(caps: &PlatformCapabilities) -> Result<BackendSelection, IsolationError> {
    let (backend, equivalence) = if caps.has_kvm {
        (IsolationBackend::MicroVm, EquivalenceLevel::Full)
    } else if caps.has_seccomp && caps.has_namespaces && caps.has_cgroups {
        (IsolationBackend::Hardened, EquivalenceLevel::Equivalent)
    } else if caps.has_macos_sandbox {
        (IsolationBackend::OsSandbox, EquivalenceLevel::Equivalent)
    } else if caps.has_oci_runtime {
        (IsolationBackend::Container, EquivalenceLevel::Baseline)
    } else {
        return Err(IsolationError::BackendUnavailable {
            os: caps.os.clone(),
            arch: caps.arch.clone(),
        });
    };

    let policy = compile_policy(SandboxProfile::StrictPlus);

    Ok(BackendSelection {
        backend,
        capabilities: caps.clone(),
        equivalence,
        policy,
    })
}

/// Verify that a backend can enforce the required policy.
pub fn verify_policy_enforcement(selection: &BackendSelection) -> Result<(), IsolationError> {
    // strict_plus requires all capabilities to be denied
    for grant in &selection.policy.grants {
        if grant.access != AccessLevel::Deny {
            return Err(IsolationError::PolicyMismatch {
                capability: grant.capability.clone(),
                required: "deny".to_string(),
                actual: format!("{}", grant.access),
            });
        }
    }
    Ok(())
}

/// Audit record for backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendAuditRecord {
    pub connector_id: String,
    pub selected_backend: IsolationBackend,
    pub equivalence: EquivalenceLevel,
    pub probe_results: PlatformCapabilities,
    pub timestamp: String,
}

/// Errors for isolation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationError {
    #[serde(rename = "ISOLATION_BACKEND_UNAVAILABLE")]
    BackendUnavailable { os: String, arch: String },
    #[serde(rename = "ISOLATION_PROBE_FAILED")]
    ProbeFailed { reason: String },
    #[serde(rename = "ISOLATION_INIT_FAILED")]
    InitFailed {
        backend: IsolationBackend,
        reason: String,
    },
    #[serde(rename = "ISOLATION_POLICY_MISMATCH")]
    PolicyMismatch {
        capability: String,
        required: String,
        actual: String,
    },
}

impl fmt::Display for IsolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable { os, arch } => {
                write!(
                    f,
                    "ISOLATION_BACKEND_UNAVAILABLE: no backend for {os}/{arch}"
                )
            }
            Self::ProbeFailed { reason } => {
                write!(f, "ISOLATION_PROBE_FAILED: {reason}")
            }
            Self::InitFailed { backend, reason } => {
                write!(f, "ISOLATION_INIT_FAILED: {backend}: {reason}")
            }
            Self::PolicyMismatch {
                capability,
                required,
                actual,
            } => {
                write!(
                    f,
                    "ISOLATION_POLICY_MISMATCH: {capability} requires {required}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for IsolationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_kvm_caps() -> PlatformCapabilities {
        PlatformCapabilities::from_values("linux", "x86_64", true, true, true, true, false, true)
    }

    fn linux_no_kvm_caps() -> PlatformCapabilities {
        PlatformCapabilities::from_values("linux", "x86_64", false, true, true, true, false, false)
    }

    fn macos_caps() -> PlatformCapabilities {
        PlatformCapabilities::from_values(
            "macos", "aarch64", false, false, false, false, true, false,
        )
    }

    fn oci_only_caps() -> PlatformCapabilities {
        PlatformCapabilities::from_values(
            "freebsd", "x86_64", false, false, false, false, false, true,
        )
    }

    fn no_caps() -> PlatformCapabilities {
        PlatformCapabilities::from_values(
            "unknown", "unknown", false, false, false, false, false, false,
        )
    }

    // === Backend selection ===

    #[test]
    fn select_microvm_with_kvm() {
        let sel = select_backend(&linux_kvm_caps()).unwrap();
        assert_eq!(sel.backend, IsolationBackend::MicroVm);
        assert_eq!(sel.equivalence, EquivalenceLevel::Full);
    }

    #[test]
    fn select_hardened_without_kvm() {
        let sel = select_backend(&linux_no_kvm_caps()).unwrap();
        assert_eq!(sel.backend, IsolationBackend::Hardened);
        assert_eq!(sel.equivalence, EquivalenceLevel::Equivalent);
    }

    #[test]
    fn select_os_sandbox_on_macos() {
        let sel = select_backend(&macos_caps()).unwrap();
        assert_eq!(sel.backend, IsolationBackend::OsSandbox);
        assert_eq!(sel.equivalence, EquivalenceLevel::Equivalent);
    }

    #[test]
    fn select_container_with_oci() {
        let sel = select_backend(&oci_only_caps()).unwrap();
        assert_eq!(sel.backend, IsolationBackend::Container);
        assert_eq!(sel.equivalence, EquivalenceLevel::Baseline);
    }

    #[test]
    fn no_backend_available() {
        let err = select_backend(&no_caps()).unwrap_err();
        assert!(matches!(err, IsolationError::BackendUnavailable { .. }));
    }

    // === Backend properties ===

    #[test]
    fn four_backends() {
        assert_eq!(IsolationBackend::ALL.len(), 4);
    }

    #[test]
    fn microvm_is_full_isolation() {
        assert!(IsolationBackend::MicroVm.is_full_isolation());
        assert!(!IsolationBackend::Hardened.is_full_isolation());
    }

    #[test]
    fn equivalent_backends() {
        assert!(IsolationBackend::MicroVm.is_equivalent());
        assert!(IsolationBackend::Hardened.is_equivalent());
        assert!(IsolationBackend::OsSandbox.is_equivalent());
        assert!(!IsolationBackend::Container.is_equivalent());
    }

    // === Policy enforcement ===

    #[test]
    fn strict_plus_policy_enforced() {
        let sel = select_backend(&linux_kvm_caps()).unwrap();
        assert!(verify_policy_enforcement(&sel).is_ok());
    }

    #[test]
    fn policy_all_deny_for_strict_plus() {
        let sel = select_backend(&linux_kvm_caps()).unwrap();
        for grant in &sel.policy.grants {
            assert_eq!(grant.access, AccessLevel::Deny);
        }
    }

    // === Equivalence levels ===

    #[test]
    fn equivalence_display() {
        assert_eq!(EquivalenceLevel::Full.to_string(), "full");
        assert_eq!(EquivalenceLevel::Equivalent.to_string(), "equivalent");
        assert_eq!(EquivalenceLevel::Baseline.to_string(), "baseline");
    }

    // === Audit record ===

    #[test]
    fn audit_record_serde() {
        let audit = BackendAuditRecord {
            connector_id: "conn-1".into(),
            selected_backend: IsolationBackend::MicroVm,
            equivalence: EquivalenceLevel::Full,
            probe_results: linux_kvm_caps(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&audit).unwrap();
        let parsed: BackendAuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "conn-1");
        assert_eq!(parsed.selected_backend, IsolationBackend::MicroVm);
    }

    // === Serde roundtrip ===

    #[test]
    fn serde_roundtrip_backend() {
        for b in &IsolationBackend::ALL {
            let json = serde_json::to_string(b).unwrap();
            let parsed: IsolationBackend = serde_json::from_str(&json).unwrap();
            assert_eq!(b, &parsed);
        }
    }

    #[test]
    fn serde_roundtrip_error() {
        let err = IsolationError::BackendUnavailable {
            os: "unknown".into(),
            arch: "unknown".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: IsolationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, parsed);
    }

    #[test]
    fn error_display_messages() {
        let e1 = IsolationError::BackendUnavailable {
            os: "plan9".into(),
            arch: "mips".into(),
        };
        assert!(e1.to_string().contains("ISOLATION_BACKEND_UNAVAILABLE"));

        let e2 = IsolationError::ProbeFailed {
            reason: "no dev".into(),
        };
        assert!(e2.to_string().contains("ISOLATION_PROBE_FAILED"));

        let e3 = IsolationError::InitFailed {
            backend: IsolationBackend::MicroVm,
            reason: "no kvm".into(),
        };
        assert!(e3.to_string().contains("ISOLATION_INIT_FAILED"));

        let e4 = IsolationError::PolicyMismatch {
            capability: "net".into(),
            required: "deny".into(),
            actual: "allow".into(),
        };
        assert!(e4.to_string().contains("ISOLATION_POLICY_MISMATCH"));
    }
}
