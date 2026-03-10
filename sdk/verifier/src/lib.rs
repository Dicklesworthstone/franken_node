#![forbid(unsafe_code)]

//! Universal Verifier SDK -- public facade module.
//!
//! This module re-exports the core verifier SDK types and operations for
//! external consumption. External verifiers depend on this crate to replay
//! structurally bound capsules and reproduce claim verdicts without privileged
//! internal access.
//!
//! # Security Posture
//!
//! This workspace crate is structural-only. It publishes deterministic schema,
//! digest, and replay helpers for external tooling, but it is not the
//! replacement-critical canonical verifier and it does not claim detached
//! cryptographic verification authority.
//!
//! # Schema Version
//!
//! The current schema version is `vsdk-v1.0`. All capsules and manifests
//! must carry this version.
//!
//! # Event Codes
//!
//! - CAPSULE_CREATED: A new replay capsule has been created.
//! - CAPSULE_SIGNED: A capsule has been signed.
//! - CAPSULE_REPLAY_START: Capsule replay has started.
//! - CAPSULE_VERDICT_REPRODUCED: Capsule verdict has been reproduced.
//! - SDK_VERSION_CHECK: SDK version compatibility check performed.
//!
//! # Error Codes
//!
//! - ERR_CAPSULE_SIGNATURE_INVALID: Capsule signature verification failed.
//! - ERR_CAPSULE_SCHEMA_MISMATCH: Capsule schema version is not supported.
//! - ERR_CAPSULE_REPLAY_DIVERGED: Replay output does not match expected hash.
//! - ERR_CAPSULE_VERDICT_MISMATCH: Reproduced verdict differs from original.
//! - ERR_SDK_VERSION_UNSUPPORTED: SDK version is not supported.
//! - ERR_CAPSULE_ACCESS_DENIED: Privileged access attempted during replay.
//!
//! # Invariants
//!
//! - INV-CAPSULE-STABLE-SCHEMA: Capsule schema format is stable across SDK versions.
//! - INV-CAPSULE-VERSIONED-API: Every API surface carries a version identifier.
//! - INV-CAPSULE-NO-PRIVILEGED-ACCESS: External replay requires no privileged internal access.
//! - INV-CAPSULE-VERDICT-REPRODUCIBLE: Same capsule always produces the same verdict.

pub mod capsule;

/// SDK version string for compatibility checks.
/// INV-CAPSULE-VERSIONED-API: every API surface carries a version identifier.
pub const SDK_VERSION: &str = "vsdk-v1.0";

/// Minimum supported SDK version.
pub const SDK_VERSION_MIN: &str = "vsdk-v1.0";

/// Explicit posture marker for the standalone workspace SDK surface.
pub const STRUCTURAL_ONLY_SECURITY_POSTURE: &str = "structural_only_not_replacement_critical";

/// Stable rule id for guardrails that must fence the workspace SDK surface.
pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK";

// ---------------------------------------------------------------------------
// Event codes (public-facing)
// ---------------------------------------------------------------------------

/// Event: a new replay capsule has been created.
pub const CAPSULE_CREATED: &str = "CAPSULE_CREATED";
/// Event: a capsule has been signed.
pub const CAPSULE_SIGNED: &str = "CAPSULE_SIGNED";
/// Event: capsule replay has started.
pub const CAPSULE_REPLAY_START: &str = "CAPSULE_REPLAY_START";
/// Event: capsule verdict has been reproduced.
pub const CAPSULE_VERDICT_REPRODUCED: &str = "CAPSULE_VERDICT_REPRODUCED";
/// Event: SDK version compatibility check performed.
pub const SDK_VERSION_CHECK: &str = "SDK_VERSION_CHECK";

// ---------------------------------------------------------------------------
// Error codes (public-facing)
// ---------------------------------------------------------------------------

/// Error: capsule signature verification failed.
pub const ERR_CAPSULE_SIGNATURE_INVALID: &str = "ERR_CAPSULE_SIGNATURE_INVALID";
/// Error: capsule schema version is not supported.
pub const ERR_CAPSULE_SCHEMA_MISMATCH: &str = "ERR_CAPSULE_SCHEMA_MISMATCH";
/// Error: replay output does not match expected hash.
pub const ERR_CAPSULE_REPLAY_DIVERGED: &str = "ERR_CAPSULE_REPLAY_DIVERGED";
/// Error: reproduced verdict differs from original.
pub const ERR_CAPSULE_VERDICT_MISMATCH: &str = "ERR_CAPSULE_VERDICT_MISMATCH";
/// Error: SDK version is not supported.
pub const ERR_SDK_VERSION_UNSUPPORTED: &str = "ERR_SDK_VERSION_UNSUPPORTED";
/// Error: privileged access attempted during replay.
pub const ERR_CAPSULE_ACCESS_DENIED: &str = "ERR_CAPSULE_ACCESS_DENIED";

// ---------------------------------------------------------------------------
// Invariants (public-facing)
// ---------------------------------------------------------------------------

/// Invariant: capsule schema format is stable across SDK versions.
pub const INV_CAPSULE_STABLE_SCHEMA: &str = "INV-CAPSULE-STABLE-SCHEMA";
/// Invariant: every API surface carries a version identifier.
pub const INV_CAPSULE_VERSIONED_API: &str = "INV-CAPSULE-VERSIONED-API";
/// Invariant: external replay requires no privileged internal access.
pub const INV_CAPSULE_NO_PRIVILEGED_ACCESS: &str = "INV-CAPSULE-NO-PRIVILEGED-ACCESS";
/// Invariant: same capsule always produces the same verdict.
pub const INV_CAPSULE_VERDICT_REPRODUCIBLE: &str = "INV-CAPSULE-VERDICT-REPRODUCIBLE";

// ---------------------------------------------------------------------------
// SDK version check
// ---------------------------------------------------------------------------

/// Check whether a given SDK version string is supported.
///
/// Returns `Ok(())` if supported, or an error string if not.
///
/// # INV-CAPSULE-VERSIONED-API
/// # INV-CAPSULE-STABLE-SCHEMA
pub fn check_sdk_version(version: &str) -> Result<(), String> {
    if version == SDK_VERSION {
        Ok(())
    } else {
        Err(format!(
            "{}: requested={}, supported={}",
            ERR_SDK_VERSION_UNSUPPORTED, version, SDK_VERSION
        ))
    }
}

/// A structured audit event for SDK operations.
#[derive(Debug, Clone)]
pub struct SdkEvent {
    pub event_code: &'static str,
    pub detail: String,
}

impl SdkEvent {
    pub fn new(event_code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            event_code,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_version_constant() {
        assert_eq!(SDK_VERSION, "vsdk-v1.0");
    }

    #[test]
    fn test_sdk_version_min_constant() {
        assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0");
    }

    #[test]
    fn test_structural_only_posture_markers_defined() {
        assert_eq!(
            STRUCTURAL_ONLY_SECURITY_POSTURE,
            "structural_only_not_replacement_critical"
        );
        assert_eq!(
            STRUCTURAL_ONLY_RULE_ID,
            "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK"
        );
    }

    #[test]
    fn test_check_sdk_version_supported() {
        assert!(check_sdk_version("vsdk-v1.0").is_ok());
    }

    #[test]
    fn test_check_sdk_version_unsupported() {
        let err = check_sdk_version("vsdk-v99.0");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains(ERR_SDK_VERSION_UNSUPPORTED));
    }

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(CAPSULE_CREATED, "CAPSULE_CREATED");
        assert_eq!(CAPSULE_SIGNED, "CAPSULE_SIGNED");
        assert_eq!(CAPSULE_REPLAY_START, "CAPSULE_REPLAY_START");
        assert_eq!(CAPSULE_VERDICT_REPRODUCED, "CAPSULE_VERDICT_REPRODUCED");
        assert_eq!(SDK_VERSION_CHECK, "SDK_VERSION_CHECK");
    }

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(ERR_CAPSULE_SIGNATURE_INVALID, "ERR_CAPSULE_SIGNATURE_INVALID");
        assert_eq!(ERR_CAPSULE_SCHEMA_MISMATCH, "ERR_CAPSULE_SCHEMA_MISMATCH");
        assert_eq!(ERR_CAPSULE_REPLAY_DIVERGED, "ERR_CAPSULE_REPLAY_DIVERGED");
        assert_eq!(ERR_CAPSULE_VERDICT_MISMATCH, "ERR_CAPSULE_VERDICT_MISMATCH");
        assert_eq!(ERR_SDK_VERSION_UNSUPPORTED, "ERR_SDK_VERSION_UNSUPPORTED");
        assert_eq!(ERR_CAPSULE_ACCESS_DENIED, "ERR_CAPSULE_ACCESS_DENIED");
    }

    #[test]
    fn test_invariant_codes_defined() {
        assert_eq!(INV_CAPSULE_STABLE_SCHEMA, "INV-CAPSULE-STABLE-SCHEMA");
        assert_eq!(INV_CAPSULE_VERSIONED_API, "INV-CAPSULE-VERSIONED-API");
        assert_eq!(INV_CAPSULE_NO_PRIVILEGED_ACCESS, "INV-CAPSULE-NO-PRIVILEGED-ACCESS");
        assert_eq!(INV_CAPSULE_VERDICT_REPRODUCIBLE, "INV-CAPSULE-VERDICT-REPRODUCIBLE");
    }

    #[test]
    fn test_sdk_event_new() {
        let evt = SdkEvent::new(CAPSULE_CREATED, "test capsule created");
        assert_eq!(evt.event_code, CAPSULE_CREATED);
        assert_eq!(evt.detail, "test capsule created");
    }

    #[test]
    fn test_sdk_event_clone() {
        let evt = SdkEvent::new(CAPSULE_SIGNED, "signed");
        let cloned = evt.clone();
        assert_eq!(cloned.event_code, evt.event_code);
        assert_eq!(cloned.detail, evt.detail);
    }

    #[test]
    fn test_sdk_event_debug() {
        let evt = SdkEvent::new(SDK_VERSION_CHECK, "version check");
        let debug = format!("{:?}", evt);
        assert!(debug.contains("SDK_VERSION_CHECK"));
    }
}
