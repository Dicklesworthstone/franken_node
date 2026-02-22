//! Conformance checks for bd-ac83 remote computation naming registry.

#[path = "../../crates/franken-node/src/security/remote_cap.rs"]
mod remote_cap_impl;

pub mod security {
    pub mod remote_cap {
        pub use crate::remote_cap_impl::*;
    }
}

#[path = "../../crates/franken-node/src/remote/computation_registry.rs"]
mod computation_registry;

use computation_registry::{
    ComputationRegistry, ERR_MALFORMED_COMPUTATION_NAME, ERR_UNKNOWN_COMPUTATION, RegistryCatalog,
    is_canonical_computation_name,
};
use security::remote_cap::{CapabilityGate, CapabilityProvider, RemoteOperation, RemoteScope};
use std::fs;
use std::path::Path;

const CATALOG_REL: &str = "artifacts/10.14/remote_registry_catalog.json";

fn catalog_path() -> std::path::PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut root = manifest.to_path_buf();
    loop {
        let candidate = root.join(CATALOG_REL);
        if candidate.exists() {
            return candidate;
        }
        if !root.pop() {
            break;
        }
    }
    std::path::PathBuf::from(CATALOG_REL)
}

fn load_registry() -> ComputationRegistry {
    let raw = fs::read_to_string(catalog_path())
        .expect("registry catalog artifact must exist");
    let catalog: RegistryCatalog = serde_json::from_str(&raw).expect("catalog json must parse");
    ComputationRegistry::from_catalog(catalog, "trace-catalog-load")
        .expect("catalog entries should be valid")
}

#[test]
fn catalog_contains_canonical_entries() {
    let mut registry = load_registry();
    let entries = registry.list_computations();
    assert!(
        entries.len() >= 4,
        "expected at least 4 registered computations"
    );

    for entry in entries {
        assert!(is_canonical_computation_name(&entry.name));
        let looked_up = registry
            .validate_computation_name(&entry.name, "trace-lookup")
            .expect("registered entry should validate");
        assert_eq!(looked_up.name, entry.name);
    }
}

#[test]
fn malformed_and_unknown_names_have_stable_error_codes() {
    let mut registry = load_registry();

    let malformed = registry
        .validate_computation_name("trust.verify-manifest.v1", "trace-malformed")
        .expect_err("malformed name must fail");
    assert_eq!(malformed.code(), ERR_MALFORMED_COMPUTATION_NAME);

    let unknown = registry
        .validate_computation_name("trust.unknown_job.v1", "trace-unknown")
        .expect_err("unknown name must fail");
    assert_eq!(unknown.code(), ERR_UNKNOWN_COMPUTATION);
}

#[test]
fn dispatch_is_gated_by_remote_cap() {
    let mut registry = load_registry();
    let computation = "trust.verify_manifest.v1";
    let endpoint = "https://compute.example.com/verify";
    let mut gate = CapabilityGate::new("registry-test-secret");

    let denied = registry
        .authorize_dispatch(
            computation,
            endpoint,
            None,
            &mut gate,
            1_700_000_010,
            "trace-dispatch-missing",
        )
        .expect_err("missing capability should deny dispatch");
    assert_eq!(denied.code(), "REMOTECAP_MISSING");

    let provider = CapabilityProvider::new("registry-test-secret");
    let (cap, _) = provider
        .issue(
            "ops-control-plane",
            RemoteScope::new(
                vec![RemoteOperation::RemoteComputation],
                vec!["https://compute.example.com".to_string()],
            ),
            1_700_000_000,
            3600,
            true,
            false,
            "trace-issue",
        )
        .expect("issue capability");

    let allowed = registry.authorize_dispatch(
        computation,
        endpoint,
        Some(&cap),
        &mut gate,
        1_700_000_011,
        "trace-dispatch-allowed",
    );
    assert!(allowed.is_ok(), "registered name + valid cap must pass");
}

#[test]
fn registry_version_only_moves_forward() {
    let mut registry = load_registry();
    let current = registry.registry_version();
    registry
        .bump_version(current + 1, "trace-upgrade")
        .expect("upgrade should succeed");
    let err = registry
        .bump_version(current + 1, "trace-regression")
        .expect_err("same version should fail");
    assert_eq!(err.code(), "ERR_REGISTRY_VERSION_REGRESSION");
}
