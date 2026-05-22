//! Comprehensive conformance test harness for MMR proof verification system.
//!
//! This harness implements systematic testing of all MUST/SHOULD requirements
//! from the MMR specification, following Pattern 4 (spec-derived testing).

pub mod runner;
pub mod traits;
pub mod fixtures;
pub mod comparison;
pub mod context;
pub mod logging;

pub use runner::ConformanceRunner;
pub use traits::{ConformanceTest, TestCategory, RequirementLevel, TestResult};
pub use fixtures::FixtureLoader;
pub use comparison::ComparisonMode;
pub use context::TestContext;
pub use logging::StructuredLogger;

/// Re-export core MMR types for test implementations
pub use frankenengine_node::control_plane::mmr_proofs::{
    MmrCheckpoint, MmrRoot, InclusionProof, PrefixProof, ProofError,
    mmr_inclusion_proof, mmr_prefix_proof, verify_inclusion, verify_prefix,
    marker_leaf_hash,
};
pub use frankenengine_node::control_plane::marker_stream::{MarkerEventType, MarkerStream};

/// Conformance test registration macro
#[macro_export]
macro_rules! register_conformance_test {
    ($test_struct:expr) => {
        inventory::submit!(Box<new(dyn ConformanceTest + Send + Sync)>($test_struct))
    };
}

/// Initialize conformance test inventory
pub fn init() {
    // This ensures all tests are registered via the inventory crate
    let _ = inventory::iter::<Box<dyn ConformanceTest + Send + Sync>>;
}