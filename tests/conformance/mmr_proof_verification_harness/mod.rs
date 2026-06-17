//! Comprehensive conformance test harness for MMR proof verification system.
//!
//! This harness implements systematic testing of all MUST/SHOULD requirements
//! from the MMR specification, following Pattern 4 (spec-derived testing).

pub mod comparison;
pub mod context;
pub mod fixtures;
pub mod logging;
pub mod runner;
pub mod tests;
pub mod traits;

pub use comparison::ComparisonMode;
pub use context::TestContext;
pub use fixtures::FixtureLoader;
pub use logging::StructuredLogger;
pub use runner::ConformanceRunner;
pub use traits::{ConformanceTest, RequirementLevel, TestCategory, TestResult};

pub use frankenengine_node::control_plane::marker_stream::{MarkerEventType, MarkerStream};
/// Re-export core MMR types for test implementations
pub use frankenengine_node::control_plane::mmr_proofs::{
    InclusionProof, MMR_ROOT_WITNESS_ARTIFACT_ID, MMR_ROOT_WITNESS_CONNECTOR_ID, MmrCheckpoint,
    MmrRoot, MmrRootReattestationChain, MmrRootWitnessReceipt, PrefixProof, ProofError,
    marker_leaf_hash, mmr_inclusion_proof, mmr_prefix_proof, mmr_root_reattestation,
    mmr_root_witness_artifact, mmr_root_witness_statement, verify_inclusion, verify_prefix,
    verify_root_reattestation, verify_root_reattestation_chain, verify_root_witness_anteriority,
    verify_root_witness_receipt,
};
pub use frankenengine_node::crypto::ED25519_V1_CRYPTO_SUITE;
pub use frankenengine_node::observability::evidence_ledger::{
    EvidenceLedger, LedgerCapacity, MMR_ROOT_WITNESS_EVIDENCE_DECISION_PREFIX,
    MMR_ROOT_WITNESS_EVIDENCE_SCHEMA_VERSION,
};
pub use frankenengine_node::security::threshold_sig::{
    PartialSignature, SignerKey, ThresholdConfig, sign,
};

/// Conformance test registration macro
#[macro_export]
macro_rules! register_conformance_test {
    ($test_struct:expr) => {
        let _ = &$test_struct;
    };
}

/// Initialize conformance test inventory
pub fn init() {}
