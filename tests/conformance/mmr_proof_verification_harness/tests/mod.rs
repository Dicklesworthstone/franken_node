//! Systematic conformance tests for MMR proof verification.
//!
//! This module contains comprehensive test coverage for all MUST/SHOULD requirements
//! from the MMR specification, organized by functional area.

pub mod checkpoint_management;
pub mod cryptographic_security;
pub mod edge_cases;
pub mod error_handling;
pub mod inclusion_proof_generation;
pub mod inclusion_proof_verification;
pub mod performance;
pub mod prefix_proof_generation;
pub mod prefix_proof_verification;
pub mod serialization;

use super::*;

/// Register all conformance tests
pub fn register_all_tests(runner: &mut ConformanceRunner) {
    // Checkpoint Management tests (R1.*)
    runner.register(Box::new(
        checkpoint_management::CheckpointEnabledDisabledTest,
    ));
    runner.register(Box::new(checkpoint_management::CheckpointFailClosedTest));
    runner.register(Box::new(
        checkpoint_management::CheckpointDeterministicRebuildTest,
    ));
    runner.register(Box::new(checkpoint_management::CheckpointCapacityLimitTest));
    runner.register(Box::new(checkpoint_management::CheckpointEvictionTest));
    runner.register(Box::new(
        checkpoint_management::CheckpointTreeSizePreservationTest,
    ));

    // Inclusion Proof Generation tests (R2.*)
    runner.register(Box::new(
        inclusion_proof_generation::InclusionProofValidGenerationTest,
    ));
    runner.register(Box::new(
        inclusion_proof_generation::InclusionProofEvictedSequenceTest,
    ));
    runner.register(Box::new(
        inclusion_proof_generation::InclusionProofOutOfRangeTest,
    ));
    runner.register(Box::new(
        inclusion_proof_generation::InclusionProofStaleCheckpointTest,
    ));
    runner.register(Box::new(
        inclusion_proof_generation::InclusionProofDisabledTest,
    ));
    runner.register(Box::new(
        inclusion_proof_generation::InclusionProofDeterministicTest,
    ));
    runner.register(Box::new(
        inclusion_proof_generation::InclusionProofAuditPathLengthTest,
    ));

    // Inclusion Proof Verification tests (R3.*)
    runner.register(Box::new(
        inclusion_proof_verification::InclusionVerificationValidTest,
    ));
    runner.register(Box::new(
        inclusion_proof_verification::InclusionVerificationWrongMarkerTest,
    ));
    runner.register(Box::new(
        inclusion_proof_verification::InclusionVerificationWrongRootTest,
    ));
    runner.register(Box::new(
        inclusion_proof_verification::InclusionVerificationTreeSizeMismatchTest,
    ));
    runner.register(Box::new(
        inclusion_proof_verification::InclusionVerificationLeafIndexBoundaryTest,
    ));
    runner.register(Box::new(
        inclusion_proof_verification::InclusionVerificationOversizedAuditPathTest,
    ));
    runner.register(Box::new(
        inclusion_proof_verification::InclusionVerificationConstantTimeTest,
    ));

    // Prefix Proof Generation tests (R4.*)
    runner.register(Box::new(
        prefix_proof_generation::PrefixProofValidGenerationTest,
    ));
    runner.register(Box::new(
        prefix_proof_generation::PrefixProofInvalidOrderingTest,
    ));
    runner.register(Box::new(
        prefix_proof_generation::PrefixProofDisabledCheckpointTest,
    ));
    runner.register(Box::new(
        prefix_proof_generation::PrefixProofRelationshipValidationTest,
    ));
    runner.register(Box::new(
        prefix_proof_generation::RootReattestationValidChainTest,
    ));
    runner.register(Box::new(
        prefix_proof_generation::RootReattestationTamperRejectionTest,
    ));
    runner.register(Box::new(
        prefix_proof_generation::RootWitnessCosigningValidTest,
    ));
    runner.register(Box::new(
        prefix_proof_generation::RootWitnessBackdatedForgeryRejectionTest,
    ));
    runner.register(Box::new(
        prefix_proof_generation::RootWitnessEvidenceLedgerRecordingTest,
    ));

    // Prefix Proof Verification tests (R5.*)
    runner.register(Box::new(
        prefix_proof_verification::PrefixVerificationValidTest,
    ));
    runner.register(Box::new(
        prefix_proof_verification::PrefixVerificationInvalidSizesTest,
    ));
    runner.register(Box::new(
        prefix_proof_verification::PrefixVerificationMismatchedRootSizesTest,
    ));
    runner.register(Box::new(
        prefix_proof_verification::PrefixVerificationRootRelationshipsTest,
    ));
    runner.register(Box::new(
        prefix_proof_verification::PrefixVerificationConstantTimeTest,
    ));

    // Error Handling tests (R6.*)
    runner.register(Box::new(error_handling::ErrorCodeSpecificityTest));
    runner.register(Box::new(error_handling::ErrorStructureTest));
    runner.register(Box::new(error_handling::ErrorFailClosedTest));

    // Cryptographic Security tests (R7.*)
    runner.register(Box::new(cryptographic_security::DomainSeparationTest));
    runner.register(Box::new(cryptographic_security::LengthPrefixingTest));
    runner.register(Box::new(
        cryptographic_security::HashCollisionResistanceTest,
    ));
    runner.register(Box::new(
        cryptographic_security::ConstantTimeComparisonsTest,
    ));
    runner.register(Box::new(cryptographic_security::DeterministicHashingTest));

    // Serialization tests (R8.*)
    runner.register(Box::new(serialization::JsonRoundTripTest));
    runner.register(Box::new(serialization::ProofFieldPreservationTest));
    runner.register(Box::new(serialization::MalformedRejectionTest));

    // Performance tests
    runner.register(Box::new(performance::AuditPathScalingTest));
    runner.register(Box::new(performance::LargeTreePerformanceTest));

    // Edge cases and robustness
    runner.register(Box::new(edge_cases::EmptyStreamTest));
    runner.register(Box::new(edge_cases::SingleMarkerTest));
    runner.register(Box::new(edge_cases::UnicodeHandlingTest));
    runner.register(Box::new(edge_cases::ExtremeValuesTest));
}
