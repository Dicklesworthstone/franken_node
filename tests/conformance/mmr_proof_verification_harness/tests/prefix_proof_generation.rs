//! Prefix proof and root re-attestation conformance tests (R4.*).

use super::super::*;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn prefix_pair(
    ctx: &TestContext,
    prefix_count: u64,
    super_count: u64,
) -> (MmrCheckpoint, MmrCheckpoint) {
    let prefix_stream = ctx.generate_markers(prefix_count, "prefix-chain");
    let super_stream = ctx.generate_markers(super_count, "prefix-chain");
    (
        ctx.create_checkpoint(&prefix_stream),
        ctx.create_checkpoint(&super_stream),
    )
}

fn assert_prefix_verifies(
    proof: &PrefixProof,
    prefix_checkpoint: &MmrCheckpoint,
    super_checkpoint: &MmrCheckpoint,
) -> Option<TestResult> {
    let prefix_root = prefix_checkpoint.root().expect("prefix root");
    let super_root = super_checkpoint.root().expect("super root");
    verify_prefix(proof, prefix_root, super_root)
        .err()
        .map(|err| TestResult::fail(format!("prefix proof failed verification: {err}")))
}

fn witness_signing_key(index: u32) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"mmr_root_witness_conformance_seed_v1:");
    hasher.update(index.to_le_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn witness_threshold_config(threshold: u32, total: u32) -> (Vec<SigningKey>, ThresholdConfig) {
    let mut signing_keys = Vec::new();
    let mut signer_keys = Vec::new();
    for index in 0..total {
        let signing_key = witness_signing_key(index);
        signer_keys.push(SignerKey {
            key_id: format!("ltv-witness-{index}"),
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        });
        signing_keys.push(signing_key);
    }

    (
        signing_keys,
        ThresholdConfig {
            threshold,
            total_signers: total,
            signer_keys,
        },
    )
}

fn root_witness_receipt(
    ctx: &TestContext,
    observed_at_unix_seconds: u64,
    signature_count: usize,
) -> Result<MmrRootWitnessReceipt, String> {
    let stream = ctx.generate_markers(7, "root-witness");
    let checkpoint = ctx.create_checkpoint(&stream);
    let root = checkpoint.root().expect("witness root").clone();
    let statement = mmr_root_witness_statement(
        &root,
        observed_at_unix_seconds,
        "cross-zone-witnesses",
        "ltv-policy-v1",
    )
    .map_err(|err| format!("root witness statement failed: {err}"))?;

    let (signing_keys, threshold_config) = witness_threshold_config(2, 3);
    let signatures = signing_keys
        .iter()
        .zip(threshold_config.signer_keys.iter())
        .take(signature_count)
        .map(|(signing_key, signer_key)| {
            sign(
                signing_key,
                &signer_key.key_id,
                MMR_ROOT_WITNESS_ARTIFACT_ID,
                MMR_ROOT_WITNESS_CONNECTOR_ID,
                &statement.content_hash,
            )
        })
        .collect::<Vec<PartialSignature>>();
    let witness_artifact = mmr_root_witness_artifact(&statement, signatures)
        .map_err(|err| format!("root witness artifact failed: {err}"))?;

    Ok(MmrRootWitnessReceipt {
        statement,
        threshold_config,
        witness_artifact,
        trace_id: "trace-root-witness".to_string(),
        timestamp: "2026-06-17T00:00:00Z".to_string(),
    })
}

pub struct PrefixProofValidGenerationTest;

impl ConformanceTest for PrefixProofValidGenerationTest {
    fn id(&self) -> &str {
        "R4.1"
    }
    fn name(&self) -> &str {
        "Valid prefix proof generation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "4"
    }
    fn description(&self) -> &str {
        "MUST generate valid prefix proofs"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (prefix_checkpoint, super_checkpoint) = prefix_pair(ctx, 5, 11);
        let proof = match mmr_prefix_proof(&prefix_checkpoint, &super_checkpoint) {
            Ok(proof) => proof,
            Err(err) => return TestResult::fail(format!("prefix generation failed: {err}")),
        };

        if proof.prefix_size != 5 || proof.super_tree_size != 11 {
            return TestResult::fail(format!(
                "unexpected proof sizes prefix={} super={}",
                proof.prefix_size, proof.super_tree_size
            ));
        }
        if proof.super_leaf_hashes.len() != 11 {
            return TestResult::fail(format!(
                "proof must carry all super-checkpoint leaves, got {}",
                proof.super_leaf_hashes.len()
            ));
        }

        if let Some(failure) = assert_prefix_verifies(&proof, &prefix_checkpoint, &super_checkpoint)
        {
            return failure;
        }

        TestResult::pass()
    }
}

pub struct PrefixProofInvalidOrderingTest;

impl ConformanceTest for PrefixProofInvalidOrderingTest {
    fn id(&self) -> &str {
        "R4.2"
    }
    fn name(&self) -> &str {
        "Invalid ordering rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "4"
    }
    fn description(&self) -> &str {
        "MUST reject when prefix_size > super_tree_size"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (prefix_checkpoint, super_checkpoint) = prefix_pair(ctx, 12, 6);
        match mmr_prefix_proof(&prefix_checkpoint, &super_checkpoint) {
            Err(err) if err.code() == "MMR_PREFIX_SIZE_INVALID" => TestResult::pass(),
            Err(err) => TestResult::fail(format!("unexpected error: {err}")),
            Ok(_) => TestResult::fail("larger prefix checkpoint was accepted"),
        }
    }
}

pub struct PrefixProofDisabledCheckpointTest;

impl ConformanceTest for PrefixProofDisabledCheckpointTest {
    fn id(&self) -> &str {
        "R4.3"
    }
    fn name(&self) -> &str {
        "Disabled checkpoint rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "4"
    }
    fn description(&self) -> &str {
        "MUST reject when checkpoints are disabled"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let stream = ctx.generate_markers(4, "disabled-prefix");
        let enabled_checkpoint = ctx.create_checkpoint(&stream);
        let disabled_checkpoint = MmrCheckpoint::disabled();

        match mmr_prefix_proof(&enabled_checkpoint, &disabled_checkpoint) {
            Err(err) if err.code() == "MMR_DISABLED" => TestResult::pass(),
            Err(err) => TestResult::fail(format!("unexpected error: {err}")),
            Ok(_) => TestResult::fail("disabled super-checkpoint was accepted"),
        }
    }
}

pub struct PrefixProofRelationshipValidationTest;

impl ConformanceTest for PrefixProofRelationshipValidationTest {
    fn id(&self) -> &str {
        "R4.4"
    }
    fn name(&self) -> &str {
        "Prefix relationship validation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "4"
    }
    fn description(&self) -> &str {
        "MUST validate prefix relationship"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let prefix_stream = ctx.generate_markers(5, "original-prefix");
        let unrelated_super_stream = ctx.generate_markers(11, "different-prefix");
        let prefix_checkpoint = ctx.create_checkpoint(&prefix_stream);
        let unrelated_super_checkpoint = ctx.create_checkpoint(&unrelated_super_stream);

        match mmr_prefix_proof(&prefix_checkpoint, &unrelated_super_checkpoint) {
            Err(err) if err.code() == "MMR_INVALID_PROOF" => TestResult::pass(),
            Err(err) => TestResult::fail(format!("unexpected error: {err}")),
            Ok(_) => TestResult::fail("unrelated super-checkpoint was accepted as a prefix"),
        }
    }
}

pub struct RootReattestationValidChainTest;

impl ConformanceTest for RootReattestationValidChainTest {
    fn id(&self) -> &str {
        "R4.5"
    }
    fn name(&self) -> &str {
        "Valid root re-attestation chain"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "4"
    }
    fn description(&self) -> &str {
        "MUST bind old MMR roots to newer roots through re-attested prefix chains"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (checkpoint_a, checkpoint_b) = prefix_pair(ctx, 4, 8);
        let (_, checkpoint_c) = prefix_pair(ctx, 8, 12);

        let first = match mmr_root_reattestation(
            &checkpoint_a,
            &checkpoint_b,
            1_700_000_100,
            ED25519_V1_CRYPTO_SUITE,
        ) {
            Ok(reattestation) => reattestation,
            Err(err) => return TestResult::fail(format!("first re-attestation failed: {err}")),
        };
        let second = match mmr_root_reattestation(
            &checkpoint_b,
            &checkpoint_c,
            1_700_000_200,
            ED25519_V1_CRYPTO_SUITE,
        ) {
            Ok(reattestation) => reattestation,
            Err(err) => return TestResult::fail(format!("second re-attestation failed: {err}")),
        };

        if let Err(err) = verify_root_reattestation(&first) {
            return TestResult::fail(format!("single re-attestation did not verify: {err}"));
        }

        let chain = MmrRootReattestationChain {
            origin_root: checkpoint_a.root().expect("origin root").clone(),
            attestations: vec![first, second],
        };
        match verify_root_reattestation_chain(&chain) {
            Ok(root) if root == *checkpoint_c.root().expect("terminal root") => TestResult::pass(),
            Ok(root) => TestResult::fail(format!("chain ended at unexpected root: {root:?}")),
            Err(err) => TestResult::fail(format!("chain verification failed: {err}")),
        }
    }
}

pub struct RootReattestationTamperRejectionTest;

impl ConformanceTest for RootReattestationTamperRejectionTest {
    fn id(&self) -> &str {
        "R4.6"
    }
    fn name(&self) -> &str {
        "Re-attestation tamper rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "4"
    }
    fn description(&self) -> &str {
        "MUST reject re-attestation hashes after prefix or root tampering"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let (checkpoint_a, checkpoint_b) = prefix_pair(ctx, 5, 9);
        let mut reattestation = match mmr_root_reattestation(
            &checkpoint_a,
            &checkpoint_b,
            1_700_000_100,
            ED25519_V1_CRYPTO_SUITE,
        ) {
            Ok(reattestation) => reattestation,
            Err(err) => return TestResult::fail(format!("re-attestation failed: {err}")),
        };
        reattestation.prefix_proof.super_leaf_hashes[0] = marker_leaf_hash("tampered-super-leaf");

        match verify_root_reattestation(&reattestation) {
            Err(err) if err.code() == "MMR_ROOT_MISMATCH" || err.code() == "MMR_INVALID_PROOF" => {
                TestResult::pass()
            }
            Err(err) => TestResult::fail(format!("unexpected error: {err}")),
            Ok(()) => TestResult::fail("tampered re-attestation was accepted"),
        }
    }
}

pub struct RootWitnessCosigningValidTest;

impl ConformanceTest for RootWitnessCosigningValidTest {
    fn id(&self) -> &str {
        "R4.7"
    }
    fn name(&self) -> &str {
        "Valid independent root witness cosigning"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "4"
    }
    fn description(&self) -> &str {
        "MUST verify k-of-n independent witness signatures over an MMR root"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let receipt = match root_witness_receipt(ctx, 1_700_000_100, 2) {
            Ok(receipt) => receipt,
            Err(err) => return TestResult::fail(err),
        };

        let verification = match verify_root_witness_receipt(&receipt) {
            Ok(verification) => verification,
            Err(err) => return TestResult::fail(format!("root witness did not verify: {err}")),
        };
        if verification.valid_signatures != 2 || verification.threshold != 2 {
            return TestResult::fail(format!(
                "unexpected witness quorum valid={} threshold={}",
                verification.valid_signatures, verification.threshold
            ));
        }

        match verify_root_witness_anteriority(&receipt, 1_700_000_200) {
            Ok(anteriority)
                if anteriority
                    .event_codes
                    .iter()
                    .any(|code| code == "FN-MMR-ROOT-WITNESS-ANTERIORITY-VERIFIED") =>
            {
                TestResult::pass()
            }
            Ok(_) => TestResult::fail("anteriority verification omitted event code"),
            Err(err) => TestResult::fail(format!("anteriority verification failed: {err}")),
        }
    }
}

pub struct RootWitnessBackdatedForgeryRejectionTest;

impl ConformanceTest for RootWitnessBackdatedForgeryRejectionTest {
    fn id(&self) -> &str {
        "R4.8"
    }
    fn name(&self) -> &str {
        "Back-dated root witness rejection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Security
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "4"
    }
    fn description(&self) -> &str {
        "MUST reject roots whose witness observation is after the verification time"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let receipt = match root_witness_receipt(ctx, 1_700_000_300, 2) {
            Ok(receipt) => receipt,
            Err(err) => return TestResult::fail(err),
        };

        match verify_root_witness_anteriority(&receipt, 1_700_000_200) {
            Err(err) if err.code() == "MMR_INVALID_PROOF" => TestResult::pass(),
            Err(err) => TestResult::fail(format!("unexpected error: {err}")),
            Ok(_) => TestResult::fail("too-late root witness was accepted as anterior"),
        }
    }
}

pub struct RootWitnessEvidenceLedgerRecordingTest;

impl ConformanceTest for RootWitnessEvidenceLedgerRecordingTest {
    fn id(&self) -> &str {
        "R4.9"
    }
    fn name(&self) -> &str {
        "Root witness evidence ledger recording"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }
    fn spec_section(&self) -> &str {
        "4"
    }
    fn description(&self) -> &str {
        "MUST record verified root witness receipts as proof-of-anteriority ledger evidence"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let receipt = match root_witness_receipt(ctx, 1_700_000_100, 2) {
            Ok(receipt) => receipt,
            Err(err) => return TestResult::fail(err),
        };
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(4, 64 * 1024));

        let (entry_id, verification) =
            match ledger.append_mmr_root_witness_receipt(&receipt, 1_700_000_200) {
                Ok(result) => result,
                Err(err) => {
                    return TestResult::fail(format!("root witness evidence append failed: {err}"));
                }
            };
        if verification.valid_signatures != 2 || verification.threshold != 2 {
            return TestResult::fail(format!(
                "unexpected witness quorum valid={} threshold={}",
                verification.valid_signatures, verification.threshold
            ));
        }
        if ledger.total_appended() != 1 {
            return TestResult::fail(format!(
                "ledger appended count mismatch: {}",
                ledger.total_appended()
            ));
        }

        let Some((retained_id, entry, _)) = ledger.iter_all().next() else {
            return TestResult::fail("ledger did not retain appended witness entry");
        };
        if *retained_id != entry_id {
            return TestResult::fail(format!(
                "retained entry id mismatch: retained={retained_id} appended={entry_id}"
            ));
        }
        if entry.schema_version != MMR_ROOT_WITNESS_EVIDENCE_SCHEMA_VERSION {
            return TestResult::fail(format!(
                "unexpected ledger schema version: {}",
                entry.schema_version
            ));
        }
        if !entry
            .decision_id
            .starts_with(MMR_ROOT_WITNESS_EVIDENCE_DECISION_PREFIX)
        {
            return TestResult::fail(format!(
                "unexpected witness decision id: {}",
                entry.decision_id
            ));
        }
        if entry
            .payload
            .get("schema_version")
            .and_then(|value| value.as_str())
            != Some(MMR_ROOT_WITNESS_EVIDENCE_SCHEMA_VERSION)
        {
            return TestResult::fail("witness payload omitted schema version");
        }

        TestResult::pass()
    }
}
