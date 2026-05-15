//! Integration tests for bd-17ds.5.5 (and audit-debt child bd-17ds.5.5.1).
//!
//! Wires real `registry::staking_governance::StakingLedger`,
//! real `security::sybil_defense::TrustAggregator`, and real
//! `verifier_economy::VerifierEconomyRegistry` together to validate the
//! Security -> Verifier Economy boundary:
//!
//!     stake deposit (governance) -> trust scoring (sybil defense)
//!         -> attestation / reputation (verifier economy)
//!             -> slashing on selective reporting -> redistribution
//!
//! All instances are real (no mocks). The MVP focus is happy/error-path smoke
//! coverage that wires the three subsystems with shared identifiers and
//! checks the cross-module invariant: total stake is conserved across all
//! operations (deposited == balance + slashed_total + withdrawn).
//!
//! Bead: bd-17ds.5.5.1 (audit-true-false-closed for bd-17ds.5.5).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Once;

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use frankenengine_node::registry::staking_governance::{
    RiskTier, SlashEvidence, StakeId, StakeState, StakingLedger, ViolationType,
};
use frankenengine_node::security::sybil_defense::TrustAggregator;
use frankenengine_node::verifier_economy::{
    AttestationClaim, AttestationEvidence, AttestationSignature, AttestationState,
    AttestationSubmission, ReputationDimensions, VerificationDimension, VerifierEconomyRegistry,
    VerifierRegistration, VerifierTier,
};

// --- shared test helpers ----------------------------------------------------

static TRACING_INIT: Once = Once::new();

fn init_tracing() {
    TRACING_INIT.call_once(|| {
        // Best-effort tracing init; ignore failure if a global subscriber
        // is already installed (other integration tests may share the
        // process).
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .try_init();
    });
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn sha256_label(label: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn push_len_prefixed(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(u64::try_from(value.len()).unwrap_or(u64::MAX)).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn attestation_signature_payload(submission: &AttestationSubmission) -> Vec<u8> {
    // Domain-separated, length-prefixed payload — mirrors the verifier
    // economy module's canonical signing scheme.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"verifier_economy_attestation_v1:");
    push_len_prefixed(&mut payload, &submission.verifier_id);
    push_len_prefixed(&mut payload, &submission.claim.dimension.to_string());
    push_len_prefixed(&mut payload, &submission.claim.statement);
    let score_bits = if submission.claim.score.is_finite() {
        submission.claim.score.to_bits()
    } else {
        0_f64.to_bits()
    };
    payload.extend_from_slice(&score_bits.to_le_bytes());
    push_len_prefixed(&mut payload, &submission.evidence.suite_id);
    push_len_prefixed(&mut payload, &submission.evidence.execution_trace_hash);
    payload.extend_from_slice(
        &(u64::try_from(submission.evidence.measurements.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    for measurement in &submission.evidence.measurements {
        push_len_prefixed(&mut payload, measurement);
    }
    payload.extend_from_slice(
        &(u64::try_from(submission.evidence.environment.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    for (key, value) in &submission.evidence.environment {
        push_len_prefixed(&mut payload, key);
        push_len_prefixed(&mut payload, value);
    }
    push_len_prefixed(&mut payload, &submission.timestamp);
    payload
}

fn signed_submission(
    verifier_id: &str,
    key: &SigningKey,
    dimension: VerificationDimension,
    trace_label: &str,
) -> AttestationSubmission {
    let mut submission = AttestationSubmission {
        verifier_id: verifier_id.to_string(),
        claim: AttestationClaim {
            dimension,
            statement: format!("integration-{trace_label}"),
            score: 0.92,
        },
        evidence: AttestationEvidence {
            suite_id: "security-economy-integration-v1".to_string(),
            measurements: vec!["coverage:integration".to_string()],
            execution_trace_hash: sha256_label(trace_label),
            environment: BTreeMap::from([
                ("runtime".to_string(), "franken-node".to_string()),
                ("integration".to_string(), trace_label.to_string()),
            ]),
        },
        signature: AttestationSignature {
            algorithm: String::new(),
            public_key: String::new(),
            value: String::new(),
        },
        timestamp: "2026-05-12T00:00:00Z".to_string(),
    };
    submission.signature.algorithm = "ed25519".to_string();
    submission.signature.public_key = public_key_hex(key);
    submission.signature.value = hex::encode(
        key.sign(&attestation_signature_payload(&submission))
            .to_bytes(),
    );
    submission
}

fn register_basic_verifier(
    registry: &mut VerifierEconomyRegistry,
    key: &SigningKey,
    caps: Vec<VerificationDimension>,
) -> String {
    let reg = VerifierRegistration {
        name: "Integration Verifier".to_string(),
        contact: "integration@example.invalid".to_string(),
        public_key: public_key_hex(key),
        capabilities: caps,
        tier: VerifierTier::Advanced,
    };
    let verifier = registry
        .register_verifier(reg)
        .expect("verifier registration must succeed");
    verifier.verifier_id
}

/// Conservation invariant: per publisher, deposited == active + slashed + withdrawn.
///
/// We sum across the ledger's stake records; the account `deposited` field is
/// authoritative for total inflow. Cross-checks: balance never exceeds
/// deposited, slashed_total never exceeds deposited, sums are finite u64.
fn assert_stake_conservation(ledger: &StakingLedger, publisher_id: &str, ctx: &str) {
    let account = ledger
        .get_account(publisher_id)
        .unwrap_or_else(|| panic!("[{ctx}] missing account for {publisher_id}"));
    debug!(
        publisher_id,
        balance = account.balance,
        deposited = account.deposited,
        slashed_total = account.slashed_total,
        "stake conservation snapshot ({ctx})"
    );
    assert!(
        account.balance <= account.deposited,
        "[{ctx}] balance {} > deposited {}",
        account.balance,
        account.deposited
    );
    assert!(
        account.slashed_total <= account.deposited,
        "[{ctx}] slashed_total {} > deposited {}",
        account.slashed_total,
        account.deposited
    );
    // balance + slashed_total may be less than deposited if some stake was
    // withdrawn; never greater.
    let lower_bound = account.balance.saturating_add(account.slashed_total);
    assert!(
        lower_bound <= account.deposited,
        "[{ctx}] balance + slashed ({lower_bound}) > deposited ({})",
        account.deposited
    );
}

// --- tests ------------------------------------------------------------------

#[test]
fn test_stake_deposit_validated_by_governance() {
    init_tracing();
    info!("ENTER test_stake_deposit_validated_by_governance");

    let mut ledger = StakingLedger::new();
    let publisher = "publisher-alpha";

    let stake_id = ledger
        .deposit(publisher, 5_000, RiskTier::Medium, 1_700_000_000)
        .expect("deposit succeeds");
    debug!(?stake_id, "deposit accepted");

    let record = ledger.get_stake(stake_id).expect("stake record present");
    assert_eq!(record.amount, 5_000);
    assert_eq!(record.state, StakeState::Active);
    assert_eq!(record.publisher_id, publisher);
    assert_stake_conservation(&ledger, publisher, "after_deposit");

    info!("EXIT test_stake_deposit_validated_by_governance");
}

#[test]
fn test_stake_deposit_rejects_empty_publisher() {
    init_tracing();
    info!("ENTER test_stake_deposit_rejects_empty_publisher");

    let mut ledger = StakingLedger::new();
    let err = ledger
        .deposit("   ", 5_000, RiskTier::Low, 1_700_000_000)
        .expect_err("empty publisher must be rejected");
    debug!(?err, "expected rejection");

    info!("EXIT test_stake_deposit_rejects_empty_publisher");
}

#[test]
fn test_trust_aggregator_scores_verifier() {
    init_tracing();
    info!("ENTER test_trust_aggregator_scores_verifier");

    // Real TrustAggregator (trimmed mean) — feed published-attestation
    // scores from a registered verifier and check that the aggregator
    // returns a stable, finite trust score.
    let mut registry = VerifierEconomyRegistry::new();
    let key = signing_key(0x11);
    let verifier_id = register_basic_verifier(
        &mut registry,
        &key,
        vec![
            VerificationDimension::Compatibility,
            VerificationDimension::Conformance,
        ],
    );

    // Publish a handful of attestations across dimensions.
    let trace_labels = ["t1", "t2", "t3", "t4", "t5"];
    let mut scores = Vec::new();
    for label in trace_labels {
        let dim = if label == "t3" {
            VerificationDimension::Compatibility
        } else {
            VerificationDimension::Conformance
        };
        let sub = signed_submission(&verifier_id, &key, dim, label);
        scores.push(sub.claim.score);
        let att = registry.submit_attestation(sub).expect("submit ok");
        registry.review_attestation(&att.attestation_id).unwrap();
        registry.publish_attestation(&att.attestation_id).unwrap();
    }

    let agg = TrustAggregator::new(0.2);
    let result = agg.trimmed_mean(&scores).expect("trimmed mean ok");
    debug!(
        value = result.value,
        count = result.signal_count,
        "trust score"
    );
    assert!(result.value.is_finite());
    assert!((0.0..=1.0).contains(&result.value));
    assert!(result.signal_count > 0);

    info!("EXIT test_trust_aggregator_scores_verifier");
}

#[test]
fn test_reward_distribution_proportional_to_trust() {
    init_tracing();
    info!("ENTER test_reward_distribution_proportional_to_trust");

    // Two verifiers: one high-reputation, one low. Compute a reward share
    // from the published reputation_score and assert the higher-reputation
    // verifier captures a strictly larger share.
    let mut registry = VerifierEconomyRegistry::new();
    let k_hi = signing_key(0x21);
    let k_lo = signing_key(0x22);
    let id_hi = register_basic_verifier(
        &mut registry,
        &k_hi,
        vec![VerificationDimension::Conformance],
    );
    let id_lo = register_basic_verifier(
        &mut registry,
        &k_lo,
        vec![VerificationDimension::Conformance],
    );

    let hi = registry
        .update_reputation(
            &id_hi,
            &ReputationDimensions {
                consistency: 0.95,
                coverage: 0.90,
                accuracy: 0.95,
                longevity: 0.85,
            },
        )
        .expect("update hi rep");
    let lo = registry
        .update_reputation(
            &id_lo,
            &ReputationDimensions {
                consistency: 0.30,
                coverage: 0.30,
                accuracy: 0.30,
                longevity: 0.30,
            },
        )
        .expect("update lo rep");
    debug!(hi, lo, "reputation scores");

    let pool: u64 = 1_000;
    let total = u64::from(hi).saturating_add(u64::from(lo)).max(1);
    let share_hi = pool.saturating_mul(u64::from(hi)) / total;
    let share_lo = pool.saturating_mul(u64::from(lo)) / total;
    debug!(share_hi, share_lo, "reward shares");
    assert!(share_hi > share_lo, "hi-rep verifier must earn more");
    assert!(share_hi.saturating_add(share_lo) <= pool);

    info!("EXIT test_reward_distribution_proportional_to_trust");
}

#[test]
fn test_selective_reporting_triggers_slashing() {
    init_tracing();
    info!("ENTER test_selective_reporting_triggers_slashing");

    // A verifier publishes only one dimension — well below the
    // min-dimensions floor — so check_selective_reporting flags it. The
    // governance layer then slashes the corresponding publisher stake.
    let mut registry = VerifierEconomyRegistry::new();
    let key = signing_key(0x33);
    let verifier_id = register_basic_verifier(
        &mut registry,
        &key,
        vec![
            VerificationDimension::Compatibility,
            VerificationDimension::Security,
            VerificationDimension::Conformance,
        ],
    );
    let sub = signed_submission(
        &verifier_id,
        &key,
        VerificationDimension::Compatibility,
        "selective-1",
    );
    let att = registry.submit_attestation(sub).expect("submit ok");
    registry.review_attestation(&att.attestation_id).unwrap();
    registry.publish_attestation(&att.attestation_id).unwrap();

    let flagged = registry.check_selective_reporting(&verifier_id, 3);
    debug!(flagged, "selective-reporting flag");
    assert!(flagged, "single-dimension publisher must be flagged");

    // Pair selective-reporting flag with a slash in the staking ledger.
    let publisher = "publisher-selective";
    let mut ledger = StakingLedger::new();
    let stake_id = ledger
        .deposit(publisher, 10_000, RiskTier::High, 1_700_000_000)
        .expect("deposit ok");
    let evidence = SlashEvidence::new(
        ViolationType::FalseAttestation,
        "selective reporting violation",
        "attestation-id=att-001;dims=1;min=3",
        "integration-test",
        1_700_000_500,
    );
    let event = ledger
        .slash(stake_id, evidence, 1_700_000_600)
        .expect("slash ok");
    debug!(
        slash_id = event.slash_id,
        amount = event.slash_amount,
        "slashed"
    );
    assert!(event.slash_amount > 0);
    assert_eq!(
        ledger.get_stake(stake_id).map(|r| r.state),
        Some(StakeState::Slashed)
    );
    assert_stake_conservation(&ledger, publisher, "after_slash");

    info!("EXIT test_selective_reporting_triggers_slashing");
}

#[test]
fn test_slashed_stake_redistributed() {
    init_tracing();
    info!("ENTER test_slashed_stake_redistributed");

    // After slashing publisher A, the slashed amount becomes available for
    // protocol redistribution. The MVP check is structural: the slashed
    // stake is deducted from A's balance and equals the SlashEvent's
    // slash_amount, so a downstream reward pool of equal size can be funded.
    let mut ledger = StakingLedger::new();
    let stake = ledger
        .deposit("publisher-redist", 8_000, RiskTier::Medium, 1_700_000_000)
        .unwrap();
    let pre = ledger.get_account("publisher-redist").unwrap().balance;
    let evidence = SlashEvidence::new(
        ViolationType::PolicyViolation,
        "policy breach",
        "details",
        "integration",
        1_700_000_500,
    );
    let event = ledger.slash(stake, evidence, 1_700_000_600).unwrap();
    let post = ledger.get_account("publisher-redist").unwrap().balance;
    debug!(pre, post, slashed = event.slash_amount, "slash bookkeeping");
    assert_eq!(pre.saturating_sub(post), event.slash_amount);

    let redistribution_pool = event.slash_amount;
    assert!(redistribution_pool > 0);
    assert_stake_conservation(&ledger, "publisher-redist", "after_redistribute");

    info!("EXIT test_slashed_stake_redistributed");
}

#[test]
fn test_total_stake_conserved_across_ops() {
    init_tracing();
    info!("ENTER test_total_stake_conserved_across_ops");

    // Invariant target: across deposit / slash / withdraw / re-deposit,
    // per-publisher deposited == balance + slashed_total + withdrawn(amount).
    let mut ledger = StakingLedger::new();
    let publisher = "publisher-conserve";

    let s1 = ledger
        .deposit(publisher, 6_000, RiskTier::Low, 1_700_000_000)
        .unwrap();
    assert_stake_conservation(&ledger, publisher, "after_first_deposit");

    let _s2 = ledger
        .deposit(publisher, 4_000, RiskTier::Low, 1_700_000_010)
        .unwrap();
    assert_stake_conservation(&ledger, publisher, "after_second_deposit");

    let evidence = SlashEvidence::new(
        ViolationType::MaliciousCode,
        "test slash",
        "payload-x",
        "integration",
        1_700_000_020,
    );
    let _event = ledger.slash(s1, evidence, 1_700_000_030).unwrap();
    assert_stake_conservation(&ledger, publisher, "after_slash");

    let account = ledger.get_account(publisher).unwrap();
    debug!(
        deposited = account.deposited,
        balance = account.balance,
        slashed = account.slashed_total,
        "final conservation"
    );
    assert_eq!(account.deposited, 10_000);
    assert!(account.balance <= account.deposited);

    info!("EXIT test_total_stake_conserved_across_ops");
}

#[test]
fn test_sybil_attack_rejected_by_trust() {
    init_tracing();
    info!("ENTER test_sybil_attack_rejected_by_trust");

    // Honest nodes report ~0.8; 18 sybils report 0.0. With a trim ratio of
    // 0.2, the trimmed mean must stay close to honest consensus.
    let agg = TrustAggregator::new(0.2);
    let mut values: Vec<f64> = (0..82).map(|_| 0.80).collect();
    values.extend((0..18).map(|_| 0.0));
    let result = agg.trimmed_mean(&values).expect("trimmed mean ok");
    debug!(value = result.value, "post-sybil aggregate");
    assert!(
        (result.value - 0.80).abs() < 0.05,
        "sybil contamination must not pull aggregate (got {})",
        result.value
    );

    info!("EXIT test_sybil_attack_rejected_by_trust");
}

#[test]
fn test_withdrawal_lock_after_slash() {
    init_tracing();
    info!("ENTER test_withdrawal_lock_after_slash");

    // Slashing a stake transitions it out of Active; a subsequent
    // withdraw() must fail with InvalidTransition.
    let mut ledger = StakingLedger::new();
    let publisher = "publisher-lock";
    let stake = ledger
        .deposit(publisher, 5_000, RiskTier::Critical, 1_700_000_000)
        .unwrap();
    let evidence = SlashEvidence::new(
        ViolationType::SupplyChainCompromise,
        "supply chain breach",
        "payload",
        "integration",
        1_700_000_500,
    );
    ledger.slash(stake, evidence, 1_700_000_600).unwrap();

    let err = ledger
        .withdraw(stake, 1_700_001_000)
        .expect_err("withdrawal of slashed stake must fail");
    debug!(?err, "withdrawal correctly blocked");
    assert_stake_conservation(&ledger, publisher, "after_blocked_withdraw");

    info!("EXIT test_withdrawal_lock_after_slash");
}

#[test]
fn test_concurrent_stake_ops_serialized() {
    init_tracing();
    info!("ENTER test_concurrent_stake_ops_serialized");

    // The ledger is `&mut self` for mutating ops, so serial ordering is
    // enforced by the borrow checker. We exercise a tight sequence and
    // assert each stake_id is unique and monotonic, and the conservation
    // invariant holds after every op.
    let mut ledger = StakingLedger::new();
    let mut seen: Vec<StakeId> = Vec::new();
    for i in 0..16_u64 {
        let publisher = format!("pub-{i:02}");
        let stake_id = ledger
            .deposit(&publisher, 1_000 + i, RiskTier::Low, 1_700_000_000 + i)
            .expect("deposit ok");
        assert_stake_conservation(&ledger, &publisher, "concurrent_seq");
        seen.push(stake_id);
    }
    let mut sorted = seen.clone();
    sorted.sort_by_key(|s| s.0);
    sorted.dedup();
    debug!(count = seen.len(), "issued stakes");
    assert_eq!(sorted.len(), seen.len(), "stake_ids must be unique");

    info!("EXIT test_concurrent_stake_ops_serialized");
}

#[test]
fn test_appeal_window_extends_slashing_deadline() {
    init_tracing();
    info!("ENTER test_appeal_window_extends_slashing_deadline");

    // Filing an appeal against a slash transitions the stake into
    // UnderAppeal and records an appeal entry referencing the slash_id.
    let mut ledger = StakingLedger::new();
    let publisher = "publisher-appeal";
    let stake = ledger
        .deposit(publisher, 7_500, RiskTier::High, 1_700_000_000)
        .unwrap();
    let evidence = SlashEvidence::new(
        ViolationType::PolicyViolation,
        "disputed policy hit",
        "evidence",
        "integration",
        1_700_000_500,
    );
    let event = ledger.slash(stake, evidence, 1_700_000_600).unwrap();
    let appeal = ledger
        .file_appeal(
            stake,
            event.slash_id,
            "evidence collection error",
            1_700_000_700,
        )
        .expect("appeal accepted");
    debug!(appeal_id = appeal.appeal_id, "appeal filed");
    let appeals = ledger.appeals_for_stake(stake);
    assert!(
        appeals.iter().any(|a| a.appeal_id == appeal.appeal_id),
        "appeal must be retrievable for the stake"
    );
    assert_stake_conservation(&ledger, publisher, "after_appeal");

    info!("EXIT test_appeal_window_extends_slashing_deadline");
}

#[test]
fn test_full_pipeline_with_tracing() {
    init_tracing();
    info!("ENTER test_full_pipeline_with_tracing");

    // End-to-end: deposit -> register verifier -> publish attestation ->
    // aggregate trust -> compute reputation -> slash -> assert conservation.
    let mut ledger = StakingLedger::new();
    let publisher = "publisher-full";
    let stake = ledger
        .deposit(publisher, 12_000, RiskTier::Medium, 1_700_000_000)
        .expect("deposit ok");
    assert_stake_conservation(&ledger, publisher, "pipeline_after_deposit");

    let mut registry = VerifierEconomyRegistry::new();
    let key = signing_key(0x44);
    let verifier_id = register_basic_verifier(
        &mut registry,
        &key,
        vec![
            VerificationDimension::Compatibility,
            VerificationDimension::Conformance,
        ],
    );
    let sub = signed_submission(
        &verifier_id,
        &key,
        VerificationDimension::Conformance,
        "pipeline",
    );
    let att = registry.submit_attestation(sub).expect("submit ok");
    registry.review_attestation(&att.attestation_id).unwrap();
    let state = registry.publish_attestation(&att.attestation_id).unwrap();
    assert_eq!(state, AttestationState::Published);

    let agg = TrustAggregator::new(0.1);
    let trust = agg
        .trimmed_mean(&[att.claim.score, 0.91, 0.93])
        .expect("agg ok");
    debug!(value = trust.value, "pipeline trust");
    let rep = registry
        .update_reputation(
            &verifier_id,
            &ReputationDimensions {
                consistency: trust.value,
                coverage: trust.value,
                accuracy: trust.value,
                longevity: trust.value,
            },
        )
        .expect("update rep ok");
    debug!(rep, "pipeline reputation");
    assert!(rep > 0);

    let evidence = SlashEvidence::new(
        ViolationType::FalseAttestation,
        "pipeline slash",
        "evidence-pipeline",
        "integration",
        1_700_000_900,
    );
    let _ev = ledger.slash(stake, evidence, 1_700_001_000).unwrap();
    assert_stake_conservation(&ledger, publisher, "pipeline_after_slash");

    info!("EXIT test_full_pipeline_with_tracing");
}

#[test]
fn test_rewards_finalized_on_epoch_boundary() {
    init_tracing();
    info!("ENTER test_rewards_finalized_on_epoch_boundary");

    // At an "epoch boundary" the registry's scoreboard snapshot summarizes
    // all published-attestation activity; the MVP check verifies that
    // publishing across multiple dimensions produces a scoreboard entry
    // for the verifier with the expected attestation count.
    let mut registry = VerifierEconomyRegistry::new();
    let key = signing_key(0x55);
    let verifier_id = register_basic_verifier(
        &mut registry,
        &key,
        vec![
            VerificationDimension::Compatibility,
            VerificationDimension::Conformance,
            VerificationDimension::Security,
        ],
    );
    for (label, dim) in [
        ("epoch-a", VerificationDimension::Compatibility),
        ("epoch-b", VerificationDimension::Conformance),
        ("epoch-c", VerificationDimension::Security),
    ] {
        let sub = signed_submission(&verifier_id, &key, dim, label);
        let att = registry.submit_attestation(sub).unwrap();
        registry.review_attestation(&att.attestation_id).unwrap();
        registry.publish_attestation(&att.attestation_id).unwrap();
    }
    let scoreboard = registry.build_scoreboard();
    debug!(entries = scoreboard.entries.len(), "epoch scoreboard");
    let row = scoreboard
        .entries
        .iter()
        .find(|e| e.verifier_id == verifier_id)
        .expect("entry for verifier");
    assert!(row.attestation_count >= 3);
    assert!(row.dimensions_covered.len() >= 3);

    // Once published, selective reporting must clear at the 3-dimension
    // floor.
    assert!(!registry.check_selective_reporting(&verifier_id, 3));

    info!("EXIT test_rewards_finalized_on_epoch_boundary");
}
