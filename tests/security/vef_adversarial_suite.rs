//! bd-3ptu: deterministic adversarial suite for VEF proof validation paths.
//!
//! Attack classes covered:
//! - receipt tampering
//! - proof replay
//! - stale-policy proofs
//! - commitment mismatch

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const EVENT_ATTACK_DETECTED: &str = "VEF-ADVERSARIAL-001";
const EVENT_ATTACK_CLASSIFIED: &str = "VEF-ADVERSARIAL-002";

const ERR_TAMPER: &str = "VEF-ADVERSARIAL-ERR-TAMPER";
const ERR_REPLAY: &str = "VEF-ADVERSARIAL-ERR-REPLAY";
const ERR_STALE_POLICY: &str = "VEF-ADVERSARIAL-ERR-STALE-POLICY";
const ERR_COMMITMENT: &str = "VEF-ADVERSARIAL-ERR-COMMITMENT";

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttackClass {
    ReceiptTampering,
    ProofReplay,
    StalePolicy,
    CommitmentMismatch,
}

impl AttackClass {
    fn as_str(&self) -> &'static str {
        match self {
            Self::ReceiptTampering => "receipt_tampering",
            Self::ProofReplay => "proof_replay",
            Self::StalePolicy => "stale_policy",
            Self::CommitmentMismatch => "commitment_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectionEvent {
    event_code: String,
    trace_id: String,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectionFailure {
    code: String,
    class: AttackClass,
    remediation_hint: String,
    detail: String,
    events: Vec<DetectionEvent>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct Receipt {
    receipt_id: String,
    actor_identity: String,
    payload: String,
    sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptChainFixture {
    chain_id: String,
    receipts: Vec<Receipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProofEnvelope {
    proof_id: String,
    chain_id: String,
    checkpoint_id: u64,
    window_start: usize,
    window_end: usize,
    window_fingerprint: String,
    commitment_hash: String,
    policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerificationRequest {
    expected_chain_id: String,
    expected_window_start: usize,
    expected_window_end: usize,
    active_policy_hash: String,
    trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProofBinding {
    chain_id: String,
    window_start: usize,
    window_end: usize,
    policy_hash: String,
}

#[derive(Debug, Default)]
struct ReplayRegistry {
    seen: BTreeMap<String, ProofBinding>,
}

fn remediation_for(class: &AttackClass) -> &'static str {
    match class {
        AttackClass::ReceiptTampering => {
            "Rebuild receipt chain from trusted source and regenerate proof for the requested window."
        }
        AttackClass::ProofReplay => {
            "Reject reused proof envelope and require a fresh proof bound to current chain/window/policy."
        }
        AttackClass::StalePolicy => {
            "Regenerate proof against the currently active policy snapshot hash."
        }
        AttackClass::CommitmentMismatch => {
            "Recompute checkpoint commitment from canonical receipts and reject mismatched proof material."
        }
    }
}

fn fail(
    class: AttackClass,
    code: &str,
    trace_id: &str,
    detail: impl Into<String>,
) -> DetectionFailure {
    let detail = detail.into();
    DetectionFailure {
        code: code.to_string(),
        remediation_hint: remediation_for(&class).to_string(),
        detail: detail.clone(),
        events: vec![
            DetectionEvent {
                event_code: EVENT_ATTACK_DETECTED.to_string(),
                trace_id: trace_id.to_string(),
                detail: detail.clone(),
            },
            DetectionEvent {
                event_code: EVENT_ATTACK_CLASSIFIED.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!("class={} code={code}", class.as_str()),
            },
        ],
        class,
    }
}

fn sha256_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("serialization must succeed in test fixtures");
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

fn receipt_hash(receipt: &Receipt) -> String {
    sha256_json(receipt)
}

fn window_hashes(
    chain: &ReceiptChainFixture,
    start: usize,
    end: usize,
) -> Result<Vec<String>, DetectionFailure> {
    if start > end {
        return Err(fail(
            AttackClass::ReceiptTampering,
            ERR_TAMPER,
            "trace-internal",
            format!("invalid window bounds start={start} end={end}"),
        ));
    }
    let slice = chain.receipts.get(start..=end).ok_or_else(|| {
        fail(
            AttackClass::ReceiptTampering,
            ERR_TAMPER,
            "trace-internal",
            format!(
                "window {start}..{end} out of bounds for chain length {}",
                chain.receipts.len()
            ),
        )
    })?;
    Ok(slice.iter().map(receipt_hash).collect())
}

fn compute_window_fingerprint(
    chain: &ReceiptChainFixture,
    start: usize,
    end: usize,
) -> Result<String, DetectionFailure> {
    let hashes = window_hashes(chain, start, end)?;
    Ok(sha256_json(&(chain.chain_id.as_str(), start, end, hashes)))
}

fn compute_commitment(
    chain: &ReceiptChainFixture,
    checkpoint_id: u64,
    start: usize,
    end: usize,
) -> Result<String, DetectionFailure> {
    let hashes = window_hashes(chain, start, end)?;
    Ok(sha256_json(&(
        "vef-adversarial-commitment-v1",
        chain.chain_id.as_str(),
        checkpoint_id,
        start,
        end,
        hashes,
    )))
}

fn mint_proof(
    chain: &ReceiptChainFixture,
    proof_id: &str,
    checkpoint_id: u64,
    start: usize,
    end: usize,
    policy_hash: &str,
) -> ProofEnvelope {
    let window_fingerprint = compute_window_fingerprint(chain, start, end).expect("valid window");
    let commitment_hash =
        compute_commitment(chain, checkpoint_id, start, end).expect("valid commitment");
    ProofEnvelope {
        proof_id: proof_id.to_string(),
        chain_id: chain.chain_id.clone(),
        checkpoint_id,
        window_start: start,
        window_end: end,
        window_fingerprint,
        commitment_hash,
        policy_hash: policy_hash.to_string(),
    }
}

fn verify_proof(
    chain: &ReceiptChainFixture,
    proof: &ProofEnvelope,
    request: &VerificationRequest,
    registry: &mut ReplayRegistry,
) -> Result<(), DetectionFailure> {
    let candidate_binding = ProofBinding {
        chain_id: request.expected_chain_id.clone(),
        window_start: request.expected_window_start,
        window_end: request.expected_window_end,
        policy_hash: request.active_policy_hash.clone(),
    };

    if let Some(previous) = registry.seen.get(&proof.proof_id)
        && previous != &candidate_binding
    {
        return Err(fail(
            AttackClass::ProofReplay,
            ERR_REPLAY,
            &request.trace_id,
            format!(
                "proof_id={} reused with different binding (prior={:?}, current={:?})",
                proof.proof_id, previous, candidate_binding
            ),
        ));
    }

    registry
        .seen
        .entry(proof.proof_id.clone())
        .or_insert(candidate_binding);

    if proof.policy_hash != request.active_policy_hash {
        return Err(fail(
            AttackClass::StalePolicy,
            ERR_STALE_POLICY,
            &request.trace_id,
            format!(
                "proof policy hash {} does not match active {}",
                proof.policy_hash, request.active_policy_hash
            ),
        ));
    }

    if proof.chain_id != request.expected_chain_id
        || proof.window_start != request.expected_window_start
        || proof.window_end != request.expected_window_end
    {
        return Err(fail(
            AttackClass::ProofReplay,
            ERR_REPLAY,
            &request.trace_id,
            format!(
                "proof binding mismatch chain/window (proof={} {}..{}, expected={} {}..{})",
                proof.chain_id,
                proof.window_start,
                proof.window_end,
                request.expected_chain_id,
                request.expected_window_start,
                request.expected_window_end
            ),
        ));
    }

    let expected_window_fingerprint = compute_window_fingerprint(
        chain,
        request.expected_window_start,
        request.expected_window_end,
    )?;
    if proof.window_fingerprint != expected_window_fingerprint {
        return Err(fail(
            AttackClass::ReceiptTampering,
            ERR_TAMPER,
            &request.trace_id,
            "window fingerprint mismatch: receipt tampering suspected",
        ));
    }

    let expected_commitment = compute_commitment(
        chain,
        proof.checkpoint_id,
        request.expected_window_start,
        request.expected_window_end,
    )?;

    if proof.commitment_hash != expected_commitment {
        return Err(fail(
            AttackClass::CommitmentMismatch,
            ERR_COMMITMENT,
            &request.trace_id,
            "checkpoint commitment mismatch",
        ));
    }

    Ok(())
}

fn sample_chain(chain_id: &str) -> ReceiptChainFixture {
    let receipts = (0_u64..6_u64)
        .map(|n| Receipt {
            receipt_id: format!("receipt-{n}"),
            actor_identity: format!("agent-{n}"),
            payload: format!("payload-{n}"),
            sequence: n,
        })
        .collect::<Vec<_>>();
    ReceiptChainFixture {
        chain_id: chain_id.to_string(),
        receipts,
    }
}

fn base_request(chain_id: &str, trace_id: &str) -> VerificationRequest {
    VerificationRequest {
        expected_chain_id: chain_id.to_string(),
        expected_window_start: 1,
        expected_window_end: 3,
        active_policy_hash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        trace_id: trace_id.to_string(),
    }
}

fn assert_error_signature(err: &DetectionFailure, code: &str, class: AttackClass) {
    assert_eq!(err.code, code);
    assert_eq!(err.class, class);
    assert!(
        err.events
            .iter()
            .any(|event| event.event_code == EVENT_ATTACK_DETECTED)
    );
    assert!(
        err.events
            .iter()
            .any(|event| event.event_code == EVENT_ATTACK_CLASSIFIED)
    );
    assert!(!err.remediation_hint.trim().is_empty());
}

#[test]
fn legitimate_proof_is_accepted() {
    let chain = sample_chain("chain-A");
    let request = base_request("chain-A", "trace-legit");
    let mut registry = ReplayRegistry::default();
    let proof = mint_proof(
        &chain,
        "proof-legit-1",
        7,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );

    let result = verify_proof(&chain, &proof, &request, &mut registry);
    assert!(result.is_ok());
}

#[test]
fn receipt_tampering_variations_fail_closed() {
    let request = base_request("chain-A", "trace-tamper");

    // 1) mutate first receipt in window
    let mut chain_1 = sample_chain("chain-A");
    chain_1.receipts[1].payload = "tampered-first".to_string();
    let proof_1 = mint_proof(
        &sample_chain("chain-A"),
        "proof-tamper-1",
        7,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    let mut registry_1 = ReplayRegistry::default();
    let err_1 = verify_proof(&chain_1, &proof_1, &request, &mut registry_1).unwrap_err();
    assert_error_signature(&err_1, ERR_TAMPER, AttackClass::ReceiptTampering);

    // 2) mutate middle receipt field
    let mut chain_2 = sample_chain("chain-A");
    chain_2.receipts[2].actor_identity = "rogue-actor".to_string();
    let proof_2 = mint_proof(
        &sample_chain("chain-A"),
        "proof-tamper-2",
        7,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    let mut registry_2 = ReplayRegistry::default();
    let err_2 = verify_proof(&chain_2, &proof_2, &request, &mut registry_2).unwrap_err();
    assert_error_signature(&err_2, ERR_TAMPER, AttackClass::ReceiptTampering);

    // 3) mutate last receipt in window
    let mut chain_3 = sample_chain("chain-A");
    chain_3.receipts[3].payload = "tampered-last".to_string();
    let proof_3 = mint_proof(
        &sample_chain("chain-A"),
        "proof-tamper-3",
        7,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    let mut registry_3 = ReplayRegistry::default();
    let err_3 = verify_proof(&chain_3, &proof_3, &request, &mut registry_3).unwrap_err();
    assert_error_signature(&err_3, ERR_TAMPER, AttackClass::ReceiptTampering);

    // 4) truncate chain (window out of bounds)
    let mut chain_4 = sample_chain("chain-A");
    chain_4.receipts.truncate(3);
    let proof_4 = mint_proof(
        &sample_chain("chain-A"),
        "proof-tamper-4",
        7,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    let mut registry_4 = ReplayRegistry::default();
    let err_4 = verify_proof(&chain_4, &proof_4, &request, &mut registry_4).unwrap_err();
    assert_error_signature(&err_4, ERR_TAMPER, AttackClass::ReceiptTampering);

    // 5) insert rogue receipt inside window
    let mut chain_5 = sample_chain("chain-A");
    chain_5.receipts.insert(
        2,
        Receipt {
            receipt_id: "rogue-receipt".to_string(),
            actor_identity: "rogue".to_string(),
            payload: "injected".to_string(),
            sequence: 2,
        },
    );
    let proof_5 = mint_proof(
        &sample_chain("chain-A"),
        "proof-tamper-5",
        7,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    let mut registry_5 = ReplayRegistry::default();
    let err_5 = verify_proof(&chain_5, &proof_5, &request, &mut registry_5).unwrap_err();
    assert_error_signature(&err_5, ERR_TAMPER, AttackClass::ReceiptTampering);
}

#[test]
fn proof_replay_variations_fail_closed() {
    let chain_a = sample_chain("chain-A");
    let chain_b = sample_chain("chain-B");
    let mut registry = ReplayRegistry::default();

    // baseline valid verification to register proof binding
    let base_request = base_request("chain-A", "trace-replay-base");
    let replayed_proof = mint_proof(
        &chain_a,
        "proof-replay-1",
        9,
        base_request.expected_window_start,
        base_request.expected_window_end,
        &base_request.active_policy_hash,
    );
    verify_proof(&chain_a, &replayed_proof, &base_request, &mut registry).unwrap();

    // 1) replay same proof for different window
    let mut different_window = base_request.clone();
    different_window.trace_id = "trace-replay-window".to_string();
    different_window.expected_window_start = 0;
    different_window.expected_window_end = 2;
    let err_1 =
        verify_proof(&chain_a, &replayed_proof, &different_window, &mut registry).unwrap_err();
    assert_error_signature(&err_1, ERR_REPLAY, AttackClass::ProofReplay);

    // 2) replay same proof under different active policy binding
    let mut different_policy = base_request.clone();
    different_policy.trace_id = "trace-replay-policy".to_string();
    different_policy.active_policy_hash =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let err_2 =
        verify_proof(&chain_a, &replayed_proof, &different_policy, &mut registry).unwrap_err();
    assert_error_signature(&err_2, ERR_REPLAY, AttackClass::ProofReplay);

    // 3) replay same proof on different chain
    let mut different_chain = base_request.clone();
    different_chain.trace_id = "trace-replay-chain".to_string();
    different_chain.expected_chain_id = "chain-B".to_string();
    let err_3 =
        verify_proof(&chain_b, &replayed_proof, &different_chain, &mut registry).unwrap_err();
    assert_error_signature(&err_3, ERR_REPLAY, AttackClass::ProofReplay);
}

#[test]
fn stale_policy_variations_fail_closed() {
    let chain = sample_chain("chain-A");
    let request = base_request("chain-A", "trace-stale");

    let stale_hashes = [
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ];

    for (idx, stale_hash) in stale_hashes.iter().enumerate() {
        let proof = mint_proof(
            &chain,
            &format!("proof-stale-{idx}"),
            11,
            request.expected_window_start,
            request.expected_window_end,
            stale_hash,
        );
        let mut registry = ReplayRegistry::default();
        let err = verify_proof(
            &chain,
            &proof,
            &VerificationRequest {
                trace_id: format!("trace-stale-{idx}"),
                ..request.clone()
            },
            &mut registry,
        )
        .unwrap_err();
        assert_error_signature(&err, ERR_STALE_POLICY, AttackClass::StalePolicy);
    }
}

#[test]
fn commitment_mismatch_variations_fail_closed() {
    let chain_a = sample_chain("chain-A");
    let chain_b = sample_chain("chain-B");
    let request = base_request("chain-A", "trace-commitment");

    // 1) commitment substituted from adjacent window
    let mut proof_1 = mint_proof(
        &chain_a,
        "proof-commitment-1",
        12,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    proof_1.commitment_hash = compute_commitment(&chain_a, 12, 0, 2).expect("alternate commitment");
    let mut registry_1 = ReplayRegistry::default();
    let err_1 = verify_proof(&chain_a, &proof_1, &request, &mut registry_1).unwrap_err();
    assert_error_signature(&err_1, ERR_COMMITMENT, AttackClass::CommitmentMismatch);

    // 2) commitment substituted from different chain
    let mut proof_2 = mint_proof(
        &chain_a,
        "proof-commitment-2",
        12,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    proof_2.commitment_hash = compute_commitment(
        &chain_b,
        12,
        request.expected_window_start,
        request.expected_window_end,
    )
    .expect("foreign chain commitment");
    let mut registry_2 = ReplayRegistry::default();
    let err_2 = verify_proof(&chain_a, &proof_2, &request, &mut registry_2).unwrap_err();
    assert_error_signature(&err_2, ERR_COMMITMENT, AttackClass::CommitmentMismatch);

    // 3) null commitment
    let mut proof_3 = mint_proof(
        &chain_a,
        "proof-commitment-3",
        12,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    proof_3.commitment_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let mut registry_3 = ReplayRegistry::default();
    let err_3 = verify_proof(&chain_a, &proof_3, &request, &mut registry_3).unwrap_err();
    assert_error_signature(&err_3, ERR_COMMITMENT, AttackClass::CommitmentMismatch);
}

#[test]
fn deterministic_error_signature_for_each_attack_class() {
    let chain = sample_chain("chain-A");
    let request = base_request("chain-A", "trace-determinism");

    // tamper determinism
    let mut tamper_signature: Option<(String, String)> = None;
    for _ in 0..100 {
        let mut tampered = chain.clone();
        tampered.receipts[1].payload = "tampered-repeat".to_string();
        let proof = mint_proof(
            &chain,
            "proof-det-tamper",
            15,
            request.expected_window_start,
            request.expected_window_end,
            &request.active_policy_hash,
        );
        let mut registry = ReplayRegistry::default();
        let err = verify_proof(&tampered, &proof, &request, &mut registry).unwrap_err();
        let sig = (err.code.clone(), err.remediation_hint.clone());
        match &tamper_signature {
            Some(expected) => assert_eq!(&sig, expected),
            None => tamper_signature = Some(sig),
        }
    }

    // replay determinism
    let mut replay_signature: Option<(String, String)> = None;
    for _ in 0..100 {
        let proof = mint_proof(
            &chain,
            "proof-det-replay",
            15,
            request.expected_window_start,
            request.expected_window_end,
            &request.active_policy_hash,
        );
        let mut registry = ReplayRegistry::default();
        verify_proof(&chain, &proof, &request, &mut registry).unwrap();
        let mut replay_request = request.clone();
        replay_request.expected_window_start = 0;
        replay_request.expected_window_end = 2;
        let err = verify_proof(&chain, &proof, &replay_request, &mut registry).unwrap_err();
        let sig = (err.code.clone(), err.remediation_hint.clone());
        match &replay_signature {
            Some(expected) => assert_eq!(&sig, expected),
            None => replay_signature = Some(sig),
        }
    }

    // stale policy determinism
    let mut stale_signature: Option<(String, String)> = None;
    for idx in 0..100 {
        let proof = mint_proof(
            &chain,
            &format!("proof-det-stale-{idx}"),
            15,
            request.expected_window_start,
            request.expected_window_end,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let mut registry = ReplayRegistry::default();
        let err = verify_proof(&chain, &proof, &request, &mut registry).unwrap_err();
        let sig = (err.code.clone(), err.remediation_hint.clone());
        match &stale_signature {
            Some(expected) => assert_eq!(&sig, expected),
            None => stale_signature = Some(sig),
        }
    }

    // commitment mismatch determinism
    let mut commitment_signature: Option<(String, String)> = None;
    for _ in 0..100 {
        let mut proof = mint_proof(
            &chain,
            "proof-det-commitment",
            15,
            request.expected_window_start,
            request.expected_window_end,
            &request.active_policy_hash,
        );
        proof.commitment_hash =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let mut registry = ReplayRegistry::default();
        let err = verify_proof(&chain, &proof, &request, &mut registry).unwrap_err();
        let sig = (err.code.clone(), err.remediation_hint.clone());
        match &commitment_signature {
            Some(expected) => assert_eq!(&sig, expected),
            None => commitment_signature = Some(sig),
        }
    }
}

#[test]
fn no_false_positives_for_legitimate_inputs() {
    let chain = sample_chain("chain-A");
    let policy =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

    let windows = [
        (0_usize, 2_usize, 21_u64),
        (1_usize, 3_usize, 22_u64),
        (3_usize, 5_usize, 23_u64),
    ];

    for (idx, (start, end, checkpoint_id)) in windows.into_iter().enumerate() {
        let request = VerificationRequest {
            expected_chain_id: chain.chain_id.clone(),
            expected_window_start: start,
            expected_window_end: end,
            active_policy_hash: policy.clone(),
            trace_id: format!("trace-legit-{idx}"),
        };
        let proof = mint_proof(
            &chain,
            &format!("proof-legit-window-{idx}"),
            checkpoint_id,
            start,
            end,
            &policy,
        );
        let mut registry = ReplayRegistry::default();
        assert!(verify_proof(&chain, &proof, &request, &mut registry).is_ok());
    }
}

#[test]
fn invalid_window_bounds_returns_tamper_with_expect_err() {
    let chain = sample_chain("chain-A");
    let err =
        compute_window_fingerprint(&chain, 4, 1).expect_err("invalid bounds must fail closed");
    assert_error_signature(&err, ERR_TAMPER, AttackClass::ReceiptTampering);
}

#[test]
fn out_of_bounds_window_returns_tamper_error() {
    let chain = sample_chain("chain-A");
    let err =
        compute_commitment(&chain, 21, 2, 9).expect_err("out-of-bounds window must fail closed");
    assert_error_signature(&err, ERR_TAMPER, AttackClass::ReceiptTampering);
}

#[test]
fn proof_reuse_with_identical_binding_is_allowed() {
    let chain = sample_chain("chain-A");
    let request = base_request("chain-A", "trace-reuse-same-binding");
    let proof = mint_proof(
        &chain,
        "proof-reuse-same-binding",
        17,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    let mut registry = ReplayRegistry::default();
    assert!(verify_proof(&chain, &proof, &request, &mut registry).is_ok());
    assert!(verify_proof(&chain, &proof, &request, &mut registry).is_ok());
}

#[test]
fn failure_events_preserve_trace_id_and_classification() {
    let request = base_request("chain-A", "trace-event-shape");
    let mut chain = sample_chain("chain-A");
    chain.receipts[1].payload = "tampered-event-shape".to_string();
    let proof = mint_proof(
        &sample_chain("chain-A"),
        "proof-event-shape",
        18,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    let mut registry = ReplayRegistry::default();
    let err = verify_proof(&chain, &proof, &request, &mut registry)
        .expect_err("tamper variant must fail");
    assert_error_signature(&err, ERR_TAMPER, AttackClass::ReceiptTampering);
    assert!(
        err.events
            .iter()
            .all(|event| event.trace_id == request.trace_id)
    );
    assert!(
        err.events
            .iter()
            .any(|event| event.detail.contains("receipt_tampering"))
    );
}

#[test]
fn remediation_hints_are_distinct_per_attack_class() {
    let chain = sample_chain("chain-A");
    let request = base_request("chain-A", "trace-remediation-unique");

    let mut tampered = chain.clone();
    tampered.receipts[1].payload = "tampered-hint".to_string();
    let tamper_err = verify_proof(
        &tampered,
        &mint_proof(
            &chain,
            "proof-remediation-tamper",
            19,
            request.expected_window_start,
            request.expected_window_end,
            &request.active_policy_hash,
        ),
        &request,
        &mut ReplayRegistry::default(),
    )
    .expect_err("tamper error required");

    let replay_proof = mint_proof(
        &chain,
        "proof-remediation-replay",
        19,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    let mut replay_registry = ReplayRegistry::default();
    verify_proof(&chain, &replay_proof, &request, &mut replay_registry)
        .expect("baseline binding registration must pass");
    let mut replay_request = request.clone();
    replay_request.expected_window_start = 0;
    replay_request.expected_window_end = 2;
    let replay_err = verify_proof(&chain, &replay_proof, &replay_request, &mut replay_registry)
        .expect_err("replay mismatch required");

    let stale_err = verify_proof(
        &chain,
        &mint_proof(
            &chain,
            "proof-remediation-stale",
            19,
            request.expected_window_start,
            request.expected_window_end,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        &request,
        &mut ReplayRegistry::default(),
    )
    .expect_err("stale policy error required");

    let mut commitment_proof = mint_proof(
        &chain,
        "proof-remediation-commitment",
        19,
        request.expected_window_start,
        request.expected_window_end,
        &request.active_policy_hash,
    );
    commitment_proof.commitment_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let commitment_err = verify_proof(
        &chain,
        &commitment_proof,
        &request,
        &mut ReplayRegistry::default(),
    )
    .expect_err("commitment mismatch required");

    let hints = [
        tamper_err.remediation_hint,
        replay_err.remediation_hint,
        stale_err.remediation_hint,
        commitment_err.remediation_hint,
    ];
    let unique: BTreeSet<&str> = hints.iter().map(String::as_str).collect();
    assert_eq!(unique.len(), hints.len());
}
