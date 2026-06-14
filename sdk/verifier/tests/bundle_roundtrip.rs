use std::collections::BTreeMap;
use std::path::PathBuf;

use frankenengine_verifier_sdk::bundle::{
    BundleArtifact, BundleChunk, BundleError, BundleHeader, BundleSignature,
    CAPABILITY_PROOF_SCHEMA_VERSION, CAPABILITY_RECEIPT_SCHEMA_VERSION, CapabilityPolicyProfile,
    CapabilityPostcondition, CapabilityProof, CapabilityReceipt, CapabilityRevocationFreshness,
    CapabilityScope, EFFECT_RECEIPT_EVENT_TYPE, EFFECT_RECEIPT_SCHEMA_VERSION, EffectKind,
    EffectPolicyOutcome, EffectReceipt, EffectReceiptChainEntry, FN_VSDK_CAPABILITY_PROOF_VERIFIED,
    FN_VSDK_CAPABILITY_RECEIPT_VERIFIED, FN_VSDK_CAPABILITY_SCHEMA_PASS,
    FN_VSDK_CAPABILITY_SCHEMA_START, FN_VSDK_EFFECT_CHAIN_PASS, FN_VSDK_EFFECT_CHAIN_START,
    FN_VSDK_EFFECT_VERIFIED, FN_VSDK_NON_EXFILTRATION_EFFECT, FN_VSDK_NON_EXFILTRATION_PASS,
    FN_VSDK_NON_EXFILTRATION_START, FlowPolicyVerdict, NonExfiltrationClaim,
    REPLAY_BUNDLE_HASH_ALGORITHM, REPLAY_BUNDLE_SCHEMA_VERSION, ReplayBundle, TimelineEvent,
    capability_proof_canonical_bytes, capability_proof_hash, capability_receipt_canonical_bytes,
    capability_receipt_hash, hash, render_effect_chain_transcript, seal, seal_capability_proof,
    seal_capability_receipt, serialize, verify, verify_capability_receipt_schema,
    verify_effect_chain, verify_non_exfiltration_claim,
};
use frankenengine_verifier_sdk::counterfactual::{
    CounterfactualCapabilityDecision, CounterfactualCapabilityError,
    CounterfactualCapabilityRequest, validate_counterfactual_capability_decision,
};
use frankenengine_verifier_sdk::{SDK_VERSION, VerifierSdk, VerifierSdkError};
use serde_json::json;
use sha2::{Digest, Sha256};

const EFFECT_CHAIN_GENESIS: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const EFFECT_PRE_BYTES: &[u8] = b"module.exports = { answer: 41 };";
const EFFECT_ARGS_BYTES: &[u8] = br#"{"path":"/app/index.js","flags":"r"}"#;
const EFFECT_RESULT_BYTES: &[u8] = b"export const answer = 42;";
const EFFECT_POST_BYTES: &[u8] = b"module.exports = { answer: 42 };";
const DENIED_PRE_BYTES: &[u8] = b"connect 169.254.169.254:80";
const DENIED_ARGS_BYTES: &[u8] = br#"{"host":"metadata.internal","port":80}"#;
const EFFECT_CHAIN_TRANSCRIPT_GOLDEN: &str =
    include_str!("fixtures/effect_chain_transcript.golden");
const CAPABILITY_PROOF_CANONICAL_GOLDEN: &str = concat!(
    "{\"actor\":\"agent://builder\",\"audience\":\"verifier://capability-test\",\"epoch\":42,",
    "\"evidence_refs\":[\"effect-chain:head:001\",\"revocation:fresh:001\"],",
    "\"expected_postconditions\":[",
    "{\"expected_hash\":\"sha256:8e1992fd9b4c6464f3a1cd4d40f6150c8f1566e404ec70a16b2dd1529bb3ca99\",\"field\":\"http_status\"},",
    "{\"expected_hash\":\"sha256:c082bb9237a57be2c405295f5f3e984e6e28f3a4ca84d2becabe1c331a31fba1\",\"field\":\"response_body\"}],",
    "\"expires_at_millis\":1775003600000,\"issued_at_millis\":1775000000000,",
    "\"policy_profile\":\"strict\",\"proof_id\":\"cap-proof-001\",",
    "\"revocation_freshness\":{\"checked_at_millis\":1775000000000,\"evidence_ref\":\"revocation:fresh:001\",\"status\":\"fresh\"},",
    "\"schema_version\":\"capability-proof-v1\",\"scopes\":[",
    "{\"access\":\"read\",\"capability\":\"fs_read\",\"resource\":\"cas://workspace/app/index.js\"},",
    "{\"access\":\"egress\",\"capability\":\"http_request\",\"resource\":\"https://api.example.test/v1/data\"}],",
    "\"side_effect_kind\":\"http_request\"}"
);
const CAPABILITY_RECEIPT_CANONICAL_GOLDEN: &str = concat!(
    "{\"actor\":\"agent://builder\",\"audience\":\"verifier://capability-test\",",
    "\"effect_receipt_chain_hash\":\"sha256:21c645997bfda31f5752ca59026f067d63d575a0909807393f9329e447f1053a\",",
    "\"epoch\":42,\"exercised_scope\":{\"access\":\"egress\",\"capability\":\"http_request\",",
    "\"resource\":\"https://api.example.test/v1/data\"},\"observed_postconditions\":[",
    "{\"expected_hash\":\"sha256:8e1992fd9b4c6464f3a1cd4d40f6150c8f1566e404ec70a16b2dd1529bb3ca99\",\"field\":\"http_status\"},",
    "{\"expected_hash\":\"sha256:c082bb9237a57be2c405295f5f3e984e6e28f3a4ca84d2becabe1c331a31fba1\",\"field\":\"response_body\"}],",
    "\"policy_profile\":\"strict\",",
    "\"proof_hash\":\"sha256:d0563896cedd3f6593a94d0e564b564dfe6d0c8df28de2f1cde0ca0597d7e6ed\",",
    "\"proof_id\":\"cap-proof-001\",\"receipt_id\":\"cap-receipt-001\",",
    "\"recorded_at_millis\":1775000001000,\"schema_version\":\"capability-receipt-v1\",",
    "\"side_effect_kind\":\"http_request\"}"
);
const CAPABILITY_PROOF_HASH_GOLDEN: &str =
    "sha256:d0563896cedd3f6593a94d0e564b564dfe6d0c8df28de2f1cde0ca0597d7e6ed";
const CAPABILITY_RECEIPT_HASH_GOLDEN: &str =
    "sha256:c1fbabac7f4542e057a8299e0b5a1309e1cec466aa1e665fd39d95506824445e";

#[test]
fn replay_bundle_serialization_and_hash_are_byte_stable() {
    let bundle = canonical_replay_bundle();

    let first_bytes = serialize(&bundle).expect("fixture should serialize");
    let second_bytes = serialize(&bundle).expect("fixture should serialize repeatedly");
    assert_eq!(first_bytes, second_bytes);

    let first_hash = hash(&first_bytes);
    let second_hash = hash(&second_bytes);
    assert_eq!(first_hash, second_hash);

    let verified = verify(&first_bytes).expect("fixture should verify");
    let verified_bytes = serialize(&verified).expect("verified bundle should reserialize");
    assert_eq!(first_bytes, verified_bytes);
    assert_eq!(bundle, verified);
}

#[test]
fn replay_bundle_verify_rejects_single_byte_mutation() {
    let bundle = canonical_replay_bundle();
    let original_bytes = serialize(&bundle).expect("fixture should serialize");
    let original_hash = hash(&original_bytes);

    let mut tampered_bytes = original_bytes.clone();
    let mutation_offset = find_subsequence(&tampered_bytes, b"quarantine")
        .expect("canonical fixture should contain the decision string");
    tampered_bytes[mutation_offset] = b'Q';

    assert_ne!(original_hash, hash(&tampered_bytes));
    assert!(verify(&tampered_bytes).is_err());
    assert_eq!(
        verify(&original_bytes).expect("original fixture should remain valid"),
        bundle
    );
}

#[test]
fn effect_chain_bundle_verifies_cas_backed_receipts_and_transcript() {
    let bundle = effect_chain_replay_bundle();
    let bundle_bytes = serialize(&bundle).expect("effect-chain fixture should serialize");

    let report = verify_effect_chain(&bundle_bytes).expect("effect chain should verify offline");

    assert_eq!(report.bundle_id, "effect-chain-bundle-001");
    assert_eq!(report.verifier_identity, "verifier://effect-chain-test");
    assert_eq!(report.effect_count, 2);
    assert_eq!(
        report.event_codes,
        vec![
            FN_VSDK_EFFECT_CHAIN_START.to_string(),
            FN_VSDK_EFFECT_VERIFIED.to_string(),
            FN_VSDK_EFFECT_CHAIN_PASS.to_string(),
        ]
    );

    let first = &report.verified_effects[0];
    assert_eq!(first.effect_kind, "fs_read");
    assert_eq!(first.outcome, "allowed");
    assert_eq!(first.capability_ref.as_deref(), Some("cap-fs-read-01"));
    assert_eq!(
        first.result_hash.as_deref(),
        Some(cas_hash(EFFECT_RESULT_BYTES).as_str())
    );
    assert_eq!(first.flow_policy_verdict, "declassified");
    assert_eq!(
        first.declassification_ref.as_deref(),
        Some("ifl-declass:network-egress-allow-001")
    );
    assert_eq!(
        first.label_set_commitment,
        lineage_hash("labels:operator_secret")
    );
    assert!(
        first
            .cas_bindings
            .iter()
            .any(|binding| binding.field == "result_hash"
                && binding.hash == cas_hash(EFFECT_RESULT_BYTES)
                && binding.artifact_path == "cas/result.txt"),
        "result_hash must be re-derived from bundled CAS bytes"
    );

    let second = &report.verified_effects[1];
    assert_eq!(second.effect_kind, "http_request");
    assert_eq!(second.outcome, "denied");
    assert_eq!(second.result_hash, None);
    assert_eq!(second.flow_policy_verdict, "blocked");
    assert!(second.output_lineage_hash.is_none());
    assert!(second.declassification_ref.is_none());
    assert_eq!(
        second.cas_bindings.len(),
        2,
        "denied effects bind only pre-state and args CAS bytes"
    );

    let transcript = render_effect_chain_transcript(&report);
    assert_eq!(transcript, EFFECT_CHAIN_TRANSCRIPT_GOLDEN);
}

#[test]
fn effect_chain_sdk_proves_selective_disclosure_non_exfiltration_claims() {
    let bundle = effect_chain_replay_bundle();
    let bundle_bytes = serialize(&bundle).expect("effect-chain fixture should serialize");
    let claim = operator_secret_external_sink_claim(Vec::new());

    let proof = verify_non_exfiltration_claim(&bundle_bytes, &claim)
        .expect("blocked external sink should prove non-exfiltration");

    assert_eq!(proof.bundle_id, "effect-chain-bundle-001");
    assert_eq!(proof.verifier_identity, "verifier://effect-chain-test");
    assert_eq!(proof.effect_count, 2);
    assert!(proof.claim_hash.starts_with("sha256:"));
    assert_eq!(
        proof.event_codes,
        vec![
            FN_VSDK_NON_EXFILTRATION_START.to_string(),
            FN_VSDK_NON_EXFILTRATION_EFFECT.to_string(),
            FN_VSDK_NON_EXFILTRATION_PASS.to_string(),
        ]
    );
    assert_eq!(proof.claim.forbidden_label_set_commitments.len(), 1);
    assert_eq!(proof.examined_effects.len(), 2);
    let first_effect = proof
        .examined_effects
        .first()
        .expect("first proof effect should be present");
    let second_effect = proof
        .examined_effects
        .get(1)
        .expect("second proof effect should be present");
    assert_eq!(
        first_effect.disclosed_label_set_commitment.as_deref(),
        Some(lineage_hash("labels:operator_secret").as_str())
    );
    assert_eq!(first_effect.proof_outcome, "not_external_sink");
    assert_eq!(second_effect.effect_kind, "http_request");
    assert_eq!(
        second_effect.disclosed_label_set_commitment.as_deref(),
        Some(lineage_hash("labels:operator_secret").as_str())
    );
    assert_eq!(second_effect.proof_outcome, "blocked_before_sink");
    assert!(second_effect.declassification_ref.is_none());

    let sdk = VerifierSdk::new("verifier://effect-chain-test");
    let facade_proof = sdk
        .verify_non_exfiltration_claim_bundle(&bundle_bytes, &claim)
        .expect("facade should verify the same non-exfiltration claim");
    assert_eq!(proof, facade_proof);
}

#[test]
fn non_exfiltration_claim_rejects_unauthorized_external_declassification() {
    let mut bundle = effect_chain_replay_bundle();
    let mut egress_receipt = timeline_effect_entry(&bundle, 1).receipt;
    egress_receipt.policy_outcome = EffectPolicyOutcome::Allowed {
        capability_ref: "cap-http-egress-01".to_string(),
    };
    egress_receipt.result_hash = Some(cas_hash(EFFECT_RESULT_BYTES));
    egress_receipt.post_state_hash = Some(cas_hash(EFFECT_POST_BYTES));
    egress_receipt.output_lineage_hash = Some(lineage_hash("operator_secret:egress"));
    egress_receipt.declassification_ref =
        Some("ifl-declass:http-egress-operator-secret".to_string());
    egress_receipt.flow_policy_verdict = FlowPolicyVerdict::Declassified;
    replace_effect_receipt_and_reseal_chain(&mut bundle, 1, egress_receipt);
    let bundle_bytes = serialize(&bundle).expect("effect-chain fixture should serialize");

    let err = verify_non_exfiltration_claim(
        &bundle_bytes,
        &operator_secret_external_sink_claim(Vec::new()),
    )
    .expect_err("undisclosed external declassification must fail closed");
    assert!(matches!(
        err,
        BundleError::NonExfiltrationViolation {
            index: 1,
            ref effect_kind,
            ref label_set_commitment,
            ..
        } if effect_kind == "http_request"
            && label_set_commitment == &lineage_hash("labels:operator_secret")
    ));

    let proof = verify_non_exfiltration_claim(
        &bundle_bytes,
        &operator_secret_external_sink_claim(vec![
            "ifl-declass:http-egress-operator-secret".to_string(),
        ]),
    )
    .expect("disclosed scoped declassification should satisfy the claim");
    let egress_proof = proof
        .examined_effects
        .get(1)
        .expect("egress proof effect should be present");
    assert_eq!(
        egress_proof.declassification_ref.as_deref(),
        Some("ifl-declass:http-egress-operator-secret")
    );
    assert_eq!(egress_proof.proof_outcome, "authorized_declassification");
}

#[test]
fn capability_proof_and_receipt_schemas_are_canonical_and_bound() {
    let proof = capability_proof_fixture();
    let receipt = capability_receipt_fixture(&proof);

    assert_eq!(
        capability_proof_canonical_bytes(&proof).expect("proof payload should encode canonically"),
        CAPABILITY_PROOF_CANONICAL_GOLDEN.as_bytes()
    );
    assert_eq!(
        capability_receipt_canonical_bytes(&receipt)
            .expect("receipt payload should encode canonically"),
        CAPABILITY_RECEIPT_CANONICAL_GOLDEN.as_bytes()
    );
    assert_eq!(
        capability_proof_hash(&proof).expect("proof hash should recompute"),
        CAPABILITY_PROOF_HASH_GOLDEN
    );
    assert_eq!(proof.proof_hash, CAPABILITY_PROOF_HASH_GOLDEN);
    assert_eq!(
        capability_receipt_hash(&receipt).expect("receipt hash should recompute"),
        CAPABILITY_RECEIPT_HASH_GOLDEN
    );
    assert_eq!(receipt.receipt_hash, CAPABILITY_RECEIPT_HASH_GOLDEN);

    let verification = verify_capability_receipt_schema(&proof, &receipt)
        .expect("receipt should be bound to the proof");
    assert_eq!(verification.proof_id, "cap-proof-001");
    assert_eq!(verification.receipt_id, "cap-receipt-001");
    assert_eq!(verification.actor, "agent://builder");
    assert_eq!(verification.audience, "verifier://capability-test");
    assert_eq!(verification.policy_profile, "strict");
    assert_eq!(verification.epoch, 42);
    assert_eq!(verification.side_effect_kind, "http_request");
    assert_eq!(verification.postcondition_count, 2);
    assert_eq!(verification.evidence_ref_count, 2);
    assert_eq!(
        verification.event_codes,
        vec![
            FN_VSDK_CAPABILITY_SCHEMA_START.to_string(),
            FN_VSDK_CAPABILITY_PROOF_VERIFIED.to_string(),
            FN_VSDK_CAPABILITY_RECEIPT_VERIFIED.to_string(),
            FN_VSDK_CAPABILITY_SCHEMA_PASS.to_string(),
        ]
    );
}

#[test]
fn capability_receipt_schema_fails_closed_on_stale_or_tampered_bindings() {
    let proof = capability_proof_fixture();
    let receipt = capability_receipt_fixture(&proof);

    let mut stale_proof = proof.clone();
    stale_proof.revocation_freshness = CapabilityRevocationFreshness::Stale {
        last_checked_at_millis: 1_774_999_000_000,
        evidence_ref: "revocation:stale:001".to_string(),
    };
    seal_capability_proof(&mut stale_proof).expect("stale proof should still self-hash");
    let err = verify_capability_receipt_schema(&stale_proof, &receipt)
        .expect_err("stale revocation evidence must fail closed");
    assert!(matches!(
        err,
        BundleError::InvalidCapabilityField {
            field: "revocation_freshness",
            ..
        }
    ));

    let mut wrong_actor = receipt.clone();
    wrong_actor.actor = "agent://other".to_string();
    seal_capability_receipt(&mut wrong_actor).expect("tampered receipt should self-hash");
    let err = verify_capability_receipt_schema(&proof, &wrong_actor)
        .expect_err("actor mismatch must fail closed");
    assert!(matches!(
        err,
        BundleError::CapabilityReceiptMismatch { field: "actor", .. }
    ));

    let mut wrong_postcondition = receipt;
    wrong_postcondition
        .observed_postconditions
        .get_mut(1)
        .expect("fixture should include response_body postcondition")
        .expected_hash = lineage_hash("post:response_body:tampered");
    seal_capability_receipt(&mut wrong_postcondition)
        .expect("tampered postcondition receipt should self-hash");
    let err = verify_capability_receipt_schema(&proof, &wrong_postcondition)
        .expect_err("postcondition mismatch must fail closed");
    assert!(matches!(
        err,
        BundleError::CapabilityReceiptMismatch {
            field: "observed_postconditions",
            ..
        }
    ));
}

#[test]
fn verifier_sdk_checks_capability_proofs_and_counterfactual_decisions_offline() {
    let proof = capability_proof_fixture();
    let receipt = capability_receipt_fixture(&proof);
    let sdk = VerifierSdk::new("verifier://capability-test");

    let proof_hash = sdk
        .verify_capability_proof(&proof)
        .expect("facade should verify capability proof schema and audience");
    assert_eq!(proof_hash, CAPABILITY_PROOF_HASH_GOLDEN);

    let receipt_verification = sdk
        .verify_capability_receipt(&proof, &receipt)
        .expect("facade should verify capability receipt binding");
    assert_eq!(receipt_verification.receipt_id, "cap-receipt-001");
    assert_eq!(
        receipt_verification.scope, receipt.exercised_scope,
        "receipt verification must disclose the exercised capability scope"
    );

    let request = capability_counterfactual_request(&proof);
    let allowed = sdk
        .validate_counterfactual_capability_decision(
            &proof,
            &request,
            CounterfactualCapabilityDecision::Allow,
        )
        .expect("matching counterfactual allow decision should verify offline");
    assert!(allowed.allowed);
    assert_eq!(allowed.decision, "allow");
    assert_eq!(allowed.expected_decision, "allow");
    assert_eq!(
        allowed.reason,
        "proof and request bindings permit capability"
    );
    assert_eq!(allowed.scope, receipt.exercised_scope);

    let mut out_of_scope_request = request.clone();
    out_of_scope_request.requested_scope.resource =
        "https://api.example.test/v1/private".to_string();
    let denied = validate_counterfactual_capability_decision(
        &proof,
        &out_of_scope_request,
        CounterfactualCapabilityDecision::Deny,
    )
    .expect("counterfactual deny should verify when the requested scope is not in the proof");
    assert!(!denied.allowed);
    assert_eq!(denied.decision, "deny");
    assert_eq!(denied.expected_decision, "deny");
    assert_eq!(denied.reason, "requested scope is outside capability proof");

    let err = sdk
        .validate_counterfactual_capability_decision(
            &proof,
            &out_of_scope_request,
            CounterfactualCapabilityDecision::Allow,
        )
        .expect_err("counterfactual allow must fail closed for an out-of-scope request");
    assert!(matches!(
        err,
        VerifierSdkError::CounterfactualCapability(
            CounterfactualCapabilityError::DecisionMismatch {
                ref expected,
                ref actual,
                ref reason,
            },
        ) if expected == "deny"
            && actual == "allow"
            && reason == "requested scope is outside capability proof"
    ));

    let foreign_sdk = VerifierSdk::new("verifier://other");
    let err = foreign_sdk
        .verify_capability_proof(&proof)
        .expect_err("foreign verifier audience must be rejected");
    assert!(matches!(
        err,
        VerifierSdkError::SessionVerifierMismatch {
            ref expected,
            ref actual,
        } if expected == "verifier://other" && actual == "verifier://capability-test"
    ));
}

#[test]
fn third_party_style_fnbundle_reader_uses_facade_and_prints_verified_effects() {
    let bundle = effect_chain_replay_bundle();
    let bundle_bytes = serialize(&bundle).expect("effect-chain fixture should serialize");
    let path = effect_chain_fnbundle_path();
    std::fs::write(&path, &bundle_bytes).expect(".fnbundle fixture should be written");

    let read_bytes = std::fs::read(&path).expect("third-party reader should read .fnbundle bytes");
    let sdk = VerifierSdk::new("verifier://effect-chain-test");
    let report = sdk
        .verify_effect_chain_bundle(&read_bytes)
        .expect("facade should verify effect-chain bundle");
    let transcript = render_effect_chain_transcript(&report);

    assert!(transcript.starts_with(FN_VSDK_EFFECT_CHAIN_START));
    assert!(transcript.contains(FN_VSDK_EFFECT_VERIFIED));
    assert!(transcript.contains(FN_VSDK_EFFECT_CHAIN_PASS));
    assert!(transcript.contains("kind=fs_read outcome=allowed"));
    assert!(transcript.contains("kind=http_request outcome=denied"));
    assert_eq!(transcript, EFFECT_CHAIN_TRANSCRIPT_GOLDEN);
}

#[test]
fn effect_chain_verification_rejects_tampered_receipts_bytes_order_and_versions() {
    let mut receipt_tampered = effect_chain_replay_bundle();
    let mut first_entry = timeline_effect_entry(&receipt_tampered, 0);
    first_entry.receipt.trace_id = "forged-trace".to_string();
    set_timeline_effect_entry(&mut receipt_tampered, 0, first_entry);
    let err = verify_effect_chain_bytes(&receipt_tampered)
        .expect_err("receipt mutation must break the recomputed receipt_hash");
    assert!(matches!(
        err,
        BundleError::EffectChainIntegrity { index: 0, ref detail }
            if detail.contains("receipt_hash")
    ));

    let mut bytes_tampered = effect_chain_replay_bundle();
    replace_artifact_bytes(&mut bytes_tampered, "cas/result.txt", b"evil output");
    let err = verify_effect_chain_bytes(&bytes_tampered)
        .expect_err("CAS byte mutation must break the receipt hash binding");
    assert!(matches!(
        err,
        BundleError::EffectReceiptMissingCasBytes { index: 0, field: "result_hash", ref hash }
            if hash == &cas_hash(EFFECT_RESULT_BYTES)
    ));

    let mut order_tampered = effect_chain_replay_bundle();
    let first_payload = order_tampered.timeline[0].payload.clone();
    order_tampered.timeline[0].payload = order_tampered.timeline[1].payload.clone();
    order_tampered.timeline[1].payload = first_payload;
    reseal_bundle(&mut order_tampered);
    let err = verify_effect_chain_bytes(&order_tampered)
        .expect_err("effect entry reordering must break chain position checks");
    assert!(matches!(
        err,
        BundleError::EffectChainIntegrity { index: 0, ref detail }
            if detail.contains("effect event position")
    ));

    let mut unsupported_bundle_schema = effect_chain_replay_bundle();
    unsupported_bundle_schema.schema_version = "vsdk-replay-bundle-v9.0".to_string();
    reseal_bundle(&mut unsupported_bundle_schema);
    let err = verify_effect_chain_bytes(&unsupported_bundle_schema)
        .expect_err("unknown bundle schema must fail before best-effort effect parsing");
    assert!(matches!(err, BundleError::UnsupportedSchema { .. }));

    let mut unsupported_sdk = effect_chain_replay_bundle();
    unsupported_sdk.sdk_version = "vsdk-v9.0".to_string();
    reseal_bundle(&mut unsupported_sdk);
    let err = verify_effect_chain_bytes(&unsupported_sdk)
        .expect_err("unknown SDK version must fail before best-effort effect parsing");
    assert!(matches!(err, BundleError::UnsupportedSdk { .. }));

    let mut unsupported_receipt_schema = effect_chain_replay_bundle();
    let mut first_entry = timeline_effect_entry(&unsupported_receipt_schema, 0);
    first_entry.receipt.schema_version = "effect-receipt-v9.0".to_string();
    set_timeline_effect_entry(&mut unsupported_receipt_schema, 0, first_entry);
    let err = verify_effect_chain_bytes(&unsupported_receipt_schema)
        .expect_err("unknown effect receipt schema must fail closed");
    assert!(matches!(
        err,
        BundleError::UnsupportedEffectReceiptSchema {
            index: 0,
            ref actual,
            ..
        } if actual == "effect-receipt-v9.0"
    ));

    let mut malformed_lineage = effect_chain_replay_bundle();
    let mut first_entry = timeline_effect_entry(&malformed_lineage, 0);
    first_entry.receipt.label_set_commitment = "sha256:ABC".to_string();
    set_timeline_effect_entry(&mut malformed_lineage, 0, first_entry);
    let err = verify_effect_chain_bytes(&malformed_lineage)
        .expect_err("malformed lineage commitments must fail closed");
    assert!(matches!(
        err,
        BundleError::MalformedEffectLineageHash {
            index: 0,
            field: "label_set_commitment",
            ..
        }
    ));
}

fn canonical_replay_bundle() -> ReplayBundle {
    let evidence_json = br#"{"schema_version":"incident-evidence-v1","incident_id":"inc-2026-04-20-cross-substrate","trace_id":"trace-cross-substrate-0042","detector":"lockstep-divergence","policy_version":"strict@2026-04-20","events":[{"event_id":"evt-0001","event_type":"external_signal","decision":"quarantine"},{"event_id":"evt-0002","event_type":"policy_eval","decision":"quarantine"},{"event_id":"evt-0003","event_type":"extension_result","decision":"release_denied"}]}"#;
    let substrate_matrix = br#"substrate,engine_version,decision,receipt
node,frankenengine-node-0.1.0,quarantine,sha256:36b7
extension-host,frankenengine-extension-host-0.1.0,quarantine,sha256:36b7
federated-peer,frankenengine-node-0.1.0,quarantine,sha256:36b7
"#;
    let transcript =
        br#"{"sequence":1,"substrate":"node","event":"external_signal","decision":"quarantine"}
{"sequence":2,"substrate":"extension-host","event":"policy_eval","decision":"quarantine"}
{"sequence":3,"substrate":"federated-peer","event":"extension_result","decision":"release_denied"}
"#;

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "evidence/inc-2026-04-20-cross-substrate.json".to_string(),
        artifact("application/json", evidence_json),
    );
    artifacts.insert(
        "matrices/cross-substrate.csv".to_string(),
        artifact("text/csv", substrate_matrix),
    );
    artifacts.insert(
        "transcripts/replay.ndjson".to_string(),
        artifact("application/x-ndjson", transcript),
    );
    let chunks = chunks_from_artifacts(&artifacts);

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "domain".to_string(),
        "conformance/sdk/extensions/federation".to_string(),
    );
    metadata.insert("matrix".to_string(), "cross-substrate".to_string());
    metadata.insert("runtime_profile".to_string(), "strict".to_string());

    let mut bundle = ReplayBundle {
        header: BundleHeader {
            hash_algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            payload_length_bytes: payload_length_bytes(&artifacts),
            chunk_count: chunks
                .len()
                .try_into()
                .expect("fixture chunk count should fit u32"),
        },
        schema_version: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
        sdk_version: SDK_VERSION.to_string(),
        bundle_id: "018f4c6e-69d5-7a52-9d4d-0f7ffab7c042".to_string(),
        incident_id: "inc-2026-04-20-cross-substrate".to_string(),
        created_at: "2026-04-20T14:05:00.000000Z".to_string(),
        policy_version: "strict@2026-04-20".to_string(),
        verifier_identity: "verifier://sdk-public-contract".to_string(),
        timeline: vec![
            TimelineEvent {
                sequence_number: 1,
                event_id: "evt-0001".to_string(),
                timestamp: "2026-04-20T14:05:00.000001Z".to_string(),
                event_type: "external_signal".to_string(),
                payload: json!({
                    "incident_id": "inc-2026-04-20-cross-substrate",
                    "signal": "cross_substrate_divergence",
                    "severity": "high"
                }),
                state_snapshot: json!({
                    "active_substrates": ["node", "extension-host", "federated-peer"],
                    "epoch": 42_u64,
                    "risk_gate": "strict"
                }),
                causal_parent: None,
                policy_version: "strict@2026-04-20".to_string(),
            },
            TimelineEvent {
                sequence_number: 2,
                event_id: "evt-0002".to_string(),
                timestamp: "2026-04-20T14:05:00.000450Z".to_string(),
                event_type: "policy_eval".to_string(),
                payload: json!({
                    "decision": "quarantine",
                    "rule_id": "policy.cross-substrate.lockstep",
                    "matched_receipts": 3_u64
                }),
                state_snapshot: json!({
                    "quarantine": true,
                    "release_window": "blocked"
                }),
                causal_parent: Some(1),
                policy_version: "strict@2026-04-20".to_string(),
            },
            TimelineEvent {
                sequence_number: 3,
                event_id: "evt-0003".to_string(),
                timestamp: "2026-04-20T14:05:00.000900Z".to_string(),
                event_type: "extension_result".to_string(),
                payload: json!({
                    "extension": "cross-substrate-verifier",
                    "decision": "release_denied",
                    "reason": "federated peer receipt requires quarantine"
                }),
                state_snapshot: json!({
                    "quarantine": true,
                    "federation_votes": {
                        "agree": 3_u64,
                        "disagree": 0_u64
                    }
                }),
                causal_parent: Some(2),
                policy_version: "strict@2026-04-20".to_string(),
            },
        ],
        initial_state_snapshot: json!({
            "baseline_epoch": 41_u64,
            "policy": "strict",
            "substrates": {
                "node": "frankenengine-node-0.1.0",
                "extension-host": "frankenengine-extension-host-0.1.0",
                "federated-peer": "frankenengine-node-0.1.0"
            }
        }),
        evidence_refs: vec![
            "evidence/inc-2026-04-20-cross-substrate.json".to_string(),
            "matrices/cross-substrate.csv".to_string(),
            "transcripts/replay.ndjson".to_string(),
        ],
        artifacts,
        chunks,
        metadata,
        integrity_hash: String::new(),
        signature: BundleSignature {
            algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            signature_hex: String::new(),
        },
    };
    seal(&mut bundle).expect("fixture should seal");
    bundle
}

fn effect_chain_replay_bundle() -> ReplayBundle {
    let pre_hash = cas_hash(EFFECT_PRE_BYTES);
    let args_hash = cas_hash(EFFECT_ARGS_BYTES);
    let result_hash = cas_hash(EFFECT_RESULT_BYTES);
    let post_hash = cas_hash(EFFECT_POST_BYTES);
    let denied_pre_hash = cas_hash(DENIED_PRE_BYTES);
    let denied_args_hash = cas_hash(DENIED_ARGS_BYTES);

    let receipts = vec![
        EffectReceipt {
            schema_version: EFFECT_RECEIPT_SCHEMA_VERSION.to_string(),
            seq: 0,
            trace_id: "trace-effect-chain-001".to_string(),
            effect_kind: EffectKind::FsRead,
            policy_outcome: EffectPolicyOutcome::Allowed {
                capability_ref: "cap-fs-read-01".to_string(),
            },
            pre_state_hash: pre_hash,
            args_hash,
            result_hash: Some(result_hash),
            post_state_hash: Some(post_hash),
            input_lineage_hash: lineage_hash("operator_secret:input"),
            output_lineage_hash: Some(lineage_hash("operator_secret:output")),
            label_set_commitment: lineage_hash("labels:operator_secret"),
            declassification_ref: Some("ifl-declass:network-egress-allow-001".to_string()),
            flow_policy_verdict: FlowPolicyVerdict::Declassified,
            recorded_at_millis: 1_775_000_000_000,
        },
        EffectReceipt {
            schema_version: EFFECT_RECEIPT_SCHEMA_VERSION.to_string(),
            seq: 1,
            trace_id: "trace-effect-chain-001".to_string(),
            effect_kind: EffectKind::HttpRequest,
            policy_outcome: EffectPolicyOutcome::Denied {
                reason: "ssrf_policy: endpoint resolves into a deny CIDR".to_string(),
            },
            pre_state_hash: denied_pre_hash,
            args_hash: denied_args_hash,
            result_hash: None,
            post_state_hash: None,
            input_lineage_hash: lineage_hash("operator_secret:input"),
            output_lineage_hash: None,
            label_set_commitment: lineage_hash("labels:operator_secret"),
            declassification_ref: None,
            flow_policy_verdict: FlowPolicyVerdict::Blocked,
            recorded_at_millis: 1_775_000_000_001,
        },
    ];
    let entries = seal_effect_entries(receipts);

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "cas/args.json".to_string(),
        artifact("application/json", EFFECT_ARGS_BYTES),
    );
    artifacts.insert(
        "cas/denied-args.json".to_string(),
        artifact("application/json", DENIED_ARGS_BYTES),
    );
    artifacts.insert(
        "cas/denied-pre.txt".to_string(),
        artifact("text/plain", DENIED_PRE_BYTES),
    );
    artifacts.insert(
        "cas/post.js".to_string(),
        artifact("text/javascript", EFFECT_POST_BYTES),
    );
    artifacts.insert(
        "cas/pre.js".to_string(),
        artifact("text/javascript", EFFECT_PRE_BYTES),
    );
    artifacts.insert(
        "cas/result.txt".to_string(),
        artifact("text/javascript", EFFECT_RESULT_BYTES),
    );
    let chunks = chunks_from_artifacts(&artifacts);
    let evidence_refs = artifacts.keys().cloned().collect::<Vec<_>>();

    let mut metadata = BTreeMap::new();
    metadata.insert("domain".to_string(), "sdk/effect-chain".to_string());
    metadata.insert("runtime_profile".to_string(), "strict".to_string());

    let mut bundle = ReplayBundle {
        header: BundleHeader {
            hash_algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            payload_length_bytes: payload_length_bytes(&artifacts),
            chunk_count: chunks
                .len()
                .try_into()
                .expect("fixture chunk count should fit u32"),
        },
        schema_version: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
        sdk_version: SDK_VERSION.to_string(),
        bundle_id: "effect-chain-bundle-001".to_string(),
        incident_id: "effect-chain-incident-001".to_string(),
        created_at: "2026-06-07T16:00:00.000000Z".to_string(),
        policy_version: "strict@2026-06-07".to_string(),
        verifier_identity: "verifier://effect-chain-test".to_string(),
        timeline: vec![
            TimelineEvent {
                sequence_number: 1,
                event_id: "evt-effect-0001".to_string(),
                timestamp: "2026-06-07T16:00:00.000001Z".to_string(),
                event_type: EFFECT_RECEIPT_EVENT_TYPE.to_string(),
                payload: serde_json::to_value(&entries[0]).expect("entry should encode as JSON"),
                state_snapshot: json!({
                    "phase": "effect_receipt",
                    "effect": "fs_read"
                }),
                causal_parent: None,
                policy_version: "strict@2026-06-07".to_string(),
            },
            TimelineEvent {
                sequence_number: 2,
                event_id: "evt-effect-0002".to_string(),
                timestamp: "2026-06-07T16:00:00.000002Z".to_string(),
                event_type: EFFECT_RECEIPT_EVENT_TYPE.to_string(),
                payload: serde_json::to_value(&entries[1]).expect("entry should encode as JSON"),
                state_snapshot: json!({
                    "phase": "effect_receipt",
                    "effect": "http_request"
                }),
                causal_parent: Some(1),
                policy_version: "strict@2026-06-07".to_string(),
            },
        ],
        initial_state_snapshot: json!({
            "trace_id": "trace-effect-chain-001",
            "policy": "strict"
        }),
        evidence_refs,
        artifacts,
        chunks,
        metadata,
        integrity_hash: String::new(),
        signature: BundleSignature {
            algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            signature_hex: String::new(),
        },
    };
    seal(&mut bundle).expect("effect-chain bundle should seal");
    bundle
}

fn verify_effect_chain_bytes(bundle: &ReplayBundle) -> Result<(), BundleError> {
    let bytes = serialize(bundle).expect("bundle should serialize");
    verify_effect_chain(&bytes).map(|_| ())
}

fn timeline_effect_entry(bundle: &ReplayBundle, index: usize) -> EffectReceiptChainEntry {
    serde_json::from_value(bundle.timeline[index].payload.clone())
        .expect("timeline payload should be an effect entry")
}

fn set_timeline_effect_entry(
    bundle: &mut ReplayBundle,
    index: usize,
    entry: EffectReceiptChainEntry,
) {
    bundle.timeline[index].payload =
        serde_json::to_value(entry).expect("entry should encode as JSON");
    reseal_bundle(bundle);
}

fn replace_effect_receipt_and_reseal_chain(
    bundle: &mut ReplayBundle,
    index: usize,
    receipt: EffectReceipt,
) {
    let mut receipts = bundle
        .timeline
        .iter()
        .cloned()
        .map(|event| {
            serde_json::from_value::<EffectReceiptChainEntry>(event.payload)
                .expect("timeline payload should be an effect entry")
                .receipt
        })
        .collect::<Vec<_>>();
    let target_receipt = receipts
        .get_mut(index)
        .expect("effect receipt index should exist");
    *target_receipt = receipt;
    for (event, entry) in bundle
        .timeline
        .iter_mut()
        .zip(seal_effect_entries(receipts))
    {
        event.payload = serde_json::to_value(entry).expect("entry should encode as JSON");
    }
    reseal_bundle(bundle);
}

fn replace_artifact_bytes(bundle: &mut ReplayBundle, path: &str, bytes: &[u8]) {
    let media_type = bundle
        .artifacts
        .get(path)
        .expect("artifact should exist")
        .media_type
        .clone();
    bundle
        .artifacts
        .insert(path.to_string(), artifact(&media_type, bytes));
    reseal_bundle(bundle);
}

fn reseal_bundle(bundle: &mut ReplayBundle) {
    bundle.chunks = chunks_from_artifacts(&bundle.artifacts);
    bundle.header.payload_length_bytes = payload_length_bytes(&bundle.artifacts);
    bundle.header.chunk_count = bundle
        .chunks
        .len()
        .try_into()
        .expect("fixture chunk count should fit u32");
    seal(bundle).expect("bundle should reseal");
}

fn seal_effect_entries(receipts: Vec<EffectReceipt>) -> Vec<EffectReceiptChainEntry> {
    let mut prev_chain_hash = EFFECT_CHAIN_GENESIS.to_string();
    let mut entries = Vec::with_capacity(receipts.len());
    for (index, receipt) in receipts.into_iter().enumerate() {
        let index = u64::try_from(index).expect("fixture index should fit u64");
        let receipt_hash = effect_receipt_hash(&receipt);
        let chain_hash = effect_chain_hash(index, &prev_chain_hash, &receipt_hash);
        entries.push(EffectReceiptChainEntry {
            index,
            prev_chain_hash,
            receipt_hash,
            chain_hash: chain_hash.clone(),
            receipt,
        });
        prev_chain_hash = chain_hash;
    }
    entries
}

fn cas_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"storage_cas_content_hash_v1:");
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn lineage_hash(label: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn operator_secret_external_sink_claim(
    allowed_declassification_refs: Vec<String>,
) -> NonExfiltrationClaim {
    NonExfiltrationClaim {
        forbidden_label_set_commitments: vec![lineage_hash("labels:operator_secret")],
        external_sink_effect_kinds: vec![
            "http_request".to_string(),
            "net_connect".to_string(),
            "spawn".to_string(),
        ],
        allowed_declassification_refs,
    }
}

fn capability_proof_fixture() -> CapabilityProof {
    let mut proof = CapabilityProof {
        schema_version: CAPABILITY_PROOF_SCHEMA_VERSION.to_string(),
        proof_id: "cap-proof-001".to_string(),
        actor: "agent://builder".to_string(),
        audience: "verifier://capability-test".to_string(),
        scopes: vec![
            CapabilityScope {
                capability: "fs_read".to_string(),
                resource: "cas://workspace/app/index.js".to_string(),
                access: "read".to_string(),
            },
            CapabilityScope {
                capability: "http_request".to_string(),
                resource: "https://api.example.test/v1/data".to_string(),
                access: "egress".to_string(),
            },
        ],
        policy_profile: CapabilityPolicyProfile::Strict,
        revocation_freshness: CapabilityRevocationFreshness::Fresh {
            checked_at_millis: 1_775_000_000_000,
            evidence_ref: "revocation:fresh:001".to_string(),
        },
        epoch: 42,
        side_effect_kind: EffectKind::HttpRequest,
        evidence_refs: vec![
            "effect-chain:head:001".to_string(),
            "revocation:fresh:001".to_string(),
        ],
        expected_postconditions: vec![
            CapabilityPostcondition {
                field: "http_status".to_string(),
                expected_hash: lineage_hash("post:http_status:200"),
            },
            CapabilityPostcondition {
                field: "response_body".to_string(),
                expected_hash: cas_hash(EFFECT_RESULT_BYTES),
            },
        ],
        issued_at_millis: 1_775_000_000_000,
        expires_at_millis: 1_775_003_600_000,
        proof_hash: String::new(),
    };
    seal_capability_proof(&mut proof).expect("capability proof fixture should seal");
    proof
}

fn capability_receipt_fixture(proof: &CapabilityProof) -> CapabilityReceipt {
    let mut receipt = CapabilityReceipt {
        schema_version: CAPABILITY_RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: "cap-receipt-001".to_string(),
        proof_id: proof.proof_id.clone(),
        proof_hash: proof.proof_hash.clone(),
        actor: proof.actor.clone(),
        audience: proof.audience.clone(),
        exercised_scope: proof
            .scopes
            .get(1)
            .expect("fixture should include http_request scope")
            .clone(),
        policy_profile: proof.policy_profile,
        epoch: proof.epoch,
        side_effect_kind: proof.side_effect_kind,
        effect_receipt_chain_hash: lineage_hash("effect-chain:head:001"),
        observed_postconditions: proof.expected_postconditions.clone(),
        recorded_at_millis: 1_775_000_001_000,
        receipt_hash: String::new(),
    };
    seal_capability_receipt(&mut receipt).expect("capability receipt fixture should seal");
    receipt
}

fn capability_counterfactual_request(proof: &CapabilityProof) -> CounterfactualCapabilityRequest {
    CounterfactualCapabilityRequest {
        actor: proof.actor.clone(),
        audience: proof.audience.clone(),
        requested_scope: proof
            .scopes
            .get(1)
            .expect("fixture should include http_request scope")
            .clone(),
        policy_profile: proof.policy_profile,
        epoch: proof.epoch,
        side_effect_kind: proof.side_effect_kind,
        observed_postconditions: proof.expected_postconditions.clone(),
    }
}

fn effect_receipt_hash(receipt: &EffectReceipt) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"runtime_effect_receipt_canonical_v1:");
    update_hash_str(&mut hasher, &receipt.schema_version);
    hasher.update(receipt.seq.to_le_bytes());
    update_hash_str(&mut hasher, &receipt.trace_id);
    hasher.update([effect_kind_tag(receipt.effect_kind)]);
    hasher.update([policy_outcome_tag(&receipt.policy_outcome)]);
    match &receipt.policy_outcome {
        EffectPolicyOutcome::Allowed { capability_ref } => {
            update_hash_str(&mut hasher, capability_ref);
        }
        EffectPolicyOutcome::Denied { reason } => {
            update_hash_str(&mut hasher, reason);
        }
    }
    update_hash_str(&mut hasher, &receipt.pre_state_hash);
    update_hash_str(&mut hasher, &receipt.args_hash);
    update_optional_hash_str(&mut hasher, receipt.result_hash.as_deref());
    update_optional_hash_str(&mut hasher, receipt.post_state_hash.as_deref());
    update_hash_str(&mut hasher, &receipt.input_lineage_hash);
    update_optional_hash_str(&mut hasher, receipt.output_lineage_hash.as_deref());
    update_hash_str(&mut hasher, &receipt.label_set_commitment);
    update_optional_hash_str(&mut hasher, receipt.declassification_ref.as_deref());
    hasher.update([flow_policy_verdict_tag(receipt.flow_policy_verdict)]);
    hasher.update(receipt.recorded_at_millis.to_le_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn effect_chain_hash(index: u64, prev_chain_hash: &str, receipt_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"runtime_effect_receipt_chain_v1:");
    hasher.update(index.to_le_bytes());
    update_hash_str(&mut hasher, prev_chain_hash);
    update_hash_str(&mut hasher, receipt_hash);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn update_hash_str(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn update_optional_hash_str(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(hash) => {
            hasher.update([1_u8]);
            update_hash_str(hasher, hash);
        }
        None => hasher.update([0_u8]),
    }
}

fn effect_kind_tag(kind: EffectKind) -> u8 {
    match kind {
        EffectKind::FsRead => 1,
        EffectKind::FsWrite => 2,
        EffectKind::NetConnect => 3,
        EffectKind::HttpRequest => 4,
        EffectKind::Spawn => 5,
        EffectKind::ModuleResolve => 6,
    }
}

fn policy_outcome_tag(outcome: &EffectPolicyOutcome) -> u8 {
    match outcome {
        EffectPolicyOutcome::Allowed { .. } => 1,
        EffectPolicyOutcome::Denied { .. } => 2,
    }
}

fn flow_policy_verdict_tag(verdict: FlowPolicyVerdict) -> u8 {
    match verdict {
        FlowPolicyVerdict::LabelClean => 1,
        FlowPolicyVerdict::Declassified => 2,
        FlowPolicyVerdict::Blocked => 3,
    }
}

fn effect_chain_fnbundle_path() -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join(format!(
        "franken-vsdk-effect-chain-{}.fnbundle",
        std::process::id()
    ))
}

fn chunks_from_artifacts(artifacts: &BTreeMap<String, BundleArtifact>) -> Vec<BundleChunk> {
    let total_chunks = artifacts
        .len()
        .try_into()
        .expect("fixture chunk count should fit u32");
    artifacts
        .iter()
        .enumerate()
        .map(|(index, (path, artifact))| BundleChunk {
            chunk_index: index
                .try_into()
                .expect("fixture chunk index should fit u32"),
            total_chunks,
            artifact_path: path.clone(),
            payload_length_bytes: u64::try_from(artifact.bytes_hex.len() / 2)
                .expect("fixture artifact length should fit u64"),
            payload_digest: artifact.digest.clone(),
        })
        .collect()
}

fn payload_length_bytes(artifacts: &BTreeMap<String, BundleArtifact>) -> u64 {
    artifacts
        .values()
        .map(|artifact| {
            u64::try_from(artifact.bytes_hex.len() / 2)
                .expect("fixture artifact length should fit u64")
        })
        .sum()
}

fn artifact(media_type: &str, bytes: &[u8]) -> BundleArtifact {
    BundleArtifact {
        media_type: media_type.to_string(),
        digest: hash(bytes),
        bytes_hex: hex_encode(bytes),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
