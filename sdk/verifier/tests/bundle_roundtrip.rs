use std::collections::BTreeMap;
use std::path::PathBuf;

use frankenengine_verifier_sdk::SDK_VERSION;
use frankenengine_verifier_sdk::VerifierSdk;
use frankenengine_verifier_sdk::bundle::{
    BundleArtifact, BundleChunk, BundleError, BundleHeader, BundleSignature,
    EFFECT_RECEIPT_EVENT_TYPE, EFFECT_RECEIPT_SCHEMA_VERSION, EffectKind, EffectPolicyOutcome,
    EffectReceipt, EffectReceiptChainEntry, FN_VSDK_EFFECT_CHAIN_PASS, FN_VSDK_EFFECT_CHAIN_START,
    FN_VSDK_EFFECT_VERIFIED, FN_VSDK_NON_EXFILTRATION_EFFECT, FN_VSDK_NON_EXFILTRATION_PASS,
    FN_VSDK_NON_EXFILTRATION_START, FlowPolicyVerdict, NonExfiltrationClaim,
    REPLAY_BUNDLE_HASH_ALGORITHM, REPLAY_BUNDLE_SCHEMA_VERSION, ReplayBundle, TimelineEvent, hash,
    render_effect_chain_transcript, seal, serialize, verify, verify_effect_chain,
    verify_non_exfiltration_claim,
};
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
