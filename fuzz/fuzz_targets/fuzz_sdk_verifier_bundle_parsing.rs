#![no_main]

use arbitrary::Arbitrary;
use frankenengine_verifier_sdk::bundle::{
    deserialize, hash, integrity_hash, verify, BundleArtifact, BundleChunk, BundleHeader,
    BundleSignature, ReplayBundle, TimelineEvent,
};
use hex::FromHex;
use libfuzzer_sys::fuzz_target;

// Fuzz target for SDK verifier bundle parsing and verification.
//
// Tests structure-aware fuzzing of the verifier SDK's bundle deserialization patterns.
// This targets untrusted verifier input through `serde_json::from_slice` calls in
// the external verifier SDK surface.
//
// Priority target (bd-11xn6): SDK verifier bundle input parsing
// - ReplayBundle: main bundle format (highest risk)
// - TimelineEvent, BundleArtifact, BundleChunk: supporting structures
// - Bundle verification logic: integrity_hash, verify
fuzz_target!(|data: FuzzInput| {
    match data {
        FuzzInput::StructuredBundle(bundle) => {
            fuzz_bundle_structured(*bundle);
        }
        FuzzInput::StructuredEvent(event) => {
            fuzz_timeline_event_structured(event);
        }
        FuzzInput::StructuredHeader(header) => {
            fuzz_bundle_header_structured(header);
        }
        FuzzInput::StructuredChunk(chunk) => {
            fuzz_bundle_chunk_structured(chunk);
        }
        FuzzInput::StructuredArtifact(artifact) => {
            fuzz_bundle_artifact_structured(artifact);
        }
        FuzzInput::StructuredSignature(signature) => {
            fuzz_bundle_signature_structured(signature);
        }
        FuzzInput::RawBundleBytes(bytes) => {
            fuzz_bundle_raw_bytes(bytes);
        }
    }
});

fn fuzz_bundle_structured(input: FuzzReplayBundle) {
    let bundle = input.into_bundle();
    if let Ok(json) = serde_json::to_vec(&bundle) {
        // Round-trip property: deserialize(serialize(bundle)) should succeed
        let deserialize_result = deserialize(&json);
        let serde_result = serde_json::from_slice::<ReplayBundle>(&json);

        // Both deserialization methods should agree
        assert_eq!(deserialize_result.is_ok(), serde_result.is_ok(),
                  "SDK deserialize and serde deserialization should agree on validity");

        // Hash should not panic on valid JSON
        let hash_result = hash(&json);
        assert!(hash_result.is_ok(), "Hash function should not fail on valid JSON");

        // Verify should handle the JSON safely
        let verify_result = verify(&json);
        // Note: verify may fail for legitimate reasons (invalid signature, etc.) but should not panic
    }
    if let Ok(pretty_json) = serde_json::to_vec_pretty(&bundle) {
        let pretty_deserialize = deserialize(&pretty_json);
        let pretty_verify = verify(&pretty_json);

        // Pretty-printed JSON should parse consistently
        if let Ok(json) = serde_json::to_vec(&bundle) {
            let normal_deserialize = deserialize(&json);
            assert_eq!(pretty_deserialize.is_ok(), normal_deserialize.is_ok(),
                      "Pretty-printed and normal JSON should have consistent parse results");
        }
    }

    // Integrity hash computation should not panic on structured input
    let integrity_result = integrity_hash(&bundle);
    // Note: integrity_hash may return error but should not panic

    verify_structured_bundle(&bundle);
}

fn fuzz_timeline_event_structured(input: FuzzTimelineEvent) {
    let event = input.into_event();
    if let Ok(json) = serde_json::to_vec(&event) {
        // Round-trip property: deserialize(serialize(event)) should succeed
        let parsed_event = serde_json::from_slice::<TimelineEvent>(&json);
        assert!(parsed_event.is_ok(), "Timeline event round-trip should succeed");
    }

    let mut bundle = create_minimal_bundle_with_header(BundleHeader {
        hash_algorithm: "sha256".to_string(),
        payload_length_bytes: 0,
        chunk_count: 0,
    });
    bundle.timeline = vec![event];

    // Integrity hash should not panic on bundle with valid timeline event
    let integrity_result = integrity_hash(&bundle);
    // Note: may legitimately fail but should not panic

    verify_structured_bundle(&bundle);
}

/// Fuzz structured BundleHeader objects
fn fuzz_bundle_header_structured(header: BundleHeader) {
    if let Ok(json) = serde_json::to_vec(&header) {
        // Round-trip property for BundleHeader
        let parsed_header = serde_json::from_slice::<BundleHeader>(&json);
        assert!(parsed_header.is_ok(), "BundleHeader round-trip should succeed");
    }

    let test_bundle = create_minimal_bundle_with_header(header);

    // Integrity hash should not panic on minimal bundle with any header
    let integrity_result = integrity_hash(&test_bundle);
    // Note: may legitimately fail but should not panic

    verify_structured_bundle(&test_bundle);
}

/// Fuzz structured BundleChunk objects
fn fuzz_bundle_chunk_structured(chunk: BundleChunk) {
    if let Ok(json) = serde_json::to_vec(&chunk) {
        // Round-trip property for BundleChunk
        let parsed_chunk = serde_json::from_slice::<BundleChunk>(&json);
        assert!(parsed_chunk.is_ok(), "BundleChunk round-trip should succeed");
    }

    // Test edge cases with chunk indices and sizes
    let test_bundle = create_minimal_bundle_with_chunks(vec![chunk]);

    // Integrity hash should not panic on bundle with any chunk
    let integrity_result = integrity_hash(&test_bundle);
    // Note: may legitimately fail but should not panic

    verify_structured_bundle(&test_bundle);
}

/// Fuzz structured BundleSignature objects
fn fuzz_bundle_signature_structured(signature: BundleSignature) {
    if let Ok(json) = serde_json::to_vec(&signature) {
        // Round-trip property for BundleSignature
        let parsed_signature = serde_json::from_slice::<BundleSignature>(&json);
        assert!(parsed_signature.is_ok(), "BundleSignature round-trip should succeed");
    }

    // Test hex decoding edge cases
    fuzz_hex_parse(&signature.signature_hex);

    // Test signature verification with fuzzed signature
    let test_bundle = create_minimal_bundle_with_signature(signature);
    verify_structured_bundle(&test_bundle);
}

/// Helper to create minimal bundle for testing components
fn create_minimal_bundle_with_header(header: BundleHeader) -> ReplayBundle {
    ReplayBundle {
        header,
        schema_version: "vsdk-replay-bundle-v1.0".to_string(),
        sdk_version: "0.1.0".to_string(),
        bundle_id: "test".to_string(),
        incident_id: "test".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        policy_version: "v1".to_string(),
        verifier_identity: "test".to_string(),
        timeline: vec![],
        initial_state_snapshot: serde_json::json!({}),
        evidence_refs: vec![],
        artifacts: std::collections::BTreeMap::new(),
        chunks: vec![],
        metadata: std::collections::BTreeMap::new(),
        integrity_hash: String::new(),
        signature: BundleSignature {
            algorithm: "ed25519".to_string(),
            signature_hex: String::new(),
        },
    }
}

/// Helper to create minimal bundle with fuzzed chunks
fn create_minimal_bundle_with_chunks(chunks: Vec<BundleChunk>) -> ReplayBundle {
    let mut bundle = create_minimal_bundle_with_header(BundleHeader {
        hash_algorithm: "sha256".to_string(),
        payload_length_bytes: 0,
        chunk_count: u32::try_from(chunks.len()).unwrap_or(u32::MAX),
    });
    bundle.chunks = chunks;
    bundle
}

/// Helper to create minimal bundle with fuzzed signature
fn create_minimal_bundle_with_signature(signature: BundleSignature) -> ReplayBundle {
    let mut bundle = create_minimal_bundle_with_header(BundleHeader {
        hash_algorithm: "sha256".to_string(),
        payload_length_bytes: 0,
        chunk_count: 0,
    });
    bundle.signature = signature;
    bundle
}

/// Helper to create minimal bundle with a fuzzed artifact.
fn create_minimal_bundle_with_artifact(artifact: BundleArtifact) -> ReplayBundle {
    let payload_length_bytes = u64::try_from(artifact.bytes_hex.len()).unwrap_or(u64::MAX);
    let mut bundle = create_minimal_bundle_with_header(BundleHeader {
        hash_algorithm: "sha256".to_string(),
        payload_length_bytes,
        chunk_count: 0,
    });
    bundle
        .artifacts
        .insert("fuzz-artifact".to_string(), artifact);
    bundle
}

/// Fuzz structured BundleArtifact objects
fn fuzz_bundle_artifact_structured(artifact: BundleArtifact) {
    if let Ok(json) = serde_json::to_vec(&artifact) {
        // Round-trip property for BundleArtifact
        let parsed_artifact = serde_json::from_slice::<BundleArtifact>(&json);
        assert!(parsed_artifact.is_ok(), "BundleArtifact round-trip should succeed");
    }

    // Test hex decoding edge cases
    fuzz_hex_parse(&artifact.bytes_hex);
    fuzz_hex_parse(&artifact.digest);

    let test_bundle = create_minimal_bundle_with_artifact(artifact);

    // Integrity hash should not panic on bundle with any artifact
    let integrity_result = integrity_hash(&test_bundle);
    // Note: may legitimately fail but should not panic

    verify_structured_bundle(&test_bundle);
}

/// Fuzz raw bundle bytes (coverage-guided approach)
fn fuzz_bundle_raw_bytes(bytes: Vec<u8>) {
    // Size guard: reject overly large inputs to prevent OOM
    if bytes.len() > 10_000_000 {
        return;
    }

    // Test deterministic behavior of main deserialization entry point
    let deserialize_result1 = deserialize(&bytes);
    let deserialize_result2 = deserialize(&bytes);
    assert_eq!(deserialize_result1.is_ok(), deserialize_result2.is_ok(),
              "SDK deserialization should be deterministic");

    // Test individual component deserialization for consistency
    let bundle_result = serde_json::from_slice::<ReplayBundle>(&bytes);
    let header_result = serde_json::from_slice::<BundleHeader>(&bytes);
    let event_result = serde_json::from_slice::<TimelineEvent>(&bytes);
    let chunk_result = serde_json::from_slice::<BundleChunk>(&bytes);
    let artifact_result = serde_json::from_slice::<BundleArtifact>(&bytes);
    let signature_result = serde_json::from_slice::<BundleSignature>(&bytes);

    // Very small inputs should be rejected for complex structures
    if bytes.len() < 10 && !bytes.is_empty() {
        assert!(bundle_result.is_err(), "Very small input should not parse as ReplayBundle");
        assert!(header_result.is_err(), "Very small input should not parse as BundleHeader");
    }

    // Empty input should be consistently rejected
    if bytes.is_empty() {
        assert!(bundle_result.is_err(), "Empty input should not parse as ReplayBundle");
        assert!(deserialize_result1.is_err(), "Empty input should not deserialize via SDK");
    }

    // Hash function should be deterministic
    let hash_result1 = hash(&bytes);
    let hash_result2 = hash(&bytes);
    assert_eq!(hash_result1.is_ok(), hash_result2.is_ok(), "Hash function should be deterministic");
    if let (Ok(h1), Ok(h2)) = (hash_result1, hash_result2) {
        assert_eq!(h1, h2, "Hash function should produce identical results for same input");
    }

    // Test validation against malformed input
    if let Ok(bundle) = deserialize(&bytes) {
        // Successfully parsed bundles should have consistent integrity hash computation
        let integrity_result1 = integrity_hash(&bundle);
        let integrity_result2 = integrity_hash(&bundle);
        assert_eq!(integrity_result1.is_ok(), integrity_result2.is_ok(),
                  "Integrity hash computation should be deterministic");

        // Verification should be deterministic on same input
        let verify_result1 = verify(&bytes);
        let verify_result2 = verify(&bytes);
        assert_eq!(verify_result1.is_ok(), verify_result2.is_ok(),
                  "Bundle verification should be deterministic");
    } else {
        // If initial deserialization fails, verify should also fail
        let verify_result = verify(&bytes);
        assert!(verify_result.is_err(), "Verify should fail if deserialization fails");
    }
}

fn verify_structured_bundle(bundle: &ReplayBundle) {
    if let Ok(bytes) = serde_json::to_vec(bundle) {
        // Verification should be deterministic
        let verify_result1 = verify(&bytes);
        let verify_result2 = verify(&bytes);
        assert_eq!(verify_result1.is_ok(), verify_result2.is_ok(),
                  "Bundle verification should be deterministic");
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzReplayBundle {
    header: BundleHeader,
    schema_version: String,
    sdk_version: String,
    bundle_id: String,
    incident_id: String,
    created_at: String,
    policy_version: String,
    verifier_identity: String,
    timeline: Vec<FuzzTimelineEvent>,
    artifacts: Vec<(String, BundleArtifact)>,
    chunks: Vec<BundleChunk>,
    metadata: Vec<(String, String)>,
    integrity_hash: String,
    signature: BundleSignature,
}

impl FuzzReplayBundle {
    fn into_bundle(self) -> ReplayBundle {
        let timeline = self
            .timeline
            .into_iter()
            .take(16)
            .map(FuzzTimelineEvent::into_event)
            .collect();
        let artifacts = self
            .artifacts
            .into_iter()
            .take(16)
            .map(|(key, artifact)| (bounded_text(key, 64), artifact))
            .collect();
        let metadata = self
            .metadata
            .into_iter()
            .take(16)
            .map(|(key, value)| (bounded_text(key, 64), bounded_text(value, 128)))
            .collect();
        ReplayBundle {
            header: self.header,
            schema_version: bounded_text(self.schema_version, 64),
            sdk_version: bounded_text(self.sdk_version, 32),
            bundle_id: bounded_text(self.bundle_id, 128),
            incident_id: bounded_text(self.incident_id, 128),
            created_at: bounded_text(self.created_at, 64),
            policy_version: bounded_text(self.policy_version, 64),
            verifier_identity: bounded_text(self.verifier_identity, 128),
            timeline,
            initial_state_snapshot: serde_json::json!({}),
            evidence_refs: Vec::new(),
            artifacts,
            chunks: self.chunks.into_iter().take(16).collect(),
            metadata,
            integrity_hash: bounded_text(self.integrity_hash, 128),
            signature: self.signature,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzTimelineEvent {
    sequence_number: u64,
    event_id: String,
    timestamp: String,
    event_type: String,
    payload: Vec<u8>,
    state_snapshot: Vec<u8>,
    causal_parent: Option<u64>,
    policy_version: String,
}

impl FuzzTimelineEvent {
    fn into_event(self) -> TimelineEvent {
        TimelineEvent {
            sequence_number: self.sequence_number,
            event_id: bounded_text(self.event_id, 128),
            timestamp: bounded_text(self.timestamp, 64),
            event_type: bounded_text(self.event_type, 64),
            payload: bytes_json(self.payload),
            state_snapshot: bytes_json(self.state_snapshot),
            causal_parent: self.causal_parent,
            policy_version: bounded_text(self.policy_version, 64),
        }
    }
}

fn bounded_text(value: String, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn bytes_json(bytes: Vec<u8>) -> serde_json::Value {
    let limit = bytes.len().min(128);
    serde_json::json!({
        "bytes_hex": hex::encode(&bytes[..limit]),
        "truncated": bytes.len() > limit,
    })
}

fn fuzz_hex_parse(candidate: &str) {
    // Test deterministic hex parsing behavior
    let hex_result1 = Vec::<u8>::from_hex(candidate);
    let hex_result2 = Vec::<u8>::from_hex(candidate);
    assert_eq!(hex_result1.is_ok(), hex_result2.is_ok(),
              "Hex parsing should be deterministic");

    // If parsing succeeds, results should be identical
    if let (Ok(bytes1), Ok(bytes2)) = (hex_result1, hex_result2) {
        assert_eq!(bytes1, bytes2, "Hex parsing should produce identical results");
    }

    // Test some basic hex validation properties
    if candidate.is_empty() {
        let empty_result = Vec::<u8>::from_hex(candidate);
        assert!(empty_result.is_ok(), "Empty string should parse as empty hex");
    }

    // Odd-length hex strings should be rejected
    if candidate.len() % 2 == 1 && !candidate.is_empty() {
        let odd_result = Vec::<u8>::from_hex(candidate);
        assert!(odd_result.is_err(), "Odd-length hex string should be rejected");
    }

    // Valid hex chars should parse if even length
    if candidate.len() % 2 == 0 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        let valid_result = Vec::<u8>::from_hex(candidate);
        assert!(valid_result.is_ok(), "Valid even-length hex should parse successfully");
    }
}

/// Input structure for hybrid structure-aware + coverage-guided fuzzing.
#[derive(Arbitrary, Debug)]
enum FuzzInput {
    /// Generate structured ReplayBundle values then test canonical SDK parsing.
    StructuredBundle(Box<FuzzReplayBundle>),
    /// Generate structured TimelineEvent values then test event parsing and bundle context.
    StructuredEvent(FuzzTimelineEvent),
    /// Generate valid structured BundleHeader then test in bundle context
    StructuredHeader(BundleHeader),
    /// Generate valid structured BundleChunk then test chunk validation
    StructuredChunk(BundleChunk),
    /// Generate valid structured BundleArtifact then test hex decoding
    StructuredArtifact(BundleArtifact),
    /// Generate valid structured BundleSignature then test signature verification
    StructuredSignature(BundleSignature),
    /// Raw bytes for coverage-guided fuzzing of parser edge cases
    RawBundleBytes(Vec<u8>),
}
