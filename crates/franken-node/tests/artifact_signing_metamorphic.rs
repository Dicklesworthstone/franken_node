use std::collections::BTreeMap;

use frankenengine_node::supply_chain::artifact_signing::{
    ArtifactSigningError, ChecksumManifest, KeyId, KeyRing, ManifestEntry, PartialSignature,
    build_and_sign_manifest, collect_threshold_signatures, sign_artifact, sign_bytes,
    verify_release, verify_threshold,
};

const CASES: usize = 100;
const THRESHOLD_PARTIAL_CAP: usize = 256;

#[test]
fn manifest_canonicalization_is_permutation_idempotent_and_detects_bit_flips() {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let mut key_ring = KeyRing::new();
    key_ring.add_key(signing_key.verifying_key());

    for case_index in 0..CASES {
        let artifacts = generated_artifacts(case_index);
        let forward_refs = artifact_refs(&artifacts);
        let mut reversed = artifacts.clone();
        reversed.reverse();
        let reversed_refs = artifact_refs(&reversed);

        let forward_manifest = build_and_sign_manifest(&forward_refs, &signing_key);
        let reversed_manifest = build_and_sign_manifest(&reversed_refs, &signing_key);

        assert_eq!(
            forward_manifest.canonical_bytes(),
            reversed_manifest.canonical_bytes(),
            "case {case_index}: manifest canonical bytes changed after input permutation"
        );
        assert_eq!(
            forward_manifest.signature, reversed_manifest.signature,
            "case {case_index}: manifest signature changed after input permutation"
        );

        let canonical_text =
            String::from_utf8_lossy(&forward_manifest.canonical_bytes()).into_owned();
        let reparsed_result = ChecksumManifest::parse_canonical(&canonical_text);
        assert!(
            reparsed_result.is_ok(),
            "case {case_index}: parse canonical manifest: {:?}",
            reparsed_result.err()
        );
        let reparsed_entries = reparsed_result.unwrap_or_default();
        let reparsed_manifest = manifest_from_entries(&forward_manifest, reparsed_entries);
        assert_eq!(
            forward_manifest.canonical_bytes(),
            reparsed_manifest.canonical_bytes(),
            "case {case_index}: parse/render canonicalization was not idempotent"
        );

        let artifacts_by_name = artifacts_map(&artifacts);
        let signatures_by_name = signatures_map(&artifacts, &signing_key);
        let report = verify_release(
            &forward_manifest,
            &artifacts_by_name,
            &signatures_by_name,
            &key_ring,
        );
        assert!(
            report.overall_pass,
            "case {case_index}: generated manifest failed verification: {:?}",
            report.results
        );

        let mut tampered_artifacts = artifacts_by_name.clone();
        let tampered_name = artifacts[0].0.clone();
        if let Some(content) = tampered_artifacts.get_mut(&tampered_name) {
            content[0] ^= 0x01;
        }
        let tampered_report = verify_release(
            &forward_manifest,
            &tampered_artifacts,
            &signatures_by_name,
            &key_ring,
        );
        assert!(
            !tampered_report.overall_pass,
            "case {case_index}: bit-flipped artifact unexpectedly verified"
        );
        assert!(
            tampered_report
                .results
                .iter()
                .any(|result| result.artifact_name == tampered_name && !result.passed),
            "case {case_index}: bit-flipped artifact was not reported as failed"
        );
    }
}

#[test]
fn parse_canonical_rejects_overlarge_manifest_without_partial_acceptance() {
    let hash = "a".repeat(64);
    let mut manifest = String::new();
    for index in 0..=4096 {
        manifest.push_str(&format!("{hash}  artifact-{index:04}.bin  1\n"));
    }

    let err = ChecksumManifest::parse_canonical(&manifest)
        .expect_err("overlarge manifest must fail closed");

    assert!(matches!(
        err,
        ArtifactSigningError::ManifestLineInvalid { line_number: 4097, ref reason }
            if reason == "manifest entry count exceeds maximum"
    ));
}

#[test]
fn threshold_collection_rejects_oversized_partial_input_before_valid_suffix() {
    let sk1 = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
    let sk2 = ed25519_dalek::SigningKey::from_bytes(&[0x45; 32]);
    let mut key_ring = KeyRing::new();
    let kid1 = key_ring.add_key(sk1.verifying_key());
    let kid2 = key_ring.add_key(sk2.verifying_key());
    let data = b"threshold oversized partial input";

    let mut partials = Vec::new();
    for index in 0..=THRESHOLD_PARTIAL_CAP {
        partials.push(PartialSignature {
            key_id: KeyId(format!("unknown-key-{index}")),
            signature: vec![index.to_le_bytes()[0]; 64],
        });
    }
    partials.push(PartialSignature {
        key_id: kid1,
        signature: sign_bytes(&sk1, data),
    });
    partials.push(PartialSignature {
        key_id: kid2,
        signature: sign_bytes(&sk2, data),
    });

    assert!(!verify_threshold(data, &partials, &key_ring, 2));
    let err = collect_threshold_signatures(data, &partials, &key_ring, 2)
        .expect_err("oversized partial input must fail closed before valid suffix");
    assert!(matches!(
        err,
        ArtifactSigningError::ThresholdInputTooLarge {
            max: THRESHOLD_PARTIAL_CAP,
            actual
        } if actual > THRESHOLD_PARTIAL_CAP
    ));
}

#[test]
fn threshold_collection_caps_repeated_attempts_per_key() {
    let sk1 = ed25519_dalek::SigningKey::from_bytes(&[0x46; 32]);
    let sk2 = ed25519_dalek::SigningKey::from_bytes(&[0x47; 32]);
    let mut key_ring = KeyRing::new();
    let kid1 = key_ring.add_key(sk1.verifying_key());
    let kid2 = key_ring.add_key(sk2.verifying_key());
    let data = b"threshold repeated attempts per key";

    let allowed_retry = vec![
        PartialSignature {
            key_id: kid1.clone(),
            signature: sign_bytes(&sk1, b"wrong payload"),
        },
        PartialSignature {
            key_id: kid1.clone(),
            signature: sign_bytes(&sk1, data),
        },
        PartialSignature {
            key_id: kid2.clone(),
            signature: sign_bytes(&sk2, data),
        },
    ];
    assert!(verify_threshold(data, &allowed_retry, &key_ring, 2));

    let capped_retry = vec![
        PartialSignature {
            key_id: kid1.clone(),
            signature: sign_bytes(&sk1, b"wrong payload 1"),
        },
        PartialSignature {
            key_id: kid1.clone(),
            signature: sign_bytes(&sk1, b"wrong payload 2"),
        },
        PartialSignature {
            key_id: kid1,
            signature: sign_bytes(&sk1, data),
        },
        PartialSignature {
            key_id: kid2,
            signature: sign_bytes(&sk2, data),
        },
    ];

    let err = collect_threshold_signatures(data, &capped_retry, &key_ring, 2)
        .expect_err("third candidate from one key must be skipped");
    assert!(matches!(
        err,
        ArtifactSigningError::ThresholdNotMet {
            required: 2,
            provided: 1
        }
    ));
}

fn generated_artifacts(case_index: usize) -> Vec<(String, Vec<u8>)> {
    let mut rng = DeterministicRng::new(0x6d657461_6d6f7270 ^ case_index as u64);
    let artifact_count = 1 + rng.next_usize(8);
    let mut artifacts = Vec::with_capacity(artifact_count);

    for artifact_index in 0..artifact_count {
        let content_len = 1 + rng.next_usize(96);
        let mut content = Vec::with_capacity(content_len);
        for _ in 0..content_len {
            content.push(rng.next_u8());
        }
        artifacts.push((
            format!("release/{case_index:03}/artifact-{artifact_index:02}.bin"),
            content,
        ));
    }

    artifacts
}

fn artifact_refs(artifacts: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
    artifacts
        .iter()
        .map(|(name, content)| (name.as_str(), content.as_slice()))
        .collect()
}

fn artifacts_map(artifacts: &[(String, Vec<u8>)]) -> BTreeMap<String, Vec<u8>> {
    artifacts.iter().cloned().collect()
}

fn signatures_map(
    artifacts: &[(String, Vec<u8>)],
    signing_key: &ed25519_dalek::SigningKey,
) -> BTreeMap<String, Vec<u8>> {
    artifacts
        .iter()
        .map(|(name, content)| (name.clone(), sign_artifact(signing_key, content)))
        .collect()
}

fn manifest_from_entries(
    original: &ChecksumManifest,
    entries: Vec<ManifestEntry>,
) -> ChecksumManifest {
    ChecksumManifest {
        entries: entries
            .into_iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect(),
        key_id: original.key_id.clone(),
        signature: original.signature.clone(),
    }
}

struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn next_usize(&mut self, upper_exclusive: usize) -> usize {
        debug_assert!(upper_exclusive > 0);
        (self.next_u64() as usize) % upper_exclusive
    }
}
