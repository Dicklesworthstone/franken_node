//! Metamorphic proptest harness for threshold signature partial→combined→verify (bd-1pvbl).
//!
//! Properties tested:
//!
//! 1. **Quorum monotonicity** — for a `k`-of-`n` config and a signature set of size `m`
//!    drawn from distinct configured signers signing the artifact's content hash,
//!    `verify_threshold` reports `verified == (m >= k)` and `valid_signatures == m`.
//! 2. **Subset independence** — any `k` of the `n` configured signers (regardless of
//!    which subset) yields `verified == true` once the threshold is met.
//! 3. **Order independence** — reversing the signature order does not change the
//!    verification result, valid count, or failure reason.
//! 4. **Content-hash binding** — mutating the artifact's `content_hash` after the
//!    signatures are produced invalidates every partial signature, so the result
//!    falls below quorum (`verified == false`, `valid_signatures == 0`).
//! 5. **Cross-content rejection** — partial signatures produced for hash A do not
//!    count toward quorum for an artifact carrying hash B.
//! 6. **Signer-id mismatch rejection** — a partial signature whose `signer_id`
//!    does not match its configured `key_id` does not count toward quorum
//!    (prevents label replay).
//! 7. **Publication-context binding** — partial signatures produced for one
//!    artifact or connector do not count toward quorum for another artifact or
//!    connector carrying the same content hash.
//!
//! These are the load-bearing safety properties: if any break, the threshold gate
//! either lets unauthorised publications through or rejects valid quorums.

use ed25519_dalek::SigningKey;
use frankenengine_node::security::threshold_sig::{
    sign, verify_threshold, FailureReason, PartialSignature, PublicationArtifact, SignerKey,
    ThresholdConfig,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

const PROP_ARTIFACT_ID: &str = "art-prop";
const PROP_CONNECTOR_ID: &str = "conn-prop";

fn signing_key_from_seed(domain: &[u8], idx: u32) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"threshold_sig_quorum_metamorphic_v1:");
    hasher.update(
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(idx.to_le_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

struct Quorum {
    config: ThresholdConfig,
    signing_keys: Vec<SigningKey>,
}

fn build_quorum(domain: &[u8], k: u32, n: u32) -> Quorum {
    let mut signing_keys = Vec::with_capacity(n as usize);
    let mut signer_keys = Vec::with_capacity(n as usize);
    for i in 0..n {
        let sk = signing_key_from_seed(domain, i);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        signer_keys.push(SignerKey {
            key_id: format!("signer-{i}"),
            public_key_hex: pk_hex,
        });
        signing_keys.push(sk);
    }
    Quorum {
        config: ThresholdConfig {
            threshold: k,
            total_signers: n,
            signer_keys,
        },
        signing_keys,
    }
}

fn sign_with_indices_for_context(
    quorum: &Quorum,
    artifact_id: &str,
    connector_id: &str,
    content_hash: &str,
    indices: &[usize],
) -> Vec<PartialSignature> {
    indices
        .iter()
        .map(|&i| {
            let key_id = &quorum.config.signer_keys[i].key_id;
            sign(
                &quorum.signing_keys[i],
                key_id,
                artifact_id,
                connector_id,
                content_hash,
            )
        })
        .collect()
}

fn sign_with_indices(
    quorum: &Quorum,
    content_hash: &str,
    indices: &[usize],
) -> Vec<PartialSignature> {
    sign_with_indices_for_context(
        quorum,
        PROP_ARTIFACT_ID,
        PROP_CONNECTOR_ID,
        content_hash,
        indices,
    )
}

fn make_artifact_with_context(
    artifact_id: &str,
    connector_id: &str,
    content_hash: &str,
    signatures: Vec<PartialSignature>,
) -> PublicationArtifact {
    PublicationArtifact {
        artifact_id: artifact_id.to_string(),
        connector_id: connector_id.to_string(),
        content_hash: content_hash.to_string(),
        signatures,
    }
}

fn make_artifact(content_hash: &str, signatures: Vec<PartialSignature>) -> PublicationArtifact {
    make_artifact_with_context(
        PROP_ARTIFACT_ID,
        PROP_CONNECTOR_ID,
        content_hash,
        signatures,
    )
}

/// Strategy generating (k, n) with `1 <= k <= n <= 8`, plus an arbitrary subset
/// size `m` in `0..=n` and an ordering of `n` signer indices used to pick which
/// `m` signers contribute partial signatures.
fn quorum_strategy() -> impl Strategy<Value = (u32, u32, u32, Vec<usize>)> {
    (1_u32..=8_u32).prop_flat_map(|n| {
        (Just(n), 1_u32..=n).prop_flat_map(|(n, k)| {
            (
                Just(k),
                Just(n),
                0_u32..=n,
                Just((0..n as usize).collect::<Vec<_>>()).prop_shuffle(),
            )
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        ..ProptestConfig::default()
    })]

    /// Property 1 + 2: quorum monotonicity and subset independence.
    /// For any (k, n, m) and any subset of `m` distinct signers, verification
    /// yields `verified == (m >= k)` and `valid_signatures == m`.
    #[test]
    fn quorum_monotonicity_and_subset_independence(
        (k, n, m, ordering) in quorum_strategy(),
        content_seed in any::<u64>(),
    ) {
        let domain = format!("quorum-{k}-of-{n}");
        let quorum = build_quorum(domain.as_bytes(), k, n);
        let content_hash = format!("hash-{content_seed:016x}");

        let chosen: Vec<usize> = ordering.iter().take(m as usize).copied().collect();
        let signatures = sign_with_indices(&quorum, &content_hash, &chosen);
        let artifact = make_artifact(&content_hash, signatures);

        let result = verify_threshold(&quorum.config, &artifact, "trace-prop", "ts-prop");

        prop_assert_eq!(
            result.valid_signatures, m,
            "valid_signatures must match the number of distinct, configured signers"
        );
        prop_assert_eq!(
            result.verified, m >= k,
            "verification must equal (m >= k) for k={}, n={}, m={}", k, n, m
        );
        prop_assert_eq!(result.threshold, k, "threshold echoed back must equal k");

        if m < k {
            match result.failure_reason {
                Some(FailureReason::BelowThreshold { have, need }) => {
                    prop_assert_eq!(have, m);
                    prop_assert_eq!(need, k);
                }
                other => prop_assert!(
                    false,
                    "below-quorum result must report BelowThreshold; got {:?}",
                    other
                ),
            }
        } else {
            prop_assert!(
                result.failure_reason.is_none(),
                "verified result must have no failure reason"
            );
        }
    }

    /// Property 3: order independence. Reversing the signatures must yield the
    /// same `verified`, `valid_signatures`, and `failure_reason` shape.
    #[test]
    fn signature_order_does_not_change_result(
        (k, n, m, ordering) in quorum_strategy(),
        content_seed in any::<u64>(),
    ) {
        let domain = format!("order-{k}-of-{n}");
        let quorum = build_quorum(domain.as_bytes(), k, n);
        let content_hash = format!("ord-{content_seed:016x}");

        let chosen: Vec<usize> = ordering.iter().take(m as usize).copied().collect();
        let signatures = sign_with_indices(&quorum, &content_hash, &chosen);

        let artifact_forward = make_artifact(&content_hash, signatures.clone());
        let mut reversed = signatures;
        reversed.reverse();
        let artifact_reverse = make_artifact(&content_hash, reversed);

        let forward = verify_threshold(&quorum.config, &artifact_forward, "t", "ts");
        let reverse = verify_threshold(&quorum.config, &artifact_reverse, "t", "ts");

        prop_assert_eq!(forward.verified, reverse.verified);
        prop_assert_eq!(forward.valid_signatures, reverse.valid_signatures);
        prop_assert_eq!(forward.threshold, reverse.threshold);
    }

    /// Property 4: content-hash binding. Tampering with the artifact's
    /// content_hash after signing makes every partial signature invalid, which
    /// drops the result below quorum.
    #[test]
    fn content_hash_tampering_invalidates_quorum(
        (k, n, _m, ordering) in quorum_strategy(),
        content_seed in any::<u64>(),
        tamper_seed in any::<u64>(),
    ) {
        prop_assume!(content_seed != tamper_seed);

        let domain = format!("tamper-{k}-of-{n}");
        let quorum = build_quorum(domain.as_bytes(), k, n);
        let original_hash = format!("orig-{content_seed:016x}");
        let mutated_hash = format!("orig-{tamper_seed:016x}");

        // Sign exactly k partial signatures so the *un-tampered* artifact would
        // verify; then swap the content hash to demonstrate the binding.
        let chosen: Vec<usize> = ordering.iter().take(k as usize).copied().collect();
        let signatures = sign_with_indices(&quorum, &original_hash, &chosen);

        let baseline = verify_threshold(
            &quorum.config,
            &make_artifact(&original_hash, signatures.clone()),
            "t",
            "ts",
        );
        prop_assert!(baseline.verified, "baseline k-of-n quorum must verify");

        let tampered = verify_threshold(
            &quorum.config,
            &make_artifact(&mutated_hash, signatures),
            "t",
            "ts",
        );
        prop_assert!(
            !tampered.verified,
            "tampered content_hash must drop below quorum"
        );
        prop_assert_eq!(
            tampered.valid_signatures,
            0,
            "every partial signature must fail under a mutated content_hash"
        );
    }

    /// Property 5: cross-content rejection. A signature for hash A submitted in
    /// an artifact carrying hash B does not count toward quorum for B.
    #[test]
    fn cross_content_signatures_do_not_count(
        n in 2_u32..=6_u32,
        content_a_seed in any::<u64>(),
        content_b_seed in any::<u64>(),
    ) {
        prop_assume!(content_a_seed != content_b_seed);

        let k = n; // require all signers so any single rejection drops below quorum
        let quorum = build_quorum(b"cross", k, n);
        let hash_a = format!("a-{content_a_seed:016x}");
        let hash_b = format!("b-{content_b_seed:016x}");

        let mut signatures: Vec<PartialSignature> =
            sign_with_indices(&quorum, &hash_a, &(0..n as usize).collect::<Vec<_>>());
        // Replace the first signer's signature with one bound to hash_b.
        let cross = sign(
            &quorum.signing_keys[0],
            &quorum.config.signer_keys[0].key_id,
            PROP_ARTIFACT_ID,
            PROP_CONNECTOR_ID,
            &hash_b,
        );
        signatures[0] = cross;

        let result = verify_threshold(
            &quorum.config,
            &make_artifact(&hash_a, signatures),
            "t",
            "ts",
        );

        prop_assert!(!result.verified, "cross-content signature must not satisfy quorum");
        prop_assert_eq!(
            result.valid_signatures,
            n - 1,
            "exactly one cross-content signature must be rejected"
        );
    }

    /// Property 6: signer-id mismatch rejection. If a partial signature's
    /// `signer_id` does not match its `key_id`, it must not count toward quorum
    /// — even when the signature itself would otherwise verify cryptographically.
    /// This prevents an attacker from re-labelling a valid signature under a
    /// different signer identity to subvert deduplication or audit logs.
    #[test]
    fn signer_id_mismatch_does_not_count(
        n in 2_u32..=6_u32,
        content_seed in any::<u64>(),
    ) {
        let k = n;
        let quorum = build_quorum(b"mismatch", k, n);
        let content_hash = format!("mm-{content_seed:016x}");

        let mut signatures: Vec<PartialSignature> =
            sign_with_indices(&quorum, &content_hash, &(0..n as usize).collect::<Vec<_>>());
        // Tamper with signer 0: keep key_id but change signer_id to signer-1's id.
        signatures[0].signer_id = quorum.config.signer_keys[1].key_id.clone();

        let result = verify_threshold(
            &quorum.config,
            &make_artifact(&content_hash, signatures),
            "t",
            "ts",
        );

        prop_assert!(
            !result.verified,
            "signer_id != key_id must drop the signature below quorum"
        );
        prop_assert!(
            result.valid_signatures < k,
            "mismatched signer_id must not contribute to valid_signatures"
        );
    }

    /// Property 7: publication-context binding. Signatures made for one artifact
    /// or connector cannot be replayed onto another artifact or connector with the
    /// same content hash.
    #[test]
    fn cross_publication_context_signatures_do_not_count(
        n in 1_u32..=6_u32,
        content_seed in any::<u64>(),
    ) {
        let k = n;
        let quorum = build_quorum(b"context-binding", k, n);
        let content_hash = format!("ctx-{content_seed:016x}");
        let indices = (0..n as usize).collect::<Vec<_>>();

        let signatures = sign_with_indices_for_context(
            &quorum,
            "art-a",
            "conn-a",
            &content_hash,
            &indices,
        );

        let artifact_replay = verify_threshold(
            &quorum.config,
            &make_artifact_with_context("art-b", "conn-a", &content_hash, signatures.clone()),
            "t-artifact-replay",
            "ts",
        );
        prop_assert!(
            !artifact_replay.verified,
            "cross-artifact signature replay must not satisfy quorum"
        );
        prop_assert_eq!(
            artifact_replay.valid_signatures,
            0,
            "every cross-artifact signature must be rejected"
        );

        let connector_replay = verify_threshold(
            &quorum.config,
            &make_artifact_with_context("art-a", "conn-b", &content_hash, signatures),
            "t-connector-replay",
            "ts",
        );
        prop_assert!(
            !connector_replay.verified,
            "cross-connector signature replay must not satisfy quorum"
        );
        prop_assert_eq!(
            connector_replay.valid_signatures,
            0,
            "every cross-connector signature must be rejected"
        );
    }
}
