//! Integration conformance: Proof-Carrying Host Effects keystone
//! (bd-f5b04.2.2.1 + bd-f5b04.2.2.2).
//!
//! Exercises the CAS and EffectReceipt public APIs *together* in the realistic
//! keystone flow — store effect bytes in the content-addressed store, build an
//! effect receipt that references those CAS hashes, chain it, verify integrity,
//! then prove that tampering with either the stored bytes or a chained receipt
//! fails closed. This is the light, normal-lane verification (links the lib
//! without `#![cfg(test)]`); per-module unit coverage additionally lives inline
//! behind the `franken_node_inline_tests` lane.
//!
//! Run: `rch exec -- cargo test -p frankenengine-node --no-default-features
//! --test cas_effect_receipt_conformance -- --nocapture`.

use frankenengine_node::runtime::effect_receipt::{
    EffectKind, EffectReceipt, EffectReceiptChain, EffectReceiptError, PolicyOutcome,
};
use frankenengine_node::storage::cas::{
    CasError, ContentAddressedStore, ContentHash, content_hash,
};

fn store() -> (tempfile::TempDir, ContentAddressedStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cas = ContentAddressedStore::with_directory(dir.path()).expect("open cas");
    (dir, cas)
}

fn allowed_receipt(seq: u64, trace_id: &str, hash: &ContentHash) -> EffectReceipt {
    EffectReceipt::allowed(
        seq,
        trace_id,
        EffectKind::FsRead,
        "cap",
        hash.clone(),
        hash.clone(),
        hash.clone(),
        hash.clone(),
        seq,
    )
}

fn allowed_chain(hash: &ContentHash, len: u64) -> EffectReceiptChain {
    let mut chain = EffectReceiptChain::new();
    for seq in 0..len {
        chain
            .append(allowed_receipt(seq, "trace-chain", hash))
            .expect("append");
    }
    chain.verify_integrity().expect("baseline verifies");
    chain
}

#[test]
fn keystone_flow_store_receipt_chain_and_verify() {
    let (_dir, cas) = store();

    // 1. Real effect bytes land in the CAS, addressed by content hash.
    let pre = cas.put(b"// module.exports = {}").expect("put pre");
    let args = cas
        .put(br#"{"path":"/app/index.js","flags":"r"}"#)
        .expect("put args");
    let result = cas.put(b"export const answer = 42;").expect("put result");
    let post = cas.put(b"// module.exports = {}").expect("put post");

    // CAS round-trips and dedups (pre == post bytes -> one blob).
    assert_eq!(
        cas.get(&result).expect("get result"),
        b"export const answer = 42;"
    );
    assert_eq!(pre, post, "identical bytes share a content hash (dedup)");
    assert_eq!(
        cas.len().expect("len"),
        3,
        "four puts, three distinct blobs"
    );

    // 2. An allowed effect receipt references the CAS hashes.
    let mut chain = EffectReceiptChain::new();
    let receipt = EffectReceipt::allowed(
        0,
        "trace-keystone",
        EffectKind::ModuleResolve,
        "cap-fs-read-01",
        pre.clone(),
        args.clone(),
        result.clone(),
        post.clone(),
        1_725_000_000_000,
    );
    chain.append(receipt).expect("append allowed");

    // 3. A denied effect is fail-closed: proof that nothing executed.
    let denied = EffectReceipt::denied(
        1,
        "trace-keystone",
        EffectKind::HttpRequest,
        "ssrf_policy: endpoint resolves into a deny CIDR",
        content_hash(b"connect 169.254.169.254:80"),
        content_hash(br#"{"host":"metadata.internal"}"#),
        1_725_000_000_001,
    );
    assert!(
        matches!(denied.policy_outcome, PolicyOutcome::Denied { .. })
            && denied.result_hash.is_none()
            && denied.post_state_hash.is_none(),
        "a denied egress must carry no result/post-state"
    );
    chain.append(denied).expect("append denied");

    // 4. The chain verifies end to end.
    assert_eq!(chain.len(), 2);
    chain.verify_integrity().expect("chain verifies");
}

#[test]
fn tampering_with_cas_bytes_fails_closed_on_read() {
    let (_dir, cas) = store();
    let hash = cas.put(b"trustworthy effect bytes").expect("put");
    // Overwrite the stored blob behind the CAS's back.
    let bytes_path = {
        // Reconstruct the sharded path the way the store does (public hex).
        let hex = hash.as_str().strip_prefix("sha256:").expect("prefix");
        _dir.path().join(&hex[..2]).join(hex)
    };
    std::fs::write(&bytes_path, b"tampered").expect("overwrite");
    assert!(
        matches!(cas.get(&hash), Err(CasError::IntegrityViolation { .. })),
        "read-time integrity check must reject tampered bytes"
    );
}

#[test]
fn tampering_with_a_chained_receipt_breaks_integrity() {
    let (_dir, cas) = store();
    let h = cas.put(b"x").expect("put");
    let chain = allowed_chain(&h, 4);

    // A forged persisted receipt whose hashes were not recomputed must fail
    // closed when the verifier re-derives every receipt hash.
    let mut entries = chain.entries().to_vec();
    entries[2].receipt.trace_id = "forged-trace".to_string();
    let err = EffectReceiptChain::verify_entries_integrity(&entries)
        .expect_err("tampered entry must fail");
    assert!(
        matches!(err, EffectReceiptError::ChainIntegrity { index: 2, .. }),
        "tampered receipt must fail at its recorded index, got {err:?}"
    );
}

#[test]
fn tampering_with_chain_linkage_fields_breaks_integrity() {
    let (_dir, cas) = store();
    let h = cas.put(b"x").expect("put");
    let chain = allowed_chain(&h, 4);

    let mut entries = chain.entries().to_vec();
    entries[1].prev_chain_hash = entries[0].prev_chain_hash.clone();
    assert!(matches!(
        EffectReceiptChain::verify_entries_integrity(&entries),
        Err(EffectReceiptError::ChainIntegrity { index: 1, .. })
    ));

    let mut entries = chain.entries().to_vec();
    entries[2].chain_hash = entries[1].chain_hash.clone();
    assert!(matches!(
        EffectReceiptChain::verify_entries_integrity(&entries),
        Err(EffectReceiptError::ChainIntegrity { index: 2, .. })
    ));

    let mut entries = chain.entries().to_vec();
    entries[2].index = 99;
    assert!(matches!(
        EffectReceiptChain::verify_entries_integrity(&entries),
        Err(EffectReceiptError::ChainIntegrity { index: 2, .. })
    ));
}

#[test]
fn cas_len_excludes_orphan_temp_files() {
    let (dir, cas) = store();
    let hash = cas.put(b"a real committed blob").expect("put");
    assert_eq!(cas.len().expect("len"), 1);
    // Drop an orphan temp file (as an interrupted write would) into the shard
    // dir; len() must still report exactly one stored blob.
    let hex = hash.as_str().strip_prefix("sha256:").expect("prefix");
    let shard = dir.path().join(&hex[..2]);
    std::fs::write(shard.join(".orphan.42.7.tmp"), b"partial").expect("orphan");
    assert_eq!(
        cas.len().expect("len"),
        1,
        "orphan temp files must not be counted as stored blobs"
    );
}

#[test]
fn malformed_content_hash_is_rejected() {
    assert!(matches!(
        ContentHash::parse("not-a-hash"),
        Err(CasError::MalformedHash { .. })
    ));
    let good = content_hash(b"ok");
    assert_eq!(ContentHash::parse(good.as_str()).expect("parse"), good);
}

#[test]
fn allowed_receipt_missing_result_is_rejected_on_append() {
    let (_dir, cas) = store();
    let h = cas.put(b"y").expect("put");
    let mut bogus = EffectReceipt::allowed(
        0,
        "t",
        EffectKind::FsWrite,
        "cap",
        h.clone(),
        h.clone(),
        h.clone(),
        h.clone(),
        0,
    );
    bogus.result_hash = None; // corrupt the invariant
    let mut chain = EffectReceiptChain::new();
    assert!(matches!(
        chain.append(bogus),
        Err(EffectReceiptError::AllowedMissingHash { .. })
    ));
}

#[test]
fn denied_receipt_with_result_is_rejected_on_append() {
    let (_dir, cas) = store();
    let h = cas.put(b"denied bytes must not exist").expect("put");
    let mut bogus = EffectReceipt::denied(
        0,
        "t",
        EffectKind::HttpRequest,
        "ssrf_policy: denied",
        h.clone(),
        h.clone(),
        0,
    );
    bogus.result_hash = Some(h);
    let mut chain = EffectReceiptChain::new();
    assert!(matches!(
        chain.append(bogus),
        Err(EffectReceiptError::DeniedHasHash {
            field: "result_hash"
        })
    ));
}

#[test]
fn cas_capacity_allows_dedup_but_rejects_new_blob() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cas = ContentAddressedStore::with_limits(dir.path(), 1024, 1).expect("open cas");

    let first = cas.put(b"same").expect("first put");
    let second = cas.put(b"same").expect("dedup put");
    assert_eq!(first, second, "dedup must not consume capacity");
    assert_eq!(cas.len().expect("len"), 1);

    assert!(matches!(
        cas.put(b"different"),
        Err(CasError::CapacityExceeded { max: 1 })
    ));
}
