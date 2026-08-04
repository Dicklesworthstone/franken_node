//! bd-5r99w.10 — differential + metamorphic replay-fidelity oracle.
//!
//! bd-5r99w.3 made `incident replay`'s decision-sequence recompute load-bearing
//! (it had been a release-build self-compare that cloned the manifest hash into
//! the verdict and could never diverge). Wiring the recompute is necessary but
//! not sufficient; this oracle proves the verdict is *faithful* (a re-derivation
//! of the recorded decisions) and *representation-invariant*, and that removing
//! the real recompute makes the suite go RED.
//!
//! Properties asserted (each logs one JSONL line per phase under a shared
//! trace-id so a `--nocapture` run yields a record→replay→verify trace):
//!
//! * **Differential / identical** — a faithfully generated, signed bundle
//!   replays as `matched` with `replayed == expected` and the full event count.
//! * **Metamorphic / serialization-invariant** — a serialize→deserialize
//!   round-trip (real file I/O) preserves the verdict and the recomputed hash.
//! * **Metamorphic / signer-invariant** — re-signing the same bundle under a
//!   different Ed25519 key yields the identical replay verdict and hash; the
//!   verdict is a function of the recorded decisions, not the signer.
//! * **Differential / mutation ⇒ diverged (self-compare killer)** — mutating
//!   ANY recorded decision (an event payload, a policy-eval decision, the
//!   initial state, or the policy version) flips the recomputed verdict to
//!   non-matched. A clone-the-manifest-hash self-compare would stay `matched`
//!   here, so this fails RED if bd-5r99w.3 ever regresses.
//! * **Fail-closed** — tampering with a *signed* bundle (without resealing) and
//!   reordering its chunks are both rejected by the trusted replay path.

use frankenengine_node::supply_chain::artifact_signing::KeyId;
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, ReplayBundleError, ReplayBundleSigningMaterial,
    generate_replay_bundle, read_bundle_from_path_with_trusted_key, recompute_replay_verdict,
    replay_bundle_with_trusted_keys, sign_replay_bundle, write_bundle_to_path_with_trusted_key,
};
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A single-field mutator applied to a recorded bundle to seed a divergence.
type BundleMutator = fn(&mut ReplayBundle);

/// Emit one canonical JSONL log line to stderr, correlated by `trace_id`.
fn log_phase(trace_id: &str, phase: &str, fields: Value) {
    let line = json!({
        "trace_id": trace_id,
        "phase": phase,
        "surface": "replay-fidelity-oracle",
        "fields": fields,
    });
    eprintln!("{line}");
}

/// A recorded incident timeline with a real policy-eval *decision* in it, so we
/// can mutate a genuine recorded decision and observe the verdict flip.
fn recorded_events() -> Vec<RawEvent> {
    vec![
        RawEvent::new(
            "2026-03-01T09:15:00.000001Z",
            EventType::ExternalSignal,
            json!({
                "detector": "extension-reputation",
                "severity": "high",
                "signal": "publisher-authority-escalation",
            }),
        )
        .with_state_snapshot(json!({
            "epoch": 91_u64,
            "runtime_profile": "balanced",
            "active_policies": ["extension-quarantine", "revocation-freshness"],
        }))
        .with_policy_version("replay-fidelity-baseline-2026-03"),
        RawEvent::new(
            "2026-03-01T09:15:00.000200Z",
            EventType::PolicyEval,
            json!({
                "confidence": 91_u64,
                "decision": "quarantine",
                "rule_id": "policy.extension.high-impact",
            }),
        )
        .with_causal_parent(1),
        RawEvent::new(
            "2026-03-01T09:15:00.000400Z",
            EventType::OperatorAction,
            json!({
                "action": "acknowledge",
                "operator": "ops-1",
            }),
        )
        .with_causal_parent(2),
    ]
}

fn signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn trusted_key_id(key: &ed25519_dalek::SigningKey) -> String {
    KeyId::from_verifying_key(&key.verifying_key()).to_string()
}

/// Build a faithfully signed bundle plus its trusted key id.
fn signed_bundle(incident_id: &str, seed: u8) -> TestResult<(ReplayBundle, String)> {
    let mut bundle = generate_replay_bundle(incident_id, &recorded_events())?;
    let key = signing_key(seed);
    sign_replay_bundle(
        &mut bundle,
        &ReplayBundleSigningMaterial {
            signing_key: &key,
            key_source: "replay-fidelity-oracle",
            signing_identity: "bd-5r99w.10-oracle",
        },
    )?;
    Ok((bundle, trusted_key_id(&key)))
}

#[test]
fn faithful_bundle_replays_as_identical() -> TestResult {
    let trace = "replay-fidelity-identical";
    log_phase(trace, "record", json!({"incident": "INC-RFO-IDENTICAL"}));
    let (bundle, key_id) = signed_bundle("INC-RFO-IDENTICAL", 0x11)?;

    log_phase(trace, "replay", json!({"events": bundle.timeline.len()}));
    let outcome = replay_bundle_with_trusted_keys(&bundle, &[key_id])?;

    log_phase(
        trace,
        "verify",
        json!({"matched": outcome.matched, "event_count": outcome.event_count}),
    );
    assert!(
        outcome.matched,
        "a faithful bundle must replay as Identical"
    );
    assert_eq!(
        outcome.replayed_sequence_hash, outcome.expected_sequence_hash,
        "recomputed hash must equal the recorded manifest hash"
    );
    assert_eq!(
        outcome.event_count,
        bundle.timeline.len(),
        "every recorded event must be replayed"
    );
    Ok(())
}

#[test]
fn verdict_is_invariant_under_serialization_roundtrip() -> TestResult {
    let trace = "replay-fidelity-serde";
    let (bundle, key_id) = signed_bundle("INC-RFO-SERDE", 0x22)?;
    log_phase(trace, "record", json!({"incident": "INC-RFO-SERDE"}));

    let direct = replay_bundle_with_trusted_keys(&bundle, std::slice::from_ref(&key_id))?;

    // Metamorphic transform: a full serialize → deserialize round-trip via real
    // file I/O must not change the verdict or the recomputed hash.
    let workspace = TempDir::new()?;
    let path = workspace.path().join("bundle.fnbundle.json");
    write_bundle_to_path_with_trusted_key(&bundle, &path, &key_id)?;
    let reloaded = read_bundle_from_path_with_trusted_key(&path, Some(&key_id))?;
    log_phase(trace, "replay", json!({"transform": "serialize-roundtrip"}));
    let round_tripped = replay_bundle_with_trusted_keys(&reloaded, std::slice::from_ref(&key_id))?;

    log_phase(
        trace,
        "verify",
        json!({
            "direct_matched": direct.matched,
            "roundtrip_matched": round_tripped.matched,
            "hash_stable": direct.replayed_sequence_hash == round_tripped.replayed_sequence_hash,
        }),
    );
    assert!(direct.matched && round_tripped.matched);
    assert_eq!(
        direct.replayed_sequence_hash, round_tripped.replayed_sequence_hash,
        "verdict hash must be invariant under serialization round-trip"
    );
    Ok(())
}

#[test]
fn verdict_is_invariant_under_signer_identity() -> TestResult {
    let trace = "replay-fidelity-signer";
    let (bundle_a, key_a) = signed_bundle("INC-RFO-SIGNER", 0x33)?;
    // Re-sign a freshly built identical bundle under a DIFFERENT key.
    let (bundle_b, key_b) = signed_bundle("INC-RFO-SIGNER", 0x44)?;
    assert_ne!(key_a, key_b, "the two signer key ids must differ");

    let a = replay_bundle_with_trusted_keys(&bundle_a, &[key_a])?;
    let b = replay_bundle_with_trusted_keys(&bundle_b, &[key_b])?;
    log_phase(
        trace,
        "verify",
        json!({"a_matched": a.matched, "b_matched": b.matched}),
    );
    assert!(a.matched && b.matched);
    assert_eq!(
        a.replayed_sequence_hash, b.replayed_sequence_hash,
        "the replay verdict must depend on the recorded decisions, not the signer"
    );
    Ok(())
}

#[test]
fn mutating_any_recorded_decision_flips_verdict_to_diverged() -> TestResult {
    let trace = "replay-fidelity-mutation";
    let (bundle, _key_id) = signed_bundle("INC-RFO-MUTATION", 0x55)?;

    // Baseline: the recompute (without the transport gate) agrees with the manifest.
    let baseline = recompute_replay_verdict(&bundle)?;
    log_phase(
        trace,
        "replay",
        json!({"baseline_matched": baseline.matched}),
    );
    assert!(
        baseline.matched,
        "the faithful recompute must match the manifest hash"
    );

    // Each mutation targets a distinct kind of recorded decision. The recompute
    // re-derives the sequence hash from the (mutated) timeline/state/policy, so a
    // genuine recompute MUST diverge. A clone-the-manifest self-compare would
    // stay matched here — this is the permanent self-compare regression guard.
    let mutators: Vec<(&str, BundleMutator)> = vec![
        ("event_payload", |b| {
            b.timeline[0].payload = json!({"detector": "TAMPERED"});
        }),
        ("policy_decision", |b| {
            b.timeline[1].payload = json!({
                "confidence": 91_u64,
                "decision": "observe", // flipped from "quarantine"
                "rule_id": "policy.extension.high-impact",
            });
        }),
        ("initial_state", |b| {
            b.initial_state_snapshot = json!({"epoch": 0_u64, "runtime_profile": "tampered"});
        }),
        ("policy_version", |b| {
            b.policy_version = "tampered-policy-version".to_string();
        }),
    ];

    for (label, mutate) in mutators {
        let mut tampered = bundle.clone();
        mutate(&mut tampered);
        let outcome = recompute_replay_verdict(&tampered)?;
        log_phase(
            trace,
            "verify",
            json!({"mutation": label, "matched": outcome.matched}),
        );
        assert!(
            !outcome.matched,
            "mutating `{label}` must flip the verdict to diverged (recompute is load-bearing, not a self-compare)"
        );
        assert_ne!(
            outcome.replayed_sequence_hash, outcome.expected_sequence_hash,
            "mutating `{label}` must make the recomputed hash differ from the stale manifest hash"
        );
    }
    Ok(())
}

#[test]
fn tampering_and_chunk_reorder_are_rejected_by_trusted_replay() -> TestResult {
    let trace = "replay-fidelity-failclosed";
    let (bundle, key_id) = signed_bundle("INC-RFO-FAILCLOSED", 0x66)?;

    // Tamper a recorded decision WITHOUT resealing: the trusted path must reject
    // it (integrity/manifest gate) rather than silently replaying.
    let mut tampered = bundle.clone();
    tampered.timeline[0].payload = json!({"detector": "TAMPERED"});
    let tampered_err =
        replay_bundle_with_trusted_keys(&tampered, std::slice::from_ref(&key_id)).unwrap_err();
    log_phase(
        trace,
        "verify",
        json!({"tamper_rejected": format!("{tampered_err:?}")}),
    );
    assert!(
        matches!(
            tampered_err,
            ReplayBundleError::IntegrityMismatch
                | ReplayBundleError::ManifestMismatch
                | ReplayBundleError::CreatedAtMismatch
                | ReplayBundleError::BundleIdMismatch
        ),
        "tampered bundle must be rejected fail-closed, got {tampered_err:?}"
    );

    // Reordering chunks (a representation change OUTSIDE documented bounds) must
    // also be rejected rather than changing the verdict.
    if bundle.chunks.len() >= 2 {
        let mut reordered = bundle.clone();
        reordered.chunks.swap(0, 1);
        let reorder_err =
            replay_bundle_with_trusted_keys(&reordered, std::slice::from_ref(&key_id)).unwrap_err();
        log_phase(
            trace,
            "verify",
            json!({"reorder_rejected": format!("{reorder_err:?}")}),
        );
        assert!(
            matches!(
                reorder_err,
                ReplayBundleError::ChunkLayoutMismatch
                    | ReplayBundleError::IntegrityMismatch
                    | ReplayBundleError::ManifestMismatch
            ),
            "chunk reorder must be rejected fail-closed, got {reorder_err:?}"
        );
    }
    Ok(())
}
