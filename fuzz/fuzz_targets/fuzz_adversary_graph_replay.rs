#![no_main]

//! Fuzz harness for
//! `frankenengine_node::security::adversary_graph::{AdversaryGraph::ingest,
//! AdversaryGraph::replay_from, AdversaryGraph::export_state_hash,
//! AdversaryGraph::get_risk_posterior, AdversaryObservation::new}` at
//! `crates/franken-node/src/security/adversary_graph.rs:107`.
//!
//! Background. `AdversaryGraph` is the Bayesian principal-risk
//! posterior tracker the runtime consults during admission decisions
//! and incident escalation. Each `AdversaryObservation` carries an
//! attacker-controllable `likelihood_compromise: f64` and
//! `evidence_weight: u64`; the graph aggregates these via Beta-prior
//! conjugate updates into `(alpha, beta)` state, then exposes a
//! posterior `f64` in `[0.0, 1.0]` per principal.
//!
//! Two production paths that downstream consumers depend on:
//!
//!   - `replay_from(&[obs])` MUST produce a graph state byte-identical
//!     to `AdversaryGraph::new()` followed by sequential `ingest` calls
//!     on the same observations. Otherwise, snapshot restore on a node
//!     restart would diverge from live-state aggregation.
//!
//!   - `export_state_hash()` MUST be deterministic on identical state.
//!     Otherwise, two replicas seeing the same observations would emit
//!     different state hashes, breaking convergence verification.
//!
//! Existing fuzz coverage of this primitive: **zero**.
//!
//! Four invariants pinned per call:
//!
//!   (A) **INV-ADV-OBSERVATION-NAN-REJECT**: `AdversaryObservation::new`
//!       MUST reject any non-finite `likelihood_compromise` (NaN, ±Inf)
//!       via `validate_observation`. The harness only ingests
//!       successfully-constructed observations; observations the
//!       constructor rejects are skipped, asserting the rejection is
//!       structural rather than accidental.
//!
//!   (B) **INV-ADV-REPLAY-DETERMINISM**: `replay_from(obs)` and
//!       sequential `ingest(obs[i])` produce byte-identical
//!       `export_state_hash()` output. Catches a regression where the
//!       two paths diverge (e.g., a refactor that changes per-call
//!       prior reset).
//!
//!   (C) **INV-ADV-STATE-HASH-DETERMINISM**: `export_state_hash()`
//!       invoked twice on the same graph returns byte-identical output.
//!       Catches a clock or RNG leak into the hash preimage.
//!
//!   (D) **INV-ADV-POSTERIOR-BOUNDED-AND-FINITE**: every
//!       `get_risk_posterior(principal_id)` result MUST be finite and
//!       in `[0.0, 1.0]`. Catches a regression that drops the Beta
//!       normalization or lets a NaN propagate through aggregation.

use arbitrary::Arbitrary;
use frankenengine_node::security::adversary_graph::{AdversaryGraph, AdversaryObservation};
use libfuzzer_sys::fuzz_target;

const MAX_OBSERVATIONS: usize = 32;
const MAX_FIELD_BYTES: usize = 64;

#[derive(Debug, Arbitrary)]
struct AdversaryGraphFuzzCase {
    observations: Vec<RawObservation>,
}

#[derive(Debug, Arbitrary)]
struct RawObservation {
    principal_id: String,
    likelihood_compromise: f64,
    evidence_weight: u64,
    evidence_ref: String,
    trace_id: String,
}

fuzz_target!(|case: AdversaryGraphFuzzCase| {
    // ── (A) Build the observation list, letting validate_observation reject
    //     non-finite likelihoods + over-cap weights structurally.
    let observations: Vec<AdversaryObservation> = case
        .observations
        .iter()
        .take(MAX_OBSERVATIONS)
        .filter_map(|raw| {
            AdversaryObservation::new(
                bounded(&raw.principal_id, MAX_FIELD_BYTES),
                raw.likelihood_compromise,
                raw.evidence_weight,
                bounded(&raw.evidence_ref, MAX_FIELD_BYTES),
                bounded(&raw.trace_id, MAX_FIELD_BYTES),
            )
            .ok()
        })
        .collect();

    // Each constructed observation's likelihood MUST be finite
    // (validate_observation rejects NaN/Inf). Pin that contract.
    for obs in &observations {
        assert!(
            obs.likelihood_compromise.is_finite(),
            "INV-ADV-OBSERVATION-NAN-REJECT violated: AdversaryObservation::new \
             constructed an observation with non-finite likelihood_compromise={} \
             — validate_observation no longer rejects non-finite inputs",
            obs.likelihood_compromise
        );
    }

    // ── (B) replay_from equivalence to sequential ingest ───────────
    let replayed = AdversaryGraph::replay_from(&observations).unwrap_or_else(|err| {
        panic!(
            "INV-ADV-REPLAY-DETERMINISM violated: replay_from rejected a \
             sequence of validate-passing observations: {err:?}"
        )
    });
    let mut sequential = AdversaryGraph::new();
    for obs in &observations {
        sequential
            .ingest(obs)
            .expect("ingest must accept observations that AdversaryObservation::new accepted");
    }
    let replayed_hash = replayed.export_state_hash();
    let sequential_hash = sequential.export_state_hash();
    assert_eq!(
        replayed_hash, sequential_hash,
        "INV-ADV-REPLAY-DETERMINISM violated: replay_from + ingest sequence \
         produced different state hashes for the same observation list \
         ({} observations)",
        observations.len()
    );

    // ── (C) state_hash is deterministic across calls on the same state ──
    let replayed_hash_again = replayed.export_state_hash();
    assert_eq!(
        replayed_hash, replayed_hash_again,
        "INV-ADV-STATE-HASH-DETERMINISM violated: export_state_hash returned \
         different hex on two calls against the same graph state"
    );

    // ── (D) Every posterior is finite + in [0.0, 1.0] ──────────────
    for posterior in replayed.posteriors() {
        let p = posterior.posterior;
        assert!(
            p.is_finite(),
            "INV-ADV-POSTERIOR-BOUNDED-AND-FINITE violated: principal {:?} \
             posterior is non-finite ({})",
            posterior.principal_id,
            p
        );
        assert!(
            (0.0..=1.0).contains(&p),
            "INV-ADV-POSTERIOR-BOUNDED-AND-FINITE violated: principal {:?} \
             posterior {} outside [0.0, 1.0] — Beta normalization was bypassed",
            posterior.principal_id,
            p
        );

        // Cross-check that get_risk_posterior agrees with the snapshot
        // walk; a divergence would mean the two query paths diverged.
        let direct = replayed.get_risk_posterior(&posterior.principal_id);
        assert_eq!(
            direct.to_bits(),
            p.to_bits(),
            "INV-ADV-POSTERIOR-BOUNDED-AND-FINITE violated: get_risk_posterior \
             returned {direct} but posteriors() snapshot for {} returned {p}",
            posterior.principal_id
        );
    }
});

fn bounded(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut out = String::with_capacity(max_bytes);
    for ch in s.chars() {
        if out.len().saturating_add(ch.len_utf8()) > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}
