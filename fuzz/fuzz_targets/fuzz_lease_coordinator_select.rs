#![no_main]

//! Fuzz harness for
//! `frankenengine_node::connector::lease_coordinator::select_coordinator`
//! at `crates/franken-node/src/connector/lease_coordinator.rs:139`. The
//! function deterministically selects a coordinator from a candidate
//! list via weighted SHA-256 — a regression that lets two replicas
//! select different coordinators for the same lease_id would split
//! consensus across the fleet.
//!
//! Existing fuzz coverage: **zero**.
//!
//! Five invariants pinned per call:
//!
//!   (A) **INV-LC-PANIC-FREE** — arbitrary inputs MUST NOT panic.
//!
//!   (B) **INV-LC-DETERMINISTIC** — same inputs invoked twice
//!       produce byte-identical selection.
//!
//!   (C) **INV-LC-ORDER-INDEPENDENT** — reversing the input
//!       candidate slice MUST produce the same selection (the
//!       function sorts internally before scoring).
//!
//!   (D) **INV-LC-SELECTED-IS-ELIGIBLE** — the `selected` node MUST
//!       be one of the candidates with weight > 0 AND a canonical
//!       node_id. Catches a regression where ineligible candidates
//!       slip into the scoring loop.
//!
//!   (E) **INV-LC-NO-ELIGIBLE-REJECTED** — when ALL candidates have
//!       weight=0 (or empty candidate list), `select_coordinator`
//!       MUST return `Err(NoCandidates)`. Catches a regression
//!       where the eligibility filter is dropped and a zero-weight
//!       candidate gets selected.

use arbitrary::Arbitrary;
use frankenengine_node::connector::lease_coordinator::{select_coordinator, CoordinatorCandidate};
use libfuzzer_sys::fuzz_target;

const MAX_CANDIDATES: usize = 16;
const MAX_NODE_ID_BYTES: usize = 128;
const MAX_LEASE_ID_BYTES: usize = 128;

#[derive(Debug, Arbitrary)]
struct LeaseCoordinatorFuzzCase {
    candidates: Vec<RawCandidate>,
    lease_id: String,
    trace_id: String,
}

#[derive(Debug, Arbitrary)]
struct RawCandidate {
    node_id: String,
    weight: u64,
}

fuzz_target!(|case: LeaseCoordinatorFuzzCase| {
    let candidates: Vec<CoordinatorCandidate> = case
        .candidates
        .iter()
        .take(MAX_CANDIDATES)
        .map(|r| CoordinatorCandidate {
            node_id: bounded(&r.node_id, MAX_NODE_ID_BYTES),
            weight: r.weight,
        })
        .collect();
    let lease_id = bounded(&case.lease_id, MAX_LEASE_ID_BYTES);
    let trace_id = bounded(&case.trace_id, MAX_LEASE_ID_BYTES);

    // ── (A) Panic-freedom: the call itself is the assertion ────────
    let first = select_coordinator(&candidates, &lease_id, &trace_id);

    // ── (B) Determinism: second call returns same selection ──────────
    let second = select_coordinator(&candidates, &lease_id, &trace_id);
    match (&first, &second) {
        (Ok(a), Ok(b)) => assert_eq!(
            a.selected, b.selected,
            "INV-LC-DETERMINISTIC violated: same input produced different selections"
        ),
        (Err(_), Err(_)) => { /* both fail identically — acceptable */ }
        (a, b) => panic!(
            "INV-LC-DETERMINISTIC violated: result variant differs across calls \
             (first={a:?}, second={b:?})"
        ),
    }

    // ── (C) Order-independence: reverse the candidates → same selection
    let mut reversed = candidates.clone();
    reversed.reverse();
    let reversed_result = select_coordinator(&reversed, &lease_id, &trace_id);
    match (&first, &reversed_result) {
        (Ok(a), Ok(b)) => assert_eq!(
            a.selected, b.selected,
            "INV-LC-ORDER-INDEPENDENT violated: reversed candidate order \
             produced a different selection (forward={:?} reversed={:?})",
            a.selected, b.selected
        ),
        (Err(_), Err(_)) => { /* both fail — acceptable */ }
        (a, b) => panic!(
            "INV-LC-ORDER-INDEPENDENT violated: reversal changed Ok/Err shape \
             (forward={a:?}, reversed={b:?})"
        ),
    }

    // ── (D) Selected is eligible (weight > 0 and original candidate)
    if let Ok(selection) = &first {
        let selected_id = &selection.selected;
        let matched = candidates
            .iter()
            .any(|c| &c.node_id == selected_id && c.weight > 0);
        assert!(
            matched,
            "INV-LC-SELECTED-IS-ELIGIBLE violated: selected={selected_id:?} is not \
             in the input with weight > 0"
        );
    }

    // ── (E) All-zero-weight or empty → Err
    let no_eligible = candidates.iter().all(|c| c.weight == 0);
    if no_eligible {
        assert!(
            first.is_err(),
            "INV-LC-NO-ELIGIBLE-REJECTED violated: all-zero-weight (or empty) \
             input returned Ok({first:?})"
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
