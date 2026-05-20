#![no_main]
#![forbid(unsafe_code)]

//! Fuzz the `BlockedProofRehydrationInput` JSON deserialization +
//! `build_blocked_proof_rehydration_plan` pipeline introduced by
//! bd-c9hho.3.
//!
//! The input is a publisher of trust-sensitive operator state: bead
//! summaries (paths, comments, deferred commands), an RCH snapshot, and
//! proof-cache / coalescer hints. It is constructed from `br` JSONL
//! output, which any agent in the swarm can write. A panic or
//! algorithmic blow-up inside `build_blocked_proof_rehydration_plan`
//! would translate to a DoS against the validation lane.
//!
//! Invariants pinned here (after a successful parse + plan build):
//!   - `plan.schema_version` is the constant the module advertises.
//!   - `plan.generated_at_ms` equals the input's `now_ms`.
//!   - `plan.candidates.len() == input.blocked_beads.len()` (the
//!     classifier emits one candidate per blocked bead).
//!   - Every candidate's `bead_id` corresponds to an input bead.
//!   - Every candidate's `command_digest` and `decision_digest` are
//!     non-empty (the digest helpers are unconditional sites).
//!   - Re-serialising the plan and re-parsing it is lossless.

use frankenengine_node::ops::validation_recovery_planner::{
    build_blocked_proof_rehydration_plan, BlockedProofRehydrationInput,
    BlockedProofRehydrationPlan, BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Cap input to keep per-iteration cost bounded. The natural
    // JSONL-derived inputs in production stay well below this.
    if data.len() > 256 * 1024 {
        return;
    }

    let Ok(json_str) = str::from_utf8(data) else {
        return;
    };

    let Ok(input) = serde_json::from_str::<BlockedProofRehydrationInput>(json_str) else {
        return;
    };

    let Ok(plan) = build_blocked_proof_rehydration_plan(&input) else {
        // Planner errors are a valid outcome; we are only hunting for
        // panics and invariant violations on the success path.
        return;
    };

    assert_eq!(
        plan.schema_version, BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION,
        "plan must advertise the module's schema version constant"
    );
    assert_eq!(
        plan.generated_at_ms, input.now_ms,
        "plan must echo the caller-supplied now_ms"
    );
    assert_eq!(
        plan.candidates.len(),
        input.blocked_beads.len(),
        "classifier must emit one candidate per blocked bead"
    );

    let input_bead_ids: BTreeSet<&str> = input
        .blocked_beads
        .iter()
        .map(|bead| bead.bead_id.as_str())
        .collect();
    for candidate in &plan.candidates {
        assert!(
            input_bead_ids.contains(candidate.bead_id.as_str()),
            "every candidate's bead_id must match an input bead"
        );
        assert!(
            !candidate.command_digest.is_empty(),
            "command_digest must be non-empty after classification"
        );
        assert!(
            !candidate.decision_digest.is_empty(),
            "decision_digest must be non-empty after classification"
        );
    }

    // Round-trip: re-serialise + re-parse must succeed losslessly.
    let serialized = serde_json::to_string(&plan).expect("plan must serialize back to JSON");
    let reparsed: BlockedProofRehydrationPlan =
        serde_json::from_str(&serialized).expect("plan JSON must round-trip");
    assert_eq!(reparsed.schema_version, plan.schema_version);
    assert_eq!(reparsed.generated_at_ms, plan.generated_at_ms);
    assert_eq!(reparsed.candidates.len(), plan.candidates.len());
});
