#![no_main]

//! Fuzz the `BlockedProofRehydrationInput` deserialization + planning seam.
//!
//! Background. `bd-c9hho.3` (commit `991675b2`) introduced
//! `BlockedProofRehydrationInput` plus the
//! `build_blocked_proof_rehydration_plan` builder. The struct derives
//! `Deserialize` and is meant to be ingested from JSON: it carries
//! attacker-influenced strings (`bead_id`, `deferred_command`,
//! `referenced_paths[i].path`, `sibling_blockers[i].summary`,
//! `latest_blocker_comment`) plus a fully-public numeric envelope
//! (`now_ms`, `max_blocker_age_ms`, the `rch_snapshot` quintuple).
//! Validation lives at the planner entry (`validate_rehydration_input`),
//! not the deserializer. Three review-fixes have already landed on the
//! validator (`179dcb35` control-char rejection; `bc4563bb` `<=`/`>`
//! boundary tighten on `validation_lane_is_safe` and `stale_age`;
//! `0ae5a4de` fail-closed-vs-duplicate ordering); this harness pins the
//! post-fix invariant set so a future review patch that touches the
//! validator or the classifier cannot regress without flagging.
//!
//! Harness shape mirrors `fuzz_audience_token_deserialize`:
//!   (A) wholly arbitrary bytes through serde_json — panic-freedom only;
//!   (B) a structurally valid template JSON with one targeted field
//!       swapped for attacker-controlled bytes, biased toward the
//!       validator's text-and-control-char seam;
//!   (C) a populated `blocked_beads` array exercising
//!       `build_blocked_proof_rehydration_plan` end-to-end on every
//!       successfully-deserialized fixture, asserting the plan-level
//!       invariants the validator guarantees.

use arbitrary::Arbitrary;
use frankenengine_node::ops::validation_recovery_planner::{
    BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION, BlockedProofRehydrationCandidate,
    BlockedProofRehydrationInput, BlockedProofRehydrationPlan,
    build_blocked_proof_rehydration_plan,
};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 32 * 1024;
const MAX_BEADS: usize = 16;

#[derive(Debug, Arbitrary)]
struct RehydrationFuzzCase {
    raw_json: Vec<u8>,
    field_under_attack: AttackField,
    poison: Vec<u8>,
    bead_count_hint: u8,
    now_ms: u64,
    max_blocker_age_ms: u64,
    rch_quintuple: [u32; 5],
    agent_mail_healthy: bool,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum AttackField {
    SchemaVersion,
    BeadId,
    DeferredCommand,
    ReferencedPath,
    BlockerSummary,
    LatestBlockerComment,
    ProofCacheHitBead,
    CoalescedCommand,
}

fuzz_target!(|case: RehydrationFuzzCase| {
    // (A) Wholly arbitrary bytes — serde_json must never panic, regardless
    //     of input. Successful parses additionally exercise the planner.
    let mut raw = case.raw_json.clone();
    if raw.len() > MAX_RAW_BYTES {
        raw.truncate(MAX_RAW_BYTES);
    }
    if let Ok(input) = serde_json::from_slice::<BlockedProofRehydrationInput>(&raw) {
        let _ = drive_planner(&input);
    }

    // (B) Targeted JSON template with one poisoned field.
    if let Some(template) = build_poisoned_input_json(&case) {
        if let Ok(input) = serde_json::from_slice::<BlockedProofRehydrationInput>(template.as_bytes())
        {
            let _ = drive_planner(&input);
        }
    }
});

fn drive_planner(input: &BlockedProofRehydrationInput) {
    match build_blocked_proof_rehydration_plan(input) {
        Ok(plan) => assert_plan_invariants(input, &plan),
        Err(_) => {
            // Any well-formed validator rejection is acceptable. The
            // panic-freedom invariant is what the harness pins.
        }
    }
}

fn assert_plan_invariants(input: &BlockedProofRehydrationInput, plan: &BlockedProofRehydrationPlan) {
    // Plan schema version must match the module constant; otherwise the
    // builder is emitting a value that downstream consumers cannot key on.
    assert_eq!(
        plan.schema_version, BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION,
        "plan.schema_version must match the module-level constant"
    );
    // `generated_at_ms` is the caller-supplied `now_ms`; the builder
    // must not silently rewrite it (a clock-rewrite bug would invalidate
    // every downstream replay-fingerprint claim).
    assert_eq!(
        plan.generated_at_ms, input.now_ms,
        "plan.generated_at_ms must equal input.now_ms"
    );
    // Candidates are 1:1 with `blocked_beads` (after de-duplication of
    // the same bead_id submitting twice is NOT performed here per spec;
    // every accepted bead becomes a candidate).
    assert_eq!(
        plan.candidates.len(),
        input.blocked_beads.len(),
        "plan.candidates len must match blocked_beads len"
    );
    for candidate in &plan.candidates {
        assert_candidate_invariants(candidate);
    }
}

fn assert_candidate_invariants(candidate: &BlockedProofRehydrationCandidate) {
    // Every candidate must carry the same module-level schema version.
    assert_eq!(
        candidate.schema_version, BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION,
        "candidate.schema_version must match the module constant"
    );
    // `command_digest` and `decision_digest` are computed via
    // `digest_rehydration_command` / `digest_rehydration_candidate` which
    // emit `sha256:` prefixes; pin the prefix invariant.
    assert!(
        candidate.command_digest.starts_with("sha256:"),
        "command_digest must carry the sha256: prefix, got {:?}",
        candidate.command_digest
    );
    assert!(
        candidate.decision_digest.starts_with("sha256:"),
        "decision_digest must carry the sha256: prefix, got {:?}",
        candidate.decision_digest
    );
    // The reason_code must be a non-empty stable identifier.
    assert!(
        !candidate.reason_code.is_empty(),
        "candidate.reason_code must be non-empty"
    );
    // `bounded_rehydration_snippet` strips control chars and caps at 180
    // chars. The post-fix invariant is: snippet contains no control
    // characters under any input. Regressing this means an attacker can
    // stamp a newline into operator-facing output via the snippet seam.
    assert!(
        !candidate.evidence_snippet.chars().any(char::is_control),
        "evidence_snippet must not contain control characters"
    );
    assert!(
        candidate.evidence_snippet.chars().count() <= 180,
        "evidence_snippet must be capped at 180 chars (got {})",
        candidate.evidence_snippet.chars().count()
    );
}

fn build_poisoned_input_json(case: &RehydrationFuzzCase) -> Option<String> {
    let poison = poison_string(&case.poison);
    let bead_count = (case.bead_count_hint as usize % (MAX_BEADS + 1)).max(1);
    let mut beads = Vec::with_capacity(bead_count);
    for idx in 0..bead_count {
        beads.push(seed_bead_json(&format!("bd-{idx:04}")));
    }

    let mut input = serde_json::json!({
        "schema_version": BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION,
        "now_ms": case.now_ms,
        "max_blocker_age_ms": case.max_blocker_age_ms.max(1),
        "rch_snapshot": {
            "active_cargo_processes": case.rch_quintuple[0],
            "max_active_cargo_processes": case.rch_quintuple[1],
            "queue_depth": case.rch_quintuple[2],
            "max_queue_depth": case.rch_quintuple[3],
            "available_workers": case.rch_quintuple[4],
        },
        "agent_mail_healthy": case.agent_mail_healthy,
        "proof_cache_hit_beads": [],
        "coalesced_commands": [],
        "blocked_beads": beads,
    });

    apply_poison(&mut input, case.field_under_attack, &poison);
    serde_json::to_string(&input).ok()
}

fn apply_poison(input: &mut serde_json::Value, field: AttackField, poison: &str) {
    let poison_value = serde_json::Value::String(poison.to_string());
    match field {
        AttackField::SchemaVersion => {
            input["schema_version"] = poison_value;
        }
        AttackField::BeadId => {
            if let Some(bead) = input["blocked_beads"]
                .as_array_mut()
                .and_then(|arr| arr.get_mut(0))
            {
                bead["bead_id"] = poison_value;
            }
        }
        AttackField::DeferredCommand => {
            if let Some(bead) = input["blocked_beads"]
                .as_array_mut()
                .and_then(|arr| arr.get_mut(0))
            {
                bead["deferred_command"] = poison_value;
            }
        }
        AttackField::ReferencedPath => {
            if let Some(bead) = input["blocked_beads"]
                .as_array_mut()
                .and_then(|arr| arr.get_mut(0))
            {
                bead["referenced_paths"] = serde_json::json!([
                    { "path": poison_value, "exists": true }
                ]);
            }
        }
        AttackField::BlockerSummary => {
            if let Some(bead) = input["blocked_beads"]
                .as_array_mut()
                .and_then(|arr| arr.get_mut(0))
            {
                bead["sibling_blockers"] = serde_json::json!([
                    { "bead_id": "bd-blocker", "status": "open", "summary": poison_value }
                ]);
            }
        }
        AttackField::LatestBlockerComment => {
            if let Some(bead) = input["blocked_beads"]
                .as_array_mut()
                .and_then(|arr| arr.get_mut(0))
            {
                bead["latest_blocker_comment"] = poison_value;
            }
        }
        AttackField::ProofCacheHitBead => {
            input["proof_cache_hit_beads"] = serde_json::json!([poison_value]);
        }
        AttackField::CoalescedCommand => {
            input["coalesced_commands"] = serde_json::json!([poison_value]);
        }
    }
}

fn seed_bead_json(bead_id: &str) -> serde_json::Value {
    serde_json::json!({
        "bead_id": bead_id,
        "state": "blocked",
        "priority": 2_u8,
        "assignee": "ScarletCanyon",
        "updated_at_ms": 1_000_u64,
        "deferred_command": "rch exec -- cargo test -p frankenengine-node fuzz_seed",
        "referenced_paths": [
            { "path": "crates/franken-node/tests/validation_proof_cache.rs", "exists": true }
        ],
        "sibling_blockers": [],
        "latest_blocker_comment": "fuzz seed comment",
        "source_only_allowed": false,
    })
}

fn poison_string(bytes: &[u8]) -> String {
    // UTF-8-safe poison that exercises the control-char + length seams.
    let cap_budget = 1024;
    let mut out = String::with_capacity(bytes.len().min(cap_budget));
    for byte in bytes.iter().copied() {
        if out.len() >= cap_budget {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&[byte]) {
            out.push_str(s);
        }
    }
    if out.is_empty() {
        out.push('\n');
    }
    out
}
