#![no_main]

//! Fuzz harness for
//! `frankenengine_node::replay::time_travel_engine::WorkflowTrace::compute_digest_bytes`
//! at `crates/franken-node/src/replay/time_travel_engine.rs:649`.
//!
//! Background. `compute_digest_bytes` is the canonical-trace-digest SHA-256
//! preimage source for the time-travel replay engine. The digest seals
//! `(trace_id, workflow_name, steps, environment, schema_version)` into
//! a 32-byte canonical fingerprint; `validate()` (at :707) recomputes the
//! digest from the trace fields and compares against `self.trace_digest`,
//! rejecting any trace whose digest doesn't match. A regression that
//! drops a field from the preimage would let an attacker mutate that
//! field while preserving the digest — a forgery class on the replay
//! attestation path.
//!
//! The preimage is length-prefix-framed:
//!
//!   ```text
//!   "replay_trace_digest_v1:" ++
//!     len(trace_id) ++ trace_id ++
//!     len(workflow_name) ++ workflow_name ++
//!     len(schema_version) ++ schema_version ++
//!     <environment-framed bytes> ++
//!     len(steps) ++
//!     for step in steps:
//!       step.seq.to_le_bytes() ++
//!       step.timestamp_ns.to_le_bytes() ++
//!       len(input) ++ input ++
//!       len(output) ++ output ++
//!       <side_effects-framed bytes>
//!   ```
//!
//! Existing fuzz coverage of this preimage: **zero**. The `fuzz_replay_*`
//! family covers `ReplayBundle` parsing but never reaches the
//! time-travel-engine trace-digest builder. This harness fills the gap
//! and pins five invariants per call:
//!
//!   (A) **INV-TRACE-DIGEST-DETERMINISM**: identical inputs produce
//!       byte-identical 32-byte digest output. A regression that
//!       introduces a clock or RNG-dependent field into the preimage
//!       would break replay verification.
//!
//!   (B) **INV-TRACE-DIGEST-OUTPUT-SHAPE**: digest is always exactly
//!       32 bytes (SHA-256). Catches a truncated-output regression.
//!
//!   (C) **INV-TRACE-DIGEST-FIELD-SENSITIVITY**: flipping any scalar
//!       string field (trace_id, workflow_name, schema_version) MUST
//!       change the digest. Catches a field-dropped-from-preimage
//!       regression.
//!
//!   (D) **INV-TRACE-DIGEST-LENGTH-PREFIX**: ("ab", "cd") and
//!       ("a", "bcd") have identical concatenated content but
//!       different length prefixes; their digests MUST differ.
//!       Catches a regression that drops the length prefix on
//!       trace_id or workflow_name.
//!
//!   (E) **INV-TRACE-DIGEST-STEP-SENSITIVITY**: appending a single
//!       additional step MUST change the digest. Catches a
//!       regression that drops the steps[] iteration or the
//!       `steps.len()` length-prefix.

use arbitrary::Arbitrary;
use frankenengine_node::replay::time_travel_engine::{
    EnvironmentSnapshot, SideEffect, TraceStep, WorkflowTrace,
};
use libfuzzer_sys::fuzz_target;

const MAX_FIELD_BYTES: usize = 256;
const MAX_STEPS: usize = 16;
const MAX_BYTES_PER_FIELD: usize = 512;

#[derive(Debug, Arbitrary)]
struct ReplayTraceDigestFuzzCase {
    trace_id: String,
    workflow_name: String,
    schema_version: String,
    environment: EnvironmentSnapshot,
    steps: Vec<TraceStep>,
    flip_selector: u8,
    extra_step: TraceStep,
}

fuzz_target!(|case: ReplayTraceDigestFuzzCase| {
    let trace_id = bounded_str(&case.trace_id, MAX_FIELD_BYTES);
    let workflow_name = bounded_str(&case.workflow_name, MAX_FIELD_BYTES);
    let schema_version = bounded_str(&case.schema_version, MAX_FIELD_BYTES);
    let environment = bounded_environment(case.environment);
    let steps = bounded_steps(case.steps);

    // ── (A) Determinism ─────────────────────────────────────────────
    let first = WorkflowTrace::compute_digest_bytes(
        &trace_id,
        &workflow_name,
        &steps,
        &environment,
        &schema_version,
    );
    let second = WorkflowTrace::compute_digest_bytes(
        &trace_id,
        &workflow_name,
        &steps,
        &environment,
        &schema_version,
    );
    assert_eq!(
        first, second,
        "INV-TRACE-DIGEST-DETERMINISM violated: identical inputs produced \
         different digest bytes"
    );

    // ── (B) Output shape — type alone enforces [u8; 32]; pin the length anyway ─
    assert_eq!(
        first.len(),
        32,
        "INV-TRACE-DIGEST-OUTPUT-SHAPE violated: digest must be 32 bytes, got {}",
        first.len()
    );

    // ── (C) Field sensitivity ──────────────────────────────────────
    let flipped = match case.flip_selector % 3 {
        0 => WorkflowTrace::compute_digest_bytes(
            &flip_str(&trace_id),
            &workflow_name,
            &steps,
            &environment,
            &schema_version,
        ),
        1 => WorkflowTrace::compute_digest_bytes(
            &trace_id,
            &flip_str(&workflow_name),
            &steps,
            &environment,
            &schema_version,
        ),
        _ => WorkflowTrace::compute_digest_bytes(
            &trace_id,
            &workflow_name,
            &steps,
            &environment,
            &flip_str(&schema_version),
        ),
    };
    assert_ne!(
        first, flipped,
        "INV-TRACE-DIGEST-FIELD-SENSITIVITY violated: flipping scalar field \
         selector {} did not change the digest — a field was dropped from \
         the preimage",
        case.flip_selector % 3,
    );

    // ── (D) Length-prefix safety ────────────────────────────────────
    // ("ab", "cd") and ("a", "bcd") have identical concatenated content
    // but different length prefixes; their digests MUST differ.
    let split_a = WorkflowTrace::compute_digest_bytes(
        "ab",
        "cd",
        &steps,
        &environment,
        &schema_version,
    );
    let split_b = WorkflowTrace::compute_digest_bytes(
        "a",
        "bcd",
        &steps,
        &environment,
        &schema_version,
    );
    assert_ne!(
        split_a, split_b,
        "INV-TRACE-DIGEST-LENGTH-PREFIX violated: (\"ab\", \"cd\") collided \
         with (\"a\", \"bcd\") — length prefix was dropped from trace_id or \
         workflow_name"
    );

    // ── (E) Step sensitivity ────────────────────────────────────────
    let extra_step = bounded_step(case.extra_step);
    let mut extended_steps = steps.clone();
    extended_steps.push(extra_step);
    let extended_digest = WorkflowTrace::compute_digest_bytes(
        &trace_id,
        &workflow_name,
        &extended_steps,
        &environment,
        &schema_version,
    );
    assert_ne!(
        first, extended_digest,
        "INV-TRACE-DIGEST-STEP-SENSITIVITY violated: appending a step did \
         not change the digest — steps[] iteration or the len-prefix on \
         steps.len() was dropped"
    );
});

fn bounded_str(s: &str, max_bytes: usize) -> String {
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

fn bounded_environment(mut env: EnvironmentSnapshot) -> EnvironmentSnapshot {
    env.schema_version = bounded_str(&env.schema_version, MAX_FIELD_BYTES);
    env.platform = bounded_str(&env.platform, MAX_FIELD_BYTES);
    env.runtime_version = bounded_str(&env.runtime_version, MAX_FIELD_BYTES);
    // Bound env_vars at 8 entries with bounded keys + values
    let mut bounded_vars = std::collections::BTreeMap::new();
    for (key, value) in env.env_vars.into_iter().take(8) {
        bounded_vars.insert(
            bounded_str(&key, MAX_FIELD_BYTES),
            bounded_str(&value, MAX_FIELD_BYTES),
        );
    }
    env.env_vars = bounded_vars;
    env
}

fn bounded_steps(steps: Vec<TraceStep>) -> Vec<TraceStep> {
    steps
        .into_iter()
        .take(MAX_STEPS)
        .map(bounded_step)
        .collect()
}

fn bounded_step(mut step: TraceStep) -> TraceStep {
    step.input.truncate(MAX_BYTES_PER_FIELD);
    step.output.truncate(MAX_BYTES_PER_FIELD);
    step.side_effects.truncate(8);
    for effect in &mut step.side_effects {
        effect.kind = bounded_str(&effect.kind, MAX_FIELD_BYTES);
        effect.payload.truncate(MAX_BYTES_PER_FIELD);
    }
    step
}

#[allow(dead_code)]
fn _force_link_side_effect_type(_: &SideEffect) {}

/// Mutate a string so the post-flip value cannot equal the pre-flip value,
/// even when the input is the empty string.
fn flip_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(1));
    out.push('\u{00}');
    out.push_str(s);
    out
}
