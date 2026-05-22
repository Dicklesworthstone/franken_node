#![no_main]

//! Fuzz harness for
//! `frankenengine_node::policy::hardening_state_machine::HardeningStateMachine::{
//! escalate, replay_transitions}` at
//! `crates/franken-node/src/policy/hardening_state_machine.rs:284`
//! and `:370`. The state machine encodes the runtime's
//! hardening-level monotonicity contract: escalation MUST move
//! strictly upward (Baseline < Standard < Enhanced < Maximum <
//! Critical); any same-or-lower target MUST fail with
//! `HardeningError::IllegalRegression`. A regression that admits a
//! lower target would let an attacker downgrade hardening without
//! the governance-rollback artifact path.
//!
//! Existing fuzz coverage of this state machine: **zero**.
//!
//! Four invariants pinned per call:
//!
//!   (A) **INV-HARDEN-MONOTONIC** — escalate(target) succeeds iff
//!       target > current_level. Catches a regression that drops
//!       the `target <= self.current_level` rejection at
//!       hardening_state_machine.rs:290.
//!
//!   (B) **INV-HARDEN-CURRENT-ADVANCES** — every successful
//!       escalation advances `current_level()` to the target.
//!
//!   (C) **INV-HARDEN-LOG-MONOTONIC** — the transition_log records
//!       to_level values that are strictly increasing across
//!       successful escalations.
//!
//!   (D) **INV-HARDEN-REPLAY-EQUIVALENCE** — replaying the
//!       transition_log via `replay_transitions(log)` reconstructs a
//!       state machine with the same `current_level()` and the same
//!       `transition_count()` as the live machine that produced the
//!       log.

use arbitrary::Arbitrary;
use frankenengine_node::policy::hardening_state_machine::{
    HardeningError, HardeningLevel, HardeningStateMachine,
};
use libfuzzer_sys::fuzz_target;

const MAX_ESCALATIONS: usize = 32;
const MAX_TRACE_BYTES: usize = 64;

#[derive(Debug, Arbitrary)]
struct HardeningStateMachineFuzzCase {
    starting_level_selector: u8,
    escalations: Vec<RawEscalation>,
}

#[derive(Debug, Arbitrary)]
struct RawEscalation {
    target_selector: u8,
    timestamp: u64,
    trace_id: String,
}

fuzz_target!(|case: HardeningStateMachineFuzzCase| {
    let starting = pick_level(case.starting_level_selector);
    let mut machine = HardeningStateMachine::with_level(starting);
    assert_eq!(
        machine.current_level(),
        starting,
        "with_level must initialize current_level correctly"
    );

    let mut last_to_level_rank: u8 = starting.rank();

    for raw in case.escalations.into_iter().take(MAX_ESCALATIONS) {
        let target = pick_level(raw.target_selector);
        let trace_id = bounded(&raw.trace_id, MAX_TRACE_BYTES);
        let pre_current = machine.current_level();

        match machine.escalate(target, raw.timestamp, &trace_id) {
            Ok(record) => {
                // ── (A) Monotonic: target MUST be strictly greater than pre-current.
                assert!(
                    target.rank() > pre_current.rank(),
                    "INV-HARDEN-MONOTONIC violated: escalate accepted target {target:?} \
                     (rank={}) when current was {pre_current:?} (rank={}) — \
                     target must be strictly greater",
                    target.rank(),
                    pre_current.rank()
                );

                // ── (B) Current advances exactly to the target.
                assert_eq!(
                    machine.current_level(),
                    target,
                    "INV-HARDEN-CURRENT-ADVANCES violated: post-escalate current_level \
                     is {:?}, expected {target:?}",
                    machine.current_level()
                );

                // ── (C) Log is strictly monotonic on successful escalations.
                assert!(
                    record.to_level.rank() > last_to_level_rank,
                    "INV-HARDEN-LOG-MONOTONIC violated: log advanced to {:?} \
                     (rank={}) which is not strictly greater than previous {}",
                    record.to_level,
                    record.to_level.rank(),
                    last_to_level_rank
                );
                last_to_level_rank = record.to_level.rank();

                // The record's from_level MUST equal pre-current.
                assert_eq!(
                    record.from_level, pre_current,
                    "TransitionRecord.from_level mismatched pre-current"
                );
            }
            Err(err) => {
                // ── Rejection contract: must be IllegalRegression with the
                //    pre-current + attempted-target pair captured verbatim.
                assert!(
                    target.rank() <= pre_current.rank(),
                    "INV-HARDEN-MONOTONIC violated: escalate REJECTED a strictly-greater \
                     target {target:?} (rank={}) when current was {pre_current:?} \
                     (rank={}): {err:?}",
                    target.rank(),
                    pre_current.rank()
                );
                assert!(
                    matches!(
                        err,
                        HardeningError::IllegalRegression {
                            current,
                            attempted,
                        } if current == pre_current && attempted == target
                    ),
                    "INV-HARDEN-MONOTONIC violated: rejection must be IllegalRegression \
                     with current={pre_current:?} attempted={target:?}, got {err:?}"
                );
                // current_level must NOT have changed on rejection.
                assert_eq!(
                    machine.current_level(),
                    pre_current,
                    "INV-HARDEN-CURRENT-ADVANCES violated: current_level moved despite \
                     rejected escalation"
                );
            }
        }
    }

    // ── (D) Replay equivalence ──────────────────────────────────────
    let log: Vec<_> = machine.transition_log().to_vec();
    let replayed = HardeningStateMachine::replay_transitions(&log);
    assert_eq!(
        replayed.current_level(),
        machine.current_level(),
        "INV-HARDEN-REPLAY-EQUIVALENCE violated: replayed current_level={:?} \
         differs from live={:?}",
        replayed.current_level(),
        machine.current_level()
    );
    assert_eq!(
        replayed.transition_count(),
        machine.transition_count(),
        "INV-HARDEN-REPLAY-EQUIVALENCE violated: replayed transition_count={} \
         differs from live={}",
        replayed.transition_count(),
        machine.transition_count()
    );
});

fn pick_level(selector: u8) -> HardeningLevel {
    match selector % 5 {
        0 => HardeningLevel::Baseline,
        1 => HardeningLevel::Standard,
        2 => HardeningLevel::Enhanced,
        3 => HardeningLevel::Maximum,
        _ => HardeningLevel::Critical,
    }
}

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
