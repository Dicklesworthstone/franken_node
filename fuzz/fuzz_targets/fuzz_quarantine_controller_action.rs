#![no_main]

//! Fuzz harness for
//! `frankenengine_node::security::quarantine_controller::QuarantineController::action_for_posterior`
//! at `crates/franken-node/src/security/quarantine_controller.rs:256`.
//! The function maps an adversary risk posterior to a `ControlAction`
//! (None, Throttle, Isolate, Quarantine, Revoke). A regression that
//! treats NaN as "no action" or that mishandles threshold ordering
//! would let an attacker land an `Isolate` decision on a `Revoke`-tier
//! posterior — bypassing the strictest control tier.
//!
//! Existing fuzz coverage: **zero**.
//!
//! Five invariants pinned per call:
//!
//!   (A) **INV-QC-PANIC-FREE** — arbitrary `posterior: f64` MUST NOT
//!       panic the action mapper.
//!
//!   (B) **INV-QC-NAN-FORCES-REVOKE** — non-finite `posterior`
//!       (NaN, ±Inf) MUST map to `Some(ControlAction::Revoke)` per
//!       the documented fail-closed semantics at line 257.
//!
//!   (C) **INV-QC-MONOTONIC-UNDER-VALID-POLICY** — for a valid policy
//!       (validated by `QuarantineThresholdPolicy::validate()` ⇒
//!       throttle ≤ isolate ≤ quarantine ≤ revoke), increasing
//!       posterior MUST produce non-decreasing severity. Verified by
//!       comparing the action at posterior P1 against the action at
//!       posterior P2 > P1.
//!
//!   (D) **INV-QC-DEFAULT-POLICY-CONSTRUCTS** — a controller
//!       constructed from `QuarantineThresholdPolicy::default()` and
//!       a non-empty signing key MUST succeed via `new`. Catches a
//!       regression where the default policy fails its own
//!       `validate()`.
//!
//!   (E) **INV-QC-BELOW-THROTTLE-NONE** — for a valid policy with
//!       throttle > 0.0, any posterior < throttle MUST map to `None`.
//!       Catches a regression where the lowest-tier check fires too
//!       eagerly.

use arbitrary::Arbitrary;
use frankenengine_node::security::quarantine_controller::{
    ControlAction, QuarantineController, QuarantineThresholdPolicy,
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct QuarantineControllerFuzzCase {
    throttle: f64,
    isolate: f64,
    quarantine: f64,
    revoke: f64,
    posterior_a: f64,
    posterior_b: f64,
    signing_key: String,
}

fuzz_target!(|case: QuarantineControllerFuzzCase| {
    // ── (D) Default policy + a fixed signing key must always succeed.
    let default_controller = QuarantineController::new(
        QuarantineThresholdPolicy::default(),
        "test-signing-key-with-stable-marker",
    );
    assert!(
        default_controller.is_ok(),
        "INV-QC-DEFAULT-POLICY-CONSTRUCTS violated: default policy + valid \
         signing key failed: {:?}",
        default_controller.err()
    );
    let default_controller = default_controller.expect("checked above");

    // ── (B) Non-finite posterior MUST map to Revoke.
    for non_finite in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let action = default_controller.action_for_posterior(non_finite);
        assert_eq!(
            action,
            Some(ControlAction::Revoke),
            "INV-QC-NAN-FORCES-REVOKE violated: posterior={non_finite} mapped \
             to {action:?}, expected Some(Revoke)"
        );
    }

    // Build a fuzz-driven policy. If it doesn't validate, skip the
    // remaining invariants (they only hold under a valid policy).
    let fuzz_policy = QuarantineThresholdPolicy {
        throttle: case.throttle,
        isolate: case.isolate,
        quarantine: case.quarantine,
        revoke: case.revoke,
    };
    let signing_key = bounded(&case.signing_key, 256);
    let Ok(controller) = QuarantineController::new(fuzz_policy.clone(), signing_key.as_str())
    else {
        return;
    };

    // ── (A) Panic-freedom: any f64 input must not panic.
    let action_a = controller.action_for_posterior(case.posterior_a);
    let action_b = controller.action_for_posterior(case.posterior_b);

    // ── (C) Monotonicity: under a valid policy, p1 < p2 ⇒ severity(p1) ≤ severity(p2).
    // Severity rank: None < Throttle < Isolate < Quarantine < Revoke.
    if case.posterior_a.is_finite() && case.posterior_b.is_finite() {
        let (lo, hi, action_lo, action_hi) = if case.posterior_a <= case.posterior_b {
            (case.posterior_a, case.posterior_b, action_a, action_b)
        } else {
            (case.posterior_b, case.posterior_a, action_b, action_a)
        };
        assert!(
            severity_rank(action_lo) <= severity_rank(action_hi),
            "INV-QC-MONOTONIC violated: posterior {lo} ({:?}, rank {}) > posterior {hi} \
             ({:?}, rank {}) — action severity should be non-decreasing in posterior",
            action_lo,
            severity_rank(action_lo),
            action_hi,
            severity_rank(action_hi)
        );
    }

    // ── (E) Below-throttle → None (valid policy with throttle > 0.0).
    if fuzz_policy.throttle > 0.0 && fuzz_policy.throttle.is_finite() {
        // Use a posterior strictly below the throttle threshold. We bias to 0.0
        // for safety when throttle is very small.
        let below_throttle = if fuzz_policy.throttle > 1e-9 {
            fuzz_policy.throttle - 1e-9
        } else {
            0.0
        };
        let below_action = controller.action_for_posterior(below_throttle);
        assert_eq!(
            below_action, None,
            "INV-QC-BELOW-THROTTLE-NONE violated: posterior {below_throttle} (< \
             throttle={}) mapped to {below_action:?}, expected None",
            fuzz_policy.throttle
        );
    }
});

fn severity_rank(action: Option<ControlAction>) -> u8 {
    match action {
        None => 0,
        Some(ControlAction::Throttle) => 1,
        Some(ControlAction::Isolate) => 2,
        Some(ControlAction::Quarantine) => 3,
        Some(ControlAction::Revoke) => 4,
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
