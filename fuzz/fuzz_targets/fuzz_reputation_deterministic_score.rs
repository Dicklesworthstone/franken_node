#![no_main]

//! Fuzz harness for
//! `frankenengine_node::supply_chain::reputation::deterministic_score`
//! at `crates/franken-node/src/supply_chain/reputation.rs:835`.
//!
//! Background. `deterministic_score(signals, decay_config) -> f64` is
//! the pure reputation scorer the supply-chain admission flow consults
//! when ranking publishers for trust-card issuance. It starts at a
//! provisional 30.0, iterates the signal list, applies each signal's
//! `weight_override` (falling back to `SignalKind::default_weight`),
//! and clamps the running score to `[0.0, 100.0]` after every
//! addition. A regression that drops the `is_finite()` guard on
//! `weight_override`, or drops the `is_finite()` guard on
//! `candidate = score + weight`, would let an attacker:
//!
//!   - inject `weight_override = NaN` → `candidate = score + NaN =
//!     NaN`, which propagates through every subsequent signal and
//!     corrupts every downstream consumer of the score
//!   - inject `weight_override = ±∞` → `candidate = ±∞`, clamped to
//!     `[0, 100]` only if the `is_finite()` guard catches it
//!
//! Existing fuzz coverage of this function: **zero**.
//!
//! This harness pins four invariants per call against adversarial
//! signal sequences:
//!
//!   (A) **INV-REPUTATION-DETERMINISM** — `deterministic_score(s, c)`
//!       invoked twice produces byte-identical `f64` output (modulo
//!       NaN's intentional non-self-equality — see (B)).
//!
//!   (B) **INV-REPUTATION-FINITE** — the output is ALWAYS finite
//!       (`is_finite()`). Catches a regression that drops the
//!       `candidate.is_finite()` guard at reputation.rs:843, which
//!       would let a NaN `weight_override` poison the running score
//!       and propagate through every subsequent signal.
//!
//!   (C) **INV-REPUTATION-BOUNDED** — the output is ALWAYS in
//!       `[0.0, 100.0]`. Catches a regression that drops the
//!       `clamp(0.0, 100.0)` at reputation.rs:844.
//!
//!   (D) **INV-REPUTATION-EMPTY-PROVISIONAL** — `deterministic_score(
//!       &[], c)` returns exactly `30.0` (the provisional initial
//!       score). Catches a regression that changes the starting
//!       constant — every published score baseline depends on this.

use arbitrary::Arbitrary;
use frankenengine_node::supply_chain::reputation::{
    deterministic_score, DecayConfig, ReputationSignal, SignalKind,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_SIGNALS: usize = 64;
const MAX_FIELD_BYTES: usize = 64;
const MAX_EVIDENCE_ENTRIES: usize = 4;

#[derive(Debug, Arbitrary)]
struct ReputationScoreFuzzCase {
    signals: Vec<RawSignal>,
    decay_daily_rate: f64,
    decay_baseline: f64,
    decay_min_interval_days: u32,
}

#[derive(Debug, Arbitrary)]
struct RawSignal {
    signal_id: String,
    publisher_id: String,
    kind_selector: u8,
    observed_at: String,
    weight_override: Option<f64>,
    description: String,
    evidence: Vec<(String, String)>,
}

fuzz_target!(|case: ReputationScoreFuzzCase| {
    let signals = build_signals(&case.signals);
    let decay = DecayConfig {
        daily_rate: case.decay_daily_rate,
        baseline: case.decay_baseline,
        min_interval_days: case.decay_min_interval_days,
    };

    // ── (A) Determinism ─────────────────────────────────────────────
    let first = deterministic_score(&signals, &decay);
    let second = deterministic_score(&signals, &decay);
    // Both first and second MUST be finite per (B); equality on f64
    // is therefore safe here (no NaN trap).
    assert_eq!(
        first.to_bits(),
        second.to_bits(),
        "INV-REPUTATION-DETERMINISM violated: identical inputs produced \
         different scores ({first} vs {second})"
    );

    // ── (B) Finiteness ──────────────────────────────────────────────
    assert!(
        first.is_finite(),
        "INV-REPUTATION-FINITE violated: deterministic_score returned a \
         non-finite value {first} — a NaN/Inf weight_override leaked through \
         the is_finite() guard at reputation.rs:843"
    );

    // ── (C) Bounded ─────────────────────────────────────────────────
    assert!(
        (0.0..=100.0).contains(&first),
        "INV-REPUTATION-BOUNDED violated: deterministic_score returned {first}, \
         outside [0.0, 100.0]; the clamp at reputation.rs:844 was bypassed"
    );

    // ── (D) Empty input → provisional 30.0 ──────────────────────────
    let empty_score = deterministic_score(&[], &decay);
    assert_eq!(
        empty_score.to_bits(),
        30.0_f64.to_bits(),
        "INV-REPUTATION-EMPTY-PROVISIONAL violated: empty signal list \
         must return exactly 30.0, got {empty_score}"
    );
});

fn build_signals(raw: &[RawSignal]) -> Vec<ReputationSignal> {
    raw.iter()
        .take(MAX_SIGNALS)
        .map(|r| ReputationSignal {
            signal_id: bounded_str(&r.signal_id, MAX_FIELD_BYTES),
            publisher_id: bounded_str(&r.publisher_id, MAX_FIELD_BYTES),
            kind: pick_kind(r.kind_selector),
            observed_at: bounded_str(&r.observed_at, MAX_FIELD_BYTES),
            // weight_override is intentionally NOT sanitized — fuzzing this
            // field IS the test surface. The production code MUST handle
            // any f64 (NaN/Inf/±huge) via the is_finite() guard chain.
            weight_override: r.weight_override,
            description: bounded_str(&r.description, MAX_FIELD_BYTES),
            evidence: r
                .evidence
                .iter()
                .take(MAX_EVIDENCE_ENTRIES)
                .map(|(k, v)| (bounded_str(k, MAX_FIELD_BYTES), bounded_str(v, MAX_FIELD_BYTES)))
                .collect::<BTreeMap<_, _>>(),
        })
        .collect()
}

fn pick_kind(selector: u8) -> SignalKind {
    match selector % 9 {
        0 => SignalKind::ProvenanceConsistency,
        1 => SignalKind::VulnerabilityResponseTime,
        2 => SignalKind::RevocationEvent,
        3 => SignalKind::ExtensionQuality,
        4 => SignalKind::CommunityReport,
        5 => SignalKind::CertificationAdherence,
        6 => SignalKind::CertificationLapse,
        7 => SignalKind::QuarantineEvent,
        _ => SignalKind::QuarantineResolution,
    }
}

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
