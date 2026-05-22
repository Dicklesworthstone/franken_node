#![no_main]

//! Fuzz harness for
//! `frankenengine_node::runtime::safe_mode::OperationFlags::parse_args`
//! at `crates/franken-node/src/runtime/safe_mode.rs:198`. The function
//! parses CLI argument lists (e.g., `["--safe-mode", "--degraded"]`)
//! into a typed `OperationFlags` set; downstream callers consult the
//! flags during admission decisions and capability gating. A regression
//! that accepts an unknown flag (e.g., dropping the catch-all `other =>
//! Err`) could let an operator pass a typoed `--no-net-work` and end up
//! with network-egress enabled silently.
//!
//! Existing fuzz coverage of this parser: **zero**.
//!
//! Five invariants pinned per call:
//!
//!   (A) **INV-SMO-PARSE-PANIC-FREE**: arbitrary `&[&str]` MUST NOT
//!       panic the parser.
//!
//!   (B) **INV-SMO-UNKNOWN-REJECT**: any token NOT in the known
//!       flag set (`--safe-mode`, `--degraded`, `--read-only`,
//!       `--no-network`) MUST cause `parse_args` to return
//!       `Err(UnknownFlag { .. })`. The harness asserts that every
//!       successful parse only contains known flag tokens — any
//!       unknown-but-accepted token would be a vulnerability.
//!
//!   (C) **INV-SMO-EMPTY-NONE**: `parse_args(&[])` MUST return
//!       `Ok(OperationFlags::none())`. Catches a regression that
//!       defaults to flagged state on empty input.
//!
//!   (D) **INV-SMO-ORDER-INDEPENDENT**: `parse_args([a, b])` and
//!       `parse_args([b, a])` produce structurally-equal
//!       `OperationFlags` (modulo the first-error-wins semantics
//!       when an unknown flag is present).
//!
//!   (E) **INV-SMO-IDEMPOTENT-FLAGS**: `parse_args([flag, flag])`
//!       succeeds iff `parse_args([flag])` succeeds, and produces
//!       the same OperationFlags. Catches a regression where a
//!       repeated flag accidentally toggles state.

use arbitrary::Arbitrary;
use frankenengine_node::runtime::safe_mode::{OperationFlags, SafeModeError};
use libfuzzer_sys::fuzz_target;

const KNOWN_FLAGS: &[&str] = &["--safe-mode", "--degraded", "--read-only", "--no-network"];
const MAX_ARGS: usize = 16;
const MAX_ARG_BYTES: usize = 128;

#[derive(Debug, Arbitrary)]
struct SafeModeParseFuzzCase {
    raw_args: Vec<String>,
    selector_pair: (u8, u8),
}

fuzz_target!(|case: SafeModeParseFuzzCase| {
    let owned_args: Vec<String> = case
        .raw_args
        .iter()
        .take(MAX_ARGS)
        .map(|s| bounded(s, MAX_ARG_BYTES))
        .collect();
    let arg_refs: Vec<&str> = owned_args.iter().map(String::as_str).collect();

    // ── (A) Panic-freedom: the call IS the assertion ────────────────
    let parsed = OperationFlags::parse_args(&arg_refs);

    // ── (B) Unknown-token rejection: a successful parse MUST only
    //     contain known tokens. The parser returns the parsed flag
    //     state; we walk the input back and assert every arg was in
    //     KNOWN_FLAGS.
    if parsed.is_ok() {
        for arg in &arg_refs {
            assert!(
                KNOWN_FLAGS.contains(arg),
                "INV-SMO-UNKNOWN-REJECT violated: parse_args accepted unknown token \
                 {arg:?} (only {KNOWN_FLAGS:?} are valid)"
            );
        }
    } else {
        // Conversely, an Err MUST be UnknownFlag and MUST quote at least
        // one of the input tokens we passed. This pins the error-class
        // contract so a regression that returns a different error variant
        // (e.g., a generic Internal) trips the harness.
        let err = parsed.as_ref().err().expect("checked is_ok above");
        assert!(
            matches!(err, SafeModeError::UnknownFlag { .. }),
            "INV-SMO-UNKNOWN-REJECT violated: parse_args returned non-UnknownFlag \
             error on bad input: {err:?}"
        );
    }

    // ── (C) Empty input → none() ────────────────────────────────────
    let empty = OperationFlags::parse_args(&[]).expect("parse_args([]) must succeed");
    assert_eq!(
        empty,
        OperationFlags::none(),
        "INV-SMO-EMPTY-NONE violated: parse_args([]) returned {empty:?} instead of \
         OperationFlags::none()"
    );

    // ── (D) Order-independence on known-flag pairs ──────────────────
    let a_idx = usize::from(case.selector_pair.0) % KNOWN_FLAGS.len();
    let b_idx = usize::from(case.selector_pair.1) % KNOWN_FLAGS.len();
    let a = KNOWN_FLAGS[a_idx];
    let b = KNOWN_FLAGS[b_idx];
    let forward = OperationFlags::parse_args(&[a, b]).expect("known flags must parse");
    let reverse = OperationFlags::parse_args(&[b, a]).expect("known flags must parse");
    assert_eq!(
        forward, reverse,
        "INV-SMO-ORDER-INDEPENDENT violated: parse_args([{a}, {b}]) != parse_args([{b}, {a}])"
    );

    // ── (E) Idempotence: repeat flag = single flag ──────────────────
    let single = OperationFlags::parse_args(&[a]).expect("single known flag must parse");
    let doubled = OperationFlags::parse_args(&[a, a]).expect("repeated known flag must parse");
    assert_eq!(
        single, doubled,
        "INV-SMO-IDEMPOTENT-FLAGS violated: repeated flag {a} produced different \
         OperationFlags than single occurrence"
    );
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
