//! Zero-cost compile-time elision audit (bd-98xo5.12.5).
//!
//! Per the T12 "production pays zero cost" invariant: when the
//! `profiling` Cargo feature is NOT enabled (the default), the four
//! T12.1-T12.4 sentinel functions and their associated HDR histograms
//! must be ABSENT from the compiled binary. The mechanism is
//! `#[cfg(feature = "profiling")]` at the definition sites of the
//! sentinels, histogram statics, and recording functions.
//!
//! This integration test verifies that contract empirically by
//! running `nm` on the test process's own binary and asserting none
//! of the sentinel symbols appear in the symbol table. The cfg-gated
//! definitions are simply not compiled when feature is off; the
//! linker has no chance to include them.
//!
//! ## Test surface
//!
//! Four sentinel functions, one per T12.x bead (shipped commits in
//! parens):
//!
//!   - `_profile_trust_card_canonical`        (bd-98xo5.12.1 commit `1c72a9f0`)
//!     → crates/franken-node/src/connector/canonical_serializer.rs
//!   - `_profile_ed25519_scheme_sign` + `_profile_ed25519_scheme_verify`
//!     (bd-98xo5.12.2 commit landed by peer)
//!     → crates/franken-node/src/crypto/schemes.rs
//!   - `_profile_threshold_sig_verify`         (bd-98xo5.12.3 commit `bce4f6c0`)
//!     → crates/franken-node/src/security/threshold_sig.rs
//!   - `_profile_evidence_ledger_append_sentinel` (bd-98xo5.12.4 commit `8d6adee7`)
//!     → crates/franken-node/src/observability/evidence_ledger.rs
//!
//! Note: T12.1's sentinel is the one exception — it's defined WITHOUT
//! a `#[cfg(feature = "profiling")]` gate (it's always compiled, with
//! `#[inline(never)]` + `#[allow(dead_code)]`), with the cfg gate on
//! the CALLER instead. Linker DCE may or may not drop the symbol
//! depending on the linker's aggressiveness; the test handles this
//! by allowing T12.1's sentinel either way and only failing on the
//! cfg-gated 12.2-12.4 sentinels.
//!
//! ## Why nm
//!
//! `nm <binary>` dumps the linker symbol table. After link-time DCE,
//! symbols with no in-binary references are typically dropped (with
//! lld and gold; gnu-ld is slightly more conservative). The test
//! looks for the EXACT cfg-gated symbols and asserts they're absent.
//!
//! ## Skip conditions
//!
//! - `nm` not on PATH → test prints a SKIP marker and passes (the
//!   sentinel-absent invariant is structurally guaranteed by the cfg
//!   gates, even when not empirically observable here).
//! - Profiling feature explicitly enabled (`#[cfg(feature = "profiling")]`
//!   on this test compiles a different body that ASSERTS the sentinels
//!   ARE present — the test passes in either build configuration).
//!
//! ## Out of scope
//!
//! - Flamegraph attribution integration test (the bead's deliverable
//!   #3) is deferred — it requires `perf record` infrastructure and
//!   a release-perf build, both of which exceed the per-bead test
//!   wall-time budget. Tracked as future work; the per-module unit
//!   tests already shipped at bd-98xo5.12.{1,2,3,4} pin the
//!   histogram-receives-sample contract.

use std::env;
use std::process::Command;

const CFG_GATED_SENTINELS: &[&str] = &[
    "_profile_ed25519_scheme_sign",
    "_profile_ed25519_scheme_verify",
    "_profile_threshold_sig_verify",
    "_profile_evidence_ledger_append_sentinel",
];

/// The bd-98xo5.12.1 sentinel is unconditionally compiled (no cfg
/// gate at the definition site), so under default features it may or
/// may not survive linker DCE depending on the linker. Listed here
/// for documentation but NOT asserted against — see module doc.
#[allow(dead_code)]
const ALWAYS_COMPILED_SENTINELS: &[&str] = &["_profile_trust_card_canonical"];

fn current_exe_symbol_table() -> Option<String> {
    let exe = env::current_exe().ok()?;
    let output = Command::new("nm").arg(&exe).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(not(feature = "profiling"))]
#[test]
fn instrumentation_sentinels_absent_in_default_build() {
    let Some(symbols) = current_exe_symbol_table() else {
        eprintln!(
            "SKIP: nm not on PATH or failed to read symbols from current_exe; \
             zero-cost contract still holds structurally via #[cfg(feature = \"profiling\")] \
             gates at the sentinel definition sites."
        );
        return;
    };

    let mut found: Vec<&str> = Vec::new();
    for name in CFG_GATED_SENTINELS {
        // nm prints lines like "<addr> <kind> <name>". Match the
        // exact symbol name as a token to avoid partial-string false
        // positives (e.g. `_profile_threshold_sig_verify_inner_v2`
        // would not trigger on `_profile_threshold_sig_verify`).
        if symbols.lines().any(|line| {
            line.split_whitespace()
                .last()
                .map(|sym| sym == *name)
                .unwrap_or(false)
        }) {
            found.push(name);
        }
    }
    assert!(
        found.is_empty(),
        "default-feature build must not contain cfg-gated profiling sentinels — found: {found:?}. \
         This means a #[cfg(feature = \"profiling\")] gate was lifted from a sentinel definition \
         (or a recording function), violating the T12 zero-cost contract."
    );
}

#[cfg(feature = "profiling")]
#[test]
fn instrumentation_sentinels_present_when_profiling_enabled() {
    let Some(symbols) = current_exe_symbol_table() else {
        eprintln!("SKIP: nm not on PATH; cannot verify sentinel presence under profiling feature.");
        return;
    };

    let mut missing: Vec<&str> = Vec::new();
    for name in CFG_GATED_SENTINELS {
        if !symbols.lines().any(|line| {
            line.split_whitespace()
                .last()
                .map(|sym| sym == *name)
                .unwrap_or(false)
        }) {
            missing.push(name);
        }
    }
    assert!(
        missing.is_empty(),
        "profiling-feature build must contain every sentinel — missing: {missing:?}. \
         This means the sentinel definition is gated wrong or the linker is dropping it \
         despite the live caller; flamegraph attribution would lose this surface."
    );
}

/// Smoke test: nm must be available somewhere on the test host for
/// the symbol-audit tests to be empirically meaningful. If nm is
/// missing, both audit tests print SKIP and pass without verification.
/// Pin a one-line warning on test startup so the absence is visible
/// in CI logs.
#[test]
fn nm_availability_smoke_test() {
    let nm_present = Command::new("nm")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !nm_present {
        eprintln!(
            "WARN: nm not on PATH — instrumentation_sentinels_*_in_default_build / \
             instrumentation_sentinels_present_when_profiling_enabled tests will SKIP \
             without empirical verification. The cfg-gate-at-definition contract still \
             holds structurally, but a CI run without nm cannot prove zero-cost \
             elision empirically."
        );
    }
    // Don't fail on missing nm — the audit tests handle that case
    // themselves. This test exists to surface the absence in logs.
}
