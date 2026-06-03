#![no_main]
#![forbid(unsafe_code)]

//! Fuzz `ClaimCompiler::compile` — the publisher-facing claim
//! validator at
//! `crates/franken-node/src/claims/claim_compiler.rs:181`.
//!
//! The compiler ingests an `ExternalClaim {claim_id, claim_text,
//! evidence_uris, source_id}` from an untrusted publisher and returns
//! a `CompilationResult::{Accepted, Rejected}`. Every accept admits the
//! claim into the evidence pipeline; every reject must surface a
//! stable `ClaimRejectionReason` with an `ERR_CLAIM_*` error code.
//!
//! Existing coverage (rg `claim_compiler|claims::` over `fuzz/`):
//! ZERO — the module has rich unit tests but no fuzz harness driving
//! the public boundary. This harness fills that gap.
//!
//! Invariants pinned on every `compile` call:
//!   (a) Panic-freedom — arbitrary bytes split into the four claim
//!       fields must NEVER panic the compiler.
//!   (b) Rejection contract — a `Rejected` outcome must carry a
//!       non-empty `error_code` (the `ERR_CLAIM_*` strings the unit
//!       tests assert against).
//!   (c) Acceptance contract — an `Accepted` outcome must carry a
//!       non-empty `claim_id` and at least one `evidence_uri` (the
//!       compiler's documented prerequisite for emitting an
//!       executable contract).
//!   (d) Blocked-source idempotence — running the same claim through
//!       a compiler that has its `source_id` blocklisted must reject;
//!       the unblocked compiler may accept or reject depending on
//!       other rules, but the two outcomes MUST differ (or both
//!       reject for a different reason) — i.e. blocking changes the
//!       decision shape.

use frankenengine_node::claims::claim_compiler::{
    ClaimCompiler, CompilationResult, CompilerConfig, ExternalClaim,
};
use libfuzzer_sys::fuzz_target;
use std::str;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(text) = str::from_utf8(data) else {
        return;
    };

    // Split the input into the four ExternalClaim fields by NUL
    // separators. The four-field shape mirrors the production wire
    // format (one claim per record, four fields per claim). Remaining
    // NUL-separated chunks fold into `evidence_uris`.
    let mut parts = text.split('\0');
    let claim_id = parts.next().unwrap_or("").to_string();
    let claim_text = parts.next().unwrap_or("").to_string();
    let source_id = parts.next().unwrap_or("").to_string();
    let evidence_uris: Vec<String> = parts.map(String::from).collect();

    let claim = ExternalClaim {
        claim_id: claim_id.clone(),
        claim_text,
        evidence_uris: evidence_uris.clone(),
        source_id: source_id.clone(),
    };

    // Open compiler — fixed signer / signing-key / clock so the run is
    // deterministic w.r.t. the input bytes.
    let open = ClaimCompiler::new(CompilerConfig::new(
        "fuzz-signer",
        "fuzz-signing-key",
        1_700_000_000_000,
    ));
    let open_outcome = open.compile(&claim);

    // (b) + (c) outcome-shape contracts on the open compiler.
    match &open_outcome {
        CompilationResult::Rejected {
            claim_id: rejected_id,
            error_code,
            ..
        } => {
            assert!(
                !error_code.is_empty(),
                "rejection must carry a non-empty ERR_CLAIM_* error_code"
            );
            assert_eq!(
                rejected_id, &claim.claim_id,
                "rejected outcome must echo the input claim_id"
            );
        }
        CompilationResult::Compiled { contract, .. } => {
            assert!(
                !contract.claim_id.is_empty(),
                "accepted contract must carry a non-empty claim_id"
            );
            assert!(
                !contract.evidence_uris.is_empty(),
                "accepted contract must carry at least one evidence_uri"
            );
        }
    }

    // (d) blocked-source check: if the open compiler accepted, a
    // compiler that blocks the same `source_id` MUST reject the same
    // claim. If the open compiler already rejected, the blocked
    // compiler also rejects — both runs must terminate without panic.
    let blocked = ClaimCompiler::new(
        CompilerConfig::new("fuzz-signer", "fuzz-signing-key", 1_700_000_000_000)
            .with_blocked_source(source_id.clone()),
    );
    let blocked_outcome = blocked.compile(&claim);

    if matches!(open_outcome, CompilationResult::Compiled { .. }) {
        assert!(
            matches!(blocked_outcome, CompilationResult::Rejected { .. }),
            "blocking the source must flip a Compiled outcome to Rejected"
        );
    }
});
