#![no_main]

//! Fuzz harness for `frankenengine_node::encoding::deterministic_seed::derive_seed`.
//!
//! Background. `derive_seed(domain, content_hash, config)` at
//! `crates/franken-node/src/encoding/deterministic_seed.rs:279` is the
//! foundational seed-derivation primitive for the runtime: erasure coding,
//! repair scheduling, replica placement, and integrity verification all
//! draw deterministic seeds from this function. The implementation
//! domain-separates via a static UTF-8 prefix string + a `0x00` null
//! separator + 32-byte `content_hash` + 32-byte `config_hash` fed through
//! SHA-256.
//!
//! Existing fuzz coverage of this primitive: **zero** before this harness.
//! `rg derive_seed fuzz/fuzz_targets/` returns no hits. The
//! `threshold_sig_parity.rs` and `fuzz_crypto_scheme_*` harnesses cover
//! signature/verify surfaces but never invoke the seed deriver. This
//! harness fills that gap and pins four invariants the production
//! callers rely on:
//!
//!   (A) **Determinism**: `derive_seed(d, ch, cfg) == derive_seed(d, ch, cfg)`
//!       across two independent invocations. A regression here would
//!       break the runtime's deterministic-replay contract — the same
//!       publication artifact would derive different scheduling seeds
//!       on two nodes, breaking convergence.
//!
//!   (B) **Output stability**: the returned `DeterministicSeed` echoes
//!       the input `domain` and `config.version` byte-for-byte. A drift
//!       here means downstream consumers (which use these fields as
//!       indexing keys) would see a value that no longer matches the
//!       input — a subtle correctness bug that wouldn't surface in
//!       single-deriver tests.
//!
//!   (C) **Domain separation**: `derive_seed(d_i, ch, cfg) !=
//!       derive_seed(d_j, ch, cfg)` for any two distinct domain tags
//!       (i != j). The implementation uses the static-text domain
//!       prefix; the only way this property breaks is if someone
//!       collides two prefixes (currently all five are distinct
//!       `"franken_node.<scope>.v1"` strings). The harness exercises
//!       every (d_i, d_j) pair across all 5 variants and asserts
//!       inequality.
//!
//!   (D) **Content sensitivity**: flipping a single bit in `content_hash`
//!       MUST change the derived seed. Otherwise an attacker who
//!       controls content but whose flipped bit lands in a "dead"
//!       region of the SHA-256 preimage could collide seeds. SHA-256
//!       structurally prevents this (avalanche), but the test
//!       confirms our wiring doesn't masque the avalanche by
//!       dropping content_hash from the preimage.

use arbitrary::Arbitrary;
use frankenengine_node::encoding::deterministic_seed::{
    derive_seed, ContentHash, DomainTag, ScheduleConfig,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_PARAMETERS: usize = 32;
const MAX_PARAM_KEY_BYTES: usize = 64;
const MAX_PARAM_VALUE_BYTES: usize = 256;

#[derive(Debug, Arbitrary)]
struct DeterministicSeedFuzzCase {
    domain_selector: u8,
    flip_bit_index: u8,
    content_hash_bytes: [u8; 32],
    config_version: u32,
    config_parameters: Vec<(String, String)>,
}

fuzz_target!(|case: DeterministicSeedFuzzCase| {
    // ── Build inputs from the fuzz case ──────────────────────────────
    let domain_tag = pick_domain(case.domain_selector);
    let content = ContentHash::from_bytes(case.content_hash_bytes);
    let config = build_bounded_config(case.config_version, &case.config_parameters);

    // ── (A) Determinism — same inputs MUST produce same seed twice ──
    let first = derive_seed(&domain_tag, &content, &config);
    let second = derive_seed(&domain_tag, &content, &config);
    assert_eq!(
        first.bytes, second.bytes,
        "INV-SEED-DETERMINISM violated: derive_seed produced different bytes \
         for the same (domain, content_hash, config) tuple"
    );

    // ── (B) Output stability — domain/version echoed faithfully ─────
    assert_eq!(
        first.domain, domain_tag,
        "INV-SEED-OUTPUT-STABILITY violated: DeterministicSeed.domain \
         does not match the input DomainTag"
    );
    assert_eq!(
        first.config_version, config.version,
        "INV-SEED-OUTPUT-STABILITY violated: DeterministicSeed.config_version \
         does not match the input ScheduleConfig.version"
    );

    // ── (C) Domain separation — every other domain MUST differ ──────
    for other in DomainTag::all() {
        if *other == domain_tag {
            continue;
        }
        let other_seed = derive_seed(other, &content, &config);
        assert_ne!(
            first.bytes, other_seed.bytes,
            "INV-SEED-DOMAIN-SEP violated: derive_seed({:?}, ...) collided with \
             derive_seed({:?}, ...) for the same (content_hash, config)",
            domain_tag, other,
        );
    }

    // ── (D) Content sensitivity — flipping a single bit MUST change the seed ─
    let bit_index = usize::from(case.flip_bit_index) % (32 * 8);
    let byte_index = bit_index / 8;
    let mut flipped_bytes = case.content_hash_bytes;
    flipped_bytes[byte_index] ^= 1u8 << (bit_index % 8);
    let flipped_content = ContentHash::from_bytes(flipped_bytes);
    let flipped_seed = derive_seed(&domain_tag, &flipped_content, &config);
    assert_ne!(
        first.bytes, flipped_seed.bytes,
        "INV-SEED-CONTENT-SENSITIVITY violated: flipping bit {bit_index} in \
         content_hash produced an identical seed — content_hash is being \
         dropped from the SHA-256 preimage"
    );
});

fn pick_domain(selector: u8) -> DomainTag {
    let all = DomainTag::all();
    all[usize::from(selector) % all.len()]
}

fn build_bounded_config(version: u32, parameters: &[(String, String)]) -> ScheduleConfig {
    let mut bounded = BTreeMap::new();
    for (key, value) in parameters.iter().take(MAX_PARAMETERS) {
        if !key.is_empty()
            && key.len() <= MAX_PARAM_KEY_BYTES
            && value.len() <= MAX_PARAM_VALUE_BYTES
        {
            bounded.insert(key.clone(), value.clone());
        }
    }
    ScheduleConfig {
        version,
        parameters: bounded,
    }
}
