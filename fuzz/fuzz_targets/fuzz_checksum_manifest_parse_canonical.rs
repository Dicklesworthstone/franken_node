#![no_main]
#![forbid(unsafe_code)]

//! Fuzz `ChecksumManifest::parse_canonical` — the publisher-facing
//! manifest text parser at
//! `crates/franken-node/src/supply_chain/artifact_signing.rs:233`.
//!
//! The parser ingests release-manifest text of the form
//! `<sha256>  <name>  <size>\n` (one line per entry, two-space
//! separators, trailing newline) and is documented as the security
//! boundary that rejects path-traversal artifact names, duplicate
//! entries, non-canonical decimal sizes, mis-sorted entries, and
//! non-hex sha256 hashes. Publishers control the manifest text in
//! the release-signing flow, so a panic or invariant violation on
//! attacker-shaped input would translate to a DoS or signature-
//! validity break.
//!
//! Despite 47+ existing fuzz harnesses in `fuzz/fuzz_targets/` and
//! a rich unit-test suite (`parse_canonical_rejects_path_traversal`,
//! `parse_canonical_rejects_absolute_path`, ...), `parse_canonical`
//! itself had no fuzz coverage before this harness.
//!
//! Invariants pinned on every successful parse:
//!   (a) Each `ManifestEntry.sha256` is exactly 64 lowercase hex
//!       characters (the parser's own contract).
//!   (b) Each `ManifestEntry.name` is non-empty, contains no `..`
//!       segments, does not start with `/`, and contains no `\\`
//!       characters (the SECURITY-documented path-traversal guard).
//!   (c) Entries are sorted ascending by `name` and names are
//!       unique (canonical-order + dedup contract).
//!   (d) Round-trip: rebuilding a `ChecksumManifest` from the
//!       parsed entries and re-serialising via `canonical_bytes()`
//!       must re-parse losslessly.

use frankenengine_node::supply_chain::artifact_signing::{ChecksumManifest, ManifestEntry};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Cap fuzz input to keep per-iteration cost bounded. Real release
    // manifests stay well below 256 KiB.
    if data.len() > 256 * 1024 {
        return;
    }
    let Ok(text) = str::from_utf8(data) else {
        return;
    };

    let Ok(entries) = ChecksumManifest::parse_canonical(text) else {
        // Parser errors are valid outcomes; this harness only hunts
        // for panics and invariant violations on the success path.
        return;
    };

    // (a) sha256 contract: 64 lowercase hex chars.
    for entry in &entries {
        assert_eq!(
            entry.sha256.len(),
            64,
            "parser must reject non-64-char sha256: {:?}",
            entry.sha256
        );
        assert!(
            entry
                .sha256
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "parser must reject non-lowercase-hex sha256: {:?}",
            entry.sha256
        );
    }

    // (b) name path-traversal contract.
    for entry in &entries {
        assert!(!entry.name.is_empty(), "parser must reject empty name");
        assert!(
            !entry.name.split('/').any(|seg| seg == ".."),
            "parser must reject `..` segments: {:?}",
            entry.name
        );
        assert!(
            !entry.name.starts_with('/'),
            "parser must reject absolute names: {:?}",
            entry.name
        );
        assert!(
            !entry.name.contains('\\'),
            "parser must reject backslash names: {:?}",
            entry.name
        );
    }

    // (c) ordering + uniqueness contract.
    let mut previous: Option<&str> = None;
    for entry in &entries {
        if let Some(previous_name) = previous {
            assert!(
                previous_name < entry.name.as_str(),
                "names must be strictly ascending: {:?} >= {:?}",
                previous_name,
                entry.name
            );
        }
        previous = Some(entry.name.as_str());
    }

    // (d) round-trip via ChecksumManifest::canonical_bytes(): parsed
    // entries → BTreeMap → canonical text → re-parse must agree.
    let mut roundtrip_map: BTreeMap<String, ManifestEntry> = BTreeMap::new();
    for entry in entries.iter().cloned() {
        roundtrip_map.insert(entry.name.clone(), entry);
    }
    let manifest = ChecksumManifest {
        entries: roundtrip_map,
    };
    let canonical = manifest.canonical_bytes();
    let canonical_text = str::from_utf8(&canonical)
        .expect("canonical_bytes always produces valid UTF-8 (hex + name + decimal)");
    let reparsed = ChecksumManifest::parse_canonical(canonical_text)
        .expect("canonical re-serialisation must always re-parse");
    assert_eq!(
        reparsed.len(),
        entries.len(),
        "round-trip must preserve entry count"
    );
    for (a, b) in entries.iter().zip(reparsed.iter()) {
        assert_eq!(a.sha256, b.sha256, "round-trip sha256 mismatch");
        assert_eq!(a.name, b.name, "round-trip name mismatch");
        assert_eq!(a.size_bytes, b.size_bytes, "round-trip size mismatch");
    }
});
