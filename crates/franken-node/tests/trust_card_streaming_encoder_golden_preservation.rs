//! Trust-card golden HMAC preservation gate (bd-98xo5.4.4).
//!
//! THIS TEST IS THE GATE FOR T4.5 (trust_card::to_canonical_json
//! migration to the streaming encoder). If any of the four
//! pre-existing trust-card golden files at
//! `crates/franken-node/tests/golden/trust_card_encoder/*.golden`
//! produces different bytes through the NEW streaming encoder
//! (`connector::canonical_serializer::canonical_bytes`, shipped at
//! bd-98xo5.4.2 commit b6a75037), the migration CANNOT land
//! without a schema_version bump.
//!
//! ## Why goldens are the right gate
//!
//! Trust cards are HMAC-SHA-256 signed snapshots. The HMAC chain is:
//!
//!   canonical_bytes(card_with_blank_hash_and_sig)
//!       → SHA-256
//!       → card.card_hash
//!       → HMAC(b"trust_card_registry_sig_v1:" || card_hash, registry_key)
//!       → card.registry_signature
//!
//! ANY byte shift in the canonical bytes propagates through SHA-256
//! and HMAC to BOTH `card_hash` AND `registry_signature`, breaking
//! every on-disk trust card and the entire trust chain. The goldens
//! at `tests/golden/trust_card_encoder/*.golden` are the canonical
//! reference: they're the exact bytes the OLD encoder
//! (`trust_card::to_canonical_json` → `canonicalize_value` → `to_string`)
//! produces today, and the streaming encoder MUST match them
//! byte-for-byte.
//!
//! ## What this test does NOT do
//!
//! - Doesn't re-derive card_hash/registry_signature from the bytes.
//!   The transitive property (identical bytes → identical
//!   downstream hash + HMAC) follows from byte-equality + the
//!   determinism of SHA-256 and HMAC. The existing
//!   `verify_card_signature` already exercises that transitive chain
//!   for in-memory cards.
//! - Doesn't load the goldens as TrustCard structs. The bead body
//!   speaks of "the canonical-byte form of the trust card" — the
//!   goldens ARE that byte form, so we round-trip through
//!   serde_json::Value (which is what the streaming encoder
//!   consumes) and assert the bytes back out.

use frankenengine_node::connector::canonical_serializer::canonical_bytes;
use std::fs;
use std::path::{Path, PathBuf};

const GOLDEN_NAMES: &[&str] = &[
    "active_minimal",
    "dependency_rich",
    "revoked_quarantine",
    "audit_heavy",
];

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/trust_card_encoder")
}

fn assert_golden_round_trips(name: &str) {
    let path: PathBuf = goldens_dir().join(format!("{name}.golden"));
    let golden_bytes =
        fs::read(&path).unwrap_or_else(|err| panic!("read golden {}: {err}", path.display()));
    let value: serde_json::Value = serde_json::from_slice(&golden_bytes)
        .unwrap_or_else(|err| panic!("golden {} must parse as JSON: {err}", path.display()));
    let new_bytes = canonical_bytes(&value);
    if new_bytes != golden_bytes {
        // On mismatch dump the actual bytes next to the golden so the
        // operator can diff. NOT in the same directory as the original
        // golden to avoid accidental overwrites by snapshot tools.
        let actual_path = path.with_extension("actual");
        fs::write(&actual_path, &new_bytes)
            .unwrap_or_else(|err| panic!("write actual bytes {}: {err}", actual_path.display()));
        panic!(
            "streaming encoder produced different bytes for golden `{name}`. \
             Golden: {} bytes; New: {} bytes. \
             Actual written to {}. \
             This is the bd-98xo5.4.4 gate: the bd-98xo5.4.2 streaming \
             encoder canonical_bytes() must produce byte-identical output \
             to the OLD trust_card::to_canonical_json path that produced \
             the goldens. A divergence here means T4.5 (the migration) \
             CANNOT land without a trust_card schema_version bump.",
            golden_bytes.len(),
            new_bytes.len(),
            actual_path.display(),
        );
    }
}

/// Sanity-check that the goldens dir exists and contains all four
/// expected files. A missing golden is a separate failure mode from
/// byte-mismatch and gets a distinct error message.
#[test]
fn trust_card_goldens_dir_contains_all_four_fixtures() {
    let dir = goldens_dir();
    assert!(
        dir.is_dir(),
        "goldens directory must exist at {}",
        dir.display()
    );
    for name in GOLDEN_NAMES {
        let path = dir.join(format!("{name}.golden"));
        assert!(
            path.is_file(),
            "expected golden fixture at {} (bd-98xo5.4.4 references all 4 fixtures); missing one would mean a peer commit deleted/renamed it",
            path.display()
        );
    }
}

#[test]
fn streaming_encoder_preserves_active_minimal_golden() {
    assert_golden_round_trips("active_minimal");
}

#[test]
fn streaming_encoder_preserves_dependency_rich_golden() {
    assert_golden_round_trips("dependency_rich");
}

#[test]
fn streaming_encoder_preserves_revoked_quarantine_golden() {
    assert_golden_round_trips("revoked_quarantine");
}

#[test]
fn streaming_encoder_preserves_audit_heavy_golden() {
    assert_golden_round_trips("audit_heavy");
}

/// Aggregate test that runs the byte-equality check on every golden
/// in the directory. Catches a peer commit that drops a new golden
/// into the tree without updating GOLDEN_NAMES.
#[test]
fn streaming_encoder_preserves_every_golden_in_directory() {
    let dir = goldens_dir();
    let entries =
        fs::read_dir(&dir).unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()));
    let mut count = 0;
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("golden") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_else(|| panic!("non-UTF-8 golden filename at {}", path.display()))
            .to_string();
        assert_golden_round_trips(&stem);
        count += 1;
    }
    assert!(
        count >= GOLDEN_NAMES.len(),
        "expected at least {} goldens but found {} — peer commit may have removed fixtures",
        GOLDEN_NAMES.len(),
        count
    );
}

/// Self-test: the streaming encoder must produce IDENTICAL bytes for
/// the same input across multiple invocations. A regression that made
/// the encoder non-deterministic would silently break golden
/// preservation in surprising ways (the goldens might "appear" to
/// pass on a single run and fail on the next).
#[test]
fn streaming_encoder_is_idempotent_on_goldens() {
    for name in GOLDEN_NAMES {
        let path: PathBuf = goldens_dir().join(format!("{name}.golden"));
        let golden_bytes = fs::read(&path).expect("golden read");
        let value: serde_json::Value = serde_json::from_slice(&golden_bytes).expect("golden parse");
        let bytes_a = canonical_bytes(&value);
        let bytes_b = canonical_bytes(&value);
        let bytes_c = canonical_bytes(&value);
        assert_eq!(bytes_a, bytes_b, "{name}: invocation 1 vs 2 differ");
        assert_eq!(bytes_b, bytes_c, "{name}: invocation 2 vs 3 differ");
    }
}

/// Helper to silence the `Path` import on the unused branch when
/// future authors expand the test.
#[allow(dead_code)]
fn _path_lint_silencer(_: &Path) {}
