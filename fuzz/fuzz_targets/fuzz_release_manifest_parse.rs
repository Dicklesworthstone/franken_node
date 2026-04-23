#![no_main]

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use frankenengine_node::supply_chain::artifact_signing::{
    ArtifactSigningError, ChecksumManifest, KeyId, ManifestEntry,
};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 256 * 1024;
const MAX_ENTRIES: usize = 64;
const MAX_SUFFIX_CHARS: usize = 48;

#[derive(Debug, Arbitrary)]
struct ManifestParseInput {
    raw_bytes: Vec<u8>,
    entries: Vec<FuzzManifestEntry>,
}

#[derive(Debug, Arbitrary)]
struct FuzzManifestEntry {
    hash_bytes: [u8; 32],
    name_suffix: String,
    size_bytes: u64,
}

fuzz_target!(|input: ManifestParseInput| {
    fuzz_raw_manifest_bytes(&input.raw_bytes);
    fuzz_structured_manifest(input.entries);
});

fn fuzz_raw_manifest_bytes(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_BYTES {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };

    if let Ok(entries) = ChecksumManifest::parse_canonical(text) {
        assert_canonical_roundtrip(&entries);
    }
}

fn fuzz_structured_manifest(entries: Vec<FuzzManifestEntry>) {
    let entries = canonical_entries(entries);
    let canonical = render_entries(&entries);

    let parsed = ChecksumManifest::parse_canonical(&canonical)
        .expect("generated canonical manifest must parse");
    assert_eq!(parsed, entries);
    assert_canonical_roundtrip(&parsed);

    assert_manifest_line_invalid(&drop_trailing_newline(&canonical));
    assert_manifest_line_invalid(&duplicate_first_row(&canonical));
    if entries.len() > 1 {
        assert_manifest_line_invalid(&reverse_rows(&canonical));
    }
    assert_manifest_line_invalid(&replace_first_name(&canonical, "../evil"));
    assert_manifest_line_invalid(&uppercase_first_hash_nibble(&canonical));
    assert_manifest_line_invalid(&add_leading_zero_to_first_size(&canonical));
}

fn canonical_entries(entries: Vec<FuzzManifestEntry>) -> Vec<ManifestEntry> {
    let mut by_name = BTreeMap::new();
    for (index, entry) in entries.into_iter().take(MAX_ENTRIES).enumerate() {
        let suffix = sanitize_suffix(&entry.name_suffix);
        let name = format!("artifact-{index:04}-{suffix}.bin");
        by_name.insert(
            name.clone(),
            ManifestEntry {
                name,
                sha256: hex::encode(entry.hash_bytes),
                size_bytes: entry.size_bytes,
            },
        );
    }

    if by_name.is_empty() {
        by_name.insert(
            "artifact-0000-empty.bin".to_string(),
            ManifestEntry {
                name: "artifact-0000-empty.bin".to_string(),
                sha256: "0".repeat(64),
                size_bytes: 0,
            },
        );
    }

    by_name.into_values().collect()
}

fn sanitize_suffix(value: &str) -> String {
    let mut suffix = String::new();
    for ch in value.chars().take(MAX_SUFFIX_CHARS) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            suffix.push(ch);
        }
    }
    if suffix.is_empty() {
        "entry".to_string()
    } else {
        suffix
    }
}

fn render_entries(entries: &[ManifestEntry]) -> String {
    let mut text = String::new();
    for entry in entries {
        text.push_str(&format!(
            "{}  {}  {}\n",
            entry.sha256, entry.name, entry.size_bytes
        ));
    }
    text
}

fn assert_canonical_roundtrip(entries: &[ManifestEntry]) {
    let manifest = ChecksumManifest {
        entries: entries
            .iter()
            .map(|entry| (entry.name.clone(), entry.clone()))
            .collect(),
        key_id: KeyId("fuzz-key".to_string()),
        signature: Vec::new(),
    };
    let canonical =
        String::from_utf8(manifest.canonical_bytes()).expect("canonical manifest bytes are ASCII");
    let reparsed = ChecksumManifest::parse_canonical(&canonical)
        .expect("canonicalized parsed manifest must parse again");
    assert_eq!(reparsed, manifest.entries.into_values().collect::<Vec<_>>());
}

fn assert_manifest_line_invalid(text: &str) {
    let result = ChecksumManifest::parse_canonical(text);
    assert!(
        matches!(
            result,
            Err(ArtifactSigningError::ManifestLineInvalid { .. })
        ),
        "mutated manifest must fail closed with a typed manifest-line error: {result:?}"
    );
}

fn drop_trailing_newline(canonical: &str) -> String {
    canonical
        .strip_suffix('\n')
        .unwrap_or(canonical)
        .to_string()
}

fn duplicate_first_row(canonical: &str) -> String {
    let Some(first_row) = canonical.lines().next() else {
        return canonical.to_string();
    };
    format!("{canonical}{first_row}\n")
}

fn reverse_rows(canonical: &str) -> String {
    let mut rows = canonical.lines().collect::<Vec<_>>();
    rows.reverse();
    format!("{}\n", rows.join("\n"))
}

fn replace_first_name(canonical: &str, replacement: &str) -> String {
    mutate_first_row(canonical, |parts| {
        parts[1] = replacement.to_string();
    })
}

fn uppercase_first_hash_nibble(canonical: &str) -> String {
    mutate_first_row(canonical, |parts| {
        let mut chars = parts[0].chars().collect::<Vec<_>>();
        if let Some(first) = chars.first_mut() {
            *first = 'A';
        }
        parts[0] = chars.into_iter().collect();
    })
}

fn add_leading_zero_to_first_size(canonical: &str) -> String {
    mutate_first_row(canonical, |parts| {
        parts[2] = format!("0{}", parts[2]);
    })
}

fn mutate_first_row(canonical: &str, mutate: impl FnOnce(&mut [String; 3])) -> String {
    let mut rows = canonical.lines().map(str::to_string).collect::<Vec<_>>();
    if let Some(first) = rows.first_mut() {
        let split = first.splitn(3, "  ").collect::<Vec<_>>();
        if split.len() == 3 {
            let mut parts = [
                split[0].to_string(),
                split[1].to_string(),
                split[2].to_string(),
            ];
            mutate(&mut parts);
            *first = format!("{}  {}  {}", parts[0], parts[1], parts[2]);
        }
    }
    format!("{}\n", rows.join("\n"))
}
