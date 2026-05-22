#![no_main]
#![forbid(unsafe_code)]

//! Structure-aware fuzzing for remote idempotency key derivation.
//!
//! The target checks deterministic derivation, hex round trips, framed domain /
//! computation / epoch separation, duplicate-payload collision accounting, and
//! registry-aware validation parity for canonical remote computation names.

use std::collections::BTreeSet;

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use frankenengine_node::remote::computation_registry::{
    is_canonical_computation_name, ComputationEntry, ComputationRegistry,
};
use frankenengine_node::remote::idempotency::{
    key_fingerprint, IdempotencyError, IdempotencyKey, IdempotencyKeyDeriver, IDEMPOTENCY_KEY_LEN,
};
use frankenengine_node::security::remote_cap::RemoteOperation;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_LABEL_BYTES: usize = 48;
const MAX_DOMAIN_BYTES: usize = 64;
const MAX_PAYLOAD_BYTES: usize = 256;
const MAX_PAYLOADS: usize = 16;

#[derive(Debug)]
struct IdempotencyCase {
    domain_prefix_seed: Vec<u8>,
    alternate_domain_seed: Vec<u8>,
    primary_name: NameSpec,
    alternate_name: NameSpec,
    malformed_seed: Vec<u8>,
    epoch: u64,
    payload: Vec<u8>,
    payloads: Vec<Vec<u8>>,
}

impl<'a> Arbitrary<'a> for IdempotencyCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            domain_prefix_seed: bounded_bytes(u, MAX_DOMAIN_BYTES)?,
            alternate_domain_seed: bounded_bytes(u, MAX_DOMAIN_BYTES)?,
            primary_name: NameSpec::arbitrary(u)?,
            alternate_name: NameSpec::arbitrary(u)?,
            malformed_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            epoch: u64::arbitrary(u)?,
            payload: bounded_bytes(u, MAX_PAYLOAD_BYTES)?,
            payloads: bounded_vec_of_bytes(u, MAX_PAYLOADS, MAX_PAYLOAD_BYTES)?,
        })
    }
}

#[derive(Debug)]
struct NameSpec {
    domain_seed: Vec<u8>,
    action_seed: Vec<u8>,
    version_seed: u16,
}

impl<'a> Arbitrary<'a> for NameSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            domain_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            action_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            version_seed: u16::arbitrary(u)?,
        })
    }
}

impl NameSpec {
    fn canonical_name(&self, salt: usize) -> String {
        format!(
            "{}.{}.v{}",
            component("domain", salt, &self.domain_seed),
            component("action", salt, &self.action_seed),
            u32::from(self.version_seed % 4096).saturating_add(1)
        )
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(case) = IdempotencyCase::arbitrary(&mut u) else {
        return;
    };

    fuzz_idempotency_case(case);
});

fn fuzz_idempotency_case(case: IdempotencyCase) {
    let domain_prefix = nonempty_bytes(case.domain_prefix_seed, b"remote-idempotency");
    let alternate_domain = nonempty_distinct_bytes(
        case.alternate_domain_seed,
        &domain_prefix,
        b"remote-idempotency-alt",
    );
    let deriver = match IdempotencyKeyDeriver::new(&domain_prefix) {
        Ok(deriver) => deriver,
        Err(_) => return,
    };
    let alternate_deriver = match IdempotencyKeyDeriver::new(&alternate_domain) {
        Ok(deriver) => deriver,
        Err(_) => return,
    };

    let primary_name = case.primary_name.canonical_name(0);
    let alternate_name = distinct_name(case.alternate_name.canonical_name(1), &primary_name);
    assert!(is_canonical_computation_name(&primary_name));
    assert!(is_canonical_computation_name(&alternate_name));

    let key = match deriver.derive_key(&primary_name, case.epoch, &case.payload) {
        Ok(key) => key,
        Err(_) => return,
    };
    check_determinism(&deriver, &primary_name, case.epoch, &case.payload, key);
    check_hex_roundtrip(key);
    check_fingerprint(key);
    check_separation(
        &deriver,
        &alternate_deriver,
        &primary_name,
        &alternate_name,
        case.epoch,
        &case.payload,
        key,
    );
    check_collision_accounting(&deriver, &primary_name, case.epoch, case.payloads);
    check_registry_parity(&deriver, &primary_name, case.epoch, &case.payload);
    check_rejection_paths(&deriver, &case.malformed_seed);
}

fn check_determinism(
    deriver: &IdempotencyKeyDeriver,
    name: &str,
    epoch: u64,
    payload: &[u8],
    key: IdempotencyKey,
) {
    let Ok(replayed) = deriver.derive_key(name, epoch, payload) else {
        return;
    };
    assert_eq!(key, replayed, "same remote idempotency inputs must replay");
    assert_eq!(
        deriver.domain_prefix(),
        deriver.domain_prefix(),
        "domain prefix accessor must be stable"
    );
}

fn check_hex_roundtrip(key: IdempotencyKey) {
    let hex = key.to_hex();
    assert_eq!(hex.len(), IDEMPOTENCY_KEY_LEN.saturating_mul(2));

    let reparsed = IdempotencyKey::from_hex(&hex);
    assert_eq!(reparsed, Ok(key), "hex serialization must round trip");

    let uppercase = hex.to_ascii_uppercase();
    let uppercase_reparsed = IdempotencyKey::from_hex(&uppercase);
    assert_eq!(
        uppercase_reparsed,
        Ok(key),
        "hex parser must preserve key bytes across case"
    );
}

fn check_fingerprint(key: IdempotencyKey) {
    let fingerprint = key_fingerprint(&key);
    assert!(fingerprint.starts_with("fp:"));
    assert_eq!(fingerprint.len(), 19);
    assert!(
        fingerprint
            .strip_prefix("fp:")
            .is_some_and(|suffix| suffix.chars().all(|ch| ch.is_ascii_hexdigit())),
        "fingerprint suffix must be fixed-width hex"
    );
}

fn check_separation(
    deriver: &IdempotencyKeyDeriver,
    alternate_deriver: &IdempotencyKeyDeriver,
    primary_name: &str,
    alternate_name: &str,
    epoch: u64,
    payload: &[u8],
    key: IdempotencyKey,
) {
    if let Ok(name_key) = deriver.derive_key(alternate_name, epoch, payload) {
        assert_ne!(
            key, name_key,
            "different canonical computation names must domain-separate keys"
        );
    }

    if let Ok(epoch_key) = deriver.derive_key(primary_name, epoch.wrapping_add(1), payload) {
        assert_ne!(key, epoch_key, "epoch must be part of key derivation");
    }

    if let Ok(domain_key) = alternate_deriver.derive_key(primary_name, epoch, payload) {
        assert_ne!(
            key, domain_key,
            "domain prefix must be part of key derivation"
        );
    }

    let mut extended_payload = payload.to_vec();
    extended_payload.push(0);
    if let Ok(payload_key) = deriver.derive_key(primary_name, epoch, &extended_payload) {
        assert_ne!(
            key, payload_key,
            "request bytes must be part of key derivation"
        );
    }
}

fn check_collision_accounting(
    deriver: &IdempotencyKeyDeriver,
    name: &str,
    epoch: u64,
    mut payloads: Vec<Vec<u8>>,
) {
    if payloads.is_empty() {
        payloads.push(Vec::new());
    }
    if let Some(first) = payloads.first().cloned() {
        payloads.push(first);
    }
    let payloads: Vec<Vec<u8>> = payloads
        .into_iter()
        .take(MAX_PAYLOADS.saturating_add(1))
        .map(|payload| payload.into_iter().take(MAX_PAYLOAD_BYTES).collect())
        .collect();

    let unique_payloads: BTreeSet<Vec<u8>> = payloads.iter().cloned().collect();
    let expected_duplicate_count = payloads.len().saturating_sub(unique_payloads.len());
    let Ok(collisions) = deriver.collision_count(name, epoch, &payloads) else {
        return;
    };
    assert_eq!(
        collisions, expected_duplicate_count,
        "duplicate payloads should account for deterministic idempotency collisions"
    );
}

fn check_registry_parity(deriver: &IdempotencyKeyDeriver, name: &str, epoch: u64, payload: &[u8]) {
    let mut registry = ComputationRegistry::new(1, "trace-fuzz-load");
    let registration = registry.register_computation(sample_entry(name), "trace-fuzz-register");
    if registration.is_err() {
        return;
    }

    let direct = deriver.derive_key(name, epoch, payload);
    let registered =
        deriver.derive_registered_key(&mut registry, name, epoch, payload, "trace-fuzz-derive");
    assert_eq!(
        registered, direct,
        "registered derivation must match direct derivation after registry validation"
    );

    let catalog = registry.to_catalog();
    let restored = ComputationRegistry::from_catalog(catalog.clone(), "trace-fuzz-restore");
    let Ok(mut restored) = restored else {
        return;
    };
    assert_eq!(restored.registry_version(), catalog.registry_version);
    assert_eq!(restored.list_computations(), catalog.entries);
    assert!(
        restored
            .validate_computation_name(name, "trace-fuzz-restored-lookup")
            .is_ok(),
        "catalog restore must preserve registered computation lookup"
    );
}

fn check_rejection_paths(deriver: &IdempotencyKeyDeriver, malformed_seed: &[u8]) {
    let blank_err = deriver.derive_key(" \t\n", 0, b"payload");
    assert!(matches!(
        blank_err,
        Err(IdempotencyError::EmptyComputationName)
    ));
    assert!(matches!(
        IdempotencyKeyDeriver::new(&[]),
        Err(IdempotencyError::EmptyDomainPrefix)
    ));

    let malformed = malformed_name(malformed_seed);
    if !is_canonical_computation_name(&malformed) {
        let mut registry = ComputationRegistry::new(1, "trace-fuzz-malformed-load");
        let registered = deriver.derive_registered_key(
            &mut registry,
            &malformed,
            0,
            b"payload",
            "trace-fuzz-malformed",
        );
        assert!(
            matches!(registered, Err(IdempotencyError::RegistryRejected { .. })),
            "registry-aware derivation must reject malformed or unknown names"
        );
    }

    let short_hex = "00".repeat(IDEMPOTENCY_KEY_LEN.saturating_sub(1));
    assert!(matches!(
        IdempotencyKey::from_hex(&short_hex),
        Err(IdempotencyError::InvalidHex { .. })
    ));
}

fn sample_entry(name: &str) -> ComputationEntry {
    ComputationEntry {
        name: name.to_string(),
        description: "Remote idempotency fuzz computation".to_string(),
        required_capabilities: vec![
            RemoteOperation::RemoteComputation,
            RemoteOperation::FederationSync,
        ],
        input_schema: r#"{"type":"object"}"#.to_string(),
        output_schema: r#"{"type":"object"}"#.to_string(),
    }
}

fn bounded_vec_of_bytes(
    u: &mut Unstructured<'_>,
    max_items: usize,
    max_item_bytes: usize,
) -> ArbResult<Vec<Vec<u8>>> {
    let count = usize::arbitrary(u)? % max_items.saturating_add(1);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(bounded_bytes(u, max_item_bytes)?);
    }
    Ok(out)
}

fn bounded_bytes(u: &mut Unstructured<'_>, max: usize) -> ArbResult<Vec<u8>> {
    let len = usize::arbitrary(u)? % max.saturating_add(1);
    let bytes = u.bytes(len)?;
    Ok(bytes.to_vec())
}

fn nonempty_bytes(mut seed: Vec<u8>, fallback: &[u8]) -> Vec<u8> {
    seed.truncate(MAX_DOMAIN_BYTES);
    if seed.is_empty() {
        fallback.to_vec()
    } else {
        seed
    }
}

fn nonempty_distinct_bytes(seed: Vec<u8>, first: &[u8], fallback: &[u8]) -> Vec<u8> {
    let mut candidate = nonempty_bytes(seed, fallback);
    if candidate == first {
        candidate.push(1);
    }
    candidate
}

fn component(prefix: &str, salt: usize, seed: &[u8]) -> String {
    let mut out = String::with_capacity(prefix.len().saturating_add(16));
    out.push_str(prefix);
    out.push('_');
    out.push_str(&salt.to_string());
    for byte in seed.iter().take(16) {
        let ch = match byte % 37 {
            n @ 0..=25 => char::from(b'a'.saturating_add(n)),
            n @ 26..=35 => char::from(b'0'.saturating_add(n.saturating_sub(26))),
            _ => '_',
        };
        out.push(ch);
    }
    out
}

fn distinct_name(candidate: String, existing: &str) -> String {
    if candidate == existing {
        "remote_idempotency.alt.v1".to_string()
    } else {
        candidate
    }
}

fn malformed_name(seed: &[u8]) -> String {
    if seed.is_empty() {
        return "bad-name".to_string();
    }
    let mut out = String::from("bad");
    for byte in seed.iter().take(16) {
        let ch = match byte % 6 {
            0 => '-',
            1 => '.',
            2 => 'A',
            3 => '\n',
            4 => ' ',
            _ => char::from(b'a'.saturating_add(byte % 26)),
        };
        out.push(ch);
    }
    out
}
