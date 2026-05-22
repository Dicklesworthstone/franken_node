#![no_main]
#![forbid(unsafe_code)]

//! Structure-aware fuzzing for the remote computation registry.
//!
//! This target exercises canonical name validation, registration normalization,
//! duplicate rejection, audit emission, catalog round trips, monotonic version
//! bumps, and missing-capability dispatch denial.

use std::collections::{BTreeMap, BTreeSet};

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use frankenengine_node::remote::computation_registry::{
    is_canonical_computation_name, ComputationEntry, ComputationRegistry, ComputationRegistryError,
    RegistryCatalog, CR_LOOKUP_MALFORMED, CR_LOOKUP_SUCCESS, CR_LOOKUP_UNKNOWN, CR_REGISTRY_LOADED,
    CR_REGISTRY_REJECTED, CR_VERSION_UPGRADED, ERR_DUPLICATE_COMPUTATION,
    ERR_INVALID_COMPUTATION_ENTRY, ERR_MALFORMED_COMPUTATION_NAME, ERR_REGISTRY_VERSION_REGRESSION,
    ERR_UNKNOWN_COMPUTATION,
};
use frankenengine_node::security::remote_cap::{CapabilityGate, RemoteOperation};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_ENTRIES: usize = 24;
const MAX_LABEL_BYTES: usize = 32;
const MAX_TEXT_BYTES: usize = 256;
const MAX_CAPABILITIES: usize = 12;
const KNOWN_EVENT_CODES: &[&str] = &[
    CR_REGISTRY_LOADED,
    CR_LOOKUP_SUCCESS,
    CR_LOOKUP_UNKNOWN,
    CR_LOOKUP_MALFORMED,
    CR_VERSION_UPGRADED,
    CR_REGISTRY_REJECTED,
];

#[derive(Debug)]
struct RegistryCase {
    version: u64,
    bump_version: u64,
    entries: Vec<EntrySpec>,
    lookup_name: NameSpec,
    unknown_name: NameSpec,
    malformed_seed: Vec<u8>,
}

impl<'a> Arbitrary<'a> for RegistryCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            version: u64::arbitrary(u)?,
            bump_version: u64::arbitrary(u)?,
            entries: bounded_vec(u, MAX_ENTRIES)?,
            lookup_name: NameSpec::arbitrary(u)?,
            unknown_name: NameSpec::arbitrary(u)?,
            malformed_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
        })
    }
}

#[derive(Debug)]
struct EntrySpec {
    name: NameSpec,
    flags: u8,
    description_seed: Vec<u8>,
    input_schema_seed: Vec<u8>,
    output_schema_seed: Vec<u8>,
    capabilities: Vec<FuzzOperation>,
}

impl<'a> Arbitrary<'a> for EntrySpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            name: NameSpec::arbitrary(u)?,
            flags: u8::arbitrary(u)?,
            description_seed: bounded_bytes(u, MAX_TEXT_BYTES)?,
            input_schema_seed: bounded_bytes(u, MAX_TEXT_BYTES)?,
            output_schema_seed: bounded_bytes(u, MAX_TEXT_BYTES)?,
            capabilities: bounded_vec(u, MAX_CAPABILITIES)?,
        })
    }
}

impl EntrySpec {
    fn entry(&self, index: usize) -> ComputationEntry {
        let mut name = self.name.canonical_name(index);
        if self.flags & 0b0000_0001 != 0 {
            name = format!(" {name}\t");
        }
        if self.flags & 0b0000_0010 != 0 {
            name = malformed_name(&self.name.domain_seed);
        }

        ComputationEntry {
            name,
            description: field_text(
                "description",
                &self.description_seed,
                self.flags & 0b0000_0100 != 0,
            ),
            required_capabilities: self
                .capabilities
                .iter()
                .copied()
                .map(FuzzOperation::into_operation)
                .collect(),
            input_schema: field_text(
                "input",
                &self.input_schema_seed,
                self.flags & 0b0000_1000 != 0,
            ),
            output_schema: field_text(
                "output",
                &self.output_schema_seed,
                self.flags & 0b0001_0000 != 0,
            ),
        }
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

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzOperation {
    NetworkEgress,
    FederationSync,
    RevocationFetch,
    RemoteAttestationVerify,
    TelemetryExport,
    RemoteComputation,
    ArtifactUpload,
}

impl FuzzOperation {
    fn into_operation(self) -> RemoteOperation {
        match self {
            Self::NetworkEgress => RemoteOperation::NetworkEgress,
            Self::FederationSync => RemoteOperation::FederationSync,
            Self::RevocationFetch => RemoteOperation::RevocationFetch,
            Self::RemoteAttestationVerify => RemoteOperation::RemoteAttestationVerify,
            Self::TelemetryExport => RemoteOperation::TelemetryExport,
            Self::RemoteComputation => RemoteOperation::RemoteComputation,
            Self::ArtifactUpload => RemoteOperation::ArtifactUpload,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(case) = RegistryCase::arbitrary(&mut u) else {
        return;
    };

    fuzz_registry_case(case);
});

fn fuzz_registry_case(case: RegistryCase) {
    let mut registry = ComputationRegistry::new(case.version, "trace-fuzz-load");
    assert_eq!(registry.registry_version(), case.version);
    assert_eq!(registry.audit_events().len(), 1);
    assert_eq!(registry.audit_events()[0].event_code, CR_REGISTRY_LOADED);

    let mut expected_entries = BTreeMap::new();
    for (index, spec) in case.entries.iter().enumerate() {
        let raw = spec.entry(index);
        let expected = expected_registration(&raw, &expected_entries);
        let result = registry.register_computation(raw, &trace_id("register", index));
        check_registration_result(&result, &expected);
        if result.is_ok() {
            let normalized = expected.normalized_entry;
            expected_entries.insert(normalized.name.clone(), normalized);
        }
        check_audit_log(registry.audit_events());
        check_listing(&registry, &expected_entries);
    }

    check_lookup_paths(
        &mut registry,
        &expected_entries,
        &case.lookup_name,
        &case.unknown_name,
        &case.malformed_seed,
    );
    check_version_bump(&mut registry, case.version, case.bump_version);
    check_catalog_roundtrip(&registry);
    check_missing_cap_dispatch(&mut registry, &expected_entries);
}

#[derive(Debug)]
struct ExpectedRegistration {
    normalized_entry: ComputationEntry,
    expected_error_code: Option<&'static str>,
}

fn expected_registration(
    raw: &ComputationEntry,
    existing: &BTreeMap<String, ComputationEntry>,
) -> ExpectedRegistration {
    let normalized = normalized_entry(raw);
    let expected_error_code = if !is_canonical_computation_name(&normalized.name) {
        Some(ERR_MALFORMED_COMPUTATION_NAME)
    } else if normalized.description.is_empty()
        || normalized.input_schema.is_empty()
        || normalized.output_schema.is_empty()
    {
        Some(ERR_INVALID_COMPUTATION_ENTRY)
    } else if existing.contains_key(&normalized.name) {
        Some(ERR_DUPLICATE_COMPUTATION)
    } else {
        None
    };

    ExpectedRegistration {
        normalized_entry: normalized,
        expected_error_code,
    }
}

fn check_registration_result(
    result: &Result<(), ComputationRegistryError>,
    expected: &ExpectedRegistration,
) {
    match (result, expected.expected_error_code) {
        (Ok(()), None) => {}
        (Err(err), Some(expected_code)) => {
            assert_eq!(err.code(), expected_code);
            let rendered = err.to_string();
            assert!(
                !rendered.chars().any(char::is_control),
                "registry errors must sanitize control characters before Display"
            );
        }
        (Ok(()), Some(expected_code)) => {
            assert!(
                expected_code.is_empty(),
                "registration unexpectedly succeeded for {expected_code}"
            );
        }
        (Err(err), None) => {
            assert!(
                err.code().is_empty(),
                "registration unexpectedly failed with {}",
                err.code()
            );
        }
    }
}

fn check_listing(
    registry: &ComputationRegistry,
    expected_entries: &BTreeMap<String, ComputationEntry>,
) {
    let listed = registry.list_computations();
    assert_eq!(listed.len(), expected_entries.len());

    for entry in &listed {
        let Some(expected) = expected_entries.get(&entry.name) else {
            assert!(
                expected_entries.contains_key(&entry.name),
                "listed entry must have been registered"
            );
            continue;
        };
        assert_eq!(entry, expected);
        assert!(entry
            .required_capabilities
            .contains(&RemoteOperation::RemoteComputation));
        assert_sorted_unique(&entry.required_capabilities);
    }
}

fn check_lookup_paths(
    registry: &mut ComputationRegistry,
    expected_entries: &BTreeMap<String, ComputationEntry>,
    lookup_name: &NameSpec,
    unknown_name: &NameSpec,
    malformed_seed: &[u8],
) {
    if let Some((name, expected_entry)) = expected_entries.iter().next() {
        let lookup = registry.validate_computation_name(name, "trace-fuzz-known-lookup");
        assert_eq!(lookup, Ok(expected_entry.clone()));
    }

    let unknown = distinct_unknown_name(unknown_name.canonical_name(999), expected_entries);
    let unknown_result = registry.validate_computation_name(&unknown, "trace-fuzz-unknown-lookup");
    assert!(
        matches!(
            unknown_result,
            Err(ComputationRegistryError::UnknownComputation { .. })
        ),
        "canonical unregistered names must fail as unknown"
    );
    if let Err(err) = unknown_result {
        assert_eq!(err.code(), ERR_UNKNOWN_COMPUTATION);
    }

    let malformed = malformed_name(malformed_seed);
    if !is_canonical_computation_name(&malformed) {
        let malformed_result =
            registry.validate_computation_name(&malformed, "trace-fuzz-malformed-lookup");
        assert!(
            matches!(
                malformed_result,
                Err(ComputationRegistryError::MalformedComputationName { .. })
            ),
            "malformed names must fail before lookup"
        );
        if let Err(err) = malformed_result {
            assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
            assert!(!err.to_string().chars().any(char::is_control));
        }
    }

    let generated = lookup_name.canonical_name(1001);
    assert!(is_canonical_computation_name(&generated));
}

fn check_version_bump(registry: &mut ComputationRegistry, initial: u64, bump_version: u64) {
    let before = registry.registry_version();
    let result = registry.bump_version(bump_version, "trace-fuzz-version-bump");
    if bump_version > before {
        assert!(result.is_ok());
        assert_eq!(registry.registry_version(), bump_version);
    } else {
        assert!(matches!(
            result,
            Err(ComputationRegistryError::VersionRegression { .. })
        ));
        assert_eq!(registry.registry_version(), before);
        if let Err(err) = result {
            assert_eq!(err.code(), ERR_REGISTRY_VERSION_REGRESSION);
        }
    }
    assert!(registry.registry_version() >= initial);
}

fn check_catalog_roundtrip(registry: &ComputationRegistry) {
    let catalog = registry.to_catalog();
    let serialized = serde_json::to_vec(&catalog);
    let Ok(serialized) = serialized else {
        return;
    };
    let parsed: Result<RegistryCatalog, _> = serde_json::from_slice(&serialized);
    let Ok(parsed) = parsed else {
        return;
    };
    assert_eq!(parsed, catalog);

    let restored = ComputationRegistry::from_catalog(catalog.clone(), "trace-fuzz-catalog");
    let Ok(restored) = restored else {
        return;
    };
    assert_eq!(restored.registry_version(), catalog.registry_version);
    assert_eq!(restored.list_computations(), catalog.entries);
    check_audit_log(restored.audit_events());
}

fn check_missing_cap_dispatch(
    registry: &mut ComputationRegistry,
    expected_entries: &BTreeMap<String, ComputationEntry>,
) {
    let Some((name, _)) = expected_entries.iter().next() else {
        return;
    };
    let Ok(mut gate) = CapabilityGate::new("registry-fuzz-secret") else {
        return;
    };
    let result = registry.authorize_dispatch(
        name,
        "https://compute.example.com/job",
        None,
        &mut gate,
        1_700_000_000,
        "trace-fuzz-missing-cap",
    );
    assert!(
        matches!(result, Err(ComputationRegistryError::DispatchDenied { .. })),
        "registered dispatch without a capability must fail closed"
    );
}

fn check_audit_log(
    events: &[frankenengine_node::remote::computation_registry::RegistryAuditEvent],
) {
    assert!(!events.is_empty());
    for event in events {
        assert!(KNOWN_EVENT_CODES.contains(&event.event_code.as_str()));
        if let Some(name) = &event.computation_name {
            assert!(
                !name.chars().any(char::is_control),
                "audit computation_name must be display-sanitized"
            );
        }
    }
}

fn normalized_entry(raw: &ComputationEntry) -> ComputationEntry {
    let mut capabilities: BTreeSet<RemoteOperation> =
        raw.required_capabilities.iter().copied().collect();
    capabilities.insert(RemoteOperation::RemoteComputation);
    ComputationEntry {
        name: raw.name.trim().to_string(),
        description: raw.description.trim().to_string(),
        required_capabilities: capabilities.into_iter().collect(),
        input_schema: raw.input_schema.trim().to_string(),
        output_schema: raw.output_schema.trim().to_string(),
    }
}

fn assert_sorted_unique(values: &[RemoteOperation]) {
    let unique: BTreeSet<RemoteOperation> = values.iter().copied().collect();
    assert_eq!(unique.len(), values.len());
    let sorted: Vec<RemoteOperation> = unique.into_iter().collect();
    assert_eq!(sorted, values);
}

fn field_text(prefix: &str, seed: &[u8], blank: bool) -> String {
    if blank {
        return " \t\n ".to_string();
    }
    format!(" {prefix}:{} ", ascii_text(seed))
}

fn ascii_text(seed: &[u8]) -> String {
    let mut out = String::new();
    for byte in seed.iter().take(MAX_TEXT_BYTES) {
        let ch = match byte % 38 {
            n @ 0..=25 => char::from(b'a'.saturating_add(n)),
            n @ 26..=35 => char::from(b'0'.saturating_add(n.saturating_sub(26))),
            36 => '_',
            _ => '-',
        };
        out.push(ch);
    }
    if out.is_empty() {
        "x".to_string()
    } else {
        out
    }
}

fn distinct_unknown_name(
    mut candidate: String,
    existing: &BTreeMap<String, ComputationEntry>,
) -> String {
    let mut salt = 0usize;
    while existing.contains_key(&candidate) {
        candidate = format!("unknown.lookup_{salt}.v1");
        salt = salt.saturating_add(1);
    }
    candidate
}

fn trace_id(prefix: &str, index: usize) -> String {
    format!("trace-fuzz-{prefix}-{index}")
}

fn component(prefix: &str, salt: usize, seed: &[u8]) -> String {
    let mut out = String::new();
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

fn bounded_vec<'a, T: Arbitrary<'a>>(
    u: &mut Unstructured<'a>,
    max_items: usize,
) -> ArbResult<Vec<T>> {
    let count = usize::arbitrary(u)? % max_items.saturating_add(1);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(T::arbitrary(u)?);
    }
    Ok(out)
}

fn bounded_bytes(u: &mut Unstructured<'_>, max: usize) -> ArbResult<Vec<u8>> {
    let len = usize::arbitrary(u)? % max.saturating_add(1);
    Ok(u.bytes(len)?.to_vec())
}
