//! Authenticate publisher-approved source bytes without the product or engine.
//!
//! The publisher signs the exact registration manifest bytes using Ed25519.
//! Its initial-version content hash binds the raw FNSGCAP1 artifact. The existing
//! independent capsule reader then checks framing, canonical metadata, paths,
//! and every retained file digest. It never extracts files or evaluates code.
//!
//! Success authenticates publisher statements and byte integrity. It does not
//! establish registry admission, provenance, current revocation, source-graph
//! completeness, execution, or enforcement of the signed authority. The graph
//! commitment is recorded and authenticated, not rederived by this SDK.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::incident_bundle::{decode_evidence_json, native_capture::module_capsule};
pub use module_capsule::SourceCapsuleSummary;

/// Raw manifest and raw artifact bounds match installed registry admission.
pub const MAX_PUBLISHER_SOURCE_BYTES: usize = 5 * 1024 * 1024;
const MAX_ENCODED_BYTES: usize = MAX_PUBLISHER_SOURCE_BYTES.div_ceil(3) * 4;
/// Bound the entire transport before parsing either base64 field. The small
/// allowance accommodates the fixed schema and object syntax, not other fields.
pub const MAX_PUBLISHER_SOURCE_INPUT_BYTES: usize = 2 * MAX_ENCODED_BYTES + 256;
pub const PUBLISHER_SOURCE_INPUT_SCHEMA: &str = "franken-verifier/publisher-source-input/v1";
pub const REGISTRATION_SCHEMA_V1: &str = "franken-node/extension-registration-manifest/v1";
pub const REGISTRATION_SCHEMA_V2: &str = "franken-node/extension-registration-manifest/v2";
pub const RUNTIME_AUTHORITY_SCHEMA: &str = "franken-node/artifact-runtime-authority/v1";
pub const PUBLISHER_REVOCATION_LIST_SCHEMA: &str = "franken-node/publisher-revocation-list/v1";
pub const PUBLISHER_PROVENANCE_CHAIN_SCHEMA: &str = "franken-node/publisher-provenance-chain/v1";
const PUBLISHER_REVOCATION_DOMAIN: &[u8] = b"franken-node/publisher-revocation-list/v1:";
const PUBLISHER_PROVENANCE_DOMAIN: &[u8] = b"franken-node/publisher-provenance-chain/v1:";
const MAX_REVOCATION_LIST_BYTES: usize = 512 * 1024;
const MAX_PROVENANCE_CHAIN_BYTES: usize = 512 * 1024;
const MAX_REVOCATION_ENTRIES: usize = 1024;
const MAX_PROVENANCE_LINKS: usize = 256;

const CAPABILITIES: &[&str] = &[
    "builtin",
    "console",
    "env_read",
    "fs_read",
    "fs_write",
    "heap_allocate",
    "module_load",
    "network_egress",
    "process_spawn",
    "random_read",
    "timer",
    "vm_dispatch",
];

/// Static error categories deliberately omit untrusted paths, source bytes,
/// field values, and parser diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherSourceError {
    InputTooLarge,
    InputJsonInvalid,
    InputInvalid,
    ManifestInvalid,
    UnsupportedSchema,
    SignatureInvalid,
    ArtifactHashMismatch,
    RuntimeAuthorityInvalid,
    CapsuleInvalid,
    RevocationSignatureInvalid,
    RevocationListInvalid,
    RevocationFreshnessPolicyInvalid,
    RevocationListNotYetValid,
    RevocationListStale,
    PublisherRevoked,
    ProvenanceSignatureInvalid,
    ProvenanceChainInvalid,
}

impl std::fmt::Display for PublisherSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "publisher source input exceeds its byte bound",
            Self::InputJsonInvalid => "publisher source transport is not unambiguous JSON",
            Self::InputInvalid => "invalid publisher source transport",
            Self::ManifestInvalid => "invalid signed publisher registration manifest",
            Self::UnsupportedSchema => "unsupported publisher registration schema or authority",
            Self::SignatureInvalid => "publisher signature does not verify under the trusted key",
            Self::ArtifactHashMismatch => "source artifact differs from the signed content hash",
            Self::RuntimeAuthorityInvalid => "invalid signed publisher runtime authority",
            Self::CapsuleInvalid => "invalid publisher source capsule",
            Self::RevocationSignatureInvalid => {
                "revocation list signature does not verify under the trusted revocation authority"
            }
            Self::RevocationListInvalid => "invalid signed publisher revocation list",
            Self::RevocationFreshnessPolicyInvalid => {
                "publisher revocation freshness window must be greater than zero"
            }
            Self::RevocationListNotYetValid => {
                "publisher revocation list was issued after the trusted evaluation time"
            }
            Self::RevocationListStale => {
                "publisher revocation list is outside the trusted freshness window"
            }
            Self::PublisherRevoked => {
                "publisher, signing key, or package version is revoked by the signed revocation list"
            }
            Self::ProvenanceSignatureInvalid => {
                "provenance chain signature does not verify under the trusted provenance authority"
            }
            Self::ProvenanceChainInvalid => {
                "provenance chain is malformed or does not bind the verified manifest and artifact"
            }
        })
    }
}

impl std::error::Error for PublisherSourceError {}

type Result<T> = std::result::Result<T, PublisherSourceError>;

fn serialize_decimal<T: std::fmt::Display, S: Serializer>(
    value: &T,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

/// Authenticated ceilings, never capability grants or an enforcement verdict.
/// Numeric limits remain integers in Rust and serialize as decimal strings so
/// language consumers preserve the entire u64 range without floating-point loss.
/// The original signed manifest encodes these same limits as JSON integers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublisherRuntimeAuthority {
    pub schema_version: String,
    pub policy_revision: String,
    pub allowed_capabilities: Vec<String>,
    pub allow_process_shape: bool,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_instructions: u64,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_registers: u32,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_call_depth: u32,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_heap_objects: u32,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_total_memory_bytes: u64,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_console_entries: u32,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_parse_source_bytes: u64,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_parse_tokens: u64,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_parse_recursion_depth: u64,
}

/// Source-free claims authenticated under the caller's publisher anchor.
/// Manifest and artifact hashes use plain SHA-256 with a sha256: prefix; the
/// capsule digest uses the separate FNSGCAP1 domain and length framing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedPublisherSource {
    pub registration_schema: String,
    pub package_name: String,
    pub publisher_id: String,
    pub version: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
    pub capsule_digest: String,
    /// Product artifact-signing key ID; authenticated identity remains the
    /// complete independently supplied public key, not this shortened label.
    pub signer_key_id: String,
    pub signer_public_key_hex: String,
    pub runtime_authority: Option<PublisherRuntimeAuthority>,
    pub capsule: SourceCapsuleSummary,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputEnvelope {
    schema_version: String,
    manifest_base64: String,
    capsule_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedManifest {
    schema_version: String,
    name: String,
    publisher_id: String,
    initial_version: VersionEntry,
    tags: Vec<String>,
    runtime_authority: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionEntry {
    version: String,
    parent_version: Option<String>,
    content_hash: String,
    registered_at: String,
    compatible_with: Vec<String>,
}

fn text_is_bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn version_components(value: &str) -> Option<[u64; 3]> {
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    let mut parts = value.split('.');
    let mut version = [0_u64; 3];
    for component in &mut version {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 20 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *component = part.parse().ok()?;
    }
    parts.next().is_none().then_some(version)
}

fn package_version_identity(value: &str) -> Option<(&str, [u64; 3])> {
    if !text_is_bounded(value, 385) {
        return None;
    }
    // Scoped package names may contain '@'; only the last separator marks
    // the version. Preserve the signed spelling while comparing its numeric
    // identity so leading zeroes cannot bypass revocation.
    let (package, version) = value.rsplit_once('@')?;
    if !text_is_bounded(package, 256) {
        return None;
    }
    Some((package, version_components(version)?))
}

fn valid_version(value: &str) -> bool {
    version_components(value).is_some()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_authority(value: &Value) -> Result<PublisherRuntimeAuthority> {
    use PublisherSourceError::RuntimeAuthorityInvalid as Invalid;
    const FIELDS: &[&str] = &[
        "schema_version",
        "policy_revision",
        "allowed_capabilities",
        "allow_process_shape",
        "max_instructions",
        "max_registers",
        "max_call_depth",
        "max_heap_objects",
        "max_total_memory_bytes",
        "max_console_entries",
        "max_parse_source_bytes",
        "max_parse_tokens",
        "max_parse_recursion_depth",
    ];
    let fields = value.as_object().ok_or(Invalid)?;
    if fields.len() != FIELDS.len() || fields.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(Invalid);
    }
    let string = |field: &str| fields[field].as_str().ok_or(Invalid).map(str::to_owned);
    let integer = |field: &str| fields[field].as_u64().ok_or(Invalid);
    let narrow =
        |field: &str| -> Result<u32> { u32::try_from(integer(field)?).map_err(|_| Invalid) };
    let allowed_capabilities: Vec<String> = fields["allowed_capabilities"]
        .as_array()
        .filter(|capabilities| capabilities.len() <= CAPABILITIES.len())
        .ok_or(Invalid)?
        .iter()
        .map(|capability| capability.as_str().map(str::to_owned).ok_or(Invalid))
        .collect::<Result<_>>()?;
    let unique: std::collections::BTreeSet<_> =
        allowed_capabilities.iter().map(String::as_str).collect();
    if unique.len() != allowed_capabilities.len()
        || unique
            .iter()
            .any(|capability| !CAPABILITIES.contains(capability))
        || ["console", "heap_allocate", "vm_dispatch"]
            .iter()
            .any(|capability| !unique.contains(capability))
    {
        return Err(Invalid);
    }
    let authority = PublisherRuntimeAuthority {
        schema_version: string("schema_version")?,
        policy_revision: string("policy_revision")?,
        allowed_capabilities,
        allow_process_shape: fields["allow_process_shape"].as_bool().ok_or(Invalid)?,
        max_instructions: integer("max_instructions")?,
        max_registers: narrow("max_registers")?,
        max_call_depth: narrow("max_call_depth")?,
        max_heap_objects: narrow("max_heap_objects")?,
        max_total_memory_bytes: integer("max_total_memory_bytes")?,
        max_console_entries: narrow("max_console_entries")?,
        max_parse_source_bytes: integer("max_parse_source_bytes")?,
        max_parse_tokens: integer("max_parse_tokens")?,
        max_parse_recursion_depth: integer("max_parse_recursion_depth")?,
    };
    // Match the published native authority envelope, not a consumer's defaults.
    if authority.schema_version != RUNTIME_AUTHORITY_SCHEMA
        || !text_is_bounded(&authority.policy_revision, 128)
        || authority.max_instructions == 0
        || !(1..=65_536).contains(&authority.max_registers)
        || !(1..=10_000).contains(&authority.max_call_depth)
        || authority.max_heap_objects == 0
        || authority.max_total_memory_bytes == 0
        || authority.max_console_entries == 0
        || !(1..=2_097_152).contains(&authority.max_parse_source_bytes)
        || !(1..=131_072).contains(&authority.max_parse_tokens)
        || !(1..=384).contains(&authority.max_parse_recursion_depth)
    {
        return Err(Invalid);
    }
    Ok(authority)
}

fn parse_manifest(bytes: &[u8]) -> Result<(SignedManifest, Option<PublisherRuntimeAuthority>)> {
    use PublisherSourceError::{ManifestInvalid, UnsupportedSchema};
    let value = decode_evidence_json(bytes).map_err(|_| ManifestInvalid)?;
    let object = value.as_object().ok_or(ManifestInvalid)?;
    let schema = object
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or(ManifestInvalid)?;
    match schema {
        REGISTRATION_SCHEMA_V1 if !object.contains_key("runtime_authority") => {}
        REGISTRATION_SCHEMA_V2
            if object
                .get("runtime_authority")
                .is_some_and(Value::is_object) => {}
        _ => return Err(UnsupportedSchema),
    }
    // An absent optional value and a recorded null are not the same wire
    // statement. The canonical version object always records parent_version.
    if !object
        .get("initial_version")
        .and_then(Value::as_object)
        .is_some_and(|version| version.contains_key("parent_version"))
    {
        return Err(ManifestInvalid);
    }
    let manifest: SignedManifest = serde_json::from_value(value).map_err(|_| ManifestInvalid)?;
    let version = &manifest.initial_version;
    if !text_is_bounded(&manifest.name, 256)
        || !text_is_bounded(&manifest.publisher_id, 256)
        || !valid_version(&version.version)
        || version
            .parent_version
            .as_ref()
            .is_some_and(|parent| !valid_version(parent))
        || !valid_digest(&version.content_hash)
        || !text_is_bounded(&version.registered_at, 64)
        || version.compatible_with.len() > 32
        || version
            .compatible_with
            .iter()
            .any(|marker| !text_is_bounded(marker, 128))
        || manifest.tags.len() > 32
        || manifest.tags.iter().any(|tag| !text_is_bounded(tag, 128))
    {
        return Err(ManifestInvalid);
    }
    let authority = manifest
        .runtime_authority
        .as_ref()
        .map(parse_authority)
        .transpose()?;
    Ok((manifest, authority))
}

/// Verify exact publisher-signed bytes and the complete retained capsule frame.
///
/// The caller supplies its independently trusted public key. An embedded key,
/// local registry envelope, or artifact self-hash cannot establish that trust.
/// A v1 statement must omit runtime_authority; v2 requires its complete object.
/// A signature over another byte encoding is not accepted, even if it parses
/// to the same JSON values.
///
/// # Errors
///
/// Rejects oversized input, invalid signatures, ambiguous or unsupported signed
/// statements, invalid authority, altered artifacts, and malformed capsules.
/// Returned errors never include source or untrusted parser diagnostics.
pub fn verify_publisher_source(
    manifest_bytes: &[u8],
    signature: &[u8; 64],
    capsule_bytes: &[u8],
    trusted_publisher: &VerifyingKey,
) -> Result<VerifiedPublisherSource> {
    if manifest_bytes.len() > MAX_PUBLISHER_SOURCE_BYTES
        || capsule_bytes.len() > MAX_PUBLISHER_SOURCE_BYTES
    {
        return Err(PublisherSourceError::InputTooLarge);
    }
    trusted_publisher
        .verify_strict(manifest_bytes, &Signature::from_bytes(signature))
        .map_err(|_| PublisherSourceError::SignatureInvalid)?;
    let (manifest, runtime_authority) = parse_manifest(manifest_bytes)?;
    let artifact_digest = hex::encode(Sha256::digest(capsule_bytes));
    if !bool::from(
        manifest
            .initial_version
            .content_hash
            .as_bytes()
            .ct_eq(artifact_digest.as_bytes()),
    ) {
        return Err(PublisherSourceError::ArtifactHashMismatch);
    }
    let capsule = module_capsule::inspect_authenticated(capsule_bytes)
        .map_err(|_| PublisherSourceError::CapsuleInvalid)?;
    let mut key_id = Sha256::new();
    key_id.update(b"artifact_signing_keyid_v1:");
    key_id.update(32_u64.to_le_bytes());
    key_id.update(trusted_publisher.as_bytes());
    Ok(VerifiedPublisherSource {
        registration_schema: manifest.schema_version,
        package_name: manifest.name,
        publisher_id: manifest.publisher_id,
        version: manifest.initial_version.version,
        manifest_sha256: format!("sha256:{}", hex::encode(Sha256::digest(manifest_bytes))),
        artifact_sha256: format!("sha256:{artifact_digest}"),
        capsule_digest: module_capsule::capsule_digest(capsule_bytes),
        signer_key_id: hex::encode(&key_id.finalize()[..8]),
        signer_public_key_hex: hex::encode(trusted_publisher.as_bytes()),
        runtime_authority,
        capsule,
    })
}

fn decode_component(encoded: &str) -> Result<Vec<u8>> {
    if encoded.len() > MAX_ENCODED_BYTES {
        return Err(PublisherSourceError::InputTooLarge);
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| PublisherSourceError::InputInvalid)?;
    if bytes.len() > MAX_PUBLISHER_SOURCE_BYTES {
        return Err(PublisherSourceError::InputTooLarge);
    }
    if STANDARD.encode(&bytes) != encoded {
        return Err(PublisherSourceError::InputInvalid);
    }
    Ok(bytes)
}

/// Decode the bounded publisher-source transport and authenticate its contents.
/// Base64 is canonical and carries the publisher's exact signed bytes; neither
/// JSON input nor signature bytes are regenerated from parsed statements.
///
/// # Errors
///
/// Returns InputJsonInvalid for malformed or duplicate transport JSON,
/// InputInvalid for unsupported transport fields/schema or base64, and the
/// underlying verification error for a rejected publisher statement or capsule.
pub fn verify_publisher_source_input(
    input_bytes: &[u8],
    signature: &[u8; 64],
    trusted_publisher: &VerifyingKey,
) -> Result<VerifiedPublisherSource> {
    if input_bytes.len() > MAX_PUBLISHER_SOURCE_INPUT_BYTES {
        return Err(PublisherSourceError::InputTooLarge);
    }
    let value =
        decode_evidence_json(input_bytes).map_err(|_| PublisherSourceError::InputJsonInvalid)?;
    let envelope: InputEnvelope =
        serde_json::from_value(value).map_err(|_| PublisherSourceError::InputInvalid)?;
    if envelope.schema_version != PUBLISHER_SOURCE_INPUT_SCHEMA {
        return Err(PublisherSourceError::InputInvalid);
    }
    let manifest_bytes = decode_component(&envelope.manifest_base64)?;
    let capsule_bytes = decode_component(&envelope.capsule_base64)?;
    verify_publisher_source(
        &manifest_bytes,
        signature,
        &capsule_bytes,
        trusted_publisher,
    )
}

/// Offline Ed25519-authenticated revocation list for publisher source verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherRevocationList {
    pub schema_version: String,
    pub issued_at: String,
    pub revoked_publisher_ids: Vec<String>,
    pub revoked_signer_key_ids: Vec<String>,
    /// Entries formatted as `<package_name>@<version>`.
    pub revoked_package_versions: Vec<String>,
}

/// Single link in a hash-linked publisher version provenance chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherProvenanceLink {
    pub version: String,
    pub parent_version: Option<String>,
    pub content_hash: String,
    pub manifest_sha256: String,
    pub previous_link_sha256: Option<String>,
}

/// Offline Ed25519-authenticated provenance lineage for a publisher package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherProvenanceChain {
    pub schema_version: String,
    pub package_name: String,
    pub publisher_id: String,
    pub links: Vec<PublisherProvenanceLink>,
}

/// Independently anchored trust inputs for offline revocation + provenance verification.
/// The caller supplies the evaluation time and maximum age from its own policy,
/// never from the untrusted artifact. Historical verification can use a retained
/// trusted time; this verifier does not read a wall clock or fetch a newer list.
pub struct PublisherTrustPolicy<'a> {
    pub revocation_authority: &'a VerifyingKey,
    pub revocation_list_bytes: &'a [u8],
    pub revocation_signature: &'a [u8; 64],
    pub evaluation_time: DateTime<Utc>,
    /// Nonzero exclusive validity window: age equal to this limit is stale.
    pub max_revocation_age_secs: u64,
    pub provenance: Option<(&'a VerifyingKey, &'a [u8], &'a [u8; 64])>,
}

/// Authenticated publisher source combined with verified revocation and optional provenance facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedPublisherSourceWithTrust {
    pub source: VerifiedPublisherSource,
    pub revocation_list_sha256: String,
    pub revocation_authority_public_key_hex: String,
    pub revocation_issued_at: String,
    pub revocation_evaluated_at: String,
    #[serde(serialize_with = "serialize_decimal")]
    pub max_revocation_age_secs: u64,
    pub provenance_chain_sha256: Option<String>,
    pub provenance_authority_public_key_hex: Option<String>,
    pub provenance_link_count: Option<usize>,
}

/// Compute the domain-separated signing payload for a [`PublisherRevocationList`].
#[must_use]
pub fn revocation_list_signing_payload(raw_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PUBLISHER_REVOCATION_DOMAIN.len() + 8 + raw_bytes.len());
    payload.extend_from_slice(PUBLISHER_REVOCATION_DOMAIN);
    payload.extend_from_slice(&(raw_bytes.len() as u64).to_le_bytes());
    payload.extend_from_slice(raw_bytes);
    payload
}

/// Compute the domain-separated signing payload for a [`PublisherProvenanceChain`].
#[must_use]
pub fn provenance_chain_signing_payload(raw_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PUBLISHER_PROVENANCE_DOMAIN.len() + 8 + raw_bytes.len());
    payload.extend_from_slice(PUBLISHER_PROVENANCE_DOMAIN);
    payload.extend_from_slice(&(raw_bytes.len() as u64).to_le_bytes());
    payload.extend_from_slice(raw_bytes);
    payload
}

/// Compute the canonical SHA-256 link digest (`sha256:<hex>`) for a [`PublisherProvenanceLink`].
#[must_use]
pub fn provenance_link_digest(link: &PublisherProvenanceLink) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"franken-node/publisher-provenance-link/v1:");
    hasher.update((link.version.len() as u64).to_le_bytes());
    hasher.update(link.version.as_bytes());
    match &link.parent_version {
        Some(parent) => {
            hasher.update([1_u8]);
            hasher.update((parent.len() as u64).to_le_bytes());
            hasher.update(parent.as_bytes());
        }
        None => hasher.update([0_u8]),
    }
    hasher.update((link.content_hash.len() as u64).to_le_bytes());
    hasher.update(link.content_hash.as_bytes());
    hasher.update((link.manifest_sha256.len() as u64).to_le_bytes());
    hasher.update(link.manifest_sha256.as_bytes());
    match &link.previous_link_sha256 {
        Some(prev) => {
            hasher.update([1_u8]);
            hasher.update((prev.len() as u64).to_le_bytes());
            hasher.update(prev.as_bytes());
        }
        None => hasher.update([0_u8]),
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Verify publisher-signed source bytes together with a signed revocation list
/// and optional hash-linked, strictly increasing numeric-version lineage.
///
/// Revocation issuance must be valid RFC 3339, no later than the caller's
/// evaluation time, and younger than its nonzero maximum age. This establishes
/// freshness relative to those explicit inputs, not that the supplied list is
/// the newest published list or that the artifact is authorized to execute.
pub fn verify_publisher_source_with_trust_policy(
    manifest_bytes: &[u8],
    signature: &[u8; 64],
    capsule_bytes: &[u8],
    trusted_publisher: &VerifyingKey,
    policy: &PublisherTrustPolicy<'_>,
) -> Result<VerifiedPublisherSourceWithTrust> {
    if policy.max_revocation_age_secs == 0 {
        return Err(PublisherSourceError::RevocationFreshnessPolicyInvalid);
    }
    if policy.revocation_list_bytes.len() > MAX_REVOCATION_LIST_BYTES {
        return Err(PublisherSourceError::InputTooLarge);
    }
    let revocation_payload = revocation_list_signing_payload(policy.revocation_list_bytes);
    policy
        .revocation_authority
        .verify_strict(
            &revocation_payload,
            &Signature::from_bytes(policy.revocation_signature),
        )
        .map_err(|_| PublisherSourceError::RevocationSignatureInvalid)?;

    let revocation_value = decode_evidence_json(policy.revocation_list_bytes)
        .map_err(|_| PublisherSourceError::RevocationListInvalid)?;
    let revocation_list: PublisherRevocationList = serde_json::from_value(revocation_value)
        .map_err(|_| PublisherSourceError::RevocationListInvalid)?;
    if revocation_list.schema_version != PUBLISHER_REVOCATION_LIST_SCHEMA
        || !text_is_bounded(&revocation_list.issued_at, 64)
        || revocation_list.revoked_publisher_ids.len() > MAX_REVOCATION_ENTRIES
        || revocation_list.revoked_signer_key_ids.len() > MAX_REVOCATION_ENTRIES
        || revocation_list.revoked_package_versions.len() > MAX_REVOCATION_ENTRIES
        || revocation_list
            .revoked_publisher_ids
            .iter()
            .any(|id| !text_is_bounded(id, 256))
        || revocation_list.revoked_signer_key_ids.iter().any(|id| {
            id.len() != 16
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || revocation_list
            .revoked_package_versions
            .iter()
            .any(|entry| package_version_identity(entry).is_none())
    {
        return Err(PublisherSourceError::RevocationListInvalid);
    }
    let issued_at = DateTime::parse_from_rfc3339(&revocation_list.issued_at)
        .map_err(|_| PublisherSourceError::RevocationListInvalid)?;
    let age = policy
        .evaluation_time
        .signed_duration_since(issued_at)
        .to_std()
        .map_err(|_| PublisherSourceError::RevocationListNotYetValid)?;
    if age >= std::time::Duration::from_secs(policy.max_revocation_age_secs) {
        return Err(PublisherSourceError::RevocationListStale);
    }

    let source =
        verify_publisher_source(manifest_bytes, signature, capsule_bytes, trusted_publisher)?;
    let (parsed_manifest, _) = parse_manifest(manifest_bytes)?;
    let source_version =
        version_components(&source.version).ok_or(PublisherSourceError::ManifestInvalid)?;
    if revocation_list
        .revoked_publisher_ids
        .iter()
        .any(|id| bool::from(id.as_bytes().ct_eq(source.publisher_id.as_bytes())))
        || revocation_list
            .revoked_signer_key_ids
            .iter()
            .any(|id| bool::from(id.as_bytes().ct_eq(source.signer_key_id.as_bytes())))
        || revocation_list
            .revoked_package_versions
            .iter()
            .any(|entry| {
                package_version_identity(entry).is_some_and(|(package, version)| {
                    bool::from(package.as_bytes().ct_eq(source.package_name.as_bytes()))
                        && version == source_version
                })
            })
    {
        return Err(PublisherSourceError::PublisherRevoked);
    }

    let (provenance_chain_sha256, provenance_authority_public_key_hex, provenance_link_count) =
        if let Some((prov_authority, prov_bytes, prov_sig)) = policy.provenance {
            if prov_bytes.len() > MAX_PROVENANCE_CHAIN_BYTES {
                return Err(PublisherSourceError::InputTooLarge);
            }
            let prov_payload = provenance_chain_signing_payload(prov_bytes);
            prov_authority
                .verify_strict(&prov_payload, &Signature::from_bytes(prov_sig))
                .map_err(|_| PublisherSourceError::ProvenanceSignatureInvalid)?;
            let prov_value = decode_evidence_json(prov_bytes)
                .map_err(|_| PublisherSourceError::ProvenanceChainInvalid)?;
            let chain: PublisherProvenanceChain = serde_json::from_value(prov_value)
                .map_err(|_| PublisherSourceError::ProvenanceChainInvalid)?;
            if chain.schema_version != PUBLISHER_PROVENANCE_CHAIN_SCHEMA
                || chain.package_name != source.package_name
                || chain.publisher_id != source.publisher_id
                || chain.links.is_empty()
                || chain.links.len() > MAX_PROVENANCE_LINKS
            {
                return Err(PublisherSourceError::ProvenanceChainInvalid);
            }
            let mut prev_version: Option<&str> = None;
            let mut prev_components = None;
            let mut prev_digest: Option<String> = None;
            for (idx, link) in chain.links.iter().enumerate() {
                let components = version_components(&link.version)
                    .ok_or(PublisherSourceError::ProvenanceChainInvalid)?;
                if prev_components.is_some_and(|previous| components <= previous)
                    || !valid_digest(&link.content_hash)
                    || !link
                        .manifest_sha256
                        .strip_prefix("sha256:")
                        .is_some_and(valid_digest)
                {
                    return Err(PublisherSourceError::ProvenanceChainInvalid);
                }
                if idx == 0 {
                    if link.parent_version.is_some() || link.previous_link_sha256.is_some() {
                        return Err(PublisherSourceError::ProvenanceChainInvalid);
                    }
                } else if link.parent_version.as_deref() != prev_version
                    || link.previous_link_sha256.as_deref() != prev_digest.as_deref()
                {
                    return Err(PublisherSourceError::ProvenanceChainInvalid);
                }
                prev_version = Some(&link.version);
                prev_components = Some(components);
                prev_digest = Some(provenance_link_digest(link));
            }
            let tip = chain
                .links
                .last()
                .ok_or(PublisherSourceError::ProvenanceChainInvalid)?;
            if tip.version != source.version
                || tip.parent_version != parsed_manifest.initial_version.parent_version
                || !bool::from(
                    tip.content_hash
                        .as_bytes()
                        .ct_eq(parsed_manifest.initial_version.content_hash.as_bytes()),
                )
                || !bool::from(
                    tip.manifest_sha256
                        .as_bytes()
                        .ct_eq(source.manifest_sha256.as_bytes()),
                )
            {
                return Err(PublisherSourceError::ProvenanceChainInvalid);
            }
            (
                Some(format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(prov_bytes))
                )),
                Some(hex::encode(prov_authority.as_bytes())),
                Some(chain.links.len()),
            )
        } else {
            (None, None, None)
        };

    Ok(VerifiedPublisherSourceWithTrust {
        source,
        revocation_list_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(policy.revocation_list_bytes))
        ),
        revocation_authority_public_key_hex: hex::encode(policy.revocation_authority.as_bytes()),
        revocation_issued_at: revocation_list.issued_at,
        revocation_evaluated_at: policy
            .evaluation_time
            .to_rfc3339_opts(SecondsFormat::AutoSi, true),
        max_revocation_age_secs: policy.max_revocation_age_secs,
        provenance_chain_sha256,
        provenance_authority_public_key_hex,
        provenance_link_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x5b; 32])
    }

    fn evaluation_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-11T00:30:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn producer_vectors() -> Vec<Value> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/module_source_capsules.json"
        ))
        .unwrap();
        assert_eq!(fixture["execution_performed"], false);
        fixture["vectors"].as_array().unwrap().clone()
    }

    fn capsule() -> Vec<u8> {
        STANDARD
            .decode(
                producer_vectors()[0]["module_sources"]["capsule_base64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
    }

    fn authority() -> Value {
        json!({
            "schema_version": RUNTIME_AUTHORITY_SCHEMA,
            "policy_revision": "publisher-policy-1",
            "allowed_capabilities": ["builtin", "console", "heap_allocate", "module_load", "vm_dispatch"],
            "allow_process_shape": false,
            "max_instructions": u64::MAX,
            "max_registers": 65_536,
            "max_call_depth": 10_000,
            "max_heap_objects": u32::MAX,
            "max_total_memory_bytes": u64::MAX,
            "max_console_entries": u32::MAX,
            "max_parse_source_bytes": 2_097_152,
            "max_parse_tokens": 131_072,
            "max_parse_recursion_depth": 384,
        })
    }

    fn manifest(bytes: &[u8], with_authority: bool) -> Value {
        let mut value = json!({
            "schema_version": REGISTRATION_SCHEMA_V1,
            "name": "publisher-package",
            "publisher_id": "publisher-1",
            "initial_version": {
                "version": "1.2.3",
                "parent_version": null,
                "content_hash": hex::encode(Sha256::digest(bytes)),
                "registered_at": "2026-11-10T00:00:00Z",
                "compatible_with": [],
            },
            "tags": ["source-capsule"],
        });
        if with_authority {
            value["schema_version"] = json!(REGISTRATION_SCHEMA_V2);
            value["runtime_authority"] = authority();
        }
        value
    }

    fn verify_signed(raw: &[u8], capsule: &[u8]) -> Result<VerifiedPublisherSource> {
        verify_publisher_source(
            raw,
            &key().sign(raw).to_bytes(),
            capsule,
            &key().verifying_key(),
        )
    }

    fn verify_value(value: &Value, capsule: &[u8]) -> Result<VerifiedPublisherSource> {
        verify_signed(&serde_json::to_vec(value).unwrap(), capsule)
    }

    fn transport(manifest: &[u8], capsule: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema_version": PUBLISHER_SOURCE_INPUT_SCHEMA,
            "manifest_base64": STANDARD.encode(manifest),
            "capsule_base64": STANDARD.encode(capsule),
        }))
        .unwrap()
    }

    fn header(bytes: &[u8]) -> (&str, &[u8]) {
        let end = 12 + u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        (std::str::from_utf8(&bytes[12..end]).unwrap(), &bytes[end..])
    }

    fn frame(metadata: &str, payload: &[u8]) -> Vec<u8> {
        let mut bytes = b"FNSGCAP1".to_vec();
        bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        bytes.extend_from_slice(metadata.as_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn authenticates_real_source_capsules_and_preserves_full_width_authority() {
        let vectors = producer_vectors();
        assert_eq!(vectors.len(), 3);
        for vector in vectors {
            let sources = &vector["module_sources"];
            let capsule = STANDARD
                .decode(sources["capsule_base64"].as_str().unwrap())
                .unwrap();
            for with_authority in [false, true] {
                let raw = serde_json::to_vec(&manifest(&capsule, with_authority)).unwrap();
                let verified = verify_signed(&raw, &capsule).unwrap();
                assert_eq!(verified.package_name, "publisher-package");
                assert_eq!(verified.publisher_id, "publisher-1");
                assert_eq!(verified.version, "1.2.3");
                assert_eq!(
                    verified.artifact_sha256,
                    format!("sha256:{}", hex::encode(Sha256::digest(&capsule)))
                );
                assert_eq!(
                    verified.manifest_sha256,
                    format!("sha256:{}", hex::encode(Sha256::digest(&raw)))
                );
                assert_eq!(verified.capsule_digest, sources["capsule_digest"]);
                assert_eq!(
                    verified.capsule.graph_input_hash,
                    sources["graph_input_hash"]
                );
                assert!(!verified.capsule.graph_hash_recomputed);
                let summary = &verified.capsule;
                assert_eq!(summary.capsule_bytes, capsule.len());
                assert_eq!(summary.payload_bytes, header(&capsule).1.len());
                assert_eq!(
                    summary.input_count,
                    summary.file_count
                        + summary.metadata_file_count
                        + summary.directory_count
                        + summary.missing_count
                        + summary.symlink_count
                );
                let serialized = serde_json::to_value(&verified).unwrap();
                if with_authority {
                    let signed = verified.runtime_authority.as_ref().unwrap();
                    assert_eq!(signed.max_instructions, u64::MAX);
                    assert_eq!(signed.max_heap_objects, u32::MAX);
                    assert_eq!(
                        serialized["runtime_authority"]["max_total_memory_bytes"],
                        "18446744073709551615"
                    );
                    assert_eq!(
                        serialized["runtime_authority"]["max_instructions"],
                        "18446744073709551615"
                    );
                    assert_eq!(
                        serialized["runtime_authority"]["max_heap_objects"],
                        "4294967295"
                    );
                    for field in [
                        "max_registers",
                        "max_call_depth",
                        "max_console_entries",
                        "max_parse_source_bytes",
                        "max_parse_tokens",
                        "max_parse_recursion_depth",
                    ] {
                        assert!(
                            serialized["runtime_authority"][field].is_string(),
                            "{field}"
                        );
                    }
                } else {
                    assert!(verified.runtime_authority.is_none());
                    assert_eq!(serialized["runtime_authority"], Value::Null);
                }
                let input = transport(&raw, &capsule);
                assert_eq!(
                    verify_publisher_source_input(
                        &input,
                        &key().sign(&raw).to_bytes(),
                        &key().verifying_key()
                    )
                    .unwrap(),
                    verified
                );
            }
        }
    }

    #[test]
    fn exact_signed_encoding_and_external_anchor_are_authoritative() {
        let capsule = capsule();
        let value = manifest(&capsule, false);
        let compact = serde_json::to_vec(&value).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        let original = verify_signed(&compact, &capsule).unwrap();
        let reformatted = verify_signed(&pretty, &capsule).unwrap();
        assert_ne!(original.manifest_sha256, reformatted.manifest_sha256);
        assert_eq!(original.artifact_sha256, reformatted.artifact_sha256);
        let signature = key().sign(&compact).to_bytes();
        assert_eq!(
            verify_publisher_source(&pretty, &signature, &capsule, &key().verifying_key()),
            Err(PublisherSourceError::SignatureInvalid)
        );
        assert_eq!(
            verify_publisher_source(
                &compact,
                &signature,
                &capsule,
                &SigningKey::from_bytes(&[0x6c; 32]).verifying_key()
            ),
            Err(PublisherSourceError::SignatureInvalid)
        );
        assert_eq!(
            verify_publisher_source(&compact, &[0; 64], &capsule, &key().verifying_key()),
            Err(PublisherSourceError::SignatureInvalid)
        );
        let mut altered = capsule.clone();
        altered.push(0);
        assert_eq!(
            verify_signed(&compact, &altered),
            Err(PublisherSourceError::ArtifactHashMismatch)
        );
    }

    #[test]
    fn signed_schema_unknown_fields_and_ambiguous_members_are_rejected() {
        let capsule = capsule();
        let valid = manifest(&capsule, false);
        for (field, replacement) in [
            ("schema_version", json!("unsupported")),
            ("runtime_authority", Value::Null),
            ("runtime_authority", authority()),
        ] {
            let mut changed = valid.clone();
            changed[field] = replacement;
            assert_eq!(
                verify_value(&changed, &capsule),
                Err(PublisherSourceError::UnsupportedSchema)
            );
        }
        for replacement in [Value::Null, json!(false), json!("authority")] {
            let mut changed = manifest(&capsule, true);
            changed["runtime_authority"] = replacement;
            assert_eq!(
                verify_value(&changed, &capsule),
                Err(PublisherSourceError::UnsupportedSchema)
            );
        }
        let mut missing_authority = manifest(&capsule, true);
        missing_authority
            .as_object_mut()
            .unwrap()
            .remove("runtime_authority");
        assert_eq!(
            verify_value(&missing_authority, &capsule),
            Err(PublisherSourceError::UnsupportedSchema)
        );
        for pointer in ["", "/initial_version"] {
            let mut changed = valid.clone();
            changed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(
                    "PRIVATE-UNRECOGNIZED-FIELD".into(),
                    json!("PRIVATE-SOURCE-SENTINEL"),
                );
            assert_eq!(
                verify_value(&changed, &capsule),
                Err(PublisherSourceError::ManifestInvalid)
            );
        }
        let raw = serde_json::to_string(&valid).unwrap();
        let duplicate = format!(
            "{},\"\\u006eame\":\"PRIVATE-SOURCE-SENTINEL\"}}",
            &raw[..raw.len() - 1]
        );
        assert_eq!(
            verify_signed(duplicate.as_bytes(), &capsule),
            Err(PublisherSourceError::ManifestInvalid)
        );
        let mut missing_parent = valid.clone();
        missing_parent["initial_version"]
            .as_object_mut()
            .unwrap()
            .remove("parent_version");
        assert_eq!(
            verify_value(&missing_parent, &capsule),
            Err(PublisherSourceError::ManifestInvalid)
        );
        for (pointer, replacement) in [
            ("/name", json!("")),
            ("/publisher_id", json!("publisher\n")),
            ("/initial_version/version", json!("1.2")),
            (
                "/initial_version/version",
                json!("18446744073709551616.0.0"),
            ),
            ("/initial_version/content_hash", json!("F".repeat(64))),
            ("/initial_version/registered_at", json!("")),
            ("/tags", json!(["a".repeat(129)])),
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert_eq!(
                verify_value(&changed, &capsule),
                Err(PublisherSourceError::ManifestInvalid),
                "{pointer}"
            );
        }
    }

    #[test]
    fn every_authority_ceiling_and_capability_constraint_is_enforced() {
        let capsule = capsule();
        let valid = manifest(&capsule, true);
        let fields: Vec<_> = valid["runtime_authority"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for field in fields {
            let mut changed = valid.clone();
            changed["runtime_authority"]
                .as_object_mut()
                .unwrap()
                .remove(&field);
            assert_eq!(
                verify_value(&changed, &capsule),
                Err(PublisherSourceError::RuntimeAuthorityInvalid),
                "{field}"
            );
        }
        for field in [
            "max_instructions",
            "max_registers",
            "max_call_depth",
            "max_heap_objects",
            "max_total_memory_bytes",
            "max_console_entries",
            "max_parse_source_bytes",
            "max_parse_tokens",
            "max_parse_recursion_depth",
        ] {
            for replacement in [json!(0), json!(-1), json!(1.5), json!("1")] {
                let mut changed = valid.clone();
                changed["runtime_authority"][field] = replacement;
                assert_eq!(
                    verify_value(&changed, &capsule),
                    Err(PublisherSourceError::RuntimeAuthorityInvalid),
                    "{field}"
                );
            }
        }
        for (field, replacement) in [
            ("max_registers", json!(65_537)),
            ("max_call_depth", json!(10_001)),
            ("max_heap_objects", json!(u64::from(u32::MAX) + 1)),
            ("max_console_entries", json!(u64::from(u32::MAX) + 1)),
            ("max_parse_source_bytes", json!(2_097_153)),
            ("max_parse_tokens", json!(131_073)),
            ("max_parse_recursion_depth", json!(385)),
            ("schema_version", json!("unsupported")),
            ("policy_revision", json!("revision\n")),
            ("policy_revision", json!("x".repeat(129))),
            ("allow_process_shape", json!("false")),
            (
                "allowed_capabilities",
                json!(["console", "heap_allocate", "vm_dispatch", "unknown"]),
            ),
            (
                "allowed_capabilities",
                json!(["console", "heap_allocate", "vm_dispatch", "console"]),
            ),
            ("allowed_capabilities", json!(["console", "vm_dispatch"])),
            ("unknown_authority", json!("PRIVATE-SOURCE-SENTINEL")),
        ] {
            let mut changed = valid.clone();
            changed["runtime_authority"][field] = replacement;
            assert_eq!(
                verify_value(&changed, &capsule),
                Err(PublisherSourceError::RuntimeAuthorityInvalid),
                "{field}"
            );
        }
        let raw = serde_json::to_string(&valid).unwrap();
        let overflow = raw.replacen("18446744073709551615", "18446744073709551616", 1);
        assert_eq!(
            verify_signed(overflow.as_bytes(), &capsule),
            Err(PublisherSourceError::RuntimeAuthorityInvalid)
        );
        let duplicate = raw.replacen(
            "\"max_instructions\":",
            "\"max_instructions\":1,\"max_instructions\":",
            1,
        );
        assert_eq!(
            verify_signed(duplicate.as_bytes(), &capsule),
            Err(PublisherSourceError::ManifestInvalid)
        );
    }

    #[test]
    fn correctly_signed_artifact_hash_cannot_mask_invalid_capsule_bytes() {
        let original = capsule();
        let mut cases = Vec::new();
        let mut invalid_magic = original.clone();
        invalid_magic[0] = b'X';
        cases.push(invalid_magic);
        let mut header_overflow = original.clone();
        header_overflow[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(header_overflow);
        let mut damaged_source = original.clone();
        *damaged_source.last_mut().unwrap() ^= 1;
        cases.push(damaged_source);
        cases.push(original[..original.len() - 1].to_vec());
        let mut unclaimed = original.clone();
        unclaimed.extend_from_slice(b"PRIVATE-SOURCE-SENTINEL");
        cases.push(unclaimed);
        let (metadata, payload) = header(&original);
        cases.push(frame(&format!("{metadata}\n"), payload));
        cases.push(frame(
            &metadata.replacen("\"kind\":\"file\"", "\"kind\":\"file_metadata\"", 1),
            payload,
        ));
        for bytes in cases {
            let error = verify_value(&manifest(&bytes, true), &bytes).unwrap_err();
            assert_eq!(error, PublisherSourceError::CapsuleInvalid);
            assert!(!format!("{error:?}: {error}").contains("PRIVATE-SOURCE-SENTINEL"));
        }
    }

    #[test]
    fn metadata_is_existence_only_and_graph_hash_is_not_rederived() {
        let original = capsule();
        let (metadata, payload) = header(&original);
        let parsed: Value = serde_json::from_str(metadata).unwrap();
        let old_graph = parsed["graph_hash"].as_str().unwrap();
        let new_graph = format!("sha256:{}", "f".repeat(64));
        let metadata = metadata.replace(old_graph, &new_graph);
        // Synthetic wire probe around real captured file payloads. This does
        // not claim a genuine producer graph or successful graph reconstruction.
        let original_root = r#""inputs":[{"path":"","content":{"kind":"directory"}}"#;
        let added_probe = r#""inputs":[{"path":"","content":{"kind":"directory"}},{"path":"0-PRIVATE-SOURCE-PROBE","content":{"kind":"file_metadata"}}"#;
        assert_eq!(metadata.matches(original_root).count(), 1);
        let metadata = metadata.replacen(original_root, added_probe, 1);
        let bytes = frame(&metadata, payload);
        let verified = verify_value(&manifest(&bytes, false), &bytes).unwrap();
        assert_eq!(verified.capsule.metadata_file_count, 1);
        assert_eq!(verified.capsule.graph_input_hash, new_graph);
        assert!(!verified.capsule.graph_hash_recomputed);
        assert_eq!(verified.capsule.payload_bytes, payload.len());
        let output = serde_json::to_string(&verified).unwrap();
        assert!(!output.contains("PRIVATE-SOURCE-PROBE"));
        assert!(!output.contains("app.mjs"));
        for field in [
            r#","bytes":0"#,
            r#","sha256":"unused""#,
            r#","target":"private""#,
        ] {
            let invalid = metadata.replacen(
                r#"{"kind":"file_metadata"}"#,
                &format!(r#"{{"kind":"file_metadata"{field}}}"#),
                1,
            );
            let bytes = frame(&invalid, payload);
            assert_eq!(
                verify_value(&manifest(&bytes, false), &bytes),
                Err(PublisherSourceError::CapsuleInvalid)
            );
        }
    }

    #[test]
    fn transport_rejects_duplicates_unknown_fields_and_noncanonical_base64() {
        let capsule = capsule();
        let raw = serde_json::to_vec(&manifest(&capsule, false)).unwrap();
        let input = transport(&raw, &capsule);
        let signature = key().sign(&raw).to_bytes();
        let check =
            |bytes: &[u8]| verify_publisher_source_input(bytes, &signature, &key().verifying_key());
        let text = std::str::from_utf8(&input).unwrap();
        let duplicate = format!(
            "{},\"\\u0063apsule_base64\":\"ignored\"}}",
            &text[..text.len() - 1]
        );
        assert_eq!(
            check(duplicate.as_bytes()),
            Err(PublisherSourceError::InputJsonInvalid)
        );
        for (field, replacement) in [
            ("schema_version", json!("unsupported")),
            ("unsigned_claim", json!("PRIVATE-SOURCE-SENTINEL")),
            ("manifest_base64", json!("not base64")),
            (
                "capsule_base64",
                json!(format!("{}\n", STANDARD.encode(&capsule))),
            ),
        ] {
            let mut value: Value = serde_json::from_slice(&input).unwrap();
            value[field] = replacement;
            assert_eq!(
                check(&serde_json::to_vec(&value).unwrap()),
                Err(PublisherSourceError::InputInvalid),
                "{field}"
            );
        }
        let mut missing: Value = serde_json::from_slice(&input).unwrap();
        missing.as_object_mut().unwrap().remove("manifest_base64");
        assert_eq!(
            check(&serde_json::to_vec(&missing).unwrap()),
            Err(PublisherSourceError::InputInvalid)
        );
        assert_eq!(check(b"{"), Err(PublisherSourceError::InputJsonInvalid));
        assert_eq!(check(&[0xff]), Err(PublisherSourceError::InputJsonInvalid));
    }

    #[test]
    fn raw_and_encoded_bounds_are_checked_before_untrusted_work() {
        let large = vec![b'X'; MAX_PUBLISHER_SOURCE_BYTES + 1];
        assert_eq!(
            verify_publisher_source(&large, &[0; 64], &[], &key().verifying_key()),
            Err(PublisherSourceError::InputTooLarge)
        );
        assert_eq!(
            verify_publisher_source(&[], &[0; 64], &large, &key().verifying_key()),
            Err(PublisherSourceError::InputTooLarge)
        );
        assert_eq!(
            decode_component(&"A".repeat(MAX_ENCODED_BYTES + 1)),
            Err(PublisherSourceError::InputTooLarge)
        );
        assert_eq!(
            decode_component(&STANDARD.encode(&large)),
            Err(PublisherSourceError::InputTooLarge)
        );
        let input = vec![b' '; MAX_PUBLISHER_SOURCE_INPUT_BYTES + 1];
        assert_eq!(
            verify_publisher_source_input(&input, &[0; 64], &key().verifying_key()),
            Err(PublisherSourceError::InputTooLarge)
        );
    }

    #[test]
    fn trust_policy_enforces_signed_revocation_lists_and_hash_linked_provenance() {
        let rev_signer = SigningKey::from_bytes(&[0x71; 32]);
        let prov_signer = SigningKey::from_bytes(&[0x72; 32]);
        let capsule_bytes = capsule();
        let v1_manifest = manifest(&capsule_bytes, false);
        let v1_raw = serde_json::to_vec(&v1_manifest).unwrap();
        let v1_manifest_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&v1_raw)));

        let mut v2_manifest = manifest(&capsule_bytes, true);
        v2_manifest["initial_version"]["version"] = json!("1.2.4");
        v2_manifest["initial_version"]["parent_version"] = json!("1.2.3");
        let v2_raw = serde_json::to_vec(&v2_manifest).unwrap();
        let v2_sig = key().sign(&v2_raw).to_bytes();
        let v2_manifest_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&v2_raw)));
        let content_hash = hex::encode(Sha256::digest(&capsule_bytes));

        let clean_revocations = PublisherRevocationList {
            schema_version: PUBLISHER_REVOCATION_LIST_SCHEMA.into(),
            issued_at: "2026-11-11T00:00:00Z".into(),
            revoked_publisher_ids: vec!["other-publisher".into()],
            revoked_signer_key_ids: vec!["0000000000000000".into()],
            revoked_package_versions: vec!["publisher-package@0.0.1".into()],
        };
        let rev_raw = serde_json::to_vec(&clean_revocations).unwrap();
        let rev_sig = rev_signer
            .sign(&revocation_list_signing_payload(&rev_raw))
            .to_bytes();

        let genesis_link = PublisherProvenanceLink {
            version: "1.2.3".into(),
            parent_version: None,
            content_hash: content_hash.clone(),
            manifest_sha256: v1_manifest_sha256,
            previous_link_sha256: None,
        };
        let tip_link = PublisherProvenanceLink {
            version: "1.2.4".into(),
            parent_version: Some("1.2.3".into()),
            content_hash,
            manifest_sha256: v2_manifest_sha256,
            previous_link_sha256: Some(provenance_link_digest(&genesis_link)),
        };
        let chain = PublisherProvenanceChain {
            schema_version: PUBLISHER_PROVENANCE_CHAIN_SCHEMA.into(),
            package_name: "publisher-package".into(),
            publisher_id: "publisher-1".into(),
            links: vec![genesis_link, tip_link],
        };
        let prov_raw = serde_json::to_vec(&chain).unwrap();
        let prov_sig = prov_signer
            .sign(&provenance_chain_signing_payload(&prov_raw))
            .to_bytes();

        let verified = verify_publisher_source_with_trust_policy(
            &v2_raw,
            &v2_sig,
            &capsule_bytes,
            &key().verifying_key(),
            &PublisherTrustPolicy {
                revocation_authority: &rev_signer.verifying_key(),
                revocation_list_bytes: &rev_raw,
                revocation_signature: &rev_sig,
                evaluation_time: evaluation_time(),
                max_revocation_age_secs: 3600,
                provenance: Some((&prov_signer.verifying_key(), &prov_raw, &prov_sig)),
            },
        )
        .unwrap();
        assert_eq!(verified.provenance_link_count, Some(2));
        let signer_key_id = verified.source.signer_key_id.clone();

        // Wrong revocation authority must be rejected.
        assert_eq!(
            verify_publisher_source_with_trust_policy(
                &v2_raw,
                &v2_sig,
                &capsule_bytes,
                &key().verifying_key(),
                &PublisherTrustPolicy {
                    revocation_authority: &prov_signer.verifying_key(),
                    revocation_list_bytes: &rev_raw,
                    revocation_signature: &rev_sig,
                    evaluation_time: evaluation_time(),
                    max_revocation_age_secs: 3600,
                    provenance: None,
                },
            ),
            Err(PublisherSourceError::RevocationSignatureInvalid)
        );

        // Revoking publisher_id, signer_key_id, or package@version must each fail closed.
        for revoked in [
            PublisherRevocationList {
                revoked_publisher_ids: vec!["publisher-1".into()],
                ..clean_revocations.clone()
            },
            PublisherRevocationList {
                revoked_signer_key_ids: vec![signer_key_id],
                ..clean_revocations.clone()
            },
            PublisherRevocationList {
                revoked_package_versions: vec!["publisher-package@1.2.4".into()],
                ..clean_revocations.clone()
            },
        ] {
            let bytes = serde_json::to_vec(&revoked).unwrap();
            let sig = rev_signer
                .sign(&revocation_list_signing_payload(&bytes))
                .to_bytes();
            assert_eq!(
                verify_publisher_source_with_trust_policy(
                    &v2_raw,
                    &v2_sig,
                    &capsule_bytes,
                    &key().verifying_key(),
                    &PublisherTrustPolicy {
                        revocation_authority: &rev_signer.verifying_key(),
                        revocation_list_bytes: &bytes,
                        revocation_signature: &sig,
                        evaluation_time: evaluation_time(),
                        max_revocation_age_secs: 3600,
                        provenance: None,
                    },
                ),
                Err(PublisherSourceError::PublisherRevoked)
            );
        }

        // Broken previous_link_sha256 in provenance chain must fail closed.
        let mut broken_chain = chain;
        broken_chain.links[1].previous_link_sha256 = Some(format!("sha256:{}", "0".repeat(64)));
        let broken_bytes = serde_json::to_vec(&broken_chain).unwrap();
        let broken_sig = prov_signer
            .sign(&provenance_chain_signing_payload(&broken_bytes))
            .to_bytes();
        assert_eq!(
            verify_publisher_source_with_trust_policy(
                &v2_raw,
                &v2_sig,
                &capsule_bytes,
                &key().verifying_key(),
                &PublisherTrustPolicy {
                    revocation_authority: &rev_signer.verifying_key(),
                    revocation_list_bytes: &rev_raw,
                    revocation_signature: &rev_sig,
                    evaluation_time: evaluation_time(),
                    max_revocation_age_secs: 3600,
                    provenance: Some((&prov_signer.verifying_key(), &broken_bytes, &broken_sig)),
                },
            ),
            Err(PublisherSourceError::ProvenanceChainInvalid)
        );
    }

    #[test]
    fn trust_policy_revokes_numeric_version_aliases_and_scoped_packages() {
        let revocation_signer = SigningKey::from_bytes(&[0x71; 32]);
        let capsule_bytes = capsule();
        for package in ["publisher-package", "@audit/publisher-package"] {
            for (version, revoked_version) in [
                ("1.2.3", "01.02.03"),
                ("01.02.03", "1.2.3"),
                ("1.2.3", "1.2.3"),
                ("18446744073709551615.0.1", "18446744073709551615.00.01"),
            ] {
                let mut source_manifest = manifest(&capsule_bytes, true);
                source_manifest["name"] = json!(package);
                source_manifest["initial_version"]["version"] = json!(version);
                let manifest_raw = serde_json::to_vec(&source_manifest).unwrap();
                let manifest_signature = key().sign(&manifest_raw).to_bytes();
                let verify_entry = |entry: &str| {
                    let revocations = PublisherRevocationList {
                        schema_version: PUBLISHER_REVOCATION_LIST_SCHEMA.into(),
                        issued_at: "2026-11-11T00:00:00Z".into(),
                        revoked_publisher_ids: vec![],
                        revoked_signer_key_ids: vec![],
                        revoked_package_versions: vec![entry.into()],
                    };
                    let revocation_raw = serde_json::to_vec(&revocations).unwrap();
                    let revocation_signature = revocation_signer
                        .sign(&revocation_list_signing_payload(&revocation_raw))
                        .to_bytes();
                    verify_publisher_source_with_trust_policy(
                        &manifest_raw,
                        &manifest_signature,
                        &capsule_bytes,
                        &key().verifying_key(),
                        &PublisherTrustPolicy {
                            revocation_authority: &revocation_signer.verifying_key(),
                            revocation_list_bytes: &revocation_raw,
                            revocation_signature: &revocation_signature,
                            evaluation_time: evaluation_time(),
                            max_revocation_age_secs: 3600,
                            provenance: None,
                        },
                    )
                };
                assert_eq!(
                    verify_entry(&format!("{package}@{revoked_version}")),
                    Err(PublisherSourceError::PublisherRevoked),
                    "numeric identity must match: {package}@{version} vs {revoked_version}",
                );
                assert!(verify_entry("other-package@1.2.3").is_ok());
                assert!(verify_entry(&format!("{package}@1.2.4")).is_ok());
                for invalid in [
                    "missing-version",
                    "@1.2.3",
                    "package@",
                    "package@1.2",
                    "package@1.2.3.4",
                    "package@+1.2.3",
                    "package@18446744073709551616.0.0",
                ] {
                    assert_eq!(
                        verify_entry(invalid),
                        Err(PublisherSourceError::RevocationListInvalid)
                    );
                }
            }
        }
    }

    #[test]
    fn trust_policy_checks_revocation_freshness_at_exact_caller_boundaries() {
        let rev_signer = SigningKey::from_bytes(&[0x71; 32]);
        let capsule_bytes = capsule();
        let manifest_raw = serde_json::to_vec(&manifest(&capsule_bytes, true)).unwrap();
        let manifest_sig = key().sign(&manifest_raw).to_bytes();
        let verify_at = |issued_at: &str, at: DateTime<Utc>, maximum_age: u64| {
            let revocations = PublisherRevocationList {
                schema_version: PUBLISHER_REVOCATION_LIST_SCHEMA.into(),
                issued_at: issued_at.into(),
                revoked_publisher_ids: vec![],
                revoked_signer_key_ids: vec![],
                revoked_package_versions: vec![],
            };
            let raw = serde_json::to_vec(&revocations).unwrap();
            let signature = rev_signer
                .sign(&revocation_list_signing_payload(&raw))
                .to_bytes();
            verify_publisher_source_with_trust_policy(
                &manifest_raw,
                &manifest_sig,
                &capsule_bytes,
                &key().verifying_key(),
                &PublisherTrustPolicy {
                    revocation_authority: &rev_signer.verifying_key(),
                    revocation_list_bytes: &raw,
                    revocation_signature: &signature,
                    evaluation_time: at,
                    max_revocation_age_secs: maximum_age,
                    provenance: None,
                },
            )
        };

        // Each list has a genuine signature from the independently trusted
        // revocation authority. Authenticity alone cannot make its time valid.
        for (issued_at, expected) in [
            ("trusted-time", PublisherSourceError::RevocationListInvalid),
            (
                "2026-02-30T00:00:00Z",
                PublisherSourceError::RevocationListInvalid,
            ),
            (
                "2026-11-11T00:30:00.000000001Z",
                PublisherSourceError::RevocationListNotYetValid,
            ),
            (
                "2100-01-01T00:00:00Z",
                PublisherSourceError::RevocationListNotYetValid,
            ),
            (
                "2026-11-10T23:30:00Z",
                PublisherSourceError::RevocationListStale,
            ),
            (
                "2026-11-10T23:29:59.999999999Z",
                PublisherSourceError::RevocationListStale,
            ),
            (
                "2000-01-01T00:00:00Z",
                PublisherSourceError::RevocationListStale,
            ),
        ] {
            assert_eq!(
                verify_at(issued_at, evaluation_time(), 3600),
                Err(expected),
                "issued_at={issued_at}"
            );
        }
        for issued_at in [
            "2026-11-11T00:30:00Z",
            "2026-11-11T01:30:00+01:00",
            "2026-11-10T23:30:00.000000001Z",
        ] {
            let verified = verify_at(issued_at, evaluation_time(), 3600).unwrap();
            assert_eq!(verified.revocation_issued_at, issued_at);
            assert_eq!(verified.revocation_evaluated_at, "2026-11-11T00:30:00Z");
            assert_eq!(verified.max_revocation_age_secs, 3600);
            assert_eq!(verified.provenance_link_count, None);
            assert_eq!(
                serde_json::to_value(verified).unwrap()["max_revocation_age_secs"],
                "3600"
            );
        }
        assert_eq!(
            verify_at("2026-11-11T00:30:00Z", evaluation_time(), 0),
            Err(PublisherSourceError::RevocationFreshnessPolicyInvalid)
        );

        // Historical verification uses the supplied time, not the host clock;
        // an operator-selected large window never wraps a signed time interval.
        let historical_time = DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        verify_at("2000-01-01T00:00:00Z", historical_time, 1).unwrap();
        let wide = verify_at("1900-01-01T00:00:00Z", evaluation_time(), u64::MAX).unwrap();
        assert_eq!(
            serde_json::to_value(wide).unwrap()["max_revocation_age_secs"],
            u64::MAX.to_string()
        );
    }

    #[test]
    fn trust_policy_rejects_signed_nonmonotonic_provenance_versions() {
        let rev_signer = SigningKey::from_bytes(&[0x71; 32]);
        let prov_signer = SigningKey::from_bytes(&[0x72; 32]);
        let capsule_bytes = capsule();
        let revocations = PublisherRevocationList {
            schema_version: PUBLISHER_REVOCATION_LIST_SCHEMA.into(),
            issued_at: "2026-11-11T00:00:00Z".into(),
            revoked_publisher_ids: vec![],
            revoked_signer_key_ids: vec![],
            revoked_package_versions: vec![],
        };
        let rev_raw = serde_json::to_vec(&revocations).unwrap();
        let rev_sig = rev_signer
            .sign(&revocation_list_signing_payload(&rev_raw))
            .to_bytes();

        for (versions, accepted) in [
            (vec!["1.2.3"], true),
            (vec!["1.2.9", "1.2.10"], true),
            (vec!["1.9.99", "2.0.0"], true),
            (
                vec!["18446744073709551615.0.0", "18446744073709551615.0.1"],
                true,
            ),
            (vec!["1.2.3", "1.2.3"], false),
            (vec!["1.2.3", "01.2.3"], false),
            (vec!["2.0.0", "1.9.99"], false),
            (vec!["1.0.0", "2.0.0", "1.0.1"], false),
            (vec!["1.0.0", "2.0.0", "1.0.0"], false),
        ] {
            let mut links: Vec<PublisherProvenanceLink> = Vec::new();
            let mut tip_raw = Vec::new();
            for version in &versions {
                let parent_version = links.last().map(|link| link.version.clone());
                let previous_link_sha256 = links.last().map(provenance_link_digest);
                let mut registration = manifest(&capsule_bytes, true);
                registration["initial_version"]["version"] = json!(version);
                registration["initial_version"]["parent_version"] = json!(parent_version);
                tip_raw = serde_json::to_vec(&registration).unwrap();
                links.push(PublisherProvenanceLink {
                    version: (*version).into(),
                    parent_version,
                    content_hash: hex::encode(Sha256::digest(&capsule_bytes)),
                    manifest_sha256: format!("sha256:{}", hex::encode(Sha256::digest(&tip_raw))),
                    previous_link_sha256,
                });
            }
            let chain = PublisherProvenanceChain {
                schema_version: PUBLISHER_PROVENANCE_CHAIN_SCHEMA.into(),
                package_name: "publisher-package".into(),
                publisher_id: "publisher-1".into(),
                links,
            };
            let prov_raw = serde_json::to_vec(&chain).unwrap();
            let prov_sig = prov_signer
                .sign(&provenance_chain_signing_payload(&prov_raw))
                .to_bytes();
            let result = verify_publisher_source_with_trust_policy(
                &tip_raw,
                &key().sign(&tip_raw).to_bytes(),
                &capsule_bytes,
                &key().verifying_key(),
                &PublisherTrustPolicy {
                    revocation_authority: &rev_signer.verifying_key(),
                    revocation_list_bytes: &rev_raw,
                    revocation_signature: &rev_sig,
                    evaluation_time: evaluation_time(),
                    max_revocation_age_secs: 3600,
                    provenance: Some((&prov_signer.verifying_key(), &prov_raw, &prov_sig)),
                },
            );
            if accepted {
                assert_eq!(
                    result.unwrap().provenance_link_count,
                    Some(versions.len()),
                    "versions={versions:?}"
                );
            } else {
                assert_eq!(
                    result,
                    Err(PublisherSourceError::ProvenanceChainInvalid),
                    "versions={versions:?}"
                );
            }
        }
    }
}
