//! Offline recomputation for the **live migration-throughput delta** artifact.
//!
//! Applies the verifier-SDK rule — "claims require evidence; verification runs
//! outside the producing runtime" — to the charter's ≥3× migration-velocity
//! claim (PRODUCT_CHARTER §5, CLAIM-002). Two committed artifacts back the
//! claim:
//!
//! * `artifacts/migration/throughput_delta_evidence.json` — the **census**:
//!   per-fixture frozen input digests plus every measured wall-clock run of
//!   the tooled (`franken-node migrate audit/rewrite/validate`) and baseline
//!   (checked-in reference codemods) pipelines.
//! * `artifacts/migration/throughput_delta.json` — the **signed summary**:
//!   pooled medians, the velocity ratio in basis points, a deterministic
//!   bootstrap CI95, a corpus digest over the census, and a detached Ed25519
//!   signature over the canonical unsigned payload.
//!
//! [`verify_throughput_delta`] proves, with **zero trust in the producing
//! runtime**:
//!
//! 1. the summary is authentically signed (pinned harness anchor or an
//!    operator-supplied trust anchor);
//! 2. every census entry's declared medians and per-fixture ratio are the
//!    faithful integer functions of its recorded runs;
//! 3. the pooled medians, overall velocity ratio, and bootstrap CI are the
//!    faithful deterministic functions of the whole census (same splitmix64
//!    stream, same floor-mean median rule, same basis-point rounding); and
//! 4. the corpus digest commits to exactly the census presented, and the
//!    ratio meets the signed threshold.
//!
//! The signed payload carries integers only (milliseconds, basis points);
//! floats fail verification.
//!
//! # Schema Versions
//!
//! * Summary: [`MIGTP_SCHEMA_VERSION`].
//! * Evidence census: [`MIGTP_EVIDENCE_SCHEMA_VERSION`].
//!
//! # Event Codes
//!
//! * `FN-VSDK-MIGTP-RECOMPUTE-START`
//! * `FN-VSDK-MIGTP-CENSUS-RECOMPUTED`
//! * `FN-VSDK-MIGTP-DELTA-PASS`

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

/// Schema version pinned by the signed throughput delta.
pub const MIGTP_SCHEMA_VERSION: &str = "franken-node/migration-throughput/v1";
/// Schema version pinned by the committed evidence census.
pub const MIGTP_EVIDENCE_SCHEMA_VERSION: &str = "franken-node/migration-throughput-evidence/v1";
/// Signature algorithm marker carried by the delta.
pub const MIGTP_SIGNATURE_ALGORITHM: &str = "ed25519";
/// Stable identifier for the reproducible throughput harness signing key.
pub const MIGTP_HARNESS_KEY_ID: &str = "franken-node-migration-throughput-harness-v1";

/// Domain separator for the Ed25519 signature preimage.
const MIGTP_SIGNATURE_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:migration-throughput-signature:v1:";
/// Domain separator for per-fixture census digests.
const MIGTP_EVIDENCE_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:migration-throughput-evidence:v1:";
/// Domain separator for the corpus digest over all fixtures.
const MIGTP_CORPUS_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:migration-throughput-corpus:v1:";
/// Seed preimage for the deterministic harness signing key.
const MIGTP_SEED_PREIMAGE: &[u8] = b"frankenengine-verifier-sdk:migration-throughput-harness-key:v1";

const SHA256_PREFIX: &str = "sha256:";

/// Event code emitted at the start of a throughput recompute.
pub const FN_VSDK_MIGTP_RECOMPUTE_START: &str = "FN-VSDK-MIGTP-RECOMPUTE-START";
/// Event code emitted once the census has been fully recomputed.
pub const FN_VSDK_MIGTP_CENSUS_RECOMPUTED: &str = "FN-VSDK-MIGTP-CENSUS-RECOMPUTED";
/// Event code emitted on a fully verified delta that meets the threshold.
pub const FN_VSDK_MIGTP_DELTA_PASS: &str = "FN-VSDK-MIGTP-DELTA-PASS";

/// One paired wall-clock measurement of both pipelines for a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensusRun {
    /// Zero-based measured-run index (warmups are excluded from the census).
    pub run_index: u64,
    /// Sum of the three tooled pipeline command durations, whole milliseconds.
    pub tool_ms: u64,
    /// Per-command tooled durations (audit, rewrite, validate).
    pub tool_commands_ms: Vec<u64>,
    /// Per-command tooled exit codes.
    pub tool_exit_codes: Vec<i64>,
    /// Sum of the three baseline pipeline command durations, whole milliseconds.
    pub baseline_ms: u64,
    /// Per-command baseline durations (audit, rewrite, validate).
    pub baseline_commands_ms: Vec<u64>,
    /// Per-command baseline exit codes.
    pub baseline_exit_codes: Vec<i64>,
}

/// One frozen input file of a fixture (path + content digest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensusInputFile {
    /// Repository-relative fixture file path.
    pub path: String,
    /// `sha256:` hex digest of the file bytes.
    pub sha256: String,
}

/// The census entry for a single fixture. The serialized field set is exactly
/// what the Python emitter writes; the SDK canonicalizes the raw entry
/// verbatim to recompute its corpus contribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureCensusEntry {
    /// Stable fixture identifier.
    pub fixture_id: String,
    /// `cohort` or `holdout`.
    pub role: String,
    /// Repository-relative fixture directory.
    pub source_path_rel: String,
    /// Frozen input files with content digests.
    pub input_files: Vec<CensusInputFile>,
    /// Documented expected static-validate outcome.
    pub expected_validate: String,
    /// Measured runs backing this fixture.
    pub runs: Vec<CensusRun>,
    /// Declared median of `runs[*].tool_ms`.
    pub tool_median_ms: u64,
    /// Declared median of `runs[*].baseline_ms`.
    pub baseline_median_ms: u64,
    /// Declared per-fixture velocity ratio in basis points.
    pub ratio_bp: u64,
}

/// Deterministic bootstrap CI95 of the velocity ratio, in basis points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapCi95 {
    /// Number of resamples.
    pub resamples: u64,
    /// Splitmix64 seed.
    pub seed: u64,
    /// 2.5th percentile of resampled ratios.
    pub ci95_low_bp: u64,
    /// 97.5th percentile of resampled ratios.
    pub ci95_high_bp: u64,
}

/// Detached signature block carried by the delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationThroughputSignature {
    /// Signature algorithm; must equal [`MIGTP_SIGNATURE_ALGORITHM`].
    pub algorithm: String,
    /// Stable key identifier.
    pub signer_key_id: String,
    /// Hex-encoded 32-byte Ed25519 public key the signature verifies against.
    pub signer_public_key_hex: String,
    /// Hex-encoded 64-byte Ed25519 signature over the canonical unsigned payload.
    pub signature_hex: String,
}

/// The full signed delta as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedThroughputDelta {
    /// Schema version; must equal [`MIGTP_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Generation timestamp (part of the signed payload).
    pub generated_at: String,
    /// Human-readable manual-baseline protocol description.
    pub protocol: String,
    /// Signed minimum acceptable velocity ratio, in basis points.
    pub required_velocity_ratio_bp: u64,
    /// Signed pooled velocity ratio, in basis points.
    pub velocity_ratio_bp: u64,
    /// Signed pooled median baseline pipeline duration, whole milliseconds.
    pub median_baseline_ms: u64,
    /// Signed pooled median tooled pipeline duration, whole milliseconds.
    pub median_tool_ms: u64,
    /// Signed deterministic bootstrap CI95.
    pub bootstrap_ci95: BootstrapCi95,
    /// Signed per-fixture ratio of the single holdout fixture, basis points.
    pub holdout_ratio_bp: u64,
    /// Cohort fixture identifiers (sorted).
    pub fixture_ids_cohort: Vec<String>,
    /// Holdout fixture identifiers (exactly one).
    pub fixture_ids_holdout: Vec<String>,
    /// Warmup runs excluded from the census.
    pub warmup_runs: u64,
    /// Measured runs per fixture recorded in the census.
    pub measured_runs: u64,
    /// `sha256:` digest over all `(fixture_id, evidence_digest)` pairs.
    pub corpus_digest: String,
    /// Detached Ed25519 signature block.
    pub signature: MigrationThroughputSignature,
}

/// Outcome of a successful delta verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedThroughputDelta {
    /// Delta schema version.
    pub schema_version: String,
    /// The verified velocity ratio, basis points.
    pub velocity_ratio_bp: u64,
    /// Verified bootstrap CI95.
    pub bootstrap_ci95: BootstrapCi95,
    /// Number of census fixtures verified.
    pub fixture_count: usize,
    /// The verified holdout ratio, basis points.
    pub holdout_ratio_bp: u64,
    /// The key id that signed the delta.
    pub signer_key_id: String,
    /// Event codes emitted by this verification.
    pub event_codes: Vec<String>,
}

/// Trust anchor used to verify the delta signature.
#[derive(Debug, Clone)]
pub enum ThroughputTrustAnchor {
    /// Pin to the reproducible throughput harness public key
    /// ([`migtp_harness_verifying_key`]) — the default for the committed
    /// artifact and any third party recomputing the key from its public seed.
    HarnessDefault,
    /// Pin to an operator-supplied Ed25519 trust anchor (for re-signed
    /// production deltas).
    OperatorKey(VerifyingKey),
}

/// Errors surfaced by [`verify_throughput_delta`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationThroughputError {
    /// A delta or census document failed to parse as JSON.
    Json(String),
    /// The delta schema version is unsupported.
    UnsupportedDeltaSchema { expected: String, actual: String },
    /// The census schema version is unsupported.
    UnsupportedCensusSchema { expected: String, actual: String },
    /// A floating-point value appeared where canonical integers are required.
    FloatingPointValue { path: String },
    /// The census carried no fixtures.
    EmptyCensus,
    /// The same fixture id appeared twice in the census.
    DuplicateCensusFixture { fixture_id: String },
    /// The delta's fixture id sets do not exactly match the census.
    FixtureSetMismatch,
    /// The holdout contract (exactly one holdout fixture) was violated.
    HoldoutContractViolated { actual: usize },
    /// Unsupported signature algorithm.
    SignatureAlgorithmUnsupported { actual: String },
    /// The embedded signer key did not match the trust anchor.
    SignerKeyMismatch,
    /// The embedded signer key or signature was malformed.
    SignatureMalformed,
    /// The Ed25519 signature did not verify over the canonical payload.
    SignatureInvalid,
    /// A census entry's declared aggregates disagree with its recorded runs.
    CensusRecomputeMismatch { fixture_id: String, detail: String },
    /// The delta's declared aggregates disagree with the recomputed values.
    DeltaRecomputeMismatch { detail: String },
    /// The corpus digest does not commit to the presented census.
    CorpusDigestMismatch,
    /// The signed threshold is not met by the recomputed ratio.
    ThresholdNotMet { ratio_bp: u64, required_bp: u64 },
}

impl fmt::Display for MigrationThroughputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(detail) => write!(formatter, "json error: {detail}"),
            Self::UnsupportedDeltaSchema { expected, actual } => {
                write!(formatter, "unsupported delta schema: expected {expected}, got {actual}")
            }
            Self::UnsupportedCensusSchema { expected, actual } => {
                write!(formatter, "unsupported census schema: expected {expected}, got {actual}")
            }
            Self::FloatingPointValue { path } => {
                write!(formatter, "float value where integer required: {path}")
            }
            Self::EmptyCensus => write!(formatter, "census carries no fixtures"),
            Self::DuplicateCensusFixture { fixture_id } => {
                write!(formatter, "duplicate census fixture: {fixture_id}")
            }
            Self::FixtureSetMismatch => {
                write!(formatter, "delta fixture id sets do not match the census")
            }
            Self::HoldoutContractViolated { actual } => {
                write!(formatter, "holdout contract requires exactly one holdout, got {actual}")
            }
            Self::SignatureAlgorithmUnsupported { actual } => {
                write!(formatter, "unsupported signature algorithm: {actual}")
            }
            Self::SignerKeyMismatch => write!(formatter, "signer key does not match anchor"),
            Self::SignatureMalformed => write!(formatter, "malformed signer key or signature"),
            Self::SignatureInvalid => write!(formatter, "signature invalid"),
            Self::CensusRecomputeMismatch { fixture_id, detail } => {
                write!(formatter, "census recompute mismatch for {fixture_id}: {detail}")
            }
            Self::DeltaRecomputeMismatch { detail } => {
                write!(formatter, "delta recompute mismatch: {detail}")
            }
            Self::CorpusDigestMismatch => write!(formatter, "corpus digest mismatch"),
            Self::ThresholdNotMet { ratio_bp, required_bp } => {
                write!(formatter, "velocity ratio {ratio_bp}bp below required {required_bp}bp")
            }
        }
    }
}

impl std::error::Error for MigrationThroughputError {}

type MigrationThroughputResult<T> = Result<T, MigrationThroughputError>;

// --------------------------------------------------------------------------- //
// Harness key (deterministic, RFC 8032; seed = SHA-256 of a public constant).
// --------------------------------------------------------------------------- //

/// The deterministic throughput harness signing key.
///
/// The seed is `SHA-256` of a public domain constant, so any party can
/// regenerate the identical key. Adversarial trust uses
/// [`ThroughputTrustAnchor::OperatorKey`].
#[must_use]
pub fn migtp_harness_signing_key() -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(MIGTP_SEED_PREIMAGE);
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// The public half of the reproducible throughput harness key.
#[must_use]
pub fn migtp_harness_verifying_key() -> VerifyingKey {
    migtp_harness_signing_key().verifying_key()
}

/// Hex-encode the reproducible throughput harness public key (32 bytes).
#[must_use]
pub fn migtp_harness_public_key_hex() -> String {
    hex::encode(migtp_harness_verifying_key().to_bytes())
}

// --------------------------------------------------------------------------- //
// Deterministic integer math (mirrored exactly by the Python emitter).
// --------------------------------------------------------------------------- //

/// Median of non-negative integers; even-length lists take the floor mean of
/// the two middle values.
#[must_use]
pub fn median_u64(values: &[u64]) -> u64 {
    let mut ordered = values.to_vec();
    ordered.sort_unstable();
    if ordered.is_empty() {
        return 0;
    }
    let mid = ordered.len() / 2;
    if ordered.len() % 2 == 1 {
        ordered[mid]
    } else {
        let sum = u128::from(ordered[mid - 1]) + u128::from(ordered[mid]);
        u64::try_from(sum / 2).unwrap_or(u64::MAX)
    }
}

/// Round-half-up basis-point ratio; denominator must be positive.
#[must_use]
pub fn ratio_bp(numerator_ms: u64, denominator_ms: u64) -> Option<u64> {
    if denominator_ms == 0 {
        return None;
    }
    let product = u128::from(numerator_ms) * 10_000_u128 + u128::from(denominator_ms / 2);
    u64::try_from(product / u128::from(denominator_ms)).ok()
}

/// One step of splitmix64: `(next_state, output)`.
#[must_use]
pub fn splitmix64(state: u64) -> (u64, u64) {
    let next = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = next;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (next, z ^ (z >> 31))
}

/// Deterministic percentile bootstrap CI95 over paired
/// `(tool_ms, baseline_ms)` samples; mirrors the Python emitter exactly.
#[must_use]
pub fn bootstrap_ci_bp(pairs: &[(u64, u64)], resamples: u64, seed: u64) -> Option<BootstrapCi95> {
    let n = pairs.len();
    if n == 0 || resamples == 0 {
        return None;
    }
    let n_u64 = u64::try_from(n).ok()?;
    let mut state = seed;
    let mut ratios: Vec<u64> = Vec::with_capacity(usize::try_from(resamples).ok()?);
    for _ in 0..resamples {
        let mut tool_sample: Vec<u64> = Vec::with_capacity(n);
        let mut baseline_sample: Vec<u64> = Vec::with_capacity(n);
        for _ in 0..n {
            let (next, out) = splitmix64(state);
            state = next;
            let index = usize::try_from(out % n_u64).ok()?;
            tool_sample.push(pairs[index].0);
            baseline_sample.push(pairs[index].1);
        }
        let tool_median = median_u64(&tool_sample);
        if tool_median == 0 {
            continue;
        }
        ratios.push(ratio_bp(median_u64(&baseline_sample), tool_median)?);
    }
    if ratios.is_empty() {
        return None;
    }
    ratios.sort_unstable();
    let count = u64::try_from(ratios.len()).ok()?;
    let lo_index = usize::try_from((2 * resamples) / 40).ok()?;
    let hi_offset = (2 * resamples) / 40;
    let hi_index = usize::try_from(count.saturating_sub(1).saturating_sub(hi_offset)).ok()?;
    Some(BootstrapCi95 {
        resamples,
        seed,
        ci95_low_bp: ratios[lo_index],
        ci95_high_bp: ratios[hi_index],
    })
}

// --------------------------------------------------------------------------- //
// Canonical JSON + hashing helpers (byte-compatible with the Python emitter
// and with honesty_manifest.rs / calibration.rs).
// --------------------------------------------------------------------------- //

fn canonical_json_value_bytes(value: Value) -> MigrationThroughputResult<Vec<u8>> {
    let canonical = canonicalize_value(value);
    serde_json::to_vec(&canonical).map_err(|source| MigrationThroughputError::Json(source.to_string()))
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut object = serde_json::Map::with_capacity(entries.len());
            for (key, value) in entries {
                object.insert(key, canonicalize_value(value));
            }
            Value::Object(object)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn reject_float_values(value: &Value, path: &str) -> MigrationThroughputResult<()> {
    match value {
        Value::Number(number) if number.is_f64() => Err(MigrationThroughputError::FloatingPointValue {
            path: path.to_string(),
        }),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_float_values(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, item) in map {
                reject_float_values(item, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn sha256_prefixed(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_len_prefixed(&mut hasher, payload);
    format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

fn migtp_signature_message(canonical_unsigned: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        MIGTP_SIGNATURE_DOMAIN.len() + 8 + canonical_unsigned.len(),
    );
    message.extend_from_slice(MIGTP_SIGNATURE_DOMAIN);
    let len = u64::try_from(canonical_unsigned.len()).unwrap_or(u64::MAX);
    message.extend_from_slice(&len.to_le_bytes());
    message.extend_from_slice(canonical_unsigned);
    message
}

fn census_digest_for(entry: &Value) -> MigrationThroughputResult<String> {
    let canonical = canonical_json_value_bytes(entry.clone())?;
    Ok(sha256_prefixed(MIGTP_EVIDENCE_DOMAIN, &canonical))
}

fn corpus_digest_for(pairs: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MIGTP_CORPUS_DOMAIN);
    for (fixture_id, digest) in pairs {
        update_len_prefixed(&mut hasher, fixture_id.as_bytes());
        update_len_prefixed(&mut hasher, digest.as_bytes());
    }
    format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn parse_verifying_key(hex_str: &str) -> MigrationThroughputResult<VerifyingKey> {
    let bytes = hex::decode(hex_str).map_err(|_| MigrationThroughputError::SignatureMalformed)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| MigrationThroughputError::SignatureMalformed)?;
    VerifyingKey::from_bytes(&array).map_err(|_| MigrationThroughputError::SignatureMalformed)
}

fn parse_signature(hex_str: &str) -> MigrationThroughputResult<Signature> {
    let bytes = hex::decode(hex_str).map_err(|_| MigrationThroughputError::SignatureMalformed)?;
    Signature::from_slice(&bytes).map_err(|_| MigrationThroughputError::SignatureMalformed)
}

fn constant_time_eq_bytes(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

// --------------------------------------------------------------------------- //
// Verification
// --------------------------------------------------------------------------- //

/// Verify a signed migration-throughput delta against its committed census,
/// recomputing every aggregate with zero trust in the producing runtime.
///
/// # Errors
///
/// Returns a [`MigrationThroughputError`] if either document is malformed,
/// the signature does not verify against the trust anchor, any census
/// entry's declared aggregates disagree with its recorded runs, the pooled
/// aggregates or bootstrap CI disagree with the census, the corpus digest
/// does not commit to the census, or the ratio misses the signed threshold.
pub fn verify_throughput_delta(
    delta_bytes: &[u8],
    evidence_bytes: &[u8],
    anchor: &ThroughputTrustAnchor,
) -> MigrationThroughputResult<VerifiedThroughputDelta> {
    // --- Parse + float-reject both documents ------------------------------- //
    let delta_value: Value = serde_json::from_slice(delta_bytes)
        .map_err(|source| MigrationThroughputError::Json(source.to_string()))?;
    reject_float_values(&delta_value, "$")?;
    let delta: SignedThroughputDelta = serde_json::from_value(delta_value.clone())
        .map_err(|source| MigrationThroughputError::Json(source.to_string()))?;

    let evidence_value: Value = serde_json::from_slice(evidence_bytes)
        .map_err(|source| MigrationThroughputError::Json(source.to_string()))?;
    reject_float_values(&evidence_value, "$")?;

    // --- Schemas ----------------------------------------------------------- //
    if delta.schema_version != MIGTP_SCHEMA_VERSION {
        return Err(MigrationThroughputError::UnsupportedDeltaSchema {
            expected: MIGTP_SCHEMA_VERSION.to_string(),
            actual: delta.schema_version,
        });
    }
    let evidence_schema = evidence_value
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| MigrationThroughputError::Json("census.schema_version missing".to_string()))?
        .to_string();
    if evidence_schema != MIGTP_EVIDENCE_SCHEMA_VERSION {
        return Err(MigrationThroughputError::UnsupportedCensusSchema {
            expected: MIGTP_EVIDENCE_SCHEMA_VERSION.to_string(),
            actual: evidence_schema,
        });
    }

    // --- Signature --------------------------------------------------------- //
    if delta.signature.algorithm != MIGTP_SIGNATURE_ALGORITHM {
        return Err(MigrationThroughputError::SignatureAlgorithmUnsupported {
            actual: delta.signature.algorithm.clone(),
        });
    }
    let anchor_key = match anchor {
        ThroughputTrustAnchor::HarnessDefault => migtp_harness_verifying_key(),
        ThroughputTrustAnchor::OperatorKey(key) => *key,
    };
    let embedded_key = parse_verifying_key(&delta.signature.signer_public_key_hex)?;
    if !constant_time_eq_bytes(&embedded_key.to_bytes(), &anchor_key.to_bytes()) {
        return Err(MigrationThroughputError::SignerKeyMismatch);
    }

    let mut unsigned_value = delta_value.clone();
    if let Some(object) = unsigned_value.as_object_mut() {
        object.remove("signature");
    }
    let canonical_unsigned = canonical_json_value_bytes(unsigned_value)?;
    let message = migtp_signature_message(&canonical_unsigned);
    let signature = parse_signature(&delta.signature.signature_hex)?;
    anchor_key
        .verify_strict(&message, &signature)
        .map_err(|_| MigrationThroughputError::SignatureInvalid)?;

    // --- Index the census, rejecting duplicates ---------------------------- //
    let census_entries: Vec<FixtureCensusEntry> = serde_json::from_value(
        evidence_value
            .get("fixtures")
            .cloned()
            .ok_or_else(|| {
                MigrationThroughputError::Json("census.fixtures missing".to_string())
            })?,
    )
    .map_err(|source| MigrationThroughputError::Json(source.to_string()))?;
    if census_entries.is_empty() {
        return Err(MigrationThroughputError::EmptyCensus);
    }
    let raw_fixtures = evidence_value
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| MigrationThroughputError::Json("census.fixtures missing".to_string()))?;

    let mut census_index: BTreeMap<String, &Value> = BTreeMap::new();
    for (entry, raw) in census_entries.iter().zip(raw_fixtures.iter()) {
        if census_index.insert(entry.fixture_id.clone(), raw).is_some() {
            return Err(MigrationThroughputError::DuplicateCensusFixture {
                fixture_id: entry.fixture_id.clone(),
            });
        }
    }

    // --- Holdout + fixture-set contracts ----------------------------------- //
    let holdout_count = census_entries.iter().filter(|e| e.role == "holdout").count();
    if holdout_count != 1 {
        return Err(MigrationThroughputError::HoldoutContractViolated { actual: holdout_count });
    }
    let mut census_ids: Vec<String> =
        census_entries.iter().map(|e| e.fixture_id.clone()).collect();
    census_ids.sort();
    let mut declared_ids = delta.fixture_ids_cohort.clone();
    declared_ids.extend(delta.fixture_ids_holdout.iter().cloned());
    declared_ids.sort();
    if census_ids != declared_ids {
        return Err(MigrationThroughputError::FixtureSetMismatch);
    }

    // --- Recompute each census entry's aggregates from its runs ------------ //
    let mut pooled_pairs: Vec<(u64, u64)> = Vec::new();
    let mut corpus_pairs: BTreeMap<String, String> = BTreeMap::new();
    for entry in &census_entries {
        let runs: Vec<(u64, u64)> = entry.runs.iter().map(|r| (r.tool_ms, r.baseline_ms)).collect();
        if runs.is_empty() {
            return Err(MigrationThroughputError::CensusRecomputeMismatch {
                fixture_id: entry.fixture_id.clone(),
                detail: "no recorded runs".to_string(),
            });
        }
        let tool_values: Vec<u64> = runs.iter().map(|(tool, _)| *tool).collect();
        let baseline_values: Vec<u64> = runs.iter().map(|(_, baseline)| *baseline).collect();
        let tool_median = median_u64(&tool_values);
        let baseline_median = median_u64(&baseline_values);
        let entry_ratio = ratio_bp(baseline_median, tool_median).ok_or_else(|| {
            MigrationThroughputError::CensusRecomputeMismatch {
                fixture_id: entry.fixture_id.clone(),
                detail: "zero tool median".to_string(),
            }
        })?;
        if tool_median != entry.tool_median_ms
            || baseline_median != entry.baseline_median_ms
            || entry_ratio != entry.ratio_bp
        {
            return Err(MigrationThroughputError::CensusRecomputeMismatch {
                fixture_id: entry.fixture_id.clone(),
                detail: format!(
                    "declared (tool={},baseline={},ratio={}) vs recomputed \
                     (tool={tool_median},baseline={baseline_median},ratio={entry_ratio})",
                    entry.tool_median_ms,
                    entry.baseline_median_ms,
                    entry.ratio_bp
                ),
            });
        }
        pooled_pairs.extend(runs);
        corpus_pairs.insert(entry.fixture_id.clone(), census_digest_for(
            census_index.get(&entry.fixture_id).copied().ok_or_else(|| {
                MigrationThroughputError::CensusRecomputeMismatch {
                    fixture_id: entry.fixture_id.clone(),
                    detail: "raw census value missing".to_string(),
                }
            })?,
        )?);
    }

    // --- Recompute pooled aggregates + bootstrap --------------------------- //
    let pooled_tool_values: Vec<u64> = pooled_pairs.iter().map(|(tool, _)| *tool).collect();
    let pooled_baseline_values: Vec<u64> = pooled_pairs.iter().map(|(_, baseline)| *baseline).collect();
    let pooled_tool = median_u64(&pooled_tool_values);
    let pooled_baseline = median_u64(&pooled_baseline_values);
    let recomputed_ratio = ratio_bp(pooled_baseline, pooled_tool).ok_or_else(|| {
        MigrationThroughputError::DeltaRecomputeMismatch { detail: "zero pooled tool median".to_string() }
    })?;
    let recomputed_ci = bootstrap_ci_bp(&pooled_pairs, delta.bootstrap_ci95.resamples, delta.bootstrap_ci95.seed)
        .ok_or_else(|| MigrationThroughputError::DeltaRecomputeMismatch {
            detail: "bootstrap produced no resamples".to_string(),
        })?;

    if pooled_tool != delta.median_tool_ms || pooled_baseline != delta.median_baseline_ms {
        return Err(MigrationThroughputError::DeltaRecomputeMismatch {
            detail: format!(
                "pooled medians declared ({},{}) vs recomputed ({pooled_tool},{pooled_baseline})",
                delta.median_tool_ms, delta.median_baseline_ms
            ),
        });
    }
    if recomputed_ratio != delta.velocity_ratio_bp {
        return Err(MigrationThroughputError::DeltaRecomputeMismatch {
            detail: format!(
                "ratio declared {} vs recomputed {recomputed_ratio}",
                delta.velocity_ratio_bp
            ),
        });
    }
    if recomputed_ci != delta.bootstrap_ci95 {
        return Err(MigrationThroughputError::DeltaRecomputeMismatch {
            detail: "bootstrap CI disagrees with census recompute".to_string(),
        });
    }
    let holdout_entry = census_entries
        .iter()
        .find(|entry| entry.role == "holdout")
        .ok_or(MigrationThroughputError::HoldoutContractViolated { actual: 0 })?;
    if holdout_entry.ratio_bp != delta.holdout_ratio_bp {
        return Err(MigrationThroughputError::DeltaRecomputeMismatch {
            detail: "holdout ratio disagrees with census".to_string(),
        });
    }

    // --- Corpus digest ------------------------------------------------------ //
    let recomputed_corpus = corpus_digest_for(&corpus_pairs);
    if !constant_time_eq_bytes(
        recomputed_corpus.as_bytes(),
        delta.corpus_digest.as_bytes(),
    ) {
        return Err(MigrationThroughputError::CorpusDigestMismatch);
    }

    // --- Threshold ---------------------------------------------------------- //
    if delta.velocity_ratio_bp < delta.required_velocity_ratio_bp {
        return Err(MigrationThroughputError::ThresholdNotMet {
            ratio_bp: delta.velocity_ratio_bp,
            required_bp: delta.required_velocity_ratio_bp,
        });
    }

    Ok(VerifiedThroughputDelta {
        schema_version: delta.schema_version,
        velocity_ratio_bp: delta.velocity_ratio_bp,
        bootstrap_ci95: delta.bootstrap_ci95,
        fixture_count: census_entries.len(),
        holdout_ratio_bp: delta.holdout_ratio_bp,
        signer_key_id: delta.signature.signer_key_id,
        event_codes: vec![
            FN_VSDK_MIGTP_RECOMPUTE_START.to_string(),
            FN_VSDK_MIGTP_CENSUS_RECOMPUTED.to_string(),
            FN_VSDK_MIGTP_DELTA_PASS.to_string(),
        ],
    })
}
