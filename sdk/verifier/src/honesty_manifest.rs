//! Offline recomputation for the README **Honesty Manifest**.
//!
//! The project thesis is "claims require evidence; the verifier SDK runs
//! outside the producing runtime." This module applies that rule to the
//! README's *headline* claims (test counts, fuzz-target count, validator
//! count, unsafe-block count, license string, replay-load-bearing flag).
//!
//! Two committed artifacts back the claims:
//!
//! * `docs/honesty_manifest_evidence.json` — the **census**: a granular,
//!   per-file/per-site snapshot of the committed tree from which each claim is
//!   derived (e.g. one `{source, count}` entry per `.rs` file that contributes
//!   `#[test]` attributes). This is the "committed tree snapshot" any third
//!   party can independently regenerate from source.
//! * `docs/honesty_manifest.json` — the **signed manifest**: for each claim it
//!   binds the recomputed value, the README's pinned value, a drift tolerance,
//!   and an `evidence_digest` over the matching census entry, plus a single
//!   `corpus_digest` over all claims and a detached Ed25519 signature over the
//!   canonical unsigned payload.
//!
//! [`verify_honesty_manifest`] proves, with **zero trust in the producing
//! runtime**:
//!
//! 1. the manifest is authentically signed (Ed25519, pinned harness anchor or
//!    an operator-supplied trust anchor);
//! 2. every claim's recorded value is the faithful function of the committed
//!    census (`evidence_digest` + value recompute);
//! 3. the recorded value is within tolerance of the README's pinned claim
//!    (truth-in-labeling); and
//! 4. the corpus digest commits to exactly the claim set presented.
//!
//! Flipping a single count, value, digest, or signature byte makes
//! verification fail closed. The census↔tree binding (does the census match
//! the live tree?) is enforced separately and continuously by
//! `scripts/check_claims_manifest.py --check-honesty`; together the two layers
//! form a complete chain from source tree to signed, independently
//! re-verifiable claim.
//!
//! # Schema Versions
//!
//! * Manifest: [`HONESTY_MANIFEST_SCHEMA_VERSION`].
//! * Evidence corpus: [`HONESTY_EVIDENCE_SCHEMA_VERSION`].
//!
//! # Event Codes
//!
//! * `FN-VSDK-HONESTY-RECOMPUTE-START`
//! * `FN-VSDK-HONESTY-CLAIMS-RECOMPUTED`
//! * `FN-VSDK-HONESTY-MANIFEST-PASS`

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

/// Schema version pinned by the signed Honesty Manifest.
pub const HONESTY_MANIFEST_SCHEMA_VERSION: &str = "franken-node/honesty-manifest/v1";
/// Schema version pinned by the committed evidence census.
pub const HONESTY_EVIDENCE_SCHEMA_VERSION: &str = "franken-node/honesty-manifest-evidence/v1";
/// Signature algorithm marker carried by the manifest.
pub const HONESTY_MANIFEST_SIGNATURE_ALGORITHM: &str = "ed25519";
/// Stable identifier for the reproducible harness signing key.
pub const HONESTY_MANIFEST_HARNESS_KEY_ID: &str = "franken-node-honesty-manifest-harness-v1";

/// Domain separator for the Ed25519 signature preimage.
const HONESTY_MANIFEST_SIGNATURE_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:honesty-manifest-signature:v1:";
/// Domain separator for per-claim evidence digests.
const HONESTY_CLAIM_EVIDENCE_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:honesty-claim-evidence:v1:";
/// Domain separator for the corpus digest over all claims.
const HONESTY_CORPUS_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:honesty-corpus:v1:";
/// Seed preimage for the deterministic harness signing key.
const HONESTY_MANIFEST_HARNESS_SEED_PREIMAGE: &[u8] =
    b"frankenengine-verifier-sdk:honesty-manifest-harness-key:v1";

const SHA256_PREFIX: &str = "sha256:";

/// Event code emitted at the start of an Honesty Manifest recompute.
pub const FN_VSDK_HONESTY_RECOMPUTE_START: &str = "FN-VSDK-HONESTY-RECOMPUTE-START";
/// Event code emitted once every claim value has been recomputed.
pub const FN_VSDK_HONESTY_CLAIMS_RECOMPUTED: &str = "FN-VSDK-HONESTY-CLAIMS-RECOMPUTED";
/// Event code emitted on a fully verified manifest.
pub const FN_VSDK_HONESTY_MANIFEST_PASS: &str = "FN-VSDK-HONESTY-MANIFEST-PASS";

/// One raw census item backing a claim (e.g. one source file's `#[test]` count,
/// or one registered fuzz target / validator script).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Tree-relative source path or stable identifier.
    pub source: String,
    /// The count this source contributes to the claim total.
    pub count: u64,
}

/// The census entry for a single claim. The serialized field set is exactly
/// `{claim_id, items, scalar}`; the SDK canonicalizes this entry verbatim to
/// recompute its `evidence_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Claim this census entry backs.
    pub claim_id: String,
    /// Per-source counts (empty for scalar claims and for must-be-zero claims).
    pub items: Vec<EvidenceItem>,
    /// Scalar evidence for string/bool claims (`None` for count claims).
    pub scalar: Option<String>,
}

/// The committed evidence corpus: a granular snapshot of the committed tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HonestyEvidence {
    /// Schema version; must equal [`HONESTY_EVIDENCE_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Generation timestamp (informational; not part of any digest).
    pub generated_at: String,
    /// One entry per claim.
    pub claims: Vec<EvidenceEntry>,
}

/// How a claim's value is derived from its census entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    /// Sum of `items.count`; compared to the README value within `tolerance_bp`.
    Count,
    /// Sum of `items.count`; compared to the README value exactly.
    Exact,
    /// `scalar`; compared to the README value exactly.
    String,
    /// `scalar` parsed as a boolean; compared to the README value exactly.
    Bool,
}

/// A single signed claim entry within the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestClaim {
    /// Stable claim identifier (joins to the matching [`EvidenceEntry`]).
    pub claim_id: String,
    /// How the value is derived from the census entry.
    pub kind: ClaimKind,
    /// The value recomputed from the committed census at generation time.
    pub recomputed_value: Value,
    /// The value the README headline pins (counts: rounded badge number).
    pub readme_value: Value,
    /// Allowed drift, in basis points, of `recomputed_value` vs `readme_value`
    /// (count claims only; `0` for exact/string/bool).
    pub tolerance_bp: u64,
    /// `sha256:` digest over the matching census entry.
    pub evidence_digest: String,
    /// Human-readable README claim text (for audit trails).
    pub readme_claim: String,
}

/// Detached signature block carried by the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HonestyManifestSignature {
    /// Signature algorithm; must equal [`HONESTY_MANIFEST_SIGNATURE_ALGORITHM`].
    pub algorithm: String,
    /// Stable key identifier.
    pub signer_key_id: String,
    /// Hex-encoded 32-byte Ed25519 public key the signature verifies against.
    pub signer_public_key_hex: String,
    /// Hex-encoded 64-byte Ed25519 signature over the canonical unsigned payload.
    pub signature_hex: String,
}

/// The full signed manifest as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHonestyManifest {
    /// Schema version; must equal [`HONESTY_MANIFEST_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Generation timestamp (part of the signed payload).
    pub generated_at: String,
    /// Signed claim set.
    pub claims: Vec<ManifestClaim>,
    /// `sha256:` digest over all `(claim_id, evidence_digest)` pairs.
    pub corpus_digest: String,
    /// Detached Ed25519 signature block.
    pub signature: HonestyManifestSignature,
}

/// Outcome of a successful manifest verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedHonestyManifest {
    /// Manifest schema version.
    pub schema_version: String,
    /// Number of claims verified.
    pub claim_count: usize,
    /// The verified corpus digest.
    pub corpus_digest: String,
    /// The key id that signed the manifest.
    pub signer_key_id: String,
    /// Event codes emitted by this verification.
    pub event_codes: Vec<String>,
}

/// Trust anchor used to verify the manifest signature.
#[derive(Debug, Clone)]
pub enum HonestyTrustAnchor {
    /// Pin to the reproducible harness public key ([`harness_verifying_key`]).
    /// This is the default for the committed artifact and any third party who
    /// recomputes the harness key from its public seed.
    HarnessDefault,
    /// Pin to an operator-supplied Ed25519 trust anchor (for re-signed
    /// production manifests).
    OperatorKey(VerifyingKey),
}

/// Errors surfaced by [`verify_honesty_manifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HonestyManifestError {
    /// A manifest or evidence document failed to parse as JSON.
    Json(String),
    /// The manifest schema version is unsupported.
    UnsupportedManifestSchema { expected: String, actual: String },
    /// The evidence schema version is unsupported.
    UnsupportedEvidenceSchema { expected: String, actual: String },
    /// A floating-point value appeared where canonical integers are required.
    FloatingPointValue { path: String },
    /// The manifest carried no claims.
    EmptyManifest,
    /// The same claim id appeared twice in the manifest.
    DuplicateManifestClaim { claim_id: String },
    /// The same claim id appeared twice in the evidence corpus.
    DuplicateEvidenceClaim { claim_id: String },
    /// A manifest claim had no matching evidence entry.
    MissingEvidence { claim_id: String },
    /// An evidence entry had no matching manifest claim.
    UnexpectedEvidence { claim_id: String },
    /// Unsupported signature algorithm.
    SignatureAlgorithmUnsupported { actual: String },
    /// The embedded signer public key was malformed.
    SignerKeyMalformed,
    /// The embedded signer public key did not match the trust anchor.
    SignerKeyMismatch,
    /// The signature bytes were malformed.
    SignatureMalformed,
    /// The Ed25519 signature did not verify against the trust anchor.
    SignatureInvalid,
    /// A census entry's recomputed digest did not match the manifest.
    EvidenceDigestMismatch { claim_id: String },
    /// A count/exact claim's value did not equal the sum of its census items.
    EvidenceSumMismatch {
        claim_id: String,
        expected: u64,
        actual: u64,
    },
    /// A claim's recorded value type was invalid for its kind.
    InvalidValueType { claim_id: String, detail: String },
    /// A string/bool claim's scalar did not match its recorded value.
    ValueMismatch { claim_id: String },
    /// A count claim drifted from its README value beyond tolerance.
    ToleranceExceeded {
        claim_id: String,
        recomputed_value: u64,
        readme_value: u64,
        tolerance_bp: u64,
        drift_bp: u64,
    },
    /// An exact/string/bool claim disagreed with its README value.
    ReadmeValueMismatch { claim_id: String },
    /// The corpus digest did not match the recomputed value.
    CorpusDigestMismatch,
}

impl fmt::Display for HonestyManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(source) => write!(f, "honesty manifest JSON error: {source}"),
            Self::UnsupportedManifestSchema { expected, actual } => write!(
                f,
                "honesty manifest schema mismatch: expected {expected}, got {actual}"
            ),
            Self::UnsupportedEvidenceSchema { expected, actual } => write!(
                f,
                "honesty evidence schema mismatch: expected {expected}, got {actual}"
            ),
            Self::FloatingPointValue { path } => {
                write!(
                    f,
                    "honesty manifest contains floating point value at {path}"
                )
            }
            Self::EmptyManifest => write!(f, "honesty manifest contains no claims"),
            Self::DuplicateManifestClaim { claim_id } => {
                write!(f, "duplicate manifest claim `{claim_id}`")
            }
            Self::DuplicateEvidenceClaim { claim_id } => {
                write!(f, "duplicate evidence entry `{claim_id}`")
            }
            Self::MissingEvidence { claim_id } => {
                write!(f, "no census evidence for claim `{claim_id}`")
            }
            Self::UnexpectedEvidence { claim_id } => {
                write!(f, "census evidence `{claim_id}` has no manifest claim")
            }
            Self::SignatureAlgorithmUnsupported { actual } => {
                write!(f, "unsupported honesty signature algorithm `{actual}`")
            }
            Self::SignerKeyMalformed => write!(f, "honesty manifest signer key is malformed"),
            Self::SignerKeyMismatch => {
                write!(f, "honesty manifest signer key does not match trust anchor")
            }
            Self::SignatureMalformed => write!(f, "honesty manifest signature is malformed"),
            Self::SignatureInvalid => write!(f, "honesty manifest signature did not verify"),
            Self::EvidenceDigestMismatch { claim_id } => {
                write!(f, "census digest mismatch for claim `{claim_id}`")
            }
            Self::EvidenceSumMismatch {
                claim_id,
                expected,
                actual,
            } => write!(
                f,
                "census sum mismatch for claim `{claim_id}`: recorded {expected}, census {actual}"
            ),
            Self::InvalidValueType { claim_id, detail } => {
                write!(f, "claim `{claim_id}` has invalid value type: {detail}")
            }
            Self::ValueMismatch { claim_id } => {
                write!(f, "scalar value mismatch for claim `{claim_id}`")
            }
            Self::ToleranceExceeded {
                claim_id,
                recomputed_value,
                readme_value,
                tolerance_bp,
                drift_bp,
            } => write!(
                f,
                "claim `{claim_id}` drift {drift_bp}bp exceeds tolerance {tolerance_bp}bp \
                 (recomputed {recomputed_value} vs README {readme_value})"
            ),
            Self::ReadmeValueMismatch { claim_id } => {
                write!(
                    f,
                    "claim `{claim_id}` recomputed value disagrees with README value"
                )
            }
            Self::CorpusDigestMismatch => write!(f, "honesty manifest corpus digest mismatch"),
        }
    }
}

impl std::error::Error for HonestyManifestError {}

/// Result alias for honesty-manifest verification.
pub type HonestyManifestResult<T> = Result<T, HonestyManifestError>;

/// Derive the reproducible harness signing key from its public seed.
///
/// The seed is `SHA-256` of a public domain constant, so any party can
/// regenerate the identical key (Ed25519 is deterministic, RFC 8032). The
/// harness key provides a reproducible integrity signature for the committed
/// artifact; adversarial trust uses [`HonestyTrustAnchor::OperatorKey`].
#[must_use]
pub fn harness_signing_key() -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(HONESTY_MANIFEST_HARNESS_SEED_PREIMAGE);
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// The public half of the reproducible harness key.
#[must_use]
pub fn harness_verifying_key() -> VerifyingKey {
    harness_signing_key().verifying_key()
}

/// Hex-encode the reproducible harness public key (32 bytes).
#[must_use]
pub fn harness_public_key_hex() -> String {
    hex::encode(harness_verifying_key().to_bytes())
}

// --------------------------------------------------------------------------- //
// Effective test coverage (bd-5r99w.14)
//
// A raw test *count* is Goodhart-bait, so the honest "tests" signal is
// effective coverage: how much behavior is actually pinned (mutation adequacy,
// enforced by the mutants-gate against a registered floor) plus a statistical
// confidence interval on the executed-test pass set. This module provides the
// interval half — the Wilson score interval — as a deterministic, auditor-
// recomputable function over a measured (successes, trials) pair, in integer
// basis points (no floats survive into any canonical artifact).
// --------------------------------------------------------------------------- //

/// The standard normal quantile z for a 95% two-sided interval (1.96), in
/// milli-units, for use with [`wilson_score_interval_bp`].
pub const WILSON_Z_95_MILLI: u64 = 1_960;

/// Compute the Wilson score interval for a binomial proportion, returned as
/// `(lower_bp, upper_bp)` in basis points (0..=10000).
///
/// The Wilson interval is preferred over the naive normal interval for pass-rate
/// estimation because it stays within `[0, 1]`, behaves well at the extremes
/// (e.g. all tests passing does NOT yield a degenerate `[1, 1]`), and is well
/// defined for small samples. `z_milli` is the standard-normal quantile times
/// 1000 (use [`WILSON_Z_95_MILLI`] for a 95% interval).
///
/// `trials == 0` yields the non-informative `(0, 10000)`.
#[must_use]
pub fn wilson_score_interval_bp(successes: u64, trials: u64, z_milli: u64) -> (u64, u64) {
    if trials == 0 {
        return (0, 10_000);
    }
    let successes = successes.min(trials);
    let n = trials as f64;
    let p_hat = successes as f64 / n;
    let z = z_milli as f64 / 1_000.0;
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let center = (p_hat + z2 / (2.0 * n)) / denom;
    let margin = (z / denom) * ((p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * n * n))).sqrt();
    let lower = (center - margin).clamp(0.0, 1.0);
    let upper = (center + margin).clamp(0.0, 1.0);
    (to_basis_points(lower), to_basis_points(upper))
}

/// The Wilson lower confidence bound on a pass rate, in basis points — the
/// honest "at least this much of the executed-test behavior holds" figure.
#[must_use]
pub fn wilson_lower_bound_bp(successes: u64, trials: u64, z_milli: u64) -> u64 {
    wilson_score_interval_bp(successes, trials, z_milli).0
}

/// Round a probability in `[0, 1]` to the nearest basis point.
fn to_basis_points(probability: f64) -> u64 {
    let scaled = (probability.clamp(0.0, 1.0) * 10_000.0).round();
    if scaled.is_finite() { scaled as u64 } else { 0 }
}

/// Build the Ed25519 signature preimage for a canonical unsigned payload.
#[must_use]
pub fn honesty_signature_message(canonical_unsigned: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(HONESTY_MANIFEST_SIGNATURE_DOMAIN.len() + 8 + canonical_unsigned.len());
    message.extend_from_slice(HONESTY_MANIFEST_SIGNATURE_DOMAIN);
    let len = u64::try_from(canonical_unsigned.len()).unwrap_or(u64::MAX);
    message.extend_from_slice(&len.to_le_bytes());
    message.extend_from_slice(canonical_unsigned);
    message
}

/// Recompute the `sha256:` digest over a single census entry value. The entry
/// must be the canonical `{claim_id, items, scalar}` object.
fn evidence_digest_for(entry: &Value) -> HonestyManifestResult<String> {
    let canonical = canonical_json_value_bytes(entry.clone())?;
    Ok(sha256_prefixed(HONESTY_CLAIM_EVIDENCE_DOMAIN, &canonical))
}

/// Recompute the corpus digest over the ordered `(claim_id, evidence_digest)`
/// pairs, sorted by claim id.
fn corpus_digest_for(pairs: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HONESTY_CORPUS_DOMAIN);
    for (claim_id, digest) in pairs {
        update_len_prefixed(&mut hasher, claim_id.as_bytes());
        update_len_prefixed(&mut hasher, digest.as_bytes());
    }
    format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize()))
}

/// Verify a signed Honesty Manifest against its committed census, recomputing
/// every claim value with zero trust in the producing runtime.
///
/// # Errors
///
/// Returns a [`HonestyManifestError`] if the manifest or evidence is
/// malformed, the signature does not verify against the trust anchor, any
/// claim's census digest or value does not match, any count drifts beyond
/// tolerance, or the corpus digest does not commit to the presented claims.
pub fn verify_honesty_manifest(
    manifest_bytes: &[u8],
    evidence_bytes: &[u8],
    anchor: &HonestyTrustAnchor,
) -> HonestyManifestResult<VerifiedHonestyManifest> {
    // --- Parse + float-reject both documents ------------------------------- //
    let manifest_value: Value = serde_json::from_slice(manifest_bytes)
        .map_err(|source| HonestyManifestError::Json(source.to_string()))?;
    reject_float_values(&manifest_value, "$")?;
    let manifest: SignedHonestyManifest = serde_json::from_value(manifest_value.clone())
        .map_err(|source| HonestyManifestError::Json(source.to_string()))?;

    let evidence_value: Value = serde_json::from_slice(evidence_bytes)
        .map_err(|source| HonestyManifestError::Json(source.to_string()))?;
    reject_float_values(&evidence_value, "$")?;
    let evidence: HonestyEvidence = serde_json::from_value(evidence_value.clone())
        .map_err(|source| HonestyManifestError::Json(source.to_string()))?;

    // --- Schemas ----------------------------------------------------------- //
    if manifest.schema_version != HONESTY_MANIFEST_SCHEMA_VERSION {
        return Err(HonestyManifestError::UnsupportedManifestSchema {
            expected: HONESTY_MANIFEST_SCHEMA_VERSION.to_string(),
            actual: manifest.schema_version,
        });
    }
    if evidence.schema_version != HONESTY_EVIDENCE_SCHEMA_VERSION {
        return Err(HonestyManifestError::UnsupportedEvidenceSchema {
            expected: HONESTY_EVIDENCE_SCHEMA_VERSION.to_string(),
            actual: evidence.schema_version,
        });
    }
    if manifest.claims.is_empty() {
        return Err(HonestyManifestError::EmptyManifest);
    }

    // --- Signature --------------------------------------------------------- //
    if manifest.signature.algorithm != HONESTY_MANIFEST_SIGNATURE_ALGORITHM {
        return Err(HonestyManifestError::SignatureAlgorithmUnsupported {
            actual: manifest.signature.algorithm.clone(),
        });
    }
    let anchor_key = match anchor {
        HonestyTrustAnchor::HarnessDefault => harness_verifying_key(),
        HonestyTrustAnchor::OperatorKey(key) => *key,
    };
    let embedded_key = parse_verifying_key(&manifest.signature.signer_public_key_hex)?;
    if !constant_time_eq_bytes(&embedded_key.to_bytes(), &anchor_key.to_bytes()) {
        return Err(HonestyManifestError::SignerKeyMismatch);
    }

    // Canonicalize the unsigned payload by dropping the signature key from the
    // parsed object — operating on the Value guarantees byte-parity with the
    // generator regardless of struct field naming.
    let mut unsigned_value = manifest_value.clone();
    if let Some(object) = unsigned_value.as_object_mut() {
        object.remove("signature");
    }
    let canonical_unsigned = canonical_json_value_bytes(unsigned_value)?;
    let message = honesty_signature_message(&canonical_unsigned);
    let signature = parse_signature(&manifest.signature.signature_hex)?;
    anchor_key
        .verify_strict(&message, &signature)
        .map_err(|_| HonestyManifestError::SignatureInvalid)?;

    // --- Index the census, rejecting duplicates ---------------------------- //
    let mut evidence_index: BTreeMap<String, &Value> = BTreeMap::new();
    let evidence_array = evidence_value
        .get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| HonestyManifestError::Json("evidence.claims missing".to_string()))?;
    for (entry, raw) in evidence.claims.iter().zip(evidence_array.iter()) {
        if evidence_index.insert(entry.claim_id.clone(), raw).is_some() {
            return Err(HonestyManifestError::DuplicateEvidenceClaim {
                claim_id: entry.claim_id.clone(),
            });
        }
    }

    // --- Recompute each claim from the census ------------------------------ //
    let mut seen_claims: BTreeMap<String, String> = BTreeMap::new();
    for claim in &manifest.claims {
        if seen_claims.contains_key(&claim.claim_id) {
            return Err(HonestyManifestError::DuplicateManifestClaim {
                claim_id: claim.claim_id.clone(),
            });
        }
        let entry_value = *evidence_index.get(&claim.claim_id).ok_or_else(|| {
            HonestyManifestError::MissingEvidence {
                claim_id: claim.claim_id.clone(),
            }
        })?;
        let entry: EvidenceEntry = serde_json::from_value(entry_value.clone())
            .map_err(|source| HonestyManifestError::Json(source.to_string()))?;

        // (a) census digest binds the manifest claim to its census entry.
        let recomputed_digest = evidence_digest_for(entry_value)?;
        if !constant_time_eq(&recomputed_digest, &claim.evidence_digest) {
            return Err(HonestyManifestError::EvidenceDigestMismatch {
                claim_id: claim.claim_id.clone(),
            });
        }

        // (b) value recompute per kind.
        verify_claim_value(claim, &entry)?;

        seen_claims.insert(claim.claim_id.clone(), claim.evidence_digest.clone());
    }

    // Reject census entries with no corresponding manifest claim.
    for entry in &evidence.claims {
        if !seen_claims.contains_key(&entry.claim_id) {
            return Err(HonestyManifestError::UnexpectedEvidence {
                claim_id: entry.claim_id.clone(),
            });
        }
    }

    // --- Corpus digest ----------------------------------------------------- //
    let recomputed_corpus = corpus_digest_for(&seen_claims);
    if !constant_time_eq(&recomputed_corpus, &manifest.corpus_digest) {
        return Err(HonestyManifestError::CorpusDigestMismatch);
    }

    Ok(VerifiedHonestyManifest {
        schema_version: manifest.schema_version,
        claim_count: manifest.claims.len(),
        corpus_digest: manifest.corpus_digest,
        signer_key_id: manifest.signature.signer_key_id,
        event_codes: vec![
            FN_VSDK_HONESTY_RECOMPUTE_START.to_string(),
            FN_VSDK_HONESTY_CLAIMS_RECOMPUTED.to_string(),
            FN_VSDK_HONESTY_MANIFEST_PASS.to_string(),
        ],
    })
}

/// Recompute and check a single claim's value against its census entry and the
/// README's pinned value.
fn verify_claim_value(claim: &ManifestClaim, entry: &EvidenceEntry) -> HonestyManifestResult<()> {
    match claim.kind {
        ClaimKind::Count | ClaimKind::Exact => {
            let recorded = value_as_u64(&claim.recomputed_value).ok_or_else(|| {
                HonestyManifestError::InvalidValueType {
                    claim_id: claim.claim_id.clone(),
                    detail: "recomputed_value must be a non-negative integer".to_string(),
                }
            })?;
            let readme = value_as_u64(&claim.readme_value).ok_or_else(|| {
                HonestyManifestError::InvalidValueType {
                    claim_id: claim.claim_id.clone(),
                    detail: "readme_value must be a non-negative integer".to_string(),
                }
            })?;
            let census_sum = entry
                .items
                .iter()
                .fold(0_u64, |acc, item| acc.saturating_add(item.count));
            if census_sum != recorded {
                return Err(HonestyManifestError::EvidenceSumMismatch {
                    claim_id: claim.claim_id.clone(),
                    expected: recorded,
                    actual: census_sum,
                });
            }
            if matches!(claim.kind, ClaimKind::Exact) {
                if recorded != readme {
                    return Err(HonestyManifestError::ReadmeValueMismatch {
                        claim_id: claim.claim_id.clone(),
                    });
                }
            } else {
                let drift_bp = drift_bp(recorded, readme);
                if drift_bp > claim.tolerance_bp {
                    return Err(HonestyManifestError::ToleranceExceeded {
                        claim_id: claim.claim_id.clone(),
                        recomputed_value: recorded,
                        readme_value: readme,
                        tolerance_bp: claim.tolerance_bp,
                        drift_bp,
                    });
                }
            }
            Ok(())
        }
        ClaimKind::String => {
            let recorded = claim.recomputed_value.as_str().ok_or_else(|| {
                HonestyManifestError::InvalidValueType {
                    claim_id: claim.claim_id.clone(),
                    detail: "recomputed_value must be a string".to_string(),
                }
            })?;
            let scalar =
                entry
                    .scalar
                    .as_deref()
                    .ok_or_else(|| HonestyManifestError::InvalidValueType {
                        claim_id: claim.claim_id.clone(),
                        detail: "string claim requires a scalar census value".to_string(),
                    })?;
            if !constant_time_eq(scalar, recorded) {
                return Err(HonestyManifestError::ValueMismatch {
                    claim_id: claim.claim_id.clone(),
                });
            }
            if claim.readme_value.as_str() != Some(recorded) {
                return Err(HonestyManifestError::ReadmeValueMismatch {
                    claim_id: claim.claim_id.clone(),
                });
            }
            Ok(())
        }
        ClaimKind::Bool => {
            let recorded = claim.recomputed_value.as_bool().ok_or_else(|| {
                HonestyManifestError::InvalidValueType {
                    claim_id: claim.claim_id.clone(),
                    detail: "recomputed_value must be a boolean".to_string(),
                }
            })?;
            let scalar =
                entry
                    .scalar
                    .as_deref()
                    .ok_or_else(|| HonestyManifestError::InvalidValueType {
                        claim_id: claim.claim_id.clone(),
                        detail: "bool claim requires a scalar census value".to_string(),
                    })?;
            let scalar_bool =
                parse_bool(scalar).ok_or_else(|| HonestyManifestError::InvalidValueType {
                    claim_id: claim.claim_id.clone(),
                    detail: "bool claim scalar must be `true` or `false`".to_string(),
                })?;
            if scalar_bool != recorded {
                return Err(HonestyManifestError::ValueMismatch {
                    claim_id: claim.claim_id.clone(),
                });
            }
            if claim.readme_value.as_bool() != Some(recorded) {
                return Err(HonestyManifestError::ReadmeValueMismatch {
                    claim_id: claim.claim_id.clone(),
                });
            }
            Ok(())
        }
    }
}

fn drift_bp(recomputed: u64, readme: u64) -> u64 {
    if readme == 0 {
        return if recomputed == 0 { 0 } else { u64::MAX };
    }
    let diff = recomputed.max(readme) - recomputed.min(readme);
    // diff/readme in basis points, rounded down.
    (u128::from(diff).saturating_mul(10_000) / u128::from(readme))
        .try_into()
        .unwrap_or(u64::MAX)
}

fn value_as_u64(value: &Value) -> Option<u64> {
    value.as_u64()
}

fn parse_bool(text: &str) -> Option<bool> {
    match text {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_verifying_key(hex_str: &str) -> HonestyManifestResult<VerifyingKey> {
    let bytes = hex::decode(hex_str).map_err(|_| HonestyManifestError::SignerKeyMalformed)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| HonestyManifestError::SignerKeyMalformed)?;
    VerifyingKey::from_bytes(&array).map_err(|_| HonestyManifestError::SignerKeyMalformed)
}

fn parse_signature(hex_str: &str) -> HonestyManifestResult<Signature> {
    let bytes = hex::decode(hex_str).map_err(|_| HonestyManifestError::SignatureMalformed)?;
    Signature::from_slice(&bytes).map_err(|_| HonestyManifestError::SignatureMalformed)
}

// --------------------------------------------------------------------------- //
// Canonical JSON + hashing helpers (kept byte-compatible with the Python
// generator in scripts/check_claims_manifest.py and with calibration.rs).
// --------------------------------------------------------------------------- //

fn canonical_json_value_bytes(value: Value) -> HonestyManifestResult<Vec<u8>> {
    let canonical = canonicalize_value(value);
    serde_json::to_vec(&canonical).map_err(|source| HonestyManifestError::Json(source.to_string()))
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

fn reject_float_values(value: &Value, path: &str) -> HonestyManifestResult<()> {
    match value {
        Value::Number(number) if number.is_f64() => Err(HonestyManifestError::FloatingPointValue {
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

fn constant_time_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn constant_time_eq_bytes(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// Build a small but representative manifest+evidence pair signed by the
    /// harness key, mirroring exactly what the Python generator emits.
    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let evidence = serde_json::json!({
            "schema_version": HONESTY_EVIDENCE_SCHEMA_VERSION,
            "generated_at": "1970-01-01T00:00:00Z",
            "claims": [
                {
                    "claim_id": "integration_tests_run_by_cargo_test",
                    "items": [
                        {"source": "tests/a.rs", "count": 2000},
                        {"source": "tests/b.rs", "count": 1750}
                    ],
                    "scalar": null
                },
                {
                    "claim_id": "unsafe_blocks",
                    "items": [],
                    "scalar": null
                },
                {
                    "claim_id": "license",
                    "items": [],
                    "scalar": "LicenseRef-MIT-OpenAI-Anthropic-Rider"
                },
                {
                    "claim_id": "replay_verdict_load_bearing",
                    "items": [],
                    "scalar": "true"
                }
            ]
        });

        // Per-claim evidence digests recomputed exactly as the SDK does.
        let evidence_claims = evidence["claims"].as_array().unwrap();
        let digest_for = |claim_id: &str| -> String {
            let entry = evidence_claims
                .iter()
                .find(|c| c["claim_id"] == claim_id)
                .unwrap()
                .clone();
            evidence_digest_for(&entry).unwrap()
        };

        let claims = serde_json::json!([
            {
                "claim_id": "integration_tests_run_by_cargo_test",
                "kind": "count",
                "recomputed_value": 3750,
                "readme_value": 3800,
                "tolerance_bp": 3000,
                "evidence_digest": digest_for("integration_tests_run_by_cargo_test"),
                "readme_claim": "~3.8k e2e"
            },
            {
                "claim_id": "unsafe_blocks",
                "kind": "exact",
                "recomputed_value": 0,
                "readme_value": 0,
                "tolerance_bp": 0,
                "evidence_digest": digest_for("unsafe_blocks"),
                "readme_claim": "0"
            },
            {
                "claim_id": "license",
                "kind": "string",
                "recomputed_value": "LicenseRef-MIT-OpenAI-Anthropic-Rider",
                "readme_value": "LicenseRef-MIT-OpenAI-Anthropic-Rider",
                "tolerance_bp": 0,
                "evidence_digest": digest_for("license"),
                "readme_claim": "MIT + Rider"
            },
            {
                "claim_id": "replay_verdict_load_bearing",
                "kind": "bool",
                "recomputed_value": true,
                "readme_value": true,
                "tolerance_bp": 0,
                "evidence_digest": digest_for("replay_verdict_load_bearing"),
                "readme_claim": "load-bearing"
            }
        ]);

        // corpus digest over (claim_id, evidence_digest) sorted by id.
        let mut pairs: BTreeMap<String, String> = BTreeMap::new();
        for claim in claims.as_array().unwrap() {
            pairs.insert(
                claim["claim_id"].as_str().unwrap().to_string(),
                claim["evidence_digest"].as_str().unwrap().to_string(),
            );
        }
        let corpus_digest = corpus_digest_for(&pairs);

        let unsigned = serde_json::json!({
            "schema_version": HONESTY_MANIFEST_SCHEMA_VERSION,
            "generated_at": "1970-01-01T00:00:00Z",
            "claims": claims,
            "corpus_digest": corpus_digest
        });
        let canonical_unsigned = canonical_json_value_bytes(unsigned.clone()).unwrap();
        let signing_key = harness_signing_key();
        let message = honesty_signature_message(&canonical_unsigned);
        let signature = signing_key.sign(&message);

        let mut manifest = unsigned;
        manifest["signature"] = serde_json::json!({
            "algorithm": HONESTY_MANIFEST_SIGNATURE_ALGORITHM,
            "signer_key_id": HONESTY_MANIFEST_HARNESS_KEY_ID,
            "signer_public_key_hex": harness_public_key_hex(),
            "signature_hex": hex::encode(signature.to_bytes())
        });

        (
            serde_json::to_vec(&manifest).unwrap(),
            serde_json::to_vec(&evidence).unwrap(),
        )
    }

    #[test]
    fn harness_key_is_deterministic() {
        assert_eq!(harness_public_key_hex(), harness_public_key_hex());
        assert_eq!(harness_public_key_hex().len(), 64);
    }

    #[test]
    fn verifies_well_formed_manifest() {
        let (manifest, evidence) = fixture();
        let verified =
            verify_honesty_manifest(&manifest, &evidence, &HonestyTrustAnchor::HarnessDefault)
                .expect("manifest verifies");
        assert_eq!(verified.claim_count, 4);
        assert_eq!(verified.signer_key_id, HONESTY_MANIFEST_HARNESS_KEY_ID);
        assert!(
            verified
                .event_codes
                .contains(&FN_VSDK_HONESTY_MANIFEST_PASS.to_string())
        );
    }

    #[test]
    fn flipping_a_census_count_is_rejected() {
        let (manifest, evidence) = fixture();
        let mut evidence_value: Value = serde_json::from_slice(&evidence).unwrap();
        evidence_value["claims"][0]["items"][0]["count"] = serde_json::Value::from(2001_u64);
        let tampered = serde_json::to_vec(&evidence_value).unwrap();
        let err =
            verify_honesty_manifest(&manifest, &tampered, &HonestyTrustAnchor::HarnessDefault)
                .unwrap_err();
        // Changing the census changes the entry digest first.
        assert!(matches!(
            err,
            HonestyManifestError::EvidenceDigestMismatch { .. }
        ));
    }

    #[test]
    fn flipping_a_manifest_value_breaks_the_signature() {
        let (manifest, evidence) = fixture();
        let mut manifest_value: Value = serde_json::from_slice(&manifest).unwrap();
        manifest_value["claims"][0]["recomputed_value"] = serde_json::Value::from(9999_u64);
        let tampered = serde_json::to_vec(&manifest_value).unwrap();
        let err =
            verify_honesty_manifest(&tampered, &evidence, &HonestyTrustAnchor::HarnessDefault)
                .unwrap_err();
        assert!(matches!(err, HonestyManifestError::SignatureInvalid));
    }

    #[test]
    fn re_signing_with_a_foreign_key_is_rejected() {
        let (manifest, evidence) = fixture();
        let mut manifest_value: Value = serde_json::from_slice(&manifest).unwrap();
        // Attacker forges a value AND re-signs with their own key, embedding it.
        manifest_value["claims"][0]["recomputed_value"] = serde_json::Value::from(9999_u64);
        let mut unsigned = manifest_value.clone();
        unsigned.as_object_mut().unwrap().remove("signature");
        let canonical = canonical_json_value_bytes(unsigned).unwrap();
        let foreign = SigningKey::from_bytes(&[42_u8; 32]);
        let sig = foreign.sign(&honesty_signature_message(&canonical));
        manifest_value["signature"]["signer_public_key_hex"] =
            Value::from(hex::encode(foreign.verifying_key().to_bytes()));
        manifest_value["signature"]["signature_hex"] = Value::from(hex::encode(sig.to_bytes()));
        let tampered = serde_json::to_vec(&manifest_value).unwrap();
        let err =
            verify_honesty_manifest(&tampered, &evidence, &HonestyTrustAnchor::HarnessDefault)
                .unwrap_err();
        // Pinned harness anchor rejects the foreign key before signature check.
        assert!(matches!(err, HonestyManifestError::SignerKeyMismatch));
    }

    #[test]
    fn operator_anchor_accepts_re_signed_manifest() {
        let (manifest, evidence) = fixture();
        let mut manifest_value: Value = serde_json::from_slice(&manifest).unwrap();
        let mut unsigned = manifest_value.clone();
        unsigned.as_object_mut().unwrap().remove("signature");
        let canonical = canonical_json_value_bytes(unsigned).unwrap();
        let operator = SigningKey::from_bytes(&[7_u8; 32]);
        let sig = operator.sign(&honesty_signature_message(&canonical));
        manifest_value["signature"]["signer_public_key_hex"] =
            Value::from(hex::encode(operator.verifying_key().to_bytes()));
        manifest_value["signature"]["signer_key_id"] = Value::from("operator-2026");
        manifest_value["signature"]["signature_hex"] = Value::from(hex::encode(sig.to_bytes()));
        let re_signed = serde_json::to_vec(&manifest_value).unwrap();
        let verified = verify_honesty_manifest(
            &re_signed,
            &evidence,
            &HonestyTrustAnchor::OperatorKey(operator.verifying_key()),
        )
        .expect("operator-anchored manifest verifies");
        assert_eq!(verified.signer_key_id, "operator-2026");
    }

    #[test]
    fn tolerance_band_is_enforced() {
        let (manifest, evidence) = fixture();
        let mut manifest_value: Value = serde_json::from_slice(&manifest).unwrap();
        // Tighten tolerance to 0 so 3750 vs 3800 (~132bp) drift trips it; then
        // re-sign with the harness key so the signature passes and we reach the
        // tolerance check.
        manifest_value["claims"][0]["tolerance_bp"] = Value::from(0_u64);
        let mut unsigned = manifest_value.clone();
        unsigned.as_object_mut().unwrap().remove("signature");
        let canonical = canonical_json_value_bytes(unsigned).unwrap();
        let sig = harness_signing_key().sign(&honesty_signature_message(&canonical));
        manifest_value["signature"]["signature_hex"] = Value::from(hex::encode(sig.to_bytes()));
        let tightened = serde_json::to_vec(&manifest_value).unwrap();
        let err =
            verify_honesty_manifest(&tightened, &evidence, &HonestyTrustAnchor::HarnessDefault)
                .unwrap_err();
        assert!(matches!(
            err,
            HonestyManifestError::ToleranceExceeded { .. }
        ));
    }

    #[test]
    fn drift_bp_math() {
        assert_eq!(drift_bp(100, 100), 0);
        assert_eq!(drift_bp(110, 100), 1000); // +10%
        assert_eq!(drift_bp(90, 100), 1000); // -10%
        assert_eq!(drift_bp(0, 0), 0);
        assert_eq!(drift_bp(1, 0), u64::MAX);
    }

    /// Assert a basis-point value is within `tol` of `expected`.
    fn assert_near_bp(got: u64, expected: u64, tol: u64, label: &str) {
        let diff = got.max(expected) - got.min(expected);
        assert!(
            diff <= tol,
            "{label}: got {got}bp, expected ~{expected}bp (±{tol})"
        );
    }

    #[test]
    fn wilson_interval_matches_textbook_values() {
        // 95/100 at 95%: Wilson CI ~ [0.8882, 0.9784].
        let (lo, hi) = wilson_score_interval_bp(95, 100, WILSON_Z_95_MILLI);
        assert_near_bp(lo, 8882, 2, "wilson lower 95/100");
        assert_near_bp(hi, 9784, 2, "wilson upper 95/100");

        // 50/100 at 95%: symmetric ~ [0.4038, 0.5962].
        let (lo, hi) = wilson_score_interval_bp(50, 100, WILSON_Z_95_MILLI);
        assert_near_bp(lo, 4038, 2, "wilson lower 50/100");
        assert_near_bp(hi, 5962, 2, "wilson upper 50/100");

        // All-pass is NOT degenerate [1,1]: 100/100 has a lower bound < 1.
        let (lo, hi) = wilson_score_interval_bp(100, 100, WILSON_Z_95_MILLI);
        assert_near_bp(lo, 9630, 3, "wilson lower 100/100");
        assert!(lo < 10_000, "all-pass lower bound must stay below 1.0");
        assert_eq!(hi, 10_000, "all-pass upper bound clamps at 1.0");

        // No observations -> non-informative full interval.
        assert_eq!(
            wilson_score_interval_bp(0, 0, WILSON_Z_95_MILLI),
            (0, 10_000)
        );
    }

    #[test]
    fn wilson_lower_bound_is_monotone_in_successes() {
        // More passing tests at the same sample size can only raise the floor.
        let weak = wilson_lower_bound_bp(90, 100, WILSON_Z_95_MILLI);
        let strong = wilson_lower_bound_bp(95, 100, WILSON_Z_95_MILLI);
        assert!(
            weak < strong,
            "lower bound must increase with more successes: {weak} !< {strong}"
        );
        // Saturating: successes capped at trials.
        assert_eq!(
            wilson_lower_bound_bp(200, 100, WILSON_Z_95_MILLI),
            wilson_lower_bound_bp(100, 100, WILSON_Z_95_MILLI),
            "successes are clamped to trials"
        );
    }

    #[test]
    fn unknown_schema_is_rejected() {
        let (manifest, evidence) = fixture();
        let mut manifest_value: Value = serde_json::from_slice(&manifest).unwrap();
        manifest_value["schema_version"] = Value::from("franken-node/honesty-manifest/v99");
        let bad = serde_json::to_vec(&manifest_value).unwrap();
        let err = verify_honesty_manifest(&bad, &evidence, &HonestyTrustAnchor::HarnessDefault)
            .unwrap_err();
        assert!(matches!(
            err,
            HonestyManifestError::UnsupportedManifestSchema { .. }
        ));
    }
}
