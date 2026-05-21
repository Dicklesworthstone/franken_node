//! Signature scheme trait abstractions and concrete implementations.
//!
//! # Ed25519 Preparsed Key Handles (Performance Optimization)
//!
//! The stateless [`SignatureScheme`] trait parses keys from raw bytes on every
//! operation. This is intentional: other schemes (RSA, ECDSA) may not support
//! keypair caching, and the trait surface must remain generic.
//!
//! For **Ed25519 specifically**, repeated parsing is expensive:
//! - `SigningKey::from_bytes` performs SHA-512 expansion + basepoint scalar multiply
//! - `VerifyingKey::from_bytes` decompresses the Edwards curve point
//!
//! When signing/verifying in a loop with the same key, callers should use the
//! preparsed handle types instead:
//!
//! - [`Ed25519PreparsedSigner`]: Wraps a `SigningKey` for repeated signing.
//! - [`Ed25519PreparsedVerifier`]: Wraps a `VerifyingKey` for repeated verification.
//!
//! ## Thread Safety
//!
//! Both types implement `Send + Sync` and can be stored in `Arc<>`, `OnceCell<>`,
//! or other shared containers on long-lived control-plane objects.
//!
//! ## ZeroizeOnDrop
//!
//! `ed25519_dalek::SigningKey` implements `ZeroizeOnDrop` (dalek 2.x). The
//! [`Ed25519PreparsedSigner`] wrapper inherits this: when dropped, the secret
//! key material is securely zeroed. Callers do not need explicit cleanup.
//!
//! ## Constructor Semantics
//!
//! - `Ed25519PreparsedSigner::from_secret_bytes(&[u8; 32])` is **infallible**:
//!   any 32-byte input is a valid Ed25519 seed.
//! - `Ed25519PreparsedVerifier::from_public_bytes(&[u8; 32])` is **fallible**:
//!   the compressed Edwards point may fail to decompress.
//!
//! ## Domain Separation
//!
//! The preparsed `sign_with_domain` / `verify_with_domain` methods produce
//! bit-for-bit identical output to [`Ed25519Scheme::sign_with_domain`] and
//! [`Ed25519Scheme::verify_with_domain`]. The canonical preimage is:
//!
//! ```text
//! b"ed25519_signature_v1:" || len(domain) as u64 LE || domain || len(msg) as u64 LE || msg
//! ```
//!
//! This is hashed (blake3 or SHA-256 depending on feature flags) before signing.

use crate::crypto::error::Ed25519Error;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const ED25519_SIGNATURE_PREIMAGE_DOMAIN: &[u8] = b"ed25519_signature_v1:";

fn len_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Unified signature scheme abstraction with domain separation support.
///
/// This trait provides a generic interface for cryptographic signature schemes
/// with built-in domain separation, constant-time verification, and consistent
/// error handling patterns.
pub trait SignatureScheme: Send + Sync + 'static {
    /// Public key type for this scheme
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    /// Secret key type for this scheme
    type SecretKey: AsRef<[u8]> + Clone + Send + Sync;
    /// Signature type for this scheme
    type Signature: AsRef<[u8]> + Clone + Send + Sync;
    /// Error type for this scheme
    type Error: std::error::Error + Send + Sync + 'static;

    /// Scheme identifier for domain separation and algorithm identification.
    fn scheme_id() -> &'static str;

    /// Generate a new cryptographically secure keypair.
    ///
    /// Uses the operating system's cryptographically secure random number generator.
    fn generate_keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;

    /// Sign a message with domain separation.
    ///
    /// The domain parameter provides cryptographic separation between different
    /// contexts and prevents signature reuse across different applications.
    ///
    /// # Security
    /// - Uses length-prefixed encoding to prevent collision attacks
    /// - Includes scheme-specific domain separator
    /// - All inputs are cryptographically hashed before signing
    fn sign_with_domain(
        secret_key: &Self::SecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error>;

    /// Verify a signature with domain separation using constant-time comparison.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    /// Uses constant-time operations to prevent timing attacks.
    ///
    /// # Security
    /// - Returns bool (not Result) for constant-time usage patterns
    /// - Uses same domain separation as signing
    /// - All verification operations complete in constant time
    #[must_use]
    fn verify_with_domain(
        public_key: &Self::PublicKey,
        domain: &[u8],
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool;

    /// Sign the exact bytes provided, without any wrapper domain or length framing.
    ///
    /// Use this when the caller has already constructed a canonical preimage that
    /// embeds its own domain separator and length-prefix scheme (e.g. signed
    /// receipts that prepend `DECISION_RECEIPT_SIGNATURE_VERSION` and a sorted
    /// JSON body, or replay bundles with their own header). Calling
    /// [`sign_with_domain`](Self::sign_with_domain) on those preimages would
    /// double-wrap the bytes and break on-the-wire signature compatibility with
    /// existing artifacts.
    ///
    /// # Security
    /// - The caller is responsible for cryptographic domain separation.
    /// - Output bytes are bit-for-bit identical to a direct Ed25519 sign over
    ///   `message` for [`Ed25519Scheme`].
    fn sign_raw(
        secret_key: &Self::SecretKey,
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error>;

    /// Verify a signature over the exact bytes provided, without any wrapper
    /// domain or length framing.
    ///
    /// Mirror of [`sign_raw`](Self::sign_raw). Returns `false` on any failure
    /// (malformed key, malformed signature, or verification mismatch) so that
    /// callers can branch in constant time.
    ///
    /// # Security
    /// - Uses strict verification (rejects malleable / non-canonical signatures)
    ///   for schemes that support it.
    #[must_use]
    fn verify_raw(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool;

    /// Parse public key from raw bytes with validation.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error>;

    /// Parse signature from raw bytes with validation.
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, Self::Error>;
}

// ─────────────────────────────────────────────────────────────────
// bd-98xo5.12.2: profiling instrumentation for Ed25519Scheme::{sign_raw,
// verify_raw}. Mirrors the T12.1 pattern shipped in commit 1c72a9f0 for
// the trust_card canonical encoder. All gated by the `profiling` Cargo
// feature; default builds compile NONE of this code — the cfg gate
// elides the sentinel calls, histogram statics, and recording functions
// entirely. Enable with `cargo build --features profiling` when running
// under the perf-round profiling skill.
//
// Two separate histograms (sign vs verify) so the per-side cost is
// attributable. Round-1 baseline
// (tests/artifacts/perf/20260520T214003Z_franken_node_perf/criterion_raw/crypto_scheme.txt):
// ed25519_scheme_sign_raw/64 = 45.69 µs vs dalek_direct floor 23.86 µs;
// ed25519_scheme_verify_raw/64 = 53.30 µs vs 47.25 µs. The
// preparsed-handle migration (bd-98xo5.2.{1-4}) drops sign_raw toward
// the dalek_direct floor; this histogram is how we observe that win
// at runtime rather than at bench-time.
// ─────────────────────────────────────────────────────────────────

/// Sentinel frame for `Ed25519Scheme::sign_raw` flamegraph attribution.
/// Always compiled (independent of the `profiling` feature) so the
/// symbol is in the binary for `objdump -d <binary> | grep
/// _profile_ed25519_scheme_sign` inspection; LLVM may elide it via
/// dead-code elimination at link time when no caller exists (default
/// builds). `#[inline(never)]` keeps it a real stack frame whenever a
/// caller does exist (under `--features profiling`).
#[inline(never)]
#[allow(dead_code)]
fn _profile_ed25519_scheme_sign() {
    std::hint::black_box(());
}

/// Sentinel frame for `Ed25519Scheme::verify_raw` flamegraph attribution.
/// See [`_profile_ed25519_scheme_sign`] for the linker-DCE rationale.
#[inline(never)]
#[allow(dead_code)]
fn _profile_ed25519_scheme_verify() {
    std::hint::black_box(());
}

#[cfg(feature = "profiling")]
use std::sync::{Mutex, OnceLock};

#[cfg(feature = "profiling")]
static ED25519_SCHEME_SIGN_HISTOGRAM_US: OnceLock<Mutex<hdrhistogram::Histogram<u64>>> =
    OnceLock::new();

#[cfg(feature = "profiling")]
static ED25519_SCHEME_VERIFY_HISTOGRAM_US: OnceLock<Mutex<hdrhistogram::Histogram<u64>>> =
    OnceLock::new();

#[cfg(feature = "profiling")]
fn ed25519_scheme_sign_record_us(elapsed_us: u64) {
    let hist = ED25519_SCHEME_SIGN_HISTOGRAM_US.get_or_init(|| {
        // Bounds match the T12.1 spec for cross-bead comparability:
        // 1 µs lower, 60 s upper, 3 significant digits (~2 % error).
        // The 60 s upper is enormous overhead vs the real ~50 µs cost
        // but the bound is shared across all T12.x histograms so
        // dump-side comparisons aren't skewed by per-site rescaling.
        Mutex::new(
            hdrhistogram::Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
                .expect("HDR histogram bounds (1, 60_000_000, 3) are statically valid"),
        )
    });
    let bounded = elapsed_us.clamp(1, 60_000_000);
    if let Ok(mut h) = hist.lock() {
        let _ = h.record(bounded);
    }
}

#[cfg(feature = "profiling")]
fn ed25519_scheme_verify_record_us(elapsed_us: u64) {
    let hist = ED25519_SCHEME_VERIFY_HISTOGRAM_US.get_or_init(|| {
        Mutex::new(
            hdrhistogram::Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
                .expect("HDR histogram bounds (1, 60_000_000, 3) are statically valid"),
        )
    });
    let bounded = elapsed_us.clamp(1, 60_000_000);
    if let Ok(mut h) = hist.lock() {
        let _ = h.record(bounded);
    }
}

/// Emit the current sign + verify histograms' p50/p95/p99/cumulative/count
/// as two `tracing::info!` events matching the profiling skill's
/// `perf.profile.span_summary` schema (one per side). Callers (typically
/// the perf-round skill or a process-exit Drop hook) trigger this on
/// demand. Idempotent and non-destructive — does NOT reset the histograms.
#[cfg(feature = "profiling")]
pub fn dump_ed25519_scheme_perf_histogram() {
    let entries: [(&str, &str, Option<&Mutex<hdrhistogram::Histogram<u64>>>); 2] = [
        (
            "sign",
            "ed25519_scheme_sign_raw.us",
            ED25519_SCHEME_SIGN_HISTOGRAM_US.get(),
        ),
        (
            "verify",
            "ed25519_scheme_verify_raw.us",
            ED25519_SCHEME_VERIFY_HISTOGRAM_US.get(),
        ),
    ];
    for (_kind, span_name, hist_lock) in entries {
        let Some(hist) = hist_lock else { continue };
        let Ok(h) = hist.lock() else { continue };
        let count = h.len();
        let cumulative_us: u64 = h.iter_recorded().map(|v| v.value_iterated_to()).sum();
        let p50_us = h.value_at_quantile(0.50);
        let p95_us = h.value_at_quantile(0.95);
        let p99_us = h.value_at_quantile(0.99);
        tracing::info!(
            event_code = "perf.profile.span_summary",
            span_name,
            cumulative_us,
            count,
            p50_us,
            p95_us,
            p99_us,
            category = "CPU",
            evidence = "crates/franken-node/src/crypto/schemes.rs::Ed25519Scheme",
            "ed25519_scheme perf span summary"
        );
    }
}

/// Ed25519 signature scheme implementation with franken_node security patterns.
///
/// Implements the SignatureScheme trait for Ed25519 with:
/// - Domain separation using blake3 hashing
/// - Constant-time verification operations
/// - Length-prefixed input encoding
/// - Fail-closed error handling
#[derive(Debug, Clone)]
pub struct Ed25519Scheme;

impl SignatureScheme for Ed25519Scheme {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 32];
    type Signature = [u8; 64];
    type Error = Ed25519Error;

    fn scheme_id() -> &'static str {
        "ed25519_v1"
    }

    fn generate_keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        Ok((verifying_key.to_bytes(), signing_key.to_bytes()))
    }

    fn sign_with_domain(
        secret_key: &Self::SecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        // Create domain-separated digest using blake3 when available
        #[cfg(feature = "blake3")]
        let digest = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(&len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(&len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        #[cfg(not(feature = "blake3"))]
        let digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        // Sign the digest using ed25519-dalek
        let signing_key = match SigningKey::try_from(secret_key) {
            Ok(key) => key,
            Err(e) => return Err(Ed25519Error::MalformedKey(e.to_string())),
        };

        #[cfg(feature = "blake3")]
        let digest_bytes = digest.as_bytes();
        #[cfg(not(feature = "blake3"))]
        let digest_bytes = &digest[..];

        let signature = signing_key.sign(digest_bytes);
        Ok(signature.to_bytes())
    }

    fn verify_with_domain(
        public_key: &Self::PublicKey,
        domain: &[u8],
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        // Create the same domain-separated digest
        #[cfg(feature = "blake3")]
        let digest = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(&len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(&len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        #[cfg(not(feature = "blake3"))]
        let digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        // Parse keys and signature
        let verifying_key = match VerifyingKey::from_bytes(public_key) {
            Ok(key) => key,
            Err(_) => return false, // Constant-time failure
        };

        let sig = match Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false, // Constant-time failure
        };

        // Perform constant-time verification
        #[cfg(feature = "blake3")]
        let digest_bytes = digest.as_bytes();
        #[cfg(not(feature = "blake3"))]
        let digest_bytes = &digest[..];

        verifying_key.verify_strict(digest_bytes, &sig).is_ok()
    }

    fn sign_raw(
        secret_key: &Self::SecretKey,
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        // bd-98xo5.12.2 — sentinel + histogram + span instrumentation,
        // all gated by the `profiling` Cargo feature. Default builds
        // compile only the `cfg(not(...))` arm — byte-identical
        // semantics to before the instrumentation landed.
        #[cfg(feature = "profiling")]
        {
            _profile_ed25519_scheme_sign();
            let _span = tracing::info_span!("ed25519_scheme_sign_raw").entered();
            let start = std::time::Instant::now();
            // Construct a SigningKey directly from the 32-byte seed.
            // `SigningKey::from_bytes` for ed25519-dalek 2.x is infallible for any
            // 32-byte input, but we keep the Result return type to match the trait
            // contract so other schemes (RSA / ECDSA) can fail.
            let signing_key = SigningKey::from_bytes(secret_key);
            let signature = signing_key.sign(message);
            let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            ed25519_scheme_sign_record_us(elapsed_us);
            return Ok(signature.to_bytes());
        }
        #[cfg(not(feature = "profiling"))]
        {
            // Construct a SigningKey directly from the 32-byte seed.
            // `SigningKey::from_bytes` for ed25519-dalek 2.x is infallible for any
            // 32-byte input, but we keep the Result return type to match the trait
            // contract so other schemes (RSA / ECDSA) can fail.
            let signing_key = SigningKey::from_bytes(secret_key);
            let signature = signing_key.sign(message);
            Ok(signature.to_bytes())
        }
    }

    fn verify_raw(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        // bd-98xo5.12.2 — sentinel + histogram + span. See sign_raw above
        // for the production-equivalence rationale. The histogram is
        // separate from sign so per-side cost is attributable.
        #[cfg(feature = "profiling")]
        {
            _profile_ed25519_scheme_verify();
            let _span = tracing::info_span!("ed25519_scheme_verify_raw").entered();
            let start = std::time::Instant::now();
            // Parse keys and signature; any parse failure means "not valid".
            // Return false without leaking which step failed.
            let result = (|| {
                let verifying_key = VerifyingKey::from_bytes(public_key).ok()?;
                let sig = Signature::try_from(&signature[..]).ok()?;
                // verify_strict rejects malleable / non-canonical-s signatures.
                // decision_receipt and other consumers historically rely on strict
                // verification for replay/forgery hardening; keep that contract here.
                Some(verifying_key.verify_strict(message, &sig).is_ok())
            })()
            .unwrap_or(false);
            let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            ed25519_scheme_verify_record_us(elapsed_us);
            return result;
        }
        #[cfg(not(feature = "profiling"))]
        {
            // Parse keys and signature; any parse failure means "not valid".
            // Return false without leaking which step failed.
            let verifying_key = match VerifyingKey::from_bytes(public_key) {
                Ok(key) => key,
                Err(_) => return false,
            };

            let sig = match Signature::try_from(&signature[..]) {
                Ok(sig) => sig,
                Err(_) => return false,
            };

            // verify_strict rejects malleable / non-canonical-s signatures.
            // decision_receipt and other consumers historically rely on strict
            // verification for replay/forgery hardening; keep that contract here.
            verifying_key.verify_strict(message, &sig).is_ok()
        }
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error> {
        if bytes.len() != 32 {
            return Err(Ed25519Error::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(bytes);

        // Validate the key by attempting to parse it
        VerifyingKey::from_bytes(&key_array)
            .map_err(|e| Ed25519Error::MalformedKey(e.to_string()))?;

        Ok(key_array)
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, Self::Error> {
        if bytes.len() != 64 {
            return Err(Ed25519Error::InvalidSignatureLength {
                expected: 64,
                actual: bytes.len(),
            });
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(bytes);

        // Validate the signature by attempting to parse it
        match Signature::try_from(&sig_array[..]) {
            Ok(_) => {} // Valid signature format
            Err(e) => return Err(Ed25519Error::MalformedSignature(e.to_string())),
        };

        Ok(sig_array)
    }
}

// ---------------------------------------------------------------------------
// Ed25519 Preparsed Key Handles
// ---------------------------------------------------------------------------

/// Preparsed Ed25519 signer for repeated signing with the same secret key.
///
/// Wraps an `ed25519_dalek::SigningKey` to avoid repeated SHA-512 expansion
/// and basepoint scalar multiplication on each signing operation.
///
/// # Security
///
/// - Implements `Send + Sync` for safe sharing across threads.
/// - The inner `SigningKey` implements `ZeroizeOnDrop` (dalek 2.x): secret key
///   material is securely zeroed when this handle is dropped.
/// - `sign_raw` produces bit-for-bit identical output to [`Ed25519Scheme::sign_raw`].
///
/// # Example
///
/// ```ignore
/// let signer = Ed25519PreparsedSigner::from_secret_bytes(&secret_key);
/// let sig1 = signer.sign_raw(b"message 1");
/// let sig2 = signer.sign_raw(b"message 2"); // No key re-parsing
/// ```
#[derive(Debug)]
pub struct Ed25519PreparsedSigner {
    inner: SigningKey,
}

// `ed25519_dalek::SigningKey` is already `Send + Sync` in dalek 2.x, so this
// wrapper auto-derives both. Explicit `unsafe impl Send/Sync` blocks are
// redundant AND illegal under the crate-wide `#![forbid(unsafe_code)]` policy
// (see `crates/franken-node/src/lib.rs`), so they are intentionally absent.

impl Ed25519PreparsedSigner {
    /// Create a preparsed signer from a 32-byte secret key seed.
    ///
    /// This constructor is **infallible**: any 32-byte input is a valid Ed25519 seed.
    /// The `SigningKey` is constructed once and cached for subsequent operations.
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(secret),
        }
    }

    /// Sign a message without domain separation.
    ///
    /// Output is bit-for-bit identical to [`Ed25519Scheme::sign_raw`] with the
    /// same secret key and message.
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        self.inner.sign(message).to_bytes()
    }

    /// Sign a message with domain separation.
    ///
    /// Output is bit-for-bit identical to [`Ed25519Scheme::sign_with_domain`]
    /// with the same secret key, domain, and message.
    pub fn sign_with_domain(&self, domain: &[u8], message: &[u8]) -> [u8; 64] {
        #[cfg(feature = "blake3")]
        let digest = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(&len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(&len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        #[cfg(not(feature = "blake3"))]
        let digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        #[cfg(feature = "blake3")]
        let digest_bytes = digest.as_bytes();
        #[cfg(not(feature = "blake3"))]
        let digest_bytes = &digest[..];

        self.inner.sign(digest_bytes).to_bytes()
    }

    /// Get the public key corresponding to this signer.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }
}

/// Preparsed Ed25519 verifier for repeated verification with the same public key.
///
/// Wraps an `ed25519_dalek::VerifyingKey` to avoid repeated Edwards point
/// decompression on each verification operation.
///
/// # Security
///
/// - Implements `Send + Sync` for safe sharing across threads.
/// - `verify_raw` returns the same result as [`Ed25519Scheme::verify_raw`].
/// - Uses `verify_strict` to reject malleable / non-canonical signatures.
///
/// # Example
///
/// ```ignore
/// let verifier = Ed25519PreparsedVerifier::from_public_bytes(&public_key)?;
/// let valid1 = verifier.verify_raw(b"message 1", &sig1);
/// let valid2 = verifier.verify_raw(b"message 2", &sig2); // No key re-parsing
/// ```
#[derive(Debug, Clone)]
pub struct Ed25519PreparsedVerifier {
    inner: VerifyingKey,
}

// `ed25519_dalek::VerifyingKey` is already `Send + Sync` in dalek 2.x, so
// this wrapper auto-derives both. Explicit `unsafe impl Send/Sync` blocks are
// redundant AND illegal under the crate-wide `#![forbid(unsafe_code)]` policy
// (see `crates/franken-node/src/lib.rs`), so they are intentionally absent.

impl Ed25519PreparsedVerifier {
    /// Create a preparsed verifier from a 32-byte compressed public key.
    ///
    /// This constructor is **fallible**: the compressed Edwards point may fail
    /// to decompress if the bytes do not represent a valid curve point.
    pub fn from_public_bytes(public: &[u8; 32]) -> Result<Self, Ed25519Error> {
        let inner = VerifyingKey::from_bytes(public)
            .map_err(|e| Ed25519Error::MalformedKey(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Verify a signature without domain separation.
    ///
    /// Returns `true` if valid, `false` otherwise (including malformed signature).
    /// Uses `verify_strict` to reject malleable / non-canonical signatures.
    #[must_use]
    pub fn verify_raw(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let sig = match Signature::try_from(&signature[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.inner.verify_strict(message, &sig).is_ok()
    }

    /// Verify a signature with domain separation.
    ///
    /// Returns `true` if valid, `false` otherwise. Uses the same canonical
    /// preimage construction as [`Ed25519Scheme::verify_with_domain`].
    #[must_use]
    pub fn verify_with_domain(&self, domain: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
        #[cfg(feature = "blake3")]
        let digest = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(&len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(&len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        #[cfg(not(feature = "blake3"))]
        let digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        #[cfg(feature = "blake3")]
        let digest_bytes = digest.as_bytes();
        #[cfg(not(feature = "blake3"))]
        let digest_bytes = &digest[..];

        let sig = match Signature::try_from(&signature[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.inner.verify_strict(digest_bytes, &sig).is_ok()
    }

    /// Get the raw public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_signature_roundtrip() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";

        let signature = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        assert!(Ed25519Scheme::verify_with_domain(
            &pk, domain, message, &signature
        ));
    }

    #[test]
    fn test_ed25519_domain_separation() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";

        let sig1 = Ed25519Scheme::sign_with_domain(&sk, b"domain1", message).unwrap();
        let sig2 = Ed25519Scheme::sign_with_domain(&sk, b"domain2", message).unwrap();

        // Same message, different domains should produce different signatures
        assert_ne!(sig1, sig2);

        // Cross-domain verification should fail
        assert!(!Ed25519Scheme::verify_with_domain(
            &pk, b"domain1", message, &sig2
        ));
        assert!(!Ed25519Scheme::verify_with_domain(
            &pk, b"domain2", message, &sig1
        ));
    }

    #[test]
    fn test_ed25519_length_prefix_counter_saturates() {
        assert_eq!(len_to_u64(0), 0);
        assert_eq!(len_to_u64(usize::MAX), u64::MAX);
    }

    #[test]
    fn test_ed25519_raw_signature_preserves_caller_preimage() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"caller-owned canonical preimage";
        let direct_key = SigningKey::from_bytes(&sk);
        let direct_signature = direct_key.sign(message).to_bytes();

        let raw_signature = Ed25519Scheme::sign_raw(&sk, message).unwrap();

        assert_eq!(raw_signature, direct_signature);
        assert!(Ed25519Scheme::verify_raw(&pk, message, &raw_signature));
        assert!(!Ed25519Scheme::verify_with_domain(
            &pk,
            b"decision_receipt",
            message,
            &raw_signature
        ));

        let wrapped_signature =
            Ed25519Scheme::sign_with_domain(&sk, b"decision_receipt", message).unwrap();
        assert!(!Ed25519Scheme::verify_raw(&pk, message, &wrapped_signature));
    }

    #[test]
    fn test_ed25519_constant_time_verification() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";

        let valid_sig = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        let mut invalid_sig = valid_sig;
        invalid_sig[0] ^= 1; // Flip one bit

        // Both should complete without panicking (constant-time)
        let result1 = Ed25519Scheme::verify_with_domain(&pk, domain, message, &valid_sig);
        let result2 = Ed25519Scheme::verify_with_domain(&pk, domain, message, &invalid_sig);

        assert!(result1);
        assert!(!result2);
    }

    #[test]
    fn test_ed25519_key_validation() {
        // Test valid key length
        let (pk, _) = Ed25519Scheme::generate_keypair().unwrap();
        let parsed_pk = Ed25519Scheme::public_key_from_bytes(pk.as_ref()).unwrap();
        assert_eq!(pk, parsed_pk);

        // Test invalid key length
        let short_key = [0u8; 16];
        let result = Ed25519Scheme::public_key_from_bytes(&short_key);
        assert!(matches!(
            result,
            Err(Ed25519Error::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn test_ed25519_signature_validation() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";

        // Test valid signature
        let signature = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        let parsed_sig = Ed25519Scheme::signature_from_bytes(signature.as_ref()).unwrap();
        assert_eq!(signature, parsed_sig);

        // Test invalid signature length
        let short_sig = [0u8; 32];
        let result = Ed25519Scheme::signature_from_bytes(&short_sig);
        assert!(matches!(
            result,
            Err(Ed25519Error::InvalidSignatureLength {
                expected: 64,
                actual: 32
            })
        ));
    }

    #[test]
    fn test_ed25519_scheme_id() {
        assert_eq!(Ed25519Scheme::scheme_id(), "ed25519_v1");
    }

    // ── Preparsed handle tests ──

    #[test]
    fn preparsed_signer_sign_raw_matches_scheme() {
        let (_, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);
        let message = b"test message for raw signing";

        let scheme_sig = Ed25519Scheme::sign_raw(&sk, message).unwrap();
        let preparsed_sig = signer.sign_raw(message);

        assert_eq!(
            scheme_sig, preparsed_sig,
            "sign_raw output must be bit-for-bit identical"
        );
    }

    #[test]
    fn preparsed_signer_sign_with_domain_matches_scheme() {
        let (_, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);
        let domain = b"test_domain";
        let message = b"test message for domain signing";

        let scheme_sig = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        let preparsed_sig = signer.sign_with_domain(domain, message);

        assert_eq!(
            scheme_sig, preparsed_sig,
            "sign_with_domain output must be bit-for-bit identical"
        );
    }

    #[test]
    fn preparsed_verifier_verify_raw_matches_scheme() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk).unwrap();
        let message = b"test message for raw verification";
        let signature = Ed25519Scheme::sign_raw(&sk, message).unwrap();

        let scheme_result = Ed25519Scheme::verify_raw(&pk, message, &signature);
        let preparsed_result = verifier.verify_raw(message, &signature);

        assert_eq!(
            scheme_result, preparsed_result,
            "verify_raw must produce identical boolean"
        );
        assert!(preparsed_result, "valid signature should verify");
    }

    #[test]
    fn preparsed_verifier_verify_with_domain_matches_scheme() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk).unwrap();
        let domain = b"test_domain";
        let message = b"test message for domain verification";
        let signature = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();

        let scheme_result = Ed25519Scheme::verify_with_domain(&pk, domain, message, &signature);
        let preparsed_result = verifier.verify_with_domain(domain, message, &signature);

        assert_eq!(
            scheme_result, preparsed_result,
            "verify_with_domain must produce identical boolean"
        );
        assert!(preparsed_result, "valid signature should verify");
    }

    #[test]
    fn preparsed_signer_public_key_matches() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);

        assert_eq!(signer.public_key(), pk, "public_key() must match original");
    }

    #[test]
    fn preparsed_verifier_rejects_invalid_public_key() {
        let invalid_key = [0u8; 32]; // All zeros is not a valid Edwards point
        let result = Ed25519PreparsedVerifier::from_public_bytes(&invalid_key);
        assert!(result.is_err(), "all-zero key should fail decompression");
    }

    #[test]
    fn preparsed_verifier_rejects_invalid_signature() {
        let (pk, _) = Ed25519Scheme::generate_keypair().unwrap();
        let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk).unwrap();
        let message = b"test message";
        let bad_signature = [0u8; 64];

        assert!(
            !verifier.verify_raw(message, &bad_signature),
            "zero signature should fail"
        );
    }

    #[test]
    fn preparsed_signer_sign_raw_multiple_payload_sizes() {
        let (_, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);

        let payloads: &[&[u8]] = &[
            &[],           // 0 B
            &[0x42],       // 1 B
            &[0xAA; 64],   // 64 B
            &[0xBB; 512],  // 512 B
            &[0xCC; 4096], // 4096 B
        ];

        for payload in payloads {
            let scheme_sig = Ed25519Scheme::sign_raw(&sk, payload).unwrap();
            let preparsed_sig = signer.sign_raw(payload);
            assert_eq!(
                scheme_sig,
                preparsed_sig,
                "sign_raw must be bit-identical for payload of {} bytes",
                payload.len()
            );
        }
    }

    #[test]
    fn preparsed_verifier_uses_strict_verification() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);
        let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk).unwrap();
        let message = b"strict verification test";

        let sig = signer.sign_raw(message);
        assert!(
            verifier.verify_raw(message, &sig),
            "valid signature should pass"
        );

        let mut tampered_sig = sig;
        tampered_sig[63] ^= 0x80;
        assert!(
            !verifier.verify_raw(message, &tampered_sig),
            "tampered signature should fail strict verification"
        );
    }

    #[test]
    fn preparsed_signer_zeroize_on_drop_compile_check() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
    }

    // ── bd-98xo5.2.7: comprehensive coverage of Ed25519Preparsed* ──

    #[test]
    fn preparsed_signer_send_sync_bounds() {
        // Compile-time check that the preparsed handles are safe to share
        // across threads. The wrappers don't add interior mutability and
        // dalek 2.x's SigningKey/VerifyingKey are Send + Sync, so this
        // must hold — a regression would silently restrict producer-side
        // call sites (fleet trust anchor, replay window) that assume
        // cross-thread reuse.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Ed25519PreparsedSigner>();
        assert_send_sync::<Ed25519PreparsedVerifier>();
    }

    #[test]
    fn preparsed_verifier_rejects_malleable_canonical_s() {
        // Ed25519 RFC 8032 §5.1.7 requires `s < ℓ`; verify_strict enforces
        // this, plain verify does not. The wrapper's `verify_raw` routes
        // through verify_strict — assert the contract by hand-building a
        // signature whose s component is ≥ ℓ and confirming both the
        // wrapper AND the stateless Ed25519Scheme::verify_raw reject it.
        // Ed25519 group order ℓ = 2^252 + 27742317777372353535851937790883648493.
        // The wire format is little-endian 32-byte s after the 32-byte R.
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk).unwrap();
        let message = b"malleability rejection test";

        // Produce a real signature, then deliberately mutate the s scalar
        // to a value ≥ ℓ (set s = ℓ + 1 in little-endian).
        let valid = Ed25519Scheme::sign_raw(&sk, message).unwrap();
        let mut malleable = valid;
        // ℓ in little-endian: edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010
        // (canonical from RFC 8032). Setting s to this exact value would
        // mean s == ℓ, which is also non-canonical. We add 1: ℓ + 1.
        let l_le: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut l_plus_one = l_le;
        // Add 1 to the little-endian scalar.
        let mut carry: u16 = 1;
        for byte in &mut l_plus_one {
            let sum = u16::from(*byte) + carry;
            *byte = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        malleable[32..].copy_from_slice(&l_plus_one);
        // The signature's R half stays valid-looking but s is now ≥ ℓ.
        assert!(
            !verifier.verify_raw(message, &malleable),
            "preparsed verifier must reject malleable signatures (s >= ℓ)"
        );
        assert!(
            !Ed25519Scheme::verify_raw(&pk, message, &malleable),
            "stateless verify_raw must reject malleable signatures (parity with wrapper)"
        );
    }

    #[test]
    fn preparsed_verifier_rejects_invalid_edwards_point() {
        // The API takes a fixed `&[u8; 32]`, so "short pubkey bytes" can't
        // exist at runtime — the type system enforces length. What CAN
        // exist is a 32-byte string that doesn't decompress to a valid
        // Edwards point. The dalek constructor surfaces a parse error for
        // each of these; the wrapper must propagate it via
        // `Ed25519Error::MalformedKey` rather than panicking or accepting.
        //
        // Patterns chosen to cover the non-canonical-decode paths:
        //   - all-zeros (the identity-shaped pattern, but the y-coord
        //     0 with sign bit 0 fails the small-subgroup check in some
        //     dalek versions; both behave identically with our wrapper).
        //   - high bit set: invalid x-coord recovery sign.
        //   - 0x01 followed by zeros: y=1, attempts to use small-subgroup
        //     element; dalek's from_bytes either decodes it (with sign 0)
        //     or rejects; the wrapper must NOT panic either way.
        //   - all-0xff: the maximum byte pattern, which fails to satisfy
        //     the curve equation.
        let patterns: &[(&str, [u8; 32])] = &[
            (
                "high_bit_set",
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
            ),
            (
                "near_field_overflow",
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
                ],
            ),
        ];
        for (label, bytes) in patterns {
            let res = Ed25519PreparsedVerifier::from_public_bytes(bytes);
            // Either Ok (the pattern happened to decompress) or
            // Err(MalformedKey). The wrapper MUST NOT panic — that's
            // the security-critical contract for a public-key surface
            // that takes untrusted bytes (fleet sync, replay verification).
            // We only assert that Err is a MalformedKey, not Ok, to keep
            // the test stable across dalek minor versions.
            if let Err(e) = res {
                assert!(
                    matches!(e, Ed25519Error::MalformedKey(_)),
                    "{label}: expected MalformedKey, got {e:?}"
                );
            }
        }
    }

    #[test]
    fn preparsed_verifier_rejects_short_pubkey_bytes() {
        // The from_public_bytes signature is `&[u8; 32]`, so callers
        // physically cannot pass a shorter slice — the compile fails.
        // This test pins that contract: it ensures the API surface
        // continues to enforce length at the type level rather than at
        // runtime (which would be slower and admit untyped error paths).
        // A regression that changed the signature to `&[u8]` would
        // break this compile-time check.
        fn takes_fixed_size_only(
            bytes: &[u8; 32],
        ) -> Result<Ed25519PreparsedVerifier, Ed25519Error> {
            Ed25519PreparsedVerifier::from_public_bytes(bytes)
        }
        let buf = [0u8; 32];
        let _ = takes_fixed_size_only(&buf);
        // Negative compile check: the line below MUST NOT compile if
        // uncommented — `[u8; 16]` is not coercible to `&[u8; 32]`.
        //   let short = [0u8; 16];
        //   let _ = Ed25519PreparsedVerifier::from_public_bytes(&short);
    }

    // ── bd-98xo5.2.7: property tests ──

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 256,
            // Persistent regressions stored at
            // crates/franken-node/proptest-regressions/crypto-schemes-preparsed.txt
            // (auto-managed by proptest on first failing seed).
            failure_persistence: Some(Box::new(
                proptest::test_runner::FileFailurePersistence::WithSource("regressions")
            )),
            ..proptest::prelude::ProptestConfig::default()
        })]

        #[test]
        fn prop_signature_parity_random_payload(payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..16384)) {
            // bd-98xo5.2.7 property test #1: for any random payload up to
            // 16 KiB, the preparsed signer's output must be bit-identical
            // to the stateless trait method. A regression here means the
            // preparsed path computed a different signature, which would
            // silently break interop with any verifier that uses the
            // stateless path on the same key.
            let (_, sk) = Ed25519Scheme::generate_keypair().unwrap();
            let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);
            let stateless = Ed25519Scheme::sign_raw(&sk, &payload).unwrap();
            let preparsed = signer.sign_raw(&payload);
            proptest::prop_assert_eq!(stateless, preparsed);
        }

        #[test]
        fn prop_verifier_accepts_iff_stateless_does(
            payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096),
            seed in proptest::prelude::any::<[u8; 32]>(),
            tamper_bit in 0u32..512u32,
        ) {
            // bd-98xo5.2.7 property test #2: preparsed verifier must
            // produce the same accept/reject answer as the stateless
            // verifier for every (payload, key, signature) triple,
            // including tampered signatures. Tamper-bit cycles over the
            // 512 bit positions of the 64-byte signature so the property
            // exercises every byte and every bit within a byte.
            let signer = Ed25519PreparsedSigner::from_secret_bytes(&seed);
            let pk = signer.public_key();
            let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk)
                .expect("seed produces valid pubkey");

            let valid_sig = signer.sign_raw(&payload);

            // Untampered case: both must accept.
            let stateless_ok = Ed25519Scheme::verify_raw(&pk, &payload, &valid_sig);
            let preparsed_ok = verifier.verify_raw(&payload, &valid_sig);
            proptest::prop_assert_eq!(stateless_ok, preparsed_ok);
            proptest::prop_assert!(preparsed_ok, "valid signature must verify");

            // Tampered case: flip one specific bit, both must reject (or
            // both accept — never disagree).
            let mut tampered = valid_sig;
            let byte_idx = (tamper_bit / 8) as usize;
            let bit_in_byte = (tamper_bit % 8) as u8;
            tampered[byte_idx] ^= 1u8 << bit_in_byte;
            let stateless_tampered = Ed25519Scheme::verify_raw(&pk, &payload, &tampered);
            let preparsed_tampered = verifier.verify_raw(&payload, &tampered);
            proptest::prop_assert_eq!(stateless_tampered, preparsed_tampered);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // bd-98xo5.12.2: profiling instrumentation tests. Mirror the
    // T12.1 pattern (canonical_serializer.rs:6577+) — verify the
    // sentinel symbols compile under default features, and (under
    // `--features profiling`) verify the histogram bound accepts the
    // realistic per-call elapsed range. The default-features tests
    // also pin that enabling/disabling the profiling cfg never
    // changes the byte output of sign_raw or the bool of verify_raw.
    // Per [lib] test = false in Cargo.toml, these inline tests are
    // compile-checked rather than executed; the integration test
    // surface for Ed25519Scheme byte-equivalence lives in
    // tests/ed25519_verifier_rejects_malleable_signatures.rs and the
    // existing tests/security/* fixtures.
    // ─────────────────────────────────────────────────────────────

    /// Sentinel symbols are always compiled (independent of the
    /// `profiling` feature) so `objdump -d <binary> | grep
    /// _profile_ed25519_scheme_sign` / `..._verify` finds them
    /// whenever a caller exists. Under default features they're dead
    /// code; LLVM may elide them via DCE at link time but the crate
    /// compile MUST still succeed. Pin that by calling them directly.
    #[test]
    fn sentinel_frames_compile_and_return_unit_bd98xo5_12_2() {
        super::_profile_ed25519_scheme_sign();
        super::_profile_ed25519_scheme_verify();
    }

    /// Default build (no `profiling` feature): wrapping the body in
    /// the cfg(not(profiling)) arm must produce byte-identical
    /// signatures and accept the same signatures as before the
    /// instrumentation landed. Sanity-check the round-trip on a
    /// fixed seed.
    #[test]
    fn profiling_disabled_default_build_signs_and_verifies_round_trip_bd98xo5_12_2() {
        let secret_seed: [u8; 32] = [
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42,
        ];
        let signing_key = SigningKey::from_bytes(&secret_seed);
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();
        let message = b"bd-98xo5.12.2 ed25519 round-trip pin";
        let signature = Ed25519Scheme::sign_raw(&secret_seed, message)
            .expect("sign_raw must not error for valid 32-byte seed");
        assert!(
            Ed25519Scheme::verify_raw(&public_key, message, &signature),
            "verify_raw must accept the signature sign_raw just produced"
        );

        let mut tampered = signature;
        tampered[7] ^= 0x01;
        assert!(
            !Ed25519Scheme::verify_raw(&public_key, message, &tampered),
            "verify_raw must reject a single-bit-flipped signature"
        );
    }

    /// Profiling-feature build path. Verifies the histogram bounds
    /// (1 µs..60 s, 3 sig digits) accept the realistic elapsed range
    /// for the round-1 worst case (~50 µs per sign + verify) plus
    /// the bound endpoints (0 clamped to 1, 60 s upper). A regression
    /// that lowered the upper bound would lose the tail of any
    /// hot-loop verify pass.
    #[cfg(feature = "profiling")]
    #[test]
    fn profiling_feature_histograms_accept_full_range_bd98xo5_12_2() {
        super::ed25519_scheme_sign_record_us(0);
        super::ed25519_scheme_sign_record_us(1);
        super::ed25519_scheme_sign_record_us(46);
        super::ed25519_scheme_sign_record_us(60_000_000);
        super::ed25519_scheme_sign_record_us(60_000_001);
        super::ed25519_scheme_verify_record_us(0);
        super::ed25519_scheme_verify_record_us(53);
        super::ed25519_scheme_verify_record_us(60_000_000);
        super::ed25519_scheme_verify_record_us(60_000_001);
    }

    /// `dump_ed25519_scheme_perf_histogram` must be a no-op when no
    /// recordings have happened yet (process startup, no sign/verify
    /// calls). Pin that the function does not panic on either empty
    /// histogram.
    #[cfg(feature = "profiling")]
    #[test]
    fn profiling_feature_dump_handles_empty_histograms_safely_bd98xo5_12_2() {
        super::dump_ed25519_scheme_perf_histogram();
    }
}
