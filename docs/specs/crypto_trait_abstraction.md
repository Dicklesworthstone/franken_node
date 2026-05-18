# Crypto Trait Abstraction Design

**Status**: Design Phase (bd-18dd1)  
**Author**: CrimsonCrane  
**Date**: 2026-04-27

## Overview

This document defines concrete trait abstractions to unify cryptographic operations across the franken_node codebase. The design addresses inconsistencies in signature verification, key material handling, and crypto scheme selection across multiple modules.

## Motivation

Current cryptographic operations are scattered across:
- `ed25519_verify` module - direct Ed25519 operations
- `decision_receipt` module - receipt signature validation
- `remote_cap` module - capability signature verification  
- `replay_bundle` module - bundle integrity checks

Each module implements crypto operations independently, leading to:
- Code duplication
- Inconsistent error handling
- Security pattern violations
- Testing complexity

## Design

### Core Traits

#### SignatureScheme Trait

```rust
/// Unified signature scheme abstraction
pub trait SignatureScheme: Send + Sync + 'static {
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    type SecretKey: AsRef<[u8]> + Clone + Send + Sync;
    type Signature: AsRef<[u8]> + Clone + Send + Sync;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Scheme identifier for domain separation
    fn scheme_id() -> &'static str;
    
    /// Generate a new keypair
    fn generate_keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    
    /// Sign a message with domain separation
    fn sign_with_domain(
        secret_key: &Self::SecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error>;
    
    /// Verify a signature with domain separation and constant-time comparison
    fn verify_with_domain(
        public_key: &Self::PublicKey,
        domain: &[u8], 
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool; // Note: returns bool for constant-time usage
    
    /// Parse public key from bytes
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error>;
    
    /// Parse signature from bytes
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, Self::Error>;
}
```

#### CryptoSigner Trait

```rust
/// High-level signing operations with built-in security patterns
pub trait CryptoSigner {
    type Scheme: SignatureScheme;
    type SigningKey;
    
    /// Sign with automatic domain separation
    fn sign_message(
        &self,
        key: &Self::SigningKey,
        context: &str,
        message: &[u8],
    ) -> Result<<Self::Scheme as SignatureScheme>::Signature, <Self::Scheme as SignatureScheme>::Error>;
    
    /// Sign structured data with type-safe domain separation
    fn sign_structured<T: Serialize>(
        &self,
        key: &Self::SigningKey,
        context: &str,
        data: &T,
    ) -> Result<<Self::Scheme as SignatureScheme>::Signature, <Self::Scheme as SignatureScheme>::Error>;
}
```

#### KeyMaterial Trait

```rust
/// Key material management with security guarantees
pub trait KeyMaterial: Send + Sync {
    type PublicKey: AsRef<[u8]> + Clone;
    type SecretKey;
    type Error: std::error::Error + Send + Sync + 'static;
    
    /// Load key material from secure storage
    fn load_from_secure_storage(
        key_id: &str,
    ) -> Result<Self, Self::Error>;
    
    /// Export public key for verification
    fn public_key(&self) -> &Self::PublicKey;
    
    /// Check if key material is valid/not expired
    fn is_valid(&self) -> bool;
    
    /// Get key fingerprint for logging/identification
    fn fingerprint(&self) -> String;
    
    /// Secure key rotation
    fn rotate(&mut self) -> Result<(), Self::Error>;
}
```

### Concrete Implementations

#### Ed25519Scheme

```rust
/// Ed25519 signature scheme implementation
pub struct Ed25519Scheme;

impl SignatureScheme for Ed25519Scheme {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 32]; 
    type Signature = [u8; 64];
    type Error = Ed25519Error;
    
    fn scheme_id() -> &'static str {
        "ed25519_v1"
    }
    
    fn sign_with_domain(
        secret_key: &Self::SecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ed25519_sign_v1:");
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        hasher.update(&(message.len() as u64).to_le_bytes());
        hasher.update(message);
        let digest = hasher.finalize();
        
        // Use ed25519_dalek for actual signing
        // ... implementation details
    }
    
    fn verify_with_domain(
        public_key: &Self::PublicKey,
        domain: &[u8],
        message: &[u8], 
        signature: &Self::Signature,
    ) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ed25519_verify_v1:");
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        hasher.update(&(message.len() as u64).to_le_bytes());
        hasher.update(message);
        let digest = hasher.finalize();
        
        // Use constant-time verification
        // Return bool (not Result) for constant-time usage
        match ed25519_dalek::verify_strict(public_key, digest.as_bytes(), signature) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
}
```

#### Ed25519Signer

```rust
/// Ed25519-specific signer with security patterns
pub struct Ed25519Signer {
    _phantom: PhantomData<Ed25519Scheme>,
}

impl CryptoSigner for Ed25519Signer {
    type Scheme = Ed25519Scheme;
    type SigningKey = [u8; 32];
    
    fn sign_message(
        &self,
        key: &Self::SigningKey,
        context: &str,
        message: &[u8],
    ) -> Result<[u8; 64], Ed25519Error> {
        let domain = format!("franken_node_{}:", context);
        Ed25519Scheme::sign_with_domain(key, domain.as_bytes(), message)
    }
    
    fn sign_structured<T: Serialize>(
        &self,
        key: &Self::SigningKey,
        context: &str,
        data: &T,
    ) -> Result<[u8; 64], Ed25519Error> {
        let serialized = serde_json::to_vec(data)
            .map_err(|e| Ed25519Error::SerializationFailed(e.to_string()))?;
        self.sign_message(key, context, &serialized)
    }
}
```

### Security Patterns Integration

All implementations enforce established franken_node security patterns:

1. **Domain Separation**: Every signature operation includes context-specific domain separators
2. **Constant-Time Operations**: All verification uses `ct_eq` patterns  
3. **Length Prefixing**: Variable-length inputs are length-prefixed to prevent collision
4. **Fail-Closed**: Invalid operations return secure defaults
5. **Saturating Arithmetic**: All counter operations use `saturating_add`

### Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum Ed25519Error {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    
    #[error("Signature verification failed")]
    VerificationFailed,
    
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
}
```

## Migration Strategy

### Phase 1: Core Trait Implementation — ✅ Complete (2026-05-01)

Implemented under `crates/franken-node/src/crypto/`:
- `mod.rs` — public surface (`SignatureScheme`, `CryptoSigner`, `KeyMaterial`, `Ed25519Scheme`, `Ed25519Signer`, `Ed25519Error`).
- `schemes.rs` — `SignatureScheme` trait + `Ed25519Scheme` impl with `ED25519_SIGNATURE_PREIMAGE_DOMAIN = b"ed25519_signature_v1:"` and length-prefixed canonical inputs.
- `signer.rs` — `CryptoSigner` trait + `Ed25519Signer` with built-in security patterns.
- `key_material.rs` — `KeyMaterial` trait with secret-zeroization guarantees.
- `error.rs` — typed errors implementing `std::error::Error`.
- `tests.rs` — round-trip, domain-separation, and constant-time tests.

The ergonomics proof-of-concept lives in the `tests.rs` test suite. No other module in the crate currently routes its signature path through these traits; Phase 2 covers that migration.

### Phase 2: Consumer Module Updates — beads filed 2026-05-18

| Module | Bead | Status |
|---|---|---|
| `security/decision_receipt.rs` | [`bd-dwx4l`](../../.beads/) | open |
| `security/remote_cap.rs` (single-signer paths only; threshold-sig stays in `security::threshold_sig`) | [`bd-acvur`](../../.beads/) | open, blocked-by `bd-dwx4l` |
| `tools/replay_bundle.rs` (the tool side; the SDK side at `sdk/verifier/src/bundle.rs` stays independent per the engine-split contract) | [`bd-lbnkf`](../../.beads/) | open, blocked-by `bd-dwx4l` |

**Signature-compat consideration shared by all three migrations.** A naive migration that pipes the existing canonical preimage through `Ed25519Scheme::sign_with_domain` adds the wrapper domain (`b"ed25519_signature_v1:"`) plus length-prefix framing in front of bytes that are already canonically domain-separated and length-prefixed by the consumer module. That changes the bytes Ed25519 actually signs, which invalidates every existing signed `Receipt`, capability token, and `.fnbundle` in the wild and breaks every golden in `tests/golden/`.

`bd-dwx4l` therefore introduces a `sign_raw` / `verify_raw` API on `Ed25519Scheme` (or a peer `RawSignatureScheme` trait) that bypasses the wrapper domain and length-prefix framing. Consumer modules that already do their own canonicalization use the raw path, getting the trait benefit (algorithm agility, consistent error handling, unified key material) without changing on-the-wire bytes. New consumers that have no canonical layer of their own use the default `sign_with_domain` and inherit the wrapper.

### Phase 3: Security Hardening — bead filed 2026-05-18

Tracked as [`bd-rcscw`](../../.beads/) (blocked-by `bd-dwx4l`, `bd-acvur`, `bd-lbnkf`). Covers:

- Audit every crypto call site for the four invariants: constant-time comparison, domain-separator coverage, length-prefixed canonical inputs, saturating arithmetic on counters/sequences/timestamps in crypto paths.
- New fuzz targets under `fuzz/fuzz_targets/`: `fuzz_crypto_scheme_roundtrip`, `fuzz_crypto_scheme_cross_domain`, `fuzz_crypto_signer_chain`.
- Criterion benchmark `crypto_scheme_bench` proving the zero-cost-abstraction claim within 5% of direct `ed25519_dalek` calls.

### Phase 4: Advanced Features — deferred

Not yet scoped. When the time comes for additional schemes (P-256), HSM-backed `KeyMaterial`, or crypto agility for scheme migration, file the bead under `bd-18dd1` as a Phase 4 sub-tree.

## Testing Strategy

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_roundtrip() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";
        
        let signature = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        assert!(Ed25519Scheme::verify_with_domain(&pk, domain, message, &signature));
    }
    
    #[test]  
    fn test_domain_separation() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        
        let sig1 = Ed25519Scheme::sign_with_domain(&sk, b"domain1", message).unwrap();
        let sig2 = Ed25519Scheme::sign_with_domain(&sk, b"domain2", message).unwrap();
        
        // Same message, different domains should produce different signatures
        assert_ne!(sig1, sig2);
        
        // Cross-domain verification should fail
        assert!(!Ed25519Scheme::verify_with_domain(&pk, b"domain1", message, &sig2));
        assert!(!Ed25519Scheme::verify_with_domain(&pk, b"domain2", message, &sig1));
    }
    
    #[test]
    fn test_constant_time_verification() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";
        
        let valid_sig = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        let mut invalid_sig = valid_sig.clone();
        invalid_sig[0] ^= 1; // Flip one bit
        
        // Both should complete in similar time (constant-time)
        let start = std::time::Instant::now();
        let result1 = Ed25519Scheme::verify_with_domain(&pk, domain, message, &valid_sig);
        let time1 = start.elapsed();
        
        let start = std::time::Instant::now();
        let result2 = Ed25519Scheme::verify_with_domain(&pk, domain, message, &invalid_sig);
        let time2 = start.elapsed();
        
        assert!(result1);
        assert!(!result2);
        // In practice, timing should be similar (this is hard to test deterministically)
    }
}
```

## Implementation Notes

- All trait methods marked as `#[must_use]` where appropriate
- Public APIs documented with security considerations
- Integration with existing `crate::security::constant_time` module
- Backward compatibility maintained during migration
- Zero-cost abstractions - traits compile to direct function calls

## Dependencies

```toml
[dependencies]
ed25519-dalek = { version = "2.0", features = ["serde"] }
blake3 = "1.5"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
```

## Follow-on Work

This design phase created the foundation. Filed beads:

| Phase | Item | Bead | Status |
|---|---|---|---|
| 1 | Implement core crypto traits module | (rolled into `bd-18dd1`) | ✅ closed 2026-05-01 |
| 2 | Migrate `security::decision_receipt` to traits | `bd-dwx4l` | open |
| 2 | Migrate `security::remote_cap` single-signer paths to traits | `bd-acvur` | open, blocked-by `bd-dwx4l` |
| 2 | Migrate `tools::replay_bundle` tool-side to traits | `bd-lbnkf` | open, blocked-by `bd-dwx4l` |
| 3 | Crypto audit + fuzz + Criterion bench | `bd-rcscw` | open, blocked-by Phase 2 |
| 4 | P-256, HSM-backed `KeyMaterial`, scheme migration agility | (deferred, not yet scoped) | — |

The "ed25519_verify" item from earlier drafts of this spec was aspirational; no such module exists in the crate. The relevant work is absorbed into the three Phase 2 migrations above (each consumer currently uses direct `ed25519_dalek` calls inline).

Each migration bead includes:
- Module-specific trait integration with **signature-compat preservation** (see Phase 2 above).
- Security pattern validation (constant-time, domain separators, length-prefixed inputs, saturating arithmetic).
- Re-running existing goldens to prove byte-identical canonical preimages.
- A new integration test asserting the migration path (trait-mediated signature matches pre-migration golden bytes).