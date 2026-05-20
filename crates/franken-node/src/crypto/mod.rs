//! Cryptographic trait abstractions for unified crypto operations.
//!
//! This module provides trait-based abstractions over cryptographic operations,
//! enabling algorithm agility, consistent security patterns, and better testability
//! across the franken_node codebase.
//!
//! # Design Principles
//!
//! - **Domain Separation**: All signature operations include context-specific domain separators
//! - **Constant-Time Operations**: All verification uses constant-time comparison patterns
//! - **Length Prefixing**: Variable-length inputs are length-prefixed to prevent collision
//! - **Fail-Closed**: Invalid operations return secure defaults
//! - **Saturating Arithmetic**: All counter operations use `saturating_add`
//!
//! # Core Traits
//!
//! - [`SignatureScheme`]: Low-level signature scheme abstraction with domain separation
//! - [`CryptoSigner`]: High-level signing operations with built-in security patterns
//! - [`KeyMaterial`]: Key material management with security guarantees
//!
//! # Concrete Implementations
//!
//! - [`Ed25519Scheme`]: Ed25519 signature scheme implementation
//! - [`Ed25519Signer`]: Ed25519-specific signer with security patterns

mod error;
mod key_material;
mod schemes;
mod signer;

pub use error::*;
pub use key_material::*;
pub use schemes::*;
pub use signer::*;

// Re-export for convenience
pub use ed25519_dalek;

#[cfg(test)]
mod tests;
