//! bd-1r2: Audience-bound token chains for control actions.
//!
//! Enhancement Map 9E.4 mandates capability token delegation chains for
//! migration and control-plane actions. Each token is bound to a specific
//! audience, carries an explicit capability allowlist, and links to its
//! parent via a hash chain. Delegation strictly attenuates: every child
//! token must grant a subset of its parent's capabilities and audience.
//!
//! # Invariants
//!
//! - **INV-ABT-ATTENUATION**: Delegation never widens capabilities beyond parent scope.
//! - **INV-ABT-AUDIENCE**: Token audience must match executing service identity.
//! - **INV-ABT-EXPIRY**: Expired tokens are rejected regardless of chain validity.
//! - **INV-ABT-REPLAY**: Nonce uniqueness is enforced within an epoch.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ed25519_dalek::{Signature, Verifier};

use crate::security::constant_time;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Token issued (issuer, audience, capability_count, expiry).
pub const ABT_001: &str = "ABT-001";
/// Token delegated (delegator, new_audience, chain_depth).
pub const ABT_002: &str = "ABT-002";
/// Token verified (chain_depth, audience_match, duration_us).
pub const ABT_003: &str = "ABT-003";
/// Token rejected (reason, attempted_audience, chain_depth).
pub const ABT_004: &str = "ABT-004";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Delegation attempted to widen capabilities beyond parent scope.
pub const ERR_ABT_ATTENUATION_VIOLATION: &str = "ERR_ABT_ATTENUATION_VIOLATION";
/// Audience does not match the executing service identity.
pub const ERR_ABT_AUDIENCE_MISMATCH: &str = "ERR_ABT_AUDIENCE_MISMATCH";
/// Token has passed its expiry timestamp.
pub const ERR_ABT_TOKEN_EXPIRED: &str = "ERR_ABT_TOKEN_EXPIRED";
/// Nonce was already used within the current epoch.
pub const ERR_ABT_REPLAY_DETECTED: &str = "ERR_ABT_REPLAY_DETECTED";
/// Token signature is missing, malformed, signed by an untrusted issuer, or invalid.
pub const ERR_ABT_SIGNATURE_INVALID: &str = "ERR_ABT_SIGNATURE_INVALID";

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

/// INV-ABT-ATTENUATION: Delegation never widens capabilities beyond parent scope.
pub const INV_ABT_ATTENUATION: &str = "INV-ABT-ATTENUATION";
/// INV-ABT-AUDIENCE: Token audience must match executing service identity.
pub const INV_ABT_AUDIENCE: &str = "INV-ABT-AUDIENCE";
/// INV-ABT-EXPIRY: Expired tokens are rejected regardless of chain validity.
pub const INV_ABT_EXPIRY: &str = "INV-ABT-EXPIRY";
/// INV-ABT-REPLAY: Nonce uniqueness is enforced within an epoch.
pub const INV_ABT_REPLAY: &str = "INV-ABT-REPLAY";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique token identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenId(pub String);

impl TokenId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TokenId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Action scope that can be granted by a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ActionScope {
    /// Initiate or manage migrations.
    Migrate,
    /// Rollback to prior state.
    Rollback,
    /// Promote artifacts / trust levels.
    Promote,
    /// Revoke credentials or tokens.
    Revoke,
    /// Modify configuration parameters.
    Configure,
}

impl ActionScope {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Migrate => "migrate",
            Self::Rollback => "rollback",
            Self::Promote => "promote",
            Self::Revoke => "revoke",
            Self::Configure => "configure",
        }
    }

    /// All defined action scopes.
    pub fn all() -> BTreeSet<Self> {
        let mut set = BTreeSet::new();
        set.insert(Self::Migrate);
        set.insert(Self::Rollback);
        set.insert(Self::Promote);
        set.insert(Self::Revoke);
        set.insert(Self::Configure);
        set
    }
}

impl std::fmt::Display for ActionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// An audience-bound token for control-plane actions.
///
/// Each token binds authority to a specific audience (target services),
/// carries an explicit capability allowlist, and optionally links to a
/// parent token via `parent_token_hash` to form a delegation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudienceBoundToken {
    /// Unique identifier for this token.
    pub token_id: TokenId,
    /// Identity of the entity that issued this token.
    pub issuer: String,
    /// List of intended recipient service identifiers.
    pub audience: Vec<String>,
    /// Granted action scopes (strictly attenuated on delegation).
    pub capabilities: BTreeSet<ActionScope>,
    /// UTC timestamp (ms) when the token was issued.
    pub issued_at: u64,
    /// UTC timestamp (ms) after which the token is invalid.
    pub expires_at: u64,
    /// Unique nonce for replay detection within an epoch.
    pub nonce: String,
    /// Hash of the parent token (None for root tokens).
    pub parent_token_hash: Option<String>,
    /// Signature over the canonical preimage.
    pub signature: String,
    /// Maximum number of further delegations (0 = no further delegation).
    pub max_delegation_depth: u8,
}

impl AudienceBoundToken {
    /// Build the canonical detached-signature preimage for this token.
    ///
    /// The signature intentionally excludes the `signature` field and binds
    /// every other field with domain-separated, length-prefixed framing.
    pub fn signature_preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"audience_bound_token_signature_v1:");
        append_len_prefixed_str(&mut preimage, self.token_id.as_str());
        append_len_prefixed_str(&mut preimage, &self.issuer);
        append_len_to_vec(&mut preimage, self.audience.len());
        for audience in &self.audience {
            append_len_prefixed_str(&mut preimage, audience);
        }
        append_len_to_vec(&mut preimage, self.capabilities.len());
        for capability in &self.capabilities {
            append_len_prefixed_str(&mut preimage, capability.label());
        }
        preimage.extend_from_slice(&self.issued_at.to_le_bytes());
        preimage.extend_from_slice(&self.expires_at.to_le_bytes());
        append_len_prefixed_str(&mut preimage, &self.nonce);
        match &self.parent_token_hash {
            Some(parent_hash) => {
                preimage.push(1);
                append_len_prefixed_str(&mut preimage, parent_hash);
            }
            None => preimage.push(0),
        }
        preimage.push(self.max_delegation_depth);
        preimage
    }

    /// Compute the SHA-256 hash of this token for chain integrity.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"audience_auth_v1:");
        let tid = self.token_id.as_str();
        update_len_prefixed(&mut hasher, tid);
        update_len_prefixed(&mut hasher, &self.issuer);
        hasher.update(len_to_u64(self.audience.len()).to_le_bytes());
        for aud in &self.audience {
            update_len_prefixed(&mut hasher, aud);
        }
        hasher.update(len_to_u64(self.capabilities.len()).to_le_bytes());
        for cap in &self.capabilities {
            let label = cap.label();
            update_len_prefixed(&mut hasher, label);
        }
        hasher.update(self.issued_at.to_le_bytes());
        hasher.update(self.expires_at.to_le_bytes());
        update_len_prefixed(&mut hasher, &self.nonce);
        match &self.parent_token_hash {
            Some(ph) => {
                hasher.update(1u8.to_le_bytes());
                update_len_prefixed(&mut hasher, ph);
            }
            None => {
                hasher.update(0u8.to_le_bytes());
            }
        }
        update_len_prefixed(&mut hasher, &self.signature);
        hasher.update([self.max_delegation_depth]);
        hex::encode(hasher.finalize())
    }

    /// Check whether this token is expired at `now_ms`.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at
    }

    /// Check whether this token has a valid (positive) validity window.
    pub fn has_valid_window(&self) -> bool {
        self.issued_at < self.expires_at
    }

    /// Whether this is a root token (no parent).
    pub fn is_root(&self) -> bool {
        self.parent_token_hash.is_none()
    }

    /// Check if audience contains a specific service identity.
    pub fn audience_contains(&self, service_id: &str) -> bool {
        self.audience
            .iter()
            .fold(false, |acc, a| acc | constant_time::ct_eq(a, service_id))
    }
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn update_len_prefixed(hasher: &mut Sha256, value: &str) {
    hasher.update(len_to_u64(value.len()).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn append_len_to_vec(output: &mut Vec<u8>, len: usize) {
    output.extend_from_slice(&len_to_u64(len).to_le_bytes());
}

fn append_len_prefixed_str(output: &mut Vec<u8>, value: &str) {
    append_len_to_vec(output, value.len());
    output.extend_from_slice(value.as_bytes());
}

/// Error type for audience-bound token operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenError {
    pub code: String,
    pub message: String,
}

impl TokenError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn attenuation_violation(detail: impl Into<String>) -> Self {
        Self::new(ERR_ABT_ATTENUATION_VIOLATION, detail)
    }

    pub fn audience_mismatch(attempted: &str, actual: &[String]) -> Self {
        Self::new(
            ERR_ABT_AUDIENCE_MISMATCH,
            format!(
                "Audience mismatch: requester '{}' not in {:?}",
                attempted, actual
            ),
        )
    }

    pub fn token_expired(token_id: &TokenId) -> Self {
        Self::new(
            ERR_ABT_TOKEN_EXPIRED,
            format!("Token '{}' has expired", token_id),
        )
    }

    pub fn replay_detected(nonce: &str) -> Self {
        Self::new(
            ERR_ABT_REPLAY_DETECTED,
            format!("Nonce '{}' already used in current epoch", nonce),
        )
    }

    pub fn signature_invalid(token_id: &TokenId, detail: impl Into<String>) -> Self {
        Self::new(
            ERR_ABT_SIGNATURE_INVALID,
            format!("Token '{}' signature invalid: {}", token_id, detail.into()),
        )
    }
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Audit event emitted during token operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEvent {
    pub event_code: String,
    pub token_id: String,
    pub trace_id: String,
    pub epoch_id: u64,
    pub action_id: String,
    pub detail: String,
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// TokenChain
// ---------------------------------------------------------------------------

/// An ordered sequence of delegation tokens forming a chain of custody.
///
/// The first token is the root; each subsequent token's `parent_token_hash`
/// links to the hash of its predecessor. Capabilities are monotonically
/// narrowing.
#[derive(Debug, Clone, Serialize)]
pub struct TokenChain {
    tokens: Vec<AudienceBoundToken>,
}

impl<'de> Deserialize<'de> for TokenChain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawTokenChain {
            tokens: Vec<AudienceBoundToken>,
        }

        let raw = RawTokenChain::deserialize(deserializer)?;
        if raw.tokens.is_empty() {
            return Err(serde::de::Error::custom("token chain cannot be empty"));
        }

        let mut chain = TokenChain::new(raw.tokens[0].clone())
            .map_err(|e| serde::de::Error::custom(e.message))?;

        for token in raw.tokens.into_iter().skip(1) {
            chain
                .append(token)
                .map_err(|e| serde::de::Error::custom(e.message))?;
        }

        Ok(chain)
    }
}

impl TokenChain {
    /// Create a new chain starting from a root token.
    pub fn new(root: AudienceBoundToken) -> Result<Self, TokenError> {
        if !root.is_root() {
            return Err(TokenError::new(
                ERR_ABT_ATTENUATION_VIOLATION,
                "First token in chain must be a root token (no parent_token_hash)",
            ));
        }
        if !root.has_valid_window() {
            return Err(TokenError::new(
                ERR_ABT_TOKEN_EXPIRED,
                "Root token has zero or negative validity window",
            ));
        }
        Ok(Self { tokens: vec![root] })
    }

    /// Append a delegated token to the chain, enforcing attenuation invariants.
    pub fn append(&mut self, token: AudienceBoundToken) -> Result<(), TokenError> {
        let parent = self.tokens.last().ok_or_else(|| {
            TokenError::new(
                ERR_ABT_ATTENUATION_VIOLATION,
                "cannot append to an empty token chain".to_string(),
            )
        })?;

        // Check parent_token_hash links to parent.
        let parent_hash = parent.hash();
        match &token.parent_token_hash {
            Some(h) if constant_time::ct_eq(h, &parent_hash) => {}
            Some(h) => {
                return Err(TokenError::new(
                    ERR_ABT_ATTENUATION_VIOLATION,
                    format!(
                        "parent_token_hash mismatch: expected '{}', got '{}'",
                        parent_hash, h
                    ),
                ));
            }
            None => {
                return Err(TokenError::new(
                    ERR_ABT_ATTENUATION_VIOLATION,
                    "Delegated token must have parent_token_hash",
                ));
            }
        }

        // INV-ABT-ATTENUATION: capabilities must be a subset of parent's.
        if !token.capabilities.is_subset(&parent.capabilities) {
            let extra: Vec<_> = token
                .capabilities
                .difference(&parent.capabilities)
                .map(|s| s.label())
                .collect();
            return Err(TokenError::attenuation_violation(format!(
                "Delegated token grants capabilities not in parent: {:?}",
                extra
            )));
        }

        // Audience must be a subset of parent's audience.
        let parent_aud: BTreeSet<&str> = parent.audience.iter().map(|s| s.as_str()).collect();
        for aud in &token.audience {
            if !parent_aud.contains(aud.as_str()) {
                return Err(TokenError::attenuation_violation(format!(
                    "Delegated token audience '{}' not in parent audience {:?}",
                    aud, parent.audience
                )));
            }
        }

        // Check delegation depth.
        if parent.max_delegation_depth == 0 {
            return Err(TokenError::new(
                ERR_ABT_ATTENUATION_VIOLATION,
                "Parent token has max_delegation_depth of 0 and cannot be delegated",
            ));
        }
        if token.max_delegation_depth >= parent.max_delegation_depth {
            return Err(TokenError::new(
                ERR_ABT_ATTENUATION_VIOLATION,
                format!(
                    "Delegated token max_delegation_depth {} must be strictly less than parent's {}",
                    token.max_delegation_depth, parent.max_delegation_depth
                ),
            ));
        }

        let root = &self.tokens[0];
        let max_chain_len = usize::from(root.max_delegation_depth).saturating_add(1);
        if self.tokens.len() >= max_chain_len {
            return Err(TokenError::new(
                ERR_ABT_ATTENUATION_VIOLATION,
                format!(
                    "Chain depth {} would exceed max_delegation_depth {} (max chain length {})",
                    self.tokens.len(),
                    root.max_delegation_depth,
                    max_chain_len
                ),
            ));
        }

        // INV-ABT-EXPIRY-ATTENUATION: child must not outlive parent.
        if token.expires_at > parent.expires_at {
            return Err(TokenError::new(
                ERR_ABT_ATTENUATION_VIOLATION,
                format!(
                    "Delegated token expires_at {} exceeds parent's {}",
                    token.expires_at, parent.expires_at
                ),
            ));
        }

        // Child must not be issued before parent.
        if token.issued_at < parent.issued_at {
            return Err(TokenError::new(
                ERR_ABT_ATTENUATION_VIOLATION,
                format!(
                    "Delegated token issued_at {} is before parent's {}",
                    token.issued_at, parent.issued_at
                ),
            ));
        }

        // Validity window check.
        if !token.has_valid_window() {
            return Err(TokenError::new(
                ERR_ABT_TOKEN_EXPIRED,
                "Delegated token has zero or negative validity window",
            ));
        }

        push_bounded(&mut self.tokens, token, MAX_TOKENS);
        Ok(())
    }

    /// Number of tokens in the chain (root = depth 1).
    pub fn depth(&self) -> usize {
        self.tokens.len()
    }

    /// The root token.
    pub fn root(&self) -> Option<&AudienceBoundToken> {
        self.tokens.first()
    }

    /// The leaf (most recently delegated) token.
    pub fn leaf(&self) -> Option<&AudienceBoundToken> {
        self.tokens.last()
    }

    /// All tokens in chain order.
    pub fn tokens(&self) -> &[AudienceBoundToken] {
        &self.tokens
    }
}

// ---------------------------------------------------------------------------
// TokenValidator
// ---------------------------------------------------------------------------

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::push_bounded;
const MAX_TOKENS: usize = 4096;
/// Maximum nonces tracked per epoch before oldest-first eviction.
/// Without this cap, an adversary controlling token creation could exhaust
/// memory by verifying many unique-nonce tokens over a long epoch.
const MAX_NONCES: usize = 65_536;

/// Insert a nonce into a bounded set, evicting the oldest entry when at capacity.
/// This prevents unbounded memory growth from an adversary replaying many tokens
/// and ensures that eviction is based on time, not lexicographical sorting.
fn insert_nonce_bounded(
    set: &mut BTreeSet<String>,
    queue: &mut VecDeque<String>,
    nonce: String,
    cap: usize,
) {
    if cap == 0 {
        set.clear();
        queue.clear();
        return;
    }
    if set.insert(nonce.clone()) {
        while queue.len() >= cap {
            if let Some(oldest) = queue.pop_front() {
                set.remove(&oldest);
            }
        }
        queue.push_back(nonce);
    }
}

/// Validates audience-bound token chains, enforcing expiry, replay detection,
/// and audience matching.
pub struct TokenValidator {
    /// Trusted Ed25519 issuer keys keyed by exact issuer identity.
    trusted_issuer_keys: BTreeMap<String, ed25519_dalek::VerifyingKey>,
    /// Nonces seen in the current epoch.
    seen_nonces: BTreeSet<String>,
    /// Insertion order of nonces for bounded eviction.
    seen_nonces_queue: VecDeque<String>,
    /// Current epoch ID for replay scoping.
    epoch_id: u64,
    /// Emitted events.
    events: Vec<TokenEvent>,
    /// Counters.
    tokens_issued: u64,
    tokens_delegated: u64,
    tokens_verified: u64,
    tokens_rejected: u64,
}

impl TokenValidator {
    pub fn new(epoch_id: u64) -> Self {
        Self {
            trusted_issuer_keys: BTreeMap::new(),
            seen_nonces: BTreeSet::new(),
            seen_nonces_queue: VecDeque::new(),
            epoch_id,
            events: Vec::new(),
            tokens_issued: 0,
            tokens_delegated: 0,
            tokens_verified: 0,
            tokens_rejected: 0,
        }
    }

    /// Trust `verifying_key` for tokens whose `issuer` exactly matches `issuer`.
    pub fn trust_issuer_key(
        &mut self,
        issuer: impl Into<String>,
        verifying_key: ed25519_dalek::VerifyingKey,
    ) {
        self.trusted_issuer_keys
            .insert(issuer.into(), verifying_key);
    }

    /// Builder-style variant of [`Self::trust_issuer_key`].
    #[must_use]
    pub fn with_trusted_issuer_key(
        mut self,
        issuer: impl Into<String>,
        verifying_key: ed25519_dalek::VerifyingKey,
    ) -> Self {
        self.trust_issuer_key(issuer, verifying_key);
        self
    }

    fn verify_token_signature(&self, token: &AudienceBoundToken) -> Result<(), TokenError> {
        let verifying_key = self.trusted_issuer_keys.get(&token.issuer).ok_or_else(|| {
            TokenError::signature_invalid(
                &token.token_id,
                format!("issuer '{}' is not trusted", token.issuer),
            )
        })?;
        let signature_hex = token
            .signature
            .strip_prefix("ed25519:")
            .unwrap_or(&token.signature);
        let signature_bytes = hex::decode(signature_hex).map_err(|_| {
            TokenError::signature_invalid(&token.token_id, "signature is not valid hex")
        })?;

        let signature = Signature::from_slice(&signature_bytes).map_err(|error| {
            TokenError::signature_invalid(
                &token.token_id,
                format!("signature length invalid: {error}"),
            )
        })?;
        verifying_key
            .verify(&token.signature_preimage(), &signature)
            .map_err(|error| {
                TokenError::signature_invalid(
                    &token.token_id,
                    format!("ed25519 verify failed: {error}"),
                )
            })
    }

    /// Record a root token issuance.
    pub fn record_issuance(&mut self, token: &AudienceBoundToken, trace_id: &str, now_ms: u64) {
        self.tokens_issued = self.tokens_issued.saturating_add(1);
        insert_nonce_bounded(
            &mut self.seen_nonces,
            &mut self.seen_nonces_queue,
            token.nonce.clone(),
            MAX_NONCES,
        );
        push_bounded(
            &mut self.events,
            TokenEvent {
                event_code: ABT_001.to_string(),
                token_id: token.token_id.as_str().to_string(),
                trace_id: trace_id.to_string(),
                epoch_id: self.epoch_id,
                action_id: format!("issue-{}", token.token_id),
                detail: format!(
                    "Issued token with {} capabilities to audience {:?}",
                    token.capabilities.len(),
                    token.audience
                ),
                timestamp_ms: now_ms,
            },
            MAX_EVENTS,
        );
    }

    /// Record a delegation event.
    pub fn record_delegation(
        &mut self,
        token: &AudienceBoundToken,
        chain_depth: usize,
        trace_id: &str,
        now_ms: u64,
    ) {
        self.tokens_delegated = self.tokens_delegated.saturating_add(1);
        insert_nonce_bounded(
            &mut self.seen_nonces,
            &mut self.seen_nonces_queue,
            token.nonce.clone(),
            MAX_NONCES,
        );
        push_bounded(
            &mut self.events,
            TokenEvent {
                event_code: ABT_002.to_string(),
                token_id: token.token_id.as_str().to_string(),
                trace_id: trace_id.to_string(),
                epoch_id: self.epoch_id,
                action_id: format!("delegate-{}", token.token_id),
                detail: format!(
                    "Delegated token at depth {} to audience {:?}",
                    chain_depth, token.audience
                ),
                timestamp_ms: now_ms,
            },
            MAX_EVENTS,
        );
    }

    /// Verify a full token chain against a requester identity.
    ///
    /// Checks:
    /// 1. No expired tokens (INV-ABT-EXPIRY)
    /// 2. No nonce replay (INV-ABT-REPLAY)
    /// 3. Chain hash integrity
    /// 4. Audience match on leaf token (INV-ABT-AUDIENCE)
    /// 5. Attenuation (INV-ABT-ATTENUATION) is enforced structurally by TokenChain
    pub fn verify_chain(
        &mut self,
        chain: &TokenChain,
        requester_id: &str,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<(), TokenError> {
        let tokens = chain.tokens();

        if tokens.is_empty() {
            return Err(TokenError::new(
                ERR_ABT_ATTENUATION_VIOLATION,
                "token chain is empty".to_string(),
            ));
        }

        // Check all tokens for expiry.
        for (i, token) in tokens.iter().enumerate() {
            if token.is_expired(now_ms) {
                self.tokens_rejected = self.tokens_rejected.saturating_add(1);
                let err = TokenError::token_expired(&token.token_id);
                push_bounded(
                    &mut self.events,
                    TokenEvent {
                        event_code: ABT_004.to_string(),
                        token_id: token.token_id.as_str().to_string(),
                        trace_id: trace_id.to_string(),
                        epoch_id: self.epoch_id,
                        action_id: format!("verify-expired-{}", i),
                        detail: format!(
                            "Token at chain position {} expired (expires_at={}, now={})",
                            i, token.expires_at, now_ms
                        ),
                        timestamp_ms: now_ms,
                    },
                    MAX_EVENTS,
                );
                return Err(err);
            }
        }

        // Check validity windows.
        for token in tokens.iter() {
            if !token.has_valid_window() {
                self.tokens_rejected = self.tokens_rejected.saturating_add(1);
                return Err(TokenError::new(
                    ERR_ABT_TOKEN_EXPIRED,
                    format!(
                        "Token '{}' has zero or negative validity window (issued_at={}, expires_at={})",
                        token.token_id, token.issued_at, token.expires_at
                    ),
                ));
            }
        }

        // INV-ABT-REPLAY: check nonce replay.
        let mut chain_nonces = BTreeSet::new();
        for token in tokens.iter() {
            if !chain_nonces.insert(token.nonce.clone()) {
                self.tokens_rejected = self.tokens_rejected.saturating_add(1);
                let err = TokenError::replay_detected(&token.nonce);
                push_bounded(
                    &mut self.events,
                    TokenEvent {
                        event_code: ABT_004.to_string(),
                        token_id: token.token_id.as_str().to_string(),
                        trace_id: trace_id.to_string(),
                        epoch_id: self.epoch_id,
                        action_id: format!("verify-replay-{}", token.token_id),
                        detail: format!("Nonce '{}' duplicated within token chain", token.nonce),
                        timestamp_ms: now_ms,
                    },
                    MAX_EVENTS,
                );
                return Err(err);
            }
        }

        // In multi-token chains the root token is allowed to appear in multiple
        // delegation chains (different leaves), so its nonce is skipped during
        // the check.  In single-token (root-only) chains the root IS checked.
        // All delegated (non-root) nonces are always checked to block prefix
        // replay attacks where an attacker strips the leaf.
        let is_multi = tokens.len() > 1;
        for token in tokens.iter() {
            if is_multi && token.parent_token_hash.is_none() {
                continue; // root in multi-token chain — skip replay check
            }
            if self.seen_nonces.contains(&token.nonce) {
                self.tokens_rejected = self.tokens_rejected.saturating_add(1);
                let err = TokenError::replay_detected(&token.nonce);
                push_bounded(
                    &mut self.events,
                    TokenEvent {
                        event_code: ABT_004.to_string(),
                        token_id: token.token_id.as_str().to_string(),
                        trace_id: trace_id.to_string(),
                        epoch_id: self.epoch_id,
                        action_id: format!("verify-replay-{}", token.token_id),
                        detail: format!("Nonce '{}' replay detected", token.nonce),
                        timestamp_ms: now_ms,
                    },
                    MAX_EVENTS,
                );
                return Err(err);
            }
        }

        // Verify chain hash integrity.
        for i in 1..tokens.len() {
            let parent_hash = tokens[i - 1].hash();
            match &tokens[i].parent_token_hash {
                Some(h) if constant_time::ct_eq(h, &parent_hash) => {}
                _ => {
                    self.tokens_rejected = self.tokens_rejected.saturating_add(1);
                    return Err(TokenError::new(
                        ERR_ABT_ATTENUATION_VIOLATION,
                        format!(
                            "Chain integrity violation at position {}: parent_token_hash mismatch",
                            i
                        ),
                    ));
                }
            }
        }

        // Verify every token's issuer-bound detached signature before
        // accepting the chain or recording replay state.
        for token in tokens.iter() {
            if let Err(err) = self.verify_token_signature(token) {
                self.tokens_rejected = self.tokens_rejected.saturating_add(1);
                push_bounded(
                    &mut self.events,
                    TokenEvent {
                        event_code: ABT_004.to_string(),
                        token_id: token.token_id.as_str().to_string(),
                        trace_id: trace_id.to_string(),
                        epoch_id: self.epoch_id,
                        action_id: format!("verify-signature-{}", token.token_id),
                        detail: err.message.clone(),
                        timestamp_ms: now_ms,
                    },
                    MAX_EVENTS,
                );
                return Err(err);
            }
        }

        // INV-ABT-AUDIENCE: Check audience match on leaf token.
        let Some(leaf) = chain.leaf() else {
            self.tokens_rejected = self.tokens_rejected.saturating_add(1);
            return Err(TokenError::new(
                ERR_ABT_ATTENUATION_VIOLATION,
                "token chain missing leaf token".to_string(),
            ));
        };
        if !leaf.audience_contains(requester_id) {
            self.tokens_rejected = self.tokens_rejected.saturating_add(1);
            let err = TokenError::audience_mismatch(requester_id, &leaf.audience);
            push_bounded(
                &mut self.events,
                TokenEvent {
                    event_code: ABT_004.to_string(),
                    token_id: leaf.token_id.as_str().to_string(),
                    trace_id: trace_id.to_string(),
                    epoch_id: self.epoch_id,
                    action_id: format!("verify-audience-{}", leaf.token_id),
                    detail: format!(
                        "Audience mismatch: requester '{}' not in {:?}",
                        requester_id, leaf.audience
                    ),
                    timestamp_ms: now_ms,
                },
                MAX_EVENTS,
            );
            return Err(err);
        }

        // All checks passed: record all token nonces and emit success event.
        for token in tokens.iter() {
            insert_nonce_bounded(
                &mut self.seen_nonces,
                &mut self.seen_nonces_queue,
                token.nonce.clone(),
                MAX_NONCES,
            );
        }
        self.tokens_verified = self.tokens_verified.saturating_add(1);
        push_bounded(
            &mut self.events,
            TokenEvent {
                event_code: ABT_003.to_string(),
                token_id: leaf.token_id.as_str().to_string(),
                trace_id: trace_id.to_string(),
                epoch_id: self.epoch_id,
                action_id: format!("verify-ok-{}", leaf.token_id),
                detail: format!(
                    "Chain verified: depth={}, audience_match=true",
                    tokens.len()
                ),
                timestamp_ms: now_ms,
            },
            MAX_EVENTS,
        );

        Ok(())
    }

    /// Check audience on a single token.
    pub fn check_audience(
        &self,
        token: &AudienceBoundToken,
        requester_id: &str,
    ) -> Result<(), TokenError> {
        if token.audience_contains(requester_id) {
            Ok(())
        } else {
            Err(TokenError::audience_mismatch(requester_id, &token.audience))
        }
    }

    /// Reset nonces for a new epoch.
    pub fn advance_epoch(&mut self, new_epoch_id: u64) {
        self.seen_nonces.clear();
        self.seen_nonces_queue.clear();
        self.epoch_id = new_epoch_id;
    }

    /// Current epoch ID.
    pub fn epoch_id(&self) -> u64 {
        self.epoch_id
    }

    /// Drain and return all recorded events.
    pub fn take_events(&mut self) -> Vec<TokenEvent> {
        std::mem::take(&mut self.events)
    }

    /// Borrow all recorded events.
    pub fn events(&self) -> &[TokenEvent] {
        &self.events
    }

    /// Counters for metrics.
    pub fn tokens_issued(&self) -> u64 {
        self.tokens_issued
    }

    pub fn tokens_delegated(&self) -> u64 {
        self.tokens_delegated
    }

    pub fn tokens_verified(&self) -> u64 {
        self.tokens_verified
    }

    pub fn tokens_rejected(&self) -> u64 {
        self.tokens_rejected
    }

    /// Number of unique nonces seen in the current epoch.
    pub fn nonce_count(&self) -> usize {
        self.seen_nonces.len()
    }
}

// ---------------------------------------------------------------------------
// Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<TokenValidator>();
    assert_sync::<TokenValidator>();
    assert_send::<TokenChain>();
    assert_sync::<TokenChain>();
    assert_send::<AudienceBoundToken>();
    assert_sync::<AudienceBoundToken>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use crate::security::constant_time;

    use ed25519_dalek::{Signer, SigningKey};

    use super::{
        ActionScope, AudienceBoundToken, ERR_ABT_ATTENUATION_VIOLATION, ERR_ABT_AUDIENCE_MISMATCH,
        ERR_ABT_REPLAY_DETECTED, ERR_ABT_SIGNATURE_INVALID, ERR_ABT_TOKEN_EXPIRED, TokenChain,
        TokenError, TokenId, TokenValidator, len_to_u64,
    };
    use std::collections::BTreeSet;

    // -- Helpers --

    fn fixture_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[14_u8; 32])
    }

    fn sign_token(token: &mut AudienceBoundToken) {
        token.signature.clear();
        token.signature = hex::encode(
            fixture_signing_key()
                .sign(&token.signature_preimage())
                .to_bytes(),
        );
    }

    fn trusted_validator(epoch_id: u64) -> TokenValidator {
        TokenValidator::new(epoch_id)
            .with_trusted_issuer_key("issuer-1", fixture_signing_key().verifying_key())
            .with_trusted_issuer_key("delegator-1", fixture_signing_key().verifying_key())
    }

    fn root_token(id: &str, depth: u8) -> AudienceBoundToken {
        let mut token = AudienceBoundToken {
            token_id: TokenId::new(id),
            issuer: "issuer-1".to_string(),
            audience: vec!["kernel-A".to_string(), "kernel-B".to_string()],
            capabilities: ActionScope::all(),
            issued_at: 1000,
            expires_at: 100_000,
            nonce: format!("nonce-{}", id),
            parent_token_hash: None,
            signature: String::new(),
            max_delegation_depth: depth,
        };
        sign_token(&mut token);
        token
    }

    fn delegate_token(
        parent: &AudienceBoundToken,
        id: &str,
        audience: Vec<String>,
        capabilities: BTreeSet<ActionScope>,
    ) -> AudienceBoundToken {
        let mut token = AudienceBoundToken {
            token_id: TokenId::new(id),
            issuer: "delegator-1".to_string(),
            audience,
            capabilities,
            issued_at: parent.issued_at.saturating_add(100),
            expires_at: parent.expires_at,
            nonce: format!("nonce-{}", id),
            parent_token_hash: Some(parent.hash()),
            signature: String::new(),
            max_delegation_depth: parent.max_delegation_depth.saturating_sub(1),
        };
        sign_token(&mut token);
        token
    }

    fn narrow_caps() -> BTreeSet<ActionScope> {
        let mut set = BTreeSet::new();
        set.insert(ActionScope::Migrate);
        set.insert(ActionScope::Rollback);
        set
    }

    fn single_cap(scope: ActionScope) -> BTreeSet<ActionScope> {
        let mut set = BTreeSet::new();
        set.insert(scope);
        set
    }

    // -- TokenId --

    #[test]
    fn test_token_id_display() {
        let id = TokenId::new("tok-123");
        assert_eq!(format!("{}", id), "tok-123");
    }

    #[test]
    fn test_token_id_as_str() {
        let id = TokenId::new("tok-456");
        assert_eq!(id.as_str(), "tok-456");
    }

    // -- ActionScope --

    #[test]
    fn test_action_scope_labels() {
        assert_eq!(ActionScope::Migrate.label(), "migrate");
        assert_eq!(ActionScope::Rollback.label(), "rollback");
        assert_eq!(ActionScope::Promote.label(), "promote");
        assert_eq!(ActionScope::Revoke.label(), "revoke");
        assert_eq!(ActionScope::Configure.label(), "configure");
    }

    #[test]
    fn test_action_scope_all() {
        let all = ActionScope::all();
        assert_eq!(all.len(), 5);
        assert!(all.contains(&ActionScope::Migrate));
        assert!(all.contains(&ActionScope::Rollback));
        assert!(all.contains(&ActionScope::Promote));
        assert!(all.contains(&ActionScope::Revoke));
        assert!(all.contains(&ActionScope::Configure));
    }

    #[test]
    fn test_action_scope_display() {
        assert_eq!(format!("{}", ActionScope::Migrate), "migrate");
    }

    #[test]
    fn test_action_scope_serde_roundtrip() {
        let scope = ActionScope::Promote;
        let json = serde_json::to_string(&scope).unwrap();
        let parsed: ActionScope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, scope);
    }

    // -- AudienceBoundToken --

    #[test]
    fn test_root_token_creation() {
        let token = root_token("root-1", 3);
        assert!(token.is_root());
        assert!(token.has_valid_window());
        assert!(!token.is_expired(50_000));
    }

    #[test]
    fn test_token_hash_deterministic() {
        let t1 = root_token("root-1", 3);
        let t2 = root_token("root-1", 3);
        assert!(constant_time::ct_eq_bytes(
            t1.hash().as_bytes(),
            t2.hash().as_bytes()
        ));
    }

    #[test]
    fn test_token_hash_changes_with_id() {
        let t1 = root_token("root-1", 3);
        let t2 = root_token("root-2", 3);
        assert!(!constant_time::ct_eq_bytes(
            t1.hash().as_bytes(),
            t2.hash().as_bytes()
        ));
    }

    #[test]
    fn len_to_u64_converts_representative_lengths_without_unchecked_casts() {
        assert_eq!(len_to_u64(0), 0);
        assert_eq!(len_to_u64(1), 1);
        assert_eq!(len_to_u64(usize::from(u16::MAX)), u64::from(u16::MAX));
    }

    #[test]
    fn token_hash_length_prefix_distinguishes_ambiguous_field_boundaries() {
        let mut left = root_token("ab", 3);
        left.issuer = "c".to_string();
        let mut right = root_token("a", 3);
        right.issuer = "bc".to_string();
        right.nonce = left.nonce.clone();
        right.signature = left.signature.clone();

        assert_eq!(
            format!("{}{}", left.token_id.as_str(), left.issuer),
            format!("{}{}", right.token_id.as_str(), right.issuer)
        );
        assert!(!constant_time::ct_eq_bytes(
            left.hash().as_bytes(),
            right.hash().as_bytes()
        ));
    }

    #[test]
    fn token_hash_length_prefix_distinguishes_collection_boundaries() {
        let mut single = root_token("root-audience-boundary", 3);
        single.audience = vec!["kernel-Akernel-B".to_string()];
        let mut split = root_token("root-audience-boundary", 3);
        split.audience = vec!["kernel-A".to_string(), "kernel-B".to_string()];

        assert_eq!(single.audience.concat(), split.audience.concat());
        assert!(!constant_time::ct_eq_bytes(
            single.hash().as_bytes(),
            split.hash().as_bytes()
        ));
    }

    #[test]
    fn signature_preimage_excludes_signature_field() {
        let mut left = root_token("root-signature-preimage", 3);
        let mut right = left.clone();
        left.signature = "ed25519:aa".to_string();
        right.signature = "ed25519:bb".to_string();

        assert_eq!(left.signature_preimage(), right.signature_preimage());
    }

    #[test]
    fn delegate_token_issued_at_saturates_instead_of_wrapping() {
        let mut root = root_token("root-max-issued-at", 3);
        root.issued_at = u64::MAX;

        let child = delegate_token(
            &root,
            "child-max-issued-at",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );

        assert_eq!(child.issued_at, u64::MAX);
    }

    #[test]
    fn test_token_is_expired() {
        let token = root_token("root-1", 0);
        assert!(!token.is_expired(99_999));
        assert!(token.is_expired(100_000));
        assert!(token.is_expired(200_000));
    }

    #[test]
    fn test_token_has_valid_window() {
        let mut token = root_token("root-1", 0);
        assert!(token.has_valid_window());
        token.expires_at = token.issued_at; // zero window
        assert!(!token.has_valid_window());
        token.expires_at = token.issued_at - 1; // negative window
        assert!(!token.has_valid_window());
    }

    #[test]
    fn test_token_audience_contains() {
        let token = root_token("root-1", 0);
        assert!(token.audience_contains("kernel-A"));
        assert!(token.audience_contains("kernel-B"));
        assert!(!token.audience_contains("kernel-C"));
    }

    #[test]
    fn test_token_serde_roundtrip() {
        let token = root_token("root-1", 3);
        let json = serde_json::to_string(&token).unwrap();
        let parsed = serde_json::from_str::<AudienceBoundToken>(&json).unwrap();
        assert_eq!(parsed, token);
    }

    // -- TokenError --

    #[test]
    fn test_error_display() {
        let err = TokenError::attenuation_violation("test violation");
        let s = format!("{}", err);
        assert!(s.contains(ERR_ABT_ATTENUATION_VIOLATION));
        assert!(s.contains("test violation"));
    }

    #[test]
    fn test_error_audience_mismatch() {
        let err = TokenError::audience_mismatch("kernel-C", &["kernel-A".to_string()]);
        assert_eq!(err.code, ERR_ABT_AUDIENCE_MISMATCH);
        assert!(err.message.contains("kernel-C"));
    }

    #[test]
    fn test_error_token_expired() {
        let err = TokenError::token_expired(&TokenId::new("tok-1"));
        assert_eq!(err.code, ERR_ABT_TOKEN_EXPIRED);
    }

    #[test]
    fn test_error_replay_detected() {
        let err = TokenError::replay_detected("nonce-abc");
        assert_eq!(err.code, ERR_ABT_REPLAY_DETECTED);
        assert!(err.message.contains("nonce-abc"));
    }

    #[test]
    fn test_error_signature_invalid() {
        let err = TokenError::signature_invalid(&TokenId::new("tok-1"), "forged");
        assert_eq!(err.code, ERR_ABT_SIGNATURE_INVALID);
        assert!(err.message.contains("tok-1"));
        assert!(err.message.contains("forged"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let err = TokenError::new("TEST", "test message");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: TokenError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    // -- TokenChain --

    #[test]
    fn test_chain_new_root() {
        let root = root_token("root-1", 3);
        let chain = TokenChain::new(root.clone()).unwrap();
        assert_eq!(chain.depth(), 1);
        assert_eq!(chain.root().unwrap().token_id, root.token_id);
        assert_eq!(chain.leaf().unwrap().token_id, root.token_id);
    }

    #[test]
    fn test_chain_rejects_non_root_first() {
        let mut token = root_token("root-1", 3);
        token.parent_token_hash = Some("invalid-hash".to_string());
        let err = TokenChain::new(token).unwrap_err();
        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
    }

    #[test]
    fn test_chain_single_hop_delegation() {
        let root = root_token("root-1", 3);
        let child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child).unwrap();
        assert_eq!(chain.depth(), 2);
    }

    #[test]
    fn test_chain_multi_hop_delegation() {
        let root = root_token("root-1", 5);
        let mut chain = TokenChain::new(root.clone()).unwrap();

        let c1 = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string(), "kernel-B".to_string()],
            narrow_caps(),
        );
        chain.append(c1.clone()).unwrap();

        let c2 = delegate_token(
            &c1,
            "child-2",
            vec!["kernel-A".to_string()],
            single_cap(ActionScope::Migrate),
        );
        chain.append(c2.clone()).unwrap();

        let c3 = delegate_token(
            &c2,
            "child-3",
            vec!["kernel-A".to_string()],
            single_cap(ActionScope::Migrate),
        );
        chain.append(c3).unwrap();

        assert_eq!(chain.depth(), 4);
    }

    #[test]
    fn test_chain_audience_escalation_rejected() {
        let root = root_token("root-1", 3);
        let child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string(), "kernel-C".to_string()], // kernel-C not in parent
            narrow_caps(),
        );
        let mut chain = TokenChain::new(root).unwrap();
        let err = chain.append(child).unwrap_err();
        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
        assert!(err.message.contains("kernel-C"));
    }

    #[test]
    fn test_chain_scope_escalation_rejected() {
        // Parent only has narrow caps (Migrate, Rollback). Child tries to add Configure.
        let root = root_token("root-1", 3);
        let narrow_root = AudienceBoundToken {
            capabilities: narrow_caps(),
            ..root.clone()
        };
        let mut all_plus_configure = narrow_caps();
        all_plus_configure.insert(ActionScope::Configure); // wider than parent
        let child = delegate_token(
            &narrow_root,
            "child-1",
            vec!["kernel-A".to_string()],
            all_plus_configure,
        );
        let mut chain = TokenChain::new(narrow_root).unwrap();
        let err = chain.append(child).unwrap_err();
        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
    }

    #[test]
    fn test_chain_depth_limit_exceeded() {
        let root = root_token("root-1", 1); // max depth 1 => root + 1 child max
        let child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child.clone()).unwrap();
        // Third token should fail
        let grandchild = delegate_token(
            &child,
            "child-2",
            vec!["kernel-A".to_string()],
            single_cap(ActionScope::Migrate),
        );
        let err = chain.append(grandchild).unwrap_err();
        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
        assert!(err.message.contains("max_delegation_depth"));
    }

    #[test]
    fn test_chain_zero_validity_rejected() {
        let root = root_token("root-1", 3);
        let mut child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.expires_at = child.issued_at; // zero validity
        // Need to recompute parent_token_hash since child changed
        child.parent_token_hash = Some(root.hash());
        let mut chain = TokenChain::new(root).unwrap();
        let err = chain.append(child).unwrap_err();
        assert_eq!(err.code, ERR_ABT_TOKEN_EXPIRED);
    }

    #[test]
    fn test_chain_root_zero_validity_rejected() {
        let mut root = root_token("root-1", 0);
        root.expires_at = root.issued_at;
        let err = TokenChain::new(root).unwrap_err();
        assert_eq!(err.code, ERR_ABT_TOKEN_EXPIRED);
    }

    #[test]
    fn test_chain_forged_parent_hash() {
        let root = root_token("root-1", 3);
        let mut child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.parent_token_hash = Some("forged-hash-value".to_string());
        let mut chain = TokenChain::new(root).unwrap();
        let err = chain.append(child).unwrap_err();
        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
        assert!(err.message.contains("mismatch"));
    }

    #[test]
    fn test_chain_missing_parent_hash_on_delegate() {
        let root = root_token("root-1", 3);
        let mut child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.parent_token_hash = None;
        let mut chain = TokenChain::new(root).unwrap();
        let err = chain.append(child).unwrap_err();
        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
    }

    #[test]
    fn test_chain_empty_capabilities_valid() {
        // Fully attenuated token (grants nothing) is valid.
        let root = root_token("root-1", 3);
        let child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            BTreeSet::new(),
        );
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child).unwrap();
        assert!(chain.leaf().unwrap().capabilities.is_empty());
    }

    #[test]
    fn test_chain_tokens_accessor() {
        let root = root_token("root-1", 3);
        let chain = TokenChain::new(root).unwrap();
        assert_eq!(chain.tokens().len(), 1);
    }

    #[test]
    fn test_chain_depth_20() {
        let root = root_token("root-1", 25);
        let mut chain = TokenChain::new(root.clone()).unwrap();
        let mut prev = root;
        for i in 1..=20 {
            let child = delegate_token(
                &prev,
                &format!("child-{}", i),
                vec!["kernel-A".to_string(), "kernel-B".to_string()],
                narrow_caps(),
            );
            chain.append(child.clone()).unwrap();
            prev = child;
        }
        assert_eq!(chain.depth(), 21);
    }

    // -- TokenValidator --

    #[test]
    fn test_validator_new() {
        let v = TokenValidator::new(1);
        assert_eq!(v.epoch_id(), 1);
        assert_eq!(v.tokens_issued(), 0);
        assert_eq!(v.tokens_verified(), 0);
        assert_eq!(v.tokens_rejected(), 0);
    }

    #[test]
    fn test_validator_record_issuance() {
        let mut v = trusted_validator(1);
        let token = root_token("root-1", 0);
        v.record_issuance(&token, "trace-1", 1000);
        assert_eq!(v.tokens_issued(), 1);
        assert_eq!(v.events().len(), 1);
        assert_eq!(v.events()[0].event_code, ABT_001);
    }

    #[test]
    fn test_validator_record_delegation() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 3);
        let child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        v.record_delegation(&child, 2, "trace-1", 2000);
        assert_eq!(v.tokens_delegated(), 1);
        assert_eq!(v.events()[0].event_code, ABT_002);
    }

    #[test]
    fn test_validator_verify_chain_success() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 3);
        let child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child).unwrap();

        v.verify_chain(&chain, "kernel-A", 50_000, "trace-1")
            .unwrap();
        assert_eq!(v.tokens_verified(), 1);
    }

    #[test]
    fn test_validator_rejects_untrusted_issuer_signature() {
        let mut v = TokenValidator::new(1);
        let root = root_token("root-untrusted", 0);
        let chain = TokenChain::new(root).unwrap();

        let err = v
            .verify_chain(&chain, "kernel-A", 50_000, "trace-untrusted")
            .unwrap_err();

        assert_eq!(err.code, ERR_ABT_SIGNATURE_INVALID);
        assert_eq!(v.tokens_rejected(), 1);
        assert_eq!(v.tokens_verified(), 0);
    }

    #[test]
    fn test_validator_rejects_forged_non_empty_signature() {
        let mut v = trusted_validator(1);
        let mut root = root_token("root-forged-signature", 0);
        root.signature = "not-a-valid-ed25519-signature".to_string();
        let chain = TokenChain::new(root).unwrap();

        let err = v
            .verify_chain(&chain, "kernel-A", 50_000, "trace-forged")
            .unwrap_err();

        assert_eq!(err.code, ERR_ABT_SIGNATURE_INVALID);
        assert_eq!(v.tokens_rejected(), 1);
        assert_eq!(v.tokens_verified(), 0);
    }

    #[test]
    fn test_validator_rejects_signed_field_tampering() {
        let mut v = trusted_validator(1);
        let mut root = root_token("root-tampered", 0);
        root.audience = vec!["kernel-A".to_string(), "kernel-C".to_string()];
        let chain = TokenChain::new(root).unwrap();

        let err = v
            .verify_chain(&chain, "kernel-C", 50_000, "trace-tampered")
            .unwrap_err();

        assert_eq!(err.code, ERR_ABT_SIGNATURE_INVALID);
        assert_eq!(v.tokens_rejected(), 1);
        assert_eq!(v.tokens_verified(), 0);
    }

    #[test]
    fn test_validator_audience_mismatch() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 0);
        let chain = TokenChain::new(root).unwrap();

        let err = v
            .verify_chain(&chain, "kernel-C", 50_000, "trace-1")
            .unwrap_err();
        assert_eq!(err.code, ERR_ABT_AUDIENCE_MISMATCH);
        assert_eq!(v.tokens_rejected(), 1);
    }

    #[test]
    fn test_validator_expired_token_rejected() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 0);
        let chain = TokenChain::new(root).unwrap();

        let err = v
            .verify_chain(&chain, "kernel-A", 200_000, "trace-1")
            .unwrap_err();
        assert_eq!(err.code, ERR_ABT_TOKEN_EXPIRED);
        assert_eq!(v.tokens_rejected(), 1);
    }

    #[test]
    fn test_validator_expired_intermediate_rejected() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 3);
        let mut child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.expires_at = 2000; // expires much sooner
        child.parent_token_hash = Some(root.hash());
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child).unwrap();

        let err = v
            .verify_chain(&chain, "kernel-A", 5000, "trace-1")
            .unwrap_err();
        assert_eq!(err.code, ERR_ABT_TOKEN_EXPIRED);
    }

    #[test]
    fn test_validator_nonce_replay_detected() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 0);
        let chain = TokenChain::new(root).unwrap();

        v.verify_chain(&chain, "kernel-A", 50_000, "trace-1")
            .unwrap();

        // Same chain again => nonce replay.
        let root2 = root_token("root-1", 0); // same nonce
        let chain2 = TokenChain::new(root2).unwrap();
        let err = v
            .verify_chain(&chain2, "kernel-A", 50_000, "trace-2")
            .unwrap_err();
        assert_eq!(err.code, ERR_ABT_REPLAY_DETECTED);
    }

    #[test]
    fn test_validator_advance_epoch_clears_nonces() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 0);
        let chain = TokenChain::new(root).unwrap();
        v.verify_chain(&chain, "kernel-A", 50_000, "trace-1")
            .unwrap();

        v.advance_epoch(2);
        assert_eq!(v.epoch_id(), 2);
        assert_eq!(v.nonce_count(), 0);

        // Same nonce now allowed in new epoch.
        let root2 = root_token("root-1", 0);
        let chain2 = TokenChain::new(root2).unwrap();
        v.verify_chain(&chain2, "kernel-A", 50_000, "trace-2")
            .unwrap();
    }

    #[test]
    fn test_validator_check_audience_pass() {
        let v = trusted_validator(1);
        let token = root_token("root-1", 0);
        v.check_audience(&token, "kernel-A").unwrap();
    }

    #[test]
    fn test_validator_check_audience_fail() {
        let v = trusted_validator(1);
        let token = root_token("root-1", 0);
        let err = v.check_audience(&token, "kernel-C").unwrap_err();
        assert_eq!(err.code, ERR_ABT_AUDIENCE_MISMATCH);
    }

    #[test]
    fn test_validator_take_events_drains() {
        let mut v = trusted_validator(1);
        let token = root_token("root-1", 0);
        v.record_issuance(&token, "trace-1", 1000);
        assert_eq!(v.events().len(), 1);
        let drained = v.take_events();
        assert_eq!(drained.len(), 1);
        assert!(v.events().is_empty());
    }

    #[test]
    fn test_validator_chain_integrity_violation() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 3);
        let mut child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        // Corrupt the parent_token_hash manually in the chain tokens.
        // We must bypass TokenChain::append since it checks integrity.
        // Build chain manually:
        child.parent_token_hash = Some("tampered-hash".to_string());
        let chain = TokenChain {
            tokens: vec![root, child],
        };

        let err = v
            .verify_chain(&chain, "kernel-A", 50_000, "trace-1")
            .unwrap_err();
        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
    }

    #[test]
    fn test_validator_verify_deep_chain() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 25);
        let mut chain = TokenChain::new(root.clone()).unwrap();
        let mut prev = root;
        for i in 1..=10 {
            let child = delegate_token(
                &prev,
                &format!("child-{}", i),
                vec!["kernel-A".to_string(), "kernel-B".to_string()],
                narrow_caps(),
            );
            chain.append(child.clone()).unwrap();
            prev = child;
        }
        v.verify_chain(&chain, "kernel-A", 50_000, "trace-1")
            .unwrap();
        assert_eq!(v.tokens_verified(), 1);
    }

    // -- Event codes defined --

    #[test]
    fn test_event_codes_defined() {
        assert!(!ABT_001.is_empty());
        assert!(!ABT_002.is_empty());
        assert!(!ABT_003.is_empty());
        assert!(!ABT_004.is_empty());
    }

    // -- Error codes defined --

    #[test]
    fn test_error_codes_defined() {
        assert!(!ERR_ABT_ATTENUATION_VIOLATION.is_empty());
        assert!(!ERR_ABT_AUDIENCE_MISMATCH.is_empty());
        assert!(!ERR_ABT_TOKEN_EXPIRED.is_empty());
        assert!(!ERR_ABT_REPLAY_DETECTED.is_empty());
        assert!(!ERR_ABT_SIGNATURE_INVALID.is_empty());
    }

    // -- Invariant tags defined --

    #[test]
    fn test_invariant_tags_defined() {
        assert!(!INV_ABT_ATTENUATION.is_empty());
        assert!(!INV_ABT_AUDIENCE.is_empty());
        assert!(!INV_ABT_EXPIRY.is_empty());
        assert!(!INV_ABT_REPLAY.is_empty());
    }

    // -- Additional attenuation tests --

    #[test]
    fn test_delegate_with_all_parent_caps() {
        let root = root_token("root-1", 3);
        let child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            ActionScope::all(), // same as parent => valid (subset)
        );
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child).unwrap();
    }

    #[test]
    fn test_chain_serde_roundtrip() {
        let root = root_token("root-1", 3);
        let child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child).unwrap();
        let json = serde_json::to_string(&chain).unwrap();
        let parsed: TokenChain = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.depth(), 2);
    }

    #[test]
    fn test_token_event_serde_roundtrip() {
        let ev = TokenEvent {
            event_code: ABT_001.to_string(),
            token_id: "tok-1".to_string(),
            trace_id: "tr-1".to_string(),
            epoch_id: 42,
            action_id: "issue-tok-1".to_string(),
            detail: "test event".to_string(),
            timestamp_ms: 1000,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let parsed: TokenEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, ABT_001);
    }

    #[test]
    fn test_validator_metrics_accumulate() {
        let mut v = trusted_validator(1);

        let t1 = root_token("root-1", 0);
        v.record_issuance(&t1, "tr", 1000);

        let t2 = AudienceBoundToken {
            token_id: TokenId::new("root-2"),
            nonce: format!("nonce-{}", "root-2"),
            signature: format!("sig-{}", "root-2"),
            ..t1.clone()
        };
        v.record_issuance(&t2, "tr", 1000);

        assert_eq!(v.tokens_issued(), 2);
        assert_eq!(v.tokens_delegated(), 0);
    }

    #[test]
    fn test_verify_rejects_after_leaf_audience_narrowed() {
        let mut v = trusted_validator(1);
        let root = root_token("root-1", 3);
        let child = delegate_token(
            &root,
            "child-1",
            vec!["kernel-A".to_string()], // narrowed from [kernel-A, kernel-B]
            narrow_caps(),
        );
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child).unwrap();

        // kernel-B is in root audience but not in leaf
        let err = v
            .verify_chain(&chain, "kernel-B", 50_000, "trace-1")
            .unwrap_err();
        assert_eq!(err.code, ERR_ABT_AUDIENCE_MISMATCH);
    }

    #[test]
    fn test_cross_audience_replay_rejected() {
        let mut v = trusted_validator(1);

        // First: verify for kernel-A
        let root = root_token("root-1", 0);
        let chain = TokenChain::new(root).unwrap();
        v.verify_chain(&chain, "kernel-A", 50_000, "trace-1")
            .unwrap();

        // Same token replay for kernel-B
        let root2 = root_token("root-1", 0); // same nonce
        let chain2 = TokenChain::new(root2).unwrap();
        let err = v
            .verify_chain(&chain2, "kernel-B", 50_000, "trace-2")
            .unwrap_err();
        assert_eq!(err.code, ERR_ABT_REPLAY_DETECTED);
    }

    #[test]
    fn test_deserialize_empty_chain_rejected() {
        let err = serde_json::from_str::<TokenChain>(r#"{"tokens":[]}"#).unwrap_err();

        assert!(err.to_string().contains("token chain cannot be empty"));
    }

    #[test]
    fn test_deserialize_non_root_first_rejected() {
        let mut token = root_token("root-with-parent", 3);
        token.parent_token_hash = Some("unexpected-parent-link".to_string());
        let json = serde_json::json!({ "tokens": [token] }).to_string();

        let err = serde_json::from_str::<TokenChain>(&json).unwrap_err();

        assert!(err.to_string().contains("First token in chain"));
    }

    #[test]
    fn test_deserialize_mismatched_delegate_parent_rejected() {
        let root = root_token("root-1", 3);
        let mut child = delegate_token(
            &root,
            "child-mismatch",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.parent_token_hash = Some("wrong-parent-link".to_string());
        let json = serde_json::json!({ "tokens": [root, child] }).to_string();

        let err = serde_json::from_str::<TokenChain>(&json).unwrap_err();

        assert!(err.to_string().contains("parent_token_hash mismatch"));
    }

    #[test]
    fn test_append_child_issued_before_parent_rejected() {
        let root = root_token("root-1", 3);
        let mut child = delegate_token(
            &root,
            "child-issued-before-parent",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.issued_at = root.issued_at.saturating_sub(1);
        child.parent_token_hash = Some(root.hash());
        let mut chain = TokenChain::new(root).unwrap();

        let err = chain.append(child).unwrap_err();

        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
        assert!(err.message.contains("issued_at"));
    }

    #[test]
    fn test_append_child_outliving_parent_rejected() {
        let root = root_token("root-1", 3);
        let mut child = delegate_token(
            &root,
            "child-outlives-parent",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.expires_at = root.expires_at.saturating_add(1);
        child.parent_token_hash = Some(root.hash());
        let mut chain = TokenChain::new(root).unwrap();

        let err = chain.append(child).unwrap_err();

        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
        assert!(err.message.contains("expires_at"));
    }

    #[test]
    fn test_append_child_with_equal_delegation_depth_rejected() {
        let root = root_token("root-1", 3);
        let mut child = delegate_token(
            &root,
            "child-equal-depth",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.max_delegation_depth = root.max_delegation_depth;
        child.parent_token_hash = Some(root.hash());
        let mut chain = TokenChain::new(root).unwrap();

        let err = chain.append(child).unwrap_err();

        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
        assert!(err.message.contains("strictly less"));
    }

    #[test]
    fn test_verify_empty_manual_chain_rejected() {
        let mut v = trusted_validator(1);
        let chain = TokenChain { tokens: Vec::new() };

        let err = v
            .verify_chain(&chain, "kernel-A", 50_000, "trace-empty")
            .unwrap_err();

        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
        assert_eq!(v.tokens_verified(), 0);
        assert!(v.events().is_empty());
    }

    #[test]
    fn test_verify_invalid_window_manual_chain_rejected() {
        let mut v = trusted_validator(1);
        let mut root = root_token("root-invalid-window", 0);
        root.expires_at = root.issued_at;
        let chain = TokenChain { tokens: vec![root] };

        let err = v
            .verify_chain(&chain, "kernel-A", 999, "trace-invalid-window")
            .unwrap_err();

        assert_eq!(err.code, ERR_ABT_TOKEN_EXPIRED);
        assert_eq!(v.tokens_rejected(), 1);
        assert_eq!(v.nonce_count(), 0);
    }

    #[test]
    fn test_check_audience_empty_audience_rejected() {
        let v = trusted_validator(1);
        let mut token = root_token("root-empty-audience", 0);
        token.audience.clear();

        let err = v.check_audience(&token, "kernel-A").unwrap_err();

        assert_eq!(err.code, ERR_ABT_AUDIENCE_MISMATCH);
        assert!(err.message.contains("kernel-A"));
    }

    #[test]
    fn negative_action_scope_unknown_variant_is_rejected_by_serde() {
        let err = serde_json::from_str::<ActionScope>(r#""snapshot""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn negative_action_scope_wrong_case_is_rejected_by_serde() {
        let err = serde_json::from_str::<ActionScope>(r#""migrate""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn negative_token_missing_nonce_is_rejected_by_serde() {
        let token = root_token("root-missing-nonce", 0);
        let mut value = serde_json::to_value(token).expect("token should serialize");
        value
            .as_object_mut()
            .expect("token json should be an object")
            .remove("nonce");

        let err = serde_json::from_value::<AudienceBoundToken>(value).unwrap_err();

        assert!(err.to_string().contains("nonce"));
    }

    #[test]
    fn negative_token_wrong_expiry_type_is_rejected_by_serde() {
        let token = root_token("root-bad-expiry-type", 0);
        let mut value = serde_json::to_value(token).expect("token should serialize");
        value
            .as_object_mut()
            .expect("token json should be an object")
            .insert(
                "expires_at".to_string(),
                serde_json::Value::String("tomorrow".to_string()),
            );

        let err = serde_json::from_value::<AudienceBoundToken>(value).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_verify_expiry_boundary_precedes_nonce_replay_check() {
        let mut validator = trusted_validator(7);
        let root = root_token("root-expiry-precedence", 0);
        validator.record_issuance(&root, "trace-issued", root.issued_at);
        let chain = TokenChain::new(root.clone()).unwrap();

        let err = validator
            .verify_chain(
                &chain,
                "kernel-A",
                root.expires_at,
                "trace-expired-boundary",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_ABT_TOKEN_EXPIRED);
        assert_eq!(validator.tokens_rejected(), 1);
        assert_eq!(
            validator
                .events()
                .last()
                .map(|event| event.event_code.as_str()),
            Some(ABT_004)
        );
        assert!(
            validator
                .events()
                .last()
                .expect("rejection event should be recorded")
                .detail
                .contains("expired")
        );
    }

    #[test]
    fn negative_manual_child_without_parent_link_fails_chain_integrity() {
        let mut validator = trusted_validator(7);
        let root = root_token("root-manual-missing-parent", 3);
        let mut child = delegate_token(
            &root,
            "child-manual-missing-parent",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.parent_token_hash = None;
        let chain = TokenChain {
            tokens: vec![root, child],
        };

        let err = validator
            .verify_chain(&chain, "kernel-A", 50_000, "trace-missing-parent-link")
            .unwrap_err();

        assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
        assert!(err.message.contains("parent_token_hash mismatch"));
        assert_eq!(validator.tokens_rejected(), 1);
    }

    #[test]
    fn negative_check_audience_is_case_sensitive() {
        let validator = trusted_validator(7);
        let token = root_token("root-audience-case", 0);

        let err = validator.check_audience(&token, "KERNEL-A").unwrap_err();

        assert_eq!(err.code, ERR_ABT_AUDIENCE_MISMATCH);
        assert!(err.message.contains("KERNEL-A"));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_tokens_without_appending() {
        let mut tokens = vec![root_token("root-old", 0)];

        push_bounded(&mut tokens, root_token("root-new", 0), 0);

        assert!(tokens.is_empty());
    }

    #[test]
    fn push_bounded_single_capacity_evicts_oldest_token() {
        let mut tokens = vec![root_token("root-old", 0)];

        push_bounded(&mut tokens, root_token("root-new", 0), 1);

        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_id.as_str(), "root-new");
    }

    #[test]
    fn insert_nonce_bounded_zero_capacity_clears_existing_state() {
        let mut set = BTreeSet::new();
        let mut queue = VecDeque::new();
        set.insert("old-nonce".to_string());
        queue.push_back("old-nonce".to_string());

        insert_nonce_bounded(&mut set, &mut queue, "new-nonce".to_string(), 0);

        assert!(set.is_empty());
        assert!(queue.is_empty());
    }

    #[test]
    fn insert_nonce_bounded_duplicate_nonce_does_not_extend_queue() {
        let mut set = BTreeSet::new();
        let mut queue = VecDeque::new();

        insert_nonce_bounded(&mut set, &mut queue, "dup-nonce".to_string(), 4);
        insert_nonce_bounded(&mut set, &mut queue, "dup-nonce".to_string(), 4);

        assert_eq!(set.len(), 1);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.front().map(String::as_str), Some("dup-nonce"));
    }

    #[test]
    fn insert_nonce_bounded_capacity_evicts_oldest_nonce() {
        let mut set = BTreeSet::new();
        let mut queue = VecDeque::new();

        insert_nonce_bounded(&mut set, &mut queue, "nonce-a".to_string(), 2);
        insert_nonce_bounded(&mut set, &mut queue, "nonce-b".to_string(), 2);
        insert_nonce_bounded(&mut set, &mut queue, "nonce-c".to_string(), 2);

        assert!(!set.contains("nonce-a"));
        assert!(set.contains("nonce-b"));
        assert!(set.contains("nonce-c"));
        assert_eq!(
            queue.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["nonce-b", "nonce-c"]
        );
    }

    #[test]
    fn verify_chain_rejects_duplicate_nonce_inside_single_chain() {
        let mut validator = trusted_validator(8);
        let root = root_token("root-duplicate-nonce", 3);
        let mut child = delegate_token(
            &root,
            "child-duplicate-nonce",
            vec!["kernel-A".to_string()],
            narrow_caps(),
        );
        child.nonce = root.nonce.clone();
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child).unwrap();

        let err = validator
            .verify_chain(&chain, "kernel-A", 50_000, "trace-duplicate-nonce")
            .unwrap_err();

        assert_eq!(err.code, ERR_ABT_REPLAY_DETECTED);
        assert_eq!(validator.tokens_rejected(), 1);
        assert_eq!(validator.nonce_count(), 0);
        assert!(
            validator
                .events()
                .last()
                .expect("rejection event")
                .detail
                .contains("duplicated within token chain")
        );
    }

    #[test]
    fn verify_chain_empty_leaf_audience_rejected_without_nonce_recording() {
        let mut validator = trusted_validator(8);
        let root = root_token("root-empty-leaf-audience", 3);
        let child = delegate_token(&root, "child-empty-audience", Vec::new(), narrow_caps());
        let mut chain = TokenChain::new(root).unwrap();
        chain.append(child).unwrap();

        let err = validator
            .verify_chain(&chain, "kernel-A", 50_000, "trace-empty-audience")
            .unwrap_err();

        assert_eq!(err.code, ERR_ABT_AUDIENCE_MISMATCH);
        assert_eq!(validator.tokens_rejected(), 1);
        assert_eq!(validator.nonce_count(), 0);
    }
}
