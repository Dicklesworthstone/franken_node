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
use std::collections::BTreeSet;

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
    /// Compute the SHA-256 hash of this token for chain integrity.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.token_id.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(self.issuer.as_bytes());
        hasher.update(b"|");
        for aud in &self.audience {
            hasher.update(aud.as_bytes());
            hasher.update(b"|");
        }
        for cap in &self.capabilities {
            hasher.update(cap.label().as_bytes());
            hasher.update(b"|");
        }
        hasher.update(self.issued_at.to_le_bytes());
        hasher.update(b"|");
        hasher.update(self.expires_at.to_le_bytes());
        hasher.update(b"|");
        hasher.update(self.nonce.as_bytes());
        hasher.update(b"|");
        if let Some(ref ph) = self.parent_token_hash {
            hasher.update(ph.as_bytes());
        }
        hasher.update(b"|");
        hasher.update(self.signature.as_bytes());
        hasher.update(b"|");
        hasher.update([self.max_delegation_depth]);
        format!("{:x}", hasher.finalize())
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
        self.audience.iter().any(|a| a == service_id)
    }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenChain {
    tokens: Vec<AudienceBoundToken>,
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
        let parent = self.tokens.last().unwrap();

        // Check parent_token_hash links to parent.
        let parent_hash = parent.hash();
        match &token.parent_token_hash {
            Some(h) if h == &parent_hash => {}
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
        let root = &self.tokens[0];
        let max_chain_len = root.max_delegation_depth as usize + 1;
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

        // Validity window check.
        if !token.has_valid_window() {
            return Err(TokenError::new(
                ERR_ABT_TOKEN_EXPIRED,
                "Delegated token has zero or negative validity window",
            ));
        }

        self.tokens.push(token);
        Ok(())
    }

    /// Number of tokens in the chain (root = depth 1).
    pub fn depth(&self) -> usize {
        self.tokens.len()
    }

    /// The root token.
    pub fn root(&self) -> &AudienceBoundToken {
        &self.tokens[0]
    }

    /// The leaf (most recently delegated) token.
    pub fn leaf(&self) -> &AudienceBoundToken {
        self.tokens.last().unwrap()
    }

    /// All tokens in chain order.
    pub fn tokens(&self) -> &[AudienceBoundToken] {
        &self.tokens
    }
}

// ---------------------------------------------------------------------------
// TokenValidator
// ---------------------------------------------------------------------------

/// Validates audience-bound token chains, enforcing expiry, replay detection,
/// and audience matching.
pub struct TokenValidator {
    /// Nonces seen in the current epoch.
    seen_nonces: BTreeSet<String>,
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
            seen_nonces: BTreeSet::new(),
            epoch_id,
            events: Vec::new(),
            tokens_issued: 0,
            tokens_delegated: 0,
            tokens_verified: 0,
            tokens_rejected: 0,
        }
    }

    /// Record a root token issuance.
    pub fn record_issuance(&mut self, token: &AudienceBoundToken, trace_id: &str, now_ms: u64) {
        self.tokens_issued += 1;
        self.seen_nonces.insert(token.nonce.clone());
        self.events.push(TokenEvent {
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
        });
    }

    /// Record a delegation event.
    pub fn record_delegation(
        &mut self,
        token: &AudienceBoundToken,
        chain_depth: usize,
        trace_id: &str,
        now_ms: u64,
    ) {
        self.tokens_delegated += 1;
        self.seen_nonces.insert(token.nonce.clone());
        self.events.push(TokenEvent {
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
        });
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

        // Check all tokens for expiry.
        for (i, token) in tokens.iter().enumerate() {
            if token.is_expired(now_ms) {
                self.tokens_rejected += 1;
                let err = TokenError::token_expired(&token.token_id);
                self.events.push(TokenEvent {
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
                });
                return Err(err);
            }
        }

        // Check validity windows.
        for token in tokens.iter() {
            if !token.has_valid_window() {
                self.tokens_rejected += 1;
                return Err(TokenError::new(
                    ERR_ABT_TOKEN_EXPIRED,
                    format!(
                        "Token '{}' has zero or negative validity window (issued_at={}, expires_at={})",
                        token.token_id, token.issued_at, token.expires_at
                    ),
                ));
            }
        }

        // Check nonce replay.
        for token in tokens.iter() {
            if self.seen_nonces.contains(&token.nonce) {
                self.tokens_rejected += 1;
                let err = TokenError::replay_detected(&token.nonce);
                self.events.push(TokenEvent {
                    event_code: ABT_004.to_string(),
                    token_id: token.token_id.as_str().to_string(),
                    trace_id: trace_id.to_string(),
                    epoch_id: self.epoch_id,
                    action_id: format!("verify-replay-{}", token.token_id),
                    detail: format!("Nonce '{}' replay detected", token.nonce),
                    timestamp_ms: now_ms,
                });
                return Err(err);
            }
        }

        // Verify chain hash integrity.
        for i in 1..tokens.len() {
            let parent_hash = tokens[i - 1].hash();
            match &tokens[i].parent_token_hash {
                Some(h) if h == &parent_hash => {}
                _ => {
                    self.tokens_rejected += 1;
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

        // INV-ABT-AUDIENCE: Check audience match on leaf token.
        let leaf = chain.leaf();
        if !leaf.audience_contains(requester_id) {
            self.tokens_rejected += 1;
            let err = TokenError::audience_mismatch(requester_id, &leaf.audience);
            self.events.push(TokenEvent {
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
            });
            return Err(err);
        }

        // All checks passed: record nonces and emit success event.
        for token in tokens.iter() {
            self.seen_nonces.insert(token.nonce.clone());
        }
        self.tokens_verified += 1;
        self.events.push(TokenEvent {
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
        });

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
    use super::*;

    // -- Helpers --

    fn root_token(id: &str, depth: u8) -> AudienceBoundToken {
        AudienceBoundToken {
            token_id: TokenId::new(id),
            issuer: "issuer-1".to_string(),
            audience: vec!["kernel-A".to_string(), "kernel-B".to_string()],
            capabilities: ActionScope::all(),
            issued_at: 1000,
            expires_at: 100_000,
            nonce: format!("nonce-{}", id),
            parent_token_hash: None,
            signature: format!("sig-{}", id),
            max_delegation_depth: depth,
        }
    }

    fn delegate_token(
        parent: &AudienceBoundToken,
        id: &str,
        audience: Vec<String>,
        capabilities: BTreeSet<ActionScope>,
    ) -> AudienceBoundToken {
        AudienceBoundToken {
            token_id: TokenId::new(id),
            issuer: "delegator-1".to_string(),
            audience,
            capabilities,
            issued_at: parent.issued_at + 100,
            expires_at: parent.expires_at,
            nonce: format!("nonce-{}", id),
            parent_token_hash: Some(parent.hash()),
            signature: format!("sig-{}", id),
            max_delegation_depth: 0,
        }
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
        assert_eq!(t1.hash(), t2.hash());
    }

    #[test]
    fn test_token_hash_changes_with_id() {
        let t1 = root_token("root-1", 3);
        let t2 = root_token("root-2", 3);
        assert_ne!(t1.hash(), t2.hash());
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
        let parsed: AudienceBoundToken = serde_json::from_str(&json).unwrap();
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
        assert_eq!(chain.root().token_id, root.token_id);
        assert_eq!(chain.leaf().token_id, root.token_id);
    }

    #[test]
    fn test_chain_rejects_non_root_first() {
        let mut token = root_token("root-1", 3);
        token.parent_token_hash = Some("fake-hash".to_string());
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
        assert!(chain.leaf().capabilities.is_empty());
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
        let mut v = TokenValidator::new(1);
        let token = root_token("root-1", 0);
        v.record_issuance(&token, "trace-1", 1000);
        assert_eq!(v.tokens_issued(), 1);
        assert_eq!(v.events().len(), 1);
        assert_eq!(v.events()[0].event_code, ABT_001);
    }

    #[test]
    fn test_validator_record_delegation() {
        let mut v = TokenValidator::new(1);
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
        let mut v = TokenValidator::new(1);
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
    fn test_validator_audience_mismatch() {
        let mut v = TokenValidator::new(1);
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
        let mut v = TokenValidator::new(1);
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
        let mut v = TokenValidator::new(1);
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
        let mut v = TokenValidator::new(1);
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
        let mut v = TokenValidator::new(1);
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
        let v = TokenValidator::new(1);
        let token = root_token("root-1", 0);
        v.check_audience(&token, "kernel-A").unwrap();
    }

    #[test]
    fn test_validator_check_audience_fail() {
        let v = TokenValidator::new(1);
        let token = root_token("root-1", 0);
        let err = v.check_audience(&token, "kernel-C").unwrap_err();
        assert_eq!(err.code, ERR_ABT_AUDIENCE_MISMATCH);
    }

    #[test]
    fn test_validator_take_events_drains() {
        let mut v = TokenValidator::new(1);
        let token = root_token("root-1", 0);
        v.record_issuance(&token, "trace-1", 1000);
        assert_eq!(v.events().len(), 1);
        let drained = v.take_events();
        assert_eq!(drained.len(), 1);
        assert!(v.events().is_empty());
    }

    #[test]
    fn test_validator_chain_integrity_violation() {
        let mut v = TokenValidator::new(1);
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
        let mut v = TokenValidator::new(1);
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
        let mut v = TokenValidator::new(1);

        let t1 = root_token("root-1", 0);
        v.record_issuance(&t1, "tr", 1000);

        let t2 = AudienceBoundToken {
            token_id: TokenId::new("root-2"),
            nonce: "nonce-root-2".to_string(),
            signature: "sig-root-2".to_string(),
            ..t1.clone()
        };
        v.record_issuance(&t2, "tr", 1000);

        assert_eq!(v.tokens_issued(), 2);
        assert_eq!(v.tokens_delegated(), 0);
    }

    #[test]
    fn test_verify_rejects_after_leaf_audience_narrowed() {
        let mut v = TokenValidator::new(1);
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
        let mut v = TokenValidator::new(1);

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
}
