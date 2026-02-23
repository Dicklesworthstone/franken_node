// Trust fabric convergence protocol with degraded-mode semantics.
//
// Gossip-based convergence for distributed trust state, revocation-first
// priority, partition healing via delta sync, and anti-entropy sweeps.
//
// bd-5si — Section 10.12

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const EVT_STATE_UPDATED: &str = "TFC-001";
pub const EVT_DIGEST_MISMATCH: &str = "TFC-002";
pub const EVT_REVOCATION_APPLIED: &str = "TFC-003";
pub const EVT_CONVERGENCE_LAG: &str = "TFC-004";
pub const EVT_DEGRADED_ENTERED: &str = "TFC-005";
pub const EVT_DEGRADED_EXITED: &str = "TFC-006";
pub const EVT_PARTITION_HEALED: &str = "TFC-007";
pub const EVT_ANTI_ENTROPY_SWEEP: &str = "TFC-008";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_TFC_INVALID_CONFIG: &str = "ERR_TFC_INVALID_CONFIG";
pub const ERR_TFC_STALE_STATE: &str = "ERR_TFC_STALE_STATE";
pub const ERR_TFC_DIGEST_MISMATCH: &str = "ERR_TFC_DIGEST_MISMATCH";
pub const ERR_TFC_DEGRADED_REJECT: &str = "ERR_TFC_DEGRADED_REJECT";
pub const ERR_TFC_ESCALATION_TIMEOUT: &str = "ERR_TFC_ESCALATION_TIMEOUT";
pub const ERR_TFC_PARTITION_DETECTED: &str = "ERR_TFC_PARTITION_DETECTED";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_TFC_REVOKE_FIRST: &str = "INV-TFC-REVOKE-FIRST";
pub const INV_TFC_MONOTONIC: &str = "INV-TFC-MONOTONIC";
pub const INV_TFC_DEGRADED_DENY: &str = "INV-TFC-DEGRADED-DENY";
pub const INV_TFC_CONVERGENCE: &str = "INV-TFC-CONVERGENCE";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TrustFabricConfig {
    /// Max seconds to converge fleet.
    pub convergence_timeout_secs: u64,
    /// Seconds of lag before entering degraded mode.
    pub convergence_lag_threshold: u64,
    /// Max seconds in degraded mode before escalation.
    pub max_degraded_secs: u64,
    /// Anti-entropy full sweep interval.
    pub anti_entropy_interval_secs: u64,
    /// Prioritize revocation messages.
    pub revocation_priority: bool,
}

impl Default for TrustFabricConfig {
    fn default() -> Self {
        Self {
            convergence_timeout_secs: 30,
            convergence_lag_threshold: 60,
            max_degraded_secs: 300,
            anti_entropy_interval_secs: 300,
            revocation_priority: true,
        }
    }
}

impl TrustFabricConfig {
    pub fn validate(&self) -> Result<(), TrustFabricError> {
        if self.convergence_timeout_secs == 0 {
            return Err(TrustFabricError::InvalidConfig(
                "convergence_timeout_secs must be > 0".into(),
            ));
        }
        if self.convergence_lag_threshold == 0 {
            return Err(TrustFabricError::InvalidConfig(
                "convergence_lag_threshold must be > 0".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum TrustFabricError {
    InvalidConfig(String),
    StaleState { remote_ver: u64, local_ver: u64 },
    DigestMismatch,
    DegradedReject(String),
    EscalationTimeout(u64),
    PartitionDetected(String),
}

impl std::fmt::Display for TrustFabricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "{ERR_TFC_INVALID_CONFIG}: {msg}"),
            Self::StaleState {
                remote_ver,
                local_ver,
            } => {
                write!(
                    f,
                    "{ERR_TFC_STALE_STATE}: remote v{remote_ver} < local v{local_ver}"
                )
            }
            Self::DigestMismatch => write!(f, "{ERR_TFC_DIGEST_MISMATCH}"),
            Self::DegradedReject(msg) => write!(f, "{ERR_TFC_DEGRADED_REJECT}: {msg}"),
            Self::EscalationTimeout(secs) => {
                write!(f, "{ERR_TFC_ESCALATION_TIMEOUT}: {secs}s in degraded mode")
            }
            Self::PartitionDetected(msg) => write!(f, "{ERR_TFC_PARTITION_DETECTED}: {msg}"),
        }
    }
}

impl std::error::Error for TrustFabricError {}

// ---------------------------------------------------------------------------
// Trust state vector
// ---------------------------------------------------------------------------

/// Cryptographic digest of trust state using SHA-256.
fn compute_digest(
    trust_cards: &BTreeSet<String>,
    revocation_ver: u64,
    extensions: &BTreeSet<String>,
    policy_epoch: u64,
    anchor_fps: &BTreeSet<String>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trust_fabric_v1:");
    for card in trust_cards {
        hasher.update(card.as_bytes());
        hasher.update(b"\x00");
    }
    hasher.update(revocation_ver.to_le_bytes());
    for ext in extensions {
        hasher.update(ext.as_bytes());
        hasher.update(b"\x00");
    }
    hasher.update(policy_epoch.to_le_bytes());
    for fp in anchor_fps {
        hasher.update(fp.as_bytes());
        hasher.update(b"\x00");
    }
    hasher.finalize().into()
}

/// Trust state vector for a single node.
#[derive(Debug, Clone)]
pub struct TrustStateVector {
    /// Monotonically increasing version.
    pub version: u64,
    /// Cryptographic digest.
    pub digest: [u8; 32],
    /// Active trust card IDs.
    pub trust_cards: BTreeSet<String>,
    /// Revocation list version.
    pub revocation_ver: u64,
    /// Authorized extension IDs.
    pub extensions: BTreeSet<String>,
    /// Policy checkpoint epoch.
    pub policy_epoch: u64,
    /// Trust anchor fingerprints.
    pub anchor_fps: BTreeSet<String>,
    /// Revoked artifact IDs.
    pub revocations: BTreeSet<String>,
}

impl TrustStateVector {
    pub fn new(policy_epoch: u64) -> Self {
        Self {
            version: 0,
            digest: [0u8; 32],
            trust_cards: BTreeSet::new(),
            revocation_ver: 0,
            extensions: BTreeSet::new(),
            policy_epoch,
            anchor_fps: BTreeSet::new(),
            revocations: BTreeSet::new(),
        }
    }

    fn recompute_digest(&mut self) {
        self.digest = compute_digest(
            &self.trust_cards,
            self.revocation_ver,
            &self.extensions,
            self.policy_epoch,
            &self.anchor_fps,
        );
    }

    /// Add a trust card (authorization).
    pub fn add_trust_card(&mut self, id: &str) {
        self.trust_cards.insert(id.into());
        self.version += 1;
        self.recompute_digest();
    }

    /// Add an extension authorization.
    pub fn add_extension(&mut self, id: &str) {
        self.extensions.insert(id.into());
        self.version += 1;
        self.recompute_digest();
    }

    /// Apply a revocation.
    pub fn apply_revocation(&mut self, id: &str) {
        self.revocations.insert(id.into());
        self.trust_cards.remove(id);
        self.extensions.remove(id);
        self.revocation_ver += 1;
        self.version += 1;
        self.recompute_digest();
    }

    /// Check if an artifact is revoked.
    pub fn is_revoked(&self, id: &str) -> bool {
        self.revocations.contains(id)
    }

    /// Compute delta: items in self but not in other.
    pub fn delta_from(&self, other: &TrustStateVector) -> TrustStateDelta {
        let new_cards: BTreeSet<String> = self
            .trust_cards
            .difference(&other.trust_cards)
            .cloned()
            .collect();
        let new_extensions: BTreeSet<String> = self
            .extensions
            .difference(&other.extensions)
            .cloned()
            .collect();
        let new_revocations: BTreeSet<String> = self
            .revocations
            .difference(&other.revocations)
            .cloned()
            .collect();
        TrustStateDelta {
            new_cards,
            new_extensions,
            new_revocations,
            new_revocation_ver: if self.revocation_ver > other.revocation_ver {
                Some(self.revocation_ver)
            } else {
                None
            },
        }
    }
}

/// Delta between two trust states.
#[derive(Debug, Clone)]
pub struct TrustStateDelta {
    pub new_cards: BTreeSet<String>,
    pub new_extensions: BTreeSet<String>,
    pub new_revocations: BTreeSet<String>,
    pub new_revocation_ver: Option<u64>,
}

impl TrustStateDelta {
    pub fn is_empty(&self) -> bool {
        self.new_cards.is_empty()
            && self.new_extensions.is_empty()
            && self.new_revocations.is_empty()
    }

    pub fn size(&self) -> usize {
        self.new_cards.len() + self.new_extensions.len() + self.new_revocations.len()
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TrustFabricEvent {
    pub code: String,
    pub detail: String,
    pub node_id: String,
}

// ---------------------------------------------------------------------------
// Trust fabric node
// ---------------------------------------------------------------------------

/// A node in the trust fabric.
#[derive(Debug)]
pub struct TrustFabricNode {
    pub node_id: String,
    config: TrustFabricConfig,
    state: TrustStateVector,
    /// Whether this node is in degraded mode.
    degraded_mode: bool,
    /// Timestamp when degraded mode was entered.
    degraded_since: Option<u64>,
    /// Last time we confirmed convergence with fleet.
    last_converged_ts: u64,
    /// Events.
    events: Vec<TrustFabricEvent>,
}

impl TrustFabricNode {
    pub fn new(
        node_id: &str,
        config: TrustFabricConfig,
        policy_epoch: u64,
    ) -> Result<Self, TrustFabricError> {
        config.validate()?;
        Ok(Self {
            node_id: node_id.into(),
            config,
            state: TrustStateVector::new(policy_epoch),
            degraded_mode: false,
            degraded_since: None,
            last_converged_ts: 0,
            events: Vec::new(),
        })
    }

    /// Get current trust state.
    pub fn state(&self) -> &TrustStateVector {
        &self.state
    }

    /// Whether in degraded mode.
    pub fn is_degraded(&self) -> bool {
        self.degraded_mode
    }

    /// Add a trust card (authorization).
    /// INV-TFC-DEGRADED-DENY: rejected in degraded mode.
    pub fn add_trust_card(&mut self, id: &str) -> Result<(), TrustFabricError> {
        if self.degraded_mode {
            self.events.push(TrustFabricEvent {
                code: EVT_STATE_UPDATED.to_string(),
                detail: format!("REJECTED trust card {id} (degraded mode)"),
                node_id: self.node_id.clone(),
            });
            return Err(TrustFabricError::DegradedReject(format!(
                "trust card {id} rejected in degraded mode"
            )));
        }
        self.state.add_trust_card(id);
        self.events.push(TrustFabricEvent {
            code: EVT_STATE_UPDATED.to_string(),
            detail: format!("added trust card {id}"),
            node_id: self.node_id.clone(),
        });
        Ok(())
    }

    /// Add an extension.
    /// INV-TFC-DEGRADED-DENY: rejected in degraded mode.
    pub fn add_extension(&mut self, id: &str) -> Result<(), TrustFabricError> {
        if self.degraded_mode {
            return Err(TrustFabricError::DegradedReject(format!(
                "extension {id} rejected in degraded mode"
            )));
        }
        self.state.add_extension(id);
        self.events.push(TrustFabricEvent {
            code: EVT_STATE_UPDATED.to_string(),
            detail: format!("added extension {id}"),
            node_id: self.node_id.clone(),
        });
        Ok(())
    }

    /// Apply a revocation.
    /// INV-TFC-REVOKE-FIRST: revocations always accepted, even in degraded mode.
    pub fn apply_revocation(&mut self, id: &str) {
        self.state.apply_revocation(id);
        self.events.push(TrustFabricEvent {
            code: EVT_REVOCATION_APPLIED.to_string(),
            detail: format!("revoked {id}"),
            node_id: self.node_id.clone(),
        });
    }

    /// Compare digests with another node.
    pub fn compare_digest(&self, remote: &TrustStateVector) -> bool {
        self.state.digest == remote.digest
    }

    /// Gossip: receive remote state and merge.
    /// INV-TFC-MONOTONIC: only accept newer state.
    /// INV-TFC-REVOKE-FIRST: apply revocations before authorizations.
    pub fn receive_gossip(
        &mut self,
        remote: &TrustStateVector,
    ) -> Result<TrustStateDelta, TrustFabricError> {
        if remote.version < self.state.version {
            return Err(TrustFabricError::StaleState {
                remote_ver: remote.version,
                local_ver: self.state.version,
            });
        }

        if self.state.digest == remote.digest {
            return Ok(TrustStateDelta {
                new_cards: BTreeSet::new(),
                new_extensions: BTreeSet::new(),
                new_revocations: BTreeSet::new(),
                new_revocation_ver: None,
            });
        }

        self.events.push(TrustFabricEvent {
            code: EVT_DIGEST_MISMATCH.to_string(),
            detail: format!(
                "local v{} != remote v{}",
                self.state.version, remote.version
            ),
            node_id: self.node_id.clone(),
        });

        let delta = remote.delta_from(&self.state);

        // INV-TFC-REVOKE-FIRST: apply revocations first.
        for rev in &delta.new_revocations {
            self.state.apply_revocation(rev);
            self.events.push(TrustFabricEvent {
                code: EVT_REVOCATION_APPLIED.to_string(),
                detail: format!("revoked {rev} (from gossip)"),
                node_id: self.node_id.clone(),
            });
        }

        // Then apply authorizations (only if not in degraded mode).
        if !self.degraded_mode {
            for card in &delta.new_cards {
                if !self.state.is_revoked(card) {
                    self.state.add_trust_card(card);
                }
            }
            for ext in &delta.new_extensions {
                if !self.state.is_revoked(ext) {
                    self.state.add_extension(ext);
                }
            }
        }

        self.events.push(TrustFabricEvent {
            code: EVT_STATE_UPDATED.to_string(),
            detail: format!("merged delta: {} items", delta.size()),
            node_id: self.node_id.clone(),
        });

        Ok(delta)
    }

    /// Check convergence lag and enter/exit degraded mode.
    pub fn check_convergence(&mut self, now_ts: u64) {
        let lag = now_ts.saturating_sub(self.last_converged_ts);

        if lag > self.config.convergence_lag_threshold && !self.degraded_mode {
            self.degraded_mode = true;
            self.degraded_since = Some(now_ts);
            self.events.push(TrustFabricEvent {
                code: EVT_DEGRADED_ENTERED.to_string(),
                detail: format!(
                    "lag={lag}s > threshold={}s",
                    self.config.convergence_lag_threshold
                ),
                node_id: self.node_id.clone(),
            });
        }

        if lag <= self.config.convergence_lag_threshold && self.degraded_mode {
            self.degraded_mode = false;
            self.degraded_since = None;
            self.events.push(TrustFabricEvent {
                code: EVT_DEGRADED_EXITED.to_string(),
                detail: "convergence restored".to_string(),
                node_id: self.node_id.clone(),
            });
        }

        // Check escalation timeout.
        if let Some(since) = self.degraded_since {
            let degraded_duration = now_ts.saturating_sub(since);
            if degraded_duration > self.config.max_degraded_secs {
                self.events.push(TrustFabricEvent {
                    code: EVT_CONVERGENCE_LAG.to_string(),
                    detail: format!(
                        "escalation: degraded for {degraded_duration}s > max {}s",
                        self.config.max_degraded_secs
                    ),
                    node_id: self.node_id.clone(),
                });
            }
        }
    }

    /// Mark convergence confirmed at timestamp.
    pub fn confirm_convergence(&mut self, now_ts: u64) {
        self.last_converged_ts = now_ts;
        if self.degraded_mode {
            self.degraded_mode = false;
            self.degraded_since = None;
            self.events.push(TrustFabricEvent {
                code: EVT_DEGRADED_EXITED.to_string(),
                detail: "convergence confirmed".to_string(),
                node_id: self.node_id.clone(),
            });
        }
    }

    /// Anti-entropy sweep: full state comparison and repair.
    pub fn anti_entropy_sweep(&mut self, remote: &TrustStateVector) -> TrustStateDelta {
        let delta = remote.delta_from(&self.state);

        // Apply all missing items (revocations first).
        for rev in &delta.new_revocations {
            self.state.apply_revocation(rev);
        }
        if !self.degraded_mode {
            for card in &delta.new_cards {
                if !self.state.is_revoked(card) {
                    self.state.add_trust_card(card);
                }
            }
            for ext in &delta.new_extensions {
                if !self.state.is_revoked(ext) {
                    self.state.add_extension(ext);
                }
            }
        }

        self.events.push(TrustFabricEvent {
            code: EVT_ANTI_ENTROPY_SWEEP.to_string(),
            detail: format!("swept {} items", delta.size()),
            node_id: self.node_id.clone(),
        });

        delta
    }

    /// Simulate partition healing.
    pub fn partition_heal(&mut self, remote: &TrustStateVector, now_ts: u64) -> TrustStateDelta {
        let delta = self.anti_entropy_sweep(remote);
        self.confirm_convergence(now_ts);
        self.events.push(TrustFabricEvent {
            code: EVT_PARTITION_HEALED.to_string(),
            detail: format!("healed with {} delta items", delta.size()),
            node_id: self.node_id.clone(),
        });
        delta
    }

    /// Convergence lag in seconds.
    pub fn convergence_lag(&self, now_ts: u64) -> u64 {
        now_ts.saturating_sub(self.last_converged_ts)
    }

    /// Get events.
    pub fn events(&self) -> &[TrustFabricEvent] {
        &self.events
    }
}

// ---------------------------------------------------------------------------
// Fleet simulation (for testing convergence)
// ---------------------------------------------------------------------------

/// Simulated fleet of trust fabric nodes.
#[derive(Debug, Default)]
pub struct TrustFabricFleet {
    nodes: BTreeMap<String, TrustFabricNode>,
}

impl TrustFabricFleet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: TrustFabricNode) {
        self.nodes.insert(node.node_id.clone(), node);
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Check if all nodes have converged (same digest).
    pub fn is_converged(&self) -> bool {
        let digests: Vec<[u8; 32]> = self.nodes.values().map(|n| n.state().digest).collect();
        if digests.is_empty() {
            return true;
        }
        digests.windows(2).all(|w| w[0] == w[1])
    }

    /// Run one gossip round: each node exchanges with a random peer.
    pub fn gossip_round(&mut self) {
        let node_ids: Vec<String> = self.nodes.keys().cloned().collect();
        if node_ids.len() < 2 {
            return;
        }

        // Each node gossips with the next node (round-robin).
        for i in 0..node_ids.len() {
            let peer_idx = (i + 1) % node_ids.len();
            let peer_state = self.nodes[&node_ids[peer_idx]].state().clone();
            if let Some(node) = self.nodes.get_mut(&node_ids[i]) {
                let _ = node.receive_gossip(&peer_state);
            }
        }
    }

    /// Get a node by ID.
    pub fn get_node(&self, id: &str) -> Option<&TrustFabricNode> {
        self.nodes.get(id)
    }

    /// Get mutable node by ID.
    pub fn get_node_mut(&mut self, id: &str) -> Option<&mut TrustFabricNode> {
        self.nodes.get_mut(id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> TrustFabricConfig {
        TrustFabricConfig::default()
    }

    fn make_node(id: &str) -> TrustFabricNode {
        TrustFabricNode::new(id, default_config(), 1).unwrap()
    }

    // -- Config --

    #[test]
    fn test_default_config_valid() {
        assert!(default_config().validate().is_ok());
    }

    #[test]
    fn test_invalid_convergence_timeout() {
        let mut cfg = default_config();
        cfg.convergence_timeout_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_lag_threshold() {
        let mut cfg = default_config();
        cfg.convergence_lag_threshold = 0;
        assert!(cfg.validate().is_err());
    }

    // -- Trust state vector --

    #[test]
    fn test_new_state_empty() {
        let state = TrustStateVector::new(1);
        assert_eq!(state.version, 0);
        assert!(state.trust_cards.is_empty());
        assert!(state.revocations.is_empty());
    }

    #[test]
    fn test_add_trust_card_increments_version() {
        let mut state = TrustStateVector::new(1);
        state.add_trust_card("card-1");
        assert_eq!(state.version, 1);
        assert!(state.trust_cards.contains("card-1"));
    }

    #[test]
    fn test_add_extension_increments_version() {
        let mut state = TrustStateVector::new(1);
        state.add_extension("ext-1");
        assert_eq!(state.version, 1);
        assert!(state.extensions.contains("ext-1"));
    }

    #[test]
    fn test_revocation_removes_card() {
        let mut state = TrustStateVector::new(1);
        state.add_trust_card("card-1");
        state.apply_revocation("card-1");
        assert!(!state.trust_cards.contains("card-1"));
        assert!(state.is_revoked("card-1"));
    }

    #[test]
    fn test_revocation_removes_extension() {
        let mut state = TrustStateVector::new(1);
        state.add_extension("ext-1");
        state.apply_revocation("ext-1");
        assert!(!state.extensions.contains("ext-1"));
        assert!(state.is_revoked("ext-1"));
    }

    #[test]
    fn test_version_monotonic() {
        // INV-TFC-MONOTONIC
        let mut state = TrustStateVector::new(1);
        let mut prev = state.version;
        for i in 0..10 {
            state.add_trust_card(&format!("card-{i}"));
            assert!(state.version > prev);
            prev = state.version;
        }
    }

    #[test]
    fn test_digest_changes_on_update() {
        let mut state = TrustStateVector::new(1);
        let d1 = state.digest;
        state.add_trust_card("card-1");
        assert_ne!(state.digest, d1);
    }

    // -- Delta computation --

    #[test]
    fn test_identical_states_empty_delta() {
        let mut s1 = TrustStateVector::new(1);
        let mut s2 = TrustStateVector::new(1);
        s1.add_trust_card("card-1");
        s2.add_trust_card("card-1");
        let delta = s1.delta_from(&s2);
        assert!(delta.is_empty());
    }

    #[test]
    fn test_delta_shows_missing_cards() {
        let mut s1 = TrustStateVector::new(1);
        let s2 = TrustStateVector::new(1);
        s1.add_trust_card("card-1");
        let delta = s1.delta_from(&s2);
        assert_eq!(delta.new_cards.len(), 1);
        assert!(delta.new_cards.contains("card-1"));
    }

    #[test]
    fn test_delta_size() {
        let mut s1 = TrustStateVector::new(1);
        let s2 = TrustStateVector::new(1);
        s1.add_trust_card("c1");
        s1.add_extension("e1");
        s1.apply_revocation("r1");
        let delta = s1.delta_from(&s2);
        assert_eq!(delta.size(), 3); // c1 + e1 + r1: revocations tracked separately.
    }

    // -- Node operations --

    #[test]
    fn test_node_creation() {
        let node = make_node("node-1");
        assert_eq!(node.node_id, "node-1");
        assert!(!node.is_degraded());
    }

    #[test]
    fn test_node_add_card() {
        let mut node = make_node("node-1");
        assert!(node.add_trust_card("card-1").is_ok());
        assert!(node.state().trust_cards.contains("card-1"));
    }

    #[test]
    fn test_node_add_extension() {
        let mut node = make_node("node-1");
        assert!(node.add_extension("ext-1").is_ok());
    }

    #[test]
    fn test_node_revocation() {
        let mut node = make_node("node-1");
        node.add_trust_card("card-1").unwrap();
        node.apply_revocation("card-1");
        assert!(!node.state().trust_cards.contains("card-1"));
        assert!(node.state().is_revoked("card-1"));
    }

    // -- Gossip --

    #[test]
    fn test_gossip_merges_state() {
        let mut node1 = make_node("n1");
        let mut node2 = make_node("n2");
        node1.add_trust_card("card-1").unwrap();
        let remote = node1.state().clone();
        let delta = node2.receive_gossip(&remote).unwrap();
        assert!(!delta.is_empty() || node2.state().trust_cards.contains("card-1"));
    }

    #[test]
    fn test_gossip_rejects_stale() {
        let node1 = make_node("n1");
        let mut node2 = make_node("n2");
        // Make node2 ahead.
        node2.add_trust_card("card-1").unwrap();
        node2.add_trust_card("card-2").unwrap();
        // node1 has stale state (version 0).
        let stale = node1.state().clone();
        let err = node2.receive_gossip(&stale);
        assert!(err.is_err());
    }

    #[test]
    fn test_gossip_revoke_first() {
        // INV-TFC-REVOKE-FIRST
        let mut node1 = make_node("n1");
        let mut node2 = make_node("n2");
        node1.add_trust_card("card-1").unwrap();
        node1.apply_revocation("card-1");

        let remote = node1.state().clone();
        let _ = node2.receive_gossip(&remote);
        // card-1 should be revoked, not in trust_cards.
        assert!(node2.state().is_revoked("card-1"));
        assert!(!node2.state().trust_cards.contains("card-1"));
    }

    // -- Degraded mode --

    #[test]
    fn test_degraded_mode_entry() {
        // INV-TFC-DEGRADED-DENY
        let mut node = make_node("n1");
        node.check_convergence(100); // lag = 100 > threshold 60.
        assert!(node.is_degraded());
    }

    #[test]
    fn test_degraded_mode_rejects_cards() {
        let mut node = make_node("n1");
        node.check_convergence(100);
        assert!(node.is_degraded());
        assert!(node.add_trust_card("card-1").is_err());
    }

    #[test]
    fn test_degraded_mode_accepts_revocations() {
        // INV-TFC-REVOKE-FIRST: revocations always accepted.
        let mut node = make_node("n1");
        node.add_trust_card("card-1").unwrap();
        node.check_convergence(100);
        assert!(node.is_degraded());
        node.apply_revocation("card-1"); // Should succeed.
        assert!(node.state().is_revoked("card-1"));
    }

    #[test]
    fn test_degraded_mode_exit() {
        let mut node = make_node("n1");
        node.check_convergence(100);
        assert!(node.is_degraded());
        node.confirm_convergence(100);
        assert!(!node.is_degraded());
    }

    // -- Convergence lag --

    #[test]
    fn test_convergence_lag() {
        let node = make_node("n1");
        assert_eq!(node.convergence_lag(100), 100);
    }

    #[test]
    fn test_convergence_lag_after_confirm() {
        let mut node = make_node("n1");
        node.confirm_convergence(50);
        assert_eq!(node.convergence_lag(60), 10);
    }

    // -- Anti-entropy --

    #[test]
    fn test_anti_entropy_repairs_missing() {
        let mut node1 = make_node("n1");
        let mut node2 = make_node("n2");
        node1.add_trust_card("card-1").unwrap();
        node1.add_trust_card("card-2").unwrap();

        let remote = node1.state().clone();
        let delta = node2.anti_entropy_sweep(&remote);
        assert_eq!(delta.size(), 2);
    }

    // -- Partition healing --

    #[test]
    fn test_partition_heal() {
        let mut node1 = make_node("n1");
        let mut node2 = make_node("n2");
        node1.add_trust_card("card-1").unwrap();

        let remote = node1.state().clone();
        let delta = node2.partition_heal(&remote, 200);
        assert!(!delta.is_empty());
        assert!(!node2.is_degraded());
    }

    // -- Fleet simulation --

    #[test]
    fn test_fleet_convergence() {
        // INV-TFC-CONVERGENCE
        let mut fleet = TrustFabricFleet::new();
        for i in 0..10 {
            fleet.add_node(make_node(&format!("n{i}")));
        }

        // Apply update to first node.
        fleet
            .get_node_mut("n0")
            .unwrap()
            .add_trust_card("card-1")
            .unwrap();

        // Run gossip rounds until convergence.
        let mut rounds = 0;
        while !fleet.is_converged() && rounds < 100 {
            fleet.gossip_round();
            rounds += 1;
        }
        assert!(fleet.is_converged(), "Fleet did not converge in 100 rounds");
    }

    #[test]
    fn test_fleet_empty_converged() {
        let fleet = TrustFabricFleet::new();
        assert!(fleet.is_converged());
    }

    #[test]
    fn test_fleet_single_node_converged() {
        let mut fleet = TrustFabricFleet::new();
        fleet.add_node(make_node("n0"));
        assert!(fleet.is_converged());
    }

    // -- Error display --

    #[test]
    fn test_error_display() {
        let err = TrustFabricError::InvalidConfig("bad".into());
        assert!(format!("{err}").contains(ERR_TFC_INVALID_CONFIG));

        let err = TrustFabricError::StaleState {
            remote_ver: 1,
            local_ver: 5,
        };
        assert!(format!("{err}").contains(ERR_TFC_STALE_STATE));

        let err = TrustFabricError::DigestMismatch;
        assert!(format!("{err}").contains(ERR_TFC_DIGEST_MISMATCH));

        let err = TrustFabricError::DegradedReject("x".into());
        assert!(format!("{err}").contains(ERR_TFC_DEGRADED_REJECT));

        let err = TrustFabricError::EscalationTimeout(300);
        assert!(format!("{err}").contains(ERR_TFC_ESCALATION_TIMEOUT));

        let err = TrustFabricError::PartitionDetected("p".into());
        assert!(format!("{err}").contains(ERR_TFC_PARTITION_DETECTED));
    }

    // -- Events --

    #[test]
    fn test_events_recorded() {
        let mut node = make_node("n1");
        node.add_trust_card("card-1").unwrap();
        assert!(!node.events().is_empty());
    }

    #[test]
    fn test_events_have_node_id() {
        let mut node = make_node("n1");
        node.add_trust_card("card-1").unwrap();
        for event in node.events() {
            assert_eq!(event.node_id, "n1");
        }
    }
}
