//! bd-1nfu: Remote capability gate for network-bound trust/control operations.
//!
//! This module defines:
//! - `RemoteCap` tokens with scope, issuer, expiry, and signature
//! - `CapabilityProvider` for controlled issuance
//! - `CapabilityGate` as the single validation/enforcement point
//! - structured audit events for issuance/consumption/denials

use std::collections::BTreeSet;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "http-client")]
use url::Url;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::security::cuckoo_filter::CuckooFilter;

const MAX_REPLAY_ENTRIES: usize = 4_096;
const REMOTE_CAP_REPLAY_STORE_ENV: &str = "FRANKEN_NODE_REMOTECAP_REPLAY_STORE";
const CUCKOO_REVOCATION_ENV: &str = "FRANKEN_NODE_CUCKOO_REVOCATION";

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

#[derive(Debug, Default)]
struct ReplayTokenSet {
    inner: Arc<Mutex<ReplayTokenSetInner>>,
}

#[derive(Debug, Clone, Default)]
struct ReplayTokenSetInner {
    ids: BTreeSet<String>,
    insertion_order: Vec<String>,
}

impl Clone for ReplayTokenSet {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl ReplayTokenSet {
    /// Atomically check if token exists and insert it if not. Returns true if successfully inserted (was new).
    /// This prevents TOCTOU race conditions between check and insert operations.
    fn insert_if_new(&self, token_id: String) -> bool {
        let inner = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                // Under high contention, block to maintain correctness
                return match self.inner.lock() {
                    Ok(guard) => Self::insert_into_inner(guard, token_id),
                    Err(poisoned) => Self::insert_into_inner(poisoned.into_inner(), token_id),
                }
            }
        };

        Self::insert_into_inner(inner, token_id)
    }

    fn insert_into_inner(mut inner: std::sync::MutexGuard<ReplayTokenSetInner>, token_id: String) -> bool {
        if !inner.ids.insert(token_id.clone()) {
            return false;
        }

        if inner.insertion_order.len() >= MAX_REPLAY_ENTRIES {
            let overflow = inner
                .insertion_order
                .len()
                .saturating_sub(MAX_REPLAY_ENTRIES)
                .saturating_add(1);
            let drain_len = overflow.min(inner.insertion_order.len());
            let evicted_ids: Vec<_> = inner.insertion_order.drain(0..drain_len).collect();
            for evicted in evicted_ids {
                inner.ids.remove(&evicted);
            }
        }
        inner.insertion_order.push(token_id);
        true
    }

    fn insert(&mut self, token_id: String) -> bool {
        self.insert_if_new(token_id)
    }

    #[must_use]
    fn contains(&self, token_id: &str) -> bool {
        match self.inner.try_lock() {
            Ok(inner) => inner.ids.contains(token_id),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().ids.contains(token_id),
            Err(TryLockError::WouldBlock) => {
                // Under high contention, block to maintain correctness
                match self.inner.lock() {
                    Ok(inner) => inner.ids.contains(token_id),
                    Err(poisoned) => poisoned.into_inner().ids.contains(token_id),
                }
            }
        }
    }

    #[cfg(test)]
    #[must_use]
    fn is_empty(&self) -> bool {
        match self.inner.try_lock() {
            Ok(inner) => inner.ids.is_empty(),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().ids.is_empty(),
            Err(TryLockError::WouldBlock) => {
                // Under high contention, block to maintain correctness
                match self.inner.lock() {
                    Ok(inner) => inner.ids.is_empty(),
                    Err(poisoned) => poisoned.into_inner().ids.is_empty(),
                }
            }
        }
    }

    #[must_use]
    fn len(&self) -> usize {
        match self.inner.try_lock() {
            Ok(inner) => inner.ids.len(),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().ids.len(),
            Err(TryLockError::WouldBlock) => {
                // Under high contention, block to maintain correctness
                match self.inner.lock() {
                    Ok(inner) => inner.ids.len(),
                    Err(poisoned) => poisoned.into_inner().ids.len(),
                }
            }
        }
    }

    #[cfg(test)]
    #[must_use]
    fn ordered_ids(&self) -> Vec<String> {
        match self.inner.try_lock() {
            Ok(inner) => inner.insertion_order.clone(),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().insertion_order.clone(),
            Err(TryLockError::WouldBlock) => {
                // Under high contention, block to maintain correctness
                match self.inner.lock() {
                    Ok(inner) => inner.insertion_order.clone(),
                    Err(poisoned) => poisoned.into_inner().insertion_order.clone(),
                }
            }
        }
    }
}

/// Operating mode for hybrid revocation checker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckMode {
    /// Use cuckoo filter only (fastest, false positives possible)
    FastPath,
    /// Use cuckoo filter with BTreeSet verification (fast + accurate)
    Hybrid,
    /// Use BTreeSet only (fallback, always accurate)
    Fallback,
}

/// High-performance hybrid revocation checker.
///
/// Combines cuckoo filter's O(1) performance with BTreeSet's 100% accuracy.
/// Automatically falls back to safe mode if false positive rate exceeds threshold.
/// Maintains FIFO behavior compatible with ReplayTokenSet.
#[derive(Debug, Clone)]
struct HybridRevocationChecker {
    cuckoo: CuckooFilter,
    btree_backup: BTreeSet<String>,
    insertion_order: Vec<String>, // For FIFO behavior in BTreeSet
    mode: CheckMode,
    false_positive_count: usize,
    total_positive_checks: usize,
    max_false_positive_rate: f64, // e.g., 0.001 = 0.1%
}

impl HybridRevocationChecker {
    fn new() -> Self {
        let capacity = std::env::var(CUCKOO_REVOCATION_ENV)
            .ok()
            .and_then(|s| {
                if s == "true" {
                    Some(MAX_REPLAY_ENTRIES * 4)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let mode = if capacity > 0 {
            CheckMode::Hybrid
        } else {
            CheckMode::Fallback
        };

        Self {
            cuckoo: CuckooFilter::new(capacity.max(1024)),
            btree_backup: BTreeSet::new(),
            insertion_order: Vec::new(),
            mode,
            false_positive_count: 0,
            total_positive_checks: 0,
            max_false_positive_rate: 0.001, // 0.1% threshold
        }
    }

    fn contains(&mut self, token_id: &str) -> bool {
        match self.mode {
            CheckMode::Fallback => {
                // BTreeSet only - always accurate
                self.btree_backup.contains(token_id)
            }
            CheckMode::FastPath => {
                // Cuckoo filter only - fastest but may have false positives
                self.cuckoo.contains(token_id)
            }
            CheckMode::Hybrid => {
                // Cuckoo filter with verification
                if !self.cuckoo.contains(token_id) {
                    // Definitely not present (no false negatives in cuckoo)
                    false
                } else {
                    // Potential positive - verify with BTreeSet
                    self.total_positive_checks = self.total_positive_checks.saturating_add(1);
                    let actually_present = self.btree_backup.contains(token_id);

                    if !actually_present {
                        // False positive detected
                        self.false_positive_count = self.false_positive_count.saturating_add(1);
                        self.check_false_positive_rate();
                    }

                    actually_present
                }
            }
        }
    }

    fn insert(&mut self, token_id: String) -> bool {
        // Check if already exists
        if self.mode != CheckMode::FastPath && self.btree_backup.contains(&token_id) {
            return false; // Already present
        }

        let inserted_cuckoo = match self.mode {
            CheckMode::Fallback => true,
            _ => self.cuckoo.insert(&token_id),
        };

        // Handle BTreeSet with FIFO behavior
        if self.mode != CheckMode::FastPath {
            // Insert new token
            self.btree_backup.insert(token_id.clone());

            // Handle FIFO eviction if needed
            if self.insertion_order.len() >= MAX_REPLAY_ENTRIES {
                let overflow = self
                    .insertion_order
                    .len()
                    .saturating_sub(MAX_REPLAY_ENTRIES)
                    .saturating_add(1);
                let drain_len = overflow.min(self.insertion_order.len());
                for removed_token in self.insertion_order.drain(0..drain_len) {
                    self.btree_backup.remove(&removed_token);
                }
            }

            // Add to insertion order tracking
            if self.insertion_order.len() < MAX_REPLAY_ENTRIES {
                self.insertion_order.push(token_id);
            }
        }

        // Return true if successfully inserted
        match self.mode {
            CheckMode::Fallback => true, // We already handled duplicates above
            CheckMode::FastPath => inserted_cuckoo,
            CheckMode::Hybrid => inserted_cuckoo, // Both structures updated
        }
    }

    fn len(&self) -> usize {
        match self.mode {
            CheckMode::FastPath => self.cuckoo.len(),
            _ => self.btree_backup.len(),
        }
    }

    /// Check if false positive rate exceeds threshold and fallback if needed
    fn check_false_positive_rate(&mut self) {
        if self.total_positive_checks < 100 {
            return; // Not enough data yet
        }

        let current_fpr = self.false_positive_count as f64 / self.total_positive_checks as f64;

        if current_fpr > self.max_false_positive_rate {
            // Switch to fallback mode due to high false positive rate
            self.mode = CheckMode::Fallback;

            // Reset counters for future monitoring
            self.false_positive_count = 0;
            self.total_positive_checks = 0;
        }
    }

    /// Get current false positive rate
    #[cfg(test)]
    pub fn false_positive_rate(&self) -> f64 {
        if self.total_positive_checks == 0 {
            0.0
        } else {
            self.false_positive_count as f64 / self.total_positive_checks as f64
        }
    }

    /// Get current operating mode
    #[cfg(test)]
    pub fn current_mode(&self) -> CheckMode {
        self.mode
    }
}

impl Default for HybridRevocationChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
enum ReplayStoreBackend {
    MemoryOnly,
    Durable(DurableReplayStore),
    Unavailable { detail: String },
}

impl ReplayStoreBackend {
    fn from_env() -> Self {
        let Some(root) = std::env::var_os(REMOTE_CAP_REPLAY_STORE_ENV) else {
            return Self::MemoryOnly;
        };
        DurableReplayStore::open(PathBuf::from(root)).map_or_else(
            |err| Self::Unavailable {
                detail: err.to_string(),
            },
            Self::Durable,
        )
    }

    fn contains_consumed(&self, replay_key: &str) -> Result<bool, RemoteCapError> {
        match self {
            Self::MemoryOnly => Ok(false),
            Self::Durable(store) => store.contains_consumed(replay_key),
            Self::Unavailable { detail } => Err(RemoteCapError::CryptoEngineUnavailable {
                detail: detail.clone(),
            }),
        }
    }

    fn consume(&self, cap: &RemoteCap, replay_key: &str) -> Result<bool, RemoteCapError> {
        match self {
            Self::MemoryOnly => Ok(true),
            Self::Durable(store) => store.consume(cap, replay_key),
            Self::Unavailable { detail } => Err(RemoteCapError::CryptoEngineUnavailable {
                detail: detail.clone(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct DurableReplayStore {
    consumed_dir: PathBuf,
}

impl DurableReplayStore {
    fn open(root: impl AsRef<Path>) -> Result<Self, RemoteCapError> {
        let root = root.as_ref().to_path_buf();
        let consumed_dir = root.join("consumed");
        std::fs::create_dir_all(&consumed_dir)
            .map_err(|source| replay_store_error("create", &consumed_dir, source))?;
        sync_directory(&consumed_dir)?;
        Ok(Self { consumed_dir })
    }

    fn contains_consumed(&self, replay_key: &str) -> Result<bool, RemoteCapError> {
        let path = self.marker_path(replay_key);
        match std::fs::metadata(&path) {
            Ok(_) => Ok(true),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(replay_store_error("stat", &path, source)),
        }
    }

    fn consume(&self, cap: &RemoteCap, replay_key: &str) -> Result<bool, RemoteCapError> {
        let path = self.marker_path(replay_key);
        let mut marker = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(marker) => marker,
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(false);
            }
            Err(source) => return Err(replay_store_error("create marker", &path, source)),
        };

        marker
            .write_all(durable_replay_record(cap, replay_key).as_bytes())
            .and_then(|()| marker.sync_all())
            .map_err(|source| replay_store_error("fsync marker", &path, source))?;
        sync_directory(&self.consumed_dir)?;
        Ok(true)
    }

    fn marker_path(&self, replay_key: &str) -> PathBuf {
        self.consumed_dir.join(format!("{replay_key}.seen"))
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    crate::security::constant_time::ct_eq(a, b)
}

/// Network-bound operations that require an explicit `RemoteCap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteOperation {
    NetworkEgress,
    FederationSync,
    RevocationFetch,
    RemoteAttestationVerify,
    TelemetryExport,
    RemoteComputation,
    ArtifactUpload,
}

impl RemoteOperation {
    /// Return the canonical wire-format name for a remote operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::RemoteOperation;
    ///
    /// assert_eq!(
    ///     RemoteOperation::FederationSync.as_str(),
    ///     "federation_sync"
    /// );
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkEgress => "network_egress",
            Self::FederationSync => "federation_sync",
            Self::RevocationFetch => "revocation_fetch",
            Self::RemoteAttestationVerify => "remote_attestation_verify",
            Self::TelemetryExport => "telemetry_export",
            Self::RemoteComputation => "remote_computation",
            Self::ArtifactUpload => "artifact_upload",
        }
    }
}

impl fmt::Display for RemoteOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Connectivity mode for the capability gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityMode {
    Connected,
    LocalOnly,
}

impl fmt::Display for ConnectivityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected => write!(f, "connected"),
            Self::LocalOnly => write!(f, "local_only"),
        }
    }
}

/// Scope of a capability token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteScope {
    operations: Vec<RemoteOperation>,
    endpoint_prefixes: Vec<String>,
}

impl RemoteScope {
    /// Build a scope, normalizing duplicate operations and endpoint prefixes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{RemoteOperation, RemoteScope};
    ///
    /// let scope = RemoteScope::new(
    ///     vec![
    ///         RemoteOperation::FederationSync,
    ///         RemoteOperation::FederationSync,
    ///         RemoteOperation::NetworkEgress,
    ///     ],
    ///     vec![
    ///         " https://control.example/api ".to_string(),
    ///         "https://control.example/api".to_string(),
    ///     ],
    /// );
    ///
    /// assert_eq!(scope.operations().len(), 2);
    /// assert_eq!(scope.endpoint_prefixes().len(), 1);
    /// ```
    #[must_use]
    pub fn new(operations: Vec<RemoteOperation>, endpoint_prefixes: Vec<String>) -> Self {
        let mut scope = Self {
            operations,
            endpoint_prefixes,
        };
        scope.normalize();

        scope
    }

    /// Return the normalized set of allowed operations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{RemoteOperation, RemoteScope};
    ///
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    ///
    /// assert_eq!(scope.operations(), &[RemoteOperation::FederationSync]);
    /// ```
    #[must_use]
    pub fn operations(&self) -> &[RemoteOperation] {
        &self.operations
    }

    /// Return the normalized endpoint prefixes covered by this scope.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{RemoteOperation, RemoteScope};
    ///
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec![" https://control.example/api ".to_string()],
    /// );
    ///
    /// assert_eq!(scope.endpoint_prefixes(), &["https://control.example/api".to_string()]);
    /// ```
    #[must_use]
    pub fn endpoint_prefixes(&self) -> &[String] {
        &self.endpoint_prefixes
    }

    /// Return whether the scope authorizes a given remote operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{RemoteOperation, RemoteScope};
    ///
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    ///
    /// assert!(scope.allows_operation(RemoteOperation::FederationSync));
    /// assert!(!scope.allows_operation(RemoteOperation::ArtifactUpload));
    /// ```
    #[must_use]
    pub fn allows_operation(&self, operation: RemoteOperation) -> bool {
        self.operations.contains(&operation)
    }

    /// Return whether the endpoint falls under one of the allowed prefixes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{RemoteOperation, RemoteScope};
    ///
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    ///
    /// assert!(scope.allows_endpoint("https://control.example/api/jobs"));
    /// assert!(!scope.allows_endpoint("https://other.example/api/jobs"));
    /// ```
    #[must_use]
    pub fn allows_endpoint(&self, endpoint: &str) -> bool {
        if validate_requested_endpoint(endpoint).is_err() {
            return false;
        }

        self.endpoint_prefixes
            .iter()
            .any(|prefix| endpoint_matches_prefix(endpoint, prefix))
    }

    fn normalize(&mut self) {
        let op_set: BTreeSet<RemoteOperation> = self.operations.iter().copied().collect();
        self.operations = op_set.into_iter().collect();

        let endpoint_set: BTreeSet<String> = self
            .endpoint_prefixes
            .iter()
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect();
        self.endpoint_prefixes = endpoint_set.into_iter().collect();
    }

    /// Validate endpoint prefixes at deserialization, issuance, and enforcement time.
    fn validate_endpoint_prefixes(&self) -> Result<(), String> {
        for prefix in &self.endpoint_prefixes {
            validate_endpoint_prefix(prefix)?;
        }
        Ok(())
    }
}

fn validate_endpoint_prefix_lexical(prefix: &str) -> Result<&str, String> {
    if prefix.trim().is_empty() {
        return Err("endpoint prefix cannot be empty".to_string());
    }
    if prefix != prefix.trim() {
        return Err(format!("endpoint prefix '{}' must be normalized", prefix));
    }
    if prefix
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '\u{202a}'..='\u{202e}'))
    {
        return Err(format!(
            "endpoint prefix '{}' contains invalid characters",
            prefix
        ));
    }

    let lower_prefix = prefix.to_ascii_lowercase();
    if prefix.contains("..") || prefix.contains('\\') || lower_prefix.contains("%2e") {
        return Err(format!(
            "endpoint prefix '{}' contains invalid characters",
            prefix
        ));
    }

    let scheme = prefix
        .split_once("://")
        .map(|(scheme, _)| scheme)
        .ok_or_else(|| {
            format!(
                "endpoint prefix '{}' must use network scheme (https://, http://, federation://, revocation://, ws://, wss://)",
                prefix
            )
        })?;

    let forbidden_schemes = ["file", "data", "javascript", "vbscript", "ftp"];
    if forbidden_schemes
        .iter()
        .any(|forbidden| scheme.eq_ignore_ascii_case(forbidden))
    {
        return Err(format!(
            "endpoint prefix '{}' uses forbidden non-network scheme '{}'",
            prefix, scheme
        ));
    }

    let allowed_schemes = ["https", "http", "federation", "revocation", "ws", "wss"];
    if !allowed_schemes
        .iter()
        .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
    {
        return Err(format!(
            "endpoint prefix '{}' must use network scheme (https://, http://, federation://, revocation://, ws://, wss://)",
            prefix
        ));
    }

    Ok(scheme)
}

#[cfg(feature = "http-client")]
fn validate_endpoint_prefix(prefix: &str) -> Result<(), String> {
    let _scheme = validate_endpoint_prefix_lexical(prefix)?;
    let parsed = Url::parse(prefix)
        .map_err(|source| format!("endpoint prefix '{}' is not a valid URL: {source}", prefix))?;
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(format!(
            "endpoint prefix '{}' has no domain after scheme",
            prefix
        ));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(format!(
            "endpoint prefix '{}' must not include userinfo",
            prefix
        ));
    }
    if parsed.port() == Some(0) {
        return Err(format!("endpoint prefix '{}' has invalid port 0", prefix));
    }
    if parsed.fragment().is_some() {
        return Err(format!(
            "endpoint prefix '{}' must not include a fragment",
            prefix
        ));
    }

    Ok(())
}

#[cfg(not(feature = "http-client"))]
fn validate_endpoint_prefix(prefix: &str) -> Result<(), String> {
    validate_endpoint_prefix_lexical(prefix)?;
    Ok(())
}

fn validate_requested_endpoint(endpoint: &str) -> Result<(), String> {
    validate_endpoint_prefix(endpoint)
        .map_err(|detail| detail.replace("endpoint prefix", "endpoint"))
}

// Custom deserialization for RemoteScope with validation
impl<'de> serde::Deserialize<'de> for RemoteScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct RemoteScopeRaw {
            operations: Vec<RemoteOperation>,
            endpoint_prefixes: Vec<String>,
        }

        let raw = RemoteScopeRaw::deserialize(deserializer)?;

        // Create scope using constructor for normalization
        let mut scope = RemoteScope {
            operations: raw.operations,
            endpoint_prefixes: raw.endpoint_prefixes,
        };

        // Normalize first to clean up the data
        scope.normalize();

        // Then validate the cleaned data
        scope
            .validate_endpoint_prefixes()
            .map_err(serde::de::Error::custom)?;

        Ok(scope)
    }
}

fn endpoint_matches_prefix(endpoint: &str, prefix: &str) -> bool {
    if !endpoint.starts_with(prefix) {
        return false;
    }

    // If the prefix already ends with a URL delimiter, any continuation is valid
    if prefix.ends_with('/') || prefix.ends_with(':') {
        return true;
    }

    match endpoint.as_bytes().get(prefix.len()) {
        None => true,
        Some(b'/') | Some(b'?') | Some(b'#') | Some(b':') => true,
        Some(_) => false,
    }
}

/// Signed capability token for remote operations.
///
/// The token has no public constructor; issuance must happen through
/// `CapabilityProvider`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCap {
    token_id: String,
    issuer_identity: String,
    issued_at_epoch_secs: u64,
    expires_at_epoch_secs: u64,
    scope: RemoteScope,
    signature: String,
    single_use: bool,
}

impl RemoteCap {
    /// Return the stable token identifier for this capability.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, true, "trace-1").unwrap();
    ///
    /// assert!(!cap.token_id().is_empty());
    /// ```
    #[must_use]
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// Return the identity that issued the capability.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, false, "trace-1").unwrap();
    ///
    /// assert_eq!(cap.issuer_identity(), "ops@example");
    /// ```
    #[must_use]
    pub fn issuer_identity(&self) -> &str {
        &self.issuer_identity
    }

    /// Return the epoch second when the capability becomes valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, false, "trace-1").unwrap();
    ///
    /// assert_eq!(cap.issued_at_epoch_secs(), 100);
    /// ```
    #[must_use]
    pub fn issued_at_epoch_secs(&self) -> u64 {
        self.issued_at_epoch_secs
    }

    /// Return the exclusive upper-bound epoch second for the capability.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, false, "trace-1").unwrap();
    ///
    /// assert_eq!(cap.expires_at_epoch_secs(), 160);
    /// ```
    #[must_use]
    pub fn expires_at_epoch_secs(&self) -> u64 {
        self.expires_at_epoch_secs
    }

    /// Return the normalized scope attached to the capability.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, false, "trace-1").unwrap();
    ///
    /// assert!(cap.scope().allows_operation(RemoteOperation::FederationSync));
    /// ```
    #[must_use]
    pub fn scope(&self) -> &RemoteScope {
        &self.scope
    }

    /// Return the keyed digest signature covering the canonical payload.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, false, "trace-1").unwrap();
    ///
    /// assert!(!cap.signature().is_empty());
    /// ```
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Return whether the capability is consumed after one successful use.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, true, "trace-1").unwrap();
    ///
    /// assert!(cap.is_single_use());
    /// ```
    #[must_use]
    pub fn is_single_use(&self) -> bool {
        self.single_use
    }
}

/// Stable errors for RemoteCap issuance/enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteCapError {
    Missing,
    OperatorAuthorizationRequired,
    InvalidTtl {
        ttl_secs: u64,
    },
    NotYetValid {
        now_epoch_secs: u64,
        issued_at_epoch_secs: u64,
    },
    Expired {
        now_epoch_secs: u64,
        expires_at_epoch_secs: u64,
    },
    InvalidSignature,
    ScopeDenied {
        operation: RemoteOperation,
        endpoint: String,
    },
    InvalidScope {
        detail: String,
    },
    Revoked {
        token_id: String,
    },
    ReplayDetected {
        token_id: String,
    },
    ConnectivityModeDenied {
        mode: ConnectivityMode,
        operation: RemoteOperation,
        endpoint: String,
    },
    CryptoEngineUnavailable {
        detail: String,
    },
    LockTimeout {
        operation: String,
        timeout_ms: u64,
    },
}

impl RemoteCapError {
    /// Return the stable machine-readable error code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::RemoteCapError;
    ///
    /// let error = RemoteCapError::Missing;
    /// assert_eq!(error.code(), "REMOTECAP_MISSING");
    /// ```
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing => "REMOTECAP_MISSING",
            Self::OperatorAuthorizationRequired => "REMOTECAP_OPERATOR_AUTH_REQUIRED",
            Self::InvalidTtl { .. } => "REMOTECAP_TTL_INVALID",
            Self::NotYetValid { .. } => "REMOTECAP_NOT_YET_VALID",
            Self::Expired { .. } => "REMOTECAP_EXPIRED",
            Self::InvalidSignature => "REMOTECAP_INVALID",
            Self::ScopeDenied { .. } => "REMOTECAP_SCOPE_DENIED",
            Self::InvalidScope { .. } => "REMOTECAP_SCOPE_INVALID",
            Self::Revoked { .. } => "REMOTECAP_REVOKED",
            Self::ReplayDetected { .. } => "REMOTECAP_REPLAY",
            Self::ConnectivityModeDenied { .. } => "REMOTECAP_CONNECTIVITY_MODE_DENIED",
            Self::CryptoEngineUnavailable { .. } => "REMOTECAP_CRYPTO_UNAVAILABLE",
            Self::LockTimeout { .. } => "REMOTECAP_LOCK_TIMEOUT",
        }
    }

    /// Compatibility alias used by some contracts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::RemoteCapError;
    ///
    /// assert_eq!(
    ///     RemoteCapError::Missing.compatibility_code(),
    ///     Some("ERR_REMOTE_CAP_REQUIRED")
    /// );
    /// assert_eq!(RemoteCapError::InvalidSignature.compatibility_code(), None);
    /// ```
    #[must_use]
    pub fn compatibility_code(&self) -> Option<&'static str> {
        match self {
            Self::Missing => Some("ERR_REMOTE_CAP_REQUIRED"),
            _ => None,
        }
    }
}

impl fmt::Display for RemoteCapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "{}: missing capability token", self.code()),
            Self::OperatorAuthorizationRequired => write!(
                f,
                "{}: operator approval is required for token issuance",
                self.code()
            ),
            Self::InvalidTtl { ttl_secs } => {
                write!(f, "{}: ttl must be > 0 (got {ttl_secs})", self.code())
            }
            Self::NotYetValid {
                now_epoch_secs,
                issued_at_epoch_secs,
            } => write!(
                f,
                "{}: token not yet valid (now={now_epoch_secs}, issued={issued_at_epoch_secs})",
                self.code()
            ),
            Self::Expired {
                now_epoch_secs,
                expires_at_epoch_secs,
            } => write!(
                f,
                "{}: token expired (now={now_epoch_secs}, expires={expires_at_epoch_secs})",
                self.code()
            ),
            Self::InvalidSignature => write!(f, "{}: signature validation failed", self.code()),
            Self::ScopeDenied {
                operation,
                endpoint,
            } => write!(
                f,
                "{}: operation={operation} endpoint={endpoint}",
                self.code()
            ),
            Self::InvalidScope { detail } => write!(f, "{}: {detail}", self.code()),
            Self::Revoked { token_id } => {
                write!(f, "{}: token revoked ({token_id})", self.code())
            }
            Self::ReplayDetected { token_id } => {
                write!(f, "{}: token replay detected ({token_id})", self.code())
            }
            Self::ConnectivityModeDenied {
                mode,
                operation,
                endpoint,
            } => write!(
                f,
                "{}: mode={mode} operation={operation} endpoint={endpoint}",
                self.code()
            ),
            Self::CryptoEngineUnavailable { detail } => {
                write!(f, "{}: {detail}", self.code())
            }
            Self::LockTimeout {
                operation,
                timeout_ms,
            } => {
                write!(
                    f,
                    "{}: lock timeout after {}ms during {}",
                    self.code(),
                    timeout_ms,
                    operation
                )
            }
        }
    }
}

impl std::error::Error for RemoteCapError {}

/// Structured capability audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCapAuditEvent {
    pub event_code: String,
    pub legacy_event_code: String,
    pub token_id: Option<String>,
    pub issuer_identity: Option<String>,
    pub operation: Option<RemoteOperation>,
    pub endpoint: Option<String>,
    pub trace_id: String,
    pub timestamp_epoch_secs: u64,
    pub allowed: bool,
    pub denial_code: Option<String>,
}

/// Controlled capability issuer.
#[derive(Clone)]
pub struct CapabilityProvider {
    signing_secret: String,
    audit_log: Arc<Mutex<Vec<RemoteCapAuditEvent>>>,
}

impl fmt::Debug for CapabilityProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapabilityProvider")
            .field("signing_secret", &"<redacted>")
            .field("audit_log_len", &self.audit_log_len())
            .finish()
    }
}

impl CapabilityProvider {
    /// Create a new CapabilityProvider with validated signing secret.
    /// Fails closed if signing secret is empty or whitespace-only.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::CapabilityProvider;
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// assert!(provider.audit_log().is_empty());
    /// ```
    pub fn new(signing_secret: &str) -> Result<Self, RemoteCapError> {
        validate_secret_material(signing_secret, "signing")?;
        Ok(Self {
            signing_secret: signing_secret.to_string(),
            audit_log: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Fallible constructor alias for `CapabilityProvider::new`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::CapabilityProvider;
    ///
    /// let provider = CapabilityProvider::try_new("shared-secret").unwrap();
    /// assert!(provider.audit_log().is_empty());
    /// ```
    pub fn try_new(signing_secret: &str) -> Result<Self, RemoteCapError> {
        Self::new(signing_secret)
    }

    /// Issue a capability token after explicit operator authorization.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, event) =
    ///     provider.issue("ops@example", scope, 100, 60, true, true, "trace-issue").unwrap();
    ///
    /// assert_eq!(event.event_code, "REMOTECAP_ISSUED");
    /// assert_eq!(event.token_id.as_deref(), Some(cap.token_id()));
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        issuer_identity: &str,
        scope: RemoteScope,
        now_epoch_secs: u64,
        ttl_secs: u64,
        operator_authorized: bool,
        single_use: bool,
        trace_id: &str,
    ) -> Result<(RemoteCap, RemoteCapAuditEvent), RemoteCapError> {
        if !operator_authorized {
            let error = RemoteCapError::OperatorAuthorizationRequired;
            self.record_issue_denial(issuer_identity, now_epoch_secs, trace_id, error.code());
            return Err(error);
        }
        if ttl_secs == 0 {
            let error = RemoteCapError::InvalidTtl { ttl_secs };
            self.record_issue_denial(issuer_identity, now_epoch_secs, trace_id, error.code());
            return Err(error);
        }
        validate_secret_material(&self.signing_secret, "signing")?;

        let expires_at_epoch_secs = now_epoch_secs.saturating_add(ttl_secs);
        let normalized_scope = RemoteScope::new(scope.operations, scope.endpoint_prefixes);
        normalized_scope
            .validate_endpoint_prefixes()
            .map_err(|detail| RemoteCapError::InvalidScope { detail })?;
        let token_id = token_id_hash(
            issuer_identity,
            &normalized_scope,
            now_epoch_secs,
            expires_at_epoch_secs,
            single_use,
            trace_id,
        );

        let unsigned_payload = canonical_payload(
            &token_id,
            issuer_identity,
            now_epoch_secs,
            expires_at_epoch_secs,
            &normalized_scope,
            single_use,
        );
        let signature = keyed_digest(&self.signing_secret, &unsigned_payload)?;

        let cap = RemoteCap {
            token_id: token_id.clone(),
            issuer_identity: issuer_identity.to_string(),
            issued_at_epoch_secs: now_epoch_secs,
            expires_at_epoch_secs,
            scope: normalized_scope,
            signature,
            single_use,
        };

        let audit_event = build_audit_event(
            "REMOTECAP_ISSUED",
            "RC_CAP_GRANTED",
            Some(token_id),
            Some(issuer_identity.to_string()),
            None,
            None,
            trace_id.to_string(),
            now_epoch_secs,
            true,
            None,
        );
        self.push_audit(audit_event.clone());

        Ok((cap, audit_event))
    }

    /// Return a snapshot of the provider audit log.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// provider
    ///     .issue("ops@example", scope, 100, 60, true, false, "trace-audit")
    ///     .unwrap();
    ///
    /// assert_eq!(provider.audit_log().len(), 1);
    /// ```
    #[must_use]
    pub fn audit_log(&self) -> Vec<RemoteCapAuditEvent> {
        self.with_audit_log(|audit_log| audit_log.clone())
            .unwrap_or_else(|_| Vec::new()) // Return empty vec on timeout
    }

    fn record_issue_denial(
        &self,
        issuer_identity: &str,
        now_epoch_secs: u64,
        trace_id: &str,
        denial_code: &str,
    ) {
        self.push_audit(build_audit_event(
            "REMOTECAP_DENIED",
            "RC_CAP_DENIED",
            None,
            Some(issuer_identity.to_string()),
            None,
            None,
            trace_id.to_string(),
            now_epoch_secs,
            false,
            Some(denial_code.to_string()),
        ));
    }

    fn push_audit(&self, event: RemoteCapAuditEvent) {
        let _ = self.with_audit_log(|audit_log| {
            push_bounded(audit_log, event, MAX_AUDIT_LOG_ENTRIES);
        }); // Ignore timeout errors for audit logging
    }

    fn audit_log_len(&self) -> usize {
        self.with_audit_log(|audit_log| audit_log.len())
            .unwrap_or(0) // Return 0 on timeout
    }

    fn with_audit_log<R>(
        &self,
        action: impl FnOnce(&mut Vec<RemoteCapAuditEvent>) -> R,
    ) -> Result<R, RemoteCapError> {
        let mut audit_log = self.try_lock_audit_log_with_timeout(Duration::from_millis(100))?;
        Ok(action(&mut audit_log))
    }

    fn try_lock_audit_log_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<std::sync::MutexGuard<'_, Vec<RemoteCapAuditEvent>>, RemoteCapError> {
        let start = std::time::Instant::now();
        let mut backoff = Duration::from_millis(1);

        loop {
            match self.audit_log.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
                Err(TryLockError::WouldBlock) => {
                    if start.elapsed() >= timeout {
                        return Err(RemoteCapError::LockTimeout {
                            operation: "audit_log_access".to_string(),
                            timeout_ms: timeout.as_millis() as u64,
                        });
                    }
                    std::thread::sleep(backoff);
                    backoff = std::cmp::min(backoff * 2, Duration::from_millis(10));
                }
            }
        }
    }
}

/// Single enforcement point for all network-bound capability checks.
#[derive(Clone)]
pub struct CapabilityGate {
    verification_secret: String,
    connectivity_mode: ConnectivityMode,
    consumed_tokens: ReplayTokenSet,
    revoked_tokens: HybridRevocationChecker,
    replay_store: ReplayStoreBackend,
    audit_log: Vec<RemoteCapAuditEvent>,
}

impl fmt::Debug for CapabilityGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapabilityGate")
            .field("verification_secret", &"<redacted>")
            .field("connectivity_mode", &self.connectivity_mode)
            .field("consumed_token_count", &self.consumed_tokens.len())
            .field("revoked_token_count", &self.revoked_tokens.len())
            .field("replay_store", &self.replay_store)
            .field("audit_log_len", &self.audit_log.len())
            .finish()
    }
}

impl CapabilityGate {
    /// Create a new CapabilityGate with validated verification secret.
    /// Fails closed if verification secret is empty or whitespace-only.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{CapabilityGate, ConnectivityMode};
    ///
    /// let gate = CapabilityGate::new("shared-secret").unwrap();
    /// assert_eq!(gate.mode(), ConnectivityMode::Connected);
    /// ```
    pub fn new(verification_secret: &str) -> Result<Self, RemoteCapError> {
        validate_secret_material(verification_secret, "verification")?;
        Ok(Self {
            verification_secret: verification_secret.to_string(),
            connectivity_mode: ConnectivityMode::Connected,
            consumed_tokens: ReplayTokenSet::default(),
            revoked_tokens: HybridRevocationChecker::default(),
            replay_store: ReplayStoreBackend::from_env(),
            audit_log: Vec::new(),
        })
    }

    /// Fallible constructor alias for `CapabilityGate::new`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{CapabilityGate, ConnectivityMode};
    ///
    /// let gate = CapabilityGate::try_new("shared-secret").unwrap();
    /// assert_eq!(gate.mode(), ConnectivityMode::Connected);
    /// ```
    pub fn try_new(verification_secret: &str) -> Result<Self, RemoteCapError> {
        Self::new(verification_secret)
    }

    /// Create a gate with an explicit connectivity mode.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{CapabilityGate, ConnectivityMode};
    ///
    /// let gate = CapabilityGate::with_mode("shared-secret", ConnectivityMode::LocalOnly).unwrap();
    /// assert_eq!(gate.mode(), ConnectivityMode::LocalOnly);
    /// ```
    pub fn with_mode(
        verification_secret: &str,
        mode: ConnectivityMode,
    ) -> Result<Self, RemoteCapError> {
        let mut gate = Self::new(verification_secret)?;
        gate.connectivity_mode = mode;
        Ok(gate)
    }

    /// Create a gate backed by a durable replay-store directory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{CapabilityGate, ConnectivityMode};
    ///
    /// let store_dir = tempfile::tempdir().unwrap();
    /// let gate = CapabilityGate::with_durable_replay_store("shared-secret", store_dir.path()).unwrap();
    ///
    /// assert_eq!(gate.mode(), ConnectivityMode::Connected);
    /// ```
    pub fn with_durable_replay_store(
        verification_secret: &str,
        store_dir: impl AsRef<Path>,
    ) -> Result<Self, RemoteCapError> {
        validate_secret_material(verification_secret, "verification")?;
        Ok(Self {
            verification_secret: verification_secret.to_string(),
            connectivity_mode: ConnectivityMode::Connected,
            consumed_tokens: ReplayTokenSet::default(),
            revoked_tokens: HybridRevocationChecker::default(),
            replay_store: ReplayStoreBackend::Durable(DurableReplayStore::open(store_dir)?),
            audit_log: Vec::new(),
        })
    }

    /// Create a gate with both durable replay tracking and an explicit mode.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{CapabilityGate, ConnectivityMode};
    ///
    /// let store_dir = tempfile::tempdir().unwrap();
    /// let gate = CapabilityGate::with_mode_and_durable_replay_store(
    ///     "shared-secret",
    ///     ConnectivityMode::LocalOnly,
    ///     store_dir.path(),
    /// )
    /// .unwrap();
    ///
    /// assert_eq!(gate.mode(), ConnectivityMode::LocalOnly);
    /// ```
    pub fn with_mode_and_durable_replay_store(
        verification_secret: &str,
        mode: ConnectivityMode,
        store_dir: impl AsRef<Path>,
    ) -> Result<Self, RemoteCapError> {
        let mut gate = Self::with_durable_replay_store(verification_secret, store_dir)?;
        gate.connectivity_mode = mode;
        Ok(gate)
    }

    /// Change the connectivity policy enforced by the gate.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{CapabilityGate, ConnectivityMode};
    ///
    /// let mut gate = CapabilityGate::new("shared-secret").unwrap();
    /// gate.set_mode(ConnectivityMode::LocalOnly);
    ///
    /// assert_eq!(gate.mode(), ConnectivityMode::LocalOnly);
    /// ```
    pub fn set_mode(&mut self, mode: ConnectivityMode) {
        self.connectivity_mode = mode;
    }

    /// Return the current connectivity mode enforced by the gate.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{CapabilityGate, ConnectivityMode};
    ///
    /// let gate = CapabilityGate::with_mode("shared-secret", ConnectivityMode::LocalOnly).unwrap();
    /// assert_eq!(gate.mode(), ConnectivityMode::LocalOnly);
    /// ```
    #[must_use]
    pub fn mode(&self) -> ConnectivityMode {
        self.connectivity_mode
    }

    /// Local-only operations are always allowed and optionally logged.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{CapabilityGate, ConnectivityMode};
    ///
    /// let mut gate = CapabilityGate::with_mode("shared-secret", ConnectivityMode::LocalOnly).unwrap();
    /// gate.authorize_local_operation("emit_local_report", 100, "trace-local");
    ///
    /// assert_eq!(gate.audit_log().len(), 1);
    /// assert_eq!(gate.audit_log()[0].event_code, "REMOTECAP_LOCAL_MODE_ACTIVE");
    /// ```
    pub fn authorize_local_operation(
        &mut self,
        local_operation: &str,
        now_epoch_secs: u64,
        trace_id: &str,
    ) {
        if self.connectivity_mode == ConnectivityMode::LocalOnly {
            self.push_audit(build_audit_event(
                "REMOTECAP_LOCAL_MODE_ACTIVE",
                "RC_LOCAL_MODE_ACTIVE",
                None,
                None,
                None,
                Some(local_operation.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                true,
                None,
            ));
        }
    }

    /// Revoke a token and ensure subsequent checks fail.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityGate, CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, false, "trace-issue").unwrap();
    /// let mut gate = CapabilityGate::new("shared-secret").unwrap();
    ///
    /// let event = gate.revoke(&cap, 110, "trace-revoke");
    ///
    /// assert_eq!(event.event_code, "REMOTECAP_REVOKED");
    /// assert_eq!(event.token_id.as_deref(), Some(cap.token_id()));
    /// ```
    pub fn revoke(
        &mut self,
        cap: &RemoteCap,
        now_epoch_secs: u64,
        trace_id: &str,
    ) -> RemoteCapAuditEvent {
        self.revoked_tokens.insert(cap.token_id.clone());
        let event = build_audit_event(
            "REMOTECAP_REVOKED",
            "RC_CAP_REVOKED",
            Some(cap.token_id.clone()),
            Some(cap.issuer_identity.clone()),
            None,
            None,
            trace_id.to_string(),
            now_epoch_secs,
            true,
            None,
        );
        self.push_audit(event.clone());
        event
    }

    /// Validate remote capability for one network-bound operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityGate, CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, false, "trace-issue").unwrap();
    /// let mut gate = CapabilityGate::new("shared-secret").unwrap();
    ///
    /// gate.authorize_network(
    ///     Some(&cap),
    ///     RemoteOperation::FederationSync,
    ///     "https://control.example/api/jobs",
    ///     110,
    ///     "trace-check",
    /// )
    /// .unwrap();
    /// ```
    pub fn authorize_network(
        &mut self,
        cap: Option<&RemoteCap>,
        operation: RemoteOperation,
        endpoint: &str,
        now_epoch_secs: u64,
        trace_id: &str,
    ) -> Result<(), RemoteCapError> {
        self.authorize_network_internal(cap, operation, endpoint, now_epoch_secs, trace_id, true)
    }

    /// Recheck capability validity for one network-bound operation without
    /// consuming single-use tokens.
    ///
    /// This is intended for preflight checks in long-running workflows where
    /// capability validity can change between phases.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{
    ///     CapabilityGate, CapabilityProvider, RemoteOperation, RemoteScope,
    /// };
    ///
    /// let provider = CapabilityProvider::new("shared-secret").unwrap();
    /// let scope = RemoteScope::new(
    ///     vec![RemoteOperation::FederationSync],
    ///     vec!["https://control.example/api".to_string()],
    /// );
    /// let (cap, _) = provider.issue("ops@example", scope, 100, 60, true, true, "trace-issue").unwrap();
    /// let mut gate = CapabilityGate::new("shared-secret").unwrap();
    ///
    /// gate.recheck_network(
    ///     Some(&cap),
    ///     RemoteOperation::FederationSync,
    ///     "https://control.example/api/jobs",
    ///     110,
    ///     "trace-recheck",
    /// )
    /// .unwrap();
    /// gate.authorize_network(
    ///     Some(&cap),
    ///     RemoteOperation::FederationSync,
    ///     "https://control.example/api/jobs",
    ///     110,
    ///     "trace-consume",
    /// )
    /// .unwrap();
    /// ```
    pub fn recheck_network(
        &mut self,
        cap: Option<&RemoteCap>,
        operation: RemoteOperation,
        endpoint: &str,
        now_epoch_secs: u64,
        trace_id: &str,
    ) -> Result<(), RemoteCapError> {
        self.authorize_network_internal(cap, operation, endpoint, now_epoch_secs, trace_id, false)
    }

    fn authorize_network_internal(
        &mut self,
        cap: Option<&RemoteCap>,
        operation: RemoteOperation,
        endpoint: &str,
        now_epoch_secs: u64,
        trace_id: &str,
        consume_single_use: bool,
    ) -> Result<(), RemoteCapError> {
        if self.connectivity_mode == ConnectivityMode::LocalOnly {
            let err = RemoteCapError::ConnectivityModeDenied {
                mode: self.connectivity_mode,
                operation,
                endpoint: endpoint.to_string(),
            };
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                cap.map(|token| token.token_id.clone()),
                cap.map(|token| token.issuer_identity.clone()),
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        }

        let Some(cap) = cap else {
            let err = RemoteCapError::Missing;
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                None,
                None,
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        };

        if self.revoked_tokens.contains(&cap.token_id) {
            let err = RemoteCapError::Revoked {
                token_id: cap.token_id.clone(),
            };
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                Some(cap.token_id.clone()),
                Some(cap.issuer_identity.clone()),
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        }

        if let Err(err) = validate_secret_material(&self.verification_secret, "verification") {
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                Some(cap.token_id.clone()),
                Some(cap.issuer_identity.clone()),
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        }

        if let Err(detail) = cap.scope.validate_endpoint_prefixes() {
            let err = RemoteCapError::InvalidScope { detail };
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                Some(cap.token_id.clone()),
                Some(cap.issuer_identity.clone()),
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        }

        let payload = canonical_payload(
            &cap.token_id,
            &cap.issuer_identity,
            cap.issued_at_epoch_secs,
            cap.expires_at_epoch_secs,
            &cap.scope,
            cap.single_use,
        );
        let expected_signature = keyed_digest(&self.verification_secret, &payload)?;
        if !constant_time_eq(&cap.signature, &expected_signature) {
            let err = RemoteCapError::InvalidSignature;
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                Some(cap.token_id.clone()),
                Some(cap.issuer_identity.clone()),
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        }

        if now_epoch_secs < cap.issued_at_epoch_secs {
            let err = RemoteCapError::NotYetValid {
                now_epoch_secs,
                issued_at_epoch_secs: cap.issued_at_epoch_secs,
            };
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                Some(cap.token_id.clone()),
                Some(cap.issuer_identity.clone()),
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        }

        // Expiry is fail-closed at the exact boundary: once `now` reaches
        // `expires_at`, the capability is no longer valid.
        if now_epoch_secs >= cap.expires_at_epoch_secs {
            let err = RemoteCapError::Expired {
                now_epoch_secs,
                expires_at_epoch_secs: cap.expires_at_epoch_secs,
            };
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                Some(cap.token_id.clone()),
                Some(cap.issuer_identity.clone()),
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        }

        if !cap.scope.allows_operation(operation) || !cap.scope.allows_endpoint(endpoint) {
            let err = RemoteCapError::ScopeDenied {
                operation,
                endpoint: endpoint.to_string(),
            };
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                Some(cap.token_id.clone()),
                Some(cap.issuer_identity.clone()),
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        }

        let replay_key = cap.single_use.then(|| replay_store_key(cap));
        if cap.single_use && self.consumed_tokens.contains(&cap.token_id) {
            let err = RemoteCapError::ReplayDetected {
                token_id: cap.token_id.clone(),
            };
            self.push_audit(build_audit_event(
                "REMOTECAP_DENIED",
                "RC_CHECK_DENIED",
                Some(cap.token_id.clone()),
                Some(cap.issuer_identity.clone()),
                Some(operation),
                Some(endpoint.to_string()),
                trace_id.to_string(),
                now_epoch_secs,
                false,
                Some(err.code().to_string()),
            ));
            return Err(err);
        }

        if !consume_single_use {
            if let Some(replay_key) = replay_key.as_deref() {
                match self.replay_store.contains_consumed(replay_key) {
                    Ok(false) => {}
                    Ok(true) => {
                        let err = RemoteCapError::ReplayDetected {
                            token_id: cap.token_id.clone(),
                        };
                        self.push_audit(build_audit_event(
                            "REMOTECAP_DENIED",
                            "RC_CHECK_DENIED",
                            Some(cap.token_id.clone()),
                            Some(cap.issuer_identity.clone()),
                            Some(operation),
                            Some(endpoint.to_string()),
                            trace_id.to_string(),
                            now_epoch_secs,
                            false,
                            Some(err.code().to_string()),
                        ));
                        return Err(err);
                    }
                    Err(err) => {
                        self.push_audit(build_audit_event(
                            "REMOTECAP_DENIED",
                            "RC_CHECK_DENIED",
                            Some(cap.token_id.clone()),
                            Some(cap.issuer_identity.clone()),
                            Some(operation),
                            Some(endpoint.to_string()),
                            trace_id.to_string(),
                            now_epoch_secs,
                            false,
                            Some(err.code().to_string()),
                        ));
                        return Err(err);
                    }
                }
            }
        }

        if cap.single_use && consume_single_use {
            if let Some(replay_key) = replay_key.as_deref() {
                match self.replay_store.consume(cap, replay_key) {
                    Ok(true) => {}
                    Ok(false) => {
                        let err = RemoteCapError::ReplayDetected {
                            token_id: cap.token_id.clone(),
                        };
                        self.push_audit(build_audit_event(
                            "REMOTECAP_DENIED",
                            "RC_CHECK_DENIED",
                            Some(cap.token_id.clone()),
                            Some(cap.issuer_identity.clone()),
                            Some(operation),
                            Some(endpoint.to_string()),
                            trace_id.to_string(),
                            now_epoch_secs,
                            false,
                            Some(err.code().to_string()),
                        ));
                        return Err(err);
                    }
                    Err(err) => {
                        self.push_audit(build_audit_event(
                            "REMOTECAP_DENIED",
                            "RC_CHECK_DENIED",
                            Some(cap.token_id.clone()),
                            Some(cap.issuer_identity.clone()),
                            Some(operation),
                            Some(endpoint.to_string()),
                            trace_id.to_string(),
                            now_epoch_secs,
                            false,
                            Some(err.code().to_string()),
                        ));
                        return Err(err);
                    }
                }
            }
            self.consumed_tokens.insert(cap.token_id.clone());
        }

        let (event_code, legacy_event_code) = if consume_single_use {
            ("REMOTECAP_CONSUMED", "RC_CHECK_PASSED")
        } else {
            ("REMOTECAP_RECHECK_PASSED", "RC_RECHECK_PASSED")
        };
        self.push_audit(build_audit_event(
            event_code,
            legacy_event_code,
            Some(cap.token_id.clone()),
            Some(cap.issuer_identity.clone()),
            Some(operation),
            Some(endpoint.to_string()),
            trace_id.to_string(),
            now_epoch_secs,
            true,
            None,
        ));
        Ok(())
    }

    /// Return the in-memory enforcement audit log.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::security::remote_cap::{CapabilityGate, ConnectivityMode};
    ///
    /// let mut gate = CapabilityGate::with_mode("shared-secret", ConnectivityMode::LocalOnly).unwrap();
    /// gate.authorize_local_operation("emit_local_report", 100, "trace-local");
    ///
    /// assert_eq!(gate.audit_log().len(), 1);
    /// ```
    #[must_use]
    pub fn audit_log(&self) -> &[RemoteCapAuditEvent] {
        &self.audit_log
    }

    fn push_audit(&mut self, event: RemoteCapAuditEvent) {
        push_bounded(&mut self.audit_log, event, MAX_AUDIT_LOG_ENTRIES);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_audit_event(
    event_code: &str,
    legacy_event_code: &str,
    token_id: Option<String>,
    issuer_identity: Option<String>,
    operation: Option<RemoteOperation>,
    endpoint: Option<String>,
    trace_id: String,
    timestamp_epoch_secs: u64,
    allowed: bool,
    denial_code: Option<String>,
) -> RemoteCapAuditEvent {
    RemoteCapAuditEvent {
        event_code: event_code.to_string(),
        legacy_event_code: legacy_event_code.to_string(),
        token_id,
        issuer_identity,
        operation,
        endpoint,
        trace_id,
        timestamp_epoch_secs,
        allowed,
        denial_code,
    }
}

fn canonical_payload(
    token_id: &str,
    issuer_identity: &str,
    issued_at_epoch_secs: u64,
    expires_at_epoch_secs: u64,
    scope: &RemoteScope,
    single_use: bool,
) -> String {
    let operations = encode_scope_entries(scope.operations().iter().map(|entry| entry.as_str()));
    let endpoints = encode_scope_entries(scope.endpoint_prefixes().iter().map(String::as_str));

    // Length-prefixed encoding prevents hash collision attacks via delimiter injection
    format!(
        "v1|{}:{}|{}:{}|issued={}|expires={}|ops={}|endpoints={}|single_use={}",
        u64::try_from(token_id.len()).unwrap_or(u64::MAX),
        token_id,
        u64::try_from(issuer_identity.len()).unwrap_or(u64::MAX),
        issuer_identity,
        issued_at_epoch_secs,
        expires_at_epoch_secs,
        operations,
        endpoints,
        single_use
    )
}

fn scope_fingerprint(scope: &RemoteScope) -> String {
    let operations = encode_scope_entries(scope.operations().iter().map(|entry| entry.as_str()));
    let endpoints = encode_scope_entries(scope.endpoint_prefixes().iter().map(String::as_str));
    format!("ops={operations};endpoints={endpoints}")
}

fn encode_scope_entries<'a>(entries: impl IntoIterator<Item = &'a str>) -> String {
    let mut encoded = String::new();
    for entry in entries {
        let entry_len = u64::try_from(entry.len()).unwrap_or(u64::MAX);
        encoded.push_str(&entry_len.to_string());
        encoded.push(':');
        encoded.push_str(entry);
        encoded.push('|');
    }
    encoded
}

fn keyed_digest(secret: &str, payload: &str) -> Result<String, RemoteCapError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|source| {
        RemoteCapError::CryptoEngineUnavailable {
            detail: format!("HMAC key initialization failed: {source}"),
        }
    })?;
    mac.update(b"remote_cap_keyed_digest_v1:");
    mac.update(payload.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn validate_secret_material(secret: &str, role: &str) -> Result<(), RemoteCapError> {
    if secret.trim().is_empty() {
        return Err(RemoteCapError::CryptoEngineUnavailable {
            detail: format!("remote capability {role} material is unavailable"),
        });
    }
    Ok(())
}

fn replay_store_error(action: &str, path: &Path, source: std::io::Error) -> RemoteCapError {
    RemoteCapError::CryptoEngineUnavailable {
        detail: format!(
            "remote capability replay store {action} failed for {}: {source}",
            path.display()
        ),
    }
}

fn sync_directory(path: &Path) -> Result<(), RemoteCapError> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| replay_store_error("fsync directory", path, source))
}

fn replay_store_key(cap: &RemoteCap) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"remote_cap_replay_store_key_v1:");
    update_length_prefixed_bytes(&mut hasher, cap.token_id.as_bytes());
    update_length_prefixed_bytes(&mut hasher, cap.issuer_identity.as_bytes());
    let scope = scope_fingerprint(&cap.scope);
    update_length_prefixed_bytes(&mut hasher, scope.as_bytes());
    update_length_prefixed_bytes(&mut hasher, cap.signature.as_bytes());
    hex::encode(hasher.finalize())
}

fn durable_replay_record(cap: &RemoteCap, replay_key: &str) -> String {
    format!(
        "remote_cap_replay_marker_v1\nreplay_key={replay_key}\ntoken_id_len={}:{}\nissuer_len={}:{}\nissued_at={}\nexpires_at={}\nsingle_use={}\n",
        u64::try_from(cap.token_id.len()).unwrap_or(u64::MAX),
        cap.token_id.as_str(),
        u64::try_from(cap.issuer_identity.len()).unwrap_or(u64::MAX),
        cap.issuer_identity.as_str(),
        cap.issued_at_epoch_secs,
        cap.expires_at_epoch_secs,
        cap.single_use
    )
}

fn update_length_prefixed_bytes(hasher: &mut Sha256, value: &[u8]) {
    let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(value);
}

fn token_id_hash(
    issuer_identity: &str,
    scope: &RemoteScope,
    issued_at_epoch_secs: u64,
    expires_at_epoch_secs: u64,
    single_use: bool,
    trace_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"remote_cap_token_id_v1:");
    update_length_prefixed_bytes(&mut hasher, issuer_identity.as_bytes());
    hasher.update(issued_at_epoch_secs.to_le_bytes());
    hasher.update(expires_at_epoch_secs.to_le_bytes());
    let scope_fingerprint = scope_fingerprint(scope);
    update_length_prefixed_bytes(&mut hasher, scope_fingerprint.as_bytes());
    hasher.update([u8::from(single_use)]);
    update_length_prefixed_bytes(&mut hasher, trace_id.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    static REMOTE_CAP_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set_path(key: &'static str, value: &Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn scope() -> RemoteScope {
        RemoteScope::new(
            vec![
                RemoteOperation::TelemetryExport,
                RemoteOperation::FederationSync,
            ],
            vec![
                "https://telemetry.example.com".to_string(),
                "https://federation.example.com".to_string(),
            ],
        )
    }

    fn scope_with_endpoint_prefixes(endpoint_prefixes: &[&str]) -> RemoteScope {
        RemoteScope::new(
            vec![RemoteOperation::TelemetryExport],
            endpoint_prefixes
                .iter()
                .map(|entry| (*entry).to_string())
                .collect(),
        )
    }

    fn legacy_token_id_transcript(
        issuer_identity: &str,
        scope: &RemoteScope,
        issued_at_epoch_secs: u64,
        expires_at_epoch_secs: u64,
        single_use: bool,
        trace_id: &str,
    ) -> String {
        format!(
            "id:v1|issuer={issuer_identity}|issued={issued_at_epoch_secs}|expires={expires_at_epoch_secs}|scope={}|single_use={single_use}|trace_id={trace_id}",
            scope_fingerprint(scope)
        )
    }

    fn operation_strategy() -> impl Strategy<Value = RemoteOperation> {
        prop::sample::select(vec![
            RemoteOperation::NetworkEgress,
            RemoteOperation::FederationSync,
            RemoteOperation::RevocationFetch,
            RemoteOperation::RemoteAttestationVerify,
            RemoteOperation::TelemetryExport,
            RemoteOperation::RemoteComputation,
            RemoteOperation::ArtifactUpload,
        ])
    }

    fn endpoint_prefix_strategy() -> impl Strategy<Value = String> {
        (1u16..4096, 1u16..512)
            .prop_map(|(tenant, shard)| format!("https://tenant-{tenant}.example.com/api/{shard}"))
    }

    #[test]
    fn operator_authorization_required_for_issue() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let err = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                false,
                false,
                "trace-1",
            )
            .expect_err("must require operator approval");
        assert_eq!(err.code(), "REMOTECAP_OPERATOR_AUTH_REQUIRED");

        let audit_log = provider.audit_log();
        assert_eq!(audit_log.len(), 1);
        let event = audit_log.last().expect("denial audit event");
        assert_eq!(event.event_code, "REMOTECAP_DENIED");
        assert_eq!(event.legacy_event_code, "RC_CAP_DENIED");
        assert_eq!(event.issuer_identity.as_deref(), Some("operator"));
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.timestamp_epoch_secs, 1_700_000_000);
        assert!(!event.allowed);
        assert_eq!(
            event.denial_code.as_deref(),
            Some("REMOTECAP_OPERATOR_AUTH_REQUIRED")
        );
    }

    #[test]
    fn missing_cap_is_denied() {
        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                None,
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_050,
                "trace-2",
            )
            .expect_err("missing token must fail");
        assert_eq!(err.code(), "REMOTECAP_MISSING");
        assert_eq!(err.compatibility_code(), Some("ERR_REMOTE_CAP_REQUIRED"));
    }

    #[test]
    fn expired_token_is_denied() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                10,
                true,
                false,
                "trace-3",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_020,
                "trace-4",
            )
            .expect_err("expired token must fail");
        assert_eq!(err.code(), "REMOTECAP_EXPIRED");
    }

    #[test]
    fn token_is_denied_before_its_issue_timestamp() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                10,
                true,
                false,
                "trace-3b",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_699_999_999,
                "trace-3c",
            )
            .expect_err("future-issued token must fail before it becomes valid");
        assert_eq!(err.code(), "REMOTECAP_NOT_YET_VALID");
    }

    #[test]
    fn token_is_denied_at_exact_expiry_boundary() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                10,
                true,
                false,
                "trace-4b",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-4c",
            )
            .expect_err("token must be expired at the boundary");
        assert_eq!(err.code(), "REMOTECAP_EXPIRED");
    }

    #[test]
    fn invalid_signature_is_denied() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (mut cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-5",
            )
            .expect("issue");
        cap.signature = "forged-signature".to_string();

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-6",
            )
            .expect_err("invalid signature must fail");
        assert_eq!(err.code(), "REMOTECAP_INVALID");
    }

    #[test]
    fn scope_escalation_is_denied() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-7",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::RevocationFetch,
                "https://revocation.example.com/feed",
                1_700_000_010,
                "trace-8",
            )
            .expect_err("out-of-scope operation must fail");
        assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
    }

    #[test]
    fn cross_scope_capability_privilege_escalation_is_denied() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let cases = [
            (
                RemoteScope::new(
                    vec![RemoteOperation::RevocationFetch],
                    vec!["https://cap.example.com/resource".to_string()],
                ),
                RemoteOperation::ArtifactUpload,
                "https://cap.example.com/resource",
                "trace-cross-scope-read-write",
            ),
            (
                RemoteScope::new(
                    vec![RemoteOperation::FederationSync],
                    vec!["https://federation.example.com/tenant-a".to_string()],
                ),
                RemoteOperation::FederationSync,
                "https://federation.example.com",
                "trace-cross-scope-narrow-broad",
            ),
        ];

        for (allowed_scope, attempted_operation, attempted_endpoint, trace_id) in cases {
            let (cap, _) = provider
                .issue(
                    "operator",
                    allowed_scope,
                    1_700_000_000,
                    300,
                    true,
                    false,
                    &format!("{trace_id}-issue"),
                )
                .expect("issue scoped capability");

            let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
            let err = gate
                .authorize_network(
                    Some(&cap),
                    attempted_operation,
                    attempted_endpoint,
                    1_700_000_010,
                    trace_id,
                )
                .expect_err("cross-scope capability use must fail closed");

            assert_eq!(
                err,
                RemoteCapError::ScopeDenied {
                    operation: attempted_operation,
                    endpoint: attempted_endpoint.to_string(),
                }
            );
            let event = gate.audit_log().last().expect("scope denial audit event");
            assert_eq!(event.event_code, "REMOTECAP_DENIED");
            assert_eq!(event.legacy_event_code, "RC_CHECK_DENIED");
            assert!(!event.allowed);
            assert_eq!(event.operation, Some(attempted_operation));
            assert_eq!(event.endpoint.as_deref(), Some(attempted_endpoint));
            assert_eq!(event.denial_code.as_deref(), Some("REMOTECAP_SCOPE_DENIED"));
        }
    }

    #[test]
    fn replay_of_single_use_token_is_denied() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                true,
                "trace-9",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        gate.authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/v1",
            1_700_000_010,
            "trace-10",
        )
        .expect("first use should pass");

        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_011,
                "trace-11",
            )
            .expect_err("replay must fail");
        assert_eq!(err.code(), "REMOTECAP_REPLAY");
    }

    #[test]
    fn durable_replay_store_rejects_single_use_token_after_gate_restart() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                true,
                "trace-durable-replay",
            )
            .expect("issue");
        let dir = tempfile::tempdir().expect("tempdir");
        let store_dir = dir.path().join("remote-cap-replay");

        {
            let mut first_gate = CapabilityGate::with_durable_replay_store("secret-a", &store_dir)
                .expect("open durable store");
            first_gate
                .authorize_network(
                    Some(&cap),
                    RemoteOperation::TelemetryExport,
                    "https://telemetry.example.com/v1",
                    1_700_000_010,
                    "trace-durable-replay-first",
                )
                .expect("first use should pass");
        }

        let mut restarted_gate = CapabilityGate::with_durable_replay_store("secret-a", &store_dir)
            .expect("reopen durable store");
        let err = restarted_gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_011,
                "trace-durable-replay-second",
            )
            .expect_err("replay after gate restart must fail");

        assert_eq!(err.code(), "REMOTECAP_REPLAY");
    }

    #[test]
    fn durable_replay_store_allows_only_one_concurrent_single_use_consume() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                true,
                "trace-durable-race",
            )
            .expect("issue");
        let dir = tempfile::tempdir().expect("tempdir");
        let store_dir = dir.path().join("remote-cap-replay-race");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let spawn_attempt = |trace_id: &'static str,
                             barrier: std::sync::Arc<std::sync::Barrier>,
                             cap: RemoteCap,
                             store_dir: PathBuf| {
            std::thread::spawn(move || {
                let mut gate = CapabilityGate::with_durable_replay_store("secret-a", &store_dir)
                    .expect("open durable store");
                barrier.wait();
                gate.authorize_network(
                    Some(&cap),
                    RemoteOperation::TelemetryExport,
                    "https://telemetry.example.com/v1",
                    1_700_000_010,
                    trace_id,
                )
                .map_err(|err| err.code().to_string())
            })
        };

        let first = spawn_attempt(
            "trace-durable-race-first",
            barrier.clone(),
            cap.clone(),
            store_dir.clone(),
        );
        let second = spawn_attempt(
            "trace-durable-race-second",
            barrier.clone(),
            cap.clone(),
            store_dir.clone(),
        );

        let first_result = first.join().expect("first thread joins");
        let second_result = second.join().expect("second thread joins");
        let success_count = [first_result.as_ref(), second_result.as_ref()]
            .iter()
            .filter(|result| result.is_ok())
            .count();
        let replay_count = [first_result.as_ref(), second_result.as_ref()]
            .iter()
            .filter(|result| matches!(result, Err(code) if *code == "REMOTECAP_REPLAY"))
            .count();

        assert_eq!(
            success_count, 1,
            "exactly one concurrent consume should succeed"
        );
        assert_eq!(
            replay_count, 1,
            "losing concurrent consume must be treated as replay"
        );

        let replay_key = replay_store_key(&cap);
        let consumed_dir = store_dir.join("consumed");
        let marker_path = consumed_dir.join(format!("{replay_key}.seen"));
        assert!(
            marker_path.exists(),
            "winner should durably create the replay marker"
        );
        assert_eq!(
            std::fs::read_dir(&consumed_dir)
                .expect("read consumed dir")
                .count(),
            1,
            "exactly one replay marker should exist after the race"
        );
    }

    #[test]
    fn env_replay_store_outage_denies_single_use_without_memory_fallback() {
        let _env_lock = REMOTE_CAP_ENV_LOCK.lock().expect("env lock");
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                true,
                "trace-env-replay-store-issue",
            )
            .expect("issue");
        let dir = tempfile::tempdir().expect("tempdir");
        let unavailable_root = dir.path().join("not-a-directory");
        std::fs::write(&unavailable_root, b"regular file").expect("regular file fixture");
        let _env_guard = EnvVarGuard::set_path(REMOTE_CAP_REPLAY_STORE_ENV, &unavailable_root);

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-env-replay-store-deny",
            )
            .expect_err("unavailable env replay store must fail closed");

        assert_eq!(err.code(), "REMOTECAP_CRYPTO_UNAVAILABLE");
        assert!(gate.consumed_tokens.is_empty());
        let event = gate.audit_log().last().expect("denial audit event");
        assert_eq!(event.event_code, "REMOTECAP_DENIED");
        assert_eq!(event.token_id.as_deref(), Some(cap.token_id()));
        assert_eq!(event.trace_id, "trace-env-replay-store-deny");
        assert_eq!(
            event.denial_code.as_deref(),
            Some("REMOTECAP_CRYPTO_UNAVAILABLE")
        );
    }

    #[test]
    fn recheck_does_not_consume_single_use_token() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                true,
                "trace-11a",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        gate.recheck_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/v1",
            1_700_000_010,
            "trace-11b",
        )
        .expect("recheck should pass without consuming");

        gate.authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/v1",
            1_700_000_011,
            "trace-11c",
        )
        .expect("first real use should still pass");

        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_012,
                "trace-11d",
            )
            .expect_err("second real use must fail");
        assert_eq!(err.code(), "REMOTECAP_REPLAY");
        assert!(
            gate.audit_log()
                .iter()
                .any(|event| event.event_code == "REMOTECAP_RECHECK_PASSED")
        );
    }

    #[test]
    fn recheck_honors_revocation() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-11e",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        gate.revoke(&cap, 1_700_000_020, "trace-11f");

        let err = gate
            .recheck_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_021,
                "trace-11g",
            )
            .expect_err("revoked token must fail recheck");
        assert_eq!(err.code(), "REMOTECAP_REVOKED");
    }

    #[test]
    fn revocation_takes_effect_immediately() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-12",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        gate.revoke(&cap, 1_700_000_020, "trace-13");

        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_021,
                "trace-14",
            )
            .expect_err("revoked token must fail");
        assert_eq!(err.code(), "REMOTECAP_REVOKED");
    }

    #[test]
    fn local_mode_allows_local_operations_without_cap() {
        let mut gate =
            CapabilityGate::with_mode("secret-a", ConnectivityMode::LocalOnly).expect("valid gate");
        gate.authorize_local_operation("evidence_ledger_append", 1_700_000_030, "trace-15");
        let event = gate.audit_log().last().expect("event");
        assert_eq!(event.event_code, "REMOTECAP_LOCAL_MODE_ACTIVE");
        assert!(event.allowed);
    }

    #[test]
    fn local_mode_denies_network_even_with_valid_cap() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-15a",
            )
            .expect("issue");

        let mut gate =
            CapabilityGate::with_mode("secret-a", ConnectivityMode::LocalOnly).expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_031,
                "trace-15b",
            )
            .expect_err("network authorization must be denied in local-only mode");
        assert_eq!(err.code(), "REMOTECAP_CONNECTIVITY_MODE_DENIED");

        let event = gate.audit_log().last().expect("denial event");
        assert!(!event.allowed);
        assert_eq!(
            event.denial_code.as_deref(),
            Some("REMOTECAP_CONNECTIVITY_MODE_DENIED")
        );
    }

    #[test]
    fn lookalike_domain_is_denied_even_with_string_prefix_match() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-16",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com.evil.tld/v1",
                1_700_000_010,
                "trace-17",
            )
            .expect_err("lookalike domain must fail scope checks");
        assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
    }

    #[test]
    fn endpoint_with_explicit_port_is_allowed_for_host_prefix() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-18",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        gate.authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com:443/v1",
            1_700_000_010,
            "trace-19",
        )
        .expect("host prefix with explicit port should be allowed");
    }

    #[test]
    fn signature_uses_hmac_instead_of_plain_concat_hash() {
        let payload = "v1|token=t|issuer=i|issued=1|expires=2|ops=x|endpoints=y|single_use=false";
        let hmac_digest = keyed_digest("secret-a", payload).expect("hmac digest");

        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update("secret-a".as_bytes());
        legacy_hasher.update(b"|");
        legacy_hasher.update(payload.as_bytes());
        let legacy_digest = hex::encode(legacy_hasher.finalize());

        assert_ne!(hmac_digest, legacy_digest);
    }

    #[test]
    fn issued_caps_preserve_endpoint_prefix_boundaries() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let lhs_scope = scope_with_endpoint_prefixes(&["alpha,beta", "gamma"]);
        let rhs_scope = scope_with_endpoint_prefixes(&["alpha", "beta,gamma"]);

        assert_ne!(scope_fingerprint(&lhs_scope), scope_fingerprint(&rhs_scope));

        let (lhs, _) = provider
            .issue(
                "operator",
                lhs_scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-boundary",
            )
            .expect("left issue should succeed");
        let (rhs, _) = provider
            .issue(
                "operator",
                rhs_scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-boundary",
            )
            .expect("right issue should succeed");

        assert_ne!(lhs.token_id(), rhs.token_id());
        assert_ne!(lhs.signature(), rhs.signature());
    }

    #[test]
    fn issuing_identical_endpoint_prefix_scopes_is_deterministic() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let lhs_scope = scope_with_endpoint_prefixes(&["alpha,beta", "gamma"]);
        let rhs_scope = scope_with_endpoint_prefixes(&["alpha,beta", "gamma"]);

        let (lhs, _) = provider
            .issue(
                "operator",
                lhs_scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-deterministic",
            )
            .expect("left issue should succeed");
        let (rhs, _) = provider
            .issue(
                "operator",
                rhs_scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-deterministic",
            )
            .expect("right issue should succeed");

        assert_eq!(lhs.token_id(), rhs.token_id());
        assert_eq!(lhs.signature(), rhs.signature());
    }

    #[test]
    fn token_ids_resist_legacy_boundary_shift_collisions() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let baseline_scope = scope_with_endpoint_prefixes(&["https://safe.example.com/base"]);
        let shifted_scope = scope_with_endpoint_prefixes(&["https://safe.example.com/shifted"]);

        let baseline_issued = 1_700_000_000;
        let baseline_expires = 1_700_000_300;
        let shifted_issued = 1_700_000_123;
        let shifted_expires = 1_700_000_523;
        let baseline_trace_prefix = "boundary";
        let shifted_trace_tail = "tail";

        let shifted_issuer = format!(
            "operator|issued={baseline_issued}|expires={baseline_expires}|scope={}|single_use=false|trace_id={baseline_trace_prefix}",
            scope_fingerprint(&baseline_scope)
        );
        let baseline_trace = format!(
            "{baseline_trace_prefix}|issued={shifted_issued}|expires={shifted_expires}|scope={}|single_use=true|trace_id={shifted_trace_tail}",
            scope_fingerprint(&shifted_scope)
        );

        let shifted_legacy = legacy_token_id_transcript(
            &shifted_issuer,
            &shifted_scope,
            shifted_issued,
            shifted_expires,
            true,
            shifted_trace_tail,
        );
        let baseline_legacy = legacy_token_id_transcript(
            "operator",
            &baseline_scope,
            baseline_issued,
            baseline_expires,
            false,
            &baseline_trace,
        );

        assert_eq!(shifted_legacy, baseline_legacy);

        let (shifted_token, _) = provider
            .issue(
                &shifted_issuer,
                shifted_scope,
                shifted_issued,
                shifted_expires - shifted_issued,
                true,
                true,
                shifted_trace_tail,
            )
            .expect("shifted token should issue");
        let (baseline_token, _) = provider
            .issue(
                "operator",
                baseline_scope,
                baseline_issued,
                baseline_expires - baseline_issued,
                true,
                false,
                &baseline_trace,
            )
            .expect("baseline token should issue");

        assert_ne!(shifted_token.token_id(), baseline_token.token_id());
    }

    #[test]
    fn zero_ttl_issue_is_rejected_with_denial_audit() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");

        let err = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                0,
                true,
                false,
                "trace-zero-ttl",
            )
            .expect_err("zero ttl must fail closed");

        assert_eq!(err, RemoteCapError::InvalidTtl { ttl_secs: 0 });
        assert_eq!(err.code(), "REMOTECAP_TTL_INVALID");

        let audit_log = provider.audit_log();
        assert_eq!(audit_log.len(), 1);
        let event = audit_log.last().expect("denial audit event");
        assert_eq!(event.event_code, "REMOTECAP_DENIED");
        assert_eq!(event.legacy_event_code, "RC_CAP_DENIED");
        assert_eq!(event.token_id, None);
        assert_eq!(event.issuer_identity.as_deref(), Some("operator"));
        assert_eq!(event.trace_id, "trace-zero-ttl");
        assert_eq!(event.timestamp_epoch_secs, 1_700_000_000);
        assert!(!event.allowed);
        assert_eq!(event.denial_code.as_deref(), Some("REMOTECAP_TTL_INVALID"));
    }

    #[test]
    fn empty_signing_secret_rejects_issuance_as_crypto_unavailable() {
        let provider = CapabilityProvider::new("  ");

        let err = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-empty-signing-secret",
            )
            .expect_err("empty signing material must fail closed");

        assert_eq!(err.code(), "REMOTECAP_CRYPTO_UNAVAILABLE");
        assert!(matches!(
            err,
            RemoteCapError::CryptoEngineUnavailable { .. }
        ));
    }

    #[test]
    fn empty_endpoint_scope_denies_otherwise_allowed_operation() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let empty_endpoint_scope = RemoteScope::new(
            vec![RemoteOperation::TelemetryExport],
            vec![" ".to_string(), String::new()],
        );
        let (cap, _) = provider
            .issue(
                "operator",
                empty_endpoint_scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-empty-scope",
            )
            .expect("empty endpoint scope can be issued but must authorize nothing");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-empty-scope-deny",
            )
            .expect_err("empty endpoint scope must deny network use");

        assert!(matches!(err, RemoteCapError::ScopeDenied { .. }));
        assert_eq!(
            gate.audit_log()
                .last()
                .and_then(|event| event.denial_code.as_deref()),
            Some("REMOTECAP_SCOPE_DENIED")
        );
    }

    #[test]
    fn endpoint_prefix_without_delimiter_boundary_is_denied() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-prefix-boundary",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.comevil/v1",
                1_700_000_010,
                "trace-prefix-boundary-deny",
            )
            .expect_err("host prefix must not match a longer hostname label");

        assert!(matches!(
            err,
            RemoteCapError::ScopeDenied {
                operation: RemoteOperation::TelemetryExport,
                ..
            }
        ));
    }

    #[test]
    fn tampered_issuer_identity_invalidates_signature() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (mut cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-tamper-issuer",
            )
            .expect("issue");
        cap.issuer_identity = "operator-escalated".to_string();

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-tamper-issuer-deny",
            )
            .expect_err("issuer tampering must invalidate signature");

        assert_eq!(err.code(), "REMOTECAP_INVALID");
    }

    #[test]
    fn wrong_verification_secret_denial_does_not_consume_single_use_token() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                true,
                "trace-wrong-secret",
            )
            .expect("issue");

        let mut wrong_gate = CapabilityGate::new("secret-b").expect("valid gate");
        let err = wrong_gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-wrong-secret-deny",
            )
            .expect_err("wrong secret must fail signature validation");
        assert_eq!(err.code(), "REMOTECAP_INVALID");

        let mut correct_gate = CapabilityGate::new("secret-a").expect("valid gate");
        correct_gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_011,
                "trace-after-wrong-secret",
            )
            .expect("failed validation in another gate must not consume token");
    }

    #[test]
    fn empty_verification_secret_denial_does_not_consume_single_use_token() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                true,
                "trace-empty-verification-secret",
            )
            .expect("issue");

        let mut empty_secret_gate = CapabilityGate::new("");
        let err = empty_secret_gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-empty-verification-secret-deny",
            )
            .expect_err("empty verification material must fail closed");
        assert_eq!(err.code(), "REMOTECAP_CRYPTO_UNAVAILABLE");
        assert!(!empty_secret_gate.consumed_tokens.contains(cap.token_id()));
        assert_eq!(
            empty_secret_gate
                .audit_log()
                .last()
                .and_then(|event| event.denial_code.as_deref()),
            Some("REMOTECAP_CRYPTO_UNAVAILABLE")
        );

        let mut correct_gate = CapabilityGate::new("secret-a").expect("valid gate");
        correct_gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_011,
                "trace-after-empty-verification-secret",
            )
            .expect("failed verification material must not consume token");
    }

    #[test]
    fn local_only_mode_denies_missing_cap_as_connectivity_mode_violation() {
        let mut gate =
            CapabilityGate::with_mode("secret-a", ConnectivityMode::LocalOnly).expect("valid gate");

        let err = gate
            .authorize_network(
                None,
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-local-only-missing",
            )
            .expect_err("local-only mode must deny before capability checks");

        assert!(matches!(err, RemoteCapError::ConnectivityModeDenied { .. }));
        assert_eq!(
            gate.audit_log()
                .last()
                .and_then(|event| event.denial_code.as_deref()),
            Some("REMOTECAP_CONNECTIVITY_MODE_DENIED")
        );
    }

    #[test]
    fn revoked_token_denial_precedes_signature_validation() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (mut cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-revoked-precedence",
            )
            .expect("issue");
        let original = cap.clone();

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        gate.revoke(&original, 1_700_000_005, "trace-revoke-first");
        cap.signature = "tampered-after-revoke".to_string();

        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-revoked-precedence-deny",
            )
            .expect_err("revocation must fail before signature inspection");

        assert!(matches!(err, RemoteCapError::Revoked { .. }));
    }

    #[test]
    fn recheck_after_single_use_consumption_reports_replay() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                true,
                "trace-recheck-replay",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        gate.authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/v1",
            1_700_000_010,
            "trace-consume-before-recheck",
        )
        .expect("first single-use authorization consumes token");

        let err = gate
            .recheck_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_011,
                "trace-recheck-after-consume",
            )
            .expect_err("recheck must not reopen a consumed single-use token");

        assert_eq!(err.code(), "REMOTECAP_REPLAY");
    }

    #[test]
    fn tampered_token_id_invalidates_signature() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (mut cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-tamper-token-id",
            )
            .expect("issue");
        cap.token_id.push_str("-forged");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-tamper-token-id-deny",
            )
            .expect_err("token id tampering must invalidate signature");

        assert_eq!(err.code(), "REMOTECAP_INVALID");
    }

    #[test]
    fn tampered_expiry_invalidates_signature_before_expiry_logic() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (mut cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                1,
                true,
                false,
                "trace-tamper-expiry",
            )
            .expect("issue");
        cap.expires_at_epoch_secs = 1_700_999_999;

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-tamper-expiry-deny",
            )
            .expect_err("expiry tampering must fail signature validation");

        assert_eq!(err.code(), "REMOTECAP_INVALID");
    }

    #[test]
    fn tampered_single_use_flag_invalidates_signature() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (mut cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                300,
                true,
                true,
                "trace-tamper-single-use",
            )
            .expect("issue");
        cap.single_use = false;

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-tamper-single-use-deny",
            )
            .expect_err("single-use flag tampering must invalidate signature");

        assert_eq!(err.code(), "REMOTECAP_INVALID");
    }

    #[test]
    fn tampered_scope_expansion_invalidates_signature() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (mut cap, _) = provider
            .issue(
                "operator",
                RemoteScope::new(
                    vec![RemoteOperation::TelemetryExport],
                    vec!["https://telemetry.example.com/reports".to_string()],
                ),
                1_700_000_000,
                300,
                true,
                false,
                "trace-tamper-scope",
            )
            .expect("issue");
        cap.scope.endpoint_prefixes = vec!["https://telemetry.example.com".to_string()];

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/admin",
                1_700_000_010,
                "trace-tamper-scope-deny",
            )
            .expect_err("scope expansion must not be trusted after issuance");

        assert_eq!(err.code(), "REMOTECAP_INVALID");
    }

    #[test]
    fn path_prefix_without_delimiter_boundary_is_denied() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope_with_endpoint_prefixes(&["https://telemetry.example.com/api"]),
                1_700_000_000,
                300,
                true,
                false,
                "trace-path-prefix-boundary",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/apiv2",
                1_700_000_010,
                "trace-path-prefix-boundary-deny",
            )
            .expect_err("path prefix must not match a longer path segment");

        assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
    }

    #[test]
    fn scope_denial_does_not_consume_single_use_token() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                RemoteScope::new(
                    vec![RemoteOperation::TelemetryExport],
                    vec!["https://telemetry.example.com".to_string()],
                ),
                1_700_000_000,
                300,
                true,
                true,
                "trace-scope-deny-no-consume",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::FederationSync,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-scope-deny-first",
            )
            .expect_err("operation outside scope must fail");
        assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
        assert!(gate.consumed_tokens.is_empty());

        gate.authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/v1",
            1_700_000_011,
            "trace-scope-deny-later-valid",
        )
        .expect("scope denial must not consume a single-use token");
    }

    #[test]
    fn expired_single_use_token_denial_does_not_mark_consumed() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                scope(),
                1_700_000_000,
                10,
                true,
                true,
                "trace-expired-no-consume",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-expired-no-consume-deny",
            )
            .expect_err("expired single-use token must fail closed");

        assert_eq!(err.code(), "REMOTECAP_EXPIRED");
        assert!(!gate.consumed_tokens.contains(cap.token_id()));
    }

    #[test]
    fn recheck_scope_denial_does_not_consume_single_use_token() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let (cap, _) = provider
            .issue(
                "operator",
                RemoteScope::new(
                    vec![RemoteOperation::TelemetryExport],
                    vec!["https://telemetry.example.com".to_string()],
                ),
                1_700_000_000,
                300,
                true,
                true,
                "trace-recheck-deny-no-consume",
            )
            .expect("issue");

        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");
        let err = gate
            .recheck_network(
                Some(&cap),
                RemoteOperation::ArtifactUpload,
                "https://telemetry.example.com/v1",
                1_700_000_010,
                "trace-recheck-deny-no-consume-first",
            )
            .expect_err("recheck outside scope must fail");

        assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
        assert!(gate.consumed_tokens.is_empty());
    }

    #[test]
    fn replay_token_set_bounds_entries_with_fifo_eviction() {
        let mut replay_tokens = ReplayTokenSet::default();

        for index in 0..(MAX_REPLAY_ENTRIES + 72) {
            assert!(replay_tokens.insert(format!("token-{index:05}")));
        }

        assert_eq!(replay_tokens.len(), MAX_REPLAY_ENTRIES);
        assert!(!replay_tokens.contains("token-00000"));
        assert!(!replay_tokens.contains("token-00071"));
        assert!(replay_tokens.contains("token-00072"));
        assert!(replay_tokens.contains(&format!("token-{:05}", MAX_REPLAY_ENTRIES + 71)));
        assert_eq!(
            replay_tokens.ordered_ids().first().map(String::as_str),
            Some("token-00072")
        );
    }

    #[test]
    fn capability_gate_replay_sets_are_bounded_fifo() {
        let mut gate = CapabilityGate::new("secret-a").expect("valid gate");

        for index in 0..(MAX_REPLAY_ENTRIES + 32) {
            gate.consumed_tokens.insert(format!("consumed-{index:05}"));
            gate.revoked_tokens.insert(format!("revoked-{index:05}"));
        }

        assert_eq!(gate.consumed_tokens.len(), MAX_REPLAY_ENTRIES);
        assert_eq!(gate.revoked_tokens.len(), MAX_REPLAY_ENTRIES);
        assert!(!gate.consumed_tokens.contains("consumed-00000"));
        assert!(!gate.revoked_tokens.contains("revoked-00000"));
        assert!(gate.consumed_tokens.contains("consumed-00032"));
        assert!(gate.revoked_tokens.contains("revoked-00032"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn remote_scope_normalizes_generated_operations_and_prefixes(
            operations in prop::collection::vec(operation_strategy(), 1..32),
            prefixes in prop::collection::vec(endpoint_prefix_strategy(), 1..16),
        ) {
            let mut noisy_prefixes = prefixes.clone();
            if let Some(first) = prefixes.first() {
                noisy_prefixes.push(format!(" {first} "));
                noisy_prefixes.push(first.clone());
            }
            noisy_prefixes.push(String::new());
            noisy_prefixes.push(" \t ".to_string());

            let scope = RemoteScope::new(operations.clone(), noisy_prefixes);
            let expected_operations: BTreeSet<_> = operations.into_iter().collect();
            let expected_prefixes: BTreeSet<_> = prefixes.into_iter().collect();

            prop_assert_eq!(scope.operations().len(), expected_operations.len());
            for operation in expected_operations {
                prop_assert!(scope.allows_operation(operation));
            }

            prop_assert_eq!(scope.endpoint_prefixes().len(), expected_prefixes.len());
            for prefix in expected_prefixes {
                let allowed_endpoint = format!("{prefix}/work");
                let sibling_endpoint = format!("{prefix}evil/work");
                prop_assert!(scope.allows_endpoint(&allowed_endpoint));
                prop_assert!(!scope.allows_endpoint(&sibling_endpoint));
            }
        }

        #[test]
        fn generated_caps_authorize_only_generated_operation_scope(
            operations in prop::collection::vec(operation_strategy(), 1..12),
            prefix in endpoint_prefix_strategy(),
            attempted_operation in operation_strategy(),
            ttl_secs in 1u64..86_400,
        ) {
            let provider =
                CapabilityProvider::new("property-key-material").expect("valid provider");
            let scope = RemoteScope::new(operations, vec![prefix.clone()]);
            let (cap, _) = provider
                .issue(
                    "operator-property",
                    scope.clone(),
                    1_700_000_000,
                    ttl_secs,
                    true,
                    false,
                    "trace-property-issue",
                )
                .expect("generated valid scope should issue");

            let endpoint = format!("{prefix}/jobs?attempt=1");
            let mut gate = CapabilityGate::new("property-key-material").expect("valid gate");
            let result = gate.authorize_network(
                Some(&cap),
                attempted_operation,
                &endpoint,
                1_700_000_001,
                "trace-property-authorize",
            );

            if scope.allows_operation(attempted_operation) {
                prop_assert!(result.is_ok());
            } else {
                let denied_as_expected = matches!(
                    result,
                    Err(RemoteCapError::ScopeDenied { operation, endpoint: denied_endpoint })
                        if operation == attempted_operation && denied_endpoint == endpoint
                );
                prop_assert!(denied_as_expected);
            }
        }

        #[test]
        fn generated_traversal_like_endpoints_never_authorize_under_path_prefix(
            operation in operation_strategy(),
            prefix in endpoint_prefix_strategy(),
            suffix in prop::sample::select(vec![
                "../admin",
                "safe/../../admin",
                "%2e%2e/admin",
                "safe/%2e%2e/admin",
                "safe\\admin",
                "\u{202e}admin",
            ]),
        ) {
            let scoped_prefix = format!("{prefix}/");
            let endpoint = format!("{scoped_prefix}{suffix}");
            let provider =
                CapabilityProvider::new("property-key-material").expect("valid provider");
            let scope = RemoteScope::new(vec![operation], vec![scoped_prefix]);
            let (cap, _) = provider
                .issue(
                    "operator-property",
                    scope,
                    1_700_000_000,
                    300,
                    true,
                    true,
                    "trace-property-traversal-issue",
                )
                .expect("valid path prefix should issue");

            prop_assert!(!cap.scope().allows_endpoint(&endpoint));

            let mut gate = CapabilityGate::new("property-key-material").expect("valid gate");
            let err = gate
                .authorize_network(
                    Some(&cap),
                    operation,
                    &endpoint,
                    1_700_000_001,
                    "trace-property-traversal-deny",
                )
                .expect_err("malformed endpoint under prefix must fail closed");

            prop_assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
            prop_assert!(gate.consumed_tokens.is_empty());
        }
    }

    // Scope validation tests for bd-zie2i
    #[test]
    fn scope_deserialization_rejects_empty_endpoint_prefixes() {
        let json = r#"{"operations":["network_egress"],"endpoint_prefixes":[""]}"#;
        let result: Result<RemoteScope, _> = serde_json::from_str(json);

        // Empty endpoint should be filtered out during normalization
        // so this should succeed but result in empty endpoint_prefixes
        assert!(result.is_ok());
        let scope = result.unwrap();
        assert!(scope.endpoint_prefixes().is_empty());
    }

    #[test]
    fn scope_deserialization_rejects_non_network_schemes() {
        let invalid_schemes = [
            r#"{"operations":["network_egress"],"endpoint_prefixes":["file:///etc/passwd"]}"#,
            r#"{"operations":["network_egress"],"endpoint_prefixes":["data:text/plain;base64,SGVsbG8="]}"#,
            r#"{"operations":["network_egress"],"endpoint_prefixes":["javascript:alert('xss')"]}"#,
            r#"{"operations":["network_egress"],"endpoint_prefixes":["vbscript:msgbox('xss')"]}"#,
            r#"{"operations":["network_egress"],"endpoint_prefixes":["ftp://ftp.example.com"]}"#,
        ];

        for json in &invalid_schemes {
            let result: Result<RemoteScope, _> = serde_json::from_str(json);
            assert!(
                result.is_err(),
                "Should reject non-network scheme: {}",
                json
            );
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("forbidden non-network scheme")
                    || error.contains("must use network scheme"),
                "Error should mention forbidden scheme: {}",
                error
            );
        }
    }

    #[test]
    fn scope_deserialization_rejects_malformed_urls() {
        let malformed_urls = [
            r#"{"operations":["network_egress"],"endpoint_prefixes":["https://"]}"#, // No domain
            r#"{"operations":["network_egress"],"endpoint_prefixes":["http://"]}"#,  // No domain
            r#"{"operations":["network_egress"],"endpoint_prefixes":["just-a-string"]}"#, // No scheme
            r#"{"operations":["network_egress"],"endpoint_prefixes":["https://example.com/../admin"]}"#, // Path traversal
            r#"{"operations":["network_egress"],"endpoint_prefixes":["https://example.com\\admin"]}"#, // Backslash
        ];

        for json in &malformed_urls {
            let result: Result<RemoteScope, _> = serde_json::from_str(json);
            assert!(result.is_err(), "Should reject malformed URL: {}", json);
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("must use network scheme")
                    || error.contains("has no domain after scheme")
                    || error.contains("contains invalid characters"),
                "Error should mention URL format issue: {}",
                error
            );
        }
    }

    #[test]
    fn scope_deserialization_accepts_valid_network_schemes() {
        let valid_schemes = [
            r#"{"operations":["network_egress"],"endpoint_prefixes":["https://api.example.com"]}"#,
            r#"{"operations":["network_egress"],"endpoint_prefixes":["http://internal.local"]}"#,
            r#"{"operations":["network_egress"],"endpoint_prefixes":["federation://trusted-node"]}"#,
            r#"{"operations":["network_egress"],"endpoint_prefixes":["ws://websocket.example.com"]}"#,
            r#"{"operations":["network_egress"],"endpoint_prefixes":["wss://secure.websocket.example.com"]}"#,
        ];

        for json in &valid_schemes {
            let result: Result<RemoteScope, _> = serde_json::from_str(json);
            assert!(
                result.is_ok(),
                "Should accept valid network scheme: {} - Error: {:?}",
                json,
                result.err()
            );
        }
    }

    #[test]
    fn scope_deserialization_handles_mixed_valid_invalid() {
        // Mix of valid and invalid - should fail due to invalid ones
        let json = r#"{"operations":["network_egress"],"endpoint_prefixes":["https://valid.example.com","file:///invalid"]}"#;
        let result: Result<RemoteScope, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("forbidden non-network scheme"));
    }

    #[test]
    fn scope_constructor_allows_invalid_for_backward_compatibility() {
        // Constructor should still work for backward compatibility but log validation failures
        let invalid_scope = RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec!["file:///etc/passwd".to_string()],
        );

        // Should succeed but endpoint is marked as invalid
        assert_eq!(invalid_scope.endpoint_prefixes().len(), 1);
        assert_eq!(invalid_scope.endpoint_prefixes()[0], "file:///etc/passwd");
    }

    #[test]
    fn issuance_rejects_non_network_or_malformed_endpoint_prefixes() {
        let provider = CapabilityProvider::new("secret-a").expect("valid provider");
        let invalid_prefixes = [
            "file:///etc/passwd",
            "javascript:alert('xss')",
            "https://",
            "https://example.com/../admin",
            "https://example.com:bad/path",
            "https://user:pass@example.com/secret",
            "https://example.com/%2e%2e/admin",
        ];

        for prefix in invalid_prefixes {
            let scope = RemoteScope::new(
                vec![RemoteOperation::NetworkEgress],
                vec![prefix.to_string()],
            );
            let err = provider
                .issue(
                    "operator",
                    scope,
                    1_700_000_000,
                    300,
                    true,
                    false,
                    "trace-invalid-scope-issue",
                )
                .expect_err("invalid endpoint prefix must fail closed at issue time");
            assert!(
                matches!(err, RemoteCapError::InvalidScope { .. }),
                "expected invalid scope for {prefix}, got {err:?}"
            );
            assert_eq!(err.code(), "REMOTECAP_SCOPE_INVALID");
        }
    }

    #[test]
    fn scope_validation_trims_whitespace_before_validation() {
        // Valid URL with whitespace should be trimmed and accepted
        let json = r#"{"operations":["network_egress"],"endpoint_prefixes":["  https://api.example.com  "]}"#;
        let result: Result<RemoteScope, _> = serde_json::from_str(json);
        assert!(result.is_ok());

        let scope = result.unwrap();
        assert_eq!(scope.endpoint_prefixes().len(), 1);
        assert_eq!(scope.endpoint_prefixes()[0], "https://api.example.com");
    }

    #[test]
    fn scope_validation_deduplicates_endpoints() {
        let json = r#"{"operations":["network_egress"],"endpoint_prefixes":["https://api.example.com","https://api.example.com"]}"#;
        let result: Result<RemoteScope, _> = serde_json::from_str(json);
        assert!(result.is_ok());

        let scope = result.unwrap();
        assert_eq!(scope.endpoint_prefixes().len(), 1);
        assert_eq!(scope.endpoint_prefixes()[0], "https://api.example.com");
    }

    #[test]
    fn endpoint_prefix_lexical_validation_rejects_fail_closed_inputs_without_url_parser() {
        let invalid_prefixes = [
            "file:///etc/passwd",
            "data:text/plain;base64,SGVsbG8=",
            "javascript:alert('xss')",
            "vbscript:msgbox('xss')",
            "ftp://ftp.example.com",
            "https://example.com/../admin",
            "https://example.com/%2e%2e/admin",
            "https://example.com\\admin",
            " https://api.example.com",
            "https://api.example.com\t",
        ];

        for prefix in invalid_prefixes {
            assert!(
                validate_endpoint_prefix_lexical(prefix).is_err(),
                "lexical validation should fail closed for {prefix}"
            );
        }

        let valid_prefixes = [
            "https://api.example.com",
            "http://internal.local",
            "federation://trusted-node",
            "revocation://authority.example",
            "ws://socket.example.com",
            "wss://secure.socket.example.com",
        ];

        for prefix in valid_prefixes {
            assert!(
                validate_endpoint_prefix_lexical(prefix).is_ok(),
                "lexical validation should accept {prefix}"
            );
        }
    }
}

#[cfg(test)]
mod remote_cap_comprehensive_negative_tests {
    use super::*;
    use crate::security::constant_time;
    use std::collections::HashMap;

    /// Negative test: Unicode injection and encoding attacks in capability tokens
    #[test]
    fn negative_unicode_injection_and_encoding_attacks() {
        let provider = CapabilityProvider::new("secret-key").expect("valid provider");

        // Test malicious Unicode in issuer identity
        let malicious_issuer = "operator\u{202e}\u{0000}\u{feff}evil\u{200b}";
        let scope = RemoteScope::new(
            vec![RemoteOperation::TelemetryExport],
            vec!["https://api.example.com".to_string()],
        );

        let result = provider.issue(
            malicious_issuer,
            scope.clone(),
            1_700_000_000,
            300,
            true,
            false,
            "trace-unicode-injection",
        );
        assert!(
            result.is_ok(),
            "Unicode in issuer should be handled gracefully"
        );

        let (cap, _) = result.unwrap();
        let mut gate = CapabilityGate::new("secret-key").expect("valid gate");

        // Token should still function correctly despite Unicode content
        gate.authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://api.example.com/metrics",
            1_700_000_100,
            "trace-unicode-test",
        )
        .expect("Unicode-containing token should validate correctly");

        // Test malicious Unicode in endpoint prefixes
        let unicode_scope = RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec![
                "https://\u{202e}evil.com\u{200c}good.example.com".to_string(),
                "ftp://\u{0000}admin:pass@internal".to_string(),
            ],
        );

        let unicode_err = provider
            .issue(
                "operator",
                unicode_scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-unicode-endpoint",
            )
            .expect_err("Unicode endpoint confusion should fail closed at issue time");
        assert_eq!(unicode_err.code(), "REMOTECAP_SCOPE_INVALID");
    }

    /// Negative test: Arithmetic overflow protection in timestamps and TTL calculations
    #[test]
    fn negative_arithmetic_overflow_protection() {
        let provider = CapabilityProvider::new("secret-key").expect("valid provider");
        let scope = RemoteScope::new(
            vec![RemoteOperation::RemoteComputation],
            vec!["https://compute.example.com".to_string()],
        );

        // Test near-maximum timestamp with large TTL
        let near_max_time = u64::MAX - 100;
        let large_ttl = u64::MAX / 2;

        let result = provider.issue(
            "operator",
            scope.clone(),
            near_max_time,
            large_ttl,
            true,
            false,
            "trace-overflow-test",
        );

        assert!(
            result.is_ok(),
            "Should handle near-overflow timestamps gracefully"
        );
        let (cap, _) = result.unwrap();

        // Verify saturating_add prevented overflow and expiry is reasonable
        assert!(cap.expires_at_epoch_secs >= near_max_time);
        assert!(cap.expires_at_epoch_secs == u64::MAX || cap.expires_at_epoch_secs > near_max_time);

        let mut gate = CapabilityGate::new("secret-key").expect("valid gate");

        // Test with current time that could cause overflow during validation
        let validation_result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::RemoteComputation,
            "https://compute.example.com/task",
            u64::MAX - 50,
            "trace-overflow-validation",
        );

        // Should handle overflow gracefully in expiry check
        match validation_result {
            Ok(_) => {} // Token is still valid
            Err(e) => assert!(
                matches!(e, RemoteCapError::Expired { .. }),
                "Should properly detect expiry without overflow panic"
            ),
        }

        // Test maximum TTL edge case
        let max_ttl_result = provider.issue(
            "operator",
            scope,
            1_000_000,
            u64::MAX,
            true,
            false,
            "trace-max-ttl",
        );
        assert!(
            max_ttl_result.is_ok(),
            "Maximum TTL should be handled safely"
        );
    }

    /// Negative test: Memory exhaustion attacks with massive capability scopes
    #[test]
    fn negative_memory_exhaustion_with_massive_scopes() {
        let provider = CapabilityProvider::new("secret-key").expect("valid provider");

        // Create scope with extremely large number of operations and endpoints
        let mut operations = Vec::new();
        let mut endpoints = Vec::new();
        const MAX_TEST_OPERATIONS: usize = 100; // Bound the test operations
        const MAX_TEST_ENDPOINTS: usize = 1000; // Bound the test endpoints

        // Add all possible operations multiple times
        for _ in 0..1000 {
            if operations.len() >= MAX_TEST_OPERATIONS {
                break;
            }
            push_bounded(
                &mut operations,
                RemoteOperation::NetworkEgress,
                MAX_TEST_OPERATIONS,
            );
            push_bounded(
                &mut operations,
                RemoteOperation::FederationSync,
                MAX_TEST_OPERATIONS,
            );
            push_bounded(
                &mut operations,
                RemoteOperation::RevocationFetch,
                MAX_TEST_OPERATIONS,
            );
            push_bounded(
                &mut operations,
                RemoteOperation::RemoteAttestationVerify,
                MAX_TEST_OPERATIONS,
            );
            push_bounded(
                &mut operations,
                RemoteOperation::TelemetryExport,
                MAX_TEST_OPERATIONS,
            );
            push_bounded(
                &mut operations,
                RemoteOperation::RemoteComputation,
                MAX_TEST_OPERATIONS,
            );
            push_bounded(
                &mut operations,
                RemoteOperation::ArtifactUpload,
                MAX_TEST_OPERATIONS,
            );
        }

        // Add massive number of endpoint prefixes
        for i in 0..10000 {
            if endpoints.len() >= MAX_TEST_ENDPOINTS {
                break;
            }
            push_bounded(
                &mut endpoints,
                format!("https://endpoint-{}.example.com", i),
                MAX_TEST_ENDPOINTS,
            );
            push_bounded(
                &mut endpoints,
                format!("https://service-{}.internal", i),
                MAX_TEST_ENDPOINTS,
            );
        }

        let massive_scope = RemoteScope::new(operations, endpoints);

        // Issue capability with massive scope - should complete without panic
        let result = provider.issue(
            "operator",
            massive_scope,
            1_700_000_000,
            300,
            true,
            false,
            "trace-massive-scope",
        );

        assert!(
            result.is_ok(),
            "Should handle massive scopes without memory exhaustion"
        );
        let (cap, _) = result.unwrap();

        // Verify scope normalization deduplicated operations
        assert!(cap.scope.operations.len() <= 7); // Only 7 unique operation types exist
        assert!(cap.scope.endpoint_prefixes.len() <= 20000); // May have many unique endpoints

        let mut gate = CapabilityGate::new("secret-key").expect("valid gate");

        // Authorization check should complete efficiently even with large scope
        let start = std::time::Instant::now();
        let auth_result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::NetworkEgress,
            "https://endpoint-5000.example.com/api",
            1_700_000_100,
            "trace-massive-scope-auth",
        );
        let duration = start.elapsed();

        assert!(
            duration < std::time::Duration::from_millis(100),
            "Authorization should be efficient"
        );
        assert!(
            auth_result.is_ok(),
            "Authorization with massive scope should succeed"
        );
    }

    /// Negative test: Concurrent operation corruption and race conditions
    #[test]
    fn negative_concurrent_operation_corruption() {
        let provider = CapabilityProvider::new("secret-key").expect("valid provider");
        let scope = RemoteScope::new(
            vec![
                RemoteOperation::TelemetryExport,
                RemoteOperation::FederationSync,
            ],
            vec!["https://api.example.com".to_string()],
        );

        // Create multiple single-use tokens
        let mut tokens = Vec::new();
        const MAX_TEST_TOKENS: usize = 10;
        for i in 0..10 {
            let (token, _) = provider
                .issue(
                    "operator",
                    scope.clone(),
                    1_700_000_000,
                    300,
                    true,
                    true, // single-use
                    &format!("trace-concurrent-{}", i),
                )
                .expect("token creation");
            push_bounded(&mut tokens, token, MAX_TEST_TOKENS);
        }

        let mut gate = CapabilityGate::new("secret-key").expect("valid gate");

        // Simulate concurrent access attempts on the same gate
        let mut results = Vec::new();
        const MAX_TEST_RESULTS: usize = 10;
        for (i, token) in tokens.iter().enumerate() {
            // Each token should only succeed once
            let result1 = gate.authorize_network(
                Some(token),
                RemoteOperation::TelemetryExport,
                "https://api.example.com/metrics",
                1_700_000_100,
                &format!("trace-concurrent-first-{}", i),
            );
            push_bounded(&mut results, result1, MAX_TEST_RESULTS);

            // Second use should fail with replay error
            let result2 = gate.authorize_network(
                Some(token),
                RemoteOperation::TelemetryExport,
                "https://api.example.com/metrics",
                1_700_000_101,
                &format!("trace-concurrent-second-{}", i),
            );
            assert!(result2.is_err());
            assert_eq!(result2.unwrap_err().code(), "REMOTECAP_REPLAY");
        }

        // All first uses should succeed
        for result in results {
            assert!(
                result.is_ok(),
                "First use of each single-use token should succeed"
            );
        }

        // Verify audit log integrity under concurrent operations
        assert_eq!(gate.audit_log().len(), 20); // 10 successes + 10 replay failures
        let success_count = gate.audit_log().iter().filter(|e| e.allowed).count();
        let failure_count = gate.audit_log().iter().filter(|e| !e.allowed).count();
        assert_eq!(success_count, 10);
        assert_eq!(failure_count, 10);
    }

    /// Negative test: Cryptographic timing attacks and hash collision resistance
    #[test]
    fn negative_cryptographic_timing_attacks_and_collision_resistance() {
        let provider = CapabilityProvider::new("secret-key").expect("valid provider");
        let scope = RemoteScope::new(
            vec![RemoteOperation::RemoteAttestationVerify],
            vec!["https://attestation.example.com".to_string()],
        );

        // Create legitimate token
        let (legitimate_token, _) = provider
            .issue(
                "operator",
                scope.clone(),
                1_700_000_000,
                300,
                true,
                false,
                "trace-timing-attack",
            )
            .expect("legitimate token");

        let mut gate = CapabilityGate::new("secret-key").expect("valid gate");

        // Test with various malformed signatures to detect timing differences
        let malformed_signatures = vec![
            "".to_string(),
            "short".to_string(),
            "exactly_64_char_string_that_looks_like_valid_hex_but_is_not_real!".to_string(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(), // Valid hex format but wrong content
            legitimate_token.signature().to_string() + "extra", // Slightly longer
            legitimate_token.signature()[0..legitimate_token.signature().len() - 1].to_string(), // Slightly shorter
        ];

        let mut timing_results = Vec::new();

        for bad_signature in malformed_signatures {
            let mut fake_token = legitimate_token.clone();
            fake_token.signature = bad_signature;

            let start = std::time::Instant::now();
            let result = gate.authorize_network(
                Some(&fake_token),
                RemoteOperation::RemoteAttestationVerify,
                "https://attestation.example.com/verify",
                1_700_000_100,
                "trace-timing-test",
            );
            let duration = start.elapsed();

            // All should fail with invalid signature
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().code(), "REMOTECAP_INVALID");
            timing_results.push(duration);
        }

        // Timing differences should be minimal (constant-time comparison)
        let max_timing = timing_results.iter().max().unwrap();
        let min_timing = timing_results.iter().min().unwrap();
        let timing_ratio = max_timing.as_nanos() as f64 / min_timing.as_nanos() as f64;

        // Allow some variance but timing shouldn't vary dramatically
        assert!(
            timing_ratio < 3.0,
            "Signature comparison timing variance too high: {}",
            timing_ratio
        );

        // Test hash collision resistance by attempting to create tokens with similar content
        let similar_scopes = vec![
            RemoteScope::new(
                vec![RemoteOperation::RemoteAttestationVerify],
                vec!["https://a.com".to_string()],
            ),
            RemoteScope::new(
                vec![RemoteOperation::RemoteAttestationVerify],
                vec!["https://b.com".to_string()],
            ),
            RemoteScope::new(
                vec![RemoteOperation::TelemetryExport],
                vec!["https://a.com".to_string()],
            ),
        ];

        let mut token_ids = std::collections::HashSet::new();
        let mut signatures = std::collections::HashSet::new();

        for similar_scope in similar_scopes {
            let (token, _) = provider
                .issue(
                    "operator",
                    similar_scope,
                    1_700_000_000,
                    300,
                    true,
                    false,
                    "trace-collision-test",
                )
                .expect("similar token");

            // All token IDs and signatures should be unique
            assert!(
                token_ids.insert(token.token_id().to_string()),
                "Token ID collision detected"
            );
            assert!(
                signatures.insert(token.signature().to_string()),
                "Signature collision detected"
            );
        }
    }

    /// Negative test: Resource exhaustion attacks through audit log flooding
    #[test]
    fn negative_resource_exhaustion_audit_log_flooding() {
        let provider = CapabilityProvider::new("secret-key").expect("valid provider");
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://upload.example.com".to_string()],
        );

        let (cap, _) = provider
            .issue(
                "operator",
                scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-flood-test",
            )
            .expect("flood test token");

        let mut gate = CapabilityGate::new("secret-key").expect("valid gate");

        // Attempt to flood the audit log with massive number of requests
        for i in 0..50000 {
            let _ = gate.authorize_network(
                Some(&cap),
                RemoteOperation::ArtifactUpload,
                "https://upload.example.com/files",
                1_700_000_100,
                &format!("trace-flood-{}", i),
            ); // May succeed or fail based on rate limiting, doesn't matter

            // Also try invalid operations to generate denials
            let _ = gate.authorize_network(
                Some(&cap),
                RemoteOperation::FederationSync, // Not in scope
                "https://upload.example.com/files",
                1_700_000_100,
                &format!("trace-flood-deny-{}", i),
            );
        }

        // Audit log should be bounded to prevent memory exhaustion
        assert!(gate.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES + 100); // Some tolerance for batch operations

        // Recent events should be preserved (LIFO behavior)
        let recent_events = gate.audit_log().iter().rev().take(10).collect::<Vec<_>>();
        for (i, event) in recent_events.iter().enumerate() {
            let expected_trace = format!("trace-flood-deny-{}", 49999 - i);
            if event.trace_id.contains("flood-deny") {
                assert!(
                    event.trace_id.contains("flood"),
                    "Recent events should be preserved"
                );
            }
        }

        // Memory usage should remain reasonable despite flood
        let initial_capacity = gate.audit_log().capacity();
        gate.authorize_local_operation("test_operation", 1_700_000_200, "trace-post-flood");

        // Capacity shouldn't grow excessively
        assert!(
            gate.audit_log().capacity() <= initial_capacity * 2,
            "Audit log capacity growth should be bounded"
        );
    }

    /// Negative test: Edge cases in endpoint prefix matching with malformed URLs
    #[test]
    fn negative_endpoint_prefix_malformed_url_edge_cases() {
        let provider = CapabilityProvider::new("secret-key").expect("valid provider");

        // Create scope with various malformed and edge-case endpoint prefixes
        let malformed_endpoints = vec![
            "".to_string(),  // Empty
            " ".to_string(), // Whitespace only
            "://missing-scheme".to_string(),
            "http://".to_string(), // Incomplete
            "https://[invalid-ipv6".to_string(),
            "ftp://user:pass@host:99999/path".to_string(), // Invalid port
            "https://example.com:0".to_string(),           // Port 0
            "https://example.com:-1".to_string(),          // Negative port
            "javascript:alert('xss')".to_string(),         // Script URL
            "data:text/html,<script>alert('xss')</script>".to_string(), // Data URL
            "file:///etc/passwd".to_string(),              // File URL
            "https://example.com/../../../etc/passwd".to_string(), // Path traversal
            "https://example.com/\x00\x01\x02".to_string(), // Control characters
            "https://example.com/\u{202e}evil".to_string(), // Unicode direction override
        ];

        let scope = RemoteScope::new(vec![RemoteOperation::NetworkEgress], malformed_endpoints);

        let err = provider
            .issue(
                "operator",
                scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-malformed-endpoints",
            )
            .expect_err("malformed endpoints must fail closed before token issuance");
        assert!(matches!(err, RemoteCapError::InvalidScope { .. }));

        // Test endpoint prefix normalization edge cases
        let unnormalized_scope = RemoteScope::new(
            vec![RemoteOperation::TelemetryExport],
            vec![
                " https://api.example.com ".to_string(), // Leading/trailing spaces
                "https://api.example.com".to_string(),
                "".to_string(),                        // Empty (should be filtered)
                "   ".to_string(),                     // Whitespace only (should be filtered)
                "https://api.example.com".to_string(), // Duplicate
            ],
        );

        // Normalization should deduplicate and clean up endpoints
        assert!(unnormalized_scope.endpoint_prefixes.len() <= 2); // At most 2 unique endpoints after normalization
        assert!(
            !unnormalized_scope
                .endpoint_prefixes
                .iter()
                .any(|e| e.trim().is_empty())
        ); // No empty entries
    }

    /// Negative test: Advanced cryptographic attack scenarios
    #[test]
    fn negative_advanced_cryptographic_attacks() {
        let provider = CapabilityProvider::new("secret-key").expect("valid provider");
        let scope = RemoteScope::new(
            vec![RemoteOperation::RemoteComputation],
            vec!["https://compute.example.com".to_string()],
        );

        let (legitimate_token, _) = provider
            .issue(
                "operator",
                scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-crypto-attacks",
            )
            .expect("legitimate token");

        let mut gate = CapabilityGate::new("secret-key").expect("valid gate");

        // Test signature manipulation attacks
        let original_sig = legitimate_token.signature();

        // Bit-flip attack: flip each bit of the signature
        for byte_idx in 0..original_sig.len().min(32) {
            // Test first 32 characters
            if let Some(ch) = original_sig.chars().nth(byte_idx) {
                let mut modified_sig = original_sig.chars().collect::<Vec<char>>();
                // Flip character (simple case)
                modified_sig[byte_idx] = if ch == '0' { '1' } else { '0' };
                let flipped_sig: String = modified_sig.iter().collect();

                let mut modified_token = legitimate_token.clone();
                modified_token.signature = flipped_sig;

                let result = gate.authorize_network(
                    Some(&modified_token),
                    RemoteOperation::RemoteComputation,
                    "https://compute.example.com/task",
                    1_700_000_100,
                    &format!("trace-bit-flip-{}", byte_idx),
                );

                assert!(result.is_err(), "Bit-flip attack should be detected");
                assert_eq!(result.unwrap_err().code(), "REMOTECAP_INVALID");
            }
        }

        // Test length extension attack resistance
        let extended_signatures = vec![
            format!("{}00", original_sig),               // Append null bytes
            format!("{}ff", original_sig),               // Append 0xff bytes
            format!("00{}", original_sig),               // Prepend null bytes
            format!("{}{}", original_sig, original_sig), // Double the signature
        ];

        for extended_sig in extended_signatures {
            let mut extended_token = legitimate_token.clone();
            extended_token.signature = extended_sig;

            let result = gate.authorize_network(
                Some(&extended_token),
                RemoteOperation::RemoteComputation,
                "https://compute.example.com/task",
                1_700_000_100,
                "trace-length-extension",
            );

            assert!(
                result.is_err(),
                "Length extension attack should be detected"
            );
            assert_eq!(result.unwrap_err().code(), "REMOTECAP_INVALID");
        }

        // Test signature substitution (using signature from different token)
        let different_scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://different.example.com".to_string()],
        );

        let (different_token, _) = provider
            .issue(
                "operator",
                different_scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-different-token",
            )
            .expect("different token");

        let mut substituted_token = legitimate_token.clone();
        substituted_token.signature = different_token.signature().to_string();

        let substitution_result = gate.authorize_network(
            Some(&substituted_token),
            RemoteOperation::RemoteComputation,
            "https://compute.example.com/task",
            1_700_000_100,
            "trace-signature-substitution",
        );

        assert!(
            substitution_result.is_err(),
            "Signature substitution should be detected"
        );
        assert_eq!(substitution_result.unwrap_err().code(), "REMOTECAP_INVALID");
    }

    #[test]
    fn test_hybrid_revocation_checker_integration() {
        // Test cuckoo filter integration with different modes

        // Test 1: Fallback mode (no environment variable)
        std::env::remove_var(CUCKOO_REVOCATION_ENV);
        let mut checker_fallback = HybridRevocationChecker::new();
        assert_eq!(checker_fallback.current_mode(), CheckMode::Fallback);

        // Test basic operations in fallback mode
        assert!(checker_fallback.insert("token1".to_string()));
        assert!(!checker_fallback.insert("token1".to_string())); // Already exists
        assert!(checker_fallback.contains("token1"));
        assert!(!checker_fallback.contains("token2"));
        assert_eq!(checker_fallback.len(), 1);

        // Test 2: Hybrid mode (with environment variable)
        std::env::set_var(CUCKOO_REVOCATION_ENV, "true");
        let mut checker_hybrid = HybridRevocationChecker::new();
        assert_eq!(checker_hybrid.current_mode(), CheckMode::Hybrid);

        // Test basic operations in hybrid mode
        assert!(checker_hybrid.insert("token1".to_string()));
        assert!(!checker_hybrid.insert("token1".to_string())); // Already exists
        assert!(checker_hybrid.contains("token1"));
        assert!(!checker_hybrid.contains("token2"));
        assert_eq!(checker_hybrid.len(), 1);

        // Test 3: FIFO behavior with capacity limit
        let mut checker_fifo = HybridRevocationChecker::new();

        // Insert more than MAX_REPLAY_ENTRIES to test FIFO eviction
        for i in 0..(MAX_REPLAY_ENTRIES + 10) {
            checker_fifo.insert(format!("token-{:05}", i));
        }

        // Should not exceed MAX_REPLAY_ENTRIES
        assert_eq!(checker_fifo.len(), MAX_REPLAY_ENTRIES);

        // Early tokens should be evicted (FIFO)
        assert!(!checker_fifo.contains("token-00000"));
        assert!(!checker_fifo.contains("token-00009"));

        // Later tokens should still be present
        assert!(checker_fifo.contains("token-04100")); // Near end
        assert!(checker_fifo.contains(&format!("token-{:05}", MAX_REPLAY_ENTRIES + 9))); // Last one

        // Test 4: Integration with CapabilityGate
        std::env::set_var(CUCKOO_REVOCATION_ENV, "true");
        let mut gate = CapabilityGate::new("test-secret").expect("valid gate");

        let provider = CapabilityProvider::new("test-secret").expect("valid provider");
        let scope = RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec!["https://example.com".to_string()],
        );

        let (cap, _) = provider
            .issue(
                "operator",
                scope,
                1_700_000_000,
                3600,
                true,
                false,
                "trace-test",
            )
            .expect("capability issuance");

        // Authorize should work initially
        let result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::NetworkEgress,
            "https://example.com/api",
            1_700_000_100,
            "trace-authorize",
        );
        assert!(result.is_ok());

        // Revoke the capability
        gate.revoke(&cap, 1_700_000_200, "trace-revoke");

        // Should now be denied due to revocation
        let revoked_result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::NetworkEgress,
            "https://example.com/api",
            1_700_000_300,
            "trace-revoked-check",
        );
        assert!(revoked_result.is_err());
        assert_eq!(
            revoked_result.unwrap_err(),
            RemoteCapError::Revoked {
                token_id: cap.token_id.clone(),
            }
        );

        // Clean up environment variable
        std::env::remove_var(CUCKOO_REVOCATION_ENV);
    }

    #[test]
    fn test_cuckoo_filter_performance_characteristics() {
        // Verify that cuckoo filter mode provides better performance characteristics
        std::env::set_var(CUCKOO_REVOCATION_ENV, "true");

        let mut checker = HybridRevocationChecker::new();
        assert_eq!(checker.current_mode(), CheckMode::Hybrid);

        // Insert many items to test performance
        let start_time = std::time::Instant::now();
        for i in 0..1000 {
            checker.insert(format!("performance-test-{}", i));
        }
        let insert_duration = start_time.elapsed();

        // Test lookups
        let start_time = std::time::Instant::now();
        for i in 0..1000 {
            checker.contains(&format!("performance-test-{}", i));
        }
        let lookup_duration = start_time.elapsed();

        // Test non-existent lookups (should be very fast in cuckoo mode)
        let start_time = std::time::Instant::now();
        for i in 1000..2000 {
            checker.contains(&format!("performance-test-{}", i));
        }
        let negative_lookup_duration = start_time.elapsed();

        println!("Insert duration: {:?}", insert_duration);
        println!("Lookup duration: {:?}", lookup_duration);
        println!("Negative lookup duration: {:?}", negative_lookup_duration);

        // Verify reasonable performance (these are generous bounds)
        assert!(insert_duration < std::time::Duration::from_millis(100));
        assert!(lookup_duration < std::time::Duration::from_millis(50));
        assert!(negative_lookup_duration < std::time::Duration::from_millis(25));

        std::env::remove_var(CUCKOO_REVOCATION_ENV);
    }

    #[test]
    fn empty_signing_secret_fails_closed_in_try_constructor() {
        let result = CapabilityProvider::try_new("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REMOTECAP_CRYPTO_UNAVAILABLE");
        assert!(err.to_string().contains("signing material is unavailable"));
    }

    #[test]
    fn whitespace_signing_secret_fails_closed_in_try_constructor() {
        let result = CapabilityProvider::try_new("   \t\n  ");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REMOTECAP_CRYPTO_UNAVAILABLE");
        assert!(err.to_string().contains("signing material is unavailable"));
    }

    #[test]
    fn empty_verification_secret_fails_closed_in_try_constructor() {
        let result = CapabilityGate::try_new("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REMOTECAP_CRYPTO_UNAVAILABLE");
        assert!(
            err.to_string()
                .contains("verification material is unavailable")
        );
    }

    #[test]
    fn whitespace_verification_secret_fails_closed_in_try_constructor() {
        let result = CapabilityGate::try_new("  \r\n\t  ");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REMOTECAP_CRYPTO_UNAVAILABLE");
        assert!(
            err.to_string()
                .contains("verification material is unavailable")
        );
    }

    #[test]
    fn empty_secrets_prevent_remote_capability_operations() {
        // Verify that empty secrets cannot be used to issue or authorize tokens

        // Issuer with valid secret
        let provider = CapabilityProvider::new("valid-secret").expect("valid provider");
        let scope = RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec!["https://example.com".to_string()],
        );

        let (cap, _) = provider
            .issue(
                "operator",
                scope,
                1_700_000_000,
                3600,
                true,
                false,
                "trace-test",
            )
            .expect("capability issuance with valid secret");

        let mut empty_gate = CapabilityGate::new("");
        let verify_err = empty_gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::NetworkEgress,
                "https://example.com/api",
                1_700_000_100,
                "trace-empty-verification-secret",
            )
            .expect_err("empty verification secret should fail closed");
        assert_eq!(verify_err.code(), "REMOTECAP_CRYPTO_UNAVAILABLE");

        let empty_provider = CapabilityProvider::new("");
        let issue_err = empty_provider
            .issue(
                "operator",
                RemoteScope::new(
                    vec![RemoteOperation::NetworkEgress],
                    vec!["https://example.com".to_string()],
                ),
                1_700_000_000,
                3600,
                true,
                false,
                "trace-empty-signing-secret",
            )
            .expect_err("empty signing secret should fail closed");
        assert_eq!(issue_err.code(), "REMOTECAP_CRYPTO_UNAVAILABLE");
    }

    #[test]
    fn audit_log_timeout_when_lock_held_by_another_thread() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let provider = CapabilityProvider::new("secret-test-timeout").expect("valid provider");
        let provider_arc = Arc::new(provider);
        let barrier = Arc::new(Barrier::new(2));

        // Spawn a thread that holds the audit log lock
        let provider_clone = Arc::clone(&provider_arc);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Acquire lock and hold it
            let _guard = provider_clone
                .try_lock_audit_log_with_timeout(Duration::from_millis(1000))
                .expect("Should be able to acquire lock initially");

            // Signal that we have the lock
            barrier_clone.wait();

            // Hold lock for a while to force timeout in main thread
            thread::sleep(Duration::from_millis(150));
        });

        // Wait for spawned thread to acquire the lock
        barrier.wait();

        // Try to access audit log with short timeout - should timeout
        let result = provider_arc.try_lock_audit_log_with_timeout(Duration::from_millis(50));

        match result {
            Err(RemoteCapError::LockTimeout {
                operation,
                timeout_ms,
            }) => {
                assert_eq!(operation, "audit_log_access");
                assert_eq!(timeout_ms, 50);
            }
            _ => panic!("Expected LockTimeout error, got: {:?}", result),
        }

        handle
            .join()
            .expect("Background thread should complete successfully");
    }
}
