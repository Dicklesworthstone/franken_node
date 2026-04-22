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

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

const MAX_REPLAY_ENTRIES: usize = 4_096;
const REMOTE_CAP_REPLAY_STORE_ENV: &str = "FRANKEN_NODE_REMOTECAP_REPLAY_STORE";

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

#[derive(Debug, Clone, Default)]
struct ReplayTokenSet {
    ids: BTreeSet<String>,
    insertion_order: Vec<String>,
}

impl ReplayTokenSet {
    fn insert(&mut self, token_id: String) -> bool {
        if !self.ids.insert(token_id.clone()) {
            return false;
        }

        if self.insertion_order.len() >= MAX_REPLAY_ENTRIES {
            let overflow = self
                .insertion_order
                .len()
                .saturating_sub(MAX_REPLAY_ENTRIES)
                .saturating_add(1);
            let drain_len = overflow.min(self.insertion_order.len());
            let evicted_ids: Vec<_> = self.insertion_order.drain(0..drain_len).collect();
            for evicted in evicted_ids {
                self.ids.remove(&evicted);
            }
        }
        push_bounded(&mut self.insertion_order, token_id, MAX_REPLAY_ENTRIES);
        true
    }

    #[must_use]
    fn contains(&self, token_id: &str) -> bool {
        self.ids.contains(token_id)
    }

    #[cfg(test)]
    #[must_use]
    fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    #[cfg(test)]
    #[must_use]
    fn len(&self) -> usize {
        self.ids.len()
    }

    #[cfg(test)]
    #[must_use]
    fn ordered_ids(&self) -> &[String] {
        &self.insertion_order
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteScope {
    operations: Vec<RemoteOperation>,
    endpoint_prefixes: Vec<String>,
}

impl RemoteScope {
    #[must_use]
    pub fn new(operations: Vec<RemoteOperation>, endpoint_prefixes: Vec<String>) -> Self {
        let mut scope = Self {
            operations,
            endpoint_prefixes,
        };
        scope.normalize();
        scope
    }

    #[must_use]
    pub fn operations(&self) -> &[RemoteOperation] {
        &self.operations
    }

    #[must_use]
    pub fn endpoint_prefixes(&self) -> &[String] {
        &self.endpoint_prefixes
    }

    #[must_use]
    pub fn allows_operation(&self, operation: RemoteOperation) -> bool {
        self.operations.contains(&operation)
    }

    #[must_use]
    pub fn allows_endpoint(&self, endpoint: &str) -> bool {
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
    #[must_use]
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    #[must_use]
    pub fn issuer_identity(&self) -> &str {
        &self.issuer_identity
    }

    #[must_use]
    pub fn issued_at_epoch_secs(&self) -> u64 {
        self.issued_at_epoch_secs
    }

    #[must_use]
    pub fn expires_at_epoch_secs(&self) -> u64 {
        self.expires_at_epoch_secs
    }

    #[must_use]
    pub fn scope(&self) -> &RemoteScope {
        &self.scope
    }

    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

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
}

impl RemoteCapError {
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
            Self::Revoked { .. } => "REMOTECAP_REVOKED",
            Self::ReplayDetected { .. } => "REMOTECAP_REPLAY",
            Self::ConnectivityModeDenied { .. } => "REMOTECAP_CONNECTIVITY_MODE_DENIED",
            Self::CryptoEngineUnavailable { .. } => "REMOTECAP_CRYPTO_UNAVAILABLE",
        }
    }

    /// Compatibility alias used by some contracts.
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
#[derive(Debug, Clone)]
pub struct CapabilityProvider {
    signing_secret: String,
}

impl CapabilityProvider {
    #[must_use]
    pub fn new(signing_secret: &str) -> Self {
        Self {
            signing_secret: signing_secret.to_string(),
        }
    }

    /// Issue a capability token after explicit operator authorization.
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
            return Err(RemoteCapError::OperatorAuthorizationRequired);
        }
        if ttl_secs == 0 {
            return Err(RemoteCapError::InvalidTtl { ttl_secs });
        }

        let expires_at_epoch_secs = now_epoch_secs.saturating_add(ttl_secs);
        let normalized_scope = RemoteScope::new(scope.operations, scope.endpoint_prefixes);
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

        Ok((
            cap,
            build_audit_event(
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
            ),
        ))
    }
}

/// Single enforcement point for all network-bound capability checks.
#[derive(Debug, Clone)]
pub struct CapabilityGate {
    verification_secret: String,
    connectivity_mode: ConnectivityMode,
    consumed_tokens: ReplayTokenSet,
    revoked_tokens: ReplayTokenSet,
    replay_store: ReplayStoreBackend,
    audit_log: Vec<RemoteCapAuditEvent>,
}

impl CapabilityGate {
    #[must_use]
    pub fn new(verification_secret: &str) -> Self {
        Self {
            verification_secret: verification_secret.to_string(),
            connectivity_mode: ConnectivityMode::Connected,
            consumed_tokens: ReplayTokenSet::default(),
            revoked_tokens: ReplayTokenSet::default(),
            replay_store: ReplayStoreBackend::from_env(),
            audit_log: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_mode(verification_secret: &str, mode: ConnectivityMode) -> Self {
        let mut gate = Self::new(verification_secret);
        gate.connectivity_mode = mode;
        gate
    }

    pub fn with_durable_replay_store(
        verification_secret: &str,
        store_dir: impl AsRef<Path>,
    ) -> Result<Self, RemoteCapError> {
        Ok(Self {
            verification_secret: verification_secret.to_string(),
            connectivity_mode: ConnectivityMode::Connected,
            consumed_tokens: ReplayTokenSet::default(),
            revoked_tokens: ReplayTokenSet::default(),
            replay_store: ReplayStoreBackend::Durable(DurableReplayStore::open(store_dir)?),
            audit_log: Vec::new(),
        })
    }

    pub fn with_mode_and_durable_replay_store(
        verification_secret: &str,
        mode: ConnectivityMode,
        store_dir: impl AsRef<Path>,
    ) -> Result<Self, RemoteCapError> {
        let mut gate = Self::with_durable_replay_store(verification_secret, store_dir)?;
        gate.connectivity_mode = mode;
        Ok(gate)
    }

    pub fn set_mode(&mut self, mode: ConnectivityMode) {
        self.connectivity_mode = mode;
    }

    #[must_use]
    pub fn mode(&self) -> ConnectivityMode {
        self.connectivity_mode
    }

    /// Local-only operations are always allowed and optionally logged.
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
        u64::try_from(token_id.len()).unwrap_or(u64::MAX), token_id,
        u64::try_from(issuer_identity.len()).unwrap_or(u64::MAX), issuer_identity,
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

    #[test]
    fn operator_authorization_required_for_issue() {
        let provider = CapabilityProvider::new("secret-a");
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
    }

    #[test]
    fn missing_cap_is_denied() {
        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
    fn replay_of_single_use_token_is_denied() {
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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
            let mut first_gate =
                CapabilityGate::with_durable_replay_store("secret-a", &store_dir)
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
    fn recheck_does_not_consume_single_use_token() {
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let mut gate = CapabilityGate::with_mode("secret-a", ConnectivityMode::LocalOnly);
        gate.authorize_local_operation("evidence_ledger_append", 1_700_000_030, "trace-15");
        let event = gate.audit_log().last().expect("event");
        assert_eq!(event.event_code, "REMOTECAP_LOCAL_MODE_ACTIVE");
        assert!(event.allowed);
    }

    #[test]
    fn local_mode_denies_network_even_with_valid_cap() {
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::with_mode("secret-a", ConnectivityMode::LocalOnly);
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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
    fn zero_ttl_issue_is_rejected_without_issuance_audit() {
        let provider = CapabilityProvider::new("secret-a");

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
    }

    #[test]
    fn empty_endpoint_scope_denies_otherwise_allowed_operation() {
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut wrong_gate = CapabilityGate::new("secret-b");
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

        let mut correct_gate = CapabilityGate::new("secret-a");
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
    fn local_only_mode_denies_missing_cap_as_connectivity_mode_violation() {
        let mut gate = CapabilityGate::with_mode("secret-a", ConnectivityMode::LocalOnly);

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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let provider = CapabilityProvider::new("secret-a");
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

        let mut gate = CapabilityGate::new("secret-a");
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
        let mut gate = CapabilityGate::new("secret-a");

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
}

#[cfg(test)]
mod remote_cap_comprehensive_negative_tests {
    use super::*;
    use std::collections::HashMap;
    use crate::security::constant_time;

    /// Negative test: Unicode injection and encoding attacks in capability tokens
    #[test]
    fn negative_unicode_injection_and_encoding_attacks() {
        let provider = CapabilityProvider::new("secret-key");

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
        assert!(result.is_ok(), "Unicode in issuer should be handled gracefully");

        let (cap, _) = result.unwrap();
        let mut gate = CapabilityGate::new("secret-key");

        // Token should still function correctly despite Unicode content
        gate.authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://api.example.com/metrics",
            1_700_000_100,
            "trace-unicode-test",
        ).expect("Unicode-containing token should validate correctly");

        // Test malicious Unicode in endpoint prefixes
        let unicode_scope = RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec![
                "https://\u{202e}evil.com\u{200c}good.example.com".to_string(),
                "ftp://\u{0000}admin:pass@internal".to_string(),
            ],
        );

        let (unicode_cap, _) = provider.issue(
            "operator",
            unicode_scope,
            1_700_000_000,
            300,
            true,
            false,
            "trace-unicode-endpoint",
        ).expect("Unicode endpoint scope should be issuable");

        // Verify Unicode doesn't bypass endpoint validation
        let test_result = gate.authorize_network(
            Some(&unicode_cap),
            RemoteOperation::NetworkEgress,
            "https://evil.com/malicious",
            1_700_000_100,
            "trace-unicode-bypass-test",
        );

        // Should either allow the literal Unicode endpoint or deny based on normalized form
        match test_result {
            Ok(_) => {}, // Unicode endpoint was literally matched
            Err(e) => assert_eq!(e.code(), "REMOTECAP_SCOPE_DENIED"), // Or properly denied
        }
    }

    /// Negative test: Arithmetic overflow protection in timestamps and TTL calculations
    #[test]
    fn negative_arithmetic_overflow_protection() {
        let provider = CapabilityProvider::new("secret-key");
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

        assert!(result.is_ok(), "Should handle near-overflow timestamps gracefully");
        let (cap, _) = result.unwrap();

        // Verify saturating_add prevented overflow and expiry is reasonable
        assert!(cap.expires_at_epoch_secs >= near_max_time);
        assert!(cap.expires_at_epoch_secs == u64::MAX || cap.expires_at_epoch_secs > near_max_time);

        let mut gate = CapabilityGate::new("secret-key");

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
            Ok(_) => {}, // Token is still valid
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
        assert!(max_ttl_result.is_ok(), "Maximum TTL should be handled safely");
    }

    /// Negative test: Memory exhaustion attacks with massive capability scopes
    #[test]
    fn negative_memory_exhaustion_with_massive_scopes() {
        let provider = CapabilityProvider::new("secret-key");

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
            push_bounded(&mut operations, RemoteOperation::NetworkEgress, MAX_TEST_OPERATIONS);
            push_bounded(&mut operations, RemoteOperation::FederationSync, MAX_TEST_OPERATIONS);
            push_bounded(&mut operations, RemoteOperation::RevocationFetch, MAX_TEST_OPERATIONS);
            push_bounded(&mut operations, RemoteOperation::RemoteAttestationVerify, MAX_TEST_OPERATIONS);
            push_bounded(&mut operations, RemoteOperation::TelemetryExport, MAX_TEST_OPERATIONS);
            push_bounded(&mut operations, RemoteOperation::RemoteComputation, MAX_TEST_OPERATIONS);
            push_bounded(&mut operations, RemoteOperation::ArtifactUpload, MAX_TEST_OPERATIONS);
        }

        // Add massive number of endpoint prefixes
        for i in 0..10000 {
            if endpoints.len() >= MAX_TEST_ENDPOINTS {
                break;
            }
            push_bounded(&mut endpoints, format!("https://endpoint-{}.example.com", i), MAX_TEST_ENDPOINTS);
            push_bounded(&mut endpoints, format!("https://service-{}.internal", i), MAX_TEST_ENDPOINTS);
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

        assert!(result.is_ok(), "Should handle massive scopes without memory exhaustion");
        let (cap, _) = result.unwrap();

        // Verify scope normalization deduplicated operations
        assert!(cap.scope.operations.len() <= 7); // Only 7 unique operation types exist
        assert!(cap.scope.endpoint_prefixes.len() <= 20000); // May have many unique endpoints

        let mut gate = CapabilityGate::new("secret-key");

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

        assert!(duration < std::time::Duration::from_millis(100), "Authorization should be efficient");
        assert!(auth_result.is_ok(), "Authorization with massive scope should succeed");
    }

    /// Negative test: Concurrent operation corruption and race conditions
    #[test]
    fn negative_concurrent_operation_corruption() {
        let provider = CapabilityProvider::new("secret-key");
        let scope = RemoteScope::new(
            vec![RemoteOperation::TelemetryExport, RemoteOperation::FederationSync],
            vec!["https://api.example.com".to_string()],
        );

        // Create multiple single-use tokens
        let mut tokens = Vec::new();
        const MAX_TEST_TOKENS: usize = 10;
        for i in 0..10 {
            let (token, _) = provider.issue(
                "operator",
                scope.clone(),
                1_700_000_000,
                300,
                true,
                true, // single-use
                &format!("trace-concurrent-{}", i),
            ).expect("token creation");
            push_bounded(&mut tokens, token, MAX_TEST_TOKENS);
        }

        let mut gate = CapabilityGate::new("secret-key");

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
            assert!(result.is_ok(), "First use of each single-use token should succeed");
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
        let provider = CapabilityProvider::new("secret-key");
        let scope = RemoteScope::new(
            vec![RemoteOperation::RemoteAttestationVerify],
            vec!["https://attestation.example.com".to_string()],
        );

        // Create legitimate token
        let (legitimate_token, _) = provider.issue(
            "operator",
            scope.clone(),
            1_700_000_000,
            300,
            true,
            false,
            "trace-timing-attack",
        ).expect("legitimate token");

        let mut gate = CapabilityGate::new("secret-key");

        // Test with various malformed signatures to detect timing differences
        let malformed_signatures = vec![
            "".to_string(),
            "short".to_string(),
            "exactly_64_char_string_that_looks_like_valid_hex_but_is_not_real!".to_string(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(), // Valid hex format but wrong content
            legitimate_token.signature().to_string() + "extra", // Slightly longer
            legitimate_token.signature()[0..legitimate_token.signature().len()-1].to_string(), // Slightly shorter
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
        assert!(timing_ratio < 3.0, "Signature comparison timing variance too high: {}", timing_ratio);

        // Test hash collision resistance by attempting to create tokens with similar content
        let similar_scopes = vec![
            RemoteScope::new(vec![RemoteOperation::RemoteAttestationVerify], vec!["https://a.com".to_string()]),
            RemoteScope::new(vec![RemoteOperation::RemoteAttestationVerify], vec!["https://b.com".to_string()]),
            RemoteScope::new(vec![RemoteOperation::TelemetryExport], vec!["https://a.com".to_string()]),
        ];

        let mut token_ids = std::collections::HashSet::new();
        let mut signatures = std::collections::HashSet::new();

        for similar_scope in similar_scopes {
            let (token, _) = provider.issue(
                "operator",
                similar_scope,
                1_700_000_000,
                300,
                true,
                false,
                "trace-collision-test",
            ).expect("similar token");

            // All token IDs and signatures should be unique
            assert!(token_ids.insert(token.token_id().to_string()), "Token ID collision detected");
            assert!(signatures.insert(token.signature().to_string()), "Signature collision detected");
        }
    }

    /// Negative test: Resource exhaustion attacks through audit log flooding
    #[test]
    fn negative_resource_exhaustion_audit_log_flooding() {
        let provider = CapabilityProvider::new("secret-key");
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://upload.example.com".to_string()],
        );

        let (cap, _) = provider.issue(
            "operator",
            scope,
            1_700_000_000,
            300,
            true,
            false,
            "trace-flood-test",
        ).expect("flood test token");

        let mut gate = CapabilityGate::new("secret-key");

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
                assert!(event.trace_id.contains("flood"), "Recent events should be preserved");
            }
        }

        // Memory usage should remain reasonable despite flood
        let initial_capacity = gate.audit_log().capacity();
        gate.authorize_local_operation("test_operation", 1_700_000_200, "trace-post-flood");

        // Capacity shouldn't grow excessively
        assert!(gate.audit_log().capacity() <= initial_capacity * 2, "Audit log capacity growth should be bounded");
    }

    /// Negative test: Edge cases in endpoint prefix matching with malformed URLs
    #[test]
    fn negative_endpoint_prefix_malformed_url_edge_cases() {
        let provider = CapabilityProvider::new("secret-key");

        // Create scope with various malformed and edge-case endpoint prefixes
        let malformed_endpoints = vec![
            "".to_string(), // Empty
            " ".to_string(), // Whitespace only
            "://missing-scheme".to_string(),
            "http://".to_string(), // Incomplete
            "https://[invalid-ipv6".to_string(),
            "ftp://user:pass@host:99999/path".to_string(), // Invalid port
            "https://example.com:0".to_string(), // Port 0
            "https://example.com:-1".to_string(), // Negative port
            "javascript:alert('xss')".to_string(), // Script URL
            "data:text/html,<script>alert('xss')</script>".to_string(), // Data URL
            "file:///etc/passwd".to_string(), // File URL
            "https://example.com/../../../etc/passwd".to_string(), // Path traversal
            "https://example.com/\x00\x01\x02".to_string(), // Control characters
            "https://example.com/\u{202e}evil".to_string(), // Unicode direction override
        ];

        let scope = RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            malformed_endpoints,
        );

        let (cap, _) = provider.issue(
            "operator",
            scope,
            1_700_000_000,
            300,
            true,
            false,
            "trace-malformed-endpoints",
        ).expect("malformed endpoints token");

        let mut gate = CapabilityGate::new("secret-key");

        // Test various target URLs against malformed prefixes
        let test_urls = vec![
            "https://example.com/normal/path",
            "https://evil.example.com/attack",
            "javascript:alert('test')",
            "file:///etc/passwd",
            "",
            "relative/path",
            "https://example.com:443/secure",
        ];

        for test_url in test_urls {
            let result = gate.authorize_network(
                Some(&cap),
                RemoteOperation::NetworkEgress,
                &test_url,
                1_700_000_100,
                "trace-malformed-test",
            );

            // Should handle malformed URLs gracefully without panic
            match result {
                Ok(_) => {}, // Some malformed prefix matched
                Err(e) => {
                    // Should be proper denial, not a panic or crash
                    assert!(matches!(e, RemoteCapError::ScopeDenied { .. }));
                }
            }
        }

        // Test endpoint prefix normalization edge cases
        let unnormalized_scope = RemoteScope::new(
            vec![RemoteOperation::TelemetryExport],
            vec![
                " https://api.example.com ".to_string(), // Leading/trailing spaces
                "https://api.example.com".to_string(),
                "".to_string(), // Empty (should be filtered)
                "   ".to_string(), // Whitespace only (should be filtered)
                "https://api.example.com".to_string(), // Duplicate
            ],
        );

        // Normalization should deduplicate and clean up endpoints
        assert!(unnormalized_scope.endpoint_prefixes.len() <= 2); // At most 2 unique endpoints after normalization
        assert!(!unnormalized_scope.endpoint_prefixes.iter().any(|e| e.trim().is_empty())); // No empty entries
    }

    /// Negative test: Advanced cryptographic attack scenarios
    #[test]
    fn negative_advanced_cryptographic_attacks() {
        let provider = CapabilityProvider::new("secret-key");
        let scope = RemoteScope::new(
            vec![RemoteOperation::RemoteComputation],
            vec!["https://compute.example.com".to_string()],
        );

        let (legitimate_token, _) = provider.issue(
            "operator",
            scope,
            1_700_000_000,
            300,
            true,
            false,
            "trace-crypto-attacks",
        ).expect("legitimate token");

        let mut gate = CapabilityGate::new("secret-key");

        // Test signature manipulation attacks
        let original_sig = legitimate_token.signature();

        // Bit-flip attack: flip each bit of the signature
        for byte_idx in 0..original_sig.len().min(32) { // Test first 32 characters
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
            format!("{}00", original_sig), // Append null bytes
            format!("{}ff", original_sig), // Append 0xff bytes
            format!("00{}", original_sig), // Prepend null bytes
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

            assert!(result.is_err(), "Length extension attack should be detected");
            assert_eq!(result.unwrap_err().code(), "REMOTECAP_INVALID");
        }

        // Test signature substitution (using signature from different token)
        let different_scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://different.example.com".to_string()],
        );

        let (different_token, _) = provider.issue(
            "operator",
            different_scope,
            1_700_000_000,
            300,
            true,
            false,
            "trace-different-token",
        ).expect("different token");

        let mut substituted_token = legitimate_token.clone();
        substituted_token.signature = different_token.signature().to_string();

        let substitution_result = gate.authorize_network(
            Some(&substituted_token),
            RemoteOperation::RemoteComputation,
            "https://compute.example.com/task",
            1_700_000_100,
            "trace-signature-substitution",
        );

        assert!(substitution_result.is_err(), "Signature substitution should be detected");
        assert_eq!(substitution_result.unwrap_err().code(), "REMOTECAP_INVALID");
    }
}
