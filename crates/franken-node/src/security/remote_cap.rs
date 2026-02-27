//! bd-1nfu: Remote capability gate for network-bound trust/control operations.
//!
//! This module defines:
//! - `RemoteCap` tokens with scope, issuer, expiry, and signature
//! - `CapabilityProvider` for controlled issuance
//! - `CapabilityGate` as the single validation/enforcement point
//! - structured audit events for issuance/consumption/denials

use std::collections::BTreeSet;
use std::fmt;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut result = 0;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }
    result == 0
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
    pub operations: Vec<RemoteOperation>,
    pub endpoint_prefixes: Vec<String>,
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
}

impl RemoteCapError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing => "REMOTECAP_MISSING",
            Self::OperatorAuthorizationRequired => "REMOTECAP_OPERATOR_AUTH_REQUIRED",
            Self::InvalidTtl { .. } => "REMOTECAP_TTL_INVALID",
            Self::Expired { .. } => "REMOTECAP_EXPIRED",
            Self::InvalidSignature => "REMOTECAP_INVALID",
            Self::ScopeDenied { .. } => "REMOTECAP_SCOPE_DENIED",
            Self::Revoked { .. } => "REMOTECAP_REVOKED",
            Self::ReplayDetected { .. } => "REMOTECAP_REPLAY",
            Self::ConnectivityModeDenied { .. } => "REMOTECAP_CONNECTIVITY_MODE_DENIED",
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
        let token_id = sha256_hex(
            format!(
                "id:v1|issuer={issuer_identity}|issued={now_epoch_secs}|expires={expires_at_epoch_secs}|scope={}|single_use={single_use}|trace_id={trace_id}",
                scope_fingerprint(&normalized_scope)
            )
            .as_bytes(),
        );

        let unsigned_payload = canonical_payload(
            &token_id,
            issuer_identity,
            now_epoch_secs,
            expires_at_epoch_secs,
            &normalized_scope,
            single_use,
        );
        let signature = keyed_digest(&self.signing_secret, &unsigned_payload);

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
    consumed_tokens: BTreeSet<String>,
    revoked_tokens: BTreeSet<String>,
    audit_log: Vec<RemoteCapAuditEvent>,
}

impl CapabilityGate {
    #[must_use]
    pub fn new(verification_secret: &str) -> Self {
        Self {
            verification_secret: verification_secret.to_string(),
            connectivity_mode: ConnectivityMode::Connected,
            consumed_tokens: BTreeSet::new(),
            revoked_tokens: BTreeSet::new(),
            audit_log: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_mode(verification_secret: &str, mode: ConnectivityMode) -> Self {
        let mut gate = Self::new(verification_secret);
        gate.connectivity_mode = mode;
        gate
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
            self.audit_log.push(build_audit_event(
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
        self.audit_log.push(event.clone());
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
            self.audit_log.push(build_audit_event(
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
            self.audit_log.push(build_audit_event(
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
            self.audit_log.push(build_audit_event(
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
        let expected_signature = keyed_digest(&self.verification_secret, &payload);
        if !constant_time_eq(&cap.signature, &expected_signature) {
            let err = RemoteCapError::InvalidSignature;
            self.audit_log.push(build_audit_event(
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
            self.audit_log.push(build_audit_event(
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
            self.audit_log.push(build_audit_event(
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

        if cap.single_use && self.consumed_tokens.contains(&cap.token_id) {
            let err = RemoteCapError::ReplayDetected {
                token_id: cap.token_id.clone(),
            };
            self.audit_log.push(build_audit_event(
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

        if cap.single_use && consume_single_use {
            self.consumed_tokens.insert(cap.token_id.clone());
        }

        let (event_code, legacy_event_code) = if consume_single_use {
            ("REMOTECAP_CONSUMED", "RC_CHECK_PASSED")
        } else {
            ("REMOTECAP_RECHECK_PASSED", "RC_RECHECK_PASSED")
        };
        self.audit_log.push(build_audit_event(
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
    let operations = scope
        .operations
        .iter()
        .map(|entry| entry.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let endpoints = scope.endpoint_prefixes.join(",");
    format!(
        "v1|token={token_id}|issuer={issuer_identity}|issued={issued_at_epoch_secs}|expires={expires_at_epoch_secs}|ops={operations}|endpoints={endpoints}|single_use={single_use}"
    )
}

fn scope_fingerprint(scope: &RemoteScope) -> String {
    let operations = scope
        .operations
        .iter()
        .map(|entry| entry.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "ops={operations};endpoints={}",
        scope.endpoint_prefixes.join(",")
    )
}

fn keyed_digest(secret: &str, payload: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"remote_cap_hash_v1:");
    hasher.update(input);
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
        let hmac_digest = keyed_digest("secret-a", payload);

        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update("secret-a".as_bytes());
        legacy_hasher.update(b"|");
        legacy_hasher.update(payload.as_bytes());
        let legacy_digest = hex::encode(legacy_hasher.finalize());

        assert_ne!(hmac_digest, legacy_digest);
    }
}
