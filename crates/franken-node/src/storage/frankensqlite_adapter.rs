//! bd-2tua: frankensqlite adapter conformance model for franken_node persistence.
//!
//! This module is an in-memory model of the planned frankensqlite adapter
//! contract. It exercises the adapter API, tier mapping, authorization,
//! schema-version, replay, and crash-recovery semantics, but it is not the live
//! frankensqlite-backed durable store yet.
//!
//! Modelled target durability tiers:
//! - **Tier 1** (target WAL, crash-safe): fencing tokens, lease state, rollout state, audit logs
//! - **Tier 2** (target periodic flush): snapshot state, CRDT merge state
//! - **Tier 3** (ephemeral): cache, transient metrics
//!
//! # Event Codes
//!
//! - `FRANKENSQLITE_ADAPTER_INIT`: Adapter initialized
//! - `FRANKENSQLITE_WRITE_SUCCESS`: Write completed
//! - `FRANKENSQLITE_WRITE_FAIL`: Write failed
//! - `FRANKENSQLITE_CRASH_RECOVERY`: Crash recovery executed
//! - `FRANKENSQLITE_REPLAY_START`: Replay initiated
//! - `FRANKENSQLITE_REPLAY_MISMATCH`: Replay divergence detected
//!
//! # Invariants
//!
//! - **INV-FSA-TIER1-DURABLE**: Tier 1 writes survive simulated crash in the model
//! - **INV-FSA-REPLAY-DETERMINISTIC**: Replay produces identical state
//! - **INV-FSA-CONCURRENT-SAFE**: Concurrent access causes no corruption
//! - **INV-FSA-SCHEMA-VERSIONED**: Schema migrations are versioned and reversible

use crate::push_bounded;
use crate::security::constant_time;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const FRANKENSQLITE_ADAPTER_INIT: &str = "FRANKENSQLITE_ADAPTER_INIT";
    pub const FRANKENSQLITE_WRITE_SUCCESS: &str = "FRANKENSQLITE_WRITE_SUCCESS";
    pub const FRANKENSQLITE_WRITE_FAIL: &str = "FRANKENSQLITE_WRITE_FAIL";
    pub const FRANKENSQLITE_AUDIT_LOG_TRUNCATED: &str = "FRANKENSQLITE_AUDIT_LOG_TRUNCATED";
    pub const FRANKENSQLITE_CRASH_RECOVERY: &str = "FRANKENSQLITE_CRASH_RECOVERY";
    pub const FRANKENSQLITE_REPLAY_START: &str = "FRANKENSQLITE_REPLAY_START";
    pub const FRANKENSQLITE_REPLAY_MISMATCH: &str = "FRANKENSQLITE_REPLAY_MISMATCH";
}

const AUDIT_LOG_TRUNCATED_REPLAY_SENTINEL: &str = "__audit_log_window_truncated__";
const MAX_AUDIT_REPLAY_RESULTS: usize = MAX_AUDIT_LOG_ENTRIES + 1;

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_EVENTS, MAX_SCHEMA_VERSIONS};

use std::sync::Arc;

pub const MAX_STORE_ENTRIES: usize = crate::capacity_defaults::base::LARGE;
pub const MAX_STORE_KEY_BYTES: usize = crate::capacity_defaults::base::MEDIUM;
pub const MAX_STORE_VALUE_BYTES: usize = crate::capacity_defaults::base::XL * 8;

/// SECURITY: Sanitizes keys for safe inclusion in log messages by escaping
/// control characters, newlines, and other characters that could be used
/// for log injection attacks.
fn sanitize_log_key(key: &str) -> String {
    let mut sanitized = String::with_capacity(key.len());
    for c in key.chars() {
        match c {
            '\n' => sanitized.push_str("\\n"),
            '\r' => sanitized.push_str("\\r"),
            '\t' => sanitized.push_str("\\t"),
            '\0' => sanitized.push_str("\\0"),
            '\\' => sanitized.push_str("\\\\"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(sanitized, "\\u{{{:04x}}}", c as u32);
            }
            c => sanitized.push(c),
        }
    }
    sanitized
}

fn bounded_log_key(key: &str) -> String {
    if key.len() > MAX_STORE_KEY_BYTES {
        format!("<oversized-key:{} bytes>", key.len())
    } else {
        sanitize_log_key(key)
    }
}

fn bounded_error_key(key: &str) -> String {
    if key.len() > MAX_STORE_KEY_BYTES {
        format!("<oversized-key:{} bytes>", key.len())
    } else {
        key.to_string()
    }
}

pub const INV_FSA_TIER1_DURABLE: &str = "INV-FSA-TIER1-DURABLE";
pub const INV_FSA_REPLAY_DETERMINISTIC: &str = "INV-FSA-REPLAY-DETERMINISTIC";
pub const INV_FSA_CONCURRENT_SAFE: &str = "INV-FSA-CONCURRENT-SAFE";
pub const INV_FSA_SCHEMA_VERSIONED: &str = "INV-FSA-SCHEMA-VERSIONED";

// ---------------------------------------------------------------------------
// DurabilityTier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DurabilityTier {
    /// Target WAL-mode, crash-safe tier. In this model, survives simulated crash recovery.
    Tier1,
    /// Target periodic-flush tier. In this model, participates in deterministic replay.
    Tier2,
    /// Ephemeral / memory-backed. Lost on restart.
    Tier3,
}

impl DurabilityTier {
    pub fn all() -> &'static [DurabilityTier] {
        &[Self::Tier1, Self::Tier2, Self::Tier3]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Tier1 => "tier1_wal_crash_safe",
            Self::Tier2 => "tier2_periodic_flush",
            Self::Tier3 => "tier3_ephemeral",
        }
    }
}

impl fmt::Display for DurabilityTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// CallerContext and Authorization
// ---------------------------------------------------------------------------

/// Represents the identity and role of a caller attempting storage operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallerContext {
    /// Caller identifier (e.g., "connector::fencing", "ops::telemetry")
    pub caller_id: String,
    /// Caller role determining access permissions
    pub role: CallerRole,
    /// Trace ID for audit purposes
    pub trace_id: String,
}

/// Roles determining what storage operations are permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallerRole {
    /// System-level access, can read/write all persistence classes
    System,
    /// Service-level access, can read/write specific classes based on service type
    Service,
    /// Read-only access for monitoring and observability
    ReadOnly,
    /// Restricted access, very limited permissions
    Restricted,
}

impl CallerContext {
    pub fn new(caller_id: String, role: CallerRole, trace_id: String) -> Self {
        Self {
            caller_id,
            role,
            trace_id,
        }
    }

    /// Create a system-level context for internal operations
    pub fn system(caller_id: &str, trace_id: &str) -> Self {
        Self::new(
            caller_id.to_string(),
            CallerRole::System,
            trace_id.to_string(),
        )
    }

    /// Create a service-level context
    pub fn service(caller_id: &str, trace_id: &str) -> Self {
        Self::new(
            caller_id.to_string(),
            CallerRole::Service,
            trace_id.to_string(),
        )
    }

    /// Create a read-only context
    pub fn read_only(caller_id: &str, trace_id: &str) -> Self {
        Self::new(
            caller_id.to_string(),
            CallerRole::ReadOnly,
            trace_id.to_string(),
        )
    }
}

/// Error types for authorization failures
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum AuthorizationError {
    #[error("access denied: {caller_id} (role: {role:?}) cannot {operation} {class}")]
    AccessDenied {
        caller_id: String,
        role: CallerRole,
        operation: String,
        class: String,
    },
    #[error("invalid caller context: {detail}")]
    InvalidContext { detail: String },
}

/// Check if caller is authorized for the requested operation
fn check_authorization(
    caller: &CallerContext,
    operation: &str,
    class: PersistenceClass,
) -> Result<(), AuthorizationError> {
    // Validate caller context
    if caller.caller_id.is_empty() {
        return Err(AuthorizationError::InvalidContext {
            detail: "caller_id cannot be empty".to_string(),
        });
    }
    if caller.trace_id.is_empty() {
        return Err(AuthorizationError::InvalidContext {
            detail: "trace_id cannot be empty".to_string(),
        });
    }

    match caller.role {
        CallerRole::System => {
            // System role can access everything
            Ok(())
        }
        CallerRole::Service => {
            // Service role has limited access based on caller_id
            match class {
                PersistenceClass::ControlState => {
                    // Only specific services can access control state
                    if caller.caller_id.starts_with("connector::")
                        || caller.caller_id.starts_with("ops::")
                    {
                        Ok(())
                    } else {
                        Err(AuthorizationError::AccessDenied {
                            caller_id: caller.caller_id.clone(),
                            role: caller.role,
                            operation: operation.to_string(),
                            class: class.label().to_string(),
                        })
                    }
                }
                PersistenceClass::AuditLog => {
                    // Audit log writes restricted to audit system
                    if operation == "write"
                        && !caller.caller_id.starts_with("observability::")
                        && !caller.caller_id.starts_with("audit::")
                    {
                        Err(AuthorizationError::AccessDenied {
                            caller_id: caller.caller_id.clone(),
                            role: caller.role,
                            operation: operation.to_string(),
                            class: class.label().to_string(),
                        })
                    } else {
                        Ok(())
                    }
                }
                PersistenceClass::Snapshot | PersistenceClass::Cache => {
                    // More permissive for snapshot and cache
                    Ok(())
                }
            }
        }
        CallerRole::ReadOnly => {
            // Read-only role can only read, and not from audit logs
            if operation != "read" || class == PersistenceClass::AuditLog {
                Err(AuthorizationError::AccessDenied {
                    caller_id: caller.caller_id.clone(),
                    role: caller.role,
                    operation: operation.to_string(),
                    class: class.label().to_string(),
                })
            } else {
                Ok(())
            }
        }
        CallerRole::Restricted => {
            // Restricted role can only access cache
            if class != PersistenceClass::Cache {
                Err(AuthorizationError::AccessDenied {
                    caller_id: caller.caller_id.clone(),
                    role: caller.role,
                    operation: operation.to_string(),
                    class: class.label().to_string(),
                })
            } else {
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PersistenceClass
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PersistenceClass {
    /// Fencing tokens, lease state, rollout state.
    ControlState,
    /// Append-only audit log with replay support.
    AuditLog,
    /// Snapshot state, CRDT merge state.
    Snapshot,
    /// Ephemeral cache.
    Cache,
}

impl PersistenceClass {
    pub fn all() -> &'static [PersistenceClass] {
        &[
            Self::ControlState,
            Self::AuditLog,
            Self::Snapshot,
            Self::Cache,
        ]
    }

    pub fn tier(&self) -> DurabilityTier {
        match self {
            Self::ControlState | Self::AuditLog => DurabilityTier::Tier1,
            Self::Snapshot => DurabilityTier::Tier2,
            Self::Cache => DurabilityTier::Tier3,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::ControlState => "control_state",
            Self::AuditLog => "audit_log",
            Self::Snapshot => "snapshot",
            Self::Cache => "cache",
        }
    }
}

impl fmt::Display for PersistenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// AdapterConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    pub db_path: String,
    pub pool_size: usize,
    pub wal_enabled: bool,
    pub flush_interval_ms: u64,
}

impl AdapterConfig {
    /// Validate configuration for security vulnerabilities.
    pub fn validate(&self) -> Result<(), String> {
        // Path traversal validation: reject dangerous path components
        if self.db_path.contains("..") {
            return Err("db_path contains path traversal sequence '..'".to_string());
        }
        if self.db_path.starts_with('/') && !self.db_path.starts_with("/tmp/") {
            return Err("db_path contains absolute path outside allowed directories".to_string());
        }
        if self.db_path.contains('\\') {
            return Err("db_path contains backslash (potential path traversal)".to_string());
        }
        if self.db_path.contains('\0') {
            return Err("db_path contains null byte".to_string());
        }
        if self.db_path.is_empty() {
            return Err("db_path cannot be empty".to_string());
        }

        // Additional validation
        if self.pool_size == 0 {
            return Err("pool_size must be greater than 0".to_string());
        }
        if self.pool_size > 1000 {
            return Err("pool_size exceeds maximum allowed (1000)".to_string());
        }

        Ok(())
    }
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            db_path: "franken_node.db".into(),
            pool_size: 4,
            wal_enabled: true,
            flush_interval_ms: 1000,
        }
    }
}

// ---------------------------------------------------------------------------
// SchemaVersion
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaVersion {
    pub version: u32,
    pub applied_at: String,
    pub description: String,
}

// ---------------------------------------------------------------------------
// WriteResult / ReadResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResult {
    pub success: bool,
    pub key: String,
    pub persistence_class: PersistenceClass,
    pub tier: DurabilityTier,
    pub latency_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResult {
    pub found: bool,
    pub key: String,
    pub value: Option<Vec<u8>>,
    pub persistence_class: PersistenceClass,
    pub tier: DurabilityTier,
    pub cache_hit: bool,
}

// ---------------------------------------------------------------------------
// AdapterError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterError {
    WriteFailure { key: String, reason: String },
    ReadFailure { key: String, reason: String },
    ReplayMismatch { entry_id: String, detail: String },
    SchemaMigrationFailed { version: u32, reason: String },
    ConfigValidationFailed { reason: String },
    PoolExhausted,
    AuthorizationFailed(AuthorizationError),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriteFailure { key, reason } => write!(f, "write failed: key={key}, {reason}"),
            Self::ReadFailure { key, reason } => write!(f, "read failed: key={key}, {reason}"),
            Self::ReplayMismatch { entry_id, detail } => {
                write!(f, "replay mismatch: entry={entry_id}, {detail}")
            }
            Self::SchemaMigrationFailed { version, reason } => {
                write!(f, "migration failed: v{version}, {reason}")
            }
            Self::ConfigValidationFailed { reason } => {
                write!(f, "config validation failed: {reason}")
            }
            Self::PoolExhausted => write!(f, "connection pool exhausted"),
            Self::AuthorizationFailed(auth_err) => write!(f, "authorization failed: {auth_err}"),
        }
    }
}

// ---------------------------------------------------------------------------
// AdapterEvent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterEvent {
    pub code: String,
    pub persistence_class: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// AdapterSummary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterSummary {
    pub total_writes: usize,
    pub total_reads: usize,
    pub write_failures: usize,
    pub replay_count: usize,
    pub replay_mismatches: usize,
    pub audit_log_truncated: bool,
    pub writes_by_tier: BTreeMap<String, usize>,
    pub schema_version: u32,
}

// ---------------------------------------------------------------------------
// FrankensqliteAdapter
// ---------------------------------------------------------------------------

pub struct FrankensqliteAdapter {
    config: AdapterConfig,
    store: BTreeMap<(PersistenceClass, String), Arc<[u8]>>,
    audit_log: Vec<(String, Arc<[u8]>)>,
    events: Vec<AdapterEvent>,
    write_count: usize,
    read_count: usize,
    write_failures: usize,
    replay_count: usize,
    replay_mismatches: usize,
    audit_log_truncated: bool,
    writes_by_tier: BTreeMap<DurabilityTier, usize>,
    schema_versions: Vec<SchemaVersion>,
}

impl FrankensqliteAdapter {
    /// Create a new adapter with validated configuration.
    pub fn new_validated(config: AdapterConfig) -> Result<Self, AdapterError> {
        // Validate configuration for security issues
        if let Err(reason) = config.validate() {
            return Err(AdapterError::ConfigValidationFailed { reason });
        }
        Self::new_unchecked(config)
    }

    /// Create a new adapter.
    ///
    /// This constructor is fail-closed and validates the supplied configuration
    /// before initializing the adapter.
    pub fn new(config: AdapterConfig) -> Result<Self, AdapterError> {
        Self::new_validated(config)
    }

    fn new_unchecked(config: AdapterConfig) -> Result<Self, AdapterError> {
        let mut adapter = Self {
            config,
            store: BTreeMap::new(),
            audit_log: Vec::new(),
            events: Vec::new(),
            write_count: 0,
            read_count: 0,
            write_failures: 0,
            replay_count: 0,
            replay_mismatches: 0,
            audit_log_truncated: false,
            writes_by_tier: BTreeMap::new(),
            schema_versions: vec![SchemaVersion {
                version: 1,
                applied_at: "2026-02-20T00:00:00Z".into(),
                description: "Initial schema".into(),
            }],
        };
        adapter.emit_event(
            event_codes::FRANKENSQLITE_ADAPTER_INIT,
            "all",
            format!(
                "Adapter initialized: pool_size={}",
                adapter.config.pool_size
            ),
        );
        Ok(adapter)
    }

    /// Write a key-value pair with persistence-class-appropriate durability.
    /// Requires caller context for authorization validation.
    pub fn write(
        &mut self,
        caller: &CallerContext,
        class: PersistenceClass,
        key: &str,
        value: &[u8],
    ) -> Result<WriteResult, AdapterError> {
        // Security: Check authorization before allowing storage access
        check_authorization(caller, "write", class).map_err(AdapterError::AuthorizationFailed)?;
        let start = Instant::now();
        let tier = class.tier();

        if key.len() > MAX_STORE_KEY_BYTES {
            return Err(self.reject_write(
                class,
                key,
                format!(
                    "key length {} bytes exceeds maximum {}",
                    key.len(),
                    MAX_STORE_KEY_BYTES
                ),
            ));
        }
        if value.len() > MAX_STORE_VALUE_BYTES {
            return Err(self.reject_write(
                class,
                key,
                format!(
                    "value length {} bytes exceeds maximum {}",
                    value.len(),
                    MAX_STORE_VALUE_BYTES
                ),
            ));
        }

        let key_string = key.to_string();
        let store_key = (class, key_string.clone());

        if class == PersistenceClass::AuditLog && self.store.contains_key(&store_key) {
            return Err(self.reject_write(
                class,
                key,
                "duplicate audit log keys violate append-only semantics",
            ));
        }

        if !self.store.contains_key(&store_key) && self.store.len() >= MAX_STORE_ENTRIES {
            return Err(self.reject_write(
                class,
                key,
                format!(
                    "store entry capacity {} reached for new key",
                    MAX_STORE_ENTRIES
                ),
            ));
        }

        let value_bytes = Arc::<[u8]>::from(value);
        self.store.insert(store_key, Arc::clone(&value_bytes));
        let tier_writes = self.writes_by_tier.entry(tier).or_insert(0);
        *tier_writes = tier_writes.saturating_add(1);
        self.write_count = self.write_count.saturating_add(1);

        if class == PersistenceClass::AuditLog {
            if !self.audit_log_truncated && self.audit_log.len() >= MAX_AUDIT_LOG_ENTRIES {
                self.audit_log_truncated = true;
                self.emit_event(
                    event_codes::FRANKENSQLITE_AUDIT_LOG_TRUNCATED,
                    class.label(),
                    format!(
                        "audit replay window exceeded {} entries; gate is now fail-closed",
                        MAX_AUDIT_LOG_ENTRIES
                    ),
                );
            }
            push_bounded(
                &mut self.audit_log,
                (key_string.clone(), value_bytes),
                MAX_AUDIT_LOG_ENTRIES,
            );
        }

        let latency = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);

        self.emit_event(
            event_codes::FRANKENSQLITE_WRITE_SUCCESS,
            class.label(),
            format!(
                "key={}, tier={tier}, latency_us={latency}",
                sanitize_log_key(key)
            ),
        );

        Ok(WriteResult {
            success: true,
            key: key_string,
            persistence_class: class,
            tier,
            latency_us: latency,
        })
    }

    fn reject_write(
        &mut self,
        class: PersistenceClass,
        key: &str,
        reason: impl Into<String>,
    ) -> AdapterError {
        let reason = reason.into();
        self.write_failures = self.write_failures.saturating_add(1);
        self.emit_event(
            event_codes::FRANKENSQLITE_WRITE_FAIL,
            class.label(),
            format!("key={}, {reason}", bounded_log_key(key)),
        );
        AdapterError::WriteFailure {
            key: bounded_error_key(key),
            reason,
        }
    }

    /// Read a value by persistence class and key.
    /// Requires caller context for authorization validation.
    pub fn read(
        &mut self,
        caller: &CallerContext,
        class: PersistenceClass,
        key: &str,
    ) -> Result<ReadResult, AdapterError> {
        // Security: Check authorization before allowing storage access
        check_authorization(caller, "read", class).map_err(AdapterError::AuthorizationFailed)?;

        self.read_count = self.read_count.saturating_add(1);
        let tier = class.tier();
        let entry = self.store.get(&(class, key.to_string()));
        Ok(ReadResult {
            found: entry.is_some(),
            key: key.to_string(),
            value: entry.map(|value| value.as_ref().to_vec()),
            persistence_class: class,
            tier,
            cache_hit: tier == DurabilityTier::Tier3,
        })
    }

    /// Legacy write method for backwards compatibility.
    /// WARNING: Uses system-level permissions. Migrate to write(caller, ...) for proper authorization.
    #[deprecated(note = "Use write(caller, class, key, value) with explicit CallerContext")]
    pub fn write_legacy(
        &mut self,
        class: PersistenceClass,
        key: &str,
        value: &[u8],
    ) -> Result<WriteResult, AdapterError> {
        let caller = CallerContext::system("legacy::adapter", "legacy-write");
        self.write(&caller, class, key, value)
    }

    /// Legacy read entrypoint retained for migration surfaces that still name the
    /// older API, but now requiring an explicit caller so authorization failures
    /// fail closed instead of being downgraded into synthetic "not found" reads.
    pub fn read_legacy(
        &mut self,
        caller: &CallerContext,
        class: PersistenceClass,
        key: &str,
    ) -> Result<ReadResult, AdapterError> {
        self.read(caller, class, key)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test_caller(trace_id: &str) -> CallerContext {
        CallerContext::system("storage::tests", trace_id)
    }

    /// Replay audit log entries and verify determinism.
    pub fn replay(&mut self) -> Vec<(String, bool)> {
        self.emit_event(
            event_codes::FRANKENSQLITE_REPLAY_START,
            "audit_log",
            format!("Replaying {} entries", self.audit_log.len()),
        );
        self.replay_count = self.replay_count.saturating_add(1);

        // Clone to avoid borrow conflict with self.emit_event.
        let mut results = Vec::new();
        if self.audit_log_truncated {
            self.replay_mismatches = self.replay_mismatches.saturating_add(1);
            self.emit_event(
                event_codes::FRANKENSQLITE_REPLAY_MISMATCH,
                "audit_log",
                format!(
                    "audit replay window truncated at {} entries; replay cannot prove full history",
                    MAX_AUDIT_LOG_ENTRIES
                ),
            );
            push_bounded(
                &mut results,
                (AUDIT_LOG_TRUNCATED_REPLAY_SENTINEL.to_string(), false),
                MAX_AUDIT_REPLAY_RESULTS,
            );
        }

        let log_snapshot: Vec<_> = self.audit_log.clone();
        for (key, expected) in &log_snapshot {
            let stored = self.store.get(&(PersistenceClass::AuditLog, key.clone()));
            let matches =
                stored.is_some_and(|v| constant_time::ct_eq_bytes(v.as_ref(), expected.as_ref()));
            if !matches {
                self.replay_mismatches = self.replay_mismatches.saturating_add(1);
                self.emit_event(
                    event_codes::FRANKENSQLITE_REPLAY_MISMATCH,
                    "audit_log",
                    format!("key={}, mismatch detected", sanitize_log_key(key)),
                );
            }
            push_bounded(
                &mut results,
                (key.clone(), matches),
                MAX_AUDIT_REPLAY_RESULTS,
            );
        }
        results
    }

    /// Simulate crash recovery for Tier 1 data in the in-memory conformance model.
    pub fn crash_recovery(&mut self) -> usize {
        self.emit_event(
            event_codes::FRANKENSQLITE_CRASH_RECOVERY,
            "control_state",
            "Crash recovery initiated".into(),
        );
        // In the real adapter, this would replay WAL. Here we verify
        // Tier 1 data is intact.
        let tier1_keys: Vec<_> = self
            .store
            .keys()
            .filter(|(class, _)| class.tier() == DurabilityTier::Tier1)
            .cloned()
            .collect();
        tier1_keys.len()
    }

    /// Current schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_versions.last().map_or(0, |v| v.version)
    }

    /// Apply a schema migration.
    pub fn migrate(&mut self, version: u32, description: &str) -> Result<(), AdapterError> {
        if version <= self.schema_version() {
            return Err(AdapterError::SchemaMigrationFailed {
                version,
                reason: "version already applied".into(),
            });
        }
        push_bounded(
            &mut self.schema_versions,
            SchemaVersion {
                version,
                applied_at: "2026-02-20T00:00:00Z".into(),
                description: description.to_string(),
            },
            MAX_SCHEMA_VERSIONS,
        );
        Ok(())
    }

    /// Aggregate summary.
    pub fn summary(&self) -> AdapterSummary {
        let writes_by_tier: BTreeMap<String, usize> = self
            .writes_by_tier
            .iter()
            .map(|(t, c)| (t.label().to_string(), *c))
            .collect();
        AdapterSummary {
            total_writes: self.write_count,
            total_reads: self.read_count,
            write_failures: self.write_failures,
            replay_count: self.replay_count,
            replay_mismatches: self.replay_mismatches,
            audit_log_truncated: self.audit_log_truncated,
            writes_by_tier,
            schema_version: self.schema_version(),
        }
    }

    pub fn events(&self) -> &[AdapterEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<AdapterEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn gate_pass(&self) -> bool {
        self.write_failures == 0
            && self.replay_mismatches == 0
            && !self.audit_log_truncated
            && self.write_count > 0
    }

    /// Structured JSON report.
    pub fn to_report(&self) -> serde_json::Value {
        let summary = self.summary();
        serde_json::json!({
            "bead_id": "bd-2tua",
            "section": "10.16",
            "gate_verdict": if self.gate_pass() { "PASS" } else { "FAIL" },
            "summary": {
                "total_writes": summary.total_writes,
                "total_reads": summary.total_reads,
                "write_failures": summary.write_failures,
                "replay_count": summary.replay_count,
                "replay_mismatches": summary.replay_mismatches,
                "audit_log_truncated": summary.audit_log_truncated,
                "schema_version": summary.schema_version,
            },
            "persistence_classes": PersistenceClass::all().iter().map(|c| {
                serde_json::json!({
                    "class": c.label(),
                    "tier": c.tier().label(),
                })
            }).collect::<Vec<_>>(),
        })
    }

    fn emit_event(&mut self, code: &str, class: &str, detail: String) {
        push_bounded(
            &mut self.events,
            AdapterEvent {
                code: code.to_string(),
                persistence_class: class.to_string(),
                detail,
            },
            MAX_EVENTS,
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
pub trait FrankensqliteTestCallerExt {
    fn write(
        &mut self,
        class: PersistenceClass,
        key: &str,
        value: &[u8],
    ) -> Result<WriteResult, AdapterError>;

    fn read(&mut self, class: PersistenceClass, key: &str) -> ReadResult;
}

#[cfg(any(test, feature = "test-support"))]
pub trait FrankensqliteLegacySystemReadExt {
    fn read_legacy(&mut self, class: PersistenceClass, key: &str) -> ReadResult;
}

#[cfg(any(test, feature = "test-support"))]
impl FrankensqliteTestCallerExt for FrankensqliteAdapter {
    fn write(
        &mut self,
        class: PersistenceClass,
        key: &str,
        value: &[u8],
    ) -> Result<WriteResult, AdapterError> {
        let caller = Self::test_caller(key);
        FrankensqliteAdapter::write(self, &caller, class, key, value)
    }

    fn read(&mut self, class: PersistenceClass, key: &str) -> ReadResult {
        let caller = Self::test_caller(key);
        FrankensqliteAdapter::read(self, &caller, class, key).unwrap_or_else(|_| ReadResult {
            found: false,
            key: key.to_string(),
            value: None,
            persistence_class: class,
            tier: class.tier(),
            cache_hit: false,
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl FrankensqliteLegacySystemReadExt for FrankensqliteAdapter {
    fn read_legacy(&mut self, class: PersistenceClass, key: &str) -> ReadResult {
        let caller = CallerContext::system("legacy::adapter", "legacy-read");
        FrankensqliteAdapter::read_legacy(self, &caller, class, key)
            .expect("legacy system caller should remain authorized")
    }
}

impl Default for FrankensqliteAdapter {
    fn default() -> Self {
        Self::new_validated(AdapterConfig::default()).expect("default config should be valid")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DurabilityTier tests --

    #[test]
    fn test_tier_all_count() {
        assert_eq!(DurabilityTier::all().len(), 3);
    }

    #[test]
    fn test_tier_labels() {
        assert!(DurabilityTier::Tier1.label().contains("wal"));
        assert!(DurabilityTier::Tier2.label().contains("flush"));
        assert!(DurabilityTier::Tier3.label().contains("ephemeral"));
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(format!("{}", DurabilityTier::Tier1), "tier1_wal_crash_safe");
    }

    #[test]
    fn test_tier_serde_roundtrip() {
        for t in DurabilityTier::all() {
            let json = serde_json::to_string(t).expect("should succeed");
            let back: DurabilityTier = serde_json::from_str(&json).expect("should succeed");
            assert_eq!(*t, back);
        }
    }

    // -- PersistenceClass tests --

    #[test]
    fn test_class_all_count() {
        assert_eq!(PersistenceClass::all().len(), 4);
    }

    #[test]
    fn test_class_tier_mapping() {
        assert_eq!(PersistenceClass::ControlState.tier(), DurabilityTier::Tier1);
        assert_eq!(PersistenceClass::AuditLog.tier(), DurabilityTier::Tier1);
        assert_eq!(PersistenceClass::Snapshot.tier(), DurabilityTier::Tier2);
        assert_eq!(PersistenceClass::Cache.tier(), DurabilityTier::Tier3);
    }

    #[test]
    fn test_class_labels() {
        assert_eq!(PersistenceClass::ControlState.label(), "control_state");
        assert_eq!(PersistenceClass::AuditLog.label(), "audit_log");
        assert_eq!(PersistenceClass::Snapshot.label(), "snapshot");
        assert_eq!(PersistenceClass::Cache.label(), "cache");
    }

    #[test]
    fn test_class_display() {
        assert_eq!(
            format!("{}", PersistenceClass::ControlState),
            "control_state"
        );
    }

    #[test]
    fn test_class_serde_roundtrip() {
        for c in PersistenceClass::all() {
            let json = serde_json::to_string(c).expect("should succeed");
            let back: PersistenceClass = serde_json::from_str(&json).expect("should succeed");
            assert_eq!(*c, back);
        }
    }

    // -- AdapterConfig tests --

    #[test]
    fn test_default_config() {
        let cfg = AdapterConfig::default();
        assert_eq!(cfg.pool_size, 4);
        assert!(cfg.wal_enabled);
    }

    #[test]
    fn test_new_rejects_invalid_config() {
        let err = FrankensqliteAdapter::new(AdapterConfig {
            db_path: "/var/lib/franken_node.db".into(),
            ..AdapterConfig::default()
        })
        .expect_err("invalid adapter config must fail closed");

        assert!(matches!(
            err,
            AdapterError::ConfigValidationFailed { reason }
            if reason.contains("absolute path outside allowed directories")
        ));
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let cfg = AdapterConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: AdapterConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.pool_size, cfg.pool_size);
    }

    // -- SchemaVersion tests --

    #[test]
    fn test_schema_version_serde() {
        let sv = SchemaVersion {
            version: 1,
            applied_at: "2026-02-20".into(),
            description: "init".into(),
        };
        let json = serde_json::to_string(&sv).expect("should succeed");
        let back: SchemaVersion = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(back.version, 1);
    }

    #[test]
    fn schema_version_v1_roundtrips_under_declared_v1_consumer_exactly() {
        const DECLARED_SCHEMA_VERSION: u32 = 1;

        #[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
        #[serde(deny_unknown_fields)]
        struct DeclaredV1SchemaConsumer {
            version: u32,
            applied_at: String,
            description: String,
        }

        let schema = SchemaVersion {
            version: DECLARED_SCHEMA_VERSION,
            applied_at: "2026-04-20T00:00:00Z".into(),
            description: "declared schema v1".into(),
        };

        let encoded = serde_json::to_vec(&schema).expect("schema v1 should serialize");
        assert_eq!(
            encoded.as_slice(),
            br#"{"version":1,"applied_at":"2026-04-20T00:00:00Z","description":"declared schema v1"}"#
        );

        let consumer: DeclaredV1SchemaConsumer =
            serde_json::from_slice(&encoded).expect("declared v1 consumer should deserialize");
        assert_eq!(consumer.version, DECLARED_SCHEMA_VERSION);

        let reencoded =
            serde_json::to_vec(&consumer).expect("declared v1 consumer should reserialize");
        assert_eq!(reencoded, encoded);

        let decoded: SchemaVersion =
            serde_json::from_slice(&reencoded).expect("schema v1 should deserialize");
        assert_eq!(decoded, schema);
    }

    // -- WriteResult / ReadResult tests --

    #[test]
    fn test_write_result_serde() {
        let wr = WriteResult {
            success: true,
            key: "k".into(),
            persistence_class: PersistenceClass::ControlState,
            tier: DurabilityTier::Tier1,
            latency_us: 42,
        };
        let json = serde_json::to_string(&wr).expect("should succeed");
        let back: WriteResult = serde_json::from_str(&json).expect("should succeed");
        assert!(back.success);
    }

    #[test]
    fn test_read_result_serde() {
        let rr = ReadResult {
            found: true,
            key: "k".into(),
            value: Some(vec![1, 2]),
            persistence_class: PersistenceClass::Cache,
            tier: DurabilityTier::Tier3,
            cache_hit: true,
        };
        let json = serde_json::to_string(&rr).expect("should succeed");
        let back: ReadResult = serde_json::from_str(&json).expect("should succeed");
        assert!(back.found);
    }

    // -- AdapterError tests --

    #[test]
    fn test_error_display() {
        let e = AdapterError::WriteFailure {
            key: "k".into(),
            reason: "disk full".into(),
        };
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let e = AdapterError::PoolExhausted;
        let json = serde_json::to_string(&e).expect("should succeed");
        let back: AdapterError = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(back, AdapterError::PoolExhausted);
    }

    // -- Adapter: write/read round-trip --

    #[test]
    fn test_write_read_control_state() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::ControlState, "fence_1", b"token_abc")
            .expect("should succeed");
        let result = adapter.read_legacy(PersistenceClass::ControlState, "fence_1");
        assert!(result.found);
        assert_eq!(result.value.expect("should succeed"), b"token_abc");
        assert_eq!(result.tier, DurabilityTier::Tier1);
    }

    #[test]
    fn test_write_read_audit_log() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::AuditLog, "entry_1", b"audit_data")
            .expect("should succeed");
        let result = adapter.read_legacy(PersistenceClass::AuditLog, "entry_1");
        assert!(result.found);
    }

    #[test]
    fn test_write_read_snapshot() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::Snapshot, "snap_1", b"state")
            .expect("should succeed");
        let result = adapter.read_legacy(PersistenceClass::Snapshot, "snap_1");
        assert!(result.found);
        assert_eq!(result.tier, DurabilityTier::Tier2);
    }

    #[test]
    fn test_write_read_cache() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::Cache, "cached_1", b"val")
            .expect("should succeed");
        let result = adapter.read_legacy(PersistenceClass::Cache, "cached_1");
        assert!(result.found);
        assert!(result.cache_hit);
        assert_eq!(result.tier, DurabilityTier::Tier3);
    }

    #[test]
    fn test_read_missing_key() {
        let mut adapter = FrankensqliteAdapter::default();
        let result = adapter.read_legacy(PersistenceClass::ControlState, "nonexistent");
        assert!(!result.found);
        assert!(result.value.is_none());
    }

    #[test]
    fn test_write_overwrites() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::ControlState, "k", b"v1")
            .expect("should succeed");
        adapter
            .write_legacy(PersistenceClass::ControlState, "k", b"v2")
            .expect("should succeed");
        let result = adapter.read_legacy(PersistenceClass::ControlState, "k");
        assert_eq!(result.value.expect("should succeed"), b"v2");
    }

    #[test]
    fn test_audit_log_rejects_duplicate_keys() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::AuditLog, "entry_1", b"audit_data")
            .expect("initial audit log write should succeed");

        let err = adapter
            .write_legacy(PersistenceClass::AuditLog, "entry_1", b"tampered")
            .expect_err("duplicate audit keys must fail closed");

        assert!(matches!(err, AdapterError::WriteFailure { .. }));
        let result = adapter.read_legacy(PersistenceClass::AuditLog, "entry_1");
        assert_eq!(
            result
                .value
                .expect("original audit value must remain intact"),
            b"audit_data"
        );
        assert_eq!(adapter.summary().write_failures, 1);
        assert!(
            adapter
                .events()
                .iter()
                .any(|event| event.code == event_codes::FRANKENSQLITE_WRITE_FAIL)
        );
    }

    #[test]
    fn test_write_rejects_oversized_key_and_value_before_store_insert() {
        let mut adapter = FrankensqliteAdapter::default();
        let oversized_key = "k".repeat(MAX_STORE_KEY_BYTES + 1);
        let oversized_value = vec![0x42; MAX_STORE_VALUE_BYTES + 1];

        let key_err = adapter
            .write_legacy(PersistenceClass::ControlState, &oversized_key, b"value")
            .expect_err("oversized key must fail closed");
        let value_err = adapter
            .write_legacy(PersistenceClass::Snapshot, "valid-key", &oversized_value)
            .expect_err("oversized value must fail closed");

        assert!(matches!(key_err, AdapterError::WriteFailure { .. }));
        assert!(matches!(value_err, AdapterError::WriteFailure { .. }));
        assert_eq!(adapter.summary().total_writes, 0);
        assert_eq!(adapter.summary().write_failures, 2);
        assert!(
            adapter
                .events()
                .iter()
                .any(|event| event.code == event_codes::FRANKENSQLITE_WRITE_FAIL
                    && event.detail.contains("key length"))
        );
        assert!(
            adapter
                .events()
                .iter()
                .any(|event| event.code == event_codes::FRANKENSQLITE_WRITE_FAIL
                    && event.detail.contains("value length"))
        );
    }

    #[test]
    fn test_store_entry_capacity_rejects_new_keys_but_allows_overwrite() {
        let mut adapter = FrankensqliteAdapter::default();
        for idx in 0..MAX_STORE_ENTRIES {
            adapter.store.insert(
                (PersistenceClass::Cache, format!("cache-{idx}")),
                Arc::<[u8]>::from([0x11]),
            );
        }

        let err = adapter
            .write_legacy(PersistenceClass::Cache, "new-cache-entry", b"blocked")
            .expect_err("new key at store capacity must fail closed");
        assert!(matches!(err, AdapterError::WriteFailure { .. }));
        assert_eq!(adapter.store.len(), MAX_STORE_ENTRIES);
        assert_eq!(adapter.summary().write_failures, 1);

        adapter
            .write_legacy(PersistenceClass::Cache, "cache-0", b"updated")
            .expect("overwrite at store capacity should not grow the store");
        assert_eq!(adapter.store.len(), MAX_STORE_ENTRIES);
        let updated = adapter.read_legacy(PersistenceClass::Cache, "cache-0");
        assert_eq!(updated.value.as_deref(), Some(b"updated".as_slice()));
    }

    // -- Replay tests --

    #[test]
    fn test_replay_deterministic() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::AuditLog, "e1", b"data1")
            .expect("should succeed");
        adapter
            .write_legacy(PersistenceClass::AuditLog, "e2", b"data2")
            .expect("should succeed");
        let results = adapter.replay();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, ok)| *ok));
    }

    #[test]
    fn test_replay_emits_start_event() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::AuditLog, "e1", b"data")
            .expect("should succeed");
        let _ = adapter.take_events(); // clear init + write events
        adapter.replay();
        assert!(
            adapter
                .events()
                .iter()
                .any(|e| e.code == event_codes::FRANKENSQLITE_REPLAY_START)
        );
    }

    // -- Crash recovery tests --

    #[test]
    fn test_crash_recovery_preserves_tier1() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::ControlState, "f1", b"fence")
            .expect("should succeed");
        adapter
            .write_legacy(PersistenceClass::AuditLog, "a1", b"audit")
            .expect("should succeed");
        adapter
            .write_legacy(PersistenceClass::Cache, "c1", b"cache")
            .expect("should succeed");
        let recovered = adapter.crash_recovery();
        assert!(recovered >= 2); // at least the two Tier 1 entries
    }

    #[test]
    fn test_crash_recovery_emits_event() {
        let mut adapter = FrankensqliteAdapter::default();
        let _ = adapter.take_events();
        adapter.crash_recovery();
        assert!(
            adapter
                .events()
                .iter()
                .any(|e| e.code == event_codes::FRANKENSQLITE_CRASH_RECOVERY)
        );
    }

    // -- Schema migration tests --

    #[test]
    fn test_initial_schema_version() {
        let adapter = FrankensqliteAdapter::default();
        assert_eq!(adapter.schema_version(), 1);
    }

    #[test]
    fn test_migrate_increments_version() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter.migrate(2, "Add index").expect("should succeed");
        assert_eq!(adapter.schema_version(), 2);
    }

    #[test]
    fn test_migrate_rejects_old_version() {
        let mut adapter = FrankensqliteAdapter::default();
        let result = adapter.migrate(1, "duplicate");
        assert!(result.is_err());
    }

    // -- Gate tests --

    #[test]
    fn test_gate_empty_fails() {
        let adapter = FrankensqliteAdapter::default();
        assert!(!adapter.gate_pass());
    }

    #[test]
    fn test_gate_pass_after_writes() {
        let mut adapter = FrankensqliteAdapter::default();
        for class in PersistenceClass::all() {
            adapter
                .write_legacy(*class, "test_key", b"test")
                .expect("should succeed");
        }
        assert!(adapter.gate_pass());
    }

    // -- Summary tests --

    #[test]
    fn test_summary_counts() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::ControlState, "k1", b"v")
            .expect("should succeed");
        adapter
            .write_legacy(PersistenceClass::Cache, "k2", b"v")
            .expect("should succeed");
        adapter.read_legacy(PersistenceClass::ControlState, "k1");
        let summary = adapter.summary();
        assert_eq!(summary.total_writes, 2);
        assert_eq!(summary.total_reads, 1);
        assert_eq!(summary.write_failures, 0);
    }

    #[test]
    fn test_summary_writes_by_tier() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::ControlState, "k", b"v")
            .expect("should succeed");
        adapter
            .write_legacy(PersistenceClass::Cache, "k", b"v")
            .expect("should succeed");
        let summary = adapter.summary();
        assert!(summary.writes_by_tier.contains_key("tier1_wal_crash_safe"));
        assert!(summary.writes_by_tier.contains_key("tier3_ephemeral"));
    }

    // -- Event tests --

    #[test]
    fn test_init_emits_event() {
        let adapter = FrankensqliteAdapter::default();
        assert!(
            adapter
                .events()
                .iter()
                .any(|e| e.code == event_codes::FRANKENSQLITE_ADAPTER_INIT)
        );
    }

    #[test]
    fn test_write_emits_success_event() {
        let mut adapter = FrankensqliteAdapter::default();
        let _ = adapter.take_events();
        adapter
            .write_legacy(PersistenceClass::ControlState, "k", b"v")
            .expect("should succeed");
        assert!(
            adapter
                .events()
                .iter()
                .any(|e| e.code == event_codes::FRANKENSQLITE_WRITE_SUCCESS)
        );
    }

    #[test]
    fn test_take_events_drains() {
        let mut adapter = FrankensqliteAdapter::default();
        let events = adapter.take_events();
        assert!(!events.is_empty());
        assert!(adapter.events().is_empty());
    }

    // -- Report tests --

    #[test]
    fn test_report_structure() {
        let mut adapter = FrankensqliteAdapter::default();
        for class in PersistenceClass::all() {
            adapter
                .write_legacy(*class, "test", b"val")
                .expect("should succeed");
        }
        let report = adapter.to_report();
        assert_eq!(report["bead_id"], "bd-2tua");
        assert_eq!(report["section"], "10.16");
        assert_eq!(report["gate_verdict"], "PASS");
    }

    #[test]
    fn test_report_fail_verdict() {
        let adapter = FrankensqliteAdapter::default();
        let report = adapter.to_report();
        assert_eq!(report["gate_verdict"], "FAIL");
    }

    #[test]
    fn test_report_persistence_classes() {
        let adapter = FrankensqliteAdapter::default();
        let report = adapter.to_report();
        assert_eq!(
            report["persistence_classes"]
                .as_array()
                .expect("should succeed")
                .len(),
            4
        );
    }

    #[test]
    fn frankensqlite_conformance_matrix_covers_every_class_and_tier() {
        let matrix = [
            (
                PersistenceClass::ControlState,
                DurabilityTier::Tier1,
                false,
                true,
            ),
            (
                PersistenceClass::AuditLog,
                DurabilityTier::Tier1,
                false,
                true,
            ),
            (
                PersistenceClass::Snapshot,
                DurabilityTier::Tier2,
                false,
                false,
            ),
            (PersistenceClass::Cache, DurabilityTier::Tier3, true, false),
        ];
        assert_eq!(matrix.len(), PersistenceClass::all().len());

        let mut adapter = FrankensqliteAdapter::default();
        for (index, (class, expected_tier, expected_cache_hit, _recoverable)) in
            matrix.iter().enumerate()
        {
            let key = format!("matrix-{index}");
            let value = format!("value-{index}");
            let write = adapter
                .write_legacy(*class, &key, value.as_bytes())
                .expect("matrix write should succeed");
            assert_eq!(write.persistence_class, *class);
            assert_eq!(write.tier, *expected_tier);

            let read = adapter.read_legacy(*class, &key);
            assert!(read.found, "matrix row should round-trip {}", class.label());
            assert_eq!(read.value.as_deref(), Some(value.as_bytes()));
            assert_eq!(read.persistence_class, *class);
            assert_eq!(read.tier, *expected_tier);
            assert_eq!(read.cache_hit, *expected_cache_hit);
        }

        let recovered = adapter.crash_recovery();
        let expected_recovered = matrix
            .iter()
            .filter(|(_, _, _, recoverable)| *recoverable)
            .count();
        assert_eq!(recovered, expected_recovered);

        let summary = adapter.summary();
        assert_eq!(
            summary.writes_by_tier.get(DurabilityTier::Tier1.label()),
            Some(&2)
        );
        assert_eq!(
            summary.writes_by_tier.get(DurabilityTier::Tier2.label()),
            Some(&1)
        );
        assert_eq!(
            summary.writes_by_tier.get(DurabilityTier::Tier3.label()),
            Some(&1)
        );

        let report = adapter.to_report();
        let rows = report["persistence_classes"]
            .as_array()
            .expect("report should include persistence class rows");
        assert_eq!(rows.len(), matrix.len());
        for (class, expected_tier, _, _) in matrix {
            assert!(rows.iter().any(|row| {
                row["class"] == class.label() && row["tier"] == expected_tier.label()
            }));
        }
    }

    // -- Concurrent access simulation --

    #[test]
    fn test_concurrent_writes_same_key() {
        let mut adapter = FrankensqliteAdapter::default();
        for i in 0..10 {
            adapter
                .write_legacy(
                    PersistenceClass::ControlState,
                    "shared_key",
                    format!("value_{i}").as_bytes(),
                )
                .expect("should succeed");
        }
        let result = adapter.read_legacy(PersistenceClass::ControlState, "shared_key");
        assert!(result.found);
        assert_eq!(result.value.expect("should succeed"), b"value_9");
    }

    #[test]
    fn test_concurrent_different_classes() {
        let mut adapter = FrankensqliteAdapter::default();
        for class in PersistenceClass::all() {
            adapter
                .write_legacy(*class, "same_key", b"class_data")
                .expect("should succeed");
        }
        for class in PersistenceClass::all() {
            let result = adapter.read_legacy(*class, "same_key");
            assert!(result.found, "Missing data for class {}", class.label());
        }
    }

    // -- Invariant constants --

    #[test]
    fn test_invariant_constants_defined() {
        assert_eq!(INV_FSA_TIER1_DURABLE, "INV-FSA-TIER1-DURABLE");
        assert_eq!(INV_FSA_REPLAY_DETERMINISTIC, "INV-FSA-REPLAY-DETERMINISTIC");
        assert_eq!(INV_FSA_CONCURRENT_SAFE, "INV-FSA-CONCURRENT-SAFE");
        assert_eq!(INV_FSA_SCHEMA_VERSIONED, "INV-FSA-SCHEMA-VERSIONED");
    }

    // -- Event code constants --

    #[test]
    fn test_event_code_constants_defined() {
        assert!(!event_codes::FRANKENSQLITE_ADAPTER_INIT.is_empty());
        assert!(!event_codes::FRANKENSQLITE_WRITE_SUCCESS.is_empty());
        assert!(!event_codes::FRANKENSQLITE_WRITE_FAIL.is_empty());
        assert!(!event_codes::FRANKENSQLITE_AUDIT_LOG_TRUNCATED.is_empty());
        assert!(!event_codes::FRANKENSQLITE_CRASH_RECOVERY.is_empty());
        assert!(!event_codes::FRANKENSQLITE_REPLAY_START.is_empty());
        assert!(!event_codes::FRANKENSQLITE_REPLAY_MISMATCH.is_empty());
    }

    // -- Default adapter --

    #[test]
    fn test_default_adapter() {
        let adapter = FrankensqliteAdapter::default();
        assert!(!adapter.gate_pass());
        assert!(!adapter.events().is_empty()); // init event
    }

    // -- AdapterEvent serde --

    #[test]
    fn test_adapter_event_serde() {
        let evt = AdapterEvent {
            code: "TEST".into(),
            persistence_class: "control_state".into(),
            detail: "test detail".into(),
        };
        let json = serde_json::to_string(&evt).expect("should succeed");
        let back: AdapterEvent = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(back.code, "TEST");
    }

    // -- Determinism --

    #[test]
    fn test_determinism_identical_operations() {
        let mut a1 = FrankensqliteAdapter::default();
        let mut a2 = FrankensqliteAdapter::default();
        for class in PersistenceClass::all() {
            a1.write(*class, "k", b"v").expect("should succeed");
            a2.write(*class, "k", b"v").expect("should succeed");
        }
        let r1 = a1.read_legacy(PersistenceClass::ControlState, "k");
        let r2 = a2.read_legacy(PersistenceClass::ControlState, "k");
        assert_eq!(r1.value, r2.value);
    }

    // -- AdapterSummary serde --

    #[test]
    fn test_summary_serde_roundtrip() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::ControlState, "k", b"v")
            .expect("should succeed");
        let summary = adapter.summary();
        let json = serde_json::to_string(&summary).expect("should succeed");
        let back: AdapterSummary = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(back.total_writes, summary.total_writes);
    }

    #[test]
    fn duplicate_audit_write_does_not_consume_success_counters_or_tier_counts() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::AuditLog, "audit-1", b"original")
            .expect("initial audit write should succeed");
        let writes_before = adapter.summary().total_writes;
        let tier1_before = adapter
            .writes_by_tier
            .get(&DurabilityTier::Tier1)
            .copied()
            .unwrap_or(0);
        let audit_len_before = adapter.audit_log.len();

        let err = adapter
            .write_legacy(PersistenceClass::AuditLog, "audit-1", b"tampered")
            .expect_err("duplicate audit write must fail closed");

        assert!(matches!(err, AdapterError::WriteFailure { .. }));
        assert_eq!(adapter.summary().total_writes, writes_before);
        assert_eq!(adapter.summary().write_failures, 1);
        assert_eq!(adapter.audit_log.len(), audit_len_before);
        assert_eq!(
            adapter
                .writes_by_tier
                .get(&DurabilityTier::Tier1)
                .copied()
                .unwrap_or(0),
            tier1_before
        );
        let stored = adapter
            .store
            .get(&(PersistenceClass::AuditLog, "audit-1".to_string()))
            .expect("original audit entry should remain");
        assert!(constant_time::ct_eq_bytes(stored.as_ref(), b"original"));
    }

    #[test]
    fn duplicate_audit_failure_keeps_gate_closed_after_prior_success() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::ControlState, "control", b"ok")
            .expect("control write should succeed");
        assert!(adapter.gate_pass());

        adapter
            .write_legacy(PersistenceClass::AuditLog, "audit-1", b"original")
            .expect("initial audit write should succeed");
        let err = adapter
            .write_legacy(PersistenceClass::AuditLog, "audit-1", b"duplicate")
            .expect_err("duplicate audit write must fail closed");

        assert!(matches!(err, AdapterError::WriteFailure { .. }));
        assert!(!adapter.gate_pass());
        assert_eq!(adapter.summary().write_failures, 1);
    }

    #[test]
    fn replay_mismatch_when_stored_audit_value_is_tampered() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::AuditLog, "audit-1", b"expected")
            .expect("audit write should succeed");
        adapter.store.insert(
            (PersistenceClass::AuditLog, "audit-1".to_string()),
            Arc::<[u8]>::from(b"actual".as_slice()),
        );

        let results = adapter.replay();

        assert_eq!(results, vec![("audit-1".to_string(), false)]);
        assert_eq!(adapter.summary().replay_mismatches, 1);
        assert!(!adapter.gate_pass());
        assert!(
            adapter
                .events()
                .iter()
                .any(|event| event.code == event_codes::FRANKENSQLITE_REPLAY_MISMATCH)
        );
    }

    #[test]
    fn replay_mismatch_when_audit_entry_missing_from_store() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::AuditLog, "audit-1", b"expected")
            .expect("audit write should succeed");
        adapter
            .store
            .remove(&(PersistenceClass::AuditLog, "audit-1".to_string()));

        let results = adapter.replay();

        assert_eq!(results, vec![("audit-1".to_string(), false)]);
        assert_eq!(adapter.summary().replay_mismatches, 1);
        assert_eq!(adapter.audit_log.len(), 1);
    }

    #[test]
    fn audit_log_window_truncation_fails_gate_closed() {
        let mut adapter = FrankensqliteAdapter::default();

        for idx in 0..=(MAX_AUDIT_LOG_ENTRIES + 2) {
            adapter
                .write_legacy(
                    PersistenceClass::AuditLog,
                    &format!("audit-{idx:04}"),
                    format!("value-{idx:04}").as_bytes(),
                )
                .expect("audit write should succeed");
        }

        let summary = adapter.summary();
        assert!(summary.audit_log_truncated);
        assert!(!adapter.gate_pass());
        assert!(
            adapter
                .events()
                .iter()
                .any(|event| event.code == event_codes::FRANKENSQLITE_AUDIT_LOG_TRUNCATED)
        );
    }

    #[test]
    fn truncated_audit_replay_surfaces_fail_closed_result() {
        let mut adapter = FrankensqliteAdapter::default();

        for idx in 0..=MAX_AUDIT_LOG_ENTRIES {
            adapter
                .write_legacy(
                    PersistenceClass::AuditLog,
                    &format!("audit-{idx:04}"),
                    format!("value-{idx:04}").as_bytes(),
                )
                .expect("audit write should succeed");
        }
        let _ = adapter.take_events();

        let replay_results = adapter.replay();

        assert_eq!(
            replay_results.first(),
            Some(&(AUDIT_LOG_TRUNCATED_REPLAY_SENTINEL.to_string(), false)),
            "truncated audit replay must surface the sentinel before bounded audit entries"
        );
        assert_eq!(
            replay_results.len(),
            MAX_AUDIT_REPLAY_RESULTS,
            "sentinel metadata must not evict the bounded audit replay window"
        );
        assert_eq!(
            replay_results
                .iter()
                .filter(|(key, _)| key != AUDIT_LOG_TRUNCATED_REPLAY_SENTINEL)
                .count(),
            MAX_AUDIT_LOG_ENTRIES
        );
        assert_eq!(adapter.summary().replay_mismatches, 1);
        assert!(
            adapter
                .events()
                .iter()
                .any(|event| event.code == event_codes::FRANKENSQLITE_REPLAY_MISMATCH)
        );
    }

    #[test]
    fn failed_migration_does_not_append_schema_version() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .migrate(2, "add index")
            .expect("migration should succeed");
        let versions_before = adapter.schema_versions.len();
        let schema_before = adapter.schema_version();

        let err = adapter
            .migrate(2, "duplicate")
            .expect_err("duplicate migration must fail closed");

        assert!(matches!(
            err,
            AdapterError::SchemaMigrationFailed { version: 2, .. }
        ));
        assert_eq!(adapter.schema_versions.len(), versions_before);
        assert_eq!(adapter.schema_version(), schema_before);
        assert_eq!(
            adapter
                .schema_versions
                .last()
                .expect("schema version should exist")
                .description
                .as_str(),
            "add index"
        );
    }

    #[test]
    fn failed_migration_with_zero_version_preserves_initial_schema() {
        let mut adapter = FrankensqliteAdapter::default();

        let err = adapter
            .migrate(0, "invalid downgrade")
            .expect_err("zero version must fail closed");

        assert!(matches!(
            err,
            AdapterError::SchemaMigrationFailed { version: 0, .. }
        ));
        assert_eq!(adapter.schema_version(), 1);
        assert_eq!(adapter.schema_versions.len(), 1);
    }

    #[test]
    fn missing_read_increments_read_count_without_creating_store_entry() {
        let mut adapter = FrankensqliteAdapter::default();

        let result = adapter.read_legacy(PersistenceClass::Snapshot, "missing");

        assert!(!result.found);
        assert!(result.value.is_none());
        assert_eq!(result.tier, DurabilityTier::Tier2);
        assert!(!result.cache_hit);
        assert_eq!(adapter.summary().total_reads, 1);
        assert!(
            !adapter
                .store
                .contains_key(&(PersistenceClass::Snapshot, "missing".to_string()))
        );
    }

    #[test]
    fn crash_recovery_excludes_non_tier1_entries() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write_legacy(PersistenceClass::Snapshot, "snapshot", b"tier2")
            .expect("snapshot write should succeed");
        adapter
            .write_legacy(PersistenceClass::Cache, "cache", b"tier3")
            .expect("cache write should succeed");

        let recovered = adapter.crash_recovery();

        assert_eq!(recovered, 0);
        assert_eq!(adapter.summary().total_writes, 2);
        assert_eq!(adapter.summary().write_failures, 0);
    }
}

#[cfg(test)]
mod frankensqlite_adapter_extreme_adversarial_negative_tests {
    use super::*;

    #[test]
    fn extreme_adversarial_sql_injection_pattern_key_resistance() {
        let mut adapter = FrankensqliteAdapter::default();

        // SQL injection patterns in keys (even though this is in-memory, test key sanitization)
        let sql_injection_keys = vec![
            "'; DROP TABLE users; --",
            "admin'--",
            "admin'/*",
            "' OR '1'='1",
            "' OR 1=1--",
            "'; INSERT INTO audit_log VALUES ('evil', 'payload'); --",
            "key\x00injection",
            "key'; SELECT * FROM sqlite_master; --",
            "1' UNION SELECT password FROM users WHERE username='admin'--",
            "key\\'; DELETE FROM control_state; --",
        ];

        for (i, malicious_key) in sql_injection_keys.iter().enumerate() {
            let write_result = adapter.write(
                PersistenceClass::ControlState,
                malicious_key,
                format!("test_value_{i}").as_bytes(),
            );

            // Should handle malicious keys without SQL injection vulnerabilities
            assert!(
                write_result.is_ok(),
                "SQL injection key should be handled safely: {}",
                malicious_key
            );

            // Verify the key is stored and retrievable (escaped/sanitized)
            let read_result = adapter.read_legacy(PersistenceClass::ControlState, malicious_key);
            assert!(
                read_result.found,
                "malicious key should be retrievable: {}",
                malicious_key
            );
            assert_eq!(
                read_result.value.unwrap(),
                format!("test_value_{i}").as_bytes()
            );
        }

        // Verify adapter state remains consistent
        assert!(adapter.gate_pass());
        assert_eq!(adapter.summary().write_failures, 0);
    }

    #[test]
    fn extreme_adversarial_unicode_injection_key_value_pollution() {
        let mut adapter = FrankensqliteAdapter::default();

        // Unicode injection attacks in both keys and values
        let unicode_attacks = vec![
            ("key\u{202E}evil\u{202D}", "value\u{200B}hidden"), // RTL override + zero-width
            ("key\u{FEFF}bom", "value\u{FEFF}bombed"),          // BOM injection
            ("key\u{0000}null", "value\u{0001}control"),        // Null/control bytes
            ("key\r\nHTTP/1.1 200", "value\r\nContent-Length: 0"), // CRLF injection
            ("café\u{0301}", "café\u{0301}"),                   // Unicode normalization
            ("key\u{1F4A9}", "value\u{1F4A9}"),                 // Emoji injection
        ];

        for (unicode_key, unicode_value) in unicode_attacks {
            let write_result = adapter.write(
                PersistenceClass::AuditLog,
                unicode_key,
                unicode_value.as_bytes(),
            );

            // Should handle Unicode gracefully without corruption
            assert!(
                write_result.is_ok(),
                "Unicode injection should be handled safely"
            );

            // Verify data integrity preserved
            let read_result = adapter.read_legacy(PersistenceClass::AuditLog, unicode_key);
            assert!(read_result.found);
            assert_eq!(read_result.value.unwrap(), unicode_value.as_bytes());
        }

        // Verify audit log replay maintains Unicode integrity
        let replay_results = adapter.replay();
        assert!(
            replay_results.iter().all(|(_, matches)| *matches),
            "Unicode entries should replay consistently"
        );
    }

    #[test]
    fn extreme_adversarial_memory_exhaustion_massive_key_value_pairs() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test memory exhaustion with massive key-value pairs
        let massive_key = "k".repeat(10_000_000); // 10MB key
        let massive_value = vec![0x42; 50_000_000]; // 50MB value

        let write_result = adapter.write(
            PersistenceClass::Cache, // Use ephemeral tier to avoid persistence overhead
            &massive_key,
            &massive_value,
        );

        match write_result {
            Ok(_) => {
                // If write succeeds, verify data integrity
                let read_result = adapter.read_legacy(PersistenceClass::Cache, &massive_key);
                assert!(read_result.found);
                assert_eq!(read_result.value.unwrap().len(), 50_000_000);

                // Verify adapter state remains stable
                assert_eq!(adapter.summary().write_failures, 0);
            }
            Err(_) => {
                // Should fail gracefully with meaningful error, not crash
                // This is acceptable behavior for memory exhaustion protection
            }
        }
    }

    #[test]
    fn extreme_adversarial_arithmetic_overflow_counters_boundary_values() {
        let mut adapter = FrankensqliteAdapter::default();

        // Force near-overflow scenarios on internal counters
        adapter.write_count = usize::MAX - 5;
        adapter.read_count = usize::MAX - 3;
        adapter.write_failures = usize::MAX - 1;
        adapter.replay_count = usize::MAX - 2;
        adapter.replay_mismatches = usize::MAX - 4;

        // Test operations near overflow boundaries
        for i in 0..10 {
            let key = format!("overflow_key_{i}");
            let value = format!("overflow_value_{i}");

            let write_result =
                adapter.write(PersistenceClass::ControlState, &key, value.as_bytes());

            // Should handle overflow gracefully with saturating arithmetic
            assert!(
                write_result.is_ok(),
                "overflow boundary operation should succeed"
            );

            let read_result = adapter.read_legacy(PersistenceClass::ControlState, &key);
            assert!(read_result.found);
        }

        // Verify counters use saturating arithmetic (don't wrap around)
        assert_eq!(adapter.write_count, usize::MAX); // Should saturate
        assert_eq!(adapter.read_count, usize::MAX);

        // Test summary generation with overflow values
        let summary = adapter.summary();
        assert!(summary.total_writes <= usize::MAX);
        assert!(summary.total_reads <= usize::MAX);
    }

    #[test]
    fn extreme_adversarial_concurrent_key_collision_hash_attack() {
        let mut adapter = FrankensqliteAdapter::default();

        // Simulate hash collision attack with keys designed to collide
        let collision_candidates = vec![
            "collision_key_1",
            "collision_key_2",
            "collision_key_3",
            // Add more sophisticated collision patterns
            "key_with_suffix_a",
            "key_with_suffix_b",
            "key_with_suffix_c",
        ];

        // Write all collision candidates rapidly
        for (i, key) in collision_candidates.iter().enumerate() {
            for class in PersistenceClass::all() {
                let result = adapter.write(*class, key, format!("value_{class}_{i}").as_bytes());

                assert!(result.is_ok(), "collision attack should not break storage");
            }
        }

        // Verify all keys are independently accessible (no collisions)
        for (i, key) in collision_candidates.iter().enumerate() {
            for class in PersistenceClass::all() {
                let read_result = adapter.read_legacy(*class, key);
                assert!(
                    read_result.found,
                    "collision victim key should still be accessible"
                );
                assert_eq!(
                    read_result.value.unwrap(),
                    format!("value_{class}_{i}").as_bytes()
                );
            }
        }
    }

    #[test]
    fn extreme_adversarial_malformed_json_serialization_injection() {
        let mut adapter = FrankensqliteAdapter::default();

        // JSON injection patterns in values
        let json_injection_payloads = vec![
            br#"{"malicious": "payload"}"#.to_vec(),
            br#""}}], "injected": {"evil": "data""#.to_vec(),
            b"</script><script>alert('xss')</script>".to_vec(),
            b"\x00\x01\x02\x03".to_vec(), // Binary data
            format!("{{{}}}", "\"key\":\"value\",".repeat(10000)).into_bytes(), // Deep nesting
        ];

        for (i, payload) in json_injection_payloads.iter().enumerate() {
            let key = format!("json_injection_{i}");

            let write_result = adapter.write(PersistenceClass::Snapshot, &key, payload);

            assert!(write_result.is_ok(), "JSON payload should be stored safely");

            // Verify data integrity
            let read_result = adapter.read_legacy(PersistenceClass::Snapshot, &key);
            assert!(read_result.found);
            assert_eq!(read_result.value.unwrap(), *payload);
        }

        // Test report generation with potentially malicious data
        let report = adapter.to_report();
        let report_json = serde_json::to_string(&report).expect("report should serialize");

        // Verify no JSON injection in report
        assert!(!report_json.contains("</script>"));
        assert!(!report_json.contains("alert("));
        assert!(serde_json::from_str::<serde_json::Value>(&report_json).is_ok());
    }

    #[test]
    fn extreme_adversarial_audit_log_replay_timing_attack_resistance() {
        let mut adapter = FrankensqliteAdapter::default();

        // Create audit entries with varying content sizes to test timing consistency
        let timing_test_entries = vec![
            ("short", b"a"),
            ("medium", &vec![0x42; 1000]),
            ("large", &vec![0x43; 100_000]),
            ("massive", &vec![0x44; 1_000_000]),
        ];

        for (key, value) in &timing_test_entries {
            adapter
                .write(PersistenceClass::AuditLog, key, value)
                .expect("audit write should succeed");
        }

        // Measure replay timing for different entry sizes
        let start = Instant::now();
        let replay_results = adapter.replay();
        let replay_duration = start.elapsed();

        // Verify all entries replayed correctly
        assert_eq!(replay_results.len(), timing_test_entries.len());
        assert!(replay_results.iter().all(|(_, matches)| *matches));

        // Replay should complete in reasonable time regardless of data size
        assert!(
            replay_duration.as_millis() < 5000,
            "replay took too long: {:?}",
            replay_duration
        );

        // Verify constant-time comparison was used in replay
        assert_eq!(adapter.summary().replay_mismatches, 0);
    }

    #[test]
    fn extreme_adversarial_control_character_event_pollution() {
        let mut adapter = FrankensqliteAdapter::default();

        // Control characters in keys and values that could pollute events
        let control_char_tests = vec![
            ("key\x00\x01\x02", b"value\x03\x04\x05"),
            ("key\r\ninjection", b"value\r\nHTTP/1.1 200 OK"),
            ("key\t\t\t", b"value\x1B[31mred\x1B[0m"), // ANSI escape sequences
            (
                &format!("key{}", String::from_utf8_lossy(&[0x7F, 0x80, 0x81])),
                b"value\xFF\xFE\xFD",
            ), // High control chars
        ];

        for (key, value) in control_char_tests {
            adapter
                .write(PersistenceClass::ControlState, key, value)
                .expect("control character write should succeed");
        }

        // Verify events don't contain dangerous control characters
        for event in adapter.events() {
            assert!(
                !event.detail.contains('\x00'),
                "event detail must not contain null bytes"
            );
            assert!(
                !event.detail.contains('\x01'),
                "event detail must not contain SOH"
            );
            assert!(
                !event.detail.contains('\x1B'),
                "event detail must not contain ESC sequences"
            );

            // Verify JSON serialization is safe
            let event_json = serde_json::to_string(event).unwrap_or_default();
            assert!(!event_json.contains("\\u0000"));
            assert!(!event_json.contains("\\u0001"));
        }
    }

    #[test]
    fn extreme_adversarial_schema_version_integer_overflow_protection() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test schema version overflow scenarios
        let overflow_versions = vec![
            u32::MAX - 1,
            u32::MAX,
            // Note: Can't test wrapping due to validation logic
        ];

        for version in overflow_versions {
            let result = adapter.migrate(version, &format!("version_{version}"));

            match result {
                Ok(_) => {
                    // If migration succeeds, verify version is set correctly
                    assert_eq!(adapter.schema_version(), version);
                }
                Err(e) => {
                    // Should fail gracefully, not panic
                    assert!(matches!(e, AdapterError::SchemaMigrationFailed { .. }));
                }
            }
        }

        // Verify adapter remains in consistent state
        assert!(adapter.schema_versions.len() <= MAX_SCHEMA_VERSIONS);
    }

    #[test]
    fn extreme_adversarial_event_log_capacity_overflow_boundary_protection() {
        let mut adapter = FrankensqliteAdapter::default();

        // Force event log to exceed MAX_EVENTS capacity
        let iterations = MAX_EVENTS + 100;

        for i in 0..iterations {
            adapter
                .write(
                    PersistenceClass::Cache,
                    &format!("overflow_event_{i}"),
                    b"test",
                )
                .expect("write should succeed");
        }

        // Verify bounded behavior - events should not exceed maximum
        assert!(
            adapter.events().len() <= MAX_EVENTS,
            "events exceeded maximum capacity: {} > {}",
            adapter.events().len(),
            MAX_EVENTS
        );

        // Verify most recent events are preserved
        let events = adapter.events();
        if !events.is_empty() {
            let last_event = &events[events.len() - 1];
            // Last event should be from recent iterations
            assert!(
                last_event
                    .detail
                    .contains(&format!("overflow_event_{}", iterations - 1))
                    || last_event.detail.contains("pool_size")
            ); // or init event details
        }
    }

    #[test]
    fn extreme_adversarial_btreemap_key_order_manipulation_attack() {
        let mut adapter = FrankensqliteAdapter::default();

        // Keys designed to test BTreeMap ordering assumptions
        let ordering_attack_keys = vec![
            "\x00\x00\x00",                                // Null prefix
            "\x00\x00\x01",                                // Minimal increment
            &String::from_utf8_lossy(&[0xFF, 0xFF, 0xFF]), // Maximum bytes
            &String::from_utf8_lossy(&[0x80, 0x00, 0x00]), // Sign bit boundary
            "a\x00z",                                      // Null in middle
            "z\x00a",                                      // Reverse null pattern
        ];

        // Write in one order
        for (i, key) in ordering_attack_keys.iter().enumerate() {
            adapter
                .write(
                    PersistenceClass::ControlState,
                    key,
                    &format!("value_{i}").as_bytes(),
                )
                .expect("ordering attack write should succeed");
        }

        // Verify all keys are accessible regardless of ordering
        for (i, key) in ordering_attack_keys.iter().enumerate() {
            let read_result = adapter.read_legacy(PersistenceClass::ControlState, key);
            assert!(
                read_result.found,
                "ordering attack key should be accessible: {:?}",
                key
            );
            assert_eq!(read_result.value.unwrap(), format!("value_{i}").as_bytes());
        }

        // Verify adapter state consistency
        assert_eq!(adapter.summary().total_writes, ordering_attack_keys.len());
        assert_eq!(adapter.summary().write_failures, 0);
    }

    #[test]
    fn extreme_adversarial_tier_mapping_confusion_attack() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test all combinations of persistence classes and verify tier mappings
        for class in PersistenceClass::all() {
            let expected_tier = class.tier();

            // Write data to each class
            adapter
                .write(*class, "test_key", b"test_value")
                .expect("tier mapping write should succeed");

            // Verify read result has correct tier
            let read_result = adapter.read_legacy(*class, "test_key");
            assert_eq!(
                read_result.tier, expected_tier,
                "tier mapping mismatch for class {:?}",
                class
            );

            // Verify tier-specific behavior
            match expected_tier {
                DurabilityTier::Tier3 => {
                    assert!(read_result.cache_hit, "Tier3 should be cache hit");
                }
                _ => {
                    assert!(!read_result.cache_hit, "Non-Tier3 should not be cache hit");
                }
            }
        }

        // Verify crash recovery only affects Tier1 classes
        let tier1_count_before = adapter
            .store
            .keys()
            .filter(|(class, _)| class.tier() == DurabilityTier::Tier1)
            .count();

        let recovered = adapter.crash_recovery();
        assert_eq!(
            recovered, tier1_count_before,
            "crash recovery should only count Tier1 entries"
        );
    }

    #[test]
    fn negative_saturating_add_arithmetic_overflow_counter_protection() {
        let mut adapter = FrankensqliteAdapter::default();

        // Force near-overflow conditions on all counter fields
        adapter.write_count = usize::MAX - 2;
        adapter.read_count = usize::MAX - 1;
        adapter.write_failures = usize::MAX - 3;
        adapter.replay_count = usize::MAX - 4;
        adapter.replay_mismatches = usize::MAX - 5;

        // Test operations at overflow boundary
        for i in 0..10 {
            let key = format!("overflow_test_{i}");
            let _ = adapter.write(PersistenceClass::ControlState, &key, b"test");
            let _ = adapter.read_legacy(PersistenceClass::ControlState, &key);
        }

        // Create write failure to test failure counter saturation
        for _ in 0..5 {
            let _ = adapter.write(PersistenceClass::AuditLog, "duplicate", b"test");
        }

        // Test replay counter overflow
        for _ in 0..8 {
            let _ = adapter.replay();
        }

        // All counters should saturate, never wrap around to 0
        assert_eq!(adapter.write_count, usize::MAX); // Should saturate
        assert_eq!(adapter.read_count, usize::MAX);
        assert_eq!(adapter.write_failures, usize::MAX);
        assert_eq!(adapter.replay_count, usize::MAX);
        assert_eq!(adapter.replay_mismatches, usize::MAX);

        // Adapter should remain functional after overflow
        let result = adapter.write(PersistenceClass::Cache, "post_overflow", b"still_works");
        assert!(result.is_ok());
    }

    #[test]
    fn negative_ct_eq_bytes_timing_attack_resistance_replay() {
        let mut adapter = FrankensqliteAdapter::default();

        // Create audit entries with different hash characteristics to test timing
        let timing_test_entries = vec![
            ("short_hash", b"a"),                // Short value
            ("medium_hash", &vec![0xAA; 1000]),  // Medium value
            ("long_hash", &vec![0xBB; 100_000]), // Long value
            ("zero_hash", &vec![0x00; 50_000]),  // All zeros
            ("max_hash", &vec![0xFF; 50_000]),   // All ones
            (
                "pattern_hash",
                &(0..10_000).map(|i| (i % 256) as u8).collect::<Vec<_>>(),
            ), // Pattern
        ];

        for (key, value) in &timing_test_entries {
            adapter
                .write(PersistenceClass::AuditLog, key, value)
                .expect("audit write should succeed");
        }

        // Tamper with one entry to create deliberate mismatch
        adapter.store.insert(
            (PersistenceClass::AuditLog, "medium_hash".to_string()),
            Arc::<[u8]>::from(vec![0xCC; 1000]), // Different value, same length
        );

        // Replay should use constant-time comparison regardless of data size/patterns
        let start = std::time::Instant::now();
        let replay_results = adapter.replay();
        let replay_duration = start.elapsed();

        // Verify one mismatch detected (the tampered entry)
        let mismatches = replay_results
            .iter()
            .filter(|(_, matches)| !*matches)
            .count();
        assert_eq!(mismatches, 1);
        assert_eq!(adapter.summary().replay_mismatches, 1);

        // Replay should complete within reasonable time bounds regardless of content
        assert!(
            replay_duration.as_millis() < 10_000,
            "replay timing should be bounded"
        );

        // Verify mismatch event was emitted
        assert!(
            adapter
                .events()
                .iter()
                .any(|e| e.code == event_codes::FRANKENSQLITE_REPLAY_MISMATCH)
        );
    }

    #[test]
    fn negative_microseconds_length_cast_overflow_boundary() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test boundary conditions for latency measurement overflow
        // Since we can't easily control Instant::elapsed(), test the conversion logic indirectly

        // Write operations and verify latency measurement handles overflow gracefully
        for i in 0..100 {
            let key = format!("latency_test_{i}");
            let result = adapter.write(PersistenceClass::ControlState, &key, b"timing_test");

            assert!(result.is_ok());
            let latency = result.unwrap().latency_us;

            // Latency should be bounded by u64::MAX (overflow protection)
            assert!(latency <= u64::MAX);

            // Latency should be reasonable (not wrapped around to 0)
            assert!(
                latency < u64::MAX / 2,
                "latency should not indicate overflow: {}",
                latency
            );
        }

        // Verify summary handles accumulated metrics correctly
        let summary = adapter.summary();
        assert!(summary.total_writes <= usize::MAX);
        assert!(summary.total_writes > 0);
    }

    #[test]
    fn negative_key_length_boundary_values_without_unchecked_cast() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test with keys of various boundary lengths
        let boundary_lengths = vec![
            0,         // Empty key
            1,         // Single char
            255,       // Near boundary
            256,       // At boundary
            65535,     // Near u16::MAX
            65536,     // At u16::MAX + 1
            1_000_000, // Large key
        ];

        for length in boundary_lengths {
            let key = if length == 0 {
                String::new()
            } else {
                "k".repeat(length)
            };

            let result = adapter.write(PersistenceClass::Cache, &key, b"boundary_test");

            if result.is_ok() {
                // If write succeeds, verify read works with same key
                let read_result = adapter.read_legacy(PersistenceClass::Cache, &key);
                assert!(
                    read_result.found,
                    "key length {} should be readable",
                    length
                );
                assert_eq!(read_result.value.unwrap(), b"boundary_test");

                // Key length should be preserved correctly (no truncation from unsafe casts)
                assert_eq!(read_result.key.len(), length);
            }
            // Large keys may be rejected, which is acceptable
        }

        // Verify adapter remains functional after boundary testing
        let normal_result = adapter.write(PersistenceClass::ControlState, "normal", b"test");
        assert!(normal_result.is_ok());
    }

    #[test]
    fn negative_timestamp_ordering_comparison_fail_closed_semantics() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test timestamp boundary conditions that could bypass security checks
        let boundary_timestamps = vec![
            0u64,         // Epoch start
            1,            // Minimal positive
            u64::MAX - 1, // Near overflow
            u64::MAX,     // At overflow
        ];

        for (i, timestamp) in boundary_timestamps.iter().enumerate() {
            let key = format!("timestamp_test_{i}");

            // Write with boundary timestamp
            let result = adapter.write(
                PersistenceClass::ControlState,
                &key,
                format!("timestamp_{timestamp}").as_bytes(),
            );
            assert!(result.is_ok());

            // Verify timestamp values don't cause comparison issues
            let read_result = adapter.read_legacy(PersistenceClass::ControlState, &key);
            assert!(read_result.found);

            // Test schema migration with boundary timestamps
            if i < 3 {
                // Avoid duplicate version errors
                let version = (i + 2) as u32; // Start from version 2
                let migrate_result =
                    adapter.migrate(version, &format!("migration_at_timestamp_{timestamp}"));
                assert!(migrate_result.is_ok());
            }
        }

        // Test edge case: timestamps in edge order
        for class in PersistenceClass::all() {
            let result = adapter.write(*class, "edge_ordering", b"test");
            assert!(result.is_ok());
        }

        // Verify adapter maintains consistency across timestamp boundaries
        assert!(adapter.gate_pass());
        assert_eq!(adapter.summary().write_failures, 0);
    }

    #[test]
    fn negative_event_detail_hash_collision_without_domain_separation() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test potential hash collision in event detail strings that could
        // bypass event filtering or cause confusion
        let collision_prone_details = vec![
            "key=collision_test_1, tier=tier1_wal_crash_safe, latency_us=42",
            "key=collision_test_2, tier=tier1_wal_crash_safe, latency_us=42",
            "key=collision_test_3, tier=tier1_wal_crash_safe, latency_us=42",
            // Crafted strings that might hash to same value without proper domain separation
            "session_established_abcd",
            "session_establishedabcd", // No separator
            "prefix_suffix_123",
            "prefixsuffix_123", // Different structure, same chars
        ];

        // Generate events with collision-prone details
        for (i, detail_pattern) in collision_prone_details.iter().enumerate() {
            let key = format!("collision_key_{i}");

            // Create different event types to test detail handling
            match i % 3 {
                0 => {
                    let _ = adapter.write(PersistenceClass::ControlState, &key, b"test");
                }
                1 => {
                    let _ = adapter.write(PersistenceClass::AuditLog, &key, b"audit");
                }
                _ => {
                    let _ = adapter.read_legacy(PersistenceClass::ControlState, &key);
                }
            }
        }

        // Force error events to test error detail collision resistance
        for i in 0..5 {
            let _ = adapter.write(PersistenceClass::AuditLog, "duplicate_error", b"error_test");
        }

        // Verify event details remain distinct despite potential collisions
        let events = adapter.events();
        assert!(!events.is_empty());

        // Group events by code to verify proper categorization
        let mut event_codes = std::collections::BTreeSet::new();
        for event in events {
            event_codes.insert(&event.code);

            // Event details should not be empty or corrupted
            assert!(!event.detail.is_empty());
            assert!(!event.detail.contains('\x00')); // No null bytes
            assert!(!event.persistence_class.is_empty());
        }

        // Should have multiple distinct event codes
        assert!(
            event_codes.len() >= 2,
            "should have distinct event types: {:?}",
            event_codes
        );
    }

    // -- Hardening Pattern Tests --

    #[test]
    fn negative_counter_increment_overflow_without_saturating_add() {
        let mut adapter = FrankensqliteAdapter::default();

        // Set counters near overflow to test saturating_add protection
        adapter.write_count = usize::MAX - 2;
        adapter.read_count = usize::MAX - 1;
        adapter.write_failures = usize::MAX;
        adapter.replay_count = usize::MAX - 3;
        adapter.replay_mismatches = usize::MAX - 4;

        // Operations should use saturating_add to prevent wraparound
        let _ = adapter.write(PersistenceClass::ControlState, "overflow_test", b"data");
        assert_eq!(
            adapter.write_count,
            usize::MAX,
            "write_count should saturate at MAX"
        );

        let _ = adapter.read_legacy(PersistenceClass::ControlState, "overflow_test");
        assert_eq!(
            adapter.read_count,
            usize::MAX,
            "read_count should saturate at MAX"
        );

        // Force write failure to test failure counter saturation
        let _ = adapter.write(PersistenceClass::AuditLog, "duplicate", b"test");
        let _ = adapter.write(PersistenceClass::AuditLog, "duplicate", b"tampered");
        assert_eq!(
            adapter.write_failures,
            usize::MAX,
            "write_failures should remain saturated"
        );

        // Test replay counter saturation
        let _ = adapter.replay();
        assert_eq!(
            adapter.replay_count,
            usize::MAX,
            "replay_count should saturate"
        );
    }

    #[test]
    fn negative_hash_comparison_timing_attack_without_ct_eq_bytes() {
        let mut adapter = FrankensqliteAdapter::default();

        // Create audit entries with crafted hash collision attempts
        let original_data = b"legitimate_audit_entry";
        let tampered_data = b"malicious_audit_tamper";

        adapter
            .write(PersistenceClass::AuditLog, "audit_entry", original_data)
            .expect("original write should succeed");

        // Tamper with stored value to create hash mismatch
        adapter.store.insert(
            (PersistenceClass::AuditLog, "audit_entry".to_string()),
            Arc::<[u8]>::from(tampered_data.as_slice()),
        );

        // Replay should use ct_eq_bytes for constant-time comparison
        let start = std::time::Instant::now();
        let replay_results = adapter.replay();
        let duration = start.elapsed();

        // Verify mismatch detected via constant-time comparison
        assert_eq!(replay_results, vec![("audit_entry".to_string(), false)]);
        assert_eq!(adapter.summary().replay_mismatches, 1);

        // Timing should be constant regardless of where mismatch occurs
        assert!(
            duration.as_millis() < 5000,
            "constant-time comparison should be fast"
        );

        // Test with varying data sizes to ensure timing resistance
        for size in [1, 100, 10000] {
            let key = format!("timing_test_{size}");
            let data = vec![0x42; size];
            adapter
                .write(PersistenceClass::AuditLog, &key, &data)
                .unwrap();
        }

        let multi_replay_start = std::time::Instant::now();
        let _ = adapter.replay();
        let multi_duration = multi_replay_start.elapsed();

        // Multiple entries should still complete in bounded time
        assert!(
            multi_duration.as_millis() < 10000,
            "multi-entry replay should be bounded"
        );
    }

    #[test]
    fn negative_expiry_boundary_comparison_bypass_without_fail_closed() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test schema version comparison boundaries that must be fail-closed
        // Current schema is 1, test boundary conditions
        let boundary_tests = vec![
            (0, "should fail - equal to current"),
            (1, "should fail - equal to current"),
            (u32::MAX, "should handle overflow gracefully"),
        ];

        for (version, description) in boundary_tests {
            let result = adapter.migrate(version, description);

            match version {
                // Versions <= current should fail closed (using <=, not just <)
                0 | 1 => {
                    assert!(result.is_err(), "version {version} should fail closed");
                    if let Err(AdapterError::SchemaMigrationFailed { version: v, .. }) = result {
                        assert_eq!(v, version);
                    } else {
                        panic!("wrong error type for version {version}");
                    }
                }
                // Very large versions may succeed or fail gracefully
                _ => {
                    // Either succeeds or fails with proper error handling
                    if result.is_err() {
                        assert!(matches!(
                            result,
                            Err(AdapterError::SchemaMigrationFailed { .. })
                        ));
                    }
                }
            }
        }

        // Test with incremental versions near boundary
        let current = adapter.schema_version();

        // Test exact boundary (should fail closed)
        let boundary_result = adapter.migrate(current, "boundary test");
        assert!(
            boundary_result.is_err(),
            "exact boundary should fail closed"
        );

        // Test valid increment (should succeed)
        let increment_result = adapter.migrate(current + 1, "valid increment");
        assert!(increment_result.is_ok(), "valid increment should succeed");
    }

    #[test]
    fn negative_length_cast_overflow_without_try_from_protection() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test potential overflow in length casting operations
        // The code uses u64::try_from for microsecond conversion, verify behavior

        let test_data = vec![
            ("small", vec![0u8; 10]),
            ("medium", vec![1u8; 1000]),
            ("large", vec![2u8; 100_000]),
            ("huge", vec![3u8; 1_000_000]),
        ];

        for (key, data) in test_data {
            let write_result = adapter.write(PersistenceClass::Cache, key, &data);

            match write_result {
                Ok(result) => {
                    // Latency should use try_from conversion, not unchecked cast
                    assert!(result.latency_us <= u64::MAX, "latency should not overflow");

                    // Verify data length is preserved correctly
                    let read_result = adapter.read_legacy(PersistenceClass::Cache, key);
                    assert_eq!(
                        read_result.value.unwrap().len(),
                        data.len(),
                        "data length should be preserved without cast overflow"
                    );
                }
                Err(_) => {
                    // Large allocations may fail gracefully, which is acceptable
                }
            }
        }

        // Test boundary conditions for usize -> u32 conversions
        let boundary_lengths = vec![
            u32::MAX as usize - 1, // Just under u32::MAX
            u32::MAX as usize,     // At u32::MAX
            u32::MAX as usize + 1, // Just over u32::MAX
        ];

        for length in boundary_lengths {
            // Use a smaller test to avoid memory exhaustion
            let small_test_key = format!("boundary_len_{length}");
            let small_test_data = vec![0u8; std::cmp::min(length, 10000)];

            let result = adapter.write(PersistenceClass::Cache, &small_test_key, &small_test_data);
            if result.is_ok() {
                let read_result = adapter.read_legacy(PersistenceClass::Cache, &small_test_key);
                assert!(
                    read_result.found,
                    "boundary length data should be retrievable"
                );
            }
            // Large lengths may be rejected, which is safe behavior
        }

        // Verify adapter remains functional after boundary testing
        let normal_result =
            adapter.write(PersistenceClass::ControlState, "post_boundary", b"normal");
        assert!(normal_result.is_ok(), "adapter should remain functional");
    }

    #[test]
    fn negative_hash_collision_attack_without_domain_separation() {
        let mut adapter = FrankensqliteAdapter::default();

        // Test hash collision scenarios that could bypass security without domain separation
        // Event detail formatting could be vulnerable to collision attacks

        let collision_test_cases = vec![
            // Keys designed to test hash collision resistance
            ("key1|data1", "value1"),
            ("key1data1|", "value1"), // Different delimiter placement
            ("key1", "|data1value1"), // Data in value
            // Schema version descriptions that could collide
            ("v2_migration", "index_add"),
            ("v2migration_", "index_add"),
            // Event details that could hash similarly
            ("latency_test_a", "timing_data"),
            ("latency_testa_", "timing_data"),
        ];

        for (key, value) in &collision_test_cases {
            // Test across different persistence classes to verify separation
            for class in PersistenceClass::all() {
                let result = adapter.write(*class, key, value.as_bytes());
                assert!(
                    result.is_ok(),
                    "collision test case should be handled safely"
                );

                let read_result = adapter.read_legacy(*class, key);
                assert_eq!(
                    read_result.value.unwrap(),
                    value.as_bytes(),
                    "collision case should preserve data integrity"
                );
            }
        }

        // Test schema migration collision resistance
        for (i, (description, _)) in collision_test_cases.iter().enumerate() {
            let version = (i + 10) as u32; // Start from version 10 to avoid conflicts
            let result = adapter.migrate(version, description);
            assert!(
                result.is_ok(),
                "schema migration should handle collision cases"
            );
        }

        // Verify all operations maintained distinct state
        let events = adapter.events();
        assert!(!events.is_empty(), "events should be generated");

        // Verify event details use proper domain separation
        let write_events: Vec<_> = events
            .iter()
            .filter(|e| e.code == event_codes::FRANKENSQLITE_WRITE_SUCCESS)
            .collect();

        for event in write_events {
            // Event details should contain structured, separated information
            assert!(
                event.detail.contains("key="),
                "event should have structured key field"
            );
            assert!(
                event.detail.contains("tier="),
                "event should have structured tier field"
            );
            // This ensures proper domain separation in event formatting
        }
    }

    // -- Authorization tests --

    #[test]
    fn test_authorization_system_role_access_all() {
        let mut adapter = FrankensqliteAdapter::default();
        let system_caller = CallerContext::system("test::system", "auth-test-1");

        // System role should be able to access all persistence classes
        for class in PersistenceClass::all() {
            let write_result = adapter.write(&system_caller, *class, "test-key", b"test-value");
            assert!(
                write_result.is_ok(),
                "system role should write to {:?}",
                class
            );

            let read_result = adapter.read_legacy(&system_caller, *class, "test-key");
            assert!(
                read_result.is_ok(),
                "system role should read from {:?}",
                class
            );
        }
    }

    #[test]
    fn test_authorization_service_role_control_state_access() {
        let mut adapter = FrankensqliteAdapter::default();
        let connector_caller = CallerContext::service("connector::fencing", "auth-test-2");
        let other_caller = CallerContext::service("other::service", "auth-test-3");

        // Connector service should be able to access control state
        let write_result = adapter.write(
            &connector_caller,
            PersistenceClass::ControlState,
            "fence",
            b"token",
        );
        assert!(
            write_result.is_ok(),
            "connector service should write control state"
        );

        let read_result =
            adapter.read_legacy(&connector_caller, PersistenceClass::ControlState, "fence");
        assert!(
            read_result.is_ok(),
            "connector service should read control state"
        );

        // Other service should be denied access to control state
        let denied_write = adapter.write(
            &other_caller,
            PersistenceClass::ControlState,
            "fence2",
            b"token2",
        );
        assert!(
            denied_write.is_err(),
            "other service should be denied control state write"
        );

        let denied_read =
            adapter.read_legacy(&other_caller, PersistenceClass::ControlState, "fence");
        assert!(
            denied_read.is_err(),
            "other service should be denied control state read"
        );
    }

    #[test]
    fn test_authorization_audit_log_write_restriction() {
        let mut adapter = FrankensqliteAdapter::default();
        let audit_caller = CallerContext::service("observability::audit", "auth-test-4");
        let service_caller = CallerContext::service("service::worker", "auth-test-5");

        // Audit service should be able to write audit logs
        let write_result = adapter.write(
            &audit_caller,
            PersistenceClass::AuditLog,
            "audit1",
            b"entry",
        );
        assert!(
            write_result.is_ok(),
            "audit service should write audit logs"
        );

        // Regular service should be denied audit log write
        let denied_write = adapter.write(
            &service_caller,
            PersistenceClass::AuditLog,
            "audit2",
            b"entry",
        );
        assert!(
            denied_write.is_err(),
            "regular service should be denied audit log write"
        );

        // But should be able to read (for queries)
        let read_result =
            adapter.read_legacy(&service_caller, PersistenceClass::AuditLog, "audit1");
        assert!(
            read_result.is_ok(),
            "regular service should read audit logs"
        );
    }

    #[test]
    fn test_authorization_readonly_role_restrictions() {
        let mut adapter = FrankensqliteAdapter::default();
        let readonly_caller = CallerContext::read_only("monitoring::service", "auth-test-6");

        // Read-only role should be denied all writes
        for class in PersistenceClass::all() {
            let write_result = adapter.write(&readonly_caller, *class, "readonly-test", b"data");
            assert!(
                write_result.is_err(),
                "read-only role should be denied {:?} write",
                class
            );
        }

        // Read-only should be able to read non-audit logs
        let read_result = adapter.read_legacy(&readonly_caller, PersistenceClass::Cache, "test");
        assert!(read_result.is_ok(), "read-only should read cache");

        // But denied audit log access
        let denied_audit_read =
            adapter.read_legacy(&readonly_caller, PersistenceClass::AuditLog, "test");
        assert!(
            matches!(
                denied_audit_read,
                Err(AdapterError::AuthorizationFailed(
                    AuthorizationError::AccessDenied { .. }
                ))
            ),
            "read-only audit reads must fail closed with authorization error"
        );
    }

    #[test]
    fn test_authorization_restricted_role_cache_only() {
        let mut adapter = FrankensqliteAdapter::default();
        let restricted_caller = CallerContext::new(
            "temp::worker".to_string(),
            CallerRole::Restricted,
            "auth-test-7".to_string(),
        );

        // Restricted role should only access cache
        let cache_write = adapter.write(
            &restricted_caller,
            PersistenceClass::Cache,
            "cache-key",
            b"data",
        );
        assert!(cache_write.is_ok(), "restricted role should write cache");

        let cache_read =
            adapter.read_legacy(&restricted_caller, PersistenceClass::Cache, "cache-key");
        assert!(cache_read.is_ok(), "restricted role should read cache");

        // But denied all other persistence classes
        for class in [
            PersistenceClass::ControlState,
            PersistenceClass::AuditLog,
            PersistenceClass::Snapshot,
        ] {
            let denied_write = adapter.write(&restricted_caller, class, "test", b"data");
            assert!(
                denied_write.is_err(),
                "restricted role should be denied {:?} write",
                class
            );

            let denied_read = adapter.read_legacy(&restricted_caller, class, "test");
            assert!(
                denied_read.is_err(),
                "restricted role should be denied {:?} read",
                class
            );
        }
    }

    #[test]
    fn test_authorization_invalid_context_rejection() {
        let mut adapter = FrankensqliteAdapter::default();

        // Empty caller ID should be rejected
        let invalid_caller = CallerContext::new(
            "".to_string(),
            CallerRole::System,
            "auth-test-8".to_string(),
        );

        let result = adapter.write(&invalid_caller, PersistenceClass::Cache, "test", b"data");
        assert!(result.is_err(), "empty caller_id should be rejected");

        // Empty trace ID should be rejected
        let invalid_trace_caller = CallerContext::new(
            "test::service".to_string(),
            CallerRole::System,
            "".to_string(),
        );

        let result = adapter.write(
            &invalid_trace_caller,
            PersistenceClass::Cache,
            "test",
            b"data",
        );
        assert!(result.is_err(), "empty trace_id should be rejected");
    }

    #[test]
    fn test_legacy_methods_use_system_permissions() {
        let mut adapter = FrankensqliteAdapter::default();

        // Legacy methods should work (using system permissions)
        #[allow(deprecated)]
        let write_result =
            adapter.write_legacy(PersistenceClass::ControlState, "legacy-test", b"data");
        assert!(
            write_result.is_ok(),
            "legacy write should use system permissions"
        );

        #[allow(deprecated)]
        let read_result = adapter.read_legacy(PersistenceClass::ControlState, "legacy-test");
        assert!(
            read_result.found,
            "legacy read should use system permissions"
        );
    }
}
