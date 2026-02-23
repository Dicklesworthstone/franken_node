//! bd-1p2b: Control-plane retention policy (`required` vs `ephemeral`) and storage enforcement.
//!
//! Retention class is mandatory per message type. Required objects are durably stored.
//! Ephemeral objects may be dropped only under policy (TTL or storage pressure).

use std::collections::BTreeMap;

/// Retention class for a control-plane message.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RetentionClass {
    Required,
    Ephemeral,
}

impl RetentionClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// Per-type retention policy.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub message_type: String,
    pub retention_class: RetentionClass,
    pub ephemeral_ttl_seconds: u64,
}

/// Registry of retention policies per message type.
#[derive(Debug, Default)]
pub struct RetentionRegistry {
    policies: BTreeMap<String, RetentionPolicy>,
}

impl RetentionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, policy: RetentionPolicy) -> Result<(), RetentionError> {
        if policy.message_type.is_empty() {
            return Err(RetentionError::InvalidPolicy {
                reason: "message_type must not be empty".into(),
            });
        }
        if policy.retention_class == RetentionClass::Ephemeral && policy.ephemeral_ttl_seconds == 0
        {
            return Err(RetentionError::InvalidPolicy {
                reason: "ephemeral_ttl_seconds must be > 0 for ephemeral class".into(),
            });
        }
        self.policies.insert(policy.message_type.clone(), policy);
        Ok(())
    }

    pub fn classify(&self, message_type: &str) -> Result<&RetentionPolicy, RetentionError> {
        self.policies
            .get(message_type)
            .ok_or_else(|| RetentionError::Unclassified {
                message_type: message_type.to_string(),
            })
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }
}

/// Stored control-plane message.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub message_id: String,
    pub message_type: String,
    pub retention_class: RetentionClass,
    pub stored_at: u64,
    pub size_bytes: u64,
}

/// Audit record for a retention decision.
#[derive(Debug, Clone)]
pub struct RetentionDecision {
    pub message_id: String,
    pub message_type: String,
    pub retention_class: String,
    pub action: String,
    pub reason: String,
    pub timestamp: u64,
}

/// Errors from retention operations.
#[derive(Debug, Clone, PartialEq)]
pub enum RetentionError {
    Unclassified { message_type: String },
    DropRequired { message_id: String },
    InvalidPolicy { reason: String },
    StorageFull { current_bytes: u64, max_bytes: u64 },
    NotFound { message_id: String },
}

impl RetentionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unclassified { .. } => "CPR_UNCLASSIFIED",
            Self::DropRequired { .. } => "CPR_DROP_REQUIRED",
            Self::InvalidPolicy { .. } => "CPR_INVALID_POLICY",
            Self::StorageFull { .. } => "CPR_STORAGE_FULL",
            Self::NotFound { .. } => "CPR_NOT_FOUND",
        }
    }
}

impl std::fmt::Display for RetentionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unclassified { message_type } => write!(f, "CPR_UNCLASSIFIED: {message_type}"),
            Self::DropRequired { message_id } => write!(f, "CPR_DROP_REQUIRED: {message_id}"),
            Self::InvalidPolicy { reason } => write!(f, "CPR_INVALID_POLICY: {reason}"),
            Self::StorageFull {
                current_bytes,
                max_bytes,
            } => write!(f, "CPR_STORAGE_FULL: {current_bytes}/{max_bytes}"),
            Self::NotFound { message_id } => write!(f, "CPR_NOT_FOUND: {message_id}"),
        }
    }
}

/// Retention-enforced message store.
#[derive(Debug)]
pub struct RetentionStore {
    registry: RetentionRegistry,
    messages: BTreeMap<String, StoredMessage>,
    total_bytes: u64,
    max_bytes: u64,
    decisions: Vec<RetentionDecision>,
}

impl RetentionStore {
    pub fn new(registry: RetentionRegistry, max_bytes: u64) -> Result<Self, RetentionError> {
        if max_bytes == 0 {
            return Err(RetentionError::InvalidPolicy {
                reason: "max_bytes must be > 0".into(),
            });
        }
        Ok(Self {
            registry,
            messages: BTreeMap::new(),
            total_bytes: 0,
            max_bytes,
            decisions: Vec::new(),
        })
    }

    /// Store a message with retention enforcement.
    ///
    /// INV-CPR-CLASSIFIED: rejects unclassified messages.
    /// INV-CPR-REQUIRED-DURABLE: required messages always stored.
    pub fn store(
        &mut self,
        message_id: &str,
        message_type: &str,
        size_bytes: u64,
        now: u64,
    ) -> Result<(), RetentionError> {
        let policy = self.registry.classify(message_type)?;
        let class = policy.retention_class;

        // Check storage capacity
        if self.total_bytes + size_bytes > self.max_bytes {
            // Try ephemeral cleanup first
            self.cleanup_ephemeral(now);
            if self.total_bytes + size_bytes > self.max_bytes {
                return Err(RetentionError::StorageFull {
                    current_bytes: self.total_bytes,
                    max_bytes: self.max_bytes,
                });
            }
        }

        let msg = StoredMessage {
            message_id: message_id.to_string(),
            message_type: message_type.to_string(),
            retention_class: class,
            stored_at: now,
            size_bytes,
        };

        self.decisions.push(RetentionDecision {
            message_id: message_id.to_string(),
            message_type: message_type.to_string(),
            retention_class: class.label().to_string(),
            action: "store".into(),
            reason: format!("classified as {}", class.label()),
            timestamp: now,
        });

        self.total_bytes += size_bytes;
        self.messages.insert(message_id.to_string(), msg);
        Ok(())
    }

    /// Attempt to drop a message.
    ///
    /// INV-CPR-REQUIRED-DURABLE: required messages cannot be dropped.
    pub fn drop_message(&mut self, message_id: &str, now: u64) -> Result<(), RetentionError> {
        let msg = self
            .messages
            .get(message_id)
            .ok_or_else(|| RetentionError::NotFound {
                message_id: message_id.to_string(),
            })?;

        if msg.retention_class == RetentionClass::Required {
            return Err(RetentionError::DropRequired {
                message_id: message_id.to_string(),
            });
        }

        let msg = self.messages.remove(message_id).unwrap();
        self.total_bytes = self.total_bytes.saturating_sub(msg.size_bytes);

        self.decisions.push(RetentionDecision {
            message_id: message_id.to_string(),
            message_type: msg.message_type.clone(),
            retention_class: msg.retention_class.label().to_string(),
            action: "drop".into(),
            reason: "explicit drop request".into(),
            timestamp: now,
        });

        Ok(())
    }

    /// Cleanup expired ephemeral messages.
    ///
    /// INV-CPR-EPHEMERAL-POLICY: only dropped when TTL expires.
    pub fn cleanup_ephemeral(&mut self, now: u64) -> Vec<RetentionDecision> {
        let mut to_drop = Vec::new();

        for (id, msg) in &self.messages {
            if msg.retention_class == RetentionClass::Ephemeral
                && let Ok(policy) = self.registry.classify(&msg.message_type)
            {
                let age = now.saturating_sub(msg.stored_at);
                if age >= policy.ephemeral_ttl_seconds {
                    to_drop.push(id.clone());
                }
            }
        }

        let mut dropped = Vec::new();
        for id in to_drop {
            if let Some(msg) = self.messages.remove(&id) {
                self.total_bytes = self.total_bytes.saturating_sub(msg.size_bytes);
                let decision = RetentionDecision {
                    message_id: id,
                    message_type: msg.message_type,
                    retention_class: "ephemeral".into(),
                    action: "drop".into(),
                    reason: "ttl_expired".into(),
                    timestamp: now,
                };
                self.decisions.push(decision.clone());
                dropped.push(decision);
            }
        }

        dropped
    }

    /// Get all audit decisions.
    pub fn decisions(&self) -> &[RetentionDecision] {
        &self.decisions
    }

    /// Get storage stats.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    pub fn contains(&self, message_id: &str) -> bool {
        self.messages.contains_key(message_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> RetentionRegistry {
        let mut reg = RetentionRegistry::new();
        reg.register(RetentionPolicy {
            message_type: "invoke".into(),
            retention_class: RetentionClass::Required,
            ephemeral_ttl_seconds: 0,
        })
        .unwrap();
        reg.register(RetentionPolicy {
            message_type: "heartbeat".into(),
            retention_class: RetentionClass::Ephemeral,
            ephemeral_ttl_seconds: 60,
        })
        .unwrap();
        reg.register(RetentionPolicy {
            message_type: "audit".into(),
            retention_class: RetentionClass::Required,
            ephemeral_ttl_seconds: 0,
        })
        .unwrap();
        reg
    }

    #[test]
    fn store_required_message() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        store.store("m1", "invoke", 100, 1000).unwrap();
        assert!(store.contains("m1"));
    }

    #[test]
    fn store_ephemeral_message() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        store.store("m1", "heartbeat", 50, 1000).unwrap();
        assert!(store.contains("m1"));
    }

    #[test]
    fn reject_unclassified() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        let err = store.store("m1", "unknown_type", 100, 1000).unwrap_err();
        assert_eq!(err.code(), "CPR_UNCLASSIFIED");
    }

    #[test]
    fn cannot_drop_required() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        store.store("m1", "invoke", 100, 1000).unwrap();
        let err = store.drop_message("m1", 1001).unwrap_err();
        assert_eq!(err.code(), "CPR_DROP_REQUIRED");
        assert!(store.contains("m1")); // still there
    }

    #[test]
    fn can_drop_ephemeral() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        store.store("m1", "heartbeat", 50, 1000).unwrap();
        store.drop_message("m1", 1001).unwrap();
        assert!(!store.contains("m1"));
    }

    #[test]
    fn ephemeral_ttl_cleanup() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        store.store("m1", "heartbeat", 50, 1000).unwrap();
        store.store("m2", "heartbeat", 50, 1050).unwrap();
        // At t=1060, m1 has age 60 (>=TTL), m2 has age 10
        let dropped = store.cleanup_ephemeral(1060);
        assert_eq!(dropped.len(), 1);
        assert!(!store.contains("m1"));
        assert!(store.contains("m2"));
    }

    #[test]
    fn required_survives_cleanup() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        store.store("m1", "invoke", 100, 1000).unwrap();
        store.store("m2", "heartbeat", 50, 1000).unwrap();
        store.cleanup_ephemeral(1200); // way past TTL
        assert!(store.contains("m1")); // required survives
        assert!(!store.contains("m2")); // ephemeral dropped
    }

    #[test]
    fn storage_full_error() {
        let mut store = RetentionStore::new(registry(), 200).unwrap();
        store.store("m1", "invoke", 150, 1000).unwrap();
        let err = store.store("m2", "invoke", 100, 1001).unwrap_err();
        assert_eq!(err.code(), "CPR_STORAGE_FULL");
    }

    #[test]
    fn storage_pressure_triggers_ephemeral_cleanup() {
        let mut store = RetentionStore::new(registry(), 200).unwrap();
        store.store("m1", "heartbeat", 150, 1000).unwrap();
        // m1 is expired at t=1100, so store should clean it up to make room
        store.store("m2", "invoke", 100, 1100).unwrap();
        assert!(!store.contains("m1"));
        assert!(store.contains("m2"));
    }

    #[test]
    fn drop_not_found() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        let err = store.drop_message("missing", 1000).unwrap_err();
        assert_eq!(err.code(), "CPR_NOT_FOUND");
    }

    #[test]
    fn decisions_recorded() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        store.store("m1", "invoke", 100, 1000).unwrap();
        store.store("m2", "heartbeat", 50, 1000).unwrap();
        assert!(store.decisions().len() >= 2);
        assert!(
            store
                .decisions()
                .iter()
                .any(|d| d.action == "store" && d.message_id == "m1")
        );
    }

    #[test]
    fn bytes_tracked() {
        let mut store = RetentionStore::new(registry(), 10000).unwrap();
        store.store("m1", "invoke", 100, 1000).unwrap();
        store.store("m2", "heartbeat", 50, 1000).unwrap();
        assert_eq!(store.total_bytes(), 150);
        store.drop_message("m2", 1001).unwrap();
        assert_eq!(store.total_bytes(), 100);
    }

    #[test]
    fn invalid_policy_empty_type() {
        let mut reg = RetentionRegistry::new();
        let err = reg
            .register(RetentionPolicy {
                message_type: "".into(),
                retention_class: RetentionClass::Required,
                ephemeral_ttl_seconds: 0,
            })
            .unwrap_err();
        assert_eq!(err.code(), "CPR_INVALID_POLICY");
    }

    #[test]
    fn invalid_policy_ephemeral_zero_ttl() {
        let mut reg = RetentionRegistry::new();
        let err = reg
            .register(RetentionPolicy {
                message_type: "test".into(),
                retention_class: RetentionClass::Ephemeral,
                ephemeral_ttl_seconds: 0,
            })
            .unwrap_err();
        assert_eq!(err.code(), "CPR_INVALID_POLICY");
    }

    #[test]
    fn invalid_store_zero_max_bytes() {
        let err = RetentionStore::new(registry(), 0).unwrap_err();
        assert_eq!(err.code(), "CPR_INVALID_POLICY");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            RetentionError::Unclassified {
                message_type: "".into()
            }
            .code(),
            "CPR_UNCLASSIFIED"
        );
        assert_eq!(
            RetentionError::DropRequired {
                message_id: "".into()
            }
            .code(),
            "CPR_DROP_REQUIRED"
        );
        assert_eq!(
            RetentionError::InvalidPolicy { reason: "".into() }.code(),
            "CPR_INVALID_POLICY"
        );
        assert_eq!(
            RetentionError::StorageFull {
                current_bytes: 0,
                max_bytes: 0
            }
            .code(),
            "CPR_STORAGE_FULL"
        );
        assert_eq!(
            RetentionError::NotFound {
                message_id: "".into()
            }
            .code(),
            "CPR_NOT_FOUND"
        );
    }

    #[test]
    fn error_display() {
        let e = RetentionError::DropRequired {
            message_id: "m1".into(),
        };
        assert!(e.to_string().contains("CPR_DROP_REQUIRED"));
    }

    #[test]
    fn retention_class_labels() {
        assert_eq!(RetentionClass::Required.label(), "required");
        assert_eq!(RetentionClass::Ephemeral.label(), "ephemeral");
    }
}
