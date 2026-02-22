//! bd-2aj: Ecosystem extension registry API.
//!
//! Implements RegistryAPI for the ecosystem network-effect layer. Provides
//! extension registration with signed metadata, version lineage queries,
//! compatibility matrix lookups, and deprecation/revocation notifications.
//! All mutations produce immutable audit log entries (INV-ENE-REGISTRY).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// -- Event codes ---------------------------------------------------------------

pub const ENE_001_REGISTRY_MUTATION: &str = "ENE-001";
pub const ENE_002_REGISTRY_QUERY: &str = "ENE-002";
pub const ENE_009_API_AUTH_REJECT: &str = "ENE-009";
pub const ENE_010_API_RATE_LIMIT: &str = "ENE-010";
pub const ENE_011_SYBIL_REJECT: &str = "ENE-011";

// -- Invariant tags ------------------------------------------------------------

pub const INV_ENE_REGISTRY: &str = "INV-ENE-REGISTRY";
pub const INV_ENE_SYBIL: &str = "INV-ENE-SYBIL";

// -- Error codes ---------------------------------------------------------------

pub const ERR_ENE_DUPLICATE_REG: &str = "ERR-ENE-DUPLICATE-REG";
pub const ERR_ENE_NOT_FOUND: &str = "ERR-ENE-NOT-FOUND";
pub const ERR_ENE_REVOKED: &str = "ERR-ENE-REVOKED";
pub const ERR_ENE_SYBIL: &str = "ERR-ENE-SYBIL";
pub const ERR_ENE_AUTH: &str = "ERR-ENE-AUTH";

// -- Errors --------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum RegistryError {
    #[error("duplicate extension registration: `{0}` (code: {ERR_ENE_DUPLICATE_REG})")]
    DuplicateRegistration(String),
    #[error("extension `{0}` not found (code: {ERR_ENE_NOT_FOUND})")]
    NotFound(String),
    #[error("extension `{0}` has been revoked (code: {ERR_ENE_REVOKED})")]
    Revoked(String),
    #[error("sybil resistance: duplicate publisher key `{0}` (code: {ERR_ENE_SYBIL})")]
    SybilDuplicate(String),
    #[error("authentication failure (code: {ERR_ENE_AUTH})")]
    AuthFailure(String),
}

// -- Extension status ----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionStatus {
    Active,
    Deprecated,
    Revoked,
}

impl std::fmt::Display for ExtensionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Deprecated => write!(f, "deprecated"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

// -- Extension metadata --------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionMetadata {
    pub extension_id: String,
    pub publisher_id: String,
    pub publisher_key: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub status: ExtensionStatus,
    pub created_at: String,
    pub updated_at: String,
    pub signature: String,
    pub tags: Vec<String>,
}

// -- Version lineage entry -----------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionLineageEntry {
    pub version: String,
    pub published_at: String,
    pub changelog: String,
    pub parent_version: Option<String>,
}

// -- Compatibility entry -------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityEntry {
    pub runtime: String,
    pub runtime_version: String,
    pub compatible: bool,
    pub tested_at: String,
}

// -- Audit log entry -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryAuditEntry {
    pub sequence: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub timestamp: String,
    pub extension_id: String,
    pub event_code: String,
    pub event_type: String,
    pub detail: String,
}

// -- Registry event (emitted) --------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub event_code: String,
    pub extension_id: String,
    pub detail: String,
    pub timestamp: String,
    pub trace_id: String,
}

// -- Extension record (stored) -------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionRecord {
    pub metadata: ExtensionMetadata,
    pub lineage: Vec<VersionLineageEntry>,
    pub compatibility: Vec<CompatibilityEntry>,
}

// -- Registry ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemRegistry {
    extensions: BTreeMap<String, ExtensionRecord>,
    publisher_keys: BTreeMap<String, String>,
    audit_trail: Vec<RegistryAuditEntry>,
    events: Vec<RegistryEvent>,
    next_sequence: u64,
}

impl Default for EcosystemRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EcosystemRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            extensions: BTreeMap::new(),
            publisher_keys: BTreeMap::new(),
            audit_trail: Vec::new(),
            events: Vec::new(),
            next_sequence: 0,
        }
    }

    /// Register a new extension with signed metadata.
    pub fn register_extension(
        &mut self,
        metadata: ExtensionMetadata,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<&ExtensionRecord, RegistryError> {
        // Sybil check: reject duplicate publisher keys from different publishers.
        if let Some(existing_pub) = self.publisher_keys.get(&metadata.publisher_key)
            && existing_pub != &metadata.publisher_id
        {
            self.emit_event(
                ENE_011_SYBIL_REJECT,
                &metadata.extension_id,
                &format!(
                    "duplicate key {} from publisher {}",
                    metadata.publisher_key, metadata.publisher_id
                ),
                timestamp,
                trace_id,
            );
            return Err(RegistryError::SybilDuplicate(
                metadata.publisher_key.clone(),
            ));
        }

        // Duplicate extension check.
        if self.extensions.contains_key(&metadata.extension_id) {
            return Err(RegistryError::DuplicateRegistration(
                metadata.extension_id.clone(),
            ));
        }

        let ext_id = metadata.extension_id.clone();
        self.publisher_keys.insert(
            metadata.publisher_key.clone(),
            metadata.publisher_id.clone(),
        );

        let initial_lineage = VersionLineageEntry {
            version: metadata.version.clone(),
            published_at: timestamp.to_owned(),
            changelog: "Initial registration".to_owned(),
            parent_version: None,
        };

        let record = ExtensionRecord {
            metadata,
            lineage: vec![initial_lineage],
            compatibility: Vec::new(),
        };

        self.extensions.insert(ext_id.clone(), record);
        self.append_audit_entry(
            &ext_id,
            ENE_001_REGISTRY_MUTATION,
            "extension_registered",
            &format!("Extension {} registered", ext_id),
            timestamp,
        );
        self.emit_event(
            ENE_001_REGISTRY_MUTATION,
            &ext_id,
            "registered",
            timestamp,
            trace_id,
        );

        Ok(&self.extensions[&ext_id])
    }

    /// Get an extension by ID.
    pub fn get_extension(
        &mut self,
        extension_id: &str,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<&ExtensionRecord, RegistryError> {
        self.emit_event(
            ENE_002_REGISTRY_QUERY,
            extension_id,
            "get_extension",
            timestamp,
            trace_id,
        );
        self.extensions
            .get(extension_id)
            .ok_or_else(|| RegistryError::NotFound(extension_id.to_owned()))
    }

    /// Get version lineage for an extension.
    pub fn get_lineage(
        &mut self,
        extension_id: &str,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<&[VersionLineageEntry], RegistryError> {
        self.emit_event(
            ENE_002_REGISTRY_QUERY,
            extension_id,
            "get_lineage",
            timestamp,
            trace_id,
        );
        let record = self
            .extensions
            .get(extension_id)
            .ok_or_else(|| RegistryError::NotFound(extension_id.to_owned()))?;
        Ok(&record.lineage)
    }

    /// Add a version to the lineage.
    pub fn add_version(
        &mut self,
        extension_id: &str,
        entry: VersionLineageEntry,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<(), RegistryError> {
        let record = self
            .extensions
            .get_mut(extension_id)
            .ok_or_else(|| RegistryError::NotFound(extension_id.to_owned()))?;
        if record.metadata.status == ExtensionStatus::Revoked {
            return Err(RegistryError::Revoked(extension_id.to_owned()));
        }
        record.metadata.version = entry.version.clone();
        record.metadata.updated_at = timestamp.to_owned();
        record.lineage.push(entry);
        self.append_audit_entry(
            extension_id,
            ENE_001_REGISTRY_MUTATION,
            "version_added",
            &format!("Version added to {}", extension_id),
            timestamp,
        );
        self.emit_event(
            ENE_001_REGISTRY_MUTATION,
            extension_id,
            "version_added",
            timestamp,
            trace_id,
        );
        Ok(())
    }

    /// Get compatibility matrix for an extension.
    pub fn get_compatibility(
        &mut self,
        extension_id: &str,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<&[CompatibilityEntry], RegistryError> {
        self.emit_event(
            ENE_002_REGISTRY_QUERY,
            extension_id,
            "get_compatibility",
            timestamp,
            trace_id,
        );
        let record = self
            .extensions
            .get(extension_id)
            .ok_or_else(|| RegistryError::NotFound(extension_id.to_owned()))?;
        Ok(&record.compatibility)
    }

    /// Add a compatibility entry.
    pub fn add_compatibility(
        &mut self,
        extension_id: &str,
        entry: CompatibilityEntry,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<(), RegistryError> {
        let record = self
            .extensions
            .get_mut(extension_id)
            .ok_or_else(|| RegistryError::NotFound(extension_id.to_owned()))?;
        record.compatibility.push(entry);
        self.append_audit_entry(
            extension_id,
            ENE_001_REGISTRY_MUTATION,
            "compat_added",
            &format!("Compatibility entry added for {}", extension_id),
            timestamp,
        );
        self.emit_event(
            ENE_001_REGISTRY_MUTATION,
            extension_id,
            "compat_added",
            timestamp,
            trace_id,
        );
        Ok(())
    }

    /// Deprecate an extension.
    pub fn deprecate_extension(
        &mut self,
        extension_id: &str,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<(), RegistryError> {
        let record = self
            .extensions
            .get_mut(extension_id)
            .ok_or_else(|| RegistryError::NotFound(extension_id.to_owned()))?;
        record.metadata.status = ExtensionStatus::Deprecated;
        record.metadata.updated_at = timestamp.to_owned();
        self.append_audit_entry(
            extension_id,
            ENE_001_REGISTRY_MUTATION,
            "deprecated",
            &format!("Extension {} deprecated", extension_id),
            timestamp,
        );
        self.emit_event(
            ENE_001_REGISTRY_MUTATION,
            extension_id,
            "deprecated",
            timestamp,
            trace_id,
        );
        Ok(())
    }

    /// Revoke an extension.
    pub fn revoke_extension(
        &mut self,
        extension_id: &str,
        reason: &str,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<(), RegistryError> {
        let record = self
            .extensions
            .get_mut(extension_id)
            .ok_or_else(|| RegistryError::NotFound(extension_id.to_owned()))?;
        record.metadata.status = ExtensionStatus::Revoked;
        record.metadata.updated_at = timestamp.to_owned();
        self.append_audit_entry(
            extension_id,
            ENE_001_REGISTRY_MUTATION,
            "revoked",
            &format!("Extension {} revoked: {}", extension_id, reason),
            timestamp,
        );
        self.emit_event(
            ENE_001_REGISTRY_MUTATION,
            extension_id,
            &format!("revoked: {}", reason),
            timestamp,
            trace_id,
        );
        Ok(())
    }

    /// List all extensions.
    #[must_use]
    pub fn list_extensions(&self) -> Vec<&ExtensionRecord> {
        self.extensions.values().collect()
    }

    /// Get extension count.
    #[must_use]
    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }

    /// Get the audit trail.
    #[must_use]
    pub fn audit_trail(&self) -> &[RegistryAuditEntry] {
        &self.audit_trail
    }

    /// Get audit trail length.
    #[must_use]
    pub fn audit_trail_len(&self) -> usize {
        self.audit_trail.len()
    }

    /// Verify audit trail integrity via hash chain.
    pub fn verify_audit_integrity(&self) -> Result<(), RegistryError> {
        let mut expected_prev = String::new();
        for entry in &self.audit_trail {
            if entry.prev_hash != expected_prev {
                return Err(RegistryError::AuthFailure(format!(
                    "audit chain broken at seq {}: expected prev_hash {}, got {}",
                    entry.sequence, expected_prev, entry.prev_hash
                )));
            }
            let computed = compute_audit_hash(entry);
            if computed != entry.entry_hash {
                return Err(RegistryError::AuthFailure(format!(
                    "audit entry {} hash mismatch: expected {}, got {}",
                    entry.sequence, computed, entry.entry_hash
                )));
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }

    /// Take all pending events (drains the buffer).
    pub fn take_events(&mut self) -> Vec<RegistryEvent> {
        std::mem::take(&mut self.events)
    }

    // -- Internal helpers -------------------------------------------------------

    fn append_audit_entry(
        &mut self,
        extension_id: &str,
        event_code: &str,
        event_type: &str,
        detail: &str,
        timestamp: &str,
    ) {
        let prev_hash = self
            .audit_trail
            .last()
            .map_or(String::new(), |e| e.entry_hash.clone());
        let sequence = self.next_sequence;
        self.next_sequence += 1;

        let mut entry = RegistryAuditEntry {
            sequence,
            prev_hash,
            entry_hash: String::new(),
            timestamp: timestamp.to_owned(),
            extension_id: extension_id.to_owned(),
            event_code: event_code.to_owned(),
            event_type: event_type.to_owned(),
            detail: detail.to_owned(),
        };
        entry.entry_hash = compute_audit_hash(&entry);
        self.audit_trail.push(entry);
    }

    fn emit_event(
        &mut self,
        event_code: &str,
        extension_id: &str,
        detail: &str,
        timestamp: &str,
        trace_id: &str,
    ) {
        self.events.push(RegistryEvent {
            event_code: event_code.to_owned(),
            extension_id: extension_id.to_owned(),
            detail: detail.to_owned(),
            timestamp: timestamp.to_owned(),
            trace_id: trace_id.to_owned(),
        });
    }
}

/// Compute SHA-256 hash for an audit entry.
fn compute_audit_hash(entry: &RegistryAuditEntry) -> String {
    let payload = format!(
        "{}:{}:{}:{}:{}:{}",
        entry.sequence,
        entry.prev_hash,
        entry.timestamp,
        entry.extension_id,
        entry.event_code,
        entry.detail,
    );
    let digest = Sha256::digest(payload.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(n: u32) -> String {
        format!("2026-01-{n:02}T00:00:00Z")
    }

    fn make_metadata(ext_id: &str, pub_id: &str, key: &str) -> ExtensionMetadata {
        ExtensionMetadata {
            extension_id: ext_id.to_owned(),
            publisher_id: pub_id.to_owned(),
            publisher_key: key.to_owned(),
            name: format!("Extension {ext_id}"),
            description: "Test extension".to_owned(),
            version: "1.0.0".to_owned(),
            status: ExtensionStatus::Active,
            created_at: ts(1),
            updated_at: ts(1),
            signature: "sig-placeholder".to_owned(),
            tags: vec!["test".to_owned()],
        }
    }

    #[test]
    fn test_register_extension() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        let record = reg.register_extension(meta, &ts(1), "trace-1").unwrap();
        assert_eq!(record.metadata.extension_id, "ext-1");
        assert_eq!(record.lineage.len(), 1);
        assert_eq!(reg.extension_count(), 1);
    }

    #[test]
    fn test_duplicate_registration_rejected() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta.clone(), &ts(1), "t").unwrap();
        let result = reg.register_extension(meta, &ts(2), "t");
        assert!(matches!(
            result,
            Err(RegistryError::DuplicateRegistration(_))
        ));
    }

    #[test]
    fn test_sybil_duplicate_key_rejected() {
        let mut reg = EcosystemRegistry::new();
        let meta1 = make_metadata("ext-1", "pub-1", "shared-key");
        reg.register_extension(meta1, &ts(1), "t").unwrap();
        let meta2 = make_metadata("ext-2", "pub-2", "shared-key");
        let result = reg.register_extension(meta2, &ts(2), "t");
        assert!(matches!(result, Err(RegistryError::SybilDuplicate(_))));
    }

    #[test]
    fn test_same_publisher_same_key_ok() {
        let mut reg = EcosystemRegistry::new();
        let meta1 = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta1, &ts(1), "t").unwrap();
        let meta2 = make_metadata("ext-2", "pub-1", "key-1");
        let result = reg.register_extension(meta2, &ts(2), "t");
        assert!(result.is_ok());
        assert_eq!(reg.extension_count(), 2);
    }

    #[test]
    fn test_get_extension() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        let record = reg.get_extension("ext-1", &ts(2), "t").unwrap();
        assert_eq!(record.metadata.publisher_id, "pub-1");
    }

    #[test]
    fn test_get_extension_not_found() {
        let mut reg = EcosystemRegistry::new();
        let result = reg.get_extension("nonexistent", &ts(1), "t");
        assert!(matches!(result, Err(RegistryError::NotFound(_))));
    }

    #[test]
    fn test_get_lineage() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        let lineage = reg.get_lineage("ext-1", &ts(2), "t").unwrap();
        assert_eq!(lineage.len(), 1);
        assert_eq!(lineage[0].version, "1.0.0");
    }

    #[test]
    fn test_add_version() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        let entry = VersionLineageEntry {
            version: "2.0.0".to_owned(),
            published_at: ts(2),
            changelog: "Major update".to_owned(),
            parent_version: Some("1.0.0".to_owned()),
        };
        reg.add_version("ext-1", entry, &ts(2), "t").unwrap();
        let lineage = reg.get_lineage("ext-1", &ts(3), "t").unwrap();
        assert_eq!(lineage.len(), 2);
        assert_eq!(lineage[1].version, "2.0.0");
    }

    #[test]
    fn test_add_version_to_revoked_fails() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        reg.revoke_extension("ext-1", "malicious", &ts(2), "t")
            .unwrap();
        let entry = VersionLineageEntry {
            version: "2.0.0".to_owned(),
            published_at: ts(3),
            changelog: "Should fail".to_owned(),
            parent_version: None,
        };
        let result = reg.add_version("ext-1", entry, &ts(3), "t");
        assert!(matches!(result, Err(RegistryError::Revoked(_))));
    }

    #[test]
    fn test_get_compatibility() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        let compat = reg.get_compatibility("ext-1", &ts(2), "t").unwrap();
        assert!(compat.is_empty());
    }

    #[test]
    fn test_add_compatibility() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        let entry = CompatibilityEntry {
            runtime: "node".to_owned(),
            runtime_version: "20.0.0".to_owned(),
            compatible: true,
            tested_at: ts(2),
        };
        reg.add_compatibility("ext-1", entry, &ts(2), "t").unwrap();
        let compat = reg.get_compatibility("ext-1", &ts(3), "t").unwrap();
        assert_eq!(compat.len(), 1);
        assert!(compat[0].compatible);
    }

    #[test]
    fn test_deprecate_extension() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        reg.deprecate_extension("ext-1", &ts(2), "t").unwrap();
        let record = reg.get_extension("ext-1", &ts(3), "t").unwrap();
        assert_eq!(record.metadata.status, ExtensionStatus::Deprecated);
    }

    #[test]
    fn test_revoke_extension() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        reg.revoke_extension("ext-1", "compromise", &ts(2), "t")
            .unwrap();
        let record = reg.get_extension("ext-1", &ts(3), "t").unwrap();
        assert_eq!(record.metadata.status, ExtensionStatus::Revoked);
    }

    #[test]
    fn test_list_extensions() {
        let mut reg = EcosystemRegistry::new();
        let m1 = make_metadata("ext-1", "pub-1", "key-1");
        let m2 = make_metadata("ext-2", "pub-2", "key-2");
        reg.register_extension(m1, &ts(1), "t").unwrap();
        reg.register_extension(m2, &ts(2), "t").unwrap();
        assert_eq!(reg.list_extensions().len(), 2);
    }

    #[test]
    fn test_audit_trail_created_on_registration() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        assert!(reg.audit_trail_len() >= 1);
        assert_eq!(reg.audit_trail()[0].event_code, ENE_001_REGISTRY_MUTATION);
    }

    #[test]
    fn test_audit_trail_integrity() {
        let mut reg = EcosystemRegistry::new();
        let m1 = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(m1, &ts(1), "t").unwrap();
        reg.deprecate_extension("ext-1", &ts(2), "t").unwrap();
        reg.verify_audit_integrity().unwrap();
    }

    #[test]
    fn test_events_emitted_on_register() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "trace-123").unwrap();
        let events = reg.take_events();
        assert!(!events.is_empty());
        assert_eq!(events[0].event_code, ENE_001_REGISTRY_MUTATION);
        assert_eq!(events[0].trace_id, "trace-123");
    }

    #[test]
    fn test_events_emitted_on_query() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        reg.take_events(); // drain registration events
        let _ = reg.get_extension("ext-1", &ts(2), "trace-q");
        let events = reg.take_events();
        assert!(
            events
                .iter()
                .any(|e| e.event_code == ENE_002_REGISTRY_QUERY)
        );
    }

    #[test]
    fn test_take_events_drains() {
        let mut reg = EcosystemRegistry::new();
        let meta = make_metadata("ext-1", "pub-1", "key-1");
        reg.register_extension(meta, &ts(1), "t").unwrap();
        let events1 = reg.take_events();
        assert!(!events1.is_empty());
        let events2 = reg.take_events();
        assert!(events2.is_empty());
    }

    #[test]
    fn test_extension_status_display() {
        assert_eq!(ExtensionStatus::Active.to_string(), "active");
        assert_eq!(ExtensionStatus::Deprecated.to_string(), "deprecated");
        assert_eq!(ExtensionStatus::Revoked.to_string(), "revoked");
    }

    #[test]
    fn test_default_registry() {
        let reg = EcosystemRegistry::default();
        assert_eq!(reg.extension_count(), 0);
        assert_eq!(reg.audit_trail_len(), 0);
    }

    #[test]
    fn test_deprecate_not_found() {
        let mut reg = EcosystemRegistry::new();
        let result = reg.deprecate_extension("nonexistent", &ts(1), "t");
        assert!(matches!(result, Err(RegistryError::NotFound(_))));
    }

    #[test]
    fn test_revoke_not_found() {
        let mut reg = EcosystemRegistry::new();
        let result = reg.revoke_extension("nonexistent", "reason", &ts(1), "t");
        assert!(matches!(result, Err(RegistryError::NotFound(_))));
    }

    #[test]
    fn test_event_code_constants() {
        assert_eq!(ENE_001_REGISTRY_MUTATION, "ENE-001");
        assert_eq!(ENE_002_REGISTRY_QUERY, "ENE-002");
        assert_eq!(ENE_009_API_AUTH_REJECT, "ENE-009");
        assert_eq!(ENE_010_API_RATE_LIMIT, "ENE-010");
        assert_eq!(ENE_011_SYBIL_REJECT, "ENE-011");
    }

    #[test]
    fn test_invariant_constants() {
        assert_eq!(INV_ENE_REGISTRY, "INV-ENE-REGISTRY");
        assert_eq!(INV_ENE_SYBIL, "INV-ENE-SYBIL");
    }

    #[test]
    fn test_error_code_constants() {
        assert_eq!(ERR_ENE_DUPLICATE_REG, "ERR-ENE-DUPLICATE-REG");
        assert_eq!(ERR_ENE_NOT_FOUND, "ERR-ENE-NOT-FOUND");
        assert_eq!(ERR_ENE_REVOKED, "ERR-ENE-REVOKED");
        assert_eq!(ERR_ENE_SYBIL, "ERR-ENE-SYBIL");
        assert_eq!(ERR_ENE_AUTH, "ERR-ENE-AUTH");
    }

    #[test]
    fn test_multiple_audit_entries_chain() {
        let mut reg = EcosystemRegistry::new();
        let m1 = make_metadata("ext-1", "pub-1", "key-1");
        let m2 = make_metadata("ext-2", "pub-2", "key-2");
        reg.register_extension(m1, &ts(1), "t").unwrap();
        reg.register_extension(m2, &ts(2), "t").unwrap();
        reg.deprecate_extension("ext-1", &ts(3), "t").unwrap();
        reg.revoke_extension("ext-2", "test", &ts(4), "t").unwrap();

        // All entries should chain correctly
        reg.verify_audit_integrity().unwrap();
        assert!(reg.audit_trail_len() >= 4);
    }
}
