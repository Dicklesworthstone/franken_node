//! bd-2kd9: Claim compiler and public trust scoreboard pipeline.
//!
//! External claims compile to executable evidence contracts. Unverifiable claim
//! text is blocked at compile time. Scoreboard updates publish signed evidence
//! links with SHA-256 digests for tamper detection.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Report schema version.
pub const SCHEMA_VERSION: &str = "claim-compiler-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const CLAIM_COMPILATION_START: &str = "CLAIM_COMPILATION_START";
    pub const CLAIM_CONTRACT_GENERATED: &str = "CLAIM_CONTRACT_GENERATED";
    pub const CLAIM_VERIFICATION_LINKED: &str = "CLAIM_VERIFICATION_LINKED";
    pub const SCOREBOARD_UPDATE_PUBLISHED: &str = "SCOREBOARD_UPDATE_PUBLISHED";
    pub const SCOREBOARD_EVIDENCE_SIGNED: &str = "SCOREBOARD_EVIDENCE_SIGNED";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_CLAIM_UNVERIFIABLE: &str = "ERR_CLAIM_UNVERIFIABLE";
    pub const ERR_CLAIM_SYNTAX_INVALID: &str = "ERR_CLAIM_SYNTAX_INVALID";
    pub const ERR_CLAIM_EVIDENCE_MISSING: &str = "ERR_CLAIM_EVIDENCE_MISSING";
    pub const ERR_CLAIM_BLOCKED: &str = "ERR_CLAIM_BLOCKED";
    pub const ERR_SCOREBOARD_SIGNATURE_INVALID: &str = "ERR_SCOREBOARD_SIGNATURE_INVALID";
    pub const ERR_SCOREBOARD_STALE_EVIDENCE: &str = "ERR_SCOREBOARD_STALE_EVIDENCE";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_CLAIM_EXECUTABLE_CONTRACT: &str = "INV-CLAIM-EXECUTABLE-CONTRACT";
    pub const INV_CLAIM_BLOCK_UNVERIFIABLE: &str = "INV-CLAIM-BLOCK-UNVERIFIABLE";
    pub const INV_SCOREBOARD_SIGNED_EVIDENCE: &str = "INV-SCOREBOARD-SIGNED-EVIDENCE";
    pub const INV_SCOREBOARD_FRESH_LINKS: &str = "INV-SCOREBOARD-FRESH-LINKS";
}

// ---------------------------------------------------------------------------
// Claim compilation
// ---------------------------------------------------------------------------

/// Reason why a claim failed compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimRejectionReason {
    SyntaxInvalid,
    EvidenceMissing,
    Unverifiable,
    Blocked,
}

impl ClaimRejectionReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SyntaxInvalid => error_codes::ERR_CLAIM_SYNTAX_INVALID,
            Self::EvidenceMissing => error_codes::ERR_CLAIM_EVIDENCE_MISSING,
            Self::Unverifiable => error_codes::ERR_CLAIM_UNVERIFIABLE,
            Self::Blocked => error_codes::ERR_CLAIM_BLOCKED,
        }
    }
}

/// An external claim submitted for compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalClaim {
    pub claim_id: String,
    pub claim_text: String,
    pub evidence_uris: Vec<String>,
    pub source_id: String,
}

/// A compiled evidence contract produced from a valid claim.
///
/// INV-CLAIM-EXECUTABLE-CONTRACT: every accepted claim yields a contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledContract {
    pub claim_id: String,
    pub claim_text: String,
    pub evidence_uris: Vec<String>,
    pub source_id: String,
    pub compiled_at_epoch_ms: u64,
    pub contract_digest: String,
    pub signer_id: String,
    pub signature: String,
}

/// Outcome of claim compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompilationResult {
    /// Claim compiled successfully into an executable evidence contract.
    Compiled {
        contract: CompiledContract,
        event_code: String,
    },
    /// Claim was rejected at compile time.
    Rejected {
        claim_id: String,
        reason: ClaimRejectionReason,
        error_code: String,
    },
}

/// Configuration for the claim compiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerConfig {
    pub signer_id: String,
    pub signing_key: String,
    pub now_epoch_ms: u64,
    /// Optional list of blocked source IDs.
    pub blocked_sources: Vec<String>,
}

impl CompilerConfig {
    pub fn new(
        signer_id: impl Into<String>,
        signing_key: impl Into<String>,
        now_epoch_ms: u64,
    ) -> Self {
        Self {
            signer_id: signer_id.into(),
            signing_key: signing_key.into(),
            now_epoch_ms,
            blocked_sources: Vec::new(),
        }
    }

    pub fn with_blocked_source(mut self, source_id: impl Into<String>) -> Self {
        self.blocked_sources.push(source_id.into());
        self
    }
}

/// The claim compiler: validates and compiles external claims.
///
/// INV-CLAIM-BLOCK-UNVERIFIABLE: unverifiable claims are rejected.
/// INV-CLAIM-EXECUTABLE-CONTRACT: accepted claims produce executable contracts.
pub struct ClaimCompiler {
    config: CompilerConfig,
}

impl ClaimCompiler {
    pub fn new(config: CompilerConfig) -> Self {
        Self { config }
    }

    /// Compile an external claim into an evidence contract.
    ///
    /// Returns `CompilationResult::Rejected` if the claim is unverifiable,
    /// has invalid syntax, missing evidence, or is from a blocked source.
    pub fn compile(&self, claim: &ExternalClaim) -> CompilationResult {
        // Check blocked source
        // INV-CLAIM-BLOCK-UNVERIFIABLE
        if self.config.blocked_sources.contains(&claim.source_id) {
            return CompilationResult::Rejected {
                claim_id: claim.claim_id.clone(),
                reason: ClaimRejectionReason::Blocked,
                error_code: error_codes::ERR_CLAIM_BLOCKED.to_string(),
            };
        }

        // Syntax validation: claim text must be non-empty
        if claim.claim_text.trim().is_empty() {
            return CompilationResult::Rejected {
                claim_id: claim.claim_id.clone(),
                reason: ClaimRejectionReason::SyntaxInvalid,
                error_code: error_codes::ERR_CLAIM_SYNTAX_INVALID.to_string(),
            };
        }

        // Evidence must be present
        if claim.evidence_uris.is_empty() {
            return CompilationResult::Rejected {
                claim_id: claim.claim_id.clone(),
                reason: ClaimRejectionReason::EvidenceMissing,
                error_code: error_codes::ERR_CLAIM_EVIDENCE_MISSING.to_string(),
            };
        }

        // Evidence URIs must be well-formed (non-empty, starts with scheme)
        for uri in &claim.evidence_uris {
            if !is_valid_evidence_uri(uri) {
                return CompilationResult::Rejected {
                    claim_id: claim.claim_id.clone(),
                    reason: ClaimRejectionReason::Unverifiable,
                    error_code: error_codes::ERR_CLAIM_UNVERIFIABLE.to_string(),
                };
            }
        }

        // Compile: produce executable evidence contract
        let contract_digest = compute_contract_digest(
            &claim.claim_id,
            &claim.claim_text,
            &claim.evidence_uris,
            &claim.source_id,
        );
        let signature = sign_contract(
            &contract_digest,
            &self.config.signer_id,
            &self.config.signing_key,
        );

        let contract = CompiledContract {
            claim_id: claim.claim_id.clone(),
            claim_text: claim.claim_text.clone(),
            evidence_uris: claim.evidence_uris.clone(),
            source_id: claim.source_id.clone(),
            compiled_at_epoch_ms: self.config.now_epoch_ms,
            contract_digest,
            signer_id: self.config.signer_id.clone(),
            signature,
        };

        // INV-CLAIM-EXECUTABLE-CONTRACT
        CompilationResult::Compiled {
            contract,
            event_code: event_codes::CLAIM_CONTRACT_GENERATED.to_string(),
        }
    }
}

fn is_valid_evidence_uri(uri: &str) -> bool {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Must have a scheme prefix
    trimmed.starts_with("https://")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("ipfs://")
        || trimmed.starts_with("file://")
        || trimmed.starts_with("urn:")
}

fn compute_contract_digest(
    claim_id: &str,
    claim_text: &str,
    evidence_uris: &[String],
    source_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"claim_compiler_hash_v1:");
    hasher.update(claim_id.as_bytes());
    hasher.update(b"|");
    hasher.update(claim_text.as_bytes());
    hasher.update(b"|");
    for uri in evidence_uris {
        hasher.update(uri.as_bytes());
        hasher.update(b",");
    }
    hasher.update(b"|");
    hasher.update(source_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn sign_contract(digest: &str, signer_id: &str, signing_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"claim_compiler_sign_v1:");
    hasher.update(digest.as_bytes());
    hasher.update(b"|");
    hasher.update(signer_id.as_bytes());
    hasher.update(b"|");
    hasher.update(signing_key.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Scoreboard pipeline
// ---------------------------------------------------------------------------

/// Reason for scoreboard rejection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreboardRejectionReason {
    SignatureInvalid,
    StaleEvidence,
}

impl ScoreboardRejectionReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SignatureInvalid => error_codes::ERR_SCOREBOARD_SIGNATURE_INVALID,
            Self::StaleEvidence => error_codes::ERR_SCOREBOARD_STALE_EVIDENCE,
        }
    }
}

/// A single entry on the public trust scoreboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreboardEntry {
    pub entry_id: String,
    pub claim_id: String,
    pub trust_score: u64,
    pub evidence_link: String,
    pub signed_digest: String,
    pub published_at_epoch_ms: u64,
}

/// A scoreboard snapshot is an atomic collection of entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardSnapshot {
    pub schema_version: String,
    pub snapshot_id: String,
    pub entries: BTreeMap<String, ScoreboardEntry>,
    pub snapshot_digest: String,
    pub published_at_epoch_ms: u64,
}

/// Outcome of a scoreboard update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreboardUpdateResult {
    Published {
        snapshot_id: String,
        entry_count: usize,
        event_code: String,
    },
    Rejected {
        reason: ScoreboardRejectionReason,
        error_code: String,
    },
}

/// Configuration for the scoreboard pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardConfig {
    pub signer_id: String,
    pub signing_key: String,
    pub now_epoch_ms: u64,
    /// Maximum age (in ms) for evidence links before they are considered stale.
    pub max_evidence_age_ms: u64,
}

impl ScoreboardConfig {
    pub fn new(
        signer_id: impl Into<String>,
        signing_key: impl Into<String>,
        now_epoch_ms: u64,
        max_evidence_age_ms: u64,
    ) -> Self {
        Self {
            signer_id: signer_id.into(),
            signing_key: signing_key.into(),
            now_epoch_ms,
            max_evidence_age_ms,
        }
    }
}

/// The scoreboard pipeline: publishes signed evidence snapshots.
///
/// INV-SCOREBOARD-SIGNED-EVIDENCE: every snapshot has a signed digest.
/// INV-SCOREBOARD-FRESH-LINKS: stale evidence is rejected.
pub struct ScoreboardPipeline {
    config: ScoreboardConfig,
}

impl ScoreboardPipeline {
    pub fn new(config: ScoreboardConfig) -> Self {
        Self { config }
    }

    /// Publish a scoreboard snapshot from a list of compiled contracts.
    ///
    /// Returns `ScoreboardUpdateResult::Published` if all entries pass
    /// freshness and signature checks. Returns `Rejected` otherwise.
    pub fn publish(
        &self,
        snapshot_id: &str,
        contracts: &[CompiledContract],
    ) -> ScoreboardUpdateResult {
        // INV-SCOREBOARD-FRESH-LINKS: reject stale evidence
        for contract in contracts {
            if self
                .config
                .now_epoch_ms
                .saturating_sub(contract.compiled_at_epoch_ms)
                > self.config.max_evidence_age_ms
            {
                return ScoreboardUpdateResult::Rejected {
                    reason: ScoreboardRejectionReason::StaleEvidence,
                    error_code: error_codes::ERR_SCOREBOARD_STALE_EVIDENCE.to_string(),
                };
            }
        }

        // Validate all contract signatures
        for contract in contracts {
            let expected_sig = sign_contract(
                &contract.contract_digest,
                &contract.signer_id,
                &self.config.signing_key,
            );
            if contract.signature != expected_sig {
                return ScoreboardUpdateResult::Rejected {
                    reason: ScoreboardRejectionReason::SignatureInvalid,
                    error_code: error_codes::ERR_SCOREBOARD_SIGNATURE_INVALID.to_string(),
                };
            }
        }

        // Build entries atomically
        let mut entries = BTreeMap::new();
        for (i, contract) in contracts.iter().enumerate() {
            let entry_id = format!("{}-entry-{}", snapshot_id, i);
            let evidence_link = contract.evidence_uris.first().cloned().unwrap_or_default();
            let signed_digest = compute_entry_digest(
                &entry_id,
                &contract.claim_id,
                &evidence_link,
                &self.config.signer_id,
                &self.config.signing_key,
            );
            let entry = ScoreboardEntry {
                entry_id: entry_id.clone(),
                claim_id: contract.claim_id.clone(),
                trust_score: 100, // base trust score for valid contracts
                evidence_link,
                signed_digest,
                published_at_epoch_ms: self.config.now_epoch_ms,
            };
            entries.insert(entry_id, entry);
        }

        // INV-SCOREBOARD-SIGNED-EVIDENCE
        ScoreboardUpdateResult::Published {
            snapshot_id: snapshot_id.to_string(),
            entry_count: entries.len(),
            event_code: event_codes::SCOREBOARD_UPDATE_PUBLISHED.to_string(),
        }
    }

    /// Build a full scoreboard snapshot from compiled contracts.
    pub fn build_snapshot(
        &self,
        snapshot_id: &str,
        contracts: &[CompiledContract],
    ) -> Option<ScoreboardSnapshot> {
        // Check freshness first
        for contract in contracts {
            if self
                .config
                .now_epoch_ms
                .saturating_sub(contract.compiled_at_epoch_ms)
                > self.config.max_evidence_age_ms
            {
                return None;
            }
        }

        let mut entries = BTreeMap::new();
        for (i, contract) in contracts.iter().enumerate() {
            let entry_id = format!("{}-entry-{}", snapshot_id, i);
            let evidence_link = contract.evidence_uris.first().cloned().unwrap_or_default();
            let signed_digest = compute_entry_digest(
                &entry_id,
                &contract.claim_id,
                &evidence_link,
                &self.config.signer_id,
                &self.config.signing_key,
            );
            let entry = ScoreboardEntry {
                entry_id: entry_id.clone(),
                claim_id: contract.claim_id.clone(),
                trust_score: 100,
                evidence_link,
                signed_digest,
                published_at_epoch_ms: self.config.now_epoch_ms,
            };
            entries.insert(entry_id, entry);
        }

        let snapshot_digest = compute_snapshot_digest(snapshot_id, &entries);

        Some(ScoreboardSnapshot {
            schema_version: SCHEMA_VERSION.to_string(),
            snapshot_id: snapshot_id.to_string(),
            entries,
            snapshot_digest,
            published_at_epoch_ms: self.config.now_epoch_ms,
        })
    }
}

fn compute_entry_digest(
    entry_id: &str,
    claim_id: &str,
    evidence_link: &str,
    signer_id: &str,
    signing_key: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"claim_compiler_entry_v1:");
    hasher.update(entry_id.as_bytes());
    hasher.update(b"|");
    hasher.update(claim_id.as_bytes());
    hasher.update(b"|");
    hasher.update(evidence_link.as_bytes());
    hasher.update(b"|");
    hasher.update(signer_id.as_bytes());
    hasher.update(b"|");
    hasher.update(signing_key.as_bytes());
    hex::encode(hasher.finalize())
}

fn compute_snapshot_digest(
    snapshot_id: &str,
    entries: &BTreeMap<String, ScoreboardEntry>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"claim_compiler_snapshot_v1:");
    hasher.update(snapshot_id.as_bytes());
    for (key, entry) in entries {
        hasher.update(b"|");
        hasher.update(key.as_bytes());
        hasher.update(b":");
        hasher.update(entry.signed_digest.as_bytes());
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Helper: make a valid claim for testing
// ---------------------------------------------------------------------------

/// Build a well-formed `ExternalClaim` for testing.
pub fn make_test_claim(claim_id: &str, source_id: &str) -> ExternalClaim {
    ExternalClaim {
        claim_id: claim_id.to_string(),
        claim_text: format!("Test claim: {claim_id}"),
        evidence_uris: vec![format!("https://evidence.example.com/{claim_id}")],
        source_id: source_id.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn compiler(now_epoch_ms: u64) -> ClaimCompiler {
        let cfg = CompilerConfig::new("signer-A", "key-secret", now_epoch_ms);
        ClaimCompiler::new(cfg)
    }

    fn scoreboard(now_epoch_ms: u64) -> ScoreboardPipeline {
        let cfg = ScoreboardConfig::new("signer-A", "key-secret", now_epoch_ms, 60_000);
        ScoreboardPipeline::new(cfg)
    }

    // --- Claim compiler tests ---

    #[test]
    fn compile_valid_claim_produces_contract() {
        let cc = compiler(10_000);
        let claim = make_test_claim("c1", "src-1");
        let result = cc.compile(&claim);
        match result {
            CompilationResult::Compiled {
                contract,
                event_code,
            } => {
                assert_eq!(contract.claim_id, "c1");
                assert_eq!(event_code, event_codes::CLAIM_CONTRACT_GENERATED);
                assert!(!contract.contract_digest.is_empty());
                assert!(!contract.signature.is_empty());
            }
            CompilationResult::Rejected { .. } => panic!("expected compiled"),
        }
    }

    #[test]
    fn compile_rejects_empty_claim_text() {
        // INV-CLAIM-BLOCK-UNVERIFIABLE
        let cc = compiler(10_000);
        let claim = ExternalClaim {
            claim_id: "c2".to_string(),
            claim_text: "   ".to_string(),
            evidence_uris: vec!["https://e.com/c2".to_string()],
            source_id: "src-1".to_string(),
        };
        let result = cc.compile(&claim);
        assert!(matches!(
            result,
            CompilationResult::Rejected {
                reason: ClaimRejectionReason::SyntaxInvalid,
                ..
            }
        ));
    }

    #[test]
    fn compile_rejects_missing_evidence() {
        let cc = compiler(10_000);
        let claim = ExternalClaim {
            claim_id: "c3".to_string(),
            claim_text: "Valid text".to_string(),
            evidence_uris: vec![],
            source_id: "src-1".to_string(),
        };
        let result = cc.compile(&claim);
        assert!(matches!(
            result,
            CompilationResult::Rejected {
                reason: ClaimRejectionReason::EvidenceMissing,
                ..
            }
        ));
    }

    #[test]
    fn compile_rejects_invalid_evidence_uri() {
        let cc = compiler(10_000);
        let claim = ExternalClaim {
            claim_id: "c4".to_string(),
            claim_text: "Valid text".to_string(),
            evidence_uris: vec!["not-a-uri".to_string()],
            source_id: "src-1".to_string(),
        };
        let result = cc.compile(&claim);
        assert!(matches!(
            result,
            CompilationResult::Rejected {
                reason: ClaimRejectionReason::Unverifiable,
                ..
            }
        ));
    }

    #[test]
    fn compile_rejects_blocked_source() {
        let cfg = CompilerConfig::new("signer-A", "key-secret", 10_000)
            .with_blocked_source("blocked-src");
        let cc = ClaimCompiler::new(cfg);
        let claim = make_test_claim("c5", "blocked-src");
        let result = cc.compile(&claim);
        assert!(matches!(
            result,
            CompilationResult::Rejected {
                reason: ClaimRejectionReason::Blocked,
                ..
            }
        ));
    }

    #[test]
    fn contract_digest_is_deterministic() {
        let cc = compiler(10_000);
        let claim = make_test_claim("c6", "src-1");
        let r1 = cc.compile(&claim);
        let r2 = cc.compile(&claim);
        match (r1, r2) {
            (
                CompilationResult::Compiled { contract: c1, .. },
                CompilationResult::Compiled { contract: c2, .. },
            ) => {
                assert_eq!(c1.contract_digest, c2.contract_digest);
                assert_eq!(c1.signature, c2.signature);
            }
            _ => panic!("expected both compiled"),
        }
    }

    #[test]
    fn different_claims_produce_different_digests() {
        let cc = compiler(10_000);
        let c1 = make_test_claim("c7a", "src-1");
        let c2 = make_test_claim("c7b", "src-1");
        let r1 = cc.compile(&c1);
        let r2 = cc.compile(&c2);
        match (r1, r2) {
            (
                CompilationResult::Compiled { contract: ct1, .. },
                CompilationResult::Compiled { contract: ct2, .. },
            ) => {
                assert_ne!(ct1.contract_digest, ct2.contract_digest);
            }
            _ => panic!("expected both compiled"),
        }
    }

    #[test]
    fn compile_supports_multiple_evidence_uris() {
        let cc = compiler(10_000);
        let claim = ExternalClaim {
            claim_id: "c8".to_string(),
            claim_text: "Multi-evidence claim".to_string(),
            evidence_uris: vec![
                "https://evidence.example.com/a".to_string(),
                "ipfs://QmTestHash".to_string(),
            ],
            source_id: "src-1".to_string(),
        };
        let result = cc.compile(&claim);
        assert!(matches!(result, CompilationResult::Compiled { .. }));
    }

    // --- Scoreboard tests ---

    #[test]
    fn scoreboard_publishes_valid_snapshot() {
        let cc = compiler(10_000);
        let sb = scoreboard(10_000);
        let claim = make_test_claim("sc1", "src-1");
        let contract = match cc.compile(&claim) {
            CompilationResult::Compiled { contract, .. } => contract,
            _ => panic!("expected compiled"),
        };
        let result = sb.publish("snap-1", &[contract]);
        assert!(matches!(
            result,
            ScoreboardUpdateResult::Published { entry_count: 1, .. }
        ));
    }

    #[test]
    fn scoreboard_rejects_stale_evidence() {
        // INV-SCOREBOARD-FRESH-LINKS
        let cc = compiler(10_000);
        let sb = scoreboard(100_000); // now is 100k, contract compiled at 10k -> 90k > 60k threshold
        let claim = make_test_claim("sc2", "src-1");
        let contract = match cc.compile(&claim) {
            CompilationResult::Compiled { contract, .. } => contract,
            _ => panic!("expected compiled"),
        };
        let result = sb.publish("snap-2", &[contract]);
        assert!(matches!(
            result,
            ScoreboardUpdateResult::Rejected {
                reason: ScoreboardRejectionReason::StaleEvidence,
                ..
            }
        ));
    }

    #[test]
    fn scoreboard_rejects_tampered_signature() {
        // INV-SCOREBOARD-SIGNED-EVIDENCE
        let cc = compiler(10_000);
        let sb = scoreboard(10_000);
        let claim = make_test_claim("sc3", "src-1");
        let mut contract = match cc.compile(&claim) {
            CompilationResult::Compiled { contract, .. } => contract,
            _ => panic!("expected compiled"),
        };
        contract.signature = "tampered-sig".to_string();
        let result = sb.publish("snap-3", &[contract]);
        assert!(matches!(
            result,
            ScoreboardUpdateResult::Rejected {
                reason: ScoreboardRejectionReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn scoreboard_build_snapshot_produces_btree_ordered_entries() {
        let cc = compiler(10_000);
        let sb = scoreboard(10_000);
        let claims: Vec<_> = (0..5)
            .map(|i| make_test_claim(&format!("ordered-{i}"), "src-1"))
            .collect();
        let contracts: Vec<_> = claims
            .iter()
            .filter_map(|c| match cc.compile(c) {
                CompilationResult::Compiled { contract, .. } => Some(contract),
                _ => None,
            })
            .collect();
        let snapshot = sb
            .build_snapshot("snap-ordered", &contracts)
            .expect("snapshot");
        let keys: Vec<_> = snapshot.entries.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap ordering must be deterministic");
    }

    #[test]
    fn scoreboard_snapshot_digest_is_deterministic() {
        let cc = compiler(10_000);
        let sb = scoreboard(10_000);
        let claim = make_test_claim("det-1", "src-1");
        let contract = match cc.compile(&claim) {
            CompilationResult::Compiled { contract, .. } => contract,
            _ => panic!("expected compiled"),
        };
        let s1 = sb
            .build_snapshot("snap-det", std::slice::from_ref(&contract))
            .expect("s1");
        let s2 = sb.build_snapshot("snap-det", &[contract]).expect("s2");
        assert_eq!(s1.snapshot_digest, s2.snapshot_digest);
    }

    #[test]
    fn scoreboard_build_snapshot_returns_none_for_stale() {
        let cc = compiler(10_000);
        let sb = scoreboard(100_000);
        let claim = make_test_claim("stale-1", "src-1");
        let contract = match cc.compile(&claim) {
            CompilationResult::Compiled { contract, .. } => contract,
            _ => panic!("expected compiled"),
        };
        assert!(sb.build_snapshot("snap-stale", &[contract]).is_none());
    }

    #[test]
    fn empty_contracts_list_publishes_empty_snapshot() {
        let sb = scoreboard(10_000);
        let result = sb.publish("snap-empty", &[]);
        assert!(matches!(
            result,
            ScoreboardUpdateResult::Published { entry_count: 0, .. }
        ));
    }

    // --- Error code coverage ---

    #[test]
    fn rejection_reason_codes_are_correct() {
        assert_eq!(
            ClaimRejectionReason::SyntaxInvalid.code(),
            error_codes::ERR_CLAIM_SYNTAX_INVALID
        );
        assert_eq!(
            ClaimRejectionReason::EvidenceMissing.code(),
            error_codes::ERR_CLAIM_EVIDENCE_MISSING
        );
        assert_eq!(
            ClaimRejectionReason::Unverifiable.code(),
            error_codes::ERR_CLAIM_UNVERIFIABLE
        );
        assert_eq!(
            ClaimRejectionReason::Blocked.code(),
            error_codes::ERR_CLAIM_BLOCKED
        );
    }

    #[test]
    fn scoreboard_rejection_codes_are_correct() {
        assert_eq!(
            ScoreboardRejectionReason::SignatureInvalid.code(),
            error_codes::ERR_SCOREBOARD_SIGNATURE_INVALID
        );
        assert_eq!(
            ScoreboardRejectionReason::StaleEvidence.code(),
            error_codes::ERR_SCOREBOARD_STALE_EVIDENCE
        );
    }

    // --- URI validation ---

    #[test]
    fn valid_evidence_uri_schemes() {
        assert!(is_valid_evidence_uri("https://example.com/evidence"));
        assert!(is_valid_evidence_uri("http://example.com/evidence"));
        assert!(is_valid_evidence_uri("ipfs://QmHash"));
        assert!(is_valid_evidence_uri("file:///path/to/file"));
        assert!(is_valid_evidence_uri("urn:evidence:12345"));
    }

    #[test]
    fn invalid_evidence_uri_schemes() {
        assert!(!is_valid_evidence_uri(""));
        assert!(!is_valid_evidence_uri("   "));
        assert!(!is_valid_evidence_uri("not-a-uri"));
        assert!(!is_valid_evidence_uri("ftp://server/file"));
    }

    // --- Schema version ---

    #[test]
    fn schema_version_is_set() {
        assert_eq!(SCHEMA_VERSION, "claim-compiler-v1.0");
    }

    // --- Invariant constants ---

    #[test]
    fn invariant_constants_match_spec() {
        assert_eq!(
            invariants::INV_CLAIM_EXECUTABLE_CONTRACT,
            "INV-CLAIM-EXECUTABLE-CONTRACT"
        );
        assert_eq!(
            invariants::INV_CLAIM_BLOCK_UNVERIFIABLE,
            "INV-CLAIM-BLOCK-UNVERIFIABLE"
        );
        assert_eq!(
            invariants::INV_SCOREBOARD_SIGNED_EVIDENCE,
            "INV-SCOREBOARD-SIGNED-EVIDENCE"
        );
        assert_eq!(
            invariants::INV_SCOREBOARD_FRESH_LINKS,
            "INV-SCOREBOARD-FRESH-LINKS"
        );
    }

    // --- Event code constants ---

    #[test]
    fn event_code_constants_match_spec() {
        assert_eq!(
            event_codes::CLAIM_COMPILATION_START,
            "CLAIM_COMPILATION_START"
        );
        assert_eq!(
            event_codes::CLAIM_CONTRACT_GENERATED,
            "CLAIM_CONTRACT_GENERATED"
        );
        assert_eq!(
            event_codes::CLAIM_VERIFICATION_LINKED,
            "CLAIM_VERIFICATION_LINKED"
        );
        assert_eq!(
            event_codes::SCOREBOARD_UPDATE_PUBLISHED,
            "SCOREBOARD_UPDATE_PUBLISHED"
        );
        assert_eq!(
            event_codes::SCOREBOARD_EVIDENCE_SIGNED,
            "SCOREBOARD_EVIDENCE_SIGNED"
        );
    }
}
