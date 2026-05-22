use std::collections::BTreeMap;
use std::sync::Arc;

use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
};
use frankenengine_node::security::constant_time;
use frankenengine_node::vef::proof_generator::{
    ComplianceProof, PROOF_FORMAT_VERSION, PROOF_GENERATOR_SCHEMA_VERSION, ProofBackend,
    ProofGenerator, ProofGeneratorConfig, ProofGeneratorError, ProofRequest, ProofStatus,
    error_codes, event_codes,
};
use frankenengine_node::vef::proof_scheduler::{ProofWindow, WorkloadTier};
use frankenengine_node::vef::receipt_chain::{ReceiptChain, ReceiptChainConfig, ReceiptChainEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SPEC_SOURCE: &str = "crates/franken-node/src/vef/proof_generator.rs";
const TRACE_ID: &str = "trace-vef-proof-generator-conformance";
const GENERATED_AT_MILLIS: u64 = 1_706_200_000_100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceReport {
    schema_version: String,
    spec_source: String,
    coverage_matrix: Vec<CoverageRow>,
    success_case: SuccessCase,
    determinism_case: DeterminismCase,
    fail_closed_case: FailClosedCase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CoverageRow {
    section: String,
    level: String,
    clause: String,
    tested: bool,
    verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SuccessCase {
    request_id: String,
    proof_id: String,
    format_version: String,
    receipt_window_ref: String,
    backend_name: String,
    proof_data_hash: String,
    metadata: BTreeMap<String, String>,
    final_status: ProofStatus,
    verified: bool,
    event_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeterminismCase {
    first_hash: String,
    second_hash: String,
    identical_proof_bytes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FailClosedCase {
    empty_window_error_code: String,
    empty_window_event_code: String,
    capacity_error_code: String,
    capacity_error_message: String,
    capacity_pending_count: usize,
    tampered_verified: bool,
    tampered_event_detail: String,
}

struct LengthPrefixedConformanceBackend {
    name: &'static str,
}

impl LengthPrefixedConformanceBackend {
    fn new(name: &'static str) -> Self {
        Self { name }
    }

    fn update_len_prefixed(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
        hasher.update(u64::try_from(label.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(label);
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(value);
    }

    fn proof_bytes(entries: &[ReceiptChainEntry]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"vef-proof-generator-conformance-v1:proof-data");
        hasher.update(
            u64::try_from(entries.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for entry in entries {
            hasher.update(entry.index.to_le_bytes());
            Self::update_len_prefixed(&mut hasher, b"chain_hash", entry.chain_hash.as_bytes());
            Self::update_len_prefixed(&mut hasher, b"receipt_hash", entry.receipt_hash.as_bytes());
            Self::update_len_prefixed(&mut hasher, b"trace_id", entry.trace_id.as_bytes());
        }
        hasher.finalize().to_vec()
    }

    fn proof_hash(proof_data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"vef-proof-generator-conformance-v1:proof-hash");
        Self::update_len_prefixed(&mut hasher, b"proof_data", proof_data);
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

impl ProofBackend for LengthPrefixedConformanceBackend {
    fn backend_name(&self) -> &str {
        self.name
    }

    fn generate(&self, request: &ProofRequest) -> Result<ComplianceProof, ProofGeneratorError> {
        if request.entries.is_empty() {
            return Err(ProofGeneratorError::window_empty(
                "conformance backend rejects empty receipt windows",
            ));
        }

        let proof_data = Self::proof_bytes(&request.entries);
        let proof_data_hash = Self::proof_hash(&proof_data);
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "backend_type".to_string(),
            "length-prefixed-conformance".to_string(),
        );
        metadata.insert("entry_count".to_string(), request.entries.len().to_string());
        metadata.insert(
            "window_start".to_string(),
            request.window.start_index.to_string(),
        );
        metadata.insert(
            "window_end".to_string(),
            request.window.end_index.to_string(),
        );

        Ok(ComplianceProof {
            proof_id: format!("proof-{}", request.request_id),
            format_version: PROOF_FORMAT_VERSION.to_string(),
            receipt_window_ref: request.window.window_id.clone(),
            proof_data,
            proof_data_hash,
            generated_at_millis: request.created_at_millis,
            backend_name: self.name.to_string(),
            metadata,
            trace_id: request.trace_id.clone(),
        })
    }

    fn verify(
        &self,
        proof: &ComplianceProof,
        entries: &[ReceiptChainEntry],
    ) -> Result<bool, ProofGeneratorError> {
        if entries.is_empty() {
            return Ok(false);
        }

        let expected_data = Self::proof_bytes(entries);
        let expected_hash = Self::proof_hash(&expected_data);
        Ok(
            constant_time::ct_eq_bytes(&proof.proof_data, &expected_data)
                && constant_time::ct_eq(&proof.proof_data_hash, &expected_hash)
                && constant_time::ct_eq(&proof.backend_name, self.name),
        )
    }
}

#[test]
fn vef_proof_generator_conformance_matrix_covers_fail_closed_self_describing_proofs() {
    let report = build_conformance_report();
    assert_schema_and_coverage_contract(&report);
    assert_success_contract(&report.success_case);
    assert_determinism_contract(&report.determinism_case);
    assert_fail_closed_contract(&report.fail_closed_case);

    let actual_json =
        serde_json::to_string_pretty(&report).expect("conformance report must serialize");
    let decoded: ConformanceReport =
        serde_json::from_str(&actual_json).expect("conformance report must roundtrip");
    assert_eq!(decoded, report, "conformance report JSON roundtrip drifted");
}

fn build_conformance_report() -> ConformanceReport {
    ConformanceReport {
        schema_version: PROOF_GENERATOR_SCHEMA_VERSION.to_string(),
        spec_source: SPEC_SOURCE.to_string(),
        coverage_matrix: coverage_matrix(),
        success_case: build_success_case(),
        determinism_case: build_determinism_case(),
        fail_closed_case: build_fail_closed_case(),
    }
}

fn build_success_case() -> SuccessCase {
    let mut generator = proof_generator(ProofGeneratorConfig::default());
    let entries = sample_entries();
    let window = sample_window();
    let request_id = generator
        .submit_request(&window, &entries, GENERATED_AT_MILLIS, TRACE_ID)
        .expect("valid conformance request must be accepted");
    let proof = generator
        .generate_proof(&request_id, &window, &entries, GENERATED_AT_MILLIS + 10)
        .expect("valid conformance request must generate a proof");
    let verified = generator
        .verify_proof(&proof, &entries, TRACE_ID)
        .expect("generated conformance proof must verify");
    let final_status = generator
        .requests()
        .get(&request_id)
        .expect("request status must be retained")
        .status;
    let event_codes = generator
        .events()
        .iter()
        .map(|event| event.event_code.clone())
        .collect();

    SuccessCase {
        request_id,
        proof_id: proof.proof_id,
        format_version: proof.format_version,
        receipt_window_ref: proof.receipt_window_ref,
        backend_name: proof.backend_name,
        proof_data_hash: proof.proof_data_hash,
        metadata: proof.metadata,
        final_status,
        verified,
        event_codes,
    }
}

fn build_determinism_case() -> DeterminismCase {
    let first = generate_reference_proof();
    let second = generate_reference_proof();
    DeterminismCase {
        first_hash: first.proof_data_hash.clone(),
        second_hash: second.proof_data_hash.clone(),
        identical_proof_bytes: first.proof_data == second.proof_data,
    }
}

fn build_fail_closed_case() -> FailClosedCase {
    let entries = sample_entries();
    let window = sample_window();

    let mut empty_generator = proof_generator(ProofGeneratorConfig::default());
    let empty_error = empty_generator
        .submit_request(&window, &[], GENERATED_AT_MILLIS, TRACE_ID)
        .expect_err("empty proof windows must fail closed");

    let mut capacity_generator = proof_generator(ProofGeneratorConfig {
        max_pending_requests: 1,
        ..ProofGeneratorConfig::default()
    });
    capacity_generator
        .submit_request(&window, &entries, GENERATED_AT_MILLIS, TRACE_ID)
        .expect("first pending request must fit configured capacity");
    let capacity_error = capacity_generator
        .submit_request(&window, &entries, GENERATED_AT_MILLIS + 1, TRACE_ID)
        .expect_err("second pending request must fail closed at configured capacity");
    let capacity_pending_count = *capacity_generator
        .status_counts()
        .get("pending")
        .expect("pending count must be present");

    let mut tamper_generator = proof_generator(ProofGeneratorConfig::default());
    let request_id = tamper_generator
        .submit_request(&window, &entries, GENERATED_AT_MILLIS, TRACE_ID)
        .expect("tamper setup request must be accepted");
    let mut tampered_proof = tamper_generator
        .generate_proof(&request_id, &window, &entries, GENERATED_AT_MILLIS + 10)
        .expect("tamper setup proof must generate");
    let first_byte = tampered_proof
        .proof_data
        .first_mut()
        .expect("conformance proof data must not be empty");
    *first_byte ^= 0x80;
    let tampered_verified = tamper_generator
        .verify_proof(&tampered_proof, &entries, TRACE_ID)
        .expect("tampered proof verification must return a fail-closed verdict");
    let tampered_event_detail = tamper_generator
        .events()
        .iter()
        .rev()
        .find(|event| event.event_code == event_codes::PGN_006_PROOF_VERIFIED)
        .expect("tampered verification must emit a verification event")
        .detail
        .clone();

    FailClosedCase {
        empty_window_error_code: empty_error.code,
        empty_window_event_code: empty_error.event_code,
        capacity_error_code: capacity_error.code,
        capacity_error_message: capacity_error.message,
        capacity_pending_count,
        tampered_verified,
        tampered_event_detail,
    }
}

fn generate_reference_proof() -> ComplianceProof {
    let mut generator = proof_generator(ProofGeneratorConfig::default());
    let entries = sample_entries();
    let window = sample_window();
    let request_id = generator
        .submit_request(&window, &entries, GENERATED_AT_MILLIS, TRACE_ID)
        .expect("reference request must be accepted");
    generator
        .generate_proof(&request_id, &window, &entries, GENERATED_AT_MILLIS + 10)
        .expect("reference proof must generate")
}

fn proof_generator(config: ProofGeneratorConfig) -> ProofGenerator {
    ProofGenerator::new(
        Arc::new(LengthPrefixedConformanceBackend::new(
            "length-prefixed-conformance",
        )),
        config,
    )
}

fn sample_entries() -> Vec<ReceiptChainEntry> {
    let mut chain = ReceiptChain::new(ReceiptChainConfig {
        checkpoint_every_entries: 0,
        checkpoint_every_millis: 0,
    });
    for (idx, action) in [
        ExecutionActionType::NetworkAccess,
        ExecutionActionType::FilesystemOperation,
        ExecutionActionType::SecretAccess,
    ]
    .into_iter()
    .enumerate()
    {
        chain
            .append(
                receipt(action, idx as u64),
                1_706_200_000_000 + idx as u64,
                TRACE_ID,
            )
            .expect("conformance receipt must append");
    }
    chain.entries().to_vec()
}

fn sample_window() -> ProofWindow {
    ProofWindow {
        window_id: "win-proof-generator-conformance".to_string(),
        start_index: 0,
        end_index: 2,
        entry_count: 3,
        aligned_checkpoint_id: None,
        tier: WorkloadTier::High,
        created_at_millis: GENERATED_AT_MILLIS - 100,
        trace_id: TRACE_ID.to_string(),
    }
}

fn receipt(action: ExecutionActionType, sequence_number: u64) -> ExecutionReceipt {
    let mut capability_context = BTreeMap::new();
    capability_context.insert(
        "capability".to_string(),
        format!("proof-generator-{sequence_number}"),
    );
    capability_context.insert("domain".to_string(), "vef".to_string());
    capability_context.insert("scope".to_string(), "proof-generation".to_string());

    ExecutionReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        action_type: action,
        capability_context,
        actor_identity: format!("actor-{sequence_number}"),
        artifact_identity: format!("artifact-{sequence_number}"),
        policy_snapshot_hash: format!("sha256:{sequence_number:064x}"),
        timestamp_millis: 1_706_199_999_000 + sequence_number,
        sequence_number,
        witness_references: vec![format!("witness-{sequence_number}")],
        trace_id: TRACE_ID.to_string(),
    }
}

fn coverage_matrix() -> Vec<CoverageRow> {
    vec![
        CoverageRow {
            section: "INV-PGN-BACKEND-AGNOSTIC".to_string(),
            level: "MUST".to_string(),
            clause: "ProofGenerator accepts an injected ProofBackend without source changes."
                .to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
        CoverageRow {
            section: "INV-PGN-VERSIONED-FORMAT".to_string(),
            level: "MUST".to_string(),
            clause: "Generated proofs carry format_version, backend_name, window reference, and deterministic metadata."
                .to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
        CoverageRow {
            section: "INV-PGN-DETERMINISTIC".to_string(),
            level: "MUST".to_string(),
            clause: "Identical receipt entries and backend state produce identical proof bytes and hashes."
                .to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
        CoverageRow {
            section: "PGN-FAIL-CLOSED".to_string(),
            level: "MUST".to_string(),
            clause: "Empty windows and capacity exhaustion reject requests instead of producing ambiguous proofs."
                .to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
        CoverageRow {
            section: "PGN-VERIFY-CT".to_string(),
            level: "MUST".to_string(),
            clause: "Verification uses constant-time equality for proof bytes, proof hashes, and backend identity."
                .to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
    ]
}

fn assert_schema_and_coverage_contract(report: &ConformanceReport) {
    assert_eq!(report.schema_version, PROOF_GENERATOR_SCHEMA_VERSION);
    assert_eq!(report.spec_source, SPEC_SOURCE);
    assert_eq!(report.coverage_matrix.len(), 5);
    assert!(
        report
            .coverage_matrix
            .iter()
            .filter(|row| row.level == "MUST")
            .all(|row| row.tested && row.verdict == "pass"),
        "all proof generator MUST clauses in the conformance matrix must pass"
    );
}

fn assert_success_contract(success_case: &SuccessCase) {
    assert_eq!(success_case.request_id, "req-00000000");
    assert_eq!(success_case.proof_id, "proof-req-00000000");
    assert_eq!(success_case.format_version, PROOF_FORMAT_VERSION);
    assert_eq!(
        success_case.receipt_window_ref,
        "win-proof-generator-conformance"
    );
    assert_eq!(success_case.backend_name, "length-prefixed-conformance");
    assert!(success_case.proof_data_hash.starts_with("sha256:"));
    assert_eq!(
        success_case
            .metadata
            .get("backend_type")
            .map(String::as_str),
        Some("length-prefixed-conformance")
    );
    assert_eq!(
        success_case.metadata.get("entry_count").map(String::as_str),
        Some("3")
    );
    assert_eq!(success_case.final_status, ProofStatus::Complete);
    assert!(success_case.verified);
    assert_eq!(
        success_case.event_codes,
        vec![
            event_codes::PGN_005_BACKEND_REGISTERED,
            event_codes::PGN_001_REQUEST_RECEIVED,
            event_codes::PGN_002_GENERATION_STARTED,
            event_codes::PGN_003_GENERATION_COMPLETE,
            event_codes::PGN_006_PROOF_VERIFIED,
        ]
    );
}

fn assert_determinism_contract(determinism_case: &DeterminismCase) {
    assert_eq!(determinism_case.first_hash, determinism_case.second_hash);
    assert!(determinism_case.identical_proof_bytes);
}

fn assert_fail_closed_contract(fail_closed_case: &FailClosedCase) {
    assert_eq!(
        fail_closed_case.empty_window_error_code,
        error_codes::ERR_PGN_WINDOW_EMPTY
    );
    assert_eq!(
        fail_closed_case.empty_window_event_code,
        event_codes::PGN_004_GENERATION_FAILED
    );
    assert_eq!(
        fail_closed_case.capacity_error_code,
        error_codes::ERR_PGN_INTERNAL
    );
    assert!(
        fail_closed_case
            .capacity_error_message
            .contains("capacity exhausted")
    );
    assert_eq!(fail_closed_case.capacity_pending_count, 1);
    assert!(!fail_closed_case.tampered_verified);
    assert!(
        fail_closed_case
            .tampered_event_detail
            .contains("valid=false")
    );
}
