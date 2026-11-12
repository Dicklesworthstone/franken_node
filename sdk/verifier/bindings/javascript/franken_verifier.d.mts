export type EvidenceFormat = "incident-bundle" | "capsule" | "signed-bundle" | "resolution-receipt" | "publisher-source" | "publisher-source-trust" | "counterfactual-receipt" | "ltv-evidence";
export interface VerifierOptions {
  /** Trusted SDK executable, installed separately; never supplied by evidence. */
  verifier: string;
  format?: EvidenceFormat;
  /** Independent original receipt authority, only for incident-bundle. Missing proof fails. */
  trustedRunPublicKeyHex?: string;
  /** Independent product root; requires original-run trust and portable session evidence. */
  trustedRuntimePublicKeyHex?: string;
  /** Independent revocation authority; required only for publisher-source-trust. */
  trustedRevocationPublicKeyHex?: string;
  /** Optional independent provenance authority; requires a matching signed chain. */
  trustedProvenancePublicKeyHex?: string;
  /** Required trust evaluation time: four-digit RFC3339 year, non-leap seconds, <=9 fraction digits. */
  evaluationTime?: string;
  /** Required freshness window: canonical positive decimal u64 string, never a rounded number. */
  maxRevocationAgeSecs?: string;
  /** Required detached signature for signed-bundle, publisher-source formats, and counterfactual-receipt. */
  signatureHex?: string;
  timeoutMs?: number;
}
export interface NativeCaptureMetadata {
  payload_sha256: string;
  payload_bytes: number;
  captured_terminal_state: "completed" | "uncaught_exception" | "engine_failure";
  host_io_exchange_count: number;
}
export interface IncidentFacts {
  bundle_id: string;
  incident_id: string;
  created_at: string;
  policy_version: string;
  event_count: number;
  integrity_hash: string;
  decision_sequence_hash: string;
  signer_public_key_hex: string;
  signing_identity: string;
  native_capture: NativeCaptureMetadata | null;
}
/** Authenticated original receipt-authority statement, not guest execution. */
export interface RunOriginMetadata {
  receipt_id: string;
  receipt_hash: string;
  signer_public_key_hex: string;
  record_sha256: string;
}
export interface RunIncidentFacts extends IncidentFacts {
  run_origin: RunOriginMetadata;
}
/** Original engine ledger attribution; not guest execution or cleanup. */
export interface RuntimeOriginMetadata {
  session_nonce: string;
  product_root_key_id: string;
  producer_id: string;
  evidence_key_id: string;
  /** Canonical decimal u64 string; never rounded to a JS number. */
  signed_epoch: string;
}
export interface RuntimeIncidentFacts extends RunIncidentFacts {
  runtime_origin: RuntimeOriginMetadata;
}
export interface CapsuleFacts {
  capsule_id: string;
  expected_hash: string;
  actual_hash: string;
  signer_public_key_hex: string;
}
export interface SignedBundleFacts {
  bundle_id: string;
  incident_id: string;
  event_count: number;
  integrity_hash: string;
  signer_public_key_hex: string;
}
/** Authenticated resolver decision; no grant of execution or package authority. */
export type ResolutionReceiptFacts = {
  receipt_id: string;
  crypto_suite: "ed25519-v1";
  module_graph_hash: string;
  package_name: string;
  requested_range: string;
  policy_profile: "strict" | "balanced" | "legacy_risky";
  capability_budget_mode: "advisory" | "enforced";
  rejected_alternative_count: number;
  canonical_hash: string;
  signer_key_id: string;
  signer_public_key_hex: string;
} & ({ decision: "admit"; selected_version: string } | { decision: "reject"; selected_version: null });
/** Publisher-signed ceilings; these are not grants of runtime authority. */
export interface PublisherRuntimeAuthority {
  schema_version: "franken-node/artifact-runtime-authority/v1";
  policy_revision: string;
  allowed_capabilities: Array<"builtin" | "console" | "env_read" | "fs_read" | "fs_write" | "heap_allocate"
    | "module_load" | "network_egress" | "process_spawn" | "random_read" | "timer" | "vm_dispatch">;
  allow_process_shape: boolean;
  /** All numeric ceilings are exact positive decimal strings, including u32 fields. */
  max_instructions: string;
  max_registers: string;
  max_call_depth: string;
  max_heap_objects: string;
  max_total_memory_bytes: string;
  max_console_entries: string;
  max_parse_source_bytes: string;
  max_parse_tokens: string;
  max_parse_recursion_depth: string;
}
/** Authenticated capsule content metadata; paths and source bytes are not returned. */
export interface PublisherSourceCapsule {
  schema_version: "franken-node/module-source-capsule/v1";
  graph_input_hash: string;
  /** The standalone SDK does not reconstruct the module graph. */
  graph_hash_recomputed: false;
  capsule_bytes: number;
  payload_bytes: number;
  input_count: number;
  file_count: number;
  metadata_file_count: number;
  directory_count: number;
  missing_count: number;
  symlink_count: number;
  symlink_policy: "reject" | "contained";
  /** Null means the producer selected its native default conditions. */
  condition_count: number | null;
  additional_condition_count: number;
}
/** Publisher authentication, not provenance, revocation, graph reconstruction or execution. */
export type PublisherSourceFacts = {
  package_name: string;
  publisher_id: string;
  version: string;
  manifest_sha256: string;
  artifact_sha256: string;
  capsule_digest: string;
  signer_key_id: string;
  signer_public_key_hex: string;
  capsule: PublisherSourceCapsule;
} & (
  { registration_schema: "franken-node/extension-registration-manifest/v1"; runtime_authority: null }
  | { registration_schema: "franken-node/extension-registration-manifest/v2"; runtime_authority: PublisherRuntimeAuthority }
);
/** Independently authenticated revocation freshness and optional provenance; no execution grant. */
export type PublisherSourceTrustFacts = {
  source: PublisherSourceFacts;
  revocation_list_sha256: string;
  revocation_authority_public_key_hex: string;
  revocation_issued_at: string;
  /** Same exact instant requested by the caller, normalized by the Rust verifier. */
  revocation_evaluated_at: string;
  max_revocation_age_secs: string;
} & (
  { provenance_chain_sha256: null; provenance_authority_public_key_hex: null; provenance_link_count: null }
  | { provenance_chain_sha256: string; provenance_authority_public_key_hex: string; provenance_link_count: number }
);
export interface CounterfactualReceiptFacts {
  baseline_integrity_hash: string;
  mode: "single" | "sweep";
  result_count: number;
  signer_public_key_hex: string;
}
export interface LtvEvidenceFacts {
  artifact_id: string;
  artifact_hash: string;
  crypto_suite: string;
  as_of_unix_seconds: string;
  claimed_at_unix_seconds: string;
  witness_group_id: string;
  witness_policy_id: string;
  reattestation_count: number;
  hybrid_survived_algo_death: boolean;
  signer_public_key_hex: string;
}
export type Verification = {
  schema_version: "franken-verifier-cli/v1";
  verdict: "verified";
  artifact_sha256: string;
} & (
  { format: "incident-bundle"; scope: "authenticated_recorded_incident"; facts: IncidentFacts }
  | { format: "incident-bundle"; scope: "authenticated_run_incident"; facts: RunIncidentFacts }
  | { format: "incident-bundle"; scope: "authenticated_runtime_incident"; facts: RuntimeIncidentFacts }
  | { format: "capsule"; scope: "authenticated_capsule_content"; facts: CapsuleFacts }
  | { format: "signed-bundle"; scope: "authenticated_sdk_replay_bundle"; facts: SignedBundleFacts }
  | { format: "resolution-receipt"; scope: "authenticated_resolution_decision"; facts: ResolutionReceiptFacts }
  | { format: "publisher-source"; scope: "authenticated_publisher_source_content"; facts: PublisherSourceFacts }
  | { format: "publisher-source-trust"; scope: "authenticated_publisher_source_trust"; facts: PublisherSourceTrustFacts }
  | { format: "counterfactual-receipt"; scope: "authenticated_counterfactual_receipt"; facts: CounterfactualReceiptFacts }
  | { format: "ltv-evidence"; scope: "authenticated_ltv_anteriority"; facts: LtvEvidenceFacts }
);
export class VerifierError extends Error {
  readonly code: string;
  readonly exitCode: number | null;
  readonly stderr: Uint8Array;
  constructor(code: string, message: string, options?: { exitCode?: number | null; stderr?: Uint8Array });
}
export const PROTOCOL: "franken-verifier-cli/v1";
export const MAX_INPUT_BYTES: number;
export function verifyArtifact(data: Uint8Array, trustedPublicKeyHex: string, options: VerifierOptions): Promise<Verification>;
