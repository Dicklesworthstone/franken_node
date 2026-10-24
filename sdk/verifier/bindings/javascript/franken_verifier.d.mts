export type EvidenceFormat = "incident-bundle" | "capsule" | "signed-bundle";
export interface VerifierOptions {
  /** Trusted SDK executable, installed separately; never supplied by evidence. */
  verifier: string;
  format?: EvidenceFormat;
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
export type Verification = {
  schema_version: "franken-verifier-cli/v1";
  verdict: "verified";
  artifact_sha256: string;
} & (
  { format: "incident-bundle"; scope: "authenticated_recorded_incident"; facts: IncidentFacts }
  | { format: "capsule"; scope: "authenticated_capsule_content"; facts: CapsuleFacts }
  | { format: "signed-bundle"; scope: "authenticated_sdk_replay_bundle"; facts: SignedBundleFacts }
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
