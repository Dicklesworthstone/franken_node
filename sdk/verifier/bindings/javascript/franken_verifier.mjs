/** Offline verifier API backed by the separately trusted independent Rust SDK. */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";

export const PROTOCOL = "franken-verifier-cli/v1";
export const MAX_INPUT_BYTES = 64 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024 + 1;
const SCOPES = Object.freeze({
  "incident-bundle": "authenticated_recorded_incident",
  capsule: "authenticated_capsule_content",
  "signed-bundle": "authenticated_sdk_replay_bundle",
  "resolution-receipt": "authenticated_resolution_decision",
  "publisher-source": "authenticated_publisher_source_content",
  "counterfactual-receipt": "authenticated_counterfactual_receipt",
  "ltv-evidence": "authenticated_ltv_anteriority",
});

export class VerifierError extends Error {
  constructor(code, message, { exitCode = null, stderr = Buffer.alloc(0) } = {}) {
    super(message);
    this.name = "VerifierError";
    this.code = code;
    this.exitCode = exitCode;
    this.stderr = stderr;
  }
}

const hex = (value, length) => typeof value === "string" && new RegExp(`^[0-9a-fA-F]{${length}}$`, "u").test(value);
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const keys = (value, expected) => object(value) && Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const boundedText = (value) => typeof value === "string" && value.trim().length > 0
  && Buffer.byteLength(value, "utf8") <= 4096 && Buffer.from(value, "utf8").toString("utf8") === value;

function runOriginValid(origin, anchor) {
  return keys(origin, ["receipt_id", "receipt_hash", "signer_public_key_hex", "record_sha256"])
    && typeof origin.receipt_id === "string" && /^[A-Za-z0-9_-]{1,128}$/u.test(origin.receipt_id)
    && typeof origin.receipt_hash === "string" && /^sha256:[0-9a-f]{64}$/u.test(origin.receipt_hash)
    && origin.signer_public_key_hex === anchor
    && typeof origin.record_sha256 === "string" && /^[0-9a-f]{64}$/u.test(origin.record_sha256);
}

function runtimeOriginValid(origin, anchor) {
  return keys(origin, ["session_nonce", "product_root_key_id", "producer_id", "evidence_key_id", "signed_epoch"])
    && typeof origin.session_nonce === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(origin.session_nonce)
    && origin.product_root_key_id === `ed25519:${anchor}`
    && typeof origin.producer_id === "string" && origin.producer_id.length > 0 && origin.producer_id.length <= 512
    && typeof origin.evidence_key_id === "string" && /^ed25519:[0-9a-f]{64}$/u.test(origin.evidence_key_id)
    && typeof origin.signed_epoch === "string" && /^(0|[1-9][0-9]{0,19})$/u.test(origin.signed_epoch)
    && BigInt(origin.signed_epoch) <= 18_446_744_073_709_551_615n;
}

const publisherText = (value, limit) => boundedText(value) && value === value.trim()
  && Buffer.byteLength(value, "utf8") <= limit && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
const digest = (value) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
const decimalLimit = (value, limit) => typeof value === "string" && /^[1-9][0-9]{0,19}$/u.test(value)
  && BigInt(value) <= limit;
const PUBLISHER_CAPABILITIES = ["builtin", "console", "env_read", "fs_read", "fs_write", "heap_allocate",
  "module_load", "network_egress", "process_spawn", "random_read", "timer", "vm_dispatch"];
const PUBLISHER_LIMITS = Object.freeze({
  max_instructions: 18_446_744_073_709_551_615n, max_registers: 65_536n,
  max_call_depth: 10_000n, max_heap_objects: 4_294_967_295n,
  max_total_memory_bytes: 18_446_744_073_709_551_615n, max_console_entries: 4_294_967_295n,
  max_parse_source_bytes: 2_097_152n, max_parse_tokens: 131_072n, max_parse_recursion_depth: 384n,
});

function publisherAuthorityValid(authority) {
  return keys(authority, ["schema_version", "policy_revision", "allowed_capabilities", "allow_process_shape", ...Object.keys(PUBLISHER_LIMITS)])
    && authority.schema_version === "franken-node/artifact-runtime-authority/v1"
    && publisherText(authority.policy_revision, 128)
    && typeof authority.allow_process_shape === "boolean"
    && Array.isArray(authority.allowed_capabilities)
    && authority.allowed_capabilities.length <= PUBLISHER_CAPABILITIES.length
    && new Set(authority.allowed_capabilities).size === authority.allowed_capabilities.length
    && authority.allowed_capabilities.every((value) => PUBLISHER_CAPABILITIES.includes(value))
    && ["console", "heap_allocate", "vm_dispatch"].every((value) => authority.allowed_capabilities.includes(value))
    && Object.entries(PUBLISHER_LIMITS).every(([name, limit]) => decimalLimit(authority[name], limit));
}

function publisherSourceValid(facts, anchor) {
  const summary = facts.capsule;
  const counts = ["file_count", "metadata_file_count", "directory_count", "missing_count", "symlink_count"];
  return publisherText(facts.package_name, 256) && publisherText(facts.publisher_id, 256)
    && publisherText(facts.version, 128) && /^[0-9]+\.[0-9]+\.[0-9]+$/u.test(facts.version)
    && ["manifest_sha256", "artifact_sha256", "capsule_digest"].every((name) => digest(facts[name]))
    && facts.signer_key_id === createHash("sha256").update("artifact_signing_keyid_v1:")
      .update(Buffer.from([32, 0, 0, 0, 0, 0, 0, 0])).update(Buffer.from(anchor, "hex")).digest("hex").slice(0, 16)
    && (facts.registration_schema === "franken-node/extension-registration-manifest/v1" && facts.runtime_authority === null
      || facts.registration_schema === "franken-node/extension-registration-manifest/v2" && publisherAuthorityValid(facts.runtime_authority))
    && keys(summary, ["schema_version", "graph_input_hash", "graph_hash_recomputed", "capsule_bytes", "payload_bytes",
      "input_count", ...counts, "symlink_policy", "condition_count", "additional_condition_count"])
    && summary.schema_version === "franken-node/module-source-capsule/v1"
    && digest(summary.graph_input_hash) && summary.graph_hash_recomputed === false
    && count(summary.capsule_bytes) && summary.capsule_bytes >= 12 && summary.capsule_bytes <= 5 * 1024 * 1024
    && count(summary.payload_bytes) && summary.payload_bytes <= summary.capsule_bytes - 12
    && count(summary.input_count) && summary.input_count > 0 && summary.input_count <= 1024
    && counts.every((name) => count(summary[name]) && summary[name] <= summary.input_count)
    && counts.reduce((total, name) => total + summary[name], 0) === summary.input_count
    && ["reject", "contained"].includes(summary.symlink_policy)
    && (summary.symlink_policy === "contained" || summary.symlink_count === 0)
    && (summary.condition_count === null || count(summary.condition_count) && summary.condition_count <= 64)
    && count(summary.additional_condition_count) && summary.additional_condition_count <= 62
    && (summary.condition_count === null || summary.condition_count + summary.additional_condition_count <= 64);
}

function factsValid(facts, format, anchor, runAnchor, runtimeAnchor) {
  const expected = {
    "incident-bundle": ["bundle_id", "incident_id", "created_at", "policy_version", "event_count", "integrity_hash", "decision_sequence_hash", "signer_public_key_hex", "signing_identity", "native_capture"],
    capsule: ["capsule_id", "expected_hash", "actual_hash", "signer_public_key_hex"],
    "signed-bundle": ["bundle_id", "incident_id", "event_count", "integrity_hash", "signer_public_key_hex"],
    "resolution-receipt": ["receipt_id", "crypto_suite", "module_graph_hash", "package_name", "requested_range", "policy_profile", "capability_budget_mode", "decision", "selected_version", "rejected_alternative_count", "canonical_hash", "signer_key_id", "signer_public_key_hex"],
    "publisher-source": ["registration_schema", "package_name", "publisher_id", "version", "manifest_sha256", "artifact_sha256", "capsule_digest", "signer_key_id", "signer_public_key_hex", "runtime_authority", "capsule"],
    "counterfactual-receipt": ["baseline_integrity_hash", "mode", "result_count", "signer_public_key_hex"],
    "ltv-evidence": ["artifact_id", "artifact_hash", "crypto_suite", "as_of_unix_seconds", "claimed_at_unix_seconds", "witness_group_id", "witness_policy_id", "reattestation_count", "hybrid_survived_algo_death", "signer_public_key_hex"],
  }[format];
  if (runAnchor !== undefined) expected.push("run_origin");
  if (runtimeAnchor !== undefined) expected.push("runtime_origin");
  if (!keys(facts, expected) || facts.signer_public_key_hex !== anchor) return false;
  if (format === "publisher-source") return publisherSourceValid(facts, anchor);
  if (format === "counterfactual-receipt") {
    return typeof facts.baseline_integrity_hash === "string" && /^[0-9a-f]{64}$/u.test(facts.baseline_integrity_hash)
      && ["single", "sweep"].includes(facts.mode)
      && count(facts.result_count) && facts.result_count >= 1 && facts.result_count <= 1024
      && (facts.mode === "sweep" || facts.result_count === 1);
  }
  if (format === "ltv-evidence") {
    const hashBody = typeof facts.artifact_hash === "string" && facts.artifact_hash.startsWith("sha256:")
      ? facts.artifact_hash.slice(7) : facts.artifact_hash;
    return publisherText(facts.artifact_id, 256)
      && typeof hashBody === "string" && /^[0-9a-f]{64}$/u.test(hashBody)
      && publisherText(facts.crypto_suite, 128)
      && ["as_of_unix_seconds", "claimed_at_unix_seconds"].every((k) => typeof facts[k] === "string"
        && /^(0|[1-9][0-9]{0,19})$/u.test(facts[k]) && BigInt(facts[k]) <= 18_446_744_073_709_551_615n)
      && publisherText(facts.witness_group_id, 256) && publisherText(facts.witness_policy_id, 256)
      && count(facts.reattestation_count) && facts.reattestation_count <= 64
      && typeof facts.hybrid_survived_algo_death === "boolean";
  }
  if (format === "resolution-receipt") {
    return ["receipt_id", "package_name", "requested_range"].every((key) => boundedText(facts[key]))
      && ["module_graph_hash", "canonical_hash", "signer_key_id"].every((key) => typeof facts[key] === "string" && /^sha256:[0-9a-f]{64}$/u.test(facts[key]))
      && facts.signer_key_id === `sha256:${createHash("sha256").update("franken-node/resolution-receipt/signer-key-id/v1:").update(Buffer.from(anchor, "hex")).digest("hex")}`
      && facts.crypto_suite === "ed25519-v1"
      && ["strict", "balanced", "legacy_risky"].includes(facts.policy_profile)
      && ["advisory", "enforced"].includes(facts.capability_budget_mode)
      && count(facts.rejected_alternative_count) && facts.rejected_alternative_count <= 1024
      && (facts.decision === "reject" && facts.selected_version === null
        || facts.decision === "admit" && boundedText(facts.selected_version));
  }
  for (const [key, value] of Object.entries(facts)) {
    if (key === "event_count") {
      if (!count(value)) return false;
    } else if (key === "run_origin") {
      if (!runOriginValid(value, runAnchor)) return false;
    } else if (key === "runtime_origin") {
      if (!runtimeOriginValid(value, runtimeAnchor)) return false;
    } else if (key === "native_capture") {
      if (value !== null && (!keys(value, ["payload_sha256", "payload_bytes", "captured_terminal_state", "host_io_exchange_count"])
          || !hex(value.payload_sha256, 64) || !["completed", "uncaught_exception", "engine_failure"].includes(value.captured_terminal_state)
          || !count(value.payload_bytes) || value.payload_bytes > MAX_INPUT_BYTES
          || !count(value.host_io_exchange_count) || value.host_io_exchange_count > MAX_INPUT_BYTES)) return false;
    } else if (typeof value !== "string" || value.length === 0) return false;
  }
  return true;
}

/**
 * Authenticate original bytes; never executes a captured guest or discovers its own anchor.
 * An explicit trustedRunPublicKeyHex requires the original receipt-authority
 * signature and matching run data. Missing proof or downgraded scope fails.
 * trustedRuntimePublicKeyHex additionally requires the original product-root
 * and session signatures; it does not establish guest execution or cleanup.
 */
export async function verifyArtifact(data, trustedPublicKeyHex, options) {
  const { verifier, format = "incident-bundle", trustedRunPublicKeyHex, trustedRuntimePublicKeyHex, signatureHex, timeoutMs = 10_000 } = options ?? {};
  if (!(data instanceof Uint8Array)) throw new VerifierError("INPUT_INVALID", "data must contain the original bytes");
  if (data.byteLength > MAX_INPUT_BYTES) throw new VerifierError("INPUT_TOO_LARGE", "evidence exceeds 64 MiB");
  if (typeof format !== "string" || !Object.hasOwn(SCOPES, format)) throw new VerifierError("UNSUPPORTED_FORMAT", "unsupported evidence format");
  if (!hex(trustedPublicKeyHex, 64)) throw new VerifierError("ANCHOR_INVALID", "expected a 32-byte hexadecimal public key");
  if (trustedRunPublicKeyHex !== undefined) {
    if (format !== "incident-bundle") throw new VerifierError("INPUT_INVALID", "original-run trust applies only to incident-bundle");
    if (!hex(trustedRunPublicKeyHex, 64)) throw new VerifierError("RUN_ANCHOR_INVALID", "expected a 32-byte hexadecimal run public key");
  }
  if (trustedRuntimePublicKeyHex !== undefined) {
    if (format !== "incident-bundle" || trustedRunPublicKeyHex === undefined) throw new VerifierError("INPUT_INVALID", "runtime trust requires incident-bundle and original-run trust");
    if (!hex(trustedRuntimePublicKeyHex, 64)) throw new VerifierError("RUNTIME_ANCHOR_INVALID", "expected a 32-byte hexadecimal product-root public key");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120_000) throw new VerifierError("TIMEOUT_INVALID", "timeoutMs must be finite and in (0, 120000]");
  if (typeof verifier !== "string" || verifier.length === 0 || verifier.includes("\0")) throw new VerifierError("EXECUTABLE_INVALID", "verifier must be a trusted executable path");
  const bytes = Buffer.from(data);
  const anchor = trustedPublicKeyHex.toLowerCase();
  const runAnchor = trustedRunPublicKeyHex?.toLowerCase();
  const runtimeAnchor = trustedRuntimePublicKeyHex?.toLowerCase();
  const scope = runtimeAnchor !== undefined ? "authenticated_runtime_incident" : runAnchor === undefined ? SCOPES[format] : "authenticated_run_incident";
  const args = ["verify", "--format", format, "--trusted-key-hex", anchor];
  if (runAnchor !== undefined) args.push("--trusted-run-key-hex", runAnchor);
  if (runtimeAnchor !== undefined) args.push("--trusted-runtime-key-hex", runtimeAnchor);
  if (format === "signed-bundle" || format === "publisher-source" || format === "counterfactual-receipt") {
    if (!hex(signatureHex, 128)) throw new VerifierError("SIGNATURE_MALFORMED", "a detached 64-byte signature is required");
    args.push("--signature-hex", signatureHex);
  } else if (signatureHex !== undefined) throw new VerifierError("INPUT_INVALID", "detached signatures apply only to signed-bundle, publisher-source, or counterfactual-receipt");
  return new Promise((resolve, reject) => {
    const child = execFile(verifier, args, {
      encoding: "buffer", shell: false, timeout: Math.ceil(timeoutMs),
      killSignal: "SIGKILL", maxBuffer: MAX_RESPONSE_BYTES, windowsHide: true,
    }, (error, stdout, stderr) => {
      if (error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return reject(new VerifierError("PROTOCOL_INVALID", "verifier response exceeds its size bound"));
      if (error?.killed) return reject(new VerifierError("PROCESS_TIMEOUT", "verifier exceeded its execution timeout"));
      if (error && typeof error.code !== "number") return reject(new VerifierError("PROCESS_UNAVAILABLE", "cannot execute the trusted verifier"));
      let result;
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(stdout).trim();
        result = JSON.parse(text);
        // Protocol responses are compact JSON from Rust. Re-encoding also
        // refuses duplicate members/alternate spellings without parsing artifact bytes.
        if (JSON.stringify(result) !== text) throw new Error("noncanonical response");
      } catch {
        return reject(new VerifierError("PROTOCOL_INVALID", "verifier returned invalid JSON"));
      }
      if (!object(result) || result.schema_version !== PROTOCOL) return reject(new VerifierError("PROTOCOL_INVALID", "unsupported verifier response schema"));
      const exitCode = error?.code ?? 0;
      if (result.verdict === "rejected") {
        if (![1, 2].includes(exitCode) || !keys(result, ["schema_version", "verdict", "error"])
            || !keys(result.error, ["code", "message"]) || typeof result.error.code !== "string" || !result.error.code
            || typeof result.error.message !== "string") return reject(new VerifierError("PROTOCOL_INVALID", "inconsistent rejection response"));
        return reject(new VerifierError(result.error.code, result.error.message, { exitCode, stderr }));
      }
      if (exitCode !== 0 || !keys(result, ["schema_version", "verdict", "format", "scope", "artifact_sha256", "facts"])
          || result.verdict !== "verified" || result.format !== format || result.scope !== scope
          || result.artifact_sha256 !== createHash("sha256").update(bytes).digest("hex") || !factsValid(result.facts, format, anchor, runAnchor, runtimeAnchor)) {
        return reject(new VerifierError("PROTOCOL_INVALID", "verification response does not match the request"));
      }
      resolve(result);
    });
    // Early argument/schema refusal may close stdin before a large input is
    // written. The exit/result handler still determines the typed outcome.
    child.stdin.on("error", () => {});
    child.stdin.end(bytes);
  });
}
