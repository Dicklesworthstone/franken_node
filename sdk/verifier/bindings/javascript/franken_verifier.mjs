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

function factsValid(facts, format, anchor, runAnchor, runtimeAnchor) {
  const expected = {
    "incident-bundle": ["bundle_id", "incident_id", "created_at", "policy_version", "event_count", "integrity_hash", "decision_sequence_hash", "signer_public_key_hex", "signing_identity", "native_capture"],
    capsule: ["capsule_id", "expected_hash", "actual_hash", "signer_public_key_hex"],
    "signed-bundle": ["bundle_id", "incident_id", "event_count", "integrity_hash", "signer_public_key_hex"],
  }[format];
  if (runAnchor !== undefined) expected.push("run_origin");
  if (runtimeAnchor !== undefined) expected.push("runtime_origin");
  if (!keys(facts, expected) || facts.signer_public_key_hex !== anchor) return false;
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
  if (format === "signed-bundle") {
    if (!hex(signatureHex, 128)) throw new VerifierError("SIGNATURE_MALFORMED", "a detached 64-byte signature is required");
    args.push("--signature-hex", signatureHex);
  } else if (signatureHex !== undefined) throw new VerifierError("INPUT_INVALID", "detached signatures apply only to signed-bundle");
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
