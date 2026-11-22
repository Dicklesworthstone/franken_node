//! Portable inputs for actual native incident re-execution.
//!
//! A capture is an integrity envelope, not its own trust anchor. The caller must
//! authenticate the containing run record or incident bundle before executing
//! it. Re-execution consumes the captured source and typed host-effect outcomes;
//! it never installs a live filesystem, network, entropy, or process provider.
//! Process-authorized captures preserve the globally ordered effect journal and
//! the exact request preparation observed at the authenticated provider. Replay
//! uses an expired process authority and a provider that cannot dispatch effects.
//! The original process-capture run applies the engine's conservative Unknown
//! exception floor before lowering, matching the ordered replay journal's floor.
//! This can deny a flow the ordinary bounded live provider would permit; neither
//! captured witnesses nor replay provenance are weakened to obtain a match.
//! An explicit process-shape grant is replayable: argv comes from the captured
//! launch arguments, while platform and pid are fixed engine-contained values.
//! This grant never admits environment values or access to the raw process object.
//! Separately granted EnvRead consumes only recorded names and typed outcomes,
//! never the replay host environment. Environment values retain their Secret
//! IFC floor; serialized captures may contain private values and need private
//! storage even though their Debug view is redacted.
//! Frozen module captures retain the source graph's portable capsule. Replay
//! reconstructs its closed-world resolver without opening the original project.
//! Captures without that capsule still disable runtime module loading.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NATIVE_REPLAY_CAPTURE_SCHEMA: &str = "franken-node/native-replay-capture/v3";
/// Captures the publisher's attenuated provider policy as well as guest inputs.
/// The ceiling is historical signed context, never an independent trust anchor.
pub const NATIVE_REPLAY_SCOPED_CAPTURE_SCHEMA: &str = "franken-node/native-replay-capture/v4";
pub const NATIVE_REPLAY_OUTCOME_SCHEMA: &str = "franken-node/native-replay-outcome/v2";
pub const MAX_NATIVE_REPLAY_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
pub const NATIVE_COUNTERFACTUAL_OUTCOME_SCHEMA: &str =
    "franken-node/native-counterfactual-outcome/v1";
pub const NATIVE_COUNTERFACTUAL_SCOPE: &str = "captured_inputs_capability_attenuation";
pub const MAX_NATIVE_COUNTERFACTUAL_DENIALS: usize = 32;

/// Restrictions applied to an independently authenticated capture. A branch
/// can remove existing capabilities; it cannot add authority or replace the
/// original source, settings, scheduler inputs or recorded host outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCounterfactualRequest {
    pub denied_capabilities: Vec<String>,
}

impl NativeCounterfactualRequest {
    /// Check the bounded request before starting a child. The engine additionally
    /// requires each tag to name a capability granted by the captured package.
    pub fn validate(&self) -> Result<(), String> {
        if self.denied_capabilities.is_empty()
            || self.denied_capabilities.len() > MAX_NATIVE_COUNTERFACTUAL_DENIALS
        {
            return Err(format!(
                "native counterfactual requires 1..={MAX_NATIVE_COUNTERFACTUAL_DENIALS} denied capabilities"
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for capability in &self.denied_capabilities {
            if capability.is_empty()
                || capability.len() > 64
                || !capability
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
                || !seen.insert(capability)
            {
                return Err(
                    "native counterfactual requires unique, bounded canonical capability tags"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Actual console observation from the restricted native branch. Messages may
/// contain private captured data; they are omitted from diagnostic Debug output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCounterfactualConsoleEntry {
    pub level: String,
    pub message: String,
    pub instruction_index: u64,
}

impl std::fmt::Debug for NativeCounterfactualConsoleEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeCounterfactualConsoleEntry")
            .field("message", &"[redacted]")
            .field("instruction_index", &self.instruction_index)
            .finish_non_exhaustive()
    }
}

/// A fresh native branch after successful verification of the original run.
/// Its result describes capability attenuation over captured inputs, not parity
/// with the original program or an independently certified alternative policy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCounterfactualOutcome {
    pub schema_version: String,
    pub execution_kind: String,
    pub verification_scope: String,
    pub capture_payload_sha256: String,
    pub baseline: NativeReplayOutcome,
    pub denied_capabilities: Vec<String>,
    /// Declared package grants retained after attenuation. This is not an
    /// enumeration of engine-intrinsic or ambient authority.
    pub retained_declared_capabilities: Vec<String>,
    pub terminal_state: NativeReplayTerminalState,
    pub execution_value: Option<String>,
    pub exception_value: Option<String>,
    pub engine_failure: Option<String>,
    pub exit_code: Option<i32>,
    pub instructions_executed: Option<u64>,
    pub console_output: Vec<NativeCounterfactualConsoleEntry>,
    pub captured_host_effects: usize,
    pub consumed_host_effects: usize,
    pub unused_original_host_effects: usize,
    pub console_matches_original: bool,
    pub execution_value_matches_original: Option<bool>,
    pub terminal_state_matches_original: bool,
    pub replay_certified: bool,
    pub policy_equivalence_certified: bool,
}

impl std::fmt::Debug for NativeCounterfactualOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeCounterfactualOutcome")
            .field("terminal_state", &self.terminal_state)
            .field("console_entries", &self.console_output.len())
            .field("consumed_host_effects", &self.consumed_host_effects)
            .field(
                "unused_original_host_effects",
                &self.unused_original_host_effects,
            )
            .field("observed_values", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "engine", target_os = "linux"))]
impl NativeCounterfactualOutcome {
    fn validate_for_request(
        &self,
        capture_payload_sha256: &str,
        request: &NativeCounterfactualRequest,
    ) -> Result<(), String> {
        request.validate()?;
        if self.schema_version != NATIVE_COUNTERFACTUAL_OUTCOME_SCHEMA
            || self.execution_kind != "native_counterfactual"
            || self.verification_scope != NATIVE_COUNTERFACTUAL_SCOPE
            || self.capture_payload_sha256 != capture_payload_sha256
            || self.denied_capabilities != request.denied_capabilities
            || self.baseline.verification_scope != POLICY_EQUIVALENCE_SCOPE
            || !self.baseline.satisfies_policy_equivalence()
            || self.replay_certified
            || self.policy_equivalence_certified
            || self
                .consumed_host_effects
                .checked_add(self.unused_original_host_effects)
                != Some(self.captured_host_effects)
            || self.captured_host_effects > MAX_NATIVE_REPLAY_PAYLOAD_BYTES
            || self
                .retained_declared_capabilities
                .iter()
                .any(|capability| self.denied_capabilities.contains(capability))
            || self
                .console_output
                .iter()
                .any(|entry| !matches!(entry.level.as_str(), "log" | "error" | "warn" | "info"))
        {
            return Err("native counterfactual worker returned an invalid observation".to_string());
        }
        let completed = self.terminal_state == NativeReplayTerminalState::Completed;
        if self.execution_value.is_some() != completed
            || self.instructions_executed.is_some() != completed
            || self.execution_value_matches_original.is_some() != completed
            || self.terminal_state_matches_original != completed
            || (!completed && self.exit_code.is_some())
            || self.exception_value.is_some()
                != (self.terminal_state == NativeReplayTerminalState::UncaughtException)
            || self.engine_failure.is_some()
                != (self.terminal_state == NativeReplayTerminalState::EngineFailure)
        {
            return Err(
                "native counterfactual worker returned contradictory terminal observations"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// The engine terminal state the authenticated capture describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReplayTerminalState {
    Completed,
    UncaughtException,
    /// A typed interpreter capability denial or instruction-budget stop.
    /// This never denotes a supervisor deadline, cancellation, or panic.
    EngineFailure,
}

/// Exact serialized execution inputs, bound into the signed run receipt.
/// JSON retains private source, arguments and observed environment values.
/// Debug must not expose them through containing records or diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReplayCapture {
    pub schema_version: String,
    pub payload_json: String,
    pub payload_sha256: String,
}

impl std::fmt::Debug for NativeReplayCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not print even caller-supplied metadata strings before validation.
        f.debug_struct("NativeReplayCapture")
            .field("payload_bytes", &self.payload_json.len())
            .field("payload", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl NativeReplayCapture {
    /// Check the envelope before parsing its potentially expensive typed data.
    /// This does not authenticate the producer: the containing record must
    /// already have passed signature verification against an independent key.
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(
            self.schema_version.as_str(),
            NATIVE_REPLAY_CAPTURE_SCHEMA | NATIVE_REPLAY_SCOPED_CAPTURE_SCHEMA
        ) {
            return Err(format!(
                "unsupported native replay capture schema {}",
                self.schema_version
            ));
        }
        if self.payload_json.is_empty() || self.payload_json.len() > MAX_NATIVE_REPLAY_PAYLOAD_BYTES
        {
            return Err(format!(
                "native replay payload must contain 1..={MAX_NATIVE_REPLAY_PAYLOAD_BYTES} bytes"
            ));
        }
        if self.payload_sha256 != hex::encode(Sha256::digest(self.payload_json.as_bytes())) {
            return Err("native replay payload SHA-256 does not match captured bytes".to_string());
        }
        Ok(())
    }

    /// Read the captured terminal state without linking the engine. This is
    /// descriptive metadata; execution still validates the complete typed
    /// payload after authenticating its containing record.
    pub fn terminal_state(&self) -> Result<NativeReplayTerminalState, String> {
        #[derive(Deserialize)]
        struct ExpectedTerminalState {
            terminal_state: NativeReplayTerminalState,
        }
        #[derive(Deserialize)]
        struct PayloadTerminalState {
            expected: ExpectedTerminalState,
        }

        self.validate()?;
        let payload: PayloadTerminalState = serde_json::from_str(&self.payload_json)
            .map_err(|error| format!("invalid native replay terminal state: {error}"))?;
        Ok(payload.expected.terminal_state)
    }
}

/// Comparisons of fresh native execution with the authenticated original.
/// Signatures and wall-clock timings are deliberately not execution outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReplayOutcome {
    pub schema_version: String,
    pub replay_kind: String,
    pub verification_scope: String,
    pub module_load_disabled: bool,
    pub matched: bool,
    pub divergences: Vec<String>,
    pub captured_trace_id: String,
    pub replay_trace_id: String,
    pub captured_terminal_state: NativeReplayTerminalState,
    pub replay_terminal_state: NativeReplayTerminalState,
    pub terminal_state_match: bool,
    /// Completed executions have these witnesses. Failed prefixes do not;
    /// unavailable comparisons serialize as null and never as successful.
    pub ir3_hash_match: Option<bool>,
    pub ir4_witness_match: Option<bool>,
    pub execution_value_match: Option<bool>,
    pub instruction_count_match: Option<bool>,
    pub console_match: bool,
    pub host_effects_match: bool,
    pub nondeterminism_trace_match: Option<bool>,
    pub lane_match: Option<bool>,
    pub exit_code_match: Option<bool>,
    pub exception_value_match: Option<bool>,
    /// Under `"guest_execution"` scope, withholding `ModuleLoad` without frozen
    /// sources changes the declared capability population and `decisions_match`
    /// is informational. Under [`POLICY_EQUIVALENCE_SCOPE`]
    /// (`into_policy_equivalence_outcome` / `reexecute_with_policy_equivalence`),
    /// `decisions_match == Some(true)` and `!module_load_disabled` are enforced
    /// fail-closed as part of `matched`.
    pub decisions_match: Option<bool>,
    pub policy_comparison_note: String,
}

/// Verification scope that requires both guest execution parity AND original
/// control/policy decision equivalence (`decisions_match == Some(true)` with
/// authenticated frozen module sources).
pub const POLICY_EQUIVALENCE_SCOPE: &str = "guest_execution_and_policy";

/// Divergence recorded when guest execution matches but policy decisions differ.
pub const POLICY_DECISION_DIVERGENCE: &str =
    "re-executed policy decisions differ from the captured run";

/// Divergence recorded when policy equivalence is requested on a capture that
/// withheld runtime module loading or ended before policy decisions were sealed.
pub const POLICY_EQUIVALENCE_UNAVAILABLE_DIVERGENCE: &str = "original-policy equivalence unavailable: runtime module loading was disabled or policy decisions were not captured";

/// A stricter scope can never repair a failed, incomplete, or contradictory
/// guest verdict, even if its caller omitted the explanatory divergence list.
pub const POLICY_GUEST_EXECUTION_DIVERGENCE: &str =
    "original-policy equivalence requires a fully matched completed native execution";

impl NativeReplayOutcome {
    fn completed_guest_execution_matches(&self) -> bool {
        self.schema_version == NATIVE_REPLAY_OUTCOME_SCHEMA
            && self.replay_kind == "native_reexecution"
            && matches!(
                self.verification_scope.as_str(),
                "guest_execution" | POLICY_EQUIVALENCE_SCOPE
            )
            && self.matched
            && self.divergences.is_empty()
            && !self.captured_trace_id.is_empty()
            && self.captured_trace_id == self.replay_trace_id
            && self.captured_terminal_state == NativeReplayTerminalState::Completed
            && self.replay_terminal_state == NativeReplayTerminalState::Completed
            && self.terminal_state_match
            && self.ir3_hash_match == Some(true)
            && self.ir4_witness_match == Some(true)
            && self.execution_value_match == Some(true)
            && self.instruction_count_match == Some(true)
            && self.console_match
            && self.host_effects_match
            && self.nondeterminism_trace_match == Some(true)
            && self.lane_match == Some(true)
            && self.exit_code_match == Some(true)
            && self.exception_value_match.is_none()
    }

    /// Returns `true` iff guest execution matched AND original policy decisions
    /// were re-derived under an intact frozen-module capability population.
    #[must_use]
    pub fn satisfies_policy_equivalence(&self) -> bool {
        self.completed_guest_execution_matches()
            && !self.module_load_disabled
            && self.decisions_match == Some(true)
    }

    /// Upgrade a replay outcome to [`POLICY_EQUIVALENCE_SCOPE`], failing closed
    /// (`matched = false`) whenever policy decisions diverged, were not
    /// captured (e.g., interrupted/failure-prefix runs), or ran with
    /// `module_load_disabled`.
    #[must_use]
    pub fn into_policy_equivalence_outcome(mut self) -> Self {
        // Inspect the original verdict before changing its scope. The fields
        // are public and deserializable, so matched=true alone is insufficient;
        // a missing comparison or failure-prefix label must stay a refusal.
        let guest_matches = self.completed_guest_execution_matches();
        self.verification_scope = POLICY_EQUIVALENCE_SCOPE.to_string();
        if !guest_matches
            && !self
                .divergences
                .iter()
                .any(|d| d == POLICY_GUEST_EXECUTION_DIVERGENCE)
        {
            self.divergences
                .push(POLICY_GUEST_EXECUTION_DIVERGENCE.to_string());
        }
        if self.module_load_disabled || self.decisions_match.is_none() {
            if !self
                .divergences
                .iter()
                .any(|d| d == POLICY_EQUIVALENCE_UNAVAILABLE_DIVERGENCE)
            {
                self.divergences
                    .push(POLICY_EQUIVALENCE_UNAVAILABLE_DIVERGENCE.to_string());
            }
            self.policy_comparison_note = "Original-policy equivalence requires authenticated frozen module sources and completed decision capture; uncertified or interrupted runs fail closed.".to_string();
        } else if self.decisions_match == Some(false) {
            if !self
                .divergences
                .iter()
                .any(|d| d == POLICY_DECISION_DIVERGENCE)
            {
                self.divergences
                    .push(POLICY_DECISION_DIVERGENCE.to_string());
            }
            self.policy_comparison_note = "Original-policy equivalence enforced fail-closed: re-executed policy decisions diverged from the captured run.".to_string();
        } else if !guest_matches {
            self.policy_comparison_note = "Original-policy equivalence refused: guest execution is failed, incomplete, or internally inconsistent; matching policy decisions cannot override that verdict.".to_string();
        } else {
            self.policy_comparison_note = "Captured control-policy decisions and completed guest execution matched under authenticated frozen module sources. This scope does not certify unrecorded scheduler state or provide stepwise time travel.".to_string();
        }
        self.matched = guest_matches
            && self.divergences.is_empty()
            && !self.module_load_disabled
            && self.decisions_match == Some(true);
        self
    }

    /// Fail-closed check requiring both guest execution match and policy-decision
    /// equivalence.
    pub fn enforce_policy_equivalence(&self) -> Result<(), String> {
        let promoted = self.clone().into_policy_equivalence_outcome();
        if promoted.matched {
            Ok(())
        } else {
            Err(promoted.divergences.join("; "))
        }
    }
}

/// Execute only after authenticating the enclosing signed incident bundle.
#[cfg(feature = "engine")]
pub fn reexecute(capture: &NativeReplayCapture) -> Result<NativeReplayOutcome, String> {
    engine::reexecute(capture)
}

/// Execute a restricted branch in the calling process after verifying the
/// original run. The caller must authenticate the capture independently. Use
/// [`counterfactual_supervised`] for untrusted workloads so startup, native
/// execution and cleanup share a process-enforced deadline.
#[cfg(feature = "engine")]
pub fn counterfactual(
    capture: &NativeReplayCapture,
    denied_capabilities: &[String],
) -> Result<NativeCounterfactualOutcome, String> {
    if denied_capabilities.len() > MAX_NATIVE_COUNTERFACTUAL_DENIALS
        || denied_capabilities
            .iter()
            .any(|capability| capability.len() > 64)
    {
        return Err("native counterfactual denial request exceeds its bounds".to_string());
    }
    NativeCounterfactualRequest {
        denied_capabilities: denied_capabilities.to_vec(),
    }
    .validate()?;
    engine::counterfactual(capture, denied_capabilities)
}

/// Re-execute under [`POLICY_EQUIVALENCE_SCOPE`], failing closed when policy
/// decisions diverge or when original capability/module context is unavailable.
#[cfg(feature = "engine")]
pub fn reexecute_with_policy_equivalence(
    capture: &NativeReplayCapture,
) -> Result<NativeReplayOutcome, String> {
    reexecute(capture).map(NativeReplayOutcome::into_policy_equivalence_outcome)
}

/// Default and maximum operator budgets for isolated native incident replay.
pub const DEFAULT_NATIVE_REPLAY_TIMEOUT_MS: u64 = 30_000;
pub const MAX_NATIVE_REPLAY_TIMEOUT_MS: u64 = 300_000;

/// Re-execute authenticated captured inputs in an owned process with bounded
/// startup, execution and protocol draining. The caller must first verify the
/// enclosing incident's independent authority, exactly as for reexecute.
/// Linux launches the currently mapped image through /proc/self/exe; other
/// platforms refuse this supervised scope rather than run without its bounds.
#[cfg(feature = "engine")]
pub fn reexecute_supervised(
    capture: &NativeReplayCapture,
    timeout: std::time::Duration,
) -> Result<NativeReplayOutcome, String> {
    #[cfg(target_os = "linux")]
    {
        supervised::reexecute(capture, timeout)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (capture, timeout);
        Err("supervised native incident replay currently requires Linux".to_string())
    }
}

/// Supervised re-execution promoted to [`POLICY_EQUIVALENCE_SCOPE`].
#[cfg(feature = "engine")]
pub fn reexecute_supervised_with_policy_equivalence(
    capture: &NativeReplayCapture,
    timeout: std::time::Duration,
) -> Result<NativeReplayOutcome, String> {
    reexecute_supervised(capture, timeout).map(NativeReplayOutcome::into_policy_equivalence_outcome)
}

/// Verify the original completed run, then execute a capability-restricted
/// branch in the same owned child and under one startup/execution/drain deadline.
/// The caller must authenticate the incident, source capture and runtime authority
/// independently before calling. No branch can repeat live host effects.
#[cfg(feature = "engine")]
pub fn counterfactual_supervised(
    capture: &NativeReplayCapture,
    denied_capabilities: &[String],
    timeout: std::time::Duration,
) -> Result<NativeCounterfactualOutcome, String> {
    // Bound allocations before cloning caller-owned strings into the protocol.
    if denied_capabilities.len() > MAX_NATIVE_COUNTERFACTUAL_DENIALS
        || denied_capabilities
            .iter()
            .any(|capability| capability.len() > 64)
    {
        return Err("native counterfactual denial request exceeds its bounds".to_string());
    }
    let request = NativeCounterfactualRequest {
        denied_capabilities: denied_capabilities.to_vec(),
    };
    request.validate()?;
    #[cfg(target_os = "linux")]
    {
        supervised::counterfactual(capture, &request, timeout)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (capture, request, timeout);
        Err("supervised native counterfactual execution currently requires Linux".to_string())
    }
}

/// Select the private replay child before parsing public CLI commands. This
/// worker never verifies or signs an incident: the parent authenticates the
/// bundle, and the child verifies the captured execution before any requested
/// restricted branch. Both operations install only captured-input providers.
#[doc(hidden)]
pub fn maybe_run_internal_native_replay_worker() -> Result<bool, String> {
    #[cfg(all(feature = "engine", target_os = "linux"))]
    {
        supervised::maybe_run_worker()
    }
    #[cfg(not(all(feature = "engine", target_os = "linux")))]
    {
        Ok(false)
    }
}

#[cfg(all(feature = "engine", target_os = "linux"))]
mod supervised {
    use super::{
        MAX_NATIVE_REPLAY_PAYLOAD_BYTES, MAX_NATIVE_REPLAY_TIMEOUT_MS,
        NATIVE_REPLAY_OUTCOME_SCHEMA, NativeCounterfactualOutcome, NativeCounterfactualRequest,
        NativeReplayCapture, NativeReplayOutcome,
    };
    use crate::migration::smoke_supervisor::{StopReason, Stream, supervise_with_redirected_input};
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use sha2::{Digest, Sha256};
    use std::io::{self, Read, Seek, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const WORKER_ARG: &str = "__franken-native-replay-worker-v2";
    const REQUEST_SCHEMA: &str = "franken-node/native-replay-worker-request/v2";
    const RESPONSE_SCHEMA: &str = "franken-node/native-replay-worker-response/v2";
    const FRAME_MAGIC: &[u8; 8] = b"FNRPLY2\0";
    const HEADER_BYTES: usize = 8 + 8 + 32;
    // The outer JSON escapes the already serialized capture once more.
    const BODY_LIMIT: usize = 2 * MAX_NATIVE_REPLAY_PAYLOAD_BYTES + 4096;
    const DIAGNOSTIC_LIMIT: usize = 64 * 1024;
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(
        tag = "kind",
        content = "request",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    enum Operation {
        Replay,
        Counterfactual(NativeCounterfactualRequest),
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(
        tag = "kind",
        content = "outcome",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    enum WorkerOutcome {
        Replay(Box<NativeReplayOutcome>),
        Counterfactual(Box<NativeCounterfactualOutcome>),
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        schema_version: String,
        request_id: String,
        capture: NativeReplayCapture,
        operation: Operation,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Response {
        schema_version: String,
        request_id: String,
        request_sha256: String,
        outcome: Result<WorkerOutcome, String>,
    }

    struct FrameWriter {
        bytes: Vec<u8>,
    }

    impl Write for FrameWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > (BODY_LIMIT + HEADER_BYTES).saturating_sub(self.bytes.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native replay protocol frame exceeds its byte limit",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn encode_frame(value: &impl Serialize) -> Result<Vec<u8>, String> {
        let mut writer = FrameWriter {
            bytes: vec![0; HEADER_BYTES],
        };
        serde_json::to_writer(&mut writer, value)
            .map_err(|error| format!("encode native replay protocol frame: {error}"))?;
        let length = writer.bytes.len() - HEADER_BYTES;
        let digest = Sha256::digest(&writer.bytes[HEADER_BYTES..]);
        writer.bytes[..8].copy_from_slice(FRAME_MAGIC);
        writer.bytes[8..16].copy_from_slice(&(length as u64).to_le_bytes());
        writer.bytes[16..HEADER_BYTES].copy_from_slice(&digest);
        Ok(writer.bytes)
    }

    fn body_length(header: &[u8]) -> Result<usize, String> {
        if header.len() < HEADER_BYTES || &header[..8] != FRAME_MAGIC {
            return Err(
                "native replay protocol frame has an invalid version or header".to_string(),
            );
        }
        let length = u64::from_le_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| "native replay protocol length is invalid".to_string())?,
        );
        let length = usize::try_from(length)
            .map_err(|_| "native replay protocol length is not representable".to_string())?;
        if length == 0 || length > BODY_LIMIT {
            return Err("native replay protocol frame exceeds its byte limit".to_string());
        }
        Ok(length)
    }

    fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, String> {
        let length = body_length(frame)?;
        if frame.len() != HEADER_BYTES + length {
            return Err(
                "native replay protocol frame is truncated or has trailing bytes".to_string(),
            );
        }
        let body = &frame[HEADER_BYTES..];
        if frame[16..HEADER_BYTES] != Sha256::digest(body)[..] {
            return Err("native replay protocol frame digest mismatch".to_string());
        }
        serde_json::from_slice(body)
            .map_err(|error| format!("invalid native replay protocol JSON: {error}"))
    }

    fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>, String> {
        let mut header = [0_u8; HEADER_BYTES];
        reader
            .read_exact(&mut header)
            .map_err(|error| format!("read native replay protocol header: {error}"))?;
        let length = body_length(&header)?;
        let mut frame = vec![0_u8; HEADER_BYTES + length];
        frame[..HEADER_BYTES].copy_from_slice(&header);
        reader
            .read_exact(&mut frame[HEADER_BYTES..])
            .map_err(|error| format!("read native replay protocol body: {error}"))?;
        let mut trailing = [0_u8; 1];
        loop {
            match reader.read(&mut trailing) {
                Ok(0) => return Ok(frame),
                Ok(_) => {
                    return Err("native replay protocol request has trailing bytes".to_string());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(format!("read native replay protocol request end: {error}"));
                }
            }
        }
    }

    fn remaining(deadline: Instant) -> Result<Duration, String> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err("native replay timed out before verification completed".to_string())
        } else {
            Ok(remaining)
        }
    }

    pub(super) fn reexecute(
        capture: &NativeReplayCapture,
        timeout: Duration,
    ) -> Result<NativeReplayOutcome, String> {
        match launch(capture, Operation::Replay, timeout)? {
            WorkerOutcome::Replay(outcome) => Ok(*outcome),
            WorkerOutcome::Counterfactual(_) => {
                Err("native replay worker returned another operation's result".to_string())
            }
        }
    }

    pub(super) fn counterfactual(
        capture: &NativeReplayCapture,
        request: &NativeCounterfactualRequest,
        timeout: Duration,
    ) -> Result<NativeCounterfactualOutcome, String> {
        request.validate()?;
        match launch(capture, Operation::Counterfactual(request.clone()), timeout)? {
            WorkerOutcome::Counterfactual(outcome) => Ok(*outcome),
            WorkerOutcome::Replay(_) => {
                Err("native counterfactual worker returned another operation's result".to_string())
            }
        }
    }

    fn launch(
        capture: &NativeReplayCapture,
        operation: Operation,
        timeout: Duration,
    ) -> Result<WorkerOutcome, String> {
        if timeout < Duration::from_millis(1)
            || timeout > Duration::from_millis(MAX_NATIVE_REPLAY_TIMEOUT_MS)
        {
            return Err(format!(
                "native replay timeout must be 1..={MAX_NATIVE_REPLAY_TIMEOUT_MS} milliseconds"
            ));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| "native replay deadline overflow".to_string())?;
        capture.validate()?;
        let request_id = uuid::Uuid::now_v7().to_string();
        let request = Request {
            schema_version: REQUEST_SCHEMA.to_string(),
            request_id: request_id.clone(),
            capture: capture.clone(),
            operation: operation.clone(),
        };
        let frame = encode_frame(&request)?;
        let request_sha256 = hex::encode(Sha256::digest(&frame));
        // A fresh anonymous regular file avoids a blocking pipe writer and
        // leaves no private captured source in a named temporary artifact.
        let mut input = tempfile::tempfile()
            .map_err(|error| format!("stage native replay request: {error}"))?;
        input
            .write_all(&frame)
            .and_then(|()| input.rewind())
            .map_err(|error| format!("write native replay request: {error}"))?;
        drop(frame);
        drop(request);
        remaining(deadline)?;
        let mut command = Command::new("/proc/self/exe");
        command.args([WORKER_ARG, &request_id, &std::process::id().to_string()]);
        supervise(
            &mut command,
            Stdio::from(input),
            &request_id,
            &request_sha256,
            &operation,
            &capture.payload_sha256,
            deadline,
        )
    }

    fn supervise(
        command: &mut Command,
        input: Stdio,
        request_id: &str,
        request_sha256: &str,
        operation: &Operation,
        capture_payload_sha256: &str,
        deadline: Instant,
    ) -> Result<WorkerOutcome, String> {
        let mut stdout = Vec::new();
        let mut diagnostics = 0_usize;
        let completion = supervise_with_redirected_input(
            command,
            deadline,
            DRAIN_TIMEOUT,
            input,
            |_| Ok(()),
            |stream, bytes| match stream {
                Stream::Stdout => {
                    if bytes.len() > (BODY_LIMIT + HEADER_BYTES).saturating_sub(stdout.len()) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "native replay worker stdout exceeds the protocol frame limit",
                        ));
                    }
                    stdout.extend_from_slice(bytes);
                    Ok(())
                }
                Stream::Stderr => {
                    if bytes.len() > DIAGNOSTIC_LIMIT.saturating_sub(diagnostics) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "native replay worker diagnostics exceed the byte limit",
                        ));
                    }
                    diagnostics += bytes.len();
                    Ok(())
                }
            },
        )
        .map_err(|error| format!("native replay supervision failed: {error:#}"))?;
        match completion.reason {
            StopReason::RuntimeTimeout => {
                return Err("native replay timed out; worker was killed and reaped".to_string());
            }
            StopReason::PipeTimeout => {
                return Err(
                    "native replay worker did not close its protocol streams; verification refused"
                        .to_string(),
                );
            }
            StopReason::Exited => {}
        }
        if !completion.status.success() {
            return Err(format!(
                "native replay worker exited without completing verification: {}",
                completion.status
            ));
        }
        // The shared supervisor has proved exit, drained both pipes, and
        // completed cleanup. Never accept a prefix emitted by a live child.
        let response: Response = decode_frame(&stdout)?;
        if response.schema_version != RESPONSE_SCHEMA
            || response.request_id != request_id
            || response.request_sha256 != request_sha256
        {
            return Err("native replay worker response does not match this request".to_string());
        }
        remaining(deadline)?;
        let outcome = response.outcome?;
        match (operation, &outcome) {
            (Operation::Replay, WorkerOutcome::Replay(replayed)) => {
                if replayed.schema_version != NATIVE_REPLAY_OUTCOME_SCHEMA
                    || replayed.matched != replayed.divergences.is_empty()
                {
                    return Err(
                        "native replay worker returned an invalid verification outcome".to_string(),
                    );
                }
            }
            (Operation::Counterfactual(request), WorkerOutcome::Counterfactual(branched)) => {
                branched.validate_for_request(capture_payload_sha256, request)?;
            }
            _ => {
                return Err("native replay worker returned another operation's result".to_string());
            }
        }
        Ok(outcome)
    }

    pub(super) fn maybe_run_worker() -> Result<bool, String> {
        use rustix::process::{Signal, getppid, set_parent_process_death_signal};

        let mut args = std::env::args_os();
        let _ = args.next();
        if args.next().as_deref() != Some(std::ffi::OsStr::new(WORKER_ARG)) {
            return Ok(false);
        }
        let request_id = args
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| "native replay worker requires a request identity".to_string())?;
        uuid::Uuid::parse_str(&request_id)
            .map_err(|_| "native replay worker request identity is invalid".to_string())?;
        let parent_pid = args
            .next()
            .and_then(|value| value.into_string().ok())
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| "native replay worker requires its supervisor PID".to_string())?;
        if args.next().is_some() {
            return Err("native replay worker received unexpected arguments".to_string());
        }
        // Configure this before any replay thread exists, then recheck PPid
        // to close the race where the supervisor died before PR_SET_PDEATHSIG.
        set_parent_process_death_signal(Some(Signal::KILL))
            .map_err(|error| format!("bind native replay worker lifetime: {error}"))?;
        if getppid().map(|pid| pid.as_raw_pid()) != Some(parent_pid) {
            return Err("native replay supervisor exited before worker startup".to_string());
        }
        let frame = read_frame(&mut io::stdin().lock())?;
        let request_sha256 = hex::encode(Sha256::digest(&frame));
        let request: Request = decode_frame(&frame)?;
        if request.schema_version != REQUEST_SCHEMA || request.request_id != request_id {
            return Err("native replay worker request does not match its launch".to_string());
        }
        request.capture.validate()?;
        let outcome = match request.operation {
            Operation::Replay => super::reexecute(&request.capture)
                .map(|outcome| WorkerOutcome::Replay(Box::new(outcome))),
            Operation::Counterfactual(restrictions) => {
                restrictions.validate()?;
                super::counterfactual(&request.capture, &restrictions.denied_capabilities)
                    .map(|outcome| WorkerOutcome::Counterfactual(Box::new(outcome)))
            }
        };
        let response = Response {
            schema_version: RESPONSE_SCHEMA.to_string(),
            request_id,
            request_sha256,
            // Each in-process path validates the complete canonical capture.
            // A counterfactual also verifies the original run before branching;
            // both executions are covered by the parent's single deadline.
            outcome,
        };
        let response = encode_frame(&response)?;
        let stdout = io::stdout();
        let mut output = stdout.lock();
        output
            .write_all(&response)
            .and_then(|()| output.flush())
            .map_err(|error| format!("write native replay worker response: {error}"))?;
        Ok(true)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const REQUEST_ID: &str = "019a0000-0000-7000-8000-000000000001";
        const REQUEST_DIGEST: &str =
            "1111111111111111111111111111111111111111111111111111111111111111";

        fn refusal_response() -> Response {
            Response {
                schema_version: RESPONSE_SCHEMA.to_string(),
                request_id: REQUEST_ID.to_string(),
                request_sha256: REQUEST_DIGEST.to_string(),
                outcome: Err("captured transcript verification refused".to_string()),
            }
        }

        fn shell_fixture(
            script: &str,
            frame: &[u8],
            timeout: Duration,
        ) -> (Result<NativeReplayOutcome, String>, u32) {
            let (outcome, pid) =
                shell_fixture_operation(script, frame, timeout, &Operation::Replay);
            (
                outcome.and_then(|outcome| match outcome {
                    WorkerOutcome::Replay(outcome) => Ok(*outcome),
                    WorkerOutcome::Counterfactual(_) => {
                        Err("replay fixture received a counterfactual result".to_string())
                    }
                }),
                pid,
            )
        }

        fn shell_fixture_operation(
            script: &str,
            frame: &[u8],
            timeout: Duration,
            operation: &Operation,
        ) -> (Result<WorkerOutcome, String>, u32) {
            let work = tempfile::tempdir().expect("create replay process fixture");
            let response = work.path().join("response.bin");
            let pid_path = work.path().join("worker.pid");
            std::fs::write(&response, frame).expect("write bounded response fixture");
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", script, "replay-supervision-fixture"])
                .arg(response)
                .arg(&pid_path);
            let outcome = supervise(
                &mut command,
                Stdio::null(),
                REQUEST_ID,
                REQUEST_DIGEST,
                operation,
                REQUEST_DIGEST,
                Instant::now() + timeout,
            );
            let pid = std::fs::read_to_string(pid_path)
                .expect("the actual fixture process must have started")
                .parse()
                .expect("fixture wrote its process ID");
            (outcome, pid)
        }

        fn completed_replay_outcome() -> NativeReplayOutcome {
            NativeReplayOutcome {
                schema_version: NATIVE_REPLAY_OUTCOME_SCHEMA.to_string(),
                replay_kind: "native_reexecution".to_string(),
                verification_scope: "guest_execution".to_string(),
                module_load_disabled: true,
                matched: true,
                divergences: Vec::new(),
                captured_trace_id: "captured-protocol-fixture".to_string(),
                replay_trace_id: "captured-protocol-fixture".to_string(),
                captured_terminal_state: super::super::NativeReplayTerminalState::Completed,
                replay_terminal_state: super::super::NativeReplayTerminalState::Completed,
                terminal_state_match: true,
                ir3_hash_match: Some(true),
                ir4_witness_match: Some(true),
                execution_value_match: Some(true),
                instruction_count_match: Some(true),
                console_match: true,
                host_effects_match: true,
                nondeterminism_trace_match: Some(true),
                lane_match: Some(true),
                exit_code_match: Some(true),
                exception_value_match: None,
                decisions_match: None,
                policy_comparison_note: "protocol acceptance fixture".to_string(),
            }
        }

        fn counterfactual_protocol_outcome() -> NativeCounterfactualOutcome {
            use super::super::{
                NATIVE_COUNTERFACTUAL_OUTCOME_SCHEMA, NATIVE_COUNTERFACTUAL_SCOPE,
                NativeCounterfactualConsoleEntry, NativeReplayTerminalState,
            };

            let mut baseline = completed_replay_outcome();
            baseline.module_load_disabled = false;
            baseline.decisions_match = Some(true);
            NativeCounterfactualOutcome {
                schema_version: NATIVE_COUNTERFACTUAL_OUTCOME_SCHEMA.to_string(),
                execution_kind: "native_counterfactual".to_string(),
                verification_scope: NATIVE_COUNTERFACTUAL_SCOPE.to_string(),
                capture_payload_sha256: REQUEST_DIGEST.to_string(),
                baseline: baseline.into_policy_equivalence_outcome(),
                denied_capabilities: vec!["fs_write".to_string()],
                retained_declared_capabilities: vec![
                    "fs_read".to_string(),
                    "module_load".to_string(),
                ],
                terminal_state: NativeReplayTerminalState::Completed,
                execution_value: Some("private-protocol-result".to_string()),
                exception_value: None,
                engine_failure: None,
                exit_code: None,
                instructions_executed: Some(10),
                console_output: vec![NativeCounterfactualConsoleEntry {
                    level: "log".to_string(),
                    message: "private-protocol-console".to_string(),
                    instruction_index: 3,
                }],
                captured_host_effects: 2,
                consumed_host_effects: 1,
                unused_original_host_effects: 1,
                console_matches_original: false,
                execution_value_matches_original: Some(false),
                terminal_state_matches_original: true,
                replay_certified: false,
                policy_equivalence_certified: false,
            }
        }

        #[test]
        fn replay_protocol_rejects_tampering_truncation_trailing_and_unknown_fields() {
            let frame = encode_frame(&refusal_response()).unwrap();
            let response: Response = decode_frame(&frame).unwrap();
            assert_eq!(
                response.outcome.unwrap_err(),
                "captured transcript verification refused"
            );

            let mut bad_magic = frame.clone();
            bad_magic[0] ^= 1;
            let mut bad_length = frame.clone();
            bad_length[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            let mut bad_digest = frame.clone();
            bad_digest[16] ^= 1;
            let mut trailing = frame.clone();
            trailing.push(0);
            for invalid in [
                bad_magic,
                bad_length,
                bad_digest,
                trailing,
                frame[..HEADER_BYTES - 1].to_vec(),
                frame[..frame.len() - 1].to_vec(),
            ] {
                assert!(decode_frame::<Response>(&invalid).is_err());
            }
            let mut unknown = serde_json::to_value(refusal_response()).unwrap();
            unknown["unexpected_authority"] = serde_json::json!(true);
            assert!(decode_frame::<Response>(&encode_frame(&unknown).unwrap()).is_err());

            let mut encoded = encode_frame(&refusal_response()).unwrap();
            encoded.push(0);
            assert!(read_frame(&mut encoded.as_slice()).is_err());
        }

        #[test]
        fn replay_supervisor_binds_response_and_preserves_engine_refusal() {
            let script = "printf '%s' \"$$\" > \"$2\"; /bin/cat \"$1\"";
            let frame = encode_frame(&refusal_response()).unwrap();
            let (outcome, pid) = shell_fixture(script, &frame, Duration::from_secs(2));
            assert_eq!(
                outcome.unwrap_err(),
                "captured transcript verification refused"
            );
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());

            for field in ["schema", "request", "digest"] {
                let mut response = refusal_response();
                match field {
                    "schema" => response.schema_version.push_str("-other"),
                    "request" => response.request_id.push_str("-other"),
                    "digest" => response.request_sha256 = "0".repeat(64),
                    _ => unreachable!(),
                }
                let frame = encode_frame(&response).unwrap();
                let (outcome, pid) = shell_fixture(script, &frame, Duration::from_secs(2));
                assert!(outcome.unwrap_err().contains("does not match this request"));
                assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
            }
        }

        #[test]
        fn replay_supervisor_accepts_only_consistent_completed_outcomes() {
            // This exercises the process protocol, not engine equivalence.
            // Actual replay matches are covered by incident CLI integration.
            let expected = completed_replay_outcome();
            let script = "printf '%s' \"$$\" > \"$2\"; /bin/cat \"$1\"";
            let mut response = refusal_response();
            response.outcome = Ok(WorkerOutcome::Replay(Box::new(expected.clone())));
            let frame = encode_frame(&response).unwrap();
            let (outcome, pid) = shell_fixture(script, &frame, Duration::from_secs(2));
            assert_eq!(outcome.unwrap(), expected);
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());

            for invalid in ["schema", "matched", "divergences"] {
                let mut outcome = expected.clone();
                match invalid {
                    "schema" => outcome.schema_version.push_str("-other"),
                    "matched" => outcome.matched = false,
                    "divergences" => outcome.divergences.push("console".to_string()),
                    _ => unreachable!(),
                }
                response.outcome = Ok(WorkerOutcome::Replay(Box::new(outcome)));
                let frame = encode_frame(&response).unwrap();
                let (outcome, pid) = shell_fixture(script, &frame, Duration::from_secs(2));
                assert!(
                    outcome
                        .unwrap_err()
                        .contains("invalid verification outcome")
                );
                assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
            }
        }

        #[test]
        fn counterfactual_request_bounds_and_diagnostics_preserve_private_outputs() {
            for denied_capabilities in [
                Vec::new(),
                vec!["fs_write".to_string(), "fs_write".to_string()],
                vec!["fs:write".to_string()],
                vec![" fs_write".to_string()],
                vec!["fs_write\0".to_string()],
                vec!["a".repeat(65)],
                (0..=super::super::MAX_NATIVE_COUNTERFACTUAL_DENIALS)
                    .map(|index| format!("capability_{index}"))
                    .collect(),
            ] {
                assert!(
                    NativeCounterfactualRequest {
                        denied_capabilities
                    }
                    .validate()
                    .is_err()
                );
            }
            NativeCounterfactualRequest {
                denied_capabilities: vec!["fs_write".to_string(), "network_egress".to_string()],
            }
            .validate()
            .unwrap();

            let observation = counterfactual_protocol_outcome();
            let diagnostic = format!("{observation:?} {:?}", observation.console_output[0]);
            assert!(!diagnostic.contains("private-protocol-result"));
            assert!(!diagnostic.contains("private-protocol-console"));
            let exported = serde_json::to_string(&observation).unwrap();
            assert!(exported.contains("private-protocol-result"));
            assert!(exported.contains("private-protocol-console"));
        }

        #[test]
        fn counterfactual_supervisor_binds_restrictions_baseline_and_observations() {
            // These are process-protocol fixtures. Native branch execution is
            // independently exercised by engine and incident CLI tests.
            let expected = counterfactual_protocol_outcome();
            let operation = Operation::Counterfactual(NativeCounterfactualRequest {
                denied_capabilities: expected.denied_capabilities.clone(),
            });
            let script = "printf '%s' \"$$\" > \"$2\"; /bin/cat \"$1\"";
            for mutation in 0..14 {
                let mut observation = expected.clone();
                match mutation {
                    0 => {}
                    1 => observation.schema_version.push_str("-other"),
                    2 => observation.capture_payload_sha256 = "0".repeat(64),
                    3 => observation.denied_capabilities = vec!["network_egress".to_string()],
                    4 => observation.baseline.decisions_match = Some(false),
                    5 => observation.baseline.module_load_disabled = true,
                    6 => observation.replay_certified = true,
                    7 => observation.policy_equivalence_certified = true,
                    8 => observation.unused_original_host_effects += 1,
                    9 => observation.execution_value = None,
                    10 => observation.exception_value = Some("not an exception".to_string()),
                    11 => observation.console_output[0].level = "unknown".to_string(),
                    12 => observation
                        .retained_declared_capabilities
                        .push("fs_write".to_string()),
                    13 => observation.terminal_state_matches_original = false,
                    _ => unreachable!(),
                }
                let mut response = refusal_response();
                response.outcome = Ok(WorkerOutcome::Counterfactual(Box::new(observation)));
                let frame = encode_frame(&response).unwrap();
                let (result, pid) =
                    shell_fixture_operation(script, &frame, Duration::from_secs(2), &operation);
                if mutation == 0 {
                    let WorkerOutcome::Counterfactual(observation) = result.unwrap() else {
                        panic!("expected the requested counterfactual operation");
                    };
                    assert_eq!(*observation, expected);
                } else {
                    assert!(result.is_err(), "mutation {mutation}");
                }
                assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
            }
        }

        #[test]
        fn counterfactual_supervisor_rejects_operation_confusion_and_unfinished_workers() {
            let observation = counterfactual_protocol_outcome();
            let operation = Operation::Counterfactual(NativeCounterfactualRequest {
                denied_capabilities: observation.denied_capabilities.clone(),
            });
            let mut response = refusal_response();
            response.outcome = Ok(WorkerOutcome::Counterfactual(Box::new(observation)));
            let frame = encode_frame(&response).unwrap();
            let script = "printf '%s' \"$$\" > \"$2\"; /bin/cat \"$1\"";
            let (result, pid) = shell_fixture(script, &frame, Duration::from_secs(2));
            assert!(result.unwrap_err().contains("another operation's result"));
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());

            let script = "printf '%s' \"$$\" > \"$2\"; /bin/cat \"$1\"; while :; do :; done";
            let (result, pid) =
                shell_fixture_operation(script, &frame, Duration::from_millis(100), &operation);
            assert!(result.unwrap_err().contains("timed out"));
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());

            response.outcome = Ok(WorkerOutcome::Replay(Box::new(completed_replay_outcome())));
            let frame = encode_frame(&response).unwrap();
            let script = "printf '%s' \"$$\" > \"$2\"; /bin/cat \"$1\"";
            let (result, pid) =
                shell_fixture_operation(script, &frame, Duration::from_secs(2), &operation);
            assert!(result.unwrap_err().contains("another operation's result"));
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        }

        #[test]
        fn replay_supervisor_reaps_timeout_abort_and_invalid_output() {
            let frame = encode_frame(&refusal_response()).unwrap();
            for (script, timeout, expected) in [
                (
                    "printf '%s' \"$$\" > \"$2\"; /bin/cat \"$1\"; while :; do :; done",
                    Duration::from_millis(100),
                    "timed out",
                ),
                (
                    "printf '%s' \"$$\" > \"$2\"; ulimit -c 0; kill -ABRT \"$$\"",
                    Duration::from_secs(2),
                    "exited without completing verification",
                ),
                (
                    "printf '%s' \"$$\" > \"$2\"; /bin/cat \"$1\"; exit 7",
                    Duration::from_secs(2),
                    "exited without completing verification",
                ),
                (
                    "printf '%s' \"$$\" > \"$2\"; /bin/cat \"$1\"; printf trailing",
                    Duration::from_secs(2),
                    "truncated or has trailing bytes",
                ),
                (
                    "printf '%s' \"$$\" > \"$2\"; printf short",
                    Duration::from_secs(2),
                    "invalid version or header",
                ),
                (
                    "printf '%s' \"$$\" > \"$2\"; /bin/cat /dev/zero",
                    Duration::from_secs(2),
                    "stdout exceeds the protocol frame limit",
                ),
                (
                    "printf '%s' \"$$\" > \"$2\"; /bin/cat /dev/zero >&2",
                    Duration::from_secs(2),
                    "diagnostics exceed the byte limit",
                ),
            ] {
                let started = Instant::now();
                let (outcome, pid) = shell_fixture(script, &frame, timeout);
                let error =
                    outcome.expect_err("incomplete verification must never yield a verdict");
                assert!(error.contains(expected), "{expected}: {error}");
                assert!(
                    started.elapsed() < Duration::from_secs(6),
                    "deadline and cleanup must remain bounded"
                );
                assert!(
                    !std::path::Path::new(&format!("/proc/{pid}")).exists(),
                    "replay fixture leader must have been reaped"
                );
            }
        }
    }
}

#[cfg(feature = "engine")]
pub use engine::{CapturedModuleSources, CapturingProcessSpawnProvider};

#[cfg(feature = "engine")]
mod engine {
    use base64::Engine as _;
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::extensions::artifact_contract::EffectiveCapabilityCeiling;
    use crate::ops::engine_dispatcher::PublisherHostAuthority;
    use crate::supply_chain::module_resolution_graph::file_resolution::source_graph::{
        CapturedModuleGraph, capsule, engine_resolver::CapturedEngineResolver,
    };
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{
        ConsoleEntry, ConsoleLevel, InterpreterConfig, InterpreterError, LaneChoice,
    };
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::deterministic_replay::NondeterminismTrace;
    use frankenengine_engine::evidence_ledger::RuntimeEvidenceAuthority;
    use frankenengine_engine::execution_orchestrator::{
        ExecutionOrchestrator, ExtensionPackage, LossMatrixPreset, OrchestratorConfig,
        OrchestratorError, OrchestratorResult, ProcessSpawnAttemptAuthority,
    };
    use frankenengine_engine::ir_contract::{ExecutionOutcome, Ir4Module};
    use frankenengine_engine::lowering_pipeline::AmbientAuthorityGrant;
    use frankenengine_engine::module_resolver::{
        CapabilityPolicyHook, ExecutionModuleResolver, ModuleResolver, ModuleSyntax,
        ResolutionContext, ResolutionOutcome,
    };
    use frankenengine_engine::parser::ParserOptions;
    use frankenengine_engine::runtime_config::RuntimeConfig;
    use frankenengine_engine::security_epoch::SecurityEpoch;
    use frankenengine_extension_host::host_effect_journal::{
        HostEffectJournalAttemptRecord, HostEffectJournalEntry, InMemoryHostEffectJournal,
    };
    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoControl, HostIoError, HostIoExceptionProvenance, HostIoOutcome,
        HostIoProvider, HostIoRecorder, HostIoRequest, InMemoryHostIoTranscript,
    };
    use frankenengine_extension_host::process_spawn::{
        ProcessSpawnCapability, ProcessSpawnControl, ProcessSpawnError, ProcessSpawnOutcome,
        ProcessSpawnProvider, ProcessSpawnRequest, ProcessSpawnResponse,
    };

    use super::*;

    const REPLAY_STACK_BYTES: usize = 64 * 1024 * 1024;
    const MAX_PROCESS_PREPARATION_ENTRIES: usize = 4096;
    const MAX_PROCESS_PREPARATION_BYTES: usize = MAX_NATIVE_REPLAY_PAYLOAD_BYTES / 2;

    /// Exact observations retained before the original frozen graph is consumed.
    /// Its pins gain authority only through the containing authenticated capture.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CapturedModuleSources {
        capsule_base64: String,
        capsule_digest: String,
        graph_input_hash: String,
    }

    impl std::fmt::Debug for CapturedModuleSources {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CapturedModuleSources")
                .field("sources", &"[redacted]")
                .finish_non_exhaustive()
        }
    }

    impl CapturedModuleSources {
        pub(crate) fn capture(graph: &CapturedModuleGraph) -> Result<Self, String> {
            let encoded = capsule::encode(graph)
                .map_err(|_| "cannot encode frozen replay module sources".to_string())?;
            // Bound expansion before allocating base64. The complete payload,
            // including the entry source and settings, has its own tighter cap.
            if encoded.bytes().len() > MAX_NATIVE_REPLAY_PAYLOAD_BYTES / 4 * 3 {
                return Err("frozen replay module sources exceed the capture byte budget".into());
            }
            Ok(Self {
                capsule_base64: base64::engine::general_purpose::STANDARD.encode(encoded.bytes()),
                capsule_digest: encoded.digest().to_owned(),
                graph_input_hash: graph.report().input_hash.clone(),
            })
        }

        fn restore(
            &self,
            package: &ExtensionPackage,
            settings: &CapturedOrchestratorSettings,
        ) -> Result<(ResolutionOutcome, ExecutionModuleResolver, bool), String> {
            if self.capsule_base64.len() > MAX_NATIVE_REPLAY_PAYLOAD_BYTES {
                return Err("frozen replay module sources exceed the capture byte budget".into());
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&self.capsule_base64)
                .map_err(|_| "invalid frozen replay module encoding".to_string())?;
            if base64::engine::general_purpose::STANDARD.encode(&bytes) != self.capsule_base64 {
                return Err("noncanonical frozen replay module encoding".into());
            }
            let graph = capsule::replay(&bytes, &self.capsule_digest)
                .map_err(|_| "invalid frozen replay module capsule".to_string())?;
            let configured_conditions: BTreeSet<_> = settings.module_conditions.iter().collect();
            let captured_conditions: BTreeSet<_> = graph
                .report()
                .options
                .additional_conditions
                .iter()
                .collect();
            if graph.report().options.conditions.is_some()
                || configured_conditions != captured_conditions
            {
                return Err(
                    "frozen replay package conditions differ from the captured settings".into(),
                );
            }
            let root = package
                .module_root
                .as_deref()
                .map(std::path::Path::new)
                .filter(|root| root.is_absolute())
                .ok_or_else(|| {
                    "frozen replay requires its original absolute module origin".to_string()
                })?;
            if package.source_file.as_deref() != root.join(&graph.report().entrypoint).to_str() {
                return Err("frozen replay entrypoint differs from the captured package".into());
            }
            let resolver = Arc::new(
                CapturedEngineResolver::new_with_parser_options(
                    graph,
                    &self.graph_input_hash,
                    settings.parser_options.clone(),
                )
                .map_err(|_| "invalid frozen replay source graph".to_string())?,
            );
            let policy = Arc::new(CapabilityPolicyHook::new(
                package
                    .capabilities
                    .iter()
                    .filter_map(|capability| RuntimeCapability::from_tag_str(capability))
                    .collect(),
            ));
            let admission_context = ResolutionContext::new(
                "native-module-admission",
                "native-module-admission",
                &settings.policy_id,
            );
            let entry = resolver
                .resolve(
                    &resolver.entry_request(),
                    &admission_context,
                    policy.as_ref(),
                )
                .map_err(|_| "frozen replay entrypoint policy admission failed".to_string())?;
            let uses_closed_world_lowering_only_builtins = resolver
                .authorize_closed_world_lowering_only_entry(&admission_context, policy.as_ref())
                .map_err(|_| "frozen replay lowering-only builtin admission failed".to_string())?;
            let commonjs = entry.module.record.syntax == ModuleSyntax::CommonJs;
            let goal = if commonjs {
                ParseGoal::Script
            } else {
                ParseGoal::Module
            };
            if entry.module.record.source != package.source
                || commonjs != settings.commonjs_entry
                || goal != settings.parse_goal
            {
                return Err(
                    "frozen replay prepared source or syntax differs from the captured execution"
                        .into(),
                );
            }
            let runtime = resolver
                .execution_resolver(root, policy)
                .map_err(|_| "cannot restore frozen replay module resolver".to_string())?;
            Ok((entry, runtime, uses_closed_world_lowering_only_builtins))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum CapturedProcessPreparation {
        Preflight {
            request: ProcessSpawnRequest,
            outcome: Result<(), ProcessSpawnError>,
        },
        Prepare {
            request: ProcessSpawnRequest,
            outcome: Result<ProcessSpawnRequest, ProcessSpawnError>,
        },
    }

    impl CapturedProcessPreparation {
        fn request(&self) -> &ProcessSpawnRequest {
            match self {
                Self::Preflight { request, .. } | Self::Prepare { request, .. } => request,
            }
        }

        fn is_preflight(&self) -> bool {
            matches!(self, Self::Preflight { .. })
        }
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum ProcessPreparationObservation<'a> {
        Preflight {
            request: &'a ProcessSpawnRequest,
            outcome: &'a Result<(), ProcessSpawnError>,
        },
        Prepare {
            request: &'a ProcessSpawnRequest,
            outcome: &'a Result<ProcessSpawnRequest, ProcessSpawnError>,
        },
    }

    #[derive(Debug, Default)]
    struct ProcessPreparationState {
        entries: Vec<CapturedProcessPreparation>,
        encoded_bytes: usize,
        error: Option<String>,
    }

    /// Transparent capture around the already authenticated product provider.
    /// This never grants process authority or changes the live provider's result.
    /// Preparation is captured rather than reimplementing signed alias, shell,
    /// and request-limit policy in the replay engine.
    #[derive(Debug)]
    pub struct CapturingProcessSpawnProvider {
        inner: Arc<dyn ProcessSpawnProvider>,
        state: Mutex<ProcessPreparationState>,
    }

    impl CapturingProcessSpawnProvider {
        pub fn new(inner: Arc<dyn ProcessSpawnProvider>) -> Self {
            Self {
                inner,
                state: Mutex::new(ProcessPreparationState::default()),
            }
        }

        fn record(&self, observation: ProcessPreparationObservation<'_>) {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            if state.error.is_some() {
                return;
            }
            // Serialize borrowed inputs through a bounded writer before cloning
            // anything guest-controlled into retained preparation evidence.
            let mut writer = BoundedCaptureWriter(Vec::new());
            if serde_json::to_writer(&mut writer, &observation).is_err() {
                state.error =
                    Some("process preparation exceeds the capture byte budget".to_string());
                return;
            }
            let entry: CapturedProcessPreparation = match serde_json::from_slice(&writer.0) {
                Ok(entry) => entry,
                Err(_) => {
                    state.error =
                        Some("process preparation could not be captured exactly".to_string());
                    return;
                }
            };
            if let Some(previous) = state.entries.iter().find(|previous| {
                previous.is_preflight() == entry.is_preflight()
                    && previous.request() == entry.request()
            }) {
                if previous != &entry {
                    state.error = Some(
                        "process preparation changed for an identical request during capture"
                            .to_string(),
                    );
                }
                return;
            }
            if state.entries.len() == MAX_PROCESS_PREPARATION_ENTRIES
                || writer.0.len()
                    > MAX_PROCESS_PREPARATION_BYTES.saturating_sub(state.encoded_bytes)
            {
                state.error = Some("process preparation exceeds the capture budget".to_string());
                return;
            }
            state.encoded_bytes += writer.0.len();
            state.entries.push(entry);
        }

        fn snapshot(&self) -> Result<Vec<CapturedProcessPreparation>, String> {
            let state = self
                .state
                .lock()
                .map_err(|_| "process preparation capture was interrupted".to_string())?;
            if let Some(error) = &state.error {
                return Err(error.clone());
            }
            Ok(state.entries.clone())
        }
    }

    impl ProcessSpawnProvider for CapturingProcessSpawnProvider {
        fn name(&self) -> &str {
            self.inner.name()
        }

        fn preflight_request(
            &self,
            request: &ProcessSpawnRequest,
        ) -> Result<(), ProcessSpawnError> {
            // Keep preflight allocation-free and free of state mutation. A
            // denial here has no journal/preparation record; replay will refuse
            // its unknown request rather than invent the missing observation.
            self.inner.preflight_request(request)
        }

        fn prepare_request(
            &self,
            request: &ProcessSpawnRequest,
        ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
            let outcome = self.inner.prepare_request(request);
            // The authenticated native provider's preflight is side-effect-free.
            // Observe its exact answers here, after the engine has admitted and
            // reserved the original request, without allocating in preflight.
            let original_preflight = self.inner.preflight_request(request);
            self.record(ProcessPreparationObservation::Preflight {
                request,
                outcome: &original_preflight,
            });
            if let Ok(prepared) = &outcome {
                let prepared_preflight = self.inner.preflight_request(prepared);
                self.record(ProcessPreparationObservation::Preflight {
                    request: prepared,
                    outcome: &prepared_preflight,
                });
            }
            self.record(ProcessPreparationObservation::Prepare {
                request,
                outcome: &outcome,
            });
            outcome
        }

        fn perform(
            &self,
            request: &ProcessSpawnRequest,
            granted: &[ProcessSpawnCapability],
        ) -> ProcessSpawnOutcome {
            self.inner.perform(request, granted)
        }

        fn perform_controlled(
            &self,
            request: &ProcessSpawnRequest,
            granted: &[ProcessSpawnCapability],
            control: Arc<dyn ProcessSpawnControl>,
        ) -> ProcessSpawnOutcome {
            self.inner.perform_controlled(request, granted, control)
        }

        fn cleanup_handle(&self, handle: &str) -> ProcessSpawnOutcome {
            self.inner.cleanup_handle(handle)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedProcessReplay {
        preparation: Vec<CapturedProcessPreparation>,
        journal: Vec<HostEffectJournalEntry>,
    }

    impl CapturedProcessReplay {
        fn capture(
            provider: Option<&CapturingProcessSpawnProvider>,
            journal: &[HostEffectJournalEntry],
        ) -> Result<Option<Self>, String> {
            match provider {
                Some(provider) => Ok(Some(Self {
                    preparation: provider.snapshot()?,
                    journal: journal.to_vec(),
                })),
                None if journal
                    .iter()
                    .any(|entry| matches!(entry, HostEffectJournalEntry::ProcessSpawn { .. })) =>
                {
                    Err(
                        "native replay process effects require captured request preparation"
                            .to_string(),
                    )
                }
                None => Ok(None),
            }
        }

        fn validate(&self, host_io: &[(HostIoRequest, HostIoOutcome)]) -> Result<(), String> {
            if self.preparation.len() > MAX_PROCESS_PREPARATION_ENTRIES {
                return Err("native replay process preparation has too many entries".to_string());
            }
            let mut encoded_bytes = 0_usize;
            for (index, entry) in self.preparation.iter().enumerate() {
                if self.preparation[..index].iter().any(|previous| {
                    previous.is_preflight() == entry.is_preflight()
                        && previous.request() == entry.request()
                }) {
                    return Err("native replay process preparation repeats a request".to_string());
                }
                let mut writer = BoundedCaptureWriter(Vec::new());
                serde_json::to_writer(&mut writer, entry).map_err(|_| {
                    "native replay process preparation exceeds its byte budget".to_string()
                })?;
                encoded_bytes = encoded_bytes.saturating_add(writer.0.len());
                if encoded_bytes > MAX_PROCESS_PREPARATION_BYTES {
                    return Err(
                        "native replay process preparation exceeds its byte budget".to_string()
                    );
                }
            }
            let recorded_host_io: Vec<_> = self
                .journal
                .iter()
                .filter_map(|entry| match entry {
                    HostEffectJournalEntry::HostIo { request, outcome } => {
                        Some((request.clone(), outcome.clone()))
                    }
                    HostEffectJournalEntry::ProcessSpawn { .. } => None,
                })
                .collect();
            if recorded_host_io != host_io {
                return Err(
                    "native replay global journal disagrees with its host-I/O transcript"
                        .to_string(),
                );
            }
            Ok(())
        }
    }

    /// Carries captured preparation only. The ordered engine journal supplies
    /// every effect outcome; no implementation here can access the host.
    ///
    /// Replay alone retains a one-bit verification diagnostic on a missing
    /// preflight observation. This deliberately departs from the general
    /// provider preflight purity convention: the engine makes such denials
    /// catchable before journal access, so otherwise a guest could conceal an
    /// unrecorded request. The bit never changes any subsequent provider answer
    /// and is read only after execution. Rejection neither clones nor hashes
    /// the unknown input, allocates a diagnostic string, or touches the host.
    #[derive(Debug)]
    struct CapturedReplayProcessProvider {
        preparation: Vec<CapturedProcessPreparation>,
        diverged: AtomicBool,
    }

    impl CapturedReplayProcessProvider {
        fn new(preparation: Vec<CapturedProcessPreparation>) -> Self {
            Self {
                preparation,
                diverged: AtomicBool::new(false),
            }
        }

        fn refuse(&self) -> ProcessSpawnError {
            self.diverged.store(true, Ordering::Release);
            ProcessSpawnError::Denied {
                // The detailed diagnostic is produced by verify after the
                // engine stops; an oversized request cannot allocate it here.
                reason: String::new(),
            }
        }

        fn verify(&self) -> Result<(), String> {
            if self.diverged.load(Ordering::Acquire) {
                return Err("native replay process preparation diverged, even if the guest caught its error".to_string());
            }
            Ok(())
        }
    }

    impl ProcessSpawnProvider for CapturedReplayProcessProvider {
        fn name(&self) -> &str {
            "native-replay-no-live-process"
        }

        fn preflight_request(
            &self,
            request: &ProcessSpawnRequest,
        ) -> Result<(), ProcessSpawnError> {
            match self.preparation.iter().find_map(|entry| match entry {
                CapturedProcessPreparation::Preflight {
                    request: expected,
                    outcome,
                } if expected == request => Some(outcome.clone()),
                _ => None,
            }) {
                Some(outcome) => outcome,
                None => Err(self.refuse()),
            }
        }

        fn prepare_request(
            &self,
            request: &ProcessSpawnRequest,
        ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
            match self.preparation.iter().find_map(|entry| match entry {
                CapturedProcessPreparation::Prepare {
                    request: expected,
                    outcome,
                } if expected == request => Some(outcome.clone()),
                _ => None,
            }) {
                Some(outcome) => outcome,
                None => Err(self.refuse()),
            }
        }

        fn perform(
            &self,
            _request: &ProcessSpawnRequest,
            _granted: &[ProcessSpawnCapability],
        ) -> ProcessSpawnOutcome {
            Err(self.refuse())
        }

        fn perform_controlled(
            &self,
            _request: &ProcessSpawnRequest,
            _granted: &[ProcessSpawnCapability],
            _control: Arc<dyn ProcessSpawnControl>,
        ) -> ProcessSpawnOutcome {
            Err(self.refuse())
        }

        fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
            Err(self.refuse())
        }
    }

    fn is_default_sandbox_policy(
        policy: &frankenengine_engine::containment_executor::SandboxPolicy,
    ) -> bool {
        *policy == frankenengine_engine::containment_executor::SandboxPolicy::default()
    }

    /// Every serializable setting of the actual execution orchestrator.
    /// A shared work pool is not serializable authority and is refused.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedOrchestratorSettings {
        loss_matrix_preset: LossMatrixPreset,
        force_lane: Option<LaneChoice>,
        #[serde(default, skip_serializing_if = "is_default_sandbox_policy")]
        sandbox_policy: frankenengine_engine::containment_executor::SandboxPolicy,
        drain_deadline_ticks: u64,
        cell_close_budget_ms: u64,
        max_concurrent_sagas: usize,
        epoch: SecurityEpoch,
        parse_goal: ParseGoal,
        commonjs_entry: bool,
        parser_options: ParserOptions,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        module_conditions: Vec<String>,
        auto_size_register_window: bool,
        trace_id_prefix: String,
        policy_id: String,
    }

    impl CapturedOrchestratorSettings {
        fn capture(config: &OrchestratorConfig) -> Result<Self, String> {
            if config.work_pool.is_some() {
                return Err(
                    "native replay capture does not support a shared execution work pool"
                        .to_string(),
                );
            }
            crate::config::validate_module_condition_names(&config.module_conditions)
                .map_err(|error| error.to_string())?;
            Ok(Self {
                loss_matrix_preset: config.loss_matrix_preset,
                force_lane: config.force_lane,
                sandbox_policy: config.sandbox_policy.clone(),
                drain_deadline_ticks: config.drain_deadline_ticks,
                cell_close_budget_ms: config.cell_close_budget_ms,
                max_concurrent_sagas: config.max_concurrent_sagas,
                epoch: config.epoch,
                parse_goal: config.parse_goal,
                commonjs_entry: config.commonjs_entry,
                parser_options: config.parser_options.clone(),
                module_conditions: config
                    .module_conditions
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                auto_size_register_window: config.auto_size_register_window,
                trace_id_prefix: config.trace_id_prefix.clone(),
                policy_id: config.policy_id.clone(),
            })
        }

        fn restore(&self) -> OrchestratorConfig {
            OrchestratorConfig {
                loss_matrix_preset: self.loss_matrix_preset,
                force_lane: self.force_lane,
                sandbox_policy: self.sandbox_policy.clone(),
                work_pool: None,
                drain_deadline_ticks: self.drain_deadline_ticks,
                cell_close_budget_ms: self.cell_close_budget_ms,
                max_concurrent_sagas: self.max_concurrent_sagas,
                epoch: self.epoch,
                parse_goal: self.parse_goal,
                commonjs_entry: self.commonjs_entry,
                parser_options: self.parser_options.clone(),
                module_conditions: self.module_conditions.clone(),
                auto_size_register_window: self.auto_size_register_window,
                trace_id_prefix: self.trace_id_prefix.clone(),
                policy_id: self.policy_id.clone(),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedExecution {
        trace_id: String,
        ir4_witness: Ir4Module,
        execution_value: String,
        instructions_executed: u64,
        console_output: Vec<ConsoleEntry>,
        nondeterminism_trace: NondeterminismTrace,
        lane: LaneChoice,
        exit_code: Option<i32>,
        decisions: serde_json::Value,
    }

    const MAX_FAILURE_CONTEXT_MODULES: usize = 1024;
    const MAX_FAILURE_CONTEXT_MODULE_PATH_BYTES: usize = 4096;

    fn is_lower_hex_sha256(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Exact interpreter failure prefix authenticated by `franken_engine`
    /// (`ExecutionOrchestrator::last_failed_execution_replay_context`).
    /// Distinct from a completed execution: never carries an IR4 completion
    /// witness or finalized policy decision.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedFailureContext {
        ir3_hash: String,
        instructions_executed: u64,
        dropped_console_entries: u64,
        randomness_transcript: NondeterminismTrace,
        imported_module_hashes: BTreeMap<String, String>,
    }

    impl CapturedFailureContext {
        fn validate(&self) -> Result<(), String> {
            if !is_lower_hex_sha256(&self.ir3_hash) {
                return Err(
                    "native failure replay context ir3_hash must be 64-character lowercase hex"
                        .to_string(),
                );
            }
            self.randomness_transcript
                .validate_for_replay()
                .map_err(|error| {
                    format!("invalid captured failure randomness transcript: {error}")
                })?;
            if self.imported_module_hashes.len() > MAX_FAILURE_CONTEXT_MODULES {
                return Err(
                    "native failure replay context imported_module_hashes exceeds its entry bound"
                        .to_string(),
                );
            }
            for (path, digest) in &self.imported_module_hashes {
                if path.is_empty()
                    || path.len() > MAX_FAILURE_CONTEXT_MODULE_PATH_BYTES
                    || path.chars().any(char::is_control)
                {
                    return Err(
                        "native failure replay context module path must be non-empty, bounded, and control-free"
                            .to_string(),
                    );
                }
                if !is_lower_hex_sha256(digest) {
                    return Err(
                        "native failure replay context module digest must be 64-character lowercase hex"
                            .to_string(),
                    );
                }
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedGuestException {
        trace_id: String,
        exception_value: String,
        console_output: Vec<ConsoleEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure_context: Option<CapturedFailureContext>,
    }

    /// Only engine-owned, reproducible stopping conditions. Do not classify
    /// failures by a diagnostic substring or an exit code: guest exceptions
    /// and external watchdogs can contain the same words or numbers.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum EngineFailureReason {
        CapabilityDenied {
            capability: String,
        },
        InstructionBudgetExhausted {
            budget: u64,
        },
        ConsoleBudgetExceeded {
            entries: usize,
            max_entries: usize,
            bytes: usize,
            max_bytes: usize,
        },
    }

    fn engine_failure_reason(error: &InterpreterError) -> Option<EngineFailureReason> {
        match error {
            InterpreterError::CapabilityDenied { capability } => {
                Some(EngineFailureReason::CapabilityDenied {
                    capability: capability.clone(),
                })
            }
            InterpreterError::BudgetExhausted { budget, .. } => {
                Some(EngineFailureReason::InstructionBudgetExhausted { budget: *budget })
            }
            InterpreterError::ConsoleBudgetExceeded {
                entries,
                max_entries,
                bytes,
                max_bytes,
            } => Some(EngineFailureReason::ConsoleBudgetExceeded {
                entries: *entries,
                max_entries: *max_entries,
                bytes: *bytes,
                max_bytes: *max_bytes,
            }),
            _ => None,
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedEngineFailure {
        trace_id: String,
        reason: EngineFailureReason,
        /// Preserve the complete native diagnostic as well as its typed cause.
        /// Budget diagnostics retain the engine's observed work count; that is
        /// not a completed IR4 witness or a finalized nondeterminism trace.
        diagnostic: String,
        console_output: Vec<ConsoleEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure_context: Option<CapturedFailureContext>,
    }

    impl CapturedEngineFailure {
        fn validate(&self, payload: &NativeReplayPayload) -> Result<(), String> {
            if self.trace_id.trim().is_empty()
                || self.diagnostic.is_empty()
                || self.diagnostic.len() > 4096
            {
                return Err(
                    "native engine-failure capture requires a trace and bounded diagnostic"
                        .to_string(),
                );
            }
            match &self.reason {
                EngineFailureReason::CapabilityDenied { capability } => {
                    let denied = RuntimeCapability::from_tag_str(capability).ok_or_else(|| {
                        "native engine-failure capture has an unrecognized denied capability"
                            .to_string()
                    })?;
                    // Replay strips ModuleLoad. That artificial restriction
                    // cannot stand in for an original denial of a granted cap.
                    if payload.module_sources.is_none()
                        && denied == RuntimeCapability::ModuleLoad
                        && payload.package.capabilities.iter().any(|capability| {
                            RuntimeCapability::from_tag_str(capability).as_ref() == Some(&denied)
                        })
                    {
                        return Err("native replay cannot certify a denial of originally granted module loading".to_string());
                    }
                }
                EngineFailureReason::InstructionBudgetExhausted { budget } => {
                    if *budget != payload.runtime.execution.deterministic_budget
                        && *budget != payload.runtime.execution.throughput_budget
                    {
                        return Err("captured instruction limit does not belong to either captured execution profile".to_string());
                    }
                }
                EngineFailureReason::ConsoleBudgetExceeded {
                    entries,
                    max_entries,
                    bytes,
                    max_bytes,
                } => {
                    let profiles = [
                        InterpreterConfig::deterministic_from_config(&payload.runtime.execution),
                        InterpreterConfig::throughput_from_config(&payload.runtime.execution),
                    ];
                    if !profiles.iter().any(|profile| {
                        *max_entries == profile.max_console_entries
                            && *max_bytes == profile.max_console_bytes
                    }) {
                        return Err(
                            "captured console limits do not belong to either captured execution profile"
                                .to_string(),
                        );
                    }
                    if entries <= max_entries && bytes <= max_bytes {
                        return Err(
                            "captured console stop does not exceed an execution limit".to_string()
                        );
                    }
                }
            }
            if let Some(context) = &self.failure_context {
                context.validate()?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "terminal_state", rename_all = "snake_case")]
    enum CapturedAttempt {
        Completed(Box<CapturedExecution>),
        UncaughtException(CapturedGuestException),
        EngineFailure(CapturedEngineFailure),
    }

    fn execution_decisions(result: &OrchestratorResult) -> Result<serde_json::Value, String> {
        serde_json::to_value((
            &result.posterior,
            &result.risk_state,
            &result.containment_action,
            result.expected_loss_millionths,
            &result.action_decision,
            &result.adaptive_routing_decision,
        ))
        .map_err(|error| format!("serialize native replay decisions: {error}"))
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NativeReplayPayload {
        package: ExtensionPackage,
        orchestrator: CapturedOrchestratorSettings,
        runtime: RuntimeConfig,
        ambient_authority: AmbientAuthorityGrant,
        host_io_exception_provenance: HostIoExceptionProvenance,
        process_argv: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clock_epoch_ms: Option<i64>,
        host_effect_transcript: Vec<(HostIoRequest, HostIoOutcome)>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        process: Option<CapturedProcessReplay>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        module_sources: Option<CapturedModuleSources>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability_ceiling: Option<EffectiveCapabilityCeiling>,
        expected: CapturedAttempt,
    }

    /// Re-derive publisher scope and quota decisions before using the tape.
    /// Every replay consumes this exact sequence; a counterfactual may consume
    /// only its exact prefix. A fresh gate makes invocation budgets independent
    /// of earlier verification attempts and preserves admitted failed attempts.
    fn validate_scoped_transcript(
        ceiling: &EffectiveCapabilityCeiling,
        entries: &[(HostIoRequest, HostIoOutcome)],
        capabilities: &[String],
    ) -> Result<(), String> {
        let authority = PublisherHostAuthority::new(ceiling.clone())
            .map_err(|_| "captured publisher host authority is not enforceable".to_string())?;
        let capabilities: BTreeSet<_> = capabilities
            .iter()
            .filter_map(|tag| RuntimeCapability::from_tag_str(tag))
            .collect();
        for (request, outcome) in entries {
            // Derive the required grant from the typed request, never from a
            // captured list that could omit the capability being checked.
            let required = request.required_capability();
            let runtime_capability = match required {
                HostIoCapability::FsRead => RuntimeCapability::FsRead,
                HostIoCapability::FsWrite => RuntimeCapability::FsWrite,
                HostIoCapability::NetworkSend | HostIoCapability::NetworkRecv => {
                    RuntimeCapability::NetworkEgress
                }
                HostIoCapability::RandomRead => RuntimeCapability::RandomRead,
                HostIoCapability::EnvRead => RuntimeCapability::EnvRead,
            };
            let grants = [required];
            let granted = if capabilities.contains(&runtime_capability) {
                grants.as_slice()
            } else {
                &[]
            };
            let agrees = match authority.authorize(request, granted) {
                Err(denial) => outcome.as_ref().err() == Some(&denial),
                Ok(()) => !matches!(outcome,
                    Err(HostIoError::Denied { reason })
                        if reason.starts_with("publisher_authority:")),
            };
            if !agrees {
                return Err(
                    "captured host outcome contradicts publisher scope or invocation policy"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    /// Process journals also contain pre-provider refusals and engine-owned
    /// compensation. Preparation is a deterministic map, not a per-attempt
    /// tape: conflicting results for one request are refused during capture.
    /// Only actual guest provider attempts consume the signed per-run quota.
    /// Ambiguous original/prepared aliases fail closed instead of making an
    /// admitted failed attempt look like a free preparation refusal. A request
    /// observed both at dynamic IFC refusal and provider preparation is also
    /// ambiguous: the journal does not retain the original argument labels.
    /// Replay rechecks dynamic IFC and consumes the exact global journal.
    fn validate_scoped_process_transcript(
        ceiling: &EffectiveCapabilityCeiling,
        process: &CapturedProcessReplay,
        capabilities: &[String],
    ) -> Result<(), String> {
        let authority = PublisherHostAuthority::new(ceiling.clone())
            .map_err(|_| "captured publisher process authority is not enforceable".to_string())?;
        let has_grant = capabilities.iter().any(|tag| {
            RuntimeCapability::from_tag_str(tag) == Some(RuntimeCapability::ProcessSpawn)
        });
        let grants = [ProcessSpawnCapability::Spawn];
        let granted = if has_grant { grants.as_slice() } else { &[] };
        let publisher_denial = |outcome: &ProcessSpawnOutcome| {
            matches!(outcome, Err(ProcessSpawnError::Denied { reason })
                if reason.starts_with("publisher_authority:"))
        };
        let key = |request: &ProcessSpawnRequest| {
            serde_json::to_vec(request)
                .map_err(|_| "captured process request cannot be indexed".to_string())
        };
        let mut preflights = std::collections::BTreeMap::new();
        let mut preparations = std::collections::BTreeMap::new();
        for entry in &process.preparation {
            let duplicate = match entry {
                CapturedProcessPreparation::Preflight { request, outcome } => {
                    preflights.insert(key(request)?, outcome).is_some()
                }
                CapturedProcessPreparation::Prepare { request, outcome } => {
                    preparations.insert(key(request)?, outcome).is_some()
                }
            };
            if duplicate {
                return Err("captured process preparation repeats an admission key".into());
            }
        }
        let mut prepared_requests = BTreeSet::new();
        let mut preparation_failures: std::collections::BTreeMap<&[u8], &ProcessSpawnError> =
            std::collections::BTreeMap::new();
        for (original, outcome) in &preparations {
            if !matches!(preflights.get(original), Some(Ok(()))) {
                return Err("captured process preparation lacks its original preflight".into());
            }
            match outcome {
                Err(failure) => {
                    preparation_failures.insert(original.as_slice(), failure);
                }
                Ok(prepared) => {
                    let prepared_key = key(prepared)?;
                    match preflights.get(&prepared_key) {
                        Some(Ok(())) => {
                            prepared_requests.insert(prepared_key);
                        }
                        Some(Err(failure)) => {
                            preparation_failures.insert(original.as_slice(), failure);
                        }
                        None => {
                            return Err("captured prepared process request lacks preflight".into());
                        }
                    }
                }
            }
        }
        for entry in &process.journal {
            let HostEffectJournalEntry::ProcessSpawn { request, outcome } = entry else {
                continue;
            };
            if matches!(request, ProcessSpawnRequest::Cleanup { .. }) {
                if publisher_denial(outcome)
                    || outcome.as_ref().is_ok_and(|response| {
                        !matches!(response, ProcessSpawnResponse::Cleaned { .. })
                    })
                {
                    return Err("captured cleanup contradicts engine-owned compensation".into());
                }
                continue;
            }
            let request_key = key(request)?;
            // A genuine IFC refusal precedes preparation. A public request
            // could otherwise consume a fabricated FlowPolicyBlocked outcome
            // from the replay journal without invoking the publisher guard.
            // Refuse mixed identities rather than allowing that quota escape.
            if matches!(outcome, Err(ProcessSpawnError::FlowPolicyBlocked)) {
                if preparations.contains_key(&request_key)
                    || prepared_requests.contains(&request_key)
                {
                    return Err("captured process request ambiguously aliases an IFC refusal and provider attempt".into());
                }
                continue;
            }
            if let Some(failure) = preparation_failures.get(request_key.as_slice()) {
                if prepared_requests.contains(&request_key) {
                    return Err("captured process request ambiguously aliases a preparation refusal and provider attempt".into());
                }
                if outcome.as_ref().err() != Some(*failure) || publisher_denial(outcome) {
                    return Err("captured preparation invents publisher quota admission".into());
                }
                continue;
            }
            if !prepared_requests.contains(&request_key) {
                return Err("captured process attempt lacks successful request preparation".into());
            }
            let agrees = match authority.authorize_process(request, granted) {
                Err(denial) => outcome.as_ref().err() == Some(denial.as_ref()),
                Ok(()) => !publisher_denial(outcome),
            };
            if !agrees {
                return Err(
                    "captured process outcome contradicts publisher scope or invocation policy"
                        .into(),
                );
            }
        }
        Ok(())
    }

    /// Admit only typed, bounded environment outcomes from the authenticated
    /// transcript. This never assembles a live environment or grants EnvRead.
    /// Keep validation diagnostics independent of private names and values.
    fn validate_environment_transcript(
        entries: &[(HostIoRequest, HostIoOutcome)],
        capabilities: &[String],
    ) -> Result<(), String> {
        use frankenengine_extension_host::host_io::{
            ENVIRONMENT_VALUE_MAX_BYTES, HostIoResponse, validate_environment_name,
        };

        let granted = capabilities.iter().any(|capability| {
            RuntimeCapability::from_tag_str(capability) == Some(RuntimeCapability::EnvRead)
        });
        for (request, outcome) in entries {
            match request {
                HostIoRequest::EnvRead { name } => {
                    if !granted {
                        return Err(
                            "captured environment read requires explicit EnvRead authority"
                                .to_string(),
                        );
                    }
                    validate_environment_name(name).map_err(|_| {
                        "captured environment request has an invalid or oversized name".to_string()
                    })?;
                    match outcome {
                        Ok(HostIoResponse::EnvRead { value }) => {
                            if value.as_ref().is_some_and(|value| {
                                value.len() > ENVIRONMENT_VALUE_MAX_BYTES || value.contains('\0')
                            }) {
                                return Err(
                                    "captured environment response has an invalid or oversized value"
                                        .to_string(),
                                );
                            }
                        }
                        Ok(_) => {
                            return Err(
                                "captured environment request has a mismatched response kind"
                                    .to_string(),
                            );
                        }
                        // Denials and other failures are observations, never
                        // converted to an absent variable or an empty string.
                        Err(_) => {}
                    }
                }
                _ if matches!(outcome, Ok(HostIoResponse::EnvRead { .. })) => {
                    return Err(
                        "captured environment response has a mismatched request kind".to_string(),
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    impl NativeReplayPayload {
        fn validate(&self) -> Result<(), String> {
            crate::config::validate_module_condition_names(&self.orchestrator.module_conditions)
                .map_err(|error| format!("invalid captured package conditions: {error}"))?;
            self.runtime
                .validate()
                .map_err(|error| format!("invalid captured runtime settings: {error}"))?;
            match self.ambient_authority {
                AmbientAuthorityGrant::DenyAll => {}
                AmbientAuthorityGrant::TrustedProcessShape => {
                    // This is an exhaustive match over supported engine grants:
                    // adding another grant requires a replay policy decision.
                    // The engine supplies argv from set_process_argv, a fixed
                    // linux platform and synthetic pid; it never reads ambient
                    // host metadata for this grant. Bound the one supplied
                    // input before constructing a replay engine as well as
                    // bounding its serialized envelope in encode_capture.
                    let argv_bytes = self.process_argv.iter().try_fold(0_usize, |total, arg| {
                        total.checked_add(arg.len()).ok_or_else(|| {
                            "native replay process argument length overflowed".to_string()
                        })?;
                        Ok::<_, String>(total + arg.len())
                    })?;
                    if argv_bytes > MAX_NATIVE_REPLAY_PAYLOAD_BYTES {
                        return Err(
                            "native replay process arguments exceed the capture byte budget"
                                .to_string(),
                        );
                    }
                }
            }
            if self.package.source.trim().is_empty() || self.package.extension_id.trim().is_empty()
            {
                return Err(
                    "native replay source and extension identity must not be empty".to_string(),
                );
            }
            for capability in &self.package.capabilities {
                match RuntimeCapability::from_tag_str(capability) {
                    Some(_) => {}
                    None => return Err(format!("unrecognized captured capability {capability}")),
                }
            }
            if let Some(sources) = &self.module_sources {
                sources.restore(&self.package, &self.orchestrator)?;
            }
            validate_environment_transcript(
                &self.host_effect_transcript,
                &self.package.capabilities,
            )?;
            if let Some(ceiling) = &self.capability_ceiling {
                validate_scoped_transcript(
                    ceiling,
                    &self.host_effect_transcript,
                    &self.package.capabilities,
                )?;
            }
            let has_process_authority = self.package.capabilities.iter().any(|capability| {
                RuntimeCapability::from_tag_str(capability) == Some(RuntimeCapability::ProcessSpawn)
            });
            if has_process_authority != self.process.is_some() {
                return Err("native replay process authority requires its exact preparation and ordered journal".to_string());
            }
            if self.host_io_exception_provenance != HostIoExceptionProvenance::ProviderInternal {
                return Err(
                    "native replay exception provenance differs from its original capture mode"
                        .to_string(),
                );
            }
            if let Some(process) = &self.process {
                process.validate(&self.host_effect_transcript)?;
                if let Some(ceiling) = &self.capability_ceiling {
                    validate_scoped_process_transcript(
                        ceiling,
                        process,
                        &self.package.capabilities,
                    )?;
                }
            }
            match &self.expected {
                CapturedAttempt::Completed(expected) => {
                    if expected.ir4_witness.outcome != ExecutionOutcome::Completed {
                        return Err(
                            "native replay requires a finalized successful engine attempt"
                                .to_string(),
                        );
                    }
                    if self.module_sources.is_none()
                        && expected
                            .ir4_witness
                            .hostcall_decisions
                            .iter()
                            .any(|decision| {
                                RuntimeCapability::from_tag_str(&decision.capability.0)
                                    == Some(RuntimeCapability::ModuleLoad)
                            })
                    {
                        return Err(
                            "native replay does not support runtime module loading; module source capture is required"
                                .to_string(),
                        );
                    }
                    if expected.ir4_witness.instructions_executed != expected.instructions_executed
                    {
                        return Err(
                            "native replay witness instruction count does not match the captured result"
                                .to_string(),
                        );
                    }
                    expected
                        .nondeterminism_trace
                        .validate_for_replay()
                        .map_err(|error| {
                            format!("invalid captured nondeterminism trace: {error}")
                        })?;
                    if expected.trace_id.trim().is_empty() {
                        return Err("native replay requires a captured execution trace".to_string());
                    }
                }
                CapturedAttempt::UncaughtException(expected) => {
                    if expected.trace_id.trim().is_empty() {
                        return Err(
                            "native failure replay requires a captured execution trace".to_string()
                        );
                    }
                    if let Some(context) = &expected.failure_context {
                        context.validate()?;
                    }
                    // The thrown value may legitimately be the empty string.
                    // Only the authenticated recorder boundary, not its length,
                    // establishes that this is a real failed guest attempt.
                }
                CapturedAttempt::EngineFailure(expected) => expected.validate(self)?,
            }
            Ok(())
        }
    }

    /// A replay safety backstop with no access to any host-effect mechanism.
    /// The provenance declaration concerns only its constant refusal text.
    #[derive(Debug)]
    pub struct CapturedReplayHostIo;

    impl HostIoProvider for CapturedReplayHostIo {
        fn name(&self) -> &str {
            "native-replay-no-live-host-io"
        }

        fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
            HostIoExceptionProvenance::ProviderInternal
        }

        fn perform(
            &self,
            _request: &HostIoRequest,
            _granted: &[HostIoCapability],
        ) -> HostIoOutcome {
            Err(HostIoError::Denied {
                reason: "native replay cannot perform live host I/O".to_string(),
            })
        }

        fn perform_controlled(
            &self,
            request: &HostIoRequest,
            granted: &[HostIoCapability],
            _control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            self.perform(request, granted)
        }
    }

    /// An authenticated transcript produced by the product's bounded provider.
    /// Preserve its original exception provenance while delegating exact request
    /// matching, poisoning, exhaustion, and finalization to the engine recorder.
    #[derive(Debug)]
    pub struct CapturedReplayRecorder {
        transcript: InMemoryHostIoTranscript,
    }

    impl CapturedReplayRecorder {
        pub fn new(entries: Vec<(HostIoRequest, HostIoOutcome)>) -> Self {
            Self {
                transcript: InMemoryHostIoTranscript::replaying(entries),
            }
        }
    }

    impl HostIoRecorder for CapturedReplayRecorder {
        fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
            HostIoExceptionProvenance::ProviderInternal
        }

        fn begin_execution(&self) -> Result<(), HostIoError> {
            self.transcript.begin_execution()
        }

        fn replay(&self, request: &HostIoRequest) -> Option<HostIoOutcome> {
            self.transcript.replay(request)
        }

        fn record(&self, request: &HostIoRequest, outcome: &HostIoOutcome) {
            self.transcript.record(request, outcome);
        }

        fn finish_execution(&self) -> Result<Vec<(HostIoRequest, HostIoOutcome)>, HostIoError> {
            self.transcript.finish_execution()
        }

        fn recorded_entries(&self) -> Vec<(HostIoRequest, HostIoOutcome)> {
            self.transcript.recorded_entries()
        }
    }

    /// Supplies only the exact next authenticated input to a speculative branch.
    /// This is deliberately a provider with no live mechanisms, paired with a
    /// normal recording recorder. The engine's exact-replay recorder contract
    /// still requires exhaustion; only this separate counterfactual input source
    /// may leave an original suffix unused.
    struct CounterfactualHostIo {
        entries: Vec<(HostIoRequest, HostIoOutcome)>,
        state: Mutex<CounterfactualHostIoState>,
    }

    #[derive(Default)]
    struct CounterfactualHostIoState {
        consumed: usize,
        refusal: Option<&'static str>,
    }

    impl std::fmt::Debug for CounterfactualHostIo {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("CounterfactualHostIo")
                .field("captured_entries", &self.entries.len())
                .finish_non_exhaustive()
        }
    }

    impl CounterfactualHostIo {
        fn new(entries: Vec<(HostIoRequest, HostIoOutcome)>) -> Self {
            Self {
                entries,
                state: Mutex::new(CounterfactualHostIoState::default()),
            }
        }

        fn refuse(&self, reason: &'static str) -> HostIoError {
            let mut state = self.state.lock().expect("counterfactual input state mutex");
            let reason = *state.refusal.get_or_insert(reason);
            HostIoError::Denied {
                reason: reason.to_string(),
            }
        }

        fn verify(&self, observed: &[(HostIoRequest, HostIoOutcome)]) -> Result<usize, String> {
            let state = self.state.lock().expect("counterfactual input state mutex");
            if let Some(reason) = state.refusal {
                return Err(reason.to_string());
            }
            if observed != &self.entries[..state.consumed] {
                return Err(
                    "native counterfactual effect evidence differs from its consumed captured-input prefix"
                        .to_string(),
                );
            }
            Ok(state.consumed)
        }
    }

    impl HostIoProvider for CounterfactualHostIo {
        fn name(&self) -> &str {
            "native-counterfactual-captured-inputs-only"
        }

        fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
            HostIoExceptionProvenance::ProviderInternal
        }

        fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
            let mut state = self.state.lock().expect("counterfactual input state mutex");
            if let Some(reason) = state.refusal {
                return Err(HostIoError::Denied {
                    reason: reason.to_string(),
                });
            }
            if !granted.contains(&request.required_capability()) {
                state.refusal =
                    Some("native counterfactual input request exceeds the attenuated capabilities");
                return Err(HostIoError::CapabilityMissing {
                    capability: request.required_capability(),
                });
            }
            let Some((expected_request, outcome)) = self.entries.get(state.consumed) else {
                let reason = "native counterfactual requires an uncaptured host input";
                state.refusal = Some(reason);
                return Err(HostIoError::Denied {
                    reason: reason.to_string(),
                });
            };
            if expected_request != request {
                let reason =
                    "native counterfactual host request differs from the next captured input";
                state.refusal = Some(reason);
                return Err(HostIoError::Denied {
                    reason: reason.to_string(),
                });
            }
            state.consumed += 1;
            outcome.clone()
        }

        fn perform_controlled(
            &self,
            request: &HostIoRequest,
            granted: &[HostIoCapability],
            control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            if control.checkpoint().is_err() {
                return Err(self.refuse("native counterfactual host input was cancelled"));
            }
            // No DNS, filesystem, network, environment, random, or process API
            // is reachable here, including when an input is absent or changed.
            let outcome = self.perform(request, granted);
            if control.checkpoint().is_err() {
                return Err(self.refuse("native counterfactual host input was cancelled"));
            }
            outcome
        }
    }

    struct BoundedCaptureWriter(Vec<u8>);

    impl Write for BoundedCaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_NATIVE_REPLAY_PAYLOAD_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other(format!(
                    "native replay payload exceeds {MAX_NATIVE_REPLAY_PAYLOAD_BYTES} bytes"
                )));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn encode_capture(payload: &NativeReplayPayload) -> Result<NativeReplayCapture, String> {
        let mut writer = BoundedCaptureWriter(Vec::new());
        serde_json::to_writer(&mut writer, payload)
            .map_err(|error| format!("serialize native replay capture: {error}"))?;
        let payload_sha256 = hex::encode(Sha256::digest(&writer.0));
        let payload_json = String::from_utf8(writer.0)
            .map_err(|error| format!("native replay capture was not UTF-8: {error}"))?;
        Ok(NativeReplayCapture {
            schema_version: if payload.capability_ceiling.is_some() {
                NATIVE_REPLAY_SCOPED_CAPTURE_SCHEMA
            } else {
                NATIVE_REPLAY_CAPTURE_SCHEMA
            }
            .to_string(),
            payload_json,
            payload_sha256,
        })
    }

    fn decode_capture(capture: &NativeReplayCapture) -> Result<NativeReplayPayload, String> {
        capture.validate()?;
        let payload: NativeReplayPayload = serde_json::from_str(&capture.payload_json)
            .map_err(|error| format!("invalid native replay payload: {error}"))?;
        // Reject schema downgrades, absent v4 authority, duplicate keys, ignored
        // fields, and omitted settings before captured code can reach execution.
        let canonical = encode_capture(&payload)?;
        if canonical.schema_version != capture.schema_version
            || canonical.payload_json != capture.payload_json
        {
            return Err("native replay payload is not the complete canonical capture".to_string());
        }
        Ok(payload)
    }

    struct ObservedFailure {
        attempt: CapturedAttempt,
        host_effect_transcript: Vec<(HostIoRequest, HostIoOutcome)>,
        host_effect_journal: Vec<HostEffectJournalEntry>,
    }

    /// Both guest exceptions and typed engine stops require the same finalized
    /// recorder and cell. Retained console output alone is never evidence that
    /// an interrupted, cancelled, or externally killed attempt is replayable.
    fn observe_failure(
        orchestrator: &ExecutionOrchestrator,
        error: &OrchestratorError,
    ) -> Result<ObservedFailure, String> {
        let primary = error.primary_error();
        if !matches!(
            primary,
            OrchestratorError::Interpreter(
                InterpreterError::UncaughtException { .. }
                    | InterpreterError::CapabilityDenied { .. }
                    | InterpreterError::BudgetExhausted { .. }
                    | InterpreterError::ConsoleBudgetExceeded { .. }
            )
        ) {
            return Err(
                "native failure replay requires a certified guest exception, capability denial, instruction-budget stop, or console-budget stop"
                    .to_string(),
            );
        }
        let failure = error.post_cell_failure().ok_or_else(|| {
            "native failure replay requires execution-cell cleanup evidence".to_string()
        })?;
        if !failure.cleanup.close_succeeded()
            || !failure.additional_errors.is_empty()
            || failure.uncommitted_evidence_chain.is_some()
            || failure.containment_saga_failure.is_some()
        {
            return Err(
                "native failure replay refuses incomplete recorder, evidence, or cell cleanup"
                    .to_string(),
            );
        }
        let trace_id = orchestrator
            .last_failed_trace_id()
            .filter(|trace_id| !trace_id.trim().is_empty())
            .ok_or_else(|| {
                "native failure replay requires a finalized effect boundary and trace".to_string()
            })?;
        if failure.cleanup.trace_id != trace_id {
            return Err(
                "native failure replay cleanup does not belong to the failed trace".to_string(),
            );
        }
        let cell_transcript = failure
            .cleanup
            .cell_execution_transcript
            .as_ref()
            .ok_or_else(|| {
                "native failure replay requires a certified execution-cell transcript".to_string()
            })?;
        if cell_transcript.authority.trace_id != trace_id
            || cell_transcript.authority.cell_id != failure.cleanup.cell_id
        {
            return Err(
                "native failure replay cell transcript does not belong to the failed trace"
                    .to_string(),
            );
        }
        cell_transcript.verify().map_err(|error| {
            format!("native failure replay cell transcript is invalid: {error}")
        })?;

        let entries = orchestrator.last_failed_host_effect_journal();
        let records = orchestrator.last_failed_host_effect_journal_records();
        if entries.len() != records.len()
            || records
                .iter()
                .zip(entries)
                .enumerate()
                .any(|(index, (record, entry))| {
                    !matches!(record,
                HostEffectJournalAttemptRecord::Completed { sequence, entry: recorded }
                    if usize::try_from(*sequence) == Ok(index) && recorded == entry)
                })
        {
            return Err(
                "native failure replay refuses an incomplete or discontinuous effect journal"
                    .to_string(),
            );
        }
        let host_effect_transcript: Vec<(HostIoRequest, HostIoOutcome)> = entries
            .iter()
            .filter_map(|entry| match entry {
                HostEffectJournalEntry::HostIo { request, outcome } => {
                    Some((request.clone(), outcome.clone()))
                }
                HostEffectJournalEntry::ProcessSpawn { .. } => None,
            })
            .collect();
        let console_output = orchestrator.last_failed_console_output();
        let failure_context = match orchestrator.last_failed_execution_replay_context() {
            Some(ctx) => {
                if ctx.console_output != console_output
                    || ctx.host_effect_transcript != host_effect_transcript
                {
                    return Err(
                        "native failure replay context disagrees with finalized console or host-effect sinks"
                            .to_string(),
                    );
                }
                let captured = CapturedFailureContext {
                    ir3_hash: ctx.ir3_hash.to_hex(),
                    instructions_executed: ctx.instructions_executed,
                    dropped_console_entries: ctx.dropped_console_entries,
                    randomness_transcript: ctx.randomness_transcript.clone(),
                    imported_module_hashes: ctx.imported_module_hashes.clone(),
                };
                captured.validate()?;
                Some(captured)
            }
            None => None,
        };
        let attempt = match primary {
            OrchestratorError::Interpreter(InterpreterError::UncaughtException { value }) => {
                CapturedAttempt::UncaughtException(CapturedGuestException {
                    trace_id: trace_id.to_string(),
                    exception_value: value.clone(),
                    console_output,
                    failure_context,
                })
            }
            OrchestratorError::Interpreter(error) => {
                CapturedAttempt::EngineFailure(CapturedEngineFailure {
                    trace_id: trace_id.to_string(),
                    reason: engine_failure_reason(error)
                        .ok_or_else(|| "unsupported native failure reason".to_string())?,
                    diagnostic: error.to_string(),
                    console_output,
                    failure_context,
                })
            }
            _ => return Err("unsupported native failure boundary".to_string()),
        };
        Ok(ObservedFailure {
            attempt,
            host_effect_transcript,
            host_effect_journal: entries.to_vec(),
        })
    }

    impl NativeReplayCapture {
        /// Bind the exact verified publisher ceiling used by the live provider.
        /// Called before the enclosing run statement is signed. Neither this
        /// method nor the ceiling authenticates an otherwise unsigned capture.
        pub(crate) fn with_capability_ceiling(
            self,
            ceiling: &EffectiveCapabilityCeiling,
        ) -> Result<Self, String> {
            let mut payload = decode_capture(&self)?;
            if payload.capability_ceiling.is_some() {
                return Err("native replay publisher authority is already bound".to_string());
            }
            payload.capability_ceiling = Some(ceiling.clone());
            payload.validate()?;
            encode_capture(&payload)
        }

        /// Capture the source actually passed to the native engine and its
        /// finalized response, before either can be discarded or reread.
        /// The product caller supplies the same ambient grant and argv it gave
        /// the orchestrator, and must have installed its SandboxedHostIo plus
        /// transparent policy decorators. Process capture uses the same bounded
        /// filesystem provider; replay binds its exact authenticated I/O
        /// transcript into the globally ordered journal before lowering.
        /// A process-shape grant supplies only captured arguments and the
        /// engine's deterministic metadata shape.
        #[allow(clippy::too_many_arguments)]
        pub fn from_execution(
            package: &ExtensionPackage,
            orchestrator_config: &OrchestratorConfig,
            runtime_config: &RuntimeConfig,
            ambient_authority: AmbientAuthorityGrant,
            process_argv: &[String],
            process_preparation: Option<&CapturingProcessSpawnProvider>,
            module_sources: Option<&CapturedModuleSources>,
            result: &OrchestratorResult,
        ) -> Result<Self, String> {
            Self::from_execution_with_clock_epoch(
                package,
                orchestrator_config,
                runtime_config,
                ambient_authority,
                process_argv,
                None,
                process_preparation,
                module_sources,
                result,
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn from_execution_with_clock_epoch(
            package: &ExtensionPackage,
            orchestrator_config: &OrchestratorConfig,
            runtime_config: &RuntimeConfig,
            ambient_authority: AmbientAuthorityGrant,
            process_argv: &[String],
            clock_epoch_ms: Option<i64>,
            process_preparation: Option<&CapturingProcessSpawnProvider>,
            module_sources: Option<&CapturedModuleSources>,
            result: &OrchestratorResult,
        ) -> Result<Self, String> {
            if process_preparation.is_none() && !result.host_effect_journal.is_empty() {
                return Err(
                    "native replay global journal requires captured process preparation"
                        .to_string(),
                );
            }
            if result.extension_id != package.extension_id
                || result.epoch != orchestrator_config.epoch
            {
                return Err(
                    "native replay result does not belong to the captured execution".to_string(),
                );
            }
            let payload = NativeReplayPayload {
                package: package.clone(),
                orchestrator: CapturedOrchestratorSettings::capture(orchestrator_config)?,
                runtime: runtime_config.clone(),
                ambient_authority,
                host_io_exception_provenance: HostIoExceptionProvenance::ProviderInternal,
                process_argv: process_argv.to_vec(),
                clock_epoch_ms,
                host_effect_transcript: result.host_effect_transcript.clone(),
                process: CapturedProcessReplay::capture(
                    process_preparation,
                    &result.host_effect_journal,
                )?,
                module_sources: module_sources.cloned(),
                capability_ceiling: None,
                expected: CapturedAttempt::Completed(Box::new(CapturedExecution {
                    trace_id: result.trace_id.clone(),
                    ir4_witness: result.ir4_witness.clone(),
                    execution_value: result.execution_value.clone(),
                    instructions_executed: result.instructions_executed,
                    console_output: result.console_output.clone(),
                    nondeterminism_trace: result.nondeterminism_trace.clone(),
                    lane: result.lane,
                    exit_code: result.exit_code,
                    decisions: execution_decisions(result)?,
                })),
            };
            payload.validate()?;
            encode_capture(&payload)
        }

        /// Capture a certified guest exception or engine stop and its finalized
        /// effect prefix.
        /// No successful IR4 witness or finalized nondeterminism trace is
        /// manufactured for an attempt the engine reported as failed.
        /// As with from_execution, Some process_preparation requires the exact
        /// capturing process provider and the product's bounded I/O provider.
        // Keep product-admitted source/settings/provider inputs separate from
        // the live orchestrator and error that independently establish the
        // finalized failure evidence; no caller-built payload substitutes for
        // those observations. The exemption is confined to this boundary.
        #[allow(clippy::too_many_arguments)]
        pub fn from_failed_execution(
            package: &ExtensionPackage,
            orchestrator_config: &OrchestratorConfig,
            runtime_config: &RuntimeConfig,
            ambient_authority: AmbientAuthorityGrant,
            process_argv: &[String],
            process_preparation: Option<&CapturingProcessSpawnProvider>,
            module_sources: Option<&CapturedModuleSources>,
            orchestrator: &ExecutionOrchestrator,
            error: &OrchestratorError,
        ) -> Result<Self, String> {
            Self::from_failed_execution_with_clock_epoch(
                package,
                orchestrator_config,
                runtime_config,
                ambient_authority,
                process_argv,
                None,
                process_preparation,
                module_sources,
                orchestrator,
                error,
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn from_failed_execution_with_clock_epoch(
            package: &ExtensionPackage,
            orchestrator_config: &OrchestratorConfig,
            runtime_config: &RuntimeConfig,
            ambient_authority: AmbientAuthorityGrant,
            process_argv: &[String],
            clock_epoch_ms: Option<i64>,
            process_preparation: Option<&CapturingProcessSpawnProvider>,
            module_sources: Option<&CapturedModuleSources>,
            orchestrator: &ExecutionOrchestrator,
            error: &OrchestratorError,
        ) -> Result<Self, String> {
            Self::from_finalized_failure_with_clock_epoch(
                package,
                orchestrator_config,
                runtime_config,
                ambient_authority,
                process_argv,
                clock_epoch_ms,
                process_preparation,
                module_sources,
                orchestrator,
                error,
            )
        }

        /// Capture a finalized guest exception, native capability denial,
        /// instruction-budget stop, or console-budget stop. This entrypoint never
        /// infers a failure's cause from a log line, guest value, watchdog exit,
        /// or wall-clock time.
        /// Authenticate the containing record before replaying these inputs.
        /// Process-provider and source/settings contracts match from_execution.
        #[allow(clippy::too_many_arguments)]
        pub fn from_finalized_failure(
            package: &ExtensionPackage,
            orchestrator_config: &OrchestratorConfig,
            runtime_config: &RuntimeConfig,
            ambient_authority: AmbientAuthorityGrant,
            process_argv: &[String],
            process_preparation: Option<&CapturingProcessSpawnProvider>,
            module_sources: Option<&CapturedModuleSources>,
            orchestrator: &ExecutionOrchestrator,
            error: &OrchestratorError,
        ) -> Result<Self, String> {
            Self::from_finalized_failure_with_clock_epoch(
                package,
                orchestrator_config,
                runtime_config,
                ambient_authority,
                process_argv,
                None,
                process_preparation,
                module_sources,
                orchestrator,
                error,
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn from_finalized_failure_with_clock_epoch(
            package: &ExtensionPackage,
            orchestrator_config: &OrchestratorConfig,
            runtime_config: &RuntimeConfig,
            ambient_authority: AmbientAuthorityGrant,
            process_argv: &[String],
            clock_epoch_ms: Option<i64>,
            process_preparation: Option<&CapturingProcessSpawnProvider>,
            module_sources: Option<&CapturedModuleSources>,
            orchestrator: &ExecutionOrchestrator,
            error: &OrchestratorError,
        ) -> Result<Self, String> {
            let ObservedFailure {
                attempt: expected,
                host_effect_transcript,
                host_effect_journal: journal,
            } = observe_failure(orchestrator, error)?;
            let payload = NativeReplayPayload {
                package: package.clone(),
                orchestrator: CapturedOrchestratorSettings::capture(orchestrator_config)?,
                runtime: runtime_config.clone(),
                ambient_authority,
                host_io_exception_provenance: HostIoExceptionProvenance::ProviderInternal,
                process_argv: process_argv.to_vec(),
                clock_epoch_ms,
                host_effect_transcript,
                process: CapturedProcessReplay::capture(process_preparation, &journal)?,
                module_sources: module_sources.cloned(),
                capability_ceiling: None,
                expected,
            };
            payload.validate()?;
            encode_capture(&payload)
        }
    }

    fn replay_policy_comparison_note(process_replay: bool, frozen_modules: bool) -> String {
        let mut note = if frozen_modules {
            "Replay retains the original declared capabilities and resolves modules only from authenticated frozen observations. decisions_match remains informational; matching execution is not an independent original-policy certificate."
        } else {
            "Replay disables runtime module loading. Its changed declared-capability population can change Bayesian and containment decisions; decisions_match is informational and is excluded from the guest execution verdict."
        }.to_string();
        if process_replay {
            note.push_str(" The original process-capture run and ordered replay journal both use the engine's conservative Unknown exception floor. Capture mode can deny flows the ordinary live provider permits. IR, execution, and effect comparisons remain exact; no captured witness or replay outcome is relabeled to obtain a match.");
        }
        note
    }

    fn compare_execution(
        payload: &NativeReplayPayload,
        replayed: &OrchestratorResult,
    ) -> Result<NativeReplayOutcome, String> {
        let CapturedAttempt::Completed(expected) = &payload.expected else {
            return Err("completed execution comparison requires a completed capture".to_string());
        };
        let mut outcome = NativeReplayOutcome {
            schema_version: NATIVE_REPLAY_OUTCOME_SCHEMA.to_string(),
            replay_kind: "native_reexecution".to_string(),
            verification_scope: "guest_execution".to_string(),
            module_load_disabled: payload.module_sources.is_none(),
            matched: false,
            divergences: Vec::new(),
            captured_trace_id: expected.trace_id.clone(),
            replay_trace_id: replayed.trace_id.clone(),
            captured_terminal_state: NativeReplayTerminalState::Completed,
            replay_terminal_state: NativeReplayTerminalState::Completed,
            terminal_state_match: true,
            ir3_hash_match: Some(
                expected.ir4_witness.executed_ir3_hash == replayed.ir4_witness.executed_ir3_hash,
            ),
            ir4_witness_match: Some(expected.ir4_witness == replayed.ir4_witness),
            execution_value_match: Some(expected.execution_value == replayed.execution_value),
            instruction_count_match: Some(
                expected.instructions_executed == replayed.instructions_executed,
            ),
            console_match: expected.console_output == replayed.console_output,
            host_effects_match: payload.host_effect_transcript == replayed.host_effect_transcript
                && payload
                    .process
                    .as_ref()
                    .is_none_or(|process| process.journal == replayed.host_effect_journal),
            nondeterminism_trace_match: Some(
                expected.nondeterminism_trace == replayed.nondeterminism_trace,
            ),
            lane_match: Some(expected.lane == replayed.lane),
            exit_code_match: Some(expected.exit_code == replayed.exit_code),
            exception_value_match: None,
            decisions_match: Some(expected.decisions == execution_decisions(replayed)?),
            policy_comparison_note: replay_policy_comparison_note(
                payload.process.is_some(),
                payload.module_sources.is_some(),
            ),
        };
        for (matches, subject) in [
            (outcome.ir3_hash_match == Some(true), "executed IR3"),
            (
                outcome.ir4_witness_match == Some(true),
                "IR4 execution witness",
            ),
            (
                outcome.execution_value_match == Some(true),
                "execution value",
            ),
            (
                outcome.instruction_count_match == Some(true),
                "instruction count",
            ),
            (outcome.console_match, "console output"),
            (outcome.host_effects_match, "host-effect transcript"),
            (
                outcome.nondeterminism_trace_match == Some(true),
                "nondeterminism trace",
            ),
            (outcome.lane_match == Some(true), "execution lane"),
            (outcome.exit_code_match == Some(true), "guest exit code"),
            (
                expected.trace_id == replayed.trace_id,
                "execution trace identity",
            ),
        ] {
            if !matches {
                outcome.divergences.push(format!(
                    "re-executed {subject} differs from the captured run"
                ));
            }
        }
        outcome.matched = outcome.divergences.is_empty();
        Ok(outcome)
    }

    struct TerminalObservation {
        terminal_state: NativeReplayTerminalState,
        trace_id: String,
        exception_value: Option<String>,
        engine_failure: Option<(EngineFailureReason, String)>,
        console_output: Vec<ConsoleEntry>,
        failure_context: Option<CapturedFailureContext>,
        host_effect_transcript: Vec<(HostIoRequest, HostIoOutcome)>,
        host_effect_journal: Vec<HostEffectJournalEntry>,
    }

    impl TerminalObservation {
        fn completed(result: OrchestratorResult) -> Self {
            Self {
                terminal_state: NativeReplayTerminalState::Completed,
                trace_id: result.trace_id,
                exception_value: None,
                engine_failure: None,
                console_output: result.console_output,
                failure_context: None,
                host_effect_transcript: result.host_effect_transcript,
                host_effect_journal: result.host_effect_journal,
            }
        }

        fn failed(observed: ObservedFailure) -> Result<Self, String> {
            let (
                terminal_state,
                trace_id,
                exception_value,
                engine_failure,
                console_output,
                failure_context,
            ) = match observed.attempt {
                CapturedAttempt::UncaughtException(failure) => (
                    NativeReplayTerminalState::UncaughtException,
                    failure.trace_id,
                    Some(failure.exception_value),
                    None,
                    failure.console_output,
                    failure.failure_context,
                ),
                CapturedAttempt::EngineFailure(failure) => (
                    NativeReplayTerminalState::EngineFailure,
                    failure.trace_id,
                    None,
                    Some((failure.reason, failure.diagnostic)),
                    failure.console_output,
                    failure.failure_context,
                ),
                CapturedAttempt::Completed(_) => {
                    return Err("failure observation cannot contain completed evidence".to_string());
                }
            };
            Ok(Self {
                terminal_state,
                trace_id,
                exception_value,
                engine_failure,
                console_output,
                failure_context,
                host_effect_transcript: observed.host_effect_transcript,
                host_effect_journal: observed.host_effect_journal,
            })
        }
    }

    fn compare_failure_observation(
        expected: &CapturedAttempt,
        expected_effects: &[(HostIoRequest, HostIoOutcome)],
        expected_journal: Option<&[HostEffectJournalEntry]>,
        frozen_modules: bool,
        replayed: &TerminalObservation,
    ) -> Result<NativeReplayOutcome, String> {
        let (trace_id, console_output, expected_failure_context, terminal_state, scope, note) =
            match expected {
                CapturedAttempt::UncaughtException(failure) => (
                    &failure.trace_id,
                    &failure.console_output,
                    failure.failure_context.as_ref(),
                    NativeReplayTerminalState::UncaughtException,
                    "guest_failure_prefix",
                    if failure.failure_context.is_some() {
                        "This verdict verifies an uncaught guest exception, executed IR3 hash, failure-prefix instruction count, randomness transcript, captured/dropped console output, consumed module hashes, and finalized host-effect prefix. The failed run has no completed IR4 witness or completed runtime decision to compare."
                    } else {
                        "This verdict verifies an uncaught guest exception, captured console, and finalized host-effect prefix. The failed run has no completed IR4 witness, finalized nondeterminism trace, total instruction count, or completed runtime decision to compare."
                    },
                ),
                CapturedAttempt::EngineFailure(failure) => (
                    &failure.trace_id,
                    &failure.console_output,
                    failure.failure_context.as_ref(),
                    NativeReplayTerminalState::EngineFailure,
                    "engine_failure_prefix",
                    if failure.failure_context.is_some() {
                        "This verdict verifies the typed interpreter stopping reason, exact native diagnostic, executed IR3 hash, failure-prefix instruction count, randomness transcript, captured/dropped console output, consumed module hashes, and finalized host-effect prefix. It does not replay a supervisor timeout, cancellation, or panic, and does not manufacture a completed IR4 witness or completed runtime decision."
                    } else {
                        "This verdict verifies the typed interpreter stopping reason, exact native diagnostic, captured console, and finalized host-effect prefix. It does not replay a supervisor timeout, cancellation, or panic, and does not manufacture a completed IR4 witness, finalized nondeterminism trace, or total instruction count."
                    },
                ),
                CapturedAttempt::Completed(_) => {
                    return Err("failure comparison requires a captured failed attempt".to_string());
                }
            };
        let (
            ir3_hash_match,
            instruction_count_match,
            nondeterminism_trace_match,
            dropped_console_match,
            imported_module_hashes_match,
        ) = match expected_failure_context {
            Some(expected_ctx) => {
                let replayed_ctx = replayed.failure_context.as_ref();
                (
                    Some(replayed_ctx.is_some_and(|ctx| ctx.ir3_hash == expected_ctx.ir3_hash)),
                    Some(replayed_ctx.is_some_and(|ctx| {
                        ctx.instructions_executed == expected_ctx.instructions_executed
                    })),
                    Some(replayed_ctx.is_some_and(|ctx| {
                        ctx.randomness_transcript == expected_ctx.randomness_transcript
                    })),
                    replayed_ctx.is_some_and(|ctx| {
                        ctx.dropped_console_entries == expected_ctx.dropped_console_entries
                    }),
                    replayed_ctx.is_some_and(|ctx| {
                        ctx.imported_module_hashes == expected_ctx.imported_module_hashes
                    }),
                )
            }
            None => (None, None, None, true, true),
        };
        let mut outcome = NativeReplayOutcome {
            schema_version: NATIVE_REPLAY_OUTCOME_SCHEMA.to_string(),
            replay_kind: "native_reexecution".to_string(),
            verification_scope: scope.to_string(),
            module_load_disabled: !frozen_modules,
            matched: false,
            divergences: Vec::new(),
            captured_trace_id: trace_id.clone(),
            replay_trace_id: replayed.trace_id.clone(),
            captured_terminal_state: terminal_state,
            replay_terminal_state: replayed.terminal_state,
            terminal_state_match: replayed.terminal_state == terminal_state,
            ir3_hash_match,
            ir4_witness_match: None,
            execution_value_match: None,
            instruction_count_match,
            console_match: *console_output == replayed.console_output,
            host_effects_match: expected_effects == replayed.host_effect_transcript
                && expected_journal.is_none_or(|journal| journal == replayed.host_effect_journal),
            nondeterminism_trace_match,
            lane_match: None,
            exit_code_match: None,
            exception_value_match: match expected {
                CapturedAttempt::UncaughtException(failure) => Some(
                    replayed.exception_value.as_deref() == Some(failure.exception_value.as_str()),
                ),
                _ => None,
            },
            decisions_match: None,
            policy_comparison_note: format!(
                "{note} {}",
                replay_policy_comparison_note(expected_journal.is_some(), frozen_modules)
            ),
        };
        if expected_journal.is_some() {
            outcome.policy_comparison_note.push_str(" Process outcomes are consumed in global journal order without live dispatch; filesystem outcomes are materialized from the authenticated bounded recorder and bound to that same journal before execution. Generic caller-supplied journals retain Unknown provenance.");
        }
        for (matches, subject) in [
            (outcome.terminal_state_match, "terminal state"),
            (
                outcome.exception_value_match != Some(false),
                "exception value",
            ),
            (outcome.ir3_hash_match != Some(false), "executed IR3"),
            (
                outcome.instruction_count_match != Some(false),
                "executed instruction count",
            ),
            (
                outcome.nondeterminism_trace_match != Some(false),
                "nondeterminism trace",
            ),
            (dropped_console_match, "dropped console entry count"),
            (imported_module_hashes_match, "consumed module hashes"),
            (outcome.console_match, "console output"),
            (outcome.host_effects_match, "host-effect prefix"),
            (*trace_id == replayed.trace_id, "execution trace identity"),
        ] {
            if !matches {
                outcome.divergences.push(format!(
                    "re-executed {subject} differs from the captured failure"
                ));
            }
        }
        if let CapturedAttempt::EngineFailure(failure) = expected {
            let (reason_match, diagnostic_match) = replayed
                .engine_failure
                .as_ref()
                .map(|(reason, diagnostic)| {
                    (reason == &failure.reason, diagnostic == &failure.diagnostic)
                })
                .unwrap_or((false, false));
            for (matches, subject) in [
                (reason_match, "engine failure reason"),
                (diagnostic_match, "engine failure diagnostic"),
            ] {
                if !matches {
                    outcome.divergences.push(format!(
                        "re-executed {subject} differs from the captured failure"
                    ));
                }
            }
        }
        outcome.matched = outcome.divergences.is_empty();
        Ok(outcome)
    }

    pub(super) fn reexecute(capture: &NativeReplayCapture) -> Result<NativeReplayOutcome, String> {
        let payload = decode_capture(capture)?;
        std::thread::Builder::new()
            .name("native-incident-replay".to_string())
            .stack_size(REPLAY_STACK_BYTES)
            .spawn(move || {
                // Source preparation may use the original admitted parser
                // depth. Keep it on the same large stack as native evaluation.
                payload.validate()?;
                if payload.capability_ceiling.is_none() {
                    let scoped_host_outcome =
                        payload.host_effect_transcript.iter().any(|(_, outcome)| {
                            matches!(outcome, Err(HostIoError::Denied { reason })
                            if reason.starts_with("publisher_authority:"))
                        });
                    let scoped_process_outcome = payload.process.as_ref().is_some_and(|process| {
                        process.journal.iter().any(|entry| {
                            matches!(entry,
                                HostEffectJournalEntry::ProcessSpawn {
                                    outcome: Err(ProcessSpawnError::Denied { reason }), ..
                                } if reason.starts_with("publisher_authority:")
                            )
                        })
                    });
                    if scoped_host_outcome || scoped_process_outcome {
                        // A producer may construct an intermediate capture before
                        // binding its ceiling, but that draft is never replayable.
                        // Process denials live in the global journal, outside
                        // the host-I/O projection, and must prevent downgrades too.
                        return Err(
                            "publisher-scoped outcomes require the captured publisher ceiling"
                                .to_string(),
                        );
                    }
                }
                let modules = payload
                    .module_sources
                    .as_ref()
                    .map(|sources| sources.restore(&payload.package, &payload.orchestrator))
                    .transpose()?;
                let mut package = payload.package.clone();
                if modules.is_none() {
                    package.capabilities.retain(|capability| {
                        RuntimeCapability::from_tag_str(capability)
                            != Some(RuntimeCapability::ModuleLoad)
                    });
                    // Without a captured resolver no runtime source read is
                    // authorized, including through old project-root metadata.
                    package.module_root = None;
                }
                let authority = RuntimeEvidenceAuthority::generate_runtime_owned(
                    "franken-node.incident-replay",
                    payload.orchestrator.epoch,
                    1,
                    None,
                )
                .map_err(|error| format!("initialize native replay authority: {error}"))?;
                let mut orchestrator =
                    ExecutionOrchestrator::try_new_with_runtime_config_and_authority(
                        payload.orchestrator.restore(),
                        payload.runtime.clone(),
                        payload.ambient_authority,
                        authority,
                    )
                    .map_err(|error| format!("initialize native replay engine: {error}"))?;
                orchestrator.set_process_argv(payload.process_argv.clone());
                orchestrator.set_clock_epoch_ms(payload.clock_epoch_ms);
                let replay_io = Arc::new(CapturedReplayRecorder::new(
                    payload.host_effect_transcript.clone(),
                ));
                orchestrator.set_host_io(Arc::new(CapturedReplayHostIo), Some(replay_io.clone()));
                let replay_process_provider = payload.process.as_ref().map(|process| {
                    Arc::new(CapturedReplayProcessProvider::new(
                        process.preparation.clone(),
                    ))
                });
                if let (Some(process), Some(provider)) =
                    (&payload.process, &replay_process_provider)
                {
                    // An expired authority is intentional: ordered replay must
                    // consume captured outcomes without authorizing a live call.
                    // Materialize every I/O result from the authenticated bounded
                    // recorder and require exact global-journal agreement. A
                    // generic caller-supplied replay journal still fails high.
                    let journal = InMemoryHostEffectJournal::replaying_from_host_io_source(
                        process.journal.clone(),
                        Default::default(),
                        replay_io.as_ref(),
                    )
                    .map_err(|error| format!("bind native replay host I/O source: {error}"))?;
                    orchestrator.set_process_spawn(
                        provider.clone(),
                        Arc::new(journal),
                        ProcessSpawnAttemptAuthority::expiring_at_unix_ms(0),
                    );
                }
                let result = match modules {
                    Some((entry, _resolver, true)) => {
                        let mut delivered = package.clone();
                        delivered.source = entry.module.record.source;
                        delivered.module_root = None;
                        orchestrator.execute(&delivered)
                    }
                    Some((entry, resolver, false)) => orchestrator
                        .execute_resolved_entry_with_resolver(&package, &entry, resolver),
                    None => orchestrator.execute(&package),
                };
                if let Some(provider) = replay_process_provider {
                    // A caught preparation mismatch cannot turn into a valid
                    // replay merely because the guest suppressed its exception.
                    provider.verify()?;
                }
                match (&payload.expected, result) {
                    (CapturedAttempt::Completed(_), Ok(replayed)) => {
                        compare_execution(&payload, &replayed)
                    }
                    (CapturedAttempt::Completed(_), Err(error)) => {
                        Err(format!("native re-execution failed: {error}"))
                    }
                    (
                        expected @ (CapturedAttempt::UncaughtException(_)
                        | CapturedAttempt::EngineFailure(_)),
                        Err(error),
                    ) => {
                        let observed = observe_failure(&orchestrator, &error).map_err(|reason| {
                            format!(
                                "native failure re-execution is not certified: {reason}; {error}"
                            )
                        })?;
                        let replayed = TerminalObservation::failed(observed)?;
                        compare_failure_observation(
                            expected,
                            &payload.host_effect_transcript,
                            payload
                                .process
                                .as_ref()
                                .map(|process| process.journal.as_slice()),
                            payload.module_sources.is_some(),
                            &replayed,
                        )
                    }
                    (
                        expected @ (CapturedAttempt::UncaughtException(_)
                        | CapturedAttempt::EngineFailure(_)),
                        Ok(replayed),
                    ) => {
                        let replayed = TerminalObservation::completed(replayed);
                        compare_failure_observation(
                            expected,
                            &payload.host_effect_transcript,
                            payload
                                .process
                                .as_ref()
                                .map(|process| process.journal.as_slice()),
                            payload.module_sources.is_some(),
                            &replayed,
                        )
                    }
                }
            })
            .map_err(|error| format!("start native replay worker: {error}"))?
            .join()
            .map_err(|_| {
                "native replay worker panicked before completing verification".to_string()
            })?
    }

    fn attenuated_package(
        original: &ExtensionPackage,
        denied_capabilities: &[String],
    ) -> Result<ExtensionPackage, String> {
        NativeCounterfactualRequest {
            denied_capabilities: denied_capabilities.to_vec(),
        }
        .validate()?;
        let granted: BTreeSet<_> = original
            .capabilities
            .iter()
            .filter_map(|tag| RuntimeCapability::from_tag_str(tag))
            .collect();
        let mut denied = BTreeSet::new();
        for tag in denied_capabilities {
            let capability = RuntimeCapability::from_tag_str(tag).ok_or_else(|| {
                format!("native counterfactual cannot deny unknown capability {tag}")
            })?;
            if capability.to_string() != *tag {
                return Err(format!(
                    "native counterfactual requires canonical capability name {capability}"
                ));
            }
            if matches!(
                capability,
                RuntimeCapability::VmDispatch
                    | RuntimeCapability::HeapAllocate
                    | RuntimeCapability::Console
            ) {
                return Err(format!(
                    "native counterfactual cannot deny engine-intrinsic capability {tag}"
                ));
            }
            if !granted.contains(&capability) {
                return Err(format!(
                    "native counterfactual capability {tag} was not granted by the captured run"
                ));
            }
            if capability == RuntimeCapability::ModuleLoad {
                return Err(
                    "native counterfactual cannot deny module_load before frozen entrypoint admission"
                        .to_string(),
                );
            }
            denied.insert(capability);
        }
        let mut package = original.clone();
        // Remove every spelling of the denied authority. String-only removal
        // would leave aliases such as fs:write authorized in older captures.
        package.capabilities.retain(|tag| {
            RuntimeCapability::from_tag_str(tag)
                .is_none_or(|capability| !denied.contains(&capability))
        });
        Ok(package)
    }

    struct CounterfactualObservation {
        terminal_state: NativeReplayTerminalState,
        execution_value: Option<String>,
        exception_value: Option<String>,
        engine_failure: Option<String>,
        exit_code: Option<i32>,
        instructions_executed: Option<u64>,
        console_output: Vec<ConsoleEntry>,
        host_effect_transcript: Vec<(HostIoRequest, HostIoOutcome)>,
    }

    impl CounterfactualObservation {
        fn completed(result: OrchestratorResult) -> Result<Self, String> {
            if result.ir4_witness.outcome != ExecutionOutcome::Completed
                || result.ir4_witness.instructions_executed != result.instructions_executed
            {
                return Err(
                    "native counterfactual has no consistent completed guest witness".to_string(),
                );
            }
            Ok(Self {
                terminal_state: NativeReplayTerminalState::Completed,
                execution_value: Some(result.execution_value),
                exception_value: None,
                engine_failure: None,
                exit_code: result.exit_code,
                instructions_executed: Some(result.instructions_executed),
                console_output: result.console_output,
                host_effect_transcript: result.host_effect_transcript,
            })
        }

        fn failed(observed: ObservedFailure) -> Result<Self, String> {
            let observed = TerminalObservation::failed(observed)?;
            Ok(Self {
                terminal_state: observed.terminal_state,
                execution_value: None,
                exception_value: observed.exception_value,
                engine_failure: observed.engine_failure.map(|(_, diagnostic)| diagnostic),
                exit_code: None,
                instructions_executed: None,
                console_output: observed.console_output,
                host_effect_transcript: observed.host_effect_transcript,
            })
        }
    }

    pub(super) fn counterfactual(
        capture: &NativeReplayCapture,
        denied_capabilities: &[String],
    ) -> Result<NativeCounterfactualOutcome, String> {
        let payload = decode_capture(capture)?;
        if payload.module_sources.is_none()
            || !matches!(&payload.expected, CapturedAttempt::Completed(_))
        {
            return Err(
                "native counterfactual requires a completed original run with frozen module sources"
                    .to_string(),
            );
        }
        if payload.process.is_some()
            || payload.package.capabilities.iter().any(|tag| {
                RuntimeCapability::from_tag_str(tag) == Some(RuntimeCapability::ProcessSpawn)
            })
        {
            return Err(
                "native counterfactual does not support process-authorized captures".to_string(),
            );
        }
        let package = attenuated_package(&payload.package, denied_capabilities)?;
        // A changed expected result, missing input, divergent policy decision,
        // or incomplete original run cannot become evidence for an alternative.
        // The public supervisor owns one timeout for both this baseline and the
        // branch; neither phase can outlive its owned worker process.
        let baseline = reexecute(capture)?.into_policy_equivalence_outcome();
        if !baseline.satisfies_policy_equivalence() {
            return Err(
                "native counterfactual requires successful original execution and policy verification"
                    .to_string(),
            );
        }
        let capture_payload_sha256 = capture.payload_sha256.clone();
        let denied_capabilities = denied_capabilities.to_vec();
        std::thread::Builder::new()
            .name("native-incident-counterfactual".to_string())
            .stack_size(REPLAY_STACK_BYTES)
            .spawn(move || {
                let sources = payload.module_sources.as_ref().ok_or_else(|| {
                    "native counterfactual requires frozen module sources".to_string()
                })?;
                // The original resolver and parser are retained, but every
                // resolution is authorized under the smaller capability set.
                let (entry, resolver, uses_closed_world_lowering_only_builtins) =
                    sources.restore(&package, &payload.orchestrator)?;
                let authority = RuntimeEvidenceAuthority::generate_runtime_owned(
                    "franken-node.incident-counterfactual",
                    payload.orchestrator.epoch,
                    1,
                    None,
                )
                .map_err(|error| format!("initialize native counterfactual authority: {error}"))?;
                let mut orchestrator =
                    ExecutionOrchestrator::try_new_with_runtime_config_and_authority(
                        payload.orchestrator.restore(),
                        payload.runtime.clone(),
                        payload.ambient_authority,
                        authority,
                    )
                    .map_err(|error| format!("initialize native counterfactual engine: {error}"))?;
                orchestrator.set_process_argv(payload.process_argv.clone());
                orchestrator.set_clock_epoch_ms(payload.clock_epoch_ms);
                let inputs = Arc::new(CounterfactualHostIo::new(
                    payload.host_effect_transcript.clone(),
                ));
                orchestrator.set_host_io(
                    inputs.clone(),
                    Some(Arc::new(InMemoryHostIoTranscript::recording())),
                );
                let exec_result = if uses_closed_world_lowering_only_builtins {
                    let mut delivered = package.clone();
                    delivered.source = entry.module.record.source.clone();
                    delivered.module_root = None;
                    orchestrator.execute(&delivered)
                } else {
                    orchestrator.execute_resolved_entry_with_resolver(&package, &entry, resolver)
                };
                let observed = match exec_result {
                    Ok(result) => CounterfactualObservation::completed(result)?,
                    Err(error) => CounterfactualObservation::failed(
                        observe_failure(&orchestrator, &error).map_err(|reason| {
                            format!(
                                "native counterfactual has no certified terminal observation: {reason}"
                            )
                        })?,
                    )?,
                };
                // Check the sticky input refusal after engine finalization.
                // Catching an exception, returning successfully, or requesting
                // the original next input later cannot erase a prior mismatch.
                let consumed_host_effects = inputs.verify(&observed.host_effect_transcript)?;
                let CapturedAttempt::Completed(expected) = &payload.expected else {
                    return Err("native counterfactual original run was not completed".to_string());
                };
                let console_matches_original = observed.console_output == expected.console_output;
                let execution_value_matches_original = observed
                    .execution_value
                    .as_ref()
                    .map(|value| value == &expected.execution_value);
                let captured_host_effects = payload.host_effect_transcript.len();
                Ok(NativeCounterfactualOutcome {
                    schema_version: NATIVE_COUNTERFACTUAL_OUTCOME_SCHEMA.to_string(),
                    execution_kind: "native_counterfactual".to_string(),
                    verification_scope: NATIVE_COUNTERFACTUAL_SCOPE.to_string(),
                    capture_payload_sha256,
                    baseline,
                    denied_capabilities,
                    retained_declared_capabilities: package.capabilities,
                    terminal_state: observed.terminal_state,
                    execution_value: observed.execution_value,
                    exception_value: observed.exception_value,
                    engine_failure: observed.engine_failure,
                    exit_code: observed.exit_code,
                    instructions_executed: observed.instructions_executed,
                    console_output: observed
                        .console_output
                        .into_iter()
                        .map(|entry| NativeCounterfactualConsoleEntry {
                            level: match entry.level {
                                ConsoleLevel::Log => "log",
                                ConsoleLevel::Error => "error",
                                ConsoleLevel::Warn => "warn",
                                ConsoleLevel::Info => "info",
                            }
                            .to_string(),
                            message: entry.message,
                            instruction_index: entry.instruction_index,
                        })
                        .collect(),
                    captured_host_effects,
                    consumed_host_effects,
                    unused_original_host_effects: captured_host_effects - consumed_host_effects,
                    console_matches_original,
                    execution_value_matches_original,
                    terminal_state_matches_original: observed.terminal_state
                        == NativeReplayTerminalState::Completed,
                    replay_certified: false,
                    policy_equivalence_certified: false,
                })
            })
            .map_err(|error| format!("start native counterfactual engine worker: {error}"))?
            .join()
            .map_err(|_| {
                "native counterfactual engine worker panicked before finalizing its observation"
                    .to_string()
            })?
    }

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeMap;
        use std::path::Path;

        use frankenengine_extension_host::host_io::{HostIoResponse, SandboxedHostIo};
        #[cfg(unix)]
        use frankenengine_extension_host::process_spawn::{NativeProcessSpawn, ProcessSpawnPolicy};

        use super::*;

        fn on_native_stack(test: impl FnOnce() + Send + 'static) {
            std::thread::Builder::new()
                .stack_size(REPLAY_STACK_BYTES)
                .spawn(test)
                .expect("start native test")
                .join()
                .expect("native test completed");
        }

        fn scoped_ceiling() -> EffectiveCapabilityCeiling {
            EffectiveCapabilityCeiling {
                contract_id: "publisher-replay-regression".into(),
                allowed_capabilities: ["env_read", "fs_read", "fs_write", "network_egress"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                max_calls_per_epoch: BTreeMap::from([
                    ("env_read".into(), 1),
                    ("fs_read".into(), 1),
                    ("fs_write".into(), 1),
                    ("network_egress".into(), 1),
                ]),
                capability_scopes: BTreeMap::from([
                    ("env_read".into(), "env:read".into()),
                    ("fs_read".into(), "filesystem:read".into()),
                    ("fs_write".into(), "filesystem:write".into()),
                    ("network_egress".into(), "network:egress".into()),
                ]),
                path_prefixes: None,
                host_ports: Some(BTreeSet::from(["api.example.test:443".into()])),
                env_keys: Some(BTreeSet::from(["PUBLIC_NAME".into()])),
                module_scope_prefix: None,
            }
        }

        fn scoped_process_ceiling(budget: u64) -> EffectiveCapabilityCeiling {
            let mut ceiling = scoped_ceiling();
            ceiling.allowed_capabilities.insert("process_spawn".into());
            ceiling
                .max_calls_per_epoch
                .insert("process_spawn".into(), budget);
            ceiling
                .capability_scopes
                .insert("process_spawn".into(), "process:spawn".into());
            ceiling
        }

        fn process_quota_denial() -> ProcessSpawnOutcome {
            Err(ProcessSpawnError::Denied {
                reason:
                    "publisher_authority: process invocation exceeds the admitted scope or call budget"
                        .into(),
            })
        }

        fn prepared_process_request(
            request: &ProcessSpawnRequest,
        ) -> Vec<CapturedProcessPreparation> {
            vec![
                CapturedProcessPreparation::Preflight {
                    request: request.clone(),
                    outcome: Ok(()),
                },
                CapturedProcessPreparation::Prepare {
                    request: request.clone(),
                    outcome: Ok(request.clone()),
                },
            ]
        }

        #[test]
        fn scoped_process_transcripts_rederive_failed_attempts_quota_and_cleanup() {
            let request = ProcessSpawnRequest::CloseStdin {
                handle: "retained-child".into(),
            };
            let failure = ProcessSpawnError::Io {
                operation: "close stdin".into(),
                detail: "provider failed after admission".into(),
            };
            let process = CapturedProcessReplay {
                preparation: prepared_process_request(&request),
                journal: vec![
                    HostEffectJournalEntry::ProcessSpawn {
                        request: request.clone(),
                        outcome: Err(failure),
                    },
                    HostEffectJournalEntry::ProcessSpawn {
                        request: request.clone(),
                        outcome: Ok(ProcessSpawnResponse::StdinClosed),
                    },
                    HostEffectJournalEntry::ProcessSpawn {
                        request: request.clone(),
                        outcome: process_quota_denial(),
                    },
                    HostEffectJournalEntry::ProcessSpawn {
                        request: ProcessSpawnRequest::Cleanup {
                            handle: "retained-child".into(),
                        },
                        outcome: Ok(ProcessSpawnResponse::Cleaned { was_present: true }),
                    },
                ],
            };
            let ceiling = scoped_process_ceiling(2);
            let capabilities = ["process_spawn".into()];
            process.validate(&[]).unwrap();
            for _ in 0..2 {
                validate_scoped_process_transcript(&ceiling, &process, &capabilities).unwrap();
            }
            for index in [0, 2, 3] {
                let mut forged = process.clone();
                let HostEffectJournalEntry::ProcessSpawn { outcome, .. } =
                    &mut forged.journal[index]
                else {
                    unreachable!()
                };
                *outcome = if index == 2 {
                    Ok(ProcessSpawnResponse::StdinClosed)
                } else {
                    process_quota_denial()
                };
                assert!(
                    validate_scoped_process_transcript(&ceiling, &forged, &capabilities).is_err()
                );
            }
            assert!(
                validate_scoped_process_transcript(
                    &scoped_process_ceiling(3),
                    &process,
                    &capabilities,
                )
                .is_err(),
                "widening quota cannot retain an invented exhaustion refusal"
            );
            assert!(validate_scoped_process_transcript(&ceiling, &process, &[]).is_err());
        }

        #[test]
        fn scoped_process_transcripts_preserve_preparation_refusals_and_reject_alias_ambiguity() {
            let refused = ProcessSpawnRequest::CloseStdin {
                handle: "refused-before-provider".into(),
            };
            let allowed = ProcessSpawnRequest::CloseStdin {
                handle: "prepared-child".into(),
            };
            let failure = ProcessSpawnError::PolicyViolation {
                code: "fixture_preparation".into(),
                detail: "request preparation refused before provider entry".into(),
            };
            let mut preparation = prepared_process_request(&allowed);
            preparation.extend([
                CapturedProcessPreparation::Preflight {
                    request: refused.clone(),
                    outcome: Ok(()),
                },
                CapturedProcessPreparation::Prepare {
                    request: refused.clone(),
                    outcome: Err(failure.clone()),
                },
            ]);
            let process = CapturedProcessReplay {
                preparation,
                journal: vec![
                    HostEffectJournalEntry::ProcessSpawn {
                        request: refused.clone(),
                        outcome: Err(failure.clone()),
                    },
                    HostEffectJournalEntry::ProcessSpawn {
                        request: ProcessSpawnRequest::CloseStdin {
                            handle: "refused-by-flow-before-preparation".into(),
                        },
                        outcome: Err(ProcessSpawnError::FlowPolicyBlocked),
                    },
                    HostEffectJournalEntry::ProcessSpawn {
                        request: allowed.clone(),
                        outcome: Ok(ProcessSpawnResponse::StdinClosed),
                    },
                    HostEffectJournalEntry::ProcessSpawn {
                        request: allowed,
                        outcome: process_quota_denial(),
                    },
                ],
            };
            let ceiling = scoped_process_ceiling(1);
            let capabilities = ["process_spawn".into()];
            validate_scoped_process_transcript(&ceiling, &process, &capabilities).unwrap();

            let mut forged_flow = process.clone();
            let HostEffectJournalEntry::ProcessSpawn { request, .. } = &mut forged_flow.journal[1]
            else {
                unreachable!()
            };
            *request = process.preparation[0].request().clone();
            assert!(
                validate_scoped_process_transcript(&ceiling, &forged_flow, &capabilities)
                    .unwrap_err()
                    .contains("ambiguously aliases an IFC refusal")
            );

            // An unrelated alias can prepare to the same request whose own
            // preparation fails. Its identical provider error must not become
            // a free refusal merely because it matches that failure's text.
            let alias = ProcessSpawnRequest::CloseStdin {
                handle: "foreign-alias".into(),
            };
            let mut ambiguous = process.clone();
            ambiguous.preparation.extend([
                CapturedProcessPreparation::Preflight {
                    request: alias.clone(),
                    outcome: Ok(()),
                },
                CapturedProcessPreparation::Prepare {
                    request: alias,
                    outcome: Ok(refused.clone()),
                },
            ]);
            ambiguous.journal.insert(
                1,
                HostEffectJournalEntry::ProcessSpawn {
                    request: refused,
                    outcome: Err(failure),
                },
            );
            assert!(
                validate_scoped_process_transcript(&ceiling, &ambiguous, &capabilities)
                    .unwrap_err()
                    .contains("ambiguously aliases")
            );
            let mut duplicate = process.clone();
            duplicate.preparation.push(process.preparation[0].clone());
            assert!(
                validate_scoped_process_transcript(&ceiling, &duplicate, &capabilities).is_err()
            );
            let mut forged = process;
            let CapturedProcessPreparation::Prepare { outcome, .. } =
                forged.preparation.last_mut().unwrap()
            else {
                unreachable!()
            };
            *outcome = process_quota_denial().map(|_| unreachable!());
            let HostEffectJournalEntry::ProcessSpawn { outcome, .. } = &mut forged.journal[0]
            else {
                unreachable!()
            };
            *outcome = process_quota_denial();
            assert!(validate_scoped_process_transcript(&ceiling, &forged, &capabilities).is_err());
        }

        #[test]
        fn scoped_transcripts_rederive_denials_and_charge_failed_attempts_without_refunds() {
            let ceiling = scoped_ceiling();
            let request = HostIoRequest::EnvRead {
                name: "PUBLIC_NAME".into(),
            };
            let budget_denial = HostIoError::Denied {
                reason:
                    "publisher_authority: host invocation exceeds the admitted scope or call budget"
                        .into(),
            };
            let scope_denial = HostIoError::Denied {
                reason: "publisher_authority: host request is outside the admitted scope".into(),
            };
            let tape = vec![
                (
                    request.clone(),
                    Err(HostIoError::Io {
                        detail: "provider failed".into(),
                    }),
                ),
                (request.clone(), Err(budget_denial.clone())),
                (
                    HostIoRequest::EnvRead {
                        name: "PRIVATE_NAME".into(),
                    },
                    Err(scope_denial.clone()),
                ),
            ];
            let capabilities = vec!["env_read".into()];
            for _ in 0..2 {
                validate_scoped_transcript(&ceiling, &tape, &capabilities).unwrap();
            }
            let mut changed = tape.clone();
            changed[1].1 = Ok(HostIoResponse::EnvRead {
                value: Some("ungranted".into()),
            });
            assert!(validate_scoped_transcript(&ceiling, &changed, &capabilities).is_err());
            let mut widened = ceiling.clone();
            widened.max_calls_per_epoch.insert("env_read".into(), 2);
            assert!(validate_scoped_transcript(&widened, &tape, &capabilities).is_err());
            assert!(validate_scoped_transcript(&ceiling, &tape, &[]).is_err());
            assert!(
                validate_scoped_transcript(
                    &ceiling,
                    &[(request, Err(scope_denial))],
                    &capabilities,
                )
                .is_err(),
                "an allowed request cannot retain an invented scope refusal"
            );
        }

        #[cfg(unix)]
        #[test]
        fn scoped_native_replay_is_offline_and_rejects_weakened_or_downgraded_capture_policy() {
            on_native_stack(|| {
                let workspace = tempfile::tempdir().unwrap();
                let original = workspace.path().join("original");
                std::fs::create_dir(&original).unwrap();
                std::fs::write(original.join("input.txt"), "original-source-value").unwrap();
                let legacy = record_frozen_counterfactual(
                    &original,
                    "const fs = require('fs'); const value = fs.readFileSync('input.txt', 'utf8'); fs.writeFileSync('output.txt', value); console.log(value);",
                );
                assert_eq!(legacy.schema_version, NATIVE_REPLAY_CAPTURE_SCHEMA);
                let scoped = legacy
                    .clone()
                    .with_capability_ceiling(&scoped_ceiling())
                    .unwrap();
                assert_eq!(scoped.schema_version, NATIVE_REPLAY_SCOPED_CAPTURE_SCHEMA);
                assert!(
                    scoped
                        .clone()
                        .with_capability_ceiling(&scoped_ceiling())
                        .is_err()
                );
                let archived = workspace.path().join("archived");
                std::fs::rename(&original, &archived).unwrap();
                assert!(reexecute(&scoped).unwrap().satisfies_policy_equivalence());
                assert!(
                    counterfactual(&scoped, &["fs_write".into()])
                        .unwrap()
                        .baseline
                        .satisfies_policy_equivalence()
                );
                assert!(!original.exists());
                assert_eq!(
                    std::fs::read_to_string(archived.join("output.txt")).unwrap(),
                    "original-source-value"
                );

                let mut payload = decode_capture(&scoped).unwrap();
                payload
                    .capability_ceiling
                    .as_mut()
                    .unwrap()
                    .max_calls_per_epoch
                    .insert("fs_write".into(), 0);
                assert!(
                    reexecute(&encode_capture(&payload).unwrap())
                        .unwrap_err()
                        .contains("contradicts publisher")
                );
                let mut downgraded = scoped;
                downgraded.schema_version = NATIVE_REPLAY_CAPTURE_SCHEMA.into();
                assert!(
                    reexecute(&downgraded)
                        .unwrap_err()
                        .contains("canonical capture")
                );
                let mut missing = legacy;
                missing.schema_version = NATIVE_REPLAY_SCOPED_CAPTURE_SCHEMA.into();
                assert!(
                    reexecute(&missing)
                        .unwrap_err()
                        .contains("canonical capture")
                );
            });
        }

        #[test]
        fn native_counterfactual_inputs_allow_only_an_exact_prefix_and_poison_divergence() {
            let first = HostIoRequest::FsRead {
                path: "first-private-path".into(),
            };
            let second = HostIoRequest::FsRead {
                path: "second-private-path".into(),
            };
            let first_outcome = Ok(HostIoResponse::FsRead {
                bytes: b"private-captured-input".to_vec(),
            });
            let second_outcome = Ok(HostIoResponse::FsRead {
                bytes: b"unused-input".to_vec(),
            });
            let entries = vec![
                (first.clone(), first_outcome.clone()),
                (second.clone(), second_outcome.clone()),
            ];
            let prefix = CounterfactualHostIo::new(entries.clone());
            assert_eq!(prefix.verify(&[]).unwrap(), 0);
            assert_eq!(
                prefix.perform(&first, &[HostIoCapability::FsRead]),
                first_outcome
            );
            assert_eq!(prefix.verify(&entries[..1]).unwrap(), 1);
            assert!(
                prefix.verify(&entries).is_err(),
                "unused input is not an observed effect"
            );
            let diagnostic = format!("{prefix:?}");
            assert!(!diagnostic.contains("private"));

            // A skipped/reordered input never searches ahead, and ignoring its
            // error cannot allow a later matching request to repair the branch.
            let reordered = CounterfactualHostIo::new(entries.clone());
            assert!(
                reordered
                    .perform(&second, &[HostIoCapability::FsRead])
                    .is_err()
            );
            assert!(
                reordered
                    .perform(&first, &[HostIoCapability::FsRead])
                    .is_err()
            );
            assert!(reordered.verify(&[]).is_err());

            let exhausted = CounterfactualHostIo::new(entries[..1].to_vec());
            assert_eq!(
                exhausted.perform(&first, &[HostIoCapability::FsRead]),
                first_outcome
            );
            assert!(
                exhausted
                    .perform(&second, &[HostIoCapability::FsRead])
                    .is_err()
            );
            assert!(exhausted.verify(&entries[..1]).is_err());

            let denied = CounterfactualHostIo::new(entries);
            assert!(matches!(
                denied.perform(&first, &[]),
                Err(HostIoError::CapabilityMissing { .. })
            ));
            assert!(denied.perform(&first, &[HostIoCapability::FsRead]).is_err());
            assert!(denied.verify(&[]).is_err());
        }

        #[test]
        fn native_counterfactual_attenuation_removes_semantic_aliases_and_never_adds_authority() {
            let package = ExtensionPackage {
                extension_id: "counterfactual-capabilities".into(),
                source: "1;".into(),
                source_file: None,
                module_root: None,
                capabilities: vec![
                    "module_load".into(),
                    "fs_write".into(),
                    "fs:write".into(),
                    "fs_read".into(),
                ],
                version: "test".into(),
                metadata: BTreeMap::new(),
            };
            let restricted = attenuated_package(&package, &["fs_write".into()]).unwrap();
            assert_eq!(restricted.capabilities, ["module_load", "fs_read"]);
            assert_eq!(
                package.capabilities.len(),
                4,
                "the original capture is immutable"
            );
            for denied in [
                vec![],
                vec!["fs_write".into(), "fs_write".into()],
                vec!["fs:write".into()],
                vec!["fs".into()],
                vec!["network_egress".into()],
                vec!["not_a_capability".into()],
                vec!["module_load".into()],
            ] {
                assert!(attenuated_package(&package, &denied).is_err(), "{denied:?}");
            }
            for intrinsic in ["vm_dispatch", "heap_allocate", "console"] {
                let mut explicitly_declared = package.clone();
                explicitly_declared.capabilities.push(intrinsic.into());
                let error = attenuated_package(&explicitly_declared, &[intrinsic.into()])
                    .expect_err("removing a declaration cannot revoke an engine-intrinsic grant");
                assert!(error.contains("engine-intrinsic"), "{error}");
            }
        }

        #[cfg(unix)]
        fn record_frozen_counterfactual(root: &Path, source: &str) -> NativeReplayCapture {
            use crate::supply_chain::module_resolution_graph::file_resolution::source_graph::{
                GraphOptions, capture,
            };

            let config = OrchestratorConfig {
                commonjs_entry: true,
                ..OrchestratorConfig::default()
            };
            let runtime = RuntimeConfig::default();
            let path = root.join("app.cjs");
            std::fs::write(&path, source).expect("write original frozen source");
            let graph = capture(root, "app.cjs", GraphOptions::default())
                .expect("capture original module closure");
            let sources = CapturedModuleSources::capture(&graph).unwrap();
            let graph_hash = graph.report().input_hash.clone();
            let resolver = Arc::new(
                CapturedEngineResolver::new_with_parser_options(
                    graph,
                    &graph_hash,
                    config.parser_options.clone(),
                )
                .expect("admit frozen module graph"),
            );
            let capabilities: Vec<String> =
                ["module_load", "fs_read", "fs_write", "builtin", "timer"]
                    .into_iter()
                    .map(str::to_string)
                    .collect();
            let policy = Arc::new(CapabilityPolicyHook::new(
                capabilities
                    .iter()
                    .filter_map(|tag| RuntimeCapability::from_tag_str(tag))
                    .collect(),
            ));
            let entry = resolver
                .resolve(
                    &resolver.entry_request(),
                    &ResolutionContext::new(
                        "native-module-admission",
                        "native-module-admission",
                        &config.policy_id,
                    ),
                    policy.as_ref(),
                )
                .expect("admit frozen entry source");
            let package = ExtensionPackage {
                extension_id: "native-counterfactual-regression".into(),
                source: entry.module.record.source.clone(),
                source_file: Some(path.display().to_string()),
                module_root: Some(root.display().to_string()),
                capabilities,
                version: "test".into(),
                metadata: BTreeMap::new(),
            };
            let authority = RuntimeEvidenceAuthority::generate_runtime_owned(
                "franken-node.native-counterfactual-test",
                config.epoch,
                1,
                None,
            )
            .unwrap();
            let mut orchestrator =
                ExecutionOrchestrator::try_new_with_runtime_config_and_authority(
                    config.clone(),
                    runtime.clone(),
                    AmbientAuthorityGrant::DenyAll,
                    authority,
                )
                .unwrap();
            orchestrator.set_host_io(
                Arc::new(SandboxedHostIo::with_root(root).unwrap()),
                Some(Arc::new(InMemoryHostIoTranscript::recording())),
            );
            let result = orchestrator
                .execute_resolved_entry_with_resolver(
                    &package,
                    &entry,
                    resolver.execution_resolver(root, policy).unwrap(),
                )
                .expect("complete the real original frozen run");
            NativeReplayCapture::from_execution(
                &package,
                &config,
                &runtime,
                AmbientAuthorityGrant::DenyAll,
                &[],
                None,
                Some(&sources),
                &result,
            )
            .expect("capture the completed frozen original")
        }

        #[cfg(unix)]
        #[test]
        fn native_counterfactual_executes_restrictions_offline_without_repeating_original_effects()
        {
            on_native_stack(|| {
                let workspace = tempfile::tempdir().unwrap();
                let original = workspace.path().join("original");
                std::fs::create_dir(&original).unwrap();
                std::fs::write(original.join("input.txt"), "captured-before-write").unwrap();
                let capture = record_frozen_counterfactual(
                    &original,
                    "const fs = require('fs'); const value = fs.readFileSync('input.txt', 'utf8'); console.log(value); fs.writeFileSync('output.txt', value); console.log('after-write');",
                );
                let archived = workspace.path().join("archived");
                std::fs::rename(&original, &archived).unwrap();

                let outcome = counterfactual(&capture, &["fs_write".into()])
                    .expect("execute the real restricted branch over captured inputs");
                assert!(outcome.baseline.satisfies_policy_equivalence());
                assert_eq!(
                    outcome.baseline.verification_scope,
                    POLICY_EQUIVALENCE_SCOPE
                );
                assert_eq!(
                    outcome.terminal_state,
                    NativeReplayTerminalState::EngineFailure
                );
                let failure = outcome.engine_failure.as_deref().unwrap();
                assert!(
                    failure.contains("fs_write")
                        || failure.contains("fs.write")
                        || failure.contains("fs:write"),
                    "{failure}"
                );
                assert!(outcome.execution_value.is_none());
                assert!(outcome.instructions_executed.is_none());
                assert_eq!(outcome.captured_host_effects, 2);
                assert_eq!(outcome.consumed_host_effects, 1);
                assert_eq!(outcome.unused_original_host_effects, 1);
                assert_eq!(outcome.console_output.len(), 1);
                assert_eq!(outcome.console_output[0].message, "captured-before-write");
                assert!(!outcome.console_matches_original);
                assert!(!outcome.terminal_state_matches_original);
                assert!(!outcome.replay_certified && !outcome.policy_equivalence_certified);

                let before_input = counterfactual(&capture, &["fs_read".into()]).unwrap();
                assert_eq!(
                    before_input.terminal_state,
                    NativeReplayTerminalState::EngineFailure
                );
                assert_eq!(before_input.consumed_host_effects, 0);
                assert_eq!(before_input.unused_original_host_effects, 2);
                assert!(before_input.console_output.is_empty());

                let completed = counterfactual(&capture, &["timer".into()]).unwrap();
                assert_eq!(
                    completed.terminal_state,
                    NativeReplayTerminalState::Completed
                );
                assert!(completed.execution_value.is_some());
                assert!(completed.instructions_executed.is_some());
                assert!(completed.console_matches_original);
                assert_eq!(completed.execution_value_matches_original, Some(true));
                assert_eq!(completed.consumed_host_effects, 2);
                assert_eq!(completed.unused_original_host_effects, 0);
                assert!(!completed.replay_certified && !completed.policy_equivalence_certified);

                assert!(
                    !original.exists(),
                    "neither replay may recreate the original tree"
                );
                assert_eq!(
                    std::fs::read_to_string(archived.join("output.txt")).unwrap(),
                    "captured-before-write"
                );
                assert!(reexecute(&capture).unwrap().satisfies_policy_equivalence());
            });
        }

        #[cfg(unix)]
        #[test]
        fn native_counterfactual_refuses_unverified_baselines_and_incomplete_source_authority() {
            on_native_stack(|| {
                let root = tempfile::tempdir().unwrap();
                let capture = record_frozen_counterfactual(root.path(), "console.log('original');");
                let original: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                let mut divergent = original.clone();
                let CapturedAttempt::Completed(expected) = &mut divergent.expected else {
                    panic!("fixture completed");
                };
                expected.execution_value = "forged-baseline-value".into();
                let error = counterfactual(&encode_capture(&divergent).unwrap(), &["timer".into()])
                    .expect_err("an alternative cannot launder a divergent original");
                assert!(
                    error.contains("original execution and policy verification"),
                    "{error}"
                );

                let mut missing = original.clone();
                missing.module_sources = None;
                assert!(
                    counterfactual(&encode_capture(&missing).unwrap(), &["timer".into()])
                        .unwrap_err()
                        .contains("frozen module sources")
                );
                let mut process_authorized = original;
                process_authorized
                    .package
                    .capabilities
                    .push("process_spawn".into());
                assert!(
                    counterfactual(
                        &encode_capture(&process_authorized).unwrap(),
                        &["timer".into()]
                    )
                    .unwrap_err()
                    .contains("process-authorized")
                );
            });
        }

        #[test]
        fn captured_orchestrator_restores_custom_package_conditions_without_ambient_selection() {
            let mut config = OrchestratorConfig::default();
            let defaults = CapturedOrchestratorSettings::capture(&config).unwrap();
            let historical = serde_json::to_value(&defaults).unwrap();
            assert!(historical.get("module_conditions").is_none());
            let decoded: CapturedOrchestratorSettings = serde_json::from_value(historical).unwrap();
            assert!(decoded.restore().module_conditions.is_empty());

            config.module_conditions = vec![
                "react-server".into(),
                "development".into(),
                "development".into(),
            ];
            let captured = CapturedOrchestratorSettings::capture(&config).unwrap();
            let decoded: CapturedOrchestratorSettings =
                serde_json::from_slice(&serde_json::to_vec(&captured).unwrap()).unwrap();
            assert_eq!(
                decoded.restore().module_conditions,
                vec!["development", "react-server"],
            );

            config.module_conditions = vec![String::new()];
            assert!(CapturedOrchestratorSettings::capture(&config).is_err());
        }

        /// Use the real bounded environment provider with explicit fixture
        /// values. No test reads or changes the test process environment.
        fn record_environment(
            source: &str,
            values: BTreeMap<String, String>,
        ) -> Result<NativeReplayCapture, String> {
            use frankenengine_extension_host::host_io::EnvironmentSnapshotHostIo;

            let config = OrchestratorConfig::default();
            let runtime = RuntimeConfig::default();
            let package = ExtensionPackage {
                extension_id: "native-environment-replay".to_string(),
                source: source.to_string(),
                source_file: None,
                module_root: None,
                capabilities: [
                    "vm_dispatch",
                    "heap_allocate",
                    "builtin",
                    "console",
                    "env_read",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
                version: "1.0.0".to_string(),
                metadata: BTreeMap::new(),
            };
            let authority = RuntimeEvidenceAuthority::generate_runtime_owned(
                "franken-node.native-environment-replay-test",
                config.epoch,
                1,
                None,
            )
            .map_err(|error| error.to_string())?;
            let mut orchestrator =
                ExecutionOrchestrator::try_new_with_runtime_config_and_authority(
                    config.clone(),
                    runtime.clone(),
                    AmbientAuthorityGrant::DenyAll,
                    authority,
                )
                .map_err(|error| error.to_string())?;
            let provider = EnvironmentSnapshotHostIo::with_provider(
                values,
                // Match the product capture's ProviderInternal exception
                // provenance while denying every unrelated host-I/O family.
                Arc::new(CapturedReplayHostIo),
            )
            .map_err(|error| error.to_string())?;
            orchestrator.set_host_io(
                Arc::new(provider),
                Some(Arc::new(InMemoryHostIoTranscript::recording())),
            );
            match orchestrator.execute(&package) {
                Ok(result) => NativeReplayCapture::from_execution(
                    &package,
                    &config,
                    &runtime,
                    AmbientAuthorityGrant::DenyAll,
                    &[],
                    None,
                    None,
                    &result,
                ),
                Err(error) => NativeReplayCapture::from_failed_execution(
                    &package,
                    &config,
                    &runtime,
                    AmbientAuthorityGrant::DenyAll,
                    &[],
                    None,
                    None,
                    &orchestrator,
                    &error,
                ),
            }
        }

        fn environment_values() -> BTreeMap<String, String> {
            BTreeMap::from([
                ("PATH".to_string(), "captured-not-the-host-path".to_string()),
                ("EMPTY".to_string(), String::new()),
                ("UNICODE".to_string(), "βeta\nsecond line".to_string()),
                (
                    "UNUSED_PRIVATE".to_string(),
                    "not-read-not-captured".to_string(),
                ),
            ])
        }

        #[test]
        fn native_environment_replay_preserves_values_absence_empty_and_presence() {
            on_native_stack(|| {
                for (source, name, value, result_value) in [
                    (
                        "process.env.PATH;",
                        "PATH",
                        Some("captured-not-the-host-path"),
                        "captured-not-the-host-path",
                    ),
                    (
                        "process.env['PATH'];",
                        "PATH",
                        Some("captured-not-the-host-path"),
                        "captured-not-the-host-path",
                    ),
                    ("process.env.EMPTY;", "EMPTY", Some(""), ""),
                    ("process.env.ABSENT;", "ABSENT", None, "undefined"),
                    ("process.env[''];", "", None, "undefined"),
                    ("'EMPTY' in process.env;", "EMPTY", Some(""), "true"),
                    ("'ABSENT' in process.env;", "ABSENT", None, "false"),
                    (
                        "process.env.UNICODE;",
                        "UNICODE",
                        Some("βeta\nsecond line"),
                        "βeta\nsecond line",
                    ),
                ] {
                    let capture = record_environment(source, environment_values())
                        .expect("capture native environment expression");
                    let payload: NativeReplayPayload =
                        serde_json::from_str(&capture.payload_json).unwrap();
                    let CapturedAttempt::Completed(expected) = &payload.expected else {
                        panic!("environment expression must complete");
                    };
                    assert_eq!(expected.execution_value, result_value);
                    assert_eq!(
                        payload.host_effect_transcript,
                        vec![(
                            HostIoRequest::EnvRead {
                                name: name.to_string()
                            },
                            Ok(HostIoResponse::EnvRead {
                                value: value.map(str::to_string)
                            }),
                        )]
                    );
                    assert!(!capture.payload_json.contains("not-read-not-captured"));
                    let outcome = reexecute(&capture).expect("transcript-only environment replay");
                    assert!(outcome.matched, "{outcome:?}");
                    assert_eq!(outcome.ir4_witness_match, Some(true));
                    assert_eq!(outcome.execution_value_match, Some(true));
                    assert!(outcome.host_effects_match && outcome.module_load_disabled);
                }
            });
        }

        #[test]
        fn native_environment_replay_checks_order_exhaustion_and_unused_suffixes() {
            on_native_stack(|| {
                for throws in [false, true] {
                    let source = format!(
                        "process.env.EMPTY; process.env.PATH; process.env.EMPTY; {}",
                        if throws {
                            "throw 'environment-prefix-failure';"
                        } else {
                            "0;"
                        },
                    );
                    let capture = record_environment(&source, environment_values()).unwrap();
                    let payload: NativeReplayPayload =
                        serde_json::from_str(&capture.payload_json).unwrap();
                    assert_eq!(payload.host_effect_transcript.len(), 3);
                    let outcome = reexecute(&capture).expect("replay completed or failed prefix");
                    assert!(outcome.matched, "{outcome:?}");
                    assert!(outcome.host_effects_match);
                    assert_eq!(
                        outcome.captured_terminal_state,
                        if throws {
                            NativeReplayTerminalState::UncaughtException
                        } else {
                            NativeReplayTerminalState::Completed
                        }
                    );
                    for mutate in [
                        (|p: &mut NativeReplayPayload| {
                            p.host_effect_transcript.remove(0);
                        }) as fn(&mut NativeReplayPayload),
                        |p| p.host_effect_transcript.swap(0, 1),
                        |p| {
                            p.host_effect_transcript
                                .push(p.host_effect_transcript[0].clone())
                        },
                        |p| p.host_effect_transcript.clear(),
                    ] {
                        let mut changed = payload.clone();
                        mutate(&mut changed);
                        let changed = encode_capture(&changed).unwrap();
                        assert!(
                            reexecute(&changed).is_err(),
                            "a matching terminal state cannot excuse an incomplete environment transcript"
                        );
                    }
                }
            });
        }

        #[test]
        fn native_environment_capture_keeps_secret_flow_and_authority_restrictions() {
            on_native_stack(|| {
                for source in [
                    "console.log(process.env.PATH);",
                    "const environment = process.env; environment.PATH;",
                    "const raw = process; raw.env.PATH;",
                    "process.env.PATH = 'replacement';",
                ] {
                    assert!(
                        record_environment(source, environment_values()).is_err(),
                        "environment replay must not grant raw process access, mutation, or declassification"
                    );
                }
                let capture =
                    record_environment("process.env.PATH;", environment_values()).unwrap();
                let mut payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                payload
                    .package
                    .capabilities
                    .retain(|capability| capability != "env_read");
                assert!(payload.validate().unwrap_err().contains("explicit EnvRead"));
                assert!(reexecute(&encode_capture(&payload).unwrap()).is_err());
            });
        }

        #[test]
        fn environment_transcript_admission_uses_engine_limits_and_typed_outcomes() {
            use frankenengine_extension_host::host_io::{
                ENVIRONMENT_NAME_MAX_BYTES, ENVIRONMENT_VALUE_MAX_BYTES,
            };
            let granted = vec!["env_read".to_string()];
            let request = HostIoRequest::EnvRead {
                name: "PRIVATE_NAME".to_string(),
            };
            for value in [None, Some(String::new()), Some("βeta".to_string())] {
                let entries = vec![(request.clone(), Ok(HostIoResponse::EnvRead { value }))];
                validate_environment_transcript(&entries, &granted).unwrap();
                assert!(validate_environment_transcript(&entries, &[]).is_err());
            }
            validate_environment_transcript(&[], &granted).unwrap();
            for name in [
                "invalid=name".to_string(),
                "invalid\0name".to_string(),
                "X".repeat(ENVIRONMENT_NAME_MAX_BYTES + 1),
            ] {
                let entries = vec![(
                    HostIoRequest::EnvRead { name },
                    Ok(HostIoResponse::EnvRead { value: None }),
                )];
                assert!(validate_environment_transcript(&entries, &granted).is_err());
            }
            for response in [
                HostIoResponse::EnvRead {
                    value: Some("private\0value".to_string()),
                },
                HostIoResponse::EnvRead {
                    value: Some("X".repeat(ENVIRONMENT_VALUE_MAX_BYTES + 1)),
                },
                HostIoResponse::FsRead {
                    bytes: b"private-value".to_vec(),
                },
            ] {
                let error =
                    validate_environment_transcript(&[(request.clone(), Ok(response))], &granted)
                        .expect_err("invalid environment result");
                assert!(!error.contains("PRIVATE_NAME") && !error.contains("private-value"));
            }
            let inverse = vec![(
                HostIoRequest::FsRead {
                    path: "file".to_string(),
                },
                Ok(HostIoResponse::EnvRead {
                    value: Some("private-value".to_string()),
                }),
            )];
            assert!(validate_environment_transcript(&inverse, &granted).is_err());
            let denial = vec![(
                request,
                Err(HostIoError::Denied {
                    reason: "policy".to_string(),
                }),
            )];
            validate_environment_transcript(&denial, &granted).unwrap();
        }

        #[test]
        fn malformed_environment_capture_is_rejected_before_native_execution() {
            on_native_stack(|| {
                let capture =
                    record_environment("process.env.PATH;", environment_values()).unwrap();
                let original: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                for mutate in [
                    (|p: &mut NativeReplayPayload| {
                        p.host_effect_transcript[0].1 =
                            Ok(HostIoResponse::FsRead { bytes: vec![] });
                    }) as fn(&mut NativeReplayPayload),
                    |p| {
                        p.host_effect_transcript[0].0 = HostIoRequest::EnvRead {
                            name: "bad=name".to_string(),
                        }
                    },
                    |p| {
                        p.host_effect_transcript[0].1 = Ok(HostIoResponse::EnvRead {
                            value: Some("bad\0value".to_string()),
                        })
                    },
                ] {
                    let mut payload = original.clone();
                    mutate(&mut payload);
                    assert!(payload.validate().is_err());
                    let error = reexecute(&encode_capture(&payload).unwrap()).unwrap_err();
                    assert!(error.starts_with("captured environment"), "{error}");
                }
            });
        }

        #[test]
        fn native_environment_replay_detects_changed_recorded_values() {
            on_native_stack(|| {
                let capture =
                    record_environment("process.env.PATH;", environment_values()).unwrap();
                let mut payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                payload.host_effect_transcript[0].1 = Ok(HostIoResponse::EnvRead {
                    value: Some("different-captured-value".to_string()),
                });
                // Rehash only to test the execution comparison independently
                // of the enclosing signature that an operator must verify.
                let outcome = reexecute(&encode_capture(&payload).unwrap()).unwrap();
                assert!(!outcome.matched);
                assert_eq!(outcome.execution_value_match, Some(false));
            });
        }

        fn record(root: &Path, source: &str) -> NativeReplayCapture {
            record_with_inputs(root, source, AmbientAuthorityGrant::DenyAll, &[])
        }

        const STOP_PREFIX: &str = "const fs = require('fs'); const value = fs.readFileSync('input.txt', 'utf8'); fs.writeFileSync('output.txt', value); console.log('before-engine-stop');";

        // These are native stopping conditions, not Node reference fixtures.
        // The original run really reads/writes a file before the engine stops.
        fn stopped_run(
            root: &Path,
            budget_stop: bool,
        ) -> (
            ExtensionPackage,
            OrchestratorConfig,
            RuntimeConfig,
            ExecutionOrchestrator,
            OrchestratorError,
        ) {
            let runtime = RuntimeConfig {
                execution: frankenengine_engine::runtime_config::ExecutionConfig {
                    deterministic_budget: 100_000,
                    throughput_budget: 100_000,
                    ..Default::default()
                },
                ..RuntimeConfig::default()
            };
            let ending = if budget_stop {
                "while (true) {}"
            } else {
                "process.env.MISSING;"
            };
            let stopped = stopped_run_with_settings(root, ending, runtime, None);
            let error = &stopped.4;
            if budget_stop {
                assert!(
                    matches!(
                        error.primary_error(),
                        OrchestratorError::Interpreter(InterpreterError::BudgetExhausted {
                            budget: 100_000,
                            ..
                        })
                    ),
                    "{error}"
                );
            } else {
                assert!(
                    matches!(
                        error.primary_error(),
                        OrchestratorError::Interpreter(
                            InterpreterError::CapabilityDenied { capability }
                        ) if capability == "env_read"
                    ),
                    "{error}"
                );
            }
            stopped
        }

        fn stopped_run_with_settings(
            root: &Path,
            ending: &str,
            runtime: RuntimeConfig,
            force_lane: Option<LaneChoice>,
        ) -> (
            ExtensionPackage,
            OrchestratorConfig,
            RuntimeConfig,
            ExecutionOrchestrator,
            OrchestratorError,
        ) {
            let config = OrchestratorConfig {
                commonjs_entry: false,
                force_lane,
                ..OrchestratorConfig::default()
            };
            let source = format!("{STOP_PREFIX} {ending}");
            let path = root.join("stopped.cjs");
            std::fs::write(&path, &source).unwrap();
            std::fs::write(root.join("input.txt"), "captured-before-stop").unwrap();
            let package = ExtensionPackage {
                extension_id: "native-engine-stop-replay".to_string(),
                source,
                source_file: Some(path.display().to_string()),
                module_root: Some(root.display().to_string()),
                capabilities: ["module_load", "fs_read", "fs_write", "builtin", "timer"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                version: "1.0.0".to_string(),
                metadata: BTreeMap::new(),
            };
            let authority = RuntimeEvidenceAuthority::generate_runtime_owned(
                "franken-node.native-engine-stop-test",
                config.epoch,
                1,
                None,
            )
            .unwrap();
            let mut orchestrator =
                ExecutionOrchestrator::try_new_with_runtime_config_and_authority(
                    config.clone(),
                    runtime.clone(),
                    AmbientAuthorityGrant::DenyAll,
                    authority,
                )
                .unwrap();
            orchestrator.set_host_io(
                Arc::new(SandboxedHostIo::with_root(root).unwrap()),
                Some(Arc::new(InMemoryHostIoTranscript::recording())),
            );
            let error = orchestrator
                .execute(&package)
                .expect_err("native engine stop");
            assert_eq!(
                std::fs::read_to_string(root.join("output.txt")).unwrap(),
                "captured-before-stop"
            );
            (package, config, runtime, orchestrator, error)
        }

        fn console_stopped_run(
            root: &Path,
            byte_stop: bool,
            lane: LaneChoice,
        ) -> (
            ExtensionPackage,
            OrchestratorConfig,
            RuntimeConfig,
            ExecutionOrchestrator,
            OrchestratorError,
        ) {
            let mut runtime = RuntimeConfig::default();
            runtime.execution.max_console_entries = Some(if byte_stop { 4 } else { 1 });
            let limits = InterpreterConfig::deterministic_from_config(&runtime.execution);
            let ending = if byte_stop {
                assert_eq!(limits.max_console_bytes, 8 * 1024 * 1024);
                concat!(
                    "let message = 'x'; for (let i = 0; i < 23; i++) {",
                    "message = message + message; } console.log(message + 'x');"
                )
                .to_string()
            } else {
                "console.error('refused-console-entry');".to_string()
            };
            let stopped = stopped_run_with_settings(root, &ending, runtime, Some(lane));
            let error = &stopped.4;
            let OrchestratorError::Interpreter(InterpreterError::ConsoleBudgetExceeded {
                entries,
                max_entries,
                bytes,
                max_bytes,
            }) = error.primary_error()
            else {
                panic!("expected the real typed console stop, got {error}");
            };
            assert_eq!(*entries, 2);
            assert_eq!(*max_entries, limits.max_console_entries);
            assert_eq!(*max_bytes, limits.max_console_bytes);
            if byte_stop {
                assert!(*bytes > *max_bytes && *entries <= *max_entries);
            } else {
                assert!(*entries > *max_entries && *bytes <= *max_bytes);
            }
            stopped
        }

        fn capture_stop(root: &Path, budget_stop: bool) -> NativeReplayCapture {
            capture_stopped_run(stopped_run(root, budget_stop))
        }

        fn capture_stopped_run(
            stopped: (
                ExtensionPackage,
                OrchestratorConfig,
                RuntimeConfig,
                ExecutionOrchestrator,
                OrchestratorError,
            ),
        ) -> NativeReplayCapture {
            let (package, config, runtime, orchestrator, error) = stopped;
            let capture = NativeReplayCapture::from_failed_execution(
                &package,
                &config,
                &runtime,
                AmbientAuthorityGrant::DenyAll,
                &[],
                None,
                None,
                &orchestrator,
                &error,
            )
            .expect("capture the finalized native stop through the run-facing entrypoint");
            assert_eq!(
                capture.terminal_state().expect("typed terminal state"),
                NativeReplayTerminalState::EngineFailure,
            );
            let explicit = NativeReplayCapture::from_finalized_failure(
                &package,
                &config,
                &runtime,
                AmbientAuthorityGrant::DenyAll,
                &[],
                None,
                None,
                &orchestrator,
                &error,
            )
            .expect("capture the same finalized native stop explicitly");
            assert_eq!(capture, explicit);
            capture
        }

        #[test]
        fn engine_failure_console_replay_preserves_both_limits_and_lanes() {
            on_native_stack(|| {
                for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
                    for byte_stop in [false, true] {
                        let root = tempfile::tempdir().unwrap();
                        let capture =
                            capture_stopped_run(console_stopped_run(root.path(), byte_stop, lane));
                        let payload: NativeReplayPayload =
                            serde_json::from_str(&capture.payload_json).unwrap();
                        let CapturedAttempt::EngineFailure(expected) = &payload.expected else {
                            panic!("console limit must remain a typed engine failure");
                        };
                        assert!(matches!(
                            expected.reason,
                            EngineFailureReason::ConsoleBudgetExceeded { .. }
                        ));
                        assert_eq!(expected.console_output.len(), 1);
                        assert_eq!(expected.console_output[0].message, "before-engine-stop");
                        assert_eq!(payload.host_effect_transcript.len(), 2);
                        assert!(
                            capture.payload_json.len() < 32 * 1024,
                            "the refused oversized message must not enter the retained capture"
                        );
                        for name in ["stopped.cjs", "input.txt", "output.txt"] {
                            std::fs::rename(
                                root.path().join(name),
                                root.path().join(format!("saved-{name}")),
                            )
                            .unwrap();
                        }
                        let outcome = reexecute(&capture).expect("replay native console limit");
                        assert!(outcome.matched, "{lane:?}, bytes={byte_stop}: {outcome:?}");
                        assert_eq!(outcome.verification_scope, "engine_failure_prefix");
                        assert_eq!(
                            outcome.replay_terminal_state,
                            NativeReplayTerminalState::EngineFailure
                        );
                        assert!(
                            outcome.terminal_state_match
                                && outcome.console_match
                                && outcome.host_effects_match
                        );
                        assert_eq!(outcome.ir3_hash_match, Some(true));
                        assert_eq!(outcome.ir4_witness_match, None);
                        assert_eq!(outcome.instruction_count_match, Some(true));
                        assert_eq!(outcome.nondeterminism_trace_match, Some(true));
                        assert_eq!(outcome.exception_value_match, None);
                        assert_eq!(outcome.decisions_match, None);
                        assert!(
                            !root.path().join("output.txt").exists(),
                            "offline replay must not repeat the captured write"
                        );
                        assert_eq!(
                            std::fs::read_to_string(root.path().join("saved-output.txt")).unwrap(),
                            "captured-before-stop",
                        );
                    }
                }
            });
        }

        #[test]
        fn engine_failure_console_payload_refuses_forged_limits_and_nonexhaustion() {
            on_native_stack(|| {
                let root = tempfile::tempdir().unwrap();
                let capture = capture_stopped_run(console_stopped_run(
                    root.path(),
                    false,
                    LaneChoice::QuickJs,
                ));
                let original: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                for mutate in [
                    (|p: &mut NativeReplayPayload| {
                        let CapturedAttempt::EngineFailure(failure) = &mut p.expected else {
                            panic!()
                        };
                        let EngineFailureReason::ConsoleBudgetExceeded { max_entries, .. } =
                            &mut failure.reason
                        else {
                            panic!()
                        };
                        *max_entries += 1;
                    }) as fn(&mut NativeReplayPayload),
                    |p| {
                        let CapturedAttempt::EngineFailure(failure) = &mut p.expected else {
                            panic!()
                        };
                        let EngineFailureReason::ConsoleBudgetExceeded { max_bytes, .. } =
                            &mut failure.reason
                        else {
                            panic!()
                        };
                        *max_bytes += 1;
                    },
                    |p| {
                        let CapturedAttempt::EngineFailure(failure) = &mut p.expected else {
                            panic!()
                        };
                        let EngineFailureReason::ConsoleBudgetExceeded {
                            entries,
                            max_entries,
                            bytes,
                            max_bytes,
                        } = &mut failure.reason
                        else {
                            panic!()
                        };
                        *entries = *max_entries;
                        *bytes = *max_bytes;
                    },
                    |p| p.runtime.execution.max_console_entries = Some(3),
                    |p| p.runtime.execution.max_console_entries = None,
                ] {
                    let mut changed = original.clone();
                    mutate(&mut changed);
                    let error = changed
                        .validate()
                        .expect_err("unbound or unexceeded console limit");
                    assert!(error.starts_with("captured console"), "{error}");
                    assert!(reexecute(&encode_capture(&changed).unwrap()).is_err());
                }
            });
        }

        #[test]
        fn engine_failure_console_replay_requires_exact_observation_and_complete_effects() {
            on_native_stack(|| {
                let root = tempfile::tempdir().unwrap();
                let capture = capture_stopped_run(console_stopped_run(
                    root.path(),
                    false,
                    LaneChoice::QuickJs,
                ));
                let original: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                for mutate in [
                    (|f: &mut CapturedEngineFailure| {
                        let EngineFailureReason::ConsoleBudgetExceeded { entries, .. } =
                            &mut f.reason
                        else {
                            panic!()
                        };
                        *entries += 1;
                    }) as fn(&mut CapturedEngineFailure),
                    |f| {
                        let EngineFailureReason::ConsoleBudgetExceeded { bytes, .. } =
                            &mut f.reason
                        else {
                            panic!()
                        };
                        *bytes += 1;
                    },
                    |f| f.diagnostic.push_str(" altered"),
                    |f| f.console_output[0].message.push_str(" altered"),
                ] {
                    let mut changed = original.clone();
                    let CapturedAttempt::EngineFailure(failure) = &mut changed.expected else {
                        panic!()
                    };
                    mutate(failure);
                    // Bypass only the outer hash to exercise the exact native
                    // comparison. An authenticated envelope also rejects edits.
                    let outcome = reexecute(&encode_capture(&changed).unwrap()).unwrap();
                    assert!(!outcome.matched, "{outcome:?}");
                    assert!(outcome.terminal_state_match && outcome.host_effects_match);
                }
                for mutate in [
                    (|p: &mut NativeReplayPayload| {
                        p.host_effect_transcript.remove(0);
                    }) as fn(&mut NativeReplayPayload),
                    |p| p.host_effect_transcript.swap(0, 1),
                    |p| {
                        p.host_effect_transcript
                            .push(p.host_effect_transcript[0].clone())
                    },
                ] {
                    let mut changed = original.clone();
                    mutate(&mut changed);
                    assert!(
                        reexecute(&encode_capture(&changed).unwrap()).is_err(),
                        "a repeated console stop cannot excuse a corrupt effect prefix"
                    );
                }
                let mut changed = original;
                changed.package.source =
                    format!("{STOP_PREFIX} throw 'console output budget exceeded';");
                let outcome = reexecute(&encode_capture(&changed).unwrap()).unwrap();
                assert!(!outcome.matched && !outcome.terminal_state_match);
                assert_eq!(
                    outcome.replay_terminal_state,
                    NativeReplayTerminalState::UncaughtException
                );
                assert!(outcome.console_match && outcome.host_effects_match);
            });
        }

        #[test]
        fn engine_failure_console_capture_requires_native_finalization() {
            on_native_stack(|| {
                for wrong_trace in [false, true] {
                    let root = tempfile::tempdir().unwrap();
                    let (package, config, runtime, orchestrator, mut error) =
                        console_stopped_run(root.path(), false, LaneChoice::QuickJs);
                    let OrchestratorError::Interpreter(InterpreterError::ConsoleBudgetExceeded {
                        entries,
                        max_entries,
                        bytes,
                        max_bytes,
                    }) = error.primary_error()
                    else {
                        panic!()
                    };
                    let unfinalized =
                        OrchestratorError::Interpreter(InterpreterError::ConsoleBudgetExceeded {
                            entries: *entries,
                            max_entries: *max_entries,
                            bytes: *bytes,
                            max_bytes: *max_bytes,
                        });
                    assert!(
                        NativeReplayCapture::from_finalized_failure(
                            &package,
                            &config,
                            &runtime,
                            AmbientAuthorityGrant::DenyAll,
                            &[],
                            None,
                            None,
                            &orchestrator,
                            &unfinalized,
                        )
                        .is_err(),
                        "typed console limits alone do not certify cell cleanup"
                    );
                    let OrchestratorError::PostCellFailure(failure) = &mut error else {
                        panic!()
                    };
                    if wrong_trace {
                        failure.cleanup.trace_id.push_str("-different");
                    } else {
                        failure
                            .additional_errors
                            .push(OrchestratorError::Interpreter(InterpreterError::Cancelled));
                    }
                    assert!(
                        NativeReplayCapture::from_finalized_failure(
                            &package,
                            &config,
                            &runtime,
                            AmbientAuthorityGrant::DenyAll,
                            &[],
                            None,
                            None,
                            &orchestrator,
                            &error,
                        )
                        .is_err()
                    );
                }
            });
        }

        #[test]
        fn engine_failure_replay_preserves_real_prefix_without_repeating_effects() {
            on_native_stack(|| {
                for budget_stop in [false, true] {
                    let root = tempfile::tempdir().unwrap();
                    let capture = capture_stop(root.path(), budget_stop);
                    assert_eq!(
                        capture.terminal_state().unwrap(),
                        NativeReplayTerminalState::EngineFailure
                    );
                    let payload: NativeReplayPayload =
                        serde_json::from_str(&capture.payload_json).unwrap();
                    assert_eq!(payload.host_effect_transcript.len(), 2);
                    let CapturedAttempt::EngineFailure(expected) = &payload.expected else {
                        panic!("engine stop must not be relabeled as a guest exception");
                    };
                    assert!(!expected.console_output.is_empty());
                    for name in ["stopped.cjs", "input.txt", "output.txt"] {
                        std::fs::rename(
                            root.path().join(name),
                            root.path().join(format!("saved-{name}")),
                        )
                        .unwrap();
                    }
                    let outcome = reexecute(&capture).expect("replay finalized native stop");
                    assert!(outcome.matched, "{outcome:?}");
                    assert_eq!(outcome.verification_scope, "engine_failure_prefix");
                    assert!(
                        outcome.terminal_state_match
                            && outcome.console_match
                            && outcome.host_effects_match
                    );
                    assert_eq!(
                        outcome.replay_terminal_state,
                        NativeReplayTerminalState::EngineFailure
                    );
                    assert_eq!(outcome.ir3_hash_match, Some(true));
                    assert_eq!(outcome.ir4_witness_match, None);
                    assert_eq!(outcome.instruction_count_match, Some(true));
                    assert_eq!(outcome.nondeterminism_trace_match, Some(true));
                    assert_eq!(outcome.exception_value_match, None);
                    assert_eq!(outcome.decisions_match, None);
                    assert!(outcome.module_load_disabled);
                    assert!(!root.path().join("output.txt").exists());
                    assert_eq!(
                        std::fs::read_to_string(root.path().join("saved-output.txt")).unwrap(),
                        "captured-before-stop"
                    );
                }
            });
        }

        #[test]
        fn engine_failure_replay_requires_exact_reason_and_native_diagnostic() {
            on_native_stack(|| {
                for budget_stop in [false, true] {
                    let root = tempfile::tempdir().unwrap();
                    let capture = capture_stop(root.path(), budget_stop);
                    let original: NativeReplayPayload =
                        serde_json::from_str(&capture.payload_json).unwrap();
                    for change_reason in [false, true] {
                        let mut changed = original.clone();
                        let CapturedAttempt::EngineFailure(expected) = &mut changed.expected else {
                            panic!()
                        };
                        if change_reason {
                            expected.reason = EngineFailureReason::CapabilityDenied {
                                capability: "fs_write".into(),
                            };
                        } else {
                            expected.diagnostic.push_str(" altered");
                        }
                        // Rehash to test execution comparison independently of
                        // the enclosing signature, which would also reject it.
                        let outcome = reexecute(&encode_capture(&changed).unwrap()).unwrap();
                        assert!(!outcome.matched);
                        assert!(outcome.terminal_state_match && outcome.host_effects_match);
                        assert!(
                            outcome.divergences.iter().any(|detail| detail.contains(
                                if change_reason {
                                    "engine failure reason"
                                } else {
                                    "diagnostic"
                                }
                            )),
                            "{outcome:?}"
                        );
                    }
                }
            });
        }

        #[test]
        fn engine_failure_replay_never_confuses_completion_guest_throw_or_another_stop() {
            on_native_stack(|| {
                let root = tempfile::tempdir().unwrap();
                let capture = capture_stop(root.path(), true);
                let original: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                for ending in [
                    "42;",
                    "throw 'instruction budget exhausted';",
                    "process.env.MISSING;",
                ] {
                    let mut changed = original.clone();
                    changed.package.source = format!("{STOP_PREFIX} {ending}");
                    let outcome = reexecute(&encode_capture(&changed).unwrap()).unwrap();
                    assert!(!outcome.matched, "{ending}: {outcome:?}");
                    assert!(outcome.console_match && outcome.host_effects_match);
                    assert_eq!(outcome.exception_value_match, None);
                    assert_eq!(
                        outcome.terminal_state_match,
                        ending == "process.env.MISSING;"
                    );
                }
            });
        }

        #[test]
        fn engine_failure_replay_refuses_missing_reordered_and_unused_effects() {
            on_native_stack(|| {
                for budget_stop in [false, true] {
                    let root = tempfile::tempdir().unwrap();
                    let capture = capture_stop(root.path(), budget_stop);
                    let original: NativeReplayPayload =
                        serde_json::from_str(&capture.payload_json).unwrap();
                    for mutate in [
                        (|p: &mut NativeReplayPayload| {
                            p.host_effect_transcript.remove(0);
                        }) as fn(&mut NativeReplayPayload),
                        |p| p.host_effect_transcript.swap(0, 1),
                        |p| p.host_effect_transcript.clear(),
                        |p| {
                            p.host_effect_transcript
                                .push(p.host_effect_transcript[0].clone())
                        },
                    ] {
                        let mut changed = original.clone();
                        mutate(&mut changed);
                        assert!(
                            reexecute(&encode_capture(&changed).unwrap()).is_err(),
                            "a matching stop cannot excuse an uncertified recorder boundary"
                        );
                    }
                }
            });
        }

        #[test]
        fn engine_failure_capture_rejects_uncertified_cleanup_and_wrong_trace() {
            on_native_stack(|| {
                for wrong_trace in [false, true] {
                    let root = tempfile::tempdir().unwrap();
                    let (package, config, runtime, orchestrator, mut error) =
                        stopped_run(root.path(), false);
                    let OrchestratorError::PostCellFailure(failure) = &mut error else {
                        panic!("native stop must carry finalized cell evidence");
                    };
                    if wrong_trace {
                        failure.cleanup.trace_id.push_str("-different");
                    } else {
                        failure
                            .additional_errors
                            .push(OrchestratorError::Interpreter(InterpreterError::Cancelled));
                    }
                    assert!(
                        NativeReplayCapture::from_finalized_failure(
                            &package,
                            &config,
                            &runtime,
                            AmbientAuthorityGrant::DenyAll,
                            &[],
                            None,
                            None,
                            &orchestrator,
                            &error,
                        )
                        .is_err()
                    );
                }
            });
        }

        #[test]
        fn engine_failure_capture_never_infers_certification_from_diagnostic_text() {
            assert!(engine_failure_reason(&InterpreterError::Cancelled).is_none());
            for value in [
                "capability denied: env_read",
                "instruction budget exhausted",
                "wrapper_timeout",
            ] {
                assert!(
                    engine_failure_reason(&InterpreterError::UncaughtException {
                        value: value.into()
                    })
                    .is_none()
                );
            }
            assert_eq!(
                engine_failure_reason(&InterpreterError::CapabilityDenied {
                    capability: "env_read".into()
                }),
                Some(EngineFailureReason::CapabilityDenied {
                    capability: "env_read".into()
                })
            );
            on_native_stack(|| {
                let root = tempfile::tempdir().unwrap();
                let (package, config, runtime, orchestrator, _) = stopped_run(root.path(), false);
                for error in [
                    OrchestratorError::Interpreter(InterpreterError::Cancelled),
                    OrchestratorError::Interpreter(InterpreterError::CapabilityDenied {
                        capability: "env_read".into(),
                    }),
                    OrchestratorError::Interpreter(InterpreterError::UncaughtException {
                        value: "instruction budget exhausted".into(),
                    }),
                ] {
                    assert!(
                        NativeReplayCapture::from_finalized_failure(
                            &package,
                            &config,
                            &runtime,
                            AmbientAuthorityGrant::DenyAll,
                            &[],
                            None,
                            None,
                            &orchestrator,
                            &error,
                        )
                        .is_err(),
                        "a previous finalized attempt does not certify an unrelated error"
                    );
                }
            });
        }

        #[test]
        fn engine_failure_payload_preflight_refuses_unbound_limits_and_module_authority() {
            on_native_stack(|| {
                let root = tempfile::tempdir().unwrap();
                let capture = capture_stop(root.path(), true);
                let original: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                for mutate in [
                    (|f: &mut CapturedEngineFailure| f.trace_id.clear())
                        as fn(&mut CapturedEngineFailure),
                    |f| f.diagnostic.clear(),
                    |f| f.diagnostic = "x".repeat(4097),
                    |f| {
                        f.reason = EngineFailureReason::CapabilityDenied {
                            capability: "unknown_capability".into(),
                        }
                    },
                    |f| {
                        f.reason = EngineFailureReason::CapabilityDenied {
                            capability: "module_load".into(),
                        }
                    },
                    |f| f.reason = EngineFailureReason::InstructionBudgetExhausted { budget: 7 },
                ] {
                    let mut changed = original.clone();
                    let CapturedAttempt::EngineFailure(failure) = &mut changed.expected else {
                        panic!()
                    };
                    mutate(failure);
                    assert!(changed.validate().is_err());
                    assert!(reexecute(&encode_capture(&changed).unwrap()).is_err());
                }
            });
        }

        fn record_with_inputs(
            root: &Path,
            source: &str,
            ambient_authority: AmbientAuthorityGrant,
            process_argv: &[String],
        ) -> NativeReplayCapture {
            let config = OrchestratorConfig {
                commonjs_entry: false,
                ..OrchestratorConfig::default()
            };
            let runtime = RuntimeConfig::default();
            let path = root.join("app.cjs");
            std::fs::write(&path, source).expect("write original entry");
            let package = ExtensionPackage {
                extension_id: "native-replay-regression".to_string(),
                source: source.to_string(),
                source_file: Some(path.display().to_string()),
                module_root: Some(root.display().to_string()),
                // ModuleLoad is present in every normal product profile. Its
                // absence during replay must not alter this builtin-only run.
                capabilities: ["module_load", "fs_read", "fs_write", "builtin", "timer"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                version: "test".to_string(),
                metadata: BTreeMap::new(),
            };
            let authority = RuntimeEvidenceAuthority::generate_runtime_owned(
                "franken-node.native-replay-test",
                config.epoch,
                1,
                None,
            )
            .expect("runtime authority");
            let mut orchestrator =
                ExecutionOrchestrator::try_new_with_runtime_config_and_authority(
                    config.clone(),
                    runtime.clone(),
                    ambient_authority,
                    authority,
                )
                .expect("native recorder");
            orchestrator.set_process_argv(process_argv.to_vec());
            orchestrator.set_host_io(
                Arc::new(SandboxedHostIo::with_root(root).expect("real filesystem provider")),
                Some(Arc::new(InMemoryHostIoTranscript::recording())),
            );
            match orchestrator.execute(&package) {
                Ok(result) => NativeReplayCapture::from_execution(
                    &package,
                    &config,
                    &runtime,
                    ambient_authority,
                    process_argv,
                    None,
                    None,
                    &result,
                ),
                Err(error) => NativeReplayCapture::from_failed_execution(
                    &package,
                    &config,
                    &runtime,
                    ambient_authority,
                    process_argv,
                    None,
                    None,
                    &orchestrator,
                    &error,
                ),
            }
            .expect("capture actual native result")
        }

        #[cfg(unix)]
        fn process_provider(
            root: &Path,
            ceiling: Option<&EffectiveCapabilityCeiling>,
        ) -> Arc<CapturingProcessSpawnProvider> {
            let mut policy =
                ProcessSpawnPolicy::jailed(root).expect("jailed native process policy");
            for (alias, candidates) in [
                ("mark", ["/usr/bin/touch", "/bin/touch"]),
                ("emit", ["/usr/bin/printf", "/bin/printf"]),
                ("shell", ["/usr/bin/sh", "/bin/sh"]),
            ] {
                let executable = candidates
                    .iter()
                    .map(Path::new)
                    .find(|path| path.is_file())
                    .expect("standard Unix fixture executable");
                policy
                    .authorize_alias(alias, executable)
                    .expect("authorize exact fixture executable");
            }
            policy.allow_shell = true;
            policy.shell_executable_alias = Some("shell".to_string());
            let provider: Arc<dyn ProcessSpawnProvider> =
                Arc::new(NativeProcessSpawn::new(policy).expect("native process provider"));
            let provider = match ceiling {
                Some(ceiling) => Arc::new(
                    crate::ops::engine_dispatcher::PublisherAuthorityProcessSpawn::new(
                        provider,
                        ceiling.clone(),
                    )
                    .expect("enforceable publisher process ceiling"),
                ) as Arc<dyn ProcessSpawnProvider>,
                None => provider,
            };
            Arc::new(CapturingProcessSpawnProvider::new(provider))
        }

        #[cfg(unix)]
        fn record_process(root: &Path, source: &str) -> NativeReplayCapture {
            record_process_under_ceiling(root, source, None)
        }

        #[cfg(unix)]
        fn record_process_under_ceiling(
            root: &Path,
            source: &str,
            ceiling: Option<&EffectiveCapabilityCeiling>,
        ) -> NativeReplayCapture {
            let config = OrchestratorConfig {
                commonjs_entry: false,
                ..OrchestratorConfig::default()
            };
            let runtime = RuntimeConfig::default();
            let path = root.join("process.cjs");
            std::fs::write(&path, source).expect("write original process source");
            let package = ExtensionPackage {
                extension_id: "native-process-replay-regression".to_string(),
                source: source.to_string(),
                source_file: Some(path.display().to_string()),
                module_root: Some(root.display().to_string()),
                capabilities: [
                    "module_load",
                    "process_spawn",
                    "builtin",
                    "fs_read",
                    "fs_write",
                    "timer",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
                version: "test".to_string(),
                metadata: BTreeMap::new(),
            };
            let authority = RuntimeEvidenceAuthority::generate_runtime_owned(
                "franken-node.native-process-replay-test",
                config.epoch,
                1,
                None,
            )
            .expect("runtime-owned test evidence authority");
            let mut orchestrator =
                ExecutionOrchestrator::try_new_with_runtime_config_and_authority(
                    config.clone(),
                    runtime.clone(),
                    AmbientAuthorityGrant::DenyAll,
                    authority,
                )
                .expect("native process recorder");
            orchestrator.set_host_io(
                Arc::new(SandboxedHostIo::with_root(root).expect("live bounded host I/O")),
                Some(Arc::new(InMemoryHostIoTranscript::recording())),
            );
            let provider = process_provider(root, ceiling);
            let expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock")
                .as_millis();
            let expires_at = u64::try_from(expires_at)
                .expect("test time fits")
                .saturating_add(60_000);
            orchestrator.set_process_spawn(
                provider.clone(),
                Arc::new(InMemoryHostEffectJournal::recording()),
                ProcessSpawnAttemptAuthority::expiring_at_unix_ms(expires_at),
            );
            let capture = match orchestrator.execute(&package) {
                Ok(result) => NativeReplayCapture::from_execution(
                    &package,
                    &config,
                    &runtime,
                    AmbientAuthorityGrant::DenyAll,
                    &[],
                    Some(provider.as_ref()),
                    None,
                    &result,
                ),
                Err(error) => NativeReplayCapture::from_failed_execution(
                    &package,
                    &config,
                    &runtime,
                    AmbientAuthorityGrant::DenyAll,
                    &[],
                    Some(provider.as_ref()),
                    None,
                    &orchestrator,
                    &error,
                )
                .map_err(|capture_error| {
                    format!(
                        "native process execution failed: {error}; replay capture refused: {capture_error}"
                    )
                }),
            }
            .expect("capture real process execution");
            match ceiling {
                Some(ceiling) => capture
                    .with_capability_ceiling(ceiling)
                    .expect("bind the exact enforced publisher process ceiling"),
                None => capture,
            }
        }

        #[test]
        #[cfg(unix)]
        fn scoped_process_reexecution_preserves_quota_without_repeating_live_effects() {
            on_native_stack(|| {
                let root = tempfile::tempdir().unwrap();
                let admitted = root.path().join("admitted-child-marker");
                let denied = root.path().join("denied-child-marker");
                let admitted_json = serde_json::to_string(&admitted.display().to_string()).unwrap();
                let denied_json = serde_json::to_string(&denied.display().to_string()).unwrap();
                let source = format!(
                    "const cp = require('child_process'); cp.execFileSync('mark', [{admitted_json}]); try {{ cp.execFileSync('mark', [{denied_json}]); console.log('quota-bypassed'); }} catch (error) {{ console.log('quota-enforced'); }}",
                );
                let ceiling = scoped_process_ceiling(1);
                let capture = record_process_under_ceiling(root.path(), &source, Some(&ceiling));
                assert!(
                    admitted.is_file(),
                    "an admitted child performs its real effect"
                );
                assert!(
                    !denied.exists(),
                    "exhaustion prevents a second child effect"
                );
                let payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                let process = payload.process.as_ref().unwrap();
                assert!(process.journal.iter().any(|entry| matches!(entry,
                    HostEffectJournalEntry::ProcessSpawn { outcome, .. }
                        if *outcome == process_quota_denial()
                )));
                std::fs::rename(&admitted, root.path().join("saved-admitted-marker")).unwrap();
                std::fs::rename(
                    root.path().join("process.cjs"),
                    root.path().join("saved-process.cjs"),
                )
                .unwrap();
                for _ in 0..2 {
                    let outcome = reexecute(&capture).expect("offline scoped process replay");
                    assert!(outcome.satisfies_policy_equivalence(), "{outcome:?}");
                    assert!(!admitted.exists());
                    assert!(!denied.exists());
                }
                let mut weakened = payload.clone();
                weakened
                    .capability_ceiling
                    .as_mut()
                    .unwrap()
                    .max_calls_per_epoch
                    .insert("process_spawn".into(), 2);
                let error = reexecute(&encode_capture(&weakened).unwrap()).unwrap_err();
                assert!(error.contains("invocation policy"), "{error}");
                let mut stripped = payload.clone();
                stripped.capability_ceiling = None;
                let stripped_capture = encode_capture(&stripped).unwrap();
                assert_eq!(
                    stripped_capture.schema_version,
                    NATIVE_REPLAY_CAPTURE_SCHEMA
                );
                let error = reexecute(&stripped_capture)
                    .expect_err("process-only denials cannot downgrade publisher authority");
                assert!(
                    error.contains("require the captured publisher ceiling"),
                    "{error}"
                );
                for replacement in [
                    ProcessSpawnError::Io {
                        operation: "fixture".into(),
                        detail: "provider failure cannot replace an exhausted refusal".into(),
                    },
                    ProcessSpawnError::FlowPolicyBlocked,
                ] {
                    let mut forged = payload.clone();
                    for entry in &mut forged.process.as_mut().unwrap().journal {
                        if let HostEffectJournalEntry::ProcessSpawn { outcome, .. } = entry
                            && *outcome == process_quota_denial()
                        {
                            *outcome = Err(replacement.clone());
                        }
                    }
                    reexecute(&encode_capture(&forged).unwrap())
                        .expect_err("typed provider/IFC errors cannot evade the publisher quota");
                }
                assert!(!admitted.exists());
                assert!(!denied.exists());
            });
        }

        #[test]
        #[cfg(unix)]
        fn process_reexecution_preserves_success_and_exception_without_repeating_live_effects() {
            on_native_stack(|| {
                for throws in [false, true] {
                    let root = tempfile::tempdir().expect("native process replay root");
                    let marker = root.path().join("process-marker");
                    let marker_json = serde_json::to_string(&marker.display().to_string()).unwrap();
                    let source = format!(
                        "const cp = require('child_process'); const fs = require('fs'); cp.execFileSync('mark', [{marker_json}]); fs.writeFileSync('host-marker.txt', 'captured-host-output'); console.log(cp.execFileSync('emit', ['captured-process-output'], {{ encoding: 'utf8' }})); {}",
                        if throws {
                            "throw 'captured-process-failure';"
                        } else {
                            ""
                        },
                    );
                    let capture = record_process(root.path(), &source);
                    assert!(
                        marker.is_file(),
                        "the original child really performed its effect"
                    );
                    std::fs::rename(&marker, root.path().join("saved-process-marker")).unwrap();
                    std::fs::rename(
                        root.path().join("host-marker.txt"),
                        root.path().join("saved-host-marker.txt"),
                    )
                    .unwrap();
                    std::fs::rename(
                        root.path().join("process.cjs"),
                        root.path().join("saved-process.cjs"),
                    )
                    .unwrap();
                    let payload: NativeReplayPayload =
                        serde_json::from_str(&capture.payload_json).unwrap();
                    assert_eq!(
                        payload.host_io_exception_provenance,
                        HostIoExceptionProvenance::ProviderInternal,
                        "the exact bounded I/O source preserves the original provider's floor"
                    );
                    let process = payload.process.as_ref().expect("ordered process capture");
                    assert!(
                        process.journal.iter().any(|entry| matches!(
                            entry,
                            HostEffectJournalEntry::ProcessSpawn { .. }
                        ))
                    );
                    assert!(process.preparation.iter().any(|entry| matches!(entry,
                        CapturedProcessPreparation::Prepare { request: original, outcome: Ok(prepared) } if original != prepared
                    )), "record the actual alias-to-executable preparation");
                    let outcome =
                        reexecute(&capture).expect("replay with expired process authority");
                    assert!(outcome.matched, "{outcome:?}");
                    assert!(outcome.host_effects_match);
                    assert!(outcome.console_match);
                    assert_eq!(
                        outcome.captured_terminal_state,
                        if throws {
                            NativeReplayTerminalState::UncaughtException
                        } else {
                            NativeReplayTerminalState::Completed
                        }
                    );
                    assert!(
                        !marker.exists(),
                        "replay must never spawn the marker writer"
                    );
                    assert!(
                        !root.path().join("host-marker.txt").exists(),
                        "ordered process replay must not repeat interleaved filesystem effects"
                    );
                    assert!(
                        !root.path().join("process.cjs").exists(),
                        "source comes from the capture"
                    );
                    assert!(root.path().join("saved-process-marker").exists());
                }
            });
        }

        #[test]
        #[cfg(unix)]
        fn process_reexecution_uses_captured_shell_preparation_and_policy_denials() {
            on_native_stack(|| {
                let root = tempfile::tempdir().unwrap();
                let capture = record_process(
                    root.path(),
                    "const cp = require('child_process'); const out = cp.execSync('printf shell-output', { encoding: 'utf8' }); console.log(out); try { cp.execFileSync(out ? 'unapproved-command' : 'printf', [], { encoding: 'utf8' }); } catch (error) { console.log('expected-policy-denial'); }",
                );
                let payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                let CapturedAttempt::Completed(completed) = &payload.expected else {
                    panic!(
                        "shell and caught policy denial must complete: {:?}",
                        payload.expected
                    );
                };
                assert_eq!(
                    completed
                        .console_output
                        .iter()
                        .map(|entry| entry.message.as_str())
                        .collect::<Vec<_>>(),
                    ["shell-output", "expected-policy-denial"]
                );
                let process = payload.process.as_ref().unwrap();
                assert!(
                    process.preparation.iter().any(|entry| matches!(
                        entry,
                        CapturedProcessPreparation::Prepare {
                            request,
                            outcome: Ok(prepared),
                        } if request != prepared
                    )),
                    "capture the actual shell executable selection"
                );
                assert!(
                    process.preparation.iter().all(|entry| match entry {
                        CapturedProcessPreparation::Preflight { outcome, .. } => outcome.is_ok(),
                        CapturedProcessPreparation::Prepare { outcome, .. } => outcome.is_ok(),
                    }),
                    "IFC must refuse the tainted request before provider preparation"
                );
                assert!(
                    process.journal.iter().any(|entry| matches!(
                        entry,
                        HostEffectJournalEntry::ProcessSpawn {
                            outcome: Err(ProcessSpawnError::FlowPolicyBlocked),
                            ..
                        }
                    )),
                    "preserve the exact IFC refusal: {:?}",
                    process.journal
                );
                let outcome =
                    reexecute(&capture).expect("replay exact signed shell selection and denial");
                assert!(outcome.matched, "{outcome:?}");
                assert!(outcome.host_effects_match && outcome.console_match);

                // Use a clean request to exercise the provider's preparation
                // refusal too. Child output in the original scenario taints
                // the later request, so that scenario cannot prove this phase.
                let denied_root = tempfile::tempdir().unwrap();
                let denied_capture = record_process(
                    denied_root.path(),
                    "const cp = require('child_process'); try { cp.execFileSync('unapproved-command', [], { encoding: 'utf8' }); } catch (error) { console.log('expected-policy-denial'); }",
                );
                let denied_payload: NativeReplayPayload =
                    serde_json::from_str(&denied_capture.payload_json).unwrap();
                let CapturedAttempt::Completed(denied_completed) = &denied_payload.expected else {
                    panic!(
                        "caught preparation refusal must complete: {:?}",
                        denied_payload.expected
                    );
                };
                assert_eq!(
                    denied_completed
                        .console_output
                        .iter()
                        .map(|entry| entry.message.as_str())
                        .collect::<Vec<_>>(),
                    ["expected-policy-denial"]
                );
                let denied_process = denied_payload.process.as_ref().unwrap();
                let (denied_request, denied_error) = denied_process
                    .preparation
                    .iter()
                    .find_map(|entry| match entry {
                        CapturedProcessPreparation::Prepare {
                            request,
                            outcome: Err(error @ ProcessSpawnError::PolicyViolation { code, .. }),
                        } if code == "executable_alias_denied" => Some((request, error)),
                        _ => None,
                    })
                    .expect("the clean request must reach executable-alias preparation policy");
                assert!(
                    denied_process.journal.iter().any(|entry| matches!(
                        entry,
                        HostEffectJournalEntry::ProcessSpawn {
                            request,
                            outcome: Err(error),
                        } if request == denied_request && error == denied_error
                    )),
                    "journal the exact preparation request and typed refusal"
                );
                let denied_outcome = reexecute(&denied_capture)
                    .expect("replay the exact executable-alias preparation refusal");
                assert!(denied_outcome.matched, "{denied_outcome:?}");
                assert!(denied_outcome.host_effects_match && denied_outcome.console_match);
            });
        }

        #[test]
        #[cfg(unix)]
        fn process_reexecution_rejects_unknown_preparation_even_when_guest_catches_error() {
            on_native_stack(|| {
                for throws in [false, true] {
                    let root = tempfile::tempdir().unwrap();
                    let source = format!(
                        "const cp = require('child_process'); try {{ cp.execFileSync('emit', ['original'], {{ encoding: 'utf8' }}); }} catch (error) {{ }} console.log('after-attempt'); {}",
                        if throws {
                            "throw 'captured-failure';"
                        } else {
                            ""
                        },
                    );
                    let capture = record_process(root.path(), &source);
                    let original =
                        reexecute(&capture).expect("untampered process preparation must replay");
                    assert!(original.matched, "{original:?}");
                    assert!(original.host_effects_match);
                    assert!(original.console_match);
                    assert_eq!(
                        original.captured_terminal_state,
                        if throws {
                            NativeReplayTerminalState::UncaughtException
                        } else {
                            NativeReplayTerminalState::Completed
                        }
                    );
                    for missing_preflight in [false, true] {
                        let mut payload: NativeReplayPayload =
                            serde_json::from_str(&capture.payload_json).unwrap();
                        let process = payload.process.as_mut().unwrap();
                        process
                            .preparation
                            .retain(|entry| entry.is_preflight() != missing_preflight);
                        // In the preflight case, neither the guest-visible
                        // terminal state nor a leftover journal entry can
                        // reveal the swallowed denial. The replay diagnostic
                        // must still refuse to certify this incomplete input.
                        process.journal.clear();
                        payload.validate().expect("bounded but incomplete capture");
                        let changed = encode_capture(&payload).unwrap();
                        let error = reexecute(&changed)
                            .expect_err("guest catch cannot hide missing preparation");
                        assert!(error.contains("even if the guest caught"), "{error}");
                    }
                }
            });
        }

        #[test]
        #[cfg(unix)]
        fn process_reexecution_enforces_global_effect_order_and_unused_suffix() {
            on_native_stack(|| {
                for throws in [false, true] {
                    let root = tempfile::tempdir().unwrap();
                    let source = format!(
                        "const cp = require('child_process'); const fs = require('fs'); console.log(cp.execFileSync('emit', ['first'], {{ encoding: 'utf8' }})); fs.writeFileSync('between.txt', 'between'); console.log(cp.execFileSync('emit', ['second'], {{ encoding: 'utf8' }})); {}",
                        if throws {
                            "throw 'ordered-failure';"
                        } else {
                            ""
                        },
                    );
                    let capture = record_process(root.path(), &source);
                    let mut reordered: NativeReplayPayload =
                        serde_json::from_str(&capture.payload_json).unwrap();
                    let journal = &mut reordered.process.as_mut().unwrap().journal;
                    assert!(matches!(
                        journal[0],
                        HostEffectJournalEntry::ProcessSpawn { .. }
                    ));
                    assert!(matches!(journal[1], HostEffectJournalEntry::HostIo { .. }));
                    journal.swap(0, 1);
                    reordered
                        .validate()
                        .expect("internally consistent cross-family reordering");
                    reexecute(&encode_capture(&reordered).unwrap()).expect_err(
                        "process/filesystem order is authoritative even in a failed prefix",
                    );
                    let mut trailing: NativeReplayPayload =
                        serde_json::from_str(&capture.payload_json).unwrap();
                    let journal = &mut trailing.process.as_mut().unwrap().journal;
                    journal.push(journal[0].clone());
                    trailing
                        .validate()
                        .expect("internally consistent unused process suffix");
                    reexecute(&encode_capture(&trailing).unwrap()).expect_err(
                        "unused process outcomes cannot certify success or a failed prefix",
                    );
                }
            });
        }

        #[test]
        #[cfg(unix)]
        fn process_capture_rejects_missing_authority_conflicting_preparation_and_unjournaled_preflight()
         {
            on_native_stack(|| {
                let root = tempfile::tempdir().unwrap();
                let capture = record_process(
                    root.path(),
                    "const cp = require('child_process'); console.log(cp.execFileSync('emit', ['capture'], { encoding: 'utf8' }));",
                );
                let mut missing: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                missing.process = None;
                assert!(
                    missing
                        .validate()
                        .unwrap_err()
                        .contains("exact preparation")
                );
                let mut duplicated: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                let process = duplicated.process.as_mut().unwrap();
                process.preparation.push(process.preparation[0].clone());
                assert!(
                    duplicated
                        .validate()
                        .unwrap_err()
                        .contains("repeats a request")
                );
                let payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                let mut request = payload.process.as_ref().unwrap().preparation[0]
                    .request()
                    .clone();
                let ProcessSpawnRequest::Run { launch, .. } = &mut request else {
                    panic!("execFileSync request")
                };
                launch.argv = vec!["x".repeat(MAX_PROCESS_PREPARATION_BYTES + 1)];
                let provider = process_provider(root.path(), None);
                assert!(provider.preflight_request(&request).is_err());
                let preparation = provider
                    .snapshot()
                    .expect("preflight leaves capture state untouched");
                assert!(preparation.is_empty());
                let process = payload.process.as_ref().unwrap();
                let replay = CapturedReplayProcessProvider::new(process.preparation.clone());
                assert_eq!(
                    replay.preflight_request(&request),
                    Err(ProcessSpawnError::Denied {
                        reason: String::new()
                    }),
                    "unknown inputs are refused without allocating a diagnostic"
                );
                let (known_request, known_outcome) = process
                    .preparation
                    .iter()
                    .find_map(|entry| {
                        if let CapturedProcessPreparation::Prepare { request, outcome } = entry {
                            Some((request, outcome))
                        } else {
                            None
                        }
                    })
                    .expect("captured original request preparation");
                assert_eq!(replay.preflight_request(known_request), Ok(()));
                assert_eq!(
                    replay.prepare_request(known_request),
                    *known_outcome,
                    "the diagnostic flag must not change later deterministic provider answers"
                );
                assert!(
                    replay.verify().is_err(),
                    "an unobserved denial is not replay evidence"
                );
                assert!(
                    provider.state.lock().unwrap().entries.is_empty(),
                    "oversized preflight must not allocate retained capture entries"
                );
            });
        }

        #[test]
        fn native_reexecution_restores_captured_process_shape_for_completion_and_exception() {
            on_native_stack(|| {
                for throws in [false, true] {
                    let root = tempfile::tempdir().expect("original argument program");
                    let source = format!(
                        "const fs = require('fs');\n\
                         console.log(process.argv.join('|'));\n\
                         console.log(process.platform);\n\
                         console.log(process.pid);\n\
                         fs.writeFileSync('output.txt', process.argv[2]);\n{}",
                        if throws {
                            "throw process.argv[2];\n"
                        } else {
                            ""
                        }
                    );
                    let argv = vec![
                        "captured-runtime".to_string(),
                        root.path().join("app.cjs").display().to_string(),
                        "captured argument with spaces".to_string(),
                        "βeta".to_string(),
                    ];
                    let capture = record_with_inputs(
                        root.path(),
                        &source,
                        AmbientAuthorityGrant::TrustedProcessShape,
                        &argv,
                    );
                    let payload: NativeReplayPayload =
                        serde_json::from_str(&capture.payload_json).expect("captured shape inputs");
                    assert_eq!(
                        payload.ambient_authority,
                        AmbientAuthorityGrant::TrustedProcessShape
                    );
                    assert_eq!(payload.process_argv, argv);
                    assert_eq!(
                        std::fs::read_to_string(root.path().join("output.txt"))
                            .expect("original write"),
                        "captured argument with spaces"
                    );
                    for name in ["app.cjs", "output.txt"] {
                        std::fs::rename(
                            root.path().join(name),
                            root.path().join(format!("saved-{name}")),
                        )
                        .expect("preserve original inputs outside their execution paths");
                    }
                    let outcome = reexecute(&capture).expect("replay captured process arguments");
                    assert!(outcome.matched, "{outcome:?}");
                    assert!(outcome.console_match);
                    assert!(outcome.host_effects_match);
                    assert!(outcome.module_load_disabled);
                    assert_eq!(
                        outcome.captured_terminal_state,
                        if throws {
                            NativeReplayTerminalState::UncaughtException
                        } else {
                            NativeReplayTerminalState::Completed
                        }
                    );
                    assert!(
                        !root.path().join("output.txt").exists(),
                        "replaying argv must not reinstall a live filesystem provider"
                    );
                }
            });
        }

        #[test]
        fn native_process_shape_replay_detects_changed_arguments_and_denies_other_authority() {
            on_native_stack(|| {
                let root = tempfile::tempdir().expect("argument replay boundary");
                let capture = record_with_inputs(
                    root.path(),
                    "console.log(process.argv[2]);\n",
                    AmbientAuthorityGrant::TrustedProcessShape,
                    &[
                        "runtime".to_string(),
                        "app.cjs".to_string(),
                        "original".to_string(),
                    ],
                );
                let original: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).expect("original capture");
                let mut changed = original.clone();
                changed.process_argv[2] = "changed".to_string();
                let changed = encode_capture(&changed).expect("encode changed arguments");
                let outcome =
                    reexecute(&changed).expect("changed argument program still completes");
                assert!(!outcome.matched);
                assert!(!outcome.console_match);

                for (source, expected_denial) in [
                    ("void process.env.PATH;", "capability denied: env_read"),
                    (
                        "const raw = process; console.log(raw.argv);",
                        "ambient authority violation",
                    ),
                    (
                        "console.log(process['argv']);",
                        "ambient authority violation",
                    ),
                ] {
                    let mut changed = original.clone();
                    changed.package.source = source.to_string();
                    let changed = encode_capture(&changed).expect("encode authority probe");
                    let error =
                        reexecute(&changed).expect_err("shape grant stays narrow in replay");
                    assert!(error.contains(expected_denial), "{source}: {error}");
                }
                let mut oversized = original;
                oversized.process_argv = vec!["x".repeat(MAX_NATIVE_REPLAY_PAYLOAD_BYTES + 1)];
                assert!(
                    oversized
                        .validate()
                        .expect_err("bounded process arguments")
                        .contains("process arguments exceed")
                );
                assert!(encode_capture(&oversized).is_err());
            });
        }

        #[test]
        fn native_reexecution_preserves_canonical_shape_without_optional_captures() {
            on_native_stack(|| {
                // Freeze the v3 field order without optional process/module
                // captures. This checks canonical omission; historical v2
                // envelopes remain unsupported.
                #[derive(Serialize)]
                struct MinimalPayload<'a> {
                    package: &'a ExtensionPackage,
                    orchestrator: &'a CapturedOrchestratorSettings,
                    runtime: &'a RuntimeConfig,
                    ambient_authority: AmbientAuthorityGrant,
                    host_io_exception_provenance: HostIoExceptionProvenance,
                    process_argv: &'a [String],
                    host_effect_transcript: &'a [(HostIoRequest, HostIoOutcome)],
                    expected: &'a CapturedAttempt,
                }

                let root = tempfile::tempdir().expect("minimal capture");
                let capture = record(root.path(), "console.log('existing-v2-capture');");
                let payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).expect("current capture inputs");
                assert!(payload.process.is_none());
                assert!(payload.module_sources.is_none());
                let original_payload_json = serde_json::to_string(&MinimalPayload {
                    package: &payload.package,
                    orchestrator: &payload.orchestrator,
                    runtime: &payload.runtime,
                    ambient_authority: payload.ambient_authority,
                    host_io_exception_provenance: payload.host_io_exception_provenance,
                    process_argv: &payload.process_argv,
                    host_effect_transcript: &payload.host_effect_transcript,
                    expected: &payload.expected,
                })
                .expect("minimal canonical serialization");
                let original = NativeReplayCapture {
                    schema_version: NATIVE_REPLAY_CAPTURE_SCHEMA.to_string(),
                    payload_sha256: hex::encode(Sha256::digest(original_payload_json.as_bytes())),
                    payload_json: original_payload_json,
                };
                assert_eq!(capture, original);
                let outcome = reexecute(&original).expect("accept current canonical shape");
                assert!(outcome.matched, "{outcome:?}");
            });
        }

        #[test]
        fn native_reexecution_uses_captured_source_and_effects_without_repeating_writes() {
            on_native_stack(|| {
                let root = tempfile::tempdir().expect("original application");
                std::fs::write(root.path().join("input.txt"), "captured-value")
                    .expect("original input");
                let capture = record(
                    root.path(),
                    "const fs = require('fs'); const value = fs.readFileSync('input.txt', 'utf8'); fs.writeFileSync('output.txt', value); console.log(value);",
                );
                assert_eq!(
                    std::fs::read_to_string(root.path().join("output.txt")).expect("real output"),
                    "captured-value"
                );
                // Preserve the original files. Replay has no current copy of
                // the entry or data to read and no output file it can reuse.
                for name in ["app.cjs", "input.txt", "output.txt"] {
                    std::fs::rename(
                        root.path().join(name),
                        root.path().join(format!("saved-{name}")),
                    )
                    .expect("preserve original file");
                }
                let outcome = reexecute(&capture).expect("execute captured program");
                assert!(outcome.matched, "{outcome:?}");
                assert!(outcome.module_load_disabled);
                assert_eq!(outcome.verification_scope, "guest_execution");
                assert!(
                    !root.path().join("output.txt").exists(),
                    "replay must not write"
                );
                assert_eq!(
                    std::fs::read_to_string(root.path().join("saved-output.txt"))
                        .expect("preserved output"),
                    "captured-value"
                );
            });
        }

        #[test]
        fn native_reexecution_detects_changed_results_and_unused_transcript_suffixes() {
            on_native_stack(|| {
                let root = tempfile::tempdir().expect("original application");
                let capture = record(root.path(), "console.log('authentic-output');");
                let mut payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).expect("captured input");
                let CapturedAttempt::Completed(expected) = &mut payload.expected else {
                    panic!("successful run must capture a completed attempt");
                };
                expected.execution_value = "forged-result".to_string();
                let changed = encode_capture(&payload).expect("changed expected result");
                let outcome = reexecute(&changed).expect("the source still executes");
                assert!(!outcome.matched);
                assert_eq!(outcome.execution_value_match, Some(false));
                assert!(outcome.console_match);

                payload.host_effect_transcript.push((
                    HostIoRequest::FsRead {
                        path: "unused.txt".to_string(),
                    },
                    Ok(HostIoResponse::FsRead {
                        bytes: b"unconsumed".to_vec(),
                    }),
                ));
                let trailing = encode_capture(&payload).expect("transcript suffix");
                let error = reexecute(&trailing).expect_err("unused data is not a replay");
                assert!(error.contains("unused transcript entries"), "{error}");
            });
        }

        #[test]
        fn native_reexecution_reproduces_uncaught_exception_without_repeating_effects() {
            on_native_stack(|| {
                let root = tempfile::tempdir().expect("original application");
                std::fs::write(root.path().join("input.txt"), "before-throw")
                    .expect("original input");
                let capture = record(
                    root.path(),
                    "const fs = require('fs'); const value = fs.readFileSync('input.txt', 'utf8'); fs.writeFileSync('output.txt', value); console.log(value); throw 'captured-guest-failure';",
                );
                assert_eq!(
                    capture.terminal_state().expect("captured failure state"),
                    NativeReplayTerminalState::UncaughtException
                );
                for name in ["app.cjs", "input.txt", "output.txt"] {
                    std::fs::rename(
                        root.path().join(name),
                        root.path().join(format!("saved-{name}")),
                    )
                    .expect("preserve original failure files");
                }
                let outcome = reexecute(&capture).expect("re-execute recorded guest failure");
                assert!(outcome.matched, "{outcome:?}");
                assert_eq!(outcome.verification_scope, "guest_failure_prefix");
                assert!(outcome.terminal_state_match);
                assert_eq!(outcome.exception_value_match, Some(true));
                assert!(outcome.console_match);
                assert!(outcome.host_effects_match);
                assert_eq!(outcome.ir3_hash_match, Some(true));
                assert_eq!(outcome.ir4_witness_match, None);
                assert_eq!(outcome.execution_value_match, None);
                assert_eq!(outcome.instruction_count_match, Some(true));
                assert_eq!(outcome.nondeterminism_trace_match, Some(true));
                assert_eq!(outcome.lane_match, None);
                assert_eq!(outcome.exit_code_match, None);
                assert_eq!(outcome.decisions_match, None);
                assert!(!root.path().join("app.cjs").exists());
                assert!(!root.path().join("input.txt").exists());
                assert!(!root.path().join("output.txt").exists());
                assert_eq!(
                    std::fs::read_to_string(root.path().join("saved-output.txt"))
                        .expect("preserved original effect"),
                    "before-throw"
                );
            });
        }

        #[test]
        fn failure_reexecution_rejects_changed_exception_unused_effects_and_success() {
            on_native_stack(|| {
                let root = tempfile::tempdir().expect("original application");
                let capture = record(
                    root.path(),
                    "console.log('before-throw'); throw 'original-failure';",
                );
                let mut payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).expect("captured failure input");
                let CapturedAttempt::UncaughtException(expected) = &mut payload.expected else {
                    panic!("throwing run must capture an uncaught exception");
                };
                expected.exception_value = "different-failure".to_string();
                let changed = encode_capture(&payload).expect("changed expected exception");
                let outcome = reexecute(&changed).expect("re-executed guest still throws");
                assert!(!outcome.matched);
                assert!(outcome.terminal_state_match);
                assert_eq!(outcome.exception_value_match, Some(false));
                assert!(outcome.console_match);
                assert!(outcome.host_effects_match);

                let mut trailing: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).expect("original capture");
                trailing.host_effect_transcript.push((
                    HostIoRequest::FsRead {
                        path: "unused.txt".to_string(),
                    },
                    Ok(HostIoResponse::FsRead {
                        bytes: b"unconsumed".to_vec(),
                    }),
                ));
                let trailing = encode_capture(&trailing).expect("unused failure transcript");
                let error = reexecute(&trailing)
                    .expect_err("a matching exception cannot hide an unfinalized transcript");
                assert!(error.contains("unused transcript entries"), "{error}");

                let mut no_throw: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).expect("original capture");
                no_throw.package.source = "console.log('before-throw');".to_string();
                let no_throw = encode_capture(&no_throw).expect("source that now completes");
                let outcome =
                    reexecute(&no_throw).expect("completed replay is a reported mismatch");
                assert!(!outcome.matched);
                assert!(!outcome.terminal_state_match);
                assert_eq!(
                    outcome.replay_terminal_state,
                    NativeReplayTerminalState::Completed
                );
                assert_eq!(outcome.exception_value_match, Some(false));
                assert!(outcome.console_match);
                assert!(outcome.host_effects_match);
                assert_eq!(outcome.ir4_witness_match, None);
            });
        }

        #[test]
        fn failure_reexecution_rejects_tampered_failure_context_fields() {
            on_native_stack(|| {
                let root = tempfile::tempdir().expect("original application");
                let capture = record(
                    root.path(),
                    "console.log('before-throw', Math.random()); throw 'original-failure';",
                );
                let original: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).expect("captured failure payload");
                let CapturedAttempt::UncaughtException(expected) = &original.expected else {
                    panic!("throwing run must capture an uncaught exception");
                };
                assert!(
                    expected.failure_context.is_some(),
                    "direct interpreter failure must retain FailedExecutionReplayContext"
                );

                // Tamper with each authenticated failure-context field and verify
                // replay fails closed with the matching divergence.
                for (label, expected_divergence, mutate) in [
                    (
                        "ir3_hash",
                        "executed IR3",
                        (|ctx: &mut CapturedFailureContext| {
                            ctx.ir3_hash = if ctx.ir3_hash.starts_with('0') {
                                format!("1{}", &ctx.ir3_hash[1..])
                            } else {
                                format!("0{}", &ctx.ir3_hash[1..])
                            };
                        }) as fn(&mut CapturedFailureContext),
                    ),
                    (
                        "instructions_executed",
                        "executed instruction count",
                        (|ctx: &mut CapturedFailureContext| {
                            ctx.instructions_executed = ctx.instructions_executed.saturating_add(1);
                        }) as fn(&mut CapturedFailureContext),
                    ),
                    (
                        "dropped_console_entries",
                        "dropped console entry count",
                        (|ctx: &mut CapturedFailureContext| {
                            ctx.dropped_console_entries =
                                ctx.dropped_console_entries.saturating_add(1);
                        }) as fn(&mut CapturedFailureContext),
                    ),
                    (
                        "imported_module_hashes",
                        "consumed module hashes",
                        (|ctx: &mut CapturedFailureContext| {
                            ctx.imported_module_hashes
                                .insert("tampered.cjs".to_string(), "f".repeat(64));
                        }) as fn(&mut CapturedFailureContext),
                    ),
                ] {
                    let mut tampered = original.clone();
                    let CapturedAttempt::UncaughtException(failure) = &mut tampered.expected else {
                        unreachable!();
                    };
                    mutate(failure.failure_context.as_mut().unwrap());
                    let encoded = encode_capture(&tampered).expect("encode tampered capture");
                    let outcome = reexecute(&encoded).expect("replay tampered failure capture");
                    assert!(!outcome.matched, "{label} tamper must fail closed");
                    assert!(
                        outcome
                            .divergences
                            .iter()
                            .any(|d| d.contains(expected_divergence)),
                        "{label}: missing divergence {expected_divergence:?} in {:?}",
                        outcome.divergences
                    );
                }

                // Legacy captures without failure_context remain replayable and
                // honestly report None for the unavailable prefix fields.
                let mut legacy = original.clone();
                let CapturedAttempt::UncaughtException(failure) = &mut legacy.expected else {
                    unreachable!();
                };
                failure.failure_context = None;
                let legacy_encoded = encode_capture(&legacy).expect("encode legacy capture");
                let legacy_outcome = reexecute(&legacy_encoded).expect("replay legacy capture");
                assert!(legacy_outcome.matched, "{legacy_outcome:?}");
                assert_eq!(legacy_outcome.ir3_hash_match, None);
                assert_eq!(legacy_outcome.instruction_count_match, None);
                assert_eq!(legacy_outcome.nondeterminism_trace_match, None);
            });
        }

        #[test]
        fn native_reexecution_refuses_unrecorded_module_reads_and_ambiguous_json() {
            on_native_stack(|| {
                let root = tempfile::tempdir().expect("original application");
                let capture = record(root.path(), "console.log('original');");
                std::fs::write(
                    root.path().join("private.cjs"),
                    "console.log('PRIVATE_MODULE_RAN');",
                )
                .expect("module that must not be loaded");
                let mut payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).expect("captured input");
                let original_package =
                    serde_json::to_string(&payload.package).expect("original captured package");
                payload.package.source =
                    "const loader = require; loader('./private.cjs');".to_string();
                let injected =
                    encode_capture(&payload).expect("modified source for safety regression");
                let error = reexecute(&injected).expect_err("module authority remains absent");
                assert!(
                    error.contains("module_load") || error.contains("require"),
                    "{error}"
                );

                let mut duplicate = capture;
                duplicate
                    .payload_json
                    .insert_str(1, &format!("\"package\":{original_package},"));
                duplicate.payload_sha256 =
                    hex::encode(Sha256::digest(duplicate.payload_json.as_bytes()));
                let error = reexecute(&duplicate).expect_err("duplicate input rejected");
                assert!(
                    error.contains("duplicate") || error.contains("canonical"),
                    "{error}"
                );
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(payload: &str) -> NativeReplayCapture {
        NativeReplayCapture {
            schema_version: NATIVE_REPLAY_CAPTURE_SCHEMA.to_string(),
            payload_json: payload.to_string(),
            payload_sha256: hex::encode(Sha256::digest(payload.as_bytes())),
        }
    }

    fn completed_policy_candidate() -> NativeReplayOutcome {
        NativeReplayOutcome {
            schema_version: NATIVE_REPLAY_OUTCOME_SCHEMA.to_string(),
            replay_kind: "native_reexecution".to_string(),
            verification_scope: "guest_execution".to_string(),
            module_load_disabled: false,
            matched: true,
            divergences: Vec::new(),
            captured_trace_id: "policy-scope-test".to_string(),
            replay_trace_id: "policy-scope-test".to_string(),
            captured_terminal_state: NativeReplayTerminalState::Completed,
            replay_terminal_state: NativeReplayTerminalState::Completed,
            terminal_state_match: true,
            ir3_hash_match: Some(true),
            ir4_witness_match: Some(true),
            execution_value_match: Some(true),
            instruction_count_match: Some(true),
            console_match: true,
            host_effects_match: true,
            nondeterminism_trace_match: Some(true),
            lane_match: Some(true),
            exit_code_match: Some(true),
            exception_value_match: None,
            decisions_match: Some(true),
            policy_comparison_note: "captured control decisions".to_string(),
        }
    }

    fn assert_policy_refusal(candidate: NativeReplayOutcome, label: &str) {
        assert!(!candidate.satisfies_policy_equivalence(), "{label}");
        let error = candidate.enforce_policy_equivalence().unwrap_err();
        assert!(!error.is_empty(), "refusal must explain {label}");
        let refused = candidate.into_policy_equivalence_outcome();
        assert_eq!(refused.verification_scope, POLICY_EQUIVALENCE_SCOPE);
        assert!(!refused.matched, "scope promotion must preserve {label}");
        assert!(!refused.divergences.is_empty(), "{label}");
    }

    #[test]
    fn policy_scope_accepts_a_complete_matching_native_verdict() {
        let candidate = completed_policy_candidate();
        assert!(candidate.satisfies_policy_equivalence());
        candidate.enforce_policy_equivalence().unwrap();
        let accepted = candidate.into_policy_equivalence_outcome();
        assert!(accepted.matched);
        assert!(accepted.satisfies_policy_equivalence());
        assert_eq!(accepted.verification_scope, POLICY_EQUIVALENCE_SCOPE);
        assert_eq!(accepted.clone().into_policy_equivalence_outcome(), accepted);
    }

    #[test]
    fn policy_scope_never_repairs_a_failed_guest_verdict() {
        let mut failed_without_diagnostic = completed_policy_candidate();
        failed_without_diagnostic.matched = false;
        assert_policy_refusal(
            failed_without_diagnostic,
            "failed guest without diagnostics",
        );

        let mut failed_with_diagnostic = completed_policy_candidate();
        failed_with_diagnostic.matched = false;
        failed_with_diagnostic
            .divergences
            .push("original guest mismatch".to_string());
        let refused = failed_with_diagnostic.into_policy_equivalence_outcome();
        assert!(!refused.matched);
        assert!(
            refused
                .divergences
                .iter()
                .any(|d| d == "original guest mismatch")
        );
        assert!(
            refused
                .divergences
                .iter()
                .any(|d| d == POLICY_GUEST_EXECUTION_DIVERGENCE)
        );
    }

    #[test]
    fn policy_scope_rejects_missing_or_contradictory_guest_comparisons() {
        let original = serde_json::to_value(completed_policy_candidate()).unwrap();
        for field in [
            "ir3_hash_match",
            "ir4_witness_match",
            "execution_value_match",
            "instruction_count_match",
            "nondeterminism_trace_match",
            "lane_match",
            "exit_code_match",
        ] {
            for value in [serde_json::json!(false), serde_json::Value::Null] {
                let mut changed = original.clone();
                changed[field] = value;
                let candidate: NativeReplayOutcome = serde_json::from_value(changed).unwrap();
                assert!(candidate.matched && candidate.divergences.is_empty());
                assert_policy_refusal(candidate, field);
            }
        }
        for (field, value) in [
            ("schema_version", serde_json::json!("unknown-outcome")),
            ("replay_kind", serde_json::json!("recorded_trace")),
            (
                "verification_scope",
                serde_json::json!("guest_failure_prefix"),
            ),
            ("captured_trace_id", serde_json::json!("")),
            ("replay_trace_id", serde_json::json!("different-trace")),
            (
                "captured_terminal_state",
                serde_json::json!("uncaught_exception"),
            ),
            ("replay_terminal_state", serde_json::json!("engine_failure")),
            ("terminal_state_match", serde_json::json!(false)),
            ("console_match", serde_json::json!(false)),
            ("host_effects_match", serde_json::json!(false)),
            ("exception_value_match", serde_json::json!(true)),
            ("exception_value_match", serde_json::json!(false)),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert_policy_refusal(serde_json::from_value(changed).unwrap(), field);
        }
    }

    #[test]
    fn policy_scope_requires_frozen_modules_and_available_matching_decisions() {
        for (module_load_disabled, decisions_match) in
            [(true, Some(true)), (false, None), (false, Some(false))]
        {
            let mut candidate = completed_policy_candidate();
            candidate.module_load_disabled = module_load_disabled;
            candidate.decisions_match = decisions_match;
            assert_policy_refusal(candidate, "module or policy context");
        }
    }

    #[test]
    fn engine_failure_terminal_metadata_is_distinct_and_integrity_bound() {
        let capture = envelope(
            r#"{"expected":{"terminal_state":"engine_failure","reason":{"kind":"capability_denied","capability":"env_read"}}}"#,
        );
        assert_eq!(
            capture.terminal_state().unwrap(),
            NativeReplayTerminalState::EngineFailure
        );
        assert_ne!(
            NativeReplayTerminalState::EngineFailure,
            NativeReplayTerminalState::UncaughtException
        );
        assert_eq!(
            serde_json::to_string(&NativeReplayTerminalState::EngineFailure).unwrap(),
            "\"engine_failure\""
        );
        for unrelated in [
            "cancelled",
            "wrapper_timeout",
            "panic",
            "timeout_indeterminate",
        ] {
            assert!(
                serde_json::from_value::<NativeReplayTerminalState>(serde_json::json!(unrelated))
                    .is_err()
            );
        }
        let mut changed = capture;
        changed.payload_json.push(' ');
        assert!(changed.terminal_state().is_err());
    }

    #[test]
    fn replay_capture_debug_redacts_private_payload_without_changing_serialization() {
        let capture = envelope(r#"{"source":"PRIVATE_SOURCE","environment":"PRIVATE_VALUE"}"#);
        let debug = format!("{capture:?}");
        assert!(debug.contains("payload_bytes") && debug.contains("redacted"));
        assert!(!debug.contains("PRIVATE_SOURCE") && !debug.contains("PRIVATE_VALUE"));
        let encoded = serde_json::to_string(&capture).unwrap();
        assert!(encoded.contains("PRIVATE_SOURCE") && encoded.contains("PRIVATE_VALUE"));
        let decoded: NativeReplayCapture = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, capture);
        decoded.validate().unwrap();
    }

    #[test]
    fn replay_envelope_binds_exact_source_bytes_and_schema() {
        let capture = envelope("{\"source\":\"console.log('original')\"}");
        capture.validate().expect("intact digest");
        let mut changed = capture.clone();
        changed.payload_json = "{\"source\":\"console.log('changed')\"}".to_string();
        assert!(
            changed
                .validate()
                .expect_err("changed source")
                .contains("SHA-256")
        );
        changed = capture.clone();
        changed.schema_version.push_str("/unknown");
        assert!(changed.validate().expect_err("schema").contains("schema"));
        changed = capture;
        changed.schema_version = "franken-node/native-replay-capture/v2".to_string();
        assert!(
            changed
                .validate()
                .expect_err("historical capture")
                .contains("schema")
        );
    }

    #[test]
    fn replay_envelope_refuses_empty_and_oversized_payloads() {
        assert!(envelope("").validate().is_err());
        let oversized = "x".repeat(MAX_NATIVE_REPLAY_PAYLOAD_BYTES + 1);
        assert!(
            envelope(&oversized)
                .validate()
                .expect_err("bounded")
                .contains("bytes")
        );
    }

    #[test]
    fn replay_terminal_state_is_typed_and_bound_to_exact_payload_bytes() {
        let completed = envelope("{\"expected\":{\"terminal_state\":\"completed\"}}");
        assert_eq!(
            completed.terminal_state().expect("completed metadata"),
            NativeReplayTerminalState::Completed
        );
        let failed = envelope(
            "{\"expected\":{\"terminal_state\":\"uncaught_exception\",\"exception_value\":\"\"}}",
        );
        assert_eq!(
            failed.terminal_state().expect("failed metadata"),
            NativeReplayTerminalState::UncaughtException
        );
        let mut changed = completed;
        changed.payload_json = failed.payload_json;
        assert!(
            changed
                .terminal_state()
                .expect_err("changed terminal state")
                .contains("SHA-256")
        );
        for invalid in [
            "{\"expected\":{}}",
            "{\"expected\":{\"terminal_state\":\"unknown\"}}",
            "{\"expected\":{\"terminal_state\":\"completed\",\"terminal_state\":\"uncaught_exception\"}}",
            "{\"expected\":{\"terminal_state\":\"completed\"},\"expected\":{\"terminal_state\":\"uncaught_exception\"}}",
        ] {
            assert!(envelope(invalid).terminal_state().is_err(), "{invalid}");
        }
    }
}
