//! Portable inputs for actual native incident re-execution.
//!
//! A capture is an integrity envelope, not its own trust anchor. The caller must
//! authenticate the containing run record or incident bundle before executing
//! it. Re-execution consumes the captured source and typed host-I/O outcomes;
//! it never installs a live filesystem, network, entropy, or process provider.
//! Runtime module loading is refused because the engine's module loader does
//! not yet consume the host-I/O transcript. Statically lowered builtin facades
//! remain usable, including their recorded filesystem and network effects.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NATIVE_REPLAY_CAPTURE_SCHEMA: &str = "franken-node/native-replay-capture/v1";
pub const NATIVE_REPLAY_OUTCOME_SCHEMA: &str = "franken-node/native-replay-outcome/v1";
pub const MAX_NATIVE_REPLAY_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Exact serialized execution inputs, bound into the signed run receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReplayCapture {
    pub schema_version: String,
    pub payload_json: String,
    pub payload_sha256: String,
}

impl NativeReplayCapture {
    /// Check the envelope before parsing its potentially expensive typed data.
    /// This does not authenticate the producer: the containing record must
    /// already have passed signature verification against an independent key.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != NATIVE_REPLAY_CAPTURE_SCHEMA {
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
    pub ir3_hash_match: bool,
    pub ir4_witness_match: bool,
    pub execution_value_match: bool,
    pub instruction_count_match: bool,
    pub console_match: bool,
    pub host_effects_match: bool,
    pub nondeterminism_trace_match: bool,
    pub lane_match: bool,
    pub exit_code_match: bool,
    /// Informational: withholding ModuleLoad changes the declared capability
    /// population the engine uses for Bayesian evidence. This is not included
    /// in the guest execution verdict.
    pub decisions_match: bool,
    pub policy_comparison_note: String,
}

/// Execute only after authenticating the enclosing signed incident bundle.
#[cfg(feature = "engine")]
pub fn reexecute(capture: &NativeReplayCapture) -> Result<NativeReplayOutcome, String> {
    engine::reexecute(capture)
}

#[cfg(feature = "engine")]
mod engine {
    use std::io::Write;
    use std::sync::Arc;

    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{ConsoleEntry, LaneChoice};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::deterministic_replay::NondeterminismTrace;
    use frankenengine_engine::evidence_ledger::RuntimeEvidenceAuthority;
    use frankenengine_engine::execution_orchestrator::{
        ExecutionOrchestrator, ExtensionPackage, LossMatrixPreset, OrchestratorConfig,
        OrchestratorResult,
    };
    use frankenengine_engine::ir_contract::{ExecutionOutcome, Ir4Module};
    use frankenengine_engine::lowering_pipeline::AmbientAuthorityGrant;
    use frankenengine_engine::parser::ParserOptions;
    use frankenengine_engine::runtime_config::RuntimeConfig;
    use frankenengine_engine::security_epoch::SecurityEpoch;
    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoControl, HostIoError, HostIoExceptionProvenance, HostIoOutcome,
        HostIoProvider, HostIoRecorder, HostIoRequest, InMemoryHostIoTranscript,
    };

    use super::*;

    const REPLAY_STACK_BYTES: usize = 64 * 1024 * 1024;

    /// Every serializable setting of the actual execution orchestrator.
    /// A shared work pool is not serializable authority and is refused.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedOrchestratorSettings {
        loss_matrix_preset: LossMatrixPreset,
        force_lane: Option<LaneChoice>,
        drain_deadline_ticks: u64,
        cell_close_budget_ms: u64,
        max_concurrent_sagas: usize,
        epoch: SecurityEpoch,
        parse_goal: ParseGoal,
        commonjs_entry: bool,
        parser_options: ParserOptions,
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
            Ok(Self {
                loss_matrix_preset: config.loss_matrix_preset,
                force_lane: config.force_lane,
                drain_deadline_ticks: config.drain_deadline_ticks,
                cell_close_budget_ms: config.cell_close_budget_ms,
                max_concurrent_sagas: config.max_concurrent_sagas,
                epoch: config.epoch,
                parse_goal: config.parse_goal,
                commonjs_entry: config.commonjs_entry,
                parser_options: config.parser_options.clone(),
                auto_size_register_window: config.auto_size_register_window,
                trace_id_prefix: config.trace_id_prefix.clone(),
                policy_id: config.policy_id.clone(),
            })
        }

        fn restore(&self) -> OrchestratorConfig {
            OrchestratorConfig {
                loss_matrix_preset: self.loss_matrix_preset,
                force_lane: self.force_lane,
                work_pool: None,
                drain_deadline_ticks: self.drain_deadline_ticks,
                cell_close_budget_ms: self.cell_close_budget_ms,
                max_concurrent_sagas: self.max_concurrent_sagas,
                epoch: self.epoch,
                parse_goal: self.parse_goal,
                commonjs_entry: self.commonjs_entry,
                parser_options: self.parser_options.clone(),
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
        host_effect_transcript: Vec<(HostIoRequest, HostIoOutcome)>,
        expected: CapturedExecution,
    }

    impl NativeReplayPayload {
        fn validate(&self) -> Result<(), String> {
            self.runtime
                .validate()
                .map_err(|error| format!("invalid captured runtime settings: {error}"))?;
            if self.ambient_authority != AmbientAuthorityGrant::DenyAll {
                return Err(
                    "native replay requires captured deny-all ambient authority".to_string()
                );
            }
            if self.host_io_exception_provenance != HostIoExceptionProvenance::ProviderInternal {
                return Err(
                    "native replay requires authenticated bounded host-I/O provenance".to_string(),
                );
            }
            if self.package.source.trim().is_empty() || self.package.extension_id.trim().is_empty()
            {
                return Err(
                    "native replay source and extension identity must not be empty".to_string(),
                );
            }
            for capability in &self.package.capabilities {
                match RuntimeCapability::from_tag_str(capability) {
                    Some(RuntimeCapability::ProcessSpawn | RuntimeCapability::EnvRead) => {
                        return Err(format!(
                            "native replay does not support captured {capability} authority"
                        ));
                    }
                    Some(_) => {}
                    None => return Err(format!("unrecognized captured capability {capability}")),
                }
            }
            if self.expected.ir4_witness.outcome != ExecutionOutcome::Completed {
                return Err(
                    "native replay requires a finalized successful engine attempt".to_string(),
                );
            }
            if self
                .expected
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
            if self.expected.ir4_witness.instructions_executed
                != self.expected.instructions_executed
            {
                return Err(
                    "native replay witness instruction count does not match the captured result"
                        .to_string(),
                );
            }
            self.expected
                .nondeterminism_trace
                .validate_for_replay()
                .map_err(|error| format!("invalid captured nondeterminism trace: {error}"))?;
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
            schema_version: NATIVE_REPLAY_CAPTURE_SCHEMA.to_string(),
            payload_json,
            payload_sha256,
        })
    }

    impl NativeReplayCapture {
        /// Capture the source actually passed to the native engine and its
        /// finalized response, before either can be discarded or reread.
        /// The product caller must have selected DenyAll ambient authority and
        /// installed its SandboxedHostIo plus transparent policy decorators.
        pub fn from_execution(
            package: &ExtensionPackage,
            orchestrator_config: &OrchestratorConfig,
            runtime_config: &RuntimeConfig,
            process_argv: &[String],
            result: &OrchestratorResult,
        ) -> Result<Self, String> {
            if !result.host_effect_journal.is_empty() {
                return Err("native replay capture does not support process journals".to_string());
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
                ambient_authority: AmbientAuthorityGrant::DenyAll,
                host_io_exception_provenance: HostIoExceptionProvenance::ProviderInternal,
                process_argv: process_argv.to_vec(),
                host_effect_transcript: result.host_effect_transcript.clone(),
                expected: CapturedExecution {
                    trace_id: result.trace_id.clone(),
                    ir4_witness: result.ir4_witness.clone(),
                    execution_value: result.execution_value.clone(),
                    instructions_executed: result.instructions_executed,
                    console_output: result.console_output.clone(),
                    nondeterminism_trace: result.nondeterminism_trace.clone(),
                    lane: result.lane,
                    exit_code: result.exit_code,
                    decisions: execution_decisions(result)?,
                },
            };
            payload.validate()?;
            encode_capture(&payload)
        }
    }

    fn compare_execution(
        payload: &NativeReplayPayload,
        replayed: &OrchestratorResult,
    ) -> Result<NativeReplayOutcome, String> {
        let expected = &payload.expected;
        let mut outcome = NativeReplayOutcome {
            schema_version: NATIVE_REPLAY_OUTCOME_SCHEMA.to_string(),
            replay_kind: "native_reexecution".to_string(),
            verification_scope: "guest_execution".to_string(),
            module_load_disabled: true,
            matched: false,
            divergences: Vec::new(),
            captured_trace_id: expected.trace_id.clone(),
            replay_trace_id: replayed.trace_id.clone(),
            ir3_hash_match: expected.ir4_witness.executed_ir3_hash
                == replayed.ir4_witness.executed_ir3_hash,
            ir4_witness_match: expected.ir4_witness == replayed.ir4_witness,
            execution_value_match: expected.execution_value == replayed.execution_value,
            instruction_count_match: expected.instructions_executed
                == replayed.instructions_executed,
            console_match: expected.console_output == replayed.console_output,
            host_effects_match: payload.host_effect_transcript == replayed.host_effect_transcript,
            nondeterminism_trace_match: expected.nondeterminism_trace
                == replayed.nondeterminism_trace,
            lane_match: expected.lane == replayed.lane,
            exit_code_match: expected.exit_code == replayed.exit_code,
            decisions_match: expected.decisions == execution_decisions(replayed)?,
            policy_comparison_note: "Replay disables runtime module loading. Its changed declared-capability population can change Bayesian and containment decisions; decisions_match is informational and is excluded from the guest execution verdict.".to_string(),
        };
        for (matches, subject) in [
            (outcome.ir3_hash_match, "executed IR3"),
            (outcome.ir4_witness_match, "IR4 execution witness"),
            (outcome.execution_value_match, "execution value"),
            (outcome.instruction_count_match, "instruction count"),
            (outcome.console_match, "console output"),
            (outcome.host_effects_match, "host-effect transcript"),
            (outcome.nondeterminism_trace_match, "nondeterminism trace"),
            (outcome.lane_match, "execution lane"),
            (outcome.exit_code_match, "guest exit code"),
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

    pub(super) fn reexecute(capture: &NativeReplayCapture) -> Result<NativeReplayOutcome, String> {
        capture.validate()?;
        let payload: NativeReplayPayload = serde_json::from_str(&capture.payload_json)
            .map_err(|error| format!("invalid native replay payload: {error}"))?;
        // Exact reserialization rejects duplicate keys, ignored unknown fields,
        // omitted settings that would inherit today's defaults, and alternate
        // encodings before any captured source reaches execution.
        let canonical = encode_capture(&payload)?;
        if canonical.payload_json != capture.payload_json {
            return Err("native replay payload is not the complete canonical capture".to_string());
        }
        payload.validate()?;
        std::thread::Builder::new()
            .name("native-incident-replay".to_string())
            .stack_size(REPLAY_STACK_BYTES)
            .spawn(move || {
                let mut package = payload.package.clone();
                package.capabilities.retain(|capability| {
                    RuntimeCapability::from_tag_str(capability)
                        != Some(RuntimeCapability::ModuleLoad)
                });
                // Keep the exact diagnostic/source label for IR identity, but
                // remove the old project-root dependency. The engine may inspect
                // parent-directory metadata; denied ModuleLoad prevents source,
                // package.json, and dependency reads through every runtime form.
                package.module_root = None;
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
                orchestrator.set_host_io(
                    Arc::new(CapturedReplayHostIo),
                    Some(Arc::new(CapturedReplayRecorder::new(
                        payload.host_effect_transcript.clone(),
                    ))),
                );
                let replayed = orchestrator
                    .execute(&package)
                    .map_err(|error| format!("native re-execution failed: {error}"))?;
                compare_execution(&payload, &replayed)
            })
            .map_err(|error| format!("start native replay worker: {error}"))?
            .join()
            .map_err(|_| {
                "native replay worker panicked before completing verification".to_string()
            })?
    }

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeMap;
        use std::path::Path;

        use frankenengine_extension_host::host_io::{HostIoResponse, SandboxedHostIo};

        use super::*;

        fn on_native_stack(test: impl FnOnce() + Send + 'static) {
            std::thread::Builder::new()
                .stack_size(REPLAY_STACK_BYTES)
                .spawn(test)
                .expect("start native test")
                .join()
                .expect("native test completed");
        }

        fn record(root: &Path, source: &str) -> NativeReplayCapture {
            let config = OrchestratorConfig {
                commonjs_entry: true,
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
                    AmbientAuthorityGrant::DenyAll,
                    authority,
                )
                .expect("native recorder");
            orchestrator.set_host_io(
                Arc::new(SandboxedHostIo::with_root(root).expect("real filesystem provider")),
                Some(Arc::new(InMemoryHostIoTranscript::recording())),
            );
            let result = orchestrator
                .execute(&package)
                .expect("record real execution");
            NativeReplayCapture::from_execution(&package, &config, &runtime, &[], &result)
                .expect("capture actual native result")
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
                payload.expected.execution_value = "forged-result".to_string();
                let changed = encode_capture(&payload).expect("changed expected result");
                let outcome = reexecute(&changed).expect("the source still executes");
                assert!(!outcome.matched);
                assert!(!outcome.execution_value_match);
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
                payload.package.source =
                    "const loader = require; loader('./private.cjs');".to_string();
                let injected =
                    encode_capture(&payload).expect("modified source for safety regression");
                let error = reexecute(&injected).expect_err("module authority remains absent");
                assert!(error.contains("module_load"), "{error}");

                let mut duplicate = capture;
                duplicate.payload_json.insert_str(1, "\"package\":{},");
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
        changed = capture;
        changed.schema_version.push_str("/unknown");
        assert!(changed.validate().expect_err("schema").contains("schema"));
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
}
