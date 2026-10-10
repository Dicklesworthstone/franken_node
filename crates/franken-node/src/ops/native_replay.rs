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
//! Runtime module loading is refused because the engine's module loader does
//! not yet consume the host-I/O transcript. Statically lowered builtin facades
//! remain usable, including their recorded filesystem and network effects.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NATIVE_REPLAY_CAPTURE_SCHEMA: &str = "franken-node/native-replay-capture/v2";
pub const NATIVE_REPLAY_OUTCOME_SCHEMA: &str = "franken-node/native-replay-outcome/v2";
pub const MAX_NATIVE_REPLAY_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// The engine terminal state the authenticated capture describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReplayTerminalState {
    Completed,
    UncaughtException,
}

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
    /// Informational: withholding ModuleLoad changes the declared capability
    /// population the engine uses for Bayesian evidence. This is not included
    /// in the guest execution verdict.
    pub decisions_match: Option<bool>,
    pub policy_comparison_note: String,
}

/// Execute only after authenticating the enclosing signed incident bundle.
#[cfg(feature = "engine")]
pub fn reexecute(capture: &NativeReplayCapture) -> Result<NativeReplayOutcome, String> {
    engine::reexecute(capture)
}

#[cfg(feature = "engine")]
pub use engine::{CapturingProcessSpawnProvider, ProcessReplayCaptureHostIo};

#[cfg(feature = "engine")]
mod engine {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{ConsoleEntry, InterpreterError, LaneChoice};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::deterministic_replay::NondeterminismTrace;
    use frankenengine_engine::evidence_ledger::RuntimeEvidenceAuthority;
    use frankenengine_engine::execution_orchestrator::{
        ExecutionOrchestrator, ExtensionPackage, LossMatrixPreset, OrchestratorConfig,
        OrchestratorError, OrchestratorResult, ProcessSpawnAttemptAuthority,
    };
    use frankenengine_engine::ir_contract::{ExecutionOutcome, Ir4Module};
    use frankenengine_engine::lowering_pipeline::AmbientAuthorityGrant;
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
        ProcessSpawnProvider, ProcessSpawnRequest,
    };

    use super::*;

    const REPLAY_STACK_BYTES: usize = 64 * 1024 * 1024;
    const MAX_PROCESS_PREPARATION_ENTRIES: usize = 4096;
    const MAX_PROCESS_PREPARATION_BYTES: usize = MAX_NATIVE_REPLAY_PAYLOAD_BYTES / 2;

    /// Apply the ordered replay journal's conservative exception floor during
    /// the original capture execution, before the engine constructs its IR.
    ///
    /// All actual I/O, admission, and live supervision remain with the wrapped
    /// product provider. This adds a classification restriction for capture;
    /// it never changes an effect result or relabels an existing witness.
    #[derive(Debug)]
    pub struct ProcessReplayCaptureHostIo {
        inner: Arc<dyn HostIoProvider>,
    }

    impl ProcessReplayCaptureHostIo {
        pub fn new(inner: Arc<dyn HostIoProvider>) -> Self {
            Self { inner }
        }
    }

    impl HostIoProvider for ProcessReplayCaptureHostIo {
        fn name(&self) -> &str {
            self.inner.name()
        }

        fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
            self.inner
                .filesystem_exception_provenance()
                .combine(HostIoExceptionProvenance::Unknown)
        }

        fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
            self.inner.perform(request, granted)
        }

        fn perform_controlled(
            &self,
            request: &HostIoRequest,
            granted: &[HostIoCapability],
            control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            self.inner.perform_controlled(request, granted, control)
        }
    }

    fn capture_exception_provenance(process_capture: bool) -> HostIoExceptionProvenance {
        if process_capture {
            HostIoExceptionProvenance::Unknown
        } else {
            HostIoExceptionProvenance::ProviderInternal
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
            self.preparation
                .iter()
                .find_map(|entry| match entry {
                    CapturedProcessPreparation::Preflight {
                        request: expected,
                        outcome,
                    } if expected == request => Some(outcome.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| Err(self.refuse()))
        }

        fn prepare_request(
            &self,
            request: &ProcessSpawnRequest,
        ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
            self.preparation
                .iter()
                .find_map(|entry| match entry {
                    CapturedProcessPreparation::Prepare {
                        request: expected,
                        outcome,
                    } if expected == request => Some(outcome.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| Err(self.refuse()))
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

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CapturedGuestException {
        trace_id: String,
        exception_value: String,
        console_output: Vec<ConsoleEntry>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "terminal_state", rename_all = "snake_case")]
    enum CapturedAttempt {
        Completed(CapturedExecution),
        UncaughtException(CapturedGuestException),
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        process: Option<CapturedProcessReplay>,
        expected: CapturedAttempt,
    }

    impl NativeReplayPayload {
        fn validate(&self) -> Result<(), String> {
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
                        })
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
                    Some(RuntimeCapability::EnvRead) => {
                        return Err(format!(
                            "native replay does not support captured {capability} authority"
                        ));
                    }
                    Some(_) => {}
                    None => return Err(format!("unrecognized captured capability {capability}")),
                }
            }
            let has_process_authority = self.package.capabilities.iter().any(|capability| {
                RuntimeCapability::from_tag_str(capability) == Some(RuntimeCapability::ProcessSpawn)
            });
            if has_process_authority != self.process.is_some() {
                return Err("native replay process authority requires its exact preparation and ordered journal".to_string());
            }
            if self.host_io_exception_provenance
                != capture_exception_provenance(self.process.is_some())
            {
                return Err(
                    "native replay exception provenance differs from its original capture mode"
                        .to_string(),
                );
            }
            if let Some(process) = &self.process {
                process.validate(&self.host_effect_transcript)?;
            }
            match &self.expected {
                CapturedAttempt::Completed(expected) => {
                    if expected.ir4_witness.outcome != ExecutionOutcome::Completed {
                        return Err(
                            "native replay requires a finalized successful engine attempt"
                                .to_string(),
                        );
                    }
                    if expected
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
                    // The thrown value may legitimately be the empty string.
                    // Only the authenticated recorder boundary, not its length,
                    // establishes that this is a real failed guest attempt.
                }
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

    struct ObservedGuestException {
        exception: CapturedGuestException,
        host_effect_transcript: Vec<(HostIoRequest, HostIoOutcome)>,
        host_effect_journal: Vec<HostEffectJournalEntry>,
    }

    /// Accept only an actual uncaught guest exception whose recorder and cell
    /// both finalized. An error prefix with an unknown effect boundary cannot
    /// become replay evidence merely because some console output was retained.
    fn observe_guest_exception(
        orchestrator: &ExecutionOrchestrator,
        error: &OrchestratorError,
    ) -> Result<ObservedGuestException, String> {
        let OrchestratorError::Interpreter(InterpreterError::UncaughtException { value }) =
            error.primary_error()
        else {
            return Err(
                "native failure replay supports only a certified uncaught guest exception"
                    .to_string(),
            );
        };
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
        let host_effect_transcript = entries
            .iter()
            .filter_map(|entry| match entry {
                HostEffectJournalEntry::HostIo { request, outcome } => {
                    Some((request.clone(), outcome.clone()))
                }
                HostEffectJournalEntry::ProcessSpawn { .. } => None,
            })
            .collect();
        Ok(ObservedGuestException {
            exception: CapturedGuestException {
                trace_id: trace_id.to_string(),
                exception_value: value.clone(),
                console_output: orchestrator.last_failed_console_output(),
            },
            host_effect_transcript,
            host_effect_journal: entries.to_vec(),
        })
    }

    impl NativeReplayCapture {
        /// Capture the source actually passed to the native engine and its
        /// finalized response, before either can be discarded or reread.
        /// The product caller supplies the same ambient grant and argv it gave
        /// the orchestrator, and must have installed its SandboxedHostIo plus
        /// transparent policy decorators. If process_preparation is Some, the
        /// caller must also have installed ProcessReplayCaptureHostIo during
        /// the original execution so its lowering uses the ordered journal's
        /// conservative exception floor.
        /// A process-shape grant supplies only captured arguments and the
        /// engine's deterministic metadata shape.
        pub fn from_execution(
            package: &ExtensionPackage,
            orchestrator_config: &OrchestratorConfig,
            runtime_config: &RuntimeConfig,
            ambient_authority: AmbientAuthorityGrant,
            process_argv: &[String],
            process_preparation: Option<&CapturingProcessSpawnProvider>,
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
                host_io_exception_provenance: capture_exception_provenance(
                    process_preparation.is_some(),
                ),
                process_argv: process_argv.to_vec(),
                host_effect_transcript: result.host_effect_transcript.clone(),
                process: CapturedProcessReplay::capture(
                    process_preparation,
                    &result.host_effect_journal,
                )?,
                expected: CapturedAttempt::Completed(CapturedExecution {
                    trace_id: result.trace_id.clone(),
                    ir4_witness: result.ir4_witness.clone(),
                    execution_value: result.execution_value.clone(),
                    instructions_executed: result.instructions_executed,
                    console_output: result.console_output.clone(),
                    nondeterminism_trace: result.nondeterminism_trace.clone(),
                    lane: result.lane,
                    exit_code: result.exit_code,
                    decisions: execution_decisions(result)?,
                }),
            };
            payload.validate()?;
            encode_capture(&payload)
        }

        /// Capture an uncaught guest exception and its finalized effect prefix.
        /// No successful IR4 witness or finalized nondeterminism trace is
        /// manufactured for an attempt the engine reported as failed.
        /// As with from_execution, Some process_preparation requires that the
        /// original execution installed ProcessReplayCaptureHostIo before
        /// lowering and used this exact capturing process provider.
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
            orchestrator: &ExecutionOrchestrator,
            error: &OrchestratorError,
        ) -> Result<Self, String> {
            let ObservedGuestException {
                exception: expected,
                host_effect_transcript,
                host_effect_journal: journal,
            } = observe_guest_exception(orchestrator, error)?;
            let payload = NativeReplayPayload {
                package: package.clone(),
                orchestrator: CapturedOrchestratorSettings::capture(orchestrator_config)?,
                runtime: runtime_config.clone(),
                ambient_authority,
                host_io_exception_provenance: capture_exception_provenance(
                    process_preparation.is_some(),
                ),
                process_argv: process_argv.to_vec(),
                host_effect_transcript,
                process: CapturedProcessReplay::capture(process_preparation, &journal)?,
                expected: CapturedAttempt::UncaughtException(expected),
            };
            payload.validate()?;
            encode_capture(&payload)
        }
    }

    fn replay_policy_comparison_note(process_replay: bool) -> String {
        let mut note = "Replay disables runtime module loading. Its changed declared-capability population can change Bayesian and containment decisions; decisions_match is informational and is excluded from the guest execution verdict.".to_string();
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
            module_load_disabled: true,
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
            policy_comparison_note: replay_policy_comparison_note(payload.process.is_some()),
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

    struct GuestTerminalObservation {
        terminal_state: NativeReplayTerminalState,
        trace_id: String,
        exception_value: Option<String>,
        console_output: Vec<ConsoleEntry>,
        host_effect_transcript: Vec<(HostIoRequest, HostIoOutcome)>,
        host_effect_journal: Vec<HostEffectJournalEntry>,
    }

    fn compare_failure_observation(
        expected: &CapturedGuestException,
        expected_effects: &[(HostIoRequest, HostIoOutcome)],
        expected_journal: Option<&[HostEffectJournalEntry]>,
        replayed: &GuestTerminalObservation,
    ) -> NativeReplayOutcome {
        let mut outcome = NativeReplayOutcome {
            schema_version: NATIVE_REPLAY_OUTCOME_SCHEMA.to_string(),
            replay_kind: "native_reexecution".to_string(),
            verification_scope: "guest_failure_prefix".to_string(),
            module_load_disabled: true,
            matched: false,
            divergences: Vec::new(),
            captured_trace_id: expected.trace_id.clone(),
            replay_trace_id: replayed.trace_id.clone(),
            captured_terminal_state: NativeReplayTerminalState::UncaughtException,
            replay_terminal_state: replayed.terminal_state,
            terminal_state_match: replayed.terminal_state == NativeReplayTerminalState::UncaughtException,
            ir3_hash_match: None,
            ir4_witness_match: None,
            execution_value_match: None,
            instruction_count_match: None,
            console_match: expected.console_output == replayed.console_output,
            host_effects_match: expected_effects == replayed.host_effect_transcript
                && expected_journal.is_none_or(|journal| journal == replayed.host_effect_journal),
            nondeterminism_trace_match: None,
            lane_match: None,
            exit_code_match: None,
            exception_value_match: Some(replayed.exception_value.as_deref() == Some(expected.exception_value.as_str())),
            decisions_match: None,
            policy_comparison_note: "This verdict verifies an uncaught guest exception, captured console, and finalized host-effect prefix. The failed run has no completed IR4 witness, finalized nondeterminism trace, total instruction count, or completed runtime decision to compare. Runtime module loading remains disabled.".to_string(),
        };
        if expected_journal.is_some() {
            outcome.policy_comparison_note.push_str(" Process outcomes are consumed in global journal order without live dispatch; the engine's Unknown filesystem exception provenance remains in force.");
        }
        for (matches, subject) in [
            (outcome.terminal_state_match, "terminal state"),
            (
                outcome.exception_value_match == Some(true),
                "exception value",
            ),
            (outcome.console_match, "console output"),
            (outcome.host_effects_match, "host-effect prefix"),
            (
                expected.trace_id == replayed.trace_id,
                "execution trace identity",
            ),
        ] {
            if !matches {
                outcome.divergences.push(format!(
                    "re-executed {subject} differs from the captured failure"
                ));
            }
        }
        outcome.matched = outcome.divergences.is_empty();
        outcome
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
                    // Keep the journal's Unknown provenance floor unchanged.
                    orchestrator.set_process_spawn(
                        provider.clone(),
                        Arc::new(InMemoryHostEffectJournal::replaying(
                            process.journal.clone(),
                        )),
                        ProcessSpawnAttemptAuthority::expiring_at_unix_ms(0),
                    );
                }
                let result = orchestrator.execute(&package);
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
                    (CapturedAttempt::UncaughtException(expected), Err(error)) => {
                        let ObservedGuestException {
                            exception: observed,
                            host_effect_transcript,
                            host_effect_journal,
                        } = observe_guest_exception(&orchestrator, &error).map_err(|reason| {
                            format!(
                                "native failure re-execution is not certified: {reason}; {error}"
                            )
                        })?;
                        let replayed = GuestTerminalObservation {
                            terminal_state: NativeReplayTerminalState::UncaughtException,
                            trace_id: observed.trace_id,
                            exception_value: Some(observed.exception_value),
                            console_output: observed.console_output,
                            host_effect_transcript,
                            host_effect_journal,
                        };
                        Ok(compare_failure_observation(
                            expected,
                            &payload.host_effect_transcript,
                            payload
                                .process
                                .as_ref()
                                .map(|process| process.journal.as_slice()),
                            &replayed,
                        ))
                    }
                    (CapturedAttempt::UncaughtException(expected), Ok(replayed)) => {
                        let replayed = GuestTerminalObservation {
                            terminal_state: NativeReplayTerminalState::Completed,
                            trace_id: replayed.trace_id,
                            exception_value: None,
                            console_output: replayed.console_output,
                            host_effect_transcript: replayed.host_effect_transcript,
                            host_effect_journal: replayed.host_effect_journal,
                        };
                        Ok(compare_failure_observation(
                            expected,
                            &payload.host_effect_transcript,
                            payload
                                .process
                                .as_ref()
                                .map(|process| process.journal.as_slice()),
                            &replayed,
                        ))
                    }
                }
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

        fn record(root: &Path, source: &str) -> NativeReplayCapture {
            record_with_inputs(root, source, AmbientAuthorityGrant::DenyAll, &[])
        }

        fn record_with_inputs(
            root: &Path,
            source: &str,
            ambient_authority: AmbientAuthorityGrant,
            process_argv: &[String],
        ) -> NativeReplayCapture {
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
                    &result,
                ),
                Err(error) => NativeReplayCapture::from_failed_execution(
                    &package,
                    &config,
                    &runtime,
                    ambient_authority,
                    process_argv,
                    None,
                    &orchestrator,
                    &error,
                ),
            }
            .expect("capture actual native result")
        }

        #[cfg(unix)]
        fn process_provider(root: &Path) -> Arc<CapturingProcessSpawnProvider> {
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
            Arc::new(CapturingProcessSpawnProvider::new(Arc::new(
                NativeProcessSpawn::new(policy).expect("native process provider"),
            )))
        }

        #[cfg(unix)]
        fn record_process(root: &Path, source: &str) -> NativeReplayCapture {
            let config = OrchestratorConfig {
                commonjs_entry: true,
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
                Arc::new(ProcessReplayCaptureHostIo::new(Arc::new(
                    SandboxedHostIo::with_root(root).expect("live bounded host I/O"),
                ))),
                Some(Arc::new(InMemoryHostIoTranscript::recording())),
            );
            let provider = process_provider(root);
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
            match orchestrator.execute(&package) {
                Ok(result) => NativeReplayCapture::from_execution(
                    &package,
                    &config,
                    &runtime,
                    AmbientAuthorityGrant::DenyAll,
                    &[],
                    Some(provider.as_ref()),
                    &result,
                ),
                Err(error) => NativeReplayCapture::from_failed_execution(
                    &package,
                    &config,
                    &runtime,
                    AmbientAuthorityGrant::DenyAll,
                    &[],
                    Some(provider.as_ref()),
                    &orchestrator,
                    &error,
                ),
            }
            .expect("capture real process execution")
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
                        HostIoExceptionProvenance::Unknown,
                        "the original engine execution must use the replay journal's floor"
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
                    "const cp = require('child_process'); console.log(cp.execSync('printf shell-output', { encoding: 'utf8' })); try { cp.execFileSync('unapproved-command', [], { encoding: 'utf8' }); } catch (error) { console.log('expected-policy-denial'); }",
                );
                let payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).unwrap();
                let process = payload.process.as_ref().unwrap();
                assert!(process.preparation.iter().any(|entry| matches!(
                    entry,
                    CapturedProcessPreparation::Prepare {
                        outcome: Err(_),
                        ..
                    }
                )));
                assert!(process.journal.iter().any(|entry| matches!(
                    entry,
                    HostEffectJournalEntry::ProcessSpawn {
                        outcome: Err(_),
                        ..
                    }
                )));
                let outcome =
                    reexecute(&capture).expect("replay exact signed shell selection and denial");
                assert!(outcome.matched, "{outcome:?}");
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
                let provider = process_provider(root.path());
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

                for source in [
                    "console.log(process.env.PATH);",
                    "const raw = process; console.log(raw.argv);",
                    "console.log(process['argv']);",
                ] {
                    let mut changed = original.clone();
                    changed.package.source = source.to_string();
                    let changed = encode_capture(&changed).expect("encode authority probe");
                    let error =
                        reexecute(&changed).expect_err("shape grant stays narrow in replay");
                    assert!(
                        error.contains("ambient authority violation"),
                        "{source}: {error}"
                    );
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
        fn native_reexecution_preserves_existing_v2_canonical_capture_bytes() {
            on_native_stack(|| {
                // Freeze the original v2 field order and shape independently
                // of the newly optional process capture field. Already signed
                // payloads must retain both their bytes and their digest.
                #[derive(Serialize)]
                struct OriginalV2Payload<'a> {
                    package: &'a ExtensionPackage,
                    orchestrator: &'a CapturedOrchestratorSettings,
                    runtime: &'a RuntimeConfig,
                    ambient_authority: AmbientAuthorityGrant,
                    host_io_exception_provenance: HostIoExceptionProvenance,
                    process_argv: &'a [String],
                    host_effect_transcript: &'a [(HostIoRequest, HostIoOutcome)],
                    expected: &'a CapturedAttempt,
                }

                let root = tempfile::tempdir().expect("existing v2 capture");
                let capture = record(root.path(), "console.log('existing-v2-capture');");
                let payload: NativeReplayPayload =
                    serde_json::from_str(&capture.payload_json).expect("v2 inputs");
                assert!(payload.process.is_none());
                let original_payload_json = serde_json::to_string(&OriginalV2Payload {
                    package: &payload.package,
                    orchestrator: &payload.orchestrator,
                    runtime: &payload.runtime,
                    ambient_authority: payload.ambient_authority,
                    host_io_exception_provenance: payload.host_io_exception_provenance,
                    process_argv: &payload.process_argv,
                    host_effect_transcript: &payload.host_effect_transcript,
                    expected: &payload.expected,
                })
                .expect("original v2 serialization");
                let original = NativeReplayCapture {
                    schema_version: "franken-node/native-replay-capture/v2".to_string(),
                    payload_sha256: hex::encode(Sha256::digest(original_payload_json.as_bytes())),
                    payload_json: original_payload_json,
                };
                assert_eq!(capture, original);
                let outcome = reexecute(&original).expect("accept already signed v2 shape");
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
                assert_eq!(outcome.ir3_hash_match, None);
                assert_eq!(outcome.ir4_witness_match, None);
                assert_eq!(outcome.execution_value_match, None);
                assert_eq!(outcome.instruction_count_match, None);
                assert_eq!(outcome.nondeterminism_trace_match, None);
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
