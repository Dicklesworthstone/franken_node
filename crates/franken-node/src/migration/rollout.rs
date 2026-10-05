//! Migration Autopilot Rollout State Machine.
//!
//! Provides `audit -> rewrite -> validate -> rollout` progression. Selecting an
//! existing native rewrite's `txn-...` as the migration ID binds source recovery
//! to that exact journal. Rollback persists intent before restoring files and
//! records completion only after the native recovery protocol succeeds.
//!
//! Rollout stages are local control state, not a traffic-routing implementation.
//! Unbound rollouts can be aborted but never claim to restore source files.
//! Journals and transition digests are local recovery metadata, not signatures.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[path = "rollout_store.rs"]
mod store;
use store::{Store, invalid};

pub const ROLLOUT_STATE_SCHEMA_VERSION: &str = "franken-node/migration-rollout-state/v1";
pub const ROLLOUT_REPORT_SCHEMA_VERSION: &str = "franken-node/migrate-rollout-cli/v1";

/// Current stage of workload rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutStage {
    Shadow,
    Canary,
    Ramp,
    Default,
    Aborted,
}

impl RolloutStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Canary => "canary",
            Self::Ramp => "ramp",
            Self::Default => "default",
            Self::Aborted => "aborted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "shadow" => Some(Self::Shadow),
            "canary" => Some(Self::Canary),
            "ramp" => Some(Self::Ramp),
            "default" => Some(Self::Default),
            "aborted" | "abort" | "rollback" => Some(Self::Aborted),
            _ => None,
        }
    }
}

impl std::fmt::Display for RolloutStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Execution status of the rollout. Aborted/Failed means restoration has NOT
/// completed; retry rollback with the same migration ID to resume recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutStatus {
    Pending,
    Active,
    Completed,
    Failed,
    RolledBack,
}

impl RolloutStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        }
    }
}

impl std::fmt::Display for RolloutStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RolloutTransitionEvent {
    pub from_stage: RolloutStage,
    pub to_stage: RolloutStage,
    pub action: String,
    pub reason: String,
    pub timestamp_utc: String,
    pub confidence_score: f64,
    pub ramp_pct: u8,
    /// Historical field name: this is a state digest, NOT a digital signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_signature: Option<String>,
}

/// Durable rollout state in `.franken-node/state/rollout/<migration_id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RolloutState {
    pub schema_version: String,
    pub migration_id: String,
    pub project_path: String,
    pub current_stage: RolloutStage,
    pub status: RolloutStatus,
    pub ramp_pct: u8,
    pub confidence_score: f64,
    pub lockstep_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_plan_id: Option<String>,
    /// Canonical native journal digest admitted BEFORE a rollout can proceed.
    /// An ID without a pin is refused, never repaired by trusting new metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_journal_sha256: Option<String>,
    pub history: Vec<RolloutTransitionEvent>,
    pub created_at: String,
    pub updated_at: String,
}

impl RolloutState {
    pub fn new(migration_id: String, project_path: String) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            schema_version: ROLLOUT_STATE_SCHEMA_VERSION.to_string(),
            migration_id,
            project_path,
            current_stage: RolloutStage::Shadow,
            status: RolloutStatus::Pending,
            ramp_pct: 0,
            confidence_score: 1.0,
            lockstep_verified: false,
            rollback_plan_id: None,
            rollback_journal_sha256: None,
            history: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ROLLOUT_STATE_SCHEMA_VERSION.as_bytes());
        hasher.update(self.migration_id.as_bytes());
        hasher.update(self.current_stage.as_str().as_bytes());
        hasher.update(self.status.as_str().as_bytes());
        hasher.update([self.ramp_pct]);
        hasher.update(self.confidence_score.to_le_bytes());
        hasher.update([u8::from(self.lockstep_verified)]);
        // Bind recovery identity without claiming this digest authenticates it.
        for field in [&self.rollback_plan_id, &self.rollback_journal_sha256] {
            hasher.update([u8::from(field.is_some())]);
            if let Some(value) = field {
                hasher.update((value.len() as u64).to_le_bytes());
                hasher.update(value.as_bytes());
            }
        }
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRollbackSummary {
    pub transaction_id: String,
    pub journal_sha256: String,
    /// The bound transaction's restoration was recorded. This does not certify
    /// later user edits, stop services, or roll back external side effects.
    pub restoration_recorded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RolloutReport {
    pub schema_version: String,
    pub command: String,
    pub ok: bool,
    pub migration_id: String,
    pub project_path: String,
    pub stage: RolloutStage,
    pub status: RolloutStatus,
    pub ramp_pct: u8,
    pub confidence_score: f64,
    pub lockstep_verified: bool,
    pub rollback_triggered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rollback: Option<SourceRollbackSummary>,
    pub message: String,
    pub history: Vec<RolloutTransitionEvent>,
}

impl RolloutReport {
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        let bar = match self.stage {
            RolloutStage::Shadow => "[■□□□] 0% (Shadow)".to_string(),
            RolloutStage::Canary => "[■■□□] 5% (Canary)".to_string(),
            RolloutStage::Ramp => {
                let filled = (self.ramp_pct / 25) as usize;
                let mut b = String::from("[");
                for i in 0..4 {
                    if i < filled {
                        b.push('■');
                    } else {
                        b.push('□');
                    }
                }
                b.push_str(&format!("] {}% (Ramp)", self.ramp_pct));
                b
            }
            RolloutStage::Default => "[■■■■] 100% (Default stage)".to_string(),
            RolloutStage::Aborted => "[XXXX] Aborted".to_string(),
        };
        writeln!(out, "Migration Rollout Status").unwrap();
        writeln!(out, "  Migration ID:       {}", self.migration_id).unwrap();
        writeln!(out, "  Project:            {}", self.project_path).unwrap();
        writeln!(out, "  Stage:              {} ({})", self.stage, self.status).unwrap();
        writeln!(out, "  Progress:           {}", bar).unwrap();
        writeln!(out, "  Confidence Score:   {:.2}%", self.confidence_score * 100.0).unwrap();
        writeln!(out, "  Lockstep Verified:  {}", self.lockstep_verified).unwrap();
        writeln!(out, "  Rollback Triggered: {}", self.rollback_triggered).unwrap();
        if let Some(source) = &self.source_rollback {
            writeln!(out, "  Source transaction: {}", source.transaction_id).unwrap();
            writeln!(out, "  Restore recorded:   {}", source.restoration_recorded).unwrap();
        } else {
            writeln!(out, "  Source restoration: no transaction bound").unwrap();
        }
        writeln!(out, "  Summary:            {}", self.message).unwrap();
        if !self.history.is_empty() {
            writeln!(out, "\nTransition History:").unwrap();
            for ev in &self.history {
                writeln!(out, "  {} -> {}: {} ({}) at {}", ev.from_stage, ev.to_stage, ev.action, ev.reason, ev.timestamp_utc).unwrap();
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct RolloutConfig {
    pub ramp_step_pct: u8,
    pub min_confidence_score: f64,
    pub require_lockstep_evidence: bool,
    pub auto_rollback_on_failure: bool,
    pub force: bool,
    pub lockstep_report: Option<PathBuf>,
}

impl Default for RolloutConfig {
    fn default() -> Self {
        Self {
            ramp_step_pct: 25,
            min_confidence_score: 0.90,
            require_lockstep_evidence: true,
            auto_rollback_on_failure: true,
            force: false,
            lockstep_report: None,
        }
    }
}

const MAX_LOCKSTEP_REPORT_BYTES: u64 = 16 * 1024 * 1024;

fn lockstep_input_payload(project: &Path) -> Vec<u8> {
    if project.is_file() {
        fs::read(project).unwrap_or_default()
    } else {
        fs::read(project.join("package.json"))
            .unwrap_or_else(|_| project.to_string_lossy().as_bytes().to_vec())
    }
}

/// Validate the existing lockstep report contract. Source rollback binding is
/// independent of this evidence and does not upgrade it to release certification.
pub fn verify_lockstep_evidence(project: &Path, report_path: &Path) -> Result<String, String> {
    use frankenengine_node::runtime::nversion_oracle::{DivergenceReport, OracleVerdict};

    let file = File::open(report_path)
        .map_err(|e| format!("cannot open lockstep report {}: {e}", report_path.display()))?;
    let mut raw = Vec::new();
    file.take(MAX_LOCKSTEP_REPORT_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("cannot read lockstep report {}: {e}", report_path.display()))?;
    if raw.len() as u64 > MAX_LOCKSTEP_REPORT_BYTES {
        return Err("lockstep report exceeds the evidence size limit".to_string());
    }
    let report: DivergenceReport = serde_json::from_slice(&raw)
        .map_err(|e| format!("lockstep report is not a `verify lockstep --json` report: {e}"))?;
    if report.verdict != OracleVerdict::Pass {
        return Err(format!("lockstep report verdict is {:?}, not Pass; resolve divergences before promotion", report.verdict));
    }
    if report.checks.is_empty() {
        return Err("lockstep report contains no cross-runtime checks".to_string());
    }
    let has_product_leg = report.runtimes.values().any(|rt| !rt.is_reference);
    let has_reference_leg = report.runtimes.values().any(|rt| rt.is_reference);
    if !has_product_leg || !has_reference_leg {
        return Err("lockstep report must compare the franken product runtime against at least one reference runtime".to_string());
    }
    let expected = lockstep_input_payload(project);
    if let Some(check) = report.checks.iter().find(|check| check.input != expected) {
        return Err(format!("lockstep report check {} was produced for different input than this project's current state; re-run `franken-node verify lockstep {} --json`", check.check_id, project.display()));
    }
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&raw))))
}

pub struct RolloutManager {
    project_path: PathBuf,
    migration_id: String,
}

impl RolloutManager {
    pub fn new(project_path: &Path, migration_id: Option<&str>) -> Self {
        Self {
            project_path: project_path.to_path_buf(),
            migration_id: migration_id.map(str::to_owned)
                .unwrap_or_else(|| Self::discover_or_generate_id(project_path)),
        }
    }

    fn discover_or_generate_id(project_path: &Path) -> String {
        let canonical = project_path.canonicalize().unwrap_or_else(|_| project_path.to_path_buf());
        let hex = hex::encode(Sha256::digest(canonical.to_string_lossy().as_bytes()));
        format!("mig-{}", &hex[..12])
    }

    fn open_store(&self) -> io::Result<Store> {
        if self.migration_id.is_empty()
            || self.migration_id.len() > 96
            || !self.migration_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid("migration ID must be a bounded alphanumeric identifier, not a path"));
        }
        Store::open(&self.project_path.canonicalize()?)
    }

    fn state_name(&self) -> String {
        format!("{}.json", self.migration_id)
    }

    fn validate_state(&self, state: &RolloutState) -> io::Result<()> {
        if state.schema_version != ROLLOUT_STATE_SCHEMA_VERSION
            || state.migration_id != self.migration_id
            || Path::new(&state.project_path).canonicalize()? != self.project_path.canonicalize()?
            || !state.confidence_score.is_finite()
            || !(0.0..=1.0).contains(&state.confidence_score)
            || state.ramp_pct > 100
        {
            return Err(invalid("rollout state identity, schema, confidence or percentage is invalid"));
        }
        match (&state.rollback_plan_id, &state.rollback_journal_sha256) {
            (None, None) if !state.migration_id.starts_with("txn-") => {}
            (Some(id), Some(pin)) if id == &state.migration_id
                && id.starts_with("txn-") && id.len() > 4
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && pin.len() == 64
                && pin.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {}
            _ => return Err(invalid("native rollback binding is missing, incomplete or inconsistent; do not rebind from current journal bytes")),
        }
        if state.current_stage == RolloutStage::Aborted
            && (state.ramp_pct != 0 || !matches!(state.status, RolloutStatus::Failed | RolloutStatus::RolledBack))
        {
            return Err(invalid("aborted rollout must be failed/pending recovery or rolled back at zero percent"));
        }
        if state.status == RolloutStatus::RolledBack && state.current_stage != RolloutStage::Aborted {
            return Err(invalid("restored rollout cannot be active"));
        }
        Ok(())
    }

    fn load_existing(&self, store: &Store) -> io::Result<Option<RolloutState>> {
        store.read(&self.state_name())?.map(|bytes| {
            let state: RolloutState = serde_json::from_slice(&bytes)
                .map_err(|e| invalid(format!("corrupted rollout state: {e}")))?;
            self.validate_state(&state)?;
            Ok(state)
        }).transpose()
    }

    fn persist_locked(&self, store: &Store, state: &RolloutState) -> io::Result<()> {
        self.validate_state(state)?;
        let bytes = serde_json::to_vec_pretty(state).map_err(|e| invalid(e.to_string()))?;
        store.write(&self.state_name(), &bytes)
    }

    fn load_or_init_locked(&self, store: &Store) -> io::Result<RolloutState> {
        if let Some(state) = self.load_existing(store)? {
            return Ok(state);
        }
        let mut state = RolloutState::new(
            self.migration_id.clone(),
            self.project_path.canonicalize()?.to_string_lossy().into_owned(),
        );
        if self.migration_id.starts_with("txn-") {
            self.bind_source_transaction(&mut state).map_err(invalid)?;
        }
        self.persist_locked(store, &state)?;
        Ok(state)
    }

    /// Selecting an exact native transaction ID is explicit opt-in. Never infer
    /// the most recent transaction, and never execute rollback while binding.
    #[cfg(target_os = "linux")]
    fn bind_source_transaction(&self, state: &mut RolloutState) -> Result<(), String> {
        use super::rollback::{RollbackStatus, SourceState, TransactionState};
        let preview = super::rollback::run(&self.project_path, Some(&self.migration_id), false);
        let entry = preview.transaction.as_ref()
            .ok_or_else(|| format!("cannot bind native rollback transaction: {}", preview.errors.join("; ")))?;
        if preview.status != RollbackStatus::Ready
            || entry.state != TransactionState::Applied
            || preview.files.is_empty()
            || preview.files.iter().any(|file| file.preflight_state != SourceState::Rewritten)
        {
            return Err("rollout requires an intact, fully applied native rewrite; recover interrupted or conflicting transactions with migrate rollback first".into());
        }
        state.rollback_plan_id = Some(entry.transaction_id.clone());
        state.rollback_journal_sha256 = Some(entry.journal_sha256.clone());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn bind_source_transaction(&self, _state: &mut RolloutState) -> Result<(), String> {
        Err("native transaction-bound source rollback is supported on Linux only".into())
    }

    #[cfg(target_os = "linux")]
    fn verify_bound_source(&self, state: &RolloutState) -> Result<(), String> {
        use super::rollback::{RollbackStatus, SourceState, TransactionState};
        if let (Some(id), Some(pin)) = (&state.rollback_plan_id, &state.rollback_journal_sha256) {
            let preview = super::rollback::run_pinned(&self.project_path, id, pin, false);
            if preview.status != RollbackStatus::Ready
                || !preview.transaction.as_ref().is_some_and(|entry| entry.state == TransactionState::Applied)
                || preview.files.is_empty()
                || preview.files.iter().any(|file| file.preflight_state != SourceState::Rewritten)
            {
                return Err(format!("bound rewrite is not intact and applied; promotion refused: {:?}; {}", preview.status, preview.errors.join("; ")));
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn verify_bound_source(&self, state: &RolloutState) -> Result<(), String> {
        if state.rollback_plan_id.is_some() {
            return Err("native transaction-bound source rollback is supported on Linux only".into());
        }
        Ok(())
    }

    pub fn load_or_init(&self) -> io::Result<RolloutState> {
        let store = self.open_store()?;
        self.load_or_init_locked(&store)
    }

    /// Explicit state updates still cannot change the admitted recovery identity
    /// or resurrect an aborted migration. Lifecycle methods retain the lock
    /// across read/modify/write and use persist_locked instead.
    pub fn persist(&self, state: &RolloutState) -> io::Result<()> {
        let store = self.open_store()?;
        if let Some(previous) = self.load_existing(&store)? {
            if previous.rollback_plan_id != state.rollback_plan_id
                || previous.rollback_journal_sha256 != state.rollback_journal_sha256
                || (previous.current_stage == RolloutStage::Aborted && state.current_stage != RolloutStage::Aborted)
            {
                return Err(invalid("cannot replace a bound recovery plan or revive an aborted rollout"));
            }
        } else if state.rollback_plan_id.is_some() || self.migration_id.starts_with("txn-") {
            return Err(invalid("initialize and admit the native transaction before updating rollout state"));
        }
        self.persist_locked(&store, state)
    }

    fn report(state: RolloutState, ok: bool, message: String) -> RolloutReport {
        let source_rollback = state.rollback_plan_id.as_ref().zip(state.rollback_journal_sha256.as_ref())
            .map(|(id, pin)| SourceRollbackSummary {
                transaction_id: id.clone(),
                journal_sha256: pin.clone(),
                restoration_recorded: state.status == RolloutStatus::RolledBack,
            });
        RolloutReport {
            schema_version: ROLLOUT_REPORT_SCHEMA_VERSION.into(),
            command: "migrate.rollout".into(),
            ok,
            migration_id: state.migration_id,
            project_path: state.project_path,
            stage: state.current_stage,
            status: state.status,
            ramp_pct: state.ramp_pct,
            confidence_score: state.confidence_score,
            lockstep_verified: state.lockstep_verified,
            rollback_triggered: state.current_stage == RolloutStage::Aborted,
            source_rollback,
            message,
            history: state.history,
        }
    }

    pub fn status(&self) -> io::Result<RolloutReport> {
        let store = self.open_store()?;
        let state = self.load_or_init_locked(&store)?;
        let message = format!("Rollout is in stage '{}' with status '{}'{}", state.current_stage, state.status,
            if state.current_stage == RolloutStage::Aborted && state.status == RolloutStatus::Failed {
                "; source restoration is not recorded as complete; retry rollback with the same migration ID"
            } else { "" });
        let ok = !matches!(state.status, RolloutStatus::Failed | RolloutStatus::RolledBack);
        Ok(Self::report(state, ok, message))
    }

    pub fn promote(
        &self,
        config: &RolloutConfig,
        target_stage: Option<RolloutStage>,
        target_ramp_pct: Option<u8>,
    ) -> Result<RolloutReport, String> {
        if !config.min_confidence_score.is_finite()
            || !(0.0..=1.0).contains(&config.min_confidence_score)
            || !(1..=100).contains(&config.ramp_step_pct)
        {
            return Err("rollout confidence must be finite and in [0,1]; ramp step must be in [1,100]".into());
        }
        let store = self.open_store().map_err(|e| e.to_string())?;
        let mut state = self.load_or_init_locked(&store).map_err(|e| e.to_string())?;
        if state.current_stage == RolloutStage::Aborted || state.status == RolloutStatus::Failed {
            return Err("cannot promote an aborted/rolled-back migration or one awaiting recovery".into());
        }
        let from_stage = state.current_stage;
        let next_stage = target_stage.unwrap_or(match from_stage {
            RolloutStage::Shadow => RolloutStage::Canary,
            RolloutStage::Canary => RolloutStage::Ramp,
            RolloutStage::Ramp if state.ramp_pct >= 100 => RolloutStage::Default,
            RolloutStage::Ramp => RolloutStage::Ramp,
            RolloutStage::Default => RolloutStage::Default,
            RolloutStage::Aborted => RolloutStage::Aborted,
        });
        if next_stage == RolloutStage::Aborted {
            return Err("use the rollback action to abort; promotion cannot bypass source recovery".into());
        }
        if !config.force {
            if next_stage == RolloutStage::Default && from_stage == RolloutStage::Shadow {
                return Err("cannot skip from Shadow directly to Default; requires Canary and Ramp validation".into());
            }
            if !matches!((from_stage, next_stage),
                (RolloutStage::Shadow, RolloutStage::Shadow | RolloutStage::Canary)
                | (RolloutStage::Canary, RolloutStage::Ramp)
                | (RolloutStage::Ramp, RolloutStage::Ramp)
                | (RolloutStage::Default, RolloutStage::Default))
                && !(from_stage == RolloutStage::Ramp && state.ramp_pct == 100 && next_stage == RolloutStage::Default)
            {
                return Err("promotion must follow Shadow -> Canary -> Ramp 100% -> Default".into());
            }
            if state.confidence_score < config.min_confidence_score {
                let reason = format!("confidence score {:.2} is below minimum threshold {:.2}", state.confidence_score, config.min_confidence_score);
                if config.auto_rollback_on_failure
                    && let Err(error) = self.rollback_locked(&store, state, &reason)
                {
                    return Err(format!("{reason}; automatic rollback did not complete: {error}"));
                }
                return Err(reason);
            }
        }
        self.verify_bound_source(&state)?;
        if target_ramp_pct.is_some() && next_stage != RolloutStage::Ramp {
            return Err("ramp_pct applies only to the Ramp stage".into());
        }
        let new_ramp_pct = match next_stage {
            RolloutStage::Shadow => 0,
            RolloutStage::Canary => 5,
            RolloutStage::Ramp => {
                let pct = target_ramp_pct.unwrap_or_else(|| state.ramp_pct.saturating_add(config.ramp_step_pct).min(100));
                if pct > 100 || (!config.force && pct <= state.ramp_pct) {
                    return Err("ramp percentage must increase and cannot exceed 100%".into());
                }
                pct
            }
            RolloutStage::Default => 100,
            RolloutStage::Aborted => unreachable!(),
        };
        if from_stage == next_stage && matches!(next_stage, RolloutStage::Shadow | RolloutStage::Default) {
            return Ok(Self::report(state, true, "requested rollout stage already recorded; no transition performed".into()));
        }
        let mut evidence_note = None;
        if from_stage == RolloutStage::Shadow && !state.lockstep_verified {
            match config.lockstep_report.as_deref() {
                Some(report_path) => {
                    let digest = verify_lockstep_evidence(&self.project_path, report_path)?;
                    state.lockstep_verified = true;
                    evidence_note = Some(format!("lockstep evidence {digest}"));
                }
                None if config.require_lockstep_evidence && !config.force => {
                    return Err(format!("promotion out of Shadow requires lockstep evidence: run `franken-node verify lockstep {} --json > lockstep.json` and pass --lockstep-report lockstep.json", self.project_path.display()));
                }
                None => {}
            }
        }
        let mut reason = if from_stage == next_stage && next_stage == RolloutStage::Ramp {
            format!("stepped rollout ramp to {new_ramp_pct}%")
        } else {
            format!("promoted from {from_stage} to {next_stage}")
        };
        if let Some(note) = evidence_note {
            reason.push_str("; ");
            reason.push_str(&note);
        } else if from_stage == RolloutStage::Shadow && !state.lockstep_verified {
            reason.push_str("; forced without lockstep evidence");
        }
        let now = chrono::Utc::now().to_rfc3339();
        state.history.push(RolloutTransitionEvent {
            from_stage,
            to_stage: next_stage,
            action: "promote".into(),
            reason: reason.clone(),
            timestamp_utc: now.clone(),
            confidence_score: state.confidence_score,
            ramp_pct: new_ramp_pct,
            receipt_signature: Some(state.digest()),
        });
        state.current_stage = next_stage;
        state.ramp_pct = new_ramp_pct;
        state.status = if next_stage == RolloutStage::Default { RolloutStatus::Completed } else { RolloutStatus::Active };
        state.updated_at = now;
        self.persist_locked(&store, &state).map_err(|e| e.to_string())?;
        Ok(Self::report(state, true, reason))
    }

    /// Stop local rollout progression and restore the explicitly bound native
    /// transaction, if any. There is no shell command or latest-ID inference.
    pub fn rollback(&self, reason: &str) -> Result<RolloutReport, String> {
        let store = self.open_store().map_err(|e| e.to_string())?;
        let state = self.load_or_init_locked(&store).map_err(|e| e.to_string())?;
        self.rollback_locked(&store, state, reason)
    }

    fn rollback_locked(&self, store: &Store, mut state: RolloutState, reason: &str) -> Result<RolloutReport, String> {
        if reason.len() > 4096 {
            return Err("rollback reason exceeds 4096 bytes".into());
        }
        if state.current_stage == RolloutStage::Aborted && state.status == RolloutStatus::RolledBack {
            let message = if state.rollback_plan_id.is_some() {
                "Source rollback already recorded; current files were not changed or re-certified"
            } else {
                "Rollout already aborted; no source files restored (no transaction bound)"
            };
            return Ok(Self::report(state, true, message.into()));
        }
        // Persist a failed/aborted intent FIRST. This forbids promotion after a
        // crash, and retry retains the exact original binding. Native recovery
        // then owns its own per-file durable write-ahead journal.
        if !(state.current_stage == RolloutStage::Aborted && state.status == RolloutStatus::Failed) {
            let now = chrono::Utc::now().to_rfc3339();
            let event = RolloutTransitionEvent {
                from_stage: state.current_stage,
                to_stage: RolloutStage::Aborted,
                action: "rollback_started".into(),
                reason: reason.into(),
                timestamp_utc: now.clone(),
                confidence_score: state.confidence_score,
                ramp_pct: 0,
                receipt_signature: Some(state.digest()),
            };
            state.current_stage = RolloutStage::Aborted;
            state.status = RolloutStatus::Failed;
            state.ramp_pct = 0;
            state.updated_at = now;
            state.history.push(event);
            self.persist_locked(store, &state).map_err(|e| e.to_string())?;
        }
        let restoration = self.restore_bound_source(&state)?;
        let now = chrono::Utc::now().to_rfc3339();
        let event = RolloutTransitionEvent {
            from_stage: RolloutStage::Aborted,
            to_stage: RolloutStage::Aborted,
            action: "rollback".into(),
            reason: format!("{restoration}; {reason}"),
            timestamp_utc: now.clone(),
            confidence_score: state.confidence_score,
            ramp_pct: 0,
            receipt_signature: Some(state.digest()),
        };
        state.status = RolloutStatus::RolledBack;
        state.updated_at = now;
        state.history.push(event);
        // If this final write fails, the durable intent stays retryable. The
        // native completed receipt makes the next restore idempotent.
        self.persist_locked(store, &state).map_err(|e| format!("{restoration}; completion state not persisted; retry rollback: {e}"))?;
        Ok(Self::report(state, true, format!("{restoration}; {reason}")))
    }

    #[cfg(target_os = "linux")]
    fn restore_bound_source(&self, state: &RolloutState) -> Result<String, String> {
        use super::rollback::RollbackStatus;
        let (Some(id), Some(pin)) = (&state.rollback_plan_id, &state.rollback_journal_sha256) else {
            return Ok("Rollout aborted; no source files restored (no transaction bound)".into());
        };
        let report = super::rollback::run_pinned(&self.project_path, id, pin, true);
        match report.status {
            RollbackStatus::RolledBack => Ok(format!("Restored native rewrite {id}; journal_sha256={pin}; files={}", report.files.len())),
            RollbackStatus::AlreadyRolledBack => Ok(format!("Native rewrite {id} restoration already recorded; current files were not changed or re-certified")),
            _ => {
                let details = report.errors.iter().map(String::as_str)
                    .chain(report.files.iter().filter_map(|file| file.error.as_deref()))
                    .collect::<Vec<_>>().join("; ");
                Err(format!("native source rollback {id} did not complete ({:?}); rollout remains aborted/failed; preserve journals and resolve conflicts, then retry the same migration ID: {details}", report.status))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn restore_bound_source(&self, state: &RolloutState) -> Result<String, String> {
        self.verify_bound_source(state)?;
        Ok("Rollout aborted; no source files restored (no transaction bound)".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "rollout_recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_node::runtime::nversion_oracle::{BoundaryScope, RuntimeEntry, RuntimeOracle};
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn write_lockstep_report(dir: &Path, input: &[u8], diverge: bool) -> PathBuf {
        let mut oracle = RuntimeOracle::new("rollout-test-trace", 100);
        for (id, is_reference) in [("node", true), ("franken-node", false)] {
            oracle.register_runtime(RuntimeEntry {
                runtime_id: id.to_string(), runtime_name: id.to_string(),
                version: "test".to_string(), is_reference,
            }).unwrap();
        }
        let mut outputs = BTreeMap::new();
        outputs.insert("node".to_string(), b"hello\n".to_vec());
        outputs.insert("franken-node".to_string(), if diverge { b"goodbye\n".to_vec() } else { b"hello\n".to_vec() });
        let check = oracle.run_cross_check("check-1", BoundaryScope::IO, input, &outputs).unwrap();
        if let Some(frankenengine_node::runtime::nversion_oracle::CheckOutcome::Diverge { outputs: div_outputs }) = check.outcome {
            oracle.classify_divergence("div-1", "check-1", BoundaryScope::IO, frankenengine_node::runtime::nversion_oracle::RiskTier::High, &div_outputs);
        }
        let report = oracle.generate_report(0);
        let path = dir.join(if diverge { "lockstep-diverged.json" } else { "lockstep.json" });
        fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        path
    }

    fn project_with_manifest(dir: &Path) -> Vec<u8> {
        let manifest = br#"{"name":"rollout-fixture","version":"1.0.0"}"#.to_vec();
        fs::write(dir.join("package.json"), &manifest).unwrap();
        manifest
    }

    #[test]
    fn leaving_shadow_without_lockstep_evidence_fails_closed() {
        let dir = tempdir().unwrap();
        project_with_manifest(dir.path());
        let mgr = RolloutManager::new(dir.path(), Some("mig-evidence-01"));
        let err = mgr.promote(&RolloutConfig::default(), None, None).unwrap_err();
        assert!(err.contains("requires lockstep evidence"), "{err}");
        assert_eq!(mgr.load_or_init().unwrap().current_stage, RolloutStage::Shadow);
    }

    #[test]
    fn diverged_or_foreign_lockstep_report_is_rejected() {
        let dir = tempdir().unwrap();
        let manifest = project_with_manifest(dir.path());
        let mgr = RolloutManager::new(dir.path(), Some("mig-evidence-02"));
        let diverged = write_lockstep_report(dir.path(), &manifest, true);
        let cfg = RolloutConfig { lockstep_report: Some(diverged), ..RolloutConfig::default() };
        let err = mgr.promote(&cfg, None, None).unwrap_err();
        assert!(err.contains("not Pass"), "{err}");
        let foreign = write_lockstep_report(dir.path(), b"{\"name\":\"other-project\"}", false);
        let cfg = RolloutConfig { lockstep_report: Some(foreign), ..RolloutConfig::default() };
        let err = mgr.promote(&cfg, None, None).unwrap_err();
        assert!(err.contains("different input"), "{err}");
        assert!(!mgr.load_or_init().unwrap().lockstep_verified);
    }

    #[test]
    fn forced_promotion_never_claims_lockstep_verification() {
        let dir = tempdir().unwrap();
        project_with_manifest(dir.path());
        let mgr = RolloutManager::new(dir.path(), Some("mig-evidence-03"));
        let cfg = RolloutConfig { force: true, ..RolloutConfig::default() };
        let report = mgr.promote(&cfg, None, None).unwrap();
        assert_eq!(report.stage, RolloutStage::Canary);
        assert!(!report.lockstep_verified);
        assert!(report.message.contains("forced without lockstep evidence"));
    }

    #[test]
    fn fresh_rollout_initializes_in_shadow_stage() {
        let dir = tempdir().unwrap();
        let mgr = RolloutManager::new(dir.path(), Some("mig-test-01"));
        let state = mgr.load_or_init().unwrap();
        assert_eq!(state.migration_id, "mig-test-01");
        assert_eq!(state.current_stage, RolloutStage::Shadow);
        assert_eq!(state.status, RolloutStatus::Pending);
        assert_eq!(state.ramp_pct, 0);
        assert_eq!(state.confidence_score, 1.0);
    }

    #[test]
    fn promotion_advances_through_stages() {
        let dir = tempdir().unwrap();
        let manifest = project_with_manifest(dir.path());
        let mgr = RolloutManager::new(dir.path(), Some("mig-test-02"));
        let cfg = RolloutConfig { lockstep_report: Some(write_lockstep_report(dir.path(), &manifest, false)), ..RolloutConfig::default() };
        let rep1 = mgr.promote(&cfg, None, None).unwrap();
        assert_eq!(rep1.stage, RolloutStage::Canary);
        assert_eq!(rep1.ramp_pct, 5);
        assert!(rep1.lockstep_verified);
        assert!(rep1.message.contains("lockstep evidence sha256:"));
        let rep2 = mgr.promote(&cfg, None, None).unwrap();
        assert_eq!(rep2.stage, RolloutStage::Ramp);
        assert_eq!(rep2.ramp_pct, 30);
        let rep3 = mgr.promote(&cfg, None, None).unwrap();
        assert_eq!(rep3.stage, RolloutStage::Ramp);
        assert_eq!(rep3.ramp_pct, 55);
        let rep4 = mgr.promote(&cfg, Some(RolloutStage::Ramp), Some(100)).unwrap();
        assert_eq!(rep4.stage, RolloutStage::Ramp);
        assert_eq!(rep4.ramp_pct, 100);
        let rep5 = mgr.promote(&cfg, None, None).unwrap();
        assert_eq!(rep5.stage, RolloutStage::Default);
        assert_eq!(rep5.status, RolloutStatus::Completed);
        assert_eq!(rep5.ramp_pct, 100);
    }

    #[test]
    fn direct_skip_from_shadow_to_default_fails_without_force() {
        let dir = tempdir().unwrap();
        let mgr = RolloutManager::new(dir.path(), Some("mig-test-03"));
        let err = mgr.promote(&RolloutConfig::default(), Some(RolloutStage::Default), None).unwrap_err();
        assert!(err.contains("cannot skip from Shadow directly to Default"));
    }

    #[test]
    fn low_confidence_triggers_rollback() {
        let dir = tempdir().unwrap();
        let mgr = RolloutManager::new(dir.path(), Some("mig-test-04"));
        let mut state = mgr.load_or_init().unwrap();
        state.confidence_score = 0.50;
        mgr.persist(&state).unwrap();
        let err = mgr.promote(&RolloutConfig::default(), None, None).unwrap_err();
        assert!(err.contains("confidence score 0.50 is below minimum threshold"));
        let status = mgr.status().unwrap();
        assert_eq!(status.stage, RolloutStage::Aborted);
        assert_eq!(status.status, RolloutStatus::RolledBack);
        assert!(status.rollback_triggered);
        assert!(status.source_rollback.is_none());
    }

    #[test]
    fn restart_safe_idempotency_preserves_state() {
        let dir = tempdir().unwrap();
        let manifest = project_with_manifest(dir.path());
        let mgr1 = RolloutManager::new(dir.path(), Some("mig-test-05"));
        let cfg = RolloutConfig { lockstep_report: Some(write_lockstep_report(dir.path(), &manifest, false)), ..RolloutConfig::default() };
        mgr1.promote(&cfg, None, None).unwrap();
        let mgr2 = RolloutManager::new(dir.path(), Some("mig-test-05"));
        let status = mgr2.status().unwrap();
        assert_eq!(status.stage, RolloutStage::Canary);
        assert_eq!(status.ramp_pct, 5);
        assert_eq!(status.history.len(), 1);
    }

    #[test]
    fn human_report_rendering() {
        let rep = RolloutReport {
            schema_version: ROLLOUT_REPORT_SCHEMA_VERSION.to_string(),
            command: "migrate.rollout".to_string(), ok: true,
            migration_id: "mig-test-render".to_string(), project_path: "/test/project".to_string(),
            stage: RolloutStage::Canary, status: RolloutStatus::Active, ramp_pct: 5,
            confidence_score: 0.98, lockstep_verified: true, rollback_triggered: false,
            source_rollback: None, message: "canary running smoothly".to_string(), history: vec![],
        };
        let human = rep.render_human();
        assert!(human.contains("mig-test-render"));
        assert!(human.contains("Canary"));
        assert!(human.contains("98.00%"));
    }
}
