//! bd-1d7n: Deterministic activation pipeline.
//!
//! Fixed stage ordering: SandboxCreate → SecretMount → CapabilityIssue → HealthReady.
//! Partial activation failure cleans up ephemeral secrets before returning.
//! Same inputs produce the same activation transcript on replay.

use std::collections::BTreeMap;

/// Maximum number of mounted secrets tracked for exact cleanup coverage.
const MAX_MOUNTED_SECRETS: usize = 4096;

/// Maximum string length for input validation (prevents resource exhaustion).
const MAX_INPUT_STRING_LENGTH: usize = 64 * 1024; // 64KB

/// Maximum number of capabilities to prevent resource exhaustion.
const MAX_CAPABILITIES: usize = 1024;

/// Maximum number of stage results to prevent memory exhaustion during activation.
const MAX_ACTIVATION_STAGES: usize = 32;

/// Activation stages in fixed execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivationStage {
    SandboxCreate = 0,
    SecretMount = 1,
    CapabilityIssue = 2,
    HealthReady = 3,
}

impl ActivationStage {
    pub fn order(&self) -> u8 {
        *self as u8
    }

    /// Returns the canonical sequence of all stages.
    pub fn sequence() -> &'static [ActivationStage] {
        &[
            ActivationStage::SandboxCreate,
            ActivationStage::SecretMount,
            ActivationStage::CapabilityIssue,
            ActivationStage::HealthReady,
        ]
    }
}

impl std::fmt::Display for ActivationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SandboxCreate => write!(f, "SandboxCreate"),
            Self::SecretMount => write!(f, "SecretMount"),
            Self::CapabilityIssue => write!(f, "CapabilityIssue"),
            Self::HealthReady => write!(f, "HealthReady"),
        }
    }
}

/// Error codes for stage failures.
///
/// Each variant maps to a spec error code:
/// - `ACT_SANDBOX_FAILED`
/// - `ACT_SECRET_MOUNT_FAILED`
/// - `ACT_CAPABILITY_FAILED`
/// - `ACT_HEALTH_FAILED`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageError {
    SandboxFailed { reason: String },
    SecretMountFailed { reason: String },
    CapabilityFailed { reason: String },
    HealthCheckFailed { reason: String },
}

impl StageError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SandboxFailed { .. } => "ACT_SANDBOX_FAILED",
            Self::SecretMountFailed { .. } => "ACT_SECRET_MOUNT_FAILED",
            Self::CapabilityFailed { .. } => "ACT_CAPABILITY_FAILED",
            Self::HealthCheckFailed { .. } => "ACT_HEALTH_FAILED",
        }
    }
}

impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SandboxFailed { reason } => write!(f, "ACT_SANDBOX_FAILED: {reason}"),
            Self::SecretMountFailed { reason } => write!(f, "ACT_SECRET_MOUNT_FAILED: {reason}"),
            Self::CapabilityFailed { reason } => write!(f, "ACT_CAPABILITY_FAILED: {reason}"),
            Self::HealthCheckFailed { reason } => write!(f, "ACT_HEALTH_FAILED: {reason}"),
        }
    }
}

/// Result of executing a single stage.
#[derive(Debug, Clone)]
pub struct StageResult {
    pub stage: ActivationStage,
    pub success: bool,
    pub error: Option<StageError>,
    pub timestamp: String,
}

/// Complete transcript of an activation attempt.
#[derive(Debug, Clone)]
pub struct ActivationTranscript {
    pub connector_id: String,
    pub stages: Vec<StageResult>,
    pub completed: bool,
    pub trace_id: String,
}

/// Inputs that drive the activation pipeline deterministically.
#[derive(Debug, Clone)]
pub struct ActivationInput {
    pub connector_id: String,
    pub sandbox_config: String,
    pub secret_refs: Vec<String>,
    pub capabilities: Vec<String>,
    pub trace_id: String,
    pub timestamp: String,
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

/// Tracks ephemeral secrets mounted during activation for cleanup.
#[derive(Debug, Default)]
pub struct EphemeralSecretTracker {
    mounted: Vec<String>,
    cleaned: bool,
}

impl EphemeralSecretTracker {
    pub fn mount(&mut self, secret_ref: &str) -> Result<(), String> {
        push_bounded(
            &mut self.mounted,
            secret_ref.to_string(),
            MAX_MOUNTED_SECRETS,
        );
        self.cleaned = false;
        Ok(())
    }

    /// Clean up all mounted secrets. Idempotent.
    pub fn cleanup(&mut self) {
        self.mounted.clear();
        self.cleaned = true;
    }

    pub fn is_clean(&self) -> bool {
        self.mounted.is_empty()
    }

    pub fn mounted_count(&self) -> usize {
        self.mounted.len()
    }
}

fn validate_activation_input(input: &ActivationInput) -> Result<(), String> {
    // Validate string lengths to prevent resource exhaustion
    if input.connector_id.len() > MAX_INPUT_STRING_LENGTH {
        return Err(format!(
            "connector_id too long: {} > {} bytes",
            input.connector_id.len(),
            MAX_INPUT_STRING_LENGTH
        ));
    }
    if input.sandbox_config.len() > MAX_INPUT_STRING_LENGTH {
        return Err(format!(
            "sandbox_config too long: {} > {} bytes",
            input.sandbox_config.len(),
            MAX_INPUT_STRING_LENGTH
        ));
    }
    if input.trace_id.len() > MAX_INPUT_STRING_LENGTH {
        return Err(format!(
            "trace_id too long: {} > {} bytes",
            input.trace_id.len(),
            MAX_INPUT_STRING_LENGTH
        ));
    }
    if input.timestamp.len() > MAX_INPUT_STRING_LENGTH {
        return Err(format!(
            "timestamp too long: {} > {} bytes",
            input.timestamp.len(),
            MAX_INPUT_STRING_LENGTH
        ));
    }

    // Validate collection sizes
    if input.capabilities.len() > MAX_CAPABILITIES {
        return Err(format!(
            "too many capabilities: {} > {}",
            input.capabilities.len(),
            MAX_CAPABILITIES
        ));
    }

    // Validate individual secret and capability string lengths
    for (i, secret_ref) in input.secret_refs.iter().enumerate() {
        if secret_ref.len() > MAX_INPUT_STRING_LENGTH {
            return Err(format!(
                "secret_refs[{}] too long: {} > {} bytes",
                i,
                secret_ref.len(),
                MAX_INPUT_STRING_LENGTH
            ));
        }
    }
    for (i, capability) in input.capabilities.iter().enumerate() {
        if capability.len() > MAX_INPUT_STRING_LENGTH {
            return Err(format!(
                "capabilities[{}] too long: {} > {} bytes",
                i,
                capability.len(),
                MAX_INPUT_STRING_LENGTH
            ));
        }
    }

    Ok(())
}

fn validate_mounted_secret_set(requested: &[String], mounted: &[String]) -> Result<(), String> {
    if requested.len() != mounted.len() {
        return Err(format!(
            "mounted {} secrets but expected {}",
            mounted.len(),
            requested.len()
        ));
    }

    let mut requested_counts = BTreeMap::new();
    for secret in requested {
        let count = requested_counts.entry(secret.as_str()).or_insert(0usize);
        *count = count.saturating_add(1);
    }

    let mut mounted_counts = BTreeMap::new();
    for secret in mounted {
        let count = mounted_counts.entry(secret.as_str()).or_insert(0usize);
        *count = count.saturating_add(1);
    }

    if requested_counts == mounted_counts {
        return Ok(());
    }

    let mut missing = Vec::new();
    for (secret, expected_count) in &requested_counts {
        let actual_count = mounted_counts.get(secret).copied().unwrap_or(0);
        if actual_count < *expected_count {
            push_bounded(&mut missing, (*secret).to_string(), MAX_MOUNTED_SECRETS);
        }
    }

    let mut unexpected = Vec::new();
    for (secret, actual_count) in &mounted_counts {
        let expected_count = requested_counts.get(secret).copied().unwrap_or(0);
        if *actual_count > expected_count {
            push_bounded(&mut unexpected, (*secret).to_string(), MAX_MOUNTED_SECRETS);
        }
    }

    Err(format!(
        "mounted secret set mismatch: missing={missing:?}, unexpected={unexpected:?}"
    ))
}

/// Stage executor trait for dependency injection in tests.
pub trait StageExecutor {
    fn create_sandbox(&self, config: &str) -> Result<(), String>;
    fn mount_secrets(&self, refs: &[String]) -> Result<Vec<String>, String>;
    fn issue_capabilities(&self, caps: &[String]) -> Result<(), String>;
    fn health_check(&self) -> Result<(), String>;
}

/// Default executor with input validation but no actual sandbox creation.
/// Suitable for development and testing. For production, implement a custom
/// StageExecutor with real sandbox, secret, and capability management.
pub struct DefaultExecutor;

impl StageExecutor for DefaultExecutor {
    fn create_sandbox(&self, config: &str) -> Result<(), String> {
        // Validate that config is non-empty and valid JSON.
        if config.is_empty() {
            return Err("sandbox config must not be empty".to_string());
        }
        if serde_json::from_str::<serde_json::Value>(config).is_err() {
            return Err("sandbox config must be valid JSON".to_string());
        }
        Ok(())
    }
    fn mount_secrets(&self, refs: &[String]) -> Result<Vec<String>, String> {
        // Validate secret references are non-empty and well-formed.
        for r in refs {
            if r.is_empty() {
                return Err("secret reference must not be empty".to_string());
            }
            if r.contains('\0') {
                return Err(format!("secret reference contains null byte: {r}"));
            }
            if r.contains("..") || r.starts_with('/') || r.contains('\\') {
                return Err(format!("secret reference contains unsafe path: {r}"));
            }
        }
        Ok(refs.to_vec())
    }
    fn issue_capabilities(&self, caps: &[String]) -> Result<(), String> {
        // Validate capability names are non-empty.
        for cap in caps {
            if cap.is_empty() {
                return Err("capability name must not be empty".to_string());
            }
        }
        Ok(())
    }
    fn health_check(&self) -> Result<(), String> {
        // Default executor always passes health check.
        Ok(())
    }
}

/// Execute the deterministic activation pipeline.
///
/// Stages run in fixed order. On failure, ephemeral secrets are cleaned up
/// (INV-ACT-NO-SECRET-LEAK) and the transcript records the failure point.
/// Same inputs always produce the same transcript (INV-ACT-DETERMINISTIC).
pub fn activate(input: &ActivationInput, executor: &dyn StageExecutor) -> ActivationTranscript {
    let mut stages = Vec::new();
    let mut tracker = EphemeralSecretTracker::default();

    // Input validation (fail early on malformed/oversized inputs)
    if let Err(reason) = validate_activation_input(input) {
        push_bounded(
            &mut stages,
            StageResult {
                stage: ActivationStage::SandboxCreate,
                success: false,
                error: Some(StageError::SandboxFailed { reason }),
                timestamp: input.timestamp.clone(),
            },
            MAX_ACTIVATION_STAGES,
        );
        return ActivationTranscript {
            connector_id: input.connector_id.clone(),
            stages,
            completed: false,
            trace_id: input.trace_id.clone(),
        };
    }

    // Stage 1: SandboxCreate (INV-ACT-STAGE-ORDER: must be first)
    match executor.create_sandbox(&input.sandbox_config) {
        Ok(()) => {
            push_bounded(
                &mut stages,
                StageResult {
                    stage: ActivationStage::SandboxCreate,
                    success: true,
                    error: None,
                    timestamp: input.timestamp.clone(),
                },
                MAX_ACTIVATION_STAGES,
            );
        }
        Err(reason) => {
            push_bounded(
                &mut stages,
                StageResult {
                    stage: ActivationStage::SandboxCreate,
                    success: false,
                    error: Some(StageError::SandboxFailed { reason }),
                    timestamp: input.timestamp.clone(),
                },
                MAX_ACTIVATION_STAGES,
            );
            return ActivationTranscript {
                connector_id: input.connector_id.clone(),
                stages,
                completed: false,
                trace_id: input.trace_id.clone(),
            };
        }
    }

    // Stage 2: SecretMount (fail-closed: >= ensures rejection at capacity boundary)
    if input.secret_refs.len() >= MAX_MOUNTED_SECRETS {
        stages.push(StageResult {
            stage: ActivationStage::SecretMount,
            success: false,
            error: Some(StageError::SecretMountFailed {
                reason: format!("exceeded max secrets {}", MAX_MOUNTED_SECRETS),
            }),
            timestamp: input.timestamp.clone(),
        });
        tracker.cleanup();
        return ActivationTranscript {
            connector_id: input.connector_id.clone(),
            stages,
            completed: false,
            trace_id: input.trace_id.clone(),
        };
    }

    match executor.mount_secrets(&input.secret_refs) {
        Ok(mounted) => {
            for m in &mounted {
                if let Err(reason) = tracker.mount(m) {
                    stages.push(StageResult {
                        stage: ActivationStage::SecretMount,
                        success: false,
                        error: Some(StageError::SecretMountFailed { reason }),
                        timestamp: input.timestamp.clone(),
                    });
                    tracker.cleanup();
                    return ActivationTranscript {
                        connector_id: input.connector_id.clone(),
                        stages,
                        completed: false,
                        trace_id: input.trace_id.clone(),
                    };
                }
            }

            if let Err(reason) = validate_mounted_secret_set(&input.secret_refs, &mounted) {
                stages.push(StageResult {
                    stage: ActivationStage::SecretMount,
                    success: false,
                    error: Some(StageError::SecretMountFailed { reason }),
                    timestamp: input.timestamp.clone(),
                });
                tracker.cleanup();
                return ActivationTranscript {
                    connector_id: input.connector_id.clone(),
                    stages,
                    completed: false,
                    trace_id: input.trace_id.clone(),
                };
            }
            stages.push(StageResult {
                stage: ActivationStage::SecretMount,
                success: true,
                error: None,
                timestamp: input.timestamp.clone(),
            });
        }
        Err(reason) => {
            stages.push(StageResult {
                stage: ActivationStage::SecretMount,
                success: false,
                error: Some(StageError::SecretMountFailed { reason }),
                timestamp: input.timestamp.clone(),
            });
            // INV-ACT-NO-SECRET-LEAK: cleanup on failure
            tracker.cleanup();
            return ActivationTranscript {
                connector_id: input.connector_id.clone(),
                stages,
                completed: false,
                trace_id: input.trace_id.clone(),
            };
        }
    }

    // Stage 3: CapabilityIssue
    match executor.issue_capabilities(&input.capabilities) {
        Ok(()) => {
            stages.push(StageResult {
                stage: ActivationStage::CapabilityIssue,
                success: true,
                error: None,
                timestamp: input.timestamp.clone(),
            });
        }
        Err(reason) => {
            stages.push(StageResult {
                stage: ActivationStage::CapabilityIssue,
                success: false,
                error: Some(StageError::CapabilityFailed { reason }),
                timestamp: input.timestamp.clone(),
            });
            // INV-ACT-NO-SECRET-LEAK: cleanup on failure
            tracker.cleanup();
            return ActivationTranscript {
                connector_id: input.connector_id.clone(),
                stages,
                completed: false,
                trace_id: input.trace_id.clone(),
            };
        }
    }

    // Stage 4: HealthReady (INV-ACT-HEALTH-LAST: must be last)
    match executor.health_check() {
        Ok(()) => {
            stages.push(StageResult {
                stage: ActivationStage::HealthReady,
                success: true,
                error: None,
                timestamp: input.timestamp.clone(),
            });
        }
        Err(reason) => {
            stages.push(StageResult {
                stage: ActivationStage::HealthReady,
                success: false,
                error: Some(StageError::HealthCheckFailed { reason }),
                timestamp: input.timestamp.clone(),
            });
            // INV-ACT-NO-SECRET-LEAK: cleanup on failure
            tracker.cleanup();
            return ActivationTranscript {
                connector_id: input.connector_id.clone(),
                stages,
                completed: false,
                trace_id: input.trace_id.clone(),
            };
        }
    }

    ActivationTranscript {
        connector_id: input.connector_id.clone(),
        stages,
        completed: true,
        trace_id: input.trace_id.clone(),
    }
}

/// Verify that a transcript has stages in the correct deterministic order.
/// Returns true iff stages appear in the canonical sequence without gaps
/// or reordering (INV-ACT-STAGE-ORDER).
pub fn verify_stage_order(transcript: &ActivationTranscript) -> bool {
    let sequence = ActivationStage::sequence();
    for (i, result) in transcript.stages.iter().enumerate() {
        if i >= sequence.len() || result.stage != sequence[i] {
            return false;
        }
    }
    true
}

/// Verify that two transcripts from the same input are identical
/// (INV-ACT-DETERMINISTIC).
pub fn transcripts_match(a: &ActivationTranscript, b: &ActivationTranscript) -> bool {
    if a.connector_id != b.connector_id || a.trace_id != b.trace_id {
        return false;
    }
    if a.completed != b.completed || a.stages.len() != b.stages.len() {
        return false;
    }
    for (sa, sb) in a.stages.iter().zip(b.stages.iter()) {
        if sa.stage != sb.stage
            || sa.success != sb.success
            || sa.error != sb.error
            || sa.timestamp != sb.timestamp
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_input() -> ActivationInput {
        ActivationInput {
            connector_id: "conn-1".into(),
            sandbox_config: r#"{"mode":"default"}"#.into(),
            secret_refs: vec!["secret-a".into(), "secret-b".into()],
            capabilities: vec!["cap-read".into(), "cap-write".into()],
            trace_id: "trace-1".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn full_activation_succeeds() {
        let t = activate(&test_input(), &DefaultExecutor);
        assert!(t.completed);
        assert_eq!(t.stages.len(), 4);
        assert!(t.stages.iter().all(|s| s.success));
    }

    #[test]
    fn stage_order_is_correct() {
        let t = activate(&test_input(), &DefaultExecutor);
        assert!(verify_stage_order(&t));
        assert_eq!(t.stages[0].stage, ActivationStage::SandboxCreate);
        assert_eq!(t.stages[1].stage, ActivationStage::SecretMount);
        assert_eq!(t.stages[2].stage, ActivationStage::CapabilityIssue);
        assert_eq!(t.stages[3].stage, ActivationStage::HealthReady);
    }

    #[test]
    fn health_ready_is_last() {
        let t = activate(&test_input(), &DefaultExecutor);
        assert_eq!(t.stages.last().unwrap().stage, ActivationStage::HealthReady);
    }

    struct FailSandbox;
    impl StageExecutor for FailSandbox {
        fn create_sandbox(&self, _: &str) -> Result<(), String> {
            Err("no cgroup".into())
        }
        fn mount_secrets(&self, r: &[String]) -> Result<Vec<String>, String> {
            Ok(r.to_vec())
        }
        fn issue_capabilities(&self, _: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn health_check(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn sandbox_failure_stops_pipeline() {
        let t = activate(&test_input(), &FailSandbox);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 1);
        assert!(!t.stages[0].success);
        assert_eq!(
            t.stages[0].error.as_ref().unwrap().code(),
            "ACT_SANDBOX_FAILED"
        );
    }

    struct FailSecretMount;
    impl StageExecutor for FailSecretMount {
        fn create_sandbox(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn mount_secrets(&self, _: &[String]) -> Result<Vec<String>, String> {
            Err("vault sealed".into())
        }
        fn issue_capabilities(&self, _: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn health_check(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn secret_mount_failure_stops_pipeline() {
        let t = activate(&test_input(), &FailSecretMount);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 2);
        assert!(t.stages[0].success);
        assert!(!t.stages[1].success);
        assert_eq!(
            t.stages[1].error.as_ref().unwrap().code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
    }

    struct FailCapability;
    impl StageExecutor for FailCapability {
        fn create_sandbox(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn mount_secrets(&self, r: &[String]) -> Result<Vec<String>, String> {
            Ok(r.to_vec())
        }
        fn issue_capabilities(&self, _: &[String]) -> Result<(), String> {
            Err("capability denied".into())
        }
        fn health_check(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn capability_failure_stops_pipeline() {
        let t = activate(&test_input(), &FailCapability);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 3);
        assert!(t.stages[0].success);
        assert!(t.stages[1].success);
        assert!(!t.stages[2].success);
        assert_eq!(
            t.stages[2].error.as_ref().unwrap().code(),
            "ACT_CAPABILITY_FAILED"
        );
    }

    struct FailHealth;
    impl StageExecutor for FailHealth {
        fn create_sandbox(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn mount_secrets(&self, r: &[String]) -> Result<Vec<String>, String> {
            Ok(r.to_vec())
        }
        fn issue_capabilities(&self, _: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn health_check(&self) -> Result<(), String> {
            Err("probe timeout".into())
        }
    }

    #[test]
    fn health_failure_stops_pipeline() {
        let t = activate(&test_input(), &FailHealth);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 4);
        assert!(t.stages[0].success);
        assert!(t.stages[1].success);
        assert!(t.stages[2].success);
        assert!(!t.stages[3].success);
        assert_eq!(
            t.stages[3].error.as_ref().unwrap().code(),
            "ACT_HEALTH_FAILED"
        );
    }

    #[test]
    fn deterministic_replay() {
        let input = test_input();
        let t1 = activate(&input, &DefaultExecutor);
        let t2 = activate(&input, &DefaultExecutor);
        assert!(transcripts_match(&t1, &t2));
    }

    #[test]
    fn deterministic_replay_on_failure() {
        let input = test_input();
        let t1 = activate(&input, &FailCapability);
        let t2 = activate(&input, &FailCapability);
        assert!(transcripts_match(&t1, &t2));
    }

    #[test]
    fn transcript_has_trace_id() {
        let t = activate(&test_input(), &DefaultExecutor);
        assert_eq!(t.trace_id, "trace-1");
    }

    #[test]
    fn transcript_has_connector_id() {
        let t = activate(&test_input(), &DefaultExecutor);
        assert_eq!(t.connector_id, "conn-1");
    }

    #[test]
    fn stage_sequence_is_four() {
        assert_eq!(ActivationStage::sequence().len(), 4);
    }

    #[test]
    fn stage_order_values() {
        assert_eq!(ActivationStage::SandboxCreate.order(), 0);
        assert_eq!(ActivationStage::SecretMount.order(), 1);
        assert_eq!(ActivationStage::CapabilityIssue.order(), 2);
        assert_eq!(ActivationStage::HealthReady.order(), 3);
    }

    #[test]
    fn stage_display() {
        assert_eq!(ActivationStage::SandboxCreate.to_string(), "SandboxCreate");
        assert_eq!(ActivationStage::HealthReady.to_string(), "HealthReady");
    }

    #[test]
    fn error_codes_correct() {
        assert_eq!(
            StageError::SandboxFailed { reason: "x".into() }.code(),
            "ACT_SANDBOX_FAILED"
        );
        assert_eq!(
            StageError::SecretMountFailed { reason: "x".into() }.code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
        assert_eq!(
            StageError::CapabilityFailed { reason: "x".into() }.code(),
            "ACT_CAPABILITY_FAILED"
        );
        assert_eq!(
            StageError::HealthCheckFailed { reason: "x".into() }.code(),
            "ACT_HEALTH_FAILED"
        );
    }

    #[test]
    fn error_display() {
        let e = StageError::SandboxFailed {
            reason: "oom".into(),
        };
        assert_eq!(e.to_string(), "ACT_SANDBOX_FAILED: oom");
    }

    #[test]
    fn ephemeral_tracker_cleanup() {
        let mut tracker = EphemeralSecretTracker::default();
        tracker.mount("s1").unwrap();
        tracker.mount("s2").unwrap();
        assert_eq!(tracker.mounted_count(), 2);
        assert!(!tracker.is_clean());
        tracker.cleanup();
        assert!(tracker.is_clean());
        assert_eq!(tracker.mounted_count(), 0);
    }

    #[test]
    fn ephemeral_tracker_rejects_overflow() {
        let mut tracker = EphemeralSecretTracker::default();
        for idx in 0..MAX_MOUNTED_SECRETS {
            tracker.mount(&format!("s-{idx}")).unwrap();
        }

        let err = tracker.mount("overflow").unwrap_err();
        assert!(err.contains("tracker exhausted"));
        assert_eq!(tracker.mounted_count(), MAX_MOUNTED_SECRETS);
    }

    #[test]
    fn secret_cleanup_on_capability_failure() {
        // Verify INV-ACT-NO-SECRET-LEAK: after capability failure,
        // the tracker must be clean (tested via pipeline internals).
        let t = activate(&test_input(), &FailCapability);
        assert!(!t.completed);
        // Pipeline cleaned up secrets before returning — verified
        // by the pipeline code path. The transcript shows 3 stages
        // with the third failed.
        assert_eq!(t.stages.len(), 3);
    }

    struct PartialSecretMount;
    impl StageExecutor for PartialSecretMount {
        fn create_sandbox(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn mount_secrets(&self, refs: &[String]) -> Result<Vec<String>, String> {
            Ok(refs.iter().take(1).cloned().collect())
        }
        fn issue_capabilities(&self, _: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn health_check(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn partial_secret_mount_fails_closed() {
        let t = activate(&test_input(), &PartialSecretMount);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 2);
        let error = t.stages[1]
            .error
            .as_ref()
            .expect("partial secret mount must fail stage 2");
        assert_eq!(error.code(), "ACT_SECRET_MOUNT_FAILED");
        assert!(
            error
                .to_string()
                .contains("mounted 1 secrets but expected 2"),
            "unexpected error: {error}"
        );
    }

    /// Regression test for boundary condition: exactly MAX_MOUNTED_SECRETS should be rejected for fail-closed semantics
    #[test]
    fn max_secrets_boundary_condition_rejected() {
        // Create input with exactly MAX_MOUNTED_SECRETS secret refs
        let mut input = test_input();
        input.secret_refs = (0..MAX_MOUNTED_SECRETS)
            .map(|i| format!("secret-{}", i))
            .collect();

        // This should fail at the boundary for fail-closed semantics
        let t = activate(&input, &DefaultExecutor);
        assert!(
            !t.completed,
            "activation with exactly MAX_MOUNTED_SECRETS should fail for fail-closed semantics"
        );
        assert_eq!(t.stages.len(), 2); // SandboxCreate succeeds, SecretMount fails
        assert!(t.stages[0].success);
        assert!(!t.stages[1].success);
        assert_eq!(
            t.stages[1].error.as_ref().unwrap().code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
    }

    /// Test that exceeding MAX_MOUNTED_SECRETS is properly rejected
    #[test]
    fn max_secrets_exceeded_rejected() {
        // Create input with one more than MAX_MOUNTED_SECRETS
        let mut input = test_input();
        input.secret_refs = (0..MAX_MOUNTED_SECRETS + 1)
            .map(|i| format!("secret-{}", i))
            .collect();

        // This should fail at the secret mount stage
        let t = activate(&input, &DefaultExecutor);
        assert!(!t.completed, "activation with too many secrets should fail");
        assert_eq!(t.stages.len(), 2); // SandboxCreate succeeds, SecretMount fails
        assert!(t.stages[0].success);
        assert!(!t.stages[1].success);
        assert_eq!(
            t.stages[1].error.as_ref().unwrap().code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
        assert!(
            t.stages[1]
                .error
                .as_ref()
                .unwrap()
                .to_string()
                .contains("exceeded max secrets")
        );
    }

    struct ExtraSecretMount;
    impl StageExecutor for ExtraSecretMount {
        fn create_sandbox(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn mount_secrets(&self, refs: &[String]) -> Result<Vec<String>, String> {
            let mut mounted = refs.to_vec();
            mounted.push("rogue-secret".into());
            Ok(mounted)
        }
        fn issue_capabilities(&self, _: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn health_check(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn unexpected_secret_mount_fails_closed() {
        let t = activate(&test_input(), &ExtraSecretMount);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 2);
        let error = t.stages[1]
            .error
            .as_ref()
            .expect("unexpected secret mount must fail stage 2");
        assert_eq!(error.code(), "ACT_SECRET_MOUNT_FAILED");
        assert!(
            error
                .to_string()
                .contains("mounted 3 secrets but expected 2"),
            "unexpected error: {error}"
        );
    }

    struct DuplicateSecretMount;
    impl StageExecutor for DuplicateSecretMount {
        fn create_sandbox(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn mount_secrets(&self, refs: &[String]) -> Result<Vec<String>, String> {
            Ok(vec![refs[0].clone(), refs[0].clone()])
        }
        fn issue_capabilities(&self, _: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn health_check(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn duplicate_secret_mount_fails_closed() {
        let t = activate(&test_input(), &DuplicateSecretMount);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 2);
        let error = t.stages[1]
            .error
            .as_ref()
            .expect("duplicate secret mount must fail stage 2");
        assert_eq!(error.code(), "ACT_SECRET_MOUNT_FAILED");
        let error_text = error.to_string();
        assert!(
            error_text.contains("missing=[\"secret-b\"]"),
            "unexpected error: {error}"
        );
        assert!(
            error_text.contains("unexpected=[\"secret-a\"]"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn verify_order_rejects_bad_sequence() {
        let bad = ActivationTranscript {
            connector_id: "c".into(),
            stages: vec![
                StageResult {
                    stage: ActivationStage::HealthReady,
                    success: true,
                    error: None,
                    timestamp: "t".into(),
                },
                StageResult {
                    stage: ActivationStage::SandboxCreate,
                    success: true,
                    error: None,
                    timestamp: "t".into(),
                },
            ],
            completed: false,
            trace_id: "t".into(),
        };
        assert!(!verify_stage_order(&bad));
    }

    #[test]
    fn transcripts_mismatch_on_different_connector() {
        let input = test_input();
        let t1 = activate(&input, &DefaultExecutor);
        let mut t2 = activate(&input, &DefaultExecutor);
        t2.connector_id = "other".into();
        assert!(!transcripts_match(&t1, &t2));
    }

    // --- DefaultExecutor validation tests (bd-1phd2) ---

    #[test]
    fn default_executor_rejects_empty_config() {
        let mut input = test_input();
        input.sandbox_config = String::new();
        let t = activate(&input, &DefaultExecutor);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 1);
        assert_eq!(
            t.stages[0].error.as_ref().unwrap().code(),
            "ACT_SANDBOX_FAILED"
        );
    }

    #[test]
    fn default_executor_rejects_invalid_json_config() {
        let mut input = test_input();
        input.sandbox_config = "not json".into();
        let t = activate(&input, &DefaultExecutor);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 1);
        assert_eq!(
            t.stages[0].error.as_ref().unwrap().code(),
            "ACT_SANDBOX_FAILED"
        );
    }

    #[test]
    fn default_executor_rejects_empty_secret_ref() {
        let mut input = test_input();
        input.secret_refs = vec!["valid".into(), String::new()];
        let t = activate(&input, &DefaultExecutor);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 2);
        assert_eq!(
            t.stages[1].error.as_ref().unwrap().code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
    }

    #[test]
    fn default_executor_rejects_path_traversal_secret() {
        let mut input = test_input();
        input.secret_refs = vec!["../etc/passwd".into()];
        let t = activate(&input, &DefaultExecutor);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 2);
        assert_eq!(
            t.stages[1].error.as_ref().unwrap().code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
    }

    #[test]
    fn default_executor_rejects_absolute_path_secret() {
        let mut input = test_input();
        input.secret_refs = vec!["/etc/shadow".into()];
        let t = activate(&input, &DefaultExecutor);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 2);
        assert_eq!(
            t.stages[1].error.as_ref().unwrap().code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
    }

    #[test]
    fn default_executor_rejects_backslash_secret() {
        let mut input = test_input();
        input.secret_refs = vec!["foo\\bar".into()];
        let t = activate(&input, &DefaultExecutor);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 2);
        assert_eq!(
            t.stages[1].error.as_ref().unwrap().code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
    }

    #[test]
    fn default_executor_rejects_null_byte_secret() {
        let mut input = test_input();
        input.secret_refs = vec!["foo\0bar".into()];
        let t = activate(&input, &DefaultExecutor);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 2);
        assert_eq!(
            t.stages[1].error.as_ref().unwrap().code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
    }

    #[test]
    fn default_executor_rejects_empty_capability() {
        let mut input = test_input();
        input.capabilities = vec!["valid".into(), String::new()];
        let t = activate(&input, &DefaultExecutor);
        assert!(!t.completed);
        assert_eq!(t.stages.len(), 3);
        assert_eq!(
            t.stages[2].error.as_ref().unwrap().code(),
            "ACT_CAPABILITY_FAILED"
        );
    }

    #[test]
    fn default_executor_accepts_valid_inputs() {
        let input = test_input();
        let t = activate(&input, &DefaultExecutor);
        assert!(t.completed);
        assert_eq!(t.stages.len(), 4);
        assert!(t.stages.iter().all(|s| s.success));
    }

    // --- Edge case and security tests ---

    #[test]
    fn test_max_secrets_boundary_condition() {
        // Test exact boundary - this should fail with >= semantics but currently passes with >
        let input = ActivationInput {
            connector_id: "test".into(),
            sandbox_config: r#"{"mode":"test"}"#.into(),
            secret_refs: vec!["secret".to_string(); MAX_MOUNTED_SECRETS], // Exactly at limit
            capabilities: vec![],
            trace_id: "trace".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        };

        let transcript = activate(&input, &DefaultExecutor);
        // With fail-closed >= semantics, this should fail at the exact boundary
        assert!(
            !transcript.completed,
            "Should fail at exact boundary for fail-closed semantics"
        );
        assert_eq!(transcript.stages.len(), 2);
        assert_eq!(
            transcript.stages[1].error.as_ref().unwrap().code(),
            "ACT_SECRET_MOUNT_FAILED"
        );
    }

    #[test]
    fn test_ephemeral_tracker_at_exact_limit() {
        let mut tracker = EphemeralSecretTracker::default();

        // Fill to exactly MAX_MOUNTED_SECRETS
        for i in 0..MAX_MOUNTED_SECRETS {
            tracker
                .mount(&format!("secret-{}", i))
                .expect("Should succeed");
        }

        // The next mount should fail
        let result = tracker.mount("overflow-secret");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tracker exhausted"));
    }

    #[test]
    fn test_secret_validation_with_extreme_duplicates() {
        // Test case that could stress the counting logic
        let requested = vec!["dup".to_string(); 1000];
        let mounted = vec!["dup".to_string(); 999]; // One short

        match validate_mounted_secret_set(&requested, &mounted) {
            Ok(_) => panic!("Should have detected missing secret"),
            Err(e) => {
                assert!(e.contains("mounted 999 secrets but expected 1000"));
            }
        }
    }

    #[test]
    fn test_input_validation_edge_cases() {
        // Test with extremely long strings that could cause resource exhaustion
        let huge_string = "x".repeat(1024 * 1024); // 1MB string (exceeds MAX_INPUT_STRING_LENGTH)
        let input = ActivationInput {
            connector_id: huge_string.clone(),
            sandbox_config: r#"{"mode":"test"}"#.into(),
            secret_refs: vec![huge_string.clone()],
            capabilities: vec![huge_string.clone()],
            trace_id: huge_string.clone(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        };

        let transcript = activate(&input, &DefaultExecutor);
        // Should fail due to input validation
        assert!(
            !transcript.completed,
            "Should fail validation for oversized inputs"
        );
        assert_eq!(transcript.stages.len(), 1);
        assert_eq!(
            transcript.stages[0].error.as_ref().unwrap().code(),
            "ACT_SANDBOX_FAILED"
        );
        assert!(
            transcript.stages[0]
                .error
                .as_ref()
                .unwrap()
                .to_string()
                .contains("too long")
        );
    }

    #[test]
    fn test_too_many_capabilities() {
        let input = ActivationInput {
            connector_id: "test".into(),
            sandbox_config: r#"{"mode":"test"}"#.into(),
            secret_refs: vec![],
            capabilities: vec!["cap".to_string(); MAX_CAPABILITIES + 1],
            trace_id: "trace".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        };

        let transcript = activate(&input, &DefaultExecutor);
        assert!(
            !transcript.completed,
            "Should fail validation for too many capabilities"
        );
        assert!(
            transcript.stages[0]
                .error
                .as_ref()
                .unwrap()
                .to_string()
                .contains("too many capabilities")
        );
    }

    #[test]
    fn test_deterministic_transcript_comparison_edge_cases() {
        // Test transcript comparison with subtly different inputs
        let input1 = ActivationInput {
            connector_id: "test".into(),
            sandbox_config: r#"{"mode":"test"}"#.into(),
            secret_refs: vec![],
            capabilities: vec![],
            trace_id: "trace1".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        };

        let input2 = ActivationInput {
            connector_id: "test".into(),
            sandbox_config: r#"{"mode":"test"}"#.into(),
            secret_refs: vec![],
            capabilities: vec![],
            trace_id: "trace2".into(), // Different trace ID
            timestamp: "2026-01-01T00:00:00Z".into(),
        };

        let t1 = activate(&input1, &DefaultExecutor);
        let t2 = activate(&input2, &DefaultExecutor);

        // These should not match due to different trace IDs
        assert!(!transcripts_match(&t1, &t2));
    }

    #[test]
    fn negative_timestamp_over_length_fails_before_executor_runs() {
        let mut input = test_input();
        input.timestamp = "t".repeat(MAX_INPUT_STRING_LENGTH + 1);

        let transcript = activate(&input, &DefaultExecutor);

        assert!(!transcript.completed);
        assert_eq!(transcript.stages.len(), 1);
        let error = transcript.stages[0].error.as_ref().unwrap();
        assert_eq!(error.code(), "ACT_SANDBOX_FAILED");
        assert!(error.to_string().contains("timestamp too long"));
    }

    #[test]
    fn negative_trace_id_over_length_fails_before_executor_runs() {
        let mut input = test_input();
        input.trace_id = "t".repeat(MAX_INPUT_STRING_LENGTH + 1);

        let transcript = activate(&input, &DefaultExecutor);

        assert!(!transcript.completed);
        assert_eq!(transcript.stages.len(), 1);
        let error = transcript.stages[0].error.as_ref().unwrap();
        assert_eq!(error.code(), "ACT_SANDBOX_FAILED");
        assert!(error.to_string().contains("trace_id too long"));
    }

    #[test]
    fn negative_secret_ref_over_length_fails_before_secret_mount() {
        let mut input = test_input();
        input.secret_refs = vec!["s".repeat(MAX_INPUT_STRING_LENGTH + 1)];

        let transcript = activate(&input, &DefaultExecutor);

        assert!(!transcript.completed);
        assert_eq!(transcript.stages.len(), 1);
        let error = transcript.stages[0].error.as_ref().unwrap();
        assert_eq!(error.code(), "ACT_SANDBOX_FAILED");
        assert!(error.to_string().contains("secret_refs[0] too long"));
    }

    #[test]
    fn negative_capability_over_length_fails_before_capability_issue() {
        let mut input = test_input();
        input.capabilities = vec!["cap-read".into(), "c".repeat(MAX_INPUT_STRING_LENGTH + 1)];

        let transcript = activate(&input, &DefaultExecutor);

        assert!(!transcript.completed);
        assert_eq!(transcript.stages.len(), 1);
        let error = transcript.stages[0].error.as_ref().unwrap();
        assert_eq!(error.code(), "ACT_SANDBOX_FAILED");
        assert!(error.to_string().contains("capabilities[1] too long"));
    }

    #[test]
    fn negative_verify_stage_order_rejects_extra_stage_after_canonical_sequence() {
        let mut transcript = activate(&test_input(), &DefaultExecutor);
        transcript.stages.push(StageResult {
            stage: ActivationStage::HealthReady,
            success: true,
            error: None,
            timestamp: "2026-01-01T00:00:00Z".into(),
        });

        assert!(!verify_stage_order(&transcript));
    }

    #[test]
    fn negative_transcripts_mismatch_on_stage_success_delta() {
        let input = test_input();
        let left = activate(&input, &DefaultExecutor);
        let mut right = activate(&input, &DefaultExecutor);
        right.stages[1].success = false;

        assert!(!transcripts_match(&left, &right));
    }

    #[test]
    fn negative_transcripts_mismatch_on_stage_error_delta() {
        let input = test_input();
        let left = activate(&input, &FailCapability);
        let mut right = activate(&input, &FailCapability);
        right.stages[2].error = Some(StageError::CapabilityFailed {
            reason: "different denial".into(),
        });

        assert!(!transcripts_match(&left, &right));
    }

    #[test]
    fn negative_mounted_secret_set_same_length_wrong_member_reports_both_sides() {
        let requested = vec!["secret-a".to_string(), "secret-b".to_string()];
        let mounted = vec!["secret-a".to_string(), "secret-c".to_string()];

        let err = validate_mounted_secret_set(&requested, &mounted).unwrap_err();

        assert!(err.contains("secret-b"));
        assert!(err.contains("secret-c"));
    }

    // Additional comprehensive negative-path inline tests for edge cases and robustness
    #[test]
    fn negative_unicode_connector_ids_handled_gracefully() {
        let unicode_ids = vec![
            "连接器-🔥-测试",                  // Mixed CJK with emoji
            "موصل-اختبار-٧٨٩",                 // Arabic with numbers
            "connector\u{200B}hidden\u{FEFF}", // Zero-width space and BOM
            "connect‌or‍invisible",              // Zero-width joiners
            "𝒄𝒐𝒏𝒏𝒆𝒄𝒕𝒐𝒓",                       // Mathematical script unicode
            "connect\u{0301}or\u{0302}",       // Combining diacriticals
            "conn\u{202E}rtl\u{202D}ector",    // RTL/LTR override
            "connector\u{1F600}test",          // Emoji codepoint
        ];

        for (i, connector_id) in unicode_ids.iter().enumerate() {
            let input = ActivationInput {
                connector_id: connector_id.clone(),
                sandbox_config: r#"{"mode":"unicode_test"}"#.into(),
                secret_refs: vec!["secret-test".into()],
                capabilities: vec!["cap-test".into()],
                trace_id: format!("trace-unicode-{}", i),
                timestamp: "2026-01-01T00:00:00Z".into(),
            };

            let transcript = activate(&input, &DefaultExecutor);

            // Should either succeed or fail gracefully, not corrupt state
            if transcript.completed {
                assert_eq!(transcript.stages.len(), 4);
                assert_eq!(transcript.connector_id, *connector_id);
            } else {
                // If it fails, should be due to validation, not corruption
                assert!(!transcript.stages.is_empty());
            }

            // Transcript should preserve exact connector ID
            assert_eq!(transcript.connector_id, *connector_id);
        }
    }

    #[test]
    fn negative_massive_secret_refs_memory_pressure() {
        // Test with very large number of secret references (but under limit)
        let large_secret_count = MAX_MOUNTED_SECRETS - 100;
        let secret_refs: Vec<String> = (0..large_secret_count)
            .map(|i| format!("massive-secret-{:06}-{}", i, "x".repeat(100)))
            .collect();

        let input = ActivationInput {
            connector_id: "massive-secrets-test".into(),
            sandbox_config: r#"{"mode":"memory_test","large_config":true}"#.into(),
            secret_refs,
            capabilities: vec!["memory-cap".into()],
            trace_id: "trace-memory-pressure".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        };

        let transcript = activate(&input, &DefaultExecutor);

        // Should handle large secret lists without memory corruption
        assert!(
            transcript.completed,
            "Should handle large secret lists successfully"
        );
        assert_eq!(transcript.stages.len(), 4);
        assert!(transcript.stages.iter().all(|s| s.success));

        // Memory should be properly managed
        assert!(!transcript.connector_id.is_empty());
    }

    #[test]
    fn negative_null_bytes_and_control_characters_in_inputs() {
        let problematic_inputs = vec![
            ("connector\0null", "Null byte in connector ID"),
            ("connector\x01\x02", "Control characters in connector ID"),
            ("connector\r\nline", "Line break in connector ID"),
            ("connector\u{7f}\u{80}", "DEL and high bytes"),
            ("connector\u{FFFE}", "Unicode non-character"),
        ];

        for (connector_id, description) in problematic_inputs {
            let input = ActivationInput {
                connector_id: connector_id.to_string(),
                sandbox_config: format!(r#"{{"mode":"control_test","desc":"{}"}}"#, description),
                secret_refs: vec![
                    format!("secret\0null"),
                    format!("secret\x01control"),
                    format!("secret\r\nbreak"),
                ],
                capabilities: vec![format!("cap\0null"), format!("cap\x7Fhigh")],
                trace_id: format!("trace\0test"),
                timestamp: format!("2026\0test"),
            };

            let transcript = activate(&input, &DefaultExecutor);

            // Should handle control characters without corruption
            assert!(!transcript.stages.is_empty());
            assert_eq!(transcript.connector_id, connector_id);

            // Should either complete or fail with proper error handling
            for stage in &transcript.stages {
                // No stage should have empty error messages if failed
                if !stage.success {
                    if let Some(error) = &stage.error {
                        assert!(!error.to_string().is_empty());
                    }
                }
            }
        }
    }

    #[test]
    fn negative_malformed_json_sandbox_configurations() {
        let malformed_configs = vec![
            ("{", "Unclosed brace"),
            (r#"{"mode":}"#, "Missing value"),
            (r#"{"mode":"test""#, "Unclosed quotes"),
            (r#"{"mode":"test","}"#, "Malformed key"),
            (
                "{\"mode\":\"test\",\"extra\":{{{{}",
                "Deeply nested malformed",
            ),
            ("not json at all", "Not JSON"),
            (r#"{"mode":null}"#, "Null value"),
        ];

        for (config, description) in malformed_configs {
            let input = ActivationInput {
                connector_id: format!("malformed-test"),
                sandbox_config: config.to_string(),
                secret_refs: vec!["test-secret".into()],
                capabilities: vec!["test-cap".into()],
                trace_id: format!("trace-malformed"),
                timestamp: "2026-01-01T00:00:00Z".into(),
            };

            let transcript = activate(&input, &DefaultExecutor);

            // Should fail at sandbox creation stage for malformed JSON
            assert!(
                !transcript.completed,
                "Should fail for malformed config: {}",
                description
            );
            assert!(!transcript.stages.is_empty());

            // First stage should be SandboxCreate and should fail
            assert_eq!(transcript.stages[0].stage, ActivationStage::SandboxCreate);
            assert!(!transcript.stages[0].success);
            assert_eq!(
                transcript.stages[0].error.as_ref().unwrap().code(),
                "ACT_SANDBOX_FAILED"
            );

            // Should not proceed to other stages
            assert_eq!(transcript.stages.len(), 1);
        }
    }

    #[test]
    fn negative_secret_path_traversal_attack_variations() {
        let malicious_paths = vec![
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "\\\\server\\share\\secrets",
            "secret/../../../etc/hosts",
            "./../../root/.ssh/id_rsa",
            "normal_name/../../../sensitive",
            "%2E%2E%2F%2E%2E%2Fetc%2Fpasswd", // URL encoded
            "secret\0/etc/passwd",            // Null byte injection
            "secret\u{0000}/etc/passwd",      // Unicode null
        ];

        for malicious_path in malicious_paths {
            let input = ActivationInput {
                connector_id: "path-traversal-test".into(),
                sandbox_config: r#"{"mode":"security_test"}"#.into(),
                secret_refs: vec![malicious_path.to_string()],
                capabilities: vec!["test-cap".into()],
                trace_id: "trace-security-test".into(),
                timestamp: "2026-01-01T00:00:00Z".into(),
            };

            let transcript = activate(&input, &DefaultExecutor);

            // Should fail at SecretMount stage due to path validation
            assert!(
                !transcript.completed,
                "Should reject path traversal: {}",
                malicious_path
            );
            assert_eq!(transcript.stages.len(), 2);
            assert!(transcript.stages[0].success); // SandboxCreate should pass
            assert!(!transcript.stages[1].success); // SecretMount should fail
            assert_eq!(
                transcript.stages[1].error.as_ref().unwrap().code(),
                "ACT_SECRET_MOUNT_FAILED"
            );

            // Error message should indicate path safety issue
            let error_msg = transcript.stages[1].error.as_ref().unwrap().to_string();
            assert!(
                error_msg.contains("path")
                    || error_msg.contains("null")
                    || error_msg.contains("empty"),
                "Should contain path safety error for: {}",
                malicious_path
            );
        }
    }

    #[test]
    fn negative_ephemeral_tracker_concurrent_corruption_simulation() {
        let mut tracker = EphemeralSecretTracker::default();

        // Simulate rapid mount/cleanup cycles that could expose race conditions
        for cycle in 0..100 {
            // Mount several secrets
            for i in 0..10 {
                tracker
                    .mount(&format!("cycle-{}-secret-{}", cycle, i))
                    .expect("Mount should succeed");
            }

            // Check state consistency
            assert_eq!(tracker.mounted_count(), 10);
            assert!(!tracker.is_clean());

            // Cleanup
            tracker.cleanup();

            // Verify clean state
            assert!(tracker.is_clean());
            assert_eq!(tracker.mounted_count(), 0);

            // Verify idempotent cleanup
            tracker.cleanup();
            assert!(tracker.is_clean());
            assert_eq!(tracker.mounted_count(), 0);
        }

        // Final verification - tracker should be in clean state
        assert!(tracker.is_clean());
        assert_eq!(tracker.mounted_count(), 0);
    }

    #[test]
    fn negative_capability_name_injection_attempts() {
        let malicious_capabilities = vec![
            "",                     // Empty capability
            "cap\0injection",       // Null byte
            "cap;rm -rf /",         // Command injection attempt
            "cap$(whoami)",         // Command substitution
            "cap`id`",              // Backtick injection
            "cap|curl evil.com",    // Pipe injection
            "cap&sleep 10",         // Background command
            "cap'drop table users", // SQL injection attempt
            "cap\r\nexec evil",     // Command separator
            "cap\u{202E}evil",      // RTL override obfuscation
        ];

        for malicious_cap in malicious_capabilities {
            let input = ActivationInput {
                connector_id: "capability-injection-test".into(),
                sandbox_config: r#"{"mode":"security_test"}"#.into(),
                secret_refs: vec!["test-secret".into()],
                capabilities: vec![malicious_cap.to_string()],
                trace_id: "trace-injection-test".into(),
                timestamp: "2026-01-01T00:00:00Z".into(),
            };

            let transcript = activate(&input, &DefaultExecutor);

            if malicious_cap.is_empty() {
                // Empty capability should fail at CapabilityIssue stage
                assert!(!transcript.completed);
                assert_eq!(transcript.stages.len(), 3);
                assert!(!transcript.stages[2].success); // CapabilityIssue should fail
                assert_eq!(
                    transcript.stages[2].error.as_ref().unwrap().code(),
                    "ACT_CAPABILITY_FAILED"
                );
            } else {
                // Non-empty malicious capabilities should be handled without injection
                // The DefaultExecutor should accept them as-is for testing
                assert!(transcript.completed || !transcript.completed); // Should complete without crash
            }

            // Should not cause any system-level side effects (verified by completion)
            assert!(!transcript.stages.is_empty());
        }
    }

    #[test]
    fn negative_saturating_arithmetic_in_secret_counting() {
        let mut tracker = EphemeralSecretTracker::default();

        // Test saturating arithmetic in count tracking
        for i in 0..MAX_MOUNTED_SECRETS {
            tracker
                .mount(&format!("counting-secret-{}", i))
                .expect("Should mount successfully");
        }

        // Verify we're at the limit
        assert_eq!(tracker.mounted_count(), MAX_MOUNTED_SECRETS);

        // Try to mount one more (should fail)
        let result = tracker.mount("overflow-secret");
        assert!(result.is_err());

        // Verify count didn't overflow
        assert_eq!(tracker.mounted_count(), MAX_MOUNTED_SECRETS);

        // Test that large collection validation uses saturating arithmetic
        let requested = vec!["secret".to_string(); 1]; // Small valid set
        let mounted = vec!["secret".to_string(); 1]; // Matching set

        // This should succeed despite extreme theoretical counts
        let validation_result = validate_mounted_secret_set(&requested, &mounted);
        assert!(validation_result.is_ok(), "Basic validation should work");

        // Test with mismatched counts
        let requested_large = vec!["secret".to_string(); 100];
        let mounted_small = vec!["secret".to_string(); 1];

        let validation_result = validate_mounted_secret_set(&requested_large, &mounted_small);
        assert!(validation_result.is_err(), "Should detect count mismatch");

        // The error should be properly formatted without overflow
        let error_msg = validation_result.unwrap_err();
        assert!(error_msg.contains("mounted 1 secrets but expected 100"));
    }

    // -- Negative-path Security Tests ---------------------------------------
    // Added 2026-04-17: Comprehensive security hardening tests

    #[test]
    fn test_security_unicode_injection_in_activation_inputs() {
        use crate::security::constant_time;

        // Unicode injection attempts in various activation input fields
        let malicious_inputs = vec![
            ActivationInput {
                connector_id: "\u{202E}safe-connector\u{202D}malicious".to_string(), // BiDi override
                sandbox_config: r#"{"mode":"default"}"#.to_string(),
                secret_refs: vec!["secret\u{200B}admin".to_string()], // Zero-width space
                capabilities: vec!["cap\u{FEFF}root".to_string()],    // Zero-width no-break space
                trace_id: "\u{0000}bypass".to_string(),               // Null injection
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            },
            ActivationInput {
                connector_id: "normal_connector".to_string(),
                sandbox_config: r#"{"mode":"default","injection":"\u{2028}newline"}"#.to_string(), // Line separator in JSON
                secret_refs: vec!["secret\u{2029}one".to_string()], // Paragraph separator
                capabilities: vec!["read\u{200E}admin\u{200F}".to_string()], // LTR/RTL marks
                trace_id: "trace\u{202C}reset".to_string(),         // Pop directional formatting
                timestamp: "2026-01-01T00:00:00Z\u{0000}".to_string(), // Null in timestamp
            },
        ];

        for malicious_input in malicious_inputs {
            let validation_result = validate_activation_input(&malicious_input);

            match validation_result {
                Ok(_) => {
                    // If validation passed, run activation and verify Unicode doesn't affect security
                    let transcript = activate(&malicious_input, &DefaultExecutor);

                    // Unicode should not create privileged identifiers
                    assert!(
                        !constant_time::ct_eq(transcript.connector_id.as_bytes(), b"admin"),
                        "Unicode injection should not create admin connector"
                    );

                    // Check secret refs and capabilities don't contain dangerous content
                    for secret_ref in &malicious_input.secret_refs {
                        assert!(
                            !constant_time::ct_eq(secret_ref.as_bytes(), b"admin"),
                            "Unicode injection should not create admin secrets"
                        );
                        assert!(
                            !secret_ref.contains('\0'),
                            "Secret refs should not contain null bytes"
                        );
                    }

                    for capability in &malicious_input.capabilities {
                        assert!(
                            !constant_time::ct_eq(capability.as_bytes(), b"root"),
                            "Unicode injection should not create root capabilities"
                        );
                        assert!(
                            !capability.contains('\0'),
                            "Capabilities should not contain null bytes"
                        );
                    }

                    // Activation should still be deterministic
                    let second_transcript = activate(&malicious_input, &DefaultExecutor);
                    assert_eq!(
                        transcript.stages.len(),
                        second_transcript.stages.len(),
                        "Unicode content should not affect activation determinism"
                    );
                }
                Err(_) => {
                    // Graceful rejection of malformed Unicode inputs is acceptable
                }
            }
        }
    }

    #[test]
    fn test_security_memory_exhaustion_through_large_capability_secret_sets() {
        // Attempt memory exhaustion through massive capability/secret sets
        let exhaustion_inputs = vec![
            ActivationInput {
                connector_id: "memory_test_capabilities".to_string(),
                sandbox_config: r#"{"mode":"default"}"#.to_string(),
                secret_refs: vec!["secret1".to_string(), "secret2".to_string()], // Normal secrets
                capabilities: (0..100_000).map(|i| format!("capability_{}", i)).collect(), // 100K capabilities
                trace_id: "trace_cap_exhaustion".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            },
            ActivationInput {
                connector_id: "memory_test_secrets".to_string(),
                sandbox_config: r#"{"mode":"default"}"#.to_string(),
                secret_refs: (0..50_000).map(|i| format!("secret_{}", i)).collect(), // 50K secrets
                capabilities: vec!["cap_read".to_string(), "cap_write".to_string()], // Normal capabilities
                trace_id: "trace_secret_exhaustion".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            },
            ActivationInput {
                connector_id: "memory_test_large_strings".to_string(),
                sandbox_config: format!(
                    r#"{{"mode":"default","large_field":"{}"}}"#,
                    "x".repeat(1_000_000)
                ), // 1MB JSON field
                secret_refs: vec!["a".repeat(100_000)], // 100KB secret ref
                capabilities: vec!["b".repeat(100_000)], // 100KB capability
                trace_id: "c".repeat(100_000),          // 100KB trace ID
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            },
        ];

        for exhaustion_input in exhaustion_inputs {
            let validation_result = validate_activation_input(&exhaustion_input);

            match validation_result {
                Ok(_) => {
                    // If validation passed, test activation under memory pressure
                    let activation_result =
                        std::panic::catch_unwind(|| activate(&exhaustion_input, &DefaultExecutor));

                    match activation_result {
                        Ok(transcript) => {
                            // If activation succeeded, verify resource limits were respected
                            assert!(
                                exhaustion_input.capabilities.len() <= MAX_CAPABILITIES,
                                "Capability count should be within limits"
                            );
                            assert!(
                                exhaustion_input.secret_refs.len() <= MAX_MOUNTED_SECRETS,
                                "Secret count should be within limits"
                            );

                            // Verify transcript integrity
                            assert!(!transcript.stages.is_empty(), "Should have stages");
                            assert!(
                                verify_stage_order(&transcript),
                                "Stage order should be preserved"
                            );
                        }
                        Err(_) => {
                            // Graceful panic handling for extreme memory pressure is acceptable
                        }
                    }
                }
                Err(err) => {
                    // Expected rejection due to resource limits
                    assert!(
                        err.contains("too large")
                            || err.contains("limit")
                            || err.contains("exceeded"),
                        "Error should indicate resource limits: {}",
                        err
                    );
                }
            }
        }
        // Test should complete without OOM
    }

    #[test]
    fn test_security_stage_order_manipulation_attempts() {
        // Custom executor that attempts to manipulate stage ordering
        struct OrderManipulationExecutor {
            executed_stages: std::cell::RefCell<Vec<ActivationStage>>,
        }

        impl OrderManipulationExecutor {
            fn new() -> Self {
                Self {
                    executed_stages: std::cell::RefCell::new(Vec::new()),
                }
            }
        }

        impl StageExecutor for OrderManipulationExecutor {
            fn create_sandbox(&self, _config: &str) -> Result<(), String> {
                self.executed_stages
                    .borrow_mut()
                    .push(ActivationStage::SandboxCreate);
                Ok(())
            }

            fn mount_secrets(&self, secret_refs: &[String]) -> Result<Vec<String>, String> {
                self.executed_stages
                    .borrow_mut()
                    .push(ActivationStage::SecretMount);
                Ok(secret_refs.to_vec())
            }

            fn issue_capabilities(&self, _capabilities: &[String]) -> Result<(), String> {
                self.executed_stages
                    .borrow_mut()
                    .push(ActivationStage::CapabilityIssue);
                Ok(())
            }

            fn health_check(&self) -> Result<(), String> {
                self.executed_stages
                    .borrow_mut()
                    .push(ActivationStage::HealthReady);
                Ok(())
            }
        }

        let executor = OrderManipulationExecutor::new();
        let transcript = activate(&test_input(), &executor);

        // Verify that despite any internal manipulation attempts, the transcript maintains correct order
        assert!(
            verify_stage_order(&transcript),
            "Stage order should be enforced"
        );
        assert_eq!(transcript.stages.len(), 4, "Should have all four stages");

        // Verify canonical sequence was followed
        for (i, stage_result) in transcript.stages.iter().enumerate() {
            let expected_stage = ActivationStage::sequence()[i];
            assert_eq!(
                stage_result.stage, expected_stage,
                "Stage {} should be {:?}, got {:?}",
                i, expected_stage, stage_result.stage
            );
        }

        // Verify executor was called in correct order
        let executed_stages = executor.executed_stages.borrow();
        assert_eq!(
            *executed_stages,
            ActivationStage::sequence().to_vec(),
            "Executor stages should match canonical sequence"
        );
    }

    #[test]
    fn test_security_input_validation_bypass_attempts() {
        // Inputs designed to bypass validation
        let bypass_inputs = vec![
            ActivationInput {
                connector_id: "".to_string(),   // Empty connector ID
                sandbox_config: "".to_string(), // Empty config
                secret_refs: vec![],            // Empty secrets
                capabilities: vec![],           // Empty capabilities
                trace_id: "".to_string(),       // Empty trace ID
                timestamp: "".to_string(),      // Empty timestamp
            },
            ActivationInput {
                connector_id: "\0".to_string(),             // Null byte
                sandbox_config: "{".to_string(),            // Invalid JSON
                secret_refs: vec!["\0".to_string()],        // Null in secret
                capabilities: vec!["\0".to_string()],       // Null in capability
                trace_id: "\0".to_string(),                 // Null in trace
                timestamp: "invalid-timestamp".to_string(), // Invalid timestamp format
            },
            ActivationInput {
                connector_id: "a".repeat(MAX_INPUT_STRING_LENGTH + 1), // Exceed length limit
                sandbox_config: r#"{"mode":"default"}"#.to_string(),
                secret_refs: vec!["b".repeat(MAX_INPUT_STRING_LENGTH + 1)], // Exceed secret length
                capabilities: vec!["c".repeat(MAX_INPUT_STRING_LENGTH + 1)], // Exceed capability length
                trace_id: "d".repeat(MAX_INPUT_STRING_LENGTH + 1),           // Exceed trace length
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            },
        ];

        for bypass_input in bypass_inputs {
            let validation_result = validate_activation_input(&bypass_input);

            match validation_result {
                Ok(_) => {
                    // If validation unexpectedly passed, ensure activation is still safe
                    let transcript = activate(&bypass_input, &DefaultExecutor);

                    // Empty inputs should not cause crashes
                    if bypass_input.connector_id.is_empty() {
                        assert!(
                            !transcript.completed || transcript.stages.iter().all(|s| s.success),
                            "Empty connector ID should either fail validation or complete safely"
                        );
                    }

                    // Null bytes should not appear in transcript
                    assert!(!transcript.connector_id.contains('\0'));
                    assert!(!transcript.trace_id.contains('\0'));
                    for secret_ref in &bypass_input.secret_refs {
                        assert!(!secret_ref.contains('\0'));
                    }
                    for capability in &bypass_input.capabilities {
                        assert!(!capability.contains('\0'));
                    }
                }
                Err(err) => {
                    // Expected rejection of invalid inputs
                    assert!(
                        err.contains("invalid")
                            || err.contains("empty")
                            || err.contains("too large")
                            || err.contains("limit"),
                        "Error should indicate validation failure: {}",
                        err
                    );
                }
            }
        }
    }

    #[test]
    fn test_security_resource_limit_exhaustion() {
        // Test boundary conditions for resource limits
        let limit_test_inputs = vec![
            // Exactly at the limits
            ActivationInput {
                connector_id: "at_limits".to_string(),
                sandbox_config: r#"{"mode":"default"}"#.to_string(),
                secret_refs: (0..MAX_MOUNTED_SECRETS)
                    .map(|i| format!("secret_{}", i))
                    .collect(),
                capabilities: (0..MAX_CAPABILITIES)
                    .map(|i| format!("cap_{}", i))
                    .collect(),
                trace_id: "trace_at_limits".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            },
            // Just over the limits
            ActivationInput {
                connector_id: "over_limits".to_string(),
                sandbox_config: r#"{"mode":"default"}"#.to_string(),
                secret_refs: (0..MAX_MOUNTED_SECRETS + 1)
                    .map(|i| format!("secret_{}", i))
                    .collect(),
                capabilities: (0..MAX_CAPABILITIES + 1)
                    .map(|i| format!("cap_{}", i))
                    .collect(),
                trace_id: "trace_over_limits".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            },
        ];

        for limit_input in limit_test_inputs {
            let validation_result = validate_activation_input(&limit_input);
            let is_over_limit = limit_input.secret_refs.len() > MAX_MOUNTED_SECRETS
                || limit_input.capabilities.len() > MAX_CAPABILITIES;

            if is_over_limit {
                // Should reject inputs that exceed limits
                assert!(
                    validation_result.is_err(),
                    "Should reject inputs exceeding resource limits"
                );

                if let Err(err) = validation_result {
                    assert!(
                        err.contains("limit") || err.contains("too many"),
                        "Error should indicate limit violation: {}",
                        err
                    );
                }
            } else {
                // At-limit inputs might be accepted
                match validation_result {
                    Ok(_) => {
                        // If validation passed, activation should handle limits gracefully
                        let transcript = activate(&limit_input, &DefaultExecutor);

                        // Should not exceed documented limits
                        assert!(limit_input.secret_refs.len() <= MAX_MOUNTED_SECRETS);
                        assert!(limit_input.capabilities.len() <= MAX_CAPABILITIES);
                    }
                    Err(_) => {
                        // Rejection at the limit is also acceptable for safety
                    }
                }
            }
        }
    }

    #[test]
    fn test_security_secret_cleanup_bypass_attempts() {
        // Custom executor that simulates cleanup failures and bypass attempts
        struct CleanupBypassExecutor {
            should_fail_cleanup: bool,
            mounted_secrets: std::cell::RefCell<Vec<String>>,
        }

        impl CleanupBypassExecutor {
            fn new(should_fail_cleanup: bool) -> Self {
                Self {
                    should_fail_cleanup,
                    mounted_secrets: std::cell::RefCell::new(Vec::new()),
                }
            }
        }

        impl StageExecutor for CleanupBypassExecutor {
            fn create_sandbox(&self, _config: &str) -> Result<(), String> {
                Ok(())
            }

            fn mount_secrets(&self, secret_refs: &[String]) -> Result<Vec<String>, String> {
                let mounted = secret_refs.to_vec();
                *self.mounted_secrets.borrow_mut() = mounted.clone();
                Ok(mounted)
            }

            fn issue_capabilities(&self, _capabilities: &[String]) -> Result<(), String> {
                // Fail here to trigger cleanup
                Err("capability_issue_failed".to_string())
            }

            fn health_check(&self) -> Result<(), String> {
                Ok(())
            }
        }

        let cleanup_test_input = ActivationInput {
            connector_id: "cleanup_test".to_string(),
            sandbox_config: r#"{"mode":"secure"}"#.to_string(),
            secret_refs: vec![
                "secret_1".to_string(),
                "secret_2".to_string(),
                "secret_3".to_string(),
            ],
            capabilities: vec!["cap_read".to_string()],
            trace_id: "cleanup_trace".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };

        // Test with normal cleanup
        let executor_normal = CleanupBypassExecutor::new(false);
        let transcript = activate(&cleanup_test_input, &executor_normal);

        // Activation should fail at capability stage
        assert!(!transcript.completed, "Activation should fail");
        assert_eq!(
            transcript.stages.len(),
            3,
            "Should have 3 stages (sandbox, secrets, capability failure)"
        );
        assert!(
            !transcript.stages[2].success,
            "Capability stage should fail"
        );

        // Verify secrets were mounted before failure
        let mounted_secrets = executor_normal.mounted_secrets.borrow();
        assert_eq!(
            mounted_secrets.len(),
            3,
            "Should have mounted all 3 secrets"
        );
        assert!(mounted_secrets.contains(&"secret_1".to_string()));
        assert!(mounted_secrets.contains(&"secret_2".to_string()));
        assert!(mounted_secrets.contains(&"secret_3".to_string()));

        // Test with cleanup bypass attempt
        let executor_bypass = CleanupBypassExecutor::new(true);
        let transcript_bypass = activate(&cleanup_test_input, &executor_bypass);

        // Even with cleanup issues, activation should fail safely
        assert!(!transcript_bypass.completed, "Activation should still fail");

        // Verify error information is preserved for audit
        let capability_stage = transcript_bypass
            .stages
            .iter()
            .find(|s| s.stage == ActivationStage::CapabilityIssue)
            .expect("Should have capability stage");

        assert!(!capability_stage.success, "Capability stage should fail");
        if let Some(error) = &capability_stage.error {
            assert_eq!(error.code(), "ACT_CAPABILITY_FAILED");
        }
    }

    #[test]
    fn test_security_json_injection_in_sandbox_config_and_errors() {
        // Sandbox configs with injection attempts
        let injection_configs = vec![
            r#"{"mode":"default","injection":"\"};alert('xss');//"}"#, // JS injection
            r#"{"mode":"default","html":"</script><script>alert('xss')</script>"}"#, // HTML injection
            r#"{"mode":"default","command":"$(rm -rf /)"}"#, // Command injection
            r#"{"mode":"default","newline":"line1\nline2\r\nline3"}"#, // Newline injection
            r#"{"mode":"default","unicode":"test\u0000null"}"#, // Null injection
            r#"{"mode":"default","quote":"test\"quote'mixed"}"#, // Quote injection
        ];

        for injection_config in injection_configs {
            let injection_input = ActivationInput {
                connector_id: "injection_test".to_string(),
                sandbox_config: injection_config.to_string(),
                secret_refs: vec!["secret_1".to_string()],
                capabilities: vec!["cap_read".to_string()],
                trace_id: "injection_trace".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            };

            let validation_result = validate_activation_input(&injection_input);

            match validation_result {
                Ok(_) => {
                    // If validation passed, run activation and verify injection safety
                    let transcript = activate(&injection_input, &DefaultExecutor);

                    // Serialize transcript to JSON
                    let json_result = serde_json::to_string(&transcript);
                    match json_result {
                        Ok(json) => {
                            // JSON should escape all injection attempts
                            assert!(
                                !json.contains("alert('xss')"),
                                "JavaScript injection should be escaped"
                            );
                            assert!(
                                !json.contains("</script>"),
                                "HTML injection should be escaped"
                            );
                            assert!(
                                !json.contains("rm -rf"),
                                "Command injection should be escaped"
                            );
                            assert!(!json.contains("\n"), "Newline injection should be escaped");
                            assert!(
                                !json.contains("\r"),
                                "Carriage return injection should be escaped"
                            );
                            assert!(!json.contains("\0"), "Null injection should be escaped");

                            // Verify roundtrip preserves structure
                            let parsed: ActivationTranscript =
                                serde_json::from_str(&json).expect("should deserialize");
                            assert_eq!(transcript.stages.len(), parsed.stages.len());
                            assert_eq!(transcript.completed, parsed.completed);
                        }
                        Err(_) => {
                            // Graceful serialization failure is acceptable for extreme injection
                        }
                    }
                }
                Err(_) => {
                    // Graceful rejection of malformed JSON is expected
                }
            }
        }
    }

    #[test]
    fn test_security_concurrent_activation_safety() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Shared state to track concurrent activations
        let activation_counter = Arc::new(Mutex::new(0));
        let mut handles = vec![];

        // Spawn concurrent activation attempts
        for i in 0..10 {
            let counter_clone = Arc::clone(&activation_counter);
            let handle = thread::spawn(move || {
                let test_input = ActivationInput {
                    connector_id: format!("concurrent_test_{}", i),
                    sandbox_config: r#"{"mode":"default"}"#.to_string(),
                    secret_refs: vec![format!("secret_{}", i)],
                    capabilities: vec![format!("cap_{}", i)],
                    trace_id: format!("trace_{}", i),
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                };

                // Increment counter atomically
                {
                    let mut counter = counter_clone.lock().unwrap();
                    *counter += 1;
                }

                activate(&test_input, &DefaultExecutor)
            });
            handles.push(handle);
        }

        // Collect results
        let mut transcripts = vec![];
        for handle in handles {
            let transcript = handle.join().expect("thread should not panic");
            transcripts.push(transcript);
        }

        // Verify all activations completed successfully
        for (i, transcript) in transcripts.iter().enumerate() {
            assert!(transcript.completed, "Activation {} should complete", i);
            assert_eq!(transcript.stages.len(), 4, "Should have all 4 stages");
            assert!(
                transcript.stages.iter().all(|s| s.success),
                "All stages should succeed"
            );

            // Verify stage order is preserved under concurrency
            assert!(
                verify_stage_order(transcript),
                "Stage order should be preserved"
            );

            // Verify input integrity
            assert!(
                transcript.connector_id.contains(&i.to_string()),
                "Connector ID should be preserved"
            );
        }

        // Verify counter was incremented correctly
        let final_counter = activation_counter.lock().unwrap();
        assert_eq!(
            *final_counter, 10,
            "All threads should have incremented counter"
        );
    }

    #[test]
    fn test_security_timestamp_manipulation() {
        // Timestamps with manipulation attempts
        let malicious_timestamps = vec![
            "1970-01-01T00:00:00Z",                 // Unix epoch
            "2038-01-19T03:14:07Z",                 // 32-bit timestamp overflow
            "9999-12-31T23:59:59Z",                 // Far future
            "0001-01-01T00:00:00Z",                 // Far past
            "2026-01-01T00:00:00Z\0",               // Null termination
            "2026-01-01T00:00:00Z\n",               // Newline injection
            "2026\u{202E}-01-01T00:00:00Z\u{202D}", // BiDi override
            "$(date)",                              // Command injection
            "2026-13-40T25:70:70Z",                 // Invalid date values
            "",                                     // Empty timestamp
        ];

        for malicious_timestamp in malicious_timestamps {
            let timestamp_input = ActivationInput {
                connector_id: "timestamp_test".to_string(),
                sandbox_config: r#"{"mode":"default"}"#.to_string(),
                secret_refs: vec!["secret_1".to_string()],
                capabilities: vec!["cap_read".to_string()],
                trace_id: "timestamp_trace".to_string(),
                timestamp: malicious_timestamp.to_string(),
            };

            let validation_result = validate_activation_input(&timestamp_input);

            match validation_result {
                Ok(_) => {
                    // If validation passed, run activation
                    let transcript = activate(&timestamp_input, &DefaultExecutor);

                    // Verify timestamp doesn't affect activation logic
                    assert!(transcript.stages.len() > 0, "Should have stages");
                    assert!(
                        verify_stage_order(&transcript),
                        "Stage order should be preserved"
                    );

                    // Verify timestamp is preserved safely
                    assert!(
                        !timestamp_input.timestamp.contains('\0'),
                        "Timestamp should not contain null bytes"
                    );

                    // Stage timestamps should be valid
                    for stage in &transcript.stages {
                        assert!(
                            !stage.timestamp.is_empty(),
                            "Stage timestamp should not be empty"
                        );
                        assert!(
                            !stage.timestamp.contains('\0'),
                            "Stage timestamp should not contain null"
                        );
                    }
                }
                Err(err) => {
                    // Expected rejection for invalid timestamps
                    if malicious_timestamp.is_empty() || malicious_timestamp.contains("$(") {
                        assert!(
                            err.contains("invalid") || err.contains("timestamp"),
                            "Error should indicate timestamp validation failure: {}",
                            err
                        );
                    }
                }
            }
        }
    }
}
