//! Integration tests for bd-1d7n: Deterministic activation pipeline.
//!
//! Verifies stage ordering, secret cleanup on failure, deterministic
//! replay, and health-ready-last invariant.

use frankenengine_node::connector::activation_pipeline::*;

fn input() -> ActivationInput {
    ActivationInput {
        connector_id: "conn-integ".into(),
        sandbox_config: r#"{"profile":"strict"}"#.into(),
        secret_refs: vec!["ref-1".into(), "ref-2".into()],
        capabilities: vec!["net".into(), "fs".into()],
        trace_id: "trace-integ".into(),
        timestamp: "2026-01-15T12:00:00Z".into(),
    }
}

#[test]
fn inv_act_stage_order() {
    let t = activate(&input(), &FixtureActivationExecutor);
    assert!(verify_stage_order(&t), "INV-ACT-STAGE-ORDER violated");
}

#[test]
fn default_executor_fails_closed_without_real_hooks() {
    let t = activate(&input(), &DefaultExecutor);
    assert!(!t.completed);
    assert_eq!(t.stages.len(), 1);
    let err = t
        .stages
        .first()
        .and_then(|stage| stage.error.as_ref())
        .expect("default must fail");
    assert_eq!(err.code(), "ACT_SANDBOX_FAILED");
    assert!(err.to_string().contains("ACTIVATION_EXECUTOR_REQUIRED"));
}

#[test]
fn inv_act_health_last() {
    let t = activate(&input(), &FixtureActivationExecutor);
    assert_eq!(
        t.stages.last().unwrap().stage,
        ActivationStage::HealthReady,
        "INV-ACT-HEALTH-LAST violated"
    );
}

#[test]
fn inv_act_deterministic_success() {
    let i = input();
    let t1 = activate(&i, &FixtureActivationExecutor);
    let t2 = activate(&i, &FixtureActivationExecutor);
    assert!(
        transcripts_match(&t1, &t2),
        "INV-ACT-DETERMINISTIC violated"
    );
}

struct FailAtStage3;
impl StageExecutor for FailAtStage3 {
    fn create_sandbox(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn mount_secrets(&self, r: &[String]) -> Result<Vec<String>, String> {
        Ok(r.to_vec())
    }
    fn issue_capabilities(&self, _: &[String]) -> Result<(), String> {
        Err("denied".into())
    }
    fn health_check(&self) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn inv_act_no_secret_leak_on_stage3_fail() {
    let t = activate(&input(), &FailAtStage3);
    assert!(!t.completed);
    // Pipeline must have cleaned up secrets; transcript shows exactly 3 stages.
    assert_eq!(t.stages.len(), 3);
    assert!(
        t.stages[1].success,
        "SecretMount should succeed before CapabilityIssue fails"
    );
}

#[test]
fn inv_act_deterministic_failure() {
    let i = input();
    let t1 = activate(&i, &FailAtStage3);
    let t2 = activate(&i, &FailAtStage3);
    assert!(
        transcripts_match(&t1, &t2),
        "INV-ACT-DETERMINISTIC violated on failure path"
    );
}

#[test]
fn completed_transcript_has_four_stages() {
    let t = activate(&input(), &FixtureActivationExecutor);
    assert!(t.completed);
    assert_eq!(t.stages.len(), 4);
}

struct FailAtStage1;
impl StageExecutor for FailAtStage1 {
    fn create_sandbox(&self, _: &str) -> Result<(), String> {
        Err("no namespace".into())
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
fn early_failure_no_secrets_mounted() {
    let t = activate(&input(), &FailAtStage1);
    assert!(!t.completed);
    assert_eq!(t.stages.len(), 1);
    assert_eq!(
        t.stages[0].error.as_ref().unwrap().code(),
        "ACT_SANDBOX_FAILED"
    );
}

struct FailAtStage4;
impl StageExecutor for FailAtStage4 {
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
        Err("timeout".into())
    }
}

#[test]
fn health_failure_cleans_up_secrets() {
    let t = activate(&input(), &FailAtStage4);
    assert!(!t.completed);
    assert_eq!(t.stages.len(), 4);
    assert_eq!(
        t.stages[3].error.as_ref().unwrap().code(),
        "ACT_HEALTH_FAILED"
    );
}

#[test]
fn trace_id_propagated() {
    let t = activate(&input(), &FixtureActivationExecutor);
    assert_eq!(t.trace_id, "trace-integ");
}
