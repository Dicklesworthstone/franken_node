//! Exercise the real signed store and controller, including process exits.
//! Child-only environment configuration avoids unsafe global env mutation.

use super::*;
use super::super::{RolloutConfig, RolloutManager, RolloutStage, RolloutState, RolloutStatus, RolloutTransitionEvent};
use ed25519_dalek::SigningKey;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::{Command, Output};

const ANCHOR: &str = ".franken-node/keys/migration-rollout.pub";
const STATE: &str = "mig-signed.json";

fn key() -> SigningKey { SigningKey::from_bytes(&[17;32]) }
fn provision(project: &Path) {
    fs::create_dir_all(project.join(".franken-node/keys")).unwrap();
    fs::write(project.join(ANCHOR), hex::encode(key().verifying_key().to_bytes())).unwrap();
}
fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    provision(&project);
    let secret = root.path().join("operator.seed");
    fs::write(&secret, [17;32]).unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    (root, project, secret)
}
fn initial(project: &Path) -> RolloutState {
    RolloutState::new("mig-signed".into(), project.to_str().unwrap().into())
}
fn encoded(state: &RolloutState) -> Vec<u8> { serde_json::to_vec_pretty(state).unwrap() }
fn location(project: &Path, name: &str) -> PathBuf { project.join(".franken-node/state/rollout").join(name) }
fn read_state(project: &Path, id: &str) -> RolloutState {
    let store = Store::open_with_key(project, None, None).unwrap();
    serde_json::from_slice(&store.read(&format!("{id}.json")).unwrap().unwrap()).unwrap()
}
fn chain(project: &Path, id: &str) -> receipt::ChainVerification {
    let name = format!("{id}.json");
    let raw = fs::read(location(project, &name)).unwrap();
    receipt::verify_chain(&raw, &key().verifying_key(), project.to_str().unwrap(), &name,
        Some(&receipt::sha256(&raw)), |hash| Ok(fs::read(location(project, &receipt::receipt_name(hash)?))?)).unwrap()
}

#[test]
fn signed_store_extends_full_state_and_preserves_exact_predecessors() {
    let (_root, project, secret) = fixture();
    let store = Store::open_with_key(&project, Some(&secret), None).unwrap();
    let mut state = initial(&project);
    store.write(STATE, &encoded(&state)).unwrap();
    let first = store.read_raw(STATE).unwrap().unwrap();
    assert_eq!(store.read(STATE).unwrap().unwrap(), encoded(&state));
    state.confidence_score = 0.7;
    store.write(STATE, &encoded(&state)).unwrap();
    let second = store.read_raw(STATE).unwrap().unwrap();
    let checked = receipt::verify(&second, &key().verifying_key(), project.to_str().unwrap(), STATE).unwrap();
    assert_eq!(checked.revision(), 2);
    assert_eq!(checked.previous_sha256(), Some(receipt::sha256(&first).as_str()));
    assert_eq!(fs::read(location(&project, &receipt::receipt_name(&receipt::sha256(&first)).unwrap())).unwrap(), first);
    assert_eq!(chain(&project, "mig-signed").receipts_verified, 2);
    store.write(STATE, &encoded(&state)).unwrap();
    assert_eq!(store.read_raw(STATE).unwrap().unwrap(), second); // no new revision for a no-op
    assert_eq!(fs::metadata(location(&project, STATE)).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn public_only_inspection_cannot_start_an_unsigned_write_or_initialization() {
    let (_root, project, secret) = fixture();
    let state = initial(&project);
    let read_only = Store::open_with_key(&project, None, None).unwrap();
    assert!(read_only.write(STATE, &encoded(&state)).unwrap_err().to_string().contains(SIGNING_KEY_ENV));
    assert!(!location(&project, STATE).exists());
    drop(read_only);
    Store::open_with_key(&project, Some(&secret), None).unwrap().write(STATE, &encoded(&state)).unwrap();
    let read_only = Store::open_with_key(&project, None, None).unwrap();
    assert_eq!(read_only.read(STATE).unwrap().unwrap(), encoded(&state));
    let before = fs::read(location(&project, STATE)).unwrap();
    let mut changed = state;
    changed.confidence_score = 0.6;
    assert!(read_only.write(STATE, &encoded(&changed)).is_err());
    assert_eq!(fs::read(location(&project, STATE)).unwrap(), before);
}

#[test]
fn forged_history_binding_confidence_and_completion_fail_before_interpretation() {
    let (_root, project, secret) = fixture();
    Store::open_with_key(&project, Some(&secret), None).unwrap().write(STATE, &encoded(&initial(&project))).unwrap();
    let before = fs::read(location(&project, STATE)).unwrap();
    for mutation in 0..5 {
        let mut envelope: serde_json::Value = serde_json::from_slice(&before).unwrap();
        let mut state: serde_json::Value = serde_json::from_str(envelope["state_json"].as_str().unwrap()).unwrap();
        match mutation {
            0 => state["confidence_score"] = 0.01.into(),
            1 => state["history"] = serde_json::json!([{"action":"fabricated"}]),
            2 => state["rollback_journal_sha256"] = "a".repeat(64).into(),
            3 => { state["current_stage"] = "default".into(); state["status"] = "completed".into(); }
            4 => state["updated_at"] = "fabricated timestamp".into(),
            _ => unreachable!(),
        }
        envelope["state_json"] = serde_json::to_string(&state).unwrap().into();
        fs::write(location(&project, STATE), serde_json::to_vec(&envelope).unwrap()).unwrap();
        let store = Store::open_with_key(&project, Some(&secret), None).unwrap();
        assert!(store.read(STATE).unwrap_err().to_string().contains("signature verification failed"));
        assert!(store.write(STATE, &encoded(&initial(&project))).is_err());
    }
}

#[test]
fn removing_rotating_or_late_installing_authority_never_downgrades_state() {
    let (root, project, secret) = fixture();
    Store::open_with_key(&project, Some(&secret), None).unwrap().write(STATE, &encoded(&initial(&project))).unwrap();
    let before = fs::read(location(&project, STATE)).unwrap();
    fs::rename(project.join(ANCHOR), root.path().join("retained.pub")).unwrap();
    {
        let store = Store::open_with_key(&project, None, None).unwrap();
        assert!(store.read(STATE).is_err());
        assert!(store.write(STATE, &encoded(&initial(&project))).is_err());
    }
    fs::write(project.join(ANCHOR), hex::encode(SigningKey::from_bytes(&[18;32]).verifying_key().to_bytes())).unwrap();
    assert!(Store::open_with_key(&project, Some(&secret), None).is_err());
    assert!(Store::open_with_key(&project, None, None).unwrap().read(STATE).is_err());
    assert_eq!(fs::read(location(&project, STATE)).unwrap(), before);

    let legacy = tempfile::tempdir().unwrap();
    let store = Store::open_with_key(legacy.path(), None, None).unwrap();
    let plain = encoded(&initial(legacy.path()));
    store.write(STATE, &plain).unwrap();
    provision(legacy.path());
    assert!(store.write(STATE, &plain).unwrap_err().to_string().contains("authority changed"));
    drop(store);
    assert!(Store::open_with_key(legacy.path(), None, None).unwrap().read(STATE).is_err());
    assert_eq!(fs::read(location(legacy.path(), STATE)).unwrap(), plain); // not silently adopted
}

#[test]
fn operator_key_permissions_location_aliases_and_ownership_are_admitted_before_writes() {
    for mutation in 0..5 {
        let (root, project, secret) = fixture();
        let selected = match mutation {
            0 => { fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap(); secret.clone() }
            1 => { let alias = root.path().join("alias"); symlink(&secret, &alias).unwrap(); alias }
            2 => { fs::hard_link(&secret, root.path().join("shared-key")).unwrap(); secret.clone() }
            3 => { let leaked = project.join("seed"); fs::write(&leaked, [17;32]).unwrap(); leaked }
            4 => { fs::write(&secret, [18;32]).unwrap(); secret.clone() }
            _ => unreachable!(),
        };
        assert!(Store::open_with_key(&project, Some(&selected), None).is_err(), "{mutation}");
        assert!(!location(&project, STATE).exists());
    }
}

#[test]
fn signed_state_cannot_be_transplanted_between_migrations_or_projects() {
    let (_root, project, secret) = fixture();
    Store::open_with_key(&project, Some(&secret), None).unwrap().write(STATE, &encoded(&initial(&project))).unwrap();
    let raw = fs::read(location(&project, STATE)).unwrap();
    let (_other, other, _) = fixture();
    let store = Store::open_with_key(&other, None, None).unwrap();
    fs::write(location(&other, STATE), &raw).unwrap();
    assert!(store.read(STATE).is_err());
    fs::write(location(&project, "mig-other.json"), raw).unwrap();
    assert!(Store::open_with_key(&project, None, None).unwrap().read("mig-other.json").is_err());
}

#[test]
fn independent_checkpoint_and_locked_observation_reject_authentic_replays() {
    let (_root, project, secret) = fixture();
    let mut state = initial(&project);
    let store = Store::open_with_key(&project, Some(&secret), None).unwrap();
    store.write(STATE, &encoded(&state)).unwrap();
    let old = store.read_raw(STATE).unwrap().unwrap();
    state.confidence_score = 0.7;
    store.write(STATE, &encoded(&state)).unwrap();
    let new = store.read_raw(STATE).unwrap().unwrap();
    drop(store);
    {
        let pinned = Store::open_with_key(&project, None, Some(&receipt::sha256(&old))).unwrap();
        assert!(pinned.read(STATE).unwrap_err().to_string().contains("checkpoint"));
    }
    let pinned = Store::open_with_key(&project, Some(&secret), Some(&receipt::sha256(&new))).unwrap();
    assert!(pinned.read(STATE).is_ok());
    fs::write(location(&project, STATE), old).unwrap();
    state.confidence_score = 0.8;
    assert!(pinned.write(STATE, &encoded(&state)).unwrap_err().to_string().contains("head changed"));
}

#[test]
fn receipt_archive_conflicts_block_publication_without_replacing_evidence() {
    let (_root, project, secret) = fixture();
    let store = Store::open_with_key(&project, Some(&secret), None).unwrap();
    let mut state = initial(&project);
    store.write(STATE, &encoded(&state)).unwrap();
    let before = store.read_raw(STATE).unwrap().unwrap();
    state.confidence_score = 0.7;
    let next = store.signing.seal(STATE, &encoded(&state), Some(&before)).unwrap();
    let archive = location(&project, &receipt::receipt_name(&receipt::sha256(&next)).unwrap());
    fs::write(&archive, b"preserve conflicting recovery material").unwrap();
    assert!(store.write(STATE, &encoded(&state)).unwrap_err().to_string().contains("refusing to overwrite"));
    assert_eq!(fs::read(location(&project, STATE)).unwrap(), before);
    assert_eq!(fs::read(archive).unwrap(), b"preserve conflicting recovery material");
}

const CHILD_ACTION: &str = "FRANKEN_TEST_SIGNED_ROLLOUT_ACTION";
const CHILD_PROJECT: &str = "FRANKEN_TEST_SIGNED_ROLLOUT_PROJECT";
const CHILD_ID: &str = "FRANKEN_TEST_SIGNED_ROLLOUT_ID";

fn child(project: &Path, id: &str, secret: Option<&Path>, action: &str) -> Output {
    child_at(project, id, secret, action, None)
}
fn child_at(project: &Path, id: &str, secret: Option<&Path>, action: &str, checkpoint: Option<&str>) -> Output {
    let path = module_path!().split_once("::").unwrap().1;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", &format!("{path}::controller_action_child"), "--nocapture"])
        .env(CHILD_ACTION, action).env(CHILD_PROJECT, project).env(CHILD_ID, id)
        .env_remove(SIGNING_KEY_ENV).env_remove(EXPECTED_HEAD_ENV);
    if let Some(secret) = secret { command.env(SIGNING_KEY_ENV, secret); }
    if let Some(checkpoint) = checkpoint { command.env(EXPECTED_HEAD_ENV, checkpoint); }
    command.output().unwrap()
}
fn succeeds(output: Output) { assert!(output.status.success(), "{output:?}"); }

#[test]
fn controller_action_child() {
    let Ok(action) = std::env::var(CHILD_ACTION) else { return; };
    let project = PathBuf::from(std::env::var_os(CHILD_PROJECT).unwrap());
    let id = std::env::var(CHILD_ID).unwrap();
    let manager = RolloutManager::new(&project, Some(&id));
    let result: Result<(), String> = (|| {
        match action.as_str() {
            "init" => { manager.load_or_init().map_err(|e| e.to_string())?; }
            "status" => { manager.status().map_err(|e| e.to_string())?; }
            "promote" => { manager.promote(&RolloutConfig { force: true, ..RolloutConfig::default() }, None, None)?; }
            "rollback" => { manager.rollback("operator-approved signed recovery")?; }
            "confidence" => {
                let mut state = manager.load_or_init().map_err(|e| e.to_string())?;
                state.confidence_score = 0.7;
                manager.persist(&state).map_err(|e| e.to_string())?;
            }
            "archive_crash" => {
                let store = manager.open_store().map_err(|e| e.to_string())?;
                let mut state = manager.load_or_init_locked(&store).map_err(|e| e.to_string())?;
                let name = format!("{id}.json");
                let before = store.read_raw(&name).map_err(|e| e.to_string())?.unwrap();
                state.confidence_score = 0.7;
                let raw = store.signing.seal(&name, &encoded(&state), Some(&before)).map_err(|e| e.to_string())?;
                store.archive(&raw).map_err(|e| e.to_string())?;
                std::process::exit(73); // after durable receipt, before head publication
            }
            "intent_crash" | "restored_crash" => {
                let store = manager.open_store().map_err(|e| e.to_string())?;
                let mut state = manager.load_or_init_locked(&store).map_err(|e| e.to_string())?;
                let event = RolloutTransitionEvent { from_stage: state.current_stage,
                    to_stage: RolloutStage::Aborted, action: "rollback_started".into(),
                    reason: "signed crash fixture".into(), timestamp_utc: state.updated_at.clone(),
                    confidence_score: state.confidence_score, ramp_pct: 0, receipt_signature: Some(state.digest()) };
                state.current_stage = RolloutStage::Aborted;
                state.status = RolloutStatus::Failed;
                state.ramp_pct = 0;
                state.lockstep_verified = false;
                state.validation_confidence = None;
                state.history.push(event);
                manager.persist_locked(&store, &state).map_err(|e| e.to_string())?;
                if action == "restored_crash" { manager.restore_bound_source(&state)?; }
                std::process::exit(73); // exact production persistence, no completion receipt
            }
            _ => return Err("unknown child action".into()),
        }
        Ok(())
    })();
    match result {
        Ok(()) => std::process::exit(0),
        Err(error) => { eprintln!("{error}"); std::process::exit(79); }
    }
}

fn applied() -> (tempfile::TempDir, PathBuf, PathBuf, String) {
    use super::super::super::rewrite_transaction::{Edit, RewriteTransaction};
    use super::super::super::rollback;
    let (root, project, secret) = fixture();
    fs::write(project.join("app.js"), b"original").unwrap();
    RewriteTransaction::open(&project).unwrap().apply(&[
        Edit { path: "app.js", before: b"original", after: b"candidate" }
    ]).unwrap();
    let history = rollback::run(&project, None, false);
    let id = history.history[0].transaction_id.clone();
    (root, project, secret, id)
}

#[test]
fn actual_controller_signs_initialization_promotion_intent_and_source_restoration() {
    let (_root, project, secret, id) = applied();
    succeeds(child(&project, &id, Some(&secret), "init"));
    succeeds(child(&project, &id, Some(&secret), "promote"));
    succeeds(child(&project, &id, None, "status"));
    let before = fs::read(location(&project, &format!("{id}.json"))).unwrap();
    assert_eq!(child(&project, &id, None, "rollback").status.code(), Some(79));
    assert_eq!(fs::read(project.join("app.js")).unwrap(), b"candidate");
    assert_eq!(fs::read(location(&project, &format!("{id}.json"))).unwrap(), before);
    succeeds(child_at(&project, &id, Some(&secret), "rollback", Some(&receipt::sha256(&before))));
    assert_eq!(fs::read(project.join("app.js")).unwrap(), b"original");
    let state = read_state(&project, &id);
    assert_eq!(state.status, RolloutStatus::RolledBack);
    assert_eq!(state.history.len(), 3);
    assert_eq!(chain(&project, &id).receipts_verified, 4);
}

#[test]
fn signed_intent_survives_process_exit_and_missing_signer_never_fakes_completion() {
    for crash in ["intent_crash", "restored_crash"] {
        let (_root, project, secret, id) = applied();
        succeeds(child(&project, &id, Some(&secret), "init"));
        assert_eq!(child(&project, &id, Some(&secret), crash).status.code(), Some(73));
        let intent = fs::read(location(&project, &format!("{id}.json"))).unwrap();
        assert_eq!(read_state(&project, &id).status, RolloutStatus::Failed);
        // An already signed intent authorizes this exact recovery. Resumption
        // can restore sources without a key, but cannot publish completion.
        assert_eq!(child(&project, &id, None, "rollback").status.code(), Some(79));
        assert_eq!(fs::read(project.join("app.js")).unwrap(), b"original");
        assert_eq!(fs::read(location(&project, &format!("{id}.json"))).unwrap(), intent);
        fs::write(project.join("app.js"), b"later user work").unwrap();
        succeeds(child(&project, &id, Some(&secret), "rollback"));
        assert_eq!(fs::read(project.join("app.js")).unwrap(), b"later user work");
        assert_eq!(read_state(&project, &id).status, RolloutStatus::RolledBack);
        assert_eq!(chain(&project, &id).receipts_verified, 3);
    }
}

#[test]
fn orphaned_signed_receipt_is_not_a_committed_transition_and_retry_reuses_it() {
    let (_root, project, secret) = fixture();
    let id = "mig-signed";
    succeeds(child(&project, id, Some(&secret), "init"));
    let before = fs::read(location(&project, STATE)).unwrap();
    assert_eq!(child(&project, id, Some(&secret), "archive_crash").status.code(), Some(73));
    assert_eq!(fs::read(location(&project, STATE)).unwrap(), before);
    assert_eq!(read_state(&project, id).confidence_score, 1.0);
    succeeds(child(&project, id, Some(&secret), "confidence"));
    assert_eq!(read_state(&project, id).confidence_score, 0.7);
    assert_eq!(chain(&project, id).receipts_verified, 2);
    let archives = fs::read_dir(location(&project, "")).unwrap().filter(|e|
        e.as_ref().unwrap().file_name().to_string_lossy().starts_with(".signed-")).count();
    assert_eq!(archives, 2);
}

#[test]
fn tampered_health_cannot_trigger_controller_source_restoration() {
    let (_root, project, secret, id) = applied();
    succeeds(child(&project, &id, Some(&secret), "init"));
    let path = location(&project, &format!("{id}.json"));
    let mut envelope: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut state: serde_json::Value = serde_json::from_str(envelope["state_json"].as_str().unwrap()).unwrap();
    state["confidence_score"] = 0.01.into();
    envelope["state_json"] = serde_json::to_string(&state).unwrap().into();
    let changed = serde_json::to_vec(&envelope).unwrap();
    fs::write(&path, &changed).unwrap();
    for action in ["status", "promote", "rollback"] {
        let output = child(&project, &id, Some(&secret), action);
        assert_eq!(output.status.code(), Some(79));
        assert!(String::from_utf8_lossy(&output.stderr).contains("signature verification failed"));
        assert_eq!(fs::read(project.join("app.js")).unwrap(), b"candidate");
        assert_eq!(fs::read(&path).unwrap(), changed);
    }
}

#[test]
fn linked_public_authority_never_becomes_an_unsigned_fallback() {
    for parent_link in [false, true] {
        let (root, project, _) = fixture();
        if parent_link {
            let retained = root.path().join("retained-keys");
            fs::rename(project.join(".franken-node/keys"), &retained).unwrap();
            symlink(&retained, project.join(".franken-node/keys")).unwrap();
        } else {
            let retained = root.path().join("retained-key");
            fs::rename(project.join(ANCHOR), &retained).unwrap();
            symlink(&retained, project.join(ANCHOR)).unwrap();
        }
        assert!(Store::open_with_key(&project, None, None).is_err());
        assert!(!location(&project, STATE).exists());
    }
}
