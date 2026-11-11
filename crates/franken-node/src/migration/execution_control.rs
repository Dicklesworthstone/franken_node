//! Operator containment retained across private staging and capsule execution.
//!
//! Origins are local execution context, never serialized input authority. A
//! capsule is governed by its current storage scope, not historical pathnames
//! supplied by its payload. Controller decoding and live state reads use the
//! same production safe-mode implementation as ordinary native runs. In
//! engine-enabled product builds, reference execution also checks the protected
//! native fleet admission fences; engine-free tools retain safe-mode-only scope.

use super::{EntryData, Snapshot};
use crate::runtime::safe_mode::{
    AdmittedSafeModeProject, AdmittedSafeModeScope, MAX_SAFE_MODE_STATE_BYTES, SafeModeController,
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub(super) enum Origin {
    Project(PathBuf),
    Capsule(PathBuf),
}

enum Scope {
    Project(AdmittedSafeModeProject),
    Capsule(AdmittedSafeModeScope),
}

pub(super) struct ExecutionControl {
    scopes: Vec<Scope>,
}

impl ExecutionControl {
    /// Check every role before the first guest, then retain those exact scopes
    /// for polling. Read-only capture/inspection does not acquire this permit.
    pub(super) fn admit(snapshots: &[&Snapshot]) -> Result<Self> {
        let mut projects = BTreeSet::new();
        let mut capsules = BTreeSet::new();
        for snapshot in snapshots {
            let tests = snapshot.tests()?;
            check_captured_controllers(snapshot, &tests)?;
            match &snapshot.origin {
                Some(Origin::Project(root)) => {
                    projects.insert(root.clone());
                    for test in &tests {
                        if let Some(parent) = test.parent() {
                            projects.insert(root.join(parent));
                        }
                    }
                }
                Some(Origin::Capsule(path)) => {
                    capsules.insert(path.clone());
                }
                None => {}
            }
        }
        let mut scopes = Vec::new();
        for root in projects {
            let scope = AdmittedSafeModeProject::capture(&root)?;
            ensure!(
                scope.root() == root,
                "migration source scope moved or became an alias before execution"
            );
            scopes.push(Scope::Project(scope));
        }
        for path in capsules {
            scopes.push(Scope::Capsule(AdmittedSafeModeScope::capture(&path)?));
        }
        let control = Self { scopes };
        control.enforce()?;
        Ok(control)
    }

    pub(super) fn enforce(&self) -> Result<()> {
        for scope in &self.scopes {
            match scope {
                Scope::Project(scope) => scope.enforce_reference_execution()?,
                Scope::Capsule(scope) => scope.enforce_reference_execution()?,
            }
        }
        Ok(())
    }
}

fn check_captured_controllers(snapshot: &Snapshot, tests: &[PathBuf]) -> Result<()> {
    let mut scopes = BTreeSet::from([PathBuf::new()]);
    for test in tests {
        if let Some(parent) = test.parent() {
            scopes.extend(parent.ancestors().map(Path::to_path_buf));
        }
    }
    for scope in scopes {
        let metadata = scope.join(".franken-node");
        let controller = metadata.join("safe-mode");
        let mut present = true;
        for directory in [&metadata, &controller] {
            match snapshot.entries.get(directory) {
                None => {
                    present = false;
                    break;
                }
                Some(entry) => ensure!(
                    matches!(entry.data, EntryData::Directory),
                    "captured safe-mode container must be an ordinary directory: {}",
                    directory.display()
                ),
            }
        }
        if !present {
            continue;
        }
        let state = controller.join("state.json");
        if let Some(entry) = snapshot.entries.get(&state) {
            let EntryData::File(bytes) = &entry.data else {
                anyhow::bail!(
                    "captured safe-mode state must be a regular file: {}",
                    state.display()
                );
            };
            ensure!(
                bytes.len() as u64 <= MAX_SAFE_MODE_STATE_BYTES,
                "captured safe-mode state exceeds the operator controller limit"
            );
            let controller: SafeModeController = serde_json::from_slice(bytes)
                .with_context(|| format!("invalid captured safe-mode state {}", state.display()))?;
            ensure!(
                !controller.is_active(),
                "migration execution blocked by active captured safe mode at {}; recover and review new inputs",
                state.display()
            );
        }
    }
    Ok(())
}
