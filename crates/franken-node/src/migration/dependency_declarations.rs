//! Effective npm declarations for captured project and installed-package checks.
//!
//! Root/workspace development dependencies are part of project validation. npm
//! selects them after optional, production and peer declarations. Published
//! dependencies do not install their own development tools. Validate losing
//! declarations too; precedence is not permission to hide malformed metadata.

use super::{alias, bounded_text, flag, name, time_remaining};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Declaration<'a> {
    pub section: &'static str,
    pub installed_as: &'a str,
    pub request: &'a str,
    pub package: &'a str,
    pub requirement: Option<&'a str>,
    pub optional: bool,
}

fn account(count: &mut usize, limit: usize, deadline: Instant) -> Result<()> {
    time_remaining(deadline)?;
    *count = count.checked_add(1).context("dependency declaration count overflow")?;
    ensure!(*count <= limit, "dependency declaration/peer metadata count exceeds limit");
    Ok(())
}

/// Select one effective edge per installation name without changing a manifest.
/// Returned strings borrow the captured metadata. Count all examined entries,
/// including superseded declarations and unattached peer metadata. No partially
/// validated selection is returned after a parse, deadline or budget failure.
pub(super) fn select<'a>(
    manifest: &'a Value,
    project: bool,
    deadline: Instant,
    count: &mut usize,
    limit: usize,
) -> Result<Vec<Declaration<'a>>> {
    time_remaining(deadline)?;
    ensure!(manifest.is_object(), "dependency manifest must be an object");
    let peer_meta = manifest.get("peerDependenciesMeta")
        .map(|value| value.as_object().context("peerDependenciesMeta must be an object"))
        .transpose()?;
    if let Some(metadata) = peer_meta {
        for (installed_as, value) in metadata {
            account(count, limit, deadline)?;
            name(installed_as)?;
            flag(value.as_object().context("peer dependency metadata must be an object")?, "optional")?;
        }
    }
    let mut selected = BTreeMap::new();
    // Increasing precedence. Dev is deliberately last for project/workspace
    // roots: an optional declaration cannot make a required test tool optional.
    for field in ["peerDependencies", "dependencies", "optionalDependencies", "devDependencies"] {
        if field == "devDependencies" && !project { continue; }
        let Some(value) = manifest.get(field) else { continue; };
        let declarations = value.as_object().with_context(|| format!("{field} must be an object"))?;
        for (installed_as, request) in declarations {
            account(count, limit, deadline)?;
            name(installed_as)?;
            let request = bounded_text(request, "dependency request")?;
            let (package, requirement) = alias(installed_as, Some(request))?;
            let optional_peer = peer_meta.and_then(|metadata| metadata.get(installed_as))
                .and_then(|value| value.get("optional"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            selected.insert(installed_as.as_str(), Declaration {
                section: field,
                installed_as,
                request,
                package,
                requirement,
                optional: field == "optionalDependencies"
                    || (field == "peerDependencies" && optional_peer),
            });
        }
    }
    time_remaining(deadline)?;
    Ok(selected.into_values().collect())
}

#[cfg(test)]
#[path = "dependency_declarations_tests.rs"]
mod tests;
