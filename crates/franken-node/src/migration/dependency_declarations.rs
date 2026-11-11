//! Effective npm declarations for captured project and installed-package checks.
//!
//! Root/workspace development dependencies are part of project validation. npm
//! selects them after optional, production and peer declarations. Published
//! dependencies do not install their own development tools. Validate losing
//! declarations too; precedence is not permission to hide malformed metadata.

use super::{
    DependencyAdmission, DependencyFinding, MAX_PACKAGES, alias, bounded_text, flag, graph, name,
    time_remaining,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Map, Value};
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
    *count = count
        .checked_add(1)
        .context("dependency declaration count overflow")?;
    ensure!(
        *count <= limit,
        "dependency declaration/peer metadata count exceeds limit"
    );
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
    ensure!(
        manifest.is_object(),
        "dependency manifest must be an object"
    );
    let peer_meta = manifest
        .get("peerDependenciesMeta")
        .map(|value| {
            value
                .as_object()
                .context("peerDependenciesMeta must be an object")
        })
        .transpose()?;
    if let Some(metadata) = peer_meta {
        for (installed_as, value) in metadata {
            account(count, limit, deadline)?;
            name(installed_as)?;
            flag(
                value
                    .as_object()
                    .context("peer dependency metadata must be an object")?,
                "optional",
            )?;
        }
    }
    let mut selected = BTreeMap::new();
    // Increasing precedence. Dev is deliberately last for project/workspace
    // roots: an optional declaration cannot make a required test tool optional.
    for field in [
        "peerDependencies",
        "dependencies",
        "optionalDependencies",
        "devDependencies",
    ] {
        if field == "devDependencies" && !project {
            continue;
        }
        let Some(value) = manifest.get(field) else {
            continue;
        };
        let declarations = value
            .as_object()
            .with_context(|| format!("{field} must be an object"))?;
        for (installed_as, request) in declarations {
            account(count, limit, deadline)?;
            name(installed_as)?;
            let request = bounded_text(request, "dependency request")?;
            let (package, requirement) = alias(installed_as, Some(request))?;
            let optional_peer = peer_meta
                .and_then(|metadata| metadata.get(installed_as))
                .and_then(|value| value.get("optional"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            selected.insert(
                installed_as.as_str(),
                Declaration {
                    section: field,
                    installed_as,
                    request,
                    package,
                    requirement,
                    optional: field == "optionalDependencies"
                        || (field == "peerDependencies" && optional_peer),
                },
            );
        }
    }
    time_remaining(deadline)?;
    Ok(selected.into_values().collect())
}

/// Captured root authority for scalar registry overrides, optionally selected
/// by the original dependency's version range.
/// npm and Bun retain their distinct selection contracts; both reuse the same
/// immutable authority for metadata AND actual installed edges. npm registry
/// aliases retain their replacement identity; contextual rules and nonregistry
/// replacement sources require review rather than partial application.
/// Contracts: docs.npmjs.com/cli/v11/configuring-npm/package-json/#overrides
///            bun.com/docs/pm/overrides
#[derive(Debug, Default, Clone, Serialize)]
pub(super) struct Overrides {
    rules: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    qualified: BTreeMap<String, Vec<QualifiedOverride>>,
    #[serde(skip)]
    has_qualified_replacements: bool,
    bun: bool,
}

#[derive(Debug, Clone, Serialize)]
struct QualifiedOverride {
    selector: String,
    replacement: Option<String>,
}

fn plain_override_name(key: &str) -> bool {
    name(key).is_ok()
        && key.trim_start_matches('@').split('/').all(|part| {
            part.as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn override_selector(key: &str) -> Option<(&str, Option<&str>)> {
    match key.rsplit_once('@') {
        Some((package, range)) if !package.is_empty() => {
            (plain_override_name(package) && !range.is_empty() && graph::supports_range(range))
                .then_some((package, Some(range)))
        }
        _ => plain_override_name(key).then_some((key, None)),
    }
}

fn selector_matches(package: &str, selector: &str, request: &str) -> Result<bool> {
    if selector == "*" {
        return Ok(true);
    }
    let (_, range) = alias(package, Some(request))?;
    // Arborist tests the original request first. node-semver's comparator
    // intersection is directional for exact prereleases versus ANY.
    graph::ranges_intersect(
        range.context("version-qualified override cannot verify an opaque dependency request")?,
        selector,
    )
    .context("version-qualified override requires bounded, verifiable registry ranges")
}

fn npm_registry_replacement(installed_as: &str, request: &str) -> bool {
    if !request.starts_with("npm:") {
        return graph::supports_range(request);
    }
    // An explicit npm alias is a registry fork, not an untyped source URL.
    // Keep the full request as authority so all three admission passes check
    // both the fork's identity and its range at the original lookup position.
    // An omitted range is a dist-tag lookup, never a captured version proof.
    alias(installed_as, Some(request))
        .ok()
        .is_some_and(|(package, range)| {
            plain_override_name(package) && range.is_some_and(graph::supports_range)
        })
}

impl Overrides {
    pub(super) fn capture(
        root: &Value,
        report: &mut DependencyAdmission,
        deadline: Instant,
    ) -> Result<Self> {
        time_remaining(deadline)?;
        let Some(value) = root.get("overrides") else {
            return Ok(Self::default());
        };
        let rules = value
            .as_object()
            .context("npm root overrides must be an object")?;
        if rules.is_empty() {
            return Ok(Self::default());
        }
        let mut count = 0;
        let direct: BTreeMap<_, _> = select(root, true, deadline, &mut count, MAX_PACKAGES)?
            .into_iter()
            .map(|edge| (edge.installed_as, edge.request))
            .collect();
        let mut selected = BTreeMap::new();
        let mut qualified: BTreeMap<String, Vec<QualifiedOverride>> = BTreeMap::new();
        let mut selectors: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut supported = true;
        for (key, value) in rules {
            account(&mut count, MAX_PACKAGES, deadline)?;
            ensure!(
                key.len() <= 4096 && !key.chars().any(char::is_control),
                "invalid or oversized npm override key"
            );
            let mut issue = None;
            let selector = override_selector(key);
            if selector.is_none() {
                issue = Some((
                    "unsupported_npm_override",
                    "Override keys must be package names with optional supported registry version ranges",
                ));
            }
            if let Some((package, range)) = selector {
                let range = range.unwrap_or("*");
                let preceding = selectors.entry(package).or_default();
                ensure!(
                    preceding.len() < 64,
                    "version-qualified override selectors per package exceed limit"
                );
                for previous in preceding.iter() {
                    account(&mut count, MAX_PACKAGES, deadline)?;
                    if graph::ranges_intersect(previous, range) != Some(false)
                        || graph::ranges_intersect(range, previous) != Some(false)
                    {
                        // Canonical metadata does not retain object insertion
                        // order. Never invent npm's first-rule precedence.
                        issue = Some((
                            "unsupported_npm_override",
                            "Overlapping same-name override selectors require insertion-order-aware review",
                        ));
                    }
                }
                preceding.push(range);
            }
            let mut effective = None;
            match value.as_str() {
                // npm treats literal * and the empty string as no replacement.
                // A $reference RESOLVING to * is different: it is an override.
                Some("" | "*") => {}
                Some(_) => {
                    let request = bounded_text(value, "npm override request")?;
                    let request = if let Some(reference) = request.strip_prefix('$') {
                        match direct.get(reference) {
                            Some(request) => Some(*request),
                            None => {
                                issue = Some((
                                    "unsupported_npm_override",
                                    "Override reference must name a captured root dependency; local-package reference fallback requires explicit review",
                                ));
                                None
                            }
                        }
                    } else {
                        Some(request)
                    };
                    if let Some(request) = request {
                        if selector
                            .is_some_and(|(package, _)| npm_registry_replacement(package, request))
                        {
                            effective = Some(request);
                        } else {
                            issue = Some((
                                "unsupported_npm_override",
                                "Override replacement must be a supported registry range or npm alias with an explicit supported range; tags, URLs, Git and workspace requests require explicit review",
                            ));
                        }
                    }
                }
                None => {
                    issue = Some((
                        "unsupported_npm_override",
                        "Nested or nonscalar npm override rules require explicit review",
                    ))
                }
            }
            if let (Some(request), Some((package, range))) = (effective, selector) {
                // npm's EOVERRIDE contract compares exact effective text,
                // not semantic range equivalence. Dev/optional precedence is
                // the same selection used for root $reference resolution.
                if let Some(raw) = direct.get(package) {
                    match range.map_or(Ok(true), |range| selector_matches(package, range, raw)) {
                        Ok(true) if *raw != request => {
                            issue = Some((
                                "conflicting_npm_override",
                                "EOVERRIDE: root direct dependency and selected override must use exactly the same request",
                            ));
                        }
                        Err(_) => {
                            issue = Some((
                                "unsupported_npm_override",
                                "Version-qualified override selection requires a bounded registry dependency request",
                            ));
                        }
                        _ => {}
                    }
                }
                if range.is_none() {
                    selected.insert(package.to_owned(), request.to_owned());
                }
            }
            if let Some((package, Some(range))) = selector {
                qualified
                    .entry(package.into())
                    .or_default()
                    .push(QualifiedOverride {
                        selector: range.into(),
                        replacement: effective.map(str::to_owned),
                    });
            }
            if let Some((code, detail)) = issue {
                supported = false;
                report.finding(DependencyFinding {
                    code: code.into(),
                    source: "package.json#overrides".into(),
                    package: key.clone(),
                    installed_as: key.clone(),
                    package_path: None,
                    version: value.as_str().map(str::to_owned),
                    detail: detail.into(),
                })?;
            }
        }
        time_remaining(deadline)?;
        Ok(if supported {
            Self {
                rules: selected,
                has_qualified_replacements: qualified
                    .values()
                    .flatten()
                    .any(|rule| rule.replacement.is_some()),
                qualified,
                ..Self::default()
            }
        } else {
            Self::default()
        })
    }

    /// Bun records either root field as canonical lockfile "overrides", while
    /// retaining the original dependency declarations. Validate every rule,
    /// including unused names, before admitting any replacement. The ordinary
    /// registry subset deliberately excludes references and contextual rules.
    pub(super) fn capture_bun(
        root: &Map<String, Value>,
        lock: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Self> {
        time_remaining(deadline)?;
        let empty = Map::new();
        // Presence wins, including an empty overrides object. The ignored
        // resolutions value is not an additional dependency authority.
        let selected = match root.get("overrides").or_else(|| root.get("resolutions")) {
            None => &empty,
            Some(value) => value
                .as_object()
                .context("Bun root overrides/resolutions must be an object")?,
        };
        let recorded = match lock.get("overrides") {
            None => &empty,
            Some(value) => value
                .as_object()
                .context("Bun lockfile overrides must be an object")?,
        };
        ensure!(
            lock.get("resolutions")
                .is_none_or(|value| value.as_object().is_some_and(Map::is_empty)),
            "Bun lockfile resolutions are not canonical override authority; explicit review is required"
        );
        let mut count = 0;
        for (source, rules) in [("package.json", selected), ("bun.lock", recorded)] {
            for (key, value) in rules {
                account(&mut count, MAX_PACKAGES, deadline)?;
                ensure!(
                    key.len() <= 4096 && plain_override_name(key),
                    "{source} Bun override keys must be unversioned package names; contextual and alias selectors require explicit review"
                );
                let request = bounded_text(value, "Bun override request")?;
                ensure!(
                    graph::supports_range(request),
                    "{source} Bun override replacements must be supported registry ranges; references, catalogs and replacement sources require explicit review"
                );
            }
        }
        ensure!(
            selected == recorded,
            "Bun overrides differ between captured package.json and bun.lock; stale lock requires review"
        );
        let mut rules = BTreeMap::new();
        for (key, value) in selected {
            time_remaining(deadline)?;
            rules.insert(
                key.clone(),
                bounded_text(value, "Bun override request")?.to_owned(),
            );
        }
        time_remaining(deadline)?;
        Ok(Self {
            rules,
            bun: true,
            ..Self::default()
        })
    }

    pub(super) fn replacement(&self, installed_as: &str, request: &str) -> Result<Option<&str>> {
        // Bun's plain-name rules do not replace versioned npm aliases. Alias
        // selectors and dist-tag alias rules remain outside this bounded set;
        // their original requests still undergo the ordinary range checks.
        if self.bun && request.starts_with("npm:") {
            return Ok(None);
        }
        if let Some(replacement) = self.rules.get(installed_as) {
            return Ok(Some(replacement));
        }
        let mut selected = None;
        for rule in self.qualified.get(installed_as).into_iter().flatten() {
            if selector_matches(installed_as, &rule.selector, request)? {
                // Even disjoint selectors may intersect a broad declaration.
                // Without original key order this is deliberately unresolved.
                ensure!(
                    selected.is_none(),
                    "dependency request intersects multiple version-qualified override selectors; explicit review required"
                );
                selected = Some(rule);
            }
        }
        Ok(selected.and_then(|rule| rule.replacement.as_deref()))
    }

    pub(super) fn apply<'a>(&'a self, installed_as: &str, request: &'a str) -> Result<&'a str> {
        Ok(self.replacement(installed_as, request)?.unwrap_or(request))
    }

    pub(super) fn is_empty(&self) -> bool {
        self.rules.is_empty() && !self.has_qualified_replacements
    }

    pub(super) fn review_workspace(
        &self,
        manifest: &Value,
        directory: &str,
        report: &mut DependencyAdmission,
    ) -> Result<()> {
        let record = manifest
            .as_object()
            .context("workspace manifest must be an object")?;
        self.review_context(
            record,
            &format!("{directory}/package.json"),
            Some(directory),
            report,
        )?;
        if !self.bun
            && let Some(package) = record.get("name").and_then(Value::as_str)
            && self
                .qualified
                .get(package)
                .is_some_and(|rules| rules.iter().any(|rule| rule.replacement.is_some()))
        {
            report.finding(DependencyFinding {
                code: "unsupported_npm_override_context".into(), source: "package.json#overrides".into(),
                package: package.into(), installed_as: package.into(),
                package_path: Some(directory.into()), version: None,
                detail: "Version-qualified registry overrides cannot establish authority over a direct workspace file: edge".into(),
            })?;
        }
        if !self.bun
            && let Some(package) = record.get("name").and_then(Value::as_str)
            && let Some(request) = self.rules.get(package)
        {
            // npm adds a direct file: edge for every selected workspace,
            // superseding even an explicit registry declaration of that name.
            // A global scalar registry replacement therefore violates the
            // root EOVERRIDE rule even when the workspace has no dependencies.
            report.finding(DependencyFinding {
                code: "conflicting_npm_override".into(), source: "package.json#overrides".into(),
                package: package.into(), installed_as: package.into(),
                package_path: Some(directory.into()), version: Some(request.clone()),
                detail: "EOVERRIDE: selected workspaces have direct file: edges that cannot be replaced by a root registry override".into(),
            })?;
        }
        Ok(())
    }

    /// npm excludes bundled and nested-shrinkwrapped trees from ordinary
    /// override application. Their context-sensitive rules are not inferred.
    pub(super) fn review_context(
        &self,
        record: &Map<String, Value>,
        source: &str,
        path: Option<&str>,
        report: &mut DependencyAdmission,
    ) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let mut excluded = false;
        for field in ["inBundle", "bundled", "hasShrinkwrap"] {
            excluded |= flag(record, field)?;
        }
        for field in ["bundleDependencies", "bundledDependencies"] {
            excluded |= match record.get(field) {
                None | Some(Value::Bool(false)) => false,
                Some(Value::Array(packages)) => !packages.is_empty(),
                Some(_) => true,
            };
        }
        if excluded {
            report.finding(DependencyFinding {
                code: "unsupported_npm_override_context".into(), source: source.into(),
                package: record.get("name").and_then(Value::as_str).unwrap_or_default().into(),
                installed_as: String::new(), package_path: path.map(str::to_owned),
                version: record.get("version").and_then(Value::as_str).map(str::to_owned),
                detail: "Root overrides with bundled or nested-shrinkwrapped dependencies require explicit review; their exclusion context is not approximated".into(),
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "dependency_declarations_tests.rs"]
mod tests;
