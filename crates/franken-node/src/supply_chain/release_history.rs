//! Behaviour drift across a package's own releases, read from its npm
//! packument (bd-reality-20260923-26n9r.15 deliverable 3).
//!
//! `trust scan --deep` already fetches the packument, which records every
//! published version's manifest. This module turns the releases leading up
//! to the version a project resolves into a BPET trajectory over the
//! install-time and execution surface a consumer actually vetted:
//!
//! * `install_scripts`: `preinstall` / `install` / `postinstall` hooks
//!   (code that runs on `npm install`);
//! * `native_build`: a node-gyp / prebuild native build step;
//! * `bin_entries`: executables the package installs;
//! * `runtime_dependencies`: the `dependencies` it pulls in.
//!
//! The oldest release of the window is the declared baseline. Each feature is
//! a monotone high-water mark normalized to that baseline (a release that
//! drops a capability is not drift towards risk), weighted so install-time
//! code execution dominates dependency growth. The window is then scored by
//! the camouflage detector's phase-shift and gradual-creep sub-detectors
//! with a configuration calibrated on real packuments. Windows stay inside
//! the resolved version's major line (a 4.x maintenance release published
//! after 5.0 is not drift of 5.x). Over every 6-release window of 20 widely
//! used packages (express, react, webpack, eslint, esbuild, sharp, ws, …;
//! 2,921 windows) 0.31% reached severity 0.5 and 0.17% reached 0.67; all but
//! one were releases that introduced an install script or a native build.
//! Version size and file counts are deliberately not features: ordinary
//! libraries grow.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::security::bpet::camouflage_detector::{
    DetectorConfig, DetectorError, detect_gradual_creep, detect_phase_shift,
};
use crate::security::trajectory_gaming::{
    CamouflageHint, TrajectorySample, TrajectorySeries, append_sample,
};

/// Releases scored per window (ending at the resolved version).
pub const RELEASE_WINDOW: usize = 6;
/// Fewer stable releases than this are not scored.
pub const MIN_RELEASES: usize = 4;
/// Upper bound on versions read from one packument.
pub const MAX_VERSIONS_READ: usize = 20_000;

const LIFECYCLE_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Feature weights: install-time code execution dominates.
const FEATURES: [(&str, f64, f64); 4] = [
    // (name, weight, baseline floor)
    ("install_scripts", 4.0, 1.0),
    ("native_build", 2.0, 1.0),
    ("bin_entries", 0.5, 1.0),
    ("runtime_dependencies", 0.5, 4.0),
];

/// The detector configuration calibrated for release histories.
#[must_use]
pub fn release_history_detector_config() -> DetectorConfig {
    DetectorConfig {
        phase_shift_threshold: 1.0,
        creep_slope_threshold: 0.3,
        min_samples_for_detection: MIN_RELEASES,
        window_size: 3,
        ..DetectorConfig::default()
    }
}

/// Hint severity at or above which drift raises a card's risk, per profile.
/// A raised card is High risk (Critical at 0.9), which `strict` refuses at
/// run preflight; weaker findings are reported by the scan only.
#[must_use]
pub const fn risk_bump_severity(profile: crate::config::Profile) -> f64 {
    match profile {
        crate::config::Profile::Strict => 0.5,
        crate::config::Profile::Balanced => 0.67,
        crate::config::Profile::LegacyRisky => 0.9,
    }
}

/// The execution surface one release declares in its manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseCapabilities {
    pub version: String,
    pub published_at: String,
    pub install_scripts: u32,
    pub native_build: bool,
    pub bin_entries: u32,
    pub runtime_dependencies: u32,
}

impl ReleaseCapabilities {
    fn feature(&self, name: &str) -> f64 {
        match name {
            "install_scripts" => f64::from(self.install_scripts),
            "native_build" => f64::from(u8::from(self.native_build)),
            "bin_entries" => f64::from(self.bin_entries),
            _ => f64::from(self.runtime_dependencies),
        }
    }
}

/// Result of scoring one package's recent release history.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReleaseHistoryAssessment {
    /// The scored releases, oldest (the baseline) first.
    pub releases: Vec<ReleaseCapabilities>,
    #[serde(skip)]
    pub hints: Vec<CamouflageHint>,
    pub max_severity: f64,
    /// Human-readable drift lines, e.g. `install_scripts 0 -> 1 by 2.3.0`.
    pub changes: Vec<String>,
}

fn u32_len(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

fn release_capabilities(
    version: &str,
    published_at: &str,
    manifest: &Value,
) -> ReleaseCapabilities {
    let scripts = manifest.get("scripts").and_then(Value::as_object);
    let lifecycle: Vec<&str> = LIFECYCLE_SCRIPTS
        .iter()
        .filter_map(|name| {
            scripts
                .and_then(|scripts| scripts.get(*name))
                .and_then(Value::as_str)
                .filter(|command| !command.trim().is_empty())
        })
        .collect();
    let native_build = manifest.get("gypfile").and_then(Value::as_bool) == Some(true)
        || lifecycle
            .iter()
            .any(|command| command.contains("node-gyp") || command.contains("prebuild"));
    let bin_entries = match manifest.get("bin") {
        Some(Value::String(path)) if !path.is_empty() => 1,
        Some(Value::Object(entries)) => u32_len(entries.len()),
        _ => 0,
    };
    let runtime_dependencies = manifest
        .get("dependencies")
        .and_then(Value::as_object)
        .map_or(0, |dependencies| u32_len(dependencies.len()));
    ReleaseCapabilities {
        version: version.to_string(),
        published_at: published_at.to_string(),
        install_scripts: u32_len(lifecycle.len()),
        native_build,
        bin_entries,
        runtime_dependencies,
    }
}

/// `MAJOR.MINOR.PATCH` with no pre-release or build suffix.
fn is_stable_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 9 && part.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Stable releases of `version`'s major line published at or before it,
/// oldest first, ending with `version` itself (at most `RELEASE_WINDOW`).
/// Empty when the packument does not record `version` as a stable release
/// with a publish time.
#[must_use]
pub fn release_window(packument: &Value, version: &str) -> Vec<ReleaseCapabilities> {
    let (Some(versions), Some(times)) = (
        packument.get("versions").and_then(Value::as_object),
        packument.get("time").and_then(Value::as_object),
    ) else {
        return Vec::new();
    };
    let published = |candidate: &str| {
        times
            .get(candidate)
            .and_then(Value::as_str)
            .and_then(|stamp| {
                chrono::DateTime::parse_from_rfc3339(stamp)
                    .ok()
                    .map(|at| (at, stamp))
            })
    };
    let Some((target_at, _)) = published(version).filter(|_| is_stable_version(version)) else {
        return Vec::new();
    };
    let major = |candidate: &str| candidate.split('.').next().map(str::to_owned);
    let target_major = major(version);
    let mut releases: Vec<(chrono::DateTime<chrono::FixedOffset>, ReleaseCapabilities)> = versions
        .iter()
        .take(MAX_VERSIONS_READ)
        .filter(|(candidate, _)| is_stable_version(candidate) && major(candidate) == target_major)
        .filter_map(|(candidate, manifest)| {
            let (at, stamp) = published(candidate)?;
            (at <= target_at).then(|| (at, release_capabilities(candidate, stamp, manifest)))
        })
        .collect();
    releases.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.version.cmp(&right.1.version))
    });
    let start = releases.len().saturating_sub(RELEASE_WINDOW);
    releases.drain(..start);
    if releases.last().map(|(_, release)| release.version.as_str()) != Some(version) {
        return Vec::new();
    }
    releases.into_iter().map(|(_, release)| release).collect()
}

/// Score the window: baseline-normalized, monotone, weighted features fed to
/// the phase-shift and gradual-creep detectors.
pub fn assess_release_window(
    releases: Vec<ReleaseCapabilities>,
) -> Result<Option<ReleaseHistoryAssessment>, DetectorError> {
    if releases.len() < MIN_RELEASES {
        return Ok(None);
    }
    let baseline = releases[0].clone();
    let mut high_water: BTreeMap<&str, f64> = FEATURES
        .iter()
        .map(|(name, _, _)| (*name, baseline.feature(name)))
        .collect();
    let mut series = TrajectorySeries::new(0, i64::try_from(releases.len()).unwrap_or(i64::MAX))
        .map_err(|_| DetectorError::InvalidConfig)?;
    let mut changes = Vec::new();
    for (index, release) in releases.iter().enumerate() {
        let mut observed = BTreeMap::new();
        let mut declared = BTreeMap::new();
        for (name, weight, floor) in FEATURES {
            let value = release.feature(name);
            let mark = high_water.get(name).copied().unwrap_or(0.0);
            if value > mark {
                changes.push(format!(
                    "{name} {} -> {} by {}",
                    mark, value, release.version
                ));
                high_water.insert(name, value);
            }
            let scale = baseline.feature(name).max(floor);
            observed.insert(name.to_string(), weight * high_water[name] / scale);
            declared.insert(name.to_string(), weight);
        }
        let sample =
            TrajectorySample::new(i64::try_from(index).unwrap_or(i64::MAX), observed, declared)
                .map_err(|_| DetectorError::InvalidConfig)?;
        append_sample(&mut series, sample).map_err(|_| DetectorError::InvalidConfig)?;
    }
    let config = release_history_detector_config();
    let mut hints = detect_phase_shift(&series, &config)?;
    // Creep towards *more* surface only; a shrinking package is not drift.
    hints.extend(
        detect_gradual_creep(&series, &config)?
            .into_iter()
            .filter(|hint| hint.evidence.get("slope").is_some_and(|slope| *slope > 0.0)),
    );
    let max_severity = hints.iter().map(|hint| hint.severity).fold(0.0, f64::max);
    Ok(Some(ReleaseHistoryAssessment {
        releases,
        hints,
        max_severity,
        changes,
    }))
}

/// Score the releases leading up to `version` in `packument`.
pub fn assess_release_history(
    packument: &Value,
    version: &str,
) -> Result<Option<ReleaseHistoryAssessment>, DetectorError> {
    assess_release_window(release_window(packument, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packument(releases: &[(&str, Value)]) -> Value {
        let mut versions = serde_json::Map::new();
        let mut time = serde_json::Map::new();
        for (index, (version, manifest)) in releases.iter().enumerate() {
            versions.insert((*version).to_string(), manifest.clone());
            time.insert(
                (*version).to_string(),
                Value::String(format!("2026-0{}-01T00:00:00.000Z", index + 1)),
            );
        }
        serde_json::json!({ "versions": versions, "time": time })
    }

    #[test]
    fn a_new_install_hook_is_high_severity_drift() {
        let quiet = serde_json::json!({"dependencies": {"a": "1"}});
        let hooked = serde_json::json!({
            "dependencies": {"a": "1", "b": "1"},
            "scripts": {"postinstall": "node ./setup.js"}
        });
        let doc = packument(&[
            ("1.0.0", quiet.clone()),
            ("1.1.0", quiet.clone()),
            ("1.2.0", quiet.clone()),
            ("1.3.0", hooked.clone()),
            ("1.4.0", hooked.clone()),
            ("1.5.0", hooked),
        ]);
        let assessment = assess_release_history(&doc, "1.5.0")
            .expect("detector")
            .expect("enough releases");
        assert!(assessment.max_severity >= 0.5, "{assessment:?}");
        assert!(
            assessment
                .changes
                .iter()
                .any(|change| change.starts_with("install_scripts 0 -> 1 by 1.3.0"))
        );
    }

    #[test]
    fn stable_or_shrinking_histories_stay_quiet() {
        let wide = serde_json::json!({
            "dependencies": {"a": "1", "b": "1", "c": "1", "d": "1", "e": "1"},
            "scripts": {"postinstall": "node-gyp rebuild"}, "gypfile": true
        });
        let narrow = serde_json::json!({"dependencies": {"a": "1", "b": "1", "c": "1", "d": "1", "e": "1", "f": "1"}});
        let doc = packument(&[
            ("2.0.0", wide.clone()),
            ("2.1.0", wide.clone()),
            ("2.2.0", wide),
            ("2.3.0", narrow.clone()),
            ("2.4.0", narrow.clone()),
            ("2.5.0", narrow),
        ]);
        let assessment = assess_release_history(&doc, "2.5.0")
            .expect("detector")
            .expect("enough releases");
        assert!(assessment.max_severity < 0.5, "{assessment:?}");
    }

    #[test]
    fn windows_end_at_the_resolved_stable_version() {
        let manifest = serde_json::json!({});
        let doc = packument(&[
            ("1.0.0", manifest.clone()),
            ("1.1.0-beta.1", manifest.clone()),
            ("1.1.0", manifest.clone()),
            ("1.2.0", manifest),
        ]);
        let window = release_window(&doc, "1.1.0");
        assert_eq!(
            window
                .iter()
                .map(|release| release.version.as_str())
                .collect::<Vec<_>>(),
            ["1.0.0", "1.1.0"]
        );
        assert!(release_window(&doc, "9.9.9").is_empty());
        assert!(release_window(&doc, "1.1.0-beta.1").is_empty());
        assert!(
            assess_release_history(&doc, "1.1.0")
                .expect("detector")
                .is_none()
        );
    }
}
