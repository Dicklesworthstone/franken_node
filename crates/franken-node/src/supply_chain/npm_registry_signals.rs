//! Supply-chain signals derived from an npm registry packument (the JSON
//! document at `https://registry.npmjs.org/<name>`), used by
//! `trust scan --deep` (bd-reality-20260923-26n9r.15 / .14).
//!
//! Only what the packument states is used: when the package name was first
//! published, when any version was last published, and how many maintainers
//! are listed. Maintainer fragility is scored with the DGIS fragility model
//! (`dgis::fragility_model`) over the factors observed here. Signals npm does
//! not expose (key recovery, download share, commit history) are never
//! guessed, so they never contribute a factor.

use serde_json::Value;

use crate::dgis::fragility_model::{
    FragilityFactor, FragilityScore, SOLE_MAINTAINER_BUS_FACTOR, STALE_MAINTAINER_DAYS,
};

/// A package whose name was first published fewer than this many days ago is
/// reported as new: the window in which typosquats and hijack re-publishes
/// are most often caught by the ecosystem.
pub const NEW_PACKAGE_DAYS: u64 = 30;

const SECONDS_PER_DAY: u64 = 86_400;

/// Raw facts read from a packument.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrySignals {
    /// `time.created`: first publication of the package name (RFC 3339).
    pub package_created_at: Option<String>,
    /// Latest publish time across versions (`time` entries other than the
    /// `created` / `modified` bookkeeping keys).
    pub last_published_at: Option<String>,
    /// Number of entries in the top-level `maintainers` array.
    pub maintainer_count: Option<usize>,
}

/// Read the signals from a packument. Missing or malformed fields stay `None`.
#[must_use]
pub fn parse_registry_signals(packument: &Value) -> RegistrySignals {
    let times = packument.get("time").and_then(Value::as_object);
    let package_created_at = times
        .and_then(|times| times.get("created"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let last_published_at = times.and_then(|times| {
        times
            .iter()
            .filter(|(key, _)| key.as_str() != "created" && key.as_str() != "modified")
            .filter_map(|(_, value)| value.as_str())
            .filter_map(|value| parse_epoch_secs(value).map(|secs| (secs, value)))
            .max_by_key(|(secs, _)| *secs)
            .map(|(_, value)| value.to_string())
    });
    let maintainer_count = packument
        .get("maintainers")
        .and_then(Value::as_array)
        .map(Vec::len);
    RegistrySignals {
        package_created_at,
        last_published_at,
        maintainer_count,
    }
}

/// What the signals mean for a trust card.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryFindings {
    /// Days since first publication, present only when below
    /// [`NEW_PACKAGE_DAYS`].
    pub new_package_age_days: Option<u64>,
    /// DGIS fragility over the observed maintainer factors.
    pub fragility: FragilityScore,
}

impl RegistryFindings {
    /// Human-readable findings for the trust-card summary (empty when none).
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let mut findings = Vec::new();
        if let Some(days) = self.new_package_age_days {
            findings.push(format!(
                "new package: first published {days} day(s) ago on the npm registry"
            ));
        }
        if self.fragility.is_fragile() {
            let factors = self
                .fragility
                .factors
                .iter()
                .map(|factor| match factor {
                    FragilityFactor::StaleMaintainer { staleness_days } => {
                        format!("stale_maintainer (no publish in {staleness_days} days)")
                    }
                    other => other.label().to_string(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(format!(
                "maintainer fragility {:.2} (DGIS): {factors}",
                self.fragility.total
            ));
        }
        findings
    }
}

/// Assess the signals at `now_secs` (Unix seconds).
#[must_use]
pub fn assess_registry_signals(signals: &RegistrySignals, now_secs: u64) -> RegistryFindings {
    let new_package_age_days = signals
        .package_created_at
        .as_deref()
        .and_then(|created| days_since(created, now_secs))
        .filter(|days| *days < NEW_PACKAGE_DAYS);

    let mut factors = Vec::new();
    match signals.maintainer_count {
        Some(0) => factors.push(FragilityFactor::OrphanedPackage),
        Some(count) if count <= usize::from(SOLE_MAINTAINER_BUS_FACTOR) => {
            factors.push(FragilityFactor::SingleMaintainer);
        }
        _ => {}
    }
    // A publish is the maintainer activity the registry shows.
    if let Some(days) = signals
        .last_published_at
        .as_deref()
        .and_then(|published| days_since(published, now_secs))
        && days > u64::from(STALE_MAINTAINER_DAYS)
    {
        factors.push(FragilityFactor::StaleMaintainer {
            staleness_days: u32::try_from(days).unwrap_or(u32::MAX),
        });
    }

    RegistryFindings {
        new_package_age_days,
        fragility: FragilityScore::from_factors(
            factors,
            i64::try_from(now_secs).unwrap_or(i64::MAX),
        ),
    }
}

fn parse_epoch_secs(rfc3339: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .ok()
        .map(|timestamp| timestamp.timestamp())
}

/// Whole days from `rfc3339` to `now_secs`; `None` if unparseable, 0 if the
/// timestamp is in the future (clock skew never produces a negative age).
fn days_since(rfc3339: &str, now_secs: u64) -> Option<u64> {
    let then = parse_epoch_secs(rfc3339)?;
    let now = i64::try_from(now_secs).unwrap_or(i64::MAX);
    let elapsed = u64::try_from(now.saturating_sub(then)).unwrap_or(0);
    Some(elapsed / SECONDS_PER_DAY)
}
