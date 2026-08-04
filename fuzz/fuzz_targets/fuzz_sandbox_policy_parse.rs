#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::security::sandbox_policy_compiler::{
    compile_policy, validate_policy, AccessLevel, CapabilityGrant, CompiledPolicy,
    ProfileAuditRecord, ProfileTracker, SandboxError, SandboxProfile, CAPABILITIES,
};
use libfuzzer_sys::fuzz_target;
use serde::{de::DeserializeOwned, Serialize};

const MAX_RAW_JSON_BYTES: usize = 256 * 1024;
const MAX_TEXT_CHARS: usize = 256;
const MAX_GRANTS: usize = 64;
const MAX_CHANGES: usize = 64;

fuzz_target!(|input: SandboxPolicyParseInput| {
    fuzz_raw_json(&input.raw_json);
    fuzz_profile_name(&input.profile_name);
    fuzz_structured_policy(&input);
    fuzz_profile_tracker(&input);
});

fn fuzz_raw_json(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_JSON_BYTES {
        return;
    }

    let _ = serde_json::from_slice::<serde_json::Value>(bytes);
    if let Ok(profile) = serde_json::from_slice::<SandboxProfile>(bytes) {
        assert_profile_roundtrip(profile);
    }
    if let Ok(access) = serde_json::from_slice::<AccessLevel>(bytes) {
        json_roundtrip(&access);
    }
    if let Ok(grant) = serde_json::from_slice::<CapabilityGrant>(bytes) {
        json_roundtrip(&grant);
    }
    if let Ok(policy) = serde_json::from_slice::<CompiledPolicy>(bytes) {
        json_roundtrip(&policy);
        let _ = validate_policy(&policy);
    }
    if let Ok(tracker) = serde_json::from_slice::<ProfileTracker>(bytes) {
        tracker_json_roundtrip(&tracker);
        let _ = validate_policy(&tracker.compiled_policy);
        let access = tracker.is_capability_allowed("network_access");
        json_roundtrip(&access);
    }
    if let Ok(error) = serde_json::from_slice::<SandboxError>(bytes) {
        json_roundtrip(&error);
        let rendered = error.to_string();
        assert!(!rendered.is_empty());
    }
}

fn fuzz_profile_name(raw: &str) {
    let name = bounded_text(raw, "strict");
    if let Ok(profile) = SandboxProfile::parse(&name) {
        assert_eq!(profile.as_str(), name);
        assert_profile_roundtrip(profile);
    }
}

fn fuzz_structured_policy(input: &SandboxPolicyParseInput) {
    let profile = input.profile.into_profile();
    let compiled = compile_policy(profile);
    validate_policy(&compiled).expect("compiled sandbox policy must validate");
    assert_eq!(compiled.profile, profile);
    assert_eq!(compiled.level, profile.level());
    assert_eq!(compiled.grants.len(), CAPABILITIES.len());
    json_roundtrip(&compiled);

    let mut mutated = compiled.clone();
    for grant in input.grants.iter().take(MAX_GRANTS) {
        mutated.grants.push(CapabilityGrant {
            capability: grant.capability_name(),
            access: grant.access.into_access_level(),
        });
    }
    json_roundtrip(&mutated);
    let _ = validate_policy(&mutated);
}

fn fuzz_profile_tracker(input: &SandboxPolicyParseInput) {
    let connector_id = bounded_text(&input.connector_id, "connector-fuzz");
    let mut tracker = ProfileTracker::new(connector_id.clone(), input.profile.into_profile());
    assert_eq!(tracker.connector_id, connector_id);
    assert_eq!(
        tracker.compiled_policy,
        compile_policy(tracker.current_profile)
    );
    validate_policy(&tracker.compiled_policy).expect("initial tracker policy must validate");
    tracker_json_roundtrip(&tracker);

    for (index, change) in input.changes.iter().take(MAX_CHANGES).enumerate() {
        let before_profile = tracker.current_profile;
        let before_policy = tracker.compiled_policy.clone();
        let before_len = tracker.audit_log.len();
        let target = change.profile.into_profile();
        let reason = bounded_text(&change.reason, "fuzz profile change");
        let timestamp = bounded_text(&change.timestamp, "2026-04-22T00:00:00Z");
        let result = tracker.change_profile(
            target,
            reason.clone(),
            timestamp.clone(),
            change.allow_downgrade,
        );

        if reason.trim().is_empty() || timestamp.trim().is_empty() {
            assert!(matches!(result, Err(SandboxError::CompileError { .. })));
            assert_eq!(tracker.current_profile, before_profile);
            assert_eq!(tracker.compiled_policy, before_policy);
            assert_eq!(tracker.audit_log.len(), before_len);
            continue;
        }

        // bd-4sh1w: `change_profile` no longer expresses relaxation at all — the
        // authority-granting direction has its own entry point. A relaxing target
        // must be refused here whatever `allow_downgrade` says, and the tracker
        // must be untouched.
        if before_profile.is_relaxation_to(&target) {
            assert!(matches!(result, Err(SandboxError::RelaxationBlocked { .. })));
            assert_eq!(tracker.current_profile, before_profile);
            assert_eq!(tracker.compiled_policy, before_policy);
            assert_eq!(tracker.audit_log.len(), before_len);

            // The dedicated entry point accepts exactly the same transition.
            let relaxed = tracker
                .relax_profile(target, reason.clone(), timestamp.clone())
                .expect("relax_profile must accept a relaxing target");
            assert_eq!(tracker.current_profile, target);
            assert_eq!(tracker.compiled_policy, compile_policy(target));
            validate_policy(&tracker.compiled_policy)
                .expect("relaxed tracker policy must validate");
            assert_eq!(relaxed.old_profile, Some(before_profile));
            assert_eq!(relaxed.new_profile, target);
        } else if before_profile.is_downgrade_to(&target) && !change.allow_downgrade {
            assert!(matches!(result, Err(SandboxError::DowngradeBlocked { .. })));
            assert_eq!(tracker.current_profile, before_profile);
            assert_eq!(tracker.compiled_policy, before_policy);
            assert_eq!(tracker.audit_log.len(), before_len);
        } else {
            let audit = result.expect("non-downgrade or allowed downgrade must change profile");
            assert_eq!(tracker.current_profile, target);
            assert_eq!(tracker.compiled_policy, compile_policy(target));
            validate_policy(&tracker.compiled_policy)
                .expect("changed tracker policy must validate");
            assert_eq!(audit.connector_id, tracker.connector_id);
            assert_eq!(audit.old_profile, Some(before_profile));
            assert_eq!(audit.new_profile, target);
            assert!(tracker.audit_log.len() >= before_len);
        }

        if index % 8 == 0 {
            tracker_json_roundtrip(&tracker);
        }
    }
}

fn assert_profile_roundtrip(profile: SandboxProfile) {
    json_roundtrip(&profile);
    assert_eq!(SandboxProfile::parse(profile.as_str()), Ok(profile));
    assert_eq!(compile_policy(profile).profile, profile);
}

fn json_roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug,
{
    let encoded = serde_json::to_vec(value).expect("sandbox policy JSON encode");
    let decoded: T = serde_json::from_slice(&encoded).expect("sandbox policy JSON decode");
    assert_eq!(&decoded, value);
}

fn tracker_json_roundtrip(value: &ProfileTracker) {
    let encoded = serde_json::to_vec(value).expect("sandbox tracker JSON encode");
    let decoded: ProfileTracker =
        serde_json::from_slice(&encoded).expect("sandbox tracker JSON decode");
    assert_eq!(decoded.connector_id, value.connector_id);
    assert_eq!(decoded.current_profile, value.current_profile);
    assert_eq!(decoded.compiled_policy, value.compiled_policy);
    assert_eq!(decoded.audit_log, value.audit_log);
}

fn bounded_text(raw: &str, fallback: &str) -> String {
    let text = raw.chars().take(MAX_TEXT_CHARS).collect::<String>();
    if text.trim().is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

#[derive(Debug, Arbitrary)]
struct SandboxPolicyParseInput {
    raw_json: Vec<u8>,
    profile_name: String,
    connector_id: String,
    profile: FuzzProfile,
    grants: Vec<FuzzGrant>,
    changes: Vec<FuzzChange>,
}

#[derive(Debug, Arbitrary)]
struct FuzzGrant {
    capability: FuzzCapability,
    custom_capability: String,
    access: FuzzAccessLevel,
}

impl FuzzGrant {
    fn capability_name(&self) -> String {
        match self.capability {
            FuzzCapability::Standard(selector) => {
                CAPABILITIES[usize::from(selector) % CAPABILITIES.len()].to_string()
            }
            FuzzCapability::Custom => bounded_text(&self.custom_capability, "custom_capability"),
            FuzzCapability::Empty => String::new(),
            FuzzCapability::Padded => {
                format!(" {} ", bounded_text(&self.custom_capability, "fs_read"))
            }
        }
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzChange {
    profile: FuzzProfile,
    reason: String,
    timestamp: String,
    allow_downgrade: bool,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzProfile {
    Strict,
    StrictPlus,
    Moderate,
    Permissive,
}

impl FuzzProfile {
    fn into_profile(self) -> SandboxProfile {
        match self {
            Self::Strict => SandboxProfile::Strict,
            Self::StrictPlus => SandboxProfile::StrictPlus,
            Self::Moderate => SandboxProfile::Moderate,
            Self::Permissive => SandboxProfile::Permissive,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzAccessLevel {
    Deny,
    Scoped,
    Filtered,
    Allow,
}

impl FuzzAccessLevel {
    fn into_access_level(self) -> AccessLevel {
        match self {
            Self::Deny => AccessLevel::Deny,
            Self::Scoped => AccessLevel::Scoped,
            Self::Filtered => AccessLevel::Filtered,
            Self::Allow => AccessLevel::Allow,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzCapability {
    Standard(u8),
    Custom,
    Empty,
    Padded,
}

#[allow(dead_code)]
fn _assert_public_serde_types(_: ProfileAuditRecord) {}
