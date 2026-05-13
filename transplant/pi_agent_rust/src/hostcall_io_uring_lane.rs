//! Deterministic io_uring lane policy for hostcall dispatch.
//!
//! This module intentionally models policy decisions only. It does not perform
//! syscalls or ring operations directly; integration code can consume the
//! decisions and wire them into runtime-specific execution paths.

use serde::{Deserialize, Serialize};

/// Dispatch lane selected for a hostcall attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostcallDispatchLane {
    Fast,
    IoUring,
    Compat,
}

impl HostcallDispatchLane {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::IoUring => "io_uring",
            Self::Compat => "compat",
        }
    }
}

/// Optional signal indicating whether a hostcall is likely IO-dominant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostcallIoHint {
    Unknown,
    IoHeavy,
    CpuBound,
}

impl HostcallIoHint {
    #[must_use]
    pub const fn is_io_heavy(self) -> bool {
        matches!(self, Self::IoHeavy)
    }
}

/// Normalized capability classes used by lane policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostcallCapabilityClass {
    Filesystem,
    Network,
    Execution,
    Session,
    Events,
    Environment,
    Tool,
    Ui,
    Telemetry,
    Unknown,
}

impl HostcallCapabilityClass {
    #[must_use]
    pub fn from_capability(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "read" | "write" | "filesystem" | "fs" => Self::Filesystem,
            "http" | "network" => Self::Network,
            "exec" | "execution" => Self::Execution,
            "session" => Self::Session,
            "events" => Self::Events,
            "env" | "environment" => Self::Environment,
            "tool" => Self::Tool,
            "ui" => Self::Ui,
            "log" | "telemetry" => Self::Telemetry,
            _ => Self::Unknown,
        }
    }
}

/// Explicit fallback reason when io_uring is not selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoUringFallbackReason {
    CompatKillSwitch,
    IoUringDisabled,
    IoUringUnavailable,
    MissingIoHint,
    UnsupportedCapability,
    QueueDepthBudgetExceeded,
}

impl IoUringFallbackReason {
    #[must_use]
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::CompatKillSwitch => "forced_compat_kill_switch",
            Self::IoUringDisabled => "io_uring_disabled",
            Self::IoUringUnavailable => "io_uring_unavailable",
            Self::MissingIoHint => "io_hint_missing",
            Self::UnsupportedCapability => "io_uring_capability_not_supported",
            Self::QueueDepthBudgetExceeded => "io_uring_queue_depth_budget_exceeded",
        }
    }
}

/// Runtime-tunable policy knobs for io_uring lane selection.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoUringLanePolicyConfig {
    pub enabled: bool,
    pub ring_available: bool,
    pub max_queue_depth: usize,
    pub allow_filesystem: bool,
    pub allow_network: bool,
}

impl IoUringLanePolicyConfig {
    /// Conservative profile suitable for production defaults.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            enabled: false,
            ring_available: false,
            max_queue_depth: 256,
            allow_filesystem: true,
            allow_network: true,
        }
    }

    #[must_use]
    pub const fn allow_for_capability(self, capability: HostcallCapabilityClass) -> bool {
        match capability {
            HostcallCapabilityClass::Filesystem => self.allow_filesystem,
            HostcallCapabilityClass::Network => self.allow_network,
            _ => false,
        }
    }
}

impl Default for IoUringLanePolicyConfig {
    fn default() -> Self {
        Self::conservative()
    }
}

/// Inputs consumed by [`decide_io_uring_lane`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoUringLaneDecisionInput {
    pub capability: HostcallCapabilityClass,
    pub io_hint: HostcallIoHint,
    pub queue_depth: usize,
    pub force_compat_lane: bool,
}

/// Deterministic lane decision output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoUringLaneDecision {
    pub lane: HostcallDispatchLane,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<IoUringFallbackReason>,
}

impl IoUringLaneDecision {
    #[must_use]
    pub const fn io_uring() -> Self {
        Self {
            lane: HostcallDispatchLane::IoUring,
            fallback_reason: None,
        }
    }

    #[must_use]
    pub const fn compat(reason: IoUringFallbackReason) -> Self {
        Self {
            lane: HostcallDispatchLane::Compat,
            fallback_reason: Some(reason),
        }
    }

    #[must_use]
    pub const fn fast(reason: IoUringFallbackReason) -> Self {
        Self {
            lane: HostcallDispatchLane::Fast,
            fallback_reason: Some(reason),
        }
    }

    #[must_use]
    pub fn fallback_code(self) -> Option<&'static str> {
        self.fallback_reason.map(IoUringFallbackReason::as_code)
    }
}

/// Deterministic telemetry envelope for lane decision auditing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct IoUringLaneTelemetry {
    pub lane: HostcallDispatchLane,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<IoUringFallbackReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_code: Option<String>,
    pub capability: HostcallCapabilityClass,
    pub io_hint: HostcallIoHint,
    pub queue_depth: usize,
    pub queue_depth_budget: usize,
    pub queue_depth_budget_remaining: usize,
    pub force_compat_lane: bool,
    pub policy_enabled: bool,
    pub ring_available: bool,
    pub capability_allowed: bool,
    pub queue_depth_within_budget: bool,
}

/// Build deterministic telemetry for a lane decision.
#[must_use]
pub fn build_io_uring_lane_telemetry(
    config: IoUringLanePolicyConfig,
    input: IoUringLaneDecisionInput,
    decision: IoUringLaneDecision,
) -> IoUringLaneTelemetry {
    let capability_allowed = config.allow_for_capability(input.capability);
    let queue_depth_within_budget = input.queue_depth < config.max_queue_depth;
    let queue_depth_budget_remaining = config.max_queue_depth.saturating_sub(input.queue_depth);
    IoUringLaneTelemetry {
        lane: decision.lane,
        fallback_reason: decision.fallback_reason,
        fallback_code: decision.fallback_code().map(ToString::to_string),
        capability: input.capability,
        io_hint: input.io_hint,
        queue_depth: input.queue_depth,
        queue_depth_budget: config.max_queue_depth,
        queue_depth_budget_remaining,
        force_compat_lane: input.force_compat_lane,
        policy_enabled: config.enabled,
        ring_available: config.ring_available,
        capability_allowed,
        queue_depth_within_budget,
    }
}

/// Decide lane and produce deterministic telemetry in one call.
#[must_use]
pub fn decide_io_uring_lane_with_telemetry(
    config: IoUringLanePolicyConfig,
    input: IoUringLaneDecisionInput,
) -> (IoUringLaneDecision, IoUringLaneTelemetry) {
    let decision = decide_io_uring_lane(config, input);
    let telemetry = build_io_uring_lane_telemetry(config, input, decision);
    (decision, telemetry)
}

/// Decide whether the hostcall should run via the io_uring lane.
///
/// Decision ordering is intentionally strict and deterministic:
/// 1) explicit compatibility kill-switch
/// 2) policy enabled flag
/// 3) ring availability
/// 4) IO-heavy hint presence
/// 5) capability allowlist
/// 6) queue depth budget
#[must_use]
pub const fn decide_io_uring_lane(
    config: IoUringLanePolicyConfig,
    input: IoUringLaneDecisionInput,
) -> IoUringLaneDecision {
    if input.force_compat_lane {
        return IoUringLaneDecision::compat(IoUringFallbackReason::CompatKillSwitch);
    }
    if !config.enabled {
        return IoUringLaneDecision::fast(IoUringFallbackReason::IoUringDisabled);
    }
    if !config.ring_available {
        return IoUringLaneDecision::fast(IoUringFallbackReason::IoUringUnavailable);
    }
    if !input.io_hint.is_io_heavy() {
        return IoUringLaneDecision::fast(IoUringFallbackReason::MissingIoHint);
    }
    if !config.allow_for_capability(input.capability) {
        return IoUringLaneDecision::fast(IoUringFallbackReason::UnsupportedCapability);
    }
    if input.queue_depth >= config.max_queue_depth {
        return IoUringLaneDecision::fast(IoUringFallbackReason::QueueDepthBudgetExceeded);
    }
    IoUringLaneDecision::io_uring()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> IoUringLanePolicyConfig {
        IoUringLanePolicyConfig {
            enabled: true,
            ring_available: true,
            max_queue_depth: 8,
            allow_filesystem: true,
            allow_network: true,
        }
    }

    #[test]
    fn capability_aliases_map_to_expected_classes() {
        assert_eq!(
            HostcallCapabilityClass::from_capability("read"),
            HostcallCapabilityClass::Filesystem
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("http"),
            HostcallCapabilityClass::Network
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("session"),
            HostcallCapabilityClass::Session
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("unknown-cap"),
            HostcallCapabilityClass::Unknown
        );
    }

    #[test]
    fn selects_io_uring_for_io_heavy_allowed_capability_with_budget_headroom() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Network,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 3,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::IoUring);
        assert!(decision.fallback_reason.is_none());
    }

    #[test]
    fn kill_switch_forces_compat_lane() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Filesystem,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 0,
                force_compat_lane: true,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Compat);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::CompatKillSwitch)
        );
        assert_eq!(decision.fallback_code(), Some("forced_compat_kill_switch"));
    }

    #[test]
    fn disabled_policy_falls_back_to_fast_lane() {
        let mut config = enabled_config();
        config.enabled = false;
        let decision = decide_io_uring_lane(
            config,
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Network,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 0,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::IoUringDisabled)
        );
    }

    #[test]
    fn unavailable_ring_falls_back_to_fast_lane() {
        let mut config = enabled_config();
        config.ring_available = false;
        let decision = decide_io_uring_lane(
            config,
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Network,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 0,
                force_compat_lane: false,
            },
        );
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::IoUringUnavailable)
        );
    }

    #[test]
    fn non_io_hint_falls_back_to_fast_lane() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Network,
                io_hint: HostcallIoHint::CpuBound,
                queue_depth: 0,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::MissingIoHint)
        );
    }

    #[test]
    fn unsupported_capability_falls_back_to_fast_lane() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Session,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 0,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::UnsupportedCapability)
        );
    }

    #[test]
    fn queue_depth_budget_exceeded_falls_back_to_fast_lane() {
        let decision = decide_io_uring_lane(
            enabled_config(),
            IoUringLaneDecisionInput {
                capability: HostcallCapabilityClass::Filesystem,
                io_hint: HostcallIoHint::IoHeavy,
                queue_depth: 8,
                force_compat_lane: false,
            },
        );
        assert_eq!(decision.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::QueueDepthBudgetExceeded)
        );
    }

    #[test]
    fn telemetry_builder_omits_fallback_fields_for_io_uring_success() {
        let config = enabled_config();
        let input = IoUringLaneDecisionInput {
            capability: HostcallCapabilityClass::Filesystem,
            io_hint: HostcallIoHint::IoHeavy,
            queue_depth: 2,
            force_compat_lane: false,
        };
        let decision = decide_io_uring_lane(config, input);
        let telemetry = build_io_uring_lane_telemetry(config, input, decision);
        assert_eq!(telemetry.lane, HostcallDispatchLane::IoUring);
        assert_eq!(telemetry.fallback_reason, None);
        assert_eq!(telemetry.fallback_code, None);
        assert!(telemetry.capability_allowed);
        assert!(telemetry.queue_depth_within_budget);

        let value = serde_json::to_value(&telemetry).expect("serialize telemetry");
        let obj = value.as_object().expect("telemetry object");
        assert!(!obj.contains_key("fallback_reason"));
        assert!(!obj.contains_key("fallback_code"));
        assert_eq!(obj.get("queue_depth_budget"), Some(&serde_json::json!(8)));
        assert_eq!(
            obj.get("queue_depth_budget_remaining"),
            Some(&serde_json::json!(6))
        );
    }

    #[test]
    fn telemetry_builder_includes_fallback_fields_for_fast_fallback() {
        let config = IoUringLanePolicyConfig {
            enabled: true,
            ring_available: true,
            max_queue_depth: 8,
            allow_filesystem: false,
            allow_network: true,
        };
        let input = IoUringLaneDecisionInput {
            capability: HostcallCapabilityClass::Filesystem,
            io_hint: HostcallIoHint::IoHeavy,
            queue_depth: 0,
            force_compat_lane: false,
        };
        let decision = decide_io_uring_lane(config, input);
        let telemetry = build_io_uring_lane_telemetry(config, input, decision);
        assert_eq!(telemetry.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            telemetry.fallback_reason,
            Some(IoUringFallbackReason::UnsupportedCapability)
        );
        assert_eq!(
            telemetry.fallback_code.as_deref(),
            Some("io_uring_capability_not_supported")
        );
        assert!(!telemetry.capability_allowed);

        let value = serde_json::to_value(&telemetry).expect("serialize telemetry");
        let obj = value.as_object().expect("telemetry object");
        assert_eq!(
            obj.get("fallback_code"),
            Some(&serde_json::json!("io_uring_capability_not_supported"))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn fallback_reason_matrix_reports_expected_lane_and_code() {
        struct Case {
            name: &'static str,
            config: IoUringLanePolicyConfig,
            input: IoUringLaneDecisionInput,
            expected_lane: HostcallDispatchLane,
            expected_reason: IoUringFallbackReason,
        }

        let mut disabled = enabled_config();
        disabled.enabled = false;

        let mut unavailable = enabled_config();
        unavailable.ring_available = false;

        let mut unsupported_capability = enabled_config();
        unsupported_capability.allow_network = false;

        let cases = [
            Case {
                name: "compat kill-switch",
                config: enabled_config(),
                input: IoUringLaneDecisionInput {
                    capability: HostcallCapabilityClass::Filesystem,
                    io_hint: HostcallIoHint::IoHeavy,
                    queue_depth: 0,
                    force_compat_lane: true,
                },
                expected_lane: HostcallDispatchLane::Compat,
                expected_reason: IoUringFallbackReason::CompatKillSwitch,
            },
            Case {
                name: "disabled",
                config: disabled,
                input: IoUringLaneDecisionInput {
                    capability: HostcallCapabilityClass::Network,
                    io_hint: HostcallIoHint::IoHeavy,
                    queue_depth: 0,
                    force_compat_lane: false,
                },
                expected_lane: HostcallDispatchLane::Fast,
                expected_reason: IoUringFallbackReason::IoUringDisabled,
            },
            Case {
                name: "unavailable ring",
                config: unavailable,
                input: IoUringLaneDecisionInput {
                    capability: HostcallCapabilityClass::Network,
                    io_hint: HostcallIoHint::IoHeavy,
                    queue_depth: 0,
                    force_compat_lane: false,
                },
                expected_lane: HostcallDispatchLane::Fast,
                expected_reason: IoUringFallbackReason::IoUringUnavailable,
            },
            Case {
                name: "missing io hint",
                config: enabled_config(),
                input: IoUringLaneDecisionInput {
                    capability: HostcallCapabilityClass::Network,
                    io_hint: HostcallIoHint::CpuBound,
                    queue_depth: 0,
                    force_compat_lane: false,
                },
                expected_lane: HostcallDispatchLane::Fast,
                expected_reason: IoUringFallbackReason::MissingIoHint,
            },
            Case {
                name: "unsupported capability",
                config: unsupported_capability,
                input: IoUringLaneDecisionInput {
                    capability: HostcallCapabilityClass::Network,
                    io_hint: HostcallIoHint::IoHeavy,
                    queue_depth: 0,
                    force_compat_lane: false,
                },
                expected_lane: HostcallDispatchLane::Fast,
                expected_reason: IoUringFallbackReason::UnsupportedCapability,
            },
            Case {
                name: "queue budget exceeded",
                config: enabled_config(),
                input: IoUringLaneDecisionInput {
                    capability: HostcallCapabilityClass::Filesystem,
                    io_hint: HostcallIoHint::IoHeavy,
                    queue_depth: 8,
                    force_compat_lane: false,
                },
                expected_lane: HostcallDispatchLane::Fast,
                expected_reason: IoUringFallbackReason::QueueDepthBudgetExceeded,
            },
        ];

        for case in cases {
            let decision = decide_io_uring_lane(case.config, case.input);
            assert_eq!(decision.lane, case.expected_lane, "{}", case.name);
            assert_eq!(
                decision.fallback_reason,
                Some(case.expected_reason),
                "{}",
                case.name
            );
            assert_eq!(
                decision.fallback_code(),
                Some(case.expected_reason.as_code()),
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn telemetry_budget_remaining_saturates_when_queue_depth_exceeds_budget() {
        let config = IoUringLanePolicyConfig {
            enabled: true,
            ring_available: true,
            max_queue_depth: 4,
            allow_filesystem: true,
            allow_network: true,
        };
        let input = IoUringLaneDecisionInput {
            capability: HostcallCapabilityClass::Filesystem,
            io_hint: HostcallIoHint::IoHeavy,
            queue_depth: 11,
            force_compat_lane: false,
        };

        let decision = decide_io_uring_lane(config, input);
        let telemetry = build_io_uring_lane_telemetry(config, input, decision);

        assert_eq!(decision.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            decision.fallback_reason,
            Some(IoUringFallbackReason::QueueDepthBudgetExceeded)
        );
        assert_eq!(
            telemetry.fallback_code.as_deref(),
            Some("io_uring_queue_depth_budget_exceeded")
        );
        assert!(!telemetry.queue_depth_within_budget);
        assert_eq!(telemetry.queue_depth_budget_remaining, 0);
    }

    // ── Additional public API coverage ──

    #[test]
    fn dispatch_lane_as_str_all_variants() {
        assert_eq!(HostcallDispatchLane::Fast.as_str(), "fast");
        assert_eq!(HostcallDispatchLane::IoUring.as_str(), "io_uring");
        assert_eq!(HostcallDispatchLane::Compat.as_str(), "compat");
    }

    #[test]
    fn io_hint_is_io_heavy_only_for_io_heavy_variant() {
        assert!(HostcallIoHint::IoHeavy.is_io_heavy());
        assert!(!HostcallIoHint::Unknown.is_io_heavy());
        assert!(!HostcallIoHint::CpuBound.is_io_heavy());
    }

    #[test]
    fn conservative_config_defaults() {
        let config = IoUringLanePolicyConfig::conservative();
        assert!(!config.enabled);
        assert!(!config.ring_available);
        assert_eq!(config.max_queue_depth, 256);
        assert!(config.allow_filesystem);
        assert!(config.allow_network);
        // Default impl delegates to conservative
        assert_eq!(IoUringLanePolicyConfig::default(), config);
    }

    #[test]
    fn allow_for_capability_only_filesystem_and_network() {
        let config = IoUringLanePolicyConfig {
            enabled: true,
            ring_available: true,
            max_queue_depth: 8,
            allow_filesystem: true,
            allow_network: false,
        };
        assert!(config.allow_for_capability(HostcallCapabilityClass::Filesystem));
        assert!(!config.allow_for_capability(HostcallCapabilityClass::Network));
        // All other classes always false
        assert!(!config.allow_for_capability(HostcallCapabilityClass::Execution));
        assert!(!config.allow_for_capability(HostcallCapabilityClass::Session));
        assert!(!config.allow_for_capability(HostcallCapabilityClass::Events));
        assert!(!config.allow_for_capability(HostcallCapabilityClass::Environment));
        assert!(!config.allow_for_capability(HostcallCapabilityClass::Tool));
        assert!(!config.allow_for_capability(HostcallCapabilityClass::Ui));
        assert!(!config.allow_for_capability(HostcallCapabilityClass::Telemetry));
        assert!(!config.allow_for_capability(HostcallCapabilityClass::Unknown));
    }

    #[test]
    fn decision_constructors_produce_expected_lanes() {
        let uring = IoUringLaneDecision::io_uring();
        assert_eq!(uring.lane, HostcallDispatchLane::IoUring);
        assert!(uring.fallback_reason.is_none());
        assert!(uring.fallback_code().is_none());

        let compat = IoUringLaneDecision::compat(IoUringFallbackReason::CompatKillSwitch);
        assert_eq!(compat.lane, HostcallDispatchLane::Compat);
        assert_eq!(
            compat.fallback_reason,
            Some(IoUringFallbackReason::CompatKillSwitch)
        );
        assert_eq!(compat.fallback_code(), Some("forced_compat_kill_switch"));

        let fast = IoUringLaneDecision::fast(IoUringFallbackReason::IoUringDisabled);
        assert_eq!(fast.lane, HostcallDispatchLane::Fast);
        assert_eq!(
            fast.fallback_reason,
            Some(IoUringFallbackReason::IoUringDisabled)
        );
        assert_eq!(fast.fallback_code(), Some("io_uring_disabled"));
    }

    #[test]
    fn capability_class_from_all_aliases() {
        // Filesystem aliases
        assert_eq!(
            HostcallCapabilityClass::from_capability("write"),
            HostcallCapabilityClass::Filesystem
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("filesystem"),
            HostcallCapabilityClass::Filesystem
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("fs"),
            HostcallCapabilityClass::Filesystem
        );
        // Network aliases
        assert_eq!(
            HostcallCapabilityClass::from_capability("network"),
            HostcallCapabilityClass::Network
        );
        // Execution
        assert_eq!(
            HostcallCapabilityClass::from_capability("exec"),
            HostcallCapabilityClass::Execution
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("execution"),
            HostcallCapabilityClass::Execution
        );
        // Environment
        assert_eq!(
            HostcallCapabilityClass::from_capability("env"),
            HostcallCapabilityClass::Environment
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("environment"),
            HostcallCapabilityClass::Environment
        );
        // Events
        assert_eq!(
            HostcallCapabilityClass::from_capability("events"),
            HostcallCapabilityClass::Events
        );
        // Tool
        assert_eq!(
            HostcallCapabilityClass::from_capability("tool"),
            HostcallCapabilityClass::Tool
        );
        // UI
        assert_eq!(
            HostcallCapabilityClass::from_capability("ui"),
            HostcallCapabilityClass::Ui
        );
        // Telemetry
        assert_eq!(
            HostcallCapabilityClass::from_capability("log"),
            HostcallCapabilityClass::Telemetry
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("telemetry"),
            HostcallCapabilityClass::Telemetry
        );
        // Case insensitivity
        assert_eq!(
            HostcallCapabilityClass::from_capability("READ"),
            HostcallCapabilityClass::Filesystem
        );
        assert_eq!(
            HostcallCapabilityClass::from_capability("  HTTP  "),
            HostcallCapabilityClass::Network
        );
    }

    #[test]
    fn fallback_reason_as_code_all_variants() {
        assert_eq!(
            IoUringFallbackReason::CompatKillSwitch.as_code(),
            "forced_compat_kill_switch"
        );
        assert_eq!(
            IoUringFallbackReason::IoUringDisabled.as_code(),
            "io_uring_disabled"
        );
        assert_eq!(
            IoUringFallbackReason::IoUringUnavailable.as_code(),
            "io_uring_unavailable"
        );
        assert_eq!(
            IoUringFallbackReason::MissingIoHint.as_code(),
            "io_hint_missing"
        );
        assert_eq!(
            IoUringFallbackReason::UnsupportedCapability.as_code(),
            "io_uring_capability_not_supported"
        );
        assert_eq!(
            IoUringFallbackReason::QueueDepthBudgetExceeded.as_code(),
            "io_uring_queue_depth_budget_exceeded"
        );
    }

    #[test]
    fn serde_roundtrip_decision_and_lane() {
        let decision = IoUringLaneDecision::io_uring();
        let json = serde_json::to_string(&decision).expect("serialize");
        let back: IoUringLaneDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, decision);

        let compat = IoUringLaneDecision::compat(IoUringFallbackReason::CompatKillSwitch);
        let json2 = serde_json::to_string(&compat).expect("serialize");
        let back2: IoUringLaneDecision = serde_json::from_str(&json2).expect("deserialize");
        assert_eq!(back2, compat);
    }

    #[test]
    fn decide_with_telemetry_matches_core_decision() {
        let config = enabled_config();
        let input = IoUringLaneDecisionInput {
            capability: HostcallCapabilityClass::Network,
            io_hint: HostcallIoHint::CpuBound,
            queue_depth: 1,
            force_compat_lane: false,
        };
        let expected = decide_io_uring_lane(config, input);
        let (actual, telemetry) = decide_io_uring_lane_with_telemetry(config, input);
        assert_eq!(actual, expected);
        assert_eq!(telemetry.lane, expected.lane);
        assert_eq!(telemetry.fallback_reason, expected.fallback_reason);
        assert_eq!(telemetry.fallback_code.as_deref(), expected.fallback_code());
    }

    // ── Property tests ──

    mod proptest_io_uring_lane {
        use super::*;
        use proptest::prelude::*;

        fn arb_capability() -> impl Strategy<Value = HostcallCapabilityClass> {
            prop::sample::select(vec![
                HostcallCapabilityClass::Filesystem,
                HostcallCapabilityClass::Network,
                HostcallCapabilityClass::Execution,
                HostcallCapabilityClass::Session,
                HostcallCapabilityClass::Events,
                HostcallCapabilityClass::Environment,
                HostcallCapabilityClass::Tool,
                HostcallCapabilityClass::Ui,
                HostcallCapabilityClass::Telemetry,
                HostcallCapabilityClass::Unknown,
            ])
        }

        fn arb_io_hint() -> impl Strategy<Value = HostcallIoHint> {
            prop::sample::select(vec![
                HostcallIoHint::Unknown,
                HostcallIoHint::IoHeavy,
                HostcallIoHint::CpuBound,
            ])
        }

        fn arb_config() -> impl Strategy<Value = IoUringLanePolicyConfig> {
            (
                any::<bool>(),
                any::<bool>(),
                1..512usize,
                any::<bool>(),
                any::<bool>(),
            )
                .prop_map(
                    |(enabled, ring_available, max_queue_depth, allow_fs, allow_net)| {
                        IoUringLanePolicyConfig {
                            enabled,
                            ring_available,
                            max_queue_depth,
                            allow_filesystem: allow_fs,
                            allow_network: allow_net,
                        }
                    },
                )
        }

        fn arb_input() -> impl Strategy<Value = IoUringLaneDecisionInput> {
            (arb_capability(), arb_io_hint(), 0..1024usize, any::<bool>()).prop_map(
                |(capability, io_hint, queue_depth, force_compat_lane)| IoUringLaneDecisionInput {
                    capability,
                    io_hint,
                    queue_depth,
                    force_compat_lane,
                },
            )
        }

        proptest! {
            #[test]
            fn force_compat_always_returns_compat_lane(
                cfg in arb_config(),
                capability in arb_capability(),
                io_hint in arb_io_hint(),
                queue_depth in 0..1024usize,
            ) {
                let input = IoUringLaneDecisionInput {
                    capability,
                    io_hint,
                    queue_depth,
                    force_compat_lane: true,
                };
                let decision = decide_io_uring_lane(cfg, input);
                assert_eq!(decision.lane, HostcallDispatchLane::Compat);
                assert_eq!(
                    decision.fallback_reason,
                    Some(IoUringFallbackReason::CompatKillSwitch)
                );
            }

            #[test]
            fn disabled_never_returns_io_uring(
                cfg_base in arb_config(),
                input in arb_input(),
            ) {
                let cfg = IoUringLanePolicyConfig {
                    enabled: false,
                    ..cfg_base
                };
                let input = IoUringLaneDecisionInput {
                    force_compat_lane: false,
                    ..input
                };
                let decision = decide_io_uring_lane(cfg, input);
                assert_ne!(
                    decision.lane,
                    HostcallDispatchLane::IoUring,
                    "disabled config must never select io_uring"
                );
            }

            #[test]
            fn io_uring_only_when_all_preconditions_met(
                cfg in arb_config(),
                input in arb_input(),
            ) {
                let decision = decide_io_uring_lane(cfg, input);
                if decision.lane == HostcallDispatchLane::IoUring {
                    assert!(!input.force_compat_lane, "compat kill-switch must be off");
                    assert!(cfg.enabled, "policy must be enabled");
                    assert!(cfg.ring_available, "ring must be available");
                    assert!(input.io_hint.is_io_heavy(), "must be IO-heavy");
                    assert!(
                        cfg.allow_for_capability(input.capability),
                        "capability must be allowed"
                    );
                    assert!(
                        input.queue_depth < cfg.max_queue_depth,
                        "queue depth must be within budget"
                    );
                }
            }

            #[test]
            fn decision_always_has_fallback_reason_unless_io_uring(
                cfg in arb_config(),
                input in arb_input(),
            ) {
                let decision = decide_io_uring_lane(cfg, input);
                if decision.lane == HostcallDispatchLane::IoUring {
                    assert!(
                        decision.fallback_reason.is_none(),
                        "io_uring lane must have no fallback reason"
                    );
                } else {
                    assert!(
                        decision.fallback_reason.is_some(),
                        "non-io_uring lane must have a fallback reason"
                    );
                }
            }

            #[test]
            fn telemetry_consistent_with_decision(
                cfg in arb_config(),
                input in arb_input(),
            ) {
                let (decision, telemetry) = decide_io_uring_lane_with_telemetry(cfg, input);
                assert_eq!(telemetry.lane, decision.lane);
                assert_eq!(telemetry.fallback_reason, decision.fallback_reason);
                assert_eq!(telemetry.policy_enabled, cfg.enabled);
                assert_eq!(telemetry.ring_available, cfg.ring_available);
                assert_eq!(telemetry.force_compat_lane, input.force_compat_lane);
                assert_eq!(telemetry.queue_depth, input.queue_depth);
                assert_eq!(telemetry.queue_depth_budget, cfg.max_queue_depth);
            }

            #[test]
            fn decide_is_deterministic(
                cfg in arb_config(),
                input in arb_input(),
            ) {
                let d1 = decide_io_uring_lane(cfg, input);
                let d2 = decide_io_uring_lane(cfg, input);
                assert_eq!(d1, d2, "same inputs must produce same decision");
            }
        }
    }
}
