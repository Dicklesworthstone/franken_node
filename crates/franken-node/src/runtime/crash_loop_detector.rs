//! bd-2yc4: Crash-loop detector with automatic rollback.
//!
//! Monitors connector crash frequency within a sliding window. When the
//! threshold is exceeded, triggers automatic rollback to a known-good
//! pinned version. Rollback targets must pass trust policy.

use std::collections::BTreeMap;

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
    /// Crash timestamps keyed by connector ID.
    crash_times_by_connector: BTreeMap<String, Vec<u64>>,
    /// Epoch second when last rollback occurred, keyed by connector ID.
    last_rollback_epoch_by_connector: BTreeMap<String, u64>,
    pub incidents: Vec<CrashLoopIncident>,
}

impl CrashLoopDetector {
    pub fn new(config: CrashLoopConfig) -> Self {
        Self {
            config,
            crash_times_by_connector: BTreeMap::new(),
            last_rollback_epoch_by_connector: BTreeMap::new(),
            incidents: Vec::new(),
        }
    }

    /// Record a crash event. Returns the current crash count within the window.
    pub fn record_crash(&mut self, event: &CrashEvent, epoch_secs: u64) -> u32 {
        let connector_id = event.connector_id.clone();
        let times = self
            .crash_times_by_connector
            .entry(connector_id.clone())
            .or_default();
        times.push(epoch_secs);
        // Prune timestamps outside the sliding window to bound memory.
        let cutoff = epoch_secs.saturating_sub(self.config.window_secs);
        times.retain(|&t| t >= cutoff);
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

    /// Check if the crash-loop threshold is exceeded across all connectors at time `now`.
    pub fn is_looping(&self, now: u64) -> bool {
        self.crashes_in_window(now) >= self.config.max_crashes
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
            self.incidents.push(incident);
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
            self.incidents.push(incident);
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
                self.incidents.push(incident);
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
            self.incidents.push(incident);
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
            self.incidents.push(incident);
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
        self.incidents.push(incident);
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

    #[test]
    fn below_threshold_no_trigger() {
        let mut det = CrashLoopDetector::new(config());
        let ev = crash("conn-1", "t1", "oom");
        det.record_crash(&ev, 100);
        let result = det.evaluate("conn-1", &[ev], Some(&trusted_pin()), 100, "tr1", "ts1");
        let decision = result.unwrap();
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
        let decision = result.unwrap();
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
        let decision = result.unwrap();
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
            Some(&trusted_pin()),
            102,
            "tr-a",
            "ts-a",
        )
        .unwrap();

        assert_eq!(det.crashes_in_window_for("conn-a", 102), 0);
        assert_eq!(det.crashes_in_window_for("conn-b", 102), 2);
    }
}
