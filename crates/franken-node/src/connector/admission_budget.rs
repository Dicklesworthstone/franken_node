//! bd-2k74: Per-peer admission budgets (bytes/symbols/failed-auth/inflight-decode/decode-cpu).
//!
//! Enforces multi-dimensional budgets per peer. Limit breaches are rejected and logged.
//! Budgets are configurable at runtime without code changes.

use std::collections::BTreeMap;

/// Budget limits for a single peer.
#[derive(Debug, Clone)]
pub struct AdmissionBudget {
    pub max_bytes: u64,
    pub max_symbols: u64,
    pub max_failed_auth: u32,
    pub max_inflight_decode: u32,
    pub max_decode_cpu_ms: u64,
}

impl AdmissionBudget {
    pub fn default_budget() -> Self {
        Self {
            max_bytes: 10_000_000,
            max_symbols: 100_000,
            max_failed_auth: 5,
            max_inflight_decode: 10,
            max_decode_cpu_ms: 5_000,
        }
    }
}

/// Current usage counters for a peer.
#[derive(Debug, Clone, Default)]
pub struct PeerUsage {
    pub bytes_used: u64,
    pub symbols_used: u64,
    pub failed_auth_count: u32,
    pub inflight_decode_count: u32,
    pub decode_cpu_ms: u64,
}

/// Incoming admission request.
#[derive(Debug, Clone)]
pub struct AdmissionRequest {
    pub peer_id: String,
    pub bytes_requested: u64,
    pub symbols_requested: u64,
    pub decode_cpu_estimate_ms: u64,
}

/// Which budget dimension was violated.
#[derive(Debug, Clone, PartialEq)]
pub enum BudgetDimension {
    Bytes,
    Symbols,
    FailedAuth,
    InflightDecode,
    DecodeCpu,
}

impl BudgetDimension {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Symbols => "symbols",
            Self::FailedAuth => "failed_auth",
            Self::InflightDecode => "inflight_decode",
            Self::DecodeCpu => "decode_cpu",
        }
    }
}

/// Result of an admission check.
#[derive(Debug, Clone)]
pub struct AdmissionVerdict {
    pub peer_id: String,
    pub admitted: bool,
    pub violated_dimensions: Vec<BudgetDimension>,
    pub remaining: RemainingBudget,
    pub trace_id: String,
}

/// Remaining budget after a check.
#[derive(Debug, Clone)]
pub struct RemainingBudget {
    pub bytes_remaining: u64,
    pub symbols_remaining: u64,
    pub failed_auth_remaining: u32,
    pub inflight_decode_remaining: u32,
    pub decode_cpu_remaining: u64,
}

/// Audit record for a single dimension check.
#[derive(Debug, Clone)]
pub struct BudgetCheckRecord {
    pub peer_id: String,
    pub timestamp: String,
    pub dimension: String,
    pub usage_before: u64,
    pub requested: u64,
    pub limit: u64,
    pub verdict: String,
}

/// Errors from admission budget operations.
#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionError {
    BytesExceeded {
        peer_id: String,
        used: u64,
        limit: u64,
    },
    SymbolsExceeded {
        peer_id: String,
        used: u64,
        limit: u64,
    },
    AuthExceeded {
        peer_id: String,
        count: u32,
        limit: u32,
    },
    InflightExceeded {
        peer_id: String,
        count: u32,
        limit: u32,
    },
    CpuExceeded {
        peer_id: String,
        used: u64,
        limit: u64,
    },
    InvalidBudget {
        reason: String,
    },
}

impl AdmissionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BytesExceeded { .. } => "PAB_BYTES_EXCEEDED",
            Self::SymbolsExceeded { .. } => "PAB_SYMBOLS_EXCEEDED",
            Self::AuthExceeded { .. } => "PAB_AUTH_EXCEEDED",
            Self::InflightExceeded { .. } => "PAB_INFLIGHT_EXCEEDED",
            Self::CpuExceeded { .. } => "PAB_CPU_EXCEEDED",
            Self::InvalidBudget { .. } => "PAB_INVALID_BUDGET",
        }
    }
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BytesExceeded {
                peer_id,
                used,
                limit,
            } => write!(
                f,
                "PAB_BYTES_EXCEEDED: peer={peer_id} used={used} limit={limit}"
            ),
            Self::SymbolsExceeded {
                peer_id,
                used,
                limit,
            } => write!(
                f,
                "PAB_SYMBOLS_EXCEEDED: peer={peer_id} used={used} limit={limit}"
            ),
            Self::AuthExceeded {
                peer_id,
                count,
                limit,
            } => write!(
                f,
                "PAB_AUTH_EXCEEDED: peer={peer_id} count={count} limit={limit}"
            ),
            Self::InflightExceeded {
                peer_id,
                count,
                limit,
            } => write!(
                f,
                "PAB_INFLIGHT_EXCEEDED: peer={peer_id} count={count} limit={limit}"
            ),
            Self::CpuExceeded {
                peer_id,
                used,
                limit,
            } => write!(
                f,
                "PAB_CPU_EXCEEDED: peer={peer_id} used={used} limit={limit}"
            ),
            Self::InvalidBudget { reason } => write!(f, "PAB_INVALID_BUDGET: {reason}"),
        }
    }
}

/// Validate budget configuration.
pub fn validate_budget(budget: &AdmissionBudget) -> Result<(), AdmissionError> {
    if budget.max_bytes == 0 {
        return Err(AdmissionError::InvalidBudget {
            reason: "max_bytes must be > 0".into(),
        });
    }
    if budget.max_symbols == 0 {
        return Err(AdmissionError::InvalidBudget {
            reason: "max_symbols must be > 0".into(),
        });
    }
    if budget.max_failed_auth == 0 {
        return Err(AdmissionError::InvalidBudget {
            reason: "max_failed_auth must be > 0".into(),
        });
    }
    if budget.max_inflight_decode == 0 {
        return Err(AdmissionError::InvalidBudget {
            reason: "max_inflight_decode must be > 0".into(),
        });
    }
    if budget.max_decode_cpu_ms == 0 {
        return Err(AdmissionError::InvalidBudget {
            reason: "max_decode_cpu_ms must be > 0".into(),
        });
    }
    Ok(())
}

/// Per-peer admission budget tracker.
#[derive(Debug)]
pub struct AdmissionBudgetTracker {
    budget: AdmissionBudget,
    peers: BTreeMap<String, PeerUsage>,
}

impl AdmissionBudgetTracker {
    pub fn new(budget: AdmissionBudget) -> Result<Self, AdmissionError> {
        validate_budget(&budget)?;
        Ok(Self {
            budget,
            peers: BTreeMap::new(),
        })
    }

    /// Record a failed auth attempt for a peer.
    pub fn record_failed_auth(&mut self, peer_id: &str) -> Result<(), AdmissionError> {
        let usage = self.peers.entry(peer_id.to_string()).or_default();
        usage.failed_auth_count = usage.failed_auth_count.saturating_add(1);
        if usage.failed_auth_count > self.budget.max_failed_auth {
            return Err(AdmissionError::AuthExceeded {
                peer_id: peer_id.to_string(),
                count: usage.failed_auth_count,
                limit: self.budget.max_failed_auth,
            });
        }
        Ok(())
    }

    /// Record an inflight decode starting.
    pub fn record_decode_start(&mut self, peer_id: &str) -> Result<(), AdmissionError> {
        let usage = self.peers.entry(peer_id.to_string()).or_default();
        let attempted_count = usage.inflight_decode_count.saturating_add(1);
        if attempted_count > self.budget.max_inflight_decode {
            return Err(AdmissionError::InflightExceeded {
                peer_id: peer_id.to_string(),
                count: attempted_count,
                limit: self.budget.max_inflight_decode,
            });
        }
        usage.inflight_decode_count = attempted_count;
        Ok(())
    }

    /// Record an inflight decode completing.
    pub fn record_decode_complete(&mut self, peer_id: &str) {
        if let Some(usage) = self.peers.get_mut(peer_id) {
            usage.inflight_decode_count = usage.inflight_decode_count.saturating_sub(1);
        }
    }

    /// Check admission for a request against all budget dimensions.
    ///
    /// INV-PAB-ENFORCED: evaluates bytes, symbols, failed_auth, inflight_decode, decode_cpu.
    /// INV-PAB-BOUNDED: rejects if any dimension exceeded.
    /// INV-PAB-DETERMINISTIC: same state + same config → same decision.
    pub fn check_admission(
        &self,
        request: &AdmissionRequest,
        trace_id: &str,
        timestamp: &str,
    ) -> (AdmissionVerdict, Vec<BudgetCheckRecord>) {
        let usage = self
            .peers
            .get(&request.peer_id)
            .cloned()
            .unwrap_or_default();
        let mut violations = Vec::new();
        let mut records = Vec::new();

        // Dimension 1: bytes
        let bytes_after = usage.bytes_used.saturating_add(request.bytes_requested);
        let bytes_ok = bytes_after <= self.budget.max_bytes;
        records.push(BudgetCheckRecord {
            peer_id: request.peer_id.clone(),
            timestamp: timestamp.to_string(),
            dimension: "bytes".into(),
            usage_before: usage.bytes_used,
            requested: request.bytes_requested,
            limit: self.budget.max_bytes,
            verdict: if bytes_ok { "PASS" } else { "FAIL" }.into(),
        });
        if !bytes_ok {
            violations.push(BudgetDimension::Bytes);
        }

        // Dimension 2: symbols
        let symbols_after = usage.symbols_used.saturating_add(request.symbols_requested);
        let symbols_ok = symbols_after <= self.budget.max_symbols;
        records.push(BudgetCheckRecord {
            peer_id: request.peer_id.clone(),
            timestamp: timestamp.to_string(),
            dimension: "symbols".into(),
            usage_before: usage.symbols_used,
            requested: request.symbols_requested,
            limit: self.budget.max_symbols,
            verdict: if symbols_ok { "PASS" } else { "FAIL" }.into(),
        });
        if !symbols_ok {
            violations.push(BudgetDimension::Symbols);
        }

        // Dimension 3: failed_auth (current count, no increment from request)
        let auth_ok = usage.failed_auth_count < self.budget.max_failed_auth;
        records.push(BudgetCheckRecord {
            peer_id: request.peer_id.clone(),
            timestamp: timestamp.to_string(),
            dimension: "failed_auth".into(),
            usage_before: usage.failed_auth_count as u64,
            requested: 0,
            limit: self.budget.max_failed_auth as u64,
            verdict: if auth_ok { "PASS" } else { "FAIL" }.into(),
        });
        if !auth_ok {
            violations.push(BudgetDimension::FailedAuth);
        }

        // Dimension 4: inflight_decode (current count)
        let inflight_ok = usage.inflight_decode_count < self.budget.max_inflight_decode;
        records.push(BudgetCheckRecord {
            peer_id: request.peer_id.clone(),
            timestamp: timestamp.to_string(),
            dimension: "inflight_decode".into(),
            usage_before: usage.inflight_decode_count as u64,
            requested: 0,
            limit: self.budget.max_inflight_decode as u64,
            verdict: if inflight_ok { "PASS" } else { "FAIL" }.into(),
        });
        if !inflight_ok {
            violations.push(BudgetDimension::InflightDecode);
        }

        // Dimension 5: decode_cpu
        let cpu_after = usage
            .decode_cpu_ms
            .saturating_add(request.decode_cpu_estimate_ms);
        let cpu_ok = cpu_after <= self.budget.max_decode_cpu_ms;
        records.push(BudgetCheckRecord {
            peer_id: request.peer_id.clone(),
            timestamp: timestamp.to_string(),
            dimension: "decode_cpu".into(),
            usage_before: usage.decode_cpu_ms,
            requested: request.decode_cpu_estimate_ms,
            limit: self.budget.max_decode_cpu_ms,
            verdict: if cpu_ok { "PASS" } else { "FAIL" }.into(),
        });
        if !cpu_ok {
            violations.push(BudgetDimension::DecodeCpu);
        }

        let admitted = violations.is_empty();

        let remaining = RemainingBudget {
            bytes_remaining: self.budget.max_bytes.saturating_sub(usage.bytes_used),
            symbols_remaining: self.budget.max_symbols.saturating_sub(usage.symbols_used),
            failed_auth_remaining: self
                .budget
                .max_failed_auth
                .saturating_sub(usage.failed_auth_count),
            inflight_decode_remaining: self
                .budget
                .max_inflight_decode
                .saturating_sub(usage.inflight_decode_count),
            decode_cpu_remaining: self
                .budget
                .max_decode_cpu_ms
                .saturating_sub(usage.decode_cpu_ms),
        };

        let verdict = AdmissionVerdict {
            peer_id: request.peer_id.clone(),
            admitted,
            violated_dimensions: violations,
            remaining,
            trace_id: trace_id.to_string(),
        };

        (verdict, records)
    }

    /// Admit a request: check all dimensions and, if admitted, update usage.
    ///
    /// Returns the verdict and audit records.
    pub fn admit(
        &mut self,
        request: &AdmissionRequest,
        trace_id: &str,
        timestamp: &str,
    ) -> (AdmissionVerdict, Vec<BudgetCheckRecord>) {
        let (verdict, records) = self.check_admission(request, trace_id, timestamp);
        if verdict.admitted {
            let usage = self.peers.entry(request.peer_id.clone()).or_default();
            usage.bytes_used = usage.bytes_used.saturating_add(request.bytes_requested);
            usage.symbols_used = usage.symbols_used.saturating_add(request.symbols_requested);
            usage.decode_cpu_ms = usage
                .decode_cpu_ms
                .saturating_add(request.decode_cpu_estimate_ms);
        }
        (verdict, records)
    }

    /// Get current usage for a peer.
    pub fn get_usage(&self, peer_id: &str) -> PeerUsage {
        self.peers.get(peer_id).cloned().unwrap_or_default()
    }

    /// Reset usage for a peer (e.g., on connection reset).
    pub fn reset_peer(&mut self, peer_id: &str) {
        self.peers.remove(peer_id);
    }

    /// Get the configured budget.
    pub fn budget(&self) -> &AdmissionBudget {
        &self.budget
    }

    /// Update budget without code changes (runtime reconfiguration).
    pub fn update_budget(&mut self, budget: AdmissionBudget) -> Result<(), AdmissionError> {
        validate_budget(&budget)?;
        self.budget = budget;
        Ok(())
    }

    /// Snapshot all peer usage, sorted by peer_id for determinism.
    pub fn snapshot(&self) -> Vec<(String, PeerUsage)> {
        let mut result: Vec<(String, PeerUsage)> = self
            .peers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }
}

/// Convenience: check a single request against a budget without persistent state.
pub fn check_admission_stateless(
    request: &AdmissionRequest,
    usage: &PeerUsage,
    budget: &AdmissionBudget,
    trace_id: &str,
    timestamp: &str,
) -> Result<(AdmissionVerdict, Vec<BudgetCheckRecord>), AdmissionError> {
    validate_budget(budget)?;
    let mut tracker = AdmissionBudgetTracker {
        budget: budget.clone(),
        peers: BTreeMap::new(),
    };
    tracker.peers.insert(request.peer_id.clone(), usage.clone());
    Ok(tracker.check_admission(request, trace_id, timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> AdmissionBudget {
        AdmissionBudget {
            max_bytes: 1000,
            max_symbols: 500,
            max_failed_auth: 3,
            max_inflight_decode: 5,
            max_decode_cpu_ms: 2000,
        }
    }

    fn request(peer: &str, bytes: u64, symbols: u64, cpu: u64) -> AdmissionRequest {
        AdmissionRequest {
            peer_id: peer.into(),
            bytes_requested: bytes,
            symbols_requested: symbols,
            decode_cpu_estimate_ms: cpu,
        }
    }

    #[test]
    fn admit_within_budget() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 100, 50, 200);
        let (verdict, records) = tracker.admit(&req, "tr", "ts");
        assert!(verdict.admitted);
        assert!(verdict.violated_dimensions.is_empty());
        assert_eq!(records.len(), 5); // all 5 dimensions checked
    }

    #[test]
    fn reject_bytes_exceeded() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 1001, 0, 0);
        let (verdict, _) = tracker.admit(&req, "tr", "ts");
        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::Bytes)
        );
    }

    #[test]
    fn reject_symbols_exceeded() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 0, 501, 0);
        let (verdict, _) = tracker.admit(&req, "tr", "ts");
        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::Symbols)
        );
    }

    #[test]
    fn reject_cpu_exceeded() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 0, 0, 2001);
        let (verdict, _) = tracker.admit(&req, "tr", "ts");
        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::DecodeCpu)
        );
    }

    #[test]
    fn reject_failed_auth() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        // Exceed failed auth budget (max_failed_auth = 3, so 4th triggers rejection)
        for _ in 0..4 {
            let _ = tracker.record_failed_auth("p1");
        }
        let req = request("p1", 10, 10, 10);
        let (verdict, _) = tracker.check_admission(&req, "tr", "ts");
        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::FailedAuth)
        );
    }

    #[test]
    fn reject_inflight_exceeded() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        for _ in 0..5 {
            tracker.record_decode_start("p1").unwrap();
        }
        let req = request("p1", 10, 10, 10);
        let (verdict, _) = tracker.check_admission(&req, "tr", "ts");
        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::InflightDecode)
        );
    }

    #[test]
    fn multiple_violations() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 1001, 501, 2001);
        let (verdict, _) = tracker.admit(&req, "tr", "ts");
        assert!(!verdict.admitted);
        assert_eq!(verdict.violated_dimensions.len(), 3);
    }

    #[test]
    fn cumulative_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req1 = request("p1", 600, 300, 1000);
        let (v1, _) = tracker.admit(&req1, "tr", "ts");
        assert!(v1.admitted);

        let req2 = request("p1", 500, 300, 1100);
        let (v2, _) = tracker.admit(&req2, "tr", "ts");
        assert!(!v2.admitted); // cumulative exceeds budget
    }

    #[test]
    fn independent_peers() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req1 = request("p1", 900, 400, 1800);
        let (v1, _) = tracker.admit(&req1, "tr", "ts");
        assert!(v1.admitted);

        // Different peer has fresh budget
        let req2 = request("p2", 900, 400, 1800);
        let (v2, _) = tracker.admit(&req2, "tr", "ts");
        assert!(v2.admitted);
    }

    #[test]
    fn reset_peer_clears_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 900, 400, 1800);
        tracker.admit(&req, "tr", "ts");
        tracker.reset_peer("p1");

        let usage = tracker.get_usage("p1");
        assert_eq!(usage.bytes_used, 0);
        assert_eq!(usage.symbols_used, 0);
    }

    #[test]
    fn decode_complete_decrements() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        tracker.record_decode_start("p1").unwrap();
        tracker.record_decode_start("p1").unwrap();
        assert_eq!(tracker.get_usage("p1").inflight_decode_count, 2);
        tracker.record_decode_complete("p1");
        assert_eq!(tracker.get_usage("p1").inflight_decode_count, 1);
    }

    #[test]
    fn deterministic_verdict() {
        let tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 100, 50, 200);
        let (v1, r1) = tracker.check_admission(&req, "tr", "ts");
        let (v2, r2) = tracker.check_admission(&req, "tr", "ts");
        assert_eq!(v1.admitted, v2.admitted);
        assert_eq!(v1.violated_dimensions, v2.violated_dimensions);
        assert_eq!(r1.len(), r2.len());
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.verdict, b.verdict);
        }
    }

    #[test]
    fn all_dimensions_checked() {
        let tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 10, 10, 10);
        let (_, records) = tracker.check_admission(&req, "tr", "ts");
        let dims: Vec<&str> = records.iter().map(|r| r.dimension.as_str()).collect();
        assert!(dims.contains(&"bytes"));
        assert!(dims.contains(&"symbols"));
        assert!(dims.contains(&"failed_auth"));
        assert!(dims.contains(&"inflight_decode"));
        assert!(dims.contains(&"decode_cpu"));
    }

    #[test]
    fn remaining_budget_correct() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 300, 100, 500);
        tracker.admit(&req, "tr", "ts");
        let req2 = request("p1", 10, 10, 10);
        let (verdict, _) = tracker.check_admission(&req2, "tr", "ts");
        assert_eq!(verdict.remaining.bytes_remaining, 700);
        assert_eq!(verdict.remaining.symbols_remaining, 400);
        assert_eq!(verdict.remaining.decode_cpu_remaining, 1500);
    }

    #[test]
    fn invalid_budget_zero_bytes() {
        let mut b = budget();
        b.max_bytes = 0;
        let err = AdmissionBudgetTracker::new(b).unwrap_err();
        assert_eq!(err.code(), "PAB_INVALID_BUDGET");
    }

    #[test]
    fn invalid_budget_zero_symbols() {
        let mut b = budget();
        b.max_symbols = 0;
        let err = AdmissionBudgetTracker::new(b).unwrap_err();
        assert_eq!(err.code(), "PAB_INVALID_BUDGET");
    }

    #[test]
    fn invalid_budget_zero_auth() {
        let mut b = budget();
        b.max_failed_auth = 0;
        let err = AdmissionBudgetTracker::new(b).unwrap_err();
        assert_eq!(err.code(), "PAB_INVALID_BUDGET");
    }

    #[test]
    fn invalid_budget_zero_inflight() {
        let mut b = budget();
        b.max_inflight_decode = 0;
        let err = AdmissionBudgetTracker::new(b).unwrap_err();
        assert_eq!(err.code(), "PAB_INVALID_BUDGET");
    }

    #[test]
    fn invalid_budget_zero_cpu() {
        let mut b = budget();
        b.max_decode_cpu_ms = 0;
        let err = AdmissionBudgetTracker::new(b).unwrap_err();
        assert_eq!(err.code(), "PAB_INVALID_BUDGET");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            AdmissionError::BytesExceeded {
                peer_id: "".into(),
                used: 0,
                limit: 0
            }
            .code(),
            "PAB_BYTES_EXCEEDED"
        );
        assert_eq!(
            AdmissionError::SymbolsExceeded {
                peer_id: "".into(),
                used: 0,
                limit: 0
            }
            .code(),
            "PAB_SYMBOLS_EXCEEDED"
        );
        assert_eq!(
            AdmissionError::AuthExceeded {
                peer_id: "".into(),
                count: 0,
                limit: 0
            }
            .code(),
            "PAB_AUTH_EXCEEDED"
        );
        assert_eq!(
            AdmissionError::InflightExceeded {
                peer_id: "".into(),
                count: 0,
                limit: 0
            }
            .code(),
            "PAB_INFLIGHT_EXCEEDED"
        );
        assert_eq!(
            AdmissionError::CpuExceeded {
                peer_id: "".into(),
                used: 0,
                limit: 0
            }
            .code(),
            "PAB_CPU_EXCEEDED"
        );
        assert_eq!(
            AdmissionError::InvalidBudget { reason: "".into() }.code(),
            "PAB_INVALID_BUDGET"
        );
    }

    #[test]
    fn error_display() {
        let e = AdmissionError::BytesExceeded {
            peer_id: "p1".into(),
            used: 1100,
            limit: 1000,
        };
        assert!(e.to_string().contains("PAB_BYTES_EXCEEDED"));
        assert!(e.to_string().contains("p1"));
    }

    #[test]
    fn default_budget_valid() {
        assert!(validate_budget(&AdmissionBudget::default_budget()).is_ok());
    }

    #[test]
    fn update_budget_runtime() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let mut new_budget = budget();
        new_budget.max_bytes = 2000;
        tracker.update_budget(new_budget).unwrap();
        assert_eq!(tracker.budget().max_bytes, 2000);
    }

    #[test]
    fn snapshot_sorted_by_peer() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        tracker.admit(&request("z-peer", 10, 10, 10), "tr", "ts");
        tracker.admit(&request("a-peer", 10, 10, 10), "tr", "ts");
        let snap = tracker.snapshot();
        assert_eq!(snap[0].0, "a-peer");
        assert_eq!(snap[1].0, "z-peer");
    }

    #[test]
    fn stateless_check() {
        let usage = PeerUsage {
            bytes_used: 500,
            ..Default::default()
        };
        let req = request("p1", 600, 0, 0);
        let (verdict, _) = check_admission_stateless(&req, &usage, &budget(), "tr", "ts").unwrap();
        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::Bytes)
        );
    }

    #[test]
    fn rejected_admission_does_not_mutate_empty_peer_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 1001, 10, 10);

        let (verdict, records) = tracker.admit(&req, "tr", "ts");

        assert!(!verdict.admitted);
        assert!(records.iter().any(|record| {
            record.dimension.as_str() == "bytes" && record.verdict.as_str() == "FAIL"
        }));
        let usage = tracker.get_usage("p1");
        assert_eq!(usage.bytes_used, 0);
        assert_eq!(usage.symbols_used, 0);
        assert_eq!(usage.decode_cpu_ms, 0);
    }

    #[test]
    fn rejected_cumulative_admission_keeps_prior_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let first = request("p1", 600, 300, 1100);
        let (first_verdict, _) = tracker.admit(&first, "tr", "ts");
        assert!(first_verdict.admitted);

        let rejected = request("p1", 500, 250, 1000);
        let (rejected_verdict, _) = tracker.admit(&rejected, "tr", "ts");

        assert!(!rejected_verdict.admitted);
        assert!(
            rejected_verdict
                .violated_dimensions
                .contains(&BudgetDimension::Bytes)
        );
        assert!(
            rejected_verdict
                .violated_dimensions
                .contains(&BudgetDimension::Symbols)
        );
        assert!(
            rejected_verdict
                .violated_dimensions
                .contains(&BudgetDimension::DecodeCpu)
        );
        let usage = tracker.get_usage("p1");
        assert_eq!(usage.bytes_used, 600);
        assert_eq!(usage.symbols_used, 300);
        assert_eq!(usage.decode_cpu_ms, 1100);
    }

    #[test]
    fn update_budget_rejects_invalid_budget_without_replacing_current_config() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let mut invalid = budget();
        invalid.max_symbols = 0;

        let err = tracker.update_budget(invalid).unwrap_err();

        assert_eq!(err.code(), "PAB_INVALID_BUDGET");
        assert_eq!(tracker.budget().max_symbols, 500);
        assert_eq!(tracker.budget().max_bytes, 1000);
    }

    #[test]
    fn stateless_check_rejects_invalid_budget_before_verdict() {
        let usage = PeerUsage::default();
        let req = request("p1", 1, 1, 1);
        let mut invalid = budget();
        invalid.max_bytes = 0;

        let err = check_admission_stateless(&req, &usage, &invalid, "tr", "ts").unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InvalidBudget { reason } if reason.contains("max_bytes")
        ));
    }

    #[test]
    fn decode_start_rejection_rolls_back_inflight_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        for _ in 0..5 {
            tracker.record_decode_start("p1").unwrap();
        }

        let err = tracker.record_decode_start("p1").unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InflightExceeded {
                count: 6,
                limit: 5,
                ..
            }
        ));
        assert_eq!(tracker.get_usage("p1").inflight_decode_count, 5);
    }

    #[test]
    fn decode_complete_on_zero_usage_does_not_underflow() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        tracker.record_decode_complete("p1");
        assert_eq!(tracker.get_usage("p1").inflight_decode_count, 0);

        tracker.record_decode_start("p1").unwrap();
        tracker.record_decode_complete("p1");
        tracker.record_decode_complete("p1");

        assert_eq!(tracker.get_usage("p1").inflight_decode_count, 0);
    }

    #[test]
    fn failed_auth_at_exact_limit_blocks_admission() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        for _ in 0..3 {
            tracker.record_failed_auth("p1").unwrap();
        }

        let (verdict, records) = tracker.check_admission(&request("p1", 1, 1, 1), "tr", "ts");

        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::FailedAuth)
        );
        assert_eq!(verdict.remaining.failed_auth_remaining, 0);
        assert!(records.iter().any(|record| {
            record.dimension.as_str() == "failed_auth" && record.verdict.as_str() == "FAIL"
        }));
    }

    #[test]
    fn failed_auth_exceedance_is_visible_in_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        for _ in 0..3 {
            tracker.record_failed_auth("p1").unwrap();
        }

        let err = tracker.record_failed_auth("p1").unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::AuthExceeded {
                count: 4,
                limit: 3,
                ..
            }
        ));
        assert_eq!(tracker.get_usage("p1").failed_auth_count, 4);
        let (verdict, _) = tracker.check_admission(&request("p1", 1, 1, 1), "tr", "ts");
        assert!(!verdict.admitted);
    }

    #[test]
    fn saturated_request_rejects_without_overflowing_records() {
        let tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", u64::MAX, u64::MAX, u64::MAX);

        let (verdict, records) = tracker.check_admission(&req, "tr", "ts");

        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::Bytes)
        );
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::Symbols)
        );
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::DecodeCpu)
        );
        let bytes_record = records
            .iter()
            .find(|record| record.dimension.as_str() == "bytes")
            .expect("bytes record");
        assert_eq!(bytes_record.requested, u64::MAX);
    }

    #[test]
    fn negative_byte_limit_plus_one_rejects_without_mutating_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let exact = request("p1", 1000, 0, 0);
        assert!(tracker.admit(&exact, "tr", "ts").0.admitted);

        let over = request("p1", 1, 0, 0);
        let (verdict, records) = tracker.admit(&over, "tr-over", "ts-over");

        assert!(!verdict.admitted);
        assert_eq!(tracker.get_usage("p1").bytes_used, 1000);
        assert!(records.iter().any(|record| {
            record.dimension.as_str() == "bytes"
                && record.usage_before == 1000
                && record.requested == 1
                && record.verdict.as_str() == "FAIL"
        }));
    }

    #[test]
    fn negative_symbol_limit_plus_one_rejects_without_mutating_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let exact = request("p1", 0, 500, 0);
        assert!(tracker.admit(&exact, "tr", "ts").0.admitted);

        let over = request("p1", 0, 1, 0);
        let (verdict, _) = tracker.admit(&over, "tr-over", "ts-over");

        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::Symbols)
        );
        assert_eq!(tracker.get_usage("p1").symbols_used, 500);
    }

    #[test]
    fn negative_decode_cpu_limit_plus_one_rejects_without_mutating_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let exact = request("p1", 0, 0, 2000);
        assert!(tracker.admit(&exact, "tr", "ts").0.admitted);

        let over = request("p1", 0, 0, 1);
        let (verdict, _) = tracker.admit(&over, "tr-over", "ts-over");

        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::DecodeCpu)
        );
        assert_eq!(tracker.get_usage("p1").decode_cpu_ms, 2000);
    }

    #[test]
    fn negative_stateless_inflight_limit_rejects_with_record_metadata() {
        let usage = PeerUsage {
            inflight_decode_count: 5,
            ..Default::default()
        };
        let req = request("p-stateless", 1, 1, 1);

        let (verdict, records) =
            check_admission_stateless(&req, &usage, &budget(), "trace-meta", "ts-meta").unwrap();

        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::InflightDecode)
        );
        assert_eq!(verdict.trace_id, "trace-meta");
        let inflight_record = records
            .iter()
            .find(|record| record.dimension.as_str() == "inflight_decode")
            .expect("inflight record");
        assert_eq!(inflight_record.peer_id, "p-stateless");
        assert_eq!(inflight_record.timestamp, "ts-meta");
        assert_eq!(inflight_record.verdict, "FAIL");
    }

    #[test]
    fn negative_reset_peer_clears_failed_auth_block() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        for _ in 0..3 {
            tracker.record_failed_auth("p1").unwrap();
        }
        assert!(
            !tracker
                .check_admission(&request("p1", 1, 1, 1), "tr-block", "ts-block")
                .0
                .admitted
        );

        tracker.reset_peer("p1");

        assert!(
            tracker
                .check_admission(&request("p1", 1, 1, 1), "tr-reset", "ts-reset")
                .0
                .admitted
        );
    }

    #[test]
    fn negative_failed_auth_counter_saturates_without_wrapping() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        tracker.peers.insert(
            "p-max".to_string(),
            PeerUsage {
                failed_auth_count: u32::MAX,
                ..Default::default()
            },
        );

        let err = tracker.record_failed_auth("p-max").unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::AuthExceeded {
                count: u32::MAX,
                limit: 3,
                ..
            }
        ));
        assert_eq!(tracker.get_usage("p-max").failed_auth_count, u32::MAX);
    }

    #[test]
    fn failed_auth_error_on_exceed() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        for _ in 0..3 {
            let _ = tracker.record_failed_auth("p1");
        }
        let err = tracker.record_failed_auth("p1").unwrap_err();
        assert_eq!(err.code(), "PAB_AUTH_EXCEEDED");
    }

    #[test]
    fn inflight_error_on_exceed() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        for _ in 0..5 {
            tracker.record_decode_start("p1").unwrap();
        }
        let err = tracker.record_decode_start("p1").unwrap_err();
        assert_eq!(err.code(), "PAB_INFLIGHT_EXCEEDED");
    }

    #[test]
    fn dimension_labels() {
        assert_eq!(BudgetDimension::Bytes.label(), "bytes");
        assert_eq!(BudgetDimension::Symbols.label(), "symbols");
        assert_eq!(BudgetDimension::FailedAuth.label(), "failed_auth");
        assert_eq!(BudgetDimension::InflightDecode.label(), "inflight_decode");
        assert_eq!(BudgetDimension::DecodeCpu.label(), "decode_cpu");
    }

    #[test]
    fn decode_start_at_saturated_counter_rejects_without_decrementing() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        tracker.peers.insert(
            "p-max".to_string(),
            PeerUsage {
                inflight_decode_count: u32::MAX,
                ..Default::default()
            },
        );

        let err = tracker.record_decode_start("p-max").unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InflightExceeded {
                count: u32::MAX,
                limit: 5,
                ..
            }
        ));
        assert_eq!(tracker.get_usage("p-max").inflight_decode_count, u32::MAX);
    }

    #[test]
    fn decode_start_at_exact_limit_rejects_without_mutating_count() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        tracker.peers.insert(
            "p-limit".to_string(),
            PeerUsage {
                inflight_decode_count: 5,
                ..Default::default()
            },
        );

        let err = tracker.record_decode_start("p-limit").unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InflightExceeded {
                count: 6,
                limit: 5,
                ..
            }
        ));
        assert_eq!(tracker.get_usage("p-limit").inflight_decode_count, 5);
    }

    #[test]
    fn decode_complete_unknown_peer_does_not_create_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();

        tracker.record_decode_complete("ghost-peer");

        assert!(tracker.snapshot().is_empty());
        assert_eq!(tracker.get_usage("ghost-peer").inflight_decode_count, 0);
    }

    #[test]
    fn reset_unknown_peer_keeps_existing_peer_usage() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("kept-peer", 100, 50, 25);
        assert!(tracker.admit(&req, "tr", "ts").0.admitted);

        tracker.reset_peer("missing-peer");

        let usage = tracker.get_usage("kept-peer");
        assert_eq!(usage.bytes_used, 100);
        assert_eq!(usage.symbols_used, 50);
        assert_eq!(usage.decode_cpu_ms, 25);
    }

    #[test]
    fn update_budget_rejects_zero_failed_auth_without_replacing_current_config() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let mut invalid = budget();
        invalid.max_failed_auth = 0;

        let err = tracker.update_budget(invalid).unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InvalidBudget { reason } if reason.contains("max_failed_auth")
        ));
        assert_eq!(tracker.budget().max_failed_auth, 3);
    }

    #[test]
    fn update_budget_rejects_zero_inflight_without_replacing_current_config() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let mut invalid = budget();
        invalid.max_inflight_decode = 0;

        let err = tracker.update_budget(invalid).unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InvalidBudget { reason } if reason.contains("max_inflight_decode")
        ));
        assert_eq!(tracker.budget().max_inflight_decode, 5);
    }

    #[test]
    fn stateless_check_rejects_zero_cpu_budget_with_specific_reason() {
        let usage = PeerUsage::default();
        let req = request("p-stateless", 1, 1, 1);
        let mut invalid = budget();
        invalid.max_decode_cpu_ms = 0;

        let err = check_admission_stateless(&req, &usage, &invalid, "tr", "ts").unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InvalidBudget { reason } if reason.contains("max_decode_cpu_ms")
        ));
    }

    #[test]
    fn update_budget_rejects_zero_bytes_without_replacing_current_config() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let mut invalid = budget();
        invalid.max_bytes = 0;

        let err = tracker.update_budget(invalid).unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InvalidBudget { reason } if reason.contains("max_bytes")
        ));
        assert_eq!(tracker.budget().max_bytes, 1000);
        assert_eq!(tracker.budget().max_symbols, 500);
    }

    #[test]
    fn update_budget_rejects_zero_decode_cpu_without_replacing_current_config() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let mut invalid = budget();
        invalid.max_decode_cpu_ms = 0;

        let err = tracker.update_budget(invalid).unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InvalidBudget { reason } if reason.contains("max_decode_cpu_ms")
        ));
        assert_eq!(tracker.budget().max_decode_cpu_ms, 2000);
        assert_eq!(tracker.budget().max_bytes, 1000);
    }

    #[test]
    fn stateless_check_rejects_zero_symbols_budget_with_specific_reason() {
        let usage = PeerUsage::default();
        let req = request("p-stateless", 1, 1, 1);
        let mut invalid = budget();
        invalid.max_symbols = 0;

        let err = check_admission_stateless(&req, &usage, &invalid, "tr", "ts").unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InvalidBudget { reason } if reason.contains("max_symbols")
        ));
    }

    #[test]
    fn stateless_check_rejects_zero_inflight_budget_with_specific_reason() {
        let usage = PeerUsage::default();
        let req = request("p-stateless", 1, 1, 1);
        let mut invalid = budget();
        invalid.max_inflight_decode = 0;

        let err = check_admission_stateless(&req, &usage, &invalid, "tr", "ts").unwrap_err();

        assert!(matches!(
            err,
            AdmissionError::InvalidBudget { reason } if reason.contains("max_inflight_decode")
        ));
    }

    #[test]
    fn overbudget_existing_usage_reports_zero_remaining_and_failed_records() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        tracker.peers.insert(
            "p-over".to_string(),
            PeerUsage {
                bytes_used: 1001,
                symbols_used: 501,
                decode_cpu_ms: 2001,
                ..Default::default()
            },
        );

        let (verdict, records) =
            tracker.check_admission(&request("p-over", 0, 0, 0), "tr-over", "ts-over");

        assert!(!verdict.admitted);
        assert_eq!(verdict.remaining.bytes_remaining, 0);
        assert_eq!(verdict.remaining.symbols_remaining, 0);
        assert_eq!(verdict.remaining.decode_cpu_remaining, 0);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::Bytes)
        );
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::Symbols)
        );
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::DecodeCpu)
        );
        assert!(records.iter().any(|record| {
            record.dimension.as_str() == "bytes"
                && record.usage_before == 1001
                && record.verdict.as_str() == "FAIL"
        }));
    }

    #[test]
    fn failed_auth_blocked_admit_does_not_mutate_resource_counters() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        for _ in 0..3 {
            tracker.record_failed_auth("p-auth-block").unwrap();
        }

        let (verdict, _) = tracker.admit(
            &request("p-auth-block", 100, 50, 25),
            "tr-block",
            "ts-block",
        );

        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::FailedAuth)
        );
        let usage = tracker.get_usage("p-auth-block");
        assert_eq!(usage.bytes_used, 0);
        assert_eq!(usage.symbols_used, 0);
        assert_eq!(usage.decode_cpu_ms, 0);
        assert_eq!(usage.failed_auth_count, 3);
    }

    #[test]
    fn inflight_blocked_admit_does_not_mutate_resource_counters() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        for _ in 0..5 {
            tracker.record_decode_start("p-inflight-block").unwrap();
        }

        let (verdict, _) = tracker.admit(
            &request("p-inflight-block", 100, 50, 25),
            "tr-block",
            "ts-block",
        );

        assert!(!verdict.admitted);
        assert!(
            verdict
                .violated_dimensions
                .contains(&BudgetDimension::InflightDecode)
        );
        let usage = tracker.get_usage("p-inflight-block");
        assert_eq!(usage.bytes_used, 0);
        assert_eq!(usage.symbols_used, 0);
        assert_eq!(usage.decode_cpu_ms, 0);
        assert_eq!(usage.inflight_decode_count, 5);
    }

    #[test]
    fn tighter_budget_rejects_existing_usage_on_next_admission() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        assert!(
            tracker
                .admit(&request("p-tight", 900, 100, 100), "tr", "ts")
                .0
                .admitted
        );
        let mut tighter = budget();
        tighter.max_bytes = 800;
        tracker.update_budget(tighter).unwrap();

        let (verdict, records) =
            tracker.admit(&request("p-tight", 1, 0, 0), "tr-tight", "ts-tight");

        assert!(!verdict.admitted);
        assert_eq!(verdict.remaining.bytes_remaining, 0);
        assert_eq!(tracker.get_usage("p-tight").bytes_used, 900);
        assert!(records.iter().any(|record| {
            record.dimension.as_str() == "bytes"
                && record.usage_before == 900
                && record.limit == 800
                && record.verdict.as_str() == "FAIL"
        }));
    }
}
