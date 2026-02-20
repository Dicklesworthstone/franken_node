//! bd-2k74: Per-peer admission budgets (bytes/symbols/failed-auth/inflight-decode/decode-cpu).
//!
//! Enforces multi-dimensional budgets per peer. Limit breaches are rejected and logged.
//! Budgets are configurable at runtime without code changes.

use std::collections::HashMap;

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
    BytesExceeded { peer_id: String, used: u64, limit: u64 },
    SymbolsExceeded { peer_id: String, used: u64, limit: u64 },
    AuthExceeded { peer_id: String, count: u32, limit: u32 },
    InflightExceeded { peer_id: String, count: u32, limit: u32 },
    CpuExceeded { peer_id: String, used: u64, limit: u64 },
    InvalidBudget { reason: String },
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
            Self::BytesExceeded { peer_id, used, limit } =>
                write!(f, "PAB_BYTES_EXCEEDED: peer={peer_id} used={used} limit={limit}"),
            Self::SymbolsExceeded { peer_id, used, limit } =>
                write!(f, "PAB_SYMBOLS_EXCEEDED: peer={peer_id} used={used} limit={limit}"),
            Self::AuthExceeded { peer_id, count, limit } =>
                write!(f, "PAB_AUTH_EXCEEDED: peer={peer_id} count={count} limit={limit}"),
            Self::InflightExceeded { peer_id, count, limit } =>
                write!(f, "PAB_INFLIGHT_EXCEEDED: peer={peer_id} count={count} limit={limit}"),
            Self::CpuExceeded { peer_id, used, limit } =>
                write!(f, "PAB_CPU_EXCEEDED: peer={peer_id} used={used} limit={limit}"),
            Self::InvalidBudget { reason } =>
                write!(f, "PAB_INVALID_BUDGET: {reason}"),
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
    peers: HashMap<String, PeerUsage>,
}

impl AdmissionBudgetTracker {
    pub fn new(budget: AdmissionBudget) -> Result<Self, AdmissionError> {
        validate_budget(&budget)?;
        Ok(Self {
            budget,
            peers: HashMap::new(),
        })
    }

    /// Record a failed auth attempt for a peer.
    pub fn record_failed_auth(&mut self, peer_id: &str) -> Result<(), AdmissionError> {
        let usage = self.peers.entry(peer_id.to_string()).or_default();
        usage.failed_auth_count += 1;
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
        usage.inflight_decode_count += 1;
        if usage.inflight_decode_count > self.budget.max_inflight_decode {
            usage.inflight_decode_count -= 1;
            return Err(AdmissionError::InflightExceeded {
                peer_id: peer_id.to_string(),
                count: usage.inflight_decode_count + 1,
                limit: self.budget.max_inflight_decode,
            });
        }
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
        let usage = self.peers.get(&request.peer_id).cloned().unwrap_or_default();
        let mut violations = Vec::new();
        let mut records = Vec::new();

        // Dimension 1: bytes
        let bytes_after = usage.bytes_used + request.bytes_requested;
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
        let symbols_after = usage.symbols_used + request.symbols_requested;
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
        let cpu_after = usage.decode_cpu_ms + request.decode_cpu_estimate_ms;
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
            failed_auth_remaining: self.budget.max_failed_auth.saturating_sub(usage.failed_auth_count),
            inflight_decode_remaining: self.budget.max_inflight_decode.saturating_sub(usage.inflight_decode_count),
            decode_cpu_remaining: self.budget.max_decode_cpu_ms.saturating_sub(usage.decode_cpu_ms),
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
            usage.bytes_used += request.bytes_requested;
            usage.symbols_used += request.symbols_requested;
            usage.decode_cpu_ms += request.decode_cpu_estimate_ms;
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
        peers: HashMap::new(),
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
        assert!(verdict.violated_dimensions.contains(&BudgetDimension::Bytes));
    }

    #[test]
    fn reject_symbols_exceeded() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 0, 501, 0);
        let (verdict, _) = tracker.admit(&req, "tr", "ts");
        assert!(!verdict.admitted);
        assert!(verdict.violated_dimensions.contains(&BudgetDimension::Symbols));
    }

    #[test]
    fn reject_cpu_exceeded() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        let req = request("p1", 0, 0, 2001);
        let (verdict, _) = tracker.admit(&req, "tr", "ts");
        assert!(!verdict.admitted);
        assert!(verdict.violated_dimensions.contains(&BudgetDimension::DecodeCpu));
    }

    #[test]
    fn reject_failed_auth() {
        let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
        // Exhaust failed auth budget
        for _ in 0..3 {
            let _ = tracker.record_failed_auth("p1");
        }
        let req = request("p1", 10, 10, 10);
        let (verdict, _) = tracker.check_admission(&req, "tr", "ts");
        assert!(!verdict.admitted);
        assert!(verdict.violated_dimensions.contains(&BudgetDimension::FailedAuth));
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
        assert!(verdict.violated_dimensions.contains(&BudgetDimension::InflightDecode));
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
        assert_eq!(AdmissionError::BytesExceeded { peer_id: "".into(), used: 0, limit: 0 }.code(), "PAB_BYTES_EXCEEDED");
        assert_eq!(AdmissionError::SymbolsExceeded { peer_id: "".into(), used: 0, limit: 0 }.code(), "PAB_SYMBOLS_EXCEEDED");
        assert_eq!(AdmissionError::AuthExceeded { peer_id: "".into(), count: 0, limit: 0 }.code(), "PAB_AUTH_EXCEEDED");
        assert_eq!(AdmissionError::InflightExceeded { peer_id: "".into(), count: 0, limit: 0 }.code(), "PAB_INFLIGHT_EXCEEDED");
        assert_eq!(AdmissionError::CpuExceeded { peer_id: "".into(), used: 0, limit: 0 }.code(), "PAB_CPU_EXCEEDED");
        assert_eq!(AdmissionError::InvalidBudget { reason: "".into() }.code(), "PAB_INVALID_BUDGET");
    }

    #[test]
    fn error_display() {
        let e = AdmissionError::BytesExceeded { peer_id: "p1".into(), used: 1100, limit: 1000 };
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
        let usage = PeerUsage { bytes_used: 500, ..Default::default() };
        let req = request("p1", 600, 0, 0);
        let (verdict, _) = check_admission_stateless(&req, &usage, &budget(), "tr", "ts").unwrap();
        assert!(!verdict.admitted);
        assert!(verdict.violated_dimensions.contains(&BudgetDimension::Bytes));
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
}
