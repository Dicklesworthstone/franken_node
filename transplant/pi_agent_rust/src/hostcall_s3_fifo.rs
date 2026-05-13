//! Deterministic S3-FIFO-inspired admission policy for hostcall queues.
//!
//! This module models a tri-queue policy core that can be wired into the
//! hostcall queue runtime:
//! - `small`: probationary live entries
//! - `main`: protected live entries
//! - `ghost`: recently evicted identifiers for cheap reuse signals
//!
//! It is intentionally runtime-agnostic and side-effect free beyond state
//! mutations, so integration code can compose it with existing queue and
//! telemetry paths.

#[cfg(test)]
use std::collections::BTreeSet;
use std::collections::{BTreeMap, VecDeque};

/// Fallback trigger reason when S3-FIFO policy is disabled at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3FifoFallbackReason {
    SignalQualityInsufficient,
    FairnessInstability,
}

/// Where a key ends up after one policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3FifoTier {
    Small,
    Main,
    Ghost,
    Fallback,
}

/// Deterministic decision kind from one `access` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3FifoDecisionKind {
    AdmitSmall,
    PromoteSmallToMain,
    HitMain,
    AdmitFromGhost,
    RejectFairnessBudget,
    FallbackBypass,
}

/// Decision payload produced by [`S3FifoPolicy::access`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S3FifoDecision {
    pub kind: S3FifoDecisionKind,
    pub tier: S3FifoTier,
    pub ghost_hit: bool,
    pub fallback_reason: Option<S3FifoFallbackReason>,
    pub live_depth: usize,
    pub small_depth: usize,
    pub main_depth: usize,
    pub ghost_depth: usize,
}

/// Configuration for deterministic S3-FIFO policy behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S3FifoConfig {
    pub live_capacity: usize,
    pub small_capacity: usize,
    pub ghost_capacity: usize,
    pub max_entries_per_owner: usize,
    pub fallback_window: usize,
    pub min_ghost_hits_in_window: usize,
    pub max_budget_rejections_in_window: usize,
}

impl Default for S3FifoConfig {
    fn default() -> Self {
        Self {
            live_capacity: 256,
            small_capacity: 64,
            ghost_capacity: 512,
            max_entries_per_owner: 64,
            fallback_window: 32,
            min_ghost_hits_in_window: 2,
            max_budget_rejections_in_window: 12,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveTier {
    Small,
    Main,
}

#[derive(Debug, Clone, Copy)]
struct DecisionSignal {
    ghost_hit: bool,
    budget_rejected: bool,
}

/// Snapshot for logs and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3FifoTelemetry {
    pub fallback_reason: Option<S3FifoFallbackReason>,
    pub small_depth: usize,
    pub main_depth: usize,
    pub ghost_depth: usize,
    pub live_depth: usize,
    pub ghost_hits_total: u64,
    pub admissions_total: u64,
    pub promotions_total: u64,
    pub budget_rejections_total: u64,
    pub owner_live_counts: BTreeMap<String, usize>,
}

/// Deterministic S3-FIFO-inspired tri-queue admission controller.
#[derive(Debug, Clone)]
pub struct S3FifoPolicy<K: Ord + Clone> {
    cfg: S3FifoConfig,
    small: VecDeque<K>,
    main: VecDeque<K>,
    ghost_order: BTreeMap<u64, K>,
    ghost_lookup: BTreeMap<K, u64>,
    ghost_gen: u64,
    live_tiers: BTreeMap<K, LiveTier>,
    live_owners: BTreeMap<K, String>,
    owner_live_counts: BTreeMap<String, usize>,
    recent_signals: VecDeque<DecisionSignal>,
    fallback_reason: Option<S3FifoFallbackReason>,
    ghost_hits_total: u64,
    admissions_total: u64,
    promotions_total: u64,
    budget_rejections_total: u64,
}

impl<K: Ord + Clone> S3FifoPolicy<K> {
    #[must_use]
    pub fn new(config: S3FifoConfig) -> Self {
        let live_capacity = config.live_capacity.max(2);
        let small_cap_floor = live_capacity.saturating_sub(1).max(1);
        let small_capacity = config.small_capacity.max(1).min(small_cap_floor);
        let ghost_capacity = config.ghost_capacity.max(1);
        let max_entries_per_owner = config.max_entries_per_owner.max(1);
        let fallback_window = config.fallback_window.max(1);

        Self {
            cfg: S3FifoConfig {
                live_capacity,
                small_capacity,
                ghost_capacity,
                max_entries_per_owner,
                fallback_window,
                min_ghost_hits_in_window: config.min_ghost_hits_in_window.min(fallback_window),
                max_budget_rejections_in_window: config
                    .max_budget_rejections_in_window
                    .min(fallback_window),
            },
            small: VecDeque::new(),
            main: VecDeque::new(),
            ghost_order: BTreeMap::new(),
            ghost_lookup: BTreeMap::new(),
            ghost_gen: 0,
            live_tiers: BTreeMap::new(),
            live_owners: BTreeMap::new(),
            owner_live_counts: BTreeMap::new(),
            recent_signals: VecDeque::new(),
            fallback_reason: None,
            ghost_hits_total: 0,
            admissions_total: 0,
            promotions_total: 0,
            budget_rejections_total: 0,
        }
    }

    #[must_use]
    pub const fn config(&self) -> S3FifoConfig {
        self.cfg
    }

    #[must_use]
    pub fn telemetry(&self) -> S3FifoTelemetry {
        S3FifoTelemetry {
            fallback_reason: self.fallback_reason,
            small_depth: self.small.len(),
            main_depth: self.main.len(),
            ghost_depth: self.ghost_lookup.len(),
            live_depth: self.live_depth(),
            ghost_hits_total: self.ghost_hits_total,
            admissions_total: self.admissions_total,
            promotions_total: self.promotions_total,
            budget_rejections_total: self.budget_rejections_total,
            owner_live_counts: self.owner_live_counts.clone(),
        }
    }

    #[must_use]
    pub fn live_depth(&self) -> usize {
        self.small.len().saturating_add(self.main.len())
    }

    pub fn clear_fallback(&mut self) {
        self.fallback_reason = None;
        self.recent_signals.clear();
    }

    pub fn access(&mut self, owner: &str, key: K) -> S3FifoDecision {
        if let Some(reason) = self.fallback_reason {
            return self.decision(
                S3FifoDecisionKind::FallbackBypass,
                S3FifoTier::Fallback,
                false,
                Some(reason),
            );
        }

        let mut ghost_hit = false;
        let kind = if matches!(self.live_tiers.get(&key), Some(LiveTier::Main)) {
            self.touch_main(&key);
            S3FifoDecisionKind::HitMain
        } else if matches!(self.live_tiers.get(&key), Some(LiveTier::Small)) {
            self.promote_small_to_main(&key);
            self.promotions_total = self.promotions_total.saturating_add(1);
            S3FifoDecisionKind::PromoteSmallToMain
        } else if self.ghost_lookup.contains_key(&key) {
            ghost_hit = true;
            self.ghost_hits_total = self.ghost_hits_total.saturating_add(1);
            if self.owner_at_budget(owner) {
                self.budget_rejections_total = self.budget_rejections_total.saturating_add(1);
                S3FifoDecisionKind::RejectFairnessBudget
            } else {
                self.admit_from_ghost(owner, key);
                self.admissions_total = self.admissions_total.saturating_add(1);
                S3FifoDecisionKind::AdmitFromGhost
            }
        } else if self.owner_at_budget(owner) {
            self.budget_rejections_total = self.budget_rejections_total.saturating_add(1);
            S3FifoDecisionKind::RejectFairnessBudget
        } else {
            self.admit_small(owner, key);
            self.admissions_total = self.admissions_total.saturating_add(1);
            S3FifoDecisionKind::AdmitSmall
        };

        let signal = DecisionSignal {
            ghost_hit,
            budget_rejected: kind == S3FifoDecisionKind::RejectFairnessBudget,
        };
        self.record_signal(signal);
        self.evaluate_fallback();

        let tier = Self::resolve_tier(kind, ghost_hit);
        self.decision(kind, tier, ghost_hit, self.fallback_reason)
    }

    const fn resolve_tier(kind: S3FifoDecisionKind, ghost_hit: bool) -> S3FifoTier {
        match kind {
            S3FifoDecisionKind::HitMain
            | S3FifoDecisionKind::PromoteSmallToMain
            | S3FifoDecisionKind::AdmitFromGhost => S3FifoTier::Main,
            S3FifoDecisionKind::AdmitSmall => S3FifoTier::Small,
            S3FifoDecisionKind::RejectFairnessBudget => {
                if ghost_hit {
                    S3FifoTier::Ghost
                } else {
                    S3FifoTier::Small
                }
            }
            S3FifoDecisionKind::FallbackBypass => S3FifoTier::Fallback,
        }
    }

    fn decision(
        &self,
        kind: S3FifoDecisionKind,
        tier: S3FifoTier,
        ghost_hit: bool,
        fallback_reason: Option<S3FifoFallbackReason>,
    ) -> S3FifoDecision {
        S3FifoDecision {
            kind,
            tier,
            ghost_hit,
            fallback_reason,
            live_depth: self.live_depth(),
            small_depth: self.small.len(),
            main_depth: self.main.len(),
            ghost_depth: self.ghost_lookup.len(),
        }
    }

    fn owner_at_budget(&self, owner: &str) -> bool {
        self.owner_live_counts.get(owner).copied().unwrap_or(0) >= self.cfg.max_entries_per_owner
    }

    const fn main_capacity(&self) -> usize {
        self.cfg
            .live_capacity
            .saturating_sub(self.cfg.small_capacity)
    }

    fn admit_small(&mut self, owner: &str, key: K) {
        self.purge_key(&key);
        self.small.push_back(key.clone());
        self.live_tiers.insert(key.clone(), LiveTier::Small);
        self.live_owners.insert(key, owner.to_string());
        self.increment_owner(owner);
        self.enforce_small_capacity();
        self.enforce_live_capacity();
    }

    fn admit_from_ghost(&mut self, owner: &str, key: K) {
        self.remove_ghost(&key);
        self.main.push_back(key.clone());
        self.live_tiers.insert(key.clone(), LiveTier::Main);
        self.live_owners.insert(key, owner.to_string());
        self.increment_owner(owner);
        self.enforce_main_capacity();
        self.enforce_live_capacity();
    }

    fn promote_small_to_main(&mut self, key: &K) {
        remove_from_queue(&mut self.small, key);
        self.main.push_back(key.clone());
        self.live_tiers.insert(key.clone(), LiveTier::Main);
        self.enforce_main_capacity();
        self.enforce_live_capacity();
    }

    fn touch_main(&mut self, key: &K) {
        remove_from_queue(&mut self.main, key);
        self.main.push_back(key.clone());
    }

    fn enforce_small_capacity(&mut self) {
        while self.small.len() > self.cfg.small_capacity {
            self.evict_small_front_to_ghost();
        }
    }

    fn enforce_main_capacity(&mut self) {
        while self.main.len() > self.main_capacity() {
            self.evict_main_front_to_ghost();
        }
    }

    fn enforce_live_capacity(&mut self) {
        while self.live_depth() > self.cfg.live_capacity {
            if self.small.is_empty() {
                self.evict_main_front_to_ghost();
            } else {
                self.evict_small_front_to_ghost();
            }
        }
    }

    fn evict_small_front_to_ghost(&mut self) {
        if let Some(key) = self.small.pop_front() {
            self.live_tiers.remove(&key);
            self.remove_owner_for_key(&key);
            self.push_ghost(key);
        }
    }

    fn evict_main_front_to_ghost(&mut self) {
        if let Some(key) = self.main.pop_front() {
            self.live_tiers.remove(&key);
            self.remove_owner_for_key(&key);
            self.push_ghost(key);
        }
    }

    fn purge_key(&mut self, key: &K) {
        self.remove_live_key(key);
        self.remove_ghost(key);
    }

    fn remove_live_key(&mut self, key: &K) {
        if let Some(tier) = self.live_tiers.remove(key) {
            match tier {
                LiveTier::Small => remove_from_queue(&mut self.small, key),
                LiveTier::Main => remove_from_queue(&mut self.main, key),
            }
            self.remove_owner_for_key(key);
        }
    }

    fn remove_owner_for_key(&mut self, key: &K) {
        if let Some(owner) = self.live_owners.remove(key) {
            self.decrement_owner(&owner);
        }
    }

    fn push_ghost(&mut self, key: K) {
        // Prevent generation overflow.
        if self.ghost_gen == u64::MAX {
            self.ghost_gen = 0;
            self.ghost_order.clear();
            self.ghost_lookup.clear();
        }

        self.ghost_gen = self.ghost_gen.saturating_add(1);

        if let Some(gen_mut) = self.ghost_lookup.get_mut(&key) {
            let old_gen = *gen_mut;
            *gen_mut = self.ghost_gen;
            if let Some(k_reused) = self.ghost_order.remove(&old_gen) {
                self.ghost_order.insert(self.ghost_gen, k_reused);
            }
        } else {
            self.ghost_lookup.insert(key.clone(), self.ghost_gen);
            self.ghost_order.insert(self.ghost_gen, key);
        }

        while self.ghost_lookup.len() > self.cfg.ghost_capacity {
            if let Some((_, popped_key)) = self.ghost_order.pop_first() {
                self.ghost_lookup.remove(&popped_key);
            } else {
                break;
            }
        }
    }

    fn remove_ghost(&mut self, key: &K) {
        if let Some(generation) = self.ghost_lookup.remove(key) {
            self.ghost_order.remove(&generation);
        }
    }

    fn increment_owner(&mut self, owner: &str) {
        if let Some(count) = self.owner_live_counts.get_mut(owner) {
            *count = count.saturating_add(1);
        } else {
            self.owner_live_counts.insert(owner.to_string(), 1);
        }
    }

    fn decrement_owner(&mut self, owner: &str) {
        let should_remove = self.owner_live_counts.get_mut(owner).is_some_and(|count| {
            if *count > 1 {
                *count -= 1;
                false
            } else {
                true
            }
        });

        if should_remove {
            self.owner_live_counts.remove(owner);
        }
    }

    fn record_signal(&mut self, signal: DecisionSignal) {
        self.recent_signals.push_back(signal);
        while self.recent_signals.len() > self.cfg.fallback_window {
            self.recent_signals.pop_front();
        }
    }

    fn evaluate_fallback(&mut self) {
        if self.fallback_reason.is_some() || self.recent_signals.len() < self.cfg.fallback_window {
            return;
        }

        let mut ghost_hits = 0usize;
        let mut budget_rejections = 0usize;
        for signal in &self.recent_signals {
            if signal.ghost_hit {
                ghost_hits = ghost_hits.saturating_add(1);
            }
            if signal.budget_rejected {
                budget_rejections = budget_rejections.saturating_add(1);
            }
        }

        if ghost_hits < self.cfg.min_ghost_hits_in_window {
            self.fallback_reason = Some(S3FifoFallbackReason::SignalQualityInsufficient);
        } else if budget_rejections > self.cfg.max_budget_rejections_in_window {
            self.fallback_reason = Some(S3FifoFallbackReason::FairnessInstability);
        }
    }
}

fn remove_from_queue<K: Ord>(queue: &mut VecDeque<K>, key: &K) {
    if let Some(index) = queue.iter().position(|existing| existing == key) {
        queue.remove(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> S3FifoConfig {
        S3FifoConfig {
            live_capacity: 4,
            small_capacity: 2,
            ghost_capacity: 4,
            max_entries_per_owner: 2,
            fallback_window: 4,
            min_ghost_hits_in_window: 1,
            max_budget_rejections_in_window: 2,
        }
    }

    fn assert_no_duplicates(policy: &S3FifoPolicy<String>) {
        let small: BTreeSet<_> = policy.small.iter().cloned().collect();
        let main: BTreeSet<_> = policy.main.iter().cloned().collect();
        let ghost: BTreeSet<_> = policy.ghost_lookup.keys().cloned().collect();

        assert!(small.is_disjoint(&main));
        assert!(small.is_disjoint(&ghost));
        assert!(main.is_disjoint(&ghost));
        assert_eq!(small.len() + main.len(), policy.live_tiers.len());
    }

    #[test]
    fn small_hit_promotes_to_main() {
        let mut policy = S3FifoPolicy::new(config());
        let first = policy.access("ext-a", "k1".to_string());
        assert_eq!(first.kind, S3FifoDecisionKind::AdmitSmall);

        let second = policy.access("ext-a", "k1".to_string());
        assert_eq!(second.kind, S3FifoDecisionKind::PromoteSmallToMain);
        assert_eq!(second.tier, S3FifoTier::Main);
        assert_eq!(second.main_depth, 1);
        assert_eq!(second.small_depth, 0);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn ghost_hit_reenters_live_set() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            small_capacity: 1,
            ..config()
        });

        policy.access("ext-a", "k1".to_string());
        policy.access("ext-a", "k2".to_string());
        let decision = policy.access("ext-a", "k1".to_string());

        assert_eq!(decision.kind, S3FifoDecisionKind::AdmitFromGhost);
        assert!(decision.ghost_hit);
        assert_eq!(decision.tier, S3FifoTier::Main);
        assert_eq!(policy.telemetry().ghost_hits_total, 1);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn fairness_budget_rejects_owner_overflow() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            max_entries_per_owner: 1,
            ..config()
        });

        let admitted = policy.access("ext-a", "k1".to_string());
        let rejected = policy.access("ext-a", "k2".to_string());

        assert_eq!(admitted.kind, S3FifoDecisionKind::AdmitSmall);
        assert_eq!(rejected.kind, S3FifoDecisionKind::RejectFairnessBudget);
        assert_eq!(policy.live_depth(), 1);
        assert_eq!(policy.telemetry().budget_rejections_total, 1);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn fallback_triggers_on_low_signal_quality() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            min_ghost_hits_in_window: 2,
            fallback_window: 4,
            ..config()
        });

        for idx in 0..4 {
            let key = format!("cold-{idx}");
            let _ = policy.access("ext-a", key);
        }

        assert_eq!(
            policy.telemetry().fallback_reason,
            Some(S3FifoFallbackReason::SignalQualityInsufficient)
        );

        let bypass = policy.access("ext-a", "late-key".to_string());
        assert_eq!(bypass.kind, S3FifoDecisionKind::FallbackBypass);
        assert_eq!(bypass.tier, S3FifoTier::Fallback);
    }

    #[test]
    fn fallback_triggers_on_rejection_spike() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            max_entries_per_owner: 1,
            fallback_window: 3,
            min_ghost_hits_in_window: 0,
            max_budget_rejections_in_window: 1,
            ..config()
        });

        let _ = policy.access("ext-a", "k1".to_string());
        let _ = policy.access("ext-a", "k2".to_string());
        let _ = policy.access("ext-a", "k3".to_string());

        assert_eq!(
            policy.telemetry().fallback_reason,
            Some(S3FifoFallbackReason::FairnessInstability)
        );
    }

    #[test]
    fn fallback_latches_until_clear_and_reason_stays_stable() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            min_ghost_hits_in_window: 3,
            fallback_window: 3,
            ..config()
        });

        // Trigger low-signal fallback (no ghost hits across a full window).
        let _ = policy.access("ext-a", "k1".to_string());
        let _ = policy.access("ext-a", "k2".to_string());
        let _ = policy.access("ext-a", "k3".to_string());

        let expected_reason = Some(S3FifoFallbackReason::SignalQualityInsufficient);
        assert_eq!(policy.telemetry().fallback_reason, expected_reason);

        // Once fallback is active, every decision should remain a bypass with the same reason
        // until `clear_fallback` is explicitly invoked.
        for key in ["k4", "k5", "k6"] {
            let decision = policy.access("ext-b", key.to_string());
            assert_eq!(decision.kind, S3FifoDecisionKind::FallbackBypass);
            assert_eq!(decision.tier, S3FifoTier::Fallback);
            assert_eq!(decision.fallback_reason, expected_reason);
            assert_eq!(policy.telemetry().fallback_reason, expected_reason);
        }

        policy.clear_fallback();
        assert_eq!(policy.telemetry().fallback_reason, None);

        let post_clear = policy.access("ext-b", "k7".to_string());
        assert_ne!(post_clear.kind, S3FifoDecisionKind::FallbackBypass);
    }

    #[test]
    fn fairness_fallback_reports_same_reason_during_repeated_bypass() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            max_entries_per_owner: 1,
            fallback_window: 3,
            min_ghost_hits_in_window: 0,
            max_budget_rejections_in_window: 1,
            ..config()
        });

        // Trigger fairness-instability fallback via repeated budget rejections.
        let _ = policy.access("ext-a", "k1".to_string());
        let _ = policy.access("ext-a", "k2".to_string());
        let _ = policy.access("ext-a", "k3".to_string());

        let expected_reason = Some(S3FifoFallbackReason::FairnessInstability);
        assert_eq!(policy.telemetry().fallback_reason, expected_reason);

        for key in ["k4", "k5"] {
            let decision = policy.access("ext-c", key.to_string());
            assert_eq!(decision.kind, S3FifoDecisionKind::FallbackBypass);
            assert_eq!(decision.fallback_reason, expected_reason);
            assert_eq!(policy.telemetry().fallback_reason, expected_reason);
        }
    }

    #[test]
    fn fallback_reason_transitions_low_signal_to_fairness_after_clear() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            live_capacity: 2,
            small_capacity: 1,
            ghost_capacity: 4,
            max_entries_per_owner: 1,
            fallback_window: 3,
            min_ghost_hits_in_window: 1,
            max_budget_rejections_in_window: 1,
        });

        // First epoch: no ghost hits across a full window -> low-signal fallback.
        let _ = policy.access("ext-a", "ls-live-1".to_string());
        let _ = policy.access("ext-b", "ls-ghost-seed".to_string());
        let _ = policy.access("ext-a", "ls-live-2".to_string());

        let low_signal_reason = Some(S3FifoFallbackReason::SignalQualityInsufficient);
        assert_eq!(policy.telemetry().fallback_reason, low_signal_reason);
        let low_signal_bypass = policy.access("ext-z", "ls-bypass".to_string());
        assert_eq!(low_signal_bypass.kind, S3FifoDecisionKind::FallbackBypass);
        assert_eq!(low_signal_bypass.fallback_reason, low_signal_reason);

        policy.clear_fallback();
        assert_eq!(policy.telemetry().fallback_reason, None);

        // Second epoch: one ghost-hit rejection + two direct rejections -> fairness fallback.
        let first = policy.access("ext-a", "ls-live-1".to_string());
        assert_eq!(first.kind, S3FifoDecisionKind::RejectFairnessBudget);
        assert!(first.ghost_hit);
        let _ = policy.access("ext-a", "fair-rej-1".to_string());
        let _ = policy.access("ext-a", "fair-rej-2".to_string());

        let fairness_reason = Some(S3FifoFallbackReason::FairnessInstability);
        assert_eq!(policy.telemetry().fallback_reason, fairness_reason);
        let fairness_bypass = policy.access("ext-z", "fair-bypass".to_string());
        assert_eq!(fairness_bypass.kind, S3FifoDecisionKind::FallbackBypass);
        assert_eq!(fairness_bypass.fallback_reason, fairness_reason);
    }

    #[test]
    fn fallback_reason_transitions_fairness_to_low_signal_after_clear() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            live_capacity: 2,
            small_capacity: 1,
            ghost_capacity: 4,
            max_entries_per_owner: 1,
            fallback_window: 3,
            min_ghost_hits_in_window: 1,
            max_budget_rejections_in_window: 0,
        });

        // First epoch: produce one ghost-hit budget rejection -> fairness fallback.
        let _ = policy.access("ext-b", "ff-ghost-seed".to_string());
        let _ = policy.access("ext-a", "ff-live".to_string());
        let trigger = policy.access("ext-a", "ff-ghost-seed".to_string());
        assert_eq!(trigger.kind, S3FifoDecisionKind::RejectFairnessBudget);
        assert!(trigger.ghost_hit);

        let fairness_reason = Some(S3FifoFallbackReason::FairnessInstability);
        assert_eq!(policy.telemetry().fallback_reason, fairness_reason);
        let fairness_bypass = policy.access("ext-z", "ff-bypass".to_string());
        assert_eq!(fairness_bypass.kind, S3FifoDecisionKind::FallbackBypass);
        assert_eq!(fairness_bypass.fallback_reason, fairness_reason);

        policy.clear_fallback();
        assert_eq!(policy.telemetry().fallback_reason, None);

        // Second epoch: no ghost hits across window -> low-signal fallback.
        let _ = policy.access("ext-c", "ff-low-1".to_string());
        let _ = policy.access("ext-d", "ff-low-2".to_string());
        let _ = policy.access("ext-e", "ff-low-3".to_string());

        let low_signal_reason = Some(S3FifoFallbackReason::SignalQualityInsufficient);
        assert_eq!(policy.telemetry().fallback_reason, low_signal_reason);
        let low_signal_bypass = policy.access("ext-z", "ff-low-bypass".to_string());
        assert_eq!(low_signal_bypass.kind, S3FifoDecisionKind::FallbackBypass);
        assert_eq!(low_signal_bypass.fallback_reason, low_signal_reason);
    }

    #[test]
    fn single_window_clear_cycles_preserve_reason_precedence_and_bypass_counters() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            live_capacity: 4,
            small_capacity: 2,
            ghost_capacity: 4,
            max_entries_per_owner: 1,
            fallback_window: 1,
            min_ghost_hits_in_window: 1,
            max_budget_rejections_in_window: 0,
        });

        // Epoch 1: one low-signal admission should trip fallback immediately.
        let first = policy.access("ext-a", "cold-1".to_string());
        assert_eq!(first.kind, S3FifoDecisionKind::AdmitSmall);
        let low_signal_reason = Some(S3FifoFallbackReason::SignalQualityInsufficient);
        assert_eq!(policy.telemetry().fallback_reason, low_signal_reason);

        // Bypass while latched should not mutate accumulated counters.
        let low_baseline = policy.telemetry();
        let low_bypass = policy.access("ext-a", "low-bypass".to_string());
        assert_eq!(low_bypass.kind, S3FifoDecisionKind::FallbackBypass);
        let low_after = policy.telemetry();
        assert_eq!(low_after.ghost_hits_total, low_baseline.ghost_hits_total);
        assert_eq!(
            low_after.budget_rejections_total,
            low_baseline.budget_rejections_total
        );

        policy.clear_fallback();
        assert_eq!(policy.telemetry().fallback_reason, None);

        // Epoch 2: force a one-event ghost-hit budget rejection and verify fairness reason wins.
        policy.push_ghost("ghost-hot".to_string());
        policy
            .owner_live_counts
            .insert("ext-a".to_string(), policy.config().max_entries_per_owner);

        let fairness_trigger = policy.access("ext-a", "ghost-hot".to_string());
        assert_eq!(
            fairness_trigger.kind,
            S3FifoDecisionKind::RejectFairnessBudget
        );
        assert!(fairness_trigger.ghost_hit);

        let fairness_reason = Some(S3FifoFallbackReason::FairnessInstability);
        assert_eq!(policy.telemetry().fallback_reason, fairness_reason);

        // Bypass while fairness-latched should also keep counters stable.
        let fairness_baseline = policy.telemetry();
        let fairness_bypass = policy.access("ext-a", "fair-bypass".to_string());
        assert_eq!(fairness_bypass.kind, S3FifoDecisionKind::FallbackBypass);
        let fairness_after = policy.telemetry();
        assert_eq!(
            fairness_after.ghost_hits_total,
            fairness_baseline.ghost_hits_total
        );
        assert_eq!(
            fairness_after.budget_rejections_total,
            fairness_baseline.budget_rejections_total
        );
    }

    // ── Additional public API coverage ──

    #[test]
    fn config_clamps_minimums_and_ceilings() {
        let tiny = S3FifoConfig {
            live_capacity: 0,
            small_capacity: 0,
            ghost_capacity: 0,
            max_entries_per_owner: 0,
            fallback_window: 0,
            min_ghost_hits_in_window: 100,
            max_budget_rejections_in_window: 100,
        };
        let policy = S3FifoPolicy::<String>::new(tiny);
        let cfg = policy.config();
        assert!(cfg.live_capacity >= 2, "live_capacity min is 2");
        assert!(cfg.small_capacity >= 1, "small_capacity min is 1");
        assert!(cfg.ghost_capacity >= 1, "ghost_capacity min is 1");
        assert!(cfg.max_entries_per_owner >= 1, "per-owner min is 1");
        assert!(cfg.fallback_window >= 1, "fallback_window min is 1");
        // min_ghost_hits_in_window clamped to fallback_window
        assert!(cfg.min_ghost_hits_in_window <= cfg.fallback_window);
        // max_budget_rejections_in_window clamped to fallback_window
        assert!(cfg.max_budget_rejections_in_window <= cfg.fallback_window);
    }

    #[test]
    fn live_depth_reflects_small_plus_main() {
        let mut policy = S3FifoPolicy::new(config());
        assert_eq!(policy.live_depth(), 0);

        // Admit to small
        policy.access("ext-a", "k1".to_string());
        assert_eq!(policy.live_depth(), 1);

        // Admit another to small
        policy.access("ext-b", "k2".to_string());
        assert_eq!(policy.live_depth(), 2);

        // Promote k1 to main
        policy.access("ext-a", "k1".to_string());
        // k1 moved from small to main, live_depth unchanged
        assert_eq!(policy.live_depth(), 2);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn telemetry_counters_accumulate_correctly() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            small_capacity: 1,
            max_entries_per_owner: 3,
            ..config()
        });

        // 1 admission
        policy.access("ext-a", "k1".to_string());
        let tel = policy.telemetry();
        assert_eq!(tel.admissions_total, 1);
        assert_eq!(tel.promotions_total, 0);
        assert_eq!(tel.ghost_hits_total, 0);
        assert_eq!(tel.budget_rejections_total, 0);
        assert_eq!(tel.small_depth, 1);
        assert_eq!(tel.main_depth, 0);

        // Promote k1 small → main
        policy.access("ext-a", "k1".to_string());
        let tel = policy.telemetry();
        assert_eq!(tel.promotions_total, 1);
        assert_eq!(tel.small_depth, 0);
        assert_eq!(tel.main_depth, 1);

        // Admit k2 → small, evicts to ghost since small_capacity=1
        policy.access("ext-a", "k2".to_string());
        policy.access("ext-a", "k3".to_string());
        // k2 was evicted from small to ghost when k3 entered
        let tel = policy.telemetry();
        assert!(tel.ghost_depth >= 1, "evicted key should be in ghost");
    }

    #[test]
    fn telemetry_owner_live_counts_track_per_owner() {
        let mut policy = S3FifoPolicy::new(config());
        policy.access("ext-a", "k1".to_string());
        policy.access("ext-b", "k2".to_string());
        let tel = policy.telemetry();
        assert_eq!(tel.owner_live_counts.get("ext-a"), Some(&1));
        assert_eq!(tel.owner_live_counts.get("ext-b"), Some(&1));
    }

    #[test]
    fn hit_main_reorders_without_changing_depth() {
        // Use a large fallback_window so fallback doesn't trigger during setup
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            fallback_window: 32,
            min_ghost_hits_in_window: 0,
            ..config()
        });
        // Admit and promote both keys
        policy.access("ext-a", "k1".to_string());
        policy.access("ext-a", "k1".to_string()); // promote k1 to main
        policy.access("ext-b", "k2".to_string());
        policy.access("ext-b", "k2".to_string()); // promote k2 to main

        let before = policy.telemetry();
        let depth_before = before.main_depth;

        // HitMain on k1 — should just reorder, no depth change
        let decision = policy.access("ext-a", "k1".to_string());
        assert_eq!(decision.kind, S3FifoDecisionKind::HitMain);
        assert_eq!(policy.telemetry().main_depth, depth_before);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn ghost_queue_evicts_oldest_when_at_capacity() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            ghost_capacity: 2,
            small_capacity: 1,
            ..config()
        });

        // Fill small with different keys; each evicts the previous to ghost
        policy.access("ext-a", "k1".to_string()); // small: [k1]
        policy.access("ext-b", "k2".to_string()); // small: [k2], ghost: [k1]
        policy.access("ext-a", "k3".to_string()); // small: [k3], ghost: [k1, k2]
        assert_eq!(policy.telemetry().ghost_depth, 2);

        // One more eviction exceeds ghost_capacity=2 → k1 should be dropped
        policy.access("ext-b", "k4".to_string()); // small: [k4], ghost: [k2, k3]
        assert_eq!(policy.telemetry().ghost_depth, 2);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn push_ghost_reinsertion_updates_recency_without_duplicates() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            ghost_capacity: 2,
            ..config()
        });

        policy.push_ghost("k1".to_string());
        policy.push_ghost("k2".to_string());
        assert_eq!(
            policy.ghost_order.values().cloned().collect::<Vec<_>>(),
            vec!["k1".to_string(), "k2".to_string()]
        );
        assert_eq!(policy.ghost_lookup.len(), 2);

        // Re-inserting an existing ghost key should move it to the newest slot,
        // not duplicate it.
        policy.push_ghost("k1".to_string());
        assert_eq!(
            policy.ghost_order.values().cloned().collect::<Vec<_>>(),
            vec!["k2".to_string(), "k1".to_string()]
        );
        assert_eq!(policy.ghost_lookup.len(), 2);

        // Capacity enforcement still applies after recency updates.
        policy.push_ghost("k3".to_string());
        assert_eq!(
            policy.ghost_order.values().cloned().collect::<Vec<_>>(),
            vec!["k1".to_string(), "k3".to_string()]
        );
        assert_eq!(policy.ghost_lookup.len(), 2);
    }

    #[test]
    fn capacity_enforcement_evicts_to_stay_within_live_capacity() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            live_capacity: 3,
            small_capacity: 2,
            ghost_capacity: 8,
            max_entries_per_owner: 10,
            // Prevent fallback from triggering during the test
            fallback_window: 32,
            min_ghost_hits_in_window: 0,
            max_budget_rejections_in_window: 32,
        });

        // Fill beyond live_capacity — each key from a different owner
        for i in 0..6 {
            policy.access(&format!("ext-{i}"), format!("k{i}"));
        }

        // live_depth must not exceed live_capacity
        assert!(policy.live_depth() <= 3, "live_depth must respect capacity");
        // Evicted keys should be in ghost
        assert!(policy.telemetry().ghost_depth >= 3);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = S3FifoConfig::default();
        assert_eq!(cfg.live_capacity, 256);
        assert_eq!(cfg.small_capacity, 64);
        assert_eq!(cfg.ghost_capacity, 512);
        assert_eq!(cfg.max_entries_per_owner, 64);
        assert_eq!(cfg.fallback_window, 32);
        assert_eq!(cfg.min_ghost_hits_in_window, 2);
        assert_eq!(cfg.max_budget_rejections_in_window, 12);
    }

    #[test]
    fn decision_fields_reflect_current_state() {
        let mut policy = S3FifoPolicy::new(config());
        let d1 = policy.access("ext-a", "k1".to_string());
        assert_eq!(d1.kind, S3FifoDecisionKind::AdmitSmall);
        assert_eq!(d1.tier, S3FifoTier::Small);
        assert!(!d1.ghost_hit);
        assert!(d1.fallback_reason.is_none());
        assert_eq!(d1.live_depth, 1);
        assert_eq!(d1.small_depth, 1);
        assert_eq!(d1.main_depth, 0);
    }

    #[test]
    fn clear_fallback_resets_policy_gate() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            min_ghost_hits_in_window: 3,
            fallback_window: 3,
            ..config()
        });

        let _ = policy.access("ext-a", "k1".to_string());
        let _ = policy.access("ext-a", "k2".to_string());
        let _ = policy.access("ext-a", "k3".to_string());
        assert!(policy.telemetry().fallback_reason.is_some());

        policy.clear_fallback();
        assert!(policy.telemetry().fallback_reason.is_none());

        let decision = policy.access("ext-a", "k4".to_string());
        assert_ne!(decision.kind, S3FifoDecisionKind::FallbackBypass);
    }

    #[test]
    fn clear_fallback_clears_signal_window_and_preserves_counters() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            max_entries_per_owner: 1,
            fallback_window: 3,
            min_ghost_hits_in_window: 0,
            max_budget_rejections_in_window: 1,
            ..config()
        });

        // Trigger fairness fallback from repeated budget rejections.
        let _ = policy.access("ext-a", "k1".to_string());
        let _ = policy.access("ext-a", "k2".to_string());
        let _ = policy.access("ext-a", "k3".to_string());
        assert_eq!(
            policy.telemetry().fallback_reason,
            Some(S3FifoFallbackReason::FairnessInstability)
        );
        assert_eq!(policy.recent_signals.len(), 3);

        let before_clear = policy.telemetry();
        policy.clear_fallback();

        assert_eq!(policy.telemetry().fallback_reason, None);
        assert!(
            policy.recent_signals.is_empty(),
            "clear_fallback should reset signal history"
        );

        let after_clear = policy.telemetry();
        assert_eq!(after_clear.admissions_total, before_clear.admissions_total);
        assert_eq!(after_clear.promotions_total, before_clear.promotions_total);
        assert_eq!(after_clear.ghost_hits_total, before_clear.ghost_hits_total);
        assert_eq!(
            after_clear.budget_rejections_total,
            before_clear.budget_rejections_total
        );

        // Normal decisions should resume immediately after reset.
        let admitted = policy.access("ext-b", "post-clear-admit".to_string());
        assert_eq!(admitted.kind, S3FifoDecisionKind::AdmitSmall);
        assert_eq!(policy.telemetry().fallback_reason, None);
        assert_eq!(policy.recent_signals.len(), 1);

        // Fallback can be re-triggered deterministically as a new window fills.
        let reject_1 = policy.access("ext-a", "post-clear-reject-1".to_string());
        assert_eq!(reject_1.kind, S3FifoDecisionKind::RejectFairnessBudget);
        assert_eq!(policy.telemetry().fallback_reason, None);

        let reject_2 = policy.access("ext-a", "post-clear-reject-2".to_string());
        assert_eq!(reject_2.kind, S3FifoDecisionKind::RejectFairnessBudget);
        assert_eq!(
            policy.telemetry().fallback_reason,
            Some(S3FifoFallbackReason::FairnessInstability)
        );
    }

    // ── Property tests ──

    mod proptest_s3fifo {
        use super::*;
        use proptest::prelude::*;

        fn arb_access() -> impl Strategy<Value = (String, String)> {
            let owner = prop::sample::select(vec![
                "ext-a".to_string(),
                "ext-b".to_string(),
                "ext-c".to_string(),
            ]);
            let key = prop::sample::select(vec![
                "k0".to_string(),
                "k1".to_string(),
                "k2".to_string(),
                "k3".to_string(),
                "k4".to_string(),
                "k5".to_string(),
                "k6".to_string(),
                "k7".to_string(),
            ]);
            (owner, key)
        }

        fn arb_config() -> impl Strategy<Value = S3FifoConfig> {
            (2..32usize, 1..16usize, 1..64usize, 1..8usize, 2..16usize).prop_map(
                |(live, small, ghost, per_owner, window)| S3FifoConfig {
                    live_capacity: live,
                    small_capacity: small,
                    ghost_capacity: ghost,
                    max_entries_per_owner: per_owner,
                    fallback_window: window,
                    min_ghost_hits_in_window: 0,
                    max_budget_rejections_in_window: window,
                },
            )
        }

        proptest! {
            #[test]
            fn queues_always_disjoint_after_access_sequence(
                cfg in arb_config(),
                accesses in prop::collection::vec(arb_access(), 1..50),
            ) {
                let mut policy = S3FifoPolicy::new(cfg);
                for (owner, key) in &accesses {
                    let _ = policy.access(owner, key.clone());
                }

                let small: BTreeSet<_> = policy.small.iter().cloned().collect();
                let main: BTreeSet<_> = policy.main.iter().cloned().collect();
                let ghost: BTreeSet<_> = policy.ghost_lookup.keys().cloned().collect();

                assert!(small.is_disjoint(&main), "small and main must be disjoint");
                assert!(small.is_disjoint(&ghost), "small and ghost must be disjoint");
                assert!(main.is_disjoint(&ghost), "main and ghost must be disjoint");
            }

            #[test]
            fn live_depth_never_exceeds_capacity(
                cfg in arb_config(),
                accesses in prop::collection::vec(arb_access(), 1..50),
            ) {
                let mut policy = S3FifoPolicy::new(cfg);
                for (owner, key) in &accesses {
                    let _ = policy.access(owner, key.clone());
                }
                let effective_cap = policy.config().live_capacity;
                assert!(
                    policy.live_depth() <= effective_cap,
                    "live_depth {} exceeded capacity {}",
                    policy.live_depth(),
                    effective_cap,
                );
            }

            #[test]
            fn ghost_depth_never_exceeds_capacity(
                cfg in arb_config(),
                accesses in prop::collection::vec(arb_access(), 1..50),
            ) {
                let mut policy = S3FifoPolicy::new(cfg);
                for (owner, key) in &accesses {
                    let _ = policy.access(owner, key.clone());
                }
                let ghost_cap = policy.config().ghost_capacity;
                assert!(
                    policy.telemetry().ghost_depth <= ghost_cap,
                    "ghost_depth {} exceeded capacity {}",
                    policy.telemetry().ghost_depth,
                    ghost_cap,
                );
            }

            #[test]
            fn live_depth_equals_small_plus_main(
                cfg in arb_config(),
                accesses in prop::collection::vec(arb_access(), 1..50),
            ) {
                let mut policy = S3FifoPolicy::new(cfg);
                for (owner, key) in &accesses {
                    let decision = policy.access(owner, key.clone());
                    assert_eq!(
                        decision.live_depth,
                        decision.small_depth + decision.main_depth,
                        "live_depth must equal small + main at every step"
                    );
                }
            }

            #[test]
            fn counters_monotonically_nondecreasing(
                cfg in arb_config(),
                accesses in prop::collection::vec(arb_access(), 1..50),
            ) {
                let mut policy = S3FifoPolicy::new(cfg);
                let mut prev_admissions = 0u64;
                let mut prev_promotions = 0u64;
                let mut prev_ghost_hits = 0u64;
                let mut prev_rejections = 0u64;

                for (owner, key) in &accesses {
                    let _ = policy.access(owner, key.clone());
                    let tel = policy.telemetry();
                    assert!(tel.admissions_total >= prev_admissions);
                    assert!(tel.promotions_total >= prev_promotions);
                    assert!(tel.ghost_hits_total >= prev_ghost_hits);
                    assert!(tel.budget_rejections_total >= prev_rejections);
                    prev_admissions = tel.admissions_total;
                    prev_promotions = tel.promotions_total;
                    prev_ghost_hits = tel.ghost_hits_total;
                    prev_rejections = tel.budget_rejections_total;
                }
            }

            #[test]
            fn owner_counts_match_live_keys(
                cfg in arb_config(),
                accesses in prop::collection::vec(arb_access(), 1..50),
            ) {
                let mut policy = S3FifoPolicy::new(cfg);
                for (owner, key) in &accesses {
                    let _ = policy.access(owner, key.clone());
                }

                // Verify owner counts by manually counting live_owners
                let mut expected: BTreeMap<String, usize> = BTreeMap::new();
                for owner_val in policy.live_owners.values() {
                    *expected.entry(owner_val.clone()).or_insert(0) += 1;
                }
                assert_eq!(
                    policy.owner_live_counts, expected,
                    "owner_live_counts must match actual live key distribution"
                );
            }

            #[test]
            fn live_tier_map_consistent_with_queues(
                cfg in arb_config(),
                accesses in prop::collection::vec(arb_access(), 1..50),
            ) {
                let mut policy = S3FifoPolicy::new(cfg);
                for (owner, key) in &accesses {
                    let _ = policy.access(owner, key.clone());
                }

                // Every key in small must be in live_tiers as Small
                for key in &policy.small {
                    assert_eq!(
                        policy.live_tiers.get(key),
                        Some(&LiveTier::Small),
                        "key in small queue must be tracked as Small"
                    );
                }
                // Every key in main must be in live_tiers as Main
                for key in &policy.main {
                    assert_eq!(
                        policy.live_tiers.get(key),
                        Some(&LiveTier::Main),
                        "key in main queue must be tracked as Main"
                    );
                }
                // live_tiers count must match small + main
                assert_eq!(
                    policy.live_tiers.len(),
                    policy.small.len() + policy.main.len(),
                );
            }
        }
    }
}
