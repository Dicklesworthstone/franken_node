//! Staking governance invariant conformance matrix.

use frankenengine_node::registry::staking_governance::*;
use std::collections::BTreeSet;

type TestResult = Result<(), String>;

#[derive(Clone, Copy)]
struct RequirementRow {
    invariant: &'static str,
    level: &'static str,
    behavior: &'static str,
    exercise: fn() -> TestResult,
}

const REQUIREMENTS: &[RequirementRow] = &[
    RequirementRow {
        invariant: INV_STAKE_MINIMUM,
        level: "MUST",
        behavior: "below-minimum stake deposits fail closed and exact minimum deposits succeed",
        exercise: check_stake_minimum,
    },
    RequirementRow {
        invariant: INV_STAKE_SLASH_DETERMINISTIC,
        level: "MUST",
        behavior: "same slash inputs produce identical slash amount and penalty hash",
        exercise: check_stake_slash_deterministic,
    },
    RequirementRow {
        invariant: INV_STAKE_APPEAL_WINDOW,
        level: "MUST",
        behavior: "appeals are accepted before the deadline and rejected at the deadline",
        exercise: check_stake_appeal_window,
    },
    RequirementRow {
        invariant: INV_STAKE_AUDIT_COMPLETE,
        level: "MUST",
        behavior: "stake lifecycle operations emit complete audit entries",
        exercise: check_stake_audit_complete,
    },
    RequirementRow {
        invariant: INV_STAKE_NO_DOUBLE_SLASH,
        level: "MUST",
        behavior: "already-slashed stakes and repeated evidence cannot be slashed again",
        exercise: check_stake_no_double_slash,
    },
    RequirementRow {
        invariant: INV_STAKE_WITHDRAWAL_SAFE,
        level: "MUST",
        behavior: "slashed stakes and cooldown-active sibling stakes cannot withdraw",
        exercise: check_stake_withdrawal_safe,
    },
    RequirementRow {
        invariant: INV_STK_DETERMINISTIC_PENALTY,
        level: "MUST",
        behavior: "direct penalty calculation is deterministic for fixed inputs",
        exercise: check_stk_deterministic_penalty,
    },
    RequirementRow {
        invariant: INV_STK_AUDITABLE_SLASH,
        level: "MUST",
        behavior: "slash audit entries carry evidence hash and slash invariants",
        exercise: check_stk_auditable_slash,
    },
    RequirementRow {
        invariant: INV_STK_NO_NEGATIVE_BALANCE,
        level: "MUST",
        behavior: "maximum slash floors stake and account balances at zero",
        exercise: check_stk_no_negative_balance,
    },
    RequirementRow {
        invariant: INV_STAKE_GATE_REQUIRED,
        level: "MUST",
        behavior: "capability activation is denied without sufficient active stake",
        exercise: check_stake_gate_required,
    },
    RequirementRow {
        invariant: INV_SLASH_DETERMINISTIC,
        level: "MUST",
        behavior: "canonical slash alias resolves to deterministic penalty hashes",
        exercise: check_slash_deterministic,
    },
    RequirementRow {
        invariant: INV_SLASH_AUDIT_TRAIL,
        level: "MUST",
        behavior: "canonical slash audit alias resolves to immutable audit rows",
        exercise: check_slash_audit_trail,
    },
    RequirementRow {
        invariant: INV_APPEAL_WINDOW,
        level: "MUST",
        behavior: "canonical appeal alias rejects exact-deadline appeals fail-closed",
        exercise: check_appeal_window,
    },
];

#[test]
fn registry_staking_governance_invariant_matrix_covers_contract() -> TestResult {
    let mut exercised = BTreeSet::new();
    let mut failures = Vec::new();

    for row in REQUIREMENTS {
        if row.level != "MUST" {
            failures.push(format!(
                "{}: conformance matrix only covers mandatory requirements",
                row.invariant
            ));
            continue;
        }
        if row.behavior.trim().is_empty() {
            failures.push(format!("{}: missing behavior description", row.invariant));
            continue;
        }

        match (row.exercise)() {
            Ok(()) => {
                exercised.insert(row.invariant);
            }
            Err(error) => failures.push(format!("{}: {error}", row.invariant)),
        }
    }

    let all_invariants = REQUIREMENTS
        .iter()
        .map(|row| row.invariant)
        .collect::<BTreeSet<_>>();
    let missing = all_invariants
        .difference(&exercised)
        .copied()
        .collect::<Vec<_>>();
    let coverage_passes =
        exercised.len().saturating_mul(100) >= all_invariants.len().saturating_mul(95);

    if failures.is_empty() && missing.is_empty() && coverage_passes {
        Ok(())
    } else {
        Err(format!(
            "staking governance conformance failed; exercised={}/{}, missing={missing:?}, failures={failures:?}",
            exercised.len(),
            all_invariants.len()
        ))
    }
}

fn check_stake_minimum() -> TestResult {
    let mut ledger = StakingLedger::new();
    assert_staking_err(
        ledger.deposit("publisher-min", 9, RiskTier::Low, 100),
        ERR_STAKE_INSUFFICIENT,
        "below low-tier minimum deposit",
    )?;

    let stake_id = map_staking(
        ledger.deposit("publisher-min", 10, RiskTier::Low, 101),
        "exact low-tier minimum deposit",
    )?;
    let stake = ledger
        .get_stake(stake_id)
        .ok_or_else(|| "accepted stake must be queryable".to_string())?;
    if stake.amount == 10 && stake.state == StakeState::Active {
        Ok(())
    } else {
        Err(format!(
            "exact minimum stake should be active amount=10, got state={} amount={}",
            stake.state, stake.amount
        ))
    }
}

fn check_stake_slash_deterministic() -> TestResult {
    let mut first = StakingLedger::new();
    let first_id = map_staking(
        first.deposit("publisher-a", 500, RiskTier::High, 100),
        "first deterministic deposit",
    )?;
    let first_event = map_staking(
        first.slash(
            first_id,
            evidence(ViolationType::PolicyViolation, "same-slash-payload"),
            200,
        ),
        "first deterministic slash",
    )?;

    let mut second = StakingLedger::new();
    let second_id = map_staking(
        second.deposit("publisher-b", 500, RiskTier::High, 100),
        "second deterministic deposit",
    )?;
    let second_event = map_staking(
        second.slash(
            second_id,
            evidence(ViolationType::PolicyViolation, "same-slash-payload"),
            900,
        ),
        "second deterministic slash",
    )?;

    assert_eq_string(
        first_event.evidence.evidence_hash.as_str(),
        second_event.evidence.evidence_hash.as_str(),
        "evidence hash",
    )?;
    assert_eq_u64(
        first_event.slash_amount,
        second_event.slash_amount,
        "slash amount",
    )?;
    assert_eq_string(
        first_event.penalty_hash.as_str(),
        second_event.penalty_hash.as_str(),
        "penalty hash",
    )
}

fn check_stake_appeal_window() -> TestResult {
    let slash_timestamp = 200;
    let critical_window_secs = 48 * 3600;

    let mut accepted = StakingLedger::new();
    let accepted_id = slash_critical(&mut accepted, "publisher-appeal-ok", "appeal-ok")?;
    let accepted_event = accepted
        .slash_events_for("publisher-appeal-ok")
        .first()
        .ok_or_else(|| "accepted appeal setup must create a slash event".to_string())?
        .slash_id;
    map_staking(
        accepted.file_appeal(
            accepted_id,
            accepted_event,
            "filed before deadline",
            slash_timestamp + critical_window_secs - 1,
        ),
        "appeal before deadline",
    )?;

    let mut expired = StakingLedger::new();
    let expired_id = slash_critical(&mut expired, "publisher-appeal-expired", "appeal-expired")?;
    let expired_event = expired
        .slash_events_for("publisher-appeal-expired")
        .first()
        .ok_or_else(|| "expired appeal setup must create a slash event".to_string())?
        .slash_id;
    assert_staking_err(
        expired.file_appeal(
            expired_id,
            expired_event,
            "filed at deadline",
            slash_timestamp + critical_window_secs,
        ),
        ERR_STAKE_APPEAL_EXPIRED,
        "appeal at exact deadline",
    )
}

fn check_stake_audit_complete() -> TestResult {
    let mut ledger = StakingLedger::new();
    let stake_id = map_staking(
        ledger.deposit("publisher-audit", 1000, RiskTier::Critical, 100),
        "audit deposit",
    )?;
    let slash_event = map_staking(
        ledger.slash(
            stake_id,
            evidence(ViolationType::SupplyChainCompromise, "audit-slash"),
            200,
        ),
        "audit slash",
    )?;
    let appeal = map_staking(
        ledger.file_appeal(stake_id, slash_event.slash_id, "audit appeal", 300),
        "audit appeal",
    )?;
    map_staking(
        ledger.resolve_appeal(appeal.appeal_id, false, 400),
        "audit appeal resolution",
    )?;
    map_staking(ledger.withdraw(stake_id, 500), "audit withdrawal")?;

    for code in [STAKE_001, STAKE_002, STAKE_003, STAKE_004, STAKE_005] {
        if !ledger
            .state
            .audit_log
            .iter()
            .any(|entry| entry.event_code == code)
        {
            return Err(format!("missing audit event code {code}"));
        }
    }
    if ledger.state.audit_log.len() < 5 {
        return Err(format!(
            "audit log should contain complete lifecycle, got {} entries",
            ledger.state.audit_log.len()
        ));
    }
    assert_snapshot_counter(
        &ledger,
        "total_audit_entries",
        u64::try_from(ledger.state.audit_log.len()).unwrap_or(u64::MAX),
    )
}

fn check_stake_no_double_slash() -> TestResult {
    let mut ledger = StakingLedger::new();
    let first_id = map_staking(
        ledger.deposit("publisher-double", 1000, RiskTier::Critical, 100),
        "double slash first deposit",
    )?;
    let second_id = map_staking(
        ledger.deposit("publisher-double", 1000, RiskTier::Critical, 101),
        "double slash second deposit",
    )?;
    map_staking(
        ledger.slash(
            first_id,
            evidence(ViolationType::MaliciousCode, "duplicate-evidence"),
            200,
        ),
        "initial slash",
    )?;
    assert_staking_err(
        ledger.slash(
            first_id,
            evidence(ViolationType::PolicyViolation, "distinct-evidence"),
            201,
        ),
        ERR_STAKE_ALREADY_SLASHED,
        "repeat slash on same stake",
    )?;
    assert_staking_err(
        ledger.slash(
            second_id,
            evidence(ViolationType::MaliciousCode, "duplicate-evidence"),
            202,
        ),
        ERR_STAKE_ALREADY_SLASHED,
        "repeat evidence for same publisher",
    )
}

fn check_stake_withdrawal_safe() -> TestResult {
    let mut ledger = StakingLedger::new();
    let slashed_id = map_staking(
        ledger.deposit("publisher-withdraw", 1000, RiskTier::Critical, 100),
        "withdraw slashed setup",
    )?;
    let sibling_id = map_staking(
        ledger.deposit("publisher-withdraw", 1000, RiskTier::Critical, 101),
        "withdraw cooldown setup",
    )?;
    map_staking(
        ledger.slash(
            slashed_id,
            evidence(ViolationType::MaliciousCode, "withdraw-blocking-slash"),
            200,
        ),
        "withdraw blocking slash",
    )?;
    assert_staking_err(
        ledger.withdraw(slashed_id, 201),
        ERR_STAKE_INVALID_TRANSITION,
        "slashed stake withdrawal",
    )?;
    assert_staking_err(
        ledger.withdraw(sibling_id, 202),
        ERR_STAKE_WITHDRAWAL_BLOCKED,
        "cooldown sibling withdrawal",
    )
}

fn check_stk_deterministic_penalty() -> TestResult {
    let engine = SlashingEngine::new(StakePolicy::default_policy());
    let evidence_hash = compute_evidence_hash("deterministic-penalty");
    let first = map_staking(
        engine.compute_penalty(&RiskTier::High, 500, &evidence_hash),
        "first direct penalty",
    )?;
    let second = map_staking(
        engine.compute_penalty(&RiskTier::High, 500, &evidence_hash),
        "second direct penalty",
    )?;

    assert_eq_u64(first.0, second.0, "direct penalty amount")?;
    assert_eq_string(first.1.as_str(), second.1.as_str(), "direct penalty hash")
}

fn check_stk_auditable_slash() -> TestResult {
    let mut ledger = StakingLedger::new();
    let stake_id = map_staking(
        ledger.deposit("publisher-slash-audit", 500, RiskTier::High, 100),
        "slash audit deposit",
    )?;
    let slash_event = map_staking(
        ledger.slash(
            stake_id,
            evidence(ViolationType::FalseAttestation, "auditable-slash"),
            200,
        ),
        "auditable slash",
    )?;
    let slash_audit = audit_entry(&ledger, STAKE_002)?;
    if slash_audit.evidence_hash.as_deref() != Some(slash_event.evidence.evidence_hash.as_str()) {
        return Err("slash audit entry must carry the slash evidence hash".to_string());
    }
    for invariant in [
        INV_STAKE_SLASH_DETERMINISTIC,
        INV_STAKE_NO_DOUBLE_SLASH,
        INV_STAKE_AUDIT_COMPLETE,
        INV_STK_DETERMINISTIC_PENALTY,
        INV_STK_AUDITABLE_SLASH,
        INV_STK_NO_NEGATIVE_BALANCE,
    ] {
        if !slash_audit
            .invariants_checked
            .iter()
            .any(|actual| actual == invariant)
        {
            return Err(format!("slash audit missing invariant {invariant}"));
        }
    }
    Ok(())
}

fn check_stk_no_negative_balance() -> TestResult {
    let mut ledger = StakingLedger::new();
    let stake_id = map_staking(
        ledger.deposit("publisher-nonnegative", 1000, RiskTier::Critical, 100),
        "nonnegative balance deposit",
    )?;
    let slash_event = map_staking(
        ledger.slash(
            stake_id,
            evidence(ViolationType::MaliciousCode, "full-critical-slash"),
            200,
        ),
        "full critical slash",
    )?;
    assert_eq_u64(slash_event.post_balance, 0, "post-slash stake balance")?;
    let account = ledger
        .get_account("publisher-nonnegative")
        .ok_or_else(|| "nonnegative account must exist".to_string())?;
    if account.balance > account.deposited {
        return Err(format!(
            "account balance {} exceeds deposited {}",
            account.balance, account.deposited
        ));
    }
    if account.slashed_total > account.deposited {
        return Err(format!(
            "slashed total {} exceeds deposited {}",
            account.slashed_total, account.deposited
        ));
    }
    Ok(())
}

fn check_stake_gate_required() -> TestResult {
    let mut ledger = StakingLedger::new();
    let gate = CapabilityStakeGate::new(StakePolicy::default_policy());

    let (missing_allowed, missing_code, missing_detail) =
        gate.check_stake(&ledger, "publisher-gate", &RiskTier::High, 100);
    if missing_allowed || missing_code != STAKE_007 || !missing_detail.contains(ERR_STAKE_NOT_FOUND)
    {
        return Err(format!(
            "missing stake should fail gate with {STAKE_007}/{ERR_STAKE_NOT_FOUND}, got allowed={missing_allowed} code={missing_code} detail={missing_detail}"
        ));
    }

    map_staking(
        ledger.deposit("publisher-gate", 10, RiskTier::Low, 101),
        "gate below requested tier deposit",
    )?;
    let (low_allowed, low_code, low_detail) =
        gate.check_stake(&ledger, "publisher-gate", &RiskTier::High, 102);
    if low_allowed || low_code != STAKE_007 || !low_detail.contains(ERR_STAKE_INSUFFICIENT) {
        return Err(format!(
            "below-tier stake should fail gate with {STAKE_007}/{ERR_STAKE_INSUFFICIENT}, got allowed={low_allowed} code={low_code} detail={low_detail}"
        ));
    }

    let mut passing = StakingLedger::new();
    map_staking(
        passing.deposit("publisher-gate-pass", 500, RiskTier::High, 103),
        "gate sufficient deposit",
    )?;
    let (allowed, code, detail) =
        gate.check_stake(&passing, "publisher-gate-pass", &RiskTier::High, 104);
    if allowed && code == STAKE_007 && detail.contains("passes gate") {
        Ok(())
    } else {
        Err(format!(
            "sufficient high-risk stake should pass gate, got allowed={allowed} code={code} detail={detail}"
        ))
    }
}

fn check_slash_deterministic() -> TestResult {
    let evidence_hash = compute_evidence_hash("slash-deterministic-alias");
    let first = compute_penalty_hash(&evidence_hash, 5_000, 500);
    let second = compute_penalty_hash(&evidence_hash, 5_000, 500);
    assert_eq_string(
        first.as_str(),
        second.as_str(),
        "canonical slash alias hash",
    )
}

fn check_slash_audit_trail() -> TestResult {
    let mut ledger = StakingLedger::new();
    let stake_id = map_staking(
        ledger.deposit("publisher-audit-trail", 500, RiskTier::High, 100),
        "audit-trail deposit",
    )?;
    let slash_event = map_staking(
        ledger.slash(
            stake_id,
            evidence(ViolationType::SupplyChainCompromise, "slash-audit-trail"),
            200,
        ),
        "audit-trail slash",
    )?;
    let exported = ledger.export_audit_log_jsonl();
    if !exported.contains(STAKE_002)
        || !exported.contains("slash")
        || !exported.contains(&slash_event.evidence.evidence_hash)
    {
        return Err(format!(
            "exported audit log must include slash event/evidence hash, got {exported}"
        ));
    }
    Ok(())
}

fn check_appeal_window() -> TestResult {
    let engine = SlashingEngine::new(StakePolicy::default_policy());
    let slash_timestamp = 200;
    let critical_window_secs = 48 * 3600;
    if !engine.is_within_appeal_window(
        &RiskTier::Critical,
        slash_timestamp,
        slash_timestamp + critical_window_secs - 1,
    ) {
        return Err("appeal should be inside window one second before deadline".to_string());
    }
    if engine.is_within_appeal_window(
        &RiskTier::Critical,
        slash_timestamp,
        slash_timestamp + critical_window_secs,
    ) {
        return Err("appeal should fail closed at exact deadline".to_string());
    }
    Ok(())
}

fn slash_critical(
    ledger: &mut StakingLedger,
    publisher_id: &str,
    evidence_payload: &str,
) -> Result<StakeId, String> {
    let stake_id = map_staking(
        ledger.deposit(publisher_id, 1000, RiskTier::Critical, 100),
        "critical slash setup deposit",
    )?;
    map_staking(
        ledger.slash(
            stake_id,
            evidence(ViolationType::MaliciousCode, evidence_payload),
            200,
        ),
        "critical slash setup",
    )?;
    Ok(stake_id)
}

fn evidence(violation_type: ViolationType, payload: &str) -> SlashEvidence {
    SlashEvidence::new(
        violation_type,
        "conformance violation",
        payload,
        "collector-conformance",
        1000,
    )
}

fn audit_entry<'a>(
    ledger: &'a StakingLedger,
    event_code: &str,
) -> Result<&'a StakingAuditEntry, String> {
    ledger
        .state
        .audit_log
        .iter()
        .find(|entry| entry.event_code == event_code)
        .ok_or_else(|| format!("missing audit entry for {event_code}"))
}

fn assert_snapshot_counter(ledger: &StakingLedger, field: &str, expected: u64) -> TestResult {
    let snapshot = ledger.generate_snapshot();
    let actual = snapshot
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("snapshot field `{field}` must be an unsigned integer"))?;
    assert_eq_u64(actual, expected, field)
}

fn map_staking<T>(result: Result<T, StakingError>, context: &str) -> Result<T, String> {
    result.map_err(|error| format!("{context} failed: {error}"))
}

fn assert_staking_err<T>(
    result: Result<T, StakingError>,
    expected_code: &'static str,
    context: &str,
) -> TestResult {
    match result {
        Ok(_) => Err(format!("{context}: expected error code {expected_code}")),
        Err(error) => {
            let actual_code = staking_error_code(&error);
            if actual_code == expected_code {
                Ok(())
            } else {
                Err(format!(
                    "{context}: expected error code {expected_code}, got {actual_code}: {error}"
                ))
            }
        }
    }
}

fn staking_error_code(error: &StakingError) -> &'static str {
    match error {
        StakingError::InsufficientStake { code, .. }
        | StakingError::StakeNotFound { code, .. }
        | StakingError::AlreadySlashed { code, .. }
        | StakingError::WithdrawalBlocked { code, .. }
        | StakingError::AppealExpired { code, .. }
        | StakingError::InvalidTransition { code, .. }
        | StakingError::DuplicateAppeal { code, .. } => code,
    }
}

fn assert_eq_u64(actual: u64, expected: u64, label: &str) -> TestResult {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected}, got {actual}"))
    }
}

fn assert_eq_string(actual: &str, expected: &str, label: &str) -> TestResult {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected}, got {actual}"))
    }
}
