//! Conformance tests: Connector lifecycle transition matrix.
//!
//! Exhaustively tests every `(source, target)` pair in the live lifecycle FSM
//! to verify that legal transitions succeed and illegal transitions are
//! rejected with stable error codes.
//!
//! Corresponds to bd-2gh acceptance criteria:
//! - FSM is complete and deterministic for all states.
//! - Illegal transitions return stable codes.
//! - Full transition matrix tests pass against the public crate API.

use frankenengine_node::connector::lifecycle::{
    ConnectorState, LifecycleError, transition, transition_matrix,
};
use std::collections::HashSet;
use std::fmt::Debug;

const LEGAL_TRANSITIONS: [(ConnectorState, ConnectorState); 21] = [
    (ConnectorState::Discovered, ConnectorState::Verified),
    (ConnectorState::Discovered, ConnectorState::Failed),
    (ConnectorState::Verified, ConnectorState::Installed),
    (ConnectorState::Verified, ConnectorState::Failed),
    (ConnectorState::Installed, ConnectorState::Configured),
    (ConnectorState::Installed, ConnectorState::Failed),
    (ConnectorState::Configured, ConnectorState::Active),
    (ConnectorState::Configured, ConnectorState::Failed),
    (ConnectorState::Active, ConnectorState::Paused),
    (ConnectorState::Active, ConnectorState::Cancelling),
    (ConnectorState::Active, ConnectorState::Stopped),
    (ConnectorState::Active, ConnectorState::Failed),
    (ConnectorState::Paused, ConnectorState::Active),
    (ConnectorState::Paused, ConnectorState::Cancelling),
    (ConnectorState::Paused, ConnectorState::Stopped),
    (ConnectorState::Paused, ConnectorState::Failed),
    (ConnectorState::Cancelling, ConnectorState::Stopped),
    (ConnectorState::Cancelling, ConnectorState::Failed),
    (ConnectorState::Stopped, ConnectorState::Configured),
    (ConnectorState::Stopped, ConnectorState::Failed),
    (ConnectorState::Failed, ConnectorState::Discovered),
];

fn is_legal(from: ConnectorState, to: ConnectorState) -> bool {
    LEGAL_TRANSITIONS.contains(&(from, to))
}

fn state_name(state: ConnectorState) -> &'static str {
    state.as_str()
}

fn ensure(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn failure(message: &'static str) -> String {
    message.to_owned()
}

fn ensure_eq<T>(actual: T, expected: T, label: &str) -> Result<(), String>
where
    T: PartialEq + Debug,
{
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected:?}, got {actual:?}"))
    }
}

fn expect_legal_transition(from: ConnectorState, to: ConnectorState) -> Result<(), String> {
    match transition(from, to) {
        Ok(actual) => ensure_eq(actual, to, "legal transition target"),
        Err(err) => Err(format!(
            "expected legal transition {} -> {}, got {err:?}",
            state_name(from),
            state_name(to)
        )),
    }
}

fn expect_illegal_transition(from: ConnectorState, to: ConnectorState) -> Result<(), String> {
    match transition(from, to) {
        Err(LifecycleError::IllegalTransition {
            from: actual_from,
            to: actual_to,
            permitted,
        }) => {
            ensure_eq(actual_from, from, "illegal transition source")?;
            ensure_eq(actual_to, to, "illegal transition target")?;
            ensure_eq(
                permitted.as_slice(),
                from.legal_targets(),
                "illegal transition permitted targets",
            )
        }
        Err(LifecycleError::SelfTransition { state }) => Err(format!(
            "expected IllegalTransition for {} -> {}, got SelfTransition({})",
            state_name(from),
            state_name(to),
            state_name(state)
        )),
        Ok(actual) => Err(format!(
            "expected illegal transition {} -> {}, got {actual}",
            state_name(from),
            state_name(to)
        )),
    }
}

#[test]
fn transition_matrix_matches_authoritative_transition_table() -> Result<(), String> {
    let matrix = transition_matrix();

    ensure_eq(ConnectorState::ALL.len(), 9, "state count")?;
    ensure_eq(matrix.len(), 72, "non-self transition count")?;
    ensure_eq(
        matrix.iter().filter(|entry| entry.legal).count(),
        21,
        "legal transition count",
    )?;

    for entry in matrix {
        let expected = is_legal(entry.from, entry.to);
        ensure_eq(entry.legal, expected, "matrix legality drift")?;

        if expected {
            expect_legal_transition(entry.from, entry.to)?;
        } else {
            expect_illegal_transition(entry.from, entry.to)?;
        }
    }
    Ok(())
}

#[test]
fn self_transitions_return_stable_self_error() -> Result<(), String> {
    for state in ConnectorState::ALL {
        match transition(state, state) {
            Err(LifecycleError::SelfTransition { state: actual }) => {
                ensure_eq(actual, state, "self-transition state")?;
            }
            Err(err) => {
                let _ = err;
                return Err(failure("self-transition returned unexpected error"));
            }
            Ok(actual) => {
                let _ = actual;
                return Err(failure("self-transition unexpectedly succeeded"));
            }
        }
    }
    Ok(())
}

#[test]
fn no_duplicate_legal_transitions_exist() -> Result<(), String> {
    let mut seen = HashSet::new();
    for pair in LEGAL_TRANSITIONS {
        ensure(seen.insert(pair), "duplicate legal transition")?;
    }
    Ok(())
}

#[test]
fn every_state_has_incoming_and_outgoing_edges() -> Result<(), String> {
    for state in ConnectorState::ALL {
        ensure(
            LEGAL_TRANSITIONS.iter().any(|(from, _)| *from == state),
            "state has no legal outgoing transition",
        )?;
        ensure(
            LEGAL_TRANSITIONS.iter().any(|(_, to)| *to == state),
            "state has no legal incoming transition",
        )?;
    }
    Ok(())
}

#[test]
fn happy_path_recovery_and_failure_edges_are_conformant() -> Result<(), String> {
    for pair in [
        (ConnectorState::Discovered, ConnectorState::Verified),
        (ConnectorState::Verified, ConnectorState::Installed),
        (ConnectorState::Installed, ConnectorState::Configured),
        (ConnectorState::Configured, ConnectorState::Active),
        (ConnectorState::Failed, ConnectorState::Discovered),
    ] {
        ensure(
            is_legal(pair.0, pair.1),
            "happy-path edge missing from legal transitions",
        )?;
        expect_legal_transition(pair.0, pair.1)?;
    }

    for state in ConnectorState::ALL {
        if state == ConnectorState::Failed {
            continue;
        }
        ensure(
            is_legal(state, ConnectorState::Failed),
            "state cannot transition to failed",
        )?;
    }
    Ok(())
}

#[test]
fn cancelling_edges_are_explicitly_conformant() -> Result<(), String> {
    ensure_eq(
        ConnectorState::Active.legal_targets(),
        &[
            ConnectorState::Paused,
            ConnectorState::Cancelling,
            ConnectorState::Stopped,
            ConnectorState::Failed,
        ],
        "active legal targets",
    )?;
    ensure_eq(
        ConnectorState::Paused.legal_targets(),
        &[
            ConnectorState::Active,
            ConnectorState::Cancelling,
            ConnectorState::Stopped,
            ConnectorState::Failed,
        ],
        "paused legal targets",
    )?;
    ensure_eq(
        ConnectorState::Cancelling.legal_targets(),
        &[ConnectorState::Stopped, ConnectorState::Failed],
        "cancelling legal targets",
    )?;

    expect_legal_transition(ConnectorState::Active, ConnectorState::Cancelling)?;
    expect_legal_transition(ConnectorState::Paused, ConnectorState::Cancelling)?;

    match transition(ConnectorState::Cancelling, ConnectorState::Active) {
        Err(LifecycleError::IllegalTransition {
            from,
            to,
            permitted,
        }) => {
            ensure_eq(
                from,
                ConnectorState::Cancelling,
                "cancelling illegal source",
            )?;
            ensure_eq(to, ConnectorState::Active, "cancelling illegal target")?;
            ensure_eq(
                permitted,
                vec![ConnectorState::Stopped, ConnectorState::Failed],
                "cancelling permitted targets",
            )?;
        }
        Err(err) => {
            let _ = err;
            return Err("cancelling -> active returned wrong error".to_string());
        }
        Ok(actual) => {
            let _ = actual;
            return Err("cancelling -> active unexpectedly succeeded".to_string());
        }
    }
    Ok(())
}
