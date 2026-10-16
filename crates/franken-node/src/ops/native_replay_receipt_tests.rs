//! Test the receipt terminal-state boundary outside the binary's cfg(not(test)).
//! These are metadata tests, not certified native executions or signatures.

use super::NativeReplayTerminalState;
use serde_json::{Value, json};

const STATES: [NativeReplayTerminalState; 3] = [
    NativeReplayTerminalState::Completed,
    NativeReplayTerminalState::UncaughtException,
    NativeReplayTerminalState::EngineFailure,
];

#[test]
fn native_replay_receipt_requires_the_same_completion_or_failure_category() {
    for state in STATES {
        for failed in [false, true] {
            let marker = failed.then(|| json!("original execution failure"));
            let result = state.check_receipt_failure(marker.as_ref());
            assert_eq!(result.is_ok(), state.is_failure() == failed);
            if state.is_failure() != failed {
                assert_eq!(
                    result.unwrap_err(),
                    "native replay terminal state does not match its authenticated run receipt"
                );
            }
        }
    }
}

#[test]
fn native_replay_receipt_does_not_interpret_diagnostic_text_as_an_engine_cause() {
    // The engine alone assigns the typed terminal state. Both supported failure
    // categories require a nonempty receipt error, not a matching log substring.
    for text in [
        "capability denied: env_read",
        "instruction budget exhausted",
        "the guest threw an arbitrary value",
        "βeta\nsecond line",
        " ", // Preserve the existing nonempty-string receipt contract.
    ] {
        let marker = json!(text);
        for state in [
            NativeReplayTerminalState::UncaughtException,
            NativeReplayTerminalState::EngineFailure,
        ] {
            assert!(state.check_receipt_failure(Some(&marker)).is_ok());
        }
        assert!(NativeReplayTerminalState::Completed.check_receipt_failure(Some(&marker)).is_err());
    }
}

#[test]
fn native_replay_receipt_rejects_null_and_wrong_types_instead_of_coercing_them() {
    // An omitted field means no execution failure. Explicit null is malformed,
    // not an alternative spelling of omission or an authorized failure marker.
    for marker in [Value::Null, json!(""), json!(false), json!(0), json!([]), json!({})] {
        for state in STATES {
            assert_eq!(
                state.check_receipt_failure(Some(&marker)).unwrap_err(),
                "captured run receipt has an invalid execution failure"
            );
        }
    }
    assert!(NativeReplayTerminalState::Completed.check_receipt_failure(None).is_ok());
}

#[test]
fn native_replay_receipt_keeps_nonzero_completed_exits_separate_from_native_stops() {
    // An exit status is not the engine terminal category. Pass only the signed
    // execution_failure field to the production boundary, as the CLI does.
    for code in [0, 1, 42, 95] {
        let receipt = json!({"exit_code": code});
        assert!(NativeReplayTerminalState::Completed
            .check_receipt_failure(receipt.get("execution_failure"))
            .is_ok());
        assert!(NativeReplayTerminalState::EngineFailure
            .check_receipt_failure(receipt.get("execution_failure"))
            .is_err());
    }
}

#[test]
fn native_replay_receipt_validation_does_not_echo_private_failure_values() {
    let marker = json!({"secret": "PRIVATE_RECEIPT_VALUE_MUST_NOT_BE_REPORTED"});
    for state in STATES {
        let message = state.check_receipt_failure(Some(&marker)).unwrap_err();
        assert!(!message.contains("PRIVATE_RECEIPT_VALUE_MUST_NOT_BE_REPORTED"));
    }
    let marker = json!("PRIVATE_RECEIPT_VALUE_MUST_NOT_BE_REPORTED");
    let message = NativeReplayTerminalState::Completed
        .check_receipt_failure(Some(&marker))
        .unwrap_err();
    assert!(!message.contains("PRIVATE_RECEIPT_VALUE_MUST_NOT_BE_REPORTED"));
}
