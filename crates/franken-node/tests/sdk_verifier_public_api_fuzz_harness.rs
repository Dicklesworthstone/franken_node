//! Structure-aware fuzzing for the verifier SDK public facade.

use frankenengine_verifier_sdk::{create_verifier_sdk, VerificationVerdict, VerifierSdkError};
use proptest::prelude::*;

fn bounded_text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 0..320)
        .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn valid_token() -> impl Strategy<Value = String> {
    "[A-Za-z0-9._-]{1,64}".prop_map(|value| value)
}

fn verifier_identity() -> impl Strategy<Value = String> {
    prop_oneof![
        valid_token().prop_map(|name| format!("verifier://{name}")),
        bounded_text(),
        bounded_text().prop_map(|name| format!("verifier://{name}")),
        valid_token().prop_map(|name| format!(" verifier://{name}")),
        valid_token().prop_map(|name| format!("verifier://{name} ")),
        Just("verifier://".to_string()),
        Just(format!("verifier://{}", "a".repeat(256))),
    ]
}

fn session_id() -> impl Strategy<Value = String> {
    prop_oneof![
        valid_token(),
        bounded_text(),
        valid_token().prop_map(|name| format!(" {name}")),
        valid_token().prop_map(|name| format!("{name} ")),
        Just(String::new()),
        Just(format!("session-{}", "a".repeat(256))),
    ]
}

fn is_valid_identity(identity: &str) -> bool {
    let Some(name) = identity.strip_prefix("verifier://") else {
        return false;
    };
    identity == identity.trim()
        && !name.trim().is_empty()
        && name == name.trim()
        && name.len() <= 255
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn is_valid_session_id(session_id: &str) -> bool {
    !session_id.trim().is_empty()
        && session_id == session_id.trim()
        && session_id.len() <= 255
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn sdk_public_session_boundary_accepts_only_canonical_identity_and_session_id(
        identity in verifier_identity(),
        session in session_id(),
    ) {
        let sdk = create_verifier_sdk(identity.clone());
        let result = sdk.create_session(session.clone());

        match (is_valid_identity(&identity), is_valid_session_id(&session), result) {
            (true, true, Ok(mut created)) => {
                prop_assert_eq!(&created.session_id, &session);
                prop_assert_eq!(&created.verifier_identity, &identity);
                prop_assert!(created.steps().is_empty());
                prop_assert!(!created.sealed);
                prop_assert_eq!(created.final_verdict.as_ref(), None);
                prop_assert!(!created.created_at.trim().is_empty());

                let verdict = sdk.seal_session(&mut created)
                    .expect("fresh empty valid session should seal");
                prop_assert_eq!(verdict, VerificationVerdict::Inconclusive);
                prop_assert!(created.sealed);
                prop_assert_eq!(
                    created.final_verdict.as_ref(),
                    Some(&VerificationVerdict::Inconclusive)
                );
            }
            (false, _, Err(VerifierSdkError::InvalidVerifierIdentity { actual, reason })) => {
                prop_assert_eq!(actual, identity);
                prop_assert!(!reason.trim().is_empty());
            }
            (true, false, Err(VerifierSdkError::InvalidSessionId { actual, reason })) => {
                prop_assert_eq!(actual, session);
                prop_assert!(!reason.trim().is_empty());
            }
            (expected_identity, expected_session, unexpected) => {
                prop_assert!(
                    false,
                    "unexpected verifier SDK boundary result: identity_valid={expected_identity} session_valid={expected_session} result={unexpected:?}"
                );
            }
        }
    }
}
