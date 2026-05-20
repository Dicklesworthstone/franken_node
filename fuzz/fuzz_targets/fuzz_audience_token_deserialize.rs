#![no_main]

//! Fuzz the `AudienceBoundToken` deserialization boundary.
//!
//! `AudienceBoundToken` derives `Deserialize` with five custom
//! `#[serde(deserialize_with = "...")]` paths plus a sequence visitor for
//! the audience vector. Until 0ffb6918 those paths only checked emptiness
//! and byte length; control characters slipped through and flowed into
//! operator-facing error format strings. This harness drives raw bytes
//! through `serde_json::from_slice::<AudienceBoundToken>` and asserts:
//!
//!   - the deserializer NEVER panics on any byte sequence;
//!   - when it accepts a token, every string field is non-empty (where
//!     required), fits the per-field byte cap, AND contains no
//!     `char::is_control()` codepoints — the post-fix invariant from
//!     `BoundedStringVisitor::validate`;
//!   - when it accepts a token, `validate_shape()` agrees with the
//!     deserializer (a token that survives deserialization must also
//!     survive the constructor-path check, because they enforce the same
//!     property set with different machinery — divergence is itself a
//!     bug);
//!   - the same invariants hold for the `Vec<AudienceBoundToken>`
//!     (`TokenChain`-shape) entry point used by callers that load a chain
//!     from disk or RPC.
//!
//! Inputs are biased toward exercising the new control-char rejection
//! seam: a JSON template with one targeted field swapped for arbitrary
//! UTF-8-ish bytes, alongside fully arbitrary JSON payloads.

use arbitrary::Arbitrary;
use frankenengine_node::control_plane::audience_token::{
    AudienceBoundToken, ERR_ABT_TOKEN_FIELD_CONTROL_CHAR, ERR_ABT_TOKEN_TOO_LARGE,
    MAX_AUDIENCES_PER_TOKEN, MAX_TOKEN_FIELD_BYTES, MAX_TOKEN_SIGNATURE_BYTES,
};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 32 * 1024;

#[derive(Debug, Arbitrary)]
struct AudienceTokenDeserializeCase {
    raw_json: Vec<u8>,
    field_under_attack: AttackField,
    poison: Vec<u8>,
    audience_extra: Vec<String>,
    parent_present: bool,
    max_delegation_depth: u8,
    chain_count_hint: u8,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum AttackField {
    TokenId,
    Issuer,
    Audience,
    Nonce,
    ParentTokenHash,
    Signature,
}

fuzz_target!(|case: AudienceTokenDeserializeCase| {
    // (A) Wholly arbitrary bytes — exercise serde panic-freedom on garbage.
    let mut raw = case.raw_json;
    if raw.len() > MAX_RAW_BYTES {
        raw.truncate(MAX_RAW_BYTES);
    }
    check_panic_free::<AudienceBoundToken>(&raw);
    check_panic_free::<Vec<AudienceBoundToken>>(&raw);

    // (B) Targeted poison: build a structurally valid token JSON and
    //     replace one field's value with attacker-controlled bytes,
    //     forcing the visitor to traverse the new control-char seam.
    if let Some(poisoned) = build_poisoned_token_json(&case) {
        check_panic_free::<AudienceBoundToken>(poisoned.as_bytes());
    }

    // (C) Chain shape: wrap the same poisoned token in a JSON array and
    //     exercise the BoundedTokenVecVisitor that `TokenChain`-loading
    //     callers route through.
    if let Some(chain_json) = build_poisoned_chain_json(&case) {
        check_panic_free::<Vec<AudienceBoundToken>>(chain_json.as_bytes());
    }
});

fn check_panic_free<T>(bytes: &[u8])
where
    T: serde::de::DeserializeOwned + AudienceShapeCheck,
{
    match serde_json::from_slice::<T>(bytes) {
        Ok(value) => value.assert_shape_invariants(),
        Err(_) => {} // any well-formed deserialization error is acceptable
    }
}

trait AudienceShapeCheck {
    fn assert_shape_invariants(&self);
}

impl AudienceShapeCheck for AudienceBoundToken {
    fn assert_shape_invariants(&self) {
        assert_token_post_deserialize_invariants(self);
    }
}

impl AudienceShapeCheck for Vec<AudienceBoundToken> {
    fn assert_shape_invariants(&self) {
        for token in self {
            assert_token_post_deserialize_invariants(token);
        }
    }
}

fn assert_token_post_deserialize_invariants(token: &AudienceBoundToken) {
    // Every string field that the deserializer accepted must satisfy the
    // post-fix invariant: non-empty (where required), within the per-field
    // byte cap, AND no control characters.
    assert_field_non_empty_bounded_no_control("token_id", token.token_id.as_str());
    assert_field_non_empty_bounded_no_control("issuer", &token.issuer);
    assert!(
        token.audience.len() <= MAX_AUDIENCES_PER_TOKEN,
        "audience len {} exceeds cap {}",
        token.audience.len(),
        MAX_AUDIENCES_PER_TOKEN
    );
    for entry in &token.audience {
        assert_field_non_empty_bounded_no_control("audience entry", entry);
    }
    assert_field_non_empty_bounded_no_control("nonce", &token.nonce);
    if let Some(parent_hash) = &token.parent_token_hash {
        assert_field_non_empty_bounded_no_control("parent_token_hash", parent_hash);
    }
    // Signature allows empty by deserializer contract; still cap-bounded
    // and control-free.
    assert!(
        token.signature.len() <= MAX_TOKEN_SIGNATURE_BYTES,
        "signature len {} exceeds cap {}",
        token.signature.len(),
        MAX_TOKEN_SIGNATURE_BYTES
    );
    assert!(
        !token.signature.chars().any(char::is_control),
        "signature contained control characters but deserializer accepted it"
    );

    // Validate-shape divergence check: the deserializer accepted this
    // token, so the constructor-path validate_shape must also accept it.
    // The only failures we allow are token_too_large or control_char —
    // anything else means the two paths disagree on what "valid" means.
    if let Err(err) = token.validate_shape() {
        let code = err.code.as_str();
        assert!(
            code == ERR_ABT_TOKEN_TOO_LARGE || code == ERR_ABT_TOKEN_FIELD_CONTROL_CHAR,
            "validate_shape rejected deserializer-accepted token with unexpected code {code}: {err:?}"
        );
    }
}

fn assert_field_non_empty_bounded_no_control(field: &str, value: &str) {
    assert!(
        !value.is_empty(),
        "{field} was empty but deserializer accepted it"
    );
    assert!(
        value.len() <= MAX_TOKEN_FIELD_BYTES,
        "{field} len {} exceeds cap {}",
        value.len(),
        MAX_TOKEN_FIELD_BYTES
    );
    assert!(
        !value.chars().any(char::is_control),
        "{field} contained control characters but deserializer accepted it"
    );
}

fn build_poisoned_token_json(case: &AudienceTokenDeserializeCase) -> Option<String> {
    let poison = poison_string(case);
    let extra = bounded_audience_extras(&case.audience_extra);
    let mut base = serde_json::json!({
        "token_id": "good-token",
        "issuer": "good-issuer",
        "audience": pick_audience(case, &extra),
        "capabilities": ["Migrate", "Configure"],
        "issued_at": 1_000_u64,
        "expires_at": 2_000_u64,
        "nonce": "good-nonce",
        "parent_token_hash": if case.parent_present {
            serde_json::Value::String("good-parent".to_string())
        } else {
            serde_json::Value::Null
        },
        "signature": "",
        "max_delegation_depth": case.max_delegation_depth,
    });

    match case.field_under_attack {
        AttackField::TokenId => {
            base["token_id"] = serde_json::Value::String(poison);
        }
        AttackField::Issuer => {
            base["issuer"] = serde_json::Value::String(poison);
        }
        AttackField::Audience => {
            let arr = base["audience"]
                .as_array_mut()
                .expect("audience seeded as array");
            arr.push(serde_json::Value::String(poison));
        }
        AttackField::Nonce => {
            base["nonce"] = serde_json::Value::String(poison);
        }
        AttackField::ParentTokenHash => {
            base["parent_token_hash"] = serde_json::Value::String(poison);
        }
        AttackField::Signature => {
            base["signature"] = serde_json::Value::String(poison);
        }
    }

    serde_json::to_string(&base).ok()
}

fn build_poisoned_chain_json(case: &AudienceTokenDeserializeCase) -> Option<String> {
    let count = (case.chain_count_hint as usize).min(8).max(1);
    let token = build_poisoned_token_json(case)?;
    let token_value: serde_json::Value = serde_json::from_str(&token).ok()?;
    let mut arr = Vec::with_capacity(count);
    for _ in 0..count {
        arr.push(token_value.clone());
    }
    serde_json::to_string(&serde_json::Value::Array(arr)).ok()
}

fn poison_string(case: &AudienceTokenDeserializeCase) -> String {
    // Build a UTF-8-safe poison up to ~2x the per-field cap so the visitor
    // sees both within-cap and over-cap cases.
    let cap_budget = MAX_TOKEN_FIELD_BYTES.saturating_mul(2);
    let mut out = String::with_capacity(case.poison.len().min(cap_budget));
    for byte in case.poison.iter().copied() {
        if out.len() >= cap_budget {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&[byte]) {
            out.push_str(s);
        }
    }
    if out.is_empty() {
        out.push('\n'); // ensure we exercise the control-char branch at least once
    }
    out
}

fn bounded_audience_extras(input: &[String]) -> Vec<String> {
    input
        .iter()
        .take(MAX_AUDIENCES_PER_TOKEN.saturating_add(4))
        .map(|s| {
            let mut bounded = s.clone();
            if bounded.len() > MAX_TOKEN_FIELD_BYTES {
                bounded.truncate(MAX_TOKEN_FIELD_BYTES);
            }
            bounded
        })
        .collect()
}

fn pick_audience(case: &AudienceTokenDeserializeCase, extra: &[String]) -> Vec<String> {
    let mut audience = vec!["good-service".to_string()];
    if matches!(case.field_under_attack, AttackField::Audience) {
        return audience;
    }
    for entry in extra {
        if audience.len() >= MAX_AUDIENCES_PER_TOKEN {
            break;
        }
        if !entry.is_empty() {
            audience.push(entry.clone());
        }
    }
    audience
}
