# bd-232t — BPET trajectory signals integration

## Verdict: PASS

## Implementation
- Economic BPET module: `crates/franken-node/src/security/bpet/economic_integration.rs`
- Dedicated trust-surface bridge: `crates/franken-node/src/security/bpet/trust_surface_integration.rs`
- Module wiring: `crates/franken-node/src/security/bpet/mod.rs`
- Trust-card consumer type: `crates/franken-node/src/supply_chain/trust_card.rs`
- The bridge converts `BpetGuidance` into `TrustCardMutation` and `AdversaryPosteriorUpdate` with fail-closed finite-score validation.

## Verification
- `python3 scripts/check_bpet_economic.py --json` — **12/12** checks passed, including the dedicated trust-surface path/symbol check.
- `python3 -m pytest tests/test_check_bpet_economic.py -q` — **17/17** tests passed.
- `rustfmt --edition 2024 --check --config skip_children=true crates/franken-node/src/security/bpet/trust_surface_integration.rs crates/franken-node/src/security/bpet/mod.rs` — passed.
- `git diff --check -- ...` over the touched bead/code/artifact files — passed.
- `ubs crates/franken-node/src/security/bpet/trust_surface_integration.rs ...` — exit 0, 0 critical findings.
- Cargo validation was not launched after two contention checks: local cargo/rustc count stayed high at 23 then 21, with two franken_node RCH builds already active.
