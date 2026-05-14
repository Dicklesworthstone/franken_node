# bd-35m7 Verification Summary

- Bead: `bd-35m7`
- Section: `12`
- Capability: `Risk control: trajectory-gaming camouflage`
- Verdict: `PASS`

## Scope Delivered

- Contract specification: `docs/specs/section_12/bd-35m7_contract.md`
- Machine-readable report: `artifacts/12/trajectory_gaming_camouflage_report.json`
- Verifier: `scripts/check_trajectory_gaming_camouflage.py`
- Unit tests: `tests/test_check_trajectory_gaming_camouflage.py`
- Rust runtime contract: `crates/franken-node/src/security/trajectory_gaming.rs`
- Rust detector and fixtures: `crates/franken-node/src/security/bpet/camouflage_detector.rs`, `crates/franken-node/src/security/bpet/camouflage_fixtures.rs`
- Rust trust-card pipeline mark: `crates/franken-node/src/supply_chain/trust_card.rs`
- Rust trust-card integration test: `crates/franken-node/tests/trust_card_authoritative_state_real_inputs.rs`

## Acceptance Results

- Mimicry corpus size/freshness gates are enforced (`132` patterns, quarterly freshness satisfied).
- Known-pattern recall gate enforces `>=90%` (`93.4%` measured).
- Hybrid fusion blocks behavioral-channel gaming when provenance/code signals fail.
- Motif randomization enforces distinct feature subsets on repeated trajectory evaluations.
- Adaptive-adversary resilience gate enforces `>=80%` recall over 10 rounds (`84.3%` min).
- Trust cards expose `mark_camouflage_suspected` and `TRUST_CARD_CAMOUFLAGE_SUSPECTED` so detector hints mark the signed card version, risk summary, audit history, and telemetry.
- Verification now covers `60` checks, including `18` Rust integration path/symbol checks and `24` Python unit tests.

## Scenario Coverage

- Scenario A: known mimicry pattern flagged at `>=90%` confidence.
- Scenario B: behavioral gaming + suspicious provenance is still flagged.
- Scenario C: same trajectory uses distinct motif subsets across evaluations.
- Scenario D: new pattern addition + retrain preserves `>=90%` recall.
- Scenario E: adaptive adversary over 10 rounds remains above `80%` recall.

## Determinism and Adversarial Validation

- Adaptive-round order perturbation does not change aggregate evaluation.
- Adversarial motif-subset reuse is detected by verification logic.

## Reproducible Commands

```bash
python3 scripts/check_trajectory_gaming_camouflage.py --self-test --json
python3 scripts/check_trajectory_gaming_camouflage.py --json
python3 -m unittest tests/test_check_trajectory_gaming_camouflage.py
```
