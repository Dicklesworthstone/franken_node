# bd-2zl.5 verification summary

Scope: verification-only support lane for transplant lockfile closure audit.

## Environment check
- Default verify exit: 2
- Default generate exit: 2
- Both default invocations fail in this repo because `transplant/pi_agent_rust` is absent (captured in stderr artifacts).

## Fixture-based behavior checks
- Baseline verify exit/verdict: 0 / PASS
- Determinism cmp exit: 0 (identical=True)
- Parse-failure verify exit/verdict: 1 / FAIL:PARSE
- Count-failure verify exit/verdict: 1 / FAIL:COUNT

## Interpretation
- Lockfile verification semantics behave as expected on deterministic fixture inputs.
- Failure categories map correctly to `FAIL:PARSE` and `FAIL:COUNT` with non-zero exits.
