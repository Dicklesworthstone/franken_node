# Placeholder Surface Inventory Gate

- Parent bead: `bd-2fqyv`
- Support bead: `bd-2fqyv.1.2`
- Verdict: `PASS`
- Inventory doc: `docs/governance/placeholder_surface_inventory.md`
- Rule count: `12`
- Documented open-debt occurrences: `21`
- Allowlisted fixture occurrences: `62`
- Unexpected occurrences: `0`
- Allowlist escapes: `0`

## Documented Open Debt
- `PSI-004` control-plane catalog boundary remains explicitly non-live: 15 documented occurrence(s); owner `bd-2fqyv.5`.
- `PSI-006` deterministic fuzz fixture adapter remains confined to its modeling surface: 6 documented occurrence(s); owner `bd-2fqyv.7`.

## Explicit Allowlists
- `fixture_registry_boundary` fixture trust-card registry remains test-only: 33 allowlisted occurrence(s); rationale `fixture_registry(...)`.
- `decision_receipt_demo_key_boundary` decision receipt demo signing key remains fixture-only: 19 allowlisted occurrence(s); rationale `decision_receipt::demo_signing_key(...)`.
- `incident_fixture_event_boundary` incident fixture-event helper remains test-only: 4 allowlisted occurrence(s); rationale `fixture_incident_events(...)`.
- `fuzz_gate_callsite_boundary` deterministic fuzz fixture callsites remain confined to fixture and verification paths: 6 allowlisted occurrence(s); rationale `allowlisted_simulation`.

## Failures
- None.
