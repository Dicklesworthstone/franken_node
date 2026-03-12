# bd-721z Verification Summary

- Status: **FAIL**
- Generated on: `2026-03-12`
- Modules scanned: `80`
- Findings total: `10`
- Violations (`AMB-002`, `AMB-004`): `1`
- Allowlisted (`AMB-003`): `9`
- Expired allowlist entries: `0`
- Invalid allowlist entries: `0`

## Violations

- `crates/franken-node/src/connector/supervision.rs`:139 [std::time::Instant] ambient authority API usage without allowlist entry
