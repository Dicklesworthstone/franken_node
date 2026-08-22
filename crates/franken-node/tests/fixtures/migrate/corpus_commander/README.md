# corpus_commander fixture

A real-code migration fixture for the live migration-velocity gate
(bd-reality-20260820-w0fc6.2): the wrapper manifest/lockfile around a
verbatim copy of Commander.js v12.1.0 `lib/commander.js` (2,509 LOC),
byte-identical to `tests/fixtures/migrate_corpora/commander_command_v12_1_0.js`
(sha256 pinned in `tests/fixtures/migrate_corpora/README.md`; licensing in
`tests/fixtures/migrate_corpora/LICENSES.md`).

Role in the cohort: spans the size axis with real upstream JavaScript so the
throughput measurement is not dominated by process-startup floors on 2-file
apps. This fixture is consumed by the velocity gate only; it is not referenced
by golden tests or rewrite-rule tuning.
