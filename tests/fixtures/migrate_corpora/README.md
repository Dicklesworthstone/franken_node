# Migration Audit Corpora

These fixtures provide real JavaScript inputs for the migration tree-sitter
benchmark track.

| Fixture | Role | Source | Lines | SHA-256 |
| --- | --- | --- | ---: | --- |
| `commander_command_v12_1_0.js` | Small CommonJS library module with option parsing, event handling, argument validation, and filesystem/process references. | Commander.js `v12.1.0` `lib/command.js` | 2,509 | `f92b14348d67ebab914c56d538da80afaf30e0343acee6eadcc01ca197753e6f` |
| `babel_standalone_v7_12_0.js` | Large browser bundle with parser, transform, traversal, helper, and code-generation surfaces in one realistic JS file. | Babel standalone `v7.12.0` `babel.js` package artifact | 102,253 | `0808573e27c21dcb02741e22591ba59313ec467b615bbc63f02998e0edc659bb` |

The files are committed verbatim from fixed upstream versions. They are not
synthetic stress fixtures, generated no-op loops, customer code, or private
application data.

The small corpus is intentionally larger than a toy fixture while still small
enough to catch per-file setup overhead. The large corpus is a real npm browser
bundle near the requested 50k-100k line stress band and exercises the parser on
deeply varied production JavaScript syntax.

Licenses and source URLs are recorded in `LICENSES.md`.
