# Extension Runtime Compatibility Matrix

This document provides a comprehensive compatibility matrix for the Pi
extension runtime. It covers Node.js built-in module shims, Bun API surface,
npm package stubs, and the Pi SDK -- everything an extension author needs to
know about what works in the QuickJS-based runtime.

## Node.js Built-in Module Shims

The extension runtime provides shims for standard Node.js built-in modules.
Each shim runs inside the QuickJS sandbox and routes I/O through the
capability-gated hostcall interface.

### Coverage Summary

| Module | Coverage | Key APIs |
|--------|----------|----------|
| `node:path` | Full | `join`, `dirname`, `resolve`, `basename`, `relative`, `isAbsolute`, `extname`, `normalize`, `parse`, `format`, `sep`, `delimiter`, `posix` |
| `node:os` | Full | `homedir`, `tmpdir`, `hostname`, `platform`, `arch`, `type`, `release`, `cpus`, `totalmem`, `freemem`, `uptime`, `loadavg`, `networkInterfaces`, `userInfo`, `endianness`, `EOL`, `devNull`, `constants` |
| `node:fs` | Full | `readFileSync`, `writeFileSync`, `existsSync`, `readdirSync`, `statSync`, `mkdirSync`, `rmdirSync`, `unlinkSync`, `renameSync`, `symlinkSync`, `readlinkSync`, `realpathSync`, `copyFileSync`, `appendFileSync`, `chmodSync`, `accessSync`, `lstatSync`, `openSync`, `closeSync`, `readSync`, `writeSync`, `fstatSync`, `createReadStream`, `createWriteStream`, `promises.*`, callback variants |
| `node:buffer` | Full | `Buffer.from`, `Buffer.alloc`, `Buffer.allocUnsafe`, `Buffer.concat`, `Buffer.isBuffer`, `Buffer.byteLength`, `toString(encoding)` (utf8, hex, base64, latin1, ascii) |
| `node:events` | Full | `EventEmitter` class with `on`, `once`, `off`, `emit`, `removeListener`, `removeAllListeners`, `listenerCount`, `listeners`, `prependListener` |
| `node:util` | Full | `inspect`, `promisify`, `callbackify`, `format`, `deprecate`, `inherits`, `debuglog`, `stripVTControlCharacters`, `types.*`, `TextEncoder`, `TextDecoder` |
| `node:child_process` | Full | `spawn`, `spawnSync`, `execSync`, `exec`, `execFile`, `execFileSync`, `fork` (stub) |
| `node:crypto` | Partial | `randomBytes`, `randomUUID`, `createHash` (SHA-256, SHA-1, MD5), `createHmac`, `timingSafeEqual`, `getHashes` |
| `node:http` | Partial | `request`, `get`, `createServer` (stub), `STATUS_CODES`, `METHODS`, `IncomingMessage`, `ClientRequest` -- routes through `pi.http()` hostcall |
| `node:url` | Partial | `URL` (globalThis), `URLSearchParams`, `parse`, `format`, `resolve`, `fileURLToPath`, `pathToFileURL` |
| `node:stream` | Partial | `Readable`, `Writable`, `Transform`, `PassThrough`, `Duplex`, `pipeline`, `finished` |
| `node:net` | Stub | `createConnection` (stub), `Socket` (stub); `createServer` throws -- network APIs outside sandbox |
| `node:readline` | Stub | `createInterface` (returns no-op), `promises.createInterface` -- interactive prompts unavailable |

### `node:fs` Detail

The filesystem shim uses a virtual filesystem (VFS) backed by an in-memory
`Map`. Host filesystem access is available through a fallback mechanism that
routes `readFileSync` and `statSync` calls through the hostcall boundary
(capability-gated by the `read` capability).

| API | Implementation | Notes |
|-----|---------------|-------|
| `readFileSync` | Real | VFS first, host fallback for real files |
| `writeFileSync` | Real | VFS-only (sandboxed) |
| `existsSync` | Real | VFS + host fallback |
| `statSync` | Real | VFS + host fallback |
| `readdirSync` | Real | VFS-only |
| `mkdirSync` | Real | VFS-only, supports `recursive` |
| `promises.readFile` | Real | Async wrapper around sync |
| `promises.writeFile` | Real | Async wrapper around sync |
| `promises.stat` | Real | Async wrapper around sync |
| `promises.mkdir` | Real | Async wrapper around sync |
| `promises.readdir` | Real | Async wrapper around sync |
| `promises.access` | Real | Async wrapper around sync |
| `promises.rm` | Real | Async wrapper around sync |
| `promises.rename` | Real | Async wrapper around sync |
| `openSync`/`closeSync`/`readSync`/`writeSync` | Real | File descriptor API |
| `createReadStream` | Real | Returns Readable stream |
| `createWriteStream` | Real | Returns Writable stream |
| Callback variants (`readFile`, `writeFile`, etc.) | Real | 9 callback-style functions |

### `node:crypto` Detail

| API | Implementation | Notes |
|-----|---------------|-------|
| `randomBytes(n)` | Real | Uses QuickJS random source |
| `randomUUID()` | Real | v4 UUID generation |
| `createHash(algo)` | Real | SHA-256, SHA-1, MD5 via pure-JS |
| `createHmac(algo, key)` | Real | HMAC-SHA256, HMAC-SHA1 |
| `timingSafeEqual(a, b)` | Real | Constant-time comparison |
| `getHashes()` | Real | Returns supported algorithm list |
| `pbkdf2`/`scrypt` | Real | Key derivation via native hostcall |
| `sign`/`verify` | Missing | Asymmetric crypto not implemented |
| `createCipher`/`createDecipher` | Missing | Symmetric encryption not implemented |

### `node:child_process` Detail

All subprocess APIs route through the `pi.exec()` hostcall, which requires
the `exec` capability. The `exec` capability is denied by default in
`Standard` and `Safe` policy profiles.

| API | Implementation | Notes |
|-----|---------------|-------|
| `spawn(cmd, args, opts)` | Real | Returns ChildProcess with stdout/stderr streams |
| `spawnSync(cmd, args, opts)` | Real | Synchronous via `__pi_exec_sync_native` |
| `execSync(cmd, opts)` | Real | Shell execution, returns stdout |
| `exec(cmd, opts, cb)` | Real | Async shell execution |
| `execFile(file, args, opts, cb)` | Real | Async file execution |
| `execFileSync(file, args, opts)` | Real | Synchronous file execution |
| `fork(modulePath)` | Stub | Not supported in sandbox |

## Bun API Surface

The runtime provides a `Bun` global object for compatibility with extensions
that target the Bun runtime.

| API | Status | Notes |
|-----|--------|-------|
| `Bun.argv` | Supported | Process arguments array |
| `Bun.file(path)` | Supported | Returns object with `exists()`, `text()`, `arrayBuffer()`, `json()` |
| `Bun.write(dest, data)` | Supported | Write file via `node:fs` shim |
| `Bun.which(cmd)` | Supported | Locate command via `which` exec |
| `Bun.spawn(cmd, opts)` | Supported | Via `node:child_process` shim |
| `Bun.connect(...)` | Unsupported | Network connections outside sandbox |
| `Bun.listen(...)` | Unsupported | Server listeners outside sandbox |

## npm Package Stubs

Extensions that import npm packages get virtual module stubs. These provide
enough API surface for extensions to load and register without errors. Some
stubs are functional (e.g., `uuid`, `shell-quote`), while others are no-ops
for optional features.

### Functional Stubs

| Package | Coverage | Key APIs |
|---------|----------|----------|
| `uuid` | Functional | `v4()`, `v7()`, `v1()`, `v3()`, `v5()`, `validate()`, `version()` |
| `shell-quote` | Functional | `parse(cmd)`, `quote(args)` |
| `diff` | Functional | `createTwoFilesPatch`, `createPatch`, `diffLines`, `diffChars`, `diffWords` |
| `dotenv` | Functional | `config(opts)`, `parse(src)` |
| `ms` | Functional | Duration parsing (`ms("2h")` -> `7200000`) |
| `glob` | Partial | `globSync`, `glob`, `Glob` class (basic `*`, `?`, `**` over VFS-known files) |

### No-op Stubs (Extension Loads, Feature Unavailable)

| Package | Stubbed APIs | Reason |
|---------|-------------|--------|
| `chalk` | Passthrough (no color) | Terminal colors not applicable in QuickJS |
| `chokidar` | `watch()` returns no-op | File watching not available |
| `jsdom` | `JSDOM` class (empty) | DOM not available |
| `turndown` | `TurndownService` (passthrough) | HTML-to-markdown not available |
| `node-pty` | `spawn()` returns no-op | PTY not available in sandbox |
| `jsonwebtoken` | `sign()`, `verify()`, `decode()` | Crypto-dependent, returns stubs |
| `@opentelemetry/*` | No-op spans/metrics | Telemetry not collected |
| `@xterm/*` | No-op terminal | Terminal emulation not available |
| `vscode-languageserver-protocol` | Type constants only | LSP types for compatibility |
| `@sinclair/typebox` | `Type` schema builder | JSON Schema construction |
| `@modelcontextprotocol/sdk` | `Client`, transport classes | MCP client stubs |
| `c12` (config loader) | `define()`, `loadConfig()` | Config loading stub |
| `execa` | `bash()` returns empty | Process execution via hostcall instead |
| `@anthropic-ai/sdk` | `Anthropic` class | API client stub |
| `@anthropic-ai/bedrock-sdk` | `SandboxManager` | Sandbox manager stub |
| `openai` | `OpenAI` class | API client stub |
| `adm-zip` | `AdmZip` class | Zip handling stub |
| `linkedom` | `parseHTML()` | DOM parser stub |
| `@sourcegraph/scip-typescript` | `scip.Index` class | Indexer stub |

## Pi SDK (`@mariozechner/pi-coding-agent`)

The Pi SDK virtual module provides the primary extension API surface.

| Export | Type | Description |
|--------|------|-------------|
| `keyHint(action, fallback)` | Function | Keyboard hint display helper |
| `compact(prep, model, key, instr, signal)` | Function | Context compaction |
| `completeSimple(model, prompt, opts)` | Function | Simple LLM completion |
| `fuzzyMatch(query, text, opts)` | Function | Fuzzy string matching (returns `{score, positions}`) |
| `fuzzyFilter(query, items, opts)` | Function | Filter items by fuzzy match score |
| `Text`, `Container`, `Markdown`, `Spacer` | Classes | TUI rendering components |
| `Editor`, `Box`, `SelectList`, `Input` | Classes | TUI input components |
| `Image`, `DynamicBorder`, `CancellableLoader` | Classes | TUI display components |
| `Key` | Object | Key binding constants |
| `CURSOR_MARKER` | String | Cursor position marker |
| `truncateToWidth`, `visibleWidth`, `wrapTextWithAnsi` | Functions | Text rendering utilities |
| `getEditorKeybindings` | Function | Editor key binding configuration |
| `VERSION`, `DEFAULT_MAX_LINES`, `DEFAULT_MAX_BYTES` | Constants | Runtime constants |
| `truncateHead`, `truncateTail` | Functions | Content truncation |
| `parseSessionEntries`, `convertToLlm`, `serializeConversation` | Functions | Session data utilities |
| `createBashTool`, `createReadTool`, `createWriteTool`, etc. | Functions | Tool factory functions |
| `getAgentDir`, `copyToClipboard` | Functions | System utilities |
| `highlightCode`, `getLanguageFromPath` | Functions | Code display helpers |
| `AssistantMessageComponent`, `ToolExecutionComponent`, `UserMessageComponent` | Classes | Message rendering |
| `SessionManager` | Class | Session state management |

### Pi AI SDK (`@mariozechner/pi-ai`)

| Export | Type | Description |
|--------|------|-------------|
| `StringEnum(values)` | Function | Enum type builder |
| `calculateCost()` | Function | Token cost calculation (uses `model.cost` × usage tokens) |
| `complete(model, messages, opts)` | Function | LLM completion |
| `completeSimple(model, prompt, opts)` | Function | Simple completion |
| `streamSimpleAnthropic()` | Function | Anthropic streaming (stub) |
| `streamSimpleOpenAIResponses()` | Function | OpenAI streaming (stub) |
| `getModel()`, `getApiProvider()`, `getModels()` | Functions | Model info |

## Conformance Status

Tested against a corpus of 223 real-world extensions:

| Source Tier | Pass | Fail | N/A | Total | Pass Rate |
|-------------|------|------|-----|-------|-----------|
| Official (pi-mono) | 56 | 4 | 6 | 66 | 93.3% |
| Community | 58 | 0 | 0 | 58 | 100%* |
| npm Registry | 63 | 12 | 0 | 75 | 84.0%* |
| Third-party GitHub | 20 | 3 | 0 | 23 | 87.0%* |
| Agents | 1 | 0 | 0 | 1 | 100%* |

*Community/npm/third-party extensions are tested via the compatibility
validation pack, which uses a broader load-and-register test rather than
the full differential oracle.

### Remaining Failure Categories

| Category | Count | Root Cause |
|----------|-------|------------|
| Multi-file dependency resolution | 4 | Relative specifiers across files not yet supported |
| Missing npm package specifiers | 5 | Extensions import real npm packages not stubbed |
| Host-read policy denial | 4 | Extension reads files outside allowed root |
| Runtime shape/load errors | 4 | Miscellaneous load-time errors |
| Test fixture (not a real extension) | 1 | `base_fixtures` is test infrastructure |

### Runtime API Matrix

| Surface | Pass | Fail | Total |
|---------|------|------|-------|
| Node.js APIs | 13 | 0 | 13 |
| Bun APIs | 5 | 2 | 7 |

Failing Bun APIs: `Bun.connect` and `Bun.listen` (network server/client
APIs outside the extension sandbox).

## Unsupported Features

These features are intentionally not supported in the extension sandbox:

| Feature | Reason | Alternative |
|---------|--------|-------------|
| Native Node addons (`.node`) | Binary modules cannot run in QuickJS | Use hostcalls or WASM |
| Direct network sockets | Security boundary enforcement | Use `pi.http()` hostcall |
| Direct filesystem access | Capability-gated for safety | Use `pi.tool("Read", ...)` or `node:fs` shim |
| Server listeners (`net.createServer`) | Extensions are clients, not servers | Not applicable |
| Worker threads | QuickJS is single-threaded | Not applicable |
| `node:cluster` | Process clustering not available | Not applicable |
| `node:dgram` | UDP sockets outside sandbox | Not applicable |
| `node:tls` | TLS handled by host HTTP client | Use `pi.http()` with HTTPS |

## Version Information

- QuickJS runtime: embedded via `rquickjs` crate
- Node.js API target: Node 18+ compatibility subset
- Bun API target: Bun 1.x compatibility subset
- Extension API version: `1.0`
