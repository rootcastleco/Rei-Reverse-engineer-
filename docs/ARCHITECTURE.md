# Architecture · current Python core

## Layers and trust boundaries

- **Entry points**: `rei-rea` CLI, stdio MCP and `127.0.0.1` read-only dashboard. The backend shares one Python package and catalog.
- **Registry**: `src/rei_rea/data/tools.json` is the single source of truth, generated from `scripts/generate_catalog.py`. `shutil.which` checks PATH; it never downloads/install/starts a tool. Each row says `discovery-only` or `static-adapter` and `bundled: false`.
- **Inspector**: hashing entire regular files, reading at most 8192 header bytes; recognizes PE/ELF/Mach-O/WASM/DEX/SQLite/PCAP and nested zip member names. ZIP metadata is bounded, never extracted. Directory hashing is explicitly partial when limits are reached.
- **Signals / comparisons**: entropy/signature probes, strings opt-in and byte differences, with a 16 MiB scan budget. Full-file SHA-256 remains independent of scan limits.
- **Planner**: maps observed target format to one or more specialist skills, tool capability tags and a testable evidence-first workflow. No model-generated code execution.
- **Evidence**: local `case.json` and `events.jsonl` with seq, timestamp, predecessor SHA-256 and record SHA-256. Atomic case manifest creation and exclusive writer lock guard against simple concurrency conflicts.
- **Adapters**: fixed Python code map for eleven static CLI commands with `shell=False`, no arbitrary flags, explicit `--allow-external`, process timeout and bounded capture. No dynamic methods, network probes or unrestricted `subprocess` API are exposed.

## Data flow

1. Resolve user-supplied path and refuse direct symlink targets.
2. Hash file or deterministically hash a bounded directory manifest. Determine type from verified signatures and bounded archive metadata.
3. Return structured observations with scope and limitations, not guessed code behavior.
4. Consult local tool registry for candidate providers and skill routing.
5. If a case is requested, create independent evidence metadata, appending local records with confidence and source pointers.
6. If an external parser is explicitly run, validate target against any selected case **before** execution; capture exit status, bounded text output and provenance.
7. No rollout changes to external software, remote services or firmware are performed.

## Contracts

- SHA-256 identity: hex string, full file contents; directory identity is hash of `relative_path\0size\0file_hash` records, bounded with completeness flag.
- Observation states: `observed`, `inferred`, `unknown`.
- Tool execution: catalog entry alone never grants execution permission.
- MCP output: JSON-RPC 2.0, stdio JSON lines, bounded inbound message size 1 MiB; fourteen structured tool contracts.
- Session state: no persistent MCP process handles, no target imports, no background jobs.
- Local web: GET only for `/`, `/api/tools`, `/api/health`. Loopback only, conservative CSP, no cookies or tokens.

## Planned architecture (not implemented)

```text
               Rootcastle REI REA core
                          |
             Provider-neutral capability API
                          |
         +----------------+----------------+
         |                |                |
   upstream REA MCP    native engines   mobile / firmware
         |                |                |
    session adaptor  Ghidra / rizin    JADX / Frida / QEMU
                          |
              immutable typed Evidence API
                          |
        local indexed search + reproducible parity
```

A future provider adapter must expose: `probe()` (no execution), `prepare()` (explicit scoped approval), `inspect()` (read-only), `trace()` (proof-linked), `close()` (cleanup), `capabilities()` (actual supported types) and a version-locked evidence contract. It must report unsupported operations rather than silently falling back.

## v0.2 incremental extension

```text
CLI / stdio MCP
       |
       +-- investigate() -------- inspect/hash --> deep PE/ELF/WASM --> signals --> inspect/hash
       |                                                        |
       +-- diff() ------------------------------------ structural comparisons
       |
       +-- case index/search ---> SQLite snapshot index (local metadata only)
       |
       +-- case bundle/verify --> metadata ZIP (no artifact bytes)
       |
       +-- existing v0.1 interfaces unchanged
```

Hard limits: deep parsing first 32 MiB; 256 sections/headers; 128 names; 4096 symbol/entry probes; all-in-one analysis accepts at most 64 MiB. Read-only MCP methods never create indexes; index writes and ZIP export require explicit CLI commands. SQLite is derived state and disposable. The SHA-256 event ledger remains the canonical local record; neither mechanism is a qualified independent signature.
