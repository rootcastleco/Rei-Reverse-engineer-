# REI REA v0.2 — bounded binary intelligence and casebook

## Compatibility

This release adds commands and local-only files. Existing v0.1 commands, case manifests, event-chain records, registry and MCP tool names remain compatible. No automatic migration runs at installation or startup.

## What's new

- **PE**: parse COFF/optional headers, sections, imports/exports and declared security flags. Capped tables and explicit errors for malformed RVAs.
- **ELF**: parse 32/64-bit endian-aware program/section tables, `DT_NEEDED`, bounded dynamic symbol names and GNU-stack flag.
- **WASM version 1**: bound section inventory, imported module/names and exported names; no code validation or execution.
- **Structural diff**: compare PE/ELF/WASM structures across two exact hashes.
- **One-command investigation**: full SHA-256 cross-check before/after triage; read-only, 64 MiB input limit.
- **SQLite casebook**: explicit metadata-only snapshot index and search, without event payloads.
- **Evidence bundle**: export case manifest, event ledger and report with internal checksums; source binary excluded.
- **13 MCP methods**, with new commands exposed but no external tool execution.
- **12 specialist skills**, including `rei-binary-intelligence` and `rei-casebook-forensics`.

## Commands

```bash
rei-rea investigate /lab/samples/example.wasm
rei-rea deep /lab/samples/example.exe
rei-rea diff /lab/samples/before.elf /lab/samples/after.elf
rei-rea case index /lab/cases
rei-rea case search /lab/cases --kind elf --limit 10
rei-rea case bundle /lab/cases/CASE-ID /lab/out/CASE-ID.zip
rei-rea case bundle-verify /lab/out/CASE-ID.zip
```

## Migration and rollback

The SQLite index is created only by `case index` in the specified workspace and may be deleted/recreated without losing source evidence. No existing case JSON or events require conversion. Roll back to v0.1 by reinstalling that release; v0.1 ignores the SQLite index and never reads new commands. v0.2 ZIP bundle export is not accepted by v0.1, but the enclosed `case.json` and `events.jsonl` retain their earlier layout.

## Threat and accuracy limits

No untrusted target execution, cloud uploading, full decompilation, network probing or arbitrary provider shell commands. The native parsers cover declared structures, not validated program semantics; adversarial files can trigger bounded parse errors. Partial analyses must not be promoted into complete findings. The casebook index exposes local paths, hashes and timestamps to users of the workspace. A malicious writer who controls the case files and bundle can recompute hashes; independent signatures and trusted timestamps remain future work.

## Verification

`PYTHONPATH=src python -m unittest discover -s tests -q` (46 tests in local build, including synthesized format fixtures and malformed-header probes); run a platform matrix before release. On case search, inspect `indexed_utc` and reverify the selected case with `--recheck-target`.
