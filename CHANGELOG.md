# Changelog

## Unreleased — stabilization

- Unify catalog adapter flags with code-owned commands; expose exact adapter availability.
- Batch Windows discovery with a permission-aware, bounded parallel fallback.
- Repair canonical repository identity, current capability documentation and About metadata.
- Add discovery regression tests and a catalog regeneration CI gate.


## 0.1.0 — 2026-10-31

- Introduce independent Rootcastle REI REA CLI, bounded static inspector, central catalog of 124 external tools, 9 opt-in static parser adapters, case hash chain, signals and comparisons.
- Add 8-tool local stdio MCP endpoint, 10 specialist skill entrypoints and read-only loopback catalog dashboard.
- Add test suite, GitHub Actions matrix definition, documentation and reproducible packaging scripts.
- Explicitly separate future upstream REA/Ghidra/JADX/native integrations from delivered behavior.

### Repository discoverability and documentation

- Replace the placeholder README with an evidence-grounded English guide, Mermaid architecture, MCP setup, capability matrix, FAQ and security limits.
- Add 18 curated GitHub Topics, About description and homepage to a validated metadata manifest; include a dry-run-first GitHub sync tool.
- Add metadata sync tests, package discovery keywords, and the existing MIT license to the distributed source.

## 0.2.0 — structural analysis and local casebook

- Added built-in bounded PE/ELF/WASM structural parsers and structural diffs.
- Added SHA-consistent static `investigate` workflow (max 64 MiB).
- Added SQLite casebook index/search and metadata ZIP export/verification.
- Expanded MCP from eight to thirteen read-only analysis/discovery methods.
- Added two specialist skills (12 total); retained existing v0.1 interfaces.
- Added synthetic/malformed binary regression fixtures, workflow and index tests.
- Explicitly limited authenticity and coverage claims; no external decompilers or target execution included.
