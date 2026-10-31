# REI REA v0.1 specification and verification map

## User stories

- **REA-001** Analyst can discover tools in one catalog with platform-level presence status **without execution**. Test: `test_registry`.
- **REA-002** Analyst can provide a local target and receive SHA-256, verifiable magic and bounded inventory. Tests: `test_inspector`.
- **REA-003** Analyst can get a domain-specific skill and tool workflow without fabricated implementation claims. Test: `test_mcp.test_plan_static`.
- **REA-004** Analyst can create and verify local evidence records, detect event changes and target mutation. Test: `test_evidence`.
- **REA-005** Analyst can launch only predefined static parsers with explicit CLI authorization and timeout. Tests: `test_registry`, `test_cli`.
- **REA-006** Agent can use one stdio MCP interface to the same core capabilities. Test: end-to-end subprocess handshake in `test_mcp`.
- **REA-007** Analyst can compare known file revisions and inspect bounded entropy/signatures with strings suppressed by default. Test: `test_signals`.
- **REA-008** Analyst can browse catalog over local HTTP with no write/execution endpoints. Test: web handler definition and planned localhost E2E.
- **REA-009** Ten standalone specialist skill entrypoints have valid frontmatter and task-specific acceptance. Test: external `quick_validate.py` for each and packaged root skill.

## Explicit exclusions

- Full upstream REA API parity, native semantic decompilation, runtime trace collection, cloud file uploading, automatic package installation, web scraping, target execution, firmware programming, live network scanning or commercial license bypass.

## Release acceptance criteria

- Python 3.10+ installation and all unit/integration tests pass in a locally available runtime.
- Zero default external analysis program executions for `inspect`, `signals`, `plan`, `compare`, `tools doctor` and MCP methods.
- New `run` accepts only a fixed code-reviewed adapter ID and explicit opt-in.
- Every response reports bounded inspection and evidentiary limitations.
- The case hash chain detects a one-field modification and optional target rehash detects changes.
- Ten validated skill folders and at least one valid single-skill ZIP.
- No claim of CI success until the remote GitHub Actions matrix executes.

## Rollback

Features are additive in a new repository. To disable tool launching, never call `run`; remove its CLI entry and tests in a rollback commit. To disable MCP, remove client registration rather than changing the analyst host. To revert the entire proposal, close the feature branch/PR; `main` remains intact.
