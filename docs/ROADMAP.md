# Development roadmap · evidence before promises

## Delivered — v0.1 (this branch)

- [x] Clean stand-alone Python package and CLI with no third-party runtime dependencies.
- [x] 124 curated external tool records, categorized and available in one interface.
- [x] 9 fixed read-only optional external parser adapters; no arbitrary execution.
- [x] PE/ELF/Mach-O/WASM/DEX/SQLite/ZIP/APK/IPA and other bounded format identification.
- [x] Local full SHA-256 file hashing and bounded directory identity.
- [x] Signature-offset and per-block entropy views; raw strings opt-in.
- [x] Versioned file byte comparison, bounded difference samples.
- [x] Case creation, evidence events, hash-chain verification, Markdown reports.
- [x] Format-to-skill planner and 10 independent skill entrypoints.
- [x] 8-tool stdio MCP server and read-only loopback dashboard.
- [x] Basic unit/integration suite, GitHub Actions test matrix definition.

## Deferred work from the original v0.2 proposal

- [ ] Upstream `morluto/rea` provider adapter with *actual* schema discovery and version-pinned MCP compatibility tests.
- [ ] Semantically rich artifact inventory: PE import/relocation tables, ELF symbol/xref index, Mach-O load commands, DEX manifest and Java method indexes.
- [ ] Configured sandbox runners (locked-down Windows VM, Linux user namespace, Android emulator); no automatic dynamic launch.
- [x] Durable indexed case search, exportable report bundles and baseline diff (delivered in v0.2).
- [ ] Cryptographic event-chain signing with external timestamp and key rotation.
- [ ] Malformed binary and archive fuzzing, memory/CPU quotas, threat-model conformance tests.

## Further roadmap — v0.3+ (not implemented)

- [ ] Provider API for Ghidra/PyGhidra, Rizin, JADX, Frida, QEMU, LLDB, native WASM analyzer and .NET metadata.
- [ ] Provider-aware MCP capability negotiation, tool version/feature checks, progress and cancellation.
- [ ] Queryable function graphs, symbols, types, anti-contradiction checks and negative-search coverage.
- [ ] Deterministic C/C++/Rust/Java behavioral rebuild benchmarks and differential parity suite.
- [ ] IoT/PCB/firmware evidence mapping and protocol replay against **local test fixtures only**.
- [ ] A reviewable, componentized UI for case timelines, cross-version xrefs and side-by-side code evidence.
- [ ] Release signing, reproducible builds, SBOM, dependency and container attestations.

**Not claimed:** upstream REA feature parity, full Ghidra integration, production hardening, or automatic operation of every cataloged engine. A green unit-test suite alone does not establish those properties.

## Delivered in v0.2

- [x] Read-only bounded PE/ELF/WASM structural analysis and stable hash identities.
- [x] Structural artifact-version comparisons and single-command investigations.
- [x] Metadata-only local SQLite casebook and explicit search/index operations.
- [x] Portable case bundles with internal checksums, excluding raw targets.
- [x] Expanded stdio MCP surface (13 named tools) and two additional specialist skills.

## v0.3 priorities

- [ ] Integrate upstream REA through version-pinned, contract-tested provider adapters after API capability negotiation.
- [ ] Add DEX class/method indexes and PE relocation/resource directories, ELF extended-header and symbol/xref validation.
- [ ] Run coverage-guided parser fuzzing (AFL++/libFuzzer via wrapper) and establish memory/CPU budgets.
- [ ] Optional signed, externally timestamped evidence receipts with documented key custody and rotation.
- [ ] Portable dashboard for casebook browsing with explicit opt-in, authentication and local threat model.

## Current execution plan

The next vertical slices and their executable acceptance gates are tracked in [STABILIZATION.md](STABILIZATION.md#executable-next-milestones). Historical delivered counts above describe their release, not the current total.
