# Learning REA — evidence-based curriculum

This expands the supplied REA roadmap into independent, measurable training labs. The books/papers are **references**, not content reproduced or imported into an AI model. Learn by tracing and verifying an artifact, not by collecting links.

## Phase 0 — tool literacy (2 labs)

- Read the upstream [REA overview](https://github.com/morluto/rea) and distinguish **skill instructions**, **MCP registration** and **analysis engine**.
- `rei-rea tools doctor`: reproduce catalog counts on two machines, explain why PATH discovery is not provider readiness.
- Acceptance: output contains inventory, availability limits and no false capability claims.

## Phase 1 — static evidence (3 labs)

- Inspect a locally built Hello World PE/ELF; derive SHA-256, architecture, entry points and section observations.
- Use [Ghidra](https://ghidra-sre.org/) or [Rizin](https://rizin.re/) independently, documenting exact address/offset and tool version.
- Analyze a synthetic ZIP containing traversal names and compression ratios; avoid extraction entirely.
- Acceptance: every claim points to its actual byte offset and alternative hypotheses.

## Phase 2 — app and IPC (2 labs)

- Trace a synthetic Electron UI button to preload IPC and a generated CSV, matching the source repository to one packaged artifact.
- Inspect a small Android test APK with declared manifest components and two DEX classes; distinguish declared permissions from executed behavior.
- Acceptance: implement the target feature using a fresh adapter and pass golden input/output checks.

## Phase 3 — firmware, protocols and managed targets (3 labs)

- Identify regions of a user-owned firmware/partition image with byte-offset evidence, never flash a production board.
- Parse a recorded local PCAP/HAR fixture, identify frame boundaries and errors, implement a stand-alone decoder.
- Inspect a WASM or .NET method, reconstruct the exported API contract and document lost symbol/type information.
- Acceptance: reproducible fixtures pass 100% on the designated sample set; report scope and negative cases.

## Phase 4 — reconstruction and research (2 labs)

- Recover one selected function from an authorized binary and compare decompilation with assembly and reference fixture outputs.
- Build differential tests, metamorphic properties, error corpus and a report with observed/inferred/unknown states.
- Acceptance: tests and coverage published; disagreements and partial behavior identified; no perfect-decompilation claims.

## Readings mapped to practice

| Resource | Why read it | Testable contribution |
| --- | --- | --- |
| [The Ghidra Book, 2nd ed. (2026)](https://nostarch.com/ghidra-book-2e) | Decompiler, scripting, data types and program analysis | Trace a call graph and corroborate with assembly |
| [Practical Binary Analysis](https://nostarch.com/binaryanalysis) | Executable formats, disassembly and instrumentation | Verify PE/ELF section and relocation claims |
| [Practical Malware Analysis](https://nostarch.com/malware) | Isolated static/dynamic workflows | Write an evidence plan for a benign lab sample |
| [OpenSecurityTraining2](https://ost2.fyi/) | Assembly and low-level platform foundations | Explain ABI and calling convention differences |
| [pwn.college](https://pwn.college/) | Reverse engineering challenges | Recover a deterministic local function |
| [LLM4Decompile](https://arxiv.org/abs/2403.05286) | Model-assisted decompilation | Recompile and check semantic accuracy, not fluency |
| [SALT4Decompile](https://arxiv.org/abs/2509.14646) | Logic tree representation | Compare control-flow hypotheses against an original test corpus |
| [Decomperson (USENIX 2022)](https://www.usenix.org/conference/usenixsecurity22/presentation/burk) | Human decompilation benchmark | Build a small measurable perfect-compiler-feedback task |
| [DIRTY (USENIX 2022)](https://www.usenix.org/conference/usenixsecurity22/presentation/chen-qibin) | Name and type prediction | Report probability vs verified original symbols |
| [TRex (USENIX 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/bosamiya) | Behavior-capturing types | Test typing against binary behavior rather than exact source |

The image also mentions `AutoDecompiler`, compiler-feedback attacks on agents and other papers. Bibliographic entries not independently checked in this release are **not** treated as validated research sources; add them after author/venue/DOI verification. Training completion is a human activity; creating this roadmap does not establish mastery of all referenced books or tools.
