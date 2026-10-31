---
name: rei-wasm-and-managed
description: >-
  Trace authorized WebAssembly, .NET, Java, IL, JVM bytecode and managed package control flow. Use for manifest/metadata triage, type recovery, IL inspection, WASM import/export tracing, obfuscation assessment and compatible API reconstruction.
---

# REI WASM and Managed Code

## Entry contract

Use only the target the user provides or explicitly authorizes. Establish the question, artifact SHA-256, permitted scope, desired output and actually available tools. If repository source is complete, inspect it first instead of treating every task as binary RE.

## Available tooling

Use `wasm-tools`, `WABT`, `Binaryen`, `ILSpy`, `dnSpyEx`, `ildasm`, `monodis`, `javap`, `CFR`, and compatible bytecode analyzers only when actually available.

## Procedure

1. Hash artifact and confirm format using header and container checks.
2. Recover module/type/import/export tables, metadata and declared interfaces.
3. Trace one method and its caller contract with exact offsets and signatures.
4. Cross-check generated source against bytecode; document lost symbols and generics.
5. Build a separate compatible implementation and test stable fixture outputs.

## Evidence and limits

Do not confuse decompiler output with original handwritten code; static graphs do not establish actual runtime paths.

For every conclusion record: target hash, source address/offset/file line, method and version, status (`observed`/`inferred`/`unknown`), coverage, alternative hypotheses, next verification. Do not invent installed tools or report target execution that did not happen.

See [workflow checkpoints](references/workflow.md) for outputs and acceptance criteria.
