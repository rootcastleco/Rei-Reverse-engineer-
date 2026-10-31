---
name: rei-evidence-ledger
description: >-
  Create and audit repeatable reverse-engineering case records with SHA-256 artifact identity, append-only hash-linked observations, source pointers, confidence and bounded negative searches. Use for forensic reproducibility, version differences, evidence reviews, technical findings, chain verification and release/compatibility claims.
---

# REI Evidence Ledger

## Entry contract

Use only the target the user provides or explicitly authorizes. Establish the question, artifact SHA-256, permitted scope, desired output and actually available tools. If repository source is complete, inspect it first instead of treating every task as binary RE.

## Available tooling

Run `rei-rea case init TARGET`, `rei-rea case note CASE --text ...`, `rei-rea case verify CASE --recheck-target` and `rei-rea case report CASE`. Attach offsets, file/line, address and method in every note.

## Procedure

1. Inspect identity and state whether capture was complete.
2. Append a source-attributed observation with tool/version and exact evidence location.
3. Keep uncertain interpretations separate from observations.
4. Re-hash artifacts, verify the event chain and export a concise limitations report.
5. For adversarial custody requirements, add separately managed digital signatures and external timestamps.

## Evidence and limits

A local hash chain detects accidental or unsophisticated tampering, but is not independently signed and does not prove legal chain of custody.

For every conclusion record: target hash, source address/offset/file line, method and version, status (`observed`/`inferred`/`unknown`), coverage, alternative hypotheses, next verification. Do not invent installed tools or report target execution that did not happen.

See [workflow checkpoints](references/workflow.md) for outputs and acceptance criteria.
