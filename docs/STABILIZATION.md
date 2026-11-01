# Stabilization milestone — 2026-11-01

## Baseline and repository audit

Canonical repository: https://github.com/rootcastleco/Rei-Reverse-engineer

Baseline: `48c257c631e89ed704d7d497af2a8910f18b5313`, Python package 0.2.0.
Local environment: Windows 11 build 26300, Anaconda CPython 3.14.7, AMD64.
The unmodified suite ran 52 tests in 79.166 seconds: 50 passed, one
`plan` CLI timeout (10 seconds), one skipped because `file` was absent.
The environment restricts listing of several PATH directories. A reduced PATH
passed the failing test, identifying executable discovery as the bottleneck.

Remote main CI succeeded at this exact baseline SHA:
https://github.com/rootcastleco/Rei-Reverse-engineer/actions/runs/41323430052
No published releases were returned by the repository release listing.
Topics were empty; About metadata referenced older scope.

Open changes reviewed:

- PR #6, `5d24e76de03cd577bac5b835bace3c337099e172`: bounded electronics intake,
  CLI/MCP endpoint and a specialist skill. CI succeeded at that SHA in run
  41323544503. This is signature/checksum intake, not PCB reconstruction.
  Record validation accepts unsupported S-record types; follow-up acceptance
  must explicitly separate checksums from full format parsing. Kept separate
  from this stabilization PR so its intake contract can be tightened first.
- PR #4, `ce852cb5b0ae7e119ab4c461687e29256d398d03`: only the upstream gitlink
  changes from `f72638f6` to `aa48d494`. CI run 41322739682 is `action_required`.
  No upstream API compatibility has been established; no automatic merge.
- Other remote feature branches have corresponding historical changes; the
  open-PR inventory returned only #4 and #6.

## Observable requirements and verification

| ID | Requirement | Verification |
| --- | --- | --- |
| STAB-01 | Canonical URLs in active package/docs/metadata | tracked-file search; metadata tests |
| STAB-02 | Catalog flags equal code-owned adapter IDs in both directions | `test_discovery` and regeneration CI gate |
| STAB-03 | Detecting r2 alone does not advertise rabin2 execution | frontend-only discovery regression |
| STAB-04 | No stale PATH results between requests | create/remove executable regression |
| STAB-05 | Windows discovery preserves `shutil.which` authority | denied-directory fallback and final resolver tests |
| STAB-06 | Original CLI `plan` passes its unchanged 10-second deadline | `test_cli.CliTests.test_inspect_and_plan_cli` |
| STAB-07 | Legacy CLI/MCP/evidence contracts continue working | full regression suite |

Discovery snapshots enumerate Windows directories once when permitted and
resolve potential matches with `shutil.which`. Unlistable directories cause
a conservative fallback to the standard resolver with eight concurrent I/O
workers. No tool is executed, no result persists across requests, and there is
no ceiling on registry size. Network paths can still be slow; this does not
implement cancellation of blocked operating-system filesystem calls.

`installed` and `resolved_executable` retain their historical PATH meaning.
Additive fields `adapter_available` and `adapter_executable` identify the exact
fixed command's executable. They do not establish versions, licensing, or E2E
verification. The dashboard and doctor use this more precise availability.

## Scope and release gate

This milestone does not add external engines or alter evidence files. The
14 MCP tools, 12 provider profiles and 12 skills remain available. Eleven fixed
adapters exist; their installation and actual parser accuracy are independent
checks. No full desktop application or hardware verification is claimed.

Release gates: local regression suite, all skill validations, deterministic
catalog regeneration, wheel build/smoke test and the remote six-job OS/Python
matrix. Record measured results in the PR; do not infer a release from CI alone.

## Executable next milestones

1. **Electronics intake / PR #6:** add unsupported-record-type, termination,
   count, truncated-UF2 and misleading-header fixtures. Define Recognized vs
   Parsed separately. Merge only after exact-head CI and contract review.
2. **Provider contract v1:** normalize fixed-adapter outputs with tool version,
   artifact hash, operation schema, error category and limits. Real rabin2,
   rz-bin and LLVM tests must pass on pinned installations; otherwise label
   E2E NOT VERIFIED. Preserve the existing `run` response fields.
3. **Firmware address maps:** Intel HEX/S-record/UF2 parsing with checksum,
   address/overlap and termination checks; CLI and MCP share one parser.
   Malformed fixtures, bounded reads and >=85% new-module coverage are gates.
4. **Artifact graph:** versioned local nodes/edges with artifact hash, source,
   parser version and OBSERVED/INFERRED/VERIFIED status. Test contradictions,
   stale identities and round trips before linking firmware to hardware.
5. **Engineering application:** evaluate local web, PySide and Tauri against
   packaging cost and existing Python interfaces; implement one real case
   timeline/import/report workflow, keyboard navigation and EN/TR strings.
6. **Distribution:** reproducible wheel/sdist, license inventory, SBOM and
   attestations; verify each built platform artifact before publication.

Upstream compatibility, physical measurements, proprietary providers and
cross-platform desktop binaries remain unverified dependencies, not completed
features. The existing daily upstream review workflow stays independent.

## Local verification results

- Full suite: 59 tests in 79.342 seconds, 58 passed and one skipped (`file` absent), no failures. No overall-suite speedup is claimed.
- New discovery module: coverage.py 7.11.0 reports 100% statement/branch coverage (29 statements, 10 branches); seven focused tests. This is not whole-project coverage.
- All 12 skills passed the installed skill validator.
- Python wheel built locally; publication and platform-specific executables remain separate gates.
- The original CLI timeout regression passes on the existing PATH without changing its 10-second deadline.
- External-engine E2E, peak memory and parser performance benchmarks were not measured in this milestone.
