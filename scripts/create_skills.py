#!/usr/bin/env python3
"""Rebuild the REI REA skill set after reviewing/editing the specs below.

Run intentionally: existing skill files are replaced. The tool is not run at install time.
"""
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
INIT=Path('/home/oai/skills/skill-creator/scripts/init_skill.py')
SPECS = {
    'rei-rea-orchestrator': {
        'title': 'REI REA Orchestrator',
        'description': 'Route authorized reverse-engineering investigations across native binaries, Android APKs, Electron apps, firmware, browser artifacts, .NET and WebAssembly. Use when a target file or app is supplied and the user asks what it does, to trace one feature, assess coverage, compare versions or reconstruct behavior with evidence. Coordinate the central REI REA CLI/MCP catalog, SHA-256 case ledger and specialist skills. Do not imply external engines are installed, licensed or automatically executed.',
        'tools': 'Use `rei-rea tools doctor`, `rei-rea inspect TARGET`, `rei-rea plan TARGET`, and `rei-rea case init TARGET`. In an MCP client, prefer `rei_rea_inspect`, `rei_rea_plan`, `rei_rea_case_create`, `rei_rea_tools` when actually registered.',
        'workflow': '1. Establish the exact artifact, question, authorization and analysis boundary.\n2. Inspect sources first when complete; otherwise hash and inventory the supplied artifact.\n3. Load the specialist skill based on observed format, not file extension.\n4. Start a case with evidence IDs and mark observed/inferred/unknown separately.\n5. Avoid execution until a specific runtime question, isolated environment and permission are established.\n6. Derive behavioral spec, local implementation and parity corpus; report pass/fail and unresolved gaps.',
        'guard': 'Never claim this skill installed engines or MCP. Read-only triage is default. Do not bypass third-party licensing, steal credentials, or operate against unauthorized targets. The command catalog is discovery, not automatic provisioning.'
    },
    'rei-native-binaries': {
        'title': 'REI Native Binaries',
        'description': 'Inspect authorized PE, ELF, Mach-O, COFF and native dynamic libraries. Use for x86/x64/ARM symbol and import analysis, function-call tracing, compiler artifact identification, Ghidra/radare2/IDA evidence, decompilation comparisons, patch impact and ABI compatibility reconstruction. Ground interpretations in addresses, sections, hashes and tool versions instead of assuming pseudocode equals source.',
        'tools': 'Preferred: `readelf`, `objdump`, `llvm-readobj`, `Ghidra`, `radare2`, `Rizin`, `Cutter`, `x64dbg`, `LLDB`. First run `rei-rea inspect PATH` and `rei-rea plan PATH`; `rei-rea run readelf PATH --allow-external` is opt-in only.',
        'workflow': '1. Verify PE/ELF/Mach-O header, architecture, ABI and artifact hash.\n2. Inventory sections, entry points, imports and resources before interpreting code.\n3. Trace a single feature through callers, xrefs and data transforms; capture addresses and confidence.\n4. Cross-check pseudocode against assembly, calling conventions and independent probes.\n5. For a rebuild, specify inputs/outputs and test a fixed corpus under a controlled environment.',
        'guard': 'Do not treat compiler-generated code as original source; do not execute a suspicious binary merely to obtain faster results.'
    },
    'rei-electron-and-js': {
        'title': 'REI Electron and JavaScript',
        'description': 'Investigate Electron/ASAR, Node.js, browser JavaScript bundles, preload APIs, IPC routes, source maps and client-side workflows for authorized application analysis and feature reconstruction. Trigger for Electron desktop installers, packed app.asar, minified JavaScript, browser app call graphs or IPC-based features.',
        'tools': 'Prefer textual inventory and `rg`, `asar`, source-map viewers, JS parser and officially registered upstream REA JavaScript analyzer. Record exact module paths, import edges and IPC channel names.',
        'workflow': '1. Inventory package.json, ASAR manifest and code origins; identify Electron main, renderer and preload.\n2. Locate the UI action by labels/listeners and follow IPC to backend handlers.\n3. Identify file writes, network requests and data serialization by direct code evidence.\n4. Rebuild the smallest interoperable feature behind an adapter.\n5. Verify with authorized sample traces and a version-locked fixture.',
        'guard': 'Do not infer runtime results from string matches; executing app packages or connecting live accounts requires separate authorization.'
    },
    'rei-android-apks': {
        'title': 'REI Android APKs',
        'description': 'Analyze user-supplied Android APK, AAB, DEX and Android manifests using read-only triage, JADX, Apktool and Android SDK metadata. Trigger for Android application architecture, Java/Kotlin class tracing, app permissions, manifest components, JNI boundaries and compatible local functionality reconstruction.',
        'tools': 'Catalog: `jadx`, `apktool`, `aapt2`, `apkanalyzer`, `dex2jar`, `baksmali`, `androguard`; `adb` and `Frida` are runtime tools requiring an isolated authorized test device.',
        'workflow': '1. Hash package and inspect archive boundaries without extracting untrusted members.\n2. Inventory manifest package, exported components, permissions and DEX files with appropriate tools.\n3. Trace entry Activity/Service to method calls and JNI/native code if present.\n4. Record obfuscation and resource decoding uncertainty; separate static and observed evidence.\n5. Define API/UI behavior and run device-level parity tests only with owner permission.',
        'guard': 'Never claim JADX recovers the original source or that an APK is benign because no suspicious strings were found.'
    },
    'rei-firmware-and-iot': {
        'title': 'REI Firmware and IoT',
        'description': 'Study authorized MCU, UEFI, embedded Linux, automotive telemetry, gateway, GPS/IoT and other firmware images. Use for file-system identification, container carving, SoC architecture hypotheses, boot-chain mapping, serial traces, protocol frame documentation and safe compatibility implementations.',
        'tools': 'Catalog: `binwalk`, `ubi_reader`, `jefferson`, `UEFITool`, `dtc`, `squashfs-tools`, `Ghidra`, `QEMU`, `Wireshark`, `tshark`. Hardware tools need explicit electrical and scope checks.',
        'workflow': '1. Identify acquisition method, hash and hardware revision.\n2. Map partitions, headers, byte offsets, compression and endianness without extraction.\n3. Extract only in a sandbox after checking traversal and decompression limits.\n4. Correlate code with hardware register maps, schematics, UART/logic recordings.\n5. Validate on a non-production device with recoverable firmware and rollback image.',
        'guard': 'Do not flash unknown images, infer power pinouts or change physical device state without independent verification.'
    },
    'rei-mobile-runtime': {
        'title': 'REI Mobile Runtime',
        'description': 'Perform explicitly authorized Android/iOS runtime-observation planning for owned devices or lab apps, including method instrumentation, app process traces, mobile network logs and static-to-dynamic hypothesis checks. Use only when static evidence cannot answer an app behavior question.',
        'tools': 'Use `Frida`, `adb`, platform LLDB, and controlled proxy traces when installed, permitted and appropriate. MCP skill instructions are not device access.',
        'workflow': '1. Write the precise observation question and app/device identities.\n2. Prepare a disposable test profile with no real customer secrets.\n3. Record baseline, clocks, tool versions and filtered hooks.\n4. Observe specific method or protocol behavior, not unrelated user data.\n5. Save evidence pointers and tear down hooks; compare with static hypotheses.',
        'guard': 'No covert instrumentation, unauthorized surveillance or bypass of account restrictions. Scope ownership and user consent explicitly.'
    },
    'rei-evidence-ledger': {
        'title': 'REI Evidence Ledger',
        'description': 'Create and audit repeatable reverse-engineering case records with SHA-256 artifact identity, append-only hash-linked observations, source pointers, confidence and bounded negative searches. Use for forensic reproducibility, version differences, evidence reviews, technical findings, chain verification and release/compatibility claims.',
        'tools': 'Run `rei-rea case init TARGET`, `rei-rea case note CASE --text ...`, `rei-rea case verify CASE --recheck-target` and `rei-rea case report CASE`. Attach offsets, file/line, address and method in every note.',
        'workflow': '1. Inspect identity and state whether capture was complete.\n2. Append a source-attributed observation with tool/version and exact evidence location.\n3. Keep uncertain interpretations separate from observations.\n4. Re-hash artifacts, verify the event chain and export a concise limitations report.\n5. For adversarial custody requirements, add separately managed digital signatures and external timestamps.',
        'guard': 'A local hash chain detects accidental or unsophisticated tampering, but is not independently signed and does not prove legal chain of custody.'
    },
    'rei-reconstruction-parity': {
        'title': 'REI Reconstruction Parity',
        'description': 'Reimplement a single observed application or firmware behavior from evidence while preserving original product boundaries. Use for clean-room compatibility, API replacement, local rebuilds, feature-level parity testing, corpus design, differential tests and regression-proof delivery.',
        'tools': 'Use the existing project test runner and REI case ledger. Build a fixture manifest with fixed input/output pairs. External REA analysis tools are optional sources, not proof of parity.',
        'workflow': '1. Turn observed behavior into a spec with explicit unknowns.\n2. Separate code ownership and reference evidence; do not copy private data or leaked credentials.\n3. Implement via adapter/gateway/feature flag, leaving the old core intact.\n4. Build golden tests, negative tests, metamorphic properties and timing tolerance where relevant.\n5. Publish parity coverage, mismatches, fallback and rollback procedures.',
        'guard': 'Do not copy source merely because decompilation is available or claim binary-identical reproduction without measurements.'
    },
    'rei-web-and-protocols': {
        'title': 'REI Web and Protocols',
        'description': 'Analyze user-provided HAR/PCAP/PCAPNG, documented APIs, browser workflows, GPS/IoT telemetry protocols and data formats for lawful interoperability. Use to trace request serialization, network frame boundaries, state machines, pagination, error semantics and latency from supplied recordings.',
        'tools': 'Use `tshark`, `Wireshark`, `mitmproxy`, `protobuf`, `grpcurl`, `Kaitai Struct`, and browser DevTools with user-authorized recordings. Never transform a packet capture into claims about a live server without corroboration.',
        'workflow': '1. Identify provenance and hash of supplied recording; note packet loss or redaction.\n2. Inventory endpoints, streams, frame lengths, time ordering and protocol versions.\n3. Create a state-machine and sample input/output fixtures with secrets redacted.\n4. Implement a local parser and compare byte framing, checksum, error handling and field interpretation.\n5. Test malformed and boundary frames without probing any production endpoint.',
        'guard': 'Do not perform intrusive network scanning, traffic interception or credential collection outside explicit authorization.'
    },
    'rei-wasm-and-managed': {
        'title': 'REI WASM and Managed Code',
        'description': 'Trace authorized WebAssembly, .NET, Java, IL, JVM bytecode and managed package control flow. Use for manifest/metadata triage, type recovery, IL inspection, WASM import/export tracing, obfuscation assessment and compatible API reconstruction.',
        'tools': 'Use `wasm-tools`, `WABT`, `Binaryen`, `ILSpy`, `dnSpyEx`, `ildasm`, `monodis`, `javap`, `CFR`, and compatible bytecode analyzers only when actually available.',
        'workflow': '1. Hash artifact and confirm format using header and container checks.\n2. Recover module/type/import/export tables, metadata and declared interfaces.\n3. Trace one method and its caller contract with exact offsets and signatures.\n4. Cross-check generated source against bytecode; document lost symbols and generics.\n5. Build a separate compatible implementation and test stable fixture outputs.',
        'guard': 'Do not confuse decompiler output with original handwritten code; static graphs do not establish actual runtime paths.'
    },
}


def run():
    for slug, spec in SPECS.items():
        target=ROOT/'skills'/slug
        if not target.exists():
            if INIT.exists():
                subprocess.run([sys.executable,str(INIT),slug,'--path',str(ROOT/'skills')],check=True)
            else:
                target.mkdir(parents=True)
        for fname in ('scripts/example.py','references/api_reference.md','assets/example_asset.txt'):
            (target/fname).unlink(missing_ok=True)
        for dirname in ('scripts','references','assets','agents'):
            (target/dirname).mkdir(parents=True,exist_ok=True)
        (target/'agents/openai.yaml').write_text('interface:\n  display_name: "'+spec['title']+'"\n  short_description: "'+spec['title']+' investigation workflow"\n',encoding='utf-8')
        skmd=f'''---
name: {slug}
description: >-
  {spec['description']}
---

# {spec['title']}

## Entry contract

Use only the target the user provides or explicitly authorizes. Establish the question, artifact SHA-256, permitted scope, desired output and actually available tools. If repository source is complete, inspect it first instead of treating every task as binary RE.

## Available tooling

{spec['tools']}

## Procedure

{spec['workflow']}

## Evidence and limits

{spec['guard']}

For every conclusion record: target hash, source address/offset/file line, method and version, status (`observed`/`inferred`/`unknown`), coverage, alternative hypotheses, next verification. Do not invent installed tools or report target execution that did not happen.

See [workflow checkpoints](references/workflow.md) for outputs and acceptance criteria.
'''
        (target/'SKILL.md').write_text(skmd,encoding='utf-8')
        (target/'references/workflow.md').write_text(f'''# {spec['title']} — acceptance checkpoints

## Input

- Authorized local artifact or source repository, concrete question and environment constraints
- SHA-256 artifact identifier and expected output type

## Workflow

{spec['workflow']}

## Minimum output

| Claim | State | Evidence pointer | Tool / version | Verification | Limitation |
| --- | --- | --- | --- | --- | --- |
| Example claim | unknown | pending | pending | independent fixture | not examined |

## Acceptance

1. Every claim has explicit evidence and uncertainty.
2. Input identity is stable or the changed hash is flagged.
3. Unavailable providers are named; no unsupported success claim.
4. Reconstructed behavior has passing and failing cases documented.
5. Scope/security approvals are explicit for any execution or live traffic.
''',encoding='utf-8')
    primary=ROOT/'skills/rei-rea-orchestrator'
    (primary/'references/QUICKSTART.md').write_text('''# REI REA primary interface

Install the project package with `python -m pip install -e .` at the repository root. A Skill is not a Python installation and does not register MCP on its own.

- `rei-rea tools doctor`: local PATH discovery; no external programs executed
- `rei-rea inspect /absolute/path/to/file`: SHA-256 + header and bounded container inspection
- `rei-rea plan /absolute/path/to/file`: specialist routing and candidate tools
- `rei-rea case init /absolute/path/to/file --workspace .rei-cases`: local case and hash chain
- `rei-rea case verify /absolute/path/to/case --recheck-target`: verify integrity and identity
- `rei-rea case report /absolute/path/to/case`: reproduce report
- `rei-rea run file /absolute/path/to/file --allow-external`: vetted host parser, explicit consent
- `rei-rea mcp`: stdio MCP with 6 high-level tools
- `rei-rea serve --port 8765`: local tool catalog dashboard at 127.0.0.1

Use absolute paths. Command availability and tool installation are separate. Do not execute a suspicious input on a trusted machine.
''',encoding='utf-8')
    script=primary/'scripts/doctor.py'
    script.write_text('''#!/usr/bin/env python3
"""Check the installed REI REA CLI without downloading or executing targets."""
import subprocess
import sys

result = subprocess.run([sys.executable, "-m", "rei_rea", "tools", "doctor"], check=False)
raise SystemExit(result.returncode)
''',encoding='utf-8')
    print(f'Wrote {len(SPECS)} skills')


if __name__=='__main__':
    run()
