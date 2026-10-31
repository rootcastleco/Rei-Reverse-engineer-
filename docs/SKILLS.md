# REI REA skills · installation and boundaries

There are **12** independent skill folders under `/skills`, each with `SKILL.md`, `agents/openai.yaml` and focused references.

- Primary public upload artifact: `dist/skill.zip` contains only `rei-rea-orchestrator` as a valid standalone skill instruction bundle.
- Specialist skill folders can each be packaged individually with `python /home/oai/skills/skill-creator/scripts/package_skill.py skills/rei-native-binaries dist/...` when the packager is available. Alternatively copy each folder into your own agent skill directory.
- `all-skills.zip` is a multi-skill distribution archive for bulk/manual installation. **Do not submit it as a single skill ZIP to a one-skill importer**; unpack and install each folder independently.
- Skills are **instructions**. They are not Python packages, analysis engines, MCP registrations or privileges. Install this repository's Python project separately and register the MCP transport if your host supports it.

## Routing

Use `rei-rea plan TARGET` as the authoritative format-specific routing hint. The planner does not know whether a Ghidra extension, a mobile emulator or a developer account is configured; `tools doctor` sees only local executable names. A skill should inspect available evidence and never assert capabilities solely because a tool appears in the catalog.

## Verification

```bash
python /home/oai/skills/skill-creator/scripts/quick_validate.py skills/rei-rea-orchestrator
python /home/oai/skills/skill-creator/scripts/package_skill.py skills/rei-rea-orchestrator dist
python skills/rei-rea-orchestrator/scripts/doctor.py
```

Exact paths to the `skill-creator` validator/packager depend on the environment; the commands above were used in the build environment and are not guaranteed on an end user's machine.

The v0.2 specialist skills `rei-binary-intelligence` and `rei-casebook-forensics` cover built-in structural parsers and metadata-only searchable evidence exports. The legacy skill generator now refuses to overwrite curated contents without an explicit `--force`.
