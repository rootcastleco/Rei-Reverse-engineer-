# Reviewed external provider discovery (v0.3 preview)

The `rei-rea providers list` command enumerates twelve candidate upstream engines, upstream links, local executable presence, and reviewed fixed static adapters. PATH presence is not a verified version, license entitlement, or end-to-end functionality.

| Tool | Role | Review status |
| --- | --- | --- |
| Ghidra | Native decompiler | Discovery only; analysis writes project data |
| radare2/rabin2 | Static metadata | `rabin2 -I` adapter, explicit opt-in |
| Rizin/rz-bin | Static metadata | `rz-bin -I` adapter, explicit opt-in |
| LIEF | Format-aware library | Discovery only; Python API integration not implemented |
| LLVM readobj | Object file headers | Existing vetted static adapter |
| JADX | Android decompiler | Discovery only; writes output |
| Apktool | Android resources | Discovery only; writes output |
| Binwalk | Firmware signatures | Discovery only; mode/side effects require validation |
| unblob | Firmware unpacker | Discovery only; extraction writes files |
| Frida | Runtime instrumentation | Discovery only; runtime authorization required |
| angr | Symbolic analysis | Discovery only; Python API integration not implemented |
| QEMU | Emulation | Discovery only; guest execution is not static analysis |

## Examples

```bash
rei-rea providers list
rei-rea providers inspect radare2 file.elf --allow-external
rei-rea providers inspect rizin file.elf --allow-external
rei-rea providers inspect llvm file.elf --allow-external
```

Provider installation is not automated. MCP exposes read-only `rei_rea_providers`; MCP cannot execute external binaries. The CLI invokes only vetted fixed argument templates, with `shell=False` and an explicit authorization flag. Run third-party parsers in an OS sandbox when inspecting hostile samples.
