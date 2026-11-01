# Electronics and firmware intake

This extension covers **file classification and routing**, not universal decompilation or verified hardware reconstruction.

## Supported by suffix (NOT validated as a format)

- KiCad and other board/schematic formats: .kicad_pcb, .kicad_sch, .sch, .brd, .lbr, .kicad_mod
- PCB manufacturing: Gerber copper/mask/silkscreen (.gbr, .gtl, .gbl, .gts, .gbs); Excellon drill (.drl, .xln)
- Embedded firmware: Intel HEX, Motorola S-record, UF2, ELF, binary images, DFU, FPGA bitstreams and JEDEC
- Logic analyzer and oscilloscope: VCD, FST, Saleae data and sigrok sessions, TDMS and CSV
- Electronic CAD/simulation: Verilog, VHDL, EDIF, SPICE and circuit netlists
- Mechanical CAD: STEP, IGES, STL, 3MF, DXF and DWG

Each output clearly marks **extension-only** vs **header/record-validated**. The validated classes are Intel HEX records, Motorola S-records, UF2 sampled blocks, KiCad text headers, Gerber headers, VCD headers and ELF magic. Only Intel HEX and S-record implement whole-file checks, within a 2 MiB analysis cap. Other headers alone do not guarantee whole-file validity.

## Usage

\`\`\`shell
rei-rea electronics board.kicad_pcb
rei-rea electronics controller.hex
rei-rea electronics capture.vcd
\`\`\`

The MCP method \`rei_rea_electronics\` has the same read-only contract, requiring a single local target path. Output includes complete-file SHA-256, byte count, claimed family, signature evidence, sample limits and suitable candidate tools. External software is neither downloaded nor executed.

## Recommended workflows (future adapters)

- **PCB / netlist:** KiCad native symbols, pad mapping, top/bottom photography and continuity evidence; separate visually inferred connections from measured nets. Use \`kicad-cli\` ERC once the design is verified enough to export.
- **Gerber / drill:** Parse RS-274X and Excellon geometry, coordinate units and apertures; reconstruct layer stacks only with supporting evidence. Do not claim that a fabrication export proves the original schematic.
- **Firmware:** Detect architecture, partition maps, embedded filesystems, executable code and checksums. Extraction and decompilation must be explicit and sandboxed.
- **Logic and waveforms:** Match sample rates, units and time origins; avoid treating signal edges as electrical pinout verification.
- **HDL/FPGA:** Perform syntax and netlist checks with pinned licensed tooling. Never treat bitstream reverse engineering as equivalent to original HDL.
- **Industrial electronics:** Only offline captures and safely isolated boards may be analyzed without further authorization; powered measurements require qualified operators.

## Limitations and security

No hardware is energized or flashed. No firmware encryption, secure boot, or licensing protections are bypassed. Tool recommendations are catalog candidates, not installed or verified integrations. Do not send proprietary board photos, firmware or customer captures to third-party web services without permission.
