---
name: rei-electronics-reconstruction
description: Analyze user-provided PCB CAD, Gerber, drill, firmware, FPGA, logic analyzer, oscilloscope and schematic files using evidence-based electronics intake and route to appropriate tools. Use for electronics reverse engineering, firmware triage, KiCad net reconstruction, board design comparison and tracing recorded signals.
---

# REI Electronics Reconstruction

1. Begin with \`rei-rea electronics <path>\`, record full SHA-256 and declared family, and read \`docs/ELECTRONICS.md\` for exact detection boundaries.
2. Inspect images and native CAD as independent evidence; do not infer verified electrical nets from shapes, pad proximity or component conventions.
3. Route hardware, firmware, PCB, waveform and HDL tasks to specialized optional tooling only when available and explicitly authorized.
4. Keep measured / observed / inferred / unknown connectivity distinct. Never claim guessed vias, traces, pad numbers, hidden-layer connections, firmware behavior or component values are measured.
5. Export evidence tables, candidate netlists and reports as new artifacts; never overwrite the supplied originals.
6. Before release, require attributable safe measurements for critical nets and build/ERC/tests for derived CAD. Record limitations and rollback instructions.
