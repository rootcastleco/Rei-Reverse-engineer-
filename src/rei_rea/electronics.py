"""Bounded electronics and embedded-format intake; extension is only a hint."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

MAX_SAMPLE = 2 * 1024 * 1024
FAMILIES = {
 "pcb-cad": (".kicad_pcb .kicad_sch .kicad_pro .sch .brd .pcb .dsn .kicad_mod .kicad_sym .lib .lbr", "kicad-cli gerbv pcb-rnd"),
 "gerber": (".gbr .ger .gtl .gbl .gts .gbs .gto .gbo .gko .gml .gm1 .art", "gerbv tracespace kicad-cli"),
 "excellon": (".drl .xln .exc .ncd", "gerbv kicad-cli"),
 "firmware": (".hex .ihex .s19 .s28 .s37 .srec .s1 .s2 .s3 .uf2 .elf .bin .rom .img .fw .dfu .eep .bit .sof .jed .svf .jic", "binwalk unblob ghidra srec_cat"),
 "logic-waveform": (".vcd .fst .wfm .sr .srzip .sal .logicdata .csv .tdms", "sigrok-cli pulseview gtkwave"),
 "hdl": (".v .sv .vhd .vhdl .edif .edf .xdc .sdc .qsf", "yosys iverilog ghdl"),
 "spice": (".cir .sp .spice .net .raw .asc", "ngspice ltspice"),
 "mechanical-cad": (".step .stp .iges .igs .stl .3mf .dxf .dwg .obj", "freecad openscad"),
}
FORMAT_REGISTRY = {ext: {"family": family, "tools": tools.split()} for family, (exts, tools) in FAMILIES.items() for ext in exts.split()}

def _intel_hex(sample: bytes) -> bool:
    count = 0
    for raw in sample.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith(b":") or len(line) < 11 or (len(line) - 1) % 2:
            return False
        try:
            record = bytes.fromhex(line[1:].decode("ascii"))
        except (UnicodeError, ValueError):
            return False
        if len(record) < 5 or len(record) != record[0] + 5 or sum(record) % 256:
            return False
        count += 1
    return count > 0

def _srec(sample: bytes) -> bool:
    count = 0
    for raw in sample.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not re.fullmatch(rb"S[0-9][0-9A-Fa-f]+", line) or len(line) % 2:
            return False
        try:
            record = bytes.fromhex(line[2:].decode("ascii"))
        except (UnicodeError, ValueError):
            return False
        if len(record) < 2 or record[0] != len(record) - 1 or sum(record) % 256 != 255:
            return False
        count += 1
    return count > 0

def _uf2(sample: bytes) -> bool:
    if len(sample) < 512 or len(sample) % 512:
        return False
    # UF2 magics in little-endian byte order; check sampled block boundaries.
    for offset in range(0, len(sample), 512):
        block = sample[offset:offset + 512]
        if not (block[:4] == b"UF2\n" and block[4:8] == b"WQ]\x9e" and block[-4:] == b"0o\xb1\n"):
            return False
    return True

def inspect_electronics(path: str | Path) -> dict:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise ValueError("Symlink target refused")
    p = candidate.resolve(strict=True)
    if not p.is_file():
        raise ValueError("Expected a regular file")
    digest = hashlib.sha256()
    data = bytearray()
    size = p.stat().st_size
    with p.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            if len(data) < MAX_SAMPLE:
                data.extend(block[:MAX_SAMPLE - len(data)])
    sample = bytes(data)
    ext = p.suffix.lower()
    declared = FORMAT_REGISTRY.get(ext)
    verified = None
    if sample.startswith(b":") and size <= MAX_SAMPLE and _intel_hex(sample):
        verified = "intel-hex-records"
    elif sample.startswith((b"S0", b"S1", b"S2", b"S3")) and size <= MAX_SAMPLE and _srec(sample):
        verified = "motorola-s-records"
    elif sample.startswith(b"UF2\n") and _uf2(sample):
        verified = "uf2-sampled-blocks" if size > MAX_SAMPLE else "uf2-blocks"
    elif b"(kicad_pcb" in sample[:512] or b"(kicad_sch" in sample[:512]:
        verified = "kicad-text-header"
    elif b"%FSL" in sample[:512] or b"%MOMM" in sample[:512]:
        verified = "gerber-header"
    elif sample.startswith(b"$date") and b"$end" in sample[:4096]:
        verified = "vcd-header"
    elif sample.startswith(b"\x7fELF"):
        verified = "elf-magic"
    return {
        "path": str(p), "sha256": digest.hexdigest(), "size_bytes": size,
        "extension": ext, "claimed_family": declared["family"] if declared else "unknown",
        "signature_evidence": verified,
        "validation_level": "bounded-structural-sample" if verified else "extension-only-or-unknown",
        "sample_complete": size <= MAX_SAMPLE,
        "candidate_tools": declared["tools"] if declared else [],
        "analyzer_execution": False,
        "limitations": "Does not reconstruct PCB nets, extract firmware, decode traces or run third-party tools. Never infer identity solely from suffix.",
    }
