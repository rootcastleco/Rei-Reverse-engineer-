"""Bounded structural PE, ELF and WebAssembly inspection without target execution.

This is structural parsing, not verification that a file is safe or executable.
All offsets and counts in untrusted inputs are range-checked and capped.
"""
from __future__ import annotations

from pathlib import Path
import struct

from .inspector import inspect_path

MAX_READ = 32 * 1024 * 1024
MAX_SECTIONS = 256
MAX_NAMES = 128
MAX_SYMBOLS = 4096


class ParseError(ValueError):
    """A required structure is outside the bounded input or malformed."""


class Reader:
    def __init__(self, data: bytes, endian: str = "<") -> None:
        self.data = data
        self.endian = endian

    def part(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset > len(self.data) or size > len(self.data) - offset:
            raise ParseError(f"out-of-bounds read at file offset {offset} ({size} bytes)")
        return self.data[offset:offset + size]

    def u(self, offset: int, fmt: str) -> int:
        return struct.unpack(self.endian + fmt, self.part(offset, struct.calcsize(fmt)))[0]

    def cstr(self, offset: int, limit: int = 256) -> str:
        value = self.part(offset, min(limit, max(0, len(self.data) - offset)))
        return value.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def pe_profile(data: bytes) -> dict:
    r = Reader(data)
    if r.part(0, 2) != b"MZ":
        raise ParseError("missing MZ signature")
    pe = r.u(0x3c, "I")
    if r.part(pe, 4) != b"PE\0\0":
        raise ParseError("PE signature not found at e_lfanew")
    machine, count, timestamp, _, _, optsize, flags = struct.unpack("<HHIIIHH", r.part(pe + 4, 20))
    if count > MAX_SECTIONS:
        raise ParseError("PE section count exceeds parser limit")
    opt = pe + 24
    magic = r.u(opt, "H")
    if magic not in (0x10b, 0x20b):
        raise ParseError("unsupported PE optional header magic")
    pe64 = magic == 0x20b
    minimum = 112 if pe64 else 96
    if optsize < minimum:
        raise ParseError("truncated PE optional header")
    r.part(opt, optsize)
    image_base = r.u(opt + (24 if pe64 else 28), "Q" if pe64 else "I")
    entry = r.u(opt + 16, "I")
    dll_flags = r.u(opt + 70, "H")
    num_dirs = r.u(opt + (108 if pe64 else 92), "I")
    directories_at = opt + (112 if pe64 else 96)
    dirs: list[tuple[int, int]] = []
    for i in range(min(16, num_dirs, (optsize - minimum) // 8)):
        dirs.append((r.u(directories_at + 8 * i, "I"), r.u(directories_at + 8 * i + 4, "I")))
    sec_start = opt + optsize
    sections = []
    for i in range(count):
        pos = sec_start + i * 40
        h = r.part(pos, 40)
        name = h[:8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", h, 8)
        chars = struct.unpack_from("<I", h, 36)[0]
        sections.append({"name": name, "virtual_address": vaddr, "virtual_size": vsize,
                         "raw_offset": rawptr, "raw_size": rawsize, "characteristics": f"0x{chars:08x}"})

    def rva(offset: int) -> int:
        for sec in sections:
            start = sec["virtual_address"]
            if start <= offset < start + max(sec["virtual_size"], sec["raw_size"]):
                delta = offset - start
                if delta >= sec["raw_size"]:
                    raise ParseError(f"RVA 0x{offset:x} refers to zero-filled virtual section bytes")
                return sec["raw_offset"] + delta
        size_headers = r.u(opt + 60, "I")
        if offset < size_headers:
            return offset
        raise ParseError(f"unmapped RVA 0x{offset:x}")

    imports: list[dict] = []
    if len(dirs) > 1 and dirs[1][0]:
        table = rva(dirs[1][0])
        for i in range(MAX_NAMES):
            lookup, _, _, name_rva, iat = struct.unpack("<IIIII", r.part(table + i * 20, 20))
            if not any((lookup, name_rva, iat)):
                break
            lib = r.cstr(rva(name_rva)) if name_rva else "<missing-name>"
            thunk = rva(lookup or iat)
            functions = []
            width = 8 if pe64 else 4
            for j in range(MAX_NAMES):
                value = r.u(thunk + width * j, "Q" if pe64 else "I")
                if value == 0:
                    break
                if value & (1 << (width * 8 - 1)):
                    functions.append({"ordinal": value & 0xffff})
                else:
                    functions.append({"name": r.cstr(rva(value) + 2)})
            imports.append({"library": lib, "functions": functions, "truncated": len(functions) == MAX_NAMES})
    exports: list[str] = []
    if dirs and dirs[0][0]:
        table = rva(dirs[0][0])
        names_count = r.u(table + 24, "I")
        names_rva = r.u(table + 32, "I")
        for i in range(min(names_count, MAX_NAMES)):
            name_rva = r.u(rva(names_rva) + 4 * i, "I")
            exports.append(r.cstr(rva(name_rva)))
    return {"architecture_machine": machine, "pe_bits": 64 if pe64 else 32, "timestamp_raw": timestamp,
            "image_base": image_base, "entry_point_rva": entry, "characteristics": f"0x{flags:04x}",
            "dll_characteristics": f"0x{dll_flags:04x}", "nx_compat_flag": bool(dll_flags & 0x100),
            "aslr_dynamic_base_flag": bool(dll_flags & 0x40), "sections": sections,
            "imports": imports, "exports_sample": exports,
            "limits": {"imports_per_library": MAX_NAMES, "libraries": MAX_NAMES, "export_names": MAX_NAMES}}


def elf_profile(data: bytes) -> dict:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ParseError("missing ELF signature")
    bits = {1: 32, 2: 64}.get(data[4])
    endian = {1: "<", 2: ">"}.get(data[5])
    if not bits or not endian:
        raise ParseError("unsupported ELF class or byte order")
    r = Reader(data, endian)
    if bits == 64:
        fields = struct.unpack(endian + "HHIQQQIHHHHHH", r.part(16, 48))
    else:
        fields = struct.unpack(endian + "HHIIIIIHHHHHH", r.part(16, 36))
    filetype, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstrndx = fields
    if phnum == 0xffff or (shnum == 0 and shoff) or (shstrndx == 0xffff):
        raise ParseError("ELF extended header counts are not implemented")
    if phnum > MAX_SECTIONS or shnum > MAX_SECTIONS:
        raise ParseError("ELF extended count or section count exceeds parser limit")
    expected_ph = 56 if bits == 64 else 32
    expected_sh = 64 if bits == 64 else 40
    if (phnum and phsize < expected_ph) or (shnum and shsize < expected_sh):
        raise ParseError("ELF table entry smaller than minimum structure")
    segments = []
    for i in range(phnum):
        h = r.part(phoff + i * phsize, expected_ph)
        if bits == 64:
            ptype, pflags, poff, vaddr, _, filesz, memsz, _ = struct.unpack(endian + "IIQQQQQQ", h)
        else:
            ptype, poff, vaddr, _, filesz, memsz, pflags, _ = struct.unpack(endian + "IIIIIIII", h)
        segments.append({"type": ptype, "file_offset": poff, "file_size": filesz,
                         "virtual_address": vaddr, "memory_size": memsz, "flags": pflags})
    sections = []
    for i in range(shnum):
        h = r.part(shoff + i * shsize, expected_sh)
        if bits == 64:
            name_off, stype, sflags, addr, soff, ssize, link, info, align, entsize = struct.unpack(endian + "IIQQQQIIQQ", h)
        else:
            name_off, stype, sflags, addr, soff, ssize, link, info, align, entsize = struct.unpack(endian + "IIIIIIIIII", h)
        sections.append({"name_offset": name_off, "type": stype, "flags": sflags,
                         "address": addr, "offset": soff, "size": ssize, "link": link, "entry_size": entsize})
    if 0 <= shstrndx < len(sections):
        shstr = sections[shstrndx]
        table = r.part(shstr["offset"], min(shstr["size"], 512 * 1024))
        for s in sections:
            offset = s.pop("name_offset")
            s["name"] = table[offset:offset + 128].split(b"\0", 1)[0].decode("utf-8", "replace") if offset < len(table) else "<unresolved>"
    else:
        for s in sections:
            s["name"] = "<unresolved>"
            s.pop("name_offset")
    needed = []
    symbols = []
    for sec in sections:
        if sec["type"] not in (6, 11):
            continue
        if sec["link"] >= len(sections):
            continue
        strs = sections[sec["link"]]
        strings = r.part(strs["offset"], min(strs["size"], 1024 * 1024))
        def name_at(n: int) -> str:
            return strings[n:n + 256].split(b"\0", 1)[0].decode("utf-8", "replace") if n < len(strings) else "<unresolved>"
        if sec["type"] == 6:
            stride = 16 if bits == 64 else 8
            count = min(sec["size"] // stride, MAX_SYMBOLS)
            for i in range(count):
                dtag, value = struct.unpack(endian + ("qQ" if bits == 64 else "iI"), r.part(sec["offset"] + i * stride, stride))
                if dtag == 1:
                    needed.append(name_at(value))
        if sec["type"] == 11:
            stride = 24 if bits == 64 else 16
            for i in range(min(sec["size"] // max(sec["entry_size"] or stride, stride), MAX_SYMBOLS)):
                raw = r.part(sec["offset"] + i * max(sec["entry_size"] or stride, stride), stride)
                name_index = struct.unpack_from(endian + "I", raw)[0]
                if name_index and len(symbols) < MAX_NAMES:
                    symbols.append(name_at(name_index))
    stack = next((s for s in segments if s["type"] == 0x6474e551), None)
    return {"elf_bits": bits, "endianness": "little" if endian == "<" else "big", "machine": machine,
            "file_type": filetype, "entry_address": entry, "header_version": version,
            "segments": segments, "sections": sections, "needed_libraries": needed[:MAX_NAMES],
            "dynamic_symbol_names_sample": symbols, "gnu_stack_executable_flag": bool(stack["flags"] & 1) if stack else None,
            "limits": {"sections": MAX_SECTIONS, "symbols_examined": MAX_SYMBOLS, "symbol_names": MAX_NAMES}}


def _leb(data: bytes, start: int, end: int) -> tuple[int, int]:
    value, shift, pos = 0, 0, start
    for _ in range(5):
        if pos >= end:
            raise ParseError("truncated unsigned LEB128")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            if value > 0xffffffff:
                raise ParseError("LEB128 exceeds u32 range")
            return value, pos
        shift += 7
    raise ParseError("LEB128 exceeds five-byte u32 limit")


def _name(data: bytes, offset: int, end: int) -> tuple[str, int]:
    count, pos = _leb(data, offset, end)
    if count > 65536 or pos + count > end:
        raise ParseError("name exceeds bounded section")
    return data[pos:pos + count].decode("utf-8", "replace")[:256], pos + count


def wasm_profile(data: bytes) -> dict:
    if len(data) < 8 or data[:4] != b"\0asm":
        raise ParseError("missing WebAssembly signature")
    version = int.from_bytes(data[4:8], "little")
    if version != 1:
        raise ParseError("unsupported WebAssembly binary version")
    offset, sections, imports, exports, seen = 8, [], [], [], set()
    while offset < len(data):
        if len(sections) >= MAX_SECTIONS:
            raise ParseError("too many WebAssembly sections")
        start = offset
        section_id = data[offset]
        length, offset = _leb(data, offset + 1, len(data))
        end = offset + length
        if end > len(data):
            raise ParseError("section size exceeds bounded file")
        if section_id and section_id in seen:
            raise ParseError("duplicate non-custom WebAssembly section")
        if section_id:
            seen.add(section_id)
        section = {"id": section_id, "offset": start, "payload_offset": offset, "payload_size": length}
        if section_id == 0:
            section["name"], _ = _name(data, offset, end)
        if section_id in (2, 7):
            count, pos = _leb(data, offset, end)
            if count > MAX_SYMBOLS:
                raise ParseError("import/export count exceeds parser limit")
            for _ in range(count):
                if section_id == 2:
                    module, pos = _name(data, pos, end)
                symbol, pos = _name(data, pos, end)
                if pos >= end:
                    raise ParseError("truncated import/export kind")
                kind, pos = data[pos], pos + 1
                if section_id == 7:
                    index, pos = _leb(data, pos, end)
                    if len(exports) < MAX_NAMES:
                        exports.append({"name": symbol, "kind": kind, "index": index})
                else:
                    if kind == 0 or kind == 4:
                        if kind == 4:
                            if pos >= end:
                                raise ParseError("truncated tag attribute")
                            pos += 1
                        _, pos = _leb(data, pos, end)
                    elif kind in (1, 2):
                        if kind == 1:
                            if pos >= end:
                                raise ParseError("truncated table reference type")
                            pos += 1
                        flags, pos = _leb(data, pos, end)
                        _, pos = _leb(data, pos, end)
                        if flags & 1:
                            _, pos = _leb(data, pos, end)
                    elif kind == 3:
                        if pos + 2 > end:
                            raise ParseError("truncated global type")
                        pos += 2
                    else:
                        raise ParseError("unknown WebAssembly import kind")
                    if len(imports) < MAX_NAMES:
                        imports.append({"module": module, "name": symbol, "kind": kind})
            section["entries_declared"] = count
        sections.append(section)
        offset = end
    return {"version": version, "sections": sections, "imports_sample": imports,
            "exports_sample": exports, "limits": {"sections": MAX_SECTIONS, "names": MAX_NAMES,
            "import_export_entries_examined": MAX_SYMBOLS}}


def deep_inspect(target: str | Path) -> dict:
    identity = inspect_path(target)
    if identity["kind"] == "directory":
        raise ValueError("Deep structural analysis requires a regular file")
    p = Path(identity["path"])
    if identity["kind"] not in ("pe", "elf", "wasm"):
        return {"artifact": identity, "status": "unsupported", "profile": {},
                "limitations": ["Deep structural parser currently supports PE, ELF and WebAssembly version 1 only"]}
    with p.open("rb") as stream:
        data = stream.read(MAX_READ)
    partial = identity["bytes"] > len(data)
    try:
        parse = {"pe": pe_profile, "elf": elf_profile, "wasm": wasm_profile}[identity["kind"]]
        profile = parse(data)
        status, errors = ("partial" if partial else "complete"), []
    except (ParseError, UnicodeError, struct.error) as exc:
        profile, errors, status = {}, [str(exc)], ("partial" if partial else "invalid")
    return {"artifact": {"path": identity["path"], "sha256": identity["sha256"],
                          "kind": identity["kind"], "bytes": identity["bytes"]},
            "status": status, "profile": profile, "parse_errors": errors,
            "bytes_available_to_parser": len(data),
            "limitations": ["Only the first 32 MiB is available to the structural parser; complete status means parsing finished, not semantic validation"]
                           + (["Large file: observations may be incomplete"] if partial else []),
            "provenance": "Built-in read-only structured parser; no target execution, decompilation or live instrumentation"}


def structural_diff(before: str | Path, after: str | Path) -> dict:
    a, b = deep_inspect(before), deep_inspect(after)
    if a["status"] not in ("complete", "partial") or b["status"] not in ("complete", "partial"):
        raise ValueError("Both artifacts must have parseable PE, ELF or WASM structures")
    if a["artifact"]["kind"] != b["artifact"]["kind"]:
        raise ValueError("Structural diff requires identical artifact formats")
    kind = a["artifact"]["kind"]
    if kind == "pe":
        keys = ("sections", "imports", "exports_sample")
    elif kind == "elf":
        keys = ("sections", "needed_libraries", "dynamic_symbol_names_sample")
    else:
        keys = ("sections", "imports_sample", "exports_sample")
    differences = {}
    for key in keys:
        old, new = a["profile"].get(key, []), b["profile"].get(key, [])
        if old != new:
            differences[key] = {"before": old, "after": new}
    return {"kind": kind, "before_sha256": a["artifact"]["sha256"],
            "after_sha256": b["artifact"]["sha256"], "structural_changes": differences,
            "partial": a["status"] == "partial" or b["status"] == "partial",
            "limitations": "This is a structural change report; it cannot establish code execution paths or behavioral equivalence."}
