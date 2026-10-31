"""Bounded, dependency-free format triage. No target execution or extraction."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import zipfile

READ_SIZE = 8192
MAX_ZIP_ENTRIES = 200
MAX_TREE_ENTRIES = 512
MAX_TREE_BYTES = 256 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sniff(header: bytes, filename: str) -> tuple[str, dict]:
    obs: dict = {}
    if header.startswith(b"\x7fELF"):
        obs["bits"] = {1: 32, 2: 64}.get(header[4], "unknown") if len(header) > 5 else "unknown"
        obs["endianness"] = {1: "little", 2: "big"}.get(header[5], "unknown") if len(header) > 5 else "unknown"
        if len(header) >= 20 and obs["endianness"] in ("little", "big"):
            obs["machine"] = int.from_bytes(header[18:20], obs["endianness"])
        return "elf", obs
    if header.startswith(b"MZ") and len(header) >= 0x40:
        peoff = struct.unpack_from("<I", header, 0x3C)[0]
        if peoff + 24 <= len(header) and header[peoff:peoff+4] == b"PE\x00\x00":
            obs["machine"] = struct.unpack_from("<H", header, peoff + 4)[0]
            obs["sections_declared"] = struct.unpack_from("<H", header, peoff + 6)[0]
            return "pe", obs
        return "mz-or-pe-unconfirmed", {"warning": "PE signature not confirmed in bounded header"}
    if header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xbe\xba\xfe\xca"):
        return "mach-o", obs
    if header.startswith(b"\xca\xfe\xba\xbe") and len(header) >= 8:
        count_or_version = int.from_bytes(header[4:8], "big")
        if 1 <= count_or_version <= 40:
            return "mach-o-fat", {"architectures_declared": count_or_version}
        major = int.from_bytes(header[6:8], "big")
        if 45 <= major <= 100:
            return "java-class", {"class_major_version": major}
        return "java-class-or-mach-fat-unconfirmed", {"warning": "Ambiguous class/fat Mach-O magic"}
    if header.startswith(b"\x00asm") and len(header) >= 8:
        return "wasm", {"version": int.from_bytes(header[4:8], "little")}
    if header.startswith(b"dex\n"):
        return "dex", {"dex_version": header[4:7].decode("ascii", errors="replace")}
    if header.startswith(b"SQLite format 3\x00"):
        return "sqlite", obs
    if header.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")):
        return "pcap", obs
    if header.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcapng", obs
    if header.startswith(b"\x1f\x8b"):
        return "gzip", obs
    if header.startswith(b"\xfd7zXZ\x00"):
        return "xz", obs
    if header.startswith(b"!<arch>\n"):
        return "ar-archive", obs
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        return "zip", obs
    if len(header) > 262 and header[257:262] == b"ustar":
        return "tar", obs
    if filename.lower().endswith(".asar"):
        return "asar-unconfirmed", {"warning": "Extension only; ASAR format not validated"}
    if filename.lower().endswith(".har") and header.lstrip().startswith(b"{"):
        return "har-json-unconfirmed", {"warning": "Format inferred from extension and JSON prefix"}
    return "unknown", obs


def _zip_inventory(path: Path, observations: dict, warnings: list[str]) -> str:
    with zipfile.ZipFile(path) as zipf:
        members = zipf.infolist()
        names = [m.filename for m in members]
        observations["archive_entries"] = len(members)
        observations["entries_sample"] = names[:MAX_ZIP_ENTRIES]
        observations["total_uncompressed_bytes_declared"] = sum(m.file_size for m in members)
        observations["encrypted_entries"] = sum(bool(m.flag_bits & 1) for m in members)
        suspicious = [n for n in names if n.startswith(("/", "\\")) or ".." in n.replace("\\", "/").split("/")]
        observations["unsafe_entry_paths_sample"] = suspicious[:20]
        if len(members) > MAX_ZIP_ENTRIES:
            warnings.append("Archive listing truncated to 200 entries; no members extracted")
        if suspicious:
            warnings.append("Archive contains absolute or parent-traversal entry names")
        if any(m.compress_size and m.file_size / m.compress_size > 500 for m in members):
            warnings.append("Potential high-compression-ratio archive; no extraction performed")
        name_set = set(names)
        if "AndroidManifest.xml" in name_set and any(n.startswith("classes") and n.endswith(".dex") for n in name_set):
            return "apk"
        if "BundleConfig.pb" in name_set:
            return "android-app-bundle"
        if any(n.startswith("Payload/") and ".app/" in n for n in names):
            return "ipa"
        if "[Content_Types].xml" in name_set:
            return "ooxml-package"
        if "META-INF/MANIFEST.MF" in name_set:
            return "jar"
        if "mimetype" in name_set:
            return "zip-mimetype-package"
    return "zip"


def _inspect_tree(root: Path, warnings: list[str]) -> tuple[str, dict]:
    digest = hashlib.sha256()
    count, skipped, total = 0, 0, 0
    sample: list[dict] = []
    # Use os.walk-like iteration without following symlinks; skip path traversal by path.resolve validation.
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        count += 1
        size = path.stat().st_size
        if count > MAX_TREE_ENTRIES or total + size > MAX_TREE_BYTES:
            skipped += 1
            continue
        total += size
        rel = path.relative_to(root).as_posix()
        file_hash = sha256_file(path)
        digest.update(f"{rel}\0{size}\0{file_hash}\n".encode("utf-8"))
        if len(sample) < 40:
            sample.append({"path": rel, "bytes": size, "sha256": file_hash})
    if skipped:
        warnings.append(f"Directory identity is PARTIAL: {skipped} files skipped by limits")
    return digest.hexdigest(), {"sample_files": sample, "hashed_files": count - skipped, "skipped_files": skipped, "bytes_hashed": total}


def inspect_path(path: str | Path) -> dict:
    p = Path(path).expanduser()
    if p.is_symlink():
        raise ValueError("Symlink targets are refused to prevent unintentional traversal")
    p = p.resolve(strict=True)
    warnings: list[str] = []
    if p.is_dir():
        digest, details = _inspect_tree(p, warnings)
        return {"path": str(p), "kind": "directory", "sha256": digest, "identity_complete": not bool(details["skipped_files"]),
                "bytes": details["bytes_hashed"], "observations": details, "warnings": warnings,
                "method": "ordered path + size + per-file SHA-256 manifest (bounded)"}
    if not p.is_file():
        raise ValueError("Target must be a regular file or directory")
    size = p.stat().st_size
    digest = sha256_file(p)
    with p.open("rb") as inp:
        header = inp.read(READ_SIZE)
    kind, obs = _sniff(header, p.name)
    if kind == "zip":
        try:
            kind = _zip_inventory(p, obs, warnings)
        except (zipfile.BadZipFile, ValueError, OSError) as exc:
            warnings.append(f"ZIP header exists but archive validation failed: {type(exc).__name__}")
            kind = "zip-invalid"
    if kind == "unknown":
        warnings.append("Unknown container; do not infer firmware, executable or document solely from its extension")
    return {"path": str(p), "kind": kind, "sha256": digest, "identity_complete": True,
            "bytes": size, "observations": obs, "warnings": warnings,
            "method": f"SHA-256 of full file; first {len(header)} bytes examined; bounded ZIP listing where applicable"}
