"""Lightweight local signal extraction and cross-version comparison with explicit bounds."""
from __future__ import annotations

from collections import Counter
import math
from pathlib import Path
import re

from .inspector import inspect_path

MAX_SCAN = 16 * 1024 * 1024
BLOCK = 64 * 1024
SIGNATURES = {
    "elf": b"\x7fELF", "pe-dos": b"MZ", "zip": b"PK\x03\x04", "gzip": b"\x1f\x8b",
    "sqlite": b"SQLite format 3\x00", "png": b"\x89PNG\r\n\x1a\n", "wasm": b"\x00asm",
    "dex": b"dex\n", "squashfs": b"hsqs", "jpeg": b"\xff\xd8\xff",
}


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    size = len(data)
    return -sum((cnt / size) * math.log2(cnt / size) for cnt in Counter(data).values())


def scan_signals(path: str | Path, *, include_strings: bool = False) -> dict:
    metadata = inspect_path(path)
    if metadata["kind"] == "directory":
        raise ValueError("Signals analysis requires a regular file")
    p = Path(metadata["path"])
    with p.open("rb") as f:
        data = f.read(MAX_SCAN)
    entropy = [{"offset": i, "length": len(data[i:i+BLOCK]), "bits_per_byte": round(shannon(data[i:i+BLOCK]), 4)}
               for i in range(0, len(data), BLOCK)]
    signature_hits = []
    for label, marker in SIGNATURES.items():
        pos, count = 0, 0
        while count < 16:
            off = data.find(marker, pos)
            if off < 0:
                break
            signature_hits.append({"kind": label, "offset": off})
            pos, count = off + 1, count + 1
    signature_hits.sort(key=lambda v: (v["offset"], v["kind"]))
    out = {"sha256": metadata["sha256"], "kind": metadata["kind"], "bytes_total": metadata["bytes"],
           "bytes_scanned": len(data), "partial": metadata["bytes"] > len(data),
           "entropy_64k": entropy, "embedded_signatures": signature_hits,
           "interpretation": "Entropy and magic signatures are indicators, not verified encryption, packers, code reachability or maliciousness."}
    if include_strings:
        # ASCII only, bounded by MAX_SCAN and 80 samples; explicit opt-in prevents accidental disclosure.
        candidates = []
        for match in re.finditer(rb"[\x20-\x7e]{8,256}", data):
            candidates.append({"offset": match.start(), "text": match.group().decode("ascii")})
            if len(candidates) >= 80:
                break
        out["ascii_strings_sample"] = candidates
        out["sensitivity_warning"] = "Strings may contain secrets or private data. Do not upload or share without review."
    else:
        out["strings_suppressed"] = "Opt in with --include-strings; raw strings may contain secrets."
    return out


def compare_files(before: str | Path, after: str | Path) -> dict:
    a, b = inspect_path(before), inspect_path(after)
    if a["kind"] == "directory" or b["kind"] == "directory":
        raise ValueError("Bytewise compare requires regular files")
    changed = 0
    sample: list[dict] = []
    scanned = 0
    pa, pb = Path(a["path"]), Path(b["path"])
    with pa.open("rb") as fa, pb.open("rb") as fb:
        while scanned < MAX_SCAN:
            size = min(64 * 1024, MAX_SCAN - scanned)
            va, vb = fa.read(size), fb.read(size)
            if not va and not vb:
                break
            shared = min(len(va), len(vb))
            for i in range(shared):
                if va[i] != vb[i]:
                    changed += 1
                    if len(sample) < 32:
                        sample.append({"offset": scanned+i, "old": va[i], "new": vb[i]})
            scanned += max(len(va), len(vb))
    common = min(a["bytes"], b["bytes"], MAX_SCAN)
    return {
        "before": {"path": a["path"], "sha256": a["sha256"], "bytes": a["bytes"], "kind": a["kind"]},
        "after": {"path": b["path"], "sha256": b["sha256"], "bytes": b["bytes"], "kind": b["kind"]},
        "identical_sha256": a["sha256"] == b["sha256"],
        "different_bytes_in_scanned_overlap": changed,
        "first_differing_offsets": sample,
        "scanned_overlap_bytes": common,
        "partial_byte_compare": min(a["bytes"], b["bytes"]) > MAX_SCAN,
        "byte_length_delta": b["bytes"] - a["bytes"],
        "limitations": "Byte comparison does not establish behavior equivalence; trailing additions/removals are represented in byte_length_delta.",
    }
